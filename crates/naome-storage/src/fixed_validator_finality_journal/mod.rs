//! Crash-consistent fixed-validator V0 finality installation.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, SeekFrom};
use std::path::Path;

use naome_chain::{
    ArtifactBlockId, ArtifactChainBranchSnapshot, ArtifactChainDefinition, ArtifactChainId,
    ArtifactChainState, ArtifactSetRoot,
};
use naome_consensus::{
    ActiveAgreementEntry, ConsensusAncestryId, ConsensusContextV0, ConsensusEnvelopeId,
    ConsensusEnvelopeVerifyError, ConsensusHeight, ConsensusPosition, ConsensusProposalVerifyError,
    ConsensusRound, ConsensusValueError, ConsensusValueV0, FixedAgreementSetId,
    FixedConsensusBoundedEnvelopeVerifyError, FixedConsensusBranchV0, FixedConsensusGenesisError,
    FixedConsensusPrecommitBatchSealErrorV0, OwnedVerifiedFixedConsensusTransitionV0,
    ProposerSelectionError, VerifiedFixedConsensusProposalV0, VerifiedFixedConsensusTransitionV0,
};
use naome_proof::{ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId};
use sha2::{Digest, Sha256};

use super::fixed_validator_anchor::{
    AnchorPositionV0, FixedValidatorAnchorErrorV0, FixedValidatorAnchorFileV0,
    JournalAnchorTransitionV0, sync_directory,
};
use super::fixed_validator_vote_safety_journal::{
    FixedValidatorAnchoredSignerRecoveryV0, FixedValidatorRecoveredSignerBranchV0,
    signing_lineage_id,
};
use super::{
    AppendPhase, ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError,
    CanonicalArtifactPayloadStore, CanonicalArtifactPayloadStoreError, ExclusiveLockError,
    JOURNAL_FILE_NAME, LOCK_FILE_NAME, SelectedArtifactHistory, SelectedArtifactHistoryError,
    StoreIo, open_exclusive_lock, selected_artifact_history_sealed,
};

const JOURNAL_HEADER: &[u8] = b"naome:fixed-validator-finality-journal:v0\0";
const GENESIS_STATE_DOMAIN: &[u8] = b"naome:fixed-validator-finality-journal-state-genesis:v0\0";
const STEP_STATE_DOMAIN: &[u8] = b"naome:fixed-validator-finality-journal-state-step:v0\0";

const CHAIN_ID_BYTES: usize = 32;
const GENESIS_ID_BYTES: usize = 32;
const PROTOCOL_VERSION_BYTES: usize = 4;
const FIXED_SET_ID_BYTES: usize = FixedAgreementSetId::BYTE_LENGTH;
const ROUND_LIMIT_BYTES: usize = 8;
const HEADER_FIELDS_BYTES: usize = CHAIN_ID_BYTES
    + GENESIS_ID_BYTES
    + PROTOCOL_VERSION_BYTES
    + FIXED_SET_ID_BYTES
    + ROUND_LIMIT_BYTES;
const JOURNAL_PREFIX_BYTES: usize = JOURNAL_HEADER.len() + HEADER_FIELDS_BYTES;

const FINALIZE_RECORD: u8 = 1;
const CONFLICT_HALT_RECORD: u8 = 2;
const PRESELECTION_CONFLICT_HALT_RECORD: u8 = 3;
const RECORD_HEADER_BYTES: usize = 1 + 8 + 4 + 4;
const PRESELECTION_CONFLICT_RECORD_HEADER_BYTES: usize = 1 + 8 + 4 + 4 + 4 + 4;
const RECORD_LENGTH_BYTES: u64 = 4;
const STATE_ID_BYTES: u64 = FixedValidatorFinalityJournalStateIdV0::BYTE_LENGTH as u64;
const ENTRY_FIXED_BYTES: u64 = RECORD_LENGTH_BYTES + STATE_ID_BYTES;
const MIN_SINGLE_RECORD_BODY_BYTES: usize =
    RECORD_HEADER_BYTES + VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH + 1;
const MAX_SINGLE_RECORD_BODY_BYTES: usize = RECORD_HEADER_BYTES
    + VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH
    + ARTIFACT_PAYLOAD_MAX_BYTES;
const MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES: usize = PRESELECTION_CONFLICT_RECORD_HEADER_BYTES
    + (2 * VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH)
    + 2;
const MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES: usize = PRESELECTION_CONFLICT_RECORD_HEADER_BYTES
    + (2 * VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH)
    + (2 * ARTIFACT_PAYLOAD_MAX_BYTES);
const MIN_RECORD_BODY_BYTES: usize = MIN_SINGLE_RECORD_BODY_BYTES;
const MAX_RECORD_BODY_BYTES: usize = MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES;

/// One exclusively opened joint fixed-validator consensus-and-artifact journal.
///
/// The journal reuses the artifact-chain journal file and lock namespace as a
/// clean prerelease replacement in its directory. It admits only sealed typed
/// transitions, synchronizes their exact envelope and payload together, and
/// publishes the child only after the chained state-ID footer is durable.
#[must_use]
pub struct FixedValidatorFinalityJournalV0 {
    _lock: File,
    core: FixedValidatorFinalityJournalCore<File>,
}

/// A finality journal whose every state-changing frame is synchronously copied
/// into one independent crash-safe anchor before its outcome is published.
///
/// The anchor is a separate file and commit unit. A crash between the journal
/// footer sync and anchor replacement deliberately leaves strict reopen unable
/// to choose or repair either side; it does not create cross-file atomicity.
#[must_use]
pub struct FixedValidatorAnchoredFinalityJournalV0 {
    journal: FixedValidatorFinalityJournalV0,
}

impl selected_artifact_history_sealed::Sealed for FixedValidatorFinalityJournalV0 {}

impl SelectedArtifactHistory for FixedValidatorFinalityJournalV0 {
    fn selected_chain_id(&self) -> ArtifactChainId {
        self.core.context.chain_id()
    }

    fn selected_head_block_id(&self) -> Result<ArtifactBlockId, SelectedArtifactHistoryError> {
        self.artifact_head_block_id()
            .map_err(SelectedArtifactHistoryError::fixed_validator_finality)
    }

    fn selected_artifact_set_root(&self) -> Result<ArtifactSetRoot, SelectedArtifactHistoryError> {
        self.artifact_set_root()
            .map_err(SelectedArtifactHistoryError::fixed_validator_finality)
    }

    fn selected_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, SelectedArtifactHistoryError> {
        self.artifact_branch_snapshot_at(block_id)
            .map_err(SelectedArtifactHistoryError::fixed_validator_finality)
    }
}

impl selected_artifact_history_sealed::Sealed for FixedValidatorAnchoredFinalityJournalV0 {}

impl SelectedArtifactHistory for FixedValidatorAnchoredFinalityJournalV0 {
    fn selected_chain_id(&self) -> ArtifactChainId {
        self.journal.core.context.chain_id()
    }

    fn selected_head_block_id(&self) -> Result<ArtifactBlockId, SelectedArtifactHistoryError> {
        self.artifact_head_block_id()
            .map_err(SelectedArtifactHistoryError::fixed_validator_finality)
    }

    fn selected_artifact_set_root(&self) -> Result<ArtifactSetRoot, SelectedArtifactHistoryError> {
        self.artifact_set_root()
            .map_err(SelectedArtifactHistoryError::fixed_validator_finality)
    }

    fn selected_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, SelectedArtifactHistoryError> {
        self.artifact_branch_snapshot_at(block_id)
            .map_err(SelectedArtifactHistoryError::fixed_validator_finality)
    }
}

enum FinalityAppendEvidenceV0 {
    Single(ConsensusEnvelopeId),
    Pair {
        first: ConsensusEnvelopeId,
        second: ConsensusEnvelopeId,
    },
}

struct FixedValidatorFinalityJournalCore<F> {
    file: F,
    context: ConsensusContextV0,
    replay_limit: FixedValidatorFinalityReplayLimitV0,
    branches: Vec<FixedConsensusBranchV0>,
    snapshot_index: HashMap<ArtifactBlockId, usize>,
    records: Vec<FixedValidatorFinalityRecordV0>,
    halt: Option<FixedValidatorFinalityHaltV0>,
    state_id: FixedValidatorFinalityJournalStateIdV0,
    record_sequence: u64,
    anchor: Option<FixedValidatorAnchorFileV0>,
    committed_end: u64,
    poisoned: bool,
}

fn genesis_snapshot_index(
    branches: &[FixedConsensusBranchV0],
) -> Result<HashMap<ArtifactBlockId, usize>, FixedValidatorFinalityJournalErrorV0> {
    let genesis = branches
        .first()
        .expect("every new joint journal receives its virtual-genesis branch")
        .artifact_snapshot()
        .head_block_id();
    let mut snapshot_index = HashMap::new();
    snapshot_index.try_reserve(1).map_err(|_| {
        FixedValidatorFinalityJournalErrorV0::SnapshotIndexAllocation {
            entry: 0,
            retained_snapshots: 0,
        }
    })?;
    snapshot_index.insert(genesis, 0);
    Ok(snapshot_index)
}

impl<F: StoreIo> FixedValidatorFinalityJournalCore<F> {
    fn empty(
        file: F,
        context: ConsensusContextV0,
        replay_limit: FixedValidatorFinalityReplayLimitV0,
        branches: Vec<FixedConsensusBranchV0>,
        snapshot_index: HashMap<ArtifactBlockId, usize>,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Self {
        debug_assert_eq!(snapshot_index.len(), 1);
        Self {
            file,
            context,
            replay_limit,
            branches,
            snapshot_index,
            records: Vec::new(),
            halt: None,
            state_id,
            record_sequence: 0,
            anchor: None,
            committed_end: JOURNAL_PREFIX_BYTES as u64,
            poisoned: false,
        }
    }

    fn ensure_healthy(&self) -> Result<(), FixedValidatorFinalityJournalErrorV0> {
        if self.poisoned {
            Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
        } else {
            Ok(())
        }
    }

    fn ensure_operational(&self) -> Result<(), FixedValidatorFinalityJournalErrorV0> {
        self.ensure_healthy()?;
        if let Some(halt) = self.halt {
            Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt {
                height: halt.height(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;

mod types;
pub use types::*;
mod anchored;
mod append;
mod candidate_commit;
mod historical_conflict;
mod proof_routing;
pub use historical_conflict::FixedValidatorHistoricalFinalityConflictErrorV0;
mod errors;
mod journal;
mod records;
mod recovery;
mod replay;
mod transitions;
pub use candidate_commit::*;
pub use errors::*;
use records::*;
