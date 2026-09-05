//! Crash-consistent fixed-validator V0 vote preparation and release.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    CompletedFixedValidatorProposalV0, ConsensusAncestryId, ConsensusContextV0,
    ConsensusEnvelopeId, ConsensusHeight, ConsensusKey, ConsensusPosition, ConsensusRound,
    ConsensusSignature, ConsensusVoteId, ConsensusVoteRole, ConsensusVoteTarget,
    ConsensusVoteVerifyError, FixedAgreementSetId, FixedConsensusBranchCoordinateV0,
    FixedConsensusBranchV0, FixedConsensusRoundV0, FixedValidatorHigherRoundCheckpointErrorV0,
    FixedValidatorLockPhaseV0, FixedValidatorLockStateError, FixedValidatorLockStateV0,
    FixedValidatorLockedValueV0, FixedValidatorProposalIntentErrorV0,
    FixedValidatorProposalIntentV0, FixedValidatorProposalSourceV0,
    FixedValidatorUnsignedVoteEffectV0, FixedValidatorValidValueV0, FixedValidatorVoteIntentError,
    FixedValidatorVoteIntentV0, ObservedFixedValidatorHigherRoundCheckpointV0,
    ObservedFixedValidatorProposalIntentV0, ObservedFixedValidatorVoteIntentV0,
    ProposalSigningRoot, ProposerSelectionError, VerifiedConsensusVoteV0,
    VerifiedFixedConsensusProposalV0, VerifiedFixedValidatorHigherRoundAdvanceV0,
    VerifiedReplayFixedValidatorHigherRoundCheckpointV0, VerifiedReplayFixedValidatorVoteIntentV0,
};
use sha2::{Digest, Sha256};

use super::fixed_validator_anchor::{
    AnchorPositionV0, FixedValidatorAnchorErrorV0, FixedValidatorAnchorFileV0,
    JournalAnchorTransitionV0, sync_directory,
};
use super::fixed_validator_finality_journal::{
    FixedValidatorDurableFinalityConflictV0, FixedValidatorDurableFinalityTransitionV0,
    FixedValidatorFinalityHaltKindV0, FixedValidatorFinalityJournalStateIdV0,
};
use super::{AppendPhase, ExclusiveLockError, StoreIo, open_exclusive_lock};

const JOURNAL_HEADER: &[u8] = b"naome:fixed-validator-vote-safety-journal:v0\0";
const GENESIS_STATE_DOMAIN: &[u8] = b"naome:fixed-validator-vote-safety-state-genesis:v0\0";
const STEP_STATE_DOMAIN: &[u8] = b"naome:fixed-validator-vote-safety-state-step:v0\0";
const FILE_STEM: &str = "fixed-validator-vote-safety-";
const LOCK_SUFFIX: &str = ".lock";
const JOURNAL_SUFFIX: &str = ".journal";

const CHAIN_ID_BYTES: usize = 32;
const GENESIS_ID_BYTES: usize = 32;
const PROTOCOL_VERSION_BYTES: usize = 4;
const FIXED_SET_ID_BYTES: usize = FixedAgreementSetId::BYTE_LENGTH;
const CONSENSUS_KEY_BYTES: usize = 32;
const REPLAY_LIMIT_BYTES: usize = 8;
const HEADER_FIELDS_BYTES: usize = CHAIN_ID_BYTES
    + GENESIS_ID_BYTES
    + PROTOCOL_VERSION_BYTES
    + FIXED_SET_ID_BYTES
    + CONSENSUS_KEY_BYTES
    + REPLAY_LIMIT_BYTES;
const JOURNAL_PREFIX_BYTES: usize = JOURNAL_HEADER.len() + HEADER_FIELDS_BYTES;

const PREPARE_RECORD: u8 = 1;
const COMPLETE_RECORD: u8 = 2;
const CONFLICT_HALT_RECORD: u8 = 3;
const SIGNING_LINEAGE_RECORD: u8 = 4;
const FINALITY_CONFLICT_STOP_RECORD: u8 = 5;
const HIGHER_ROUND_CHECKPOINT_RECORD: u8 = 6;
const PROPOSAL_ACTIVATION_RECORD: u8 = 7;
const PROPOSAL_PREPARE_RECORD: u8 = 8;
const PROPOSAL_COMPLETE_RECORD: u8 = 9;
const PROPOSAL_CONFLICT_HALT_RECORD: u8 = 10;
const PRESELECTION_CONFLICT_STOP_RECORD: u8 = 11;
const SIGNING_LINEAGE_DOMAIN: &[u8] = b"naome:fixed-validator-vote-safety-signing-lineage:v0\0";
const SIGNING_LINEAGE_ID_BYTES: usize = 32;
const SIGNING_LINEAGE_PAYLOAD_BYTES: usize = 8 + SIGNING_LINEAGE_ID_BYTES;
const SIGNING_LINEAGE_BODY_BYTES: usize = 1 + SIGNING_LINEAGE_PAYLOAD_BYTES;
const FINALITY_CONFLICT_STOP_PAYLOAD_BYTES: usize = 32 + 8 + 32 + 32 + 32 + 32;
const FINALITY_CONFLICT_STOP_BODY_BYTES: usize = 1 + FINALITY_CONFLICT_STOP_PAYLOAD_BYTES;
const PROPOSAL_ACTIVATION_PAYLOAD_BYTES: usize = 8;
const PROPOSAL_ACTIVATION_BODY_BYTES: usize = 1 + PROPOSAL_ACTIVATION_PAYLOAD_BYTES;
const RECORD_LENGTH_BYTES: u64 = 4;
const STATE_ID_BYTES: u64 = FixedValidatorVoteSafetyJournalStateIdV0::BYTE_LENGTH as u64;
const ENTRY_FIXED_BYTES: u64 = RECORD_LENGTH_BYTES + STATE_ID_BYTES;
const SIGNED_VOTE_BODY_BYTES: usize = 1 + VerifiedConsensusVoteV0::BYTE_LENGTH;
const MIN_RECORD_BODY_BYTES: usize = 1 + FixedValidatorVoteIntentV0::MIN_BYTE_LENGTH;
const MAX_RECORD_BODY_BYTES: usize = 1 + FixedValidatorVoteIntentV0::MAX_BYTE_LENGTH;
const MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES: usize =
    1 + ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH;
const MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES: usize =
    1 + ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH;
const MIN_PROPOSAL_INTENT_BODY_BYTES: usize =
    1 + ObservedFixedValidatorProposalIntentV0::MIN_BYTE_LENGTH;
const MAX_PROPOSAL_INTENT_BODY_BYTES: usize =
    1 + ObservedFixedValidatorProposalIntentV0::MAX_BYTE_LENGTH;
const COMPLETED_PROPOSAL_BODY_BYTES: usize =
    1 + naome_consensus::VerifiedProducerAuthorizationV0::BYTE_LENGTH;
const MAX_BOUNDED_RECORD_BODY_BYTES: usize =
    if MAX_PROPOSAL_INTENT_BODY_BYTES > MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES {
        MAX_PROPOSAL_INTENT_BODY_BYTES
    } else {
        MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES
    };

/// One exclusively opened, per-key fixed-validator vote-safety journal.
///
/// Construction consumes and privately retains the local [`SigningKey`]. The
/// enabled `zeroize` feature clears its secret bytes on drop. Rust ownership
/// cannot prove that no external seed or key copy exists; anti-equivocation
/// requires this journal to be the sole operational vote and
/// producer-authorization signing path.
///
/// The journal authenticates only the exact producer authorization sealed by
/// the current branch-bound proposal intent. It provides no proposal
/// publication, remote-signing protocol, timeout scheduling, networking, peer
/// trust, validator selection, branch choice, or finality authority.
#[must_use]
pub struct FixedValidatorVoteSafetyJournalV0 {
    _lock: File,
    signing_key: SigningKey,
    core: FixedValidatorVoteSafetyJournalCore<File>,
    session_issued: bool,
    session_seal: Arc<()>,
}

/// A per-key vote-safety journal paired with one independent crash-safe anchor.
///
/// Every state-changing frame advances the anchor before the journal publishes
/// its outcome, signing capability, live height or round effect, terminal stop,
/// or signed vote bytes. The two files remain separate commit units and no
/// cross-file atomic transaction or automatic repair is claimed.
#[must_use]
pub struct FixedValidatorAnchoredVoteSafetyJournalV0 {
    journal: FixedValidatorVoteSafetyJournalV0,
}

/// The sole signing session issued by an anchored per-key journal.
#[must_use]
pub struct FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal> {
    session: FixedValidatorVoteSafetySigningSessionV0<'journal>,
}

/// One exactly recovered branch paired with an anchored signing session.
#[must_use]
pub struct FixedValidatorAnchoredRecoveredSigningSessionV0<'journal> {
    branch: FixedConsensusBranchV0,
    session: FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal>,
}

struct FixedValidatorVoteSafetyJournalCore<F> {
    file: F,
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    signer: ConsensusKey,
    replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    proposal_replay_limit: Option<FixedValidatorProposalReplayLimitV0>,
    votes: HashMap<VoteSlot, RetainedVote>,
    proposals: HashMap<ConsensusPosition, RetainedProposal>,
    pending: Option<VoteSlot>,
    pending_proposal: Option<ConsensusPosition>,
    live_pending_intent: Option<FixedValidatorVoteIntentV0>,
    live_pending_proposal_intent: Option<FixedValidatorProposalIntentV0>,
    latest_slot: Option<VoteSlot>,
    latest_proposal_position: Option<ConsensusPosition>,
    lineage: Option<RetainedSigningLineageV0>,
    latest_current_lineage_state: Option<RetainedCurrentLineageStateV0>,
    prepared_count: u64,
    prepared_proposal_count: u64,
    halt: Option<FixedValidatorVoteSafetyHaltV0>,
    proposal_halt: Option<FixedValidatorProposalSafetyHaltV0>,
    finality_conflict_stop: Option<FixedValidatorFinalityConflictSignerStopV0>,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    record_sequence: u64,
    anchor: Option<FixedValidatorAnchorFileV0>,
    committed_end: u64,
    poisoned: bool,
}

impl<F: StoreIo> FixedValidatorVoteSafetyJournalCore<F> {
    fn empty(
        file: F,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signer: ConsensusKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Self {
        Self {
            file,
            context,
            fixed_set_id,
            signer,
            replay_limit,
            proposal_replay_limit: None,
            votes: HashMap::new(),
            proposals: HashMap::new(),
            pending: None,
            pending_proposal: None,
            live_pending_intent: None,
            live_pending_proposal_intent: None,
            latest_slot: None,
            latest_proposal_position: None,
            lineage: None,
            latest_current_lineage_state: None,
            prepared_count: 0,
            prepared_proposal_count: 0,
            halt: None,
            proposal_halt: None,
            finality_conflict_stop: None,
            state_id,
            record_sequence: 0,
            anchor: None,
            committed_end: JOURNAL_PREFIX_BYTES as u64,
            poisoned: false,
        }
    }

    fn pending_capability(&self) -> Option<FixedValidatorPreparedVoteV0> {
        self.live_pending_intent.as_ref()?;
        let slot = self.pending?;
        let retained = self
            .votes
            .get(&slot)
            .expect("every pending slot has a retained vote");
        Some(prepared_capability(slot, retained))
    }

    fn pending_summary(&self) -> Option<FixedValidatorPendingVoteV0> {
        let slot = self.pending?;
        let retained = self
            .votes
            .get(&slot)
            .expect("every pending slot has a retained vote");
        Some(FixedValidatorPendingVoteV0 {
            position: slot.position,
            role: slot.role,
            target: retained.observed_intent.target(),
            prepared_state_id: retained.prepared_state_id,
        })
    }

    fn pending_proposal_capability(&self) -> Option<FixedValidatorPreparedProposalV0> {
        self.live_pending_proposal_intent.as_ref()?;
        let position = self.pending_proposal?;
        let retained = self
            .proposals
            .get(&position)
            .expect("every pending proposal has a retained intent");
        Some(prepared_proposal_capability(position, retained))
    }

    fn pending_proposal_summary(&self) -> Option<FixedValidatorPendingProposalV0> {
        let position = self.pending_proposal?;
        let retained = self
            .proposals
            .get(&position)
            .expect("every pending proposal has a retained intent");
        Some(FixedValidatorPendingProposalV0 {
            position,
            proposal_signing_root: retained.observed_intent.proposal_signing_root(),
            prepared_state_id: retained.prepared_state_id,
        })
    }

    fn ensure_healthy(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if self.poisoned {
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        } else {
            Ok(())
        }
    }

    fn ensure_operational(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_healthy()?;
        self.ensure_not_halted()?;
        if let Some(pending) = self.restarted_pending() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::RestartedPending {
                position: pending.position,
                role: pending.role,
            });
        }
        if let Some(position) = self.restarted_pending_proposal() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::RestartedPendingProposal { position },
            );
        }
        Ok(())
    }

    fn ensure_not_halted(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_healthy()?;
        if let Some(halt) = self.halt {
            Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt {
                position: halt.position,
                role: halt.role,
            })
        } else if let Some(halt) = self.proposal_halt {
            Err(
                FixedValidatorVoteSafetyJournalErrorV0::TerminalProposalHalt {
                    position: halt.position,
                },
            )
        } else if let Some(stop) = self.finality_conflict_stop {
            Err(
                FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                    height: stop.height,
                },
            )
        } else {
            Ok(())
        }
    }

    fn restarted_pending(&self) -> Option<VoteSlot> {
        self.pending.filter(|_| self.live_pending_intent.is_none())
    }

    fn restarted_pending_proposal(&self) -> Option<ConsensusPosition> {
        self.pending_proposal
            .filter(|_| self.live_pending_proposal_intent.is_none())
    }

    fn ensure_recoverable(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_not_halted()?;
        if let Some(pending) = self.pending {
            Err(
                FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied {
                    position: pending.position,
                    role: pending.role,
                },
            )
        } else if let Some(position) = self.pending_proposal {
            Err(FixedValidatorVoteSafetyJournalErrorV0::PendingProposalRecoveryDenied { position })
        } else {
            Ok(())
        }
    }

    fn ensure_proposal_authoring_activated(
        &self,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.proposal_replay_limit
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::ProposalAuthoringNotActivated)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests;

mod types;
pub use types::*;
mod anchored;
mod append;
mod errors;
mod journal;
mod records;
mod recovery;
mod replay;
mod session;
mod transitions;
pub use errors::*;
pub use records::FixedValidatorVoteCompletionMismatchV0;
use records::*;

pub(crate) use records::signing_lineage_id;
