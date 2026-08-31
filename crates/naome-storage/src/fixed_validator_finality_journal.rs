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
    ConsensusEnvelopeVerifyError, ConsensusHeight, ConsensusPosition, ConsensusValueError,
    ConsensusValueV0, FixedAgreementSetId, FixedConsensusBranchV0, FixedConsensusGenesisError,
    OwnedVerifiedFixedConsensusTransitionV0, ProposerSelectionError,
    VerifiedFixedConsensusTransitionV0,
};
use naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;
use sha2::{Digest, Sha256};

use super::{
    AppendPhase, ExclusiveLockError, JOURNAL_FILE_NAME, LOCK_FILE_NAME, SelectedArtifactHistory,
    SelectedArtifactHistoryError, StoreIo, open_exclusive_lock, selected_artifact_history_sealed,
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
const RECORD_HEADER_BYTES: usize = 1 + 8 + 4 + 4;
const RECORD_LENGTH_BYTES: u64 = 4;
const STATE_ID_BYTES: u64 = FixedValidatorFinalityJournalStateIdV0::BYTE_LENGTH as u64;
const ENTRY_FIXED_BYTES: u64 = RECORD_LENGTH_BYTES + STATE_ID_BYTES;
const MIN_RECORD_BODY_BYTES: usize =
    RECORD_HEADER_BYTES + VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH + 1;
const MAX_RECORD_BODY_BYTES: usize = RECORD_HEADER_BYTES
    + VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH
    + ARTIFACT_PAYLOAD_MAX_BYTES;

/// Positive caller-provisioned maximum persisted finality round.
///
/// The ceiling bounds local journal admission and replay work. It is stored in
/// the journal header and is not a protocol-wide assertion that a higher-round
/// certificate is cryptographically invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorFinalityReplayLimitV0(u64);

impl FixedValidatorFinalityReplayLimitV0 {
    /// Constructs one positive local maximum round.
    pub const fn new(max_round: u64) -> Result<Self, FixedValidatorFinalityReplayLimitErrorV0> {
        if max_round == 0 {
            Err(FixedValidatorFinalityReplayLimitErrorV0)
        } else {
            Ok(Self(max_round))
        }
    }

    /// Returns the configured inclusive maximum round.
    pub const fn max_round(self) -> u64 {
        self.0
    }
}

/// A zero local replay-round ceiling is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorFinalityReplayLimitErrorV0;

impl fmt::Display for FixedValidatorFinalityReplayLimitErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixed-validator finality replay round limit must be positive")
    }
}

impl Error for FixedValidatorFinalityReplayLimitErrorV0 {}

/// Chained identity of one exact durable fixed-validator journal state.
///
/// The empty identity commits the complete synchronized header. Every later
/// identity commits the preceding identity and one exact finalized or halt
/// record. It is local persistence identity, not consensus ancestry, envelope,
/// artifact, checkpoint, or globally trusted finality by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct FixedValidatorFinalityJournalStateIdV0([u8; Self::BYTE_LENGTH]);

impl FixedValidatorFinalityJournalStateIdV0 {
    /// Exact width of one journal-state identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs one externally retained expected identity from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw journal-state identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

/// Exact first finality proof retained for one selected height.
#[derive(Debug)]
#[must_use]
pub struct FixedValidatorFinalityRecordV0 {
    position: ConsensusPosition,
    value: ConsensusValueV0,
    envelope_id: ConsensusEnvelopeId,
    canonical_record_body: Vec<u8>,
    envelope_end: usize,
    state_id: FixedValidatorFinalityJournalStateIdV0,
}

impl FixedValidatorFinalityRecordV0 {
    /// Returns the exact authenticated height and round of the retained proof.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns the exact evidence-free finalized value.
    pub const fn value(&self) -> ConsensusValueV0 {
        self.value
    }

    /// Returns the evidence-variant identity of the retained first envelope.
    pub const fn envelope_id(&self) -> ConsensusEnvelopeId {
        self.envelope_id
    }

    /// Returns the exact retained canonical envelope bytes.
    pub fn canonical_envelope_bytes(&self) -> &[u8] {
        &self.canonical_record_body[RECORD_HEADER_BYTES..self.envelope_end]
    }

    /// Returns the exact retained canonical artifact payload bytes.
    pub fn canonical_artifact_bytes(&self) -> &[u8] {
        &self.canonical_record_body[self.envelope_end..]
    }

    /// Returns the journal-state identity published by this finality record.
    pub const fn state_id(&self) -> FixedValidatorFinalityJournalStateIdV0 {
        self.state_id
    }

    fn canonical_record_body(&self) -> &[u8] {
        &self.canonical_record_body
    }
}

/// Durable terminal safety-failure evidence summary.
///
/// Both referenced envelopes were strictly verified against the same retained
/// selected parent at the same height and carry distinct exact values. The
/// summary grants diagnostic access only; no selected head remains operable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorFinalityHaltV0 {
    height: ConsensusHeight,
    selected_ancestry: ConsensusAncestryId,
    selected_envelope_id: ConsensusEnvelopeId,
    conflicting_ancestry: ConsensusAncestryId,
    conflicting_envelope_id: ConsensusEnvelopeId,
    state_id: FixedValidatorFinalityJournalStateIdV0,
}

impl FixedValidatorFinalityHaltV0 {
    /// Returns the height at which distinct finalized values were observed.
    pub const fn height(self) -> ConsensusHeight {
        self.height
    }

    /// Returns the ancestry identity of the previously selected exact value.
    pub const fn selected_ancestry(self) -> ConsensusAncestryId {
        self.selected_ancestry
    }

    /// Returns the retained first envelope identity.
    pub const fn selected_envelope_id(self) -> ConsensusEnvelopeId {
        self.selected_envelope_id
    }

    /// Returns the ancestry identity of the conflicting exact value.
    pub const fn conflicting_ancestry(self) -> ConsensusAncestryId {
        self.conflicting_ancestry
    }

    /// Returns the conflicting envelope identity committed by the halt record.
    pub const fn conflicting_envelope_id(self) -> ConsensusEnvelopeId {
        self.conflicting_envelope_id
    }

    /// Returns the terminal journal-state identity published by the halt.
    pub const fn state_id(self) -> FixedValidatorFinalityJournalStateIdV0 {
        self.state_id
    }
}

/// Result of consuming one completely verified transition at the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorFinalityCommitOutcomeV0 {
    /// One direct child became durable and operable after the commit sync.
    Finalized {
        position: ConsensusPosition,
        ancestry_id: ConsensusAncestryId,
        envelope_id: ConsensusEnvelopeId,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    },
    /// The exact value was already selected; no bytes or identity changed.
    AlreadyFinalized {
        height: ConsensusHeight,
        ancestry_id: ConsensusAncestryId,
        retained_envelope_id: ConsensusEnvelopeId,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    },
    /// A distinct valid sibling was durably recorded and operation halted.
    Halted(FixedValidatorFinalityHaltV0),
}

/// A retained selected transition whose exact finality state was acknowledged.
///
/// Private fields prevent caller construction. The live immutable journal
/// borrow keeps the issuing finality lineage operational and unchanged until a
/// key-owning vote-safety session consumes the capability.
#[must_use]
pub struct FixedValidatorDurableFinalityTransitionV0<'journal> {
    _journal: &'journal FixedValidatorFinalityJournalV0,
    transition: OwnedVerifiedFixedConsensusTransitionV0,
}

impl FixedValidatorDurableFinalityTransitionV0<'_> {
    pub(crate) const fn verified_transition(&self) -> &OwnedVerifiedFixedConsensusTransitionV0 {
        &self.transition
    }

    pub(crate) fn into_verified_transition(self) -> OwnedVerifiedFixedConsensusTransitionV0 {
        self.transition
    }
}

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

impl FixedValidatorFinalityJournalV0 {
    /// Creates and exclusively opens one empty joint journal.
    ///
    /// Creation never replaces the artifact-only or joint format already at the
    /// shared path. The returned genesis state ID must be retained through a
    /// separately trusted caller-owned anchor before it can authenticate a later
    /// operational reopen.
    pub fn create(
        directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        entries: &[ActiveAgreementEntry],
        replay_limit: FixedValidatorFinalityReplayLimitV0,
    ) -> Result<Self, FixedValidatorFinalityJournalErrorV0> {
        let branch = fixed_genesis(definition, context, entries)?;
        let prefix = canonical_prefix(context, branch.fixed_agreement_set_id(), replay_limit)?;
        let state_id = genesis_state_id(&prefix);
        let mut branches = Vec::new();
        branches.try_reserve_exact(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::Allocation {
                entry: 0,
                bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
            }
        })?;
        branches.push(branch);
        let snapshot_index = genesis_snapshot_index(&branches)?;

        let directory = directory.as_ref();
        let lock = open_shared_lock(directory)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.join(JOURNAL_FILE_NAME))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Create { source })?;
        file.append_write_all(AppendPhase::Body, &prefix)
            .and_then(|()| file.append_sync_all(AppendPhase::Body))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Create { source })?;

        Ok(Self {
            _lock: lock,
            core: FixedValidatorFinalityJournalCore::empty(
                file,
                context,
                replay_limit,
                branches,
                snapshot_index,
                state_id,
            ),
        })
    }

    /// Exclusively opens and strictly replays one externally anchored journal.
    ///
    /// Replay returns no handle unless the complete verified prefix has exactly
    /// `expected_state_id`. An incomplete final entry is truncated only after
    /// that equality is established. Complete suffix deletion, an unanchored
    /// durable append, corruption, or another expected identity fails closed.
    pub fn open_verified(
        directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        entries: &[ActiveAgreementEntry],
        replay_limit: FixedValidatorFinalityReplayLimitV0,
        expected_state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<Self, FixedValidatorFinalityJournalErrorV0> {
        let branch = fixed_genesis(definition, context, entries)?;
        let expected_prefix =
            canonical_prefix(context, branch.fixed_agreement_set_id(), replay_limit)?;
        let mut branches = Vec::new();
        branches.try_reserve_exact(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::Allocation {
                entry: 0,
                bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
            }
        })?;
        branches.push(branch);

        let directory = directory.as_ref();
        let lock = open_shared_lock(directory)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join(JOURNAL_FILE_NAME))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Open { source })?;
        let core = FixedValidatorFinalityJournalCore::replay(
            file,
            context,
            replay_limit,
            expected_prefix,
            branches,
            expected_state_id,
        )?;
        Ok(Self { _lock: lock, core })
    }

    /// Returns the exact caller-selected consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.core.context
    }

    /// Returns the header-bound local replay-round ceiling.
    pub const fn replay_limit(&self) -> FixedValidatorFinalityReplayLimitV0 {
        self.core.replay_limit
    }

    /// Returns the current unambiguous journal-state identity.
    pub fn state_id(
        &self,
    ) -> Result<FixedValidatorFinalityJournalStateIdV0, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_healthy()?;
        Ok(self.core.state_id)
    }

    /// Returns the durable terminal-halt summary, if present.
    pub fn halt(
        &self,
    ) -> Result<Option<FixedValidatorFinalityHaltV0>, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_healthy()?;
        Ok(self.core.halt)
    }

    /// Returns the exact operable finalized head.
    pub fn head(&self) -> Result<&FixedConsensusBranchV0, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self
            .core
            .branches
            .last()
            .expect("every journal retains its virtual-genesis branch"))
    }

    /// Returns the exact selected artifact-chain identity while operable.
    pub fn artifact_chain_id(
        &self,
    ) -> Result<ArtifactChainId, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self.core.context.chain_id())
    }

    /// Returns the exact finalized artifact head while operable.
    pub fn artifact_head_block_id(
        &self,
    ) -> Result<ArtifactBlockId, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self
            .core
            .branches
            .last()
            .expect("every journal retains its virtual-genesis branch")
            .artifact_snapshot()
            .head_block_id())
    }

    /// Returns the authenticated finalized artifact-set root while operable.
    pub fn artifact_set_root(
        &self,
    ) -> Result<ArtifactSetRoot, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self
            .core
            .branches
            .last()
            .expect("every journal retains its virtual-genesis branch")
            .artifact_snapshot()
            .artifact_set_root())
    }

    /// Returns one owned finalized artifact snapshot by exact selected head.
    ///
    /// Virtual genesis and every replayed or durably committed finality step are
    /// retained. Unknown or non-selected addresses return `None`; terminal halt
    /// and poisoned handles deny the lookup before inspecting history.
    pub fn artifact_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self
            .core
            .snapshot_index
            .get(&block_id)
            .and_then(|index| self.core.branches.get(*index))
            .map(|branch| branch.artifact_snapshot().clone()))
    }

    /// Returns the retained selected parent required to verify one height.
    pub fn parent_for_height(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedConsensusBranchV0>, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        let Some(parent_index) = height.value().checked_sub(1) else {
            return Ok(None);
        };
        let Ok(parent_index) = usize::try_from(parent_index) else {
            return Ok(None);
        };
        Ok(self.core.branches.get(parent_index))
    }

    /// Returns one retained first finality proof by its positive height.
    pub fn finality_record(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedValidatorFinalityRecordV0>, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        let Some(index) = height.value().checked_sub(1) else {
            return Ok(None);
        };
        let Ok(index) = usize::try_from(index) else {
            return Ok(None);
        };
        Ok(self.core.records.get(index))
    }

    /// Returns the number of durably finalized values before any terminal halt.
    pub fn finalized_len(&self) -> Result<usize, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self.core.records.len())
    }

    /// Acknowledges and reconstructs one retained signer-height transition.
    ///
    /// The caller must first persist the journal's exact current state identity
    /// in a separately protected monotonic anchor. This method rechecks that
    /// asserted identity before reconstructing the retained first envelope and
    /// artifact payload against the selected parent. The returned capability
    /// immutably borrows this healthy journal until a key-owning vote-safety
    /// session consumes it, preventing an intervening commit or conflict halt.
    pub fn acknowledge_signer_height_transition_is_externally_durable(
        &self,
        height: ConsensusHeight,
        externally_durable_state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<FixedValidatorDurableFinalityTransitionV0<'_>, FixedValidatorFinalityJournalErrorV0>
    {
        self.core.ensure_operational()?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        let transition = self.core.reconstruct_selected_transition(height)?;
        Ok(FixedValidatorDurableFinalityTransitionV0 {
            _journal: self,
            transition,
        })
    }

    /// Consumes one sealed verified transition and classifies it against history.
    pub fn commit_verified(
        &mut self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityJournalErrorV0> {
        self.core.commit_verified(transition)
    }
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

struct FixedValidatorFinalityJournalCore<F> {
    file: F,
    context: ConsensusContextV0,
    replay_limit: FixedValidatorFinalityReplayLimitV0,
    branches: Vec<FixedConsensusBranchV0>,
    snapshot_index: HashMap<ArtifactBlockId, usize>,
    records: Vec<FixedValidatorFinalityRecordV0>,
    halt: Option<FixedValidatorFinalityHaltV0>,
    state_id: FixedValidatorFinalityJournalStateIdV0,
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
            committed_end: JOURNAL_PREFIX_BYTES as u64,
            poisoned: false,
        }
    }

    fn replay(
        mut file: F,
        context: ConsensusContextV0,
        replay_limit: FixedValidatorFinalityReplayLimitV0,
        expected_prefix: Vec<u8>,
        branches: Vec<FixedConsensusBranchV0>,
        expected_state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<Self, FixedValidatorFinalityJournalErrorV0> {
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Read { offset: 0, source })?;
        if file_len < JOURNAL_PREFIX_BYTES as u64 {
            return Err(FixedValidatorFinalityJournalErrorV0::InvalidHeader);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Read { offset: 0, source })?;
        let mut actual_prefix = Vec::new();
        actual_prefix
            .try_reserve_exact(JOURNAL_PREFIX_BYTES)
            .map_err(|_| FixedValidatorFinalityJournalErrorV0::Allocation {
                entry: 0,
                bytes: JOURNAL_PREFIX_BYTES,
            })?;
        actual_prefix.resize(JOURNAL_PREFIX_BYTES, 0);
        read_exact_at(&mut file, &mut actual_prefix, 0)?;
        if actual_prefix != expected_prefix {
            return Err(FixedValidatorFinalityJournalErrorV0::HeaderMismatch);
        }

        let state_id = genesis_state_id(&actual_prefix);
        let snapshot_index = genesis_snapshot_index(&branches)?;
        let mut core = Self::empty(
            file,
            context,
            replay_limit,
            branches,
            snapshot_index,
            state_id,
        );
        let mut entry_start = JOURNAL_PREFIX_BYTES as u64;
        let mut entry = 0_u64;
        let mut recovery_offset = None;

        while entry_start < file_len {
            let remaining = file_len - entry_start;
            if remaining < RECORD_LENGTH_BYTES {
                recovery_offset = Some(entry_start);
                break;
            }
            core.file
                .seek(SeekFrom::Start(entry_start))
                .map_err(|source| FixedValidatorFinalityJournalErrorV0::Read {
                    offset: entry_start,
                    source,
                })?;
            let mut body_length_bytes = [0_u8; 4];
            read_exact_at(&mut core.file, &mut body_length_bytes, entry_start)?;
            let body_length_u32 = u32::from_be_bytes(body_length_bytes);
            let body_length = usize::try_from(body_length_u32)
                .expect("every u32 record length fits the supported Rust targets");
            if !(MIN_RECORD_BODY_BYTES..=MAX_RECORD_BODY_BYTES).contains(&body_length) {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordLength {
                    entry,
                    offset: entry_start,
                    actual: body_length_u32,
                    minimum: u32::try_from(MIN_RECORD_BODY_BYTES)
                        .expect("the minimum record length fits u32"),
                    maximum: u32::try_from(MAX_RECORD_BODY_BYTES)
                        .expect("the maximum record length fits u32"),
                });
            }
            let entry_length = ENTRY_FIXED_BYTES
                .checked_add(u64::from(body_length_u32))
                .ok_or(FixedValidatorFinalityJournalErrorV0::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                })?;
            let entry_end = entry_start.checked_add(entry_length).ok_or(
                FixedValidatorFinalityJournalErrorV0::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                },
            )?;
            if file_len < entry_end {
                recovery_offset = Some(entry_start);
                break;
            }
            if core.halt.is_some() {
                return Err(FixedValidatorFinalityJournalErrorV0::RecordAfterHalt {
                    offset: entry_start,
                });
            }

            let mut body = Vec::new();
            body.try_reserve_exact(body_length).map_err(|_| {
                FixedValidatorFinalityJournalErrorV0::Allocation {
                    entry,
                    bytes: body_length,
                }
            })?;
            body.resize(body_length, 0);
            let body_offset = entry_start + RECORD_LENGTH_BYTES;
            read_exact_at(&mut core.file, &mut body, body_offset)?;
            let footer_offset = body_offset + u64::from(body_length_u32);
            let mut stored_state_id = [0_u8; FixedValidatorFinalityJournalStateIdV0::BYTE_LENGTH];
            read_exact_at(&mut core.file, &mut stored_state_id, footer_offset)?;
            let expected_entry_state_id = step_state_id(core.state_id, body_length_bytes, &body);
            let actual_entry_state_id =
                FixedValidatorFinalityJournalStateIdV0::from_bytes(stored_state_id);
            if actual_entry_state_id != expected_entry_state_id {
                return Err(
                    FixedValidatorFinalityJournalErrorV0::RecordStateIdMismatch {
                        entry,
                        offset: entry_start,
                        expected: expected_entry_state_id,
                        actual: actual_entry_state_id,
                    },
                );
            }

            core.replay_record(entry, entry_start, body, actual_entry_state_id)?;
            core.state_id = actual_entry_state_id;
            core.committed_end = entry_end;
            entry_start = entry_end;
            entry += 1;
        }

        if core.state_id != expected_state_id {
            return Err(
                FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch {
                    expected: expected_state_id,
                    actual: core.state_id,
                },
            );
        }

        if let Some(offset) = recovery_offset {
            core.file
                .set_len(offset)
                .and_then(|()| core.file.sync_all())
                .map_err(|source| FixedValidatorFinalityJournalErrorV0::Recovery {
                    offset,
                    source,
                })?;
        } else {
            core.file
                .sync_all()
                .map_err(|source| FixedValidatorFinalityJournalErrorV0::Stabilize { source })?;
        }
        Ok(core)
    }

    fn replay_record(
        &mut self,
        entry: u64,
        offset: u64,
        body: Vec<u8>,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<(), FixedValidatorFinalityJournalErrorV0> {
        let (tag, height, parent_index, transition) = {
            let parsed = parse_record(entry, offset, &body, self.replay_limit)?;
            let height = parsed.height;
            let height_index = height_index(height).map_err(|()| {
                FixedValidatorFinalityJournalErrorV0::HeightIndexOverflow { entry, height }
            })?;
            match parsed.tag {
                FINALIZE_RECORD if height_index != self.branches.len() => {
                    return Err(
                        FixedValidatorFinalityJournalErrorV0::NonconsecutiveFinality {
                            entry,
                            height,
                        },
                    );
                }
                CONFLICT_HALT_RECORD if height_index >= self.branches.len() => {
                    return Err(FixedValidatorFinalityJournalErrorV0::InvalidConflictHalt {
                        entry,
                        height,
                    });
                }
                FINALIZE_RECORD | CONFLICT_HALT_RECORD => {}
                _ => unreachable!("record tag is parsed before classification"),
            }
            let parent_index = height_index
                .checked_sub(1)
                .expect("strict value decoding rejects height zero");
            let parent = self.branches.get(parent_index).ok_or(
                FixedValidatorFinalityJournalErrorV0::InvalidSelectedParent { entry, height },
            )?;
            let mut round = parent
                .begin_round_zero()
                .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
            for _ in 0..parsed.round {
                round = round
                    .advance_round()
                    .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
            }
            let payload = clone_bytes(parsed.payload, entry)?;
            let transition = round
                .decode_and_verify(parsed.envelope, payload)
                .map_err(|source| FixedValidatorFinalityJournalErrorV0::Replay {
                    entry,
                    offset,
                    source: Box::new(source),
                })?
                .into_owned();
            (parsed.tag, height, parent_index, transition)
        };

        match tag {
            FINALIZE_RECORD => {
                self.branches.try_reserve(1).map_err(|_| {
                    FixedValidatorFinalityJournalErrorV0::Allocation {
                        entry,
                        bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
                    }
                })?;
                self.records.try_reserve(1).map_err(|_| {
                    FixedValidatorFinalityJournalErrorV0::Allocation {
                        entry,
                        bytes: std::mem::size_of::<FixedValidatorFinalityRecordV0>(),
                    }
                })?;
                self.snapshot_index.try_reserve(1).map_err(|_| {
                    FixedValidatorFinalityJournalErrorV0::SnapshotIndexAllocation {
                        entry,
                        retained_snapshots: self.snapshot_index.len(),
                    }
                })?;
                let record = record_from_transition(&transition, state_id, body);
                let branch = transition.into_branch();
                let artifact_head = branch.artifact_snapshot().head_block_id();
                self.records.push(record);
                let branch_index = self.branches.len();
                self.branches.push(branch);
                let replaced = self.snapshot_index.insert(artifact_head, branch_index);
                debug_assert!(replaced.is_none());
            }
            CONFLICT_HALT_RECORD => {
                let selected = self.records.get(parent_index).ok_or(
                    FixedValidatorFinalityJournalErrorV0::InvalidConflictHalt { entry, height },
                )?;
                if selected.value == transition.value() {
                    return Err(FixedValidatorFinalityJournalErrorV0::InvalidConflictHalt {
                        entry,
                        height,
                    });
                }
                self.halt = Some(halt_from_transition(
                    selected.value.ancestry_id(),
                    selected.envelope_id,
                    &transition,
                    state_id,
                ));
            }
            _ => unreachable!("record tag was checked before verification"),
        }
        Ok(())
    }

    fn commit_verified(
        &mut self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityJournalErrorV0> {
        self.ensure_operational()?;
        let position = transition.position();
        let round = position.round().value();
        if round > self.replay_limit.max_round() {
            return Err(FixedValidatorFinalityJournalErrorV0::RoundLimitExceeded {
                round,
                maximum: self.replay_limit.max_round(),
            });
        }
        let value = transition.value();
        let height = value.height();
        let height_index = height_index(height).map_err(|()| {
            FixedValidatorFinalityJournalErrorV0::CommitHeightIndexOverflow { height }
        })?;
        let parent_index = height_index
            .checked_sub(1)
            .expect("a sealed transition always has positive height");
        let Some(parent) = self.branches.get(parent_index) else {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        };
        if parent.coordinate() != transition.parent_coordinate() {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        }

        if height_index < self.branches.len() {
            let selected = self
                .records
                .get(parent_index)
                .expect("each retained positive-height branch has one finality record");
            if selected.value == value {
                return Ok(FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized {
                    height,
                    ancestry_id: value.ancestry_id(),
                    retained_envelope_id: selected.envelope_id,
                    state_id: self.state_id,
                });
            }
            let selected_ancestry = selected.value.ancestry_id();
            let selected_envelope_id = selected.envelope_id;
            let entry = u64::try_from(self.records.len()).expect("record count fits u64");
            let body = canonical_record_body(CONFLICT_HALT_RECORD, &transition, entry)?;
            let body_length = u32::try_from(body.len())
                .expect("bounded fixed-validator journal record length fits u32");
            let next_state_id = step_state_id(self.state_id, body_length.to_be_bytes(), &body);
            let halt = halt_from_transition(
                selected_ancestry,
                selected_envelope_id,
                &transition,
                next_state_id,
            );
            self.append_record(&body, next_state_id, transition.envelope_id(), entry)?;
            self.halt = Some(halt);
            self.state_id = next_state_id;
            return Ok(FixedValidatorFinalityCommitOutcomeV0::Halted(halt));
        }
        if height_index != self.branches.len() {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        }

        let entry = u64::try_from(self.records.len()).expect("record count fits u64");
        self.branches.try_reserve(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::Allocation {
                entry,
                bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
            }
        })?;
        self.records.try_reserve(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::Allocation {
                entry,
                bytes: std::mem::size_of::<FixedValidatorFinalityRecordV0>(),
            }
        })?;
        self.snapshot_index.try_reserve(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::SnapshotIndexAllocation {
                entry,
                retained_snapshots: self.snapshot_index.len(),
            }
        })?;
        let body = canonical_record_body(FINALIZE_RECORD, &transition, entry)?;
        let body_length = u32::try_from(body.len())
            .expect("bounded fixed-validator journal record length fits u32");
        let next_state_id = step_state_id(self.state_id, body_length.to_be_bytes(), &body);
        let record = record_from_transition(&transition, next_state_id, body);
        let ancestry_id = value.ancestry_id();
        let envelope_id = transition.envelope_id();
        self.append_record(
            record.canonical_record_body(),
            next_state_id,
            envelope_id,
            entry,
        )?;
        let branch = transition.into_branch();
        let artifact_head = branch.artifact_snapshot().head_block_id();
        self.records.push(record);
        let branch_index = self.branches.len();
        self.branches.push(branch);
        let replaced = self.snapshot_index.insert(artifact_head, branch_index);
        debug_assert!(replaced.is_none());
        self.state_id = next_state_id;
        Ok(FixedValidatorFinalityCommitOutcomeV0::Finalized {
            position,
            ancestry_id,
            envelope_id,
            state_id: next_state_id,
        })
    }

    fn append_record(
        &mut self,
        body: &[u8],
        next_state_id: FixedValidatorFinalityJournalStateIdV0,
        envelope_id: ConsensusEnvelopeId,
        entry: u64,
    ) -> Result<(), FixedValidatorFinalityJournalErrorV0> {
        let body_length = u32::try_from(body.len())
            .expect("bounded fixed-validator journal record length fits u32");
        let body_length_bytes = body_length.to_be_bytes();
        debug_assert_eq!(
            next_state_id,
            step_state_id(self.state_id, body_length_bytes, body)
        );
        let entry_length = ENTRY_FIXED_BYTES
            .checked_add(u64::from(body_length))
            .ok_or(FixedValidatorFinalityJournalErrorV0::EntryOffsetOverflow {
                entry,
                offset: self.committed_end,
            })?;
        let next_committed_end = self.committed_end.checked_add(entry_length).ok_or(
            FixedValidatorFinalityJournalErrorV0::EntryOffsetOverflow {
                entry,
                offset: self.committed_end,
            },
        )?;
        let commit_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(self.committed_end))?;
            self.file
                .append_write_all(AppendPhase::Body, &body_length_bytes)?;
            self.file.append_write_all(AppendPhase::Body, body)?;
            self.file.append_sync_all(AppendPhase::Body)?;
            self.file
                .append_write_all(AppendPhase::Commit, next_state_id.as_bytes())?;
            self.file.append_sync_all(AppendPhase::Commit)?;
            Ok(())
        })();
        if let Err(source) = commit_result {
            self.poisoned = true;
            return Err(FixedValidatorFinalityJournalErrorV0::Commit {
                envelope_id,
                proposed_state_id: next_state_id,
                source,
            });
        }
        self.committed_end = next_committed_end;
        Ok(())
    }

    fn reconstruct_selected_transition(
        &self,
        height: ConsensusHeight,
    ) -> Result<OwnedVerifiedFixedConsensusTransitionV0, FixedValidatorFinalityJournalErrorV0> {
        self.ensure_operational()?;
        let height_index = height_index(height).map_err(|()| {
            FixedValidatorFinalityJournalErrorV0::SignerHandoffHeightIndexOverflow { height }
        })?;
        let Some(record_index) = height_index.checked_sub(1) else {
            return Err(FixedValidatorFinalityJournalErrorV0::SignerHandoffUnavailable { height });
        };
        let Some(record) = self.records.get(record_index) else {
            return Err(FixedValidatorFinalityJournalErrorV0::SignerHandoffUnavailable { height });
        };
        let parent = self
            .branches
            .get(record_index)
            .expect("each retained finality record has its selected parent");
        let mut round = parent
            .begin_round_zero()
            .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
        for _ in 0..record.position.round().value() {
            round = round
                .advance_round()
                .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
        }
        debug_assert_eq!(record.position, round.position());
        let entry = u64::try_from(record_index).expect("retained record index fits u64");
        let payload = clone_bytes(record.canonical_artifact_bytes(), entry)?;
        round
            .decode_and_verify(record.canonical_envelope_bytes(), payload)
            .map_err(
                |source| FixedValidatorFinalityJournalErrorV0::SignerHandoffReplay {
                    height,
                    source: Box::new(source),
                },
            )
            .map(VerifiedFixedConsensusTransitionV0::into_owned)
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

struct ParsedRecord<'bytes> {
    tag: u8,
    round: u64,
    height: ConsensusHeight,
    envelope: &'bytes [u8],
    payload: &'bytes [u8],
}

fn parse_record<'bytes>(
    entry: u64,
    offset: u64,
    body: &'bytes [u8],
    replay_limit: FixedValidatorFinalityReplayLimitV0,
) -> Result<ParsedRecord<'bytes>, FixedValidatorFinalityJournalErrorV0> {
    let tag = body[0];
    if !matches!(tag, FINALIZE_RECORD | CONFLICT_HALT_RECORD) {
        return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordTag {
            entry,
            offset,
            actual: tag,
        });
    }
    let round = u64::from_be_bytes(
        body[1..9]
            .try_into()
            .expect("the bounded record header has an eight-byte round"),
    );
    if round > replay_limit.max_round() {
        return Err(
            FixedValidatorFinalityJournalErrorV0::ReplayRoundLimitExceeded {
                entry,
                round,
                maximum: replay_limit.max_round(),
            },
        );
    }
    let envelope_length = usize::try_from(u32::from_be_bytes(
        body[9..13]
            .try_into()
            .expect("the bounded record header has an envelope length"),
    ))
    .expect("every u32 envelope length fits the supported Rust targets");
    if !(VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH
        ..=VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH)
        .contains(&envelope_length)
    {
        return Err(
            FixedValidatorFinalityJournalErrorV0::InvalidEnvelopeLength {
                entry,
                actual: envelope_length,
            },
        );
    }
    let payload_length = usize::try_from(u32::from_be_bytes(
        body[13..17]
            .try_into()
            .expect("the bounded record header has a payload length"),
    ))
    .expect("every u32 payload length fits the supported Rust targets");
    if !(1..=ARTIFACT_PAYLOAD_MAX_BYTES).contains(&payload_length) {
        return Err(FixedValidatorFinalityJournalErrorV0::InvalidPayloadLength {
            entry,
            actual: payload_length,
        });
    }
    let expected_length = RECORD_HEADER_BYTES
        .checked_add(envelope_length)
        .and_then(|length| length.checked_add(payload_length))
        .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
    if expected_length != body.len() {
        return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry });
    }
    let envelope_end = RECORD_HEADER_BYTES + envelope_length;
    let envelope = &body[RECORD_HEADER_BYTES..envelope_end];
    let payload = &body[envelope_end..];
    let value = ConsensusValueV0::from_canonical_bytes(&envelope[..ConsensusValueV0::BYTE_LENGTH])
        .map_err(|source| FixedValidatorFinalityJournalErrorV0::Value { entry, source })?;
    Ok(ParsedRecord {
        tag,
        round,
        height: value.height(),
        envelope,
        payload,
    })
}

fn canonical_record_body(
    tag: u8,
    transition: &OwnedVerifiedFixedConsensusTransitionV0,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorFinalityJournalErrorV0> {
    let envelope = transition.canonical_envelope_bytes();
    let payload = transition.canonical_artifact_bytes();
    let body_length = RECORD_HEADER_BYTES
        .checked_add(envelope.len())
        .and_then(|length| length.checked_add(payload.len()))
        .expect("a sealed verified transition retains bounded canonical bytes");
    let mut body = Vec::new();
    body.try_reserve_exact(body_length).map_err(|_| {
        FixedValidatorFinalityJournalErrorV0::Allocation {
            entry,
            bytes: body_length,
        }
    })?;
    body.push(tag);
    body.extend_from_slice(&transition.position().round().value().to_be_bytes());
    body.extend_from_slice(
        &u32::try_from(envelope.len())
            .expect("bounded envelope length fits u32")
            .to_be_bytes(),
    );
    body.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("bounded artifact payload length fits u32")
            .to_be_bytes(),
    );
    body.extend_from_slice(envelope);
    body.extend_from_slice(payload);
    debug_assert_eq!(body.len(), body_length);
    Ok(body)
}

fn record_from_transition(
    transition: &OwnedVerifiedFixedConsensusTransitionV0,
    state_id: FixedValidatorFinalityJournalStateIdV0,
    canonical_record_body: Vec<u8>,
) -> FixedValidatorFinalityRecordV0 {
    let envelope_end = RECORD_HEADER_BYTES + transition.canonical_envelope_bytes().len();
    debug_assert_eq!(
        &canonical_record_body[RECORD_HEADER_BYTES..envelope_end],
        transition.canonical_envelope_bytes()
    );
    debug_assert_eq!(
        &canonical_record_body[envelope_end..],
        transition.canonical_artifact_bytes()
    );
    FixedValidatorFinalityRecordV0 {
        position: transition.position(),
        value: transition.value(),
        envelope_id: transition.envelope_id(),
        canonical_record_body,
        envelope_end,
        state_id,
    }
}

fn clone_bytes(bytes: &[u8], entry: u64) -> Result<Vec<u8>, FixedValidatorFinalityJournalErrorV0> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len()).map_err(|_| {
        FixedValidatorFinalityJournalErrorV0::Allocation {
            entry,
            bytes: bytes.len(),
        }
    })?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn halt_from_transition(
    selected_ancestry: ConsensusAncestryId,
    selected_envelope_id: ConsensusEnvelopeId,
    conflicting: &OwnedVerifiedFixedConsensusTransitionV0,
    state_id: FixedValidatorFinalityJournalStateIdV0,
) -> FixedValidatorFinalityHaltV0 {
    FixedValidatorFinalityHaltV0 {
        height: conflicting.value().height(),
        selected_ancestry,
        selected_envelope_id,
        conflicting_ancestry: conflicting.value().ancestry_id(),
        conflicting_envelope_id: conflicting.envelope_id(),
        state_id,
    }
}

fn fixed_genesis(
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    entries: &[ActiveAgreementEntry],
) -> Result<FixedConsensusBranchV0, FixedValidatorFinalityJournalErrorV0> {
    FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        entries,
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .map_err(FixedValidatorFinalityJournalErrorV0::Genesis)
}

fn canonical_prefix(
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    replay_limit: FixedValidatorFinalityReplayLimitV0,
) -> Result<Vec<u8>, FixedValidatorFinalityJournalErrorV0> {
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(JOURNAL_PREFIX_BYTES)
        .map_err(|_| FixedValidatorFinalityJournalErrorV0::Allocation {
            entry: 0,
            bytes: JOURNAL_PREFIX_BYTES,
        })?;
    prefix.extend_from_slice(JOURNAL_HEADER);
    prefix.extend_from_slice(context.chain_id().as_bytes());
    prefix.extend_from_slice(context.genesis_id().as_bytes());
    prefix.extend_from_slice(&context.protocol_version().value().to_be_bytes());
    prefix.extend_from_slice(fixed_set_id.as_bytes());
    prefix.extend_from_slice(&replay_limit.max_round().to_be_bytes());
    debug_assert_eq!(prefix.len(), JOURNAL_PREFIX_BYTES);
    Ok(prefix)
}

fn genesis_state_id(prefix: &[u8]) -> FixedValidatorFinalityJournalStateIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_STATE_DOMAIN);
    hasher.update(prefix);
    FixedValidatorFinalityJournalStateIdV0::from_bytes(hasher.finalize().into())
}

fn step_state_id(
    prior: FixedValidatorFinalityJournalStateIdV0,
    body_length: [u8; 4],
    body: &[u8],
) -> FixedValidatorFinalityJournalStateIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(STEP_STATE_DOMAIN);
    hasher.update(prior.as_bytes());
    hasher.update(body_length);
    hasher.update(body);
    FixedValidatorFinalityJournalStateIdV0::from_bytes(hasher.finalize().into())
}

fn height_index(height: ConsensusHeight) -> Result<usize, ()> {
    usize::try_from(height.value()).map_err(|_| ())
}

fn open_shared_lock(directory: &Path) -> Result<File, FixedValidatorFinalityJournalErrorV0> {
    open_exclusive_lock(directory, LOCK_FILE_NAME).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => {
            FixedValidatorFinalityJournalErrorV0::LockFile { source }
        }
        ExclusiveLockError::Locked => FixedValidatorFinalityJournalErrorV0::Locked,
        ExclusiveLockError::Lock(source) => FixedValidatorFinalityJournalErrorV0::Lock { source },
    })
}

fn read_exact_at<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), FixedValidatorFinalityJournalErrorV0> {
    file.read_exact(bytes)
        .map_err(|source| FixedValidatorFinalityJournalErrorV0::Read { offset, source })
}

/// A fail-closed fixed-validator finality-journal error.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorFinalityJournalErrorV0 {
    /// The shared lock file could not be opened.
    LockFile { source: io::Error },
    /// Another artifact-chain owner already holds the shared directory lock.
    Locked,
    /// The shared lock file could not be locked.
    Lock { source: io::Error },
    /// A new joint journal could not be created or initialized.
    Create { source: io::Error },
    /// An existing joint journal could not be opened.
    Open { source: io::Error },
    /// Existing journal bytes could not be read at the reported offset.
    Read { offset: u64, source: io::Error },
    /// The journal is shorter than the complete fixed-validator V0 prefix.
    InvalidHeader,
    /// The journal prefix differs from the exact caller-provisioned context.
    HeaderMismatch,
    /// A complete record declared an unsupported body length.
    InvalidRecordLength {
        entry: u64,
        offset: u64,
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    /// Record framing arithmetic exceeded the supported file-offset range.
    EntryOffsetOverflow { entry: u64, offset: u64 },
    /// A bounded replay or retained-evidence allocation failed.
    Allocation { entry: u64, bytes: usize },
    /// The selected artifact-snapshot lookup index could not grow.
    SnapshotIndexAllocation {
        entry: u64,
        retained_snapshots: usize,
    },
    /// A complete record used an unsupported semantic tag.
    InvalidRecordTag { entry: u64, offset: u64, actual: u8 },
    /// A complete record declared an unsupported envelope length.
    InvalidEnvelopeLength { entry: u64, actual: usize },
    /// A complete record declared an unsupported artifact-payload length.
    InvalidPayloadLength { entry: u64, actual: usize },
    /// Declared component lengths did not consume the exact record body.
    InvalidRecordFraming { entry: u64 },
    /// A record footer did not extend the exact preceding state identity.
    RecordStateIdMismatch {
        entry: u64,
        offset: u64,
        expected: FixedValidatorFinalityJournalStateIdV0,
        actual: FixedValidatorFinalityJournalStateIdV0,
    },
    /// A persisted record exceeded the header-bound local replay ceiling.
    ReplayRoundLimitExceeded {
        entry: u64,
        round: u64,
        maximum: u64,
    },
    /// The record envelope did not begin with one strict canonical value.
    Value {
        entry: u64,
        source: ConsensusValueError,
    },
    /// A replayed positive height could not index this platform.
    HeightIndexOverflow { entry: u64, height: ConsensusHeight },
    /// A finalized record did not extend the exact selected height sequence.
    NonconsecutiveFinality { entry: u64, height: ConsensusHeight },
    /// A terminal-halt record did not name a distinct already-selected sibling.
    InvalidConflictHalt { entry: u64, height: ConsensusHeight },
    /// A replayed record had no retained selected parent at its exact height.
    InvalidSelectedParent { entry: u64, height: ConsensusHeight },
    /// Strict envelope, evidence, or artifact replay rejected the record.
    Replay {
        entry: u64,
        offset: u64,
        source: Box<ConsensusEnvelopeVerifyError>,
    },
    /// A complete entry followed the journal's durable terminal halt.
    RecordAfterHalt { offset: u64 },
    /// The complete replayed state did not equal the separately trusted anchor.
    ExpectedStateIdMismatch {
        expected: FixedValidatorFinalityJournalStateIdV0,
        actual: FixedValidatorFinalityJournalStateIdV0,
    },
    /// An authenticated incomplete final entry could not be truncated and synced.
    Recovery { offset: u64, source: io::Error },
    /// A fully replayed unchanged journal image could not be synchronized.
    Stabilize { source: io::Error },
    /// A verified transition exceeded the header-bound local round ceiling.
    RoundLimitExceeded { round: u64, maximum: u64 },
    /// A verified transition was not derived from the retained selected parent.
    UnselectedParent { height: ConsensusHeight },
    /// A verified transition height could not index this platform.
    CommitHeightIndexOverflow { height: ConsensusHeight },
    /// A requested signer-handoff height could not index this platform.
    SignerHandoffHeightIndexOverflow { height: ConsensusHeight },
    /// No retained selected transition exists at the requested positive height.
    SignerHandoffUnavailable { height: ConsensusHeight },
    /// Strict reconstruction of a retained signer handoff unexpectedly failed.
    SignerHandoffReplay {
        height: ConsensusHeight,
        source: Box<ConsensusEnvelopeVerifyError>,
    },
    /// The asserted external finality anchor did not name the required state.
    ExternalFinalityAnchorMismatch {
        required: FixedValidatorFinalityJournalStateIdV0,
        acknowledged: FixedValidatorFinalityJournalStateIdV0,
    },
    /// The journal has durably halted and exposes no operational branch access.
    TerminalHalt { height: ConsensusHeight },
    /// An append failed after durability may have changed.
    Commit {
        envelope_id: ConsensusEnvelopeId,
        proposed_state_id: FixedValidatorFinalityJournalStateIdV0,
        source: io::Error,
    },
    /// A prior ambiguous append makes every live-handle observation unsafe.
    Poisoned,
    /// Fixed-validator virtual genesis could not be constructed.
    Genesis(FixedConsensusGenesisError),
    /// Sequential proposer-round reconstruction failed.
    Proposer(ProposerSelectionError),
}

impl fmt::Display for FixedValidatorFinalityJournalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => write!(formatter, "journal lock file failed: {source}"),
            Self::Locked => formatter.write_str(
                "artifact-chain state is already exclusively open in this directory",
            ),
            Self::Lock { source } => write!(formatter, "journal locking failed: {source}"),
            Self::Create { source } => write!(formatter, "joint journal creation failed: {source}"),
            Self::Open { source } => write!(formatter, "joint journal opening failed: {source}"),
            Self::Read { offset, source } => {
                write!(formatter, "joint journal read failed at byte {offset}: {source}")
            }
            Self::InvalidHeader => formatter.write_str("invalid fixed-validator journal header"),
            Self::HeaderMismatch => formatter.write_str(
                "fixed-validator journal header does not match the expected context, fixed set, and round limit",
            ),
            Self::InvalidRecordLength { entry, offset, actual, minimum, maximum } => write!(
                formatter,
                "finality record {entry} at byte {offset} has body length {actual}, expected {minimum}..={maximum}"
            ),
            Self::EntryOffsetOverflow { entry, offset } => write!(
                formatter,
                "finality record {entry} at byte {offset} exceeds the offset range"
            ),
            Self::Allocation { entry, bytes } => write!(
                formatter,
                "finality record {entry} could not allocate {bytes} bytes"
            ),
            Self::SnapshotIndexAllocation {
                entry,
                retained_snapshots,
            } => write!(
                formatter,
                "finality record {entry} could not grow the selected snapshot index beyond {retained_snapshots} entries"
            ),
            Self::InvalidRecordTag { entry, offset, actual } => write!(
                formatter,
                "finality record {entry} at byte {offset} has unsupported tag {actual}"
            ),
            Self::InvalidEnvelopeLength { entry, actual } => write!(
                formatter,
                "finality record {entry} has invalid envelope length {actual}"
            ),
            Self::InvalidPayloadLength { entry, actual } => write!(
                formatter,
                "finality record {entry} has invalid artifact payload length {actual}"
            ),
            Self::InvalidRecordFraming { entry } => write!(
                formatter,
                "finality record {entry} component lengths do not consume its body"
            ),
            Self::RecordStateIdMismatch { entry, offset, expected, actual } => write!(
                formatter,
                "finality record {entry} at byte {offset} commits state {actual:?}, expected {expected:?}"
            ),
            Self::ReplayRoundLimitExceeded { entry, round, maximum } => write!(
                formatter,
                "finality record {entry} round {round} exceeds replay ceiling {maximum}"
            ),
            Self::Value { entry, source } => write!(
                formatter,
                "finality record {entry} contains an invalid value: {source}"
            ),
            Self::HeightIndexOverflow { entry, height } => write!(
                formatter,
                "finality record {entry} height {} cannot index this platform",
                height.value()
            ),
            Self::NonconsecutiveFinality { entry, height } => write!(
                formatter,
                "finality record {entry} does not consecutively install height {}",
                height.value()
            ),
            Self::InvalidConflictHalt { entry, height } => write!(
                formatter,
                "conflict record {entry} does not name a distinct finalized sibling at height {}",
                height.value()
            ),
            Self::InvalidSelectedParent { entry, height } => write!(
                formatter,
                "finality record {entry} has no selected parent for height {}",
                height.value()
            ),
            Self::Replay { entry, offset, source } => write!(
                formatter,
                "finality record {entry} at byte {offset} failed strict replay: {source}"
            ),
            Self::RecordAfterHalt { offset } => write!(
                formatter,
                "journal contains bytes after its terminal halt at byte {offset}"
            ),
            Self::ExpectedStateIdMismatch { expected, actual } => write!(
                formatter,
                "journal state mismatch: expected {expected:?}, replayed {actual:?}"
            ),
            Self::Recovery { offset, source } => write!(
                formatter,
                "incomplete finality tail at byte {offset} could not be recovered: {source}"
            ),
            Self::Stabilize { source } => {
                write!(formatter, "replayed finality journal stabilization failed: {source}")
            }
            Self::RoundLimitExceeded { round, maximum } => write!(
                formatter,
                "verified round {round} exceeds local journal ceiling {maximum}"
            ),
            Self::UnselectedParent { height } => write!(
                formatter,
                "verified transition parent is not selected for height {}",
                height.value()
            ),
            Self::CommitHeightIndexOverflow { height } => write!(
                formatter,
                "verified transition height {} cannot index this platform",
                height.value()
            ),
            Self::SignerHandoffHeightIndexOverflow { height } => write!(
                formatter,
                "signer-handoff height {} cannot index this platform",
                height.value()
            ),
            Self::SignerHandoffUnavailable { height } => write!(
                formatter,
                "no retained selected transition is available at signer-handoff height {}",
                height.value()
            ),
            Self::SignerHandoffReplay { height, source } => write!(
                formatter,
                "retained signer-handoff transition at height {} failed strict reconstruction: {source}",
                height.value()
            ),
            Self::ExternalFinalityAnchorMismatch { required, acknowledged } => write!(
                formatter,
                "external finality acknowledgement names state {acknowledged:?}, expected current state {required:?}"
            ),
            Self::TerminalHalt { height } => write!(
                formatter,
                "fixed-validator finality is terminally halted at height {}",
                height.value()
            ),
            Self::Commit { envelope_id, proposed_state_id, source } => write!(
                formatter,
                "joint commit for envelope {envelope_id:?} and state {proposed_state_id:?} has unknown durability: {source}"
            ),
            Self::Poisoned => formatter.write_str(
                "joint journal is poisoned after an ambiguous commit; drop and reopen it with a trusted state ID",
            ),
            Self::Genesis(source) => write!(formatter, "fixed-validator genesis failed: {source}"),
            Self::Proposer(source) => write!(formatter, "proposer replay failed: {source}"),
        }
    }
}

impl Error for FixedValidatorFinalityJournalErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LockFile { source }
            | Self::Lock { source }
            | Self::Create { source }
            | Self::Open { source }
            | Self::Read { source, .. }
            | Self::Recovery { source, .. }
            | Self::Stabilize { source }
            | Self::Commit { source, .. } => Some(source),
            Self::Value { source, .. } => Some(source),
            Self::Replay { source, .. } => Some(source.as_ref()),
            Self::SignerHandoffReplay { source, .. } => Some(source.as_ref()),
            Self::Genesis(source) => Some(source),
            Self::Proposer(source) => Some(source),
            Self::Locked
            | Self::InvalidHeader
            | Self::HeaderMismatch
            | Self::InvalidRecordLength { .. }
            | Self::EntryOffsetOverflow { .. }
            | Self::Allocation { .. }
            | Self::SnapshotIndexAllocation { .. }
            | Self::InvalidRecordTag { .. }
            | Self::InvalidEnvelopeLength { .. }
            | Self::InvalidPayloadLength { .. }
            | Self::InvalidRecordFraming { .. }
            | Self::RecordStateIdMismatch { .. }
            | Self::ReplayRoundLimitExceeded { .. }
            | Self::HeightIndexOverflow { .. }
            | Self::NonconsecutiveFinality { .. }
            | Self::InvalidConflictHalt { .. }
            | Self::InvalidSelectedParent { .. }
            | Self::RecordAfterHalt { .. }
            | Self::ExpectedStateIdMismatch { .. }
            | Self::RoundLimitExceeded { .. }
            | Self::UnselectedParent { .. }
            | Self::CommitHeightIndexOverflow { .. }
            | Self::SignerHandoffHeightIndexOverflow { .. }
            | Self::SignerHandoffUnavailable { .. }
            | Self::ExternalFinalityAnchorMismatch { .. }
            | Self::TerminalHalt { .. }
            | Self::Poisoned => None,
        }
    }
}

#[cfg(test)]
mod tests;
