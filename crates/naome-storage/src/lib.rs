//! Crash-consistent local persistence for NAOME artifact-chain state and payloads.
//!
//! [`ArtifactChainJournal`] stores canonical [`ArtifactBlock`] values together
//! with the exact tagged canonical artifact payload committed by each block.
//! Opening a journal reconstructs the block head and complete selected artifact
//! DAG through
//! strict [`ArtifactChainState`] replay; persisted bytes never bypass block or
//! artifact validation. One exact-parent block may also be validated read-only;
//! durable application always revalidates before selection and commit.
//!
//! [`CanonicalArtifactPayloadStore`] separately archives exact tagged payload
//! bytes from accepted artifact records or from candidates strictly validated
//! against an exact selected or memory-only branch predecessor. Archiving does
//! not make bytes selected or reusable as checked records; consumers must
//! validate them again in their target artifact context.
//!
//! [`FixedValidatorFinalityJournalV0`] is the separate fixed-validator V0
//! durable authority for coupling one strictly verified consensus transition
//! to its exact artifact successor. It cleanly replaces the artifact-only
//! journal within one prerelease directory, retains the first exact finality
//! proof per selected height, and requires an externally retained exact
//! [`FixedValidatorFinalityJournalStateIdV0`] for operational reopen. A distinct
//! verified sibling produces a durable terminal halt rather than fork choice.
//! Its retained selected transition is also the only source of a signer-height
//! handoff: the caller must explicitly acknowledge the journal's exact current
//! state identity as externally durable before the key-owning vote session can
//! consume that child.
//!
//! [`FixedValidatorVoteSafetyJournalV0`] separately owns one local consensus
//! signing key and enforces a two-sync prepare-then-complete protocol for exact
//! kernel-sealed vote intents. The key is reachable only through the journal's
//! sole lock-state session, and signing requires an explicit caller assertion
//! that the exact prepared state ID is durable in a separate monotonic anchor.
//! Before session issuance, that anchor must also cover one exact persisted
//! initial signing-lineage binding. Each later finality-authorized child lineage
//! is appended and externally acknowledged before signer memory advances, so an
//! exact anchored reopen can authorize that child even if a crash preceded its
//! first vote. When no branch object survives the process restart, the vote
//! journal issues an opaque capability that lets finality history recover only
//! the exact matching branch, including after a later finality halt when no
//! explicit conflict stop has been applied; the vote journal then rechecks
//! handle provenance and derives the latest durable current-lineage state under
//! a caller-local round-work ceiling before issuing its sole session. The
//! finality journal can also issue opaque authority for an externally anchored
//! durable conflict; explicit consumption appends a separate terminal stop to
//! each matching local signer journal without selecting or rolling back either
//! sibling. Until that authority is routed, prior point-in-time signer handoffs
//! remain unchanged.
//! The per-key chained log prevents replacement and same-slot state divergence,
//! while an anchored reopen with an unresolved vote preparation remains
//! deliberately non-signable.
//!
//! [`ArtifactBlockCandidateStore`] retains chain-scoped structural blocks,
//! including siblings and blocks with unavailable parents, without validating
//! or selecting a candidate history. These stores define no reorganization,
//! fork choice, consensus, finality, networking, or economic state.
//!
//! The journal exporters publish [`CandidateBranchRecoveryBundleV0`] bytes for
//! one caller-selected, fully validated branch anchored either at the current
//! selected head or at virtual genesis. Decoded bundles remain untrusted until
//! import preflight validates their payloads and destination prefix. The
//! genesis-anchored exporter sources its selected prefix only from
//! replay-accepted journal records; the wire bytes carry no anchor-mode or
//! provenance authority and remain a caller-owned offline artifact.
//! A separate strict staging operation re-decodes one caller-owned bundle
//! against an exact caller-selected anchor, target, and sealed selected history,
//! preflights both durable stores, and retains only its unselected suffix in the
//! candidate store followed by the validated payload archive. Those stores
//! expose independent acknowledged prefixes rather than cross-store atomicity;
//! staging never mutates or selects history and retains no peer provenance.
//! One separate candidate-backed finality boundary accepts an exact
//! caller-selected retained block, its archived payload, a complete canonical
//! finality envelope, and a caller-local round-work ceiling. It revalidates the
//! complete envelope against the current operable fixed-validator journal head
//! and delegates only the resulting sealed transition to durable finality.
//! Source-store presence grants no selection authority and neither source is
//! mutated; each staged height requires its own independently certified call.

mod block_candidate_store;
mod candidate_branch_archive_import;
mod candidate_branch_reconstruction;
mod candidate_branch_recovery_bundle;
mod candidate_branch_recovery_staging;
#[cfg(test)]
mod fault_io;
mod fixed_validator_finality_journal;
mod fixed_validator_vote_safety_journal;
mod payload_store;

pub use block_candidate_store::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateInventory,
    ArtifactBlockCandidateInventoryError, ArtifactBlockCandidateInventoryLimits,
    ArtifactBlockCandidateInventoryLimitsError, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactBlockCandidateStoreLimits,
    ArtifactBlockCandidateStoreLimitsError,
};

pub use candidate_branch_archive_import::{
    CandidateBranchArchiveImportCommitError, CandidateBranchArchiveImportError,
    CandidateBranchArchiveImportLimits, CandidateBranchArchiveImportLimitsError,
    CandidateBranchArchiveImportOutcome, CandidateBranchArchiveImportPreflightError,
};

pub use candidate_branch_recovery_bundle::{
    CandidateBranchRecoveryBundleCommitError, CandidateBranchRecoveryBundleDecodeError,
    CandidateBranchRecoveryBundleExportError, CandidateBranchRecoveryBundleImportError,
    CandidateBranchRecoveryBundleImportOutcome, CandidateBranchRecoveryBundleLimits,
    CandidateBranchRecoveryBundleLimitsError, CandidateBranchRecoveryBundleV0,
};

pub use candidate_branch_recovery_staging::{
    CandidateBranchRecoveryBundleStageError, CandidateBranchRecoveryBundleStageFailure,
    CandidateBranchRecoveryBundleStageOutcome, stage_candidate_branch_recovery_bundle_v0,
};

pub use candidate_branch_reconstruction::{
    CandidateBranchReconstructionCursor, CandidateBranchReconstructionError,
    CandidateBranchReconstructionLimits, CandidateBranchReconstructionLimitsError,
    CandidateBranchReconstructionProgress, ReconstructedCandidateBranch,
    reconstruct_candidate_branch, start_candidate_branch_reconstruction,
};
pub use fixed_validator_finality_journal::{
    CandidateBackedFinalityCommitV0, CandidateBackedFinalityErrorV0,
    FixedValidatorDurableFinalityConflictV0, FixedValidatorDurableFinalityTransitionV0,
    FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityHaltV0,
    FixedValidatorFinalityJournalErrorV0, FixedValidatorFinalityJournalStateIdV0,
    FixedValidatorFinalityJournalV0, FixedValidatorFinalityRecordV0,
    FixedValidatorFinalityReplayLimitErrorV0, FixedValidatorFinalityReplayLimitV0,
    commit_candidate_backed_finality_v0,
};
pub use fixed_validator_vote_safety_journal::{
    FixedValidatorAnchoredSignerRecoveryV0, FixedValidatorDurablePrepareAcknowledgementV0,
    FixedValidatorFinalityConflictSignerStopOutcomeV0, FixedValidatorFinalityConflictSignerStopV0,
    FixedValidatorPendingVoteV0, FixedValidatorPreparedHeightAdvanceV0,
    FixedValidatorPreparedHigherRoundAdvanceV0, FixedValidatorPreparedVoteV0,
    FixedValidatorRecoveredSignerBranchV0, FixedValidatorRecoveredSigningSessionV0,
    FixedValidatorSignedVoteV0, FixedValidatorSignerRecoveryRoundLimitV0,
    FixedValidatorVoteCompletionMismatchV0, FixedValidatorVotePrepareOutcomeV0,
    FixedValidatorVoteSafetyHaltV0, FixedValidatorVoteSafetyJournalErrorV0,
    FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalV0,
    FixedValidatorVoteSafetyReplayLimitErrorV0, FixedValidatorVoteSafetyReplayLimitV0,
    FixedValidatorVoteSafetySigningSessionV0,
};

pub use payload_store::{
    ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits, ArtifactPayloadStoreLimitsError,
    CandidateBranchPayloadArchiveError, CandidateBranchPayloadArchiveOutcome,
    CandidatePayloadArchiveError, CanonicalArtifactPayload, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
};

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use naome_chain::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId,
    ArtifactBlockPrepareError, ArtifactChainBranchSnapshot, ArtifactChainDefinition,
    ArtifactChainId, ArtifactChainState, ArtifactSetProof, ArtifactSetRoot,
};
use naome_ledger::{AcceptedArtifactRecord, ArtifactState};
use naome_proof::{ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId};

mod selected_artifact_history_sealed {
    pub trait Sealed {}
}

/// Read-only access to one replay-verified selected artifact history.
///
/// Implementations are sealed to the storage-owned journals that can establish
/// selected history by strict replay. Callers can inspect an exact selected
/// position through this capability, but cannot implement it for candidate or
/// peer-supplied state and cannot use it to mutate selection.
pub trait SelectedArtifactHistory: selected_artifact_history_sealed::Sealed {
    /// Returns the immutable artifact-chain identity.
    ///
    /// This context remains readable after a handle becomes terminal so callers
    /// can reject cross-chain inputs before any selected-state health read. It
    /// conveys no selected position or finality authority.
    fn selected_chain_id(&self) -> ArtifactChainId;

    /// Returns the exact selected artifact head while the owner is operable.
    fn selected_head_block_id(&self) -> Result<ArtifactBlockId, SelectedArtifactHistoryError>;

    /// Returns the authenticated selected artifact-set root while operable.
    fn selected_artifact_set_root(&self) -> Result<ArtifactSetRoot, SelectedArtifactHistoryError>;

    /// Returns one owned replay-verified selected snapshot while operable.
    fn selected_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, SelectedArtifactHistoryError>;
}

/// Failure to inspect storage-owned selected artifact history.
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectedArtifactHistoryError {
    /// The artifact-only selected journal denied the read.
    ArtifactChainJournal {
        source: Box<ArtifactChainJournalError>,
    },
    /// The joint fixed-validator finality journal denied the read.
    FixedValidatorFinalityJournal {
        source: Box<FixedValidatorFinalityJournalErrorV0>,
    },
}

impl SelectedArtifactHistoryError {
    fn artifact_chain(source: ArtifactChainJournalError) -> Self {
        Self::ArtifactChainJournal {
            source: Box::new(source),
        }
    }

    fn fixed_validator_finality(source: FixedValidatorFinalityJournalErrorV0) -> Self {
        Self::FixedValidatorFinalityJournal {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for SelectedArtifactHistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactChainJournal { source } => {
                write!(
                    formatter,
                    "selected artifact-chain journal read failed: {source}"
                )
            }
            Self::FixedValidatorFinalityJournal { source } => write!(
                formatter,
                "selected fixed-validator finality journal read failed: {source}"
            ),
        }
    }
}

impl Error for SelectedArtifactHistoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ArtifactChainJournal { source } => Some(source.as_ref()),
            Self::FixedValidatorFinalityJournal { source } => Some(source.as_ref()),
        }
    }
}

const LOCK_FILE_NAME: &str = "artifact-chain.lock";
const JOURNAL_FILE_NAME: &str = "artifact-chain.journal";
const JOURNAL_HEADER: &[u8] = b"naome:artifact-chain-journal:v1\0";
const CHAIN_ID_BYTES: usize = ArtifactChainId::BYTE_LENGTH;
const BLOCK_ID_BYTES: u64 = ArtifactBlockId::BYTE_LENGTH as u64;
const ENTRY_FIXED_BYTES: u64 = 4 + BLOCK_ID_BYTES;
const JOURNAL_PREFIX_BYTES: usize = JOURNAL_HEADER.len() + CHAIN_ID_BYTES;
const ENTRY_MIN_BODY_BYTES: u32 = (ARTIFACT_BLOCK_BYTES + 1) as u32;
const ENTRY_MAX_BODY_BYTES: u32 = (ARTIFACT_BLOCK_BYTES + ARTIFACT_PAYLOAD_MAX_BYTES) as u32;

/// An exclusively opened, crash-consistent journal for one selected artifact chain.
///
/// The handle privately owns both the exact block head and selected artifact DAG.
/// A commit I/O error makes the handle unusable because memory may then be ahead
/// of durable storage. Dropping and reopening is the only recovery path.
#[must_use]
pub struct ArtifactChainJournal {
    _lock: File,
    core: JournalCore<File>,
}

impl ArtifactChainJournal {
    /// Creates and exclusively opens a new empty journal for `definition`.
    ///
    /// Creation never replaces an existing journal. The prefix containing the
    /// exact chain context is synchronized before this function succeeds.
    /// Portable parent-directory-entry durability remains the caller's
    /// provisioning responsibility.
    pub fn create(
        directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
    ) -> Result<Self, ArtifactChainJournalError> {
        let directory = directory.as_ref();
        let lock = open_and_lock(directory)?;
        let journal_path = directory.join(JOURNAL_FILE_NAME);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(journal_path)
            .map_err(|source| ArtifactChainJournalError::Create { source })?;

        let chain = ArtifactChainState::new(definition);
        file.write_all(JOURNAL_HEADER)
            .and_then(|()| file.write_all(chain.chain_id().as_bytes()))
            .and_then(|()| file.sync_all())
            .map_err(|source| ArtifactChainJournalError::Create { source })?;

        Ok(Self {
            _lock: lock,
            core: JournalCore::empty(file, chain),
        })
    }

    /// Exclusively opens and strictly replays an existing journal.
    ///
    /// One incomplete final entry is recovered to the preceding committed
    /// boundary. A complete corrupt or invalid entry fails closed.
    pub fn open_recovering_unverified(
        directory: impl AsRef<Path>,
        expected_definition: ArtifactChainDefinition,
    ) -> Result<Self, ArtifactChainJournalError> {
        Self::open_inner(directory.as_ref(), expected_definition, None)
    }

    /// Opens, strictly replays, and verifies the complete block ancestry.
    ///
    /// `expected_head` must come from a separately trusted source. If an
    /// incomplete tail is visible, it is truncated only after the replayed
    /// committed prefix matches this expected head.
    pub fn open_verified(
        directory: impl AsRef<Path>,
        expected_definition: ArtifactChainDefinition,
        expected_head: ArtifactBlockId,
    ) -> Result<Self, ArtifactChainJournalError> {
        Self::open_inner(directory.as_ref(), expected_definition, Some(expected_head))
    }

    fn open_inner(
        directory: &Path,
        expected_definition: ArtifactChainDefinition,
        expected_head: Option<ArtifactBlockId>,
    ) -> Result<Self, ArtifactChainJournalError> {
        let lock = open_and_lock(directory)?;
        let journal_path = directory.join(JOURNAL_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path)
            .map_err(|source| ArtifactChainJournalError::Open { source })?;
        let core = JournalCore::replay(file, expected_definition, expected_head)?;
        Ok(Self { _lock: lock, core })
    }

    /// Returns the immutable chain context synchronized at creation or
    /// verified from the persisted prefix during open.
    pub const fn chain_id(&self) -> ArtifactChainId {
        self.core.chain.chain_id()
    }

    /// Prepares one exact-parent block without changing memory or disk.
    pub fn prepare_block(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactBlock, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        self.core
            .chain
            .prepare_block(artifact_id)
            .map_err(|source| ArtifactChainJournalError::Preparation { source })
    }

    /// Atomically validates, selects, and durably commits one exact-parent block.
    ///
    /// Ordinary validation errors perform no file I/O and leave the handle
    /// healthy. An ambiguous I/O failure after in-memory admission poisons it.
    pub fn apply_block(
        &mut self,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<&AcceptedArtifactRecord, ArtifactChainJournalError> {
        self.core.apply_block(block, canonical_artifact_bytes)
    }

    /// Validates one exact-parent block without changing memory or disk.
    ///
    /// Success is relative only to the journal's current selected state. It
    /// reserves no block, confers no selection authority, and every later
    /// application fully revalidates against the then-current state.
    pub fn validate_block(
        &self,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<(), ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        self.core
            .chain
            .validate_block(block, canonical_artifact_bytes)
            .map_err(|source| ArtifactChainJournalError::BlockAdmission { source })
    }

    /// Returns the exact committed head, or the virtual genesis anchor if empty.
    pub fn head_block_id(&self) -> Result<ArtifactBlockId, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.head_block_id())
    }

    /// Returns one committed and replay-checked block by its exact identity.
    pub fn block(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<&ArtifactBlock>, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.blocks.get(&block_id))
    }

    /// Returns an owned immutable branch snapshot at one selected artifact fork point.
    ///
    /// The virtual genesis anchor and every strictly selected block are available.
    /// An unknown or non-selected address returns `None`. Journal health is checked
    /// before the address lookup. Candidate snapshots derived from the result are
    /// memory-only and are never added to this selected snapshot index.
    pub fn branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.blocks.snapshot(block_id))
    }

    /// Returns one committed and replay-checked artifact record.
    pub fn artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<&AcceptedArtifactRecord>, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_dag().artifact(artifact_id))
    }

    /// Returns immutable access to the committed checked-artifact resolver state.
    ///
    /// The borrow contains only artifacts selected through strict block
    /// application or replay. A poisoned handle fails closed.
    pub fn artifact_state(&self) -> Result<&ArtifactState, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_state())
    }

    /// Returns the number of committed artifact records.
    pub fn len(&self) -> Result<usize, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_dag().len())
    }

    /// Returns whether no artifact records have been committed.
    pub fn is_empty(&self) -> Result<bool, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_dag().is_empty())
    }

    /// Returns the authenticated root of the committed artifact set.
    pub fn artifact_set_root(&self) -> Result<ArtifactSetRoot, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self.core.chain.artifact_dag().artifact_set_root())
    }

    /// Returns one artifact-set membership or non-membership witness.
    pub fn artifact_set_proof(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactSetProof, ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        Ok(self
            .core
            .chain
            .artifact_dag()
            .artifact_set_proof(artifact_id))
    }

    fn reserve_selected_block_entries(
        &mut self,
        additional: usize,
    ) -> Result<(), ArtifactChainJournalError> {
        self.core.ensure_healthy()?;
        self.core.blocks.reserve_entries(additional)
    }
}

impl selected_artifact_history_sealed::Sealed for ArtifactChainJournal {}

impl SelectedArtifactHistory for ArtifactChainJournal {
    fn selected_chain_id(&self) -> ArtifactChainId {
        self.chain_id()
    }

    fn selected_head_block_id(&self) -> Result<ArtifactBlockId, SelectedArtifactHistoryError> {
        self.head_block_id()
            .map_err(SelectedArtifactHistoryError::artifact_chain)
    }

    fn selected_artifact_set_root(&self) -> Result<ArtifactSetRoot, SelectedArtifactHistoryError> {
        self.artifact_set_root()
            .map_err(SelectedArtifactHistoryError::artifact_chain)
    }

    fn selected_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, SelectedArtifactHistoryError> {
        self.branch_snapshot_at(block_id)
            .map_err(SelectedArtifactHistoryError::artifact_chain)
    }
}

fn open_and_lock(directory: &Path) -> Result<File, ArtifactChainJournalError> {
    open_exclusive_lock(directory, LOCK_FILE_NAME).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => ArtifactChainJournalError::LockFile { source },
        ExclusiveLockError::Locked => ArtifactChainJournalError::Locked,
        ExclusiveLockError::Lock(source) => ArtifactChainJournalError::Lock { source },
    })
}

enum ExclusiveLockError {
    LockFile(io::Error),
    Locked,
    Lock(io::Error),
}

fn open_exclusive_lock(directory: &Path, file_name: &str) -> Result<File, ExclusiveLockError> {
    let lock_path = directory.join(file_name);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(ExclusiveLockError::LockFile)?;

    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(ExclusiveLockError::Locked),
        Err(TryLockError::Error(source)) => Err(ExclusiveLockError::Lock(source)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppendPhase {
    Body,
    Commit,
}

trait StoreIo: Read + Write + Seek {
    fn set_len(&mut self, size: u64) -> io::Result<()>;
    fn sync_all(&mut self) -> io::Result<()>;

    fn append_write_all(&mut self, _phase: AppendPhase, bytes: &[u8]) -> io::Result<()> {
        self.write_all(bytes)
    }

    fn append_sync_all(&mut self, _phase: AppendPhase) -> io::Result<()> {
        self.sync_all()
    }
}

impl StoreIo for File {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        File::set_len(self, size)
    }

    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

struct JournalCore<F> {
    file: F,
    chain: ArtifactChainState,
    blocks: SelectedBlockIndex,
    committed_end: u64,
    poisoned: bool,
}

struct SelectedBlockEntry {
    block: ArtifactBlock,
    snapshot: ArtifactChainBranchSnapshot,
}

struct SelectedBlockIndex {
    genesis: ArtifactChainBranchSnapshot,
    blocks: HashMap<ArtifactBlockId, SelectedBlockEntry>,
}

impl SelectedBlockIndex {
    fn new(chain: &ArtifactChainState) -> Self {
        Self {
            genesis: chain.branch_snapshot(),
            blocks: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn get(&self, block_id: &ArtifactBlockId) -> Option<&ArtifactBlock> {
        self.blocks.get(block_id).map(|entry| &entry.block)
    }

    fn snapshot(&self, block_id: ArtifactBlockId) -> Option<ArtifactChainBranchSnapshot> {
        if block_id == self.genesis.head_block_id() {
            Some(self.genesis.clone())
        } else {
            self.blocks
                .get(&block_id)
                .map(|entry| entry.snapshot.clone())
        }
    }

    fn artifact_set_root(&self, block_id: ArtifactBlockId) -> Option<ArtifactSetRoot> {
        if block_id == self.genesis.head_block_id() {
            Some(self.genesis.artifact_set_root())
        } else {
            self.blocks
                .get(&block_id)
                .map(|entry| entry.snapshot.artifact_set_root())
        }
    }

    fn reserve_entry(&mut self, entry: u64) -> Result<(), ArtifactChainJournalError> {
        self.blocks
            .try_reserve(1)
            .map_err(|_| ArtifactChainJournalError::BlockIndexAllocation { entry })
    }

    fn reserve_entries(&mut self, additional: usize) -> Result<(), ArtifactChainJournalError> {
        let entry = u64::try_from(self.blocks.len()).expect("block index length fits u64");
        self.blocks
            .try_reserve(additional)
            .map_err(|_| ArtifactChainJournalError::BlockIndexAllocation { entry })
    }

    fn insert(
        &mut self,
        block_id: ArtifactBlockId,
        block: ArtifactBlock,
        snapshot: ArtifactChainBranchSnapshot,
    ) {
        let replaced = self
            .blocks
            .insert(block_id, SelectedBlockEntry { block, snapshot });
        debug_assert!(replaced.is_none());
    }
}

impl<F: StoreIo> JournalCore<F> {
    fn empty(file: F, chain: ArtifactChainState) -> Self {
        let blocks = SelectedBlockIndex::new(&chain);
        Self {
            file,
            chain,
            blocks,
            committed_end: JOURNAL_PREFIX_BYTES as u64,
            poisoned: false,
        }
    }

    fn replay(
        mut file: F,
        expected_definition: ArtifactChainDefinition,
        expected_head: Option<ArtifactBlockId>,
    ) -> Result<Self, ArtifactChainJournalError> {
        let chain = ArtifactChainState::new(expected_definition);
        let expected_chain_id = chain.chain_id();
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| ArtifactChainJournalError::Read { offset: 0, source })?;
        if file_len < JOURNAL_PREFIX_BYTES as u64 {
            return Err(ArtifactChainJournalError::InvalidHeader);
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|source| ArtifactChainJournalError::Read { offset: 0, source })?;
        let mut header = [0_u8; JOURNAL_HEADER.len()];
        file.read_exact(&mut header)
            .map_err(|source| ArtifactChainJournalError::Read { offset: 0, source })?;
        if header != JOURNAL_HEADER {
            return Err(ArtifactChainJournalError::InvalidHeader);
        }

        let mut stored_chain_id = [0_u8; CHAIN_ID_BYTES];
        file.read_exact(&mut stored_chain_id).map_err(|source| {
            ArtifactChainJournalError::Read {
                offset: JOURNAL_HEADER.len() as u64,
                source,
            }
        })?;
        let actual_chain_id = ArtifactChainId::from_bytes(stored_chain_id);
        if actual_chain_id != expected_chain_id {
            return Err(ArtifactChainJournalError::ChainIdMismatch {
                expected: expected_chain_id,
                actual: actual_chain_id,
            });
        }

        let mut blocks = SelectedBlockIndex::new(&chain);
        let mut chain = chain;
        let mut entry_start = JOURNAL_PREFIX_BYTES as u64;
        let mut entry = 0_u64;

        while entry_start < file_len {
            let remaining = file_len - entry_start;
            if remaining < 4 {
                return Self::finish_replay(
                    file,
                    chain,
                    blocks,
                    entry_start,
                    expected_head,
                    Some(entry_start),
                );
            }

            let mut body_length_bytes = [0_u8; 4];
            file.read_exact(&mut body_length_bytes).map_err(|source| {
                ArtifactChainJournalError::Read {
                    offset: entry_start,
                    source,
                }
            })?;
            let body_length = u32::from_be_bytes(body_length_bytes);
            if !(ENTRY_MIN_BODY_BYTES..=ENTRY_MAX_BODY_BYTES).contains(&body_length) {
                return Err(ArtifactChainJournalError::InvalidEntryLength {
                    entry,
                    offset: entry_start,
                    actual: body_length,
                    minimum: ENTRY_MIN_BODY_BYTES,
                    maximum: ENTRY_MAX_BODY_BYTES,
                });
            }

            let entry_length = ENTRY_FIXED_BYTES + u64::from(body_length);
            let entry_end = entry_start.checked_add(entry_length).ok_or(
                ArtifactChainJournalError::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                },
            )?;
            if file_len < entry_end {
                return Self::finish_replay(
                    file,
                    chain,
                    blocks,
                    entry_start,
                    expected_head,
                    Some(entry_start),
                );
            }

            let block_offset = entry_start + 4;
            let mut block_bytes = [0_u8; ARTIFACT_BLOCK_BYTES];
            read_field(&mut file, &mut block_bytes, block_offset)?;
            let block = ArtifactBlock::from_canonical_bytes(&block_bytes)
                .expect("every fixed-length artifact block byte string is structurally valid");
            let payload_offset = block_offset + ARTIFACT_BLOCK_BYTES as u64;
            let payload_length = body_length as usize - ARTIFACT_BLOCK_BYTES;
            debug_assert!((1..=ARTIFACT_PAYLOAD_MAX_BYTES).contains(&payload_length));
            let mut payload = Vec::new();
            payload.try_reserve_exact(payload_length).map_err(|_| {
                ArtifactChainJournalError::Allocation {
                    entry,
                    bytes: payload_length,
                }
            })?;
            payload.resize(payload_length, 0);
            read_field(&mut file, &mut payload, payload_offset)?;
            let mut stored_block_id = [0_u8; ArtifactBlockId::BYTE_LENGTH];
            file.read_exact(&mut stored_block_id).map_err(|source| {
                ArtifactChainJournalError::Read {
                    offset: entry_end - BLOCK_ID_BYTES,
                    source,
                }
            })?;
            let expected_block_id = block.id();
            let actual_block_id = ArtifactBlockId::from_bytes(stored_block_id);
            if actual_block_id != expected_block_id {
                return Err(ArtifactChainJournalError::BlockIdMismatch {
                    entry,
                    offset: entry_start,
                    expected: expected_block_id,
                    actual: actual_block_id,
                });
            }

            chain.apply_block(&block, payload).map_err(|source| {
                ArtifactChainJournalError::Replay {
                    entry,
                    offset: entry_start,
                    source: Box::new(source),
                }
            })?;
            blocks.reserve_entry(entry)?;
            let snapshot = chain.branch_snapshot();
            blocks.insert(expected_block_id, block, snapshot);

            entry_start = entry_end;
            entry += 1;
        }

        Self::finish_replay(file, chain, blocks, entry_start, expected_head, None)
    }

    fn finish_replay(
        mut file: F,
        chain: ArtifactChainState,
        blocks: SelectedBlockIndex,
        committed_end: u64,
        expected_head: Option<ArtifactBlockId>,
        recovery_offset: Option<u64>,
    ) -> Result<Self, ArtifactChainJournalError> {
        if let Some(expected) = expected_head {
            let actual = chain.head_block_id();
            if actual != expected {
                return Err(ArtifactChainJournalError::HeadBlockIdMismatch { expected, actual });
            }
        }

        if let Some(offset) = recovery_offset {
            recover_tail(&mut file, offset)?;
        } else {
            file.sync_all()
                .map_err(|source| ArtifactChainJournalError::Stabilize { source })?;
        }

        Ok(Self {
            file,
            chain,
            blocks,
            committed_end,
            poisoned: false,
        })
    }

    fn apply_block(
        &mut self,
        block: &ArtifactBlock,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<&AcceptedArtifactRecord, ArtifactChainJournalError> {
        self.ensure_healthy()?;
        let expected_parent = self.chain.head_block_id();
        let actual_parent = block.parent_block_id();
        if actual_parent != expected_parent {
            return Err(ArtifactChainJournalError::BlockAdmission {
                source: ArtifactBlockApplyError::ParentBlockIdMismatch {
                    expected: expected_parent,
                    actual: actual_parent,
                },
            });
        }
        let block_bytes = block.to_canonical_bytes();
        let indexed_block = *block;
        let entry = u64::try_from(self.blocks.len()).expect("block index length fits u64");
        self.blocks.reserve_entry(entry)?;
        self.chain
            .apply_block(block, canonical_artifact_bytes)
            .map_err(|source| ArtifactChainJournalError::BlockAdmission { source })?;
        let block_id = self.chain.head_block_id();
        let snapshot = self.chain.branch_snapshot();
        self.commit_entry(block_id, &block_bytes, block.artifact_id())?;
        self.blocks.insert(block_id, indexed_block, snapshot);
        Ok(self
            .chain
            .artifact_dag()
            .artifact(block.artifact_id())
            .expect("the committed block artifact remains retained"))
    }

    fn commit_entry(
        &mut self,
        block_id: ArtifactBlockId,
        block_bytes: &[u8; ARTIFACT_BLOCK_BYTES],
        artifact_id: ArtifactId,
    ) -> Result<(), ArtifactChainJournalError> {
        let payload = self
            .chain
            .artifact_dag()
            .artifact(artifact_id)
            .expect("the committed block artifact is retained")
            .canonical_artifact_bytes();
        let body_length = block_bytes
            .len()
            .checked_add(payload.len())
            .expect("bounded artifact-chain entry length fits usize");
        let body_length = u32::try_from(body_length)
            .expect("bounded artifact-chain entry length fits the u32 framing");
        debug_assert!((ENTRY_MIN_BODY_BYTES..=ENTRY_MAX_BODY_BYTES).contains(&body_length));
        let body_length_bytes = body_length.to_be_bytes();
        let commit_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(self.committed_end))?;
            self.file
                .append_write_all(AppendPhase::Body, &body_length_bytes)?;
            self.file.append_write_all(AppendPhase::Body, block_bytes)?;
            self.file.append_write_all(AppendPhase::Body, payload)?;
            self.file.append_sync_all(AppendPhase::Body)?;
            self.file
                .append_write_all(AppendPhase::Commit, block_id.as_bytes())?;
            self.file.append_sync_all(AppendPhase::Commit)?;
            Ok(())
        })();

        match commit_result {
            Ok(()) => {}
            Err(source) => {
                self.poisoned = true;
                return Err(ArtifactChainJournalError::Commit { block_id, source });
            }
        }

        self.committed_end = self
            .committed_end
            .checked_add(ENTRY_FIXED_BYTES + u64::from(body_length))
            .expect("artifact-chain journal offsets fit u64");
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), ArtifactChainJournalError> {
        if self.poisoned {
            Err(ArtifactChainJournalError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn recover_tail<F: StoreIo>(file: &mut F, offset: u64) -> Result<(), ArtifactChainJournalError> {
    file.set_len(offset)
        .and_then(|()| file.sync_all())
        .map_err(|source| ArtifactChainJournalError::Recovery { offset, source })
}

fn read_field<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), ArtifactChainJournalError> {
    file.read_exact(bytes)
        .map_err(|source| ArtifactChainJournalError::Read { offset, source })?;
    Ok(())
}

/// A fail-closed artifact-chain journal error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactChainJournalError {
    /// The sidecar lock file could not be opened.
    LockFile { source: io::Error },
    /// Another process or handle already owns the journal lock.
    Locked,
    /// The operating-system file lock could not be acquired.
    Lock { source: io::Error },
    /// A new journal file could not be created or initialized.
    Create { source: io::Error },
    /// An existing journal file could not be opened.
    Open { source: io::Error },
    /// Existing journal bytes could not be read.
    Read { offset: u64, source: io::Error },
    /// The journal header or chain identifier is incomplete or unsupported.
    InvalidHeader,
    /// The file is bound to a different artifact-chain context.
    ChainIdMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// A complete entry declares an impossible body length.
    InvalidEntryLength {
        entry: u64,
        offset: u64,
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    /// An entry boundary cannot be represented safely.
    EntryOffsetOverflow { entry: u64, offset: u64 },
    /// Allocating one bounded artifact payload failed.
    Allocation { entry: u64, bytes: usize },
    /// Reserving the selected-block index for one journal entry failed.
    BlockIndexAllocation { entry: u64 },
    /// The commit footer does not repeat the decoded canonical block identity.
    BlockIdMismatch {
        entry: u64,
        offset: u64,
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// Strict block replay rejected one complete committed entry.
    Replay {
        entry: u64,
        offset: u64,
        source: Box<ArtifactBlockApplyError>,
    },
    /// An incomplete final entry could not be removed durably.
    Recovery { offset: u64, source: io::Error },
    /// A fully replayed visible journal image could not be stabilized.
    Stabilize { source: io::Error },
    /// Strict replay produced a different block ancestry than expected.
    HeadBlockIdMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// Read-only block preparation rejected its artifact identity.
    Preparation { source: ArtifactBlockPrepareError },
    /// The supplied block failed before journal I/O.
    BlockAdmission { source: ArtifactBlockApplyError },
    /// Commit durability is unknown and the handle is now poisoned.
    Commit {
        block_id: ArtifactBlockId,
        source: io::Error,
    },
    /// Memory may be ahead of durable storage after an ambiguous commit.
    Poisoned,
}

impl fmt::Display for ArtifactChainJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => write!(formatter, "journal lock file failed: {source}"),
            Self::Locked => {
                formatter.write_str("artifact chain journal is already exclusively open")
            }
            Self::Lock { source } => write!(formatter, "journal locking failed: {source}"),
            Self::Create { source } => write!(formatter, "journal creation failed: {source}"),
            Self::Open { source } => write!(formatter, "journal opening failed: {source}"),
            Self::Read { offset, source } => {
                write!(formatter, "journal read failed at byte {offset}: {source}")
            }
            Self::InvalidHeader => formatter.write_str("invalid artifact chain journal header"),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "artifact chain identifier mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::InvalidEntryLength {
                entry,
                offset,
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} has body length {actual}, expected {minimum}..={maximum}"
            ),
            Self::EntryOffsetOverflow { entry, offset } => write!(
                formatter,
                "journal entry {entry} at byte {offset} exceeds the offset range"
            ),
            Self::Allocation { entry, bytes } => write!(
                formatter,
                "journal entry {entry} artifact payload could not allocate {bytes} bytes"
            ),
            Self::BlockIndexAllocation { entry } => {
                write!(
                    formatter,
                    "journal entry {entry} could not reserve its block index slot"
                )
            }
            Self::BlockIdMismatch {
                entry,
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} commits block {actual:?}, expected decoded block {expected:?}"
            ),
            Self::Replay {
                entry,
                offset,
                source,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} failed strict block replay: {source}"
            ),
            Self::Recovery { offset, source } => write!(
                formatter,
                "incomplete journal tail at byte {offset} could not be recovered: {source}"
            ),
            Self::Stabilize { source } => {
                write!(formatter, "replayed journal stabilization failed: {source}")
            }
            Self::HeadBlockIdMismatch { expected, actual } => write!(
                formatter,
                "artifact-chain head mismatch: expected {expected:?}, replayed {actual:?}"
            ),
            Self::Preparation { source } => write!(formatter, "block preparation failed: {source}"),
            Self::BlockAdmission { source } => {
                write!(formatter, "block admission failed: {source}")
            }
            Self::Commit { block_id, source } => write!(
                formatter,
                "journal commit of block {block_id:?} has unknown durability: {source}"
            ),
            Self::Poisoned => formatter
                .write_str("journal is poisoned after an ambiguous commit; drop and reopen it"),
        }
    }
}

impl Error for ArtifactChainJournalError {
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
            Self::Replay { source, .. } => Some(source.as_ref()),
            Self::Preparation { source } => Some(source),
            Self::BlockAdmission { source } => Some(source),
            Self::Locked
            | Self::InvalidHeader
            | Self::ChainIdMismatch { .. }
            | Self::InvalidEntryLength { .. }
            | Self::EntryOffsetOverflow { .. }
            | Self::Allocation { .. }
            | Self::BlockIndexAllocation { .. }
            | Self::BlockIdMismatch { .. }
            | Self::HeadBlockIdMismatch { .. }
            | Self::Poisoned => None,
        }
    }
}

#[cfg(test)]
mod tests;
