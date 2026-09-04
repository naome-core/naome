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
    ConsensusEnvelopeVerifyError, ConsensusHeight, ConsensusPosition, ConsensusRound,
    ConsensusValueError, ConsensusValueV0, FixedAgreementSetId,
    FixedConsensusBoundedEnvelopeVerifyError, FixedConsensusBranchV0, FixedConsensusGenesisError,
    OwnedVerifiedFixedConsensusTransitionV0, ProposerSelectionError,
    VerifiedFixedConsensusTransitionV0,
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

/// The semantic class of one durable terminal safety failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorFinalityHaltKindV0 {
    /// One already selected value received a distinct verified sibling proof.
    SelectedSibling,
    /// Two distinct unselected direct children were verified as a neutral pair.
    PreselectionPair,
}

/// Durable terminal safety-failure evidence summary.
///
/// `first` and `second` are diagnostic evidence order only. For a selected-
/// sibling halt they retain selected then conflicting evidence. For a paired
/// preselection halt they retain ascending proposal-signing-root order. Neither
/// order grants branch, winner, rollback, or finality-selection authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorFinalityHaltV0 {
    kind: FixedValidatorFinalityHaltKindV0,
    height: ConsensusHeight,
    first_ancestry: ConsensusAncestryId,
    first_envelope_id: ConsensusEnvelopeId,
    second_ancestry: ConsensusAncestryId,
    second_envelope_id: ConsensusEnvelopeId,
    state_id: FixedValidatorFinalityJournalStateIdV0,
}

impl FixedValidatorFinalityHaltV0 {
    /// Returns the terminal evidence class.
    pub const fn kind(self) -> FixedValidatorFinalityHaltKindV0 {
        self.kind
    }

    /// Returns the height at which the terminal conflict was established.
    pub const fn height(self) -> ConsensusHeight {
        self.height
    }

    /// Returns the first ancestry in the halt's kind-specific canonical order.
    pub const fn first_ancestry(self) -> ConsensusAncestryId {
        self.first_ancestry
    }

    /// Returns the first envelope in the halt's kind-specific canonical order.
    pub const fn first_envelope_id(self) -> ConsensusEnvelopeId {
        self.first_envelope_id
    }

    /// Returns the second ancestry in the halt's kind-specific canonical order.
    pub const fn second_ancestry(self) -> ConsensusAncestryId {
        self.second_ancestry
    }

    /// Returns the second envelope in the halt's kind-specific canonical order.
    pub const fn second_envelope_id(self) -> ConsensusEnvelopeId {
        self.second_envelope_id
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

/// One exact candidate-backed direct child installed as durable finality.
///
/// Candidate and payload stores supplied availability only. The complete
/// authenticated envelope remains the sole authority for this finality
/// transition, and the source-store entries remain retained and unmodified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CandidateBackedFinalityCommitV0 {
    target: ArtifactBlockId,
    position: ConsensusPosition,
    ancestry_id: ConsensusAncestryId,
    envelope_id: ConsensusEnvelopeId,
    state_id: FixedValidatorFinalityJournalStateIdV0,
}

impl CandidateBackedFinalityCommitV0 {
    /// Returns the exact caller-selected block that became finalized.
    pub const fn target(self) -> ArtifactBlockId {
        self.target
    }

    /// Returns the authenticated height and round.
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns the installed consensus ancestry identity.
    pub const fn ancestry_id(self) -> ConsensusAncestryId {
        self.ancestry_id
    }

    /// Returns the retained complete-envelope identity.
    pub const fn envelope_id(self) -> ConsensusEnvelopeId {
        self.envelope_id
    }

    /// Returns the new durable finality-journal state identity.
    pub const fn state_id(self) -> FixedValidatorFinalityJournalStateIdV0 {
        self.state_id
    }
}

/// One exact caller-selected candidate that proved a finalized sibling conflict.
///
/// Source-store availability grants no finality or conflict authority. Only the
/// fully authenticated distinct sibling may produce the retained terminal halt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CandidateBackedFinalityConflictV0 {
    target: ArtifactBlockId,
    halt: FixedValidatorFinalityHaltV0,
}

impl CandidateBackedFinalityConflictV0 {
    /// Returns the exact caller-selected conflicting block.
    pub const fn target(self) -> ArtifactBlockId {
        self.target
    }

    /// Returns the durable terminal finality halt.
    pub const fn halt(self) -> FixedValidatorFinalityHaltV0 {
        self.halt
    }
}

/// A rejection or durable-finality failure at the candidate-backed boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBackedFinalityErrorV0 {
    /// The finality journal is not healthy and operable.
    FinalityJournal(FixedValidatorFinalityJournalErrorV0),
    /// The operation-local work ceiling exceeds the journal's persisted ceiling.
    RoundWorkLimitExceedsJournal { requested: u64, journal: u64 },
    /// The candidate store belongs to another artifact chain.
    CandidateChainMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// Exact candidate lookup or integrity verification failed.
    CandidateStore(ArtifactBlockCandidateStoreError),
    /// The exact caller-selected candidate is not retained.
    CandidateUnavailable { target: ArtifactBlockId },
    /// The envelope embeds another block address than the caller-selected target.
    EnvelopeTargetMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The retained candidate bytes differ from the envelope's exact block.
    CandidateBlockMismatch { target: ArtifactBlockId },
    /// Exact payload lookup or integrity verification failed.
    PayloadStore(CanonicalArtifactPayloadStoreError),
    /// The retained candidate's exact committed payload is unavailable.
    PayloadUnavailable { artifact_id: ArtifactId },
    /// Bounded complete-envelope verification against the selected parent failed.
    Envelope(FixedConsensusBoundedEnvelopeVerifyError),
    /// The envelope does not name an already selected positive height.
    SelectedHeightUnavailable { height: ConsensusHeight },
    /// The evidence-free value is the already selected value, not a sibling.
    SelectedValueNotDistinct { height: ConsensusHeight },
    /// An unreachable lower-level idempotent outcome violated this direct-child API.
    UnexpectedAlreadyFinalized { height: ConsensusHeight },
    /// An unreachable lower-level conflict outcome violated this direct-child API.
    UnexpectedConflictHalt { height: ConsensusHeight },
    /// An unreachable replay outcome violated the distinct-conflict API.
    UnexpectedSelectedValueReplay { height: ConsensusHeight },
    /// An unreachable new-height outcome violated the conflict API.
    UnexpectedNewFinality { height: ConsensusHeight },
}

impl fmt::Display for CandidateBackedFinalityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinalityJournal(error) => error.fmt(formatter),
            Self::RoundWorkLimitExceedsJournal { requested, journal } => write!(
                formatter,
                "candidate-backed finality work ceiling {requested} exceeds journal replay ceiling {journal}"
            ),
            Self::CandidateChainMismatch { expected, actual } => write!(
                formatter,
                "candidate store chain mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateStore(error) => error.fmt(formatter),
            Self::CandidateUnavailable { target } => {
                write!(formatter, "candidate block {target:?} is not retained")
            }
            Self::EnvelopeTargetMismatch { expected, actual } => write!(
                formatter,
                "consensus envelope block mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateBlockMismatch { target } => write!(
                formatter,
                "retained candidate bytes differ from consensus envelope block {target:?}"
            ),
            Self::PayloadStore(error) => error.fmt(formatter),
            Self::PayloadUnavailable { artifact_id } => write!(
                formatter,
                "candidate artifact payload {artifact_id:?} is not retained"
            ),
            Self::Envelope(error) => error.fmt(formatter),
            Self::SelectedHeightUnavailable { height } => write!(
                formatter,
                "candidate-backed finality conflict requires an already selected height, but height {} is unavailable",
                height.value()
            ),
            Self::SelectedValueNotDistinct { height } => write!(
                formatter,
                "candidate-backed conflict input at height {} names the already selected value",
                height.value()
            ),
            Self::UnexpectedAlreadyFinalized { height } => write!(
                formatter,
                "candidate-backed direct child unexpectedly resolved as already finalized at height {}",
                height.value()
            ),
            Self::UnexpectedConflictHalt { height } => write!(
                formatter,
                "candidate-backed direct child unexpectedly produced a conflict halt at height {}",
                height.value()
            ),
            Self::UnexpectedSelectedValueReplay { height } => write!(
                formatter,
                "candidate-backed finality conflict unexpectedly resolved as selected-value replay at height {}",
                height.value()
            ),
            Self::UnexpectedNewFinality { height } => write!(
                formatter,
                "candidate-backed finality conflict unexpectedly finalized new height {}",
                height.value()
            ),
        }
    }
}

impl Error for CandidateBackedFinalityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FinalityJournal(error) => Some(error),
            Self::CandidateStore(error) => Some(error),
            Self::PayloadStore(error) => Some(error),
            Self::Envelope(error) => Some(error),
            _ => None,
        }
    }
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

/// Opaque authority to stop matching local signers after durable finality conflict.
///
/// Private fields prevent callers from fabricating or changing the conflict
/// evidence. The live immutable journal borrow keeps the exact externally
/// anchored terminal state healthy and unchanged until one vote-safety journal
/// consumes this capability. It grants no sibling selection or rollback
/// authority.
#[must_use]
pub struct FixedValidatorDurableFinalityConflictV0<'journal> {
    _journal: &'journal FixedValidatorFinalityJournalV0,
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    halt: FixedValidatorFinalityHaltV0,
}

impl FixedValidatorDurableFinalityConflictV0<'_> {
    pub(crate) const fn context(&self) -> ConsensusContextV0 {
        self.context
    }

    pub(crate) const fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.fixed_set_id
    }

    pub(crate) const fn halt(&self) -> FixedValidatorFinalityHaltV0 {
        self.halt
    }
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
            None,
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

    /// Returns the immutable agreement-set identity bound by the journal header.
    pub fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.core
            .branches
            .first()
            .expect("every finality journal retains virtual genesis")
            .fixed_agreement_set_id()
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

    /// Issues explicit signer-stop authority for the exact anchored conflict.
    ///
    /// The finality journal must be healthy and terminally halted, and the
    /// caller must first persist its exact current state identity in a
    /// separately protected monotonic anchor. The returned non-clone value
    /// carries only the journal-verified conflict and matching context/set; a
    /// vote-safety journal must explicitly consume it to durably stop one local
    /// signer. No branch is selected, rolled back, or exposed by this handoff.
    pub fn acknowledge_signer_stop_is_externally_durable(
        &self,
        externally_durable_state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<FixedValidatorDurableFinalityConflictV0<'_>, FixedValidatorFinalityJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        let halt = self
            .core
            .halt
            .ok_or(FixedValidatorFinalityJournalErrorV0::SignerStopConflictRequired)?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        debug_assert_eq!(halt.state_id(), self.core.state_id);
        let fixed_set_id = self
            .core
            .branches
            .first()
            .expect("every finality journal retains virtual genesis")
            .fixed_agreement_set_id();
        Ok(FixedValidatorDurableFinalityConflictV0 {
            _journal: self,
            context: self.core.context,
            fixed_set_id,
            halt,
        })
    }

    /// Recovers only the retained branch named by an anchored signer capability.
    ///
    /// Under the caller's point-in-time authorization contract, this narrow read
    /// remains available after a later finality halt when the signer issued the
    /// recovery capability before any explicit conflict stop. The capability
    /// does not establish that ordering. This method rejects poisoned state,
    /// missing history, or any lineage mismatch and exposes no caller-selected
    /// height, sibling, head, or general history API.
    pub fn recover_anchored_signer_branch(
        &self,
        recovery: FixedValidatorAnchoredSignerRecoveryV0<'_>,
    ) -> Result<FixedValidatorRecoveredSignerBranchV0, FixedValidatorFinalityJournalErrorV0> {
        let branch = self.core.recover_anchored_signer_branch(&recovery)?;
        Ok(recovery.into_recovered(branch))
    }

    /// Consumes one sealed verified transition and classifies it against history.
    pub fn commit_verified(
        &mut self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityJournalErrorV0> {
        self.core.commit_verified(transition)
    }
}

impl FixedValidatorAnchoredFinalityJournalV0 {
    /// Creates a new finality journal and its independent genesis anchor.
    ///
    /// The journal header and its parent-directory entry synchronize before the
    /// anchor is installed. Failure after either write returns no operational
    /// wrapper; callers must inspect and explicitly provision a fresh directory
    /// rather than inferring or repairing authority from either file.
    pub fn create(
        journal_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        entries: &[ActiveAgreementEntry],
        replay_limit: FixedValidatorFinalityReplayLimitV0,
    ) -> Result<Self, FixedValidatorAnchoredFinalityJournalErrorV0> {
        let journal_directory = journal_directory.as_ref();
        let mut journal = FixedValidatorFinalityJournalV0::create(
            journal_directory,
            definition,
            context,
            entries,
            replay_limit,
        )
        .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        sync_directory(journal_directory)
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor)?;
        let state_id = journal
            .state_id()
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        let anchor = FixedValidatorAnchorFileV0::create_finality(
            anchor_directory.as_ref(),
            context,
            journal.fixed_agreement_set_id(),
            replay_limit.max_round(),
            *state_id.as_bytes(),
        )
        .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor)?;
        journal.core.anchor = Some(anchor);
        Ok(Self { journal })
    }

    /// Strictly opens a journal only from its independent typed anchor.
    ///
    /// Missing, corrupt, context-mismatched, behind, ahead, or divergent anchor
    /// state returns no wrapper and changes neither complete file. One incomplete
    /// final journal frame retains the existing exact-prefix recovery rule.
    pub fn open(
        journal_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        entries: &[ActiveAgreementEntry],
        replay_limit: FixedValidatorFinalityReplayLimitV0,
    ) -> Result<Self, FixedValidatorAnchoredFinalityJournalErrorV0> {
        let branch = fixed_genesis(definition, context, entries)
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        let fixed_set_id = branch.fixed_agreement_set_id();
        let expected_prefix = canonical_prefix(context, fixed_set_id, replay_limit)
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        let journal_directory = journal_directory.as_ref();
        let lock = open_shared_lock(journal_directory)
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        let anchor = FixedValidatorAnchorFileV0::open_finality(
            anchor_directory.as_ref(),
            context,
            fixed_set_id,
            replay_limit.max_round(),
        )
        .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor)?;
        let anchored = anchor.position();

        let mut branches = Vec::new();
        branches.try_reserve_exact(1).map_err(|_| {
            FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                FixedValidatorFinalityJournalErrorV0::Allocation {
                    entry: 0,
                    bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
                },
            )
        })?;
        branches.push(branch);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_directory.join(JOURNAL_FILE_NAME))
            .map_err(|source| {
                FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                    FixedValidatorFinalityJournalErrorV0::Open { source },
                )
            })?;
        let mut core = FixedValidatorFinalityJournalCore::replay(
            file,
            context,
            replay_limit,
            expected_prefix,
            branches,
            FixedValidatorFinalityJournalStateIdV0::from_bytes(anchored.state_id),
            Some(anchored.sequence),
        )
        .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        anchor
            .stabilize()
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor)?;
        core.anchor = Some(anchor);
        Ok(Self {
            journal: FixedValidatorFinalityJournalV0 { _lock: lock, core },
        })
    }

    /// Returns the exact caller-selected consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.journal.context()
    }

    /// Returns the header-bound local replay-round ceiling.
    pub const fn replay_limit(&self) -> FixedValidatorFinalityReplayLimitV0 {
        self.journal.replay_limit()
    }

    /// Returns the immutable agreement-set identity bound by both files.
    pub fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.journal.fixed_agreement_set_id()
    }

    /// Returns the current healthy journal-state identity.
    pub fn state_id(
        &self,
    ) -> Result<FixedValidatorFinalityJournalStateIdV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal.state_id()
    }

    /// Returns the durable terminal-halt summary, if present.
    pub fn halt(
        &self,
    ) -> Result<Option<FixedValidatorFinalityHaltV0>, FixedValidatorFinalityJournalErrorV0> {
        self.journal.halt()
    }

    /// Returns the exact operable finalized head.
    pub fn head(&self) -> Result<&FixedConsensusBranchV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal.head()
    }

    /// Returns the exact selected artifact-chain identity while operable.
    pub fn artifact_chain_id(
        &self,
    ) -> Result<ArtifactChainId, FixedValidatorFinalityJournalErrorV0> {
        self.journal.artifact_chain_id()
    }

    /// Returns the exact finalized artifact head while operable.
    pub fn artifact_head_block_id(
        &self,
    ) -> Result<ArtifactBlockId, FixedValidatorFinalityJournalErrorV0> {
        self.journal.artifact_head_block_id()
    }

    /// Returns the authenticated finalized artifact-set root while operable.
    pub fn artifact_set_root(
        &self,
    ) -> Result<ArtifactSetRoot, FixedValidatorFinalityJournalErrorV0> {
        self.journal.artifact_set_root()
    }

    /// Returns one retained selected snapshot by exact block identity.
    pub fn artifact_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, FixedValidatorFinalityJournalErrorV0> {
        self.journal.artifact_branch_snapshot_at(block_id)
    }

    /// Returns the retained selected parent required to verify one height.
    pub fn parent_for_height(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedConsensusBranchV0>, FixedValidatorFinalityJournalErrorV0> {
        self.journal.parent_for_height(height)
    }

    /// Returns one retained first finality proof by its positive height.
    pub fn finality_record(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedValidatorFinalityRecordV0>, FixedValidatorFinalityJournalErrorV0> {
        self.journal.finality_record(height)
    }

    /// Returns the number of durably finalized values before terminal halt.
    pub fn finalized_len(&self) -> Result<usize, FixedValidatorFinalityJournalErrorV0> {
        self.journal.finalized_len()
    }

    /// Issues one signer-height transition from the internally anchored state.
    pub fn acknowledge_signer_height_transition(
        &self,
        height: ConsensusHeight,
    ) -> Result<FixedValidatorDurableFinalityTransitionV0<'_>, FixedValidatorFinalityJournalErrorV0>
    {
        let state_id = self.journal.state_id()?;
        self.journal
            .acknowledge_signer_height_transition_is_externally_durable(height, state_id)
    }

    /// Issues signer-stop authority from the internally anchored terminal state.
    pub fn acknowledge_signer_stop(
        &self,
    ) -> Result<FixedValidatorDurableFinalityConflictV0<'_>, FixedValidatorFinalityJournalErrorV0>
    {
        let state_id = self.journal.state_id()?;
        self.journal
            .acknowledge_signer_stop_is_externally_durable(state_id)
    }

    /// Recovers only the retained branch named by an anchored signer capability.
    pub fn recover_anchored_signer_branch(
        &self,
        recovery: FixedValidatorAnchoredSignerRecoveryV0<'_>,
    ) -> Result<FixedValidatorRecoveredSignerBranchV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal.recover_anchored_signer_branch(recovery)
    }

    /// Commits one sealed transition and advances the anchor before publication.
    pub fn commit_verified(
        &mut self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal.commit_verified(transition)
    }

    /// Commits two verified unselected direct children as one neutral halt.
    ///
    /// Both transitions must name the same exact next position and selected
    /// parent and must have distinct proposal-signing roots. The journal orders
    /// them canonically, appends one paired frame, advances the external anchor
    /// once, and publishes no selected child.
    pub fn commit_verified_preselection_conflict(
        &mut self,
        first: OwnedVerifiedFixedConsensusTransitionV0,
        second: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityHaltV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal
            .core
            .commit_verified_preselection_conflict(first, second)
    }
}

/// Strictly installs one exact retained candidate as the current head's next child.
///
/// The caller selects `expected_target`; that choice grants no preference or
/// finality authority. This operation requires an operable fixed-validator
/// journal, the matching chain-scoped candidate, its exact archived Foundation
/// payload, and one complete canonical envelope. It bounds the envelope's sole
/// embedded round by both the caller-local ceiling and the journal ceiling,
/// fully verifies the envelope against the exact current head, and delegates
/// only the resulting sealed transition to the journal's durable commit.
///
/// Success changes only the finality journal. Candidate and payload entries are
/// integrity-read but never removed, marked, or rewritten. The operation does
/// no discovery, ranking, fork choice, sibling-conflict admission, rollback,
/// peer trust, or multi-height promotion.
pub fn commit_candidate_backed_finality_v0(
    journal: &mut FixedValidatorFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityCommitV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_core_v0(
        &mut journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )
}

/// Strictly installs one exact retained candidate through an anchored journal.
///
/// This has the same caller-selected verification and source-store boundaries as
/// [`commit_candidate_backed_finality_v0`], but every resulting finality frame
/// also advances the paired anchor before the commit outcome is published.
pub fn commit_candidate_backed_anchored_finality_v0(
    journal: &mut FixedValidatorAnchoredFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityCommitV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_core_v0(
        &mut journal.journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )
}

fn commit_candidate_backed_finality_core_v0<F: StoreIo>(
    journal: &mut FixedValidatorFinalityJournalCore<F>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityCommitV0, CandidateBackedFinalityErrorV0> {
    journal
        .ensure_operational()
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    if inclusive_maximum_round.value() > journal.replay_limit.max_round() {
        return Err(
            CandidateBackedFinalityErrorV0::RoundWorkLimitExceedsJournal {
                requested: inclusive_maximum_round.value(),
                journal: journal.replay_limit.max_round(),
            },
        );
    }
    let head = journal
        .branches
        .last()
        .expect("every finality journal retains its virtual-genesis branch");
    let envelope_value = decode_candidate_backed_envelope_value(
        journal.context,
        canonical_envelope_bytes,
        expected_target,
    )?;
    let expected_height = head
        .next_height()
        .map_err(FixedConsensusBoundedEnvelopeVerifyError::Proposer)
        .map_err(CandidateBackedFinalityErrorV0::Envelope)?;
    if envelope_value.height() != expected_height {
        return Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::ValueHeightMismatch {
                expected: expected_height,
                actual: envelope_value.height(),
            },
        ));
    }
    let transition = verify_candidate_backed_transition(
        head,
        candidates,
        payloads,
        expected_target,
        envelope_value,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )?;
    let outcome = journal
        .commit_verified(transition)
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    match outcome {
        FixedValidatorFinalityCommitOutcomeV0::Finalized {
            position,
            ancestry_id,
            envelope_id,
            state_id,
        } => Ok(CandidateBackedFinalityCommitV0 {
            target: expected_target,
            position,
            ancestry_id,
            envelope_id,
            state_id,
        }),
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { height, .. } => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedAlreadyFinalized { height })
        }
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedConflictHalt {
                height: halt.height(),
            })
        }
    }
}

/// Verifies one exact retained candidate as a distinct finalized sibling.
///
/// This deny-only boundary accepts only an already selected positive height. It
/// rejects the evidence-free selected value before source reads, then requires
/// complete branch-relative authentication of a distinct sibling before the
/// existing terminal conflict record may be appended. Candidate and payload
/// entries and durable bytes remain unchanged; an integrity/read failure may
/// poison only the owning live source handle under its existing reopen contract.
/// Success grants no branch or winner.
pub fn commit_candidate_backed_finality_conflict_v0(
    journal: &mut FixedValidatorFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_conflict_core_v0(
        &mut journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )
}

/// Verifies and anchors one exact candidate-backed finalized sibling conflict.
///
/// This has the same deny-only verification and source-store boundaries as
/// [`commit_candidate_backed_finality_conflict_v0`], but the terminal finality
/// frame advances the paired anchor before the halt is published.
pub fn commit_candidate_backed_anchored_finality_conflict_v0(
    journal: &mut FixedValidatorAnchoredFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_conflict_core_v0(
        &mut journal.journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )
}

fn commit_candidate_backed_finality_conflict_core_v0<F: StoreIo>(
    journal: &mut FixedValidatorFinalityJournalCore<F>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    journal
        .ensure_operational()
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    if inclusive_maximum_round.value() > journal.replay_limit.max_round() {
        return Err(
            CandidateBackedFinalityErrorV0::RoundWorkLimitExceedsJournal {
                requested: inclusive_maximum_round.value(),
                journal: journal.replay_limit.max_round(),
            },
        );
    }
    let envelope_value = decode_candidate_backed_envelope_value(
        journal.context,
        canonical_envelope_bytes,
        expected_target,
    )?;
    let height = envelope_value.height();
    let height_index = height_index(height).map_err(|()| {
        CandidateBackedFinalityErrorV0::FinalityJournal(
            FixedValidatorFinalityJournalErrorV0::CommitHeightIndexOverflow { height },
        )
    })?;
    let Some(parent_index) = height_index.checked_sub(1) else {
        return Err(CandidateBackedFinalityErrorV0::SelectedHeightUnavailable { height });
    };
    if height_index >= journal.branches.len() {
        return Err(CandidateBackedFinalityErrorV0::SelectedHeightUnavailable { height });
    }
    let parent = journal
        .branches
        .get(parent_index)
        .expect("every selected height retains its exact parent branch");
    let selected = journal
        .records
        .get(parent_index)
        .expect("every selected positive height retains one finality record");
    if selected.value == envelope_value {
        return Err(CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height });
    }
    let transition = verify_candidate_backed_transition(
        parent,
        candidates,
        payloads,
        expected_target,
        envelope_value,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )?;
    let outcome = journal
        .commit_verified(transition)
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    match outcome {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => {
            Ok(CandidateBackedFinalityConflictV0 {
                target: expected_target,
                halt,
            })
        }
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { height, .. } => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedSelectedValueReplay { height })
        }
        FixedValidatorFinalityCommitOutcomeV0::Finalized { position, .. } => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedNewFinality {
                height: position.height(),
            })
        }
    }
}

fn decode_candidate_backed_envelope_value(
    expected_context: ConsensusContextV0,
    canonical_envelope_bytes: &[u8],
    expected_target: ArtifactBlockId,
) -> Result<ConsensusValueV0, CandidateBackedFinalityErrorV0> {
    let envelope_error = |error| {
        CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(error),
        )
    };
    if canonical_envelope_bytes.len() > VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH {
        return Err(envelope_error(ConsensusEnvelopeVerifyError::InputTooLong {
            actual: canonical_envelope_bytes.len(),
            maximum: VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH,
        }));
    }
    if canonical_envelope_bytes.len() < VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH {
        return Err(envelope_error(
            ConsensusEnvelopeVerifyError::InvalidLength {
                actual: canonical_envelope_bytes.len(),
                minimum: VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH,
            },
        ));
    }
    let value = ConsensusValueV0::from_canonical_bytes(
        &canonical_envelope_bytes[..ConsensusValueV0::BYTE_LENGTH],
    )
    .map_err(|error| envelope_error(ConsensusEnvelopeVerifyError::Value(error)))?;
    let actual_context = value.context();
    if actual_context.chain_id() != expected_context.chain_id() {
        return Err(envelope_error(
            ConsensusEnvelopeVerifyError::ChainIdMismatch {
                expected: expected_context.chain_id(),
                actual: actual_context.chain_id(),
            },
        ));
    }
    if actual_context.genesis_id() != expected_context.genesis_id() {
        return Err(envelope_error(
            ConsensusEnvelopeVerifyError::GenesisIdMismatch {
                expected: expected_context.genesis_id(),
                actual: actual_context.genesis_id(),
            },
        ));
    }
    if actual_context.protocol_version() != expected_context.protocol_version() {
        return Err(envelope_error(
            ConsensusEnvelopeVerifyError::ProtocolVersionMismatch {
                expected: expected_context.protocol_version(),
                actual: actual_context.protocol_version(),
            },
        ));
    }
    let actual_target = value.artifact_block().id();
    if actual_target != expected_target {
        return Err(CandidateBackedFinalityErrorV0::EnvelopeTargetMismatch {
            expected: expected_target,
            actual: actual_target,
        });
    }
    Ok(value)
}

fn verify_candidate_backed_transition(
    parent: &FixedConsensusBranchV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    envelope_value: ConsensusValueV0,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<OwnedVerifiedFixedConsensusTransitionV0, CandidateBackedFinalityErrorV0> {
    let expected_chain = parent.context().chain_id();
    if candidates.chain_id() != expected_chain {
        return Err(CandidateBackedFinalityErrorV0::CandidateChainMismatch {
            expected: expected_chain,
            actual: candidates.chain_id(),
        });
    }
    let candidate = candidates
        .get(expected_target)
        .map_err(CandidateBackedFinalityErrorV0::CandidateStore)?
        .ok_or(CandidateBackedFinalityErrorV0::CandidateUnavailable {
            target: expected_target,
        })?;
    if candidate != envelope_value.artifact_block() {
        return Err(CandidateBackedFinalityErrorV0::CandidateBlockMismatch {
            target: expected_target,
        });
    }

    let artifact_id = candidate.artifact_id();
    let payload = payloads
        .get(artifact_id)
        .map_err(CandidateBackedFinalityErrorV0::PayloadStore)?
        .ok_or(CandidateBackedFinalityErrorV0::PayloadUnavailable { artifact_id })?;
    debug_assert_eq!(payload.artifact_id(), artifact_id);

    parent
        .decode_and_verify_envelope_with_round_limit(
            canonical_envelope_bytes,
            payload.into_canonical_artifact_bytes().into_vec(),
            inclusive_maximum_round,
        )
        .map_err(CandidateBackedFinalityErrorV0::Envelope)
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

    fn replay(
        mut file: F,
        context: ConsensusContextV0,
        replay_limit: FixedValidatorFinalityReplayLimitV0,
        expected_prefix: Vec<u8>,
        branches: Vec<FixedConsensusBranchV0>,
        expected_state_id: FixedValidatorFinalityJournalStateIdV0,
        expected_anchor_sequence: Option<u64>,
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
            core.record_sequence = core
                .record_sequence
                .checked_add(1)
                .ok_or(FixedValidatorFinalityJournalErrorV0::RecordSequenceExhausted)?;
            core.committed_end = entry_end;
            entry_start = entry_end;
            entry += 1;
        }

        if let Some(expected_sequence) = expected_anchor_sequence
            && (core.record_sequence != expected_sequence || core.state_id != expected_state_id)
        {
            return Err(match core.record_sequence.cmp(&expected_sequence) {
                std::cmp::Ordering::Greater => FixedValidatorFinalityJournalErrorV0::AnchorBehind {
                    anchored_sequence: expected_sequence,
                    journal_sequence: core.record_sequence,
                },
                std::cmp::Ordering::Less => FixedValidatorFinalityJournalErrorV0::AnchorAhead {
                    anchored_sequence: expected_sequence,
                    journal_sequence: core.record_sequence,
                },
                std::cmp::Ordering::Equal => {
                    FixedValidatorFinalityJournalErrorV0::AnchorStateMismatch {
                        sequence: expected_sequence,
                    }
                }
            });
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
        match parse_record(entry, offset, &body, self.replay_limit)? {
            ParsedRecord::Single {
                tag,
                round,
                transition: parsed,
            } => {
                let height = parsed.height;
                let height_index = height_index(height).map_err(|()| {
                    FixedValidatorFinalityJournalErrorV0::HeightIndexOverflow { entry, height }
                })?;
                match tag {
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
                let mut typed_round = parent
                    .begin_round_zero()
                    .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
                for _ in 0..round {
                    typed_round = typed_round
                        .advance_round()
                        .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
                }
                let payload = clone_bytes(parsed.payload, entry)?;
                let transition = typed_round
                    .decode_and_verify(parsed.envelope, payload)
                    .map_err(|source| FixedValidatorFinalityJournalErrorV0::Replay {
                        entry,
                        offset,
                        source: Box::new(source),
                    })?
                    .into_owned();
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
                            FixedValidatorFinalityJournalErrorV0::InvalidConflictHalt {
                                entry,
                                height,
                            },
                        )?;
                        if selected.value == transition.value() {
                            return Err(
                                FixedValidatorFinalityJournalErrorV0::InvalidConflictHalt {
                                    entry,
                                    height,
                                },
                            );
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
            ParsedRecord::PreselectionConflict {
                round,
                first: first_parsed,
                second: second_parsed,
            } => {
                let height = first_parsed.height;
                if second_parsed.height != height {
                    return Err(
                        FixedValidatorFinalityJournalErrorV0::InvalidPreselectionConflict {
                            entry,
                            height,
                        },
                    );
                }
                let height_index = height_index(height).map_err(|()| {
                    FixedValidatorFinalityJournalErrorV0::HeightIndexOverflow { entry, height }
                })?;
                if height_index != self.branches.len() {
                    return Err(
                        FixedValidatorFinalityJournalErrorV0::InvalidPreselectionConflict {
                            entry,
                            height,
                        },
                    );
                }
                let parent_index = height_index
                    .checked_sub(1)
                    .expect("strict value decoding rejects height zero");
                let parent = self.branches.get(parent_index).ok_or(
                    FixedValidatorFinalityJournalErrorV0::InvalidSelectedParent { entry, height },
                )?;
                let mut typed_round = parent
                    .begin_round_zero()
                    .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
                for _ in 0..round {
                    typed_round = typed_round
                        .advance_round()
                        .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
                }
                let first_payload = clone_bytes(first_parsed.payload, entry)?;
                let first = typed_round
                    .decode_and_verify(first_parsed.envelope, first_payload)
                    .map_err(|source| FixedValidatorFinalityJournalErrorV0::Replay {
                        entry,
                        offset,
                        source: Box::new(source),
                    })?
                    .into_owned();
                let second_payload = clone_bytes(second_parsed.payload, entry)?;
                let second = typed_round
                    .decode_and_verify(second_parsed.envelope, second_payload)
                    .map_err(|source| FixedValidatorFinalityJournalErrorV0::Replay {
                        entry,
                        offset,
                        source: Box::new(source),
                    })?
                    .into_owned();
                if first.position() != second.position()
                    || first.parent_coordinate() != second.parent_coordinate()
                    || first.value() == second.value()
                    || first.value().proposal_signing_root()
                        >= second.value().proposal_signing_root()
                {
                    return Err(
                        FixedValidatorFinalityJournalErrorV0::InvalidPreselectionConflict {
                            entry,
                            height,
                        },
                    );
                }
                self.halt = Some(halt_from_preselection_pair(&first, &second, state_id));
                Ok(())
            }
        }
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
            self.append_record(
                &body,
                next_state_id,
                FinalityAppendEvidenceV0::Single(transition.envelope_id()),
                entry,
            )?;
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
            FinalityAppendEvidenceV0::Single(envelope_id),
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

    fn commit_verified_preselection_conflict(
        &mut self,
        first: OwnedVerifiedFixedConsensusTransitionV0,
        second: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityHaltV0, FixedValidatorFinalityJournalErrorV0> {
        self.ensure_operational()?;
        let first_position = first.position();
        let second_position = second.position();
        if first_position != second_position {
            return Err(
                FixedValidatorFinalityJournalErrorV0::PreselectionConflictPositionMismatch {
                    first: first_position,
                    second: second_position,
                },
            );
        }
        let round = first_position.round().value();
        if round > self.replay_limit.max_round() {
            return Err(FixedValidatorFinalityJournalErrorV0::RoundLimitExceeded {
                round,
                maximum: self.replay_limit.max_round(),
            });
        }
        let height = first_position.height();
        let height_index = height_index(height).map_err(|()| {
            FixedValidatorFinalityJournalErrorV0::CommitHeightIndexOverflow { height }
        })?;
        if height_index != self.branches.len() {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        }
        let parent_index = height_index
            .checked_sub(1)
            .expect("a sealed transition always has positive height");
        let parent = self
            .branches
            .get(parent_index)
            .expect("the next unselected height has one selected parent");
        if first.parent_coordinate() != second.parent_coordinate()
            || first.parent_coordinate() != parent.coordinate()
        {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        }

        let first_root = first.value().proposal_signing_root();
        let second_root = second.value().proposal_signing_root();
        if first.value() == second.value() || first_root == second_root {
            return Err(
                FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct { height },
            );
        }
        let (first, second) = if first_root < second_root {
            (first, second)
        } else {
            (second, first)
        };
        let entry = u64::try_from(self.records.len()).expect("record count fits u64");
        let body = canonical_preselection_conflict_record_body(&first, &second, entry)?;
        let body_length = u32::try_from(body.len())
            .expect("bounded fixed-validator journal record length fits u32");
        let next_state_id = step_state_id(self.state_id, body_length.to_be_bytes(), &body);
        let halt = halt_from_preselection_pair(&first, &second, next_state_id);
        self.append_record(
            &body,
            next_state_id,
            FinalityAppendEvidenceV0::Pair {
                first: first.envelope_id(),
                second: second.envelope_id(),
            },
            entry,
        )?;
        self.halt = Some(halt);
        self.state_id = next_state_id;
        Ok(halt)
    }

    fn append_record(
        &mut self,
        body: &[u8],
        next_state_id: FixedValidatorFinalityJournalStateIdV0,
        evidence: FinalityAppendEvidenceV0,
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
        let next_sequence = self
            .record_sequence
            .checked_add(1)
            .ok_or(FixedValidatorFinalityJournalErrorV0::RecordSequenceExhausted)?;
        let commit_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(self.committed_end))?;
            self.file
                .append_write_all(AppendPhase::Body, &body_length_bytes)?;
            self.file.append_write_all(AppendPhase::Body, body)?;
            self.file.append_sync_all(AppendPhase::Body)?;
            self.file
                .append_write_all(AppendPhase::Commit, next_state_id.as_bytes())?;
            self.file.append_sync_all(AppendPhase::Commit)?;
            if let Some(anchor) = self.anchor.as_mut() {
                let transition = JournalAnchorTransitionV0::new(
                    anchor.pairing_seal(),
                    AnchorPositionV0 {
                        sequence: self.record_sequence,
                        state_id: *self.state_id.as_bytes(),
                    },
                    *next_state_id.as_bytes(),
                )
                .map_err(io::Error::other)?;
                debug_assert_eq!(transition.next().sequence, next_sequence);
                anchor.advance(transition).map_err(io::Error::other)?;
            }
            Ok(())
        })();
        if let Err(source) = commit_result {
            self.poisoned = true;
            return Err(match evidence {
                FinalityAppendEvidenceV0::Single(envelope_id) => {
                    FixedValidatorFinalityJournalErrorV0::Commit {
                        envelope_id,
                        proposed_state_id: next_state_id,
                        source,
                    }
                }
                FinalityAppendEvidenceV0::Pair { first, second } => {
                    FixedValidatorFinalityJournalErrorV0::PairedCommit {
                        first_envelope_id: first,
                        second_envelope_id: second,
                        proposed_state_id: next_state_id,
                        source,
                    }
                }
            });
        }
        self.committed_end = next_committed_end;
        self.record_sequence = next_sequence;
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

    fn recover_anchored_signer_branch(
        &self,
        recovery: &FixedValidatorAnchoredSignerRecoveryV0<'_>,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorFinalityJournalErrorV0> {
        self.ensure_healthy()?;
        let height = recovery.lineage.height;
        let height_index = height_index(height).map_err(|()| {
            FixedValidatorFinalityJournalErrorV0::SignerRecoveryHeightIndexOverflow { height }
        })?;
        let Some(branch_index) = height_index.checked_sub(1) else {
            return Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryUnavailable { height });
        };
        let Some(branch) = self.branches.get(branch_index) else {
            return Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryUnavailable { height });
        };
        let actual = signing_lineage_id(branch.coordinate(), height, recovery.signer);
        if actual != recovery.lineage.id {
            return Err(
                FixedValidatorFinalityJournalErrorV0::SignerRecoveryLineageMismatch { height },
            );
        }
        Ok(branch.clone())
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

struct ParsedTransitionBytes<'bytes> {
    height: ConsensusHeight,
    envelope: &'bytes [u8],
    payload: &'bytes [u8],
}

enum ParsedRecord<'bytes> {
    Single {
        tag: u8,
        round: u64,
        transition: ParsedTransitionBytes<'bytes>,
    },
    PreselectionConflict {
        round: u64,
        first: ParsedTransitionBytes<'bytes>,
        second: ParsedTransitionBytes<'bytes>,
    },
}

fn parse_round(
    entry: u64,
    body: &[u8],
    replay_limit: FixedValidatorFinalityReplayLimitV0,
) -> Result<u64, FixedValidatorFinalityJournalErrorV0> {
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
    Ok(round)
}

fn parse_record<'bytes>(
    entry: u64,
    offset: u64,
    body: &'bytes [u8],
    replay_limit: FixedValidatorFinalityReplayLimitV0,
) -> Result<ParsedRecord<'bytes>, FixedValidatorFinalityJournalErrorV0> {
    let tag = body[0];
    match tag {
        FINALIZE_RECORD | CONFLICT_HALT_RECORD => {
            if !(MIN_SINGLE_RECORD_BODY_BYTES..=MAX_SINGLE_RECORD_BODY_BYTES).contains(&body.len())
            {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordLength {
                    entry,
                    offset,
                    actual: u32::try_from(body.len()).expect("bounded record length fits u32"),
                    minimum: u32::try_from(MIN_SINGLE_RECORD_BODY_BYTES)
                        .expect("minimum single record length fits u32"),
                    maximum: u32::try_from(MAX_SINGLE_RECORD_BODY_BYTES)
                        .expect("maximum single record length fits u32"),
                });
            }
            let round = parse_round(entry, body, replay_limit)?;
            let envelope_length = parse_envelope_length(entry, &body[9..13])?;
            let payload_length = parse_payload_length(entry, &body[13..17])?;
            let expected_length = RECORD_HEADER_BYTES
                .checked_add(envelope_length)
                .and_then(|length| length.checked_add(payload_length))
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            if expected_length != body.len() {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry });
            }
            let envelope_end = RECORD_HEADER_BYTES + envelope_length;
            let transition = parsed_transition_bytes(
                entry,
                &body[RECORD_HEADER_BYTES..envelope_end],
                &body[envelope_end..],
            )?;
            Ok(ParsedRecord::Single {
                tag,
                round,
                transition,
            })
        }
        PRESELECTION_CONFLICT_HALT_RECORD => {
            if !(MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES
                ..=MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
                .contains(&body.len())
            {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordLength {
                    entry,
                    offset,
                    actual: u32::try_from(body.len()).expect("bounded record length fits u32"),
                    minimum: u32::try_from(MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
                        .expect("minimum paired record length fits u32"),
                    maximum: u32::try_from(MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
                        .expect("maximum paired record length fits u32"),
                });
            }
            let round = parse_round(entry, body, replay_limit)?;
            let first_envelope_length = parse_envelope_length(entry, &body[9..13])?;
            let first_payload_length = parse_payload_length(entry, &body[13..17])?;
            let second_envelope_length = parse_envelope_length(entry, &body[17..21])?;
            let second_payload_length = parse_payload_length(entry, &body[21..25])?;
            let first_envelope_end = PRESELECTION_CONFLICT_RECORD_HEADER_BYTES
                .checked_add(first_envelope_length)
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            let first_payload_end = first_envelope_end
                .checked_add(first_payload_length)
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            let second_envelope_end = first_payload_end
                .checked_add(second_envelope_length)
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            let expected_length = second_envelope_end
                .checked_add(second_payload_length)
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            if expected_length != body.len() {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry });
            }
            let first = parsed_transition_bytes(
                entry,
                &body[PRESELECTION_CONFLICT_RECORD_HEADER_BYTES..first_envelope_end],
                &body[first_envelope_end..first_payload_end],
            )?;
            let second = parsed_transition_bytes(
                entry,
                &body[first_payload_end..second_envelope_end],
                &body[second_envelope_end..],
            )?;
            Ok(ParsedRecord::PreselectionConflict {
                round,
                first,
                second,
            })
        }
        _ => Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordTag {
            entry,
            offset,
            actual: tag,
        }),
    }
}

fn parse_envelope_length(
    entry: u64,
    bytes: &[u8],
) -> Result<usize, FixedValidatorFinalityJournalErrorV0> {
    let actual = usize::try_from(u32::from_be_bytes(
        bytes.try_into().expect("an envelope length has four bytes"),
    ))
    .expect("every u32 envelope length fits the supported Rust targets");
    if !(VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH
        ..=VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH)
        .contains(&actual)
    {
        return Err(FixedValidatorFinalityJournalErrorV0::InvalidEnvelopeLength { entry, actual });
    }
    Ok(actual)
}

fn parse_payload_length(
    entry: u64,
    bytes: &[u8],
) -> Result<usize, FixedValidatorFinalityJournalErrorV0> {
    let actual = usize::try_from(u32::from_be_bytes(
        bytes.try_into().expect("a payload length has four bytes"),
    ))
    .expect("every u32 payload length fits the supported Rust targets");
    if !(1..=ARTIFACT_PAYLOAD_MAX_BYTES).contains(&actual) {
        return Err(FixedValidatorFinalityJournalErrorV0::InvalidPayloadLength { entry, actual });
    }
    Ok(actual)
}

fn parsed_transition_bytes<'bytes>(
    entry: u64,
    envelope: &'bytes [u8],
    payload: &'bytes [u8],
) -> Result<ParsedTransitionBytes<'bytes>, FixedValidatorFinalityJournalErrorV0> {
    let value = ConsensusValueV0::from_canonical_bytes(&envelope[..ConsensusValueV0::BYTE_LENGTH])
        .map_err(|source| FixedValidatorFinalityJournalErrorV0::Value { entry, source })?;
    Ok(ParsedTransitionBytes {
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

fn canonical_preselection_conflict_record_body(
    first: &OwnedVerifiedFixedConsensusTransitionV0,
    second: &OwnedVerifiedFixedConsensusTransitionV0,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorFinalityJournalErrorV0> {
    debug_assert_eq!(first.position(), second.position());
    debug_assert_eq!(first.parent_coordinate(), second.parent_coordinate());
    debug_assert!(first.value().proposal_signing_root() < second.value().proposal_signing_root());
    let first_envelope = first.canonical_envelope_bytes();
    let first_payload = first.canonical_artifact_bytes();
    let second_envelope = second.canonical_envelope_bytes();
    let second_payload = second.canonical_artifact_bytes();
    let body_length = PRESELECTION_CONFLICT_RECORD_HEADER_BYTES
        .checked_add(first_envelope.len())
        .and_then(|length| length.checked_add(first_payload.len()))
        .and_then(|length| length.checked_add(second_envelope.len()))
        .and_then(|length| length.checked_add(second_payload.len()))
        .expect("sealed verified transitions retain bounded canonical bytes");
    let mut body = Vec::new();
    body.try_reserve_exact(body_length).map_err(|_| {
        FixedValidatorFinalityJournalErrorV0::Allocation {
            entry,
            bytes: body_length,
        }
    })?;
    body.push(PRESELECTION_CONFLICT_HALT_RECORD);
    body.extend_from_slice(&first.position().round().value().to_be_bytes());
    for length in [
        first_envelope.len(),
        first_payload.len(),
        second_envelope.len(),
        second_payload.len(),
    ] {
        body.extend_from_slice(
            &u32::try_from(length)
                .expect("bounded paired component length fits u32")
                .to_be_bytes(),
        );
    }
    body.extend_from_slice(first_envelope);
    body.extend_from_slice(first_payload);
    body.extend_from_slice(second_envelope);
    body.extend_from_slice(second_payload);
    debug_assert_eq!(body.len(), body_length);
    debug_assert!(
        (MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES..=MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
            .contains(&body.len())
    );
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
        kind: FixedValidatorFinalityHaltKindV0::SelectedSibling,
        height: conflicting.value().height(),
        first_ancestry: selected_ancestry,
        first_envelope_id: selected_envelope_id,
        second_ancestry: conflicting.value().ancestry_id(),
        second_envelope_id: conflicting.envelope_id(),
        state_id,
    }
}

fn halt_from_preselection_pair(
    first: &OwnedVerifiedFixedConsensusTransitionV0,
    second: &OwnedVerifiedFixedConsensusTransitionV0,
    state_id: FixedValidatorFinalityJournalStateIdV0,
) -> FixedValidatorFinalityHaltV0 {
    debug_assert_eq!(first.position(), second.position());
    debug_assert!(first.value().proposal_signing_root() < second.value().proposal_signing_root());
    FixedValidatorFinalityHaltV0 {
        kind: FixedValidatorFinalityHaltKindV0::PreselectionPair,
        height: first.position().height(),
        first_ancestry: first.value().ancestry_id(),
        first_envelope_id: first.envelope_id(),
        second_ancestry: second.value().ancestry_id(),
        second_envelope_id: second.envelope_id(),
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

/// Failure to create or strictly open the paired finality journal and anchor.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorAnchoredFinalityJournalErrorV0 {
    Journal(FixedValidatorFinalityJournalErrorV0),
    Anchor(FixedValidatorAnchorErrorV0),
}

impl fmt::Display for FixedValidatorAnchoredFinalityJournalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(source) => {
                write!(formatter, "anchored finality journal failed: {source}")
            }
            Self::Anchor(source) => write!(formatter, "finality anchor failed: {source}"),
        }
    }
}

impl Error for FixedValidatorAnchoredFinalityJournalErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(source) => Some(source),
            Self::Anchor(source) => Some(source),
        }
    }
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
    /// A paired halt record did not contain two canonical next-child proofs.
    InvalidPreselectionConflict { entry: u64, height: ConsensusHeight },
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
    /// The journal contains more complete frames than its persisted anchor.
    AnchorBehind {
        anchored_sequence: u64,
        journal_sequence: u64,
    },
    /// The persisted anchor names more frames than the journal contains.
    AnchorAhead {
        anchored_sequence: u64,
        journal_sequence: u64,
    },
    /// Anchor and journal sequences agree but their chained identities differ.
    AnchorStateMismatch { sequence: u64 },
    /// The count of complete journal frames exhausted its fixed-width sequence.
    RecordSequenceExhausted,
    /// An authenticated incomplete final entry could not be truncated and synced.
    Recovery { offset: u64, source: io::Error },
    /// A fully replayed unchanged journal image could not be synchronized.
    Stabilize { source: io::Error },
    /// A verified transition exceeded the header-bound local round ceiling.
    RoundLimitExceeded { round: u64, maximum: u64 },
    /// A verified transition was not derived from the retained selected parent.
    UnselectedParent { height: ConsensusHeight },
    /// The two verified paired-halt transitions name different positions.
    PreselectionConflictPositionMismatch {
        first: ConsensusPosition,
        second: ConsensusPosition,
    },
    /// The two verified paired-halt transitions do not name distinct roots.
    PreselectionConflictNotDistinct { height: ConsensusHeight },
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
    /// Signer-stop authority requires one retained durable finality conflict.
    SignerStopConflictRequired,
    /// An anchored signer height could not index this platform.
    SignerRecoveryHeightIndexOverflow { height: ConsensusHeight },
    /// Retained finality history has no branch for the anchored signer height.
    SignerRecoveryUnavailable { height: ConsensusHeight },
    /// Retained history does not reproduce the exact anchored signer lineage.
    SignerRecoveryLineageMismatch { height: ConsensusHeight },
    /// The journal has durably halted and exposes no operational branch access.
    TerminalHalt { height: ConsensusHeight },
    /// An append failed after durability may have changed.
    Commit {
        envelope_id: ConsensusEnvelopeId,
        proposed_state_id: FixedValidatorFinalityJournalStateIdV0,
        source: io::Error,
    },
    /// A paired-halt append failed after durability may have changed.
    PairedCommit {
        first_envelope_id: ConsensusEnvelopeId,
        second_envelope_id: ConsensusEnvelopeId,
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
            Self::InvalidPreselectionConflict { entry, height } => write!(
                formatter,
                "paired conflict record {entry} does not name two canonically ordered distinct unselected children at height {}",
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
            Self::AnchorBehind {
                anchored_sequence,
                journal_sequence,
            } => write!(
                formatter,
                "finality anchor is behind at sequence {anchored_sequence}; the journal has {journal_sequence} complete frames"
            ),
            Self::AnchorAhead {
                anchored_sequence,
                journal_sequence,
            } => write!(
                formatter,
                "finality anchor is ahead at sequence {anchored_sequence}; the journal has {journal_sequence} complete frames"
            ),
            Self::AnchorStateMismatch { sequence } => write!(
                formatter,
                "finality anchor and journal have different state identities at sequence {sequence}"
            ),
            Self::RecordSequenceExhausted => {
                formatter.write_str("finality journal frame sequence is exhausted")
            }
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
            Self::PreselectionConflictPositionMismatch { first, second } => write!(
                formatter,
                "paired conflict positions differ: first {first:?}, second {second:?}"
            ),
            Self::PreselectionConflictNotDistinct { height } => write!(
                formatter,
                "paired conflict transitions do not have distinct proposal roots at height {}",
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
            Self::SignerStopConflictRequired => formatter.write_str(
                "signer-stop authority requires a durable finality conflict",
            ),
            Self::SignerRecoveryHeightIndexOverflow { height } => write!(
                formatter,
                "anchored signer-recovery height {} cannot index this platform",
                height.value()
            ),
            Self::SignerRecoveryUnavailable { height } => write!(
                formatter,
                "no retained finality branch is available for anchored signer-recovery height {}",
                height.value()
            ),
            Self::SignerRecoveryLineageMismatch { height } => write!(
                formatter,
                "retained finality branch does not match the anchored signer lineage at height {}",
                height.value()
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
            Self::PairedCommit {
                first_envelope_id,
                second_envelope_id,
                proposed_state_id,
                source,
            } => write!(
                formatter,
                "paired halt commit for envelopes {first_envelope_id:?} and {second_envelope_id:?} and state {proposed_state_id:?} has unknown durability: {source}"
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
            | Self::Commit { source, .. }
            | Self::PairedCommit { source, .. } => Some(source),
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
            | Self::InvalidPreselectionConflict { .. }
            | Self::InvalidSelectedParent { .. }
            | Self::RecordAfterHalt { .. }
            | Self::ExpectedStateIdMismatch { .. }
            | Self::AnchorBehind { .. }
            | Self::AnchorAhead { .. }
            | Self::AnchorStateMismatch { .. }
            | Self::RecordSequenceExhausted
            | Self::RoundLimitExceeded { .. }
            | Self::UnselectedParent { .. }
            | Self::PreselectionConflictPositionMismatch { .. }
            | Self::PreselectionConflictNotDistinct { .. }
            | Self::CommitHeightIndexOverflow { .. }
            | Self::SignerHandoffHeightIndexOverflow { .. }
            | Self::SignerHandoffUnavailable { .. }
            | Self::ExternalFinalityAnchorMismatch { .. }
            | Self::SignerStopConflictRequired
            | Self::SignerRecoveryHeightIndexOverflow { .. }
            | Self::SignerRecoveryUnavailable { .. }
            | Self::SignerRecoveryLineageMismatch { .. }
            | Self::TerminalHalt { .. }
            | Self::Poisoned => None,
        }
    }
}

#[cfg(test)]
mod tests;
