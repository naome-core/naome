//! Typed persistence and operational failures.

use super::*;

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
