//! Typed persistence and operational failures.

use super::*;

/// Failure to create or strictly open one paired per-key journal and anchor.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorAnchoredVoteSafetyJournalErrorV0 {
    Journal(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    Anchor(FixedValidatorAnchorErrorV0),
}

impl FixedValidatorAnchoredVoteSafetyJournalErrorV0 {
    pub(super) fn journal(source: FixedValidatorVoteSafetyJournalErrorV0) -> Self {
        Self::Journal(Box::new(source))
    }
}

impl fmt::Display for FixedValidatorAnchoredVoteSafetyJournalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(source) => {
                write!(formatter, "anchored vote-safety journal failed: {source}")
            }
            Self::Anchor(source) => write!(formatter, "vote-safety anchor failed: {source}"),
        }
    }
}

impl Error for FixedValidatorAnchoredVoteSafetyJournalErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(source) => Some(source.as_ref()),
            Self::Anchor(source) => Some(source),
        }
    }
}

/// A fail-closed fixed-validator vote-safety journal error.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorVoteSafetyJournalErrorV0 {
    LockFile {
        source: io::Error,
    },
    Locked,
    Lock {
        source: io::Error,
    },
    PathAllocation,
    Create {
        source: io::Error,
    },
    Open {
        source: io::Error,
    },
    Read {
        offset: u64,
        source: io::Error,
    },
    InvalidHeader,
    HeaderMismatch,
    InvalidRecordLength {
        entry: u64,
        offset: u64,
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    EntryOffsetOverflow {
        entry: u64,
        offset: u64,
    },
    Allocation {
        entry: u64,
        bytes: usize,
    },
    HistoryAllocation {
        entry: u64,
        retained_votes: usize,
    },
    ProposalHistoryAllocation {
        entry: u64,
        retained_proposals: usize,
    },
    InvalidRecordTag {
        entry: u64,
        offset: u64,
        actual: u8,
    },
    InvalidSigningLineageLength {
        entry: u64,
        actual: usize,
    },
    InvalidSigningLineageHeight {
        entry: u64,
        actual: ConsensusHeight,
    },
    SigningLineageWhilePending {
        entry: u64,
    },
    SigningLineageHeightExhausted {
        entry: u64,
        previous: ConsensusHeight,
    },
    NonSequentialSigningLineage {
        entry: u64,
        expected: ConsensusHeight,
        actual: ConsensusHeight,
    },
    VoteOutsideSigningLineage {
        entry: u64,
        lineage_height: ConsensusHeight,
        vote_height: ConsensusHeight,
    },
    RecordStateIdMismatch {
        entry: u64,
        offset: u64,
        expected: FixedValidatorVoteSafetyJournalStateIdV0,
        actual: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    Intent {
        entry: u64,
        offset: u64,
        source: FixedValidatorVoteIntentError,
    },
    ProposalIntent {
        entry: u64,
        offset: u64,
        source: FixedValidatorProposalIntentErrorV0,
    },
    IntentHeaderMismatch,
    FinalityConflictContextMismatch,
    FinalityConflictFixedSetMismatch,
    SigningSessionAlreadyIssued,
    SigningSessionRoundMismatch,
    SigningLineageRequired,
    SigningLineageMismatch {
        expected_height: ConsensusHeight,
        actual_height: ConsensusHeight,
    },
    ExternalSessionAnchorMismatch {
        required: FixedValidatorVoteSafetyJournalStateIdV0,
        acknowledged: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ForeignSignerRecovery,
    StaleSignerRecovery {
        recovered: FixedValidatorVoteSafetyJournalStateIdV0,
        current: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    SignerRecoveryRoundLimitExceeded {
        required: u64,
        maximum: u64,
    },
    SignerRecoveryPositionMismatch {
        required: ConsensusPosition,
        actual: ConsensusPosition,
    },
    SignerRecoveryRound(ProposerSelectionError),
    LockState(FixedValidatorLockStateError),
    SigningSessionIntent(FixedValidatorVoteIntentError),
    HigherRoundCheckpoint {
        entry: u64,
        offset: u64,
        source: FixedValidatorHigherRoundCheckpointErrorV0,
    },
    HigherRoundCheckpointReplay(FixedValidatorHigherRoundCheckpointErrorV0),
    HigherRoundCheckpointWithoutLineage {
        entry: u64,
    },
    HigherRoundCheckpointWhilePending {
        entry: u64,
    },
    HigherRoundCheckpointOutsideLineage {
        entry: u64,
        lineage_height: ConsensusHeight,
        checkpoint_height: ConsensusHeight,
    },
    HigherRoundCheckpointSourceBehindState {
        entry: u64,
        current_position: ConsensusPosition,
        current_phase: FixedValidatorLockPhaseV0,
        source_position: ConsensusPosition,
        source_phase: FixedValidatorLockPhaseV0,
    },
    VoteStateDoesNotFollowHigherRoundCheckpoint {
        entry: u64,
        checkpoint_position: ConsensusPosition,
        checkpoint_phase: FixedValidatorLockPhaseV0,
        vote_position: ConsensusPosition,
        vote_phase: FixedValidatorLockPhaseV0,
    },
    ExternalPrepareAnchorMismatch {
        prepared: FixedValidatorVoteSafetyJournalStateIdV0,
        acknowledged: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ForeignPrepareAcknowledgement,
    SignedVote {
        entry: u64,
        offset: u64,
        source: ConsensusVoteVerifyError,
    },
    InvalidCompletionLength {
        entry: u64,
        actual: usize,
    },
    CompletionMismatch {
        entry: u64,
        reason: FixedValidatorVoteCompletionMismatchV0,
    },
    CompletionWithoutPrepare {
        entry: u64,
    },
    InvalidProposalActivationLength {
        entry: u64,
        actual: usize,
    },
    DuplicateProposalActivation {
        entry: u64,
    },
    ProposalActivationWhilePending {
        entry: u64,
    },
    InvalidProposalActivation {
        entry: u64,
    },
    ProposalAuthoringNotActivated,
    ProposalReplayLimitExceeded {
        entry: u64,
        maximum: u64,
    },
    ProposalWithoutSigningLineage {
        entry: u64,
    },
    ProposalOutsideSigningLineage {
        entry: u64,
        lineage_height: ConsensusHeight,
        proposal_height: ConsensusHeight,
    },
    DuplicateProposalPrepare {
        entry: u64,
    },
    NonMonotonicProposalReplay {
        entry: u64,
        previous: ConsensusPosition,
        actual: ConsensusPosition,
    },
    ProposalAfterVote {
        proposal: ConsensusPosition,
        vote: ConsensusPosition,
        vote_role: ConsensusVoteRole,
    },
    VoteBeforeProposal {
        vote: ConsensusPosition,
        vote_role: ConsensusVoteRole,
        proposal: ConsensusPosition,
    },
    ProposalStateBehindCurrent {
        proposal: ConsensusPosition,
        current_position: ConsensusPosition,
        current_phase: FixedValidatorLockPhaseV0,
    },
    ProposalCompletionWithoutPrepare {
        entry: u64,
    },
    CompletedProposal {
        entry: u64,
        source: FixedValidatorProposalIntentErrorV0,
    },
    InvalidProposalConflictHalt {
        entry: u64,
    },
    PrepareWhilePending {
        entry: u64,
    },
    DuplicatePrepare {
        entry: u64,
    },
    InvalidConflictHalt {
        entry: u64,
    },
    InvalidFinalityConflictSignerStopLength {
        entry: u64,
        actual: usize,
    },
    InvalidFinalityConflictSignerStop {
        entry: u64,
    },
    ConflictingFinalityConflictSignerStop {
        retained_height: ConsensusHeight,
        incoming_height: ConsensusHeight,
    },
    RecordAfterHalt {
        offset: u64,
    },
    ReplayLimitExceeded {
        entry: u64,
        maximum: u64,
    },
    NonMonotonicReplay {
        entry: u64,
        previous: ConsensusPosition,
        previous_role: ConsensusVoteRole,
        actual: ConsensusPosition,
        actual_role: ConsensusVoteRole,
    },
    ExpectedStateIdMismatch {
        expected: FixedValidatorVoteSafetyJournalStateIdV0,
        actual: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    AnchorBehind {
        anchored_sequence: u64,
        journal_sequence: u64,
    },
    AnchorAhead {
        anchored_sequence: u64,
        journal_sequence: u64,
    },
    AnchorStateMismatch {
        sequence: u64,
    },
    RecordSequenceExhausted,
    Recovery {
        offset: u64,
        source: io::Error,
    },
    Stabilize {
        source: io::Error,
    },
    PendingPreparation {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    },
    PendingProposalPreparation {
        position: ConsensusPosition,
    },
    PendingHeightAdvance {
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    PendingHigherRoundAdvance {
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ExternalHeightAnchorMismatch {
        prepared: FixedValidatorVoteSafetyJournalStateIdV0,
        acknowledged: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ForeignHeightAdvance,
    StaleHeightAdvance,
    ExternalHigherRoundAnchorMismatch {
        prepared: FixedValidatorVoteSafetyJournalStateIdV0,
        acknowledged: FixedValidatorVoteSafetyJournalStateIdV0,
    },
    ForeignHigherRoundAdvance,
    StaleHigherRoundAdvance,
    PendingRecoveryDenied {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    },
    PendingProposalRecoveryDenied {
        position: ConsensusPosition,
    },
    PrepareLimitExceeded {
        maximum: u64,
    },
    ProposalPrepareLimitExceeded {
        maximum: u64,
    },
    NonMonotonicSlot {
        previous: ConsensusPosition,
        previous_role: ConsensusVoteRole,
        actual: ConsensusPosition,
        actual_role: ConsensusVoteRole,
    },
    UnknownPreparedVote,
    StalePreparedVote,
    UnknownPreparedProposal,
    StalePreparedProposal,
    RestartedPending {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    },
    RestartedPendingProposal {
        position: ConsensusPosition,
    },
    SelfVerification(ConsensusVoteVerifyError),
    SelfVerificationMismatch(FixedValidatorVoteCompletionMismatchV0),
    ProposalPreparation(FixedValidatorProposalIntentErrorV0),
    ProposalSelfVerification(FixedValidatorProposalIntentErrorV0),
    ProposalRecovery(FixedValidatorProposalIntentErrorV0),
    ProposalActivationWhileLivePending,
    ProposalReplayLimitMismatch {
        retained: u64,
        supplied: u64,
    },
    NonMonotonicProposal {
        previous: ConsensusPosition,
        actual: ConsensusPosition,
    },
    TerminalHalt {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    },
    TerminalProposalHalt {
        position: ConsensusPosition,
    },
    TerminalFinalityConflictSignerStop {
        height: ConsensusHeight,
    },
    Commit {
        proposed_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
        source: io::Error,
    },
    Poisoned,
}

impl fmt::Display for FixedValidatorVoteSafetyJournalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => write!(formatter, "vote-safety lock file failed: {source}"),
            Self::Locked => formatter.write_str("this consensus key's vote-safety journal is already exclusively open"),
            Self::Lock { source } => write!(formatter, "vote-safety journal locking failed: {source}"),
            Self::PathAllocation => formatter.write_str("vote-safety journal path could not allocate"),
            Self::Create { source } => write!(formatter, "vote-safety journal creation failed: {source}"),
            Self::Open { source } => write!(formatter, "vote-safety journal opening failed: {source}"),
            Self::Read { offset, source } => write!(formatter, "vote-safety journal read failed at byte {offset}: {source}"),
            Self::InvalidHeader => formatter.write_str("invalid fixed-validator vote-safety journal header"),
            Self::HeaderMismatch => formatter.write_str("vote-safety journal header does not match the expected context, fixed set, signer, and replay limit"),
            Self::InvalidRecordLength { entry, offset, actual, minimum, maximum } => write!(formatter, "vote-safety record {entry} at byte {offset} has body length {actual}, expected {minimum}..={maximum}, the exact signed-vote width, signing-lineage width, finality-stop width, or bounded higher-round checkpoint width"),
            Self::EntryOffsetOverflow { entry, offset } => write!(formatter, "vote-safety record {entry} at byte {offset} exceeds the offset range"),
            Self::Allocation { entry, bytes } => write!(formatter, "vote-safety record {entry} could not allocate {bytes} bytes"),
            Self::HistoryAllocation { entry, retained_votes } => write!(formatter, "vote-safety record {entry} could not grow history beyond {retained_votes} prepared votes"),
            Self::ProposalHistoryAllocation { entry, retained_proposals } => write!(formatter, "vote-safety record {entry} could not grow history beyond {retained_proposals} prepared proposals"),
            Self::InvalidRecordTag { entry, offset, actual } => write!(formatter, "vote-safety record {entry} at byte {offset} has unsupported tag {actual}"),
            Self::InvalidSigningLineageLength { entry, actual } => write!(formatter, "signing-lineage record {entry} has {actual} payload bytes"),
            Self::InvalidSigningLineageHeight { entry, actual } => write!(formatter, "signing-lineage record {entry} has reserved height {}", actual.value()),
            Self::SigningLineageWhilePending { entry } => write!(formatter, "signing-lineage record {entry} follows an uncompleted vote preparation"),
            Self::SigningLineageHeightExhausted { entry, previous } => write!(formatter, "signing-lineage record {entry} cannot advance exhausted height {}", previous.value()),
            Self::NonSequentialSigningLineage { entry, expected, actual } => write!(formatter, "signing-lineage record {entry} has height {}, expected {}", actual.value(), expected.value()),
            Self::VoteOutsideSigningLineage { entry, lineage_height, vote_height } => write!(formatter, "vote record {entry} has height {}, outside retained signing-lineage height {}", vote_height.value(), lineage_height.value()),
            Self::RecordStateIdMismatch { entry, offset, expected, actual } => write!(formatter, "vote-safety record {entry} at byte {offset} commits state {actual:?}, expected {expected:?}"),
            Self::Intent { entry, offset, source } => write!(formatter, "vote-safety intent record {entry} at byte {offset} failed strict replay: {source}"),
            Self::ProposalIntent { entry, offset, source } => write!(formatter, "proposal-intent record {entry} at byte {offset} failed strict replay: {source}"),
            Self::IntentHeaderMismatch => formatter.write_str("sealed vote intent does not match this journal's exact context, fixed set, and signer"),
            Self::FinalityConflictContextMismatch => formatter.write_str("finality-conflict stop authority does not match this vote journal's exact consensus context"),
            Self::FinalityConflictFixedSetMismatch => formatter.write_str("finality-conflict stop authority does not match this vote journal's fixed validator set"),
            Self::SigningSessionAlreadyIssued => formatter.write_str("this open vote-safety journal handle has already issued its sole signing session"),
            Self::SigningSessionRoundMismatch => formatter.write_str("signing-session round does not match this journal's exact context and fixed set"),
            Self::SigningLineageRequired => formatter.write_str("a durable signing-lineage binding is required before session issuance"),
            Self::SigningLineageMismatch { expected_height, actual_height } => write!(formatter, "signing-session lineage at height {} does not match retained height {}", actual_height.value(), expected_height.value()),
            Self::ExternalSessionAnchorMismatch { required, acknowledged } => write!(formatter, "external session acknowledgement names state {acknowledged:?}, expected current state {required:?}"),
            Self::ForeignSignerRecovery => formatter.write_str("recovered signer branch belongs to another open vote-safety journal handle"),
            Self::StaleSignerRecovery { recovered, current } => write!(formatter, "recovered signer branch names vote state {recovered:?}, but the current state is {current:?}"),
            Self::SignerRecoveryRoundLimitExceeded { required, maximum } => write!(formatter, "signer recovery requires round {required}, above caller-local ceiling {maximum}"),
            Self::SignerRecoveryPositionMismatch { required, actual } => write!(formatter, "recovered signer branch begins at {actual:?}, but anchored recovery requires {required:?}"),
            Self::SignerRecoveryRound(source) => write!(formatter, "signer recovery could not derive its exact sequential round: {source}"),
            Self::LockState(source) => write!(formatter, "vote-safety signing-session lock-state transition failed: {source}"),
            Self::SigningSessionIntent(source) => write!(formatter, "vote-safety signing session could not seal or restore its exact intent state: {source}"),
            Self::HigherRoundCheckpoint { entry, offset, source } => write!(formatter, "higher-round checkpoint record {entry} at byte {offset} failed structural replay: {source}"),
            Self::HigherRoundCheckpointReplay(source) => write!(formatter, "higher-round checkpoint failed exact typed replay: {source}"),
            Self::HigherRoundCheckpointWithoutLineage { entry } => write!(formatter, "higher-round checkpoint record {entry} has no retained signing lineage"),
            Self::HigherRoundCheckpointWhilePending { entry } => write!(formatter, "higher-round checkpoint record {entry} follows an uncompleted vote preparation"),
            Self::HigherRoundCheckpointOutsideLineage { entry, lineage_height, checkpoint_height } => write!(formatter, "higher-round checkpoint record {entry} has height {}, outside retained signing-lineage height {}", checkpoint_height.value(), lineage_height.value()),
            Self::HigherRoundCheckpointSourceBehindState { entry, current_position, current_phase, source_position, source_phase } => write!(formatter, "higher-round checkpoint record {entry} starts at {source_position:?}/{source_phase:?}, behind durable state {current_position:?}/{current_phase:?}"),
            Self::VoteStateDoesNotFollowHigherRoundCheckpoint { entry, checkpoint_position, checkpoint_phase, vote_position, vote_phase } => write!(formatter, "vote state in record {entry} at {vote_position:?}/{vote_phase:?} does not follow higher-round checkpoint {checkpoint_position:?}/{checkpoint_phase:?}"),
            Self::ExternalPrepareAnchorMismatch { prepared, acknowledged } => write!(formatter, "external durability acknowledgement names state {acknowledged:?}, expected prepared state {prepared:?}"),
            Self::ForeignPrepareAcknowledgement => formatter.write_str("external durability acknowledgement belongs to another signing session"),
            Self::SignedVote { entry, offset, source } => write!(formatter, "signed-vote record {entry} at byte {offset} failed strict verification: {source}"),
            Self::InvalidCompletionLength { entry, actual } => write!(formatter, "signed-vote record {entry} has {actual} payload bytes"),
            Self::CompletionMismatch { entry, reason } => write!(formatter, "signed-vote record {entry} does not complete its exact preparation: {reason:?}"),
            Self::CompletionWithoutPrepare { entry } => write!(formatter, "signed-vote record {entry} has no pending preparation"),
            Self::InvalidProposalActivationLength { entry, actual } => write!(formatter, "proposal-authoring activation record {entry} has {actual} payload bytes"),
            Self::DuplicateProposalActivation { entry } => write!(formatter, "proposal-authoring activation record {entry} repeats an existing activation"),
            Self::ProposalActivationWhilePending { entry } => write!(formatter, "proposal-authoring activation record {entry} follows an uncompleted preparation"),
            Self::InvalidProposalActivation { entry } => write!(formatter, "proposal-authoring activation record {entry} contains a zero replay limit"),
            Self::ProposalAuthoringNotActivated => formatter.write_str("proposal authoring has not been activated for this vote-safety journal"),
            Self::ProposalReplayLimitExceeded { entry, maximum } => write!(formatter, "proposal prepare record {entry} exceeds replay ceiling {maximum}"),
            Self::ProposalWithoutSigningLineage { entry } => write!(formatter, "proposal prepare record {entry} has no retained signing lineage"),
            Self::ProposalOutsideSigningLineage { entry, lineage_height, proposal_height } => write!(formatter, "proposal record {entry} has height {}, outside retained signing-lineage height {}", proposal_height.value(), lineage_height.value()),
            Self::DuplicateProposalPrepare { entry } => write!(formatter, "proposal prepare record {entry} repeats an existing proposal slot"),
            Self::NonMonotonicProposalReplay { entry, previous, actual } => write!(formatter, "proposal prepare record {entry} moves backward from {previous:?} to {actual:?}"),
            Self::ProposalAfterVote { proposal, vote, vote_role } => write!(formatter, "proposal slot {proposal:?} does not precede retained vote {vote:?}/{vote_role:?}"),
            Self::VoteBeforeProposal { vote, vote_role, proposal } => write!(formatter, "vote slot {vote:?}/{vote_role:?} precedes retained proposal {proposal:?}"),
            Self::ProposalStateBehindCurrent { proposal, current_position, current_phase } => write!(formatter, "proposal state {proposal:?}/Proposal is behind durable state {current_position:?}/{current_phase:?}"),
            Self::ProposalCompletionWithoutPrepare { entry } => write!(formatter, "completed-proposal record {entry} has no pending proposal preparation"),
            Self::CompletedProposal { entry, source } => write!(formatter, "completed-proposal record {entry} failed strict verification: {source}"),
            Self::InvalidProposalConflictHalt { entry } => write!(formatter, "proposal-conflict record {entry} is not a non-identical intent at an existing proposal slot"),
            Self::PrepareWhilePending { entry } => write!(formatter, "prepare record {entry} follows an uncompleted preparation"),
            Self::DuplicatePrepare { entry } => write!(formatter, "prepare record {entry} repeats an existing vote slot instead of using idempotent in-memory classification"),
            Self::InvalidConflictHalt { entry } => write!(formatter, "conflict record {entry} is not a non-identical intent at an existing vote slot"),
            Self::InvalidFinalityConflictSignerStopLength { entry, actual } => write!(formatter, "finality-conflict signer-stop record {entry} has {actual} payload bytes"),
            Self::InvalidFinalityConflictSignerStop { entry } => write!(formatter, "finality-conflict signer-stop record {entry} has an invalid reserved height"),
            Self::ConflictingFinalityConflictSignerStop { retained_height, incoming_height } => write!(formatter, "signer already stopped for finality conflict at height {}, so conflict at height {} cannot replace it", retained_height.value(), incoming_height.value()),
            Self::RecordAfterHalt { offset } => write!(formatter, "vote-safety journal contains bytes after terminal halt at byte {offset}"),
            Self::ReplayLimitExceeded { entry, maximum } => write!(formatter, "prepare record {entry} exceeds replay ceiling {maximum}"),
            Self::NonMonotonicReplay { entry, previous, previous_role, actual, actual_role } => write!(formatter, "prepare record {entry} moves backward from {previous:?}/{previous_role:?} to {actual:?}/{actual_role:?}"),
            Self::ExpectedStateIdMismatch { expected, actual } => write!(formatter, "vote-safety journal state mismatch: expected {expected:?}, replayed {actual:?}"),
            Self::AnchorBehind { anchored_sequence, journal_sequence } => write!(formatter, "vote-safety anchor is behind at sequence {anchored_sequence}; the journal has {journal_sequence} complete frames"),
            Self::AnchorAhead { anchored_sequence, journal_sequence } => write!(formatter, "vote-safety anchor is ahead at sequence {anchored_sequence}; the journal has {journal_sequence} complete frames"),
            Self::AnchorStateMismatch { sequence } => write!(formatter, "vote-safety anchor and journal have different state identities at sequence {sequence}"),
            Self::RecordSequenceExhausted => formatter.write_str("vote-safety journal frame sequence is exhausted"),
            Self::Recovery { offset, source } => write!(formatter, "incomplete vote-safety tail at byte {offset} could not be recovered: {source}"),
            Self::Stabilize { source } => write!(formatter, "replayed vote-safety journal stabilization failed: {source}"),
            Self::PendingPreparation { position, role } => write!(formatter, "vote {position:?}/{role:?} must complete before another slot can prepare"),
            Self::PendingProposalPreparation { position } => write!(formatter, "proposal {position:?} must complete before another slot can prepare"),
            Self::PendingHeightAdvance { state_id } => write!(formatter, "signer-height advance at vote-journal state {state_id:?} must be externally acknowledged before another transition"),
            Self::PendingHigherRoundAdvance { state_id } => write!(formatter, "higher-round checkpoint at vote-journal state {state_id:?} must be externally acknowledged before another transition"),
            Self::ExternalHeightAnchorMismatch { prepared, acknowledged } => write!(formatter, "external height-advance acknowledgement names state {acknowledged:?}, expected prepared state {prepared:?}"),
            Self::ForeignHeightAdvance => formatter.write_str("prepared signer-height advance belongs to another signing session"),
            Self::StaleHeightAdvance => formatter.write_str("prepared signer-height advance does not match the current durable lineage"),
            Self::ExternalHigherRoundAnchorMismatch { prepared, acknowledged } => write!(formatter, "external higher-round acknowledgement names state {acknowledged:?}, expected checkpoint state {prepared:?}"),
            Self::ForeignHigherRoundAdvance => formatter.write_str("prepared higher-round advance belongs to another signing session"),
            Self::StaleHigherRoundAdvance => formatter.write_str("prepared higher-round advance does not match the current durable checkpoint"),
            Self::PendingRecoveryDenied { position, role } => write!(formatter, "completed lock-state recovery is denied behind pending vote {position:?}/{role:?}"),
            Self::PendingProposalRecoveryDenied { position } => write!(formatter, "completed lock-state recovery is denied behind pending proposal {position:?}"),
            Self::PrepareLimitExceeded { maximum } => write!(formatter, "prepared-vote ceiling {maximum} is exhausted"),
            Self::ProposalPrepareLimitExceeded { maximum } => write!(formatter, "prepared-proposal ceiling {maximum} is exhausted"),
            Self::NonMonotonicSlot { previous, previous_role, actual, actual_role } => write!(formatter, "vote slot {actual:?}/{actual_role:?} does not follow retained {previous:?}/{previous_role:?}"),
            Self::UnknownPreparedVote => formatter.write_str("prepared-vote capability does not name retained state"),
            Self::StalePreparedVote => formatter.write_str("prepared-vote capability does not match the current durable preparation"),
            Self::UnknownPreparedProposal => formatter.write_str("prepared-proposal capability does not name retained state"),
            Self::StalePreparedProposal => formatter.write_str("prepared-proposal capability does not match the current durable preparation"),
            Self::RestartedPending { position, role } => write!(formatter, "reopened vote-safety journal has a non-signable pending preparation at {position:?}/{role:?}"),
            Self::RestartedPendingProposal { position } => write!(formatter, "reopened vote-safety journal has a non-signable pending proposal at {position:?}"),
            Self::SelfVerification(source) => write!(formatter, "new local signature failed strict consensus self-verification: {source}"),
            Self::SelfVerificationMismatch(reason) => write!(formatter, "new local signature verified as the wrong prepared vote field: {reason:?}"),
            Self::ProposalPreparation(source) => write!(formatter, "proposal authoring input was rejected before durable preparation: {source}"),
            Self::ProposalSelfVerification(source) => write!(formatter, "new local producer signature failed strict proposal self-verification: {source}"),
            Self::ProposalRecovery(source) => write!(formatter, "completed proposal state failed strict signer recovery: {source}"),
            Self::ProposalActivationWhileLivePending => formatter.write_str("proposal authoring cannot activate while a live preparation is pending"),
            Self::ProposalReplayLimitMismatch { retained, supplied } => write!(formatter, "proposal replay limit {supplied} does not match retained activation {retained}"),
            Self::NonMonotonicProposal { previous, actual } => write!(formatter, "proposal slot {actual:?} does not follow retained proposal {previous:?}"),
            Self::TerminalHalt { position, role } => write!(formatter, "vote-safety journal is terminally halted at {position:?}/{role:?}"),
            Self::TerminalProposalHalt { position } => write!(formatter, "vote-safety journal is terminally halted at proposal {position:?}"),
            Self::TerminalFinalityConflictSignerStop { height } => write!(formatter, "vote-safety journal is terminally stopped by finality conflict at height {}", height.value()),
            Self::Commit { proposed_state_id, source } => write!(formatter, "vote-safety append proposing state {proposed_state_id:?} has unknown durability: {source}"),
            Self::Poisoned => formatter.write_str("vote-safety journal is poisoned after ambiguous I/O; drop it and reopen with a trusted state ID"),
        }
    }
}

impl Error for FixedValidatorVoteSafetyJournalErrorV0 {
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
            Self::Intent { source, .. } => Some(source),
            Self::ProposalIntent { source, .. }
            | Self::CompletedProposal { source, .. }
            | Self::ProposalPreparation(source)
            | Self::ProposalSelfVerification(source)
            | Self::ProposalRecovery(source) => Some(source),
            Self::SignerRecoveryRound(source) => Some(source),
            Self::LockState(source) => Some(source),
            Self::SigningSessionIntent(source) => Some(source),
            Self::HigherRoundCheckpoint { source, .. }
            | Self::HigherRoundCheckpointReplay(source) => Some(source),
            Self::SignedVote { source, .. } | Self::SelfVerification(source) => Some(source),
            _ => None,
        }
    }
}
