//! Typed transition, intent, and checkpoint failures.

use super::*;

/// A rejected durable higher-round checkpoint decode or typed reconstruction.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorHigherRoundCheckpointErrorV0 {
    InputTooLong {
        actual: usize,
        maximum: usize,
    },
    InputTooShort {
        actual: usize,
        minimum: usize,
    },
    InvalidHeader,
    State(FixedValidatorVoteIntentError),
    HeightMismatch {
        source: ConsensusHeight,
        target: ConsensusHeight,
    },
    NotStrictlyHigher {
        source: ConsensusRound,
        target: ConsensusRound,
    },
    SourceStateBindingMismatch,
    Certificate(QuorumCertificateVerifyError),
    CertificateContextMismatch,
    CertificatePositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    PhaseRoleMismatch {
        phase: FixedValidatorLockPhaseV0,
        role: ConsensusVoteRole,
    },
    CertificateStateMismatch,
    NonCanonicalEncoding,
    AllocationFailed,
}

impl fmt::Display for FixedValidatorHigherRoundCheckpointErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "higher-round checkpoint length {actual} exceeds {maximum} bytes"
            ),
            Self::InputTooShort { actual, minimum } => write!(
                formatter,
                "higher-round checkpoint length {actual} is shorter than {minimum} bytes"
            ),
            Self::InvalidHeader => formatter.write_str("invalid higher-round checkpoint header"),
            Self::State(source) => write!(formatter, "invalid checkpoint lock state: {source}"),
            Self::HeightMismatch { source, target } => write!(
                formatter,
                "higher-round checkpoint moves from height {} to height {}",
                source.value(),
                target.value()
            ),
            Self::NotStrictlyHigher { source, target } => write!(
                formatter,
                "checkpoint target round {} is not higher than source round {}",
                target.value(),
                source.value()
            ),
            Self::SourceStateBindingMismatch => {
                formatter.write_str("checkpoint source-state binding does not match its state")
            }
            Self::Certificate(source) => source.fmt(formatter),
            Self::CertificateContextMismatch => {
                formatter.write_str("checkpoint certificate belongs to another context")
            }
            Self::CertificatePositionMismatch { expected, actual } => write!(
                formatter,
                "checkpoint certificate position {actual:?} differs from target {expected:?}"
            ),
            Self::PhaseRoleMismatch { phase, role } => write!(
                formatter,
                "checkpoint phase {phase:?} does not correspond to certificate role {role:?}"
            ),
            Self::CertificateStateMismatch => formatter
                .write_str("typed checkpoint certificate differs from retained checkpoint state"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("higher-round checkpoint differs from canonical re-encoding")
            }
            Self::AllocationFailed => {
                formatter.write_str("memory allocation failed for higher-round checkpoint")
            }
        }
    }
}

impl Error for FixedValidatorHigherRoundCheckpointErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::State(source) => Some(source),
            Self::Certificate(source) => Some(source),
            _ => None,
        }
    }
}

/// A rejected vote-intent preparation, replay, or typed-round reconstruction.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorVoteIntentError {
    InputTooLong {
        actual: usize,
        maximum: usize,
    },
    InputTooShort {
        actual: usize,
        minimum: usize,
    },
    InvalidHeader,
    ContextMismatch,
    FixedAgreementSetMismatch,
    SignerMismatch,
    SignerNotInFixedSet {
        signer: ConsensusKey,
    },
    UnknownPresenceTag {
        actual: u8,
    },
    NonCanonicalAbsentHeight,
    ReservedGenesisHeight,
    ParentHeightExhausted,
    NonSequentialHeight {
        parent: Option<ConsensusHeight>,
        current: ConsensusHeight,
    },
    UnknownPhaseTag {
        actual: u8,
    },
    UnknownRoleTag {
        actual: u8,
    },
    UnknownTargetTag {
        actual: u8,
    },
    NonCanonicalNilTarget,
    TruncatedEncoding,
    TrailingBytes {
        actual: usize,
        expected: usize,
    },
    NonCanonicalEncoding,
    AllocationFailed,
    Value(ConsensusValueError),
    RetainedCertificate(QuorumCertificateVerifyError),
    RetainedCertificateIdMismatch,
    RetainedCertificateStateMismatch,
    StateValueBranchMismatch,
    LockWithoutValidValue,
    LockValidValueMismatch {
        locked_round: ConsensusRound,
        valid_round: ConsensusRound,
    },
    CurrentRoundLockBeforePrecommit,
    CurrentValidWithoutMatchingLock,
    FutureLockedRound {
        locked: ConsensusRound,
        current: ConsensusRound,
    },
    FutureValidRound {
        valid: ConsensusRound,
        current: ConsensusRound,
    },
    ValidRoundBeforeLock {
        locked: ConsensusRound,
        valid: ConsensusRound,
    },
    EffectPositionMismatch {
        state: ConsensusPosition,
        effect: ConsensusPosition,
    },
    EffectPhaseMismatch {
        phase: FixedValidatorLockPhaseV0,
        role: ConsensusVoteRole,
    },
    EffectStateMismatch,
    EffectLineageMismatch,
    EffectTargetMismatch,
    RoundBranchMismatch,
    RoundPositionMismatch {
        record: ConsensusPosition,
        round: ConsensusPosition,
    },
    LockState(FixedValidatorLockStateError),
}

impl fmt::Display for FixedValidatorVoteIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "fixed-validator vote-intent record length {actual} exceeds {maximum} bytes"
            ),
            Self::InputTooShort { actual, minimum } => write!(
                formatter,
                "fixed-validator vote-intent record length {actual} is shorter than {minimum} bytes"
            ),
            Self::InvalidHeader => {
                formatter.write_str("invalid fixed-validator vote-intent header")
            }
            Self::ContextMismatch => {
                formatter.write_str("vote-intent context differs from the expected context")
            }
            Self::FixedAgreementSetMismatch => {
                formatter.write_str("vote-intent fixed agreement set differs from the expected set")
            }
            Self::SignerMismatch => {
                formatter.write_str("vote-intent signer differs from the expected local signer")
            }
            Self::SignerNotInFixedSet { signer } => write!(
                formatter,
                "vote-intent signer is not active in the fixed set: {signer:?}"
            ),
            Self::UnknownPresenceTag { actual } => {
                write!(formatter, "unknown vote-intent presence tag {actual}")
            }
            Self::NonCanonicalAbsentHeight => {
                formatter.write_str("absent parent height has nonzero payload")
            }
            Self::ReservedGenesisHeight => {
                formatter.write_str("vote-intent state uses reserved consensus height zero")
            }
            Self::ParentHeightExhausted => {
                formatter.write_str("vote-intent parent height has no representable child")
            }
            Self::NonSequentialHeight { parent, current } => write!(
                formatter,
                "vote-intent height {current:?} is not the direct child of parent height {parent:?}"
            ),
            Self::UnknownPhaseTag { actual } => {
                write!(formatter, "unknown vote-intent phase tag {actual}")
            }
            Self::UnknownRoleTag { actual } => {
                write!(formatter, "unknown vote-intent role tag {actual}")
            }
            Self::UnknownTargetTag { actual } => {
                write!(formatter, "unknown vote-intent target tag {actual}")
            }
            Self::NonCanonicalNilTarget => {
                formatter.write_str("nil vote-intent target has nonzero payload")
            }
            Self::TruncatedEncoding => {
                formatter.write_str("vote-intent record ends inside a declared field")
            }
            Self::TrailingBytes { actual, expected } => write!(
                formatter,
                "vote-intent record has {actual} bytes; decoded fields consume {expected}"
            ),
            Self::NonCanonicalEncoding => {
                formatter.write_str("vote-intent record differs from its canonical re-encoding")
            }
            Self::AllocationFailed => {
                formatter.write_str("memory allocation failed for the bounded vote-intent record")
            }
            Self::Value(error) => error.fmt(formatter),
            Self::RetainedCertificate(error) => error.fmt(formatter),
            Self::RetainedCertificateIdMismatch => formatter
                .write_str("retained prevote certificate identity does not match its exact bytes"),
            Self::RetainedCertificateStateMismatch => formatter.write_str(
                "retained prevote certificate does not match the retained valid value and round",
            ),
            Self::StateValueBranchMismatch => {
                formatter.write_str("retained lock or valid value belongs to another branch state")
            }
            Self::LockWithoutValidValue => {
                formatter.write_str("retained lock has no retained valid value evidence")
            }
            Self::LockValidValueMismatch {
                locked_round,
                valid_round,
            } => write!(
                formatter,
                "lock at round {locked_round:?} and valid value at round {valid_round:?} differ"
            ),
            Self::CurrentRoundLockBeforePrecommit => {
                formatter.write_str("current-round lock exists before the post-precommit phase")
            }
            Self::CurrentValidWithoutMatchingLock => formatter
                .write_str("current-round valid value lacks the matching post-precommit lock"),
            Self::FutureLockedRound { locked, current } => write!(
                formatter,
                "locked round {locked:?} is later than current round {current:?}"
            ),
            Self::FutureValidRound { valid, current } => write!(
                formatter,
                "valid round {valid:?} is later than current round {current:?}"
            ),
            Self::ValidRoundBeforeLock { locked, valid } => write!(
                formatter,
                "valid round {valid:?} is earlier than locked round {locked:?}"
            ),
            Self::EffectPositionMismatch { state, effect } => write!(
                formatter,
                "vote effect position {effect:?} differs from state position {state:?}"
            ),
            Self::EffectPhaseMismatch { phase, role } => write!(
                formatter,
                "vote role {role:?} is inconsistent with post-effect phase {phase:?}"
            ),
            Self::EffectStateMismatch => {
                formatter.write_str("vote effect was emitted for another post-effect state")
            }
            Self::EffectLineageMismatch => {
                formatter.write_str("vote effect was emitted by another live lock-state lineage")
            }
            Self::EffectTargetMismatch => formatter
                .write_str("vote target is inconsistent with the retained post-effect lock"),
            Self::RoundBranchMismatch => {
                formatter.write_str("vote-intent state belongs to another typed consensus branch")
            }
            Self::RoundPositionMismatch { record, round } => write!(
                formatter,
                "vote-intent position {record:?} differs from typed round {round:?}"
            ),
            Self::LockState(error) => error.fmt(formatter),
        }
    }
}

impl Error for FixedValidatorVoteIntentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Value(error) => Some(error),
            Self::RetainedCertificate(error) => Some(error),
            Self::LockState(error) => Some(error),
            _ => None,
        }
    }
}

/// A rejected in-memory fixed-validator locking operation.
///
/// Every error leaves position, phase, lock, and valid value unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorLockStateError {
    /// Empty lock state may start only at round zero.
    InitialRoundNotZero { actual: ConsensusRound },
    /// The operation is not valid in the current local decision phase.
    UnexpectedPhase {
        expected: FixedValidatorLockPhaseV0,
        actual: FixedValidatorLockPhaseV0,
    },
    /// The proposal was admitted against another parent branch.
    ProposalBranchMismatch,
    /// The proposal does not belong to the state's exact current position.
    ProposalPositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// A proof-derived proposal valid round is not strictly earlier than current.
    InvalidValidRound {
        valid_round: ConsensusRound,
        current_round: ConsensusRound,
    },
    /// Valid-round metadata and retained certificate evidence disagree.
    InconsistentValidRoundProof,
    /// Another exact value has verified prevote-quorum evidence at the same
    /// latest valid round.
    ///
    /// The state remains unchanged and returns no vote effect. This volatile
    /// error does not persist the conflict or itself establish durable halt,
    /// equivocation adjudication, punishment, or finality authority.
    ConflictingValidValue {
        round: ConsensusRound,
        retained: ProposalSigningRoot,
        observed: ProposalSigningRoot,
    },
    /// The quorum certificate belongs to another consensus context.
    QuorumContextMismatch,
    /// Exact-round quorum verification against the fixed set failed.
    QuorumVerification(QuorumCertificateVerifyError),
    /// The quorum certificate does not belong to the exact current position.
    QuorumPositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// The supplied quorum certificate authenticates precommits, not prevotes.
    QuorumRoleMismatch { actual: ConsensusVoteRole },
    /// The quorum target does not equal the exact expected nil or proposal root.
    QuorumTargetMismatch {
        expected: ConsensusVoteTarget,
        actual: ConsensusVoteTarget,
    },
    /// Nil-precommit round advancement received another quorum vote role.
    NilPrecommitQuorumRoleMismatch { actual: ConsensusVoteRole },
    /// Nil-precommit round advancement received a non-nil quorum target.
    NilPrecommitQuorumTargetMismatch { actual: ConsensusVoteTarget },
    /// A sequential cursor belongs to another parent branch or height base.
    RoundBranchMismatch,
    /// The supplied current-round cursor belongs to another parent or height base.
    CurrentRoundBranchMismatch,
    /// The supplied current-round cursor is not the state's exact position.
    CurrentRoundPositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// The caller-local higher-round work ceiling is reserved at zero.
    HigherRoundWorkLimitNotPositive,
    /// The unauthenticated certificate routing position failed strict framing.
    HigherRoundCertificatePosition(QuorumCertificateVerifyError),
    /// The embedded higher-round certificate names another height.
    HigherRoundHeightMismatch {
        expected: ConsensusHeight,
        actual: ConsensusHeight,
    },
    /// The embedded certificate round is not strictly above current state.
    HigherRoundNotStrictlyGreater {
        current: ConsensusRound,
        actual: ConsensusRound,
    },
    /// The embedded round exceeds caller-local sequential work policy.
    HigherRoundLimitExceeded {
        round: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The authenticated higher-round quorum names another expected position.
    HigherRoundQuorumPositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// The authenticated higher-round quorum has another expected role.
    HigherRoundQuorumRoleMismatch {
        expected: ConsensusVoteRole,
        actual: ConsensusVoteRole,
    },
    /// The authenticated higher-round quorum has another expected target.
    HigherRoundQuorumTargetMismatch {
        expected: ConsensusVoteTarget,
        actual: ConsensusVoteTarget,
    },
    /// The exact internally selected higher-round cursor could not be derived.
    HigherRoundDerivation(ProposerSelectionError),
    /// The durable checkpoint bytes could not be allocated.
    HigherRoundCheckpointAllocationFailed,
    /// A prepared higher-round transition belongs to another live lineage.
    HigherRoundAdvanceLineageMismatch,
    /// State changed after a higher-round transition was prepared.
    HigherRoundAdvanceStateMismatch,
    /// The current round cannot be incremented without overflow.
    RoundExhausted,
    /// The exact next branch-derived round could not be constructed.
    NextRoundDerivation(ProposerSelectionError),
    /// The supplied cursor is not the exact next position.
    NonSequentialRound {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// A verified height transition was produced from another parent branch.
    HeightTransitionParentMismatch,
    /// A verified transition does not complete the lock state's current height.
    HeightTransitionHeightMismatch {
        expected: ConsensusHeight,
        actual: ConsensusHeight,
    },
    /// The verified child cannot derive the next height's round-zero cursor.
    HeightTransitionRoundZero(ProposerSelectionError),
    /// Retaining canonical verified quorum evidence could not allocate memory.
    CertificateAllocationFailed,
}

impl fmt::Display for FixedValidatorLockStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialRoundNotZero { actual } => write!(
                formatter,
                "fixed-validator lock state must begin at round zero, not {actual:?}"
            ),
            Self::UnexpectedPhase { expected, actual } => write!(
                formatter,
                "fixed-validator lock operation requires phase {expected:?}, current phase is {actual:?}"
            ),
            Self::ProposalBranchMismatch => formatter
                .write_str("admitted proposal belongs to another fixed consensus parent branch"),
            Self::ProposalPositionMismatch { expected, actual } => write!(
                formatter,
                "admitted proposal position {actual:?} differs from current position {expected:?}"
            ),
            Self::InvalidValidRound {
                valid_round,
                current_round,
            } => write!(
                formatter,
                "proposal valid round {valid_round:?} is not earlier than current round {current_round:?}"
            ),
            Self::InconsistentValidRoundProof => formatter.write_str(
                "proposal valid-round metadata and canonical prevote proof are inconsistent",
            ),
            Self::ConflictingValidValue {
                round,
                retained,
                observed,
            } => write!(
                formatter,
                "valid round {round:?} has conflicting retained {retained:?} and observed {observed:?} proposal roots"
            ),
            Self::QuorumContextMismatch => formatter
                .write_str("prevote quorum context differs from the current consensus context"),
            Self::QuorumVerification(error) => error.fmt(formatter),
            Self::QuorumPositionMismatch { expected, actual } => write!(
                formatter,
                "prevote quorum position {actual:?} differs from current position {expected:?}"
            ),
            Self::QuorumRoleMismatch { actual } => write!(
                formatter,
                "current-round quorum must authenticate prevotes, not {actual:?}"
            ),
            Self::QuorumTargetMismatch { expected, actual } => write!(
                formatter,
                "prevote quorum target {actual:?} differs from expected target {expected:?}"
            ),
            Self::NilPrecommitQuorumRoleMismatch { actual } => write!(
                formatter,
                "round advancement requires precommit quorum evidence, not {actual:?}"
            ),
            Self::NilPrecommitQuorumTargetMismatch { actual } => write!(
                formatter,
                "round advancement requires a nil precommit quorum, not {actual:?}"
            ),
            Self::RoundBranchMismatch => formatter.write_str(
                "sequential round cursor belongs to another fixed consensus parent branch",
            ),
            Self::CurrentRoundBranchMismatch => formatter
                .write_str("current round cursor belongs to another fixed consensus parent branch"),
            Self::CurrentRoundPositionMismatch { expected, actual } => write!(
                formatter,
                "current round cursor position {actual:?} differs from lock-state position {expected:?}"
            ),
            Self::HigherRoundWorkLimitNotPositive => {
                formatter.write_str("higher-round caller-local inclusive maximum must be positive")
            }
            Self::HigherRoundCertificatePosition(error) => write!(
                formatter,
                "higher-round certificate position could not be strictly inspected: {error}"
            ),
            Self::HigherRoundHeightMismatch { expected, actual } => write!(
                formatter,
                "higher-round certificate height {actual:?} differs from current height {expected:?}"
            ),
            Self::HigherRoundNotStrictlyGreater { current, actual } => write!(
                formatter,
                "certificate round {actual:?} is not strictly higher than current round {current:?}"
            ),
            Self::HigherRoundLimitExceeded { round, maximum } => write!(
                formatter,
                "certificate round {round:?} exceeds caller-local inclusive maximum {maximum:?}"
            ),
            Self::HigherRoundQuorumPositionMismatch { expected, actual } => write!(
                formatter,
                "authenticated higher-round quorum position {actual:?} differs from expected position {expected:?}"
            ),
            Self::HigherRoundQuorumRoleMismatch { expected, actual } => write!(
                formatter,
                "authenticated higher-round quorum role {actual:?} differs from expected role {expected:?}"
            ),
            Self::HigherRoundQuorumTargetMismatch { expected, actual } => write!(
                formatter,
                "authenticated higher-round quorum target {actual:?} differs from expected target {expected:?}"
            ),
            Self::HigherRoundDerivation(error) => write!(
                formatter,
                "higher-round fixed-validator cursor cannot be derived: {error}"
            ),
            Self::HigherRoundCheckpointAllocationFailed => formatter
                .write_str("memory allocation failed while sealing higher-round checkpoint bytes"),
            Self::HigherRoundAdvanceLineageMismatch => formatter
                .write_str("prepared higher-round transition belongs to another live lock lineage"),
            Self::HigherRoundAdvanceStateMismatch => formatter
                .write_str("lock state changed after the higher-round transition was prepared"),
            Self::RoundExhausted => formatter
                .write_str("fixed-validator lock state cannot advance beyond the terminal round"),
            Self::NextRoundDerivation(error) => {
                write!(
                    formatter,
                    "next fixed-validator round cannot be derived: {error}"
                )
            }
            Self::NonSequentialRound { expected, actual } => write!(
                formatter,
                "next round cursor position {actual:?} differs from exact successor {expected:?}"
            ),
            Self::HeightTransitionParentMismatch => formatter.write_str(
                "verified height transition belongs to another fixed consensus parent branch",
            ),
            Self::HeightTransitionHeightMismatch { expected, actual } => write!(
                formatter,
                "verified transition height {actual:?} differs from lock-state height {expected:?}"
            ),
            Self::HeightTransitionRoundZero(error) => write!(
                formatter,
                "verified child cannot derive its next round-zero cursor: {error}"
            ),
            Self::CertificateAllocationFailed => formatter
                .write_str("memory allocation failed while retaining canonical quorum evidence"),
        }
    }
}

impl Error for FixedValidatorLockStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::QuorumVerification(error) | Self::HigherRoundCertificatePosition(error) => {
                Some(error)
            }
            Self::NextRoundDerivation(error) | Self::HigherRoundDerivation(error) => Some(error),
            Self::HeightTransitionRoundZero(error) => Some(error),
            _ => None,
        }
    }
}
