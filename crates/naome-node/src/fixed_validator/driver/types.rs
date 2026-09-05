//! Public commands, outcomes, diagnostics, and typed failures.

use super::*;

/// Opaque identity for one driver-issued phase timer.
///
/// The ticket is copyable so a runtime can retain it while scheduling and later
/// return the same value as a due event. Its private fields prevent a runtime
/// from manufacturing another context, position, phase, generation, or driver
/// lineage. It contains no deadline and proves no elapsed time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodePhaseTimeoutV0 {
    pub(super) lineage: u64,
    pub(super) context: ConsensusContextV0,
    pub(super) position: ConsensusPosition,
    pub(super) phase: FixedValidatorLockPhaseV0,
    pub(super) generation: u64,
}

impl FixedValidatorNodePhaseTimeoutV0 {
    /// Returns the exact consensus context this timer was issued for.
    pub const fn context(self) -> ConsensusContextV0 {
        self.context
    }

    /// Returns the exact height and round this timer was issued for.
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns the exact phase this timer was issued for.
    pub const fn phase(self) -> FixedValidatorLockPhaseV0 {
        self.phase
    }

    /// Returns the process-local checked timer generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// One owned input accepted by the fixed-validator node driver.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverEventV0 {
    /// Complete raw inputs for one exact node-derived current-round proposal.
    CurrentRoundProposal {
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    },
    /// One complete canonical signed current-round proposal prevote.
    CurrentRoundProposalPrevote { canonical_signed_prevote: Box<[u8]> },
    /// One complete canonical signed current-round nil prevote.
    CurrentRoundNilPrevote { canonical_signed_prevote: Box<[u8]> },
    /// Complete raw proposal inputs retained only for current-round finality classification.
    CurrentRoundFinalityProposal {
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    },
    /// One complete canonical signed current-round proposal precommit.
    CurrentRoundProposalPrecommit {
        canonical_signed_precommit: Box<[u8]>,
    },
    /// One complete canonical signed exact-current nil precommit.
    CurrentRoundNilPrecommit {
        canonical_signed_precommit: Box<[u8]>,
    },
    /// Complete raw inputs for one descriptively routed higher-round proposal.
    HigherRoundProposal {
        proposal_round: ConsensusRound,
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    },
    /// One complete canonical signed higher-round proposal prevote.
    HigherRoundProposalPrevote { canonical_signed_prevote: Box<[u8]> },
    /// The runtime reports that one exact driver-issued phase timer is due.
    TimeoutDue(FixedValidatorNodePhaseTimeoutV0),
}

/// Observable no-growth or insertion result of one accepted driver event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverAdmissionDispositionV0 {
    /// One distinct proposal, prevote, precommit, or finality input was retained.
    Inserted,
    /// The exact proposal or vote bytes were already retained without growth.
    AlreadyRetained,
    /// The exact current timer was newly marked due.
    TimeoutMarkedDue,
    /// The exact current timer was already marked due.
    AlreadyDue,
}

/// Result of one consuming driver-event admission attempt.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverAdmissionOutcomeV0<'node> {
    /// The event was admitted or recognized as an exact no-growth duplicate.
    Admitted {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        disposition: FixedValidatorNodeDriverAdmissionDispositionV0,
    },
    /// The event was not admitted and caused no signer, consensus, or durable effect.
    ///
    /// A first capacity rejection may latch deny-only saturation while preserving
    /// the retained inbox prefix and exact event.
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        event: Box<FixedValidatorNodeDriverEventV0>,
        rejection: Box<FixedValidatorNodeDriverAdmissionRejectionV0>,
    },
}

/// One event-admission rejection with no signer, consensus, or durable effect.
///
/// A first capacity rejection may latch deny-only saturation while the returned
/// driver preserves the retained inbox prefix and exact event.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverAdmissionRejectionV0 {
    /// One outward command must transfer before another event may be admitted.
    CommandPending,
    /// Saturation or a previously detected ambiguity denies ordinary admission.
    Blocked(FixedValidatorNodeDriverBlockReasonV0),
    /// Current-round reconstruction rejected the event before input inspection.
    CurrentRound(Box<FixedValidatorNodeVoteRejectionV0>),
    /// Current-round evidence arrived after the exact active due fence.
    CurrentEvidenceAfterDue {
        position: ConsensusPosition,
        phase: FixedValidatorLockPhaseV0,
    },
    /// Current-round evidence is stale after the live Prevote phase.
    CurrentEvidenceWrongPhase { actual: FixedValidatorLockPhaseV0 },
    /// Preserving the original proposal event while verifying a payload copy failed.
    ProposalPayloadCopy(TryReserveError),
    /// The owned payload exceeds the canonical artifact-envelope byte limit.
    ProposalPayloadTooLong { actual: usize, maximum: usize },
    /// Complete higher-round proposal admission rejected the routed input.
    Proposal(Box<FixedValidatorNodeProposalDeferralRejectionV0>),
    /// Complete current-round proposal admission rejected the raw input.
    CurrentProposal(Box<ConsensusProposalVerifyError>),
    /// Exact current-round active proposal-prevote admission failed.
    CurrentPrevote(FixedConsensusProposalPrevoteVerifyErrorV0),
    /// Exact current-round active nil-prevote admission failed.
    CurrentNilPrevote(FixedConsensusNilPrevoteVerifyErrorV0),
    /// Complete current-round finality proposal admission rejected the raw input.
    CurrentFinalityProposal(Box<ConsensusProposalVerifyError>),
    /// Exact current-round active proposal-precommit admission failed.
    CurrentFinalityPrecommit(FixedConsensusProposalPrecommitVerifyErrorV0),
    /// Exact current-round active nil-precommit admission failed.
    CurrentNilPrecommit(FixedConsensusNilPrecommitVerifyErrorV0),
    /// The dedicated current proposal-finality inbox entered or retained saturation.
    CurrentFinalityInboxSaturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
        newly_saturated: bool,
    },
    /// The dedicated current proposal-finality inbox could not reserve one slot.
    CurrentFinalityInboxReservation(TryReserveError),
    /// The dedicated current nil-precommit inbox entered or retained saturation.
    CurrentNilPrecommitInboxSaturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0,
        newly_saturated: bool,
    },
    /// The dedicated current nil-precommit inbox could not reserve one slot.
    CurrentNilPrecommitInboxReservation(TryReserveError),
    /// The separate current-round inbox entered or retained saturation.
    CurrentInboxSaturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundInboxSaturationV0,
        newly_saturated: bool,
    },
    /// The separate current-round inbox could not reserve one collection slot.
    CurrentInboxReservation(TryReserveError),
    /// The bounded inbox could not retain the admitted proposal token.
    ProposalInbox(Box<FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0>),
    /// Canonical vote framing, context, key, or signature verification failed.
    PrevoteRouting(ConsensusVoteVerifyError),
    /// The authenticated vote height differs from the live branch height.
    PrevoteHeightMismatch {
        current: ConsensusHeight,
        event: ConsensusHeight,
    },
    /// The authenticated vote does not name a strictly higher round.
    PrevoteNotHigher {
        signer: ConsensusRound,
        event: ConsensusRound,
    },
    /// The authenticated vote round exceeds persisted finality work policy.
    PrevoteFinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The authenticated vote round exceeds this driver's local work ceiling.
    PrevoteRoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// Exact typed-round proposal-prevote admission or retention failed.
    PrevoteInbox(Box<FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0>),
    /// The returned timer does not equal the exact active driver ticket.
    TimeoutMismatch,
}

impl fmt::Display for FixedValidatorNodeDriverAdmissionRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandPending => formatter
                .write_str("driver event admission requires pending command transfer first"),
            Self::Blocked(source) => source.fmt(formatter),
            Self::CurrentRound(source) => source.fmt(formatter),
            Self::CurrentEvidenceAfterDue { position, phase } => write!(
                formatter,
                "current-round evidence for {position:?}/{phase:?} arrived after the active due fence"
            ),
            Self::CurrentEvidenceWrongPhase { actual } => write!(
                formatter,
                "current-round evidence is stale in {actual:?} phase"
            ),
            Self::ProposalPayloadCopy(source) => write!(
                formatter,
                "driver proposal payload copy failed before admission: {source}"
            ),
            Self::ProposalPayloadTooLong { actual, maximum } => write!(
                formatter,
                "driver proposal payload has {actual} bytes; the canonical limit is {maximum}"
            ),
            Self::Proposal(source) => source.fmt(formatter),
            Self::CurrentProposal(source) => {
                write!(formatter, "current-round proposal was rejected: {source}")
            }
            Self::CurrentPrevote(source) => {
                write!(
                    formatter,
                    "current-round proposal prevote was rejected: {source}"
                )
            }
            Self::CurrentNilPrevote(source) => {
                write!(
                    formatter,
                    "current-round nil prevote was rejected: {source}"
                )
            }
            Self::CurrentFinalityProposal(source) => {
                write!(
                    formatter,
                    "current finality proposal was rejected: {source}"
                )
            }
            Self::CurrentFinalityPrecommit(source) => write!(
                formatter,
                "current proposal precommit was rejected: {source}"
            ),
            Self::CurrentNilPrecommit(source) => {
                write!(formatter, "current nil precommit was rejected: {source}")
            }
            Self::CurrentFinalityInboxSaturated {
                position,
                saturation,
                ..
            } => write!(
                formatter,
                "current proposal-finality evidence for {position:?} was not retained because {saturation}"
            ),
            Self::CurrentFinalityInboxReservation(source) => write!(
                formatter,
                "current proposal-finality inbox reservation failed before insertion: {source}"
            ),
            Self::CurrentNilPrecommitInboxSaturated {
                position,
                saturation,
                ..
            } => write!(
                formatter,
                "current nil-precommit evidence for {position:?} was not retained because {saturation}"
            ),
            Self::CurrentNilPrecommitInboxReservation(source) => write!(
                formatter,
                "current nil-precommit inbox reservation failed before insertion: {source}"
            ),
            Self::CurrentInboxSaturated {
                position,
                saturation,
                ..
            } => write!(
                formatter,
                "current-round evidence for {position:?} was not retained because {saturation}"
            ),
            Self::CurrentInboxReservation(source) => write!(
                formatter,
                "current-round inbox reservation failed before insertion: {source}"
            ),
            Self::ProposalInbox(source) => source.fmt(formatter),
            Self::PrevoteRouting(source) => {
                write!(
                    formatter,
                    "driver proposal-prevote routing failed: {source}"
                )
            }
            Self::PrevoteHeightMismatch { current, event } => write!(
                formatter,
                "driver proposal prevote height {event:?} differs from current height {current:?}"
            ),
            Self::PrevoteNotHigher { signer, event } => write!(
                formatter,
                "driver proposal prevote round {event:?} is not above signer round {signer:?}"
            ),
            Self::PrevoteFinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "driver proposal prevote round {required:?} exceeds finality ceiling {maximum:?}"
            ),
            Self::PrevoteRoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "driver proposal prevote round {required:?} exceeds local ceiling {maximum:?}"
            ),
            Self::PrevoteInbox(source) => source.fmt(formatter),
            Self::TimeoutMismatch => formatter.write_str(
                "returned phase timer does not equal the driver's undisclosed active timer",
            ),
        }
    }
}

impl Error for FixedValidatorNodeDriverAdmissionRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProposalPayloadCopy(source) => Some(source),
            Self::Proposal(source) => Some(source.as_ref()),
            Self::CurrentRound(source) => Some(source.as_ref()),
            Self::CurrentProposal(source) => Some(source.as_ref()),
            Self::CurrentPrevote(source) => Some(source),
            Self::CurrentNilPrevote(source) => Some(source),
            Self::CurrentFinalityProposal(source) => Some(source.as_ref()),
            Self::CurrentFinalityPrecommit(source) => Some(source),
            Self::CurrentNilPrecommit(source) => Some(source),
            Self::CurrentFinalityInboxReservation(source) => Some(source),
            Self::CurrentNilPrecommitInboxReservation(source) => Some(source),
            Self::CurrentInboxReservation(source) => Some(source),
            Self::ProposalInbox(source) => Some(source.as_ref()),
            Self::PrevoteRouting(source) => Some(source),
            Self::PrevoteInbox(source) => Some(source.as_ref()),
            Self::CommandPending
            | Self::Blocked(_)
            | Self::CurrentEvidenceAfterDue { .. }
            | Self::CurrentEvidenceWrongPhase { .. }
            | Self::CurrentInboxSaturated { .. }
            | Self::CurrentFinalityInboxSaturated { .. }
            | Self::CurrentNilPrecommitInboxSaturated { .. }
            | Self::ProposalPayloadTooLong { .. }
            | Self::PrevoteHeightMismatch { .. }
            | Self::PrevoteNotHigher { .. }
            | Self::PrevoteFinalityRoundLimitExceeded { .. }
            | Self::PrevoteRoundWorkLimitExceeded { .. }
            | Self::TimeoutMismatch => None,
        }
    }
}

/// Fatal driver-event admission failure; no driver or signing scope is returned.
///
/// On `Err`, consuming admission loses both volatile owners even when the failure
/// occurs before a coordinator starts. Recover only through strict reopen into a
/// fresh driver.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverAdmissionErrorV0 {
    /// Current-round reconstruction found a fatal node or signer failure.
    CurrentRound(Box<FixedValidatorNodeVoteExecutionErrorV0>),
    /// Complete higher-round proposal admission found a fatal node failure.
    Proposal(Box<FixedValidatorNodeProposalDeferralErrorV0>),
    /// The authenticated proposal-prevote round could not be derived.
    Round(ProposerSelectionError),
}

impl fmt::Display for FixedValidatorNodeDriverAdmissionErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentRound(source) => source.fmt(formatter),
            Self::Proposal(source) => source.fmt(formatter),
            Self::Round(source) => write!(
                formatter,
                "driver proposal-prevote round derivation failed: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeDriverAdmissionErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CurrentRound(source) => Some(source.as_ref()),
            Self::Proposal(source) => Some(source.as_ref()),
            Self::Round(source) => Some(source),
        }
    }
}

/// One outward action released by a driver step after any required durability.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverCommandV0 {
    /// Schedule a timer using runtime policy, then retain this exact ticket.
    ArmPhaseTimeout(FixedValidatorNodePhaseTimeoutV0),
    /// Publish one anchored proposal with its exact owned payload.
    ///
    /// Publication preserves the current timer. Local voting requires explicit
    /// re-admission through the ordinary proposal event path.
    PublishProposal {
        proposal: FixedValidatorSignedProposalV0,
        canonical_artifact_bytes: Vec<u8>,
    },
    /// Publish one already anchored vote and assume custody of any released proposal.
    PublishVote {
        vote: FixedValidatorSignedVoteV0,
        released_proposal: Option<Box<FixedValidatorNodeDeferredProposalV0>>,
    },
}

/// Descriptive identity of one actionable higher-round proposal quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[must_use]
pub struct FixedValidatorNodeDriverActionV0 {
    pub(super) position: ConsensusPosition,
    pub(super) proposal_signing_root: ProposalSigningRoot,
}

impl FixedValidatorNodeDriverActionV0 {
    /// Returns the authenticated proposal and prevote position.
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns the proposal root with strict-supermajority prevote evidence.
    pub const fn proposal_signing_root(self) -> ProposalSigningRoot {
        self.proposal_signing_root
    }
}

/// Non-authoritative identity of one strict-supermajority proposal-precommit root.
///
/// This descriptor contains no proposal bytes, certificate, signing scope, or
/// finality handle and cannot execute a consensus transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[must_use]
#[allow(
    dead_code,
    reason = "the non-authoritative descriptor is exposed only to crate diagnostics"
)]
pub(in crate::fixed_validator) struct FixedValidatorNodeDriverFinalityActionV0 {
    pub(super) position: ConsensusPosition,
    pub(super) proposal_signing_root: ProposalSigningRoot,
}

#[allow(
    dead_code,
    reason = "the descriptor accessors are exercised only by crate diagnostics"
)]
impl FixedValidatorNodeDriverFinalityActionV0 {
    /// Returns the exact current position classified by the driver.
    pub(in crate::fixed_validator) const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns the proposal root with matching strict-supermajority precommits.
    pub(in crate::fixed_validator) const fn proposal_signing_root(self) -> ProposalSigningRoot {
        self.proposal_signing_root
    }
}

/// Read-only diagnostics for the dedicated current proposal-finality inbox.
///
/// The classification itself neither selects nor finalizes a value and exposes
/// no raw retained evidence. Driver execution uses the same private selection
/// pipeline, then owns the ready inputs and repeats complete verification through
/// the node-owned finality coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
#[allow(
    dead_code,
    reason = "the private diagnostic classification is exercised by crate tests"
)]
pub(in crate::fixed_validator) enum FixedValidatorNodeDriverCurrentFinalityClassificationV0 {
    /// No proposal-target root has retained strict-supermajority precommits.
    Incomplete,
    /// Exactly one quorate root is retained without a matching valid proposal.
    QuorumMissingProposal(FixedValidatorNodeDriverFinalityActionV0),
    /// Exactly one proposal-bearing root is locally complete.
    Ready(FixedValidatorNodeDriverFinalityActionV0),
    /// Multiple proposal roots have strict-supermajority precommits; no winner is chosen.
    ConflictingRoots {
        position: ConsensusPosition,
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
    /// A denied distinct input made the retained prefix incomplete.
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    },
}

/// A temporary or invariant failure while classifying retained finality evidence.
#[derive(Debug)]
#[non_exhaustive]
#[allow(
    dead_code,
    reason = "the private diagnostic classification is exercised by crate tests"
)]
pub(in crate::fixed_validator) enum FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0 {
    /// The exact current fixed-set round could not be derived.
    Round(ProposerSelectionError),
    /// Temporary classifier storage could not be reserved.
    Reservation(TryReserveError),
    /// Individually admitted retained votes failed exact certificate construction.
    QuorumInvariant(QuorumCertificateBuildError),
}

impl fmt::Display for FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Round(source) => write!(
                formatter,
                "current proposal-finality round derivation failed: {source}"
            ),
            Self::Reservation(source) => write!(
                formatter,
                "current proposal-finality classification reservation failed: {source}"
            ),
            Self::QuorumInvariant(source) => write!(
                formatter,
                "retained current proposal precommits violated a classifier invariant: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Reservation(source) => Some(source),
            Self::QuorumInvariant(source) => Some(source),
        }
    }
}

/// A driver-step block reason with class-specific recovery semantics.
///
/// Higher-round saturation or ambiguity requires the higher inbox's full
/// drain/reset. Current saturation requires current-only drain/reset, while
/// current proposal ambiguity is derived only for the live position and may
/// become stale after authenticated higher-round advancement. Current
/// dual-quorum ambiguity remains latched until current-only drain/reset. Healthy
/// finality missing-proposal and conflicting-root blocks are derived, remain
/// open to finality admission, and end when the classification becomes
/// nonblocking or the finality inbox is drained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverBlockReasonV0 {
    /// The bounded inbox rejected a distinct input and latched saturation.
    Saturated(FixedValidatorNodeHigherRoundInboxSaturationV0),
    /// Two distinct actions are valid in the same frozen step snapshot.
    Ambiguous {
        first: FixedValidatorNodeDriverActionV0,
        second: FixedValidatorNodeDriverActionV0,
    },
    /// The current inbox denied an input and blocks current-class work until drain.
    CurrentSaturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundInboxSaturationV0,
    },
    /// Two byte-distinct fully admitted proposals compete at the live position.
    CurrentProposalAmbiguous {
        position: ConsensusPosition,
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
    /// Both proposal and nil prevote targets have an actionable current quorum.
    CurrentPrevoteQuorumAmbiguous {
        position: ConsensusPosition,
        proposal_signing_root: ProposalSigningRoot,
    },
    /// A strict-supermajority proposal precommit certificate lacks its proposal.
    CurrentFinalityProposalMissing {
        position: ConsensusPosition,
        proposal_signing_root: ProposalSigningRoot,
    },
    /// Multiple proposal roots have strict-supermajority precommit evidence.
    CurrentFinalityRootsConflicting {
        position: ConsensusPosition,
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
}

impl fmt::Display for FixedValidatorNodeDriverBlockReasonV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Saturated(source) => source.fmt(formatter),
            Self::Ambiguous { first, second } => write!(
                formatter,
                "driver snapshot has distinct actionable proposal quorums {first:?} and {second:?}"
            ),
            Self::CurrentSaturated {
                position,
                saturation,
            } => write!(
                formatter,
                "driver current-round evidence at {position:?} is blocked because {saturation}"
            ),
            Self::CurrentProposalAmbiguous {
                position,
                first,
                second,
            } => write!(
                formatter,
                "driver has byte-distinct fully admitted proposals at {position:?} with roots {first:?} and {second:?}"
            ),
            Self::CurrentPrevoteQuorumAmbiguous {
                position,
                proposal_signing_root,
            } => write!(
                formatter,
                "driver has actionable proposal {proposal_signing_root:?} and nil prevote quorums at {position:?}"
            ),
            Self::CurrentFinalityProposalMissing {
                position,
                proposal_signing_root,
            } => write!(
                formatter,
                "driver has finality precommit quorum {proposal_signing_root:?} at {position:?} but no matching proposal"
            ),
            Self::CurrentFinalityRootsConflicting {
                position,
                first,
                second,
            } => write!(
                formatter,
                "driver has conflicting proposal-finality quorums {first:?} and {second:?} at {position:?}"
            ),
        }
    }
}

/// A mutation-free rejection returned by one driver step.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverStepRejectionV0 {
    /// Temporary driver-selection storage could not be reserved.
    SelectionReservation(TryReserveError),
    /// Existing inbox classification rejected retained evidence before mutation.
    EvidenceSelection(Box<FixedValidatorNodeBufferedProposalPrecommitRejectionV0>),
    /// The selected evidence changed or failed re-admission before mutation.
    EvidenceExecution(Box<FixedValidatorNodeBufferedProposalPrecommitRejectionV0>),
    /// A current-evidence vote or exact due Proposal/Prevote close was rejected before mutation.
    Vote(Box<FixedValidatorNodeVoteRejectionV0>),
    /// Exact-current round progression was rejected before mutation.
    RoundAdvance(Box<FixedValidatorNodeRoundAdvanceRejectionV0>),
    /// Retained finality votes violated exact certificate-construction invariants.
    CurrentFinalitySelection(Box<QuorumCertificateBuildError>),
    /// Retained nil precommits violated exact batch-construction invariants.
    CurrentNilPrecommitSelection(Box<QuorumCertificateBuildError>),
    /// Fully reverified current finality evidence was rejected before mutation.
    CurrentFinality(Box<FixedValidatorNodeCurrentRoundFinalityRejectionV0>),
}

impl fmt::Display for FixedValidatorNodeDriverStepRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectionReservation(source) => write!(
                formatter,
                "driver selection storage reservation failed: {source}"
            ),
            Self::EvidenceSelection(source) | Self::EvidenceExecution(source) => {
                source.fmt(formatter)
            }
            Self::Vote(source) => source.fmt(formatter),
            Self::RoundAdvance(source) => source.fmt(formatter),
            Self::CurrentFinalitySelection(source) => source.fmt(formatter),
            Self::CurrentNilPrecommitSelection(source) => source.fmt(formatter),
            Self::CurrentFinality(source) => source.fmt(formatter),
        }
    }
}

impl Error for FixedValidatorNodeDriverStepRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectionReservation(source) => Some(source),
            Self::EvidenceSelection(source) | Self::EvidenceExecution(source) => {
                Some(source.as_ref())
            }
            Self::Vote(source) => Some(source.as_ref()),
            Self::RoundAdvance(source) => Some(source.as_ref()),
            Self::CurrentFinalitySelection(source) => Some(source.as_ref()),
            Self::CurrentNilPrecommitSelection(source) => Some(source.as_ref()),
            Self::CurrentFinality(source) => Some(source.as_ref()),
        }
    }
}

/// Result of one explicit driver step.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverStepOutcomeV0<'node> {
    /// Exactly one already pending outward command was transferred; no transition ran.
    Command {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        command: FixedValidatorNodeDriverCommandV0,
    },
    /// Exactly one existing consuming coordinator completed; no command was emitted.
    Transitioned {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Exact current evidence reached finality and the aligned driver survives.
    Finality {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        selection: FixedValidatorNodeFinalitySelectionV0,
    },
    /// No evidence or exact due timer was actionable.
    Idle {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// A blocking inbox classification denied this step's lower-priority work.
    ///
    /// Only the existing higher/current ambiguity cases may newly latch. This
    /// outcome causes no signer or durable effect.
    Blocked {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        reason: FixedValidatorNodeDriverBlockReasonV0,
    },
    /// A selected input was rejected before any driver or signer effect.
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        rejection: Box<FixedValidatorNodeDriverStepRejectionV0>,
    },
    /// A non-identical vote intent durably stopped the signer; no driver survives.
    SignerStopped(FixedValidatorVoteSafetyHaltV0),
    /// A durable finality conflict stopped finality and the signer; no driver survives.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
}

/// Result of one explicitly routed candidate-backed historical conflict.
///
/// A pending command is the only outcome that returns the driver. Once proof
/// processing begins, both success and failure consume the driver and its sole
/// signing scope under the existing finality coordination contract.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0<'node> {
    /// An already pending outward command must transfer before proof processing.
    CommandPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// The fully verified sibling conflict durably stopped finality and the signer.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
}

/// Result of one explicit exact-current paired-conflict attempt.
///
/// Pending command custody and typed pre-effect rejection return the unchanged
/// driver. Every driver invocation consumes both owned payloads. A verified
/// distinct pair stops finality and the signer without selecting either value.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0<'node> {
    /// An already pending outward command must transfer before proof processing.
    CommandPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Caller work bounds or either complete proof failed before any node effect.
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        rejection: Box<FixedValidatorNodeCurrentRoundFinalityRejectionV0>,
    },
    /// Both independently verified proofs durably stopped finality and the signer.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
}

/// Result of one explicitly routed strictly lower-round paired-conflict attempt.
///
/// Pending command custody and typed pre-effect rejection return the unchanged
/// driver. Owned payload inputs are consumed by every outcome; this does not
/// retain or return caller evidence for retry. A verified pair stops finality
/// and the signer without selecting either proposal.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0<'node> {
    /// An already pending outward command must transfer before proof processing.
    CommandPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Route or proof input was rejected before any node effect.
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        rejection: Box<FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0>,
    },
    /// Both independently verified proofs durably stopped finality and the signer.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
}

/// Result of one explicitly routed candidate-backed direct-child finality attempt.
///
/// Pending command custody and every non-fallthrough current-finality
/// classification return the unchanged driver before candidate input or source
/// work. A typed candidate rejection likewise returns the unchanged driver
/// because the existing coordinator made no node effect.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0<'node> {
    /// An already pending outward command must transfer before classification.
    CommandPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Retained exact-current finality must be resolved through [`FixedValidatorNodeDriverV0::step`].
    CurrentFinalityUnresolved {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Candidate-backed finality completed and the aligned driver survives.
    Finality {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        selection: FixedValidatorNodeFinalitySelectionV0,
    },
    /// Candidate input or source state was rejected before any node effect.
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        rejection: Box<FixedValidatorNodeCandidateBackedFinalityRejectionV0>,
    },
    /// A defensive durable finality conflict stopped finality and the signer.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
}

/// Fatal explicit candidate-backed direct-child driver failure.
///
/// Every variant consumes the driver, its sole signing scope, timer, and all
/// volatile inbox custody. Strict anchored reopen is the only continuation path.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverCandidateBackedFinalityErrorV0 {
    /// Exact-current finality classification could not derive the live round.
    CurrentFinalityRound(ProposerSelectionError),
    /// The checked timer generation has no successor for a possible child.
    TimeoutGenerationExhausted { generation: u64 },
    /// Candidate evidence reached the existing consuming finality coordinator.
    Finality(Box<FixedValidatorNodeCandidateBackedFinalityErrorV0>),
}

impl fmt::Display for FixedValidatorNodeDriverCandidateBackedFinalityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentFinalityRound(source) => write!(
                formatter,
                "driver current-finality round could not be reconstructed: {source}"
            ),
            Self::TimeoutGenerationExhausted { generation } => write!(
                formatter,
                "driver timeout generation {generation} has no successor"
            ),
            Self::Finality(source) => source.fmt(formatter),
        }
    }
}

impl Error for FixedValidatorNodeDriverCandidateBackedFinalityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CurrentFinalityRound(source) => Some(source),
            Self::Finality(source) => Some(source.as_ref()),
            Self::TimeoutGenerationExhausted { .. } => None,
        }
    }
}

/// Result of explicit direct strictly lower-round finality through the driver.
///
/// Pending commands and non-fallthrough current-finality work retain priority.
/// Typed pre-effect rejection restores the unchanged driver; supplied owned
/// payloads are consumed on every outcome and are never retained by the driver.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0<'node> {
    /// An already pending outward command must transfer first.
    CommandPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Retained exact-current finality must be resolved through the ordinary step.
    CurrentFinalityUnresolved {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Fully verified finality completed and the aligned driver survives.
    Finality {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        selection: FixedValidatorNodeFinalitySelectionV0,
    },
    /// Caller evidence was rejected before any finality or signer effect.
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        rejection: Box<FixedValidatorNodeLowerRoundFinalityRejectionV0>,
    },
    /// The existing coordinator returned defensive terminal conflict evidence.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
}

/// Result of an explicitly supplied higher-round certificate or exact vote batch.
///
/// Pending commands and retained higher-priority evidence return the unchanged
/// driver before inspecting the supplied input. A typed coordinator rejection
/// likewise returns the unchanged driver. Success durably checkpoints the new
/// round and queues one phase-timer arm, without signing or changing finality.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0<'node> {
    /// An outward command must transfer before catch-up can start.
    CommandPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Retained exact-current finality must first be resolved by `step` or drain.
    CurrentFinalityUnresolved {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Retained higher-round proposal work or a blocker must be resolved first.
    HigherEvidenceUnresolved {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// The anchored destination is live and its replacement timer arm is pending.
    Advanced {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Input was rejected before any volatile or durable transition.
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        rejection: Box<FixedValidatorNodeRoundAdvanceRejectionV0>,
    },
}

/// Result of explicit driver-owned current-round proposal authoring.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'node> {
    /// An existing command must transfer before inspecting authoring input.
    CommandPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Existing actionable evidence, a blocker, rejection, or due work takes priority.
    StepWorkPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// One durable proposal and exact payload await publication by `step`.
    Authored {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Input or availability failed before any durable signer effect.
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        rejection: Box<FixedValidatorNodeProposalAuthoringRejectionV0>,
    },
    /// A same-slot conflicting intent durably stopped the signer; no driver survives.
    SignerStopped(FixedValidatorProposalSafetyHaltV0),
}

/// Fatal driver transition failure; no driver or signing scope is returned.
///
/// On `Err`, the consuming operation loses both volatile owners even when the failure
/// occurs before a coordinator starts. Recover only through strict reopen into a
/// fresh driver.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverStepErrorV0 {
    /// A driver evidence position or round could not be derived.
    Round(ProposerSelectionError),
    /// The checked timer generation has no successor.
    TimeoutGenerationExhausted { generation: u64 },
    /// Higher-round pairing failed after the consuming boundary began.
    Evidence(Box<FixedValidatorNodeBufferedProposalPrecommitErrorV0>),
    /// Proposal- or Prevote-close voting failed after the consuming boundary began.
    Vote(Box<FixedValidatorNodeVoteExecutionErrorV0>),
    /// Node-owned round progression failed after the consuming boundary began.
    RoundAdvance(Box<FixedValidatorNodeRoundAdvanceErrorV0>),
    /// Explicit proposal authoring failed after the consuming boundary began.
    ProposalAuthoring(Box<FixedValidatorNodeProposalAuthoringErrorV0>),
    /// Current-round finality failed after the consuming boundary began.
    CurrentFinality(Box<FixedValidatorNodeCurrentRoundFinalityErrorV0>),
    /// Explicit direct lower-round finality failed after the consuming boundary began.
    LowerRoundFinality(Box<FixedValidatorNodeLowerRoundFinalityErrorV0>),
}

impl fmt::Display for FixedValidatorNodeDriverStepErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Round(source) => write!(formatter, "driver round derivation failed: {source}"),
            Self::TimeoutGenerationExhausted { generation } => write!(
                formatter,
                "driver timeout generation {generation} has no successor"
            ),
            Self::Evidence(source) => source.fmt(formatter),
            Self::Vote(source) => source.fmt(formatter),
            Self::RoundAdvance(source) => source.fmt(formatter),
            Self::CurrentFinality(source) => source.fmt(formatter),
            Self::LowerRoundFinality(source) => source.fmt(formatter),
            Self::ProposalAuthoring(source) => source.fmt(formatter),
        }
    }
}

impl Error for FixedValidatorNodeDriverStepErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Evidence(source) => Some(source.as_ref()),
            Self::Vote(source) => Some(source.as_ref()),
            Self::RoundAdvance(source) => Some(source.as_ref()),
            Self::CurrentFinality(source) => Some(source.as_ref()),
            Self::LowerRoundFinality(source) => Some(source.as_ref()),
            Self::ProposalAuthoring(source) => Some(source.as_ref()),
            Self::TimeoutGenerationExhausted { .. } => None,
        }
    }
}

/// Lossless result of clearing a saturated or ambiguous driver inbox.
#[must_use]
pub struct FixedValidatorNodeDriverDrainV0<'node> {
    pub(super) driver: Box<FixedValidatorNodeDriverV0<'node>>,
    pub(super) drained: FixedValidatorNodeHigherRoundInboxDrainV0,
}

/// Lossless result of clearing only the separate current-round inbox.
#[must_use]
pub struct FixedValidatorNodeDriverCurrentRoundDrainV0<'node> {
    pub(super) driver: Box<FixedValidatorNodeDriverV0<'node>>,
    pub(super) drained: FixedValidatorNodeCurrentRoundInboxDrainV0,
}

/// Lossless result of clearing only the dedicated current finality inbox.
#[must_use]
pub struct FixedValidatorNodeDriverCurrentFinalityDrainV0<'node> {
    pub(super) driver: Box<FixedValidatorNodeDriverV0<'node>>,
    pub(super) drained: FixedValidatorNodeCurrentRoundFinalityInboxDrainV0,
}

/// Lossless result of clearing only exact-current nil-precommit evidence.
#[must_use]
pub struct FixedValidatorNodeDriverCurrentNilPrecommitDrainV0<'node> {
    pub(super) driver: Box<FixedValidatorNodeDriverV0<'node>>,
    pub(super) drained: FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0,
}

impl<'node> FixedValidatorNodeDriverCurrentNilPrecommitDrainV0<'node> {
    /// Separates the continuing driver from every retained nil precommit.
    pub fn into_parts(
        self,
    ) -> (
        Box<FixedValidatorNodeDriverV0<'node>>,
        FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0,
    ) {
        (self.driver, self.drained)
    }
}

impl<'node> FixedValidatorNodeDriverCurrentFinalityDrainV0<'node> {
    /// Separates the continuing driver from every finality evidence item.
    pub fn into_parts(
        self,
    ) -> (
        Box<FixedValidatorNodeDriverV0<'node>>,
        FixedValidatorNodeCurrentRoundFinalityInboxDrainV0,
    ) {
        (self.driver, self.drained)
    }
}

impl<'node> FixedValidatorNodeDriverCurrentRoundDrainV0<'node> {
    /// Separates the continuing driver from every current-round evidence item.
    pub fn into_parts(
        self,
    ) -> (
        Box<FixedValidatorNodeDriverV0<'node>>,
        FixedValidatorNodeCurrentRoundInboxDrainV0,
    ) {
        (self.driver, self.drained)
    }
}

impl<'node> FixedValidatorNodeDriverDrainV0<'node> {
    /// Separates the reset driver from every previously retained evidence item.
    pub fn into_parts(
        self,
    ) -> (
        Box<FixedValidatorNodeDriverV0<'node>>,
        FixedValidatorNodeHigherRoundInboxDrainV0,
    ) {
        (self.driver, self.drained)
    }
}

/// Failure to create the closure-scoped driver; no signing scope is returned.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverCreateErrorV0 {
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    Round(ProposerSelectionError),
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    ProcessLineageExhausted,
}

impl fmt::Display for FixedValidatorNodeDriverCreateErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            } => write!(
                formatter,
                "driver signer position {signer:?} differs from branch next height {branch_next_height:?}"
            ),
            Self::Round(source) => write!(formatter, "driver current round failed: {source}"),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "driver signer round {required:?} exceeds finality ceiling {maximum:?}"
            ),
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "driver signer round {required:?} exceeds local ceiling {maximum:?}"
            ),
            Self::Session(source) => {
                write!(formatter, "driver signing session is not ready: {source}")
            }
            Self::ProcessLineageExhausted => {
                formatter.write_str("process-local driver timer lineages are exhausted")
            }
        }
    }
}

impl Error for FixedValidatorNodeDriverCreateErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Session(source) => Some(source.as_ref()),
            Self::SignerBranchHeightMismatch { .. }
            | Self::FinalityRoundLimitExceeded { .. }
            | Self::RoundWorkLimitExceeded { .. }
            | Self::ProcessLineageExhausted => None,
        }
    }
}
