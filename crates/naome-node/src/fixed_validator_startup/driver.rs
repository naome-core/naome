use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_consensus::{
    ConsensusContextV0, ConsensusHeight, ConsensusPosition, ConsensusProposalVerifyError,
    ConsensusRound, ConsensusVoteVerifyError, FixedConsensusNilPrecommitVerifyErrorV0,
    FixedConsensusNilPrevoteVerifyErrorV0, FixedConsensusProposalPrecommitVerifyErrorV0,
    FixedConsensusProposalPrevoteVerifyErrorV0, FixedConsensusRoundV0, FixedValidatorLockPhaseV0,
    ProposalSigningRoot, ProposerSelectionError, QuorumCertificateBuildError,
    VerifiedConsensusVoteV0,
};
use naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;
use naome_storage::{
    FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyHaltV0,
    FixedValidatorVoteSafetyJournalErrorV0, SelectedArtifactHistory,
};

use super::current_round_finality_inbox::{
    CurrentRoundFinalityClassificationErrorV0, CurrentRoundFinalityClassificationV0,
    CurrentRoundFinalityInboxInsertOutcomeV0, CurrentRoundFinalityInboxV0,
    CurrentRoundFinalityPreclassificationV0, CurrentRoundFinalityPrecommitInsertErrorV0,
    CurrentRoundFinalityProposalInsertErrorV0,
};
use super::current_round_inbox::{
    CurrentRoundInboxInsertOutcomeV0, CurrentRoundInboxV0, CurrentRoundNilPrevoteInsertErrorV0,
    CurrentRoundPrevoteInsertErrorV0, CurrentRoundProposalInsertErrorV0,
    CurrentRoundProposalSelectionV0, CurrentRoundQuorumSelectionErrorV0,
    CurrentRoundQuorumSelectionV0,
};
use super::current_round_nil_precommit_inbox::{
    CurrentRoundNilPrecommitInboxInsertOutcomeV0, CurrentRoundNilPrecommitInboxV0,
    CurrentRoundNilPrecommitInsertErrorV0, CurrentRoundNilPrecommitPreclassificationV0,
    CurrentRoundNilPrecommitQuorumSelectionErrorV0, CurrentRoundNilPrecommitQuorumSelectionV0,
};
use super::higher_round_proposal_pairing::{ActionableInboxSelectionV0, ActionableInboxSnapshotV0};
use super::proposal_deferral::{
    CurrentRoundErrorV0, preflight_deferred_proposal_control_framing,
    preflight_higher_round_proposal_route, verify_deferred_proposal_at_round,
};
use super::voting::{CurrentRoundErrorV0 as VotingCurrentRoundErrorV0, current_round};
use super::{
    FixedValidatorNodeBufferedProposalPrecommitErrorV0,
    FixedValidatorNodeBufferedProposalPrecommitOutcomeV0,
    FixedValidatorNodeBufferedProposalPrecommitRejectionV0, FixedValidatorNodeCurrentRoundErrorV0,
    FixedValidatorNodeCurrentRoundFinalityErrorV0,
    FixedValidatorNodeCurrentRoundFinalityInboxDrainV0,
    FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    FixedValidatorNodeCurrentRoundFinalityOutcomeV0,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0, FixedValidatorNodeCurrentRoundInboxDrainV0,
    FixedValidatorNodeCurrentRoundInboxLimitsV0, FixedValidatorNodeCurrentRoundInboxSaturationV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0,
    FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeDeferredProposalV0, FixedValidatorNodeFinalityOutcomeV0,
    FixedValidatorNodeFinalitySelectionV0, FixedValidatorNodeFinalityStoppedV0,
    FixedValidatorNodeHigherRoundInboxDrainV0, FixedValidatorNodeHigherRoundInboxLimitsV0,
    FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0,
    FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0,
    FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0,
    FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0,
    FixedValidatorNodeHigherRoundInboxSaturationV0, FixedValidatorNodeHigherRoundInboxV0,
    FixedValidatorNodeHigherRoundProposalRouteV0, FixedValidatorNodeProposalDeferralErrorV0,
    FixedValidatorNodeProposalDeferralRejectionV0, FixedValidatorNodeRoundAdvanceErrorV0,
    FixedValidatorNodeRoundAdvanceOutcomeV0, FixedValidatorNodeRoundAdvanceRejectionV0,
    FixedValidatorNodeSigningScopeV0, FixedValidatorNodeVoteExecutionErrorV0,
    FixedValidatorNodeVoteExecutionOutcomeV0, FixedValidatorNodeVoteRejectionV0,
    fixed_validator_node_current_round,
};

static NEXT_DRIVER_LINEAGE: AtomicU64 = AtomicU64::new(1);

/// Opaque identity for one driver-issued phase timer.
///
/// The ticket is copyable so a runtime can retain it while scheduling and later
/// return the same value as a due event. Its private fields prevent a runtime
/// from manufacturing another context, position, phase, generation, or driver
/// lineage. It contains no deadline and proves no elapsed time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodePhaseTimeoutV0 {
    lineage: u64,
    context: ConsensusContextV0,
    position: ConsensusPosition,
    phase: FixedValidatorLockPhaseV0,
    generation: u64,
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
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
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
pub(super) struct FixedValidatorNodeDriverFinalityActionV0 {
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
}

#[allow(
    dead_code,
    reason = "the descriptor accessors are exercised only by crate diagnostics"
)]
impl FixedValidatorNodeDriverFinalityActionV0 {
    /// Returns the exact current position classified by the driver.
    pub(super) const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns the proposal root with matching strict-supermajority precommits.
    pub(super) const fn proposal_signing_root(self) -> ProposalSigningRoot {
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
pub(super) enum FixedValidatorNodeDriverCurrentFinalityClassificationV0 {
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
pub(super) enum FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0 {
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

/// Fatal driver-step failure; no driver or signing scope is returned.
///
/// On `Err`, consuming the step loses both volatile owners even when the failure
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
    /// Exact-current round progression failed after the consuming boundary began.
    RoundAdvance(Box<FixedValidatorNodeRoundAdvanceErrorV0>),
    /// Current-round finality failed after the consuming boundary began.
    CurrentFinality(Box<FixedValidatorNodeCurrentRoundFinalityErrorV0>),
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
            Self::TimeoutGenerationExhausted { .. } => None,
        }
    }
}

/// Lossless result of clearing a saturated or ambiguous driver inbox.
#[must_use]
pub struct FixedValidatorNodeDriverDrainV0<'node> {
    driver: Box<FixedValidatorNodeDriverV0<'node>>,
    drained: FixedValidatorNodeHigherRoundInboxDrainV0,
}

/// Lossless result of clearing only the separate current-round inbox.
#[must_use]
pub struct FixedValidatorNodeDriverCurrentRoundDrainV0<'node> {
    driver: Box<FixedValidatorNodeDriverV0<'node>>,
    drained: FixedValidatorNodeCurrentRoundInboxDrainV0,
}

/// Lossless result of clearing only the dedicated current finality inbox.
#[must_use]
pub struct FixedValidatorNodeDriverCurrentFinalityDrainV0<'node> {
    driver: Box<FixedValidatorNodeDriverV0<'node>>,
    drained: FixedValidatorNodeCurrentRoundFinalityInboxDrainV0,
}

/// Lossless result of clearing only exact-current nil-precommit evidence.
#[must_use]
pub struct FixedValidatorNodeDriverCurrentNilPrecommitDrainV0<'node> {
    driver: Box<FixedValidatorNodeDriverV0<'node>>,
    drained: FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0,
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

enum PendingCommandV0 {
    Arm(FixedValidatorNodePhaseTimeoutV0),
    Publish {
        vote: FixedValidatorSignedVoteV0,
        released_proposal: Option<Box<FixedValidatorNodeDeferredProposalV0>>,
        successor_generation: u64,
    },
}

/// One non-clone, closure-scoped fixed-validator event driver.
///
/// The driver privately owns the sole live signing scope. It exposes neither a
/// mutable or consuming escape hatch back to that scope nor a caller-selected
/// action method. Its only authority projection is the sealed read-only selected
/// artifact history required by caller-owned acquisition. Evidence and due
/// timers become authoritative only through the existing fully checking
/// consuming coordinators selected by [`Self::step`].
#[must_use]
pub struct FixedValidatorNodeDriverV0<'node> {
    scope: Option<FixedValidatorNodeSigningScopeV0<'node>>,
    inbox: FixedValidatorNodeHigherRoundInboxV0,
    current_inbox: CurrentRoundInboxV0,
    current_finality_inbox: CurrentRoundFinalityInboxV0,
    current_nil_precommit_inbox: CurrentRoundNilPrecommitInboxV0,
    inclusive_maximum_round: ConsensusRound,
    lineage: u64,
    generation: u64,
    active_timeout: Option<FixedValidatorNodePhaseTimeoutV0>,
    due: bool,
    ambiguity: Option<FixedValidatorNodeDriverBlockReasonV0>,
    current_ambiguity: Option<FixedValidatorNodeDriverBlockReasonV0>,
    pending_command: Option<PendingCommandV0>,
}

impl<'node> FixedValidatorNodeDriverV0<'node> {
    /// Consumes the sole live scope and prepares this phase's first arm command.
    ///
    /// Every construction error also consumes the supplied scope without
    /// returning it. Recovery then requires the existing strict-reopen path.
    pub fn new(
        scope: FixedValidatorNodeSigningScopeV0<'node>,
        inbox_limits: FixedValidatorNodeHigherRoundInboxLimitsV0,
        current_inbox_limits: FixedValidatorNodeCurrentRoundInboxLimitsV0,
        current_finality_inbox_limits: FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
        current_nil_precommit_inbox_limits: FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<Self, FixedValidatorNodeDriverCreateErrorV0> {
        let finality_maximum_round = scope.finality.replay_limit().max_round();
        let round = fixed_validator_node_current_round(
            &scope.branch,
            &scope.signing_session,
            inclusive_maximum_round,
            finality_maximum_round,
        )
        .map_err(map_create_error)?;
        let context = round.context();
        let position = round.position();
        let phase = scope.signing_session.phase();
        drop(round);
        let lineage = NEXT_DRIVER_LINEAGE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |lineage| {
                lineage.checked_add(1)
            })
            .map_err(|_| FixedValidatorNodeDriverCreateErrorV0::ProcessLineageExhausted)?;
        let active_timeout = FixedValidatorNodePhaseTimeoutV0 {
            lineage,
            context,
            position,
            phase,
            generation: 0,
        };
        Ok(Self {
            scope: Some(scope),
            inbox: FixedValidatorNodeHigherRoundInboxV0::new(inbox_limits),
            current_inbox: CurrentRoundInboxV0::new(current_inbox_limits),
            current_finality_inbox: CurrentRoundFinalityInboxV0::new(current_finality_inbox_limits),
            current_nil_precommit_inbox: CurrentRoundNilPrecommitInboxV0::new(
                current_nil_precommit_inbox_limits,
            ),
            inclusive_maximum_round,
            lineage,
            generation: 0,
            active_timeout: Some(active_timeout),
            due: false,
            ambiguity: None,
            current_ambiguity: None,
            pending_command: Some(PendingCommandV0::Arm(active_timeout)),
        })
    }

    /// Returns the exact live signer position as read-only diagnostics.
    pub fn position(&self) -> ConsensusPosition {
        self.scope().signing_session.position()
    }

    /// Borrows only the sealed read-only selected artifact history.
    ///
    /// The borrow cannot expose the signing session or mutate selected finality.
    /// Its lifetime also prevents consuming driver work while a caller-owned
    /// acquisition workflow retains it. Target and peer choice, persistence,
    /// proposal admission, voting, and finality remain separate explicit steps.
    pub fn selected_artifact_history(&self) -> &dyn SelectedArtifactHistory {
        self.scope().finality()
    }

    /// Returns the exact live lock phase as read-only diagnostics.
    pub fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.scope().signing_session.phase()
    }

    /// Returns this driver's inclusive local round-work ceiling.
    pub const fn inclusive_maximum_round(&self) -> ConsensusRound {
        self.inclusive_maximum_round
    }

    /// Returns the higher-round retained proposal and proposal-prevote count.
    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
    }

    /// Returns the separate current proposal and proposal-or-nil prevote count.
    pub fn current_inbox_len(&self) -> usize {
        self.current_inbox.len()
    }

    /// Returns the current-round inbox's checked canonical-input byte count.
    pub const fn current_inbox_canonical_input_bytes(&self) -> u64 {
        self.current_inbox.total_canonical_input_bytes()
    }

    /// Returns the dedicated current finality proposal-and-precommit count.
    pub fn current_finality_inbox_len(&self) -> usize {
        self.current_finality_inbox.len()
    }

    /// Returns the finality inbox's checked logical canonical-input byte count.
    pub const fn current_finality_inbox_canonical_input_bytes(&self) -> u64 {
        self.current_finality_inbox.total_canonical_input_bytes()
    }

    /// Returns the dedicated exact-current nil-precommit count.
    pub fn current_nil_precommit_inbox_len(&self) -> usize {
        self.current_nil_precommit_inbox.len()
    }

    /// Returns the nil-precommit inbox's checked canonical-input byte count.
    pub const fn current_nil_precommit_inbox_canonical_input_bytes(&self) -> u64 {
        self.current_nil_precommit_inbox
            .total_canonical_input_bytes()
    }

    /// Classifies current proposal-finality evidence without changing driver work.
    ///
    /// This read-only result is descriptive only. It exposes no proposal,
    /// certificate, signing scope, or finality handle. [`Self::step`] uses the
    /// same private selection pipeline before independently copying and fully
    /// reverifying any uniquely ready evidence.
    #[allow(
        dead_code,
        reason = "the private diagnostic classifier is exercised by crate tests"
    )]
    pub(super) fn classify_current_finality_evidence(
        &self,
    ) -> Result<
        FixedValidatorNodeDriverCurrentFinalityClassificationV0,
        FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0,
    > {
        match self
            .select_current_finality()
            .map_err(FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0::Round)?
        {
            DriverCurrentFinalitySelectionV0::Saturated {
                position,
                saturation,
            } => Ok(
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated {
                    position,
                    saturation,
                },
            ),
            DriverCurrentFinalitySelectionV0::None => {
                Ok(FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete)
            }
            DriverCurrentFinalitySelectionV0::MissingProposal {
                position,
                proposal_signing_root,
            } => Ok(
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::QuorumMissingProposal(
                    FixedValidatorNodeDriverFinalityActionV0 {
                        position,
                        proposal_signing_root,
                    },
                ),
            ),
            DriverCurrentFinalitySelectionV0::Ready {
                action,
                canonical_proposal_control_bytes: _,
                canonical_artifact_bytes: _,
                canonical_precommit_certificate: _,
            } => Ok(FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)),
            DriverCurrentFinalitySelectionV0::PreselectionConflict {
                first_action,
                second_action,
                ..
            } => Ok(
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                    position: first_action.position,
                    first: first_action.proposal_signing_root,
                    second: second_action.proposal_signing_root,
                },
            ),
            DriverCurrentFinalitySelectionV0::ConflictingRoots {
                position,
                first,
                second,
            } => Ok(
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                    position,
                    first,
                    second,
                },
            ),
            DriverCurrentFinalitySelectionV0::Reservation(source) => Err(
                FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0::Reservation(source),
            ),
            DriverCurrentFinalitySelectionV0::Rejected(source) => Err(
                FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0::QuorumInvariant(
                    source,
                ),
            ),
        }
    }

    /// Returns whether the exact active phase timer has been reported due.
    pub const fn timeout_is_due(&self) -> bool {
        self.due
    }

    /// Returns whether one outward command must be emitted before another transition.
    pub const fn has_pending_command(&self) -> bool {
        self.pending_command.is_some()
    }

    /// Admits one owned event without choosing or executing a consensus action.
    ///
    /// On `Err`, this consuming call returns neither the driver nor its signing
    /// scope, even when failure occurs before a coordinator starts. Recover only
    /// through strict reopen into a fresh driver.
    pub fn admit_event(
        self,
        event: FixedValidatorNodeDriverEventV0,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(admission_rejected(
                self,
                event,
                FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending,
            ));
        }
        let bypasses_higher_block = matches!(
            &event,
            FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal { .. }
                | FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit { .. }
                | FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit { .. }
        );
        if !bypasses_higher_block && let Some(reason) = self.higher_block_reason() {
            return Ok(admission_rejected(
                self,
                event,
                FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
            ));
        }
        match event {
            FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => self.admit_current_finality_proposal(
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            ),
            FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
                canonical_signed_precommit,
            } => self.admit_current_finality_precommit(canonical_signed_precommit),
            FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit {
                canonical_signed_precommit,
            } => self.admit_current_nil_precommit(canonical_signed_precommit),
            FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => {
                if let Some(reason) = self.current_block_reason() {
                    return Ok(admission_rejected(
                        self,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        },
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
                    ));
                }
                self.admit_current_proposal(
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                )
            }
            FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                canonical_signed_prevote,
            } => {
                if let Some(reason) = self.current_block_reason() {
                    return Ok(admission_rejected(
                        self,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                            canonical_signed_prevote,
                        },
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
                    ));
                }
                self.admit_current_prevote(canonical_signed_prevote)
            }
            FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
                canonical_signed_prevote,
            } => {
                if let Some(reason) = self.current_block_reason() {
                    return Ok(admission_rejected(
                        self,
                        FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
                            canonical_signed_prevote,
                        },
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
                    ));
                }
                self.admit_current_nil_prevote(canonical_signed_prevote)
            }
            FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                proposal_round,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => self.admit_proposal(
                proposal_round,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            ),
            FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
                canonical_signed_prevote,
            } => self.admit_prevote(canonical_signed_prevote),
            FixedValidatorNodeDriverEventV0::TimeoutDue(timeout) => Ok(self.admit_timeout(timeout)),
        }
    }

    /// Executes at most one transition or emits exactly one pending command.
    ///
    /// On `Err`, this consuming call returns neither the driver nor its signing
    /// scope, even when failure occurs before a coordinator starts. Recover only
    /// through strict reopen into a fresh driver.
    pub fn step(
        mut self,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        if let Some(pending) = self.pending_command.take() {
            let command = match pending {
                PendingCommandV0::Arm(timeout) => {
                    FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(timeout)
                }
                PendingCommandV0::Publish {
                    vote,
                    released_proposal,
                    successor_generation,
                } => {
                    let timeout = self.install_next_timeout(successor_generation);
                    self.pending_command = Some(PendingCommandV0::Arm(timeout));
                    FixedValidatorNodeDriverCommandV0::PublishVote {
                        vote,
                        released_proposal,
                    }
                }
            };
            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Command {
                driver: Box::new(self),
                command,
            });
        }

        match self
            .select_current_finality()
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?
        {
            DriverCurrentFinalitySelectionV0::None
            | DriverCurrentFinalitySelectionV0::Saturated { .. } => {}
            DriverCurrentFinalitySelectionV0::Ready {
                action: _,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_precommit_certificate,
            } => {
                let canonical_proposal_control_bytes =
                    match try_copy_bytes(canonical_proposal_control_bytes) {
                        Ok(bytes) => bytes,
                        Err(source) => {
                            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                        }
                    };
                let canonical_artifact_bytes = match try_copy_bytes(canonical_artifact_bytes) {
                    Ok(bytes) => bytes,
                    Err(source) => {
                        return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                            driver: Box::new(self),
                            rejection: Box::new(
                                FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                    source,
                                ),
                            ),
                        });
                    }
                };
                return self.execute_current_finality(
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                    canonical_precommit_certificate,
                );
            }
            DriverCurrentFinalitySelectionV0::PreselectionConflict {
                first_action: _,
                first_canonical_proposal_control_bytes,
                first_canonical_artifact_bytes,
                first_canonical_precommit_certificate,
                second_action: _,
                second_canonical_proposal_control_bytes,
                second_canonical_artifact_bytes,
                second_canonical_precommit_certificate,
            } => {
                let first_canonical_proposal_control_bytes =
                    match try_copy_bytes(first_canonical_proposal_control_bytes) {
                        Ok(bytes) => bytes,
                        Err(source) => {
                            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                        }
                    };
                let first_canonical_artifact_bytes =
                    match try_copy_bytes(first_canonical_artifact_bytes) {
                        Ok(bytes) => bytes,
                        Err(source) => {
                            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                        }
                    };
                let second_canonical_proposal_control_bytes =
                    match try_copy_bytes(second_canonical_proposal_control_bytes) {
                        Ok(bytes) => bytes,
                        Err(source) => {
                            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                        }
                    };
                let second_canonical_artifact_bytes =
                    match try_copy_bytes(second_canonical_artifact_bytes) {
                        Ok(bytes) => bytes,
                        Err(source) => {
                            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                        }
                    };
                return self.execute_current_preselection_conflict(
                    first_canonical_proposal_control_bytes,
                    first_canonical_artifact_bytes,
                    first_canonical_precommit_certificate,
                    second_canonical_proposal_control_bytes,
                    second_canonical_artifact_bytes,
                    second_canonical_precommit_certificate,
                );
            }
            DriverCurrentFinalitySelectionV0::MissingProposal {
                position,
                proposal_signing_root,
            } => {
                let reason =
                    FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing {
                        position,
                        proposal_signing_root,
                    };
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                    driver: Box::new(self),
                    reason,
                });
            }
            DriverCurrentFinalitySelectionV0::ConflictingRoots {
                position,
                first,
                second,
            } => {
                let reason =
                    FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityRootsConflicting {
                        position,
                        first,
                        second,
                    };
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                    driver: Box::new(self),
                    reason,
                });
            }
            DriverCurrentFinalitySelectionV0::Rejected(source) => {
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::CurrentFinalitySelection(
                            Box::new(source),
                        ),
                    ),
                });
            }
            DriverCurrentFinalitySelectionV0::Reservation(source) => {
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                    ),
                });
            }
        }

        if let Some(reason) = self.higher_block_reason() {
            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                driver: Box::new(self),
                reason,
            });
        }

        match self.select_actionable_higher_round()? {
            DriverEvidenceSelectionV0::None => {}
            DriverEvidenceSelectionV0::One(action) => {
                return self.execute_evidence(action);
            }
            DriverEvidenceSelectionV0::Ambiguous { first, second } => {
                let reason = FixedValidatorNodeDriverBlockReasonV0::Ambiguous { first, second };
                self.ambiguity = Some(reason);
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                    driver: Box::new(self),
                    reason,
                });
            }
            DriverEvidenceSelectionV0::Rejected(rejection) => {
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::EvidenceSelection(rejection),
                    ),
                });
            }
            DriverEvidenceSelectionV0::Reservation(source) => {
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                    ),
                });
            }
        }

        match self.select_current_nil_precommit()? {
            DriverCurrentNilPrecommitSelectionV0::None => {}
            DriverCurrentNilPrecommitSelectionV0::One {
                canonical_signed_precommits,
            } => {
                return self.execute_current_nil_precommit(canonical_signed_precommits);
            }
            DriverCurrentNilPrecommitSelectionV0::Rejected(source) => {
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::CurrentNilPrecommitSelection(
                            Box::new(source),
                        ),
                    ),
                });
            }
            DriverCurrentNilPrecommitSelectionV0::Reservation(source) => {
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                    ),
                });
            }
        }

        if let Some(reason) = self.current_block_reason() {
            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                driver: Box::new(self),
                reason,
            });
        }
        match self.select_actionable_current()? {
            DriverCurrentSelectionV0::None => {}
            DriverCurrentSelectionV0::Proposal {
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => {
                return self.execute_current_proposal(
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                );
            }
            DriverCurrentSelectionV0::ProposalQuorum {
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_prevote_certificate,
            } => {
                return self.execute_current_proposal_quorum(
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                    canonical_prevote_certificate,
                );
            }
            DriverCurrentSelectionV0::NilQuorum {
                canonical_prevote_certificate,
            } => {
                return self.execute_current_nil_quorum(canonical_prevote_certificate);
            }
            DriverCurrentSelectionV0::AmbiguousQuorums {
                position,
                proposal_signing_root,
            } => {
                let reason = FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                    position,
                    proposal_signing_root,
                };
                self.current_ambiguity = Some(reason);
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                    driver: Box::new(self),
                    reason,
                });
            }
            DriverCurrentSelectionV0::Rejected(rejection) => {
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(rejection)),
                });
            }
            DriverCurrentSelectionV0::Reservation(source) => {
                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                    ),
                });
            }
        }

        if self.due {
            self.execute_due()
        } else {
            Ok(FixedValidatorNodeDriverStepOutcomeV0::Idle {
                driver: Box::new(self),
            })
        }
    }

    /// Losslessly drains only higher-round evidence and clears its blocking.
    pub fn drain_inbox_and_reset(mut self) -> FixedValidatorNodeDriverDrainV0<'node> {
        let drained = self.inbox.drain_and_reset();
        self.ambiguity = None;
        FixedValidatorNodeDriverDrainV0 {
            driver: Box::new(self),
            drained,
        }
    }

    /// Losslessly returns all separately budgeted current-round evidence.
    ///
    /// The active due observation and higher-round inbox remain unchanged.
    pub fn drain_current_inbox_and_reset(
        mut self,
    ) -> FixedValidatorNodeDriverCurrentRoundDrainV0<'node> {
        let drained = self.current_inbox.drain_and_reset();
        self.current_ambiguity = None;
        FixedValidatorNodeDriverCurrentRoundDrainV0 {
            driver: Box::new(self),
            drained,
        }
    }

    /// Losslessly returns all separately budgeted current finality evidence.
    ///
    /// Ordinary current and higher inboxes, timer and due state, pending command,
    /// and signer and finality authority remain unchanged.
    pub fn drain_current_finality_inbox_and_reset(
        mut self,
    ) -> FixedValidatorNodeDriverCurrentFinalityDrainV0<'node> {
        let drained = self.current_finality_inbox.drain_and_reset();
        FixedValidatorNodeDriverCurrentFinalityDrainV0 {
            driver: Box::new(self),
            drained,
        }
    }

    /// Losslessly returns all separately budgeted current nil precommits.
    ///
    /// Every other inbox, timer, due state, pending command, signing state, and
    /// durable authority file remains unchanged.
    pub fn drain_current_nil_precommit_inbox_and_reset(
        mut self,
    ) -> FixedValidatorNodeDriverCurrentNilPrecommitDrainV0<'node> {
        let drained = self.current_nil_precommit_inbox.drain_and_reset();
        FixedValidatorNodeDriverCurrentNilPrecommitDrainV0 {
            driver: Box::new(self),
            drained,
        }
    }

    fn admit_current_finality_proposal(
        mut self,
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_proposal_control_bytes = Some(canonical_proposal_control_bytes);
        let mut canonical_artifact_bytes = Some(canonical_artifact_bytes);
        if let Some((position, saturation)) = self.current_finality_inbox.saturation() {
            return Ok(admission_rejected(
                self,
                current_finality_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    position,
                    saturation,
                    newly_saturated: false,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_finality_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let proposal = match verify_current_proposal_at_round(
            &round,
            canonical_proposal_control_bytes
                .as_ref()
                .expect("original current finality proposal control is retained"),
            canonical_artifact_bytes
                .as_ref()
                .expect("original current finality proposal payload is retained"),
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(round);
                let rejection =
                    source.into_admission_rejection(CurrentProposalDestinationV0::Finality);
                return Ok(admission_rejected(
                    self,
                    current_finality_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    rejection,
                ));
            }
        };
        drop(round);
        match self.current_finality_inbox.try_insert_proposal(proposal) {
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundFinalityProposalInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_finality_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundFinalityProposalInsertErrorV0::Reservation(source)) => {
                Ok(admission_rejected(
                    self,
                    current_finality_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxReservation(
                        source,
                    ),
                ))
            }
        }
    }

    fn admit_current_finality_precommit(
        mut self,
        canonical_signed_precommit: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_precommit = Some(canonical_signed_precommit);
        if let Some((position, saturation)) = self.current_finality_inbox.saturation() {
            return Ok(admission_rejected(
                self,
                current_finality_precommit_event(&mut canonical_signed_precommit),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    position,
                    saturation,
                    newly_saturated: false,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_finality_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let insertion = self.current_finality_inbox.try_insert_precommit(
            &round,
            canonical_signed_precommit
                .as_ref()
                .expect("original current proposal precommit is retained"),
        );
        drop(round);
        match insertion {
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundFinalityPrecommitInsertErrorV0::Admission(source)) => {
                Ok(admission_rejected(
                    self,
                    current_finality_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(source),
                ))
            }
            Err(CurrentRoundFinalityPrecommitInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_finality_precommit_event(&mut canonical_signed_precommit),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundFinalityPrecommitInsertErrorV0::Reservation(source)) => {
                Ok(admission_rejected(
                    self,
                    current_finality_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxReservation(
                        source,
                    ),
                ))
            }
        }
    }

    fn admit_current_nil_precommit(
        mut self,
        canonical_signed_precommit: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_precommit = Some(canonical_signed_precommit);
        if let Some((position, saturation)) = self.current_nil_precommit_inbox.saturation() {
            return Ok(admission_rejected(
                self,
                current_nil_precommit_event(&mut canonical_signed_precommit),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                    position,
                    saturation,
                    newly_saturated: false,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_nil_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let insertion = self.current_nil_precommit_inbox.try_insert_nil_precommit(
            &round,
            canonical_signed_precommit
                .as_ref()
                .expect("original current nil precommit is retained"),
        );
        drop(round);
        match insertion {
            Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundNilPrecommitInsertErrorV0::Admission(source)) => {
                Ok(admission_rejected(
                    self,
                    current_nil_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(source),
                ))
            }
            Err(CurrentRoundNilPrecommitInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_nil_precommit_event(&mut canonical_signed_precommit),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundNilPrecommitInsertErrorV0::Reservation(source)) => {
                Ok(admission_rejected(
                    self,
                    current_nil_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxReservation(
                        source,
                    ),
                ))
            }
        }
    }

    fn admit_current_proposal(
        mut self,
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_proposal_control_bytes = Some(canonical_proposal_control_bytes);
        let mut canonical_artifact_bytes = Some(canonical_artifact_bytes);
        let phase = self.phase();
        if phase == FixedValidatorLockPhaseV0::Precommit {
            return Ok(admission_rejected(
                self,
                current_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                    actual: phase,
                },
            ));
        }
        if self.due {
            let position = self.position();
            return Ok(admission_rejected(
                self,
                current_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                    position,
                    phase,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let proposal = match verify_current_proposal_at_round(
            &round,
            canonical_proposal_control_bytes
                .as_ref()
                .expect("original current proposal control is retained"),
            canonical_artifact_bytes
                .as_ref()
                .expect("original current proposal payload is retained"),
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(round);
                let rejection =
                    source.into_admission_rejection(CurrentProposalDestinationV0::Voting);
                return Ok(admission_rejected(
                    self,
                    current_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    rejection,
                ));
            }
        };
        drop(round);
        match self.current_inbox.try_insert_proposal(proposal) {
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundProposalInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundProposalInsertErrorV0::Reservation(source)) => Ok(admission_rejected(
                self,
                current_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxReservation(source),
            )),
        }
    }

    fn admit_current_prevote(
        mut self,
        canonical_signed_prevote: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_prevote = Some(canonical_signed_prevote);
        let phase = self.phase();
        if phase == FixedValidatorLockPhaseV0::Precommit {
            return Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                    actual: phase,
                },
            ));
        }
        if self.due {
            let position = self.position();
            return Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                    position,
                    phase,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_prevote_event(&mut canonical_signed_prevote),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let insertion = self.current_inbox.try_insert_prevote(
            &round,
            canonical_signed_prevote
                .as_ref()
                .expect("original current proposal prevote is retained"),
        );
        drop(round);
        match insertion {
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundPrevoteInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundPrevoteInsertErrorV0::Admission(source)) => Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(source),
            )),
            Err(CurrentRoundPrevoteInsertErrorV0::Reservation(source)) => Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxReservation(source),
            )),
        }
    }

    fn admit_current_nil_prevote(
        mut self,
        canonical_signed_prevote: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_prevote = Some(canonical_signed_prevote);
        let phase = self.phase();
        if phase == FixedValidatorLockPhaseV0::Precommit {
            return Ok(admission_rejected(
                self,
                current_nil_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                    actual: phase,
                },
            ));
        }
        if self.due {
            let position = self.position();
            return Ok(admission_rejected(
                self,
                current_nil_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                    position,
                    phase,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_nil_prevote_event(&mut canonical_signed_prevote),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let insertion = self.current_inbox.try_insert_nil_prevote(
            &round,
            canonical_signed_prevote
                .as_ref()
                .expect("original current nil prevote is retained"),
        );
        drop(round);
        match insertion {
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundNilPrevoteInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_nil_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundNilPrevoteInsertErrorV0::Admission(source)) => Ok(admission_rejected(
                self,
                current_nil_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(source),
            )),
            Err(CurrentRoundNilPrevoteInsertErrorV0::Reservation(source)) => {
                Ok(admission_rejected(
                    self,
                    current_nil_prevote_event(&mut canonical_signed_prevote),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxReservation(source),
                ))
            }
        }
    }

    fn admit_proposal(
        mut self,
        proposal_round: ConsensusRound,
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_proposal_control_bytes = Some(canonical_proposal_control_bytes);
        let mut canonical_artifact_bytes = Some(canonical_artifact_bytes);
        let route = FixedValidatorNodeHigherRoundProposalRouteV0::new(
            proposal_round,
            self.inclusive_maximum_round,
        );
        let proposal_round_token = match preflight_higher_round_proposal_route(self.scope(), route)
        {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    proposal_event(
                        proposal_round,
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(Box::new(rejection)),
                ));
            }
            Err(CurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::Proposal(
                    Box::new(source),
                ));
            }
        };
        let payload_len = canonical_artifact_bytes
            .as_ref()
            .expect("original proposal payload is retained")
            .len();
        if payload_len > ARTIFACT_PAYLOAD_MAX_BYTES {
            drop(proposal_round_token);
            return Ok(admission_rejected(
                self,
                proposal_event(
                    proposal_round,
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadTooLong {
                    actual: payload_len,
                    maximum: ARTIFACT_PAYLOAD_MAX_BYTES,
                },
            ));
        }
        if let Err(source) = preflight_deferred_proposal_control_framing(
            canonical_proposal_control_bytes
                .as_ref()
                .expect("original proposal control is retained"),
        ) {
            drop(proposal_round_token);
            return Ok(admission_rejected(
                self,
                proposal_event(
                    proposal_round,
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(Box::new(
                    FixedValidatorNodeProposalDeferralRejectionV0::Proposal(Box::new(source)),
                )),
            ));
        }
        let mut artifact_copy = Vec::new();
        if let Err(source) = artifact_copy.try_reserve_exact(
            canonical_artifact_bytes
                .as_ref()
                .expect("original proposal payload is retained")
                .len(),
        ) {
            drop(proposal_round_token);
            return Ok(admission_rejected(
                self,
                proposal_event(
                    proposal_round,
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadCopy(source),
            ));
        }
        artifact_copy.extend_from_slice(
            canonical_artifact_bytes
                .as_ref()
                .expect("original proposal payload is retained"),
        );
        let proposal = match verify_deferred_proposal_at_round(
            &proposal_round_token,
            canonical_proposal_control_bytes
                .as_ref()
                .expect("original proposal control is retained"),
            artifact_copy,
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(proposal_round_token);
                return Ok(admission_rejected(
                    self,
                    proposal_event(
                        proposal_round,
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(Box::new(
                        FixedValidatorNodeProposalDeferralRejectionV0::Proposal(Box::new(source)),
                    )),
                ));
            }
        };
        drop(proposal_round_token);

        match self.inbox.try_insert_proposal(proposal) {
            Ok(FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0::Inserted) => {
                Ok(admitted(
                    self,
                    FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
                ))
            }
            Ok(FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0::AlreadyRetained {
                proposal: _,
            }) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(source) => Ok(admission_rejected(
                self,
                proposal_event(
                    proposal_round,
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalInbox(Box::new(source)),
            )),
        }
    }

    fn admit_prevote(
        mut self,
        canonical_signed_prevote: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_prevote = Some(canonical_signed_prevote);
        let context = self.scope().branch.context();
        let vote = match VerifiedConsensusVoteV0::decode_and_verify(
            canonical_signed_prevote
                .as_ref()
                .expect("original proposal prevote is retained"),
            context,
        ) {
            Ok(vote) => vote,
            Err(source) => {
                return Ok(admission_rejected(
                    self,
                    prevote_event(&mut canonical_signed_prevote),
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRouting(source),
                ));
            }
        };
        let position = vote.position();
        let current = self.position();
        if position.height() != current.height() {
            return Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteHeightMismatch {
                    current: current.height(),
                    event: position.height(),
                },
            ));
        }
        if position.round() <= current.round() {
            return Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteNotHigher {
                    signer: current.round(),
                    event: position.round(),
                },
            ));
        }
        let finality_maximum =
            ConsensusRound::new(self.scope().finality.replay_limit().max_round());
        if position.round() > finality_maximum {
            return Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteFinalityRoundLimitExceeded {
                    required: position.round(),
                    maximum: finality_maximum,
                },
            ));
        }
        if position.round() > self.inclusive_maximum_round {
            let maximum = self.inclusive_maximum_round;
            return Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRoundWorkLimitExceeded {
                    required: position.round(),
                    maximum,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = derive_round(&scope.branch, position.round())
            .map_err(FixedValidatorNodeDriverAdmissionErrorV0::Round)?;
        let insertion = self.inbox.try_insert_proposal_prevote(
            &round,
            canonical_signed_prevote
                .as_ref()
                .expect("original proposal prevote is retained"),
        );
        drop(round);
        match insertion {
            Ok(FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0::AlreadyRetained) => {
                Ok(admitted(
                    self,
                    FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
                ))
            }
            Err(source) => Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(Box::new(source)),
            )),
        }
    }

    fn admit_timeout(
        mut self,
        timeout: FixedValidatorNodePhaseTimeoutV0,
    ) -> FixedValidatorNodeDriverAdmissionOutcomeV0<'node> {
        if self.active_timeout != Some(timeout) {
            return admission_rejected(
                self,
                FixedValidatorNodeDriverEventV0::TimeoutDue(timeout),
                FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch,
            );
        }
        if self.due {
            admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue,
            )
        } else {
            self.due = true;
            admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue,
            )
        }
    }

    fn select_actionable_higher_round(
        &self,
    ) -> Result<DriverEvidenceSelectionV0, FixedValidatorNodeDriverStepErrorV0> {
        let current = self.position();
        let mut positions = Vec::new();
        if let Err(source) = positions.try_reserve_exact(self.inbox.len()) {
            return Ok(DriverEvidenceSelectionV0::Reservation(source));
        }
        positions.extend(self.inbox.retained_positions().filter(|position| {
            position.height() == current.height()
                && position.round() > current.round()
                && position.round() <= self.inclusive_maximum_round
        }));
        positions.sort_unstable();
        positions.dedup();

        if positions.is_empty() {
            return Ok(DriverEvidenceSelectionV0::None);
        }

        let parent_coordinate = self.scope().branch.coordinate();
        let snapshot = match ActionableInboxSnapshotV0::try_new(&self.inbox, parent_coordinate) {
            Ok(snapshot) => snapshot,
            Err(rejection) => {
                return Ok(DriverEvidenceSelectionV0::Rejected(Box::new(rejection)));
            }
        };
        let mut round = self
            .scope()
            .branch
            .begin_round_zero()
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
        let mut selected: Option<FixedValidatorNodeDriverActionV0> = None;
        for position in positions {
            while round.position().round() < position.round() {
                round = round
                    .advance_round()
                    .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
            }
            debug_assert_eq!(round.position().round(), position.round());
            let selection = snapshot.select_position(&round, position);
            match selection {
                Ok(ActionableInboxSelectionV0::None) => {}
                Ok(ActionableInboxSelectionV0::One {
                    proposal_signing_root,
                    canonical_prevote_certificate: _,
                }) => {
                    let action = FixedValidatorNodeDriverActionV0 {
                        position,
                        proposal_signing_root,
                    };
                    if let Some(first) = selected {
                        return Ok(DriverEvidenceSelectionV0::Ambiguous {
                            first,
                            second: action,
                        });
                    }
                    selected = Some(action);
                }
                Ok(ActionableInboxSelectionV0::Ambiguous { first, second }) => {
                    return Ok(DriverEvidenceSelectionV0::Ambiguous {
                        first: FixedValidatorNodeDriverActionV0 {
                            position,
                            proposal_signing_root: first,
                        },
                        second: FixedValidatorNodeDriverActionV0 {
                            position,
                            proposal_signing_root: second,
                        },
                    });
                }
                Err(rejection) => {
                    return Ok(DriverEvidenceSelectionV0::Rejected(Box::new(rejection)));
                }
            }
        }
        Ok(match selected {
            Some(action) => DriverEvidenceSelectionV0::One(action),
            None => DriverEvidenceSelectionV0::None,
        })
    }

    fn select_current_finality(
        &self,
    ) -> Result<DriverCurrentFinalitySelectionV0<'_>, ProposerSelectionError> {
        let position = self.position();
        let parent_coordinate = self.scope().branch.coordinate();
        match self
            .current_finality_inbox
            .preclassify(parent_coordinate, position)
        {
            CurrentRoundFinalityPreclassificationV0::Saturated {
                position,
                saturation,
            } => {
                return Ok(DriverCurrentFinalitySelectionV0::Saturated {
                    position,
                    saturation,
                });
            }
            CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit => {
                return Ok(DriverCurrentFinalitySelectionV0::None);
            }
            CurrentRoundFinalityPreclassificationV0::NeedsRound => {}
        }
        let round = derive_round(&self.scope().branch, position.round())?;
        let classification = self.current_finality_inbox.classify(&round);
        drop(round);
        match classification {
            Ok(CurrentRoundFinalityClassificationV0::Saturated {
                position,
                saturation,
            }) => Ok(DriverCurrentFinalitySelectionV0::Saturated {
                position,
                saturation,
            }),
            Ok(CurrentRoundFinalityClassificationV0::None) => {
                Ok(DriverCurrentFinalitySelectionV0::None)
            }
            Ok(CurrentRoundFinalityClassificationV0::OneQuorumMissingProposal {
                proposal_signing_root,
                canonical_precommit_certificate,
            }) => {
                drop(canonical_precommit_certificate);
                Ok(DriverCurrentFinalitySelectionV0::MissingProposal {
                    position,
                    proposal_signing_root,
                })
            }
            Ok(CurrentRoundFinalityClassificationV0::One {
                proposal_signing_root,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_precommit_certificate,
            }) => Ok(DriverCurrentFinalitySelectionV0::Ready {
                action: FixedValidatorNodeDriverFinalityActionV0 {
                    position,
                    proposal_signing_root,
                },
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_precommit_certificate,
            }),
            Ok(CurrentRoundFinalityClassificationV0::Pair { first, second }) => {
                Ok(DriverCurrentFinalitySelectionV0::PreselectionConflict {
                    first_action: FixedValidatorNodeDriverFinalityActionV0 {
                        position,
                        proposal_signing_root: first.proposal_signing_root,
                    },
                    first_canonical_proposal_control_bytes: first.canonical_proposal_control_bytes,
                    first_canonical_artifact_bytes: first.canonical_artifact_bytes,
                    first_canonical_precommit_certificate: first.canonical_precommit_certificate,
                    second_action: FixedValidatorNodeDriverFinalityActionV0 {
                        position,
                        proposal_signing_root: second.proposal_signing_root,
                    },
                    second_canonical_proposal_control_bytes: second
                        .canonical_proposal_control_bytes,
                    second_canonical_artifact_bytes: second.canonical_artifact_bytes,
                    second_canonical_precommit_certificate: second.canonical_precommit_certificate,
                })
            }
            Ok(CurrentRoundFinalityClassificationV0::ConflictingRoots { first, second }) => {
                Ok(DriverCurrentFinalitySelectionV0::ConflictingRoots {
                    position,
                    first,
                    second,
                })
            }
            Err(CurrentRoundFinalityClassificationErrorV0::Reservation(source)) => {
                Ok(DriverCurrentFinalitySelectionV0::Reservation(source))
            }
            Err(CurrentRoundFinalityClassificationErrorV0::Invariant(source)) => {
                Ok(DriverCurrentFinalitySelectionV0::Rejected(source))
            }
        }
    }

    fn execute_current_finality(
        mut self,
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
        canonical_precommit_certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let previous_position = self.position();
        let scope = self.take_scope();
        match scope.commit_current_round_finality(
            &canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            &canonical_precommit_certificate,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(
                FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection },
            )) => {
                self.scope = Some(*scope);
                if self.position() != previous_position {
                    let timeout = self.install_next_timeout(next_generation);
                    self.pending_command = Some(PendingCommandV0::Arm(timeout));
                }
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Finality {
                    driver: Box::new(self),
                    selection,
                })
            }
            Ok(FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(
                FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(stop),
            )) => Ok(FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop)),
            Ok(FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::CurrentFinality(
                        rejection,
                    )),
                })
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::CurrentFinality(
                Box::new(source),
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_current_preselection_conflict(
        mut self,
        first_canonical_proposal_control_bytes: Vec<u8>,
        first_canonical_artifact_bytes: Vec<u8>,
        first_canonical_precommit_certificate: Vec<u8>,
        second_canonical_proposal_control_bytes: Vec<u8>,
        second_canonical_artifact_bytes: Vec<u8>,
        second_canonical_precommit_certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let scope = self.take_scope();
        match scope.commit_current_round_preselection_conflict(
            &first_canonical_proposal_control_bytes,
            first_canonical_artifact_bytes,
            &first_canonical_precommit_certificate,
            &second_canonical_proposal_control_bytes,
            second_canonical_artifact_bytes,
            &second_canonical_precommit_certificate,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(
                stop,
            )) => Ok(FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop)),
            Ok(FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::Rejected {
                scope,
                rejection,
            }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::CurrentFinality(
                        rejection,
                    )),
                })
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::CurrentFinality(
                Box::new(source),
            )),
        }
    }

    fn execute_evidence(
        mut self,
        action: FixedValidatorNodeDriverActionV0,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope.try_pair_higher_round_inbox_at(
            &mut self.inbox,
            action.position,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Signed {
                scope,
                vote,
                proposal,
            }) => {
                self.scope = Some(*scope);
                self.invalidate_timeout();
                self.pending_command = Some(PendingCommandV0::Publish {
                    vote,
                    released_proposal: Some(proposal),
                    successor_generation: next_generation,
                });
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Rejected {
                scope,
                rejection,
            }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::EvidenceExecution(rejection),
                    ),
                })
            }
            Ok(FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::SignerStopped(stop)) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Evidence(Box::new(
                source,
            ))),
        }
    }

    fn select_current_nil_precommit(
        &self,
    ) -> Result<DriverCurrentNilPrecommitSelectionV0, FixedValidatorNodeDriverStepErrorV0> {
        let position = self.position();
        let parent_coordinate = self.scope().branch.coordinate();
        if matches!(
            self.current_nil_precommit_inbox
                .preclassify(parent_coordinate, position),
            CurrentRoundNilPrecommitPreclassificationV0::NoMatchingPrecommit
        ) {
            return Ok(DriverCurrentNilPrecommitSelectionV0::None);
        }
        let round = derive_round(&self.scope().branch, position.round())
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
        let selection = self.current_nil_precommit_inbox.select_nil_quorum(&round);
        drop(round);
        match selection {
            Ok(CurrentRoundNilPrecommitQuorumSelectionV0::None) => {
                Ok(DriverCurrentNilPrecommitSelectionV0::None)
            }
            Ok(CurrentRoundNilPrecommitQuorumSelectionV0::One {
                canonical_signed_precommits,
            }) => Ok(DriverCurrentNilPrecommitSelectionV0::One {
                canonical_signed_precommits,
            }),
            Err(CurrentRoundNilPrecommitQuorumSelectionErrorV0::Reservation(source)) => {
                Ok(DriverCurrentNilPrecommitSelectionV0::Reservation(source))
            }
            Err(CurrentRoundNilPrecommitQuorumSelectionErrorV0::Invariant(source)) => {
                Ok(DriverCurrentNilPrecommitSelectionV0::Rejected(source))
            }
        }
    }

    fn execute_current_nil_precommit(
        mut self,
        canonical_signed_precommits: Vec<[u8; VerifiedConsensusVoteV0::BYTE_LENGTH]>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let mut vote_refs: Vec<&[u8]> = Vec::new();
        if let Err(source) = vote_refs.try_reserve_exact(canonical_signed_precommits.len()) {
            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                driver: Box::new(self),
                rejection: Box::new(
                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                ),
            });
        }
        vote_refs.extend(
            canonical_signed_precommits
                .iter()
                .map(|canonical| canonical.as_slice()),
        );
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope
            .advance_round_for_nil_precommit_vote_batch(&vote_refs, self.inclusive_maximum_round)
        {
            Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. }) => {
                self.scope = Some(*scope);
                let timeout = self.install_next_timeout(next_generation);
                self.pending_command = Some(PendingCommandV0::Arm(timeout));
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(
                        rejection,
                    )),
                })
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::RoundAdvance(Box::new(
                source,
            ))),
        }
    }

    fn select_actionable_current(
        &self,
    ) -> Result<DriverCurrentSelectionV0, FixedValidatorNodeDriverStepErrorV0> {
        let position = self.position();
        let parent_coordinate = self.scope().branch.coordinate();
        let proposal = match self
            .current_inbox
            .select_unique_proposal(parent_coordinate, position)
        {
            CurrentRoundProposalSelectionV0::None => None,
            CurrentRoundProposalSelectionV0::One {
                proposal_signing_root,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => Some((
                proposal_signing_root,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            )),
            CurrentRoundProposalSelectionV0::Ambiguous { .. } => {
                unreachable!("current proposal ambiguity is checked before selection")
            }
        };

        match self.phase() {
            FixedValidatorLockPhaseV0::Precommit => Ok(DriverCurrentSelectionV0::None),
            FixedValidatorLockPhaseV0::Proposal => {
                let Some((
                    _proposal_signing_root,
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                )) = proposal
                else {
                    return Ok(DriverCurrentSelectionV0::None);
                };
                let control = match try_copy_bytes(canonical_proposal_control_bytes) {
                    Ok(bytes) => bytes,
                    Err(source) => return Ok(DriverCurrentSelectionV0::Reservation(source)),
                };
                let artifact = match try_copy_bytes(canonical_artifact_bytes) {
                    Ok(bytes) => bytes,
                    Err(source) => return Ok(DriverCurrentSelectionV0::Reservation(source)),
                };
                Ok(DriverCurrentSelectionV0::Proposal {
                    canonical_proposal_control_bytes: control,
                    canonical_artifact_bytes: artifact,
                })
            }
            FixedValidatorLockPhaseV0::Prevote => {
                let round = derive_round(&self.scope().branch, position.round())
                    .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
                let proposal_quorum = if let Some((proposal_signing_root, _, _)) = proposal {
                    self.current_inbox
                        .select_proposal_quorum(&round, proposal_signing_root)
                } else {
                    Ok(CurrentRoundQuorumSelectionV0::None)
                };
                let nil_quorum = self.current_inbox.select_nil_quorum(&round);
                drop(round);
                let proposal_quorum = match proposal_quorum {
                    Ok(quorum) => quorum,
                    Err(CurrentRoundQuorumSelectionErrorV0::Reservation(source)) => {
                        return Ok(DriverCurrentSelectionV0::Reservation(source));
                    }
                    Err(CurrentRoundQuorumSelectionErrorV0::Invariant(source)) => {
                        return Ok(DriverCurrentSelectionV0::Rejected(Box::new(
                            FixedValidatorNodeVoteRejectionV0::QuorumConstruction(Box::new(source)),
                        )));
                    }
                };
                let nil_quorum = match nil_quorum {
                    Ok(quorum) => quorum,
                    Err(CurrentRoundQuorumSelectionErrorV0::Reservation(source)) => {
                        return Ok(DriverCurrentSelectionV0::Reservation(source));
                    }
                    Err(CurrentRoundQuorumSelectionErrorV0::Invariant(source)) => {
                        return Ok(DriverCurrentSelectionV0::Rejected(Box::new(
                            FixedValidatorNodeVoteRejectionV0::QuorumConstruction(Box::new(source)),
                        )));
                    }
                };
                match (proposal_quorum, nil_quorum) {
                    (
                        CurrentRoundQuorumSelectionV0::One { .. },
                        CurrentRoundQuorumSelectionV0::One { .. },
                    ) => {
                        let (proposal_signing_root, _, _) = proposal
                            .expect("an actionable proposal quorum requires its retained proposal");
                        Ok(DriverCurrentSelectionV0::AmbiguousQuorums {
                            position,
                            proposal_signing_root,
                        })
                    }
                    (
                        CurrentRoundQuorumSelectionV0::One {
                            canonical_certificate,
                        },
                        CurrentRoundQuorumSelectionV0::None,
                    ) => {
                        let (_, canonical_proposal_control_bytes, canonical_artifact_bytes) =
                            proposal.expect(
                                "an actionable proposal quorum requires its retained proposal",
                            );
                        let control = match try_copy_bytes(canonical_proposal_control_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(DriverCurrentSelectionV0::Reservation(source));
                            }
                        };
                        let artifact = match try_copy_bytes(canonical_artifact_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(DriverCurrentSelectionV0::Reservation(source));
                            }
                        };
                        Ok(DriverCurrentSelectionV0::ProposalQuorum {
                            canonical_proposal_control_bytes: control,
                            canonical_artifact_bytes: artifact,
                            canonical_prevote_certificate: canonical_certificate,
                        })
                    }
                    (
                        CurrentRoundQuorumSelectionV0::None,
                        CurrentRoundQuorumSelectionV0::One {
                            canonical_certificate,
                        },
                    ) => Ok(DriverCurrentSelectionV0::NilQuorum {
                        canonical_prevote_certificate: canonical_certificate,
                    }),
                    (CurrentRoundQuorumSelectionV0::None, CurrentRoundQuorumSelectionV0::None) => {
                        Ok(DriverCurrentSelectionV0::None)
                    }
                }
            }
        }
    }

    fn execute_current_proposal(
        mut self,
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope.sign_prevote_for_proposal(
            &canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote }) => {
                self.scope = Some(*scope);
                self.invalidate_timeout();
                self.pending_command = Some(PendingCommandV0::Publish {
                    vote,
                    released_proposal: None,
                    successor_generation: next_generation,
                });
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(rejection)),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(stop)) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Vote(Box::new(source))),
        }
    }

    fn execute_current_proposal_quorum(
        mut self,
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
        canonical_prevote_certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope.sign_precommit_for_proposal_quorum(
            &canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            &canonical_prevote_certificate,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote }) => {
                self.scope = Some(*scope);
                self.invalidate_timeout();
                self.pending_command = Some(PendingCommandV0::Publish {
                    vote,
                    released_proposal: None,
                    successor_generation: next_generation,
                });
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(rejection)),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(stop)) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Vote(Box::new(source))),
        }
    }

    fn execute_current_nil_quorum(
        mut self,
        canonical_prevote_certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope.sign_precommit_for_nil_quorum(
            &canonical_prevote_certificate,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote }) => {
                self.scope = Some(*scope);
                self.invalidate_timeout();
                self.pending_command = Some(PendingCommandV0::Publish {
                    vote,
                    released_proposal: None,
                    successor_generation: next_generation,
                });
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(rejection)),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(stop)) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Vote(Box::new(source))),
        }
    }

    fn execute_due(
        mut self,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let active_timeout = self
            .active_timeout
            .expect("a due driver always retains its exact active timeout");
        let context = active_timeout.context;
        let position = active_timeout.position;
        let phase = active_timeout.phase;
        let scope = self.take_scope();
        match phase {
            FixedValidatorLockPhaseV0::Proposal | FixedValidatorLockPhaseV0::Prevote => {
                let result = if phase == FixedValidatorLockPhaseV0::Proposal {
                    scope.sign_prevote_after_proposal_close(
                        context,
                        position,
                        self.inclusive_maximum_round,
                    )
                } else {
                    scope.sign_precommit_after_prevote_close(
                        context,
                        position,
                        self.inclusive_maximum_round,
                    )
                };
                match result {
                    Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote }) => {
                        self.scope = Some(*scope);
                        self.invalidate_timeout();
                        self.pending_command = Some(PendingCommandV0::Publish {
                            vote,
                            released_proposal: None,
                            successor_generation: next_generation,
                        });
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                            driver: Box::new(self),
                        })
                    }
                    Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection }) => {
                        self.scope = Some(*scope);
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                            driver: Box::new(self),
                            rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(
                                rejection,
                            )),
                        })
                    }
                    Ok(FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(stop)) => {
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
                    }
                    Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Vote(Box::new(source))),
                }
            }
            FixedValidatorLockPhaseV0::Precommit => {
                match scope.advance_round_after_precommit_close(
                    context,
                    position,
                    self.inclusive_maximum_round,
                ) {
                    Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. }) => {
                        self.scope = Some(*scope);
                        let timeout = self.install_next_timeout(next_generation);
                        self.pending_command = Some(PendingCommandV0::Arm(timeout));
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                            driver: Box::new(self),
                        })
                    }
                    Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { scope, rejection }) => {
                        self.scope = Some(*scope);
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                            driver: Box::new(self),
                            rejection: Box::new(
                                FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(rejection),
                            ),
                        })
                    }
                    Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::RoundAdvance(
                        Box::new(source),
                    )),
                }
            }
        }
    }

    fn next_generation(&self) -> Result<u64, FixedValidatorNodeDriverStepErrorV0> {
        self.generation.checked_add(1).ok_or(
            FixedValidatorNodeDriverStepErrorV0::TimeoutGenerationExhausted {
                generation: self.generation,
            },
        )
    }

    #[cfg(test)]
    pub(super) fn set_timer_generation_for_test(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn install_next_timeout(&mut self, generation: u64) -> FixedValidatorNodePhaseTimeoutV0 {
        self.generation = generation;
        self.due = false;
        let timeout = FixedValidatorNodePhaseTimeoutV0 {
            lineage: self.lineage,
            context: self.scope().branch.context(),
            position: self.position(),
            phase: self.phase(),
            generation,
        };
        self.active_timeout = Some(timeout);
        timeout
    }

    fn invalidate_timeout(&mut self) {
        self.active_timeout = None;
        self.due = false;
    }

    fn higher_block_reason(&self) -> Option<FixedValidatorNodeDriverBlockReasonV0> {
        self.ambiguity.or_else(|| {
            self.inbox
                .saturation()
                .map(FixedValidatorNodeDriverBlockReasonV0::Saturated)
        })
    }

    fn current_block_reason(&self) -> Option<FixedValidatorNodeDriverBlockReasonV0> {
        if let Some(reason) = self.current_ambiguity {
            return Some(reason);
        }
        let position = self.position();
        if let Some((saturated_position, saturation)) = self.current_inbox.saturation() {
            return Some(FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated {
                position: saturated_position,
                saturation,
            });
        }
        match self
            .current_inbox
            .select_unique_proposal(self.scope().branch.coordinate(), position)
        {
            CurrentRoundProposalSelectionV0::Ambiguous { first, second } => Some(
                FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous {
                    position,
                    first,
                    second,
                },
            ),
            CurrentRoundProposalSelectionV0::None | CurrentRoundProposalSelectionV0::One { .. } => {
                None
            }
        }
    }

    fn scope(&self) -> &FixedValidatorNodeSigningScopeV0<'node> {
        self.scope
            .as_ref()
            .expect("live driver always owns its signing scope")
    }

    fn take_scope(&mut self) -> FixedValidatorNodeSigningScopeV0<'node> {
        self.scope
            .take()
            .expect("live driver always owns its signing scope")
    }
}

enum DriverEvidenceSelectionV0 {
    None,
    One(FixedValidatorNodeDriverActionV0),
    Ambiguous {
        first: FixedValidatorNodeDriverActionV0,
        second: FixedValidatorNodeDriverActionV0,
    },
    Rejected(Box<FixedValidatorNodeBufferedProposalPrecommitRejectionV0>),
    Reservation(TryReserveError),
}

enum DriverCurrentFinalitySelectionV0<'inbox> {
    None,
    MissingProposal {
        position: ConsensusPosition,
        proposal_signing_root: ProposalSigningRoot,
    },
    Ready {
        action: FixedValidatorNodeDriverFinalityActionV0,
        canonical_proposal_control_bytes: &'inbox [u8],
        canonical_artifact_bytes: &'inbox [u8],
        canonical_precommit_certificate: Vec<u8>,
    },
    PreselectionConflict {
        first_action: FixedValidatorNodeDriverFinalityActionV0,
        first_canonical_proposal_control_bytes: &'inbox [u8],
        first_canonical_artifact_bytes: &'inbox [u8],
        first_canonical_precommit_certificate: Vec<u8>,
        second_action: FixedValidatorNodeDriverFinalityActionV0,
        second_canonical_proposal_control_bytes: &'inbox [u8],
        second_canonical_artifact_bytes: &'inbox [u8],
        second_canonical_precommit_certificate: Vec<u8>,
    },
    ConflictingRoots {
        position: ConsensusPosition,
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    },
    Rejected(QuorumCertificateBuildError),
    Reservation(TryReserveError),
}

enum DriverCurrentNilPrecommitSelectionV0 {
    None,
    One {
        canonical_signed_precommits: Vec<[u8; VerifiedConsensusVoteV0::BYTE_LENGTH]>,
    },
    Rejected(QuorumCertificateBuildError),
    Reservation(TryReserveError),
}

enum DriverCurrentSelectionV0 {
    None,
    Proposal {
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
    },
    ProposalQuorum {
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
        canonical_prevote_certificate: Vec<u8>,
    },
    NilQuorum {
        canonical_prevote_certificate: Vec<u8>,
    },
    AmbiguousQuorums {
        position: ConsensusPosition,
        proposal_signing_root: ProposalSigningRoot,
    },
    Rejected(Box<FixedValidatorNodeVoteRejectionV0>),
    Reservation(TryReserveError),
}

#[derive(Clone, Copy)]
enum CurrentProposalDestinationV0 {
    Voting,
    Finality,
}

enum CurrentProposalVerificationErrorV0 {
    PayloadTooLong { actual: usize, maximum: usize },
    Control(ConsensusProposalVerifyError),
    PayloadCopy(TryReserveError),
}

impl CurrentProposalVerificationErrorV0 {
    fn into_admission_rejection(
        self,
        destination: CurrentProposalDestinationV0,
    ) -> FixedValidatorNodeDriverAdmissionRejectionV0 {
        match self {
            Self::PayloadTooLong { actual, maximum } => {
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadTooLong {
                    actual,
                    maximum,
                }
            }
            Self::Control(source) => match destination {
                CurrentProposalDestinationV0::Voting => {
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(Box::new(source))
                }
                CurrentProposalDestinationV0::Finality => {
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityProposal(Box::new(
                        source,
                    ))
                }
            },
            Self::PayloadCopy(source) => {
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadCopy(source)
            }
        }
    }
}

fn derive_round(
    branch: &naome_consensus::FixedConsensusBranchV0,
    required_round: ConsensusRound,
) -> Result<FixedConsensusRoundV0<'_>, ProposerSelectionError> {
    let mut round = branch.begin_round_zero()?;
    for _ in 0..required_round.value() {
        round = round.advance_round()?;
    }
    debug_assert_eq!(round.position().round(), required_round);
    Ok(round)
}

fn verify_current_proposal_at_round(
    round: &FixedConsensusRoundV0<'_>,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: &[u8],
) -> Result<Box<FixedValidatorNodeDeferredProposalV0>, CurrentProposalVerificationErrorV0> {
    let payload_len = canonical_artifact_bytes.len();
    if payload_len > ARTIFACT_PAYLOAD_MAX_BYTES {
        return Err(CurrentProposalVerificationErrorV0::PayloadTooLong {
            actual: payload_len,
            maximum: ARTIFACT_PAYLOAD_MAX_BYTES,
        });
    }
    preflight_deferred_proposal_control_framing(canonical_proposal_control_bytes)
        .map_err(CurrentProposalVerificationErrorV0::Control)?;
    let artifact_copy = try_copy_bytes(canonical_artifact_bytes)
        .map_err(CurrentProposalVerificationErrorV0::PayloadCopy)?;
    verify_deferred_proposal_at_round(round, canonical_proposal_control_bytes, artifact_copy)
        .map_err(CurrentProposalVerificationErrorV0::Control)
}

fn map_create_error(
    error: FixedValidatorNodeCurrentRoundErrorV0,
) -> FixedValidatorNodeDriverCreateErrorV0 {
    match error {
        FixedValidatorNodeCurrentRoundErrorV0::SignerBranchHeightMismatch {
            signer,
            branch_next_height,
        } => FixedValidatorNodeDriverCreateErrorV0::SignerBranchHeightMismatch {
            signer,
            branch_next_height,
        },
        FixedValidatorNodeCurrentRoundErrorV0::Round(source) => {
            FixedValidatorNodeDriverCreateErrorV0::Round(source)
        }
        FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded { required, maximum } => {
            FixedValidatorNodeDriverCreateErrorV0::FinalityRoundLimitExceeded { required, maximum }
        }
        FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded { required, maximum } => {
            FixedValidatorNodeDriverCreateErrorV0::RoundWorkLimitExceeded { required, maximum }
        }
        FixedValidatorNodeCurrentRoundErrorV0::Session(source) => {
            FixedValidatorNodeDriverCreateErrorV0::Session(source)
        }
    }
}

fn admitted<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    disposition: FixedValidatorNodeDriverAdmissionDispositionV0,
) -> FixedValidatorNodeDriverAdmissionOutcomeV0<'node> {
    FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted {
        driver: Box::new(driver),
        disposition,
    }
}

fn admission_rejected<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    event: FixedValidatorNodeDriverEventV0,
    rejection: FixedValidatorNodeDriverAdmissionRejectionV0,
) -> FixedValidatorNodeDriverAdmissionOutcomeV0<'node> {
    FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
        driver: Box::new(driver),
        event: Box::new(event),
        rejection: Box::new(rejection),
    }
}

fn proposal_event(
    proposal_round: ConsensusRound,
    canonical_proposal_control_bytes: &mut Option<Box<[u8]>>,
    canonical_artifact_bytes: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundProposal {
        proposal_round,
        canonical_proposal_control_bytes: canonical_proposal_control_bytes
            .take()
            .expect("rejected proposal retains its original control bytes"),
        canonical_artifact_bytes: canonical_artifact_bytes
            .take()
            .expect("rejected proposal retains its original payload bytes"),
    }
}

fn current_proposal_event(
    canonical_proposal_control_bytes: &mut Option<Box<[u8]>>,
    canonical_artifact_bytes: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
        canonical_proposal_control_bytes: canonical_proposal_control_bytes
            .take()
            .expect("rejected current proposal retains its original control bytes"),
        canonical_artifact_bytes: canonical_artifact_bytes
            .take()
            .expect("rejected current proposal retains its original payload bytes"),
    }
}

fn current_finality_proposal_event(
    canonical_proposal_control_bytes: &mut Option<Box<[u8]>>,
    canonical_artifact_bytes: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
        canonical_proposal_control_bytes: canonical_proposal_control_bytes
            .take()
            .expect("rejected current finality proposal retains its original control bytes"),
        canonical_artifact_bytes: canonical_artifact_bytes
            .take()
            .expect("rejected current finality proposal retains its original payload bytes"),
    }
}

fn current_finality_precommit_event(
    canonical_signed_precommit: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
        canonical_signed_precommit: canonical_signed_precommit
            .take()
            .expect("rejected current proposal precommit retains its original bytes"),
    }
}

fn current_nil_precommit_event(
    canonical_signed_precommit: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit {
        canonical_signed_precommit: canonical_signed_precommit
            .take()
            .expect("rejected current nil precommit retains its original bytes"),
    }
}

fn current_prevote_event(
    canonical_signed_prevote: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
        canonical_signed_prevote: canonical_signed_prevote
            .take()
            .expect("rejected current proposal prevote retains its original bytes"),
    }
}

fn current_nil_prevote_event(
    canonical_signed_prevote: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
        canonical_signed_prevote: canonical_signed_prevote
            .take()
            .expect("rejected current nil prevote retains its original bytes"),
    }
}

fn prevote_event(
    canonical_signed_prevote: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
        canonical_signed_prevote: canonical_signed_prevote
            .take()
            .expect("rejected proposal prevote retains its original bytes"),
    }
}

fn try_copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, TryReserveError> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len())?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}
