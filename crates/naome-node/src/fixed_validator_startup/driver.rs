use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_consensus::{
    ConsensusContextV0, ConsensusHeight, ConsensusPosition, ConsensusRound,
    ConsensusVoteVerifyError, FixedConsensusRoundV0, FixedValidatorLockPhaseV0,
    ProposalSigningRoot, ProposerSelectionError, VerifiedConsensusVoteV0,
};
use naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;
use naome_storage::{
    FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyHaltV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::higher_round_proposal_pairing::{ActionableInboxSelectionV0, ActionableInboxSnapshotV0};
use super::proposal_deferral::{
    CurrentRoundErrorV0, preflight_deferred_proposal_control_framing,
    preflight_higher_round_proposal_route, verify_deferred_proposal_at_round,
};
use super::{
    FixedValidatorNodeBufferedProposalPrecommitErrorV0,
    FixedValidatorNodeBufferedProposalPrecommitOutcomeV0,
    FixedValidatorNodeBufferedProposalPrecommitRejectionV0, FixedValidatorNodeCurrentRoundErrorV0,
    FixedValidatorNodeDeferredProposalV0, FixedValidatorNodeHigherRoundInboxDrainV0,
    FixedValidatorNodeHigherRoundInboxLimitsV0,
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
    /// One distinct proposal or proposal-prevote was retained.
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
    /// Preserving the original proposal event while verifying a copy failed.
    ProposalPayloadCopy(TryReserveError),
    /// The owned payload exceeds the canonical artifact-envelope byte limit.
    ProposalPayloadTooLong { actual: usize, maximum: usize },
    /// Complete higher-round proposal admission rejected the routed input.
    Proposal(Box<FixedValidatorNodeProposalDeferralRejectionV0>),
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
            Self::ProposalPayloadCopy(source) => write!(
                formatter,
                "driver proposal payload copy failed before admission: {source}"
            ),
            Self::ProposalPayloadTooLong { actual, maximum } => write!(
                formatter,
                "driver proposal payload has {actual} bytes; the canonical limit is {maximum}"
            ),
            Self::Proposal(source) => source.fmt(formatter),
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
            Self::ProposalInbox(source) => Some(source.as_ref()),
            Self::PrevoteRouting(source) => Some(source),
            Self::PrevoteInbox(source) => Some(source.as_ref()),
            Self::CommandPending
            | Self::Blocked(_)
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
    /// Complete higher-round proposal admission found a fatal node failure.
    Proposal(Box<FixedValidatorNodeProposalDeferralErrorV0>),
    /// The authenticated proposal-prevote round could not be derived.
    Round(ProposerSelectionError),
}

impl fmt::Display for FixedValidatorNodeDriverAdmissionErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

/// A deny-only driver state that requires a full lossless inbox drain/reset.
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
}

impl fmt::Display for FixedValidatorNodeDriverBlockReasonV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Saturated(source) => source.fmt(formatter),
            Self::Ambiguous { first, second } => write!(
                formatter,
                "driver snapshot has distinct actionable proposal quorums {first:?} and {second:?}"
            ),
        }
    }
}

/// A mutation-free rejection returned by one driver step.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverStepRejectionV0 {
    /// Temporary position-selection storage could not be reserved.
    SelectionReservation(TryReserveError),
    /// Existing inbox classification rejected retained evidence before mutation.
    EvidenceSelection(Box<FixedValidatorNodeBufferedProposalPrecommitRejectionV0>),
    /// The selected evidence changed or failed re-admission before mutation.
    EvidenceExecution(Box<FixedValidatorNodeBufferedProposalPrecommitRejectionV0>),
    /// The exact due Proposal or Prevote close was rejected before mutation.
    Vote(Box<FixedValidatorNodeVoteRejectionV0>),
    /// The exact due Precommit close was rejected before mutation.
    RoundAdvance(Box<FixedValidatorNodeRoundAdvanceRejectionV0>),
}

impl fmt::Display for FixedValidatorNodeDriverStepRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectionReservation(source) => write!(
                formatter,
                "driver snapshot position reservation failed: {source}"
            ),
            Self::EvidenceSelection(source) | Self::EvidenceExecution(source) => {
                source.fmt(formatter)
            }
            Self::Vote(source) => source.fmt(formatter),
            Self::RoundAdvance(source) => source.fmt(formatter),
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
    /// No evidence or exact due timer was actionable.
    Idle {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    /// Saturation or same-class ambiguity denied both evidence and timeout action.
    ///
    /// This step may newly latch ambiguity, but it causes no signer or durable effect.
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
}

/// Fatal driver-step failure; no driver or signing scope is returned.
///
/// On `Err`, consuming the step loses both volatile owners even when the failure
/// occurs before a coordinator starts. Recover only through strict reopen into a
/// fresh driver.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverStepErrorV0 {
    /// A retained higher-round position could not be derived.
    Round(ProposerSelectionError),
    /// The checked timer generation has no successor.
    TimeoutGenerationExhausted { generation: u64 },
    /// Higher-round pairing failed after the consuming boundary began.
    Evidence(Box<FixedValidatorNodeBufferedProposalPrecommitErrorV0>),
    /// Proposal- or Prevote-close voting failed after the consuming boundary began.
    Vote(Box<FixedValidatorNodeVoteExecutionErrorV0>),
    /// Precommit-close progression failed after the consuming boundary began.
    RoundAdvance(Box<FixedValidatorNodeRoundAdvanceErrorV0>),
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
/// The driver privately owns the sole live signing scope. It exposes neither an
/// escape hatch back to that scope nor a caller-selected action method. Evidence
/// and due timers become authoritative only through the existing fully checking
/// consuming coordinators selected by [`Self::step`].
#[must_use]
pub struct FixedValidatorNodeDriverV0<'node> {
    scope: Option<FixedValidatorNodeSigningScopeV0<'node>>,
    inbox: FixedValidatorNodeHigherRoundInboxV0,
    inclusive_maximum_round: ConsensusRound,
    lineage: u64,
    generation: u64,
    active_timeout: Option<FixedValidatorNodePhaseTimeoutV0>,
    due: bool,
    ambiguity: Option<FixedValidatorNodeDriverBlockReasonV0>,
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
            inclusive_maximum_round,
            lineage,
            generation: 0,
            active_timeout: Some(active_timeout),
            due: false,
            ambiguity: None,
            pending_command: Some(PendingCommandV0::Arm(active_timeout)),
        })
    }

    /// Returns the exact live signer position as read-only diagnostics.
    pub fn position(&self) -> ConsensusPosition {
        self.scope().signing_session.position()
    }

    /// Returns the exact live lock phase as read-only diagnostics.
    pub fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.scope().signing_session.phase()
    }

    /// Returns this driver's inclusive local round-work ceiling.
    pub const fn inclusive_maximum_round(&self) -> ConsensusRound {
        self.inclusive_maximum_round
    }

    /// Returns the combined retained proposal and proposal-prevote count.
    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
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
        if let Some(reason) = self.block_reason() {
            return Ok(admission_rejected(
                self,
                event,
                FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
            ));
        }
        match event {
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
        if let Some(reason) = self.block_reason() {
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

        if self.due {
            self.execute_due()
        } else {
            Ok(FixedValidatorNodeDriverStepOutcomeV0::Idle {
                driver: Box::new(self),
            })
        }
    }

    /// Losslessly returns all retained evidence and clears deny-only blocking.
    pub fn drain_inbox_and_reset(mut self) -> FixedValidatorNodeDriverDrainV0<'node> {
        let drained = self.inbox.drain_and_reset();
        self.ambiguity = None;
        FixedValidatorNodeDriverDrainV0 {
            driver: Box::new(self),
            drained,
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

    fn block_reason(&self) -> Option<FixedValidatorNodeDriverBlockReasonV0> {
        self.ambiguity.or_else(|| {
            self.inbox
                .saturation()
                .map(FixedValidatorNodeDriverBlockReasonV0::Saturated)
        })
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

fn prevote_event(
    canonical_signed_prevote: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
        canonical_signed_prevote: canonical_signed_prevote
            .take()
            .expect("rejected proposal prevote retains its original bytes"),
    }
}
