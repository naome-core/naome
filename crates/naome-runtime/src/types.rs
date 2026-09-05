//! Public outcomes preserve exact custody at every caller-visible yield.

use std::{collections::TryReserveError, error::Error, fmt};

use naome_consensus::{
    ConsensusPosition, FixedValidatorLockPhaseV0, FixedValidatorProposalSourceV0,
};
use naome_network::{
    ConsensusPushLengthError, ConsensusPushMessage, ConsensusPushSize, InboundConsensusPush,
    NetworkEvent, PeerId, StaticArtifactNetwork,
};
use naome_node::{
    FixedValidatorNodeCandidateBackedFinalityRejectionV0,
    FixedValidatorNodeCurrentRoundFinalityErrorV0,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0,
    FixedValidatorNodeDriverAdmissionDispositionV0, FixedValidatorNodeDriverAdmissionErrorV0,
    FixedValidatorNodeDriverAdmissionOutcomeV0, FixedValidatorNodeDriverAdmissionRejectionV0,
    FixedValidatorNodeDriverBlockReasonV0,
    FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0,
    FixedValidatorNodeDriverCandidateBackedFinalityErrorV0,
    FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0, FixedValidatorNodeDriverCommandV0,
    FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0,
    FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0,
    FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0,
    FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeDriverProposalAuthoringOutcomeV0, FixedValidatorNodeDriverStepErrorV0,
    FixedValidatorNodeDriverStepOutcomeV0, FixedValidatorNodeDriverStepRejectionV0,
    FixedValidatorNodeDriverV0, FixedValidatorNodeFinalityErrorV0,
    FixedValidatorNodeFinalitySelectionV0, FixedValidatorNodeFinalityStoppedV0,
    FixedValidatorNodeLowerRoundFinalityErrorV0, FixedValidatorNodeLowerRoundFinalityRejectionV0,
    FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0, FixedValidatorNodePhaseTimeoutV0,
    FixedValidatorNodeProposalAuthoringRejectionV0, FixedValidatorNodeRoundAdvanceRejectionV0,
};
use naome_storage::{FixedValidatorProposalSafetyHaltV0, FixedValidatorVoteSafetyHaltV0};

use crate::{
    FixedValidatorRuntimeAdmissionReportV0, FixedValidatorRuntimePublicationV0,
    FixedValidatorRuntimeTimeoutsV0, FixedValidatorRuntimeTimerV0,
    FixedValidatorRuntimeTimingErrorV0,
};

/// One transport poll, not evidence that any receipt was written or received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedValidatorRuntimeTransportPollV0 {
    InputSlotOccupied,
    PolledPending,
    BufferedEvent,
}

/// A queue refusal performs no routing, admission, timer, or transport work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedValidatorRuntimeQueueFailureV0 {
    DriverUnavailable,
    InputSlotOccupied,
    Length(ConsensusPushLengthError),
}

/// The caller's original message, including its allocations, on queue refusal.
#[derive(Debug)]
pub struct FixedValidatorRuntimeQueueErrorV0 {
    pub input: ConsensusPushMessage,
    pub reason: FixedValidatorRuntimeQueueFailureV0,
}

impl fmt::Display for FixedValidatorRuntimeQueueErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fixed-validator runtime input queue refused: {:?}",
            self.reason
        )
    }
}

impl Error for FixedValidatorRuntimeQueueErrorV0 {}

/// No driver proof operation occurred. Borrowed inputs remain with the caller;
/// methods with owned payloads return their exact allocations beside this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedValidatorRuntimeProofRefusalV0 {
    DriverUnavailable,
    Busy,
}

/// One bounded action or ownership transfer. No outcome is a liveness guarantee.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorRuntimeEventV0<'node> {
    TimerArmed(FixedValidatorRuntimeTimerV0),
    TimerDue {
        ticket: FixedValidatorNodePhaseTimeoutV0,
        result: Result<
            FixedValidatorNodeDriverAdmissionDispositionV0,
            Box<FixedValidatorNodeDriverAdmissionRejectionV0>,
        >,
    },
    Transitioned {
        position: ConsensusPosition,
        phase: FixedValidatorLockPhaseV0,
    },
    Finality(FixedValidatorNodeFinalitySelectionV0),
    DriverBlocked(FixedValidatorNodeDriverBlockReasonV0),
    DriverRejected(Box<FixedValidatorNodeDriverStepRejectionV0>),
    PublicationPrepared(ConsensusPushSize),
    PeerAttempted {
        peer_id: PeerId,
        started: bool,
    },
    PeerCompleted {
        peer_id: PeerId,
        received: bool,
    },
    PublicationComplete(Box<FixedValidatorRuntimePublicationV0>),
    Admission(Box<FixedValidatorRuntimeAdmissionReportV0>),
    /// Allocation failed before any receipt or driver admission; the exact
    /// inbound handle transfers to the caller and still owns its response path.
    UnacknowledgedInput {
        inbound: InboundConsensusPush,
        error: TryReserveError,
    },
    /// Every unrelated or unmatched transport event transfers without inspection.
    Network(NetworkEvent),
    /// The exact arm/publication remains in the runtime. No implicit retry of a
    /// transport attempt occurs when the caller polls again.
    ReservationFailed(TryReserveError),
    TimingRejected(FixedValidatorRuntimeTimingErrorV0),
    ProposalAuthored,
    AuthoringStepWorkPending,
    ProposalRejected(Box<FixedValidatorNodeProposalAuthoringRejectionV0>),
    /// Preflight did not consume the caller's proposal source.
    AuthoringBusy(FixedValidatorProposalSourceV0),
    AuthoringUnavailable(FixedValidatorProposalSourceV0),
    /// Runtime preflight did not access either caller-borrowed source store.
    StoreAuthoringBusy,
    StoreAuthoringUnavailable,
    ExplicitCommandPending,
    CurrentFinalityUnresolved,
    HigherEvidenceUnresolved,
    HigherRoundAdvanceRejected(Box<FixedValidatorNodeRoundAdvanceRejectionV0>),
    CurrentRoundFinalityRejected(Box<FixedValidatorNodeCurrentRoundFinalityRejectionV0>),
    LowerRoundFinalityRejected(Box<FixedValidatorNodeLowerRoundFinalityRejectionV0>),
    CandidateBackedFinalityRejected(Box<FixedValidatorNodeCandidateBackedFinalityRejectionV0>),
    LowerRoundPreselectionConflictRejected(
        Box<FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0>,
    ),
    CurrentRoundPreselectionConflictRejected(
        Box<FixedValidatorNodeCurrentRoundFinalityRejectionV0>,
    ),
    /// No driver survives. Only independently retained runtime custody remains.
    Fatal(Box<FixedValidatorRuntimeFailureV0>),
    DriverUnavailable,
    /// Future dependency variants transfer intact, including any driver they own.
    UnsupportedCommand(FixedValidatorNodeDriverCommandV0),
    UnsupportedStep(Box<FixedValidatorNodeDriverStepOutcomeV0<'node>>),
    UnsupportedAdmission(Box<FixedValidatorNodeDriverAdmissionOutcomeV0<'node>>),
    UnsupportedAuthoring(Box<FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'node>>),
    UnsupportedHigherRoundAdvance(Box<FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0<'node>>),
    UnsupportedCurrentRoundFinality(
        Box<FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0<'node>>,
    ),
    UnsupportedLowerRoundFinality(Box<FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0<'node>>),
    UnsupportedCandidateBackedFinality(
        Box<FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0<'node>>,
    ),
    UnsupportedCandidateBackedConflict(
        Box<FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0<'node>>,
    ),
    UnsupportedLowerRoundPreselectionConflict(
        Box<FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0<'node>>,
    ),
    UnsupportedCurrentRoundPreselectionConflict(
        Box<FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0<'node>>,
    ),
}

#[derive(Debug)]
pub enum FixedValidatorRuntimeFailureV0 {
    Step(FixedValidatorNodeDriverStepErrorV0),
    Admission(FixedValidatorNodeDriverAdmissionErrorV0),
    VoteSignerStopped(FixedValidatorVoteSafetyHaltV0),
    ProposalSignerStopped(FixedValidatorProposalSafetyHaltV0),
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
    CandidateBackedFinality(FixedValidatorNodeDriverCandidateBackedFinalityErrorV0),
    CandidateBackedConflict(FixedValidatorNodeFinalityErrorV0),
    LowerRoundPreselectionConflict(FixedValidatorNodeLowerRoundFinalityErrorV0),
    CurrentRoundPreselectionConflict(FixedValidatorNodeCurrentRoundFinalityErrorV0),
}

impl fmt::Display for FixedValidatorRuntimeFailureV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fixed-validator runtime requires strict restart: {self:?}"
        )
    }
}

impl Error for FixedValidatorRuntimeFailureV0 {}

/// All surviving ownership on an explicit runtime teardown, with no cancellation
/// or recovery claim. In-flight tickets remain inside `publication`.
#[must_use]
pub struct FixedValidatorRuntimePartsV0<'node> {
    pub driver: Option<FixedValidatorNodeDriverV0<'node>>,
    pub network: StaticArtifactNetwork,
    pub peers: Vec<PeerId>,
    pub timeouts: FixedValidatorRuntimeTimeoutsV0,
    pub timer: Option<FixedValidatorRuntimeTimerV0>,
    pub pending_arm: Option<FixedValidatorNodePhaseTimeoutV0>,
    pub publication: Option<FixedValidatorRuntimePublicationV0>,
    pub pending_network_event: Option<NetworkEvent>,
    /// Shares one slot with `pending_network_event`; at most one is present.
    pub pending_caller_input: Option<ConsensusPushMessage>,
    pub failed_admission: Option<FixedValidatorRuntimeAdmissionReportV0>,
    /// The last driver step yielded a blocker or rejection; strict input,
    /// accepted due state, an explicit drain, or proof advancement re-enables
    /// classification.
    pub step_yielded: bool,
    /// An expired exact ticket rejected by the monotone higher-inbox block.
    pub rejected_due_ticket: Option<FixedValidatorNodePhaseTimeoutV0>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedValidatorRuntimeCreateFailureV0 {
    TooManyPeers { actual: usize, maximum: usize },
    DuplicatePeer(PeerId),
    UnconfiguredPeer(PeerId),
    Timing(FixedValidatorRuntimeTimingErrorV0),
}

/// Construction rejection returns every owned input unchanged.
#[must_use]
pub struct FixedValidatorRuntimeCreateErrorV0<'node> {
    pub driver: FixedValidatorNodeDriverV0<'node>,
    pub network: StaticArtifactNetwork,
    pub peers: Vec<PeerId>,
    pub timeouts: FixedValidatorRuntimeTimeoutsV0,
    pub reason: FixedValidatorRuntimeCreateFailureV0,
}

impl fmt::Debug for FixedValidatorRuntimeCreateErrorV0<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedValidatorRuntimeCreateErrorV0")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}
