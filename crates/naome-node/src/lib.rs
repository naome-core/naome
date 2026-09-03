//! Explicit lifecycle integration for a NAOME node.
//!
//! The fixed-validator V0 boundary composes exact caller configuration,
//! anchored finality, and one anchored per-key vote-safety journal. It owns
//! strict provisioning, restart ordering, and consuming sealed or
//! candidate-backed finality-to-signer coupling plus bounded exact-current and
//! strictly lower-round certificate or exact signed-precommit-batch finality
//! admission, including caller-targeted candidate-backed batch admission;
//! direct and exact-target fresh-only candidate-store-backed plus exact
//! retained-value payload-store-backed current-round proposal authoring; direct
//! plus exact-target candidate- and payload-store-backed proposal vote
//! execution; exact signed-prevote-batch quorum construction for proposal and
//! nil precommit execution;
//! exact-event-bound current-round phase-close voting, exact-event-bound
//! sequential, quorum-driven, and caller-routed exact signed-vote-batch round
//! progression, caller-owned fully verified higher-round proposal deferral, and
//! a separately composed bounded volatile proposal buffer with mandatory later
//! full branch-relative re-verification plus exact caller-addressed
//! proposal/prevote-quorum catch-up from either a prebuilt certificate or an
//! exact signed-prevote batch and anchored precommit completion. A combined
//! bounded process-local higher-round inbox additionally retains typed-round-
//! admitted proposal prevotes and explicitly pairs one uniquely actionable
//! proposal-bearing quorum using local lexicographic evidence normalization,
//! while a closure-scoped driver owns that inbox and the sole signing scope,
//! prioritizes one unique actionable higher-round pair over an exact opaque
//! generation-bound phase-timer return, and serializes anchored vote publication
//! and timer-arm commands. It deliberately leaves daemon scheduling, networking,
//! timeout measurement and duration, key loading, finality event routing, and
//! branch-selection policy to later components.

mod fixed_validator_startup;

pub use fixed_validator_startup::{
    FixedValidatorNodeBufferedProposalPrecommitErrorV0,
    FixedValidatorNodeBufferedProposalPrecommitOutcomeV0,
    FixedValidatorNodeBufferedProposalPrecommitRejectionV0,
    FixedValidatorNodeCandidateBackedFinalityErrorV0,
    FixedValidatorNodeCandidateBackedFinalityOutcomeV0,
    FixedValidatorNodeCandidateBackedFinalityRejectionV0,
    FixedValidatorNodeCurrentRoundFinalityErrorV0, FixedValidatorNodeCurrentRoundFinalityOutcomeV0,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0, FixedValidatorNodeDeferredProposalV0,
    FixedValidatorNodeDirectoriesV0, FixedValidatorNodeDriverActionV0,
    FixedValidatorNodeDriverAdmissionDispositionV0, FixedValidatorNodeDriverAdmissionErrorV0,
    FixedValidatorNodeDriverAdmissionOutcomeV0, FixedValidatorNodeDriverAdmissionRejectionV0,
    FixedValidatorNodeDriverBlockReasonV0, FixedValidatorNodeDriverCommandV0,
    FixedValidatorNodeDriverCreateErrorV0, FixedValidatorNodeDriverDrainV0,
    FixedValidatorNodeDriverEventV0, FixedValidatorNodeDriverStepErrorV0,
    FixedValidatorNodeDriverStepOutcomeV0, FixedValidatorNodeDriverStepRejectionV0,
    FixedValidatorNodeDriverV0, FixedValidatorNodeFinalityErrorV0,
    FixedValidatorNodeFinalityOutcomeV0, FixedValidatorNodeFinalityRoundRouteV0,
    FixedValidatorNodeFinalitySelectionV0, FixedValidatorNodeFinalityStoppedV0,
    FixedValidatorNodeHigherRoundInboxAccessErrorV0, FixedValidatorNodeHigherRoundInboxDrainItemV0,
    FixedValidatorNodeHigherRoundInboxDrainV0, FixedValidatorNodeHigherRoundInboxLimitsErrorV0,
    FixedValidatorNodeHigherRoundInboxLimitsV0,
    FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0,
    FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0,
    FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0,
    FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0,
    FixedValidatorNodeHigherRoundInboxSaturationV0, FixedValidatorNodeHigherRoundInboxV0,
    FixedValidatorNodeHigherRoundProposalRouteV0, FixedValidatorNodeHigherRoundVoteBatchRouteV0,
    FixedValidatorNodeLowerRoundFinalityErrorV0, FixedValidatorNodeLowerRoundFinalityOutcomeV0,
    FixedValidatorNodeLowerRoundFinalityRejectionV0, FixedValidatorNodePhaseTimeoutV0,
    FixedValidatorNodeProposalAuthoringErrorV0, FixedValidatorNodeProposalAuthoringOutcomeV0,
    FixedValidatorNodeProposalAuthoringRejectionV0, FixedValidatorNodeProposalBufferAccessErrorV0,
    FixedValidatorNodeProposalBufferDrainV0, FixedValidatorNodeProposalBufferInsertErrorV0,
    FixedValidatorNodeProposalBufferInsertOutcomeV0, FixedValidatorNodeProposalBufferLimitsErrorV0,
    FixedValidatorNodeProposalBufferLimitsV0, FixedValidatorNodeProposalBufferSaturationV0,
    FixedValidatorNodeProposalBufferV0, FixedValidatorNodeProposalDeferralErrorV0,
    FixedValidatorNodeProposalDeferralOutcomeV0, FixedValidatorNodeProposalDeferralRejectionV0,
    FixedValidatorNodeProvisionV0, FixedValidatorNodeReadyV0,
    FixedValidatorNodeRoundAdvanceErrorV0, FixedValidatorNodeRoundAdvanceOutcomeV0,
    FixedValidatorNodeRoundAdvanceRejectionV0, FixedValidatorNodeSignerStopV0,
    FixedValidatorNodeSigningScopeV0, FixedValidatorNodeStartupErrorV0,
    FixedValidatorNodeStartupV0, FixedValidatorNodeVoteExecutionErrorV0,
    FixedValidatorNodeVoteExecutionOutcomeV0, FixedValidatorNodeVoteRejectionV0,
    FixedValidatorNodeVotingSessionV0, FixedValidatorSignerCatchUpHeightLimitV0,
};
