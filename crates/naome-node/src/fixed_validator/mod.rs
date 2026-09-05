//! Fixed-validator startup, authority, evidence, and execution responsibilities.

use std::error::Error;
use std::fmt;
use std::path::Path;

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_consensus::{
    ActiveAgreementEntry, ConsensusContextV0, ConsensusHeight, ConsensusKey, ConsensusPosition,
    ConsensusRound, FixedConsensusBranchV0, FixedConsensusGenesisError, FixedConsensusRoundV0,
    FixedValidatorLockPhaseV0, FixedValidatorLockedValueV0, FixedValidatorProposalSourceV0,
    FixedValidatorUnsignedVoteEffectV0, FixedValidatorValidValueV0, ProposerSelectionError,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    FixedValidatorAnchoredFinalityJournalErrorV0, FixedValidatorAnchoredFinalityJournalV0,
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorAnchoredVoteSafetyJournalV0,
    FixedValidatorAnchoredVoteSafetySigningSessionV0,
    FixedValidatorDurablePrepareAcknowledgementV0,
    FixedValidatorDurableProposalPrepareAcknowledgementV0,
    FixedValidatorFinalityConflictSignerStopOutcomeV0, FixedValidatorFinalityConflictSignerStopV0,
    FixedValidatorFinalityHaltV0, FixedValidatorFinalityJournalErrorV0,
    FixedValidatorFinalityReplayLimitV0, FixedValidatorPendingProposalV0,
    FixedValidatorPendingVoteV0, FixedValidatorPreparedHigherRoundAdvanceV0,
    FixedValidatorPreparedProposalV0, FixedValidatorPreparedVoteV0,
    FixedValidatorProposalPrepareOutcomeV0, FixedValidatorProposalReplayLimitV0,
    FixedValidatorProposalSafetyHaltV0, FixedValidatorRecoveredSignerBranchV0,
    FixedValidatorSignedProposalV0, FixedValidatorSignedVoteV0,
    FixedValidatorSignerRecoveryRoundLimitV0, FixedValidatorVotePrepareOutcomeV0,
    FixedValidatorVoteSafetyHaltV0, FixedValidatorVoteSafetyJournalErrorV0,
    FixedValidatorVoteSafetyReplayLimitV0,
};

mod proposal;
use proposal::{
    candidate_backed_proposal, higher_round_proposal_pairing, proposal_authoring, proposal_deferral,
};
mod inbox;
use inbox::{
    current_round_finality_inbox, current_round_inbox, current_round_nil_precommit_inbox,
    higher_round_inbox, proposal_buffer,
};
mod driver;
mod finality;
mod round_progression;
mod voting;

pub use current_round_finality_inbox::{
    FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0,
    FixedValidatorNodeCurrentRoundFinalityInboxDrainV0,
    FixedValidatorNodeCurrentRoundFinalityInboxLimitsErrorV0,
    FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
};
pub use current_round_inbox::{
    FixedValidatorNodeCurrentRoundInboxDrainItemV0, FixedValidatorNodeCurrentRoundInboxDrainV0,
    FixedValidatorNodeCurrentRoundInboxLimitsErrorV0, FixedValidatorNodeCurrentRoundInboxLimitsV0,
    FixedValidatorNodeCurrentRoundInboxSaturationV0,
};
pub use current_round_nil_precommit_inbox::{
    FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsErrorV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0,
};
pub use driver::{
    FixedValidatorNodeDriverActionV0, FixedValidatorNodeDriverAdmissionDispositionV0,
    FixedValidatorNodeDriverAdmissionErrorV0, FixedValidatorNodeDriverAdmissionOutcomeV0,
    FixedValidatorNodeDriverAdmissionRejectionV0, FixedValidatorNodeDriverBlockReasonV0,
    FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0,
    FixedValidatorNodeDriverCandidateBackedFinalityErrorV0,
    FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0, FixedValidatorNodeDriverCommandV0,
    FixedValidatorNodeDriverCreateErrorV0, FixedValidatorNodeDriverCurrentFinalityDrainV0,
    FixedValidatorNodeDriverCurrentNilPrecommitDrainV0,
    FixedValidatorNodeDriverCurrentRoundDrainV0,
    FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeDriverDrainV0, FixedValidatorNodeDriverEventV0,
    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0,
    FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0,
    FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeDriverProposalAuthoringOutcomeV0, FixedValidatorNodeDriverStepErrorV0,
    FixedValidatorNodeDriverStepOutcomeV0, FixedValidatorNodeDriverStepRejectionV0,
    FixedValidatorNodeDriverV0, FixedValidatorNodePhaseTimeoutV0,
};
pub use finality::{
    FixedValidatorNodeCandidateBackedFinalityErrorV0,
    FixedValidatorNodeCandidateBackedFinalityOutcomeV0,
    FixedValidatorNodeCandidateBackedFinalityRejectionV0,
    FixedValidatorNodeCurrentRoundFinalityErrorV0, FixedValidatorNodeCurrentRoundFinalityOutcomeV0,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0,
    FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0, FixedValidatorNodeFinalityErrorV0,
    FixedValidatorNodeFinalityOutcomeV0, FixedValidatorNodeFinalityRoundRouteV0,
    FixedValidatorNodeFinalitySelectionV0, FixedValidatorNodeLowerRoundFinalityErrorV0,
    FixedValidatorNodeLowerRoundFinalityOutcomeV0, FixedValidatorNodeLowerRoundFinalityRejectionV0,
    FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0,
};
pub use higher_round_inbox::{
    FixedValidatorNodeHigherRoundInboxAccessErrorV0, FixedValidatorNodeHigherRoundInboxDrainItemV0,
    FixedValidatorNodeHigherRoundInboxDrainV0, FixedValidatorNodeHigherRoundInboxLimitsErrorV0,
    FixedValidatorNodeHigherRoundInboxLimitsV0,
    FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0,
    FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0,
    FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0,
    FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0,
    FixedValidatorNodeHigherRoundInboxSaturationV0, FixedValidatorNodeHigherRoundInboxV0,
};
pub use higher_round_proposal_pairing::{
    FixedValidatorNodeBufferedProposalPrecommitErrorV0,
    FixedValidatorNodeBufferedProposalPrecommitOutcomeV0,
    FixedValidatorNodeBufferedProposalPrecommitRejectionV0,
};
pub use proposal_authoring::{
    FixedValidatorNodeProposalAuthoringErrorV0, FixedValidatorNodeProposalAuthoringOutcomeV0,
    FixedValidatorNodeProposalAuthoringRejectionV0,
};
pub use proposal_buffer::{
    FixedValidatorNodeProposalBufferAccessErrorV0, FixedValidatorNodeProposalBufferDrainV0,
    FixedValidatorNodeProposalBufferInsertErrorV0, FixedValidatorNodeProposalBufferInsertOutcomeV0,
    FixedValidatorNodeProposalBufferLimitsErrorV0, FixedValidatorNodeProposalBufferLimitsV0,
    FixedValidatorNodeProposalBufferSaturationV0, FixedValidatorNodeProposalBufferV0,
};
pub use proposal_deferral::{
    FixedValidatorNodeDeferredProposalV0, FixedValidatorNodeHigherRoundProposalRouteV0,
    FixedValidatorNodeProposalDeferralErrorV0, FixedValidatorNodeProposalDeferralOutcomeV0,
    FixedValidatorNodeProposalDeferralRejectionV0,
};
pub use round_progression::{
    FixedValidatorNodeHigherRoundVoteBatchRouteV0, FixedValidatorNodeRoundAdvanceErrorV0,
    FixedValidatorNodeRoundAdvanceOutcomeV0, FixedValidatorNodeRoundAdvanceRejectionV0,
};
pub use voting::{
    FixedValidatorNodeVoteExecutionErrorV0, FixedValidatorNodeVoteExecutionOutcomeV0,
    FixedValidatorNodeVoteRejectionV0,
};

mod round_context;
mod scope;
mod startup;
use round_context::{FixedValidatorNodeCurrentRoundErrorV0, fixed_validator_node_current_round};
pub use scope::*;
pub use startup::*;

#[cfg(all(test, unix))]
mod tests;

#[cfg(all(test, not(unix)))]
mod unsupported_tests;
