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

mod candidate_backed_proposal;
mod current_round_finality_inbox;
mod current_round_inbox;
mod driver;
mod finality;
mod higher_round_inbox;
mod higher_round_proposal_pairing;
mod proposal_authoring;
mod proposal_buffer;
mod proposal_deferral;
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
pub use driver::{
    FixedValidatorNodeDriverActionV0, FixedValidatorNodeDriverAdmissionDispositionV0,
    FixedValidatorNodeDriverAdmissionErrorV0, FixedValidatorNodeDriverAdmissionOutcomeV0,
    FixedValidatorNodeDriverAdmissionRejectionV0, FixedValidatorNodeDriverBlockReasonV0,
    FixedValidatorNodeDriverCommandV0, FixedValidatorNodeDriverCreateErrorV0,
    FixedValidatorNodeDriverCurrentFinalityDrainV0, FixedValidatorNodeDriverCurrentRoundDrainV0,
    FixedValidatorNodeDriverDrainV0, FixedValidatorNodeDriverEventV0,
    FixedValidatorNodeDriverStepErrorV0, FixedValidatorNodeDriverStepOutcomeV0,
    FixedValidatorNodeDriverStepRejectionV0, FixedValidatorNodeDriverV0,
    FixedValidatorNodePhaseTimeoutV0,
};
pub use finality::{
    FixedValidatorNodeCandidateBackedFinalityErrorV0,
    FixedValidatorNodeCandidateBackedFinalityOutcomeV0,
    FixedValidatorNodeCandidateBackedFinalityRejectionV0,
    FixedValidatorNodeCurrentRoundFinalityErrorV0, FixedValidatorNodeCurrentRoundFinalityOutcomeV0,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0, FixedValidatorNodeFinalityErrorV0,
    FixedValidatorNodeFinalityOutcomeV0, FixedValidatorNodeFinalityRoundRouteV0,
    FixedValidatorNodeFinalitySelectionV0, FixedValidatorNodeLowerRoundFinalityErrorV0,
    FixedValidatorNodeLowerRoundFinalityOutcomeV0, FixedValidatorNodeLowerRoundFinalityRejectionV0,
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

/// Four exact caller-owned storage namespaces used by one local signer.
///
/// Directories may be shared when the underlying typed filenames and locks do
/// not collide. This value neither creates directories nor chooses a layout.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct FixedValidatorNodeDirectoriesV0<'path> {
    finality_journal: &'path Path,
    finality_anchor: &'path Path,
    vote_journal: &'path Path,
    vote_anchor: &'path Path,
}

impl<'path> FixedValidatorNodeDirectoriesV0<'path> {
    /// Binds the exact directories supplied by the caller.
    pub const fn new(
        finality_journal: &'path Path,
        finality_anchor: &'path Path,
        vote_journal: &'path Path,
        vote_anchor: &'path Path,
    ) -> Self {
        Self {
            finality_journal,
            finality_anchor,
            vote_journal,
            vote_anchor,
        }
    }

    /// Returns the finality-journal directory.
    pub const fn finality_journal(self) -> &'path Path {
        self.finality_journal
    }

    /// Returns the finality-anchor directory.
    pub const fn finality_anchor(self) -> &'path Path {
        self.finality_anchor
    }

    /// Returns the per-key vote-journal directory.
    pub const fn vote_journal(self) -> &'path Path {
        self.vote_journal
    }

    /// Returns the per-key vote-anchor directory.
    pub const fn vote_anchor(self) -> &'path Path {
        self.vote_anchor
    }
}

/// Caller-local maximum sequential finality-to-signer height handoffs.
///
/// Zero is valid and permits only a signer already caught up to finality. This
/// local work bound grants no finality, branch-selection, or recovery authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorSignerCatchUpHeightLimitV0(u64);

impl FixedValidatorSignerCatchUpHeightLimitV0 {
    /// Constructs an inclusive height-handoff limit, including zero.
    pub const fn new(maximum: u64) -> Self {
        Self(maximum)
    }

    /// Returns the inclusive maximum number of sequential height handoffs.
    pub const fn maximum(self) -> u64 {
        self.0
    }
}

/// Exact caller-selected inputs for one fixed-validator V0 node startup.
///
/// This is an in-memory typed boundary, not an operator configuration format.
/// It deliberately provides no defaults and owns no signing key.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct FixedValidatorNodeProvisionV0<'config> {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    fixed_entries: &'config [ActiveAgreementEntry],
    directories: FixedValidatorNodeDirectoriesV0<'config>,
    finality_replay_limit: FixedValidatorFinalityReplayLimitV0,
    vote_replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    proposal_replay_limit: FixedValidatorProposalReplayLimitV0,
    signer_recovery_round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    signer_catch_up_height_limit: FixedValidatorSignerCatchUpHeightLimitV0,
}

impl<'config> FixedValidatorNodeProvisionV0<'config> {
    /// Binds every exact caller-selected startup input.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        fixed_entries: &'config [ActiveAgreementEntry],
        directories: FixedValidatorNodeDirectoriesV0<'config>,
        finality_replay_limit: FixedValidatorFinalityReplayLimitV0,
        vote_replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
        proposal_replay_limit: FixedValidatorProposalReplayLimitV0,
        signer_recovery_round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
        signer_catch_up_height_limit: FixedValidatorSignerCatchUpHeightLimitV0,
    ) -> Self {
        Self {
            definition,
            context,
            fixed_entries,
            directories,
            finality_replay_limit,
            vote_replay_limit,
            proposal_replay_limit,
            signer_recovery_round_limit,
            signer_catch_up_height_limit,
        }
    }

    /// Creates both anchored pairs and binds the exact initial lineage.
    ///
    /// Configuration is preflighted before file access. Creation is ordered but
    /// not cross-file atomic; a later failure never removes an earlier durable
    /// pair.
    pub fn create(
        self,
        signing_key: SigningKey,
    ) -> Result<FixedValidatorNodeReadyV0, FixedValidatorNodeStartupErrorV0> {
        let preflight_branch = self.preflight(&signing_key)?;
        let fixed_set_id = preflight_branch.fixed_agreement_set_id();
        let finality = FixedValidatorAnchoredFinalityJournalV0::create(
            self.directories.finality_journal,
            self.directories.finality_anchor,
            self.definition,
            self.context,
            self.fixed_entries,
            self.finality_replay_limit,
        )
        .map_err(FixedValidatorNodeStartupErrorV0::finality_pair)?;
        let mut vote = FixedValidatorAnchoredVoteSafetyJournalV0::create(
            self.directories.vote_journal,
            self.directories.vote_anchor,
            self.context,
            fixed_set_id,
            signing_key,
            self.vote_replay_limit,
        )
        .map_err(FixedValidatorNodeStartupErrorV0::vote_pair)?;
        let _ = vote
            .activate_proposal_authoring(self.proposal_replay_limit)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
        let branch = finality
            .head()
            .map_err(FixedValidatorNodeStartupErrorV0::finality)?
            .clone();
        debug_assert_eq!(branch.coordinate(), preflight_branch.coordinate());
        let round = branch
            .begin_round_zero()
            .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
        let _ = vote
            .bind_signing_lineage(&round)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
        drop(round);
        Ok(FixedValidatorNodeReadyV0 {
            finality,
            vote,
            session_plan: FixedValidatorNodeSessionPlanV0::Initial(branch),
            signer_recovery_round_limit: self.signer_recovery_round_limit,
            signer_catch_up_height_limit: self.signer_catch_up_height_limit,
        })
    }

    /// Strictly opens both anchored pairs and classifies the restart state.
    ///
    /// An anchored finality conflict is monotonically routed into the signer
    /// before any recovery capability can be issued.
    pub fn open(
        self,
        signing_key: SigningKey,
    ) -> Result<FixedValidatorNodeStartupV0, FixedValidatorNodeStartupErrorV0> {
        let preflight_branch = self.preflight(&signing_key)?;
        let fixed_set_id = preflight_branch.fixed_agreement_set_id();
        let finality = FixedValidatorAnchoredFinalityJournalV0::open(
            self.directories.finality_journal,
            self.directories.finality_anchor,
            self.definition,
            self.context,
            self.fixed_entries,
            self.finality_replay_limit,
        )
        .map_err(FixedValidatorNodeStartupErrorV0::finality_pair)?;
        let mut vote = FixedValidatorAnchoredVoteSafetyJournalV0::open(
            self.directories.vote_journal,
            self.directories.vote_anchor,
            self.context,
            fixed_set_id,
            signing_key,
            self.vote_replay_limit,
        )
        .map_err(FixedValidatorNodeStartupErrorV0::vote_pair)?;

        if let Some(finality_halt) = finality
            .halt()
            .map_err(FixedValidatorNodeStartupErrorV0::finality)?
        {
            let stop = finality
                .acknowledge_signer_stop()
                .map_err(FixedValidatorNodeStartupErrorV0::finality)?;
            let outcome = vote
                .stop_after_durable_finality_conflict(stop)
                .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
            let signer_stop = match outcome {
                FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stop)
                | FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(stop) => stop,
            };
            return Ok(FixedValidatorNodeStartupV0::FinalityStopped(
                FixedValidatorNodeFinalityStoppedV0 {
                    finality_halt,
                    signer_stop,
                },
            ));
        }

        if let Some(halt) = vote
            .halt()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::SignerStopped(
                FixedValidatorNodeSignerStopV0::VoteSafety(halt),
            ));
        }
        if let Some(halt) = vote
            .proposal_halt()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::SignerStopped(
                FixedValidatorNodeSignerStopV0::ProposalSafety(halt),
            ));
        }
        if let Some(stop) = vote
            .finality_conflict_stop()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::SignerStopped(
                FixedValidatorNodeSignerStopV0::FinalityConflict(stop),
            ));
        }
        if let Some(pending) = vote
            .pending_vote()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::PendingPreparation(pending));
        }
        if let Some(pending) = vote
            .pending_proposal()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::PendingProposal(pending));
        }

        let _ = vote
            .activate_proposal_authoring(self.proposal_replay_limit)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;

        let recovery = vote
            .acknowledge_signer_recovery()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
        let recovered = finality
            .recover_anchored_signer_branch(recovery)
            .map_err(FixedValidatorNodeStartupErrorV0::finality)?;
        Ok(FixedValidatorNodeStartupV0::Ready(Box::new(
            FixedValidatorNodeReadyV0 {
                finality,
                vote,
                session_plan: FixedValidatorNodeSessionPlanV0::Recovered(recovered),
                signer_recovery_round_limit: self.signer_recovery_round_limit,
                signer_catch_up_height_limit: self.signer_catch_up_height_limit,
            },
        )))
    }

    fn preflight(
        self,
        signing_key: &SigningKey,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorNodeStartupErrorV0> {
        let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            self.context,
            self.fixed_entries,
            ArtifactChainState::new(self.definition).branch_snapshot(),
        )
        .map_err(FixedValidatorNodeStartupErrorV0::Genesis)?;
        let signer = ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes());
        if !self
            .fixed_entries
            .iter()
            .any(|entry| entry.consensus_key() == signer)
        {
            return Err(FixedValidatorNodeStartupErrorV0::SignerNotInFixedSet { signer });
        }
        Ok(branch)
    }
}

/// A strictly opened node state that can issue exactly one scoped session.
#[must_use]
pub struct FixedValidatorNodeReadyV0 {
    finality: FixedValidatorAnchoredFinalityJournalV0,
    vote: FixedValidatorAnchoredVoteSafetyJournalV0,
    session_plan: FixedValidatorNodeSessionPlanV0,
    signer_recovery_round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    signer_catch_up_height_limit: FixedValidatorSignerCatchUpHeightLimitV0,
}

impl FixedValidatorNodeReadyV0 {
    /// Consumes the owner and runs one closure with its sole signing session.
    ///
    /// The higher-ranked closure result cannot retain a borrow of the scope, so
    /// the session cannot outlive either local journal owner.
    pub fn run_with_signing_session<R>(
        self,
        callback: impl for<'scope> FnOnce(FixedValidatorNodeSigningScopeV0<'scope>) -> R,
    ) -> Result<R, FixedValidatorNodeStartupErrorV0> {
        let Self {
            mut finality,
            mut vote,
            session_plan,
            signer_recovery_round_limit,
            signer_catch_up_height_limit,
        } = self;
        let signer = vote.signer();
        match session_plan {
            FixedValidatorNodeSessionPlanV0::Initial(branch) => {
                let round = branch
                    .begin_round_zero()
                    .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
                let signing_session = vote
                    .issue_signing_session(&round)
                    .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
                drop(round);
                Ok(callback(FixedValidatorNodeSigningScopeV0 {
                    finality: &mut finality,
                    branch,
                    signing_session: FixedValidatorNodeVotingSessionV0 {
                        signer,
                        signing_session,
                    },
                }))
            }
            FixedValidatorNodeSessionPlanV0::Recovered(recovered) => {
                let recovered = vote
                    .issue_recovered_signing_session(recovered, signer_recovery_round_limit)
                    .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
                let (branch, mut signing_session) = recovered.into_parts();
                let branch = catch_up_signer_to_finality(
                    &finality,
                    branch,
                    &mut signing_session,
                    signer_catch_up_height_limit,
                )?;
                Ok(callback(FixedValidatorNodeSigningScopeV0 {
                    finality: &mut finality,
                    branch,
                    signing_session: FixedValidatorNodeVotingSessionV0 {
                        signer,
                        signing_session,
                    },
                }))
            }
        }
    }
}

enum FixedValidatorNodeSessionPlanV0 {
    Initial(FixedConsensusBranchV0),
    Recovered(FixedValidatorRecoveredSignerBranchV0),
}

/// One non-escaping fixed-validator signing scope and its exact branch.
///
/// External finality height authority cannot enter through `signing_session`:
///
/// ```compile_fail,E0599
/// use naome_node::FixedValidatorNodeSigningScopeV0;
/// use naome_storage::FixedValidatorDurableFinalityTransitionV0;
///
/// fn advance_from_foreign_journal<'node, 'finality>(
///     scope: &mut FixedValidatorNodeSigningScopeV0<'node>,
///     foreign: FixedValidatorDurableFinalityTransitionV0<'finality>,
/// ) {
///     let _ = scope
///         .signing_session()
///         .prepare_height_with_durable_finality(foreign);
/// }
/// ```
///
/// External finality stop authority cannot enter through `signing_session`:
///
/// ```compile_fail,E0599
/// use naome_node::FixedValidatorNodeSigningScopeV0;
/// use naome_storage::FixedValidatorDurableFinalityConflictV0;
///
/// fn stop_from_foreign_journal<'node, 'finality>(
///     scope: &mut FixedValidatorNodeSigningScopeV0<'node>,
///     foreign: FixedValidatorDurableFinalityConflictV0<'finality>,
/// ) {
///     let _ = scope
///         .signing_session()
///         .stop_after_durable_finality_conflict(foreign);
/// }
/// ```
///
/// The combined `parts` borrow exposes the same restricted surface:
///
/// ```compile_fail,E0599
/// use naome_node::FixedValidatorNodeSigningScopeV0;
/// use naome_storage::FixedValidatorDurableFinalityTransitionV0;
///
/// fn advance_from_foreign_parts<'node, 'finality>(
///     scope: &mut FixedValidatorNodeSigningScopeV0<'node>,
///     foreign: FixedValidatorDurableFinalityTransitionV0<'finality>,
/// ) {
///     let (_, _, session) = scope.parts();
///     let _ = session.prepare_height_with_durable_finality(foreign);
/// }
/// ```
///
/// ```compile_fail,E0599
/// use naome_node::FixedValidatorNodeSigningScopeV0;
/// use naome_storage::FixedValidatorDurableFinalityConflictV0;
///
/// fn stop_from_foreign_parts<'node, 'finality>(
///     scope: &mut FixedValidatorNodeSigningScopeV0<'node>,
///     foreign: FixedValidatorDurableFinalityConflictV0<'finality>,
/// ) {
///     let (_, _, session) = scope.parts();
///     let _ = session.stop_after_durable_finality_conflict(foreign);
/// }
/// ```
///
/// Identity-free Proposal and Prevote close shortcuts are absent. A routed
/// close must enter through the consuming coordinator with its exact context
/// and source position:
///
/// ```compile_fail,E0599
/// use naome_consensus::ConsensusRound;
/// use naome_node::FixedValidatorNodeSigningScopeV0;
///
/// fn unbound_proposal_close(scope: FixedValidatorNodeSigningScopeV0<'_>) {
///     let _ = scope.sign_prevote_without_proposal(ConsensusRound::new(0));
/// }
/// ```
///
/// ```compile_fail,E0599
/// use naome_consensus::ConsensusRound;
/// use naome_node::FixedValidatorNodeSigningScopeV0;
///
/// fn unbound_prevote_close(scope: FixedValidatorNodeSigningScopeV0<'_>) {
///     let _ = scope.sign_precommit_without_quorum(ConsensusRound::new(0));
/// }
/// ```
#[must_use]
pub struct FixedValidatorNodeSigningScopeV0<'node> {
    finality: &'node mut FixedValidatorAnchoredFinalityJournalV0,
    branch: FixedConsensusBranchV0,
    signing_session: FixedValidatorNodeVotingSessionV0<'node>,
}

impl<'node> FixedValidatorNodeSigningScopeV0<'node> {
    /// Returns the exact branch recovered for this signing lineage.
    pub const fn branch(&self) -> &FixedConsensusBranchV0 {
        &self.branch
    }

    /// Returns read-only access to the anchored selected-finality owner.
    pub const fn finality(&self) -> &FixedValidatorAnchoredFinalityJournalV0 {
        self.finality
    }

    /// Returns the sole node-scoped voting diagnostics session.
    ///
    /// Height advancement, round advancement, and finality-conflict stop
    /// authority are deliberately absent, and current-round decision,
    /// identity-free phase-close, preparation, acknowledgement, and key-use
    /// primitives are private to this scope's consuming coordinators.
    pub fn signing_session(&mut self) -> &FixedValidatorNodeVotingSessionV0<'node> {
        &self.signing_session
    }

    #[cfg(all(test, unix))]
    pub(crate) fn signing_session_mut(&mut self) -> &mut FixedValidatorNodeVotingSessionV0<'node> {
        &mut self.signing_session
    }

    /// Borrows the read-only selected state and restricted voter together.
    pub fn parts(
        &mut self,
    ) -> (
        &FixedValidatorAnchoredFinalityJournalV0,
        &FixedConsensusBranchV0,
        &FixedValidatorNodeVotingSessionV0<'node>,
    ) {
        (self.finality, &self.branch, &self.signing_session)
    }
}

/// Public diagnostics access cannot move or exchange the owned voting session
/// between signing scopes:
///
/// ```compile_fail
/// use naome_node::FixedValidatorNodeSigningScopeV0;
///
/// fn swap_sessions<'node>(
///     left: &mut FixedValidatorNodeSigningScopeV0<'node>,
///     right: &mut FixedValidatorNodeSigningScopeV0<'node>,
/// ) {
///     std::mem::swap(left.signing_session(), right.signing_session());
/// }
/// ```
///
/// The combined diagnostics accessor preserves the same ownership boundary:
///
/// ```compile_fail
/// use naome_node::FixedValidatorNodeSigningScopeV0;
///
/// fn swap_parts<'node>(
///     left: &mut FixedValidatorNodeSigningScopeV0<'node>,
///     right: &mut FixedValidatorNodeSigningScopeV0<'node>,
/// ) {
///     let (_, _, left_session) = left.parts();
///     let (_, _, right_session) = right.parts();
///     std::mem::swap(left_session, right_session);
/// }
/// ```
///
/// Node-scoped diagnostics for one signing lineage.
///
/// This facade owns the lower-level session. Finality height, conflict-stop,
/// current-round decision, raw intent, acknowledgement, and key-use operations
/// remain private to consuming node coordinators. External callers therefore
/// cannot release a vote by manually splitting the required durable sequence:
///
/// ```compile_fail,E0624
/// use naome_node::FixedValidatorNodeVotingSessionV0;
///
/// fn bypass(session: &mut FixedValidatorNodeVotingSessionV0<'_>) {
///     let _ = session.decide_prevote_without_proposal();
/// }
/// ```
///
/// The raw durable stages are private as well:
///
/// ```compile_fail,E0624
/// use naome_consensus::{FixedConsensusRoundV0, FixedValidatorUnsignedVoteEffectV0};
/// use naome_node::FixedValidatorNodeVotingSessionV0;
/// use naome_storage::{
///     FixedValidatorDurablePrepareAcknowledgementV0, FixedValidatorPreparedVoteV0,
/// };
///
/// fn prepare(
///     session: &mut FixedValidatorNodeVotingSessionV0<'_>,
///     round: &FixedConsensusRoundV0<'_>,
///     effect: FixedValidatorUnsignedVoteEffectV0,
/// ) {
///     let _ = session.prepare_vote(round, effect);
/// }
///
/// fn acknowledge(
///     session: &FixedValidatorNodeVotingSessionV0<'_>,
///     prepared: FixedValidatorPreparedVoteV0,
/// ) {
///     let _ = session.acknowledge_prepared_vote(prepared);
/// }
///
/// fn sign(
///     session: &mut FixedValidatorNodeVotingSessionV0<'_>,
///     acknowledgement: FixedValidatorDurablePrepareAcknowledgementV0,
/// ) {
///     let _ = session.sign_prepared_vote(acknowledgement);
/// }
/// ```
///
/// Proposal preparation, acknowledgement, and producer key use are equally
/// private to the consuming authoring coordinator:
///
/// ```compile_fail,E0624
/// use naome_consensus::{FixedConsensusRoundV0, FixedValidatorProposalSourceV0};
/// use naome_node::FixedValidatorNodeVotingSessionV0;
/// use naome_storage::{
///     FixedValidatorDurableProposalPrepareAcknowledgementV0,
///     FixedValidatorPreparedProposalV0,
/// };
///
/// fn prepare(
///     session: &mut FixedValidatorNodeVotingSessionV0<'_>,
///     round: &FixedConsensusRoundV0<'_>,
///     source: FixedValidatorProposalSourceV0,
/// ) {
///     let _ = session.prepare_proposal(round, source);
/// }
///
/// fn acknowledge(
///     session: &FixedValidatorNodeVotingSessionV0<'_>,
///     prepared: FixedValidatorPreparedProposalV0,
/// ) {
///     let _ = session.acknowledge_prepared_proposal(prepared);
/// }
///
/// fn sign(
///     session: &mut FixedValidatorNodeVotingSessionV0<'_>,
///     acknowledgement: FixedValidatorDurableProposalPrepareAcknowledgementV0,
/// ) {
///     let _ = session.sign_prepared_proposal(acknowledgement);
/// }
/// ```
///
/// Quorum-driven progression is available only through the consuming node
/// scope, not through separately callable cursor, prepare, or acknowledgement
/// stages:
///
/// ```compile_fail,E0624
/// use naome_consensus::{ConsensusRound, FixedConsensusRoundV0};
/// use naome_node::FixedValidatorNodeVotingSessionV0;
/// use naome_storage::FixedValidatorPreparedHigherRoundAdvanceV0;
///
/// fn bypass_nil<'branch>(
///     session: &mut FixedValidatorNodeVotingSessionV0<'_>,
///     round: &FixedConsensusRoundV0<'branch>,
///     certificate: &[u8],
/// ) {
///     let _ = session.advance_round_for_nil_precommit_quorum(round, certificate);
/// }
///
/// fn bypass_higher<'branch>(
///     session: &mut FixedValidatorNodeVotingSessionV0<'_>,
///     round: &FixedConsensusRoundV0<'branch>,
///     certificate: &[u8],
///     prepared: FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
/// ) {
///     let _ = session.prepare_higher_round_quorum_advance(
///         round,
///         certificate,
///         ConsensusRound::new(1),
///     );
///     let _ = session.acknowledge_prepared_higher_round(prepared);
/// }
/// ```
///
/// Ordinary sequential progression is also available only through the
/// consuming, exact-event-bound node coordinator:
///
/// ```compile_fail,E0624
/// use naome_consensus::FixedConsensusRoundV0;
/// use naome_node::FixedValidatorNodeVotingSessionV0;
///
/// fn bypass(
///     session: &mut FixedValidatorNodeVotingSessionV0<'_>,
///     caller_cursor: &FixedConsensusRoundV0<'_>,
/// ) {
///     let _ = session.advance_round(caller_cursor);
/// }
/// ```
///
/// ```compile_fail,E0624
/// use naome_consensus::FixedConsensusRoundV0;
/// use naome_node::FixedValidatorNodeSigningScopeV0;
///
/// fn bypass_scope(
///     scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
///     caller_cursor: &FixedConsensusRoundV0<'_>,
/// ) {
///     let _ = scope.signing_session().advance_round(caller_cursor);
/// }
/// ```
///
/// ```compile_fail,E0624
/// use naome_consensus::FixedConsensusRoundV0;
/// use naome_node::FixedValidatorNodeSigningScopeV0;
///
/// fn bypass_parts(
///     scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
///     caller_cursor: &FixedConsensusRoundV0<'_>,
/// ) {
///     let (_, _, session) = scope.parts();
///     let _ = session.advance_round(caller_cursor);
/// }
/// ```
#[must_use]
pub struct FixedValidatorNodeVotingSessionV0<'node> {
    signer: ConsensusKey,
    signing_session: FixedValidatorAnchoredVoteSafetySigningSessionV0<'node>,
}

#[allow(
    clippy::result_large_err,
    reason = "the restricted facade preserves the established vote-safety error taxonomy"
)]
impl FixedValidatorNodeVotingSessionV0<'_> {
    /// Returns the immutable public key bound to this private signing session.
    pub(crate) const fn signer(&self) -> ConsensusKey {
        self.signer
    }

    /// Returns the exact current height and round of this signing lineage.
    pub const fn position(&self) -> ConsensusPosition {
        self.signing_session.position()
    }

    /// Returns the current fixed-validator kernel phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.signing_session.phase()
    }

    /// Returns the current locked value, if any.
    pub const fn locked_value(&self) -> Option<FixedValidatorLockedValueV0> {
        self.signing_session.locked_value()
    }

    /// Returns the current retained valid value and proof, if any.
    pub const fn valid_value(&self) -> Option<&FixedValidatorValidValueV0> {
        self.signing_session.valid_value()
    }

    /// Rejects non-operational or pending session state before input admission.
    pub(crate) fn ensure_current_vote_ready(
        &self,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.ensure_current_vote_ready()
    }

    /// Persists and anchors the exact private-state-derived proposal intent.
    pub(crate) fn prepare_proposal(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        source: FixedValidatorProposalSourceV0,
    ) -> Result<FixedValidatorProposalPrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.signing_session.prepare_proposal(round, source)
    }

    /// Converts an internally anchored proposal preparation into key-use authority.
    pub(crate) fn acknowledge_prepared_proposal(
        &self,
        prepared: FixedValidatorPreparedProposalV0,
    ) -> Result<
        FixedValidatorDurableProposalPrepareAcknowledgementV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.signing_session.acknowledge_prepared_proposal(prepared)
    }

    /// Signs and anchors proposal completion before releasing control bytes.
    pub(crate) fn sign_prepared_proposal(
        &mut self,
        acknowledgement: FixedValidatorDurableProposalPrepareAcknowledgementV0,
    ) -> Result<FixedValidatorSignedProposalV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.sign_prepared_proposal(acknowledgement)
    }

    /// Decides the current proposal path's prevote without persistence.
    pub(crate) fn decide_prevote_for_proposal(
        &mut self,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.decide_prevote_for_proposal(proposal)
    }

    /// Decides the absent-or-rejected-proposal prevote path without persistence.
    pub(crate) fn decide_prevote_without_proposal(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.decide_prevote_without_proposal()
    }

    /// Applies one proposal prevote quorum and decides precommit in memory.
    pub(crate) fn decide_precommit_for_proposal_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.decide_precommit_for_proposal_quorum(
            round,
            proposal,
            canonical_certificate,
        )
    }

    /// Applies one nil prevote quorum and decides nil precommit in memory.
    pub(crate) fn decide_precommit_for_nil_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session
            .decide_precommit_for_nil_quorum(round, canonical_certificate)
    }

    /// Decides nil precommit without a current-round quorum in memory.
    pub(crate) fn decide_precommit_without_quorum(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.decide_precommit_without_quorum()
    }

    /// Advances through one exact sequential typed round in memory.
    pub(crate) fn advance_round(
        &mut self,
        next_round: &FixedConsensusRoundV0<'_>,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.advance_round(next_round)
    }

    /// Advances in memory after verifying one exact nil-precommit quorum.
    pub(crate) fn advance_round_for_nil_precommit_quorum<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session
            .advance_round_for_nil_precommit_quorum(current_round, canonical_certificate)
    }

    /// Persists and anchors one verified higher-round checkpoint before return.
    pub(crate) fn prepare_higher_round_quorum_advance<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.signing_session.prepare_higher_round_quorum_advance(
            current_round,
            canonical_certificate,
            inclusive_maximum_round,
        )
    }

    /// Persists and anchors one exact matching proposal-prevote checkpoint.
    pub(crate) fn prepare_higher_round_proposal_prevote_advance<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        expected_position: ConsensusPosition,
        expected_proposal_root: naome_consensus::ProposalSigningRoot,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.signing_session
            .prepare_higher_round_proposal_prevote_advance(
                current_round,
                canonical_certificate,
                expected_position,
                expected_proposal_root,
                inclusive_maximum_round,
            )
    }

    /// Publishes an already anchored higher-round checkpoint to live state.
    pub(crate) fn acknowledge_prepared_higher_round<'branch>(
        &mut self,
        prepared: FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session
            .acknowledge_prepared_higher_round(prepared)
    }

    /// Persists and anchors the exact session-derived vote preparation.
    pub(crate) fn prepare_vote(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        effect: FixedValidatorUnsignedVoteEffectV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.prepare_vote(round, effect)
    }

    /// Converts an already anchored live preparation into key-use authority.
    pub(crate) fn acknowledge_prepared_vote(
        &self,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<FixedValidatorDurablePrepareAcknowledgementV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.signing_session.acknowledge_prepared_vote(prepared)
    }

    /// Signs and anchors one acknowledged preparation before releasing bytes.
    pub(crate) fn sign_prepared_vote(
        &mut self,
        acknowledgement: FixedValidatorDurablePrepareAcknowledgementV0,
    ) -> Result<FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.signing_session.sign_prepared_vote(acknowledgement)
    }
}

pub(super) enum FixedValidatorNodeCurrentRoundErrorV0 {
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    Round(ProposerSelectionError),
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    CallerRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
}

pub(super) fn fixed_validator_node_current_round<'branch>(
    branch: &'branch FixedConsensusBranchV0,
    signing_session: &FixedValidatorNodeVotingSessionV0<'_>,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: u64,
) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorNodeCurrentRoundErrorV0> {
    signing_session
        .ensure_current_vote_ready()
        .map_err(|source| FixedValidatorNodeCurrentRoundErrorV0::Session(Box::new(source)))?;
    let signer_position = signing_session.position();
    let mut round = branch
        .begin_round_zero()
        .map_err(FixedValidatorNodeCurrentRoundErrorV0::Round)?;
    if round.position().height() != signer_position.height() {
        return Err(
            FixedValidatorNodeCurrentRoundErrorV0::SignerBranchHeightMismatch {
                signer: signer_position,
                branch_next_height: round.position().height(),
            },
        );
    }
    let finality_maximum_round = ConsensusRound::new(finality_maximum_round);
    if signer_position.round() > finality_maximum_round {
        return Err(
            FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded {
                required: signer_position.round(),
                maximum: finality_maximum_round,
            },
        );
    }
    if signer_position.round() > inclusive_maximum_round {
        return Err(
            FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded {
                required: signer_position.round(),
                maximum: inclusive_maximum_round,
            },
        );
    }
    for _ in 0..signer_position.round().value() {
        round = round
            .advance_round()
            .map_err(FixedValidatorNodeCurrentRoundErrorV0::Round)?;
    }
    debug_assert_eq!(round.position(), signer_position);
    Ok(round)
}

/// A strict restart result that never hides stopped or pending signer state.
#[must_use]
pub enum FixedValidatorNodeStartupV0 {
    /// Both pairs matched and exact signer-branch recovery is prepared.
    Ready(Box<FixedValidatorNodeReadyV0>),
    /// Finality was conflict-halted and its exact stop reached the signer.
    FinalityStopped(FixedValidatorNodeFinalityStoppedV0),
    /// The signer already carried an independent terminal cause.
    SignerStopped(FixedValidatorNodeSignerStopV0),
    /// One durable vote preparation cannot be resumed or signed after restart.
    PendingPreparation(FixedValidatorPendingVoteV0),
    /// One durable proposal preparation cannot be resumed or signed after restart.
    PendingProposal(FixedValidatorPendingProposalV0),
}

fn catch_up_signer_to_finality(
    finality: &FixedValidatorAnchoredFinalityJournalV0,
    mut branch: FixedConsensusBranchV0,
    signing_session: &mut FixedValidatorAnchoredVoteSafetySigningSessionV0<'_>,
    limit: FixedValidatorSignerCatchUpHeightLimitV0,
) -> Result<FixedConsensusBranchV0, FixedValidatorNodeStartupErrorV0> {
    let finality_next_height = finality
        .head()
        .map_err(FixedValidatorNodeStartupErrorV0::finality)?
        .next_height()
        .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
    let signer_next_height = branch
        .next_height()
        .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
    let required = finality_next_height
        .value()
        .checked_sub(signer_next_height.value())
        .ok_or(FixedValidatorNodeStartupErrorV0::SignerAheadOfFinality {
            signer_next_height,
            finality_next_height,
        })?;
    if required > limit.maximum() {
        return Err(
            FixedValidatorNodeStartupErrorV0::SignerCatchUpHeightLimitExceeded {
                required,
                maximum: limit.maximum(),
            },
        );
    }
    for _ in 0..required {
        let signer_next_height = branch
            .next_height()
            .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
        let durable = finality
            .acknowledge_signer_height_transition(signer_next_height)
            .map_err(FixedValidatorNodeStartupErrorV0::finality)?;
        let prepared = signing_session
            .prepare_height_with_durable_finality(durable)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
        branch = signing_session
            .acknowledge_prepared_height(prepared)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
    }
    Ok(branch)
}

/// Exact finality halt paired with the local signer stop it authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeFinalityStoppedV0 {
    finality_halt: FixedValidatorFinalityHaltV0,
    signer_stop: FixedValidatorFinalityConflictSignerStopV0,
}

impl FixedValidatorNodeFinalityStoppedV0 {
    /// Returns the anchored finality conflict.
    pub const fn finality_halt(self) -> FixedValidatorFinalityHaltV0 {
        self.finality_halt
    }

    /// Returns the corresponding anchored per-key stop.
    pub const fn signer_stop(self) -> FixedValidatorFinalityConflictSignerStopV0 {
        self.signer_stop
    }
}

/// An already terminal signer state found while finality remained operable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorNodeSignerStopV0 {
    /// A non-identical same-slot vote intent halted the local signer.
    VoteSafety(FixedValidatorVoteSafetyHaltV0),
    /// A non-identical same-slot proposal intent halted the local signer.
    ProposalSafety(FixedValidatorProposalSafetyHaltV0),
    /// An earlier explicitly routed finality conflict stopped the signer.
    FinalityConflict(FixedValidatorFinalityConflictSignerStopV0),
}

/// A fail-closed provisioning, restart, or session-issuance failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeStartupErrorV0 {
    /// The caller's definition, context, or fixed entries cannot form genesis.
    Genesis(FixedConsensusGenesisError),
    /// The supplied signing key is absent from the exact preselected fixed set.
    SignerNotInFixedSet { signer: ConsensusKey },
    /// The paired finality journal or anchor could not create or strictly open.
    FinalityPair(Box<FixedValidatorAnchoredFinalityJournalErrorV0>),
    /// The paired vote journal or anchor could not create or strictly open.
    VotePair(Box<FixedValidatorAnchoredVoteSafetyJournalErrorV0>),
    /// An opened finality journal rejected the requested lifecycle operation.
    Finality(Box<FixedValidatorFinalityJournalErrorV0>),
    /// An opened vote journal rejected the requested lifecycle operation.
    Vote(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// Exact consensus-position derivation failed.
    Consensus(ProposerSelectionError),
    /// The recovered signer lineage is unexpectedly ahead of selected finality.
    SignerAheadOfFinality {
        signer_next_height: ConsensusHeight,
        finality_next_height: ConsensusHeight,
    },
    /// The complete catch-up gap exceeds the caller-local height-work limit.
    SignerCatchUpHeightLimitExceeded { required: u64, maximum: u64 },
}

impl FixedValidatorNodeStartupErrorV0 {
    fn finality_pair(source: FixedValidatorAnchoredFinalityJournalErrorV0) -> Self {
        Self::FinalityPair(Box::new(source))
    }

    fn vote_pair(source: FixedValidatorAnchoredVoteSafetyJournalErrorV0) -> Self {
        Self::VotePair(Box::new(source))
    }

    fn finality(source: FixedValidatorFinalityJournalErrorV0) -> Self {
        Self::Finality(Box::new(source))
    }

    fn vote(source: FixedValidatorVoteSafetyJournalErrorV0) -> Self {
        Self::Vote(Box::new(source))
    }
}

impl fmt::Display for FixedValidatorNodeStartupErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Genesis(source) => {
                write!(formatter, "invalid fixed-validator node genesis: {source}")
            }
            Self::SignerNotInFixedSet { signer } => {
                write!(
                    formatter,
                    "node signing key {signer:?} is absent from the fixed validator set"
                )
            }
            Self::FinalityPair(source) => write!(formatter, "node finality pair failed: {source}"),
            Self::VotePair(source) => write!(formatter, "node vote-safety pair failed: {source}"),
            Self::Finality(source) => write!(formatter, "node finality startup failed: {source}"),
            Self::Vote(source) => write!(formatter, "node signer startup failed: {source}"),
            Self::Consensus(source) => {
                write!(
                    formatter,
                    "node startup consensus derivation failed: {source}"
                )
            }
            Self::SignerAheadOfFinality {
                signer_next_height,
                finality_next_height,
            } => write!(
                formatter,
                "node signer next height {} is ahead of selected finality next height {}",
                signer_next_height.value(),
                finality_next_height.value()
            ),
            Self::SignerCatchUpHeightLimitExceeded { required, maximum } => write!(
                formatter,
                "node signer catch-up requires {required} height handoffs, exceeding caller-local limit {maximum}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeStartupErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Genesis(source) => Some(source),
            Self::FinalityPair(source) => Some(source.as_ref()),
            Self::VotePair(source) => Some(source.as_ref()),
            Self::Finality(source) => Some(source.as_ref()),
            Self::Vote(source) => Some(source.as_ref()),
            Self::Consensus(source) => Some(source),
            Self::SignerNotInFixedSet { .. }
            | Self::SignerAheadOfFinality { .. }
            | Self::SignerCatchUpHeightLimitExceeded { .. } => None,
        }
    }
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(all(test, not(unix)))]
mod unsupported_tests;
