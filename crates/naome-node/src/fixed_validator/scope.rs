//! Sole signing scope and its restricted session facade.

use super::*;

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
    pub(super) finality: &'node mut FixedValidatorAnchoredFinalityJournalV0,
    pub(super) branch: FixedConsensusBranchV0,
    pub(super) signing_session: FixedValidatorNodeVotingSessionV0<'node>,
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
    pub(super) signer: ConsensusKey,
    pub(super) signing_session: FixedValidatorAnchoredVoteSafetySigningSessionV0<'node>,
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
