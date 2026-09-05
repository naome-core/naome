//! Independent anchor pairing and acknowledged adapters.

use super::*;

impl FixedValidatorAnchoredVoteSafetyJournalV0 {
    /// Creates one per-key journal and its independently synchronized genesis anchor.
    pub fn create(
        journal_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signing_key: SigningKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    ) -> Result<Self, FixedValidatorAnchoredVoteSafetyJournalErrorV0> {
        let journal_directory = journal_directory.as_ref();
        let mut journal = FixedValidatorVoteSafetyJournalV0::create(
            journal_directory,
            context,
            fixed_set_id,
            signing_key,
            replay_limit,
        )
        .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        sync_directory(journal_directory)
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor)?;
        let state_id = journal
            .state_id()
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        let anchor = FixedValidatorAnchorFileV0::create_vote(
            anchor_directory.as_ref(),
            context,
            fixed_set_id,
            journal.signer(),
            replay_limit.max_prepared_votes(),
            *state_id.as_bytes(),
        )
        .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor)?;
        journal.core.anchor = Some(anchor);
        Ok(Self { journal })
    }

    /// Strictly opens one per-key journal only at its independent anchor position.
    pub fn open(
        journal_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signing_key: SigningKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    ) -> Result<Self, FixedValidatorAnchoredVoteSafetyJournalErrorV0> {
        let signer = consensus_key(&signing_key);
        let expected_prefix = canonical_prefix(context, fixed_set_id, signer, replay_limit)
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        let journal_directory = journal_directory.as_ref();
        let (lock_path, journal_path) = keyed_paths(journal_directory, signer)
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        let lock = open_key_lock(&lock_path)
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        let anchor = FixedValidatorAnchorFileV0::open_vote(
            anchor_directory.as_ref(),
            context,
            fixed_set_id,
            signer,
            replay_limit.max_prepared_votes(),
        )
        .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor)?;
        let anchored = anchor.position();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path)
            .map_err(|source| {
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal(
                    FixedValidatorVoteSafetyJournalErrorV0::Open { source },
                )
            })?;
        let mut core = FixedValidatorVoteSafetyJournalCore::replay(
            file,
            context,
            fixed_set_id,
            signer,
            replay_limit,
            expected_prefix,
            FixedValidatorVoteSafetyJournalStateIdV0::from_bytes(anchored.state_id),
            Some(anchored.sequence),
        )
        .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::journal)?;
        anchor
            .stabilize()
            .map_err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor)?;
        core.anchor = Some(anchor);
        Ok(Self {
            journal: FixedValidatorVoteSafetyJournalV0 {
                _lock: lock,
                signing_key,
                core,
                session_issued: false,
                session_seal: Arc::new(()),
            },
        })
    }

    /// Returns the exact context bound by both journal and anchor.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.journal.context()
    }

    /// Returns the exact fixed agreement-set identity bound by both files.
    pub const fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.journal.fixed_agreement_set_id()
    }

    /// Returns the public consensus key owned by this per-key pair.
    pub const fn signer(&self) -> ConsensusKey {
        self.journal.signer()
    }

    /// Returns the header- and anchor-bound preparation ceiling.
    pub const fn replay_limit(&self) -> FixedValidatorVoteSafetyReplayLimitV0 {
        self.journal.replay_limit()
    }

    /// Returns the activated independent proposal ceiling, if present.
    pub const fn proposal_replay_limit(&self) -> Option<FixedValidatorProposalReplayLimitV0> {
        self.journal.proposal_replay_limit()
    }

    /// Returns the current healthy journal-state identity for diagnostics.
    pub fn state_id(
        &self,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.state_id()
    }

    /// Activates proposal authoring and advances the paired anchor before return.
    pub fn activate_proposal_authoring(
        &mut self,
        limit: FixedValidatorProposalReplayLimitV0,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.activate_proposal_authoring(limit)
    }

    /// Binds the initial lineage and advances the anchor before returning.
    ///
    /// Repeating the exact current binding is no-write idempotence.
    pub fn bind_signing_lineage(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.bind_signing_lineage(round)
    }

    /// Issues the sole session from the already internally anchored state.
    ///
    /// No caller state identity is accepted because this wrapper owns and
    /// synchronizes the only anchor paired with the journal.
    pub fn issue_signing_session(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<
        FixedValidatorAnchoredVoteSafetySigningSessionV0<'_>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        let state_id = self.journal.state_id()?;
        self.journal
            .issue_signing_session(round, state_id)
            .map(|session| FixedValidatorAnchoredVoteSafetySigningSessionV0 { session })
    }

    /// Issues restart authority from the exact internally anchored lineage.
    pub fn acknowledge_signer_recovery(
        &self,
    ) -> Result<FixedValidatorAnchoredSignerRecoveryV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        let state_id = self.journal.state_id()?;
        self.journal
            .acknowledge_signer_recovery_is_externally_durable(state_id)
    }

    /// Issues the sole session for one capability-recovered exact branch.
    ///
    /// The wrapper reuses its current internally anchored state and accepts only
    /// the caller-local derivation-work ceiling.
    pub fn issue_recovered_signing_session(
        &mut self,
        recovered: FixedValidatorRecoveredSignerBranchV0,
        round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    ) -> Result<
        FixedValidatorAnchoredRecoveredSigningSessionV0<'_>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        let state_id = self.journal.state_id()?;
        let recovered =
            self.journal
                .issue_recovered_signing_session(recovered, state_id, round_limit)?;
        let FixedValidatorRecoveredSigningSessionV0 { branch, session } = recovered;
        Ok(FixedValidatorAnchoredRecoveredSigningSessionV0 {
            branch,
            session: FixedValidatorAnchoredVoteSafetySigningSessionV0 { session },
        })
    }

    /// Appends a proof-backed terminal stop and anchors it before publication.
    pub fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.journal.stop_after_durable_finality_conflict(conflict)
    }

    /// Returns the durable same-slot terminal halt, if present.
    pub fn halt(
        &self,
    ) -> Result<Option<FixedValidatorVoteSafetyHaltV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.halt()
    }

    /// Returns the durable proposal same-slot terminal halt, if present.
    pub fn proposal_halt(
        &self,
    ) -> Result<Option<FixedValidatorProposalSafetyHaltV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.proposal_halt()
    }

    /// Returns the durable proof-backed finality-conflict stop, if present.
    pub fn finality_conflict_stop(
        &self,
    ) -> Result<
        Option<FixedValidatorFinalityConflictSignerStopV0>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.journal.finality_conflict_stop()
    }

    /// Returns read-only diagnostics for an uncompleted preparation.
    pub fn pending_vote(
        &self,
    ) -> Result<Option<FixedValidatorPendingVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.journal.pending_vote()
    }

    /// Returns read-only diagnostics for an uncompleted proposal preparation.
    pub fn pending_proposal(
        &self,
    ) -> Result<Option<FixedValidatorPendingProposalV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.pending_proposal()
    }

    /// Returns one retained completed vote unless either terminal cause denies it.
    pub fn retained_signed_vote(
        &self,
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    ) -> Result<Option<FixedValidatorSignedVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.journal.retained_signed_vote(position, role)
    }

    /// Returns one retained completed proposal unless a terminal cause denies it.
    pub fn retained_signed_proposal(
        &self,
        position: ConsensusPosition,
    ) -> Result<Option<FixedValidatorSignedProposalV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.retained_signed_proposal(position)
    }
}

impl<'journal> FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal> {
    /// Returns the exact current height and round of this sole live lineage.
    pub const fn position(&self) -> ConsensusPosition {
        self.session.position()
    }

    /// Returns the current fixed-validator kernel phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.session.phase()
    }

    /// Returns the current locked value, if any.
    pub const fn locked_value(&self) -> Option<FixedValidatorLockedValueV0> {
        self.session.locked_value()
    }

    /// Returns the current retained valid value and proof, if any.
    pub const fn valid_value(&self) -> Option<&FixedValidatorValidValueV0> {
        self.session.valid_value()
    }

    /// Verifies that current-round vote execution may begin without changing state.
    ///
    /// Journal health and pending vote, height, or higher-round work are checked
    /// before a caller performs any separately fallible input admission. Success
    /// grants no vote or transition authority and does not reserve the session;
    /// the consuming vote path must still repeat the established checks while
    /// deriving its effect and persisting its intent.
    pub fn ensure_current_vote_ready(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.ensure_mutable()
    }

    /// Validates, persists, and anchors one private-state-derived proposal intent.
    pub fn prepare_proposal(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        source: FixedValidatorProposalSourceV0,
    ) -> Result<FixedValidatorProposalPrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.session.prepare_proposal(round, source)
    }

    /// Converts the internally anchored preparation into key-use authority.
    pub fn acknowledge_prepared_proposal(
        &self,
        prepared: FixedValidatorPreparedProposalV0,
    ) -> Result<
        FixedValidatorDurableProposalPrepareAcknowledgementV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.session
            .acknowledge_prepared_proposal_is_externally_durable(prepared, prepared.state_id())
    }

    /// Signs and anchors proposal completion before releasing control bytes.
    pub fn sign_prepared_proposal(
        &mut self,
        acknowledgement: FixedValidatorDurableProposalPrepareAcknowledgementV0,
    ) -> Result<FixedValidatorSignedProposalV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.sign_prepared_proposal(acknowledgement)
    }

    /// Appends and anchors a proof-backed terminal signer stop.
    pub fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.session.stop_after_durable_finality_conflict(conflict)
    }

    /// Decides the current proposal path's prevote without persistence.
    pub fn decide_prevote_for_proposal(
        &mut self,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.decide_prevote_for_proposal(proposal)
    }

    /// Decides the absent-or-rejected-proposal prevote path without persistence.
    pub fn decide_prevote_without_proposal(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.decide_prevote_without_proposal()
    }

    /// Applies one proposal prevote quorum and decides precommit in memory.
    pub fn decide_precommit_for_proposal_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session
            .decide_precommit_for_proposal_quorum(round, proposal, canonical_certificate)
    }

    /// Applies one nil prevote quorum and decides nil precommit in memory.
    pub fn decide_precommit_for_nil_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session
            .decide_precommit_for_nil_quorum(round, canonical_certificate)
    }

    /// Decides nil precommit without a current-round quorum in memory.
    pub fn decide_precommit_without_quorum(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.decide_precommit_without_quorum()
    }

    /// Advances through one exact sequential typed round in memory.
    pub fn advance_round(
        &mut self,
        next_round: &FixedConsensusRoundV0<'_>,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.advance_round(next_round)
    }

    /// Advances in memory after verifying one exact nil-precommit quorum.
    pub fn advance_round_for_nil_precommit_quorum<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session
            .advance_round_for_nil_precommit_quorum(current_round, canonical_certificate)
    }

    /// Persists and anchors one verified higher-round checkpoint before return.
    pub fn prepare_higher_round_quorum_advance<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.session.prepare_higher_round_quorum_advance(
            current_round,
            canonical_certificate,
            inclusive_maximum_round,
        )
    }

    /// Persists and anchors one exact matching proposal-prevote checkpoint.
    pub fn prepare_higher_round_proposal_prevote_advance<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        expected_position: ConsensusPosition,
        expected_proposal_root: ProposalSigningRoot,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.session.prepare_higher_round_proposal_prevote_advance(
            current_round,
            canonical_certificate,
            expected_position,
            expected_proposal_root,
            inclusive_maximum_round,
        )
    }

    /// Publishes an already anchored higher-round checkpoint to live state.
    ///
    /// No caller state identity is accepted; the prepare call synchronized the
    /// paired anchor before it returned this private-field capability.
    pub fn acknowledge_prepared_higher_round<'branch>(
        &mut self,
        prepared: FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        let state_id = prepared.state_id();
        self.session
            .acknowledge_prepared_higher_round_is_externally_durable(prepared, state_id)
    }

    /// Persists and anchors one exact finality-authorized child lineage.
    pub fn prepare_height_with_durable_finality<'finality>(
        &mut self,
        transition: FixedValidatorDurableFinalityTransitionV0<'finality>,
    ) -> Result<
        FixedValidatorPreparedHeightAdvanceV0<'finality>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.session
            .prepare_height_with_durable_finality(transition)
    }

    /// Advances live signer memory to an already anchored child lineage.
    ///
    /// No caller state identity is accepted; the prepared capability can only
    /// name the transition already persisted by this paired wrapper.
    pub fn acknowledge_prepared_height(
        &mut self,
        prepared: FixedValidatorPreparedHeightAdvanceV0<'_>,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorVoteSafetyJournalErrorV0> {
        let state_id = prepared.state_id();
        self.session
            .acknowledge_prepared_height_is_externally_durable(prepared, state_id)
    }

    /// Persists and anchors the exact session-derived vote preparation.
    pub fn prepare_vote(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        effect: FixedValidatorUnsignedVoteEffectV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.prepare_vote(round, effect)
    }

    /// Converts an already anchored live preparation into key-use authority.
    ///
    /// The wrapper accepts no caller identity and rechecks the private prepared
    /// capability against the exact live journal state.
    pub fn acknowledge_prepared_vote(
        &self,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<FixedValidatorDurablePrepareAcknowledgementV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.session
            .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
    }

    /// Signs the acknowledged preparation and anchors completion before release.
    pub fn sign_prepared_vote(
        &mut self,
        acknowledgement: FixedValidatorDurablePrepareAcknowledgementV0,
    ) -> Result<FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.session.sign_prepared_vote(acknowledgement)
    }
}

impl<'journal> FixedValidatorAnchoredRecoveredSigningSessionV0<'journal> {
    /// Returns the exact branch recovered for this sole signing session.
    pub const fn branch(&self) -> &FixedConsensusBranchV0 {
        &self.branch
    }

    /// Returns the recovered anchored signing session read-only.
    pub const fn session(&self) -> &FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal> {
        &self.session
    }

    /// Returns the recovered anchored signing session mutably.
    pub fn session_mut<'session>(
        &'session mut self,
    ) -> &'session mut FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal> {
        &mut self.session
    }

    /// Separates the exact recovered branch and its sole anchored session.
    ///
    /// The session continues to borrow the same per-key journal, so this does
    /// not widen key, recovery, or second-session authority.
    pub fn into_parts(
        self,
    ) -> (
        FixedConsensusBranchV0,
        FixedValidatorAnchoredVoteSafetySigningSessionV0<'journal>,
    ) {
        (self.branch, self.session)
    }
}
