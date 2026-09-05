//! Sole signing session and consensus-to-journal boundary.

use super::*;

impl FixedValidatorVoteSafetySigningSessionV0<'_> {
    /// Returns the exact current height and round of this sole live lineage.
    pub const fn position(&self) -> ConsensusPosition {
        self.lock_state.position()
    }

    /// Returns the current fixed-validator kernel phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.lock_state.phase()
    }

    /// Returns the current locked value, if any.
    pub const fn locked_value(&self) -> Option<FixedValidatorLockedValueV0> {
        self.lock_state.locked_value()
    }

    /// Returns the current retained valid value and proof, if any.
    pub const fn valid_value(&self) -> Option<&FixedValidatorValidValueV0> {
        self.lock_state.valid_value()
    }

    /// Validates and durably prepares the sole proposal allowed by private state.
    ///
    /// Scheduled-proposer and phase authority are checked before artifact work.
    /// The exact complete state and producer-signing intent synchronize before
    /// this method returns, but no key operation occurs here.
    pub fn prepare_proposal(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        source: FixedValidatorProposalSourceV0,
    ) -> Result<FixedValidatorProposalPrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.journal.core.ensure_operational()?;
        self.ensure_no_pending_height_advance()?;
        self.ensure_no_pending_higher_round_advance()?;
        if let Some(pending) = self.journal.core.pending {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            });
        }
        let intent = self
            .lock_state
            .prepare_proposal_intent(round, source, self.journal.signer())
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::ProposalPreparation)?;
        self.journal.prepare_proposal(intent)
    }

    /// Asserts that the exact prepared proposal state is externally durable.
    pub fn acknowledge_prepared_proposal_is_externally_durable(
        &self,
        prepared: FixedValidatorPreparedProposalV0,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<
        FixedValidatorDurableProposalPrepareAcknowledgementV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        if externally_durable_state_id != prepared.state_id() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalPrepareAnchorMismatch {
                    prepared: prepared.state_id(),
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        self.journal
            .core
            .validate_live_prepared_proposal(prepared)?;
        Ok(FixedValidatorDurableProposalPrepareAcknowledgementV0 {
            prepared,
            session_seal: Arc::clone(&self.journal.session_seal),
        })
    }

    /// Uses the owned key only for an acknowledged proposal preparation.
    ///
    /// The completed producer authorization synchronizes before canonical
    /// proposal-control bytes are returned.
    pub fn sign_prepared_proposal(
        &mut self,
        acknowledgement: FixedValidatorDurableProposalPrepareAcknowledgementV0,
    ) -> Result<FixedValidatorSignedProposalV0, FixedValidatorVoteSafetyJournalErrorV0> {
        if !Arc::ptr_eq(&self.journal.session_seal, &acknowledgement.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignPrepareAcknowledgement);
        }
        self.journal
            .core
            .validate_live_prepared_proposal(acknowledgement.prepared)?;
        self.journal
            .sign_prepared_proposal(acknowledgement.prepared)
    }

    /// Durably stops this already-live signer from anchored finality conflict.
    ///
    /// Stop authority deliberately preempts pending vote, height, or higher-round
    /// work. Once the terminal record synchronizes, every later session transition
    /// and key-use path fails closed; bytes released before this call cannot be
    /// retracted.
    pub fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        let outcome = self
            .journal
            .core
            .stop_after_durable_finality_conflict(conflict)?;
        self.pending_height_advance = None;
        self.pending_higher_round_advance = None;
        Ok(outcome)
    }

    /// Decides the current proposal path's prevote without exposing mutable state.
    pub fn decide_prevote_for_proposal(
        &mut self,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_prevote_for_proposal(proposal)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Decides the absent-or-rejected-proposal prevote path.
    pub fn decide_prevote_without_proposal(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_prevote_without_proposal()
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Applies one current-round proposal prevote quorum and decides precommit.
    pub fn decide_precommit_for_proposal_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_precommit_for_proposal_quorum(round, proposal, canonical_certificate)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Applies one current-round nil prevote quorum and decides nil precommit.
    pub fn decide_precommit_for_nil_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_precommit_for_nil_quorum(round, canonical_certificate)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Decides nil precommit when no current-round prevote quorum is available.
    pub fn decide_precommit_without_quorum(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .decide_precommit_without_quorum()
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Advances this lineage through one exact sequential branch-derived round.
    pub fn advance_round(
        &mut self,
        next_round: &FixedConsensusRoundV0<'_>,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .advance_round(next_round)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Advances after one exact current-round precommit/nil quorum.
    ///
    /// Journal health and pending vote, height, or higher-round work are checked
    /// before the kernel verifies the canonical certificate and exact sequential
    /// cursors. Success changes only this session's volatile lock state. Any later
    /// vote at the advanced round still passes through the unchanged durable
    /// prepare, external-anchor acknowledgement, completion, and release boundary.
    ///
    /// This method does not persist the observed quorum, schedule or infer a
    /// timeout, finalize a value, select a branch, or grant networking or peer
    /// authority.
    pub fn advance_round_for_nil_precommit_quorum<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_mutable()?;
        self.lock_state
            .advance_round_for_nil_precommit_quorum(current_round, canonical_certificate)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)
    }

    /// Verifies and durably checkpoints one phase-only higher-round catch-up.
    ///
    /// The live lock state remains unchanged while the consensus kernel derives
    /// and fully verifies the target under the caller-local inclusive maximum.
    /// The journal then synchronizes one exact chained checkpoint containing the
    /// canonical QC and complete post-jump state. No vote, key use, or live
    /// higher-round publication occurs in this stage. Every other mutable session
    /// path remains blocked until exact external acknowledgement except the
    /// explicit proof-backed finality-conflict stop, which may preempt it.
    pub fn prepare_higher_round_quorum_advance<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.ensure_mutable()?;
        let transition = self
            .lock_state
            .prepare_higher_round_quorum_advance(
                current_round,
                canonical_certificate,
                inclusive_maximum_round,
            )
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        self.persist_higher_round_advance(transition)
    }

    /// Persists one exact matching higher-round proposal-prevote checkpoint.
    ///
    /// Position, role, and proposal root are fully authenticated and matched by
    /// the lock kernel before any journal append. A mismatch therefore leaves
    /// both live state and durable state unchanged.
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
        self.ensure_mutable()?;
        let transition = self
            .lock_state
            .prepare_higher_round_proposal_prevote_advance(
                current_round,
                canonical_certificate,
                expected_position,
                expected_proposal_root,
                inclusive_maximum_round,
            )
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        self.persist_higher_round_advance(transition)
    }

    pub(super) fn persist_higher_round_advance<'branch>(
        &mut self,
        transition: VerifiedFixedValidatorHigherRoundAdvanceV0<'branch>,
    ) -> Result<
        FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        let prepared_state_id = self
            .journal
            .core
            .append_higher_round_checkpoint(transition.canonical_checkpoint_bytes())?;
        self.pending_higher_round_advance = Some(prepared_state_id);
        Ok(FixedValidatorPreparedHigherRoundAdvanceV0 {
            transition,
            prepared_state_id,
            session_seal: Arc::clone(&self.journal.session_seal),
        })
    }

    /// Acknowledges one exact durable checkpoint and publishes its live state.
    ///
    /// The external state identity, issuing session, current journal state, and
    /// latest retained checkpoint are rechecked before the consensus transition
    /// changes only position and phase. A wrong, stale, or foreign token changes
    /// no live state and leaves the session blocked; an exact anchored reopen is
    /// then the only recovery route.
    pub fn acknowledge_prepared_higher_round_is_externally_durable<'branch>(
        &mut self,
        prepared: FixedValidatorPreparedHigherRoundAdvanceV0<'branch>,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorVoteSafetyJournalErrorV0> {
        if externally_durable_state_id != prepared.prepared_state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalHigherRoundAnchorMismatch {
                    prepared: prepared.prepared_state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        if !Arc::ptr_eq(&self.journal.session_seal, &prepared.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignHigherRoundAdvance);
        }
        self.journal.core.ensure_operational()?;
        let latest_matches = matches!(
            self.journal.core.latest_current_lineage_state.as_ref(),
            Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
                if *state_id == prepared.prepared_state_id
        );
        if self.pending_higher_round_advance != Some(prepared.prepared_state_id)
            || self.journal.core.state_id != prepared.prepared_state_id
            || !latest_matches
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StaleHigherRoundAdvance);
        }
        let target_round = self
            .lock_state
            .apply_prepared_higher_round_quorum_advance(prepared.transition)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        self.pending_higher_round_advance = None;
        Ok(target_round)
    }

    /// Persists one exact finalized child before advancing signer memory.
    ///
    /// Parent, height, and child round zero are preflighted before the vote
    /// journal appends its next signing-lineage record. The returned capability
    /// keeps the finality journal immutably borrowed until the caller has made
    /// the new vote-journal state externally durable and acknowledges it.
    pub fn prepare_height_with_durable_finality<'finality>(
        &mut self,
        transition: FixedValidatorDurableFinalityTransitionV0<'finality>,
    ) -> Result<
        FixedValidatorPreparedHeightAdvanceV0<'finality>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.ensure_mutable()?;
        let child_position = self
            .lock_state
            .validate_height_transition(transition.verified_transition())
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        let child_lineage_id = signing_lineage_id(
            transition.verified_transition().child_coordinate(),
            child_position.height(),
            self.journal.signer(),
        );
        let prepared_state_id = self
            .journal
            .core
            .append_signing_lineage(child_position.height(), child_lineage_id)?;
        self.pending_height_advance = Some(prepared_state_id);
        Ok(FixedValidatorPreparedHeightAdvanceV0 {
            transition,
            prepared_state_id,
            session_seal: Arc::clone(&self.journal.session_seal),
        })
    }

    /// Acknowledges the persisted child lineage and advances signer memory.
    ///
    /// The exact vote-journal state, session provenance, and still-live
    /// finality capability are rechecked before consuming the transition and
    /// advancing this live session. Finality authorization is point-in-time:
    /// once this exact child-lineage state is externally anchored, a later
    /// finality-journal halt alone does not retroactively revoke it. An explicit
    /// durable finality-conflict stop does. If the token is dropped before this
    /// live acknowledgement, strict reopen resumes the anchored child without a
    /// new token unless that stop has been applied.
    pub fn acknowledge_prepared_height_is_externally_durable(
        &mut self,
        prepared: FixedValidatorPreparedHeightAdvanceV0<'_>,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorVoteSafetyJournalErrorV0> {
        if externally_durable_state_id != prepared.prepared_state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalHeightAnchorMismatch {
                    prepared: prepared.prepared_state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        if !Arc::ptr_eq(&self.journal.session_seal, &prepared.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignHeightAdvance);
        }
        self.journal.core.ensure_operational()?;
        if self.pending_height_advance != Some(prepared.prepared_state_id)
            || self.journal.core.state_id != prepared.prepared_state_id
            || self
                .journal
                .core
                .lineage
                .is_none_or(|lineage| lineage.state_id != prepared.prepared_state_id)
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StaleHeightAdvance);
        }
        let child = self
            .lock_state
            .advance_height_with_verified_transition(prepared.transition.into_verified_transition())
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState)?;
        self.pending_height_advance = None;
        Ok(child)
    }

    /// Durably prepares the exact effect produced by this session's private state.
    ///
    /// This is the only public route into the journal's raw intent preparation.
    /// It performs no key operation and returns only after the prepare body and
    /// chained state-ID footer have both synchronized.
    pub fn prepare_vote(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        effect: FixedValidatorUnsignedVoteEffectV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.journal.core.ensure_operational()?;
        self.ensure_no_pending_height_advance()?;
        self.ensure_no_pending_higher_round_advance()?;
        let intent = self
            .lock_state
            .prepare_vote_intent(round, effect, self.journal.signer())
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionIntent)?;
        self.journal.prepare_vote(intent)
    }

    /// Explicitly asserts that the exact prepared state ID is externally durable.
    ///
    /// The journal checks identity and live-session provenance, but it cannot
    /// inspect the external monotonic store. Calling this method is therefore a
    /// caller assertion that persistence completed before any key use.
    pub fn acknowledge_prepared_vote_is_externally_durable(
        &self,
        prepared: FixedValidatorPreparedVoteV0,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedValidatorDurablePrepareAcknowledgementV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        if externally_durable_state_id != prepared.state_id() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalPrepareAnchorMismatch {
                    prepared: prepared.state_id(),
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        self.journal.core.validate_live_prepared_vote(prepared)?;
        Ok(FixedValidatorDurablePrepareAcknowledgementV0 {
            prepared,
            session_seal: Arc::clone(&self.journal.session_seal),
        })
    }

    /// Signs only an explicitly acknowledged live preparation.
    ///
    /// Session provenance, the exact prepared state ID, and current pending
    /// state are validated before the private key is invoked. Signed bytes are
    /// returned only after the completion record and footer synchronize.
    pub fn sign_prepared_vote(
        &mut self,
        acknowledgement: FixedValidatorDurablePrepareAcknowledgementV0,
    ) -> Result<FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyJournalErrorV0> {
        if !Arc::ptr_eq(&self.journal.session_seal, &acknowledgement.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignPrepareAcknowledgement);
        }
        self.journal
            .core
            .validate_live_prepared_vote(acknowledgement.prepared)?;
        match self.journal.sign_prepared_vote(acknowledgement.prepared)? {
            FixedValidatorVoteSignOutcomeV0::Signed(signed) => Ok(signed),
            FixedValidatorVoteSignOutcomeV0::AlreadySigned(_) => {
                unreachable!("the live-preparation check rejects an already completed vote")
            }
        }
    }

    pub(super) fn ensure_mutable(&self) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.journal.core.ensure_operational()?;
        self.ensure_no_pending_height_advance()?;
        self.ensure_no_pending_higher_round_advance()?;
        if let Some(pending) = self.journal.core.pending {
            Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            })
        } else if let Some(position) = self.journal.core.pending_proposal {
            Err(FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation { position })
        } else {
            Ok(())
        }
    }

    pub(super) fn ensure_no_pending_height_advance(
        &self,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if let Some(state_id) = self.pending_height_advance {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance { state_id });
        }
        Ok(())
    }

    pub(super) fn ensure_no_pending_higher_round_advance(
        &self,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if let Some(state_id) = self.pending_higher_round_advance {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance { state_id },
            );
        }
        Ok(())
    }
}
