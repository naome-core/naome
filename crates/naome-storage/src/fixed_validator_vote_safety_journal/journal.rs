//! Raw journal creation, reopen, and capability issuance.

use super::*;

impl FixedValidatorVoteSafetyJournalV0 {
    /// Creates one empty per-key journal without replacing existing bytes.
    ///
    /// The complete header is synchronized before the genesis state identity is
    /// exposed. Parent-directory-entry durability remains a provisioning
    /// responsibility outside this file protocol.
    pub fn create(
        directory: impl AsRef<Path>,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signing_key: SigningKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    ) -> Result<Self, FixedValidatorVoteSafetyJournalErrorV0> {
        let signer = consensus_key(&signing_key);
        let prefix = canonical_prefix(context, fixed_set_id, signer, replay_limit)?;
        let state_id = genesis_state_id(&prefix);
        let directory = directory.as_ref();
        let (lock_path, journal_path) = keyed_paths(directory, signer)?;
        let lock = open_key_lock(&lock_path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(journal_path)
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Create { source })?;
        file.append_write_all(AppendPhase::Body, &prefix)
            .and_then(|()| file.append_sync_all(AppendPhase::Body))
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Create { source })?;
        Ok(Self {
            _lock: lock,
            signing_key,
            core: FixedValidatorVoteSafetyJournalCore::empty(
                file,
                context,
                fixed_set_id,
                signer,
                replay_limit,
                state_id,
            ),
            session_issued: false,
            session_seal: Arc::new(()),
        })
    }

    /// Exclusively opens and strictly replays one externally anchored journal.
    ///
    /// Replay returns no key-owning handle unless its complete verified record
    /// prefix has exactly `expected_state_id`. Only then may an incomplete final
    /// record be truncated and synchronized. A complete unanchored suffix,
    /// deletion, corruption, or another expected identity fails closed.
    pub fn open_verified(
        directory: impl AsRef<Path>,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signing_key: SigningKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
        expected_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<Self, FixedValidatorVoteSafetyJournalErrorV0> {
        let signer = consensus_key(&signing_key);
        let expected_prefix = canonical_prefix(context, fixed_set_id, signer, replay_limit)?;
        let directory = directory.as_ref();
        let (lock_path, journal_path) = keyed_paths(directory, signer)?;
        let lock = open_key_lock(&lock_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_path)
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Open { source })?;
        let core = FixedValidatorVoteSafetyJournalCore::replay(
            file,
            context,
            fixed_set_id,
            signer,
            replay_limit,
            expected_prefix,
            expected_state_id,
            None,
        )?;
        Ok(Self {
            _lock: lock,
            signing_key,
            core,
            session_issued: false,
            session_seal: Arc::new(()),
        })
    }

    /// Returns the exact header-bound consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.core.context
    }

    /// Returns the exact header-bound fixed agreement-set identity.
    pub const fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.core.fixed_set_id
    }

    /// Returns the public consensus key owned by this journal.
    pub const fn signer(&self) -> ConsensusKey {
        self.core.signer
    }

    /// Returns the local prepared-vote replay ceiling.
    pub const fn replay_limit(&self) -> FixedValidatorVoteSafetyReplayLimitV0 {
        self.core.replay_limit
    }

    /// Returns the activated independent proposal ceiling, if present.
    pub const fn proposal_replay_limit(&self) -> Option<FixedValidatorProposalReplayLimitV0> {
        self.core.proposal_replay_limit
    }

    /// Activates proposal authoring once, before this handle issues a session.
    ///
    /// The positive cap is chained into the existing journal and anchor state.
    /// Repeating the exact cap is no-write idempotence; changing it fails
    /// closed. This does not grant proposer scheduling or publication authority.
    pub fn activate_proposal_authoring(
        &mut self,
        limit: FixedValidatorProposalReplayLimitV0,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.activate_proposal_authoring(limit)
    }

    /// Durably binds the exact current branch lineage used by signing recovery.
    ///
    /// A new or legacy journal without a lineage record appends one synchronized
    /// content binding after strictly constructing or replaying the supplied
    /// typed round. An exact existing binding is no-write idempotence. A
    /// different branch or height fails without replacing it. The returned
    /// state identity must be externally durable before session issuance.
    pub fn bind_signing_lineage(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.bind_signing_lineage(round)
    }

    /// Issues the only signing session available from this open journal handle.
    ///
    /// The supplied typed round must match the retained signing-lineage record.
    /// An empty current lineage starts from exact branch-derived round zero; a
    /// lineage with a latest durably completed proposal, vote, or higher-round
    /// checkpoint reconstructs only that exact post-effect state after full
    /// typed replay.
    /// The caller must explicitly assert the exact current journal state as
    /// externally durable. A pending preparation or terminal halt cannot issue a
    /// session. Proposal authoring must already have its independent positive
    /// replay ceiling durably activated. The issuance latch is monotonic for
    /// this handle: dropping or forgetting the returned value does not permit a
    /// replacement session.
    pub fn issue_signing_session(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedValidatorVoteSafetySigningSessionV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.ensure_recoverable()?;
        self.core.ensure_proposal_authoring_activated()?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        let lock_state = self.core.recover_lock_state_for_round(round)?;

        self.session_issued = true;
        Ok(FixedValidatorVoteSafetySigningSessionV0 {
            journal: self,
            lock_state,
            pending_height_advance: None,
            pending_higher_round_advance: None,
        })
    }

    /// Issues authority to reconstruct this exact anchored signing lineage.
    ///
    /// The caller explicitly acknowledges the journal's complete current state
    /// as externally durable. A pending vote, either terminal cause, missing
    /// lineage, missing proposal activation, or prior session issuance fails
    /// before capability publication. The returned value accepts no
    /// caller-selected branch, height, signer, or round.
    pub fn acknowledge_signer_recovery_is_externally_durable(
        &self,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<FixedValidatorAnchoredSignerRecoveryV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.ensure_recoverable()?;
        self.core.ensure_proposal_authoring_activated()?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        let lineage = self
            .core
            .lineage
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)?;
        let required_position = self.core.signer_recovery_position(lineage);
        Ok(FixedValidatorAnchoredSignerRecoveryV0 {
            _journal: self,
            lineage,
            required_position,
            vote_state_id: self.core.state_id,
            signer: self.core.signer,
            session_seal: Arc::clone(&self.session_seal),
        })
    }

    /// Consumes one exact finality-reconstructed branch and issues one session.
    ///
    /// The recovered value must descend from this handle's own anchored
    /// capability. The current external vote anchor, session provenance, exact
    /// lineage, proposal activation, and latest durable current-lineage position
    /// are rechecked before the monotonic issuance latch changes. Sequential
    /// round reconstruction is bounded by the caller-local inclusive work
    /// ceiling.
    pub fn issue_recovered_signing_session(
        &mut self,
        recovered: FixedValidatorRecoveredSignerBranchV0,
        externally_durable_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
        round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    ) -> Result<FixedValidatorRecoveredSigningSessionV0<'_>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        if self.session_issued {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued);
        }
        self.core.ensure_recoverable()?;
        self.core.ensure_proposal_authoring_activated()?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        if !Arc::ptr_eq(&self.session_seal, &recovered.session_seal) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignSignerRecovery);
        }
        if recovered.vote_state_id != self.core.state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::StaleSignerRecovery {
                    recovered: recovered.vote_state_id,
                    current: self.core.state_id,
                },
            );
        }
        let required_round = recovered.required_position.round().value();
        if required_round > round_limit.maximum_round() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRoundLimitExceeded {
                    required: required_round,
                    maximum: round_limit.maximum_round(),
                },
            );
        }

        let mut round = recovered
            .branch
            .begin_round_zero()
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRound)?;
        if round.position().height() != recovered.required_position.height() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryPositionMismatch {
                    required: recovered.required_position,
                    actual: round.position(),
                },
            );
        }
        for _ in 0..required_round {
            round = round
                .advance_round()
                .map_err(FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRound)?;
        }
        debug_assert_eq!(round.position(), recovered.required_position);
        let lock_state = self.core.recover_lock_state_for_round(&round)?;
        drop(round);

        self.session_issued = true;
        Ok(FixedValidatorRecoveredSigningSessionV0 {
            branch: recovered.branch,
            session: FixedValidatorVoteSafetySigningSessionV0 {
                journal: self,
                lock_state,
                pending_height_advance: None,
                pending_higher_round_advance: None,
            },
        })
    }

    /// Returns the current exact journal-state identity, including after either
    /// terminal cause.
    pub fn state_id(
        &self,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        Ok(self.core.state_id)
    }

    /// Durably stops this signer from one exact anchored finality conflict.
    ///
    /// This path remains available before session issuance and after a live
    /// session is dropped. It accepts conflict authority only for this
    /// journal's exact consensus context and fixed validator set. The stop is
    /// monotonic, may preempt an unresolved preparation, and never performs a
    /// key operation or selects either conflicting sibling.
    pub fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.core.stop_after_durable_finality_conflict(conflict)
    }

    /// Returns the durable terminal halt summary, if present.
    pub fn halt(
        &self,
    ) -> Result<Option<FixedValidatorVoteSafetyHaltV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        Ok(self.core.halt)
    }

    /// Returns the durable proposal same-slot terminal halt, if present.
    pub fn proposal_halt(
        &self,
    ) -> Result<Option<FixedValidatorProposalSafetyHaltV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        Ok(self.core.proposal_halt)
    }

    /// Returns the durable finality-conflict signer stop, if present.
    pub fn finality_conflict_stop(
        &self,
    ) -> Result<
        Option<FixedValidatorFinalityConflictSignerStopV0>,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.core.ensure_healthy()?;
        Ok(self.core.finality_conflict_stop)
    }

    /// Returns a capability for the sole pending durable preparation.
    #[cfg(test)]
    pub(super) fn pending_prepared_vote(
        &self,
    ) -> Result<Option<FixedValidatorPreparedVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self.core.pending_capability())
    }

    /// Returns read-only diagnostics for an uncompleted preparation.
    ///
    /// This remains readable after an anchored reopen has deliberately made
    /// the pending record non-signable.
    pub fn pending_vote(
        &self,
    ) -> Result<Option<FixedValidatorPendingVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.ensure_healthy()?;
        Ok(self.core.pending_summary())
    }

    /// Returns read-only diagnostics for an uncompleted proposal preparation.
    pub fn pending_proposal(
        &self,
    ) -> Result<Option<FixedValidatorPendingProposalV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        Ok(self.core.pending_proposal_summary())
    }

    /// Durably appends and synchronizes one full consensus-provided intent.
    ///
    /// No signing occurs in this stage. Byte-identical repetition is
    /// idempotent. Any non-identical intent for an existing context/height/
    /// round/role slot durably appends a terminal halt before returning.
    pub(super) fn prepare_vote(
        &mut self,
        intent: FixedValidatorVoteIntentV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.prepare_vote(intent)
    }

    /// Signs only the exact durable preparation and releases bytes only after sync.
    pub(super) fn sign_prepared_vote(
        &mut self,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<FixedValidatorVoteSignOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.sign_prepared_vote(&self.signing_key, prepared)
    }

    pub(super) fn prepare_proposal(
        &mut self,
        intent: FixedValidatorProposalIntentV0,
    ) -> Result<FixedValidatorProposalPrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.prepare_proposal(intent)
    }

    pub(super) fn sign_prepared_proposal(
        &mut self,
        prepared: FixedValidatorPreparedProposalV0,
    ) -> Result<FixedValidatorSignedProposalV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core
            .sign_prepared_proposal(&self.signing_key, prepared)
    }

    /// Returns one retained completed vote for local diagnostics or replay.
    ///
    /// Exact bytes remain available behind a later pending preparation, but
    /// either durable terminal cause denies every vote release.
    pub fn retained_signed_vote(
        &self,
        position: ConsensusPosition,
        role: ConsensusVoteRole,
    ) -> Result<Option<FixedValidatorSignedVoteV0>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.ensure_not_halted()?;
        Ok(self
            .core
            .votes
            .get(&VoteSlot::new(position, role))
            .and_then(|record| record.signed.clone()))
    }

    /// Returns one retained completed proposal unless a terminal cause denies it.
    pub fn retained_signed_proposal(
        &self,
        position: ConsensusPosition,
    ) -> Result<Option<FixedValidatorSignedProposalV0>, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.core.ensure_not_halted()?;
        Ok(self
            .core
            .proposals
            .get(&position)
            .and_then(|record| record.signed.clone()))
    }

    /// Returns the exact state-and-intent bytes behind the latest completed vote.
    ///
    /// A caller may pass these bytes to the consensus crate's non-signing,
    /// typed-round replay verifier to reconstruct lock, valid-value, and phase
    /// state in completed-vote test fixtures. Production session recovery instead
    /// selects the latest durable current-lineage vote or checkpoint. Pending
    /// records are withheld because V0 never permits a restarted caller to advance
    /// from an unresolved prepare boundary. Either durable terminal cause also
    /// denies operational recovery.
    #[cfg(test)]
    pub(super) fn latest_completed_state_and_vote_intent_bytes(
        &self,
    ) -> Result<Option<&[u8]>, FixedValidatorVoteSafetyJournalErrorV0> {
        self.core.ensure_recoverable()?;
        let Some(latest) = self.core.latest_slot else {
            return Ok(None);
        };
        let retained = self
            .core
            .votes
            .get(&latest)
            .expect("the latest vote slot is retained");
        retained
            .signed
            .as_ref()
            .expect("a healthy non-pending latest vote is durably completed");
        Ok(Some(
            retained
                .observed_intent
                .canonical_state_and_vote_intent_bytes(),
        ))
    }
}
