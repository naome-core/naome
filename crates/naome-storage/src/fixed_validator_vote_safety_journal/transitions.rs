//! Live durable signing-safety transitions.

use super::*;

impl<F: StoreIo> FixedValidatorVoteSafetyJournalCore<F> {
    pub(super) fn stop_after_durable_finality_conflict(
        &mut self,
        conflict: FixedValidatorDurableFinalityConflictV0<'_>,
    ) -> Result<
        FixedValidatorFinalityConflictSignerStopOutcomeV0,
        FixedValidatorVoteSafetyJournalErrorV0,
    > {
        self.ensure_healthy()?;
        if conflict.context() != self.context {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::FinalityConflictContextMismatch);
        }
        if conflict.fixed_agreement_set_id() != self.fixed_set_id {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::FinalityConflictFixedSetMismatch);
        }
        let halt = conflict.halt();
        let proposed = FixedValidatorFinalityConflictSignerStopV0 {
            kind: halt.kind(),
            finality_state_id: halt.state_id(),
            height: halt.height(),
            first_ancestry: halt.first_ancestry(),
            first_envelope_id: halt.first_envelope_id(),
            second_ancestry: halt.second_ancestry(),
            second_envelope_id: halt.second_envelope_id(),
            vote_state_id: self.state_id,
        };
        if let Some(existing) = self.finality_conflict_stop {
            if existing.same_conflict(proposed) {
                return Ok(
                    FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(existing),
                );
            }
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ConflictingFinalityConflictSignerStop {
                    retained_height: existing.height,
                    incoming_height: proposed.height,
                },
            );
        }
        if let Some(existing) = self.halt {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt {
                position: existing.position,
                role: existing.role,
            });
        }
        if let Some(existing) = self.proposal_halt {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::TerminalProposalHalt {
                    position: existing.position,
                },
            );
        }
        let body = finality_conflict_stop_record(proposed, self.prepared_count)?;
        let next_state_id = self.append_record(&body, self.prepared_count)?;
        let stopped = FixedValidatorFinalityConflictSignerStopV0 {
            vote_state_id: next_state_id,
            ..proposed
        };
        self.finality_conflict_stop = Some(stopped);
        self.pending = None;
        self.pending_proposal = None;
        self.live_pending_intent = None;
        self.live_pending_proposal_intent = None;
        self.state_id = next_state_id;
        Ok(FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(
            stopped,
        ))
    }

    pub(super) fn bind_signing_lineage(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.ensure_recoverable()?;
        let lock_state = self.restore_lock_state_for_round(round)?;
        let height = lock_state.position().height();
        let id = signing_lineage_id(round.parent_coordinate(), height, self.signer);
        if let Some(lineage) = self.lineage {
            if lineage.height == height && lineage.id == id {
                return Ok(self.state_id);
            }
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
                    expected_height: lineage.height,
                    actual_height: height,
                },
            );
        }
        self.append_signing_lineage(height, id)
    }

    pub(super) fn require_vote_after_higher_round_checkpoint(
        &self,
        entry: u64,
        position: ConsensusPosition,
        phase: FixedValidatorLockPhaseV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        let Some(RetainedCurrentLineageStateV0::HigherRound { checkpoint, .. }) =
            self.latest_current_lineage_state.as_ref()
        else {
            return Ok(());
        };
        if !state_coordinate_cmp(position, phase, checkpoint.position(), checkpoint.phase()).is_gt()
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::VoteStateDoesNotFollowHigherRoundCheckpoint {
                    entry,
                    checkpoint_position: checkpoint.position(),
                    checkpoint_phase: checkpoint.phase(),
                    vote_position: position,
                    vote_phase: phase,
                },
            );
        }
        Ok(())
    }

    pub(super) fn append_signing_lineage(
        &mut self,
        height: ConsensusHeight,
        id: SigningLineageIdV0,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.ensure_operational()?;
        let had_lineage = self.lineage.is_some();
        if let Some(pending) = self.pending {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            });
        }
        if let Some(position) = self.pending_proposal {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation { position },
            );
        }
        if let Some(previous) = self.lineage {
            let expected = previous
                .height
                .value()
                .checked_add(1)
                .map(ConsensusHeight::new)
                .ok_or(
                    FixedValidatorVoteSafetyJournalErrorV0::SigningLineageHeightExhausted {
                        entry: self.prepared_count,
                        previous: previous.height,
                    },
                )?;
            if height != expected {
                return Err(
                    FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
                        entry: self.prepared_count,
                        expected,
                        actual: height,
                    },
                );
            }
        }
        let body = signing_lineage_record(height, id, self.prepared_count)?;
        let next_state_id = self.append_record(&body, self.prepared_count)?;
        self.lineage = Some(RetainedSigningLineageV0 {
            height,
            id,
            state_id: next_state_id,
        });
        self.latest_current_lineage_state = if had_lineage {
            None
        } else {
            self.latest_slot
                .filter(|slot| slot.position.height() == height)
                .map(RetainedCurrentLineageStateV0::Vote)
        };
        self.state_id = next_state_id;
        Ok(next_state_id)
    }

    pub(super) fn append_higher_round_checkpoint(
        &mut self,
        canonical_checkpoint: &[u8],
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.ensure_operational()?;
        let checkpoint = self.validate_higher_round_checkpoint(
            self.prepared_count,
            self.committed_end,
            canonical_checkpoint,
        )?;
        let body = tagged_record(
            HIGHER_ROUND_CHECKPOINT_RECORD,
            canonical_checkpoint,
            self.prepared_count,
        )?;
        let next_state_id = self.append_record(&body, self.prepared_count)?;
        self.latest_current_lineage_state = Some(RetainedCurrentLineageStateV0::HigherRound {
            checkpoint: Box::new(checkpoint),
            state_id: next_state_id,
        });
        self.state_id = next_state_id;
        Ok(next_state_id)
    }

    pub(super) fn activate_proposal_authoring(
        &mut self,
        limit: FixedValidatorProposalReplayLimitV0,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.ensure_not_halted()?;
        if self.pending.is_some() || self.pending_proposal.is_some() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ProposalActivationWhileLivePending);
        }
        if let Some(existing) = self.proposal_replay_limit {
            if existing == limit {
                return Ok(self.state_id);
            }
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ProposalReplayLimitMismatch {
                    retained: existing.max_prepared_proposals(),
                    supplied: limit.max_prepared_proposals(),
                },
            );
        }
        let body = tagged_record(
            PROPOSAL_ACTIVATION_RECORD,
            &limit.max_prepared_proposals().to_be_bytes(),
            self.record_sequence,
        )?;
        let next_state_id = self.append_record(&body, self.record_sequence)?;
        self.proposal_replay_limit = Some(limit);
        self.state_id = next_state_id;
        Ok(next_state_id)
    }

    pub(super) fn prepare_proposal(
        &mut self,
        intent: FixedValidatorProposalIntentV0,
    ) -> Result<FixedValidatorProposalPrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        self.ensure_operational()?;
        let canonical_intent = intent.canonical_intent_bytes();
        let observed =
            self.decode_observed_proposal_intent(canonical_intent, self.record_sequence, 0)?;
        let position = observed.position();
        if let Some(pending) = self.pending {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            });
        }
        if let Some(pending) = self.pending_proposal
            && pending != position
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation {
                    position: pending,
                },
            );
        }
        if let Some(retained) = self.proposals.get(&position) {
            if retained.observed_intent.canonical_intent_bytes() == canonical_intent {
                if let Some(signed) = &retained.signed {
                    return Ok(FixedValidatorProposalPrepareOutcomeV0::AlreadySigned(
                        signed.clone(),
                    ));
                }
                return Ok(FixedValidatorProposalPrepareOutcomeV0::AlreadyPrepared(
                    prepared_proposal_capability(position, retained),
                ));
            }
            let retained_intent = retained.observed_intent.clone();
            let body = tagged_record(
                PROPOSAL_CONFLICT_HALT_RECORD,
                canonical_intent,
                self.record_sequence,
            )?;
            let next_state_id = self.append_record(&body, self.record_sequence)?;
            let halt = proposal_halt(position, &retained_intent, &observed, next_state_id);
            self.proposal_halt = Some(halt);
            self.pending = None;
            self.pending_proposal = None;
            self.live_pending_intent = None;
            self.live_pending_proposal_intent = None;
            self.state_id = next_state_id;
            return Ok(FixedValidatorProposalPrepareOutcomeV0::Halted(halt));
        }
        if let Some(pending) = self.pending_proposal {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation {
                    position: pending,
                },
            );
        }
        let limit = self
            .proposal_replay_limit
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::ProposalAuthoringNotActivated)?;
        if self.prepared_proposal_count >= limit.max_prepared_proposals() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ProposalPrepareLimitExceeded {
                    maximum: limit.max_prepared_proposals(),
                },
            );
        }
        let lineage = self
            .lineage
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)?;
        if position.height() != lineage.height {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ProposalOutsideSigningLineage {
                    entry: self.record_sequence,
                    lineage_height: lineage.height,
                    proposal_height: position.height(),
                },
            );
        }
        if let Some(latest) = self.latest_proposal_position
            && position <= latest
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::NonMonotonicProposal {
                    previous: latest,
                    actual: position,
                },
            );
        }
        if let Some(latest_vote) = self.latest_slot
            && position <= latest_vote.position
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::ProposalAfterVote {
                proposal: position,
                vote: latest_vote.position,
                vote_role: latest_vote.role,
            });
        }
        let (current_position, current_phase) =
            self.current_lineage_state_coordinate(lineage.height);
        if state_coordinate_cmp(
            position,
            FixedValidatorLockPhaseV0::Proposal,
            current_position,
            current_phase,
        )
        .is_lt()
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ProposalStateBehindCurrent {
                    proposal: position,
                    current_position,
                    current_phase,
                },
            );
        }
        self.proposals.try_reserve(1).map_err(|_| {
            FixedValidatorVoteSafetyJournalErrorV0::ProposalHistoryAllocation {
                entry: self.record_sequence,
                retained_proposals: self.proposals.len(),
            }
        })?;
        let body = tagged_record(
            PROPOSAL_PREPARE_RECORD,
            canonical_intent,
            self.record_sequence,
        )?;
        let next_state_id = self.append_record(&body, self.record_sequence)?;
        self.proposals.insert(
            position,
            RetainedProposal {
                observed_intent: observed,
                prepared_state_id: next_state_id,
                signed: None,
            },
        );
        self.pending_proposal = Some(position);
        self.live_pending_proposal_intent = Some(intent);
        self.latest_proposal_position = Some(position);
        self.prepared_proposal_count += 1;
        self.state_id = next_state_id;
        Ok(FixedValidatorProposalPrepareOutcomeV0::Prepared(
            self.pending_proposal_capability()
                .expect("new proposal preparation is live"),
        ))
    }

    pub(super) fn sign_prepared_proposal(
        &mut self,
        signing_key: &SigningKey,
        prepared: FixedValidatorPreparedProposalV0,
    ) -> Result<FixedValidatorSignedProposalV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.validate_live_prepared_proposal(prepared)?;
        let intent = self.live_pending_proposal_intent.as_ref().ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::RestartedPendingProposal {
                position: prepared.position,
            },
        )?;
        let dalek_signature = signing_key.sign(&intent.signing_transcript());
        let signature = ConsensusSignature::from_bytes(dalek_signature.to_bytes());
        let completed = intent
            .complete_with_signature(signature)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::ProposalSelfVerification)?;
        let control = completed.canonical_proposal_control_bytes();
        let authorization_start = naome_consensus::ConsensusValueV0::BYTE_LENGTH;
        let authorization_end =
            authorization_start + naome_consensus::VerifiedProducerAuthorizationV0::BYTE_LENGTH;
        let body = tagged_record(
            PROPOSAL_COMPLETE_RECORD,
            &control[authorization_start..authorization_end],
            self.record_sequence,
        )?;
        let next_state_id = self.append_record(&body, self.record_sequence)?;
        let signed = signed_proposal_from_completed(completed, next_state_id);
        self.proposals
            .get_mut(&prepared.position)
            .expect("prepared proposal remains retained through completion")
            .signed = Some(signed.clone());
        self.pending_proposal = None;
        self.live_pending_proposal_intent = None;
        self.latest_current_lineage_state = Some(RetainedCurrentLineageStateV0::Proposal {
            position: prepared.position,
            state_id: next_state_id,
        });
        self.state_id = next_state_id;
        Ok(signed)
    }

    pub(super) fn validate_live_prepared_proposal(
        &self,
        prepared: FixedValidatorPreparedProposalV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_operational()?;
        let retained = self
            .proposals
            .get(&prepared.position)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::UnknownPreparedProposal)?;
        if retained.prepared_state_id != prepared.prepared_state_id
            || retained.observed_intent.proposal_signing_root() != prepared.proposal_signing_root
            || retained.signed.is_some()
            || self.pending_proposal != Some(prepared.position)
            || self.state_id != prepared.prepared_state_id
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedProposal);
        }
        let intent = self.live_pending_proposal_intent.as_ref().ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::RestartedPendingProposal {
                position: prepared.position,
            },
        )?;
        if intent.canonical_intent_bytes() != retained.observed_intent.canonical_intent_bytes() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedProposal);
        }
        Ok(())
    }

    pub(super) fn prepare_vote(
        &mut self,
        intent: FixedValidatorVoteIntentV0,
    ) -> Result<FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_operational()?;
        if let Some(position) = self.pending_proposal {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation { position },
            );
        }
        if intent.context() != self.context
            || intent.fixed_agreement_set_id() != self.fixed_set_id
            || intent.signer() != self.signer
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::IntentHeaderMismatch);
        }
        let canonical_intent = intent.canonical_state_and_vote_intent_bytes();
        let observed = self.decode_observed_intent(canonical_intent, self.prepared_count, 0)?;
        let slot = observed_intent_slot(&observed);
        if let Some(lineage) = self.lineage
            && slot.position.height() != lineage.height
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::VoteOutsideSigningLineage {
                    entry: self.prepared_count,
                    lineage_height: lineage.height,
                    vote_height: slot.position.height(),
                },
            );
        }
        self.require_vote_after_higher_round_checkpoint(
            self.prepared_count,
            observed.position(),
            observed.phase(),
        )?;
        let target = observed.target();
        if let Some(pending) = self.pending
            && pending != slot
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            });
        }
        if let Some(retained) = self.votes.get(&slot) {
            if retained
                .observed_intent
                .canonical_state_and_vote_intent_bytes()
                == canonical_intent
            {
                if let Some(signed) = &retained.signed {
                    return Ok(FixedValidatorVotePrepareOutcomeV0::AlreadySigned(
                        signed.clone(),
                    ));
                }
                return Ok(FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(
                    prepared_capability(slot, retained),
                ));
            }
            let retained_target = retained.observed_intent.target();
            let body = tagged_record(CONFLICT_HALT_RECORD, canonical_intent, self.prepared_count)?;
            let next_state_id = self.append_record(&body, self.prepared_count)?;
            let halt = FixedValidatorVoteSafetyHaltV0 {
                position: slot.position,
                role: slot.role,
                retained_target,
                conflicting_target: target,
                state_id: next_state_id,
            };
            self.halt = Some(halt);
            self.pending = None;
            self.live_pending_intent = None;
            self.state_id = next_state_id;
            return Ok(FixedValidatorVotePrepareOutcomeV0::Halted(halt));
        }
        if let Some(pending) = self.pending {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
                position: pending.position,
                role: pending.role,
            });
        }
        if self.prepared_count >= self.replay_limit.max_prepared_votes() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::PrepareLimitExceeded {
                    maximum: self.replay_limit.max_prepared_votes(),
                },
            );
        }
        if let Some(latest) = self.latest_slot
            && slot <= latest
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::NonMonotonicSlot {
                previous: latest.position,
                previous_role: latest.role,
                actual: slot.position,
                actual_role: slot.role,
            });
        }
        if let Some(proposal) = self.latest_proposal_position
            && slot.position < proposal
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::VoteBeforeProposal {
                vote: slot.position,
                vote_role: slot.role,
                proposal,
            });
        }
        let entry = self.prepared_count;
        self.votes.try_reserve(1).map_err(|_| {
            FixedValidatorVoteSafetyJournalErrorV0::HistoryAllocation {
                entry,
                retained_votes: self.votes.len(),
            }
        })?;
        let body = tagged_record(PREPARE_RECORD, canonical_intent, entry)?;
        let next_state_id = self.append_record(&body, entry)?;
        self.votes.insert(
            slot,
            RetainedVote {
                observed_intent: observed,
                prepared_state_id: next_state_id,
                signed: None,
            },
        );
        self.pending = Some(slot);
        self.live_pending_intent = Some(intent);
        self.latest_slot = Some(slot);
        self.prepared_count += 1;
        self.state_id = next_state_id;
        Ok(FixedValidatorVotePrepareOutcomeV0::Prepared(
            self.pending_capability()
                .expect("new preparation is the sole pending vote"),
        ))
    }

    pub(super) fn sign_prepared_vote(
        &mut self,
        signing_key: &SigningKey,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<FixedValidatorVoteSignOutcomeV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_operational()?;
        let retained = self
            .votes
            .get(&prepared.slot)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::UnknownPreparedVote)?;
        if retained.prepared_state_id != prepared.prepared_state_id
            || retained.observed_intent.target() != prepared.target
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        if let Some(signed) = &retained.signed {
            return Ok(FixedValidatorVoteSignOutcomeV0::AlreadySigned(
                signed.clone(),
            ));
        }
        if self.pending != Some(prepared.slot) || self.state_id != prepared.prepared_state_id {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        let intent = self.live_pending_intent.as_ref().ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::RestartedPending {
                position: prepared.slot.position,
                role: prepared.slot.role,
            },
        )?;
        if intent.canonical_state_and_vote_intent_bytes()
            != retained
                .observed_intent
                .canonical_state_and_vote_intent_bytes()
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        let dalek_signature = signing_key.sign(intent.signing_transcript());
        let signature = ConsensusSignature::from_bytes(dalek_signature.to_bytes());
        let verified = intent
            .complete_with_signature(signature)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::SelfVerification)?;
        require_verified_vote(&verified, self.signer, prepared.slot, prepared.target)
            .map_err(FixedValidatorVoteSafetyJournalErrorV0::SelfVerificationMismatch)?;
        let canonical_bytes = verified.to_canonical_bytes().to_vec();
        let body = tagged_record(COMPLETE_RECORD, &canonical_bytes, self.prepared_count)?;
        let next_state_id = self.append_record(&body, self.prepared_count)?;
        let signed = signed_vote_from_verified(&verified, canonical_bytes, next_state_id);
        self.votes
            .get_mut(&prepared.slot)
            .expect("prepared vote remains retained through completion")
            .signed = Some(signed.clone());
        self.pending = None;
        self.live_pending_intent = None;
        self.latest_current_lineage_state =
            Some(RetainedCurrentLineageStateV0::Vote(prepared.slot));
        self.state_id = next_state_id;
        Ok(FixedValidatorVoteSignOutcomeV0::Signed(signed))
    }

    pub(super) fn validate_live_prepared_vote(
        &self,
        prepared: FixedValidatorPreparedVoteV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_operational()?;
        let retained = self
            .votes
            .get(&prepared.slot)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::UnknownPreparedVote)?;
        if retained.prepared_state_id != prepared.prepared_state_id
            || retained.observed_intent.target() != prepared.target
            || retained.signed.is_some()
            || self.pending != Some(prepared.slot)
            || self.state_id != prepared.prepared_state_id
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        let intent = self.live_pending_intent.as_ref().ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::RestartedPending {
                position: prepared.slot.position,
                role: prepared.slot.role,
            },
        )?;
        if intent.canonical_state_and_vote_intent_bytes()
            != retained
                .observed_intent
                .canonical_state_and_vote_intent_bytes()
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::StalePreparedVote);
        }
        Ok(())
    }
}
