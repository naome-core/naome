//! Strict record replay and retained evidence reconstruction.

use super::*;

impl<F: StoreIo> FixedValidatorVoteSafetyJournalCore<F> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn replay(
        mut file: F,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signer: ConsensusKey,
        replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
        expected_prefix: Vec<u8>,
        expected_state_id: FixedValidatorVoteSafetyJournalStateIdV0,
        expected_anchor_sequence: Option<u64>,
    ) -> Result<Self, FixedValidatorVoteSafetyJournalErrorV0> {
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Read { offset: 0, source })?;
        if file_len < JOURNAL_PREFIX_BYTES as u64 {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidHeader);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Read { offset: 0, source })?;
        let mut actual_prefix = allocate_bytes(JOURNAL_PREFIX_BYTES, 0)?;
        read_exact_at(&mut file, &mut actual_prefix, 0)?;
        if actual_prefix != expected_prefix {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::HeaderMismatch);
        }

        let state_id = genesis_state_id(&actual_prefix);
        let mut core = Self::empty(file, context, fixed_set_id, signer, replay_limit, state_id);
        let mut entry_start = JOURNAL_PREFIX_BYTES as u64;
        let mut entry = 0_u64;
        let mut recovery_offset = None;
        while entry_start < file_len {
            if file_len - entry_start < RECORD_LENGTH_BYTES {
                recovery_offset = Some(entry_start);
                break;
            }
            core.file
                .seek(SeekFrom::Start(entry_start))
                .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Read {
                    offset: entry_start,
                    source,
                })?;
            let mut body_length_bytes = [0_u8; 4];
            read_exact_at(&mut core.file, &mut body_length_bytes, entry_start)?;
            let body_length_u32 = u32::from_be_bytes(body_length_bytes);
            let body_length = usize::try_from(body_length_u32)
                .expect("every u32 record length fits supported Rust targets");
            if !(MIN_RECORD_BODY_BYTES..=MAX_RECORD_BODY_BYTES).contains(&body_length)
                && body_length != SIGNED_VOTE_BODY_BYTES
                && body_length != SIGNING_LINEAGE_BODY_BYTES
                && body_length != FINALITY_CONFLICT_STOP_BODY_BYTES
                && body_length != PROPOSAL_ACTIVATION_BODY_BYTES
                && !(MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES
                    ..=MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES)
                    .contains(&body_length)
                && !(MIN_PROPOSAL_INTENT_BODY_BYTES..=MAX_PROPOSAL_INTENT_BODY_BYTES)
                    .contains(&body_length)
                && body_length != COMPLETED_PROPOSAL_BODY_BYTES
            {
                return Err(
                    FixedValidatorVoteSafetyJournalErrorV0::InvalidRecordLength {
                        entry,
                        offset: entry_start,
                        actual: body_length_u32,
                        minimum: u32::try_from(MIN_RECORD_BODY_BYTES)
                            .expect("minimum vote-safety record length fits u32"),
                        maximum: u32::try_from(MAX_BOUNDED_RECORD_BODY_BYTES)
                            .expect("maximum vote-safety record length fits u32"),
                    },
                );
            }
            let entry_length = ENTRY_FIXED_BYTES
                .checked_add(u64::from(body_length_u32))
                .ok_or(
                    FixedValidatorVoteSafetyJournalErrorV0::EntryOffsetOverflow {
                        entry,
                        offset: entry_start,
                    },
                )?;
            let entry_end = entry_start.checked_add(entry_length).ok_or(
                FixedValidatorVoteSafetyJournalErrorV0::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                },
            )?;
            if file_len < entry_end {
                recovery_offset = Some(entry_start);
                break;
            }
            if core.halt.is_some()
                || core.proposal_halt.is_some()
                || core.finality_conflict_stop.is_some()
            {
                return Err(FixedValidatorVoteSafetyJournalErrorV0::RecordAfterHalt {
                    offset: entry_start,
                });
            }
            let mut body = allocate_bytes(body_length, entry)?;
            let body_offset = entry_start + RECORD_LENGTH_BYTES;
            read_exact_at(&mut core.file, &mut body, body_offset)?;
            let footer_offset = body_offset + u64::from(body_length_u32);
            let mut stored_state_id = [0_u8; FixedValidatorVoteSafetyJournalStateIdV0::BYTE_LENGTH];
            read_exact_at(&mut core.file, &mut stored_state_id, footer_offset)?;
            let expected_entry_state_id = step_state_id(core.state_id, body_length_bytes, &body);
            let actual_entry_state_id =
                FixedValidatorVoteSafetyJournalStateIdV0::from_bytes(stored_state_id);
            if actual_entry_state_id != expected_entry_state_id {
                return Err(
                    FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch {
                        entry,
                        offset: entry_start,
                        expected: expected_entry_state_id,
                        actual: actual_entry_state_id,
                    },
                );
            }
            core.replay_record(entry, entry_start, body, actual_entry_state_id)?;
            core.state_id = actual_entry_state_id;
            core.record_sequence = core
                .record_sequence
                .checked_add(1)
                .ok_or(FixedValidatorVoteSafetyJournalErrorV0::RecordSequenceExhausted)?;
            core.committed_end = entry_end;
            entry_start = entry_end;
            entry += 1;
        }

        if let Some(expected_sequence) = expected_anchor_sequence
            && (core.record_sequence != expected_sequence || core.state_id != expected_state_id)
        {
            return Err(match core.record_sequence.cmp(&expected_sequence) {
                std::cmp::Ordering::Greater => {
                    FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind {
                        anchored_sequence: expected_sequence,
                        journal_sequence: core.record_sequence,
                    }
                }
                std::cmp::Ordering::Less => FixedValidatorVoteSafetyJournalErrorV0::AnchorAhead {
                    anchored_sequence: expected_sequence,
                    journal_sequence: core.record_sequence,
                },
                std::cmp::Ordering::Equal => {
                    FixedValidatorVoteSafetyJournalErrorV0::AnchorStateMismatch {
                        sequence: expected_sequence,
                    }
                }
            });
        }
        if core.state_id != expected_state_id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                    expected: expected_state_id,
                    actual: core.state_id,
                },
            );
        }
        if let Some(offset) = recovery_offset {
            core.file
                .set_len(offset)
                .and_then(|()| core.file.sync_all())
                .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Recovery {
                    offset,
                    source,
                })?;
        } else {
            core.file
                .sync_all()
                .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Stabilize { source })?;
        }
        Ok(core)
    }

    pub(super) fn replay_record(
        &mut self,
        entry: u64,
        offset: u64,
        body: Vec<u8>,
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        let (&tag, payload) = body.split_first().ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::InvalidRecordLength {
                entry,
                offset,
                actual: 0,
                minimum: 1,
                maximum: u32::try_from(MAX_BOUNDED_RECORD_BODY_BYTES)
                    .expect("maximum record length fits u32"),
            },
        )?;
        match tag {
            PREPARE_RECORD => self.replay_prepare(entry, offset, payload, state_id),
            COMPLETE_RECORD => self.replay_completion(entry, offset, payload, state_id),
            CONFLICT_HALT_RECORD => self.replay_halt(entry, offset, payload, state_id),
            SIGNING_LINEAGE_RECORD => self.replay_signing_lineage(entry, payload, state_id),
            FINALITY_CONFLICT_STOP_RECORD => self.replay_finality_conflict_stop(
                entry,
                payload,
                state_id,
                FixedValidatorFinalityHaltKindV0::SelectedSibling,
            ),
            PRESELECTION_CONFLICT_STOP_RECORD => self.replay_finality_conflict_stop(
                entry,
                payload,
                state_id,
                FixedValidatorFinalityHaltKindV0::PreselectionPair,
            ),
            HIGHER_ROUND_CHECKPOINT_RECORD => {
                self.replay_higher_round_checkpoint(entry, offset, payload, state_id)
            }
            PROPOSAL_ACTIVATION_RECORD => self.replay_proposal_activation(entry, payload),
            PROPOSAL_PREPARE_RECORD => {
                self.replay_proposal_prepare(entry, offset, payload, state_id)
            }
            PROPOSAL_COMPLETE_RECORD => self.replay_proposal_completion(entry, payload, state_id),
            PROPOSAL_CONFLICT_HALT_RECORD => {
                self.replay_proposal_halt(entry, offset, payload, state_id)
            }
            actual => Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidRecordTag {
                entry,
                offset,
                actual,
            }),
        }
    }

    pub(super) fn replay_signing_lineage(
        &mut self,
        entry: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if payload.len() != SIGNING_LINEAGE_PAYLOAD_BYTES {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidSigningLineageLength {
                    entry,
                    actual: payload.len(),
                },
            );
        }
        if self.pending.is_some() || self.pending_proposal.is_some() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SigningLineageWhilePending { entry },
            );
        }
        let had_lineage = self.lineage.is_some();
        let height = ConsensusHeight::new(u64::from_be_bytes(
            payload[..8]
                .try_into()
                .expect("the signing-lineage height has exact width"),
        ));
        if height.value() == 0 {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidSigningLineageHeight {
                    entry,
                    actual: height,
                },
            );
        }
        let id = SigningLineageIdV0(
            payload[8..]
                .try_into()
                .expect("the signing-lineage identity has exact width"),
        );
        match self.lineage {
            Some(previous) => {
                let expected = previous
                    .height
                    .value()
                    .checked_add(1)
                    .map(ConsensusHeight::new)
                    .ok_or(
                        FixedValidatorVoteSafetyJournalErrorV0::SigningLineageHeightExhausted {
                            entry,
                            previous: previous.height,
                        },
                    )?;
                if height != expected {
                    return Err(
                        FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
                            entry,
                            expected,
                            actual: height,
                        },
                    );
                }
            }
            None => {
                if let Some(latest) = self.latest_slot
                    && height != latest.position.height()
                {
                    return Err(
                        FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
                            entry,
                            expected: latest.position.height(),
                            actual: height,
                        },
                    );
                }
            }
        }
        self.lineage = Some(RetainedSigningLineageV0 {
            height,
            id,
            state_id,
        });
        self.latest_current_lineage_state = if had_lineage {
            None
        } else {
            self.latest_slot
                .filter(|slot| slot.position.height() == height)
                .map(RetainedCurrentLineageStateV0::Vote)
        };
        Ok(())
    }

    pub(super) fn replay_prepare(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if self.pending.is_some() || self.pending_proposal.is_some() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PrepareWhilePending { entry });
        }
        if self.prepared_count >= self.replay_limit.max_prepared_votes() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ReplayLimitExceeded {
                    entry,
                    maximum: self.replay_limit.max_prepared_votes(),
                },
            );
        }
        let intent = self.decode_observed_intent(payload, entry, offset)?;
        let slot = observed_intent_slot(&intent);
        if let Some(lineage) = self.lineage
            && slot.position.height() != lineage.height
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::VoteOutsideSigningLineage {
                    entry,
                    lineage_height: lineage.height,
                    vote_height: slot.position.height(),
                },
            );
        }
        self.require_vote_after_higher_round_checkpoint(entry, intent.position(), intent.phase())?;
        if self.votes.contains_key(&slot) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::DuplicatePrepare { entry });
        }
        if let Some(latest) = self.latest_slot
            && slot <= latest
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::NonMonotonicReplay {
                entry,
                previous: latest.position,
                previous_role: latest.role,
                actual: slot.position,
                actual_role: slot.role,
            });
        }
        if let Some(latest_proposal) = self.latest_proposal_position
            && slot.position < latest_proposal
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::VoteBeforeProposal {
                vote: slot.position,
                vote_role: slot.role,
                proposal: latest_proposal,
            });
        }
        self.votes.try_reserve(1).map_err(|_| {
            FixedValidatorVoteSafetyJournalErrorV0::HistoryAllocation {
                entry,
                retained_votes: self.votes.len(),
            }
        })?;
        self.votes.insert(
            slot,
            RetainedVote {
                observed_intent: intent,
                prepared_state_id: state_id,
                signed: None,
            },
        );
        self.pending = Some(slot);
        self.latest_slot = Some(slot);
        self.prepared_count += 1;
        Ok(())
    }

    pub(super) fn replay_completion(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if payload.len() != VerifiedConsensusVoteV0::BYTE_LENGTH {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidCompletionLength {
                    entry,
                    actual: payload.len(),
                },
            );
        }
        let slot = self
            .pending
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::CompletionWithoutPrepare { entry })?;
        let verified = VerifiedConsensusVoteV0::decode_and_verify(payload, self.context).map_err(
            |source| FixedValidatorVoteSafetyJournalErrorV0::SignedVote {
                entry,
                offset,
                source,
            },
        )?;
        let retained = self
            .votes
            .get_mut(&slot)
            .expect("every pending slot has one retained preparation");
        require_verified_vote(
            &verified,
            self.signer,
            slot,
            retained.observed_intent.target(),
        )
        .map_err(
            |reason| FixedValidatorVoteSafetyJournalErrorV0::CompletionMismatch { entry, reason },
        )?;
        let canonical_bytes = clone_bytes(payload, entry)?;
        retained.signed = Some(signed_vote_from_verified(
            &verified,
            canonical_bytes,
            state_id,
        ));
        self.pending = None;
        self.latest_current_lineage_state = Some(RetainedCurrentLineageStateV0::Vote(slot));
        Ok(())
    }

    pub(super) fn replay_proposal_activation(
        &mut self,
        entry: u64,
        payload: &[u8],
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if payload.len() != PROPOSAL_ACTIVATION_PAYLOAD_BYTES {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalActivationLength {
                    entry,
                    actual: payload.len(),
                },
            );
        }
        if self.proposal_replay_limit.is_some() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::DuplicateProposalActivation { entry },
            );
        }
        if self.pending.is_some() || self.pending_proposal.is_some() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ProposalActivationWhilePending { entry },
            );
        }
        let maximum = u64::from_be_bytes(
            payload
                .try_into()
                .expect("the proposal-activation payload is eight bytes"),
        );
        self.proposal_replay_limit = Some(
            FixedValidatorProposalReplayLimitV0::new(maximum).map_err(|_| {
                FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalActivation { entry }
            })?,
        );
        Ok(())
    }

    pub(super) fn replay_proposal_prepare(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if self.pending.is_some() || self.pending_proposal.is_some() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::PrepareWhilePending { entry });
        }
        let limit = self
            .proposal_replay_limit
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::ProposalAuthoringNotActivated)?;
        if self.prepared_proposal_count >= limit.max_prepared_proposals() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ProposalReplayLimitExceeded {
                    entry,
                    maximum: limit.max_prepared_proposals(),
                },
            );
        }
        let intent = self.decode_observed_proposal_intent(payload, entry, offset)?;
        let position = intent.position();
        let lineage = self.lineage.ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::ProposalWithoutSigningLineage { entry },
        )?;
        if position.height() != lineage.height {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::ProposalOutsideSigningLineage {
                    entry,
                    lineage_height: lineage.height,
                    proposal_height: position.height(),
                },
            );
        }
        if self.proposals.contains_key(&position) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::DuplicateProposalPrepare { entry });
        }
        if let Some(latest) = self.latest_proposal_position
            && position <= latest
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::NonMonotonicProposalReplay {
                    entry,
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
                entry,
                retained_proposals: self.proposals.len(),
            }
        })?;
        self.proposals.insert(
            position,
            RetainedProposal {
                observed_intent: intent,
                prepared_state_id: state_id,
                signed: None,
            },
        );
        self.pending_proposal = Some(position);
        self.latest_proposal_position = Some(position);
        self.prepared_proposal_count += 1;
        Ok(())
    }

    pub(super) fn replay_proposal_completion(
        &mut self,
        entry: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        let position = self.pending_proposal.ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::ProposalCompletionWithoutPrepare { entry },
        )?;
        let retained = self
            .proposals
            .get_mut(&position)
            .expect("every pending proposal has one retained intent");
        let completed = retained
            .observed_intent
            .verify_completed_producer_authorization(payload)
            .map_err(
                |source| FixedValidatorVoteSafetyJournalErrorV0::CompletedProposal {
                    entry,
                    source,
                },
            )?;
        retained.signed = Some(signed_proposal_from_completed(completed, state_id));
        self.pending_proposal = None;
        self.latest_current_lineage_state =
            Some(RetainedCurrentLineageStateV0::Proposal { position, state_id });
        Ok(())
    }

    pub(super) fn replay_proposal_halt(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if self.pending.is_some() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalConflictHalt { entry },
            );
        }
        let intent = self.decode_observed_proposal_intent(payload, entry, offset)?;
        let position = intent.position();
        if self
            .pending_proposal
            .is_some_and(|pending| pending != position)
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalConflictHalt { entry },
            );
        }
        let retained = self
            .proposals
            .get(&position)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalConflictHalt { entry })?;
        if retained.observed_intent.canonical_intent_bytes() == payload {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalConflictHalt { entry },
            );
        }
        self.proposal_halt = Some(proposal_halt(
            position,
            &retained.observed_intent,
            &intent,
            state_id,
        ));
        self.pending_proposal = None;
        self.live_pending_proposal_intent = None;
        Ok(())
    }

    pub(super) fn replay_higher_round_checkpoint(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        let checkpoint = self.validate_higher_round_checkpoint(entry, offset, payload)?;
        self.latest_current_lineage_state = Some(RetainedCurrentLineageStateV0::HigherRound {
            checkpoint: Box::new(checkpoint),
            state_id,
        });
        Ok(())
    }

    pub(super) fn validate_higher_round_checkpoint(
        &self,
        entry: u64,
        offset: u64,
        payload: &[u8],
    ) -> Result<ObservedFixedValidatorHigherRoundCheckpointV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        if self.pending.is_some() || self.pending_proposal.is_some() {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointWhilePending { entry },
            );
        }
        let lineage = self.lineage.ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointWithoutLineage { entry },
        )?;
        let checkpoint = ObservedFixedValidatorHigherRoundCheckpointV0::decode_and_verify(
            payload,
            self.context,
            self.fixed_set_id,
        )
        .map_err(|source| {
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpoint {
                entry,
                offset,
                source,
            }
        })?;
        if checkpoint.position().height() != lineage.height {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointOutsideLineage {
                    entry,
                    lineage_height: lineage.height,
                    checkpoint_height: checkpoint.position().height(),
                },
            );
        }
        let (current_position, current_phase) =
            self.current_lineage_state_coordinate(lineage.height);
        if state_coordinate_cmp(
            checkpoint.source_position(),
            checkpoint.source_phase(),
            current_position,
            current_phase,
        )
        .is_lt()
        {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointSourceBehindState {
                    entry,
                    current_position,
                    current_phase,
                    source_position: checkpoint.source_position(),
                    source_phase: checkpoint.source_phase(),
                },
            );
        }
        Ok(checkpoint)
    }

    pub(super) fn replay_halt(
        &mut self,
        entry: u64,
        offset: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if self.pending_proposal.is_some() {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt { entry });
        }
        let intent = self.decode_observed_intent(payload, entry, offset)?;
        let slot = observed_intent_slot(&intent);
        if self.pending.is_some_and(|pending| pending != slot) {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt { entry });
        }
        let retained = self
            .votes
            .get(&slot)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt { entry })?;
        if retained
            .observed_intent
            .canonical_state_and_vote_intent_bytes()
            == payload
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt { entry });
        }
        self.halt = Some(FixedValidatorVoteSafetyHaltV0 {
            position: slot.position,
            role: slot.role,
            retained_target: retained.observed_intent.target(),
            conflicting_target: intent.target(),
            state_id,
        });
        self.pending = None;
        Ok(())
    }

    pub(super) fn replay_finality_conflict_stop(
        &mut self,
        entry: u64,
        payload: &[u8],
        state_id: FixedValidatorVoteSafetyJournalStateIdV0,
        kind: FixedValidatorFinalityHaltKindV0,
    ) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
        if payload.len() != FINALITY_CONFLICT_STOP_PAYLOAD_BYTES {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidFinalityConflictSignerStopLength {
                    entry,
                    actual: payload.len(),
                },
            );
        }
        let finality_state_id = FixedValidatorFinalityJournalStateIdV0::from_bytes(
            payload[..32]
                .try_into()
                .expect("the finality state identity has exact width"),
        );
        let height = ConsensusHeight::new(u64::from_be_bytes(
            payload[32..40]
                .try_into()
                .expect("the finality-conflict height has exact width"),
        ));
        if height.value() == 0 {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::InvalidFinalityConflictSignerStop { entry },
            );
        }
        let first_ancestry = ConsensusAncestryId::from_bytes(
            payload[40..72]
                .try_into()
                .expect("the selected ancestry has exact width"),
        );
        let first_envelope_id = ConsensusEnvelopeId::from_bytes(
            payload[72..104]
                .try_into()
                .expect("the selected envelope identity has exact width"),
        );
        let second_ancestry = ConsensusAncestryId::from_bytes(
            payload[104..136]
                .try_into()
                .expect("the conflicting ancestry has exact width"),
        );
        let second_envelope_id = ConsensusEnvelopeId::from_bytes(
            payload[136..168]
                .try_into()
                .expect("the conflicting envelope identity has exact width"),
        );
        self.finality_conflict_stop = Some(FixedValidatorFinalityConflictSignerStopV0 {
            kind,
            finality_state_id,
            height,
            first_ancestry,
            first_envelope_id,
            second_ancestry,
            second_envelope_id,
            vote_state_id: state_id,
        });
        self.pending = None;
        self.pending_proposal = None;
        Ok(())
    }
}
