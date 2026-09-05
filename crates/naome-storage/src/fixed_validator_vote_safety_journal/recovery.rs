//! Exact selected-history and signing-lineage recovery.

use super::*;

impl<F: StoreIo> FixedValidatorVoteSafetyJournalCore<F> {
    pub(super) fn recover_lock_state_for_round(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteSafetyJournalErrorV0> {
        self.ensure_recoverable()?;
        let lineage = self
            .lineage
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)?;
        let lock_state = self.restore_lock_state_for_round(round)?;
        let height = lock_state.position().height();
        let id = signing_lineage_id(round.parent_coordinate(), height, self.signer);
        if lineage.height != height || lineage.id != id {
            return Err(
                FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
                    expected_height: lineage.height,
                    actual_height: height,
                },
            );
        }
        Ok(lock_state)
    }

    pub(super) fn signer_recovery_position(
        &self,
        lineage: RetainedSigningLineageV0,
    ) -> ConsensusPosition {
        self.latest_current_lineage_state
            .as_ref()
            .filter(|state| state.position().height() == lineage.height)
            .map_or(
                ConsensusPosition::new(lineage.height, ConsensusRound::new(0)),
                RetainedCurrentLineageStateV0::position,
            )
    }

    pub(super) fn restore_lock_state_for_round(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteSafetyJournalErrorV0> {
        if round.context() != self.context
            || round.parent_coordinate().fixed_agreement_set_id() != self.fixed_set_id
        {
            return Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionRoundMismatch);
        }
        match self.latest_current_lineage_state.as_ref() {
            None => FixedValidatorLockStateV0::try_from_round_zero(round)
                .map_err(FixedValidatorVoteSafetyJournalErrorV0::LockState),
            Some(RetainedCurrentLineageStateV0::Vote(latest)) => {
                let retained = self
                    .votes
                    .get(latest)
                    .expect("the latest completed vote remains retained");
                retained
                    .signed
                    .as_ref()
                    .expect("a recoverable latest vote is durably completed");
                VerifiedReplayFixedValidatorVoteIntentV0::decode_and_verify_for_round(
                    retained
                        .observed_intent
                        .canonical_state_and_vote_intent_bytes(),
                    round,
                    self.signer,
                )
                .map_err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionIntent)
                .map(VerifiedReplayFixedValidatorVoteIntentV0::into_lock_state)
            }
            Some(RetainedCurrentLineageStateV0::HigherRound { checkpoint, .. }) => checkpoint
                .as_ref()
                .clone()
                .verify_for_round(round)
                .map_err(FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointReplay)
                .map(VerifiedReplayFixedValidatorHigherRoundCheckpointV0::into_lock_state),
            Some(RetainedCurrentLineageStateV0::Proposal { position, state_id }) => {
                let retained = self
                    .proposals
                    .get(position)
                    .expect("the latest completed proposal remains retained");
                let signed = retained
                    .signed
                    .as_ref()
                    .expect("a recoverable latest proposal is durably completed");
                debug_assert_eq!(signed.state_id(), *state_id);
                retained
                    .observed_intent
                    .restore_lock_state_for_round(round)
                    .map_err(FixedValidatorVoteSafetyJournalErrorV0::ProposalRecovery)
            }
        }
    }

    pub(super) fn current_lineage_state_coordinate(
        &self,
        height: ConsensusHeight,
    ) -> (ConsensusPosition, FixedValidatorLockPhaseV0) {
        self.latest_current_lineage_state
            .as_ref()
            .filter(|state| state.position().height() == height)
            .map_or(
                (
                    ConsensusPosition::new(height, ConsensusRound::new(0)),
                    FixedValidatorLockPhaseV0::Proposal,
                ),
                |state| (state.position(), state.phase()),
            )
    }
}
