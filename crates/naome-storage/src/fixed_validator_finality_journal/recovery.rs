//! Exact selected-history and signing-lineage recovery.

use super::*;

impl<F: StoreIo> FixedValidatorFinalityJournalCore<F> {
    pub(super) fn reconstruct_selected_transition(
        &self,
        height: ConsensusHeight,
    ) -> Result<OwnedVerifiedFixedConsensusTransitionV0, FixedValidatorFinalityJournalErrorV0> {
        self.ensure_operational()?;
        let height_index = height_index(height).map_err(|()| {
            FixedValidatorFinalityJournalErrorV0::SignerHandoffHeightIndexOverflow { height }
        })?;
        let Some(record_index) = height_index.checked_sub(1) else {
            return Err(FixedValidatorFinalityJournalErrorV0::SignerHandoffUnavailable { height });
        };
        let Some(record) = self.records.get(record_index) else {
            return Err(FixedValidatorFinalityJournalErrorV0::SignerHandoffUnavailable { height });
        };
        let parent = self
            .branches
            .get(record_index)
            .expect("each retained finality record has its selected parent");
        let mut round = parent
            .begin_round_zero()
            .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
        for _ in 0..record.position.round().value() {
            round = round
                .advance_round()
                .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
        }
        debug_assert_eq!(record.position, round.position());
        let entry = u64::try_from(record_index).expect("retained record index fits u64");
        let payload = clone_bytes(record.canonical_artifact_bytes(), entry)?;
        round
            .decode_and_verify(record.canonical_envelope_bytes(), payload)
            .map_err(
                |source| FixedValidatorFinalityJournalErrorV0::SignerHandoffReplay {
                    height,
                    source: Box::new(source),
                },
            )
            .map(VerifiedFixedConsensusTransitionV0::into_owned)
    }

    pub(super) fn recover_anchored_signer_branch(
        &self,
        recovery: &FixedValidatorAnchoredSignerRecoveryV0<'_>,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorFinalityJournalErrorV0> {
        self.ensure_healthy()?;
        let height = recovery.lineage.height;
        let height_index = height_index(height).map_err(|()| {
            FixedValidatorFinalityJournalErrorV0::SignerRecoveryHeightIndexOverflow { height }
        })?;
        let Some(branch_index) = height_index.checked_sub(1) else {
            return Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryUnavailable { height });
        };
        let Some(branch) = self.branches.get(branch_index) else {
            return Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryUnavailable { height });
        };
        let actual = signing_lineage_id(branch.coordinate(), height, recovery.signer);
        if actual != recovery.lineage.id {
            return Err(
                FixedValidatorFinalityJournalErrorV0::SignerRecoveryLineageMismatch { height },
            );
        }
        Ok(branch.clone())
    }
}
