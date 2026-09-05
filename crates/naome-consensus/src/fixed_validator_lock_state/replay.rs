//! Typed reconstruction against the exact current branch and round.

use super::*;

pub(super) fn restore_higher_round_checkpoint_for_round(
    observed: &ObservedFixedValidatorHigherRoundCheckpointV0,
    round: &FixedConsensusRoundV0<'_>,
) -> Result<FixedValidatorLockStateV0, FixedValidatorHigherRoundCheckpointErrorV0> {
    let lock_state = restore_snapshot_for_round(&observed.target_snapshot, round)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    let certificate = round
        .decode_and_verify_quorum_certificate(&observed.canonical_certificate)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::Certificate)?;
    if certificate.position() != observed.target_snapshot.position
        || certificate.role() != observed.role
        || certificate.target() != observed.target
        || certificate.id() != observed.certificate_id
    {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::CertificateStateMismatch);
    }
    Ok(lock_state)
}

pub(super) fn restore_lock_state_for_round(
    observed: &ObservedFixedValidatorVoteIntentV0,
    round: &FixedConsensusRoundV0<'_>,
) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteIntentError> {
    if !round.verifies_consensus_signer(observed.signer) {
        return Err(FixedValidatorVoteIntentError::SignerNotInFixedSet {
            signer: observed.signer,
        });
    }
    restore_snapshot_for_round(&observed.snapshot, round)
}

pub(super) fn restore_snapshot_for_round(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
    round: &FixedConsensusRoundV0<'_>,
) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteIntentError> {
    let parent = round.parent_coordinate();
    if snapshot.context != round.context()
        || snapshot.parent_verified_height != parent.verified_height()
        || snapshot.parent_ancestry_id != parent.ancestry_id()
        || snapshot.artifact_head_block_id != parent.artifact_head_block_id()
        || snapshot.artifact_set_root != parent.artifact_set_root()
        || snapshot.fixed_agreement_set_id != parent.fixed_agreement_set_id()
        || snapshot.parent_proposer_priority_state_id
            != *parent.proposer_priority_state_id().as_bytes()
        || snapshot.post_height_proposer_priority_state_id
            != *round.post_height_proposer_priority_state_id().as_bytes()
    {
        return Err(FixedValidatorVoteIntentError::RoundBranchMismatch);
    }
    if snapshot.position != round.position() {
        return Err(FixedValidatorVoteIntentError::RoundPositionMismatch {
            record: snapshot.position,
            round: round.position(),
        });
    }
    if let Some(valid) = snapshot.valid.as_ref() {
        let position = ConsensusPosition::new(snapshot.position.height(), valid.round);
        let target = ConsensusVoteTarget::Proposal(valid.value.proposal_signing_root());
        let matches = round
            .verify_retained_prevote_certificate(
                &valid.canonical_prevote_certificate,
                position,
                target,
                valid.prevote_certificate_id,
            )
            .map_err(FixedValidatorVoteIntentError::RetainedCertificate)?;
        if !matches {
            return Err(FixedValidatorVoteIntentError::RetainedCertificateStateMismatch);
        }
    }
    Ok(FixedValidatorLockStateV0 {
        live_lineage_seal: Arc::new(()),
        parent_coordinate: parent,
        post_height_proposer_priority_state_id: round.post_height_proposer_priority_state_id(),
        position: snapshot.position,
        phase: snapshot.phase,
        locked: snapshot.locked,
        valid: snapshot.valid.clone(),
    })
}
