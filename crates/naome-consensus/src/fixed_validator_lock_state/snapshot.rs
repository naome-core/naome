//! State snapshots, bindings, and consistency invariants.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FixedValidatorVoteStateSnapshotV0 {
    pub(super) context: ConsensusContextV0,
    pub(super) parent_verified_height: Option<ConsensusHeight>,
    pub(super) parent_ancestry_id: ConsensusAncestryId,
    pub(super) artifact_head_block_id: ArtifactBlockId,
    pub(super) artifact_set_root: ArtifactSetRoot,
    pub(super) fixed_agreement_set_id: FixedAgreementSetId,
    pub(super) parent_proposer_priority_state_id: [u8; OPAQUE_ID_BYTES],
    pub(super) post_height_proposer_priority_state_id: [u8; OPAQUE_ID_BYTES],
    pub(super) position: ConsensusPosition,
    pub(super) phase: FixedValidatorLockPhaseV0,
    pub(super) locked: Option<FixedValidatorLockedValueV0>,
    pub(super) valid: Option<FixedValidatorValidValueV0>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixedValidatorProposalStateSnapshotV0 {
    pub(super) snapshot: FixedValidatorVoteStateSnapshotV0,
    pub(super) canonical_bytes: Vec<u8>,
}

impl FixedValidatorProposalStateSnapshotV0 {
    pub(crate) const MIN_BYTE_LENGTH: usize = STATE_SNAPSHOT_FIXED_BYTES;
    pub(crate) const MAX_BYTE_LENGTH: usize = STATE_SNAPSHOT_FIXED_BYTES
        + LOCK_SNAPSHOT_BYTES
        + VALID_SNAPSHOT_FIXED_BYTES
        + VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH;

    pub(crate) fn from_lock_state(
        state: &FixedValidatorLockStateV0,
    ) -> Result<Self, FixedValidatorVoteIntentError> {
        let snapshot = vote_snapshot_from_lock_state(state);
        let length = state_snapshot_length(&snapshot)?;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(length)
            .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
        append_state_snapshot(&mut canonical_bytes, &snapshot);
        debug_assert_eq!(canonical_bytes.len(), length);
        Ok(Self {
            snapshot,
            canonical_bytes,
        })
    }

    pub(crate) fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        expected_fixed_agreement_set_id: FixedAgreementSetId,
    ) -> Result<Self, FixedValidatorVoteIntentError> {
        let mut decoder = VoteIntentDecoder::new(bytes);
        let snapshot = decode_state_snapshot(
            &mut decoder,
            expected_context,
            expected_fixed_agreement_set_id,
        )?;
        decoder.finish()?;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
        canonical_bytes.extend_from_slice(bytes);
        let mut expected = Vec::new();
        expected
            .try_reserve_exact(state_snapshot_length(&snapshot)?)
            .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
        append_state_snapshot(&mut expected, &snapshot);
        if expected != canonical_bytes {
            return Err(FixedValidatorVoteIntentError::NonCanonicalEncoding);
        }
        Ok(Self {
            snapshot,
            canonical_bytes,
        })
    }

    pub(crate) const fn position(&self) -> ConsensusPosition {
        self.snapshot.position
    }

    pub(crate) const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.snapshot.phase
    }

    pub(crate) const fn context(&self) -> ConsensusContextV0 {
        self.snapshot.context
    }

    pub(crate) const fn valid_value(&self) -> Option<&FixedValidatorValidValueV0> {
        self.snapshot.valid.as_ref()
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn restore_for_round(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteIntentError> {
        restore_snapshot_for_round(&self.snapshot, round)
    }
}

pub(super) fn vote_snapshot_from_lock_state(
    state: &FixedValidatorLockStateV0,
) -> FixedValidatorVoteStateSnapshotV0 {
    let parent = state.parent_coordinate;
    FixedValidatorVoteStateSnapshotV0 {
        context: parent.context(),
        parent_verified_height: parent.verified_height(),
        parent_ancestry_id: parent.ancestry_id(),
        artifact_head_block_id: parent.artifact_head_block_id(),
        artifact_set_root: parent.artifact_set_root(),
        fixed_agreement_set_id: parent.fixed_agreement_set_id(),
        parent_proposer_priority_state_id: *parent.proposer_priority_state_id().as_bytes(),
        post_height_proposer_priority_state_id: *state
            .post_height_proposer_priority_state_id
            .as_bytes(),
        position: state.position,
        phase: state.phase,
        locked: state.locked,
        valid: state.valid.clone(),
    }
}

pub(super) fn vote_effect_state_binding(snapshot: &FixedValidatorVoteStateSnapshotV0) -> [u8; 32] {
    lock_state_binding(VOTE_EFFECT_STATE_BINDING_DOMAIN, snapshot)
}

pub(super) fn higher_round_source_state_binding(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
) -> [u8; 32] {
    lock_state_binding(HIGHER_ROUND_SOURCE_STATE_BINDING_DOMAIN, snapshot)
}

pub(super) fn lock_state_binding(
    domain: &[u8],
    snapshot: &FixedValidatorVoteStateSnapshotV0,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(snapshot.context.chain_id().as_bytes());
    hasher.update(snapshot.context.genesis_id().as_bytes());
    hasher.update(snapshot.context.protocol_version().value().to_be_bytes());
    match snapshot.parent_verified_height {
        None => {
            hasher.update([ABSENT_TAG]);
            hasher.update(0_u64.to_be_bytes());
        }
        Some(height) => {
            hasher.update([PRESENT_TAG]);
            hasher.update(height.value().to_be_bytes());
        }
    }
    hasher.update(snapshot.parent_ancestry_id.as_bytes());
    hasher.update(snapshot.artifact_head_block_id.as_bytes());
    hasher.update(snapshot.artifact_set_root.as_bytes());
    hasher.update(snapshot.fixed_agreement_set_id.as_bytes());
    hasher.update(snapshot.parent_proposer_priority_state_id);
    hasher.update(snapshot.post_height_proposer_priority_state_id);
    hasher.update(snapshot.position.height().value().to_be_bytes());
    hasher.update(snapshot.position.round().value().to_be_bytes());
    hasher.update([phase_tag(snapshot.phase)]);
    match snapshot.locked {
        None => hasher.update([ABSENT_TAG]),
        Some(locked) => {
            hasher.update([PRESENT_TAG]);
            hasher.update(locked.value.to_canonical_bytes());
            hasher.update(locked.round.value().to_be_bytes());
        }
    }
    match snapshot.valid.as_ref() {
        None => hasher.update([ABSENT_TAG]),
        Some(valid) => {
            hasher.update([PRESENT_TAG]);
            hasher.update(valid.value.to_canonical_bytes());
            hasher.update(valid.round.value().to_be_bytes());
            hasher.update(valid.prevote_certificate_id.as_bytes());
            hasher.update(
                u32::try_from(valid.canonical_prevote_certificate.len())
                    .expect("bounded quorum certificates fit u32")
                    .to_be_bytes(),
            );
            hasher.update(&valid.canonical_prevote_certificate);
        }
    }
    hasher.finalize().into()
}

pub(super) fn validate_effect_for_snapshot(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
    effect: &FixedValidatorUnsignedVoteEffectV0,
) -> Result<(), FixedValidatorVoteIntentError> {
    if effect.state_binding != vote_effect_state_binding(snapshot) {
        return Err(FixedValidatorVoteIntentError::EffectStateMismatch);
    }
    if effect.position != snapshot.position {
        return Err(FixedValidatorVoteIntentError::EffectPositionMismatch {
            state: snapshot.position,
            effect: effect.position,
        });
    }
    let expected_phase = match effect.role {
        ConsensusVoteRole::Prevote => FixedValidatorLockPhaseV0::Prevote,
        ConsensusVoteRole::Precommit => FixedValidatorLockPhaseV0::Precommit,
    };
    if snapshot.phase != expected_phase {
        return Err(FixedValidatorVoteIntentError::EffectPhaseMismatch {
            phase: snapshot.phase,
            role: effect.role,
        });
    }
    if let Some(locked) = snapshot.locked {
        if effect.role == ConsensusVoteRole::Prevote
            && effect.target != ConsensusVoteTarget::Proposal(locked.proposal_signing_root())
        {
            return Err(FixedValidatorVoteIntentError::EffectTargetMismatch);
        }
        if effect.role == ConsensusVoteRole::Precommit
            && matches!(effect.target, ConsensusVoteTarget::Proposal(_))
            && (effect.target != ConsensusVoteTarget::Proposal(locked.proposal_signing_root())
                || locked.round != snapshot.position.round())
        {
            return Err(FixedValidatorVoteIntentError::EffectTargetMismatch);
        }
        if effect.role == ConsensusVoteRole::Precommit
            && effect.target == ConsensusVoteTarget::Nil
            && locked.round == snapshot.position.round()
        {
            return Err(FixedValidatorVoteIntentError::EffectTargetMismatch);
        }
    } else if effect.role == ConsensusVoteRole::Precommit
        && matches!(effect.target, ConsensusVoteTarget::Proposal(_))
    {
        return Err(FixedValidatorVoteIntentError::EffectTargetMismatch);
    }
    validate_snapshot_invariants(snapshot)
}

pub(super) fn validate_snapshot_invariants(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
) -> Result<(), FixedValidatorVoteIntentError> {
    if snapshot.position.height().value() == 0 {
        return Err(FixedValidatorVoteIntentError::ReservedGenesisHeight);
    }
    let expected_height = match snapshot.parent_verified_height {
        None => 1,
        Some(parent) => parent
            .value()
            .checked_add(1)
            .ok_or(FixedValidatorVoteIntentError::ParentHeightExhausted)?,
    };
    if snapshot.position.height().value() != expected_height {
        return Err(FixedValidatorVoteIntentError::NonSequentialHeight {
            parent: snapshot.parent_verified_height,
            current: snapshot.position.height(),
        });
    }
    for value in snapshot
        .locked
        .iter()
        .map(|locked| locked.value)
        .chain(snapshot.valid.iter().map(|valid| valid.value))
    {
        if value.context() != snapshot.context
            || value.height() != snapshot.position.height()
            || value.parent_ancestry_id() != snapshot.parent_ancestry_id
        {
            return Err(FixedValidatorVoteIntentError::StateValueBranchMismatch);
        }
    }
    if let Some(locked) = snapshot.locked {
        if locked.round > snapshot.position.round() {
            return Err(FixedValidatorVoteIntentError::FutureLockedRound {
                locked: locked.round,
                current: snapshot.position.round(),
            });
        }
        let Some(valid) = snapshot.valid.as_ref() else {
            return Err(FixedValidatorVoteIntentError::LockWithoutValidValue);
        };
        if valid.round < locked.round {
            return Err(FixedValidatorVoteIntentError::ValidRoundBeforeLock {
                locked: locked.round,
                valid: valid.round,
            });
        }
        if valid.value != locked.value {
            return Err(FixedValidatorVoteIntentError::LockValidValueMismatch {
                locked_round: locked.round,
                valid_round: valid.round,
            });
        }
        if locked.round == snapshot.position.round()
            && snapshot.phase != FixedValidatorLockPhaseV0::Precommit
        {
            return Err(FixedValidatorVoteIntentError::CurrentRoundLockBeforePrecommit);
        }
    }
    if let Some(valid) = snapshot.valid.as_ref() {
        if valid.round > snapshot.position.round() {
            return Err(FixedValidatorVoteIntentError::FutureValidRound {
                valid: valid.round,
                current: snapshot.position.round(),
            });
        }
        if valid.round == snapshot.position.round() {
            let current_lock_matches = snapshot
                .locked
                .is_some_and(|locked| locked.round == valid.round && locked.value == valid.value);
            if snapshot.phase != FixedValidatorLockPhaseV0::Precommit || !current_lock_matches {
                return Err(FixedValidatorVoteIntentError::CurrentValidWithoutMatchingLock);
            }
        }
    }
    Ok(())
}
