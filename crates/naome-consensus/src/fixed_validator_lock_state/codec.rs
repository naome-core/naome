//! Canonical snapshot, intent, and checkpoint encodings.

use super::*;

pub(super) fn encode_state_and_vote_intent(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
    effect: &FixedValidatorUnsignedVoteEffectV0,
    signer: ConsensusKey,
) -> Result<Vec<u8>, FixedValidatorVoteIntentError> {
    let length = VOTE_INTENT_HEADER.len()
        + state_snapshot_length(snapshot)?
        + 1
        + VOTE_TARGET_BYTES
        + CONSENSUS_KEY_BYTES;
    if length > ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooLong {
            actual: length,
            maximum: ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH,
        });
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
    bytes.extend_from_slice(VOTE_INTENT_HEADER);
    append_state_snapshot(&mut bytes, snapshot);
    bytes.push(role_tag(effect.role));
    append_target(&mut bytes, effect.target);
    bytes.extend_from_slice(signer.as_bytes());
    debug_assert_eq!(bytes.len(), length);
    Ok(bytes)
}

pub(super) fn state_snapshot_length(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
) -> Result<usize, FixedValidatorVoteIntentError> {
    let valid_certificate_len = snapshot
        .valid
        .as_ref()
        .map_or(0, |valid| valid.canonical_prevote_certificate.len());
    let length = STATE_SNAPSHOT_FIXED_BYTES
        + snapshot.locked.map_or(0, |_| LOCK_SNAPSHOT_BYTES)
        + snapshot
            .valid
            .as_ref()
            .map_or(0, |_| VALID_SNAPSHOT_FIXED_BYTES + valid_certificate_len);
    if valid_certificate_len > VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooLong {
            actual: valid_certificate_len,
            maximum: VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH,
        });
    }
    Ok(length)
}

pub(super) fn append_state_snapshot(
    bytes: &mut Vec<u8>,
    snapshot: &FixedValidatorVoteStateSnapshotV0,
) {
    bytes.extend_from_slice(snapshot.context.chain_id().as_bytes());
    bytes.extend_from_slice(snapshot.context.genesis_id().as_bytes());
    bytes.extend_from_slice(&snapshot.context.protocol_version().value().to_be_bytes());
    match snapshot.parent_verified_height {
        None => {
            bytes.push(ABSENT_TAG);
            bytes.extend_from_slice(&0_u64.to_be_bytes());
        }
        Some(height) => {
            bytes.push(PRESENT_TAG);
            bytes.extend_from_slice(&height.value().to_be_bytes());
        }
    }
    bytes.extend_from_slice(snapshot.parent_ancestry_id.as_bytes());
    bytes.extend_from_slice(snapshot.artifact_head_block_id.as_bytes());
    bytes.extend_from_slice(snapshot.artifact_set_root.as_bytes());
    bytes.extend_from_slice(snapshot.fixed_agreement_set_id.as_bytes());
    bytes.extend_from_slice(&snapshot.parent_proposer_priority_state_id);
    bytes.extend_from_slice(&snapshot.post_height_proposer_priority_state_id);
    bytes.extend_from_slice(&snapshot.position.height().value().to_be_bytes());
    bytes.extend_from_slice(&snapshot.position.round().value().to_be_bytes());
    bytes.push(phase_tag(snapshot.phase));
    match snapshot.locked {
        None => bytes.push(ABSENT_TAG),
        Some(locked) => {
            bytes.push(PRESENT_TAG);
            bytes.extend_from_slice(&locked.value.to_canonical_bytes());
            bytes.extend_from_slice(&locked.round.value().to_be_bytes());
        }
    }
    match snapshot.valid.as_ref() {
        None => bytes.push(ABSENT_TAG),
        Some(valid) => {
            bytes.push(PRESENT_TAG);
            bytes.extend_from_slice(&valid.value.to_canonical_bytes());
            bytes.extend_from_slice(&valid.round.value().to_be_bytes());
            bytes.extend_from_slice(valid.prevote_certificate_id.as_bytes());
            bytes.extend_from_slice(
                &u32::try_from(valid.canonical_prevote_certificate.len())
                    .expect("bounded quorum certificates fit u32")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&valid.canonical_prevote_certificate);
        }
    }
}

pub(super) fn decode_state_snapshot(
    decoder: &mut VoteIntentDecoder<'_>,
    expected_context: ConsensusContextV0,
    expected_fixed_agreement_set_id: FixedAgreementSetId,
) -> Result<FixedValidatorVoteStateSnapshotV0, FixedValidatorVoteIntentError> {
    if decoder.take_array::<32>()? != *expected_context.chain_id().as_bytes()
        || decoder.take_array::<32>()? != *expected_context.genesis_id().as_bytes()
        || decoder.take_array::<4>()? != expected_context.protocol_version().value().to_be_bytes()
    {
        return Err(FixedValidatorVoteIntentError::ContextMismatch);
    }
    let parent_verified_tag = decoder.take_byte()?;
    let parent_verified_value = decoder.take_u64()?;
    let parent_verified_height = match parent_verified_tag {
        ABSENT_TAG if parent_verified_value == 0 => None,
        ABSENT_TAG => return Err(FixedValidatorVoteIntentError::NonCanonicalAbsentHeight),
        PRESENT_TAG if parent_verified_value > 0 => {
            Some(ConsensusHeight::new(parent_verified_value))
        }
        PRESENT_TAG => return Err(FixedValidatorVoteIntentError::ReservedGenesisHeight),
        actual => return Err(FixedValidatorVoteIntentError::UnknownPresenceTag { actual }),
    };
    let parent_ancestry_id = ConsensusAncestryId::from_bytes(decoder.take_array()?);
    let artifact_head_block_id = ArtifactBlockId::from_bytes(decoder.take_array()?);
    let artifact_set_root = ArtifactSetRoot::from_bytes(decoder.take_array()?);
    if decoder.take_array::<32>()? != *expected_fixed_agreement_set_id.as_bytes() {
        return Err(FixedValidatorVoteIntentError::FixedAgreementSetMismatch);
    }
    let parent_proposer_priority_state_id = decoder.take_array()?;
    let post_height_proposer_priority_state_id = decoder.take_array()?;
    let height = ConsensusHeight::new(decoder.take_u64()?);
    let round = ConsensusRound::new(decoder.take_u64()?);
    let position = ConsensusPosition::new(height, round);
    let phase = decode_phase(decoder.take_byte()?)?;
    let locked = match decoder.take_byte()? {
        ABSENT_TAG => None,
        PRESENT_TAG => {
            let value = ConsensusValueV0::from_canonical_bytes(
                decoder.take_slice(ConsensusValueV0::BYTE_LENGTH)?,
            )
            .map_err(FixedValidatorVoteIntentError::Value)?;
            Some(FixedValidatorLockedValueV0 {
                value,
                round: ConsensusRound::new(decoder.take_u64()?),
            })
        }
        actual => return Err(FixedValidatorVoteIntentError::UnknownPresenceTag { actual }),
    };
    let valid = match decoder.take_byte()? {
        ABSENT_TAG => None,
        PRESENT_TAG => {
            let value = ConsensusValueV0::from_canonical_bytes(
                decoder.take_slice(ConsensusValueV0::BYTE_LENGTH)?,
            )
            .map_err(FixedValidatorVoteIntentError::Value)?;
            let valid_round = ConsensusRound::new(decoder.take_u64()?);
            let encoded_id = decoder.take_array::<32>()?;
            let certificate_length = usize::try_from(decoder.take_u32()?)
                .expect("u32 always fits usize on supported targets");
            let certificate = decoder.take_slice(certificate_length)?;
            let header = decode_canonical_quorum_certificate_header(certificate)
                .map_err(FixedValidatorVoteIntentError::RetainedCertificate)?;
            if header.id.as_bytes() != &encoded_id {
                return Err(FixedValidatorVoteIntentError::RetainedCertificateIdMismatch);
            }
            let expected_certificate_position =
                ConsensusPosition::new(position.height(), valid_round);
            if header.context != expected_context
                || header.position != expected_certificate_position
                || header.role != ConsensusVoteRole::Prevote
                || header.target != ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            {
                return Err(FixedValidatorVoteIntentError::RetainedCertificateStateMismatch);
            }
            let mut canonical_prevote_certificate = Vec::new();
            canonical_prevote_certificate
                .try_reserve_exact(certificate.len())
                .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
            canonical_prevote_certificate.extend_from_slice(certificate);
            Some(FixedValidatorValidValueV0 {
                value,
                round: valid_round,
                prevote_certificate_id: header.id,
                canonical_prevote_certificate,
            })
        }
        actual => return Err(FixedValidatorVoteIntentError::UnknownPresenceTag { actual }),
    };
    let snapshot = FixedValidatorVoteStateSnapshotV0 {
        context: expected_context,
        parent_verified_height,
        parent_ancestry_id,
        artifact_head_block_id,
        artifact_set_root,
        fixed_agreement_set_id: expected_fixed_agreement_set_id,
        parent_proposer_priority_state_id,
        post_height_proposer_priority_state_id,
        position,
        phase,
        locked,
        valid,
    };
    validate_snapshot_invariants(&snapshot)?;
    Ok(snapshot)
}

pub(super) fn decode_observed_vote_intent(
    bytes: &[u8],
    expected_context: ConsensusContextV0,
    expected_fixed_agreement_set_id: FixedAgreementSetId,
    expected_signer: ConsensusKey,
) -> Result<ObservedFixedValidatorVoteIntentV0, FixedValidatorVoteIntentError> {
    if bytes.len() > ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooLong {
            actual: bytes.len(),
            maximum: ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH,
        });
    }
    if bytes.len() < ObservedFixedValidatorVoteIntentV0::MIN_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooShort {
            actual: bytes.len(),
            minimum: ObservedFixedValidatorVoteIntentV0::MIN_BYTE_LENGTH,
        });
    }
    let mut decoder = VoteIntentDecoder::new(bytes);
    if decoder.take_slice(VOTE_INTENT_HEADER.len())? != VOTE_INTENT_HEADER {
        return Err(FixedValidatorVoteIntentError::InvalidHeader);
    }
    let snapshot = decode_state_snapshot(
        &mut decoder,
        expected_context,
        expected_fixed_agreement_set_id,
    )?;
    let role = decode_role(decoder.take_byte()?)?;
    let target = decode_target(&mut decoder)?;
    let signer_bytes = decoder.take_array::<CONSENSUS_KEY_BYTES>()?;
    if signer_bytes != *expected_signer.as_bytes() {
        return Err(FixedValidatorVoteIntentError::SignerMismatch);
    }
    decoder.finish()?;

    let effect = FixedValidatorUnsignedVoteEffectV0::from_snapshot(&snapshot, role, target);
    validate_effect_for_snapshot(&snapshot, &effect)?;
    let canonical_state_and_vote_intent_bytes =
        encode_state_and_vote_intent(&snapshot, &effect, expected_signer)?;
    if canonical_state_and_vote_intent_bytes != bytes {
        return Err(FixedValidatorVoteIntentError::NonCanonicalEncoding);
    }
    Ok(ObservedFixedValidatorVoteIntentV0 {
        snapshot,
        effect,
        signer: expected_signer,
        canonical_state_and_vote_intent_bytes,
    })
}

pub(super) fn encode_higher_round_checkpoint(
    source_position: ConsensusPosition,
    source_phase: FixedValidatorLockPhaseV0,
    source_state_binding: [u8; OPAQUE_ID_BYTES],
    target_snapshot: &FixedValidatorVoteStateSnapshotV0,
    canonical_certificate: &[u8],
) -> Result<Vec<u8>, FixedValidatorVoteIntentError> {
    let length = HIGHER_ROUND_CHECKPOINT_HEADER.len()
        + HIGHER_ROUND_SOURCE_BYTES
        + state_snapshot_length(target_snapshot)?
        + CERTIFICATE_LENGTH_BYTES
        + canonical_certificate.len();
    if length > ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooLong {
            actual: length,
            maximum: ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH,
        });
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
    bytes.extend_from_slice(HIGHER_ROUND_CHECKPOINT_HEADER);
    bytes.extend_from_slice(&source_position.height().value().to_be_bytes());
    bytes.extend_from_slice(&source_position.round().value().to_be_bytes());
    bytes.push(phase_tag(source_phase));
    bytes.extend_from_slice(&source_state_binding);
    append_state_snapshot(&mut bytes, target_snapshot);
    bytes.extend_from_slice(
        &u32::try_from(canonical_certificate.len())
            .expect("bounded quorum certificates fit u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(canonical_certificate);
    debug_assert_eq!(bytes.len(), length);
    Ok(bytes)
}

pub(super) fn decode_observed_higher_round_checkpoint(
    bytes: &[u8],
    expected_context: ConsensusContextV0,
    expected_fixed_agreement_set_id: FixedAgreementSetId,
) -> Result<ObservedFixedValidatorHigherRoundCheckpointV0, FixedValidatorHigherRoundCheckpointErrorV0>
{
    if bytes.len() > ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::InputTooLong {
            actual: bytes.len(),
            maximum: ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH,
        });
    }
    if bytes.len() < ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::InputTooShort {
            actual: bytes.len(),
            minimum: ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH,
        });
    }
    let mut decoder = VoteIntentDecoder::new(bytes);
    if decoder
        .take_slice(HIGHER_ROUND_CHECKPOINT_HEADER.len())
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?
        != HIGHER_ROUND_CHECKPOINT_HEADER
    {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::InvalidHeader);
    }
    let source_position = ConsensusPosition::new(
        ConsensusHeight::new(
            decoder
                .take_u64()
                .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?,
        ),
        ConsensusRound::new(
            decoder
                .take_u64()
                .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?,
        ),
    );
    let source_phase = decode_phase(
        decoder
            .take_byte()
            .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?,
    )
    .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    let source_state_binding = decoder
        .take_array::<OPAQUE_ID_BYTES>()
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    let target_snapshot = decode_state_snapshot(
        &mut decoder,
        expected_context,
        expected_fixed_agreement_set_id,
    )
    .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    let certificate_length = usize::try_from(
        decoder
            .take_u32()
            .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?,
    )
    .expect("u32 always fits usize on supported targets");
    let certificate = decoder
        .take_slice(certificate_length)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    decoder
        .finish()
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;

    if source_position.height() != target_snapshot.position.height() {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::HeightMismatch {
            source: source_position.height(),
            target: target_snapshot.position.height(),
        });
    }
    if target_snapshot.position.round() <= source_position.round() {
        return Err(
            FixedValidatorHigherRoundCheckpointErrorV0::NotStrictlyHigher {
                source: source_position.round(),
                target: target_snapshot.position.round(),
            },
        );
    }
    let mut source_snapshot = target_snapshot.clone();
    source_snapshot.position = source_position;
    source_snapshot.phase = source_phase;
    validate_snapshot_invariants(&source_snapshot)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    if higher_round_source_state_binding(&source_snapshot) != source_state_binding {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::SourceStateBindingMismatch);
    }

    let header = decode_canonical_quorum_certificate_header(certificate)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::Certificate)?;
    if header.context != expected_context {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::CertificateContextMismatch);
    }
    if header.position != target_snapshot.position {
        return Err(
            FixedValidatorHigherRoundCheckpointErrorV0::CertificatePositionMismatch {
                expected: target_snapshot.position,
                actual: header.position,
            },
        );
    }
    let expected_phase = phase_for_role(header.role);
    if target_snapshot.phase != expected_phase {
        return Err(
            FixedValidatorHigherRoundCheckpointErrorV0::PhaseRoleMismatch {
                phase: target_snapshot.phase,
                role: header.role,
            },
        );
    }

    let canonical_checkpoint = encode_higher_round_checkpoint(
        source_position,
        source_phase,
        source_state_binding,
        &target_snapshot,
        certificate,
    )
    .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    if canonical_checkpoint != bytes {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::NonCanonicalEncoding);
    }
    let mut canonical_certificate = Vec::new();
    canonical_certificate
        .try_reserve_exact(certificate.len())
        .map_err(|_| FixedValidatorHigherRoundCheckpointErrorV0::AllocationFailed)?;
    canonical_certificate.extend_from_slice(certificate);

    Ok(ObservedFixedValidatorHigherRoundCheckpointV0 {
        source_position,
        source_phase,
        source_state_binding,
        target_snapshot,
        role: header.role,
        target: header.target,
        certificate_id: header.id,
        canonical_certificate,
        canonical_checkpoint,
    })
}

pub(super) fn phase_tag(phase: FixedValidatorLockPhaseV0) -> u8 {
    match phase {
        FixedValidatorLockPhaseV0::Proposal => PROPOSAL_PHASE_TAG,
        FixedValidatorLockPhaseV0::Prevote => PREVOTE_PHASE_TAG,
        FixedValidatorLockPhaseV0::Precommit => PRECOMMIT_PHASE_TAG,
    }
}

pub(super) const fn phase_for_role(role: ConsensusVoteRole) -> FixedValidatorLockPhaseV0 {
    match role {
        ConsensusVoteRole::Prevote => FixedValidatorLockPhaseV0::Prevote,
        ConsensusVoteRole::Precommit => FixedValidatorLockPhaseV0::Precommit,
    }
}

pub(super) fn decode_phase(
    tag: u8,
) -> Result<FixedValidatorLockPhaseV0, FixedValidatorVoteIntentError> {
    match tag {
        PROPOSAL_PHASE_TAG => Ok(FixedValidatorLockPhaseV0::Proposal),
        PREVOTE_PHASE_TAG => Ok(FixedValidatorLockPhaseV0::Prevote),
        PRECOMMIT_PHASE_TAG => Ok(FixedValidatorLockPhaseV0::Precommit),
        actual => Err(FixedValidatorVoteIntentError::UnknownPhaseTag { actual }),
    }
}

pub(super) fn role_tag(role: ConsensusVoteRole) -> u8 {
    match role {
        ConsensusVoteRole::Prevote => PREVOTE_ROLE_TAG,
        ConsensusVoteRole::Precommit => PRECOMMIT_ROLE_TAG,
    }
}

pub(super) fn decode_role(tag: u8) -> Result<ConsensusVoteRole, FixedValidatorVoteIntentError> {
    match tag {
        PREVOTE_ROLE_TAG => Ok(ConsensusVoteRole::Prevote),
        PRECOMMIT_ROLE_TAG => Ok(ConsensusVoteRole::Precommit),
        actual => Err(FixedValidatorVoteIntentError::UnknownRoleTag { actual }),
    }
}

pub(super) fn append_target(bytes: &mut Vec<u8>, target: ConsensusVoteTarget) {
    match target {
        ConsensusVoteTarget::Nil => {
            bytes.push(NIL_TARGET_TAG);
            bytes.extend_from_slice(&[0_u8; ProposalSigningRoot::BYTE_LENGTH]);
        }
        ConsensusVoteTarget::Proposal(root) => {
            bytes.push(PROPOSAL_TARGET_TAG);
            bytes.extend_from_slice(root.as_bytes());
        }
    }
}

pub(super) fn decode_target(
    decoder: &mut VoteIntentDecoder<'_>,
) -> Result<ConsensusVoteTarget, FixedValidatorVoteIntentError> {
    let tag = decoder.take_byte()?;
    let payload = decoder.take_array::<{ ProposalSigningRoot::BYTE_LENGTH }>()?;
    match tag {
        NIL_TARGET_TAG if payload == [0_u8; ProposalSigningRoot::BYTE_LENGTH] => {
            Ok(ConsensusVoteTarget::Nil)
        }
        NIL_TARGET_TAG => Err(FixedValidatorVoteIntentError::NonCanonicalNilTarget),
        PROPOSAL_TARGET_TAG => Ok(ConsensusVoteTarget::Proposal(
            ProposalSigningRoot::from_bytes(payload),
        )),
        actual => Err(FixedValidatorVoteIntentError::UnknownTargetTag { actual }),
    }
}

pub(super) struct VoteIntentDecoder<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> VoteIntentDecoder<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn take_slice(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], FixedValidatorVoteIntentError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FixedValidatorVoteIntentError::TruncatedEncoding)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(FixedValidatorVoteIntentError::TruncatedEncoding)?;
        self.offset = end;
        Ok(slice)
    }

    pub(super) fn take_array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], FixedValidatorVoteIntentError> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| FixedValidatorVoteIntentError::TruncatedEncoding)
    }

    pub(super) fn take_byte(&mut self) -> Result<u8, FixedValidatorVoteIntentError> {
        Ok(self.take_array::<1>()?[0])
    }

    pub(super) fn take_u32(&mut self) -> Result<u32, FixedValidatorVoteIntentError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    pub(super) fn take_u64(&mut self) -> Result<u64, FixedValidatorVoteIntentError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    pub(super) fn finish(self) -> Result<(), FixedValidatorVoteIntentError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(FixedValidatorVoteIntentError::TrailingBytes {
                actual: self.bytes.len(),
                expected: self.offset,
            })
        }
    }
}
