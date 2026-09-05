//! Canonical record encodings and shared validation helpers.

use super::*;

pub(super) struct ParsedTransitionBytes<'bytes> {
    pub(super) height: ConsensusHeight,
    pub(super) envelope: &'bytes [u8],
    pub(super) payload: &'bytes [u8],
}

pub(super) enum ParsedRecord<'bytes> {
    Single {
        tag: u8,
        round: u64,
        transition: ParsedTransitionBytes<'bytes>,
    },
    PreselectionConflict {
        round: u64,
        first: ParsedTransitionBytes<'bytes>,
        second: ParsedTransitionBytes<'bytes>,
    },
}

pub(super) fn parse_round(
    entry: u64,
    body: &[u8],
    replay_limit: FixedValidatorFinalityReplayLimitV0,
) -> Result<u64, FixedValidatorFinalityJournalErrorV0> {
    let round = u64::from_be_bytes(
        body[1..9]
            .try_into()
            .expect("the bounded record header has an eight-byte round"),
    );
    if round > replay_limit.max_round() {
        return Err(
            FixedValidatorFinalityJournalErrorV0::ReplayRoundLimitExceeded {
                entry,
                round,
                maximum: replay_limit.max_round(),
            },
        );
    }
    Ok(round)
}

pub(super) fn parse_record<'bytes>(
    entry: u64,
    offset: u64,
    body: &'bytes [u8],
    replay_limit: FixedValidatorFinalityReplayLimitV0,
) -> Result<ParsedRecord<'bytes>, FixedValidatorFinalityJournalErrorV0> {
    let tag = body[0];
    match tag {
        FINALIZE_RECORD | CONFLICT_HALT_RECORD => {
            if !(MIN_SINGLE_RECORD_BODY_BYTES..=MAX_SINGLE_RECORD_BODY_BYTES).contains(&body.len())
            {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordLength {
                    entry,
                    offset,
                    actual: u32::try_from(body.len()).expect("bounded record length fits u32"),
                    minimum: u32::try_from(MIN_SINGLE_RECORD_BODY_BYTES)
                        .expect("minimum single record length fits u32"),
                    maximum: u32::try_from(MAX_SINGLE_RECORD_BODY_BYTES)
                        .expect("maximum single record length fits u32"),
                });
            }
            let round = parse_round(entry, body, replay_limit)?;
            let envelope_length = parse_envelope_length(entry, &body[9..13])?;
            let payload_length = parse_payload_length(entry, &body[13..17])?;
            let expected_length = RECORD_HEADER_BYTES
                .checked_add(envelope_length)
                .and_then(|length| length.checked_add(payload_length))
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            if expected_length != body.len() {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry });
            }
            let envelope_end = RECORD_HEADER_BYTES + envelope_length;
            let transition = parsed_transition_bytes(
                entry,
                &body[RECORD_HEADER_BYTES..envelope_end],
                &body[envelope_end..],
            )?;
            Ok(ParsedRecord::Single {
                tag,
                round,
                transition,
            })
        }
        PRESELECTION_CONFLICT_HALT_RECORD => {
            if !(MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES
                ..=MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
                .contains(&body.len())
            {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordLength {
                    entry,
                    offset,
                    actual: u32::try_from(body.len()).expect("bounded record length fits u32"),
                    minimum: u32::try_from(MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
                        .expect("minimum paired record length fits u32"),
                    maximum: u32::try_from(MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
                        .expect("maximum paired record length fits u32"),
                });
            }
            let round = parse_round(entry, body, replay_limit)?;
            let first_envelope_length = parse_envelope_length(entry, &body[9..13])?;
            let first_payload_length = parse_payload_length(entry, &body[13..17])?;
            let second_envelope_length = parse_envelope_length(entry, &body[17..21])?;
            let second_payload_length = parse_payload_length(entry, &body[21..25])?;
            let first_envelope_end = PRESELECTION_CONFLICT_RECORD_HEADER_BYTES
                .checked_add(first_envelope_length)
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            let first_payload_end = first_envelope_end
                .checked_add(first_payload_length)
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            let second_envelope_end = first_payload_end
                .checked_add(second_envelope_length)
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            let expected_length = second_envelope_end
                .checked_add(second_payload_length)
                .ok_or(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry })?;
            if expected_length != body.len() {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry });
            }
            let first = parsed_transition_bytes(
                entry,
                &body[PRESELECTION_CONFLICT_RECORD_HEADER_BYTES..first_envelope_end],
                &body[first_envelope_end..first_payload_end],
            )?;
            let second = parsed_transition_bytes(
                entry,
                &body[first_payload_end..second_envelope_end],
                &body[second_envelope_end..],
            )?;
            Ok(ParsedRecord::PreselectionConflict {
                round,
                first,
                second,
            })
        }
        _ => Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordTag {
            entry,
            offset,
            actual: tag,
        }),
    }
}

pub(super) fn parse_envelope_length(
    entry: u64,
    bytes: &[u8],
) -> Result<usize, FixedValidatorFinalityJournalErrorV0> {
    let actual = usize::try_from(u32::from_be_bytes(
        bytes.try_into().expect("an envelope length has four bytes"),
    ))
    .expect("every u32 envelope length fits the supported Rust targets");
    if !(VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH
        ..=VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH)
        .contains(&actual)
    {
        return Err(FixedValidatorFinalityJournalErrorV0::InvalidEnvelopeLength { entry, actual });
    }
    Ok(actual)
}

pub(super) fn parse_payload_length(
    entry: u64,
    bytes: &[u8],
) -> Result<usize, FixedValidatorFinalityJournalErrorV0> {
    let actual = usize::try_from(u32::from_be_bytes(
        bytes.try_into().expect("a payload length has four bytes"),
    ))
    .expect("every u32 payload length fits the supported Rust targets");
    if !(1..=ARTIFACT_PAYLOAD_MAX_BYTES).contains(&actual) {
        return Err(FixedValidatorFinalityJournalErrorV0::InvalidPayloadLength { entry, actual });
    }
    Ok(actual)
}

pub(super) fn parsed_transition_bytes<'bytes>(
    entry: u64,
    envelope: &'bytes [u8],
    payload: &'bytes [u8],
) -> Result<ParsedTransitionBytes<'bytes>, FixedValidatorFinalityJournalErrorV0> {
    let value = ConsensusValueV0::from_canonical_bytes(&envelope[..ConsensusValueV0::BYTE_LENGTH])
        .map_err(|source| FixedValidatorFinalityJournalErrorV0::Value { entry, source })?;
    Ok(ParsedTransitionBytes {
        height: value.height(),
        envelope,
        payload,
    })
}

pub(super) fn canonical_record_body(
    tag: u8,
    transition: &OwnedVerifiedFixedConsensusTransitionV0,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorFinalityJournalErrorV0> {
    let envelope = transition.canonical_envelope_bytes();
    let payload = transition.canonical_artifact_bytes();
    let body_length = RECORD_HEADER_BYTES
        .checked_add(envelope.len())
        .and_then(|length| length.checked_add(payload.len()))
        .expect("a sealed verified transition retains bounded canonical bytes");
    let mut body = Vec::new();
    body.try_reserve_exact(body_length).map_err(|_| {
        FixedValidatorFinalityJournalErrorV0::Allocation {
            entry,
            bytes: body_length,
        }
    })?;
    body.push(tag);
    body.extend_from_slice(&transition.position().round().value().to_be_bytes());
    body.extend_from_slice(
        &u32::try_from(envelope.len())
            .expect("bounded envelope length fits u32")
            .to_be_bytes(),
    );
    body.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("bounded artifact payload length fits u32")
            .to_be_bytes(),
    );
    body.extend_from_slice(envelope);
    body.extend_from_slice(payload);
    debug_assert_eq!(body.len(), body_length);
    Ok(body)
}

pub(super) fn canonical_preselection_conflict_record_body(
    first: &OwnedVerifiedFixedConsensusTransitionV0,
    second: &OwnedVerifiedFixedConsensusTransitionV0,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorFinalityJournalErrorV0> {
    debug_assert_eq!(first.position(), second.position());
    debug_assert_eq!(first.parent_coordinate(), second.parent_coordinate());
    debug_assert!(first.value().proposal_signing_root() < second.value().proposal_signing_root());
    let first_envelope = first.canonical_envelope_bytes();
    let first_payload = first.canonical_artifact_bytes();
    let second_envelope = second.canonical_envelope_bytes();
    let second_payload = second.canonical_artifact_bytes();
    let body_length = PRESELECTION_CONFLICT_RECORD_HEADER_BYTES
        .checked_add(first_envelope.len())
        .and_then(|length| length.checked_add(first_payload.len()))
        .and_then(|length| length.checked_add(second_envelope.len()))
        .and_then(|length| length.checked_add(second_payload.len()))
        .expect("sealed verified transitions retain bounded canonical bytes");
    let mut body = Vec::new();
    body.try_reserve_exact(body_length).map_err(|_| {
        FixedValidatorFinalityJournalErrorV0::Allocation {
            entry,
            bytes: body_length,
        }
    })?;
    body.push(PRESELECTION_CONFLICT_HALT_RECORD);
    body.extend_from_slice(&first.position().round().value().to_be_bytes());
    for length in [
        first_envelope.len(),
        first_payload.len(),
        second_envelope.len(),
        second_payload.len(),
    ] {
        body.extend_from_slice(
            &u32::try_from(length)
                .expect("bounded paired component length fits u32")
                .to_be_bytes(),
        );
    }
    body.extend_from_slice(first_envelope);
    body.extend_from_slice(first_payload);
    body.extend_from_slice(second_envelope);
    body.extend_from_slice(second_payload);
    debug_assert_eq!(body.len(), body_length);
    debug_assert!(
        (MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES..=MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
            .contains(&body.len())
    );
    Ok(body)
}

pub(super) fn record_from_transition(
    transition: &OwnedVerifiedFixedConsensusTransitionV0,
    state_id: FixedValidatorFinalityJournalStateIdV0,
    canonical_record_body: Vec<u8>,
) -> FixedValidatorFinalityRecordV0 {
    let envelope_end = RECORD_HEADER_BYTES + transition.canonical_envelope_bytes().len();
    debug_assert_eq!(
        &canonical_record_body[RECORD_HEADER_BYTES..envelope_end],
        transition.canonical_envelope_bytes()
    );
    debug_assert_eq!(
        &canonical_record_body[envelope_end..],
        transition.canonical_artifact_bytes()
    );
    FixedValidatorFinalityRecordV0 {
        position: transition.position(),
        value: transition.value(),
        envelope_id: transition.envelope_id(),
        canonical_record_body,
        envelope_end,
        state_id,
    }
}

pub(super) fn clone_bytes(
    bytes: &[u8],
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorFinalityJournalErrorV0> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len()).map_err(|_| {
        FixedValidatorFinalityJournalErrorV0::Allocation {
            entry,
            bytes: bytes.len(),
        }
    })?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

pub(super) fn halt_from_transition(
    selected_ancestry: ConsensusAncestryId,
    selected_envelope_id: ConsensusEnvelopeId,
    conflicting: &OwnedVerifiedFixedConsensusTransitionV0,
    state_id: FixedValidatorFinalityJournalStateIdV0,
) -> FixedValidatorFinalityHaltV0 {
    FixedValidatorFinalityHaltV0 {
        kind: FixedValidatorFinalityHaltKindV0::SelectedSibling,
        height: conflicting.value().height(),
        first_ancestry: selected_ancestry,
        first_envelope_id: selected_envelope_id,
        second_ancestry: conflicting.value().ancestry_id(),
        second_envelope_id: conflicting.envelope_id(),
        state_id,
    }
}

pub(super) fn halt_from_preselection_pair(
    first: &OwnedVerifiedFixedConsensusTransitionV0,
    second: &OwnedVerifiedFixedConsensusTransitionV0,
    state_id: FixedValidatorFinalityJournalStateIdV0,
) -> FixedValidatorFinalityHaltV0 {
    debug_assert_eq!(first.position(), second.position());
    debug_assert!(first.value().proposal_signing_root() < second.value().proposal_signing_root());
    FixedValidatorFinalityHaltV0 {
        kind: FixedValidatorFinalityHaltKindV0::PreselectionPair,
        height: first.position().height(),
        first_ancestry: first.value().ancestry_id(),
        first_envelope_id: first.envelope_id(),
        second_ancestry: second.value().ancestry_id(),
        second_envelope_id: second.envelope_id(),
        state_id,
    }
}

pub(super) fn fixed_genesis(
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    entries: &[ActiveAgreementEntry],
) -> Result<FixedConsensusBranchV0, FixedValidatorFinalityJournalErrorV0> {
    FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        entries,
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .map_err(FixedValidatorFinalityJournalErrorV0::Genesis)
}

pub(super) fn canonical_prefix(
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    replay_limit: FixedValidatorFinalityReplayLimitV0,
) -> Result<Vec<u8>, FixedValidatorFinalityJournalErrorV0> {
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(JOURNAL_PREFIX_BYTES)
        .map_err(|_| FixedValidatorFinalityJournalErrorV0::Allocation {
            entry: 0,
            bytes: JOURNAL_PREFIX_BYTES,
        })?;
    prefix.extend_from_slice(JOURNAL_HEADER);
    prefix.extend_from_slice(context.chain_id().as_bytes());
    prefix.extend_from_slice(context.genesis_id().as_bytes());
    prefix.extend_from_slice(&context.protocol_version().value().to_be_bytes());
    prefix.extend_from_slice(fixed_set_id.as_bytes());
    prefix.extend_from_slice(&replay_limit.max_round().to_be_bytes());
    debug_assert_eq!(prefix.len(), JOURNAL_PREFIX_BYTES);
    Ok(prefix)
}

pub(super) fn genesis_state_id(prefix: &[u8]) -> FixedValidatorFinalityJournalStateIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_STATE_DOMAIN);
    hasher.update(prefix);
    FixedValidatorFinalityJournalStateIdV0::from_bytes(hasher.finalize().into())
}

pub(super) fn step_state_id(
    prior: FixedValidatorFinalityJournalStateIdV0,
    body_length: [u8; 4],
    body: &[u8],
) -> FixedValidatorFinalityJournalStateIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(STEP_STATE_DOMAIN);
    hasher.update(prior.as_bytes());
    hasher.update(body_length);
    hasher.update(body);
    FixedValidatorFinalityJournalStateIdV0::from_bytes(hasher.finalize().into())
}

pub(super) fn height_index(height: ConsensusHeight) -> Result<usize, ()> {
    usize::try_from(height.value()).map_err(|_| ())
}

pub(super) fn open_shared_lock(
    directory: &Path,
) -> Result<File, FixedValidatorFinalityJournalErrorV0> {
    open_exclusive_lock(directory, LOCK_FILE_NAME).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => {
            FixedValidatorFinalityJournalErrorV0::LockFile { source }
        }
        ExclusiveLockError::Locked => FixedValidatorFinalityJournalErrorV0::Locked,
        ExclusiveLockError::Lock(source) => FixedValidatorFinalityJournalErrorV0::Lock { source },
    })
}

pub(super) fn read_exact_at<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), FixedValidatorFinalityJournalErrorV0> {
    file.read_exact(bytes)
        .map_err(|source| FixedValidatorFinalityJournalErrorV0::Read { offset, source })
}
