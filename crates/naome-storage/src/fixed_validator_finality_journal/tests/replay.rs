use super::*;

#[test]
fn state_id_goldens_cover_genesis_and_two_steps() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("goldens");
    let mut journal = fixture.create(&directory);
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "9beeb687529f3dbd5e91b8ccc9aeca3ef8321b1c7a10601be4e5eb22d0f1fe53"
    );
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let block = first.value().artifact_block();
    let payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "f56cb626eb72a336f4cc19ef5cf7b84b2fc70252de39ed653302e3f64d683c5d"
    );
    selected.apply_block(&block, payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let _ = journal.commit_verified(second).unwrap();
    assert_eq!(
        hex(journal.state_id().unwrap().as_bytes()),
        "63764e2271be86b357c4dcd56f997674950e99d7a3dc3a85d56e5ea105195940"
    );
}

#[test]
fn same_value_later_round_is_idempotent_without_write() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("same-value");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_envelope_id = first.envelope_id();
    let first_envelope = first.canonical_envelope_bytes().to_vec();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let variant = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    let _ = journal.commit_verified(first).unwrap();
    let image = fs::read(directory.journal()).unwrap();
    let state = journal.state_id().unwrap();
    assert!(matches!(
        journal.commit_verified(variant).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized {
            retained_envelope_id,
            state_id,
            ..
        } if retained_envelope_id == first_envelope_id && state_id == state
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), image);
    let retained = journal
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    assert_eq!(retained.envelope_id(), first_envelope_id);
    assert_eq!(retained.canonical_envelope_bytes(), first_envelope);
    assert_eq!(retained.canonical_artifact_bytes(), first_payload);
    let durable = journal
        .acknowledge_signer_height_transition_is_externally_durable(ConsensusHeight::new(1), state)
        .unwrap();
    assert_eq!(durable.transition.position().round().value(), 0);
    assert_eq!(durable.transition.envelope_id(), first_envelope_id);
}

#[test]
fn conflicting_valid_sibling_durably_halts_and_denies_head() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("halt");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let conflict = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let denied_commit =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    let reopened_denied_commit =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 2);
    let _ = journal.commit_verified(first).unwrap();
    let pre_halt_image = fs::read(directory.journal()).unwrap();
    let halt = match journal.commit_verified(conflict).unwrap() {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(journal.halt().unwrap(), Some(halt));
    assert!(matches!(
        journal.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.artifact_chain_id(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.artifact_head_block_id(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.artifact_set_root(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.artifact_branch_snapshot_at(fixture.definition.id().virtual_genesis_block_id()),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.parent_for_height(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.finality_record(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.finalized_len(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            journal.state_id().unwrap(),
        ),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        journal.commit_verified(denied_commit),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    let state = journal.state_id().unwrap();
    let halt_image = fs::read(directory.journal()).unwrap();
    drop(journal);
    let reopened = fixture.open(&directory, state).unwrap();
    assert_eq!(reopened.halt().unwrap(), Some(halt));
    assert!(matches!(
        reopened.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.artifact_chain_id(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.artifact_head_block_id(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.artifact_set_root(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.artifact_branch_snapshot_at(fixture.definition.id().virtual_genesis_block_id()),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.parent_for_height(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.finality_record(ConsensusHeight::new(1)),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.finalized_len(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    assert!(matches!(
        reopened.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            reopened.state_id().unwrap(),
        ),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    let mut reopened = reopened;
    assert!(matches!(
        reopened.commit_verified(reopened_denied_commit),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    drop(reopened);

    let mut incomplete_after_halt = halt_image.clone();
    incomplete_after_halt.push(0);
    fs::write(directory.journal(), &incomplete_after_halt).unwrap();
    let recovered_halt = fixture.open(&directory, state).unwrap();
    assert_eq!(recovered_halt.halt().unwrap(), Some(halt));
    drop(recovered_halt);
    assert_eq!(fs::read(directory.journal()).unwrap(), halt_image);

    let mut complete_after_halt = halt_image.clone();
    complete_after_halt.extend_from_slice(&pre_halt_image[JOURNAL_PREFIX_BYTES..]);
    fs::write(directory.journal(), &complete_after_halt).unwrap();
    assert!(matches!(
        fixture.open(&directory, state),
        Err(FixedValidatorFinalityJournalErrorV0::RecordAfterHalt { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), complete_after_halt);

    fs::write(directory.journal(), &pre_halt_image).unwrap();
    assert!(matches!(
        fixture.open(&directory, state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
}

#[test]
fn mutation_duplicate_and_reorder_fail_closed() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("tamper");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let _ = journal.commit_verified(second).unwrap();
    let state = journal.state_id().unwrap();
    drop(journal);
    let image = fs::read(directory.journal()).unwrap();
    let first_len = 4
        + u32::from_be_bytes(
            image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + 4]
                .try_into()
                .unwrap(),
        ) as usize
        + 32;
    let first = &image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + first_len];
    let second = &image[JOURNAL_PREFIX_BYTES + first_len..];
    for altered in [
        {
            let mut bytes = image.clone();
            bytes[JOURNAL_PREFIX_BYTES + 5] ^= 1;
            bytes
        },
        {
            let mut bytes = image.clone();
            bytes[JOURNAL_PREFIX_BYTES + first_len - 1] ^= 1;
            bytes
        },
        [
            image[..JOURNAL_PREFIX_BYTES].to_vec(),
            first.to_vec(),
            first.to_vec(),
            second.to_vec(),
        ]
        .concat(),
        [
            image[..JOURNAL_PREFIX_BYTES].to_vec(),
            second.to_vec(),
            first.to_vec(),
        ]
        .concat(),
    ] {
        fs::write(directory.journal(), &altered).unwrap();
        assert!(fixture.open(&directory, state).is_err());
        assert_eq!(fs::read(directory.journal()).unwrap(), altered);
    }
}

#[test]
fn recomputed_state_ids_cannot_authorize_invalid_tags_or_artifact_semantics() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("semantic-tamper");
    let mut journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(transition).unwrap();
    drop(journal);

    let image = fs::read(directory.journal()).unwrap();
    let body_length_bytes: [u8; 4] = image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + 4]
        .try_into()
        .unwrap();
    let body_length = u32::from_be_bytes(body_length_bytes) as usize;
    let body_start = JOURNAL_PREFIX_BYTES + 4;
    let body_end = body_start + body_length;

    let mut invalid_tag = image.clone();
    invalid_tag[body_start] = 0xff;
    let tag_state = step_state_id(
        genesis,
        body_length_bytes,
        &invalid_tag[body_start..body_end],
    );
    invalid_tag[body_end..body_end + 32].copy_from_slice(tag_state.as_bytes());
    fs::write(directory.journal(), &invalid_tag).unwrap();
    assert!(matches!(
        fixture.open(&directory, tag_state),
        Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordTag { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), invalid_tag);

    let mut invalid_payload = image;
    invalid_payload[body_end - 1] ^= 1;
    let payload_state = step_state_id(
        genesis,
        body_length_bytes,
        &invalid_payload[body_start..body_end],
    );
    invalid_payload[body_end..body_end + 32].copy_from_slice(payload_state.as_bytes());
    fs::write(directory.journal(), &invalid_payload).unwrap();
    assert!(matches!(
        fixture.open(&directory, payload_state),
        Err(FixedValidatorFinalityJournalErrorV0::Replay { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), invalid_payload);
}

#[test]
fn max_round_is_header_bound_and_shared_namespace_rejects_old_format() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("namespace");
    let old = ArtifactChainJournal::create(&directory.0, fixture.definition).unwrap();
    assert!(matches!(
        FixedValidatorFinalityJournalV0::create(
            &directory.0,
            fixture.definition,
            fixture.context,
            &fixture.entries,
            fixture.limit,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Locked)
    ));
    drop(old);
    assert!(matches!(
        fixture.open(
            &directory,
            FixedValidatorFinalityJournalStateIdV0::from_bytes([0; 32]),
        ),
        Err(FixedValidatorFinalityJournalErrorV0::InvalidHeader)
            | Err(FixedValidatorFinalityJournalErrorV0::HeaderMismatch)
    ));

    fs::remove_file(directory.journal()).unwrap();
    let journal = fixture.create(&directory);
    let state = journal.state_id().unwrap();
    drop(journal);
    let other_limit = FixedValidatorFinalityReplayLimitV0::new(9).unwrap();
    assert!(matches!(
        FixedValidatorFinalityJournalV0::open_verified(
            &directory.0,
            fixture.definition,
            fixture.context,
            &fixture.entries,
            other_limit,
            state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::HeaderMismatch)
    ));
}

#[test]
fn round_limit_accepts_maximum_and_rejects_max_plus_one_before_io_and_replay() {
    assert_eq!(
        FixedValidatorFinalityReplayLimitV0::new(0),
        Err(FixedValidatorFinalityReplayLimitErrorV0)
    );
    let fixture = Fixture::new();
    let directory = TestDirectory::new("round-limit");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let at_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Pairing,
        fixture.limit.max_round(),
    );
    let at_limit_position = at_limit.position();
    let at_limit_ancestry = at_limit.value().ancestry_id();
    let at_limit_envelope = at_limit.envelope_id();
    let at_limit_envelope_bytes = at_limit.canonical_envelope_bytes().to_vec();
    let at_limit_payload_bytes = at_limit.canonical_artifact_bytes().to_vec();
    let above_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Union,
        fixture.limit.max_round() + 1,
    );
    let replay_above_limit = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Union,
        fixture.limit.max_round() + 1,
    );
    assert!(matches!(
        journal.commit_verified(at_limit).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    let committed_state = journal.state_id().unwrap();
    let durable = journal
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            committed_state,
        )
        .unwrap();
    assert_eq!(durable.transition.position(), at_limit_position);
    assert_eq!(durable.transition.value().ancestry_id(), at_limit_ancestry);
    assert_eq!(durable.transition.envelope_id(), at_limit_envelope);
    assert_eq!(
        durable.transition.canonical_envelope_bytes(),
        at_limit_envelope_bytes
    );
    assert_eq!(
        durable.transition.canonical_artifact_bytes(),
        at_limit_payload_bytes
    );
    drop(durable);
    let committed_image = fs::read(directory.journal()).unwrap();
    assert!(matches!(
        journal.commit_verified(above_limit),
        Err(FixedValidatorFinalityJournalErrorV0::RoundLimitExceeded {
            round,
            maximum,
        }) if round == fixture.limit.max_round() + 1 && maximum == fixture.limit.max_round()
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), committed_image);
    drop(journal);

    let reopened = fixture.open(&directory, committed_state).unwrap();
    let durable = reopened
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            committed_state,
        )
        .unwrap();
    assert_eq!(durable.transition.position(), at_limit_position);
    assert_eq!(durable.transition.value().ancestry_id(), at_limit_ancestry);
    assert_eq!(durable.transition.envelope_id(), at_limit_envelope);
    assert_eq!(
        durable.transition.canonical_envelope_bytes(),
        at_limit_envelope_bytes
    );
    assert_eq!(
        durable.transition.canonical_artifact_bytes(),
        at_limit_payload_bytes
    );
    drop(durable);
    drop(reopened);

    let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis = genesis_state_id(&prefix);
    let body = canonical_record_body(FINALIZE_RECORD, &replay_above_limit, 0).unwrap();
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let state = step_state_id(genesis, body_length_bytes, &body);
    let mut image = prefix.clone();
    image.extend_from_slice(&body_length_bytes);
    image.extend_from_slice(&body);
    image.extend_from_slice(state.as_bytes());
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(image.clone(), image),
            fixture.context,
            fixture.limit,
            prefix,
            vec![branch],
            state,
            None,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ReplayRoundLimitExceeded {
            round,
            maximum,
            ..
        }) if round == fixture.limit.max_round() + 1 && maximum == fixture.limit.max_round()
    ));
}
