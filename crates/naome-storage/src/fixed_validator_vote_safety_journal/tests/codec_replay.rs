use super::*;

#[test]
fn finality_stop_codec_has_an_independent_golden_and_strict_adversarial_replay() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("finality-stop-codec-source");
    let vote_directory = TestDirectory::new("finality-stop-codec-vote");
    let mut finality = fixture.create_finality(&finality_directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let mut body = Vec::with_capacity(169);
    body.push(0x05);
    body.extend_from_slice(halt.state_id().as_bytes());
    body.extend_from_slice(&halt.height().value().to_be_bytes());
    body.extend_from_slice(halt.first_ancestry().as_bytes());
    body.extend_from_slice(halt.first_envelope_id().as_bytes());
    body.extend_from_slice(halt.second_ancestry().as_bytes());
    body.extend_from_slice(halt.second_envelope_id().as_bytes());
    assert_eq!(body.len(), 169);
    let length = 169_u32.to_be_bytes();
    let expected_state = step_state_id(genesis, length, &body);
    assert_eq!(
        expected_state,
        FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([
            0xf1, 0x8b, 0xbd, 0x44, 0xc6, 0x81, 0x4c, 0xfa, 0x2e, 0xb8, 0xff, 0x4e, 0x53, 0xab,
            0x52, 0x09, 0xc0, 0xae, 0xa7, 0xc1, 0x2f, 0x9c, 0x81, 0xb2, 0x14, 0x4a, 0x77, 0x2e,
            0x7f, 0x24, 0xe3, 0x8f,
        ])
    );
    let mut expected_image = prefix.clone();
    expected_image.extend_from_slice(&length);
    expected_image.extend_from_slice(&body);
    expected_image.extend_from_slice(expected_state.as_bytes());
    assert_eq!(expected_image.len() - prefix.len(), 205);

    let mut vote_journal = fixture.create(&vote_directory);
    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match vote_journal
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    assert_eq!(stopped.vote_state_id(), expected_state);
    assert_eq!(fs::read(vote_path).unwrap(), expected_image);

    let mut wrong_width = prefix.clone();
    let mut wrong_width_body = vec![0_u8; 41];
    wrong_width_body[0] = 0x05;
    let wrong_width_state = append_test_record(&mut wrong_width, genesis, &wrong_width_body);
    let io = ScriptedIo::from_images(wrong_width.clone(), wrong_width);
    assert!(matches!(
        fixture.replay_scripted(io, wrong_width_state),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::InvalidFinalityConflictSignerStopLength {
                entry: 0,
                actual: 40,
            }
        )
    ));

    let mut zero_height = prefix.clone();
    let mut zero_height_body = body.clone();
    zero_height_body[33..41].fill(0);
    let zero_height_state = append_test_record(&mut zero_height, genesis, &zero_height_body);
    let io = ScriptedIo::from_images(zero_height.clone(), zero_height);
    assert!(matches!(
        fixture.replay_scripted(io, zero_height_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidFinalityConflictSignerStop { entry: 0 })
    ));

    let mut mutated_footer = expected_image.clone();
    *mutated_footer.last_mut().unwrap() ^= 0x01;
    let io = ScriptedIo::from_images(mutated_footer.clone(), mutated_footer);
    assert!(matches!(
        fixture.replay_scripted(io, expected_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch { entry: 0, .. })
    ));

    let mut post_stop = expected_image;
    let post_stop_state = append_test_record(&mut post_stop, expected_state, &body);
    let io = ScriptedIo::from_images(post_stop.clone(), post_stop);
    assert!(matches!(
        fixture.replay_scripted(io, post_stop_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordAfterHalt { .. })
    ));
}

#[test]
fn header_and_two_stage_record_framing_are_exact() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("framing");
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let prefix = fixture.prefix();
    assert_eq!(fs::read(&journal_path).unwrap(), prefix);
    assert_eq!(prefix.len(), JOURNAL_PREFIX_BYTES);

    let intent = fixture.nil_prevote_intent();
    let canonical_intent = intent.canonical_state_and_vote_intent_bytes().to_vec();
    let prepared = prepared(journal.prepare_vote(intent).unwrap());
    let prepare_body = tagged_record(PREPARE_RECORD, &canonical_intent, 0).unwrap();
    let prepare_length = u32::try_from(prepare_body.len()).unwrap().to_be_bytes();
    let prepare_state = step_state_id(genesis_state_id(&prefix), prepare_length, &prepare_body);
    assert_eq!(prepared.state_id(), prepare_state);
    let mut expected = prefix;
    expected.extend_from_slice(&prepare_length);
    expected.extend_from_slice(&prepare_body);
    expected.extend_from_slice(prepare_state.as_bytes());
    assert_eq!(fs::read(&journal_path).unwrap(), expected);

    let completed = signed(journal.sign_prepared_vote(prepared).unwrap());
    let completion_body = tagged_record(COMPLETE_RECORD, completed.canonical_bytes(), 0).unwrap();
    let completion_length = u32::try_from(completion_body.len()).unwrap().to_be_bytes();
    let completion_state = step_state_id(prepare_state, completion_length, &completion_body);
    assert_eq!(completed.state_id(), completion_state);
    expected.extend_from_slice(&completion_length);
    expected.extend_from_slice(&completion_body);
    expected.extend_from_slice(completion_state.as_bytes());
    assert_eq!(fs::read(journal_path).unwrap(), expected);
}

#[test]
fn signing_lineage_record_framing_and_state_identity_are_exact() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("lineage-framing");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let lineage_id = signing_lineage_id(
        round.parent_coordinate(),
        round.position().height(),
        fixture.signer(),
    );
    let body = signing_lineage_record(round.position().height(), lineage_id, 0).unwrap();
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let expected_state = step_state_id(genesis, length, &body);

    assert_eq!(body.len(), SIGNING_LINEAGE_BODY_BYTES);
    assert_eq!(body[0], SIGNING_LINEAGE_RECORD);
    assert_eq!(
        journal.bind_signing_lineage(&round).unwrap(),
        expected_state
    );
    let mut expected = prefix;
    expected.extend_from_slice(&length);
    expected.extend_from_slice(&body);
    expected.extend_from_slice(expected_state.as_bytes());
    assert_eq!(fs::read(journal_path).unwrap(), expected);
}

#[test]
fn complete_unanchored_suffix_and_corruption_fail_closed() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("anchor-corruption");
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(fixture.nil_prevote_intent()).unwrap());
    let prepared_state = prepared.state_id();
    let completed = signed(journal.sign_prepared_vote(prepared).unwrap());
    let completed_state = completed.state_id();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(journal);

    assert!(matches!(
        fixture.open(&directory, prepared_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual
        }) if expected == prepared_state && actual == completed_state
    ));
    let mut image = fs::read(&journal_path).unwrap();
    let prepare_payload_offset = JOURNAL_PREFIX_BYTES + 4 + 1;
    image[prepare_payload_offset] ^= 0x80;
    fs::write(&journal_path, image).unwrap();
    assert!(matches!(
        fixture.open(&directory, completed_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch { .. })
    ));
}

#[test]
fn header_replay_rejects_wrong_context_set_limit_and_key_path() {
    let fixture = Fixture::new(3);
    let directory = TestDirectory::new("wrong-header");
    let journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    drop(journal);

    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x43; 32]),
        fixture.context.protocol_version(),
    );
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            wrong_context,
            fixture.fixed_set_id(),
            fixture.signing_key(),
            fixture.replay_limit,
            genesis,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::HeaderMismatch)
    ));
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            fixture.context,
            fixture.alternate_fixed_set_id(),
            fixture.signing_key(),
            fixture.replay_limit,
            genesis,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::HeaderMismatch)
    ));
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            fixture.context,
            fixture.fixed_set_id(),
            fixture.signing_key(),
            FixedValidatorVoteSafetyReplayLimitV0::new(4).unwrap(),
            genesis,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::HeaderMismatch)
    ));
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::open_verified(
            &directory.0,
            fixture.context,
            fixture.fixed_set_id(),
            signing_key(0x99),
            fixture.replay_limit,
            genesis,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Open { source })
            if source.kind() == io::ErrorKind::NotFound
    ));
}

#[test]
fn replay_rejects_duplicate_reordered_mismatched_and_post_halt_records() {
    let fixture = Fixture::new(4);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let nil = fixture.nil_prevote_intent();
    let proposal = fixture.proposal_prevote_intent();
    let nil_prepare = tagged_record(
        PREPARE_RECORD,
        nil.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let proposal_halt = tagged_record(
        CONFLICT_HALT_RECORD,
        proposal.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let nil_complete = tagged_record(
        COMPLETE_RECORD,
        &signed_vote_bytes(&nil, &fixture.signing_key()),
        0,
    )
    .unwrap();
    let proposal_complete = tagged_record(
        COMPLETE_RECORD,
        &signed_vote_bytes(&proposal, &fixture.signing_key()),
        0,
    )
    .unwrap();

    let mut completion_first = prefix.clone();
    let completion_first_state = append_test_record(&mut completion_first, genesis, &nil_complete);
    let io = ScriptedIo::from_images(completion_first.clone(), completion_first);
    assert!(matches!(
        fixture.replay_scripted(io, completion_first_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::CompletionWithoutPrepare { entry: 0 })
    ));

    let mut duplicate = prefix.clone();
    let state = append_test_record(&mut duplicate, genesis, &nil_prepare);
    let state = append_test_record(&mut duplicate, state, &nil_complete);
    let duplicate_state = append_test_record(&mut duplicate, state, &nil_prepare);
    let io = ScriptedIo::from_images(duplicate.clone(), duplicate);
    assert!(matches!(
        fixture.replay_scripted(io, duplicate_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::DuplicatePrepare { entry: 2 })
    ));

    let mut mismatched = prefix.clone();
    let state = append_test_record(&mut mismatched, genesis, &nil_prepare);
    let mismatched_state = append_test_record(&mut mismatched, state, &proposal_complete);
    let io = ScriptedIo::from_images(mismatched.clone(), mismatched);
    assert!(matches!(
        fixture.replay_scripted(io, mismatched_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::CompletionMismatch {
            entry: 1,
            reason: FixedValidatorVoteCompletionMismatchV0::Target,
        })
    ));

    let mut post_halt = prefix;
    let state = append_test_record(&mut post_halt, genesis, &nil_prepare);
    let state = append_test_record(&mut post_halt, state, &nil_complete);
    let state = append_test_record(&mut post_halt, state, &proposal_halt);
    let post_halt_state = append_test_record(&mut post_halt, state, &proposal_complete);
    let io = ScriptedIo::from_images(post_halt.clone(), post_halt);
    assert!(matches!(
        fixture.replay_scripted(io, post_halt_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordAfterHalt { .. })
    ));
}

#[test]
fn replay_rejects_proposal_conflict_while_vote_preparation_is_pending() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("proposal-conflict-during-pending-vote");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let lineage = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round, lineage).unwrap();

    let (retained_block, retained_payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let retained = prepared_proposal(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: retained_block,
                    canonical_artifact_bytes: retained_payload,
                },
            )
            .unwrap(),
    );
    let retained = session
        .acknowledge_prepared_proposal_is_externally_durable(retained, retained.state_id())
        .unwrap();
    let _ = session.sign_prepared_proposal(retained).unwrap();

    let vote_effect = session.decide_prevote_without_proposal().unwrap();
    let pending_vote = prepared(session.prepare_vote(&round, vote_effect).unwrap());
    let pending_state = pending_vote.state_id();
    let entry = session.journal.core.record_sequence;

    let (conflicting_block, conflicting_payload) = fixture.proposal_candidate_for(ZfcAxiom::Union);
    let conflicting_state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
    let conflicting = conflicting_state
        .prepare_proposal_intent(
            &round,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block: conflicting_block,
                canonical_artifact_bytes: conflicting_payload,
            },
            fixture.signer(),
        )
        .unwrap();
    let live_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.journal.prepare_proposal(conflicting.clone()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position,
            role: ConsensusVoteRole::Prevote,
        }) if position == round.position()
    ));
    assert_eq!(session.journal.state_id().unwrap(), live_state);
    let halt_record = tagged_record(
        PROPOSAL_CONFLICT_HALT_RECORD,
        conflicting.canonical_intent_bytes(),
        entry,
    )
    .unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(session);
    drop(journal);

    let mut image = fs::read(journal_path).unwrap();
    let expected = append_test_record(&mut image, pending_state, &halt_record);
    let io = ScriptedIo::from_images(image.clone(), image);
    assert!(matches!(
        fixture.replay_scripted(io, expected),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalConflictHalt {
            entry: actual,
        }) if actual == entry
    ));
}

#[test]
fn replay_rejects_vote_conflict_while_proposal_preparation_is_pending() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("vote-conflict-during-pending-proposal");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let lineage = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, lineage).unwrap();

    let prevote_effect = session.decide_prevote_without_proposal().unwrap();
    let prevote = prepared(session.prepare_vote(&round_zero, prevote_effect).unwrap());
    let prevote = session
        .acknowledge_prepared_vote_is_externally_durable(prevote, prevote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(prevote).unwrap();
    let precommit_effect = session.decide_precommit_without_quorum().unwrap();
    let precommit = prepared(session.prepare_vote(&round_zero, precommit_effect).unwrap());
    let precommit = session
        .acknowledge_prepared_vote_is_externally_durable(precommit, precommit.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(precommit).unwrap();
    session.advance_round(&round_one).unwrap();

    let (proposal_block, proposal_payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let pending_proposal = prepared_proposal(
        session
            .prepare_proposal(
                &round_one,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: proposal_block,
                    canonical_artifact_bytes: proposal_payload,
                },
            )
            .unwrap(),
    );
    let pending_state = pending_proposal.state_id();
    let entry = session.journal.core.record_sequence;
    let conflicting_vote = fixture.proposal_prevote_intent();
    let live_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.journal.prepare_vote(conflicting_vote.clone()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation {
                position,
            }
        ) if position == round_one.position()
    ));
    assert_eq!(session.journal.state_id().unwrap(), live_state);
    let halt_record = tagged_record(
        CONFLICT_HALT_RECORD,
        conflicting_vote.canonical_state_and_vote_intent_bytes(),
        entry,
    )
    .unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(session);
    drop(journal);

    let mut image = fs::read(journal_path).unwrap();
    let expected = append_test_record(&mut image, pending_state, &halt_record);
    let io = ScriptedIo::from_images(image.clone(), image);
    assert!(matches!(
        fixture.replay_scripted(io, expected),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt {
            entry: actual,
        }) if actual == entry
    ));
}

#[test]
fn replay_rejects_proposal_conflict_for_older_slot_while_later_proposal_is_pending() {
    let fixture = Fixture::new(6);
    let directory = TestDirectory::new("older-proposal-conflict-during-later-proposal");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let lineage = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, lineage).unwrap();

    let (retained_block, retained_payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let retained = prepared_proposal(
        session
            .prepare_proposal(
                &round_zero,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: retained_block,
                    canonical_artifact_bytes: retained_payload,
                },
            )
            .unwrap(),
    );
    let retained = session
        .acknowledge_prepared_proposal_is_externally_durable(retained, retained.state_id())
        .unwrap();
    let _ = session.sign_prepared_proposal(retained).unwrap();

    let prevote_effect = session.decide_prevote_without_proposal().unwrap();
    let prevote = prepared(session.prepare_vote(&round_zero, prevote_effect).unwrap());
    let prevote = session
        .acknowledge_prepared_vote_is_externally_durable(prevote, prevote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(prevote).unwrap();
    let precommit_effect = session.decide_precommit_without_quorum().unwrap();
    let precommit = prepared(session.prepare_vote(&round_zero, precommit_effect).unwrap());
    let precommit = session
        .acknowledge_prepared_vote_is_externally_durable(precommit, precommit.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(precommit).unwrap();
    session.advance_round(&round_one).unwrap();

    let (later_block, later_payload) = fixture.proposal_candidate_for(ZfcAxiom::Union);
    let pending = prepared_proposal(
        session
            .prepare_proposal(
                &round_one,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: later_block,
                    canonical_artifact_bytes: later_payload.clone(),
                },
            )
            .unwrap(),
    );
    let pending_state = pending.state_id();
    let entry = session.journal.core.record_sequence;

    let conflicting_state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let conflicting = conflicting_state
        .prepare_proposal_intent(
            &round_zero,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block: later_block,
                canonical_artifact_bytes: later_payload,
            },
            fixture.signer(),
        )
        .unwrap();
    let live_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.journal.prepare_proposal(conflicting.clone()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::PendingProposalPreparation {
                position,
            }
        ) if position == round_one.position()
    ));
    assert_eq!(session.journal.state_id().unwrap(), live_state);
    let halt_record = tagged_record(
        PROPOSAL_CONFLICT_HALT_RECORD,
        conflicting.canonical_intent_bytes(),
        entry,
    )
    .unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(session);
    drop(journal);

    let mut image = fs::read(journal_path).unwrap();
    let expected = append_test_record(&mut image, pending_state, &halt_record);
    let io = ScriptedIo::from_images(image.clone(), image);
    assert!(matches!(
        fixture.replay_scripted(io, expected),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidProposalConflictHalt {
            entry: actual,
        }) if actual == entry
    ));
}

#[test]
fn replay_rejects_vote_conflict_for_older_slot_while_later_vote_is_pending() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("older-vote-conflict-during-later-vote");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let lineage = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round, lineage).unwrap();

    let prevote_effect = session.decide_prevote_without_proposal().unwrap();
    let prevote = prepared(session.prepare_vote(&round, prevote_effect).unwrap());
    let prevote = session
        .acknowledge_prepared_vote_is_externally_durable(prevote, prevote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(prevote).unwrap();

    let precommit_effect = session.decide_precommit_without_quorum().unwrap();
    let pending = prepared(session.prepare_vote(&round, precommit_effect).unwrap());
    let pending_state = pending.state_id();
    let entry = session.journal.core.record_sequence;
    let conflicting_vote = fixture.proposal_prevote_intent();
    let live_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.journal.prepare_vote(conflicting_vote.clone()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position,
            role: ConsensusVoteRole::Precommit,
        }) if position == round.position()
    ));
    assert_eq!(session.journal.state_id().unwrap(), live_state);
    let halt_record = tagged_record(
        CONFLICT_HALT_RECORD,
        conflicting_vote.canonical_state_and_vote_intent_bytes(),
        entry,
    )
    .unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(session);
    drop(journal);

    let mut image = fs::read(journal_path).unwrap();
    let expected = append_test_record(&mut image, pending_state, &halt_record);
    let io = ScriptedIo::from_images(image.clone(), image);
    assert!(matches!(
        fixture.replay_scripted(io, expected),
        Err(FixedValidatorVoteSafetyJournalErrorV0::InvalidConflictHalt {
            entry: actual,
        }) if actual == entry
    ));
}

#[test]
fn replay_rejects_invalid_signing_lineage_order_and_votes_outside_it() {
    let fixture = Fixture::new(4);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let first_id = signing_lineage_id(
        round.parent_coordinate(),
        round.position().height(),
        fixture.signer(),
    );
    let first_lineage = signing_lineage_record(round.position().height(), first_id, 0).unwrap();
    let child = fixture.owned_transition().into_branch();
    let child_round = child.begin_round_zero().unwrap();
    let child_id = signing_lineage_id(
        child_round.parent_coordinate(),
        child_round.position().height(),
        fixture.signer(),
    );
    let child_lineage =
        signing_lineage_record(child_round.position().height(), child_id, 1).unwrap();

    let mut duplicate = prefix.clone();
    let state = append_test_record(&mut duplicate, genesis, &first_lineage);
    let duplicate_state = append_test_record(&mut duplicate, state, &first_lineage);
    let io = ScriptedIo::from_images(duplicate.clone(), duplicate);
    assert!(matches!(
        fixture.replay_scripted(io, duplicate_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
            entry: 1,
            expected,
            actual,
        }) if expected == ConsensusHeight::new(2) && actual == ConsensusHeight::new(1)
    ));

    let skipped_lineage = signing_lineage_record(ConsensusHeight::new(3), child_id, 1).unwrap();
    let mut skipped = prefix.clone();
    let state = append_test_record(&mut skipped, genesis, &first_lineage);
    let skipped_state = append_test_record(&mut skipped, state, &skipped_lineage);
    let io = ScriptedIo::from_images(skipped.clone(), skipped);
    assert!(matches!(
        fixture.replay_scripted(io, skipped_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::NonSequentialSigningLineage {
            entry: 1,
            expected,
            actual,
        }) if expected == ConsensusHeight::new(2) && actual == ConsensusHeight::new(3)
    ));

    let prepare = tagged_record(
        PREPARE_RECORD,
        fixture
            .nil_prevote_intent()
            .canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let mut pending = prefix.clone();
    let state = append_test_record(&mut pending, genesis, &first_lineage);
    let state = append_test_record(&mut pending, state, &prepare);
    let pending_state = append_test_record(&mut pending, state, &child_lineage);
    let io = ScriptedIo::from_images(pending.clone(), pending);
    assert!(matches!(
        fixture.replay_scripted(io, pending_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageWhilePending { entry: 2 })
    ));

    let mut outside = prefix;
    let state = append_test_record(&mut outside, genesis, &child_lineage);
    let outside_state = append_test_record(&mut outside, state, &prepare);
    let io = ScriptedIo::from_images(outside.clone(), outside);
    assert!(matches!(
        fixture.replay_scripted(io, outside_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::VoteOutsideSigningLineage {
            entry: 1,
            lineage_height,
            vote_height,
        }) if lineage_height == ConsensusHeight::new(2)
            && vote_height == ConsensusHeight::new(1)
    ));

    let nil = fixture.nil_prevote_intent();
    let proposal = fixture.proposal_prevote_intent();
    let nil_prepare = tagged_record(
        PREPARE_RECORD,
        nil.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let nil_complete = tagged_record(
        COMPLETE_RECORD,
        &signed_vote_bytes(&nil, &fixture.signing_key()),
        0,
    )
    .unwrap();
    let proposal_halt = tagged_record(
        CONFLICT_HALT_RECORD,
        proposal.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let mut post_halt = fixture.prefix();
    let state = append_test_record(&mut post_halt, genesis, &first_lineage);
    let state = append_test_record(&mut post_halt, state, &nil_prepare);
    let state = append_test_record(&mut post_halt, state, &nil_complete);
    let state = append_test_record(&mut post_halt, state, &proposal_halt);
    let post_halt_state = append_test_record(&mut post_halt, state, &child_lineage);
    let io = ScriptedIo::from_images(post_halt.clone(), post_halt);
    assert!(matches!(
        fixture.replay_scripted(io, post_halt_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordAfterHalt { .. })
    ));
}

#[test]
fn incomplete_tail_is_recovered_only_after_anchor_equality() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("tail-recovery");
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(fixture.nil_prevote_intent()).unwrap());
    let prepared_state = prepared.state_id();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    drop(journal);
    let anchored = fs::read(&journal_path).unwrap();
    let mut incomplete = anchored.clone();
    incomplete.extend_from_slice(&u32::try_from(MIN_RECORD_BODY_BYTES).unwrap().to_be_bytes());
    incomplete.extend_from_slice(&[COMPLETE_RECORD, 0xaa, 0xbb]);
    fs::write(&journal_path, incomplete).unwrap();

    assert!(matches!(
        fixture.open(
            &directory,
            FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([0xee; 32])
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    assert_ne!(fs::read(&journal_path).unwrap(), anchored);
    let reopened = fixture.open(&directory, prepared_state).unwrap();
    assert_eq!(fs::read(journal_path).unwrap(), anchored);
    assert!(reopened.pending_vote().unwrap().is_some());
}
