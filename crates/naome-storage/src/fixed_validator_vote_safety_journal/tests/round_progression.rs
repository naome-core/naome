use super::*;

#[cfg(unix)]
#[test]
fn anchored_higher_round_checkpoint_reopens_at_the_persisted_phase_floor() {
    let fixture = Fixture::new(2);
    let journal_directory = TestDirectory::new("anchored-checkpoint-vote-journal");
    let anchor_directory = TestDirectory::new("anchored-checkpoint-vote-anchor");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let _ = activate_anchored_proposal_authoring(&mut journal);
    let _ = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero).unwrap();
    let prepared = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    assert_eq!(
        &fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap()[184..192],
        &3_u64.to_be_bytes()
    );
    let target_round = session.acknowledge_prepared_higher_round(prepared).unwrap();
    assert_eq!(target_round.position(), target_position);
    assert_eq!(session.position(), target_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);
    drop(session);
    drop(journal);

    let mut reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.journal.core.record_sequence, 3);
    let resumed = reopened.issue_signing_session(&target_round).unwrap();
    assert_eq!(resumed.position(), target_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
}

#[test]
fn nil_precommit_quorum_advances_session_and_next_vote_reopens_at_exact_anchor() {
    let fixture = Fixture::new(3);
    let directory = TestDirectory::new("nil-precommit-round-advance");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let bound_image = fs::read(&journal_path).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();
    let certificate = certificate_bytes(
        fixture.context,
        round_zero.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );

    let round_one = session
        .advance_round_for_nil_precommit_quorum(&round_zero, &certificate)
        .unwrap();

    assert_eq!(
        round_one.position().height(),
        round_zero.position().height()
    );
    assert_eq!(
        round_one.position().round(),
        ConsensusRound::new(round_zero.position().round().value() + 1)
    );
    assert_eq!(session.position(), round_one.position());
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(session.locked_value(), None);
    assert_eq!(session.valid_value(), None);
    assert_eq!(fs::read(&journal_path).unwrap(), bound_image);

    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round_one, effect).unwrap());
    assert_eq!(prepared.position(), round_one.position());
    assert_eq!(prepared.role(), ConsensusVoteRole::Prevote);
    let prepared_image = fs::read(&journal_path).unwrap();
    assert_ne!(prepared_image, bound_image);
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    let completed_state = signed.state_id();
    assert_eq!(signed.position(), round_one.position());
    assert_eq!(signed.role(), ConsensusVoteRole::Prevote);
    assert_eq!(signed.target(), ConsensusVoteTarget::Nil);
    drop(session);

    assert_eq!(journal.state_id().unwrap(), completed_state);
    assert_eq!(
        journal
            .retained_signed_vote(round_one.position(), ConsensusVoteRole::Prevote)
            .unwrap(),
        Some(signed.clone())
    );
    drop(journal);

    let mut reopened = fixture.open(&directory, completed_state).unwrap();
    assert_eq!(
        reopened
            .retained_signed_vote(round_one.position(), ConsensusVoteRole::Prevote)
            .unwrap(),
        Some(signed)
    );
    let resumed = reopened
        .issue_signing_session(&round_one, completed_state)
        .unwrap();
    assert_eq!(resumed.position(), round_one.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(resumed.locked_value(), None);
    assert_eq!(resumed.valid_value(), None);
}

#[test]
fn pending_preparation_blocks_nil_precommit_quorum_advance_without_mutation() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("nil-precommit-pending-vote");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut journal, &round_zero);
    let _ = session.decide_prevote_without_proposal().unwrap();
    let effect = session.decide_precommit_without_quorum().unwrap();
    let _prepared = prepared(session.prepare_vote(&round_zero, effect).unwrap());
    let prepared_image = fs::read(&journal_path).unwrap();
    let before_position = session.position();
    let before_phase = session.phase();
    let before_lock = session.locked_value();
    assert_eq!(session.valid_value(), None);
    let certificate = certificate_bytes(
        fixture.context,
        round_zero.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let higher_certificate = certificate_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );

    assert!(matches!(
        session.advance_round_for_nil_precommit_quorum(&round_zero, &certificate),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position,
            role: ConsensusVoteRole::Precommit,
        }) if position == round_zero.position()
    ));
    assert!(matches!(
        session.prepare_higher_round_quorum_advance(
            &round_zero,
            &higher_certificate,
            ConsensusRound::new(2),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position,
            role: ConsensusVoteRole::Precommit,
        }) if position == round_zero.position()
    ));
    assert_eq!(session.position(), before_position);
    assert_eq!(session.phase(), before_phase);
    assert_eq!(session.locked_value(), before_lock);
    assert_eq!(session.valid_value(), None);
    assert_eq!(fs::read(&journal_path).unwrap(), prepared_image);
}

#[test]
fn higher_round_checkpoint_requires_exact_anchor_then_preserves_vote_capacity_and_reopen() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("higher-round-checkpoint-anchor");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(3));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let bound_image = fs::read(&journal_path).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();
    let before_position = session.position();
    let before_phase = session.phase();

    let checkpoint = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(3))
        .unwrap();
    let checkpoint_state = checkpoint.state_id();
    assert_eq!(
        checkpoint_state.as_bytes(),
        &[
            0x25, 0x93, 0x02, 0xfe, 0x57, 0x35, 0xc4, 0x3f, 0xf8, 0x05, 0xf5, 0x4c, 0x98, 0xc9,
            0x03, 0x61, 0x7c, 0xe8, 0x17, 0x15, 0x84, 0x1d, 0x7d, 0xdf, 0x7b, 0x61, 0x39, 0xd9,
            0x75, 0xd6, 0x71, 0x7a,
        ]
    );
    let checkpoint_image = fs::read(&journal_path).unwrap();
    assert_eq!(session.position(), before_position);
    assert_eq!(session.phase(), before_phase);
    assert_eq!(session.locked_value(), None);
    assert_eq!(session.valid_value(), None);
    assert_ne!(checkpoint_image, bound_image);

    let frame = &checkpoint_image[bound_image.len()..];
    let body_length = usize::try_from(u32::from_be_bytes(frame[..4].try_into().unwrap())).unwrap();
    assert_eq!(body_length, MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES);
    assert_eq!(
        ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH,
        606
    );
    assert_eq!(
        ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH,
        50_370
    );
    assert_eq!(MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES, 607);
    assert_eq!(MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES, 50_371);
    assert_eq!(
        body_length,
        1 + ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH
    );
    assert_eq!(frame[4], HIGHER_ROUND_CHECKPOINT_RECORD);
    assert_eq!(frame.len(), 4 + body_length + 32);
    assert_eq!(frame.len(), 643);
    assert_eq!(4 + MAX_HIGHER_ROUND_CHECKPOINT_BODY_BYTES + 32, 50_407);
    let body = &frame[4..4 + body_length];
    assert_eq!(
        checkpoint_state,
        step_state_id(
            bound,
            u32::try_from(body_length).unwrap().to_be_bytes(),
            body
        )
    );
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance {
            state_id,
        }) if state_id == checkpoint_state
    ));
    assert!(matches!(
        session.prepare_higher_round_quorum_advance(
            &round_zero,
            &certificate,
            ConsensusRound::new(3),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance {
            state_id,
        }) if state_id == checkpoint_state
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), checkpoint_image);

    let target_round = session
        .acknowledge_prepared_higher_round_is_externally_durable(checkpoint, checkpoint_state)
        .unwrap();
    assert_eq!(target_round.position(), target_position);
    assert_eq!(session.position(), target_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(fs::read(&journal_path).unwrap(), checkpoint_image);

    let effect = session.decide_precommit_without_quorum().unwrap();
    let vote = prepared(session.prepare_vote(&target_round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(vote, vote.state_id())
        .unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    let completed_state = signed.state_id();
    assert_eq!(signed.position(), target_position);
    assert_eq!(signed.role(), ConsensusVoteRole::Precommit);
    drop(session);
    drop(journal);

    let mut reopened = fixture.open(&directory, completed_state).unwrap();
    let resumed = reopened
        .issue_signing_session(&target_round, completed_state)
        .unwrap();
    assert_eq!(resumed.position(), target_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Precommit);
}

#[test]
fn higher_round_checkpoint_durably_preserves_nonempty_lock_and_valid_proof() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("higher-round-checkpoint-retained-lock");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let payload = proof_payload();
    let artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id)
        .unwrap();
    let value = round_zero.value_for_artifact_block(block);
    let root = value.proposal_signing_root();
    let mut proposal_bytes = value.to_canonical_bytes().to_vec();
    proposal_bytes.extend_from_slice(&authorization_bytes(
        fixture.context,
        round_zero.position(),
        root,
        &fixture.signing_key(),
    ));
    proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    let proposal = round_zero
        .decode_and_verify_proposal_control(&proposal_bytes, payload)
        .unwrap();
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();

    let prevote_effect = session.decide_prevote_for_proposal(&proposal).unwrap();
    let prevote = prepared(session.prepare_vote(&round_zero, prevote_effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prevote, prevote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    let proposal_quorum = certificate_bytes(
        fixture.context,
        round_zero.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let precommit_effect = session
        .decide_precommit_for_proposal_quorum(&round_zero, &proposal, &proposal_quorum)
        .unwrap();
    let precommit = prepared(session.prepare_vote(&round_zero, precommit_effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(precommit, precommit.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    let expected_lock = session.locked_value();
    let expected_valid = session.valid_value().cloned();
    assert!(expected_lock.is_some());
    assert!(expected_valid.is_some());

    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    session.advance_round(&round_one).unwrap();
    let target_position =
        ConsensusPosition::new(round_one.position().height(), ConsensusRound::new(3));
    let catchup_quorum = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let before_checkpoint = fs::read(&journal_path).unwrap();
    let checkpoint = session
        .prepare_higher_round_quorum_advance(&round_one, &catchup_quorum, ConsensusRound::new(3))
        .unwrap();
    let checkpoint_state = checkpoint.state_id();
    let checkpoint_image = fs::read(&journal_path).unwrap();
    let frame = &checkpoint_image[before_checkpoint.len()..];
    let body_length = usize::try_from(u32::from_be_bytes(frame[..4].try_into().unwrap())).unwrap();
    assert!(body_length > MIN_HIGHER_ROUND_CHECKPOINT_BODY_BYTES);
    let target_round = session
        .acknowledge_prepared_higher_round_is_externally_durable(checkpoint, checkpoint_state)
        .unwrap();
    assert_eq!(session.position(), target_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(session.locked_value(), expected_lock);
    assert_eq!(session.valid_value(), expected_valid.as_ref());
    drop(session);
    drop(journal);

    let mut reopened = fixture.open(&directory, checkpoint_state).unwrap();
    let resumed = reopened
        .issue_signing_session(&target_round, checkpoint_state)
        .unwrap();
    assert_eq!(resumed.position(), target_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(resumed.locked_value(), expected_lock);
    assert_eq!(resumed.valid_value(), expected_valid.as_ref());
    assert_eq!(fs::read(journal_path).unwrap(), checkpoint_image);
}

#[test]
fn wrong_higher_round_anchor_blocks_live_state_and_exact_reopen_rejects_lower_round() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("higher-round-checkpoint-wrong-anchor");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();
    let checkpoint = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let checkpoint_state = checkpoint.state_id();
    assert!(matches!(
        session.acknowledge_prepared_higher_round_is_externally_durable(checkpoint, bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalHigherRoundAnchorMismatch {
            prepared,
            acknowledged,
        }) if prepared == checkpoint_state && acknowledged == bound
    ));
    assert_eq!(session.position(), round_zero.position());
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance {
            state_id,
        }) if state_id == checkpoint_state
    ));
    drop(session);
    drop(journal);

    let mut reopened = fixture.open(&directory, checkpoint_state).unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&round_zero, checkpoint_state),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointReplay(
                FixedValidatorHigherRoundCheckpointErrorV0::State(
                    FixedValidatorVoteIntentError::RoundPositionMismatch { .. }
                )
            )
        )
    ));
    let target_round = round_zero.advance_round().unwrap().advance_round().unwrap();
    let resumed = reopened
        .issue_signing_session(&target_round, checkpoint_state)
        .unwrap();
    assert_eq!(resumed.position(), target_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Precommit);
}

#[test]
fn successive_higher_round_checkpoints_replay_only_the_latest_exact_state() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("successive-higher-round-checkpoints");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_two_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let round_four_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(4));
    let first_certificate = certificate_bytes(
        fixture.context,
        round_two_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let second_certificate = certificate_bytes(
        fixture.context,
        round_four_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();

    let first = session
        .prepare_higher_round_quorum_advance(
            &round_zero,
            &first_certificate,
            ConsensusRound::new(2),
        )
        .unwrap();
    let first_state = first.state_id();
    let round_two = session
        .acknowledge_prepared_higher_round_is_externally_durable(first, first_state)
        .unwrap();
    assert_eq!(session.position(), round_two_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);

    let second = session
        .prepare_higher_round_quorum_advance(
            &round_two,
            &second_certificate,
            ConsensusRound::new(4),
        )
        .unwrap();
    let second_state = second.state_id();
    assert_ne!(second_state, first_state);
    let round_four = session
        .acknowledge_prepared_higher_round_is_externally_durable(second, second_state)
        .unwrap();
    assert_eq!(session.position(), round_four_position);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Precommit);
    drop(session);
    drop(journal);

    assert!(matches!(
        fixture.open(&directory, first_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual,
        }) if expected == first_state && actual == second_state
    ));
    let mut reopened = fixture.open(&directory, second_state).unwrap();
    let resumed = reopened
        .issue_signing_session(&round_four, second_state)
        .unwrap();
    assert_eq!(resumed.position(), round_four_position);
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Precommit);
}

#[test]
fn higher_round_checkpoint_rejects_stale_sources_and_nonadvancing_vote_state() {
    let fixture = Fixture::new(2);
    let prefix = fixture.prefix();
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_two_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let round_four_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(4));
    let first_certificate = certificate_bytes(
        fixture.context,
        round_two_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let stale_source_certificate = certificate_bytes(
        fixture.context,
        round_four_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let first = state
        .prepare_higher_round_quorum_advance(
            &round_zero,
            &first_certificate,
            ConsensusRound::new(2),
        )
        .unwrap();
    let stale_source = state
        .prepare_higher_round_quorum_advance(
            &round_zero,
            &stale_source_certificate,
            ConsensusRound::new(4),
        )
        .unwrap();

    let mut core = fixture.scripted_core(ScriptedIo::new(prefix, None));
    let _ = core.bind_signing_lineage(&round_zero).unwrap();
    let checkpoint_state = core
        .append_higher_round_checkpoint(first.canonical_checkpoint_bytes())
        .unwrap();
    let checkpoint_image = core.file.volatile.get_ref().clone();
    let checkpoint_durable = core.file.durable.clone();
    assert!(matches!(
        core.append_higher_round_checkpoint(stale_source.canonical_checkpoint_bytes()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointSourceBehindState {
                current_position,
                current_phase: FixedValidatorLockPhaseV0::Prevote,
                source_position,
                source_phase: FixedValidatorLockPhaseV0::Proposal,
                ..
            }
        ) if current_position == round_two_position && source_position == round_zero.position()
    ));
    assert_eq!(core.state_id, checkpoint_state);
    assert_eq!(core.file.volatile.get_ref(), &checkpoint_image);
    assert_eq!(core.file.durable, checkpoint_durable);
    assert!(matches!(
        core.latest_current_lineage_state,
        Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
            if state_id == checkpoint_state
    ));

    let (same_state_vote, _) = fixture.round_two_nil_prevote_intents_with_distinct_state();
    assert!(matches!(
        core.prepare_vote(same_state_vote),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::VoteStateDoesNotFollowHigherRoundCheckpoint {
                checkpoint_position,
                checkpoint_phase: FixedValidatorLockPhaseV0::Prevote,
                vote_position,
                vote_phase: FixedValidatorLockPhaseV0::Prevote,
                ..
            }
        ) if checkpoint_position == round_two_position && vote_position == round_two_position
    ));
    assert_eq!(core.state_id, checkpoint_state);
    assert_eq!(core.file.volatile.get_ref(), &checkpoint_image);
    assert_eq!(core.file.durable, checkpoint_durable);
    assert!(matches!(
        core.latest_current_lineage_state,
        Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
            if state_id == checkpoint_state
    ));
}

#[test]
fn anchored_signer_recovery_derives_checkpoint_round_under_explicit_limit() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("higher-round-checkpoint-recovery-limit");
    let finality = fixture.create_finality(&directory);
    let finality_state = finality.state_id().unwrap();
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(3));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut journal);
    let bound = journal.bind_signing_lineage(&round_zero).unwrap();
    let mut session = journal.issue_signing_session(&round_zero, bound).unwrap();
    let prepared = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(3))
        .unwrap();
    let checkpoint_state = prepared.state_id();
    let _ = session
        .acknowledge_prepared_higher_round_is_externally_durable(prepared, checkpoint_state)
        .unwrap();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    drop(session);
    drop(journal);
    drop(round_zero);
    drop(branch);
    drop(finality);

    let finality = fixture.open_finality(&directory, finality_state);
    let mut reopened = fixture.open(&directory, checkpoint_state).unwrap();
    let recovery = reopened
        .acknowledge_signer_recovery_is_externally_durable(checkpoint_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    assert!(matches!(
        reopened.issue_recovered_signing_session(
            recovered_branch,
            checkpoint_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(2),
        ),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRoundLimitExceeded {
                required: 3,
                maximum: 2,
            }
        )
    ));
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);

    let recovery = reopened
        .acknowledge_signer_recovery_is_externally_durable(checkpoint_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    let recovered = reopened
        .issue_recovered_signing_session(
            recovered_branch,
            checkpoint_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(3),
        )
        .unwrap();
    assert_eq!(recovered.session().position(), target_position);
    assert_eq!(
        recovered.session().phase(),
        FixedValidatorLockPhaseV0::Precommit
    );
    assert_eq!(fs::read(finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(vote_path).unwrap(), vote_image);
}

#[test]
fn checkpoint_file_replay_defers_quorum_signature_authority_to_typed_restore() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let lineage_id = signing_lineage_id(
        round_zero.parent_coordinate(),
        round_zero.position().height(),
        fixture.signer(),
    );
    let lineage_body =
        signing_lineage_record(round_zero.position().height(), lineage_id, 0).unwrap();
    let mut image = prefix;
    let lineage_state = append_test_record(&mut image, genesis, &lineage_body);
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let transition = state
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let mut checkpoint = transition.canonical_checkpoint_bytes().to_vec();
    *checkpoint.last_mut().unwrap() ^= 0x80;
    let body = tagged_record(HIGHER_ROUND_CHECKPOINT_RECORD, &checkpoint, 0).unwrap();
    let checkpoint_state = append_test_record(&mut image, lineage_state, &body);

    let io = ScriptedIo::from_images(image.clone(), image.clone());
    let core = fixture.replay_scripted(io, checkpoint_state).unwrap();
    assert!(matches!(
        core.latest_current_lineage_state,
        Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
            if state_id == checkpoint_state
    ));
    let target_round = round_zero.advance_round().unwrap().advance_round().unwrap();
    assert!(matches!(
        core.recover_lock_state_for_round(&target_round),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::HigherRoundCheckpointReplay(
                FixedValidatorHigherRoundCheckpointErrorV0::Certificate(
                    QuorumCertificateVerifyError::InvalidSignature { .. }
                )
            )
        )
    ));
    assert_eq!(core.state_id, checkpoint_state);
    assert_eq!(core.file.volatile.get_ref(), &image);
}
