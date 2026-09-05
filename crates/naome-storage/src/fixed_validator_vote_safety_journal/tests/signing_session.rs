use super::*;

#[test]
fn signing_session_is_issued_once_even_after_drop_or_forget() {
    let fixture = Fixture::new(2);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();

    let dropped_directory = TestDirectory::new("session-drop");
    let mut dropped_journal = fixture.create(&dropped_directory);
    let session = issue_session(&mut dropped_journal, &round);
    assert_eq!(session.position(), round.position());
    drop(session);
    assert!(matches!(
        dropped_journal.issue_signing_session(&round, dropped_journal.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));

    let forgotten_directory = TestDirectory::new("session-forget");
    let mut forgotten_journal = fixture.create(&forgotten_directory);
    let session = issue_session(&mut forgotten_journal, &round);
    std::mem::forget(session);
    assert!(matches!(
        forgotten_journal.issue_signing_session(&round, forgotten_journal.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));
}

#[test]
fn session_requires_exact_external_prepare_acknowledgement_before_signing() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-anchor-ack");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut journal, &round);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect.clone()).unwrap());
    let prepared_bytes = fs::read(&journal_path).unwrap();
    assert!(matches!(
        session.prepare_vote(&round, effect).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(actual) if actual == prepared
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), prepared_bytes);
    let wrong_state = FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([0xa5; 32]);
    assert_ne!(wrong_state, prepared.state_id());

    assert!(matches!(
        session.acknowledge_prepared_vote_is_externally_durable(prepared, wrong_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalPrepareAnchorMismatch { .. })
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), prepared_bytes);
    assert!(matches!(
        session.decide_precommit_without_quorum(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. })
    ));

    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(signed.position(), round.position());
    assert_eq!(signed.role(), ConsensusVoteRole::Prevote);
    assert_ne!(fs::read(journal_path).unwrap(), prepared_bytes);
}

#[test]
fn external_prepare_acknowledgement_is_bound_to_its_signing_session() {
    let fixture = Fixture::new(2);
    let first_directory = TestDirectory::new("session-ack-first");
    let second_directory = TestDirectory::new("session-ack-second");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut first_journal = fixture.create(&first_directory);
    let mut second_journal = fixture.create(&second_directory);
    let mut first_session = issue_session(&mut first_journal, &round);
    let mut second_session = issue_session(&mut second_journal, &round);

    let first_effect = first_session.decide_prevote_without_proposal().unwrap();
    let first_prepared = prepared(first_session.prepare_vote(&round, first_effect).unwrap());
    let first_acknowledgement = first_session
        .acknowledge_prepared_vote_is_externally_durable(first_prepared, first_prepared.state_id())
        .unwrap();
    let second_effect = second_session.decide_prevote_without_proposal().unwrap();
    let second_prepared = prepared(second_session.prepare_vote(&round, second_effect).unwrap());
    assert_eq!(first_prepared.state_id(), second_prepared.state_id());
    let (_, second_path) = keyed_paths(&second_directory.0, fixture.signer()).unwrap();
    let second_prepared_bytes = fs::read(&second_path).unwrap();

    assert!(matches!(
        second_session.sign_prepared_vote(first_acknowledgement),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignPrepareAcknowledgement)
    ));
    assert_eq!(fs::read(second_path).unwrap(), second_prepared_bytes);
}

#[test]
fn same_post_state_effect_from_parallel_kernel_is_rejected_without_a_journal_write() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-parallel-kernel");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut journal, &round);
    let local_effect = session.decide_prevote_without_proposal().unwrap();

    let payload = proof_payload();
    let artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id)
        .unwrap();
    let value = round.value_for_artifact_block(block);
    let mut proposal_bytes = value.to_canonical_bytes().to_vec();
    proposal_bytes.extend_from_slice(&authorization_bytes(
        fixture.context,
        round.position(),
        value.proposal_signing_root(),
        &fixture.signing_key(),
    ));
    proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    let proposal = round
        .decode_and_verify_proposal_control(&proposal_bytes, payload)
        .unwrap();
    let mut fresh = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
    let foreign_effect = fresh.decide_prevote_for_proposal(&proposal).unwrap();
    assert_eq!(session.phase(), fresh.phase());
    assert_eq!(session.locked_value(), fresh.locked_value());
    assert_eq!(session.valid_value(), fresh.valid_value());
    assert_ne!(local_effect.target(), foreign_effect.target());
    let before = fs::read(&journal_path).unwrap();
    assert!(matches!(
        session.prepare_vote(&round, foreign_effect),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::SigningSessionIntent(
                FixedValidatorVoteIntentError::EffectLineageMismatch
            )
        )
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), before);

    assert!(matches!(
        session.prepare_vote(&round, local_effect).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::Prepared(_)
    ));
    assert_ne!(fs::read(journal_path).unwrap(), before);
}

#[test]
fn session_preserves_lineage_across_skipped_unsigned_roles_and_rounds() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-skipped-roles");
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let mut journal = fixture.create(&directory);
    let mut session = issue_session(&mut journal, &round_zero);

    let _ = session.decide_prevote_without_proposal().unwrap();
    let _ = session.decide_precommit_without_quorum().unwrap();
    session.advance_round(&round_one).unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round_one, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(signed.position(), round_one.position());
    assert_eq!(signed.role(), ConsensusVoteRole::Prevote);
}

#[test]
fn pending_vote_blocks_durable_finality_handoff_without_mutation() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("pending-blocks-finality-handoff");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = finality.state_id().unwrap();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();

    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &round);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
    let vote_state = prepared.state_id();
    let position = session.position();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    assert!(matches!(
        session.prepare_height_with_durable_finality(durable),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation {
            position: pending_position,
            role: ConsensusVoteRole::Prevote,
        }) if pending_position == round.position()
    ));
    assert_eq!(session.position(), position);
    assert_eq!(session.journal.state_id().unwrap(), vote_state);
    assert_eq!(finality.state_id().unwrap(), finality_state);
    assert_eq!(fs::read(finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(vote_path).unwrap(), vote_image);
}

#[test]
fn completed_replay_issues_one_exact_session_but_pending_replay_issues_none() {
    let fixture = Fixture::new(3);
    let completed_directory = TestDirectory::new("session-completed-replay");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&completed_directory);
    let completed_state = {
        let mut session = issue_session(&mut journal, &round);
        let effect = session.decide_prevote_without_proposal().unwrap();
        let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
        let acknowledgement = session
            .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
            .unwrap();
        session
            .sign_prepared_vote(acknowledgement)
            .unwrap()
            .state_id()
    };
    drop(journal);

    let mut reopened = fixture.open(&completed_directory, completed_state).unwrap();
    let resumed = issue_session(&mut reopened, &round);
    assert_eq!(resumed.position(), round.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
    drop(resumed);
    assert!(matches!(
        reopened.issue_signing_session(&round, reopened.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));

    let pending_directory = TestDirectory::new("session-pending-replay");
    let mut pending_journal = fixture.create(&pending_directory);
    let pending_state = {
        let mut session = issue_session(&mut pending_journal, &round);
        let effect = session.decide_prevote_without_proposal().unwrap();
        prepared(session.prepare_vote(&round, effect).unwrap()).state_id()
    };
    drop(pending_journal);
    let mut pending_reopen = fixture.open(&pending_directory, pending_state).unwrap();
    assert!(matches!(
        pending_reopen.issue_signing_session(&round, pending_reopen.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied { .. })
    ));
}

#[test]
fn terminal_halt_never_issues_a_signing_session() {
    let fixture = Fixture::new(3);
    let directory = TestDirectory::new("session-halt-replay");
    let nil = fixture.nil_prevote_intent();
    let conflict = fixture.proposal_prevote_intent();
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(nil).unwrap());
    let _ = journal.sign_prepared_vote(prepared).unwrap();
    let halt = match journal.prepare_vote(conflict).unwrap() {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected terminal halt, got {other:?}"),
    };
    drop(journal);

    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut reopened = fixture.open(&directory, halt.state_id()).unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&round, reopened.state_id().unwrap()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
}

#[test]
fn nonidentical_same_slot_durably_halts_and_disables_release() {
    let fixture = Fixture::new(3);
    let directory = TestDirectory::new("conflict");
    let mut journal = fixture.create(&directory);
    let nil_intent = fixture.nil_prevote_intent();
    let proposal_intent = fixture.proposal_prevote_intent();
    assert_eq!(nil_intent.position(), proposal_intent.position());
    assert_eq!(nil_intent.role(), proposal_intent.role());
    assert_ne!(nil_intent.target(), proposal_intent.target());
    let prepared = prepared(journal.prepare_vote(nil_intent).unwrap());
    let completed = signed(journal.sign_prepared_vote(prepared).unwrap());
    let halt = match journal.prepare_vote(proposal_intent).unwrap() {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected durable halt, got {other:?}"),
    };
    assert!(halt.changes_target());
    assert_eq!(journal.halt().unwrap(), Some(halt));
    assert!(matches!(
        journal.retained_signed_vote(completed.position(), completed.role()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
    let halt_state = halt.state_id();
    drop(journal);

    let reopened = fixture.open(&directory, halt_state).unwrap();
    assert_eq!(reopened.halt().unwrap(), Some(halt));
    assert!(matches!(
        reopened.retained_signed_vote(completed.position(), completed.role()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
}

#[test]
fn same_target_with_nonidentical_post_state_durably_halts() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("same-target-state-conflict");
    let (empty_state, retained_valid_state) =
        fixture.round_two_nil_prevote_intents_with_distinct_state();
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(empty_state).unwrap());
    let _ = journal.sign_prepared_vote(prepared).unwrap();
    let halt = match journal.prepare_vote(retained_valid_state).unwrap() {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected same-target state halt, got {other:?}"),
    };
    assert!(!halt.changes_target());
    assert_eq!(halt.retained_target(), halt.conflicting_target());
    assert_eq!(journal.halt().unwrap(), Some(halt));
}

#[test]
fn slot_order_is_strictly_monotonic_without_mandating_every_role() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("monotonic-lower");
    let (prevote, precommit) = fixture.round_zero_nil_intents();
    let mut journal = fixture.create(&directory);
    let precommit_prepared = prepared(journal.prepare_vote(precommit).unwrap());
    let _ = journal.sign_prepared_vote(precommit_prepared).unwrap();
    assert!(matches!(
        journal.prepare_vote(prevote),
        Err(FixedValidatorVoteSafetyJournalErrorV0::NonMonotonicSlot {
            previous_role: ConsensusVoteRole::Precommit,
            actual_role: ConsensusVoteRole::Prevote,
            ..
        })
    ));

    let skip_directory = TestDirectory::new("monotonic-skip-role");
    let mut skip_journal = fixture.create(&skip_directory);
    let prevote_zero = fixture.nil_prevote_intent();
    let prevote_one = fixture.round_one_nil_prevote_intent();
    let first = prepared(skip_journal.prepare_vote(prevote_zero).unwrap());
    let _ = skip_journal.sign_prepared_vote(first).unwrap();
    let later = prepared(skip_journal.prepare_vote(prevote_one).unwrap());
    assert_eq!(later.role(), ConsensusVoteRole::Prevote);
    assert_eq!(later.position().round().value(), 1);
}

#[test]
fn legacy_completed_history_can_add_one_exact_current_lineage_binding() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("legacy-lineage-binding");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let prepared = prepared(journal.prepare_vote(fixture.nil_prevote_intent()).unwrap());
    let completed = signed(journal.sign_prepared_vote(prepared).unwrap());
    let legacy_state = completed.state_id();
    let _ = activate_proposal_authoring(&mut journal);
    let bound_state = journal.bind_signing_lineage(&round).unwrap();
    assert_ne!(bound_state, legacy_state);
    drop(journal);

    assert!(matches!(
        fixture.open(&directory, legacy_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual,
        }) if expected == legacy_state && actual == bound_state
    ));
    let mut reopened = fixture.open(&directory, bound_state).unwrap();
    let session = reopened.issue_signing_session(&round, bound_state).unwrap();
    assert_eq!(session.position(), completed.position());
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Prevote);
}

#[test]
fn create_never_overwrites_and_locking_is_per_consensus_key() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("exclusive");
    let journal = fixture.create(&directory);
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::create(
            &directory.0,
            fixture.context,
            fixture.fixed_set_id(),
            fixture.signing_key(),
            fixture.replay_limit,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Locked)
    ));
    let other = FixedValidatorVoteSafetyJournalV0::create(
        &directory.0,
        fixture.context,
        fixture.fixed_set_id(),
        signing_key(0x99),
        fixture.replay_limit,
    )
    .unwrap();
    drop(other);
    drop(journal);
    assert!(matches!(
        FixedValidatorVoteSafetyJournalV0::create(
            &directory.0,
            fixture.context,
            fixture.fixed_set_id(),
            fixture.signing_key(),
            fixture.replay_limit,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Create { source })
            if source.kind() == io::ErrorKind::AlreadyExists
    ));
    assert_ne!(fixture.signer(), key(0x99));
}

#[test]
fn replay_limit_counts_unique_preparations_not_their_completions() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("replay-limit");
    let mut journal = fixture.create(&directory);
    let intent = fixture.nil_prevote_intent();
    let prepared = prepared(journal.prepare_vote(intent.clone()).unwrap());
    let _ = journal.sign_prepared_vote(prepared).unwrap();
    assert!(matches!(
        journal.prepare_vote(intent),
        Ok(FixedValidatorVotePrepareOutcomeV0::AlreadySigned(_))
    ));

    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let round_one = round_zero.advance_round().unwrap();
    let mut state =
        FixedValidatorLockStateV0::try_from_round_zero(&branch.begin_round_zero().unwrap())
            .unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let _ = state.decide_precommit_without_quorum().unwrap();
    state.advance_round(&round_one).unwrap();
    let effect = state.decide_prevote_without_proposal().unwrap();
    let later = state
        .prepare_vote_intent(&round_one, effect, fixture.signer())
        .unwrap();
    assert!(matches!(
        journal.prepare_vote(later),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PrepareLimitExceeded { maximum: 1 })
    ));
}
