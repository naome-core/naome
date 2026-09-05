use super::*;

#[test]
fn session_advances_only_with_externally_anchored_durable_finality() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-child-height");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let transition = fixture.owned_transition();
    let expected_ancestry = transition.value().ancestry_id();
    let mut finality = fixture.create_finality(&directory);
    let genesis_state = finality.state_id().unwrap();
    assert!(matches!(
        finality.commit_verified(transition).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    let finalized_state = finality.state_id().unwrap();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let before_wrong_anchor = fs::read(&finality_path).unwrap();
    assert!(matches!(
        finality.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            genesis_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
            required,
            acknowledged,
        }) if required == finalized_state && acknowledged == genesis_state
    ));
    assert_eq!(fs::read(&finality_path).unwrap(), before_wrong_anchor);
    let mut vote_journal = fixture.create(&directory);
    let vote_genesis_state = vote_journal.state_id().unwrap();
    let activated_vote_state = activate_proposal_authoring(&mut vote_journal);
    assert!(matches!(
        vote_journal.issue_signing_session(&round, activated_vote_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)
    ));
    let vote_state = vote_journal.bind_signing_lineage(&round).unwrap();
    assert_ne!(vote_state, vote_genesis_state);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    drop(vote_journal);
    drop(finality);

    let finality = fixture.open_finality(&directory, finalized_state);
    vote_journal = fixture.open(&directory, vote_state).unwrap();
    let mut session = vote_journal
        .issue_signing_session(&round, vote_state)
        .unwrap();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finalized_state,
        )
        .unwrap();

    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let height_state = prepared_height.state_id();
    let height_image = fs::read(&vote_path).unwrap();
    assert_ne!(height_image, vote_image);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(session.position(), round.position());
    let child = session
        .acknowledge_prepared_height_is_externally_durable(prepared_height, height_state)
        .unwrap();
    assert_eq!(child.verified_height(), Some(ConsensusHeight::new(1)));
    assert_eq!(child.ancestry_id(), expected_ancestry);
    assert_eq!(child.coordinate(), finality.head().unwrap().coordinate());
    assert_eq!(session.position().height(), ConsensusHeight::new(2));
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(session.locked_value(), None);
    assert_eq!(session.valid_value(), None);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&vote_path).unwrap(), height_image);
    assert_eq!(finality.state_id().unwrap(), finalized_state);
    assert_eq!(session.journal.state_id().unwrap(), height_state);

    let replay = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finalized_state,
        )
        .unwrap();
    let advanced_position = session.position();
    let vote_state = session.journal.state_id().unwrap();
    assert!(matches!(
        session.prepare_height_with_durable_finality(replay),
        Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(
            FixedValidatorLockStateError::HeightTransitionParentMismatch,
        ))
    ));
    assert_eq!(session.position(), advanced_position);
    assert_eq!(session.journal.state_id().unwrap(), vote_state);
    assert_eq!(finality.state_id().unwrap(), finalized_state);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&vote_path).unwrap(), height_image);

    let child_round = child.begin_round_zero().unwrap();
    let conflict = fixture.owned_transition_for(ZfcAxiom::Union);
    let mut finality = finality;
    let halt = match finality.commit_verified(conflict).unwrap() {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected terminal finality halt, got {other:?}"),
    };
    assert_eq!(finality.halt().unwrap(), Some(halt));
    drop(finality);
    drop(session);
    drop(vote_journal);

    let mut vote_journal = fixture.open(&directory, height_state).unwrap();
    let mut session = vote_journal
        .issue_signing_session(&child_round, height_state)
        .unwrap();
    assert_eq!(session.position(), child_round.position());
    assert_eq!(fs::read(&vote_path).unwrap(), height_image);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&child_round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let signed_state = session
        .sign_prepared_vote(acknowledgement)
        .unwrap()
        .state_id();
    drop(session);
    drop(vote_journal);
    let mut reopened = fixture.open(&directory, signed_state).unwrap();
    let resumed = issue_session(&mut reopened, &child_round);
    assert_eq!(resumed.position(), child_round.position());
}

#[test]
fn anchored_child_lineage_reopens_after_crash_before_live_height_acknowledgement() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("child-lineage-pre-ack-crash");
    let branch = fixture.branch();
    let parent_round = branch.begin_round_zero().unwrap();
    let expected_child_coordinate = fixture.owned_transition().into_branch().coordinate();

    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = finality.state_id().unwrap();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let finality_image = fs::read(&finality_path).unwrap();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &parent_round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let child_lineage_state = prepared_height.state_id();
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();

    drop(prepared_height);
    drop(session);
    drop(vote_journal);
    drop(parent_round);
    drop(branch);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);

    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected terminal finality halt, got {other:?}"),
    };
    assert_eq!(finality.halt().unwrap(), Some(halt));
    let halted_finality_image = fs::read(&finality_path).unwrap();
    assert_ne!(halted_finality_image, finality_image);
    let halted_finality_state = halt.state_id();
    drop(finality);

    let halted_finality = fixture.open_finality(&directory, halted_finality_state);
    let mut reopened = fixture.open(&directory, child_lineage_state).unwrap();
    let vote_image_before_recovery = fs::read(&vote_path).unwrap();
    assert!(matches!(
        halted_finality.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
    ));
    let recovery = reopened
        .acknowledge_signer_recovery_is_externally_durable(child_lineage_state)
        .unwrap();
    let recovered_branch = halted_finality
        .recover_anchored_signer_branch(recovery)
        .unwrap();
    let recovered = reopened
        .issue_recovered_signing_session(
            recovered_branch,
            child_lineage_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        )
        .unwrap();
    assert_eq!(recovered.branch().coordinate(), expected_child_coordinate);
    assert_eq!(
        recovered.session().position(),
        ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(0))
    );
    assert_eq!(
        recovered.session().phase(),
        FixedValidatorLockPhaseV0::Proposal
    );
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image_before_recovery);
    assert_eq!(fs::read(&finality_path).unwrap(), halted_finality_image);
    assert_eq!(halted_finality.state_id().unwrap(), halted_finality_state);
    assert_eq!(halted_finality.halt().unwrap(), Some(halt));

    let (child, mut session) = recovered.into_parts();
    let child_round = child.begin_round_zero().unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&child_round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(fs::read(finality_path).unwrap(), halted_finality_image);
}

#[test]
fn pending_height_advance_blocks_mutation_and_wrong_anchor_recovers_only_by_reopen() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("pending-height-misuse");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    let expected_child = fixture.owned_transition().into_branch();
    let child_round = expected_child.begin_round_zero().unwrap();
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
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let prepared_state = prepared_height.state_id();
    let position = session.position();
    let phase = session.phase();
    let locked = session.locked_value();
    let valid = session.valid_value().cloned();
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let prepared_image = fs::read(&vote_path).unwrap();

    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    assert!(matches!(
        session.advance_round(&round_one),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    let nil_precommit_quorum = certificate_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    assert!(matches!(
        session.advance_round_for_nil_precommit_quorum(&round, &nil_precommit_quorum),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    let higher_round_quorum = certificate_bytes(
        fixture.context,
        round_one.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    assert!(matches!(
        session.prepare_higher_round_quorum_advance(
            &round,
            &higher_round_quorum,
            round_one.position().round(),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    let second_durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    assert!(matches!(
        session.prepare_height_with_durable_finality(second_durable),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    assert_eq!(session.position(), position);
    assert_eq!(session.phase(), phase);
    assert_eq!(session.locked_value(), locked);
    assert_eq!(session.valid_value(), valid.as_ref());
    assert_eq!(fs::read(&vote_path).unwrap(), prepared_image);

    let wrong_state = FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([0x7c; 32]);
    assert_ne!(wrong_state, prepared_state);
    assert!(matches!(
        session.acknowledge_prepared_height_is_externally_durable(
            prepared_height,
            wrong_state,
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalHeightAnchorMismatch {
            prepared,
            acknowledged,
        }) if prepared == prepared_state && acknowledged == wrong_state
    ));
    assert_eq!(session.position(), position);
    assert_eq!(fs::read(&vote_path).unwrap(), prepared_image);
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingHeightAdvance {
            state_id,
        }) if state_id == prepared_state
    ));
    drop(session);
    drop(vote_journal);
    drop(finality);

    let mut reopened = fixture.open(&directory, prepared_state).unwrap();
    let resumed = reopened
        .issue_signing_session(&child_round, prepared_state)
        .unwrap();
    assert_eq!(resumed.position(), child_round.position());
}

#[test]
fn content_equivalent_finality_journal_can_supply_signer_handoff() {
    let fixture = Fixture::new(2);
    let primary_directory = TestDirectory::new("primary-finality-handoff");
    let equivalent_directory = TestDirectory::new("equivalent-finality-handoff");
    let vote_directory = TestDirectory::new("equivalent-finality-vote");
    let mut primary = fixture.create_finality(&primary_directory);
    let mut equivalent = fixture.create_finality(&equivalent_directory);
    let _ = primary.commit_verified(fixture.owned_transition()).unwrap();
    let _ = equivalent
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let state = primary.state_id().unwrap();
    assert_eq!(equivalent.state_id().unwrap(), state);
    assert_eq!(
        equivalent.head().unwrap().coordinate(),
        primary.head().unwrap().coordinate()
    );
    let primary_record = primary
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    let expected_envelope_id = primary_record.envelope_id();
    let expected_envelope = primary_record.canonical_envelope_bytes().to_vec();
    let expected_payload = primary_record.canonical_artifact_bytes().to_vec();
    drop(equivalent);
    drop(primary);

    let equivalent = fixture.open_finality(&equivalent_directory, state);
    let primary = fixture.open_finality(&primary_directory, state);
    let equivalent_record = equivalent
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    let primary_record = primary
        .finality_record(ConsensusHeight::new(1))
        .unwrap()
        .unwrap();
    assert_eq!(equivalent_record.envelope_id(), expected_envelope_id);
    assert_eq!(primary_record.envelope_id(), expected_envelope_id);
    assert_eq!(
        equivalent_record.canonical_envelope_bytes(),
        expected_envelope
    );
    assert_eq!(primary_record.canonical_envelope_bytes(), expected_envelope);
    assert_eq!(
        equivalent_record.canonical_artifact_bytes(),
        expected_payload
    );
    assert_eq!(primary_record.canonical_artifact_bytes(), expected_payload);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut vote_journal = fixture.create(&vote_directory);
    let mut session = issue_session(&mut vote_journal, &round);
    let durable = equivalent
        .acknowledge_signer_height_transition_is_externally_durable(ConsensusHeight::new(1), state)
        .unwrap();
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let prepared_height_state = prepared_height.state_id();
    let child = session
        .acknowledge_prepared_height_is_externally_durable(prepared_height, prepared_height_state)
        .unwrap();
    assert_eq!(child.coordinate(), equivalent.head().unwrap().coordinate());
    assert_eq!(child.coordinate(), primary.head().unwrap().coordinate());
}

#[test]
fn maximum_round_finality_transition_advances_the_exact_signer_child() {
    let fixture = Fixture::new(1);
    let directory = TestDirectory::new("maximum-round-signer-handoff");
    let mut finality = fixture.create_finality(&directory);
    let transition = fixture.owned_transition_for_round(ZfcAxiom::Pairing, 8);
    let expected_position = transition.position();
    let expected_envelope = transition.envelope_id();
    let expected_ancestry = transition.value().ancestry_id();
    let expected_envelope_bytes = transition.canonical_envelope_bytes().to_vec();
    let expected_payload_bytes = transition.canonical_artifact_bytes().to_vec();
    let _ = finality.commit_verified(transition).unwrap();
    let finality_state = finality.state_id().unwrap();
    drop(finality);
    let finality = fixture.open_finality(&directory, finality_state);
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    assert_eq!(durable.verified_transition().position(), expected_position);
    assert_eq!(
        durable.verified_transition().envelope_id(),
        expected_envelope
    );
    assert_eq!(
        durable.verified_transition().value().ancestry_id(),
        expected_ancestry
    );
    assert_eq!(
        durable.verified_transition().canonical_envelope_bytes(),
        expected_envelope_bytes
    );
    assert_eq!(
        durable.verified_transition().canonical_artifact_bytes(),
        expected_payload_bytes
    );

    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let prepared_state = prepared_height.state_id();
    let child = session
        .acknowledge_prepared_height_is_externally_durable(prepared_height, prepared_state)
        .unwrap();
    assert_eq!(child.coordinate(), finality.head().unwrap().coordinate());
    assert_eq!(child.ancestry_id(), expected_ancestry);
    assert_eq!(session.position().height(), ConsensusHeight::new(2));
}

#[test]
fn prepared_height_advance_is_bound_to_its_exact_signing_session() {
    let fixture = Fixture::new(2);
    let first_finality_directory = TestDirectory::new("height-seal-finality-first");
    let second_finality_directory = TestDirectory::new("height-seal-finality-second");
    let first_vote_directory = TestDirectory::new("height-seal-vote-first");
    let second_vote_directory = TestDirectory::new("height-seal-vote-second");
    let mut first_finality = fixture.create_finality(&first_finality_directory);
    let mut second_finality = fixture.create_finality(&second_finality_directory);
    let _ = first_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let _ = second_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = first_finality.state_id().unwrap();
    assert_eq!(second_finality.state_id().unwrap(), finality_state);
    let first_durable = first_finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    let second_durable = second_finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();

    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut first_vote = fixture.create(&first_vote_directory);
    let mut second_vote = fixture.create(&second_vote_directory);
    let mut first_session = issue_session(&mut first_vote, &round);
    let mut second_session = issue_session(&mut second_vote, &round);
    let first_prepared = first_session
        .prepare_height_with_durable_finality(first_durable)
        .unwrap();
    let second_prepared = second_session
        .prepare_height_with_durable_finality(second_durable)
        .unwrap();
    let prepared_state = first_prepared.state_id();
    assert_eq!(second_prepared.state_id(), prepared_state);
    let (_, second_vote_path) = keyed_paths(&second_vote_directory.0, fixture.signer()).unwrap();
    let second_image = fs::read(&second_vote_path).unwrap();

    assert!(matches!(
        second_session
            .acknowledge_prepared_height_is_externally_durable(first_prepared, prepared_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignHeightAdvance)
    ));
    assert_eq!(second_session.position(), round.position());
    assert_eq!(fs::read(&second_vote_path).unwrap(), second_image);
    let child = second_session
        .acknowledge_prepared_height_is_externally_durable(second_prepared, prepared_state)
        .unwrap();
    assert_eq!(second_session.position().height(), ConsensusHeight::new(2));
    assert_eq!(
        child.coordinate(),
        second_finality.head().unwrap().coordinate()
    );
}
