use super::*;

#[cfg(unix)]
#[test]
fn anchored_height_handoff_and_finality_stop_advance_both_authority_files() {
    let fixture = Fixture::new(2);
    let finality_directory = TestDirectory::new("anchored-handoff-finality-journal");
    let finality_anchor_directory = TestDirectory::new("anchored-handoff-finality-anchor");
    let vote_directory = TestDirectory::new("anchored-handoff-vote-journal");
    let vote_anchor_directory = TestDirectory::new("anchored-handoff-vote-anchor");
    let mut finality = crate::FixedValidatorAnchoredFinalityJournalV0::create(
        &finality_directory.0,
        &finality_anchor_directory.0,
        fixture.definition,
        fixture.context,
        &fixture.entries(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
    )
    .unwrap();
    let mut vote = fixture.create_anchored(&vote_directory, &vote_anchor_directory);
    let parent = fixture.branch();
    let round = parent.begin_round_zero().unwrap();
    let _ = activate_anchored_proposal_authoring(&mut vote);
    let _ = vote.bind_signing_lineage(&round).unwrap();
    let mut session = vote.issue_signing_session(&round).unwrap();

    let first = fixture.owned_transition_for(ZfcAxiom::Pairing);
    assert!(matches!(
        finality.commit_verified(first).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
    ));
    assert_eq!(
        &fs::read(
            finality_anchor_directory
                .0
                .join("fixed-validator-finality.anchor")
        )
        .unwrap()[149..157],
        &1_u64.to_be_bytes()
    );
    let handoff = finality
        .acknowledge_signer_height_transition(ConsensusHeight::new(1))
        .unwrap();
    let prepared_height = session
        .prepare_height_with_durable_finality(handoff)
        .unwrap();
    assert_eq!(
        &fs::read(vote_anchor_directory.vote_anchor(fixture.signer())).unwrap()[184..192],
        &3_u64.to_be_bytes()
    );
    let child = session
        .acknowledge_prepared_height(prepared_height)
        .unwrap();
    assert_eq!(child.verified_height(), Some(ConsensusHeight::new(1)));

    let conflict = fixture.owned_transition_for(ZfcAxiom::Union);
    assert!(matches!(
        finality.commit_verified(conflict).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Halted(_)
    ));
    assert_eq!(
        &fs::read(
            finality_anchor_directory
                .0
                .join("fixed-validator-finality.anchor")
        )
        .unwrap()[149..157],
        &2_u64.to_be_bytes()
    );
    let stop = finality.acknowledge_signer_stop().unwrap();
    let _ = session.stop_after_durable_finality_conflict(stop).unwrap();
    assert_eq!(
        &fs::read(vote_anchor_directory.vote_anchor(fixture.signer())).unwrap()[184..192],
        &4_u64.to_be_bytes()
    );
    drop(session);
    assert_eq!(vote.journal.core.record_sequence, 4);
    assert!(vote.finality_conflict_stop().unwrap().is_some());
}

#[test]
fn durable_finality_conflict_preempts_live_prepared_vote_before_key_use() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("finality-stop-live-prepared");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut finality = fixture.create_finality(&directory);
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

    let mut vote_journal = fixture.create(&directory);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut vote_journal, &round);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared, prepared.state_id())
        .unwrap();
    let pre_stop_image = fs::read(&vote_path).unwrap();

    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match session
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    assert_eq!(stopped.finality_state_id(), halt.state_id());
    assert_eq!(stopped.height(), halt.height());
    assert_eq!(stopped.kind(), halt.kind());
    assert_eq!(stopped.first_ancestry(), halt.first_ancestry());
    assert_eq!(stopped.second_ancestry(), halt.second_ancestry());
    let stopped_image = fs::read(&vote_path).unwrap();
    assert_ne!(stopped_image, pre_stop_image);

    assert!(matches!(
        session.sign_prepared_vote(acknowledgement),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert_eq!(session.journal.state_id().unwrap(), stopped.vote_state_id());
    assert_eq!(
        session.journal.finality_conflict_stop().unwrap(),
        Some(stopped)
    );
    assert_eq!(fs::read(&vote_path).unwrap(), stopped_image);
}

#[test]
fn durable_finality_conflict_preempts_pending_higher_round_checkpoint() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("finality-stop-pending-higher-round");
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
    let mut finality = fixture.create_finality(&directory);
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

    let mut vote_journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut vote_journal);
    let bound = vote_journal.bind_signing_lineage(&round_zero).unwrap();
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let mut session = vote_journal
        .issue_signing_session(&round_zero, bound)
        .unwrap();
    let checkpoint = session
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let checkpoint_state = checkpoint.state_id();
    let checkpoint_image = fs::read(&vote_path).unwrap();
    assert_eq!(session.journal.state_id().unwrap(), checkpoint_state);

    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match session
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    let stopped_image = fs::read(&vote_path).unwrap();
    assert_ne!(stopped_image, checkpoint_image);
    assert_ne!(stopped.vote_state_id(), checkpoint_state);

    assert!(matches!(
        session.acknowledge_prepared_higher_round_is_externally_durable(
            checkpoint,
            checkpoint_state,
        ),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert_eq!(
        session.journal.finality_conflict_stop().unwrap(),
        Some(stopped)
    );
    drop(session);
    drop(vote_journal);

    assert!(matches!(
        fixture.open(&directory, checkpoint_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual,
        }) if expected == checkpoint_state && actual == stopped.vote_state_id()
    ));
    let mut reopened = fixture.open(&directory, stopped.vote_state_id()).unwrap();
    assert_eq!(reopened.finality_conflict_stop().unwrap(), Some(stopped));
    let target_round = branch
        .begin_round_zero()
        .unwrap()
        .advance_round()
        .unwrap()
        .advance_round()
        .unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&target_round, stopped.vote_state_id()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert_eq!(fs::read(vote_path).unwrap(), stopped_image);
}

#[test]
fn exact_restart_preserves_finality_stop_and_exact_repeat_is_no_write() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("finality-stop-restart-repeat");
    let alternate_finality_directory =
        TestDirectory::new("finality-stop-restart-alternate-conflict");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut finality = fixture.create_finality(&directory);
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

    let mut vote_journal = fixture.create(&directory);
    let prepared = prepared(
        vote_journal
            .prepare_vote(fixture.nil_prevote_intent())
            .unwrap(),
    );
    let signed = signed(vote_journal.sign_prepared_vote(prepared).unwrap());
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
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let stopped_image = fs::read(&vote_path).unwrap();
    drop(vote_journal);
    drop(finality);

    let finality = fixture.open_finality(&directory, halt.state_id());
    let mut reopened = fixture.open(&directory, stopped.vote_state_id()).unwrap();
    assert_eq!(reopened.finality_conflict_stop().unwrap(), Some(stopped));
    assert!(matches!(
        reopened.issue_signing_session(&round, stopped.vote_state_id()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert!(matches!(
        reopened.retained_signed_vote(signed.position(), signed.role()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert!(matches!(
        reopened.acknowledge_signer_recovery_is_externally_durable(stopped.vote_state_id()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));

    let repeated_conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    assert!(matches!(
        reopened
            .stop_after_durable_finality_conflict(repeated_conflict)
            .unwrap(),
        FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(existing)
            if existing == stopped
    ));
    assert_eq!(reopened.state_id().unwrap(), stopped.vote_state_id());
    assert_eq!(fs::read(&vote_path).unwrap(), stopped_image);

    let mut alternate_finality = fixture.create_finality(&alternate_finality_directory);
    let _ = alternate_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let alternate_halt = match alternate_finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::PowerSet))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected alternate finality halt, got {other:?}"),
    };
    let alternate_conflict = alternate_finality
        .acknowledge_signer_stop_is_externally_durable(alternate_halt.state_id())
        .unwrap();
    assert!(matches!(
        reopened.stop_after_durable_finality_conflict(alternate_conflict),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::ConflictingFinalityConflictSignerStop {
                retained_height,
                incoming_height,
            }
        ) if retained_height == halt.height() && incoming_height == alternate_halt.height()
    ));
    assert_eq!(reopened.state_id().unwrap(), stopped.vote_state_id());
    assert_eq!(fs::read(vote_path).unwrap(), stopped_image);
}

#[test]
fn unavailable_or_mismatched_finality_stop_authority_never_changes_vote_state() {
    let fixture = Fixture::new(2);
    let finality_directory = TestDirectory::new("finality-stop-mismatch-source");
    let primary_directory = TestDirectory::new("finality-stop-mismatch-primary");
    let context_directory = TestDirectory::new("finality-stop-mismatch-context");
    let set_directory = TestDirectory::new("finality-stop-mismatch-set");
    let mut finality = fixture.create_finality(&finality_directory);
    let primary = fixture.create(&primary_directory);
    let (_, primary_path) = keyed_paths(&primary_directory.0, fixture.signer()).unwrap();
    let primary_state = primary.state_id().unwrap();
    let primary_image = fs::read(&primary_path).unwrap();

    assert!(matches!(
        finality.acknowledge_signer_stop_is_externally_durable(finality.state_id().unwrap()),
        Err(FixedValidatorFinalityJournalErrorV0::SignerStopConflictRequired)
    ));
    assert_eq!(primary.state_id().unwrap(), primary_state);
    assert_eq!(fs::read(&primary_path).unwrap(), primary_image);

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
    let wrong_finality_anchor = FixedValidatorFinalityJournalStateIdV0::from_bytes([0x93; 32]);
    assert!(matches!(
        finality.acknowledge_signer_stop_is_externally_durable(wrong_finality_anchor),
        Err(
            FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
                required,
                acknowledged,
            }
        ) if required == halt.state_id() && acknowledged == wrong_finality_anchor
    ));
    assert_eq!(primary.state_id().unwrap(), primary_state);
    assert_eq!(fs::read(&primary_path).unwrap(), primary_image);

    let wrong_context = ConsensusContextV0::new(
        fixture.context.chain_id(),
        ConsensusGenesisId::from_bytes([0x93; 32]),
        fixture.context.protocol_version(),
    );
    let mut context_vote = FixedValidatorVoteSafetyJournalV0::create(
        &context_directory.0,
        wrong_context,
        fixture.fixed_set_id(),
        fixture.signing_key(),
        fixture.replay_limit,
    )
    .unwrap();
    let (_, context_path) = keyed_paths(&context_directory.0, fixture.signer()).unwrap();
    let context_state = context_vote.state_id().unwrap();
    let context_image = fs::read(&context_path).unwrap();
    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    assert!(matches!(
        context_vote.stop_after_durable_finality_conflict(conflict),
        Err(FixedValidatorVoteSafetyJournalErrorV0::FinalityConflictContextMismatch)
    ));
    assert_eq!(context_vote.state_id().unwrap(), context_state);
    assert_eq!(fs::read(context_path).unwrap(), context_image);

    let mut set_vote = FixedValidatorVoteSafetyJournalV0::create(
        &set_directory.0,
        fixture.context,
        fixture.alternate_fixed_set_id(),
        fixture.signing_key(),
        fixture.replay_limit,
    )
    .unwrap();
    let (_, set_path) = keyed_paths(&set_directory.0, fixture.signer()).unwrap();
    let set_state = set_vote.state_id().unwrap();
    let set_image = fs::read(&set_path).unwrap();
    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    assert!(matches!(
        set_vote.stop_after_durable_finality_conflict(conflict),
        Err(FixedValidatorVoteSafetyJournalErrorV0::FinalityConflictFixedSetMismatch)
    ));
    assert_eq!(set_vote.state_id().unwrap(), set_state);
    assert_eq!(fs::read(set_path).unwrap(), set_image);
}

#[test]
fn finality_stop_preempts_held_height_advance_authority() {
    let fixture = Fixture::new(2);
    let height_directory = TestDirectory::new("finality-stop-held-height-source");
    let conflict_directory = TestDirectory::new("finality-stop-held-height-conflict");
    let vote_directory = TestDirectory::new("finality-stop-held-height-vote");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();

    let mut height_finality = fixture.create_finality(&height_directory);
    let _ = height_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let height_finality_state = height_finality.state_id().unwrap();
    let durable_height = height_finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            height_finality_state,
        )
        .unwrap();

    let mut conflict_finality = fixture.create_finality(&conflict_directory);
    let _ = conflict_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match conflict_finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let mut vote_journal = fixture.create(&vote_directory);
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    let mut session = issue_session(&mut vote_journal, &round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable_height)
        .unwrap();
    let prepared_state = prepared_height.state_id();
    let parent_position = session.position();

    let conflict = conflict_finality
        .acknowledge_signer_stop_is_externally_durable(halt.state_id())
        .unwrap();
    let stopped = match session
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new signer stop, got {other:?}"),
    };
    let stopped_image = fs::read(&vote_path).unwrap();

    assert!(matches!(
        session.acknowledge_prepared_height_is_externally_durable(
            prepared_height,
            prepared_state,
        ),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
    assert_eq!(session.position(), parent_position);
    assert_eq!(session.journal.state_id().unwrap(), stopped.vote_state_id());
    assert_eq!(fs::read(vote_path).unwrap(), stopped_image);
}

#[test]
fn finality_stop_bypasses_exhausted_preparation_ceiling() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("finality-stop-exhausted-source");
    let vote_directory = TestDirectory::new("finality-stop-exhausted-vote");
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

    let mut vote_journal = fixture.create(&vote_directory);
    let prepared = prepared(
        vote_journal
            .prepare_vote(fixture.nil_prevote_intent())
            .unwrap(),
    );
    let _ = vote_journal.sign_prepared_vote(prepared).unwrap();
    assert!(matches!(
        vote_journal.prepare_vote(fixture.round_one_nil_prevote_intent()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PrepareLimitExceeded { maximum: 1 })
    ));
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    let exhausted_image = fs::read(&vote_path).unwrap();

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
    assert_ne!(fs::read(&vote_path).unwrap(), exhausted_image);
    assert_eq!(vote_journal.state_id().unwrap(), stopped.vote_state_id());
    assert!(matches!(
        vote_journal.prepare_vote(fixture.round_one_nil_prevote_intent()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::TerminalFinalityConflictSignerStop {
                height
            }
        ) if height == halt.height()
    ));
}

#[test]
fn existing_same_slot_halt_cannot_be_replaced_by_finality_stop() {
    let fixture = Fixture::new(2);
    let finality_directory = TestDirectory::new("finality-stop-existing-halt-source");
    let vote_directory = TestDirectory::new("finality-stop-existing-halt-vote");
    let mut finality = fixture.create_finality(&finality_directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };

    let mut vote_journal = fixture.create(&vote_directory);
    let prepared = prepared(
        vote_journal
            .prepare_vote(fixture.nil_prevote_intent())
            .unwrap(),
    );
    let _ = vote_journal.sign_prepared_vote(prepared).unwrap();
    let vote_halt = match vote_journal
        .prepare_vote(fixture.proposal_prevote_intent())
        .unwrap()
    {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected vote-safety halt, got {other:?}"),
    };
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    let halted_image = fs::read(&vote_path).unwrap();

    let conflict = finality
        .acknowledge_signer_stop_is_externally_durable(finality_halt.state_id())
        .unwrap();
    assert!(matches!(
        vote_journal.stop_after_durable_finality_conflict(conflict),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt {
            position,
            role,
        }) if position == vote_halt.position() && role == vote_halt.role()
    ));
    assert_eq!(vote_journal.state_id().unwrap(), vote_halt.state_id());
    assert_eq!(vote_journal.halt().unwrap(), Some(vote_halt));
    assert_eq!(vote_journal.finality_conflict_stop().unwrap(), None);
    assert_eq!(fs::read(vote_path).unwrap(), halted_image);
}

#[cfg(unix)]
#[test]
fn preselection_pair_stop_uses_tag_0b_and_replays_as_a_distinct_idempotent_kind() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("preselection-stop-finality");
    let finality_anchor_directory = TestDirectory::new("preselection-stop-finality-anchor");
    let selected_finality_directory = TestDirectory::new("preselection-stop-selected-finality");
    let vote_directory = TestDirectory::new("preselection-stop-vote");
    let vote_anchor_directory = TestDirectory::new("preselection-stop-vote-anchor");
    let selected_vote_directory = TestDirectory::new("preselection-stop-selected-vote");
    let selected_vote_anchor_directory =
        TestDirectory::new("preselection-stop-selected-vote-anchor");
    let mut finality =
        fixture.create_anchored_finality(&finality_directory, &finality_anchor_directory);
    let first = fixture.owned_transition_for_round(ZfcAxiom::Pairing, 2);
    let second = fixture.owned_transition_for_round(ZfcAxiom::Union, 2);
    let halt = finality
        .commit_verified_preselection_conflict(second, first)
        .unwrap();
    assert_eq!(
        halt.kind(),
        FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    let mut selected_finality = fixture.create_finality(&selected_finality_directory);
    let _ = selected_finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let selected_halt = match selected_finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::PowerSet))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected selected-sibling finality halt, got {other:?}"),
    };

    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let pair_shape = FixedValidatorFinalityConflictSignerStopV0 {
        kind: FixedValidatorFinalityHaltKindV0::PreselectionPair,
        finality_state_id: halt.state_id(),
        height: halt.height(),
        first_ancestry: halt.first_ancestry(),
        first_envelope_id: halt.first_envelope_id(),
        second_ancestry: halt.second_ancestry(),
        second_envelope_id: halt.second_envelope_id(),
        vote_state_id: genesis,
    };
    let selected_shape = FixedValidatorFinalityConflictSignerStopV0 {
        kind: FixedValidatorFinalityHaltKindV0::SelectedSibling,
        ..pair_shape
    };
    assert!(!pair_shape.same_conflict(selected_shape));
    let body = finality_conflict_stop_record(pair_shape, 0).unwrap();
    let selected_body = finality_conflict_stop_record(selected_shape, 0).unwrap();
    assert_eq!(body.len(), 169);
    assert_eq!(body[0], PRESELECTION_CONFLICT_STOP_RECORD);
    assert_eq!(selected_body[0], FINALITY_CONFLICT_STOP_RECORD);
    assert_eq!(&body[1..], &selected_body[1..]);
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let expected_state = step_state_id(genesis, length, &body);
    let selected_state = step_state_id(genesis, length, &selected_body);
    assert_ne!(selected_state, expected_state);
    let mut expected_image = prefix.clone();
    expected_image.extend_from_slice(&length);
    expected_image.extend_from_slice(&body);
    expected_image.extend_from_slice(expected_state.as_bytes());
    assert_eq!(expected_image.len() - prefix.len(), 205);

    let mut pair_retagged_as_selected = expected_image.clone();
    pair_retagged_as_selected[prefix.len() + 4] = FINALITY_CONFLICT_STOP_RECORD;
    let io = ScriptedIo::from_images(pair_retagged_as_selected.clone(), pair_retagged_as_selected);
    assert!(matches!(
        fixture.replay_scripted(io, expected_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch { entry: 0, .. })
    ));
    let mut selected_image = prefix.clone();
    selected_image.extend_from_slice(&length);
    selected_image.extend_from_slice(&selected_body);
    selected_image.extend_from_slice(selected_state.as_bytes());
    selected_image[prefix.len() + 4] = PRESELECTION_CONFLICT_STOP_RECORD;
    let io = ScriptedIo::from_images(selected_image.clone(), selected_image);
    assert!(matches!(
        fixture.replay_scripted(io, selected_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RecordStateIdMismatch { entry: 0, .. })
    ));

    let mut vote_journal = fixture.create_anchored(&vote_directory, &vote_anchor_directory);
    let conflict = finality.acknowledge_signer_stop().unwrap();
    let stopped = match vote_journal
        .stop_after_durable_finality_conflict(conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected new preselection signer stop, got {other:?}"),
    };
    assert_eq!(
        stopped.kind(),
        FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    assert_eq!(stopped.finality_state_id(), halt.state_id());
    assert_eq!(stopped.height(), halt.height());
    assert_eq!(stopped.first_ancestry(), halt.first_ancestry());
    assert_eq!(stopped.first_envelope_id(), halt.first_envelope_id());
    assert_eq!(stopped.second_ancestry(), halt.second_ancestry());
    assert_eq!(stopped.second_envelope_id(), halt.second_envelope_id());
    assert_eq!(stopped.vote_state_id(), expected_state);
    let (_, vote_path) = keyed_paths(&vote_directory.0, fixture.signer()).unwrap();
    assert_eq!(fs::read(&vote_path).unwrap(), expected_image);
    let vote_anchor_path = vote_anchor_directory.vote_anchor(fixture.signer());
    let stopped_anchor = fs::read(&vote_anchor_path).unwrap();
    assert_eq!(&stopped_anchor[184..192], &1_u64.to_be_bytes());
    assert_eq!(&stopped_anchor[192..224], expected_state.as_bytes());

    let selected_conflict = selected_finality
        .acknowledge_signer_stop_is_externally_durable(selected_halt.state_id())
        .unwrap();
    assert!(matches!(
        vote_journal.stop_after_durable_finality_conflict(selected_conflict),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::ConflictingFinalityConflictSignerStop {
                retained_height,
                incoming_height,
            }
        ) if retained_height == halt.height() && incoming_height == selected_halt.height()
    ));
    assert_eq!(vote_journal.state_id().unwrap(), expected_state);
    assert_eq!(fs::read(&vote_path).unwrap(), expected_image);
    assert_eq!(fs::read(&vote_anchor_path).unwrap(), stopped_anchor);

    let before_repeat = fs::read(&vote_path).unwrap();
    let repeat = finality.acknowledge_signer_stop().unwrap();
    assert!(matches!(
        vote_journal.stop_after_durable_finality_conflict(repeat).unwrap(),
        FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(existing)
            if existing == stopped
    ));
    assert_eq!(fs::read(&vote_path).unwrap(), before_repeat);
    assert_eq!(fs::read(&vote_anchor_path).unwrap(), stopped_anchor);
    drop(vote_journal);

    let mut selected_vote =
        fixture.create_anchored(&selected_vote_directory, &selected_vote_anchor_directory);
    let selected_conflict = selected_finality
        .acknowledge_signer_stop_is_externally_durable(selected_halt.state_id())
        .unwrap();
    let selected_stop = match selected_vote
        .stop_after_durable_finality_conflict(selected_conflict)
        .unwrap()
    {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stopped) => stopped,
        other => panic!("expected selected-sibling signer stop, got {other:?}"),
    };
    let (_, selected_vote_path) =
        keyed_paths(&selected_vote_directory.0, fixture.signer()).unwrap();
    let selected_vote_image = fs::read(&selected_vote_path).unwrap();
    let selected_vote_anchor_path = selected_vote_anchor_directory.vote_anchor(fixture.signer());
    let selected_vote_anchor_image = fs::read(&selected_vote_anchor_path).unwrap();
    let pair_conflict = finality.acknowledge_signer_stop().unwrap();
    assert!(matches!(
        selected_vote.stop_after_durable_finality_conflict(pair_conflict),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::ConflictingFinalityConflictSignerStop {
                retained_height,
                incoming_height,
            }
        ) if retained_height == selected_halt.height() && incoming_height == halt.height()
    ));
    assert_eq!(
        selected_vote.state_id().unwrap(),
        selected_stop.vote_state_id()
    );
    assert_eq!(fs::read(selected_vote_path).unwrap(), selected_vote_image);
    assert_eq!(
        fs::read(selected_vote_anchor_path).unwrap(),
        selected_vote_anchor_image
    );
    drop(selected_vote);

    let reopened = fixture
        .open_anchored(&vote_directory, &vote_anchor_directory)
        .unwrap();
    assert_eq!(reopened.finality_conflict_stop().unwrap(), Some(stopped));
    assert_eq!(reopened.state_id().unwrap(), expected_state);
    assert_eq!(fs::read(vote_path).unwrap(), expected_image);
}
