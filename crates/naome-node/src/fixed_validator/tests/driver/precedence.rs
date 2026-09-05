use super::*;

#[test]
fn actionable_higher_round_evidence_precedes_due_timeout() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-evidence-before-timeout");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));

            let driver = step_transition(driver);
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(!driver.timeout_is_due());
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                            if returned == timeout
                    ));
                    *driver
                }
                _ => panic!("the completed vote must transfer before another event"),
            };
            let (driver, signed, released_proposal) = step_publish(driver);
            let released_proposal = released_proposal
                .expect("higher-round publication must transfer the selected proposal");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), payload);
            assert_eq!(signed.position(), position);
            assert_eq!(signed.role(), ConsensusVoteRole::Precommit);
            assert_eq!(
                signed.target(),
                ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            );
            let (driver, later_timeout) = step_arm(driver);
            assert_eq!(later_timeout.position(), position);
            assert_eq!(later_timeout.phase(), FixedValidatorLockPhaseV0::Precommit);

            match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver, rejection, ..
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                    ));
                    assert_eq!(driver.position(), position);
                }
                _ => panic!("superseded due ticket must be rejected"),
            }
        })
        .unwrap();
}

#[test]
fn grouped_higher_round_selection_ignores_vote_only_rounds_and_precedes_due_timeout() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-grouped-higher-round-selection");
    let branch = fixed_branch(&fixture);
    let (round_one_value, _, _) = proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Pairing);
    let (round_two_value, _, _) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let (round_three_value, _, _) = proposal_inputs(&fixture, &branch, 3, ZfcAxiom::PowerSet);
    let (selected_value, selected_control, selected_payload) =
        proposal_inputs(&fixture, &branch, 4, ZfcAxiom::Extensionality);
    let round_one_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 1).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_one_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let round_two_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 2).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_two_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let round_three_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 3).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_three_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let selected_position = round_at(&branch, 4).position();
    let selected_root = selected_value.proposal_signing_root();
    let selected_prevote = signed_vote_bytes(
        fixture.context,
        selected_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(selected_root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, prevote_event(&round_three_prevote));
            let (driver, _) = admit(
                driver,
                proposal_event(4, &selected_control, &selected_payload),
            );
            let (driver, _) = admit(driver, prevote_event(&round_one_prevote));
            let (driver, _) = admit(driver, prevote_event(&selected_prevote));
            let (driver, _) = admit(driver, prevote_event(&round_two_prevote));
            let (driver, _) = admit_due(driver, timeout);

            let driver = step_transition(driver);
            assert_eq!(driver.position(), selected_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(!driver.timeout_is_due());
            let (driver, signed, released_proposal) = step_publish(driver);
            let released_proposal = released_proposal
                .expect("the sole actionable proposal must transfer with its precommit");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                selected_control
            );
            assert_eq!(
                released_proposal.canonical_artifact_bytes(),
                selected_payload
            );
            assert_eq!(signed.position(), selected_position);
            assert_eq!(signed.role(), ConsensusVoteRole::Precommit);
            assert_eq!(
                signed.target(),
                ConsensusVoteTarget::Proposal(selected_root)
            );
            assert_eq!(driver.inbox_len(), 4);
        })
        .unwrap();
}

#[test]
fn complete_snapshot_permutations_select_the_same_durable_precommit() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );

    let (due_first_vote, due_first_images) = run_actionable_permutation(
        &fixture,
        "driver-permutation-due-first",
        &control,
        &payload,
        &prevote,
        true,
    );
    let (evidence_first_vote, evidence_first_images) = run_actionable_permutation(
        &fixture,
        "driver-permutation-evidence-first",
        &control,
        &payload,
        &prevote,
        false,
    );

    assert_eq!(due_first_vote, evidence_first_vote);
    assert_eq!(due_first_images, evidence_first_images);
    assert_eq!(due_first_vote.position(), position);
    assert_eq!(due_first_vote.role(), ConsensusVoteRole::Precommit);
    assert_eq!(
        due_first_vote.target(),
        ConsensusVoteTarget::Proposal(value.proposal_signing_root())
    );
}

#[test]
fn incomplete_evidence_does_not_starve_an_exact_due_timeout() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-incomplete-evidence");
    let branch = fixed_branch(&fixture);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit_due(driver, timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.inbox_len(), 1);
            let (_, signed, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(signed.role(), ConsensusVoteRole::Prevote);
            assert_eq!(signed.target(), ConsensusVoteTarget::Nil);
        })
        .unwrap();
}

#[test]
fn competing_actions_block_timeout_until_lossless_full_reset() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-ambiguity");
    let branch = fixed_branch(&fixture);
    let (first_value, first_control, first_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (second_value, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let position = round_at(&branch, 2).position();
    let first_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let second_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, proposal_event(2, &second_control, &second_payload));
            let (driver, _) = admit(driver, prevote_event(&first_prevote));
            let (driver, _) = admit(driver, proposal_event(2, &first_control, &first_payload));
            let (driver, _) = admit(driver, prevote_event(&second_prevote));

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    match reason {
                        FixedValidatorNodeDriverBlockReasonV0::Ambiguous { first, second } => {
                            assert!(first < second);
                            assert_eq!(first.position(), position);
                            assert_eq!(second.position(), position);
                        }
                        _ => panic!("expected same-class evidence ambiguity"),
                    }
                    *driver
                }
                _ => panic!("competing actionable roots must block"),
            };
            assert_eq!(layout.images(), before);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::Ambiguous { .. }
                    ));
                    *driver
                }
                _ => panic!("latched ambiguity must keep blocking"),
            };

            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(drained.len(), 4);
            let (proposals, prevotes) = drained_contents(drained);
            let mut expected_proposals = vec![
                (first_control.clone(), first_payload.clone()),
                (second_control.clone(), second_payload.clone()),
            ];
            expected_proposals.sort_unstable();
            let mut expected_prevotes = vec![first_prevote.clone(), second_prevote.clone()];
            expected_prevotes.sort_unstable();
            assert_eq!(proposals, expected_proposals);
            assert_eq!(prevotes, expected_prevotes);
            assert_eq!(driver.inbox_len(), 0);
            assert!(driver.timeout_is_due());
            let driver = step_transition(*driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
        })
        .unwrap();
}

#[test]
fn competing_actionable_positions_block_without_round_preference() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-position-ambiguity");
    let branch = fixed_branch(&fixture);
    let (round_two_value, round_two_control, round_two_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (round_three_value, round_three_control, round_three_payload) =
        proposal_inputs(&fixture, &branch, 3, ZfcAxiom::Union);
    let round_two = round_at(&branch, 2).position();
    let round_three = round_at(&branch, 3).position();
    let round_two_prevote = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_two_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let round_three_prevote = signed_vote_bytes(
        fixture.context,
        round_three,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(round_three_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(
                driver,
                proposal_event(3, &round_three_control, &round_three_payload),
            );
            let (driver, _) = admit(driver, prevote_event(&round_three_prevote));
            let (driver, _) = admit(
                driver,
                proposal_event(2, &round_two_control, &round_two_payload),
            );
            let (driver, _) = admit(driver, prevote_event(&round_two_prevote));

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    match reason {
                        FixedValidatorNodeDriverBlockReasonV0::Ambiguous { first, second } => {
                            assert_eq!(first.position(), round_two);
                            assert_eq!(second.position(), round_three);
                        }
                        _ => panic!("expected cross-position evidence ambiguity"),
                    }
                    *driver
                }
                _ => panic!("the driver must not prefer a lower or earlier actionable round"),
            };
            assert_eq!(layout.images(), before);
            assert!(driver.timeout_is_due());

            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            let (proposals, prevotes) = drained_contents(drained);
            let mut expected_proposals = vec![
                (round_two_control.clone(), round_two_payload.clone()),
                (round_three_control.clone(), round_three_payload.clone()),
            ];
            expected_proposals.sort_unstable();
            let mut expected_prevotes =
                vec![round_two_prevote.clone(), round_three_prevote.clone()];
            expected_prevotes.sort_unstable();
            assert_eq!(proposals, expected_proposals);
            assert_eq!(prevotes, expected_prevotes);

            let driver = step_transition(*driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
        })
        .unwrap();
}

#[test]
fn current_nil_quorum_precedes_due_and_preserves_populated_valid_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-nil-quorum-lock-valid-retention");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let evidence_position = round_at(&branch, 2).position();
    let root = value.proposal_signing_root();
    let prevote = signed_vote_bytes(
        fixture.context,
        evidence_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round_at(&branch, 2)
        .build_quorum_certificate_from_signed_votes(
            &[prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let round_three_nil_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 3).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));
            let driver = step_transition(driver);
            let durable_evidence = layout.images();
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_some());
            assert_eq!(precommit.position(), evidence_position);
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            let (driver, precommit_timeout) = step_arm(driver);

            let (driver, _) = admit_due(driver, precommit_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), durable_evidence);
            let (driver, proposal_timeout) = step_arm(driver);

            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            let after_due_vote = layout.images();
            assert_ne!(after_due_vote, durable_evidence);
            let (driver, locked_prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(locked_prevote.position(), driver.position());
            assert_eq!(locked_prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(locked_prevote.target(), ConsensusVoteTarget::Proposal(root));
            assert_eq!(layout.images(), after_due_vote);

            let (driver, prevote_timeout) = step_arm(driver);
            assert_eq!(prevote_timeout.position(), driver.position());
            assert_eq!(prevote_timeout.phase(), FixedValidatorLockPhaseV0::Prevote);
            let (driver, disposition) =
                admit(driver, current_nil_prevote_event(&round_three_nil_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let after_due_precommit = layout.images();
            assert_ne!(after_due_precommit, after_due_vote);
            let (driver, nil_precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(nil_precommit.position(), driver.position());
            assert_eq!(nil_precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(nil_precommit.target(), ConsensusVoteTarget::Nil);
            assert_eq!(layout.images(), after_due_precommit);
            drop(driver);
        })
        .unwrap();

    let durable = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            let signing = scope.signing_session();
            assert_eq!(signing.position().round(), ConsensusRound::new(3));
            assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(
                signing.locked_value().is_none(),
                "the nil quorum must clear the prior lock"
            );
            let valid = signing
                .valid_value()
                .expect("the nil quorum must preserve complete valid evidence");
            assert_eq!(valid.round(), ConsensusRound::new(2));
            assert_eq!(valid.value().proposal_signing_root(), root);
            assert_eq!(
                valid.canonical_prevote_certificate(),
                expected_certificate.as_slice()
            );
            assert_eq!(layout.images(), durable);
        })
        .unwrap();
}

#[test]
fn current_ambiguity_is_round_local_and_higher_evidence_escapes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-ambiguity-higher-escape");
    let branch = fixed_branch(&fixture);
    let (_, first_control, first_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::PowerSet);
    let higher_position = round_at(&branch, 2).position();
    let higher_root = higher_value.proposal_signing_root();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&first_control, &first_payload),
            );
            let (driver, _) = admit(
                driver,
                current_proposal_event(&second_control, &second_payload),
            );
            let (driver, _) = admit_due(driver, timeout);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous { .. }
                    ));
                    *driver
                }
                _ => panic!("competing current proposals must block current action"),
            };

            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.current_inbox_len(), 2);
            assert!(!driver.timeout_is_due());
            let (driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.target(), ConsensusVoteTarget::Proposal(higher_root));
            assert!(released_proposal.is_some());
            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
                _ => panic!("stale current ambiguity must not block the advanced position"),
            };

            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            let mut expected = vec![
                (first_control.clone(), first_payload.clone()),
                (second_control.clone(), second_payload.clone()),
            ];
            expected.sort_unstable();
            assert_eq!(proposals, expected);
            assert!(prevotes.is_empty());
            assert!(nil_prevotes.is_empty());
        })
        .unwrap();
}

#[test]
fn actionable_higher_evidence_precedes_healthy_current_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-higher-before-current");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher_position = round_at(&branch, 2).position();
    let higher_root = higher_value.proposal_signing_root();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));

            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.current_inbox_len(), 2);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert_eq!(
                precommit.target(),
                ConsensusVoteTarget::Proposal(higher_root)
            );
            let released_proposal =
                released_proposal.expect("higher action must transfer its selected token");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                higher_control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), higher_payload);
            assert_eq!(driver.current_inbox_len(), 2);
        })
        .unwrap();
}
