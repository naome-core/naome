use super::*;

#[test]
fn missing_proposal_blocks_preselection_pair_until_completion_then_halts() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-preselection-pair-missing-proposal");
    let branch = fixed_branch(&fixture);
    let (first_value, first_control, first_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (second_value, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let position = round_at(&branch, 0).position();
    let first_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let second_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let expected_roots =
        if first_value.proposal_signing_root() < second_value.proposal_signing_root() {
            (
                first_value.proposal_signing_root(),
                second_value.proposal_signing_root(),
            )
        } else {
            (
                second_value.proposal_signing_root(),
                first_value.proposal_signing_root(),
            )
        };
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    let stopped = ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_finality_limits(
                scope,
                8,
                1024 * 1024,
                8,
                1024 * 1024,
                4,
                1024 * 1024,
                4,
            );
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, current_finality_precommit_event(&first_precommit));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&second_control, &second_payload),
            );
            let (driver, _) = admit(driver, current_finality_precommit_event(&second_precommit));
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                    position: classified_position,
                    first,
                    second,
                } if classified_position == position && (first, second) == expected_roots
            ));
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityRootsConflicting {
                            position: blocked_position,
                            first,
                            second,
                        } if blocked_position == position && (first, second) == expected_roots
                    ));
                    *driver
                }
                _ => panic!("a quorate root missing its proposal must block pair execution"),
            };
            assert_eq!(layout.images(), before);

            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&first_control, &first_payload),
            );
            match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop) => *stop,
                _ => panic!("completing the second proposal-backed root must halt"),
            }
        })
        .unwrap();
    assert_eq!(
        stopped.finality_halt().kind(),
        naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    assert_eq!(
        stopped.signer_stop().kind(),
        naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    let stopped_images = layout.images();
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => assert_eq!(reopened, stopped),
        _ => panic!("strict restart must recover the completed preselection-pair stop"),
    }
    assert_eq!(layout.images(), stopped_images);
}

#[test]
fn complete_preselection_pair_preempts_other_work_survives_saturation_and_restarts() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (left_value, left_control, left_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (right_value, right_control, right_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::PowerSet);
    let position = round_at(&branch, 0).position();
    let left_root = left_value.proposal_signing_root();
    let right_root = right_value.proposal_signing_root();
    assert_ne!(left_root, right_root);
    let standard_left_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(left_root),
        &fixture.signing_key(),
    );
    let right_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(right_root),
        &fixture.signing_key(),
    );
    let alternate_left_precommit = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(left_root),
        &fixture.signing_key(),
        0x01,
    );
    let (left_precommit, denied_precommit) = if standard_left_precommit < alternate_left_precommit {
        (alternate_left_precommit, standard_left_precommit)
    } else {
        (standard_left_precommit, alternate_left_precommit)
    };
    assert!(denied_precommit < left_precommit);
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_position = round_at(&branch, 1).position();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let expected_roots = if left_root < right_root {
        (left_root, right_root)
    } else {
        (right_root, left_root)
    };
    let expected_ancestries = if left_root < right_root {
        (left_value.ancestry_id(), right_value.ancestry_id())
    } else {
        (right_value.ancestry_id(), left_value.ancestry_id())
    };
    let mut outcomes = Vec::new();

    for (label, reverse_evidence, latch_saturation) in [
        ("driver-preselection-pair-baseline", false, false),
        ("driver-preselection-pair-saturated-reversed", true, true),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let stop = ready
            .run_with_signing_session(|scope| {
                let driver = driver_with_finality_limits(
                    scope,
                    8,
                    1024 * 1024,
                    8,
                    1024 * 1024,
                    4,
                    1024 * 1024,
                    4,
                );
                let (driver, timeout) = step_arm(driver);
                assert_eq!(timeout.generation(), 0);
                let (driver, _) = admit(
                    driver,
                    current_proposal_event(&left_control, &left_payload),
                );
                let (driver, _) = admit(driver, current_nil_precommit_event(&nil_precommit));
                let (driver, _) = admit(
                    driver,
                    proposal_event(1, &higher_control, &higher_payload),
                );
                let (driver, _) = admit(driver, prevote_event(&higher_prevote));
                let (driver, _) = admit_due(driver, timeout);
                let driver = if reverse_evidence {
                    let (driver, _) = admit(
                        driver,
                        current_finality_precommit_event(&right_precommit),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&right_control, &right_payload),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_precommit_event(&left_precommit),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&left_control, &left_payload),
                    );
                    driver
                } else {
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&left_control, &left_payload),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_precommit_event(&left_precommit),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&right_control, &right_payload),
                    );
                    let (driver, _) = admit(
                        driver,
                        current_finality_precommit_event(&right_precommit),
                    );
                    driver
                };
                assert_eq!(driver.current_finality_inbox_len(), 4);
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                        position: classified_position,
                        first,
                        second,
                    } if classified_position == position && (first, second) == expected_roots
                ));
                let driver = if latch_saturation {
                    let driver = reject_current_finality_precommit(
                        driver,
                        &denied_precommit,
                        |rejection| {
                            assert!(matches!(
                                rejection,
                                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                                    position: saturated_position,
                                    saturation:
                                        FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                                            attempted_entries: 5,
                                            maximum_entries: 4,
                                            ..
                                        },
                                    newly_saturated: true,
                                } if *saturated_position == position
                            ));
                        },
                    );
                    assert_eq!(driver.current_finality_inbox_len(), 4);
                    assert!(matches!(
                        driver.classify_current_finality_evidence().unwrap(),
                        FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                            position: classified_position,
                            first,
                            second,
                        } if classified_position == position && (first, second) == expected_roots
                    ));
                    driver
                } else {
                    driver
                };
                let mut driver = driver;
                driver.set_timer_generation_for_test(u64::MAX);
                match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop) => *stop,
                    _ => panic!(
                        "two complete finality roots must preempt due, current, higher, and nil work"
                    ),
                }
            })
            .unwrap();
        assert_eq!(
            stop.finality_halt().kind(),
            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
        );
        assert_eq!(stop.finality_halt().height(), position.height());
        assert_eq!(stop.finality_halt().first_ancestry(), expected_ancestries.0);
        assert_eq!(
            stop.finality_halt().second_ancestry(),
            expected_ancestries.1
        );
        assert_eq!(
            stop.signer_stop().kind(),
            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
        );
        assert_eq!(
            stop.signer_stop().finality_state_id(),
            stop.finality_halt().state_id()
        );
        let stopped_images = layout.images();
        let reopened = fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap();
        match reopened {
            FixedValidatorNodeStartupV0::FinalityStopped(reopened_stop) => {
                assert_eq!(reopened_stop, stop);
            }
            _ => panic!("strict restart must recover the exact preselection-pair stop"),
        }
        assert_eq!(layout.images(), stopped_images);
        outcomes.push((stop, stopped_images));
    }

    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn complete_preselection_pair_preempts_every_phase_and_due_state() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (first_value, first_control, first_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (second_value, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let position = round_at(&branch, 0).position();
    let first_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let second_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
        &fixture.signing_key(),
    );

    for (label, expected_phase, mark_due) in [
        (
            "driver-preselection-pair-proposal-live",
            FixedValidatorLockPhaseV0::Proposal,
            false,
        ),
        (
            "driver-preselection-pair-proposal-due",
            FixedValidatorLockPhaseV0::Proposal,
            true,
        ),
        (
            "driver-preselection-pair-prevote-live",
            FixedValidatorLockPhaseV0::Prevote,
            false,
        ),
        (
            "driver-preselection-pair-prevote-due",
            FixedValidatorLockPhaseV0::Prevote,
            true,
        ),
        (
            "driver-preselection-pair-precommit-live",
            FixedValidatorLockPhaseV0::Precommit,
            false,
        ),
        (
            "driver-preselection-pair-precommit-due",
            FixedValidatorLockPhaseV0::Precommit,
            true,
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let stopped = ready
            .run_with_signing_session(|scope| {
                let driver = driver_with_finality_limits(
                    scope,
                    8,
                    1024 * 1024,
                    8,
                    1024 * 1024,
                    4,
                    1024 * 1024,
                    4,
                );
                let (driver, proposal_timeout) = step_arm(driver);
                let (driver, active_timeout) = match expected_phase {
                    FixedValidatorLockPhaseV0::Proposal => (driver, proposal_timeout),
                    FixedValidatorLockPhaseV0::Prevote => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                    FixedValidatorLockPhaseV0::Precommit => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        let (driver, prevote_timeout) = step_arm(driver);
                        let (driver, _) = admit_due(driver, prevote_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                };
                let driver = if mark_due {
                    let (driver, disposition) = admit_due(driver, active_timeout);
                    assert_eq!(
                        disposition,
                        FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                    );
                    driver
                } else {
                    driver
                };
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), expected_phase);
                assert_eq!(driver.timeout_is_due(), mark_due);

                let (driver, _) = admit(
                    driver,
                    current_finality_proposal_event(&first_control, &first_payload),
                );
                let (driver, _) = admit(driver, current_finality_precommit_event(&first_precommit));
                let (driver, _) = admit(
                    driver,
                    current_finality_proposal_event(&second_control, &second_payload),
                );
                let (driver, _) =
                    admit(driver, current_finality_precommit_event(&second_precommit));
                match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop) => *stop,
                    _ => panic!("a complete pair must preempt every phase and due state"),
                }
            })
            .unwrap();
        assert_eq!(
            stopped.finality_halt().kind(),
            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
        );
        assert_eq!(stopped.finality_halt().height(), position.height());
        assert_eq!(
            stopped.signer_stop().kind(),
            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
        );
        let stopped_images = layout.images();
        match fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap()
        {
            FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
                assert_eq!(reopened, stopped)
            }
            _ => panic!("strict restart must recover the exact preselection-pair stop"),
        }
        assert_eq!(layout.images(), stopped_images);
    }
}
