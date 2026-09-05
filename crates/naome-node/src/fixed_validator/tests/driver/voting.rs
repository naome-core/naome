use super::*;

#[test]
fn driver_serializes_exact_due_phase_transitions_and_commands() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-timeout-phases");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            let (driver, proposal_timeout) = step_arm(driver);
            assert_eq!(proposal_timeout.context(), fixture.context);
            assert_eq!(proposal_timeout.position(), driver.position());
            assert_eq!(
                proposal_timeout.phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            assert_eq!(proposal_timeout.generation(), 0);

            let (driver, disposition) = admit_due(driver, proposal_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
            let (driver, disposition) = admit_due(driver, proposal_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue
            );
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);

            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
            let (driver, prevote_timeout) = step_arm(driver);
            assert_eq!(prevote_timeout.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(prevote_timeout.generation(), 1);

            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            let (driver, precommit_timeout) = step_arm(driver);
            assert_eq!(
                precommit_timeout.phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert_eq!(precommit_timeout.generation(), 2);

            let (driver, _) = admit_due(driver, precommit_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(1));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            let (driver, round_one_timeout) = step_arm(driver);
            assert_eq!(round_one_timeout.position(), driver.position());
            assert_eq!(
                round_one_timeout.phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            assert_eq!(round_one_timeout.generation(), 3);
            match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { .. } => {}
                _ => panic!("driver without evidence or due state must be idle"),
            }
        })
        .unwrap();
}

#[test]
fn exact_due_progression_preserves_populated_lock_and_valid_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-due-lock-valid-retention-no-quorum");
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
            let locked = signing
                .locked_value()
                .expect("exact due progression must preserve the existing lock");
            assert_eq!(locked.round(), ConsensusRound::new(2));
            assert_eq!(locked.proposal_signing_root(), root);
            let valid = signing
                .valid_value()
                .expect("exact due progression must preserve valid evidence");
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
fn current_proposal_and_explicit_prevote_loopback_drive_anchored_precommit() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-two-phase");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let (other_value, _, _) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let mismatched_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(other_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let expected_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, proposal_timeout) = step_arm(driver(scope, 8, 4));
            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_inbox_len(), 1);
            let (driver, _) = admit_due(driver, proposal_timeout);

            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.current_inbox_len(), 1);
            let after_prevote_anchor = layout.images();
            assert_eq!(after_prevote_anchor[0], before[0]);
            assert_eq!(after_prevote_anchor[1], before[1]);
            assert_ne!(after_prevote_anchor, before);

            let driver = match driver
                .admit_event(current_prevote_event(&expected_prevote))
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
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                            canonical_signed_prevote,
                        } if canonical_signed_prevote.as_ref() == expected_prevote.as_slice()
                    ));
                    *driver
                }
                _ => panic!("current loopback must wait for publication custody transfer"),
            };
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            let canonical_prevote = prevote.canonical_bytes().to_vec();
            assert_eq!(canonical_prevote, expected_prevote);
            let (driver, prevote_timeout) = step_arm(driver);

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
                _ => panic!("the driver must not count its own prevote before explicit loopback"),
            };
            let (driver, disposition) = admit(driver, current_prevote_event(&mismatched_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
                _ => panic!("a quorum for another root must not authorize this proposal"),
            };
            let (driver, disposition) = admit(driver, current_prevote_event(&canonical_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_prevote_event(&canonical_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_inbox_len(), 3);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                u64::try_from(
                    control.len()
                        + payload.len()
                        + mismatched_prevote.len()
                        + canonical_prevote.len()
                )
                .unwrap()
            );
            let (driver, _) = admit_due(driver, prevote_timeout);

            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.current_inbox_len(), 3);
            let after_precommit_anchor = layout.images();
            assert_eq!(after_precommit_anchor[0], before[0]);
            assert_eq!(after_precommit_anchor[1], before[1]);
            assert_ne!(after_precommit_anchor, after_prevote_anchor);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            let (driver, precommit_timeout) = step_arm(driver);
            assert_eq!(precommit_timeout.position(), driver.position());
            assert_eq!(
                precommit_timeout.phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            let driver = reject_current_prevote(driver, &canonical_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                        actual: FixedValidatorLockPhaseV0::Precommit
                    }
                ));
            });

            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            let mut expected_prevotes = vec![canonical_prevote, mismatched_prevote.clone()];
            expected_prevotes.sort_unstable();
            assert_eq!(prevotes, expected_prevotes);
            assert!(nil_prevotes.is_empty());
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.current_inbox_canonical_input_bytes(), 0);
        })
        .unwrap();
}

#[test]
fn current_nil_prevote_loopback_drives_anchored_precommit_ahead_of_due() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-prevote-quorum");
    let branch = fixed_branch(&fixture);
    let position = round_at(&branch, 0).position();
    let expected_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, proposal_timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            let after_prevote_anchor = layout.images();
            assert_ne!(after_prevote_anchor, before);

            let driver = match driver
                .admit_event(current_nil_prevote_event(&expected_prevote))
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
                        FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
                            canonical_signed_prevote,
                        } if canonical_signed_prevote.as_ref() == expected_prevote.as_slice()
                    ));
                    *driver
                }
                _ => panic!("nil loopback must wait for publication custody transfer"),
            };
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.position(), position);
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
            assert_eq!(prevote.canonical_bytes(), expected_prevote.as_slice());
            let (driver, prevote_timeout) = step_arm(driver);

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
                _ => panic!("the driver must not self-observe its published nil prevote"),
            };
            let (driver, disposition) = admit(driver, current_nil_prevote_event(&expected_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_nil_prevote_event(&expected_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                u64::try_from(expected_prevote.len()).unwrap()
            );
            let (driver, _) = admit_due(driver, prevote_timeout);

            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(!driver.timeout_is_due());
            assert_eq!(driver.current_inbox_len(), 1);
            let after_precommit_anchor = layout.images();
            assert_ne!(after_precommit_anchor, after_prevote_anchor);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.position(), position);
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            assert_eq!(layout.images(), after_precommit_anchor);
            let (driver, precommit_timeout) = step_arm(driver);
            assert_eq!(precommit_timeout.position(), position);
            assert_eq!(
                precommit_timeout.phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            let driver = reject_current_nil_prevote(driver, &expected_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                        actual: FixedValidatorLockPhaseV0::Precommit
                    }
                ));
            });
            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, proposal_prevotes, nil_prevotes) = drained_current_contents(drained);
            assert!(proposals.is_empty());
            assert!(proposal_prevotes.is_empty());
            assert_eq!(nil_prevotes, vec![expected_prevote.clone()]);
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
            assert_eq!(scope.signing_session().position(), position);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert!(scope.signing_session().locked_value().is_none());
            assert!(scope.signing_session().valid_value().is_none());
            assert_eq!(layout.images(), durable);
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = reject_current_nil_prevote(driver, &expected_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                        actual: FixedValidatorLockPhaseV0::Precommit
                    }
                ));
            });
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(layout.images(), durable);
        })
        .unwrap();
}

#[test]
fn current_proposal_and_nil_quorums_fail_closed_with_higher_escape() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current_position = round_at(&branch, 0).position();
    let current_root = current_value.proposal_signing_root();
    let proposal_prevote = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_root),
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
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

    for (label, nil_first) in [
        ("driver-current-cross-target-proposal-first", false),
        ("driver-current-cross-target-nil-first", true),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 16, 4));
                let (driver, _) = admit(
                    driver,
                    current_proposal_event(&current_control, &current_payload),
                );
                let (driver, _) = if nil_first {
                    admit(driver, current_nil_prevote_event(&nil_prevote))
                } else {
                    admit(driver, current_prevote_event(&proposal_prevote))
                };
                let (driver, _) = if nil_first {
                    admit(driver, current_prevote_event(&proposal_prevote))
                } else {
                    admit(driver, current_nil_prevote_event(&nil_prevote))
                };

                let driver = step_transition(driver);
                let (driver, local_prevote, released_proposal) = step_publish(driver);
                assert!(released_proposal.is_none());
                assert_eq!(
                    local_prevote.target(),
                    ConsensusVoteTarget::Proposal(current_root)
                );
                let (driver, prevote_timeout) = step_arm(driver);
                let (driver, _) = admit_due(driver, prevote_timeout);
                let before_ambiguity = layout.images();
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                                position,
                                proposal_signing_root,
                            } if position == current_position
                                && proposal_signing_root == current_root
                        ));
                        *driver
                    }
                    _ => panic!("competing proposal and nil quorums must fail closed"),
                };
                assert_eq!(driver.current_inbox_len(), 3);
                assert!(driver.timeout_is_due());
                assert_eq!(layout.images(), before_ambiguity);

                let driver = reject_current_nil_prevote(driver, &nil_prevote, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(
                            FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                                position,
                                proposal_signing_root,
                            }
                        ) if *position == current_position
                            && *proposal_signing_root == current_root
                    ));
                });
                assert_eq!(layout.images(), before_ambiguity);

                let (driver, _) =
                    admit(driver, proposal_event(2, &higher_control, &higher_payload));
                let (driver, _) = admit(driver, prevote_event(&higher_prevote));
                let driver = step_transition(driver);
                assert_eq!(driver.position(), higher_position);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
                let (driver, higher_vote, released_proposal) = step_publish(driver);
                assert_eq!(
                    higher_vote.target(),
                    ConsensusVoteTarget::Proposal(higher_root)
                );
                assert!(released_proposal.is_some());
                let (driver, _) = step_arm(driver);
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                                position,
                                proposal_signing_root,
                            } if position == current_position
                                && proposal_signing_root == current_root
                        ));
                        *driver
                    }
                    _ => panic!("current quorum ambiguity must remain latched until drain"),
                };

                let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
                let (proposals, proposal_prevotes, nil_prevotes) =
                    drained_current_contents(drained);
                assert_eq!(
                    proposals,
                    vec![(current_control.clone(), current_payload.clone())]
                );
                assert_eq!(proposal_prevotes, vec![proposal_prevote.clone()]);
                assert_eq!(nil_prevotes, vec![nil_prevote.clone()]);
                assert_eq!(driver.current_inbox_len(), 0);
                assert!(matches!(
                    driver.step().unwrap(),
                    FixedValidatorNodeDriverStepOutcomeV0::Idle { .. }
                ));
            })
            .unwrap();
    }
}

#[test]
fn current_signature_variants_select_one_per_signer_independent_of_insertion_order() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let standard = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
        0x01,
    );
    assert_ne!(standard, alternate);
    let preferred = if standard < alternate {
        standard.as_slice()
    } else {
        alternate.as_slice()
    };
    let expected_certificate = round_at(&branch, 0)
        .build_quorum_certificate_from_signed_votes(
            &[preferred],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let orders = [
        (
            "driver-current-signature-standard-first",
            &standard,
            &alternate,
        ),
        (
            "driver-current-signature-alternate-first",
            &alternate,
            &standard,
        ),
    ];
    let mut outcomes = Vec::new();

    for (label, first, second) in orders {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        let precommit_bytes = ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 8, 4));
                let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
                let (driver, _) = admit(driver, current_prevote_event(first));
                let (driver, _) = admit(driver, current_prevote_event(second));
                assert_eq!(driver.current_inbox_len(), 3);

                let driver = step_transition(driver);
                let (driver, published_prevote, released_proposal) = step_publish(driver);
                assert!(released_proposal.is_none());
                assert_eq!(
                    published_prevote.target(),
                    ConsensusVoteTarget::Proposal(root)
                );
                let (driver, _) = step_arm(driver);
                let driver = step_transition(driver);
                let (driver, precommit, released_proposal) = step_publish(driver);
                assert!(released_proposal.is_none());
                assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
                assert_eq!(driver.current_inbox_len(), 3);
                precommit.canonical_bytes().to_vec()
            })
            .unwrap();

        let durable = layout.images();
        assert_eq!(durable[0], before[0]);
        assert_eq!(durable[1], before[1]);
        let ready = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        ready
            .run_with_signing_session(|mut scope| {
                let signing = scope.signing_session();
                assert_eq!(signing.position(), position);
                assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Precommit);
                let locked = signing
                    .locked_value()
                    .expect("current proposal quorum must restore its exact lock");
                assert_eq!(locked.round(), ConsensusRound::new(0));
                assert_eq!(locked.proposal_signing_root(), root);
                let valid = signing
                    .valid_value()
                    .expect("current proposal quorum must restore valid evidence");
                assert_eq!(valid.round(), ConsensusRound::new(0));
                assert_eq!(valid.value().proposal_signing_root(), root);
                assert_eq!(
                    valid.canonical_prevote_certificate(),
                    expected_certificate.as_slice()
                );
                assert_eq!(layout.images(), durable);
            })
            .unwrap();
        outcomes.push((precommit_bytes, durable));
    }

    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn byte_distinct_same_root_current_proposals_fail_closed() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-same-root-ambiguity");
    let branch = fixed_branch(&fixture);
    let (round_one_value, round_one_control, round_one_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Pairing);
    let (round_two_value, plain_control, payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let root = round_two_value.proposal_signing_root();
    assert_eq!(round_one_value.proposal_signing_root(), root);
    assert_eq!(round_one_payload, payload);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, round_zero_timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _round_one_timeout) = close_empty_round(driver, round_zero_timeout);
            assert_eq!(driver.position(), round_at(&branch, 1).position());
            let (driver, _) = admit(
                driver,
                current_proposal_event(&round_one_control, &round_one_payload),
            );
            let driver = step_transition(driver);
            let (driver, valid_round_prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(
                valid_round_prevote.target(),
                ConsensusVoteTarget::Proposal(root)
            );
            let valid_round_prevote = valid_round_prevote.canonical_bytes().to_vec();
            let (driver, prevote_timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            let (driver, nil_precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(nil_precommit.target(), ConsensusVoteTarget::Nil);
            let (driver, precommit_timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, precommit_timeout);
            let driver = step_transition(driver);
            let (driver, _round_two_timeout) = step_arm(driver);
            assert_eq!(driver.position(), round_at(&branch, 2).position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.timeout_is_due());

            let valid_round_certificate = round_at(&branch, 1)
                .build_quorum_certificate_from_signed_votes(
                    &[valid_round_prevote.as_slice()],
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Proposal(root),
                )
                .unwrap()
                .to_canonical_bytes();
            let proof_control = proposal_control_with_valid_round(
                &fixture,
                round_two_value,
                round_at(&branch, 2).position(),
                &valid_round_certificate,
            );
            assert_ne!(plain_control, proof_control);
            let before_ambiguity = layout.images();

            let (driver, _) = admit(driver, current_proposal_event(&plain_control, &payload));
            let (driver, _) = admit(driver, current_proposal_event(&proof_control, &payload));
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous {
                            position,
                            first,
                            second,
                        } if position == round_at(&branch, 2).position()
                            && first == root
                            && second == root
                    ));
                    *driver
                }
                _ => panic!("byte-distinct same-root proposals must block current action"),
            };
            assert_eq!(driver.current_inbox_len(), 3);
            assert!(!driver.timeout_is_due());
            assert_eq!(layout.images(), before_ambiguity);
            let driver = match driver
                .admit_event(current_proposal_event(&plain_control, &payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(
                            FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous {
                                position,
                                first,
                                second,
                            }
                        ) if *position == round_at(&branch, 2).position()
                            && *first == root
                            && *second == root
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } if canonical_proposal_control_bytes.as_ref() == plain_control.as_slice()
                            && canonical_artifact_bytes.as_ref() == payload.as_slice()
                    ));
                    *driver
                }
                _ => panic!("live current ambiguity must deny later current proposals"),
            };
            let ambiguity_prevote = signed_vote_bytes(
                fixture.context,
                round_at(&branch, 2).position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            let driver = match driver
                .admit_event(current_prevote_event(&ambiguity_prevote))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(
                            FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous { .. }
                        )
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                            canonical_signed_prevote,
                        } if canonical_signed_prevote.as_ref() == ambiguity_prevote.as_slice()
                    ));
                    *driver
                }
                _ => panic!("live current ambiguity must deny later current prevotes"),
            };
            assert_eq!(driver.current_inbox_len(), 3);
            assert_eq!(layout.images(), before_ambiguity);
            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            let mut first_expected = vec![
                (round_one_control.clone(), round_one_payload.clone()),
                (plain_control.clone(), payload.clone()),
                (proof_control.clone(), payload.clone()),
            ];
            first_expected.sort_unstable();
            assert_eq!(proposals, first_expected);
            assert!(prevotes.is_empty());
            assert!(nil_prevotes.is_empty());

            let (driver, _) = admit(*driver, current_proposal_event(&proof_control, &payload));
            let (driver, _) = admit(driver, current_proposal_event(&plain_control, &payload));
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous {
                            first,
                            second,
                            ..
                        } if first == root && second == root
                    ));
                    *driver
                }
                _ => panic!("reverse insertion must produce the same ambiguity"),
            };
            assert_eq!(layout.images(), before_ambiguity);
            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            let mut expected = vec![
                (plain_control.clone(), payload.clone()),
                (proof_control.clone(), payload.clone()),
            ];
            expected.sort_unstable();
            assert_eq!(proposals, expected);
            assert!(prevotes.is_empty());
            assert!(nil_prevotes.is_empty());
        })
        .unwrap();
}
