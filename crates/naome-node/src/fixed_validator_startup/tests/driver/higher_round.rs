use super::*;

#[test]
fn rejected_catchup_preserves_due_timer_custody_and_exact_retry() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let role = ConsensusVoteRole::Precommit;
    let target = ConsensusVoteTarget::Nil;
    let (certificate, vote) = quorum(&fixture, 2, role, target);
    let (stale_certificate, stale_vote) = quorum(&fixture, 0, role, target);
    let (future_certificate, _) = quorum(&fixture, 5, role, target);
    let mut bad_signature = vote.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let mut bad_certificate = certificate.clone();
    *bad_certificate.last_mut().unwrap() ^= 1;
    let (_, wrong_role) = quorum(&fixture, 2, ConsensusVoteRole::Prevote, target);
    let (_, wrong_target) = quorum(
        &fixture,
        2,
        role,
        ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes([0xa5; 32])),
    );
    let inactive = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 2).position(),
        role,
        target,
        &SigningKey::from_bytes(&signing_seed(9)),
    );
    let layout = TestLayout::new("driver-catchup-rejections");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let (mut driver, _) = admit_due(driver, timeout);
            let images = layout.images();
            let custody = candidate_backed::custody(&driver);
            for bytes in [
                &[0][..],
                &[][..],
                &stale_certificate,
                &future_certificate,
                &bad_certificate,
            ] {
                driver = match driver.advance_to_higher_round_quorum(bytes).unwrap() {
                    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::Rejected {
                        driver,
                        ..
                    } => *driver,
                    _ => panic!("invalid certificate must preserve driver"),
                };
                assert_eq!(layout.images(), images);
                assert_eq!(candidate_backed::custody(&driver), custody);
                assert_eq!(driver.position(), timeout.position());
                assert_eq!(driver.phase(), timeout.phase());
                assert!(driver.timeout_is_due());
                assert!(!driver.has_pending_command());
            }
            for (label, round, votes) in [
                ("empty", 2, vec![]),
                ("malformed", 2, vec![&[0][..]]),
                ("duplicate", 2, vec![vote.as_slice(), vote.as_slice()]),
                ("signature", 2, vec![bad_signature.as_slice()]),
                ("role", 2, vec![wrong_role.as_slice()]),
                ("target", 2, vec![wrong_target.as_slice()]),
                ("position", 2, vec![stale_vote.as_slice()]),
                ("inactive", 2, vec![inactive.as_slice()]),
                ("stale-route", 0, vec![&[0][..]]),
                ("ceiling", 5, vec![&[0][..]]),
            ] {
                driver = match driver
                    .advance_to_higher_round_vote_batch(
                        &votes,
                        ConsensusRound::new(round),
                        role,
                        target,
                    )
                    .unwrap()
                {
                    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::Rejected {
                        driver,
                        rejection,
                    } => {
                        match (label, *rejection) {
                            (
                                "stale-route",
                                FixedValidatorNodeRoundAdvanceRejectionV0::NotHigherThanSigner {
                                    ..
                                },
                            )
                            | (
                                "ceiling",
                                FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                                    ..
                                },
                            ) => {}
                            (
                                _,
                                FixedValidatorNodeRoundAdvanceRejectionV0::QuorumConstruction(_),
                            ) => {}
                            (_, other) => panic!("unexpected {label} rejection: {other:?}"),
                        }
                        *driver
                    }
                    _ => panic!("invalid {label} batch must preserve driver"),
                };
                assert_eq!(layout.images(), images);
                assert_eq!(candidate_backed::custody(&driver), custody);
                assert_eq!(driver.position(), timeout.position());
                assert_eq!(driver.phase(), timeout.phase());
                assert!(driver.timeout_is_due());
                assert!(!driver.has_pending_command());
            }
            let (driver, disposition) = admit_due(driver, timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue
            );
            let driver = advanced(
                driver
                    .advance_to_higher_round_vote_batch(
                        &[&vote],
                        ConsensusRound::new(2),
                        role,
                        target,
                    )
                    .unwrap(),
            );
            assert_eq!(candidate_backed::custody(&driver), custody);
            let (driver, replacement) = step_arm(driver);
            assert_eq!(replacement.generation(), timeout.generation() + 1);
            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            assert_eq!(
                drained_current_contents(drained),
                (vec![(control.clone(), payload.clone())], vec![], vec![])
            );
        })
        .unwrap();
}

#[test]
fn catchup_generation_exhaustion_is_consuming_and_precedes_authority_writes() {
    let fixture = Fixture::new();
    let (certificate, vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    for batch in [false, true] {
        let layout = TestLayout::new("driver-catchup-generation");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        ready
            .run_with_signing_session(|scope| {
                let (mut driver, _) = step_arm(driver(scope, 8, 4));
                driver.set_timer_generation_for_test(u64::MAX);
                assert!(matches!(
                    catch_up(
                        driver,
                        batch,
                        &certificate,
                        &vote,
                        2,
                        ConsensusVoteRole::Prevote,
                        ConsensusVoteTarget::Nil
                    ),
                    Err(
                        FixedValidatorNodeDriverStepErrorV0::TimeoutGenerationExhausted {
                            generation: u64::MAX
                        }
                    )
                ));
            })
            .unwrap();
        assert_eq!(layout.images(), before);
        let reopened = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        reopened
            .run_with_signing_session(|scope| {
                assert_eq!(
                    scope.signing_session.position().round(),
                    ConsensusRound::new(0)
                );
            })
            .unwrap();
    }
}

#[test]
fn catchup_anchor_failure_consumes_driver_and_strict_reopen_reports_anchor_behind() {
    let fixture = Fixture::new();
    let (certificate, vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    for batch in [false, true] {
        let layout = TestLayout::new("driver-catchup-anchor-fault");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        let collision = next_anchor_collision(&layout.vote_anchor, 3);
        ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 8, 4));
                let error = match catch_up(
                    driver,
                    batch,
                    &certificate,
                    &vote,
                    2,
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Nil,
                ) {
                    Err(FixedValidatorNodeDriverStepErrorV0::RoundAdvance(error)) => error,
                    _ => panic!("checkpoint anchor failure must return no driver"),
                };
                assert!(
                    matches!(*error, FixedValidatorNodeRoundAdvanceErrorV0::Prepare(source)
                if matches!(*source, FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }))
                );
            })
            .unwrap();
        fs::remove_file(collision).unwrap();
        let after = layout.images();
        assert_eq!(after[0..2], before[0..2]);
        assert_ne!(after[2], before[2]);
        assert_eq!(after[3], before[3]);
        assert!(
            matches!(fixture.provision(&layout, 8).open(fixture.signing_key()),
            Err(FixedValidatorNodeStartupErrorV0::VotePair(source)) if matches!(source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner) if matches!(inner.as_ref(),
                    FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. })))
        );
    }
}

#[test]
fn pending_commands_precede_catchup_input_and_generation_checks() {
    let fixture = Fixture::new();
    for batch in [false, true] {
        let layout = TestLayout::new("driver-catchup-pending");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let mut driver = driver(scope, 8, 4);
                for publication in [false, true] {
                    driver.set_timer_generation_for_test(u64::MAX);
                    let before = layout.images();
                    driver = match catch_up(
                        driver,
                        batch,
                        &[0],
                        &[0],
                        5,
                        ConsensusVoteRole::Prevote,
                        ConsensusVoteTarget::Nil,
                    )
                    .unwrap()
                    {
                        FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::CommandPending {
                            driver,
                        } => *driver,
                        _ => panic!(
                            "pending command must precede malformed input and exhausted generation"
                        ),
                    };
                    assert!(driver.has_pending_command());
                    assert_eq!(layout.images(), before);
                    driver.set_timer_generation_for_test(0);
                    if publication {
                        let (next, vote, released) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released.is_none());
                        driver = next;
                    } else {
                        let (next, timeout) = step_arm(driver);
                        let (next, _) = admit_due(next, timeout);
                        driver = step_transition(next);
                    }
                }
            })
            .unwrap();
    }
}

#[test]
fn retained_higher_proposal_work_precedes_catchup_until_step_or_drain() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (left, left_control, left_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (right, right_control, right_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let (_, left_vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(left.proposal_signing_root()),
    );
    let (_, right_vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(right.proposal_signing_root()),
    );
    let (certificate, vote) = quorum(
        &fixture,
        3,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    for batch in [false, true] {
        for mode in [
            "actionable",
            "derived-ambiguity",
            "latched-ambiguity",
            "saturated",
        ] {
            let layout = TestLayout::new("driver-catchup-higher-priority");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready.run_with_signing_session(|scope| {
                let (driver, timeout) = step_arm(driver(scope, if mode == "saturated" { 1 } else { 8 }, 4));
                let (driver, _) = admit_due(driver, timeout);
                let (mut driver, _) = admit(driver, proposal_event(2, &left_control, &left_payload));
                if mode == "saturated" {
                    driver = reject_prevote(driver, &left_vote, |rejection| assert!(matches!(rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_))));
                } else {
                    (driver, _) = admit(driver, prevote_event(&left_vote));
                }
                if mode.contains("ambiguity") {
                    (driver, _) = admit(driver, proposal_event(2, &right_control, &right_payload));
                    (driver, _) = admit(driver, prevote_event(&right_vote));
                }
                if mode == "latched-ambiguity" {
                    driver = match driver.step().unwrap() {
                        FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason: FixedValidatorNodeDriverBlockReasonV0::Ambiguous { .. } } => *driver,
                        _ => panic!("step must latch ambiguity"),
                    };
                }
                let before = candidate_backed::custody(&driver);
                let images = layout.images();
                // Both a valid later destination and malformed input must yield to retained work.
                for malformed in [false, true] {
                    driver.set_timer_generation_for_test(u64::MAX);
                    driver = match catch_up(driver, batch, if malformed { &[0] } else { &certificate }, if malformed { &[0] } else { &vote }, 3,
                        ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil).unwrap() {
                        FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::HigherEvidenceUnresolved { driver } => *driver,
                        _ => panic!("retained {mode} must precede explicit catch-up"),
                    };
                    assert_eq!(driver.position(), timeout.position());
                    assert_eq!(driver.phase(), timeout.phase());
                    assert!(driver.timeout_is_due());
                    assert_eq!(candidate_backed::custody(&driver), before);
                    assert_eq!(layout.images(), images);
                }
                driver.set_timer_generation_for_test(timeout.generation());
                if mode == "actionable" {
                    let driver = step_transition(driver);
                    let (driver, signed, released) = step_publish(driver);
                    assert_eq!(signed.position(), round_at(&branch, 2).position());
                    assert_eq!(signed.target(), ConsensusVoteTarget::Proposal(left.proposal_signing_root()));
                    assert!(released.is_some());
                    let (driver, _) = step_arm(driver);
                    drop(advanced(catch_up(driver, batch, &certificate, &vote, 3, ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil).unwrap()));
                } else {
                    let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
                    let (proposals, votes) = drained_contents(drained);
                    let mut expected_proposals = vec![(left_control.clone(), left_payload.clone())];
                    let mut expected_votes = vec![];
                    if mode != "saturated" {
                        expected_proposals.push((right_control.clone(), right_payload.clone()));
                        expected_votes.extend([left_vote.clone(), right_vote.clone()]);
                    }
                    expected_proposals.sort_unstable(); expected_votes.sort_unstable();
                    assert_eq!(proposals, expected_proposals); assert_eq!(votes, expected_votes);
                    drop(advanced(catch_up(*driver, batch, &certificate, &vote, 3, ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil).unwrap()));
                }
            }).unwrap();
        }
    }
}

#[test]
fn current_finality_classifications_precede_explicit_catchup() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (left, left_control, left_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (right, right_control, right_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (_, left_vote) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(left.proposal_signing_root()),
    );
    let (_, right_vote) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(right.proposal_signing_root()),
    );
    for batch in [false, true] {
        for mode in ["missing", "ready", "conflicting", "pair", "saturated-pair"] {
            let layout = TestLayout::new("driver-catchup-finality-priority");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready.run_with_signing_session(|scope| {
                let (mut driver, timeout) = step_arm(driver_with_finality_limits(scope, 8, 1 << 20, 8, 1 << 20, 4, 1 << 20, 4));
                (driver, _) = admit(driver, current_finality_precommit_event(&left_vote));
                if mode != "missing" { (driver, _) = admit(driver, current_finality_proposal_event(&left_control, &left_payload)); }
                if matches!(mode, "conflicting" | "pair" | "saturated-pair") { (driver, _) = admit(driver, current_finality_precommit_event(&right_vote)); }
                if matches!(mode, "pair" | "saturated-pair") { (driver, _) = admit(driver, current_finality_proposal_event(&right_control, &right_payload)); }
                if mode == "saturated-pair" {
                    let denied = signed_vote_bytes_with_test_only_nonce_prefix(fixture.context, timeout.position(), ConsensusVoteRole::Precommit,
                        ConsensusVoteTarget::Proposal(left.proposal_signing_root()), &fixture.signing_key(), 0x35);
                    driver = reject_current_finality_precommit(driver, &denied, |rejection| assert!(matches!(rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. })));
                }
                (driver, _) = admit_due(driver, timeout);
                let before = candidate_backed::custody(&driver);
                let classification = driver.classify_current_finality_evidence().unwrap();
                let images = layout.images();
                driver.set_timer_generation_for_test(u64::MAX);
                driver = match catch_up(driver, batch, &[0], &[0], 5, ConsensusVoteRole::Prevote, ConsensusVoteTarget::Nil).unwrap() {
                    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::CurrentFinalityUnresolved { driver } => *driver,
                    _ => panic!("retained {mode} finality must precede all supplied input"),
                };
                assert_eq!(driver.classify_current_finality_evidence().unwrap(), classification);
                assert_eq!(candidate_backed::custody(&driver), before);
                assert_eq!(layout.images(), images);
                assert_eq!(driver.position(), timeout.position());
                assert_eq!(driver.phase(), timeout.phase());
                assert!(driver.timeout_is_due());
                driver.set_timer_generation_for_test(timeout.generation());
                match (mode, driver.step().unwrap()) {
                    ("ready", FixedValidatorNodeDriverStepOutcomeV0::Finality { selection, .. }) => assert!(matches!(selection,
                        FixedValidatorNodeFinalitySelectionV0::Finalized { ancestry_id, .. } if ancestry_id == left.ancestry_id())),
                    ("pair" | "saturated-pair", FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(_)) => {},
                    ("missing" | "conflicting", FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, .. }) => {
                        assert_eq!(candidate_backed::custody(&driver), before); assert_eq!(layout.images(), images);
                    }
                    _ => panic!("step must retain original finality behavior"),
                }
            }).unwrap();
        }
    }
}

fn catch_up<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    batch: bool,
    certificate: &[u8],
    vote: &[u8],
    round: u64,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> Result<
    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0<'node>,
    FixedValidatorNodeDriverStepErrorV0,
> {
    if batch {
        driver.advance_to_higher_round_vote_batch(&[vote], ConsensusRound::new(round), role, target)
    } else {
        driver.advance_to_higher_round_quorum(certificate)
    }
}

fn advanced(
    outcome: FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0<'_>,
) -> FixedValidatorNodeDriverV0<'_> {
    match outcome {
        FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::Advanced { driver } => *driver,
        _ => panic!("expected anchored catch-up"),
    }
}

fn quorum(
    fixture: &Fixture,
    round: u64,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> (Vec<u8>, Vec<u8>) {
    let branch = fixed_branch(fixture);
    let round = round_at(&branch, round);
    let vote = signed_vote_bytes(
        fixture.context,
        round.position(),
        role,
        target,
        &fixture.signing_key(),
    );
    let certificate = round
        .build_quorum_certificate_from_signed_votes(&[&vote], role, target)
        .unwrap()
        .to_canonical_bytes();
    (certificate, vote)
}

fn reject_old_timeout<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    timeout: FixedValidatorNodePhaseTimeoutV0,
) -> FixedValidatorNodeDriverV0<'node> {
    match driver
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
                FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
            ));
            assert!(
                matches!(*event, FixedValidatorNodeDriverEventV0::TimeoutDue(actual) if actual == timeout)
            );
            *driver
        }
        _ => panic!("old timer must have no authority"),
    }
}

#[test]
fn certificates_and_batches_checkpoint_every_role_target_source_phase_and_due_state() {
    let fixture = Fixture::new();
    let position = round_at(&fixed_branch(&fixture), 2).position();
    for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
        for target in [
            ConsensusVoteTarget::Nil,
            ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes([0xa1; 32])),
        ] {
            let expected_phase = match role {
                ConsensusVoteRole::Prevote => FixedValidatorLockPhaseV0::Prevote,
                ConsensusVoteRole::Precommit => FixedValidatorLockPhaseV0::Precommit,
            };
            let (certificate, vote) = quorum(&fixture, 2, role, target);
            for source_phase in 0..3 {
                for due in [false, true] {
                    let mut certificate_images = None;
                    for batch in [false, true] {
                        let layout = TestLayout::new("driver-higher-catchup-parity");
                        let ready = fixture
                            .provision(&layout, 8)
                            .create(fixture.signing_key())
                            .unwrap();
                        let old_timeout = ready
                            .run_with_signing_session(|scope| {
                                let (mut driver, mut timeout) = step_arm(driver(scope, 8, 4));
                                for _ in 0..source_phase {
                                    (driver, _) = admit_due(driver, timeout);
                                    driver = step_transition(driver);
                                    let (next, _, _) = step_publish(driver);
                                    (driver, timeout) = step_arm(next);
                                }
                                if due {
                                    (driver, _) = admit_due(driver, timeout);
                                }
                                let before = layout.images();
                                let driver = advanced(
                                    catch_up(driver, batch, &certificate, &vote, 2, role, target)
                                        .unwrap(),
                                );
                                assert_eq!(driver.position(), position);
                                assert_eq!(driver.phase(), expected_phase);
                                assert!(!driver.timeout_is_due());
                                assert!(driver.has_pending_command());
                                let after = layout.images();
                                assert_eq!(after[0..2], before[0..2]);
                                assert_ne!(after[2], before[2]);
                                assert_ne!(after[3], before[3]);
                                let (driver, replacement) = step_arm(driver);
                                assert_eq!(replacement.position(), position);
                                assert_eq!(replacement.phase(), expected_phase);
                                assert_eq!(replacement.generation(), timeout.generation() + 1);
                                assert!(!driver.has_pending_command());
                                let driver = reject_old_timeout(driver, timeout);
                                assert!(!driver.timeout_is_due());
                                drop(step_idle(driver));
                                assert_eq!(layout.images(), after);
                                timeout
                            })
                            .unwrap();
                        let images = layout.images();
                        if batch {
                            assert_eq!(Some(&images), certificate_images.as_ref());
                        } else {
                            certificate_images = Some(images.clone());
                        }
                        let reopened = expect_ready(
                            fixture
                                .provision(&layout, 8)
                                .open(fixture.signing_key())
                                .unwrap(),
                        );
                        assert!(reopened.vote.pending_vote().unwrap().is_none());
                        for checked_role in
                            [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit]
                        {
                            assert!(
                                reopened
                                    .vote
                                    .retained_signed_vote(position, checked_role)
                                    .unwrap()
                                    .is_none()
                            );
                        }
                        reopened
                            .run_with_signing_session(|mut scope| {
                                assert_eq!(scope.signing_session().position(), position);
                                assert_eq!(scope.signing_session().phase(), expected_phase);
                                assert_eq!(scope.signing_session().locked_value(), None);
                                assert_eq!(scope.signing_session().valid_value(), None);
                                let (driver, _) = step_arm(driver(scope, 8, 4));
                                drop(step_idle(reject_old_timeout(driver, old_timeout)));
                            })
                            .unwrap();
                        assert_eq!(layout.images(), images);
                    }
                }
            }
        }
    }
}

#[test]
fn catchup_preserves_all_inbox_bytes_and_non_pair_finality_saturation() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (_, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 3, ZfcAxiom::Pairing);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (_, nil) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    let (_, denied) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    let (certificate, vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    let (_, finality_vote) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
    );
    for batch in [false, true] {
        let layout = TestLayout::new("driver-higher-catchup-custody");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, timeout) = step_arm(driver_with_all_limits(
                    scope,
                    8,
                    1 << 20,
                    1,
                    1 << 20,
                    1,
                    1 << 20,
                    8,
                    1 << 20,
                    4,
                ));
                let (driver, _) =
                    admit(driver, proposal_event(3, &higher_control, &higher_payload));
                let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
                let (driver, _) =
                    admit(driver, current_finality_proposal_event(&control, &payload));
                let driver = reject_current_finality_precommit(driver, &finality_vote, |rejection| assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. })));
                let (driver, _) = admit(driver, current_nil_precommit_event(&nil));
                let driver = reject_current_nil_prevote(driver, &denied, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                            newly_saturated: true,
                            ..
                        }
                    ))
                });
                let (driver, _) = admit_due(driver, timeout);
                let classification = driver.classify_current_finality_evidence().unwrap();
                assert!(matches!(classification, FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }));
                let before = candidate_backed::custody(&driver);
                let driver = advanced(
                    catch_up(
                        driver,
                        batch,
                        &certificate,
                        &vote,
                        2,
                        ConsensusVoteRole::Prevote,
                        ConsensusVoteTarget::Nil,
                    )
                    .unwrap(),
                );
                assert_eq!(candidate_backed::custody(&driver), before);
                assert_eq!(driver.classify_current_finality_evidence().unwrap(), classification);
                let (driver, _) = step_arm(driver);
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated { .. }
                        ));
                        *driver
                    }
                    _ => panic!("current saturation must survive catch-up"),
                };
                let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
                assert_eq!(
                    drained_contents(drained),
                    (
                        vec![(higher_control.clone(), higher_payload.clone())],
                        vec![]
                    )
                );
                let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
                assert_eq!(
                    drained_current_contents(drained),
                    (vec![(control.clone(), payload.clone())], vec![], vec![])
                );
                let (driver, drained) =
                    driver.drain_current_finality_inbox_and_reset().into_parts();
                assert_eq!(
                    drained_current_finality_contents(drained),
                    (vec![(control.clone(), payload.clone())], vec![])
                );
                let (driver, drained) = driver
                    .drain_current_nil_precommit_inbox_and_reset()
                    .into_parts();
                assert_eq!(
                    drained_current_nil_precommit_contents(drained),
                    vec![nil.clone()]
                );
                assert_eq!(candidate_backed::custody(&driver), ([0; 4], [0; 3]));
            })
            .unwrap();
    }
}

#[test]
fn catchup_checkpoints_existing_lock_and_complete_valid_evidence_before_any_new_vote() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let (valid_certificate, prevote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
    );
    for batch in [false, true] {
        let (certificate, vote) = quorum(
            &fixture,
            4,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Nil,
        );
        let layout = TestLayout::new("driver-higher-catchup-lock");
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
                let (driver, signed, released) = step_publish(driver);
                assert_eq!(signed.target(), ConsensusVoteTarget::Proposal(root));
                assert!(released.is_some());
                let (driver, _) = step_arm(driver);
                let before = layout.images();
                let driver = advanced(
                    catch_up(
                        driver,
                        batch,
                        &certificate,
                        &vote,
                        4,
                        ConsensusVoteRole::Precommit,
                        ConsensusVoteTarget::Nil,
                    )
                    .unwrap(),
                );
                assert_eq!(driver.position().round(), ConsensusRound::new(4));
                assert_eq!(layout.images()[0..2], before[0..2]);
                // Reopen immediately: no later signed vote can conceal a missing checkpoint.
                drop(driver);
            })
            .unwrap();
        let images = layout.images();
        let ready = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        let position = round_at(&branch, 4).position();
        assert!(ready.vote.pending_vote().unwrap().is_none());
        for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
            assert!(
                ready
                    .vote
                    .retained_signed_vote(position, role)
                    .unwrap()
                    .is_none()
            );
        }
        ready
            .run_with_signing_session(|mut scope| {
                let signing = scope.signing_session();
                assert_eq!(signing.position(), position);
                assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Precommit);
                let locked = signing.locked_value().unwrap();
                assert_eq!(locked.round(), ConsensusRound::new(2));
                assert_eq!(locked.proposal_signing_root(), root);
                let valid = signing.valid_value().unwrap();
                assert_eq!(valid.round(), ConsensusRound::new(2));
                assert_eq!(valid.value(), value);
                assert_eq!(valid.canonical_prevote_certificate(), valid_certificate);
            })
            .unwrap();
        assert_eq!(layout.images(), images);
    }
}
