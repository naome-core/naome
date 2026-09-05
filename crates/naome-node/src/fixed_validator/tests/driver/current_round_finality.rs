use super::lower_round_finality::{Proof, drain_all, malformed, proof, retain_all, round_two};
use super::*;

fn submit<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    input: &Proof,
    batch: bool,
) -> Result<
    FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0<'node>,
    FixedValidatorNodeDriverStepErrorV0,
> {
    if batch {
        let votes: Vec<&[u8]> = input.votes.iter().map(Vec::as_slice).collect();
        driver.commit_current_round_finality_vote_batch(
            &input.control,
            input.payload.clone(),
            &votes,
        )
    } else {
        driver.commit_current_round_finality(
            &input.control,
            input.payload.clone(),
            &input.certificate,
        )
    }
}

#[test]
fn current_finality_rejections_preserve_due_custody_and_allow_exact_retry() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let valid = proof(&fixture, &branch, 2, ZfcAxiom::Pairing);
    for batch in [false, true] {
        let layout = TestLayout::new("driver-current-finality-retry");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready.run_with_signing_session(|scope| {
            let (driver, timeout) = round_two(scope, 8);
            let (driver, retained) = retain_all(driver, &fixture, &branch);
            let (mut driver, _) = admit_due(driver, timeout);
            let images = layout.images();
            let custody = candidate_backed::custody(&driver);
            for mode in ["proposal", "payload", "framing", "signature", "older", "future", "wrong-role", "duplicate", "empty"] {
                if !batch && matches!(mode, "duplicate" | "empty") { continue; }
                let mut input = valid.clone();
                match mode {
                    "proposal" => input.control = vec![0],
                    "payload" => input.payload = vec![0],
                    "framing" => { input.certificate = vec![0]; input.votes = vec![vec![0]]; }
                    "signature" => { *input.certificate.last_mut().unwrap() ^= 1; *input.votes[0].last_mut().unwrap() ^= 1; }
                    "older" => input = proof(&fixture, &branch, 1, ZfcAxiom::Pairing),
                    "future" => input = proof(&fixture, &branch, 3, ZfcAxiom::Pairing),
                    "wrong-role" => { let (certificate, vote) = higher_round::quorum(&fixture, 2, ConsensusVoteRole::Prevote,
                        ConsensusVoteTarget::Proposal(valid.value.proposal_signing_root())); input.certificate = certificate; input.votes = vec![vote]; },
                    "empty" => input.votes.clear(),
                    "duplicate" => input.votes.push(input.votes[0].clone()),
                    _ => unreachable!(),
                }
                driver = match submit(driver, &input, batch).unwrap() {
                    FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0::Rejected { driver, rejection } => {
                        assert!(matches!(*rejection, FixedValidatorNodeCurrentRoundFinalityRejectionV0::Proposal(_)
                            | FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(_)
                            | FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitBatch(_)));
                        *driver
                    }
                    _ => panic!("invalid {mode} must return the driver before effects"),
                };
                assert_eq!(driver.position(), timeout.position());
                assert_eq!(driver.phase(), timeout.phase());
                assert!(driver.timeout_is_due());
                assert!(!driver.has_pending_command());
                assert_eq!(candidate_backed::custody(&driver), custody);
                assert_eq!(layout.images(), images);
            }
            // The original exact timer remains live through every rejection.
            let disposition;
            (driver, disposition) = admit_due(driver, timeout);
            assert_eq!(disposition, FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue);
            let driver = finalized(submit(driver, &valid, batch).unwrap(), &branch, &valid);
            assert_eq!(candidate_backed::custody(&driver), custody);
            let (driver, _) = step_arm(driver);
            let _ = step_idle(drain_all(driver, retained));
        }).unwrap();
    }
}

#[test]
fn current_finality_preserves_four_saturated_inboxes_and_their_exact_bytes() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let input = proof(&fixture, &branch, 2, ZfcAxiom::Pairing);
    for batch in [false, true] {
        let layout = TestLayout::new("driver-current-finality-saturation");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready.run_with_signing_session(|scope| {
            let (driver, timeout) = round_two(scope, 1);
            let (mut driver, retained) = retain_all(driver, &fixture, &branch);
            let (_, higher_prevote) = higher_round::quorum(&fixture, 3, ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(retained.higher.value.proposal_signing_root()));
            let nil_prevote = signed_vote_bytes(fixture.context, driver.position(), ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Nil, &fixture.signing_key());
            driver = reject_current_nil_prevote(driver, &nil_prevote, |rejection| {
                assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                    newly_saturated: true, ..
                }));
            });
            driver = reject_current_finality_precommit(driver, &retained.current.votes[0], |rejection| {
                assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    newly_saturated: true, ..
                }));
            });
            let denied_nil = signed_vote_bytes_with_test_only_nonce_prefix(fixture.context, driver.position(),
                ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil, &fixture.signing_key(), 0x37);
            driver = reject_current_nil_precommit(driver, &denied_nil, |rejection| {
                assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                    newly_saturated: true, ..
                }));
            });
            (driver, _) = admit_due(driver, timeout);
            driver = reject_prevote(driver, &higher_prevote, |rejection| {
                assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(source)
                    if source.newly_saturated()));
            });
            let custody = candidate_backed::custody(&driver);
            assert_eq!(custody.0, [1; 4]);
            assert!(matches!(driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }));
            let driver = finalized(submit(driver, &input, batch).unwrap(), &branch, &input);
            assert_eq!(candidate_backed::custody(&driver), custody);
            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(reason, FixedValidatorNodeDriverBlockReasonV0::Saturated(_)));
                    *driver
                }
                _ => panic!("higher saturation must survive finality"),
            };
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(drained_contents(drained), (vec![(retained.higher.control, retained.higher.payload)], vec![]));
            let mut driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(reason, FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated { .. }));
                    *driver
                }
                _ => panic!("current saturation must survive finality"),
            };
            assert!(matches!(driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }));
            driver = reject_current_nil_precommit(driver, &denied_nil, |rejection| {
                assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                    newly_saturated: false, ..
                }));
            });
            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            assert_eq!(drained_current_contents(drained), (vec![(retained.current.control.clone(), retained.current.payload.clone())], vec![], vec![]));
            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            assert_eq!(drained_current_finality_contents(drained), (vec![(retained.current.control, retained.current.payload)], vec![]));
            let (driver, drained) = driver.drain_current_nil_precommit_inbox_and_reset().into_parts();
            assert_eq!(drained_current_nil_precommit_contents(drained), vec![retained.nil]);
            assert_eq!(candidate_backed::custody(&driver), ([0; 4], [0; 3]));
            let _ = step_idle(*driver);
        }).unwrap();
    }
}

#[test]
fn current_finality_generation_exhaustion_consumes_before_input_or_writes() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let invalid = malformed(&proof(&fixture, &branch, 2, ZfcAxiom::Pairing));
    for batch in [false, true] {
        let layout = TestLayout::new("driver-current-finality-generation");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (mut driver, _) = round_two(scope, 8);
                driver.set_timer_generation_for_test(u64::MAX);
                let before = layout.images();
                assert!(matches!(
                    submit(driver, &invalid, batch),
                    Err(
                        FixedValidatorNodeDriverStepErrorV0::TimeoutGenerationExhausted {
                            generation: u64::MAX
                        }
                    )
                ));
                assert_eq!(layout.images(), before);
            })
            .unwrap();
        let reopened = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        reopened
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 8, 4));
                assert_eq!(driver.position().height().value(), 1);
                assert!(!driver.has_pending_command());
                assert_eq!(candidate_backed::custody(&driver), ([0; 4], [0; 3]));
            })
            .unwrap();
    }
}

#[test]
fn current_finality_anchor_failures_preserve_stage_evidence_and_require_strict_reopen() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let input = proof(&fixture, &branch, 2, ZfcAxiom::Pairing);
    for batch in [false, true] {
        for fail_finality in [false, true] {
            let layout = TestLayout::new("driver-current-finality-anchor");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready.run_with_signing_session(|scope| {
                let (driver, _) = round_two(scope, 8);
                let before = layout.images();
                let (directory, offset) = if fail_finality {
                    (&layout.finality_anchor, 149)
                } else {
                    (&layout.vote_anchor, 184)
                };
                let image = directory_image(directory);
                let bytes = &image.iter().find(|(name, _)| name.ends_with(".anchor")).unwrap().1;
                let sequence = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
                let collision = next_anchor_collision(directory, sequence + 1);
                let error = match submit(driver, &input, batch) {
                    Err(FixedValidatorNodeDriverStepErrorV0::CurrentFinality(source)) => match *source {
                        FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(source) => source,
                        other => panic!("expected finality-stage failure: {other:?}"),
                    },
                    _ => panic!("anchor failure must return neither driver nor success command"),
                };
                match (fail_finality, *error) {
                    (true, FixedValidatorNodeFinalityErrorV0::Commit(source)) => {
                        assert!(matches!(*source, naome_storage::FixedValidatorFinalityJournalErrorV0::Commit { .. }));
                    }
                    (false, FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare { selection, source }) => {
                        assert!(matches!(*selection, FixedValidatorNodeFinalitySelectionV0::Finalized {
                            position, ancestry_id, ..
                        } if position == round_at(&branch, 2).position() && ancestry_id == input.value.ancestry_id()));
                        assert!(matches!(*source, FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }));
                    }
                    (_, other) => panic!("wrong durable failure stage: {other:?}"),
                }
                fs::remove_file(collision).unwrap();
                let after = layout.images();
                assert_ne!(after[0], before[0]);
                if fail_finality { assert_eq!(after[1..], before[1..]); }
                else {
                    assert_ne!(after[1], before[1]);
                    assert_ne!(after[2], before[2]);
                    assert_eq!(after[3], before[3]);
                }
            }).unwrap();
            let result = fixture.provision(&layout, 8).open(fixture.signing_key());
            match (fail_finality, result) {
                (true, Err(FixedValidatorNodeStartupErrorV0::FinalityPair(source))) => {
                    assert!(matches!(
                        *source,
                        naome_storage::FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                            naome_storage::FixedValidatorFinalityJournalErrorV0::AnchorBehind { .. }
                        )
                    ));
                }
                (false, Err(FixedValidatorNodeStartupErrorV0::VotePair(source))) => {
                    assert!(
                        matches!(*source, FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                        if matches!(*inner, FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }))
                    );
                }
                _ => panic!("strict reopen must classify the independently lagging anchor"),
            }
        }
    }
}

fn finalized<'node>(
    result: FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0<'node>,
    branch: &FixedConsensusBranchV0,
    input: &Proof,
) -> FixedValidatorNodeDriverV0<'node> {
    match result {
        FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0::Finality { driver, selection } => {
            let round = round_at(branch, input.round);
            let expected = round
                .decode_and_verify_proposal_control(&input.control, input.payload.clone())
                .unwrap()
                .seal_with_precommit_certificate(&input.certificate)
                .unwrap();
            assert!(
                matches!(selection, FixedValidatorNodeFinalitySelectionV0::Finalized {
                position, ancestry_id, envelope_id, ..
            } if position == round.position() && ancestry_id == input.value.ancestry_id()
                && envelope_id == expected.envelope_id())
            );
            *driver
        }
        _ => panic!("complete direct current-round proof must finalize"),
    }
}

#[test]
fn current_finality_forms_match_from_every_phase_and_due_state_and_reopen() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let input = proof(&fixture, &branch, 2, ZfcAxiom::Pairing);
    for phase_steps in 0..=2 {
        for due in [false, true] {
            let mut reference_images = None;
            for batch in [false, true] {
                let layout = TestLayout::new("driver-current-finality-handoff");
                let ready = fixture
                    .provision(&layout, 8)
                    .create(fixture.signing_key())
                    .unwrap();
                ready
                    .run_with_signing_session(|scope| {
                        let (mut driver, mut timeout) = round_two(scope, 8);
                        for _ in 0..phase_steps {
                            (driver, _) = admit_due(driver, timeout);
                            driver = step_transition(driver);
                            (driver, _, _) = step_publish(driver);
                            (driver, timeout) = step_arm(driver);
                        }
                        if due {
                            (driver, _) = admit_due(driver, timeout);
                        }
                        let before = layout.images();
                        let driver =
                            finalized(submit(driver, &input, batch).unwrap(), &branch, &input);
                        for (old, new) in before.iter().zip(layout.images()) {
                            assert_ne!(old, &new, "every authority image must advance");
                        }
                        assert_eq!(driver.position().height().value(), 2);
                        assert_eq!(driver.position().round().value(), 0);
                        assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                        assert!(!driver.timeout_is_due());
                        assert!(driver.has_pending_command());
                        let (driver, child_timeout) = step_arm(driver);
                        assert_eq!(child_timeout.generation(), timeout.generation() + 1);
                        assert_eq!(child_timeout.position(), driver.position());
                        assert_eq!(child_timeout.phase(), FixedValidatorLockPhaseV0::Proposal);
                        assert!(!driver.has_pending_command());
                        let driver = match driver
                            .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(timeout))
                            .unwrap()
                        {
                            FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                                driver,
                                rejection,
                                ..
                            } => {
                                assert!(matches!(
                                    *rejection,
                                    FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                                ));
                                *driver
                            }
                            _ => panic!("old timer must be invalid after child handoff"),
                        };
                        let driver = step_idle(driver);
                        let (_, disposition) = admit_due(driver, child_timeout);
                        assert_eq!(
                            disposition,
                            FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                        );
                    })
                    .unwrap();
                let images = layout.images();
                if let Some(reference) = &reference_images {
                    assert_eq!(&images, reference);
                } else {
                    reference_images = Some(images.clone());
                }
                let reopened = expect_ready(
                    fixture
                        .provision_with_catch_up_limit(&layout, 8, 0)
                        .open(fixture.signing_key())
                        .unwrap(),
                );
                assert!(reopened.vote.pending_vote().unwrap().is_none());
                reopened
                    .run_with_signing_session(|mut scope| {
                        assert_eq!(
                            scope.branch().artifact_snapshot().head_block_id(),
                            input.value.artifact_block().id()
                        );
                        assert_eq!(scope.signing_session().position().height().value(), 2);
                        assert_eq!(scope.signing_session().position().round().value(), 0);
                        assert_eq!(
                            scope.signing_session().phase(),
                            FixedValidatorLockPhaseV0::Proposal
                        );
                        assert_eq!(
                            candidate_backed::custody(&driver(scope, 8, 4)),
                            ([0; 4], [0; 3])
                        );
                    })
                    .unwrap();
                assert_eq!(layout.images(), images);
            }
        }
    }
}

#[test]
fn current_finality_waits_for_every_pending_command_without_losing_publication() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let invalid = malformed(&proof(&fixture, &branch, 2, ZfcAxiom::Pairing));
    let proposal = proof(&fixture, &branch, 0, ZfcAxiom::Union);
    let higher = proof(&fixture, &branch, 2, ZfcAxiom::PowerSet);
    let (_, higher_prevote) = higher_round::quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher.value.proposal_signing_root()),
    );
    for batch in [false, true] {
        for mode in ["arm", "prevote", "precommit", "higher", "proposal"] {
            let layout = TestLayout::new("driver-current-finality-pending");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready
                .run_with_signing_session(|scope| {
                    let mut driver = driver(scope, 8, 4);
                    if mode != "arm" {
                        let timeout;
                        (driver, timeout) = step_arm(driver);
                        if matches!(mode, "prevote" | "precommit") {
                            (driver, _) = admit_due(driver, timeout);
                            driver = step_transition(driver);
                            if mode == "precommit" {
                                (driver, _, _) = step_publish(driver);
                                let timeout;
                                (driver, timeout) = step_arm(driver);
                                (driver, _) = admit_due(driver, timeout);
                                driver = step_transition(driver);
                            }
                        } else if mode == "higher" {
                            (driver, _) =
                                admit(driver, proposal_event(2, &higher.control, &higher.payload));
                            (driver, _) = admit(driver, prevote_event(&higher_prevote));
                            driver = step_transition(driver);
                        } else {
                            driver = match driver
                                .author_proposal(
                                    naome_consensus::FixedValidatorProposalSourceV0::Fresh {
                                        artifact_block: proposal.value.artifact_block(),
                                        canonical_artifact_bytes: proposal.payload.clone(),
                                    },
                                )
                                .unwrap()
                            {
                                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Authored {
                                    driver,
                                } => *driver,
                                _ => panic!("proposal publication must be prepared"),
                            };
                        }
                    }
                    let images = layout.images();
                    let custody = candidate_backed::custody(&driver);
                    let position = driver.position();
                    let phase = driver.phase();
                    let due = driver.timeout_is_due();
                    driver.set_timer_generation_for_test(u64::MAX);
                    driver = match submit(driver, &invalid, batch).unwrap() {
                        FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0::CommandPending {
                            driver,
                        } => *driver,
                        _ => panic!("pending {mode} must precede generation and malformed input"),
                    };
                    assert_eq!(driver.position(), position);
                    assert_eq!(driver.phase(), phase);
                    assert_eq!(driver.timeout_is_due(), due);
                    assert_eq!(candidate_backed::custody(&driver), custody);
                    assert_eq!(layout.images(), images);
                    let command = match driver.step().unwrap() {
                        FixedValidatorNodeDriverStepOutcomeV0::Command { command, .. } => command,
                        _ => panic!("the original pending command must still transfer"),
                    };
                    match (mode, command) {
                        ("arm", FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(timeout)) => {
                            assert_eq!(timeout.position(), position);
                            assert_eq!(timeout.generation(), 0);
                        }
                        (
                            "prevote" | "precommit" | "higher",
                            FixedValidatorNodeDriverCommandV0::PublishVote {
                                vote,
                                released_proposal,
                            },
                        ) => {
                            assert_eq!(vote.position(), position);
                            assert_eq!(
                                vote.role(),
                                if mode == "prevote" {
                                    ConsensusVoteRole::Prevote
                                } else {
                                    ConsensusVoteRole::Precommit
                                }
                            );
                            if mode == "higher" {
                                let token = released_proposal
                                    .expect("higher publication retains its exact token");
                                assert_eq!(
                                    token.canonical_proposal_control_bytes(),
                                    higher.control
                                );
                                assert_eq!(token.canonical_artifact_bytes(), higher.payload);
                                assert_eq!(
                                    vote.target(),
                                    ConsensusVoteTarget::Proposal(
                                        higher.value.proposal_signing_root()
                                    )
                                );
                            } else {
                                assert!(released_proposal.is_none());
                                assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                            }
                        }
                        (
                            "proposal",
                            FixedValidatorNodeDriverCommandV0::PublishProposal {
                                proposal: signed,
                                canonical_artifact_bytes,
                            },
                        ) => {
                            assert_eq!(
                                signed.proposal_signing_root(),
                                proposal.value.proposal_signing_root()
                            );
                            assert_eq!(canonical_artifact_bytes, proposal.payload);
                        }
                        _ => panic!("the original {mode} command changed"),
                    }
                    assert_eq!(layout.images(), images);
                })
                .unwrap();
        }
    }
}

#[test]
fn current_finality_preserves_retained_missing_ready_conflicting_and_pair_priority() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let left = proof(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let right = proof(&fixture, &branch, 2, ZfcAxiom::Union);
    let invalid = malformed(&proof(&fixture, &branch, 1, ZfcAxiom::PowerSet));
    for batch in [false, true] {
        for mode in ["missing", "ready", "conflicting", "pair", "saturated-pair"] {
            let layout = TestLayout::new("driver-current-finality-retained");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready.run_with_signing_session(|scope| {
                let (mut driver, timeout) = round_two(scope, 4);
                (driver, _) = admit(driver, current_finality_precommit_event(&left.votes[0]));
                if mode != "missing" {
                    (driver, _) = admit(driver, current_finality_proposal_event(&left.control, &left.payload));
                }
                if matches!(mode, "conflicting" | "pair" | "saturated-pair") {
                    (driver, _) = admit(driver, current_finality_precommit_event(&right.votes[0]));
                }
                if matches!(mode, "pair" | "saturated-pair") {
                    (driver, _) = admit(driver, current_finality_proposal_event(&right.control, &right.payload));
                }
                if mode == "saturated-pair" {
                    let denied = signed_vote_bytes_with_test_only_nonce_prefix(fixture.context, driver.position(),
                        ConsensusVoteRole::Precommit, ConsensusVoteTarget::Proposal(left.value.proposal_signing_root()),
                        &fixture.signing_key(), 0x35);
                    driver = reject_current_finality_precommit(driver, &denied, |rejection| {
                        assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                            newly_saturated: true, ..
                        }));
                    });
                }
                (driver, _) = admit_due(driver, timeout);
                let images = layout.images();
                let custody = candidate_backed::custody(&driver);
                let classification = driver.classify_current_finality_evidence().unwrap();
                driver.set_timer_generation_for_test(u64::MAX);
                driver = match submit(driver, &invalid, batch).unwrap() {
                    FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0::CurrentFinalityUnresolved { driver } => *driver,
                    _ => panic!("retained {mode} must precede generation and input inspection"),
                };
                assert_eq!(driver.position(), timeout.position());
                assert_eq!(driver.phase(), timeout.phase());
                assert!(driver.timeout_is_due());
                assert!(!driver.has_pending_command());
                assert_eq!(candidate_backed::custody(&driver), custody);
                assert_eq!(driver.classify_current_finality_evidence().unwrap(), classification);
                assert_eq!(layout.images(), images);
                driver.set_timer_generation_for_test(timeout.generation());
                match (mode, driver.step().unwrap()) {
                    ("ready", FixedValidatorNodeDriverStepOutcomeV0::Finality { selection, .. }) => {
                        assert!(matches!(selection, FixedValidatorNodeFinalitySelectionV0::Finalized {
                            ancestry_id, ..
                        } if ancestry_id == left.value.ancestry_id()));
                    }
                    ("pair" | "saturated-pair", FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(_)) => {}
                    ("missing" | "conflicting", FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, .. }) => {
                        assert_eq!(candidate_backed::custody(&driver), custody);
                        assert_eq!(layout.images(), images);
                    }
                    _ => panic!("ordinary step must preserve its {mode} outcome"),
                }
            }).unwrap();
        }
    }
}

#[test]
fn saturated_unique_retained_proof_falls_through_without_granting_pair_priority() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let retained = proof(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let explicit = proof(&fixture, &branch, 2, ZfcAxiom::Union);
    for batch in [false, true] {
        let layout = TestLayout::new("driver-current-finality-saturated-unique");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready.run_with_signing_session(|scope| {
            let (mut driver, _) = round_two(scope, 2);
            (driver, _) = admit(driver, current_finality_proposal_event(&retained.control, &retained.payload));
            (driver, _) = admit(driver, current_finality_precommit_event(&retained.votes[0]));
            assert!(matches!(driver.classify_current_finality_evidence().unwrap(), FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready { .. }));
            driver = reject_current_finality_precommit(driver, &explicit.votes[0], |rejection| {
                assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. }));
            });
            let custody = candidate_backed::custody(&driver);
            assert!(matches!(driver.classify_current_finality_evidence().unwrap(), FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }));
            let driver = finalized(submit(driver, &explicit, batch).unwrap(), &branch, &explicit);
            assert_eq!(candidate_backed::custody(&driver), custody);
            let (_, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            assert_eq!(drained_current_finality_contents(drained), (vec![(retained.control.clone(), retained.payload.clone())], retained.votes.clone()));
        }).unwrap();
    }
}
