use super::lower_round_finality::{drain_all, retain_all, round_two};
use super::*;
use crate::FixedValidatorNodeDriverEnvelopeOutcomeV0 as Outcome;
use crate::FixedValidatorNodeEnvelopeRejectionV0 as Rejection;

fn proof(fixture: &Fixture, round: u64) -> OwnedVerifiedFixedConsensusTransitionV0 {
    fixture.transition(
        &fixed_branch(fixture),
        &ArtifactChainState::new(fixture.definition),
        ZfcAxiom::Pairing,
        round,
    )
}

#[test]
fn envelope_finality_accepts_all_relative_rounds_preserves_custody_and_reopens_child() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    for evidence_round in [0, 2, 3] {
        let input = proof(&fixture, evidence_round);
        let envelope = input.canonical_envelope_bytes().to_vec();
        let payload = input.canonical_artifact_bytes().to_vec();
        let value = input.value();
        let layout = TestLayout::new("driver-envelope-relative-rounds");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready.run_with_signing_session(|scope| {
            let (driver, timer) = round_two(scope, 8);
            let (driver, retained) = retain_all(driver, &fixture, &branch);
            let (driver, _) = admit_due(driver, timer);
            let custody = candidate_backed::custody(&driver);
            let images = layout.images();
            let mut driver = match driver.commit_finality_envelope(&envelope, payload.clone()).unwrap() {
                Outcome::Finality { driver, selection } => {
                    assert!(matches!(selection, FixedValidatorNodeFinalitySelectionV0::Finalized { position, ancestry_id, .. }
                        if position.round().value() == evidence_round && ancestry_id == value.ancestry_id()));
                    *driver
                }
                _ => panic!("complete direct-child proof must finalize"),
            };
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round().value(), 0);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.timeout_is_due());
            assert_eq!(candidate_backed::custody(&driver), custody);
            for (before, after) in images.iter().zip(layout.images()) { assert_ne!(*before, after); }
            let (next, armed) = step_arm(driver);
            driver = next;
            assert_eq!(armed.generation(), timer.generation() + 1);
            assert_eq!(armed.position(), driver.position());
            let driver = drain_all(driver, retained);
            let images = layout.images();
            // Selected-height replay is rejected, never rerouted to a conflict API.
            match driver.commit_finality_envelope(&envelope, payload.clone()).unwrap() {
                Outcome::Rejected { driver, rejection } => {
                    assert!(matches!(*rejection, Rejection::Proof(_)));
                    assert_eq!(driver.position().height().value(), 2);
                }
                _ => panic!("old-height envelope is not a direct child"),
            }
            assert_eq!(layout.images(), images);
        }).unwrap();
        let images = layout.images();
        let ready = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        ready
            .run_with_signing_session(|mut scope| {
                assert_eq!(scope.signing_session().position().height().value(), 2);
                assert_eq!(
                    scope.signing_session().phase(),
                    FixedValidatorLockPhaseV0::Proposal
                );
                assert_eq!(
                    scope.branch().artifact_snapshot().head_block_id(),
                    value.artifact_block().id()
                );
            })
            .unwrap();
        assert_eq!(layout.images(), images);
    }
}

#[test]
fn envelope_rejections_preserve_exact_due_state_before_valid_retry() {
    let fixture = Fixture::new();
    let input = proof(&fixture, 2);
    let envelope = input.canonical_envelope_bytes().to_vec();
    let payload = input.canonical_artifact_bytes().to_vec();
    let over = proof(&fixture, 9);
    let layout = TestLayout::new("driver-envelope-rejections");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, timer) = round_two(scope, 8);
            let (mut driver, _) = admit_due(driver, timer);
            let images = layout.images();
            let mut bad_signature = envelope.clone();
            *bad_signature.last_mut().unwrap() ^= 1;
            let mut foreign_context = envelope.clone();
            foreign_context[0] ^= 1;
            let cases = [
                (vec![], payload.clone()),
                (envelope[..envelope.len() - 1].to_vec(), payload.clone()),
                (bad_signature, payload.clone()),
                (foreign_context, payload.clone()),
                (envelope.clone(), vec![0]),
                (
                    over.canonical_envelope_bytes().to_vec(),
                    over.canonical_artifact_bytes().to_vec(),
                ),
            ];
            for (bytes, payload) in cases {
                driver = match driver.commit_finality_envelope(&bytes, payload).unwrap() {
                    Outcome::Rejected { driver, rejection } => {
                        assert!(matches!(*rejection, Rejection::Proof(_)));
                        *driver
                    }
                    _ => panic!("invalid proof must reject without effects"),
                };
                assert_eq!(layout.images(), images);
                assert_eq!(driver.position(), timer.position());
                assert_eq!(driver.phase(), timer.phase());
                assert!(driver.timeout_is_due());
                assert!(!driver.has_pending_command());
            }
            assert!(matches!(
                driver.commit_finality_envelope(&envelope, payload).unwrap(),
                Outcome::Finality { .. }
            ));
        })
        .unwrap();
}

#[test]
fn envelope_pending_and_retained_finality_precede_generation_and_proof_inspection() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let input = lower_round_finality::proof(&fixture, &branch, 0, ZfcAxiom::Pairing);
    for retained in [false, true] {
        let layout = TestLayout::new("driver-envelope-priority");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let mut driver = driver(scope, 8, 4);
                if retained {
                    (driver, _) = step_arm(driver);
                    (driver, _) = admit(driver, current_finality_precommit_event(&input.votes[0]));
                }
                driver.set_timer_generation_for_test(u64::MAX);
                let images = layout.images();
                let driver = match driver.commit_finality_envelope(&[0], vec![0]).unwrap() {
                    Outcome::CommandPending { driver } if !retained => *driver,
                    Outcome::CurrentFinalityUnresolved { driver } if retained => *driver,
                    _ => panic!("priority must precede generation and malformed proof"),
                };
                assert_eq!(driver.current_finality_inbox_len(), usize::from(retained));
                assert_eq!(layout.images(), images);
            })
            .unwrap();
    }
    let layout = TestLayout::new("driver-envelope-generation");
    fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap()
        .run_with_signing_session(|scope| {
            let (mut driver, _) = step_arm(driver(scope, 8, 4));
            driver.set_timer_generation_for_test(u64::MAX);
            let images = layout.images();
            assert!(matches!(
                driver.commit_finality_envelope(&[0], vec![0]),
                Err(
                    FixedValidatorNodeDriverStepErrorV0::TimeoutGenerationExhausted {
                        generation: u64::MAX
                    }
                )
            ));
            assert_eq!(layout.images(), images);
        })
        .unwrap();
}

#[test]
fn envelope_anchor_failures_consume_driver_and_strict_restart_refuses_ambiguous_prefix() {
    let fixture = Fixture::new();
    let input = proof(&fixture, 2);
    for fail_finality in [true, false] {
        let layout = TestLayout::new("driver-envelope-anchor-failure");
        fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap()
            .run_with_signing_session(|scope| {
                let (driver, _) = round_two(scope, 8);
                let before = layout.images();
                let (directory, offset) = if fail_finality {
                    (&layout.finality_anchor, 149)
                } else {
                    (&layout.vote_anchor, 184)
                };
                let image = directory_image(directory);
                let bytes = &image
                    .iter()
                    .find(|(name, _)| name.ends_with(".anchor"))
                    .unwrap()
                    .1;
                let sequence = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
                let collision = next_anchor_collision(directory, sequence + 1);
                assert!(matches!(
                    driver.commit_finality_envelope(
                        input.canonical_envelope_bytes(),
                        input.canonical_artifact_bytes().to_vec()
                    ),
                    Err(FixedValidatorNodeDriverStepErrorV0::CurrentFinality(_))
                ));
                fs::remove_file(collision).unwrap();
                let after = layout.images();
                assert_ne!(after[0], before[0]);
                if fail_finality {
                    assert_eq!(after[1..], before[1..]);
                } else {
                    assert_ne!(after[1], before[1]);
                    assert_ne!(after[2], before[2]);
                    assert_eq!(after[3], before[3]);
                }
            })
            .unwrap();
        assert!(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .is_err()
        );
    }
}
