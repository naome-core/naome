use super::lower_round_pair::{ProofInput, proof_input, round_two_driver};
use super::*;

type Pair<'node> = FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0<'node>;

fn submit<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    first: &ProofInput,
    second: &ProofInput,
) -> Result<Pair<'node>, FixedValidatorNodeCurrentRoundFinalityErrorV0> {
    driver.commit_current_round_preselection_conflict_vote_batches(
        &first.1,
        first.2.clone(),
        &[&first.3],
        &second.1,
        second.2.clone(),
        &[&second.3],
    )
}

#[test]
fn current_pair_waits_for_pending_arm_and_vote_before_inspecting_proofs() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-pair-pending");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let mut driver = driver(scope, 8, 4);
            for pending_vote in [false, true] {
                let before = layout.images();
                let position = driver.position();
                let phase = driver.phase();
                let timeout = driver.active_timeout();
                driver = match driver
                    .commit_current_round_preselection_conflict_vote_batches(
                        &[0],
                        vec![0],
                        &[],
                        &[0],
                        vec![0],
                        &[],
                    )
                    .unwrap()
                {
                    Pair::CommandPending { driver } => *driver,
                    _ => panic!("command custody must precede malformed proof work"),
                };
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), phase);
                assert_eq!(driver.active_timeout(), timeout);
                assert!(driver.has_pending_command());
                assert_eq!(layout.images(), before);
                if pending_vote {
                    let (next, vote, proposal) = step_publish(driver);
                    assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                    assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                    assert!(proposal.is_none());
                    driver = next;
                } else {
                    let (next, timeout) = step_arm(driver);
                    let (next, _) = admit_due(next, timeout);
                    driver = step_transition(next);
                }
            }
            assert!(driver.has_pending_command());
        })
        .unwrap();
}

#[test]
fn current_pair_halts_from_every_phase_despite_retained_work_due_and_generation_exhaustion() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let first = proof_input(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let second = proof_input(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher = proof_input(&fixture, &branch, 3, ZfcAxiom::PowerSet);
    let position = round_at(&branch, 2).position();
    let nil = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 3).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher.0.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let expected = if first.0.proposal_signing_root() < second.0.proposal_signing_root() {
        [first.0.ancestry_id(), second.0.ancestry_id()]
    } else {
        [second.0.ancestry_id(), first.0.ancestry_id()]
    };
    for phase_steps in 0..3 {
        for mode in ["empty", "missing", "ready", "saturated", "other_work"] {
            let mut reference = None;
            for reverse in [false, true] {
                let layout = TestLayout::new("driver-current-pair-priority");
                let ready = fixture
                    .provision(&layout, 8)
                    .create(fixture.signing_key())
                    .unwrap();
                let stopped = ready.run_with_signing_session(|scope| {
                    let (mut driver, mut timeout) = round_two_driver(scope, if mode == "saturated" { 1 } else { 4 });
                    for _ in 0..phase_steps {
                        (driver, _) = admit_due(driver, timeout);
                        driver = step_transition(driver);
                        let (next, vote, proposal) = step_publish(driver);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(proposal.is_none());
                        (driver, timeout) = step_arm(next);
                    }
                    if mode != "empty" {
                        (driver, _) = admit(driver, current_finality_precommit_event(&first.3));
                    }
                    if matches!(mode, "ready" | "other_work") {
                        (driver, _) = admit(driver, current_finality_proposal_event(&first.1, &first.2));
                    }
                    if mode == "saturated" {
                        driver = reject_current_finality_precommit(driver, &second.3, |rejection| {
                            assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. }));
                        });
                    }
                    if mode == "other_work" {
                        (driver, _) = admit(driver, proposal_event(3, &higher.1, &higher.2));
                        (driver, _) = admit(driver, prevote_event(&higher_prevote));
                        (driver, _) = admit(driver, current_nil_precommit_event(&nil));
                    }
                    let classification = driver.classify_current_finality_evidence().unwrap();
                    assert!(matches!((mode, classification),
                        ("empty", FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete)
                        | ("missing", FixedValidatorNodeDriverCurrentFinalityClassificationV0::QuorumMissingProposal(_))
                        | ("ready" | "other_work", FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(_))
                        | ("saturated", FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. })));
                    (driver, _) = admit_due(driver, timeout);
                    driver.set_timer_generation_for_test(u64::MAX);
                    let before = layout.images();
                    let (left, right) = if reverse { (&second, &first) } else { (&first, &second) };
                    let Pair::FinalityStopped(stop) = submit(driver, left, right).unwrap() else {
                        panic!("explicit complete pair must halt without selecting retained work")
                    };
                    assert!(before.iter().zip(layout.images()).all(|(before, after)| before != &after));
                    *stop
                }).unwrap();
                assert_eq!(
                    stopped.finality_halt().kind(),
                    naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
                );
                assert_eq!(stopped.finality_halt().first_ancestry(), expected[0]);
                assert_eq!(stopped.finality_halt().second_ancestry(), expected[1]);
                assert_eq!(
                    stopped.signer_stop().finality_state_id(),
                    stopped.finality_halt().state_id()
                );
                if let Some(previous) = &reference {
                    assert_eq!(&stopped, previous);
                } else {
                    reference = Some(stopped);
                }
                let images = layout.images();
                match fixture
                    .provision(&layout, 8)
                    .open(fixture.signing_key())
                    .unwrap()
                {
                    FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
                        assert_eq!(Some(reopened), reference)
                    }
                    _ => panic!("strict reopen must report the exact current pair halt"),
                }
                assert_eq!(layout.images(), images);
            }
        }
    }
}

#[test]
fn current_pair_rejections_preserve_exact_inbox_custody_and_allow_explicit_retry() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let first = proof_input(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let second = proof_input(&fixture, &branch, 2, ZfcAxiom::Union);
    let earlier = proof_input(&fixture, &branch, 1, ZfcAxiom::Union);
    let higher = proof_input(&fixture, &branch, 3, ZfcAxiom::PowerSet);
    let nil = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 2).position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let layout = TestLayout::new("driver-current-pair-rejection");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready.run_with_signing_session(|scope| {
        let (mut driver, timeout) = round_two_driver(scope, 1);
        (driver, _) = admit(driver, proposal_event(3, &higher.1, &higher.2));
        (driver, _) = admit(driver, current_proposal_event(&first.1, &first.2));
        (driver, _) = admit(driver, current_finality_precommit_event(&first.3));
        (driver, _) = admit(driver, current_nil_precommit_event(&nil));
        driver = reject_current_finality_precommit(driver, &second.3, |rejection| {
            assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. }));
        });
        (driver, _) = admit_due(driver, timeout);
        let classification = driver.classify_current_finality_evidence().unwrap();
        let accounting = (driver.current_inbox_canonical_input_bytes(),
            driver.current_finality_inbox_canonical_input_bytes(), driver.current_nil_precommit_inbox_canonical_input_bytes());
        let images = layout.images();
        let mut damaged = second.3.clone();
        *damaged.last_mut().unwrap() ^= 1;
        for failure in ["first", "second", "earlier", "higher", "duplicate", "signature", "empty"] {
            let right = match failure { "earlier" => &earlier, "higher" => &higher, _ => &second };
            let first_control = if failure == "first" { &[0][..] } else { &first.1 };
            let second_control = if failure == "second" { &[0][..] } else { &right.1 };
            let votes = match failure {
                "duplicate" => vec![right.3.as_slice(), right.3.as_slice()],
                "signature" => vec![damaged.as_slice()], "empty" => vec![],
                _ => vec![right.3.as_slice()],
            };
            driver = match driver.commit_current_round_preselection_conflict_vote_batches(
                first_control, first.2.clone(), &[&first.3], second_control, right.2.clone(), &votes,
            ).unwrap() {
                Pair::Rejected { driver, rejection } => {
                    assert!(matches!((failure, *rejection),
                        ("first", FixedValidatorNodeCurrentRoundFinalityRejectionV0::FirstProposal(_))
                        | ("second" | "earlier" | "higher", FixedValidatorNodeCurrentRoundFinalityRejectionV0::SecondProposal(_))
                        | ("duplicate" | "signature" | "empty", FixedValidatorNodeCurrentRoundFinalityRejectionV0::SecondPrecommitBatch(_))));
                    *driver
                }
                _ => panic!("invalid {failure} must preserve driver"),
            };
            assert_eq!((driver.inbox_len(), driver.current_inbox_len(), driver.current_finality_inbox_len(), driver.current_nil_precommit_inbox_len()), (1, 1, 1, 1));
            assert_eq!((driver.current_inbox_canonical_input_bytes(), driver.current_finality_inbox_canonical_input_bytes(), driver.current_nil_precommit_inbox_canonical_input_bytes()), accounting);
            assert_eq!(driver.classify_current_finality_evidence().unwrap(), classification);
            assert_eq!(driver.position(), timeout.position());
            assert_eq!(driver.phase(), timeout.phase());
            assert_eq!(driver.active_timeout(), Some(timeout));
            assert!(driver.timeout_is_due());
            assert!(!driver.has_pending_command());
            assert_eq!(layout.images(), images);
        }
        let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
        assert_eq!(drained_contents(drained), (vec![(higher.1.clone(), higher.2.clone())], vec![]));
        let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
        assert_eq!(drained_current_contents(drained), (vec![(first.1.clone(), first.2.clone())], vec![], vec![]));
        let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
        assert_eq!(drained_current_finality_contents(drained), (vec![], vec![first.3.clone()]));
        let (driver, drained) = driver.drain_current_nil_precommit_inbox_and_reset().into_parts();
        assert_eq!(drained_current_nil_precommit_contents(drained), vec![nil.clone()]);
        assert!(matches!(submit(*driver, &first, &second).unwrap(), Pair::FinalityStopped(_)));
    }).unwrap();
}

#[test]
fn current_pair_same_value_consumes_driver_and_reopens_the_unchanged_durable_prefix() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let first = proof_input(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let layout = TestLayout::new("driver-current-pair-same-value");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let authority = ready.run_with_signing_session(|scope| {
        let (driver, _) = round_two_driver(scope, 4);
        let before = layout.images();
        assert!(matches!(submit(driver, &first, &first),
            Err(FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(error))
                if matches!(error.as_ref(), FixedValidatorNodeFinalityErrorV0::Commit(source)
                    if matches!(source.as_ref(), naome_storage::FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct { .. }))));
        assert_eq!(layout.images(), before);
        before
    }).unwrap();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            assert_eq!(
                scope.branch().artifact_snapshot().head_block_id(),
                fixture.definition.id().virtual_genesis_block_id()
            );
            let driver = driver(scope, 8, 4);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert!(driver.has_pending_command());
        })
        .unwrap();
    assert_eq!(layout.images(), authority);
}

#[test]
fn current_pair_anchor_failures_consume_driver_and_reopen_fail_closed() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let first = proof_input(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let second = proof_input(&fixture, &branch, 2, ZfcAxiom::Union);
    for fail_finality in [true, false] {
        let layout = TestLayout::new("driver-current-pair-anchor-failure");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, _) = round_two_driver(scope, 4);
                let authority = layout.images();
                let sources = layout.source_images();
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
                let error = match submit(driver, &first, &second) {
                    Err(FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(error)) => error,
                    _ => {
                        panic!("anchor failure must consume the driver without publishing success")
                    }
                };
                match (fail_finality, *error) {
                    (true, FixedValidatorNodeFinalityErrorV0::Commit(source)) => {
                        assert!(matches!(
                            source.as_ref(),
                            naome_storage::FixedValidatorFinalityJournalErrorV0::PairedCommit { .. }
                        ));
                    }
                    (false, FixedValidatorNodeFinalityErrorV0::SignerStop { halt, source }) => {
                        assert_eq!(
                            halt.kind(),
                            naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
                        );
                        assert!(matches!(
                            source.as_ref(),
                            FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                        ));
                    }
                    (_, other) => panic!("unexpected anchor failure: {other:?}"),
                }
                fs::remove_file(collision).unwrap();
                let after = layout.images();
                assert_ne!(after[0], authority[0]);
                if fail_finality {
                    assert_eq!(after[1..], authority[1..]);
                } else {
                    assert_ne!(after[1], authority[1]);
                    assert_ne!(after[2], authority[2]);
                    assert_eq!(after[3], authority[3]);
                }
                assert_eq!(layout.source_images(), sources);
            })
            .unwrap();
        let result = fixture.provision(&layout, 8).open(fixture.signing_key());
        match (fail_finality, result) {
            (true, Err(FixedValidatorNodeStartupErrorV0::FinalityPair(source))) => {
                assert!(matches!(
                    source.as_ref(),
                    naome_storage::FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                        naome_storage::FixedValidatorFinalityJournalErrorV0::AnchorBehind { .. }
                    )
                ));
            }
            (false, Err(FixedValidatorNodeStartupErrorV0::VotePair(source))) => {
                assert!(
                    matches!(source.as_ref(), FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                    if matches!(inner.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }))
                );
            }
            _ => panic!("strict reopen must reject the independently lagging anchor"),
        }
    }
}
