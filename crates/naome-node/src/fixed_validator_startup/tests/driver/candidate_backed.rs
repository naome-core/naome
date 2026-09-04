use super::*;

#[test]
fn direct_child_signer_anchor_failure_retains_selection_and_reopens_fail_closed() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-direct-child-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let collision = next_anchor_collision(&layout.vote_anchor, 3);
    ready.run_with_signing_session(|scope| {
        let selected = ArtifactChainState::new(fixture.definition);
        let (transition, control, vote) = candidate_backed_batch_finality_inputs(
            &fixture, scope.branch(), &selected, &mut candidates, &mut payloads, ZfcAxiom::Pairing, 0);
        let target = transition.value().artifact_block().id();
        let (driver, _) = step_arm(driver(scope, 8, 0));
        let authority = layout.images();
        let sources = layout.source_images();
        let error = match driver.commit_candidate_backed_finality_vote_batch(
            &mut candidates, &mut payloads, target, &control, &[&vote], ConsensusRound::new(0),
        ) {
            Err(FixedValidatorNodeDriverCandidateBackedFinalityErrorV0::Finality(error)) => error,
            _ => panic!("failed signer handoff must consume driver"),
        };
        match *error {
            FixedValidatorNodeCandidateBackedFinalityErrorV0::Finality(error) => match *error {
                FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare { selection, source } => {
                    assert!(matches!(*selection, FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                        target: actual, position, ancestry_id, envelope_id, ..
                    } if actual == target && position == transition.position()
                        && ancestry_id == transition.value().ancestry_id() && envelope_id == transition.envelope_id()));
                    assert!(matches!(*source, FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }));
                }
                other => panic!("unexpected finality error: {other:?}"),
            },
            other => panic!("unexpected candidate error: {other:?}"),
        }
        let after = layout.images();
        assert_ne!(after[0], authority[0]);
        assert_ne!(after[1], authority[1]);
        assert_ne!(after[2], authority[2]);
        assert_eq!(after[3], authority[3]);
        assert_eq!(layout.source_images(), sources);
    }).unwrap();
    drop(candidates);
    drop(payloads);
    fs::remove_file(collision).unwrap();
    assert!(
        matches!(fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source)) if matches!(source.as_ref(),
            FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner) if matches!(inner.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. })))
    );
}

#[test]
fn direct_child_rejections_preserve_due_driver_for_source_fill_and_exact_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-direct-child-retry");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let target = value.artifact_block().id();
    let vote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    ready.run_with_signing_session(|scope| {
        let (driver, timeout) = step_arm(driver(scope, 8, 0));
        let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
        let (mut driver, _) = admit_due(driver, timeout);
        let before = custody(&driver);
        let authority = layout.images();
        for failure in ["ceiling", "candidate", "payload", "proposal", "batch"] {
            if failure == "payload" { let _ = candidates.insert(&value.artifact_block()).unwrap(); }
            if failure == "proposal" {
                let _ = payloads.validate_and_insert_branch_payload(
                    branch.artifact_snapshot(), &value.artifact_block(), payload.clone(),
                ).unwrap();
            }
            let sources = layout.source_images();
            let proposal_bytes = if failure == "proposal" || failure == "ceiling" { &[0][..] } else { &control };
            let batch = if failure == "batch" { vec![vote.as_slice(), vote.as_slice()] } else { vec![vote.as_slice()] };
            driver = match driver.commit_candidate_backed_finality_vote_batch(
                &mut candidates, &mut payloads, target, proposal_bytes, &batch,
                ConsensusRound::new(u64::from(failure == "ceiling")),
            ).unwrap() {
                FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::Rejected { driver, rejection } => {
                    match (failure, *rejection) {
                        ("ceiling", FixedValidatorNodeCandidateBackedFinalityRejectionV0::EvidenceRoundWorkLimitExceeded { .. })
                        | ("candidate", FixedValidatorNodeCandidateBackedFinalityRejectionV0::CandidateUnavailable { .. })
                        | ("payload", FixedValidatorNodeCandidateBackedFinalityRejectionV0::PayloadUnavailable { .. })
                        | ("proposal", FixedValidatorNodeCandidateBackedFinalityRejectionV0::Proposal(_))
                        | ("batch", FixedValidatorNodeCandidateBackedFinalityRejectionV0::PrecommitBatch(_)) => {}
                        (_, other) => panic!("unexpected {failure} rejection: {other:?}"),
                    }
                    *driver
                }
                _ => panic!("invalid {failure} must return unchanged driver"),
            };
            assert_eq!(custody(&driver), before);
            assert_eq!(driver.position(), timeout.position());
            assert_eq!(driver.phase(), timeout.phase());
            assert!(driver.timeout_is_due());
            assert!(!driver.has_pending_command());
            assert_eq!(layout.images(), authority);
            assert_eq!(layout.source_images(), sources);
        }
        let driver = match driver.commit_candidate_backed_finality_vote_batch(
            &mut candidates, &mut payloads, target, &control, &[&vote], ConsensusRound::new(0),
        ).unwrap() {
            FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::Finality { driver, .. } => *driver,
            _ => panic!("valid retry must finalize"),
        };
        assert_eq!(custody(&driver), before);
        assert_eq!(driver.position().height().value(), 2);
        assert!(!driver.timeout_is_due());
    }).unwrap();
}

#[test]
fn direct_child_corruption_returns_driver_and_poisons_only_candidate_handle() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-direct-child-corrupt");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    ready.run_with_signing_session(|scope| {
        let selected = ArtifactChainState::new(fixture.definition);
        let (transition, control, vote) = candidate_backed_batch_finality_inputs(
            &fixture, scope.branch(), &selected, &mut candidates, &mut payloads, ZfcAxiom::Pairing, 0);
        let target = transition.value().artifact_block().id();
        let (driver, timeout) = step_arm(driver(scope, 8, 0));
        let (driver, _) = admit_due(driver, timeout);
        flip_last_store_byte(&layout.candidate_store);
        let authority = layout.images();
        let sources = layout.source_images();
        let driver = match driver.commit_candidate_backed_finality_vote_batch(
            &mut candidates, &mut payloads, target, &control, &[&vote], ConsensusRound::new(0),
        ).unwrap() {
            FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::Rejected { driver, rejection } => {
                assert!(matches!(*rejection, FixedValidatorNodeCandidateBackedFinalityRejectionV0::CandidateStore(source)
                    if matches!(*source, ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id } if block_id == target)));
                *driver
            }
            _ => panic!("source corruption must return pre-effect driver"),
        };
        assert_eq!(driver.position(), timeout.position());
        assert!(driver.timeout_is_due());
        assert_eq!(layout.images(), authority);
        assert_eq!(layout.source_images(), sources);
        assert!(matches!(candidates.contains(target), Err(ArtifactBlockCandidateStoreError::Poisoned)));
        assert!(payloads.contains(transition.value().artifact_block().artifact_id()).unwrap());
    }).unwrap();
    drop(candidates);
    drop(payloads);
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            assert_eq!(driver(scope, 8, 0).position().height().value(), 1);
        })
        .unwrap();
}

#[test]
fn direct_child_generation_exhaustion_precedes_source_work_and_reopens_ready() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-direct-child-generation");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    ready.run_with_signing_session(|scope| {
        let selected = ArtifactChainState::new(fixture.definition);
        let (transition, control, vote) = candidate_backed_batch_finality_inputs(
            &fixture, scope.branch(), &selected, &mut candidates, &mut payloads, ZfcAxiom::Pairing, 0);
        let target = transition.value().artifact_block().id();
        let (mut driver, _) = step_arm(driver(scope, 8, 0));
        driver.set_timer_generation_for_test(u64::MAX);
        flip_last_store_byte(&layout.candidate_store);
        let authority = layout.images();
        let sources = layout.source_images();
        assert!(matches!(driver.commit_candidate_backed_finality_vote_batch(
            &mut candidates, &mut payloads, target, &control, &[&vote], ConsensusRound::new(0)),
            Err(FixedValidatorNodeDriverCandidateBackedFinalityErrorV0::TimeoutGenerationExhausted { generation: u64::MAX })));
        assert_eq!(layout.images(), authority);
        assert_eq!(layout.source_images(), sources);
        assert!(candidates.contains(target).unwrap());
    }).unwrap();
    drop(candidates);
    drop(payloads);
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            assert_eq!(driver(scope, 8, 0).position().height().value(), 1);
        })
        .unwrap();
}

#[test]
fn direct_child_handoff_preserves_four_inboxes_replaces_timer_and_reopens() {
    let fixture = Fixture::new();
    for (evidence_round, signer_round, saturated) in [(0, 0, false), (1, 2, false), (2, 0, true)] {
        let layout = TestLayout::new("driver-direct-child-handoff");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let mut candidates = create_candidate_store(&layout, fixture.definition);
        let mut payloads = create_payload_store(&layout);
        let target = ready.run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let selected = ArtifactChainState::new(fixture.definition);
            let (transition, control, vote) = candidate_backed_batch_finality_inputs(
                &fixture, &branch, &selected, &mut candidates, &mut payloads, ZfcAxiom::Pairing, evidence_round);
            let target = transition.value().artifact_block().id();
            let (_, current_control, current_payload) = proposal_inputs(&fixture, &branch, signer_round, ZfcAxiom::Union);
            let (_, higher_control, higher_payload) = proposal_inputs(&fixture, &branch, signer_round + 1, ZfcAxiom::PowerSet);
            let (mut driver, mut timeout) = step_arm(driver_with_finality_limits(scope, 8, 1 << 20, 8, 1 << 20, 1, 1 << 20, 4));
            let mut expected_nil_votes = Vec::new();
            for round in 0..signer_round {
                let nil = signed_vote_bytes(fixture.context, round_at(&branch, round).position(),
                    ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil, &fixture.signing_key());
                (driver, _) = admit(driver, current_nil_precommit_event(&nil));
                expected_nil_votes.push(nil);
                driver = step_transition(driver);
                (driver, timeout) = step_arm(driver);
            }
            (driver, _) = admit(driver, proposal_event(signer_round + 1, &higher_control, &higher_payload));
            (driver, _) = admit(driver, current_proposal_event(&current_control, &current_payload));
            (driver, _) = admit(driver, current_finality_proposal_event(&current_control, &current_payload));
            if saturated {
                let (_, denied_control, denied_payload) = proposal_inputs(&fixture, &branch, signer_round, ZfcAxiom::PowerSet);
                driver = reject_current_finality_proposal(driver, &denied_control, &denied_payload, |rejection| {
                    assert!(matches!(rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. }));
                });
                assert!(matches!(driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }));
            } else {
                assert_eq!(driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete);
            }
            let nil = signed_vote_bytes(fixture.context, driver.position(), ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil, &fixture.signing_key());
            (driver, _) = admit(driver, current_nil_precommit_event(&nil));
            expected_nil_votes.push(nil);
            (driver, _) = admit_due(driver, timeout);
            let before = custody(&driver);
            assert!(before.0.iter().all(|count| *count > 0));
            let authority = layout.images();
            let sources = layout.source_images();
            let mut driver = match driver.commit_candidate_backed_finality_vote_batch(
                &mut candidates, &mut payloads, target, &control, &[&vote], ConsensusRound::new(evidence_round),
            ).unwrap() {
                FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::Finality { driver, selection } => {
                    assert!(matches!(selection, FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                        target: actual, position, ancestry_id, envelope_id, ..
                    } if actual == target && position == transition.position()
                        && ancestry_id == transition.value().ancestry_id() && envelope_id == transition.envelope_id()));
                    *driver
                }
                _ => panic!("complete direct-child evidence must finalize"),
            };
            assert_eq!(custody(&driver), before);
            if saturated {
                assert!(matches!(driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }));
            }
            for (before, after) in authority.iter().zip(layout.images()) {
                assert_ne!(before, &after, "every authority image must advance");
            }
            assert_eq!(layout.source_images(), sources);
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round().value(), 0);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            let child_timeout;
            (driver, child_timeout) = step_arm(driver);
            assert_eq!(child_timeout.generation(), timeout.generation() + 1);
            assert_eq!(child_timeout.position(), driver.position());
            assert_eq!(child_timeout.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.has_pending_command());
            driver = match driver.admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(timeout)).unwrap() {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { driver, rejection, .. } => {
                    assert!(matches!(*rejection, FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch));
                    *driver
                }
                _ => panic!("old timer must be stale"),
            };
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(drained_contents(drained), (vec![(higher_control, higher_payload)], vec![]));
            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            assert_eq!(drained_current_contents(drained), (vec![(current_control.clone(), current_payload.clone())], vec![], vec![]));
            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            assert_eq!(drained_current_finality_contents(drained), (vec![(current_control, current_payload)], vec![]));
            let (driver, drained) = driver.drain_current_nil_precommit_inbox_and_reset().into_parts();
            expected_nil_votes.sort();
            assert_eq!(drained_current_nil_precommit_contents(drained), expected_nil_votes);
            assert_eq!(custody(&driver), ([0; 4], [0; 3]));
            let driver = step_idle(*driver);
            assert!(!driver.has_pending_command());
            let (_, disposition) = admit_due(driver, child_timeout);
            assert_eq!(disposition, FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue);
            target
        }).unwrap();
        drop(candidates);
        drop(payloads);
        let authority = layout.images();
        let reopened = expect_ready(
            fixture
                .provision_with_catch_up_limit(&layout, 8, 0)
                .open(fixture.signing_key())
                .unwrap(),
        );
        reopened
            .run_with_signing_session(|mut scope| {
                assert_eq!(scope.branch().artifact_snapshot().head_block_id(), target);
                assert_eq!(scope.signing_session().position().height().value(), 2);
                assert_eq!(scope.signing_session().position().round().value(), 0);
                assert_eq!(
                    scope.signing_session().phase(),
                    FixedValidatorLockPhaseV0::Proposal
                );
                assert_eq!(custody(&driver(scope, 8, 4)), ([0; 4], [0; 3]));
            })
            .unwrap();
        assert_eq!(layout.images(), authority);
    }
}

fn custody(driver: &FixedValidatorNodeDriverV0<'_>) -> ([usize; 4], [u64; 3]) {
    (
        [
            driver.inbox_len(),
            driver.current_inbox_len(),
            driver.current_finality_inbox_len(),
            driver.current_nil_precommit_inbox_len(),
        ],
        [
            driver.current_inbox_canonical_input_bytes(),
            driver.current_finality_inbox_canonical_input_bytes(),
            driver.current_nil_precommit_inbox_canonical_input_bytes(),
        ],
    )
}

#[test]
fn pending_arm_and_publication_precede_direct_child_work() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-direct-child-pending");
    let branch = fixed_branch(&fixture);
    let (value, _, _) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    ready
        .run_with_signing_session(|scope| {
            let mut driver = driver(scope, 8, 0);
            for publication in [false, true] {
                driver.set_timer_generation_for_test(u64::MAX);
                let authority = layout.images();
                let sources = layout.source_images();
                let before = custody(&driver);
                driver = match driver
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        value.artifact_block().id(),
                        &[0],
                        &[],
                        ConsensusRound::new(1),
                    )
                    .unwrap()
                {
                    FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::CommandPending {
                        driver,
                    } => *driver,
                    _ => panic!(
                        "pending command must precede generation, route, and malformed inputs"
                    ),
                };
                assert_eq!(layout.images(), authority);
                assert_eq!(layout.source_images(), sources);
                assert_eq!(custody(&driver), before);
                assert!(driver.has_pending_command());
                driver.set_timer_generation_for_test(0);
                if publication {
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
            drop(driver);
        })
        .unwrap();
}

#[test]
fn retained_current_finality_precedes_direct_child_even_with_exhausted_generation() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (left, left_control, left_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (right, right_control, right_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let position = round_at(&branch, 0).position();
    let left_vote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(left.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let right_vote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(right.proposal_signing_root()),
        &fixture.signing_key(),
    );
    for mode in ["missing", "ready", "conflicting", "pair", "saturated-pair"] {
        let layout = TestLayout::new(&format!("driver-direct-child-{mode}"));
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let mut candidates = create_candidate_store(&layout, fixture.definition);
        let mut payloads = create_payload_store(&layout);
        ready.run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let (candidate, control, vote) = candidate_backed_batch_finality_inputs(
                &fixture, scope.branch(), &selected, &mut candidates, &mut payloads, ZfcAxiom::PowerSet, 0);
            let target = candidate.value().artifact_block().id();
            let (mut driver, timeout) = step_arm(driver_with_finality_limits(scope, 8, 1 << 20, 8, 1 << 20, 4, 1 << 20, 0));
            (driver, _) = admit(driver, current_finality_precommit_event(&left_vote));
            if mode != "missing" {
                (driver, _) = admit(driver, current_finality_proposal_event(&left_control, &left_payload));
            }
            if matches!(mode, "conflicting" | "pair" | "saturated-pair") {
                (driver, _) = admit(driver, current_finality_precommit_event(&right_vote));
            }
            if matches!(mode, "pair" | "saturated-pair") {
                (driver, _) = admit(driver, current_finality_proposal_event(&right_control, &right_payload));
            }
            if mode == "saturated-pair" {
                let denied = signed_vote_bytes_with_test_only_nonce_prefix(fixture.context, position,
                    ConsensusVoteRole::Precommit, ConsensusVoteTarget::Proposal(left.proposal_signing_root()),
                    &fixture.signing_key(), 0x35);
                driver = reject_current_finality_precommit(driver, &denied, |rejection| {
                    assert!(matches!(rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. }));
                });
            }
            (driver, _) = admit_due(driver, timeout);
            driver.set_timer_generation_for_test(u64::MAX);
            let before = custody(&driver);
            let classification = driver.classify_current_finality_evidence().unwrap();
            let authority = layout.images();
            // A premature source read would poison this handle.
            flip_last_store_byte(&layout.candidate_store);
            let sources = layout.source_images();
            driver = match driver.commit_candidate_backed_finality_vote_batch(
                &mut candidates, &mut payloads, target, &control, &[&vote], ConsensusRound::new(0),
            ).unwrap() {
                FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::CurrentFinalityUnresolved { driver } => *driver,
                _ => panic!("retained {mode} finality must precede caller choice"),
            };
            assert_eq!(custody(&driver), before);
            assert_eq!(driver.classify_current_finality_evidence().unwrap(), classification);
            assert_eq!(layout.images(), authority);
            assert_eq!(layout.source_images(), sources);
            assert!(candidates.contains(target).unwrap());
            assert!(driver.timeout_is_due());
            driver.set_timer_generation_for_test(0);
            match (mode, driver.step().unwrap()) {
                ("ready", FixedValidatorNodeDriverStepOutcomeV0::Finality { selection, .. }) => {
                    assert!(matches!(selection, FixedValidatorNodeFinalitySelectionV0::Finalized { ancestry_id, .. }
                        if ancestry_id == left.ancestry_id()));
                }
                ("pair" | "saturated-pair", FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(_)) => {}
                ("missing" | "conflicting", FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, .. }) => {
                    assert_eq!(custody(&driver), before);
                    assert_eq!(layout.images(), authority);
                }
                _ => panic!("step must retain its original {mode} classification"),
            }
        }).unwrap();
    }
}
