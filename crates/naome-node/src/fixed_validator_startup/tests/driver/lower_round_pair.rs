use super::*;

type ProofInput = (ConsensusValueV0, Vec<u8>, Vec<u8>, Vec<u8>);

fn proof_input(
    fixture: &Fixture,
    branch: &FixedConsensusBranchV0,
    round: u64,
    axiom: ZfcAxiom,
) -> ProofInput {
    let (value, control, payload) = proposal_inputs(fixture, branch, round, axiom);
    let vote = signed_vote_bytes(
        fixture.context,
        round_at(branch, round).position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    (value, control, payload, vote)
}

fn submit_pair<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    first: &ProofInput,
    second: &ProofInput,
) -> Result<
    FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0<'node>,
    FixedValidatorNodeLowerRoundFinalityErrorV0,
> {
    driver.commit_lower_round_preselection_conflict_vote_batches(
        &first.1,
        first.2.clone(),
        &[&first.3],
        &second.1,
        second.2.clone(),
        &[&second.3],
        ConsensusRound::new(1),
    )
}

fn round_two_driver(
    scope: FixedValidatorNodeSigningScopeV0<'_>,
    finality_limit: usize,
) -> (
    FixedValidatorNodeDriverV0<'_>,
    FixedValidatorNodePhaseTimeoutV0,
) {
    let (driver, timeout) = step_arm(driver_with_finality_limits(
        scope,
        8,
        1 << 20,
        8,
        1 << 20,
        finality_limit,
        1 << 20,
        4,
    ));
    let (driver, timeout) = close_empty_round(driver, timeout);
    let (driver, timeout) = close_empty_round(driver, timeout);
    assert_eq!(driver.position().round(), ConsensusRound::new(2));
    (driver, timeout)
}

#[test]
fn lower_pair_waits_for_pending_arm_and_publication() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-lower-pair-pending");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready.run_with_signing_session(|scope| {
        let mut driver = driver(scope, 8, 4);
        for pending_publication in [false, true] {
            let before = layout.images();
            let position = driver.position();
            let phase = driver.phase();
            driver = match driver.commit_lower_round_preselection_conflict_vote_batches(
                &[0], vec![0], &[], &[0], vec![0], &[], ConsensusRound::new(u64::MAX),
            ).unwrap() {
                FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0::CommandPending { driver } => *driver,
                _ => panic!("command custody must precede route and malformed proof work"),
            };
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), phase);
            assert!(driver.has_pending_command());
            assert_eq!(layout.images(), before);
            if pending_publication {
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
        let _ = step_arm(driver);
    }).unwrap();
}

#[test]
fn lower_pair_halts_before_current_finality_and_without_successor_timer() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let first = proof_input(&fixture, &branch, 1, ZfcAxiom::Pairing);
    let second = proof_input(&fixture, &branch, 1, ZfcAxiom::Union);
    let current_first = proof_input(&fixture, &branch, 2, ZfcAxiom::PowerSet);
    let current_second = proof_input(&fixture, &branch, 2, ZfcAxiom::Infinity);
    let expected_ancestries = if first.0.proposal_signing_root() < second.0.proposal_signing_root()
    {
        [first.0.ancestry_id(), second.0.ancestry_id()]
    } else {
        [second.0.ancestry_id(), first.0.ancestry_id()]
    };
    for phase_steps in 0..=2 {
        let mut reference_stop = None;
        for mode in [
            "none",
            "ready",
            "missing",
            "conflicting",
            "pair",
            "saturated",
            "saturated-pair",
        ] {
            for reverse in [false, true] {
                let layout = TestLayout::new("driver-lower-pair-priority");
                let ready = fixture
                    .provision(&layout, 8)
                    .create(fixture.signing_key())
                    .unwrap();
                let stop = ready.run_with_signing_session(|scope| {
                let (mut driver, mut timeout) = round_two_driver(scope, if mode == "saturated" { 1 } else { 4 });
                for _ in 0..phase_steps {
                    (driver, _) = admit_due(driver, timeout);
                    driver = step_transition(driver);
                    let (next, vote, proposal) = step_publish(driver);
                    assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                    assert!(proposal.is_none());
                    (driver, timeout) = step_arm(next);
                }
                assert_eq!(driver.phase(), [FixedValidatorLockPhaseV0::Proposal,
                    FixedValidatorLockPhaseV0::Prevote, FixedValidatorLockPhaseV0::Precommit][phase_steps]);
                if mode != "none" {
                    (driver, _) = admit(driver, current_finality_precommit_event(&current_first.3));
                }
                if matches!(mode, "ready" | "pair" | "saturated-pair") {
                    (driver, _) = admit(driver, current_finality_proposal_event(&current_first.1, &current_first.2));
                }
                if matches!(mode, "conflicting" | "pair" | "saturated-pair") {
                    (driver, _) = admit(driver, current_finality_precommit_event(&current_second.3));
                }
                if matches!(mode, "pair" | "saturated-pair") {
                    (driver, _) = admit(driver, current_finality_proposal_event(&current_second.1, &current_second.2));
                }
                if matches!(mode, "saturated" | "saturated-pair") {
                    let denied = signed_vote_bytes_with_test_only_nonce_prefix(fixture.context,
                        round_at(&branch, 2).position(), ConsensusVoteRole::Precommit,
                        ConsensusVoteTarget::Proposal(current_second.0.proposal_signing_root()), &fixture.signing_key(), 0x37);
                    driver = reject_current_finality_precommit(driver, &denied, |rejection| {
                        assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                            newly_saturated: true, .. }));
                    });
                }
                let classification = driver.classify_current_finality_evidence().unwrap();
                assert!(matches!((mode, classification),
                    ("none", FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete)
                    | ("ready", FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(_))
                    | ("missing", FixedValidatorNodeDriverCurrentFinalityClassificationV0::QuorumMissingProposal(_))
                    | ("conflicting" | "pair" | "saturated-pair", FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots { .. })
                    | ("saturated", FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. })));
                (driver, _) = admit_due(driver, timeout);
                driver.set_timer_generation_for_test(u64::MAX);
                let before = layout.images();
                let sources = layout.source_images();
                let (left, right) = if reverse { (&second, &first) } else { (&first, &second) };
                let stopped = match submit_pair(driver, left, right).unwrap() {
                    FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(stopped) => *stopped,
                    _ => panic!("a fully verified lower pair must halt despite {mode} current evidence"),
                };
                for (before, after) in before.iter().zip(layout.images()) {
                    assert_ne!(before, &after, "each authority image must record the halt");
                }
                assert_eq!(layout.source_images(), sources);
                stopped
            }).unwrap();
                assert_eq!(
                    stop.finality_halt().kind(),
                    naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
                );
                assert_eq!(
                    stop.finality_halt().first_ancestry(),
                    expected_ancestries[0]
                );
                assert_eq!(
                    stop.finality_halt().second_ancestry(),
                    expected_ancestries[1]
                );
                assert_eq!(stop.signer_stop().kind(), stop.finality_halt().kind());
                assert_eq!(
                    stop.signer_stop().finality_state_id(),
                    stop.finality_halt().state_id()
                );
                if let Some(expected) = &reference_stop {
                    assert_eq!(&stop, expected);
                } else {
                    reference_stop = Some(stop);
                }
                let authority = layout.images();
                match fixture
                    .provision(&layout, 8)
                    .open(fixture.signing_key())
                    .unwrap()
                {
                    FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
                        assert_eq!(reopened, stop)
                    }
                    _ => panic!("strict reopen must report the exact lower-round neutral halt"),
                }
                assert_eq!(layout.images(), authority);
            }
        }
    }
}

#[test]
fn lower_pair_rejections_preserve_all_inbox_bytes_saturation_and_due_retry() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let first = proof_input(&fixture, &branch, 1, ZfcAxiom::Pairing);
    let second = proof_input(&fixture, &branch, 1, ZfcAxiom::Union);
    let current = proof_input(&fixture, &branch, 2, ZfcAxiom::PowerSet);
    let higher = proof_input(&fixture, &branch, 3, ZfcAxiom::Infinity);
    let nil_vote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 2).position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let layout = TestLayout::new("driver-lower-pair-rejections");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (mut driver, timeout) = round_two_driver(scope, 2);
            (driver, _) = admit(driver, proposal_event(3, &higher.1, &higher.2));
            (driver, _) = admit(driver, current_proposal_event(&current.1, &current.2));
            (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current.1, &current.2),
            );
            (driver, _) = admit(driver, current_finality_precommit_event(&current.3));
            (driver, _) = admit(driver, current_nil_precommit_event(&nil_vote));
            let denied = signed_vote_bytes_with_test_only_nonce_prefix(
                fixture.context,
                round_at(&branch, 2).position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(current.0.proposal_signing_root()),
                &fixture.signing_key(),
                0x38,
            );
            driver = reject_current_finality_precommit(driver, &denied, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                        newly_saturated: true,
                        ..
                    }
                ));
            });
            (driver, _) = admit_due(driver, timeout);
            let counts = (
                driver.inbox_len(),
                driver.current_inbox_len(),
                driver.current_finality_inbox_len(),
                driver.current_nil_precommit_inbox_len(),
            );
            assert_eq!(counts, (1, 1, 2, 1));
            let bytes = (
                driver.current_inbox_canonical_input_bytes(),
                driver.current_finality_inbox_canonical_input_bytes(),
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
            );
            let classification = driver.classify_current_finality_evidence().unwrap();
            assert!(matches!(
                classification,
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }
            ));
            let authority = layout.images();
            let sources = layout.source_images();
            let mut bad_signature = second.3.clone();
            *bad_signature.last_mut().unwrap() ^= 1;
            for failure in [
                "round",
                "first",
                "second",
                "duplicate",
                "signature",
                "missing",
            ] {
                let first_control = if matches!(failure, "round" | "first") {
                    &[0][..]
                } else {
                    &first.1
                };
                let second_control = if failure == "second" {
                    &[0][..]
                } else {
                    &second.1
                };
                let batch = match failure {
                    "duplicate" => vec![second.3.as_slice(), second.3.as_slice()],
                    "signature" => vec![bad_signature.as_slice()],
                    "missing" => vec![],
                    _ => vec![second.3.as_slice()],
                };
                driver = match driver
                    .commit_lower_round_preselection_conflict_vote_batches(
                        first_control,
                        first.2.clone(),
                        &[&first.3],
                        second_control,
                        second.2.clone(),
                        &batch,
                        ConsensusRound::new(if failure == "round" { 2 } else { 1 }),
                    )
                    .unwrap()
                {
                    FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0::Rejected {
                        driver,
                        rejection,
                    } => {
                        assert!(matches!(
                            (failure, *rejection),
                            (
                                "round",
                                FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Route(
                                    _
                                )
                            ) | (
                                "first",
                                FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(
                                    _
                                )
                            ) | (
                                "second" | "duplicate" | "signature" | "missing",
                                FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(
                                    _
                                )
                            )
                        ));
                        *driver
                    }
                    _ => {
                        panic!("invalid {failure} must return the driver without partial finality")
                    }
                };
                assert_eq!(
                    (
                        driver.inbox_len(),
                        driver.current_inbox_len(),
                        driver.current_finality_inbox_len(),
                        driver.current_nil_precommit_inbox_len()
                    ),
                    counts
                );
                assert_eq!(
                    (
                        driver.current_inbox_canonical_input_bytes(),
                        driver.current_finality_inbox_canonical_input_bytes(),
                        driver.current_nil_precommit_inbox_canonical_input_bytes()
                    ),
                    bytes
                );
                assert_eq!(
                    driver.classify_current_finality_evidence().unwrap(),
                    classification
                );
                assert_eq!(driver.position(), timeout.position());
                assert_eq!(driver.phase(), timeout.phase());
                assert!(driver.timeout_is_due());
                assert!(!driver.has_pending_command());
                assert_eq!(layout.images(), authority);
                assert_eq!(layout.source_images(), sources);
            }
            // Drain only after the assertions above, to inspect the exact retained bytes.
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(
                drained_contents(drained),
                (vec![(higher.1.clone(), higher.2.clone())], vec![])
            );
            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            assert_eq!(
                drained_current_contents(drained),
                (vec![(current.1.clone(), current.2.clone())], vec![], vec![])
            );
            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            assert_eq!(
                drained_current_finality_contents(drained),
                (
                    vec![(current.1.clone(), current.2.clone())],
                    vec![current.3.clone()]
                )
            );
            let (driver, drained) = driver
                .drain_current_nil_precommit_inbox_and_reset()
                .into_parts();
            assert_eq!(
                drained_current_nil_precommit_contents(drained),
                vec![nil_vote.clone()]
            );
            let (driver, disposition) = admit_due(*driver, timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue
            );
            assert!(matches!(
                submit_pair(driver, &first, &second).unwrap(),
                FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(_)
            ));
        })
        .unwrap();
}

#[test]
fn lower_pair_same_value_consumes_driver_and_reopens_the_unchanged_durable_prefix() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let first = proof_input(&fixture, &branch, 1, ZfcAxiom::Pairing);
    let layout = TestLayout::new("driver-lower-pair-same-value");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let authority = ready.run_with_signing_session(|scope| {
        let (driver, _) = round_two_driver(scope, 4);
        let before = layout.images();
        assert!(matches!(submit_pair(driver, &first, &first),
            Err(FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(error))
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
fn lower_pair_anchor_failures_consume_driver_and_reopen_fail_closed() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let first = proof_input(&fixture, &branch, 1, ZfcAxiom::Pairing);
    let second = proof_input(&fixture, &branch, 1, ZfcAxiom::Union);
    for fail_finality in [true, false] {
        let layout = TestLayout::new("driver-lower-pair-anchor-failure");
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
                let error = match submit_pair(driver, &first, &second) {
                    Err(FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(error)) => error,
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
