use super::*;
use FixedValidatorNodeDriverHistoricalFinalityConflictOutcomeV0 as Outcome;
use naome_storage::FixedValidatorHistoricalFinalityConflictErrorV0 as ConflictError;

#[derive(Clone)]
struct Proof {
    value: ConsensusValueV0,
    envelope: Vec<u8>,
    control: Vec<u8>,
    payload: Vec<u8>,
    vote: Vec<u8>,
    round: u64,
}

fn proof(
    fixture: &Fixture,
    branch: &FixedConsensusBranchV0,
    selected: &ArtifactChainState,
    axiom: ZfcAxiom,
    round: u64,
) -> Proof {
    let transition = fixture.transition(branch, selected, axiom, round);
    let value = transition.value();
    let position = transition.position();
    let mut control = value.to_canonical_bytes().to_vec();
    control.extend_from_slice(&authorization_bytes(
        fixture.context,
        position,
        value.proposal_signing_root(),
        &fixture.signing_key(),
    ));
    control.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    Proof {
        value,
        envelope: transition.canonical_envelope_bytes().to_vec(),
        control,
        payload: transition.canonical_artifact_bytes().to_vec(),
        vote: signed_vote_bytes(
            fixture.context,
            position,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
            &fixture.signing_key(),
        ),
        round,
    }
}

impl Proof {
    fn sealed(&self, branch: &FixedConsensusBranchV0) -> OwnedVerifiedFixedConsensusTransitionV0 {
        branch
            .decode_and_verify_envelope_with_round_limit(
                &self.envelope,
                self.payload.clone(),
                ConsensusRound::new(self.round),
            )
            .unwrap()
    }
    fn submit<'node>(
        &self,
        driver: FixedValidatorNodeDriverV0<'node>,
        batch: bool,
    ) -> Result<Outcome<'node>, FixedValidatorNodeFinalityErrorV0> {
        if batch {
            driver.commit_historical_finality_conflict_vote_batch(
                &self.control,
                self.payload.clone(),
                &[&self.vote],
                ConsensusRound::new(self.round),
            )
        } else {
            driver.commit_historical_finality_conflict(&self.envelope, self.payload.clone())
        }
    }
}

struct History {
    first: Proof,
    sibling: Proof,
    selected_variant: Proof,
    next: Proof,
    other_parent: Proof,
}

fn history<'node>(
    fixture: &Fixture,
    mut scope: FixedValidatorNodeSigningScopeV0<'node>,
) -> (FixedValidatorNodeSigningScopeV0<'node>, History) {
    let genesis = scope.branch().clone();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = proof(fixture, &genesis, &selected, ZfcAxiom::Pairing, 0);
    let selected_variant = proof(fixture, &genesis, &selected, ZfcAxiom::Pairing, 2);
    let sibling = proof(fixture, &genesis, &selected, ZfcAxiom::Union, 2);
    let sibling_branch = sibling.sealed(&genesis).into_branch();
    let mut sibling_state = ArtifactChainState::new(fixture.definition);
    sibling_state
        .apply_block(&sibling.value.artifact_block(), sibling.payload.clone())
        .unwrap();
    let other_parent = proof(
        fixture,
        &sibling_branch,
        &sibling_state,
        ZfcAxiom::PowerSet,
        0,
    );
    let transition = first.sealed(scope.branch());
    (scope, _) = expect_continuation(scope.commit_verified_finality(transition).unwrap());
    selected
        .apply_block(&first.value.artifact_block(), first.payload.clone())
        .unwrap();
    let second = proof(fixture, scope.branch(), &selected, ZfcAxiom::PowerSet, 0);
    let transition = second.sealed(scope.branch());
    (scope, _) = expect_continuation(scope.commit_verified_finality(transition).unwrap());
    selected
        .apply_block(&second.value.artifact_block(), second.payload.clone())
        .unwrap();
    let next = proof(fixture, scope.branch(), &selected, ZfcAxiom::Union, 0);
    (
        scope,
        History {
            first,
            sibling,
            selected_variant,
            next,
            other_parent,
        },
    )
}

#[test]
fn historical_conflict_halts_from_every_phase_before_retained_finality_and_without_successor_generation()
 {
    let fixture = Fixture::new();
    for batch in [false, true] {
        for phase_steps in 0..3 {
            for retained in ["empty", "ready", "saturated"] {
                let layout = TestLayout::new("historical-driver-halt");
                let ready = fixture
                    .provision(&layout, 8)
                    .create(fixture.signing_key())
                    .unwrap();
                let stopped = ready.run_with_signing_session(|scope| {
                    let (scope, history) = history(&fixture, scope);
                    let (mut driver, mut ticket) = step_arm(driver_with_finality_limits(scope, 8, 1 << 20, 8, 1 << 20, if retained == "saturated" { 1 } else { 4 }, 1 << 20, 2));
                    assert_eq!(driver.position().height().value(), 3);
                    assert_eq!(driver.position().round().value(), 0);
                    for _ in 0..phase_steps {
                        (driver, _) = admit_due(driver, ticket);
                        driver = step_transition(driver);
                        let (next, vote, proposal) = step_publish(driver);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(proposal.is_none());
                        (driver, ticket) = step_arm(next);
                    }
                    if retained != "empty" {
                        (driver, _) = admit(driver, current_finality_precommit_event(&history.next.vote));
                        if retained == "ready" {
                            (driver, _) = admit(driver, current_finality_proposal_event(&history.next.control, &history.next.payload));
                            assert!(matches!(driver.classify_current_finality_evidence().unwrap(), FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(_)));
                        } else {
                            driver = reject_current_finality_proposal(driver, &history.next.control, &history.next.payload, |rejection| {
                                assert!(matches!(rejection, FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. }));
                            });
                        }
                    }
                    (driver, _) = admit_due(driver, ticket);
                    driver.set_timer_generation_for_test(u64::MAX);
                    let before = layout.images();
                    let Outcome::FinalityStopped(stopped) = history.sibling.submit(driver, batch).unwrap() else { panic!("historical proof must stop both owners") };
                    assert_eq!(stopped.finality_halt().kind(), naome_storage::FixedValidatorFinalityHaltKindV0::SelectedSibling);
                    assert_eq!(stopped.finality_halt().height().value(), 1);
                    assert_eq!(stopped.finality_halt().first_ancestry(), history.first.value.ancestry_id());
                    assert_eq!(stopped.finality_halt().second_ancestry(), history.sibling.value.ancestry_id());
                    assert_eq!(stopped.signer_stop().finality_state_id(), stopped.finality_halt().state_id());
                    assert!(before.iter().zip(layout.images()).all(|(before, after)| before != &after));
                    *stopped
                }).unwrap();
                let images = layout.images();
                match fixture
                    .provision(&layout, 8)
                    .open(fixture.signing_key())
                    .unwrap()
                {
                    FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
                        assert_eq!(reopened, stopped)
                    }
                    _ => panic!("strict terminal reopen"),
                }
                assert_eq!(layout.images(), images);
            }
        }
    }
}

#[test]
fn historical_conflict_pending_arm_and_vote_preserve_exact_driver_custody_before_bad_proof_work() {
    let fixture = Fixture::new();
    for batch in [false, true] {
        for pending_vote in [false, true] {
            let layout = TestLayout::new("historical-driver-pending");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready
                .run_with_signing_session(|scope| {
                    let (scope, history) = history(&fixture, scope);
                    let mut driver = driver(scope, 8, 2);
                    if pending_vote {
                        let (next, ticket) = step_arm(driver);
                        (driver, _) = admit_due(next, ticket);
                        driver = step_transition(driver);
                    }
                    let (position, phase, ticket, due) = (
                        driver.position(),
                        driver.phase(),
                        driver.active_timeout(),
                        driver.timeout_is_due(),
                    );
                    let custody = candidate_backed::custody(&driver);
                    let images = layout.images();
                    let mut malformed = history.sibling.clone();
                    malformed.envelope.clear();
                    malformed.control.clear();
                    malformed.payload = vec![0];
                    malformed.round = u64::MAX;
                    let Outcome::CommandPending { driver } =
                        malformed.submit(driver, batch).unwrap()
                    else {
                        panic!("pending command must precede all proof work")
                    };
                    assert_eq!(
                        (
                            driver.position(),
                            driver.phase(),
                            driver.active_timeout(),
                            driver.timeout_is_due()
                        ),
                        (position, phase, ticket, due)
                    );
                    assert_eq!(candidate_backed::custody(&driver), custody);
                    assert_eq!(layout.images(), images);
                    assert!(driver.has_pending_command());
                    if pending_vote {
                        let (_, vote, proposal) = step_publish(*driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(proposal.is_none());
                    } else {
                        let (_, arm) = step_arm(*driver);
                        assert_eq!(arm.position(), position);
                        assert_eq!(arm.phase(), phase);
                    }
                    assert_eq!(layout.images(), images);
                })
                .unwrap();
        }
    }
}

#[test]
fn historical_conflict_delegated_rejections_consume_driver_without_writes_and_strictly_reopen_ready()
 {
    let fixture = Fixture::new();
    for batch in [false, true] {
        for mode in [
            "selected",
            "next",
            "other-parent",
            "malformed",
            "payload",
            "signature",
            "ceiling",
        ] {
            let layout = TestLayout::new("historical-driver-rejection");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            let (position, phase, head) = ready
                .run_with_signing_session(|scope| {
                    let (scope, history) = history(&fixture, scope);
                    let (driver, ticket) =
                        step_arm(driver(scope, 8, if mode == "ceiling" { 1 } else { 2 }));
                    let (driver, _) = admit_due(driver, ticket);
                    let expected = (
                        driver.position(),
                        driver.phase(),
                        driver
                            .selected_artifact_history()
                            .selected_head_block_id()
                            .unwrap(),
                    );
                    let before = layout.images();
                    let mut input = match mode {
                        "selected" => history.selected_variant,
                        "next" => history.next,
                        "other-parent" => history.other_parent,
                        _ => history.sibling,
                    };
                    match mode {
                        "malformed" => {
                            input.envelope.clear();
                            input.control.clear();
                        }
                        "payload" => input.payload = vec![0],
                        "signature" => {
                            *input.envelope.last_mut().unwrap() ^= 1;
                            *input.vote.last_mut().unwrap() ^= 1;
                        }
                        _ => {}
                    }
                    let error = match input.submit(driver, batch) {
                        Err(error) => error,
                        Ok(_) => panic!("{mode} must consume authority"),
                    };
                    let FixedValidatorNodeFinalityErrorV0::HistoricalFinalityConflict(source) =
                        error
                    else {
                        panic!("typed direct-proof failure")
                    };
                    assert!(matches!(
                        (mode, source.as_ref()),
                        ("selected", ConflictError::SelectedValueNotDistinct { .. })
                            | ("next", ConflictError::SelectedHeightUnavailable { .. })
                            | (
                                "ceiling",
                                ConflictError::EvidenceRoundWorkLimitExceeded { .. }
                                    | ConflictError::Envelope(_)
                            )
                            | (
                                "other-parent" | "malformed" | "payload" | "signature",
                                ConflictError::Envelope(_)
                                    | ConflictError::Proposal(_)
                                    | ConflictError::PrecommitBatch(_)
                            )
                    ));
                    assert_eq!(layout.images(), before);
                    expected
                })
                .unwrap();
            let images = layout.images();
            let reopened = expect_ready(
                fixture
                    .provision(&layout, 8)
                    .open(fixture.signing_key())
                    .unwrap(),
            );
            reopened
                .run_with_signing_session(|scope| {
                    let driver = driver(scope, 8, 2);
                    assert_eq!(
                        (
                            driver.position(),
                            driver.phase(),
                            driver
                                .selected_artifact_history()
                                .selected_head_block_id()
                                .unwrap()
                        ),
                        (position, phase, head)
                    );
                    assert_eq!(driver.position().height().value(), 3);
                })
                .unwrap();
            assert_eq!(layout.images(), images);
        }
    }
}

#[test]
fn historical_conflict_anchor_failures_preserve_exact_completed_prefix_and_reopen_only_anchor_behind()
 {
    let fixture = Fixture::new();
    for batch in [false, true] {
        for fail_finality in [true, false] {
            let layout = TestLayout::new("historical-driver-anchor-failure");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready
                .run_with_signing_session(|scope| {
                    let (scope, history) = history(&fixture, scope);
                    let (driver, _) = step_arm(driver(scope, 8, 2));
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
                    let sequence =
                        u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
                    let collision = next_anchor_collision(directory, sequence + 1);
                    let error = match history.sibling.submit(driver, batch) {
                        Err(error) => error,
                        _ => panic!("failed anchor must publish no terminal success"),
                    };
                    match (fail_finality, error) {
                        (
                            true,
                            FixedValidatorNodeFinalityErrorV0::HistoricalFinalityConflict(source),
                        ) => assert!(matches!(
                            source.as_ref(),
                            ConflictError::FinalityJournal(
                                naome_storage::FixedValidatorFinalityJournalErrorV0::Commit { .. }
                            )
                        )),
                        (false, FixedValidatorNodeFinalityErrorV0::SignerStop { halt, source }) => {
                            assert_eq!(
                                halt.kind(),
                                naome_storage::FixedValidatorFinalityHaltKindV0::SelectedSibling
                            );
                            assert_eq!(halt.first_ancestry(), history.first.value.ancestry_id());
                            assert_eq!(halt.second_ancestry(), history.sibling.value.ancestry_id());
                            assert!(matches!(
                                source.as_ref(),
                                FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                            ));
                        }
                        (_, other) => panic!("unexpected anchor failure {other:?}"),
                    }
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
            let images = layout.images();
            match (
                fail_finality,
                fixture.provision(&layout, 8).open(fixture.signing_key()),
            ) {
                (true, Err(FixedValidatorNodeStartupErrorV0::FinalityPair(source))) => {
                    assert!(matches!(
                        source.as_ref(),
                        naome_storage::FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                            naome_storage::FixedValidatorFinalityJournalErrorV0::AnchorBehind { .. }
                        )
                    ))
                }
                (false, Err(FixedValidatorNodeStartupErrorV0::VotePair(source))) => assert!(
                    matches!(source.as_ref(), FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner) if matches!(inner.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }))
                ),
                _ => panic!("strict reopen must reject the independently lagging anchor"),
            }
            assert_eq!(layout.images(), images);
        }
    }
}
