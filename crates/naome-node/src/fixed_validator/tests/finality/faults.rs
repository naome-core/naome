use super::*;

#[test]
fn current_round_finality_commits_before_a_pending_signer_handoff_fails() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-pending");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let (prepared_vote, finality_state_id) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                &proposer,
                &[&proposer],
            );
            let effect = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session_mut()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first vote must leave one durable preparation"),
            };
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            let before_finality = layout.images();
            let finality_state_id = match scope.commit_current_round_finality(
                &control,
                payload,
                &certificate,
                ConsensusRound::new(0),
            ) {
                Err(FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(source)) => {
                    match source.as_ref() {
                        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                            selection,
                            source,
                        } => {
                            assert!(matches!(
                                source.as_ref(),
                                FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. }
                            ));
                            match selection.as_ref() {
                                FixedValidatorNodeFinalitySelectionV0::Finalized {
                                    position: actual_position,
                                    ancestry_id,
                                    state_id,
                                    ..
                                } => {
                                    assert_eq!(*actual_position, position);
                                    assert_eq!(*ancestry_id, value.ancestry_id());
                                    *state_id
                                }
                                _ => panic!("the failure must retain the direct finality result"),
                            }
                        }
                        _ => panic!("pending signer work must fail at the height handoff"),
                    }
                }
                _ => panic!("valid finality must not be suppressed by pending signer work"),
            };
            let after_finality = layout.images();
            assert_ne!(after_finality[0], before_finality[0]);
            assert_ne!(after_finality[1], before_finality[1]);
            assert_eq!(after_finality[2], before_finality[2]);
            assert_eq!(after_finality[3], before_finality[3]);
            (prepared_vote, finality_state_id)
        })
        .unwrap();

    let finality = fixture.open_finality(&layout);
    assert_eq!(finality.state_id().unwrap(), finality_state_id);
    drop(finality);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), prepared_vote.position());
            assert_eq!(pending.role(), prepared_vote.role());
            assert_eq!(pending.target(), prepared_vote.target());
            assert_eq!(pending.state_id(), prepared_vote.state_id());
        }
        _ => panic!("strict restart must expose the durable pending signer state"),
    }
}

#[test]
fn lower_round_finality_commits_before_a_pending_signer_handoff_fails() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-pending");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let (prepared_vote, finality_state_id) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                &proposer,
                &[&proposer],
            );
            let effect = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session_mut()
                .prepare_vote(&round_one, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first later-round vote must leave one durable preparation"),
            };
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            let before_finality = layout.images();
            let finality_state_id = match scope.commit_lower_round_finality(
                &control,
                payload,
                &certificate,
                ConsensusRound::new(0),
            ) {
                Err(FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(source)) => {
                    match source.as_ref() {
                        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                            selection,
                            source,
                        } => {
                            assert!(matches!(
                                source.as_ref(),
                                FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. }
                            ));
                            match selection.as_ref() {
                                FixedValidatorNodeFinalitySelectionV0::Finalized {
                                    position: actual_position,
                                    ancestry_id,
                                    state_id,
                                    ..
                                } => {
                                    assert_eq!(*actual_position, position);
                                    assert_eq!(*ancestry_id, value.ancestry_id());
                                    *state_id
                                }
                                _ => panic!(
                                    "the failure must retain the lower-round finality result"
                                ),
                            }
                        }
                        _ => panic!("pending signer work must fail at the height handoff"),
                    }
                }
                _ => panic!("valid lower-round finality must not be suppressed by pending work"),
            };
            let after_finality = layout.images();
            assert_ne!(after_finality[0], before_finality[0]);
            assert_ne!(after_finality[1], before_finality[1]);
            assert_eq!(after_finality[2], before_finality[2]);
            assert_eq!(after_finality[3], before_finality[3]);
            (prepared_vote, finality_state_id)
        })
        .unwrap();

    let finality = fixture.open_finality(&layout);
    assert_eq!(finality.state_id().unwrap(), finality_state_id);
    drop(finality);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), prepared_vote.position());
            assert_eq!(pending.role(), prepared_vote.role());
            assert_eq!(pending.target(), prepared_vote.target());
            assert_eq!(pending.state_id(), prepared_vote.state_id());
        }
        _ => panic!("strict restart must expose the durable pending signer state"),
    }
}

#[test]
fn current_round_batch_pair_journal_rejection_consumes_scope_and_strictly_reopens_ready() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-batch-pair-not-distinct");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    let error = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let (control, payload, _, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                &proposer,
                &[&proposer],
            );
            let precommit = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &proposer,
            );
            let batch = [precommit.as_slice()];

            match scope.commit_current_round_preselection_conflict_vote_batches(
                &control,
                payload.clone(),
                &batch,
                &control,
                payload,
                &batch,
                ConsensusRound::new(0),
            ) {
                Err(error) => error,
                Ok(_) => panic!("a same-transition exact-current batch pair must fail in finality"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeFinalityErrorV0::Commit(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct {
                            height,
                        } if *height == ConsensusHeight::new(1)
                    )
            )
    ));
    assert_eq!(layout.images(), before);

    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn lower_round_pair_journal_rejection_consumes_scope_and_strictly_reopens_ready() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-pair-not-distinct");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    let error = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_two);
            let (control, payload, certificate, _, _) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                1,
                &proposer,
                &[&proposer],
            );

            match scope.commit_lower_round_preselection_conflict(
                &control,
                payload.clone(),
                &certificate,
                &control,
                payload,
                &certificate,
                ConsensusRound::new(1),
            ) {
                Err(error) => error,
                Ok(_) => panic!("a same-transition pair must fail inside finality"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeFinalityErrorV0::Commit(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct {
                            height,
                        } if *height == ConsensusHeight::new(1)
                    )
            )
    ));
    assert_eq!(layout.images(), before);

    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn lower_round_batch_pair_journal_rejection_consumes_scope_and_strictly_reopens_ready() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-batch-pair-not-distinct");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    let error = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_two);
            let (control, payload, _, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                1,
                &proposer,
                &[&proposer],
            );
            let precommit = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &proposer,
            );
            let batch = [precommit.as_slice()];

            match scope.commit_lower_round_preselection_conflict_vote_batches(
                &control,
                payload.clone(),
                &batch,
                &control,
                payload,
                &batch,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    ConsensusRound::new(1),
                    ConsensusRound::new(1),
                ),
            ) {
                Err(error) => error,
                Ok(_) => panic!("a same-transition batch pair must fail inside finality"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeFinalityErrorV0::Commit(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct {
                            height,
                        } if *height == ConsensusHeight::new(1)
                    )
            )
    ));
    assert_eq!(layout.images(), before);

    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn pending_vote_after_candidate_finality_returns_the_known_selection_without_a_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-pending");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let (prepared_vote, finality_state_id) = ready
        .run_with_signing_session(|mut scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let target = transition.value().artifact_block().id();
            retain_transition_inputs(&mut candidates, &mut payloads, scope.branch(), &transition);
            let control = proposal_control_bytes(
                transition.value(),
                transition.position(),
                &fixture.signing_key(),
            );
            let precommit = signed_vote_bytes(
                fixture.context,
                transition.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(transition.value().proposal_signing_root()),
                &fixture.signing_key(),
            );
            let batch = [precommit.as_slice()];
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session_mut()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first vote must leave one durable preparation"),
            };
            let node_before = layout.images();
            let sources_before = layout.source_images();
            let finality_state_id = match scope.commit_candidate_backed_finality_vote_batch(
                &mut candidates,
                &mut payloads,
                target,
                &control,
                &batch,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    ConsensusRound::new(0),
                    ConsensusRound::new(0),
                ),
            ) {
                Err(FixedValidatorNodeCandidateBackedFinalityErrorV0::Finality(source)) => {
                    match source.as_ref() {
                        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                            selection,
                            source,
                        } => {
                            assert!(matches!(
                                source.as_ref(),
                                FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. }
                            ));
                            match selection.as_ref() {
                                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                                    target: actual,
                                    position,
                                    ancestry_id,
                                    envelope_id,
                                    state_id,
                                } => {
                                    assert_eq!(*actual, target);
                                    assert_eq!(*position, transition.position());
                                    assert_eq!(*ancestry_id, transition.value().ancestry_id());
                                    assert_eq!(*envelope_id, transition.envelope_id());
                                    *state_id
                                }
                                _ => {
                                    panic!("the failure must retain the candidate-backed selection")
                                }
                            }
                        }
                        _ => panic!("the pending vote must prevent signer height preparation"),
                    }
                }
                _ => panic!("the pending vote must prevent signer height preparation"),
            };
            let node_after = layout.images();
            assert_ne!(node_after[0], node_before[0]);
            assert_ne!(node_after[1], node_before[1]);
            assert_eq!(node_after[2], node_before[2]);
            assert_eq!(node_after[3], node_before[3]);
            assert_eq!(layout.source_images(), sources_before);
            (prepared_vote, finality_state_id)
        })
        .unwrap();
    drop(candidates);
    drop(payloads);
    let finality = fixture.open_finality(&layout);
    assert_eq!(finality.state_id().unwrap(), finality_state_id);
    drop(finality);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), prepared_vote.position());
            assert_eq!(pending.role(), prepared_vote.role());
            assert_eq!(pending.target(), prepared_vote.target());
            assert_eq!(pending.state_id(), prepared_vote.state_id());
        }
        _ => panic!("strict restart must expose the durable pending signer state"),
    }
}

#[test]
fn durable_pending_vote_makes_post_finality_handoff_fail_closed() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-pending");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let prepared_vote = ready
        .run_with_signing_session(|mut scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session_mut()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first vote must leave one durable preparation"),
            };
            assert!(matches!(
                scope.commit_verified_finality(transition),
                Err(FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                    selection,
                    source,
                }) if matches!(
                        selection.as_ref(),
                        FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                            if position.height().value() == 1
                    )
                    && matches!(
                        source.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. }
                    )
            ));
            prepared_vote
        })
        .unwrap();
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), prepared_vote.position());
            assert_eq!(pending.state_id(), prepared_vote.state_id());
        }
        _ => panic!("strict restart must expose the durable pending signer state"),
    }
}

#[test]
fn finality_anchor_failure_returns_no_scope_and_reopens_only_as_anchor_behind() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.finality_anchor, 1);
    let error = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            match scope.commit_verified_finality(transition) {
                Err(error) => error,
                Ok(_) => panic!("the finality anchor collision must fail closed"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeFinalityErrorV0::Commit(source)
            if matches!(source.as_ref(), FixedValidatorFinalityJournalErrorV0::Commit { .. })
    ));
    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                    FixedValidatorFinalityJournalErrorV0::AnchorBehind { .. }
                )
            )
    ));
}

#[test]
fn signer_anchor_failure_preserves_known_finality_but_returns_no_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-signer-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);
    let error = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            match scope.commit_verified_finality(transition) {
                Err(error) => error,
                Ok(_) => panic!("the signer anchor collision must fail closed"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
            selection,
            source,
        } if matches!(
                selection.as_ref(),
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 1
            )
            && matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
    ));
    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }
                    )
            )
    ));
}

#[test]
fn conflict_stop_anchor_failure_returns_no_scope_and_no_false_terminal_outcome() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-conflict-stop-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let error = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let left = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let right = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 0);
            let (scope, _) = expect_continuation(scope.commit_verified_finality(left).unwrap());
            let collision = next_anchor_collision(&layout.vote_anchor, 4);
            let error = match scope.commit_verified_finality(right) {
                Err(error) => error,
                Ok(_) => panic!("the signer-stop anchor collision must fail closed"),
            };
            fs::remove_file(collision).unwrap();
            error
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeFinalityErrorV0::SignerStop { halt, source }
            if halt.height().value() == 1
                && matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
    ));
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }
                    )
            )
    ));
}

#[test]
fn paired_conflict_anchor_failures_return_no_scope_and_reopen_only_as_journal_ahead() {
    let fixture = Fixture::new();
    let selected = ArtifactChainState::new(fixture.definition);

    let finality_layout = TestLayout::new("paired-finality-anchor-failure");
    let ready = fixture
        .provision(&finality_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let finality_anchor_image = directory_image(&finality_layout.finality_anchor);
    let finality_anchor_bytes = &finality_anchor_image
        .iter()
        .find(|(name, _)| name.ends_with(".anchor"))
        .unwrap()
        .1;
    let finality_sequence = u64::from_be_bytes(finality_anchor_bytes[149..157].try_into().unwrap());
    let collision = next_anchor_collision(&finality_layout.finality_anchor, finality_sequence + 1);
    let error = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let (first_control, first_payload, first_certificate, _, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Pairing,
                    0,
                    &fixture.signing_key(),
                    &[&fixture.signing_key()],
                );
            let (second_control, second_payload, second_certificate, _, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Union,
                    0,
                    &fixture.signing_key(),
                    &[&fixture.signing_key()],
                );
            match scope.commit_current_round_preselection_conflict(
                &first_control,
                first_payload,
                &first_certificate,
                &second_control,
                second_payload,
                &second_certificate,
                ConsensusRound::new(8),
            ) {
                Err(error) => error,
                Ok(_) => panic!("the paired finality anchor collision must fail closed"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeFinalityErrorV0::Commit(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorFinalityJournalErrorV0::PairedCommit { .. }
                    )
            )
    ));
    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture
            .provision(&finality_layout, 8)
            .open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                    FixedValidatorFinalityJournalErrorV0::AnchorBehind { .. }
                )
            )
    ));

    let signer_layout = TestLayout::new("paired-signer-stop-anchor-failure");
    let ready = fixture
        .provision(&signer_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let vote_anchor_image = directory_image(&signer_layout.vote_anchor);
    let vote_anchor_bytes = &vote_anchor_image
        .iter()
        .find(|(name, _)| name.ends_with(".anchor"))
        .unwrap()
        .1;
    let vote_sequence = u64::from_be_bytes(vote_anchor_bytes[184..192].try_into().unwrap());
    let collision = next_anchor_collision(&signer_layout.vote_anchor, vote_sequence + 1);
    let error = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let proposer = fixture.signing_key();
            let (first_control, first_payload, first_certificate, _, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Pairing,
                    0,
                    &proposer,
                    &[&proposer],
                );
            let (second_control, second_payload, second_certificate, _, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Union,
                    0,
                    &proposer,
                    &[&proposer],
                );
            match scope.commit_current_round_preselection_conflict(
                &first_control,
                first_payload,
                &first_certificate,
                &second_control,
                second_payload,
                &second_certificate,
                ConsensusRound::new(8),
            ) {
                Err(error) => error,
                Ok(_) => panic!("the paired signer-stop anchor collision must fail closed"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeFinalityErrorV0::SignerStop { halt, source }
                    if halt.kind()
                        == naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
                        && matches!(
                            source.as_ref(),
                            FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                        )
            )
    ));
    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture
            .provision(&signer_layout, 8)
            .open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }
                    )
            )
    ));
}

#[test]
fn lower_round_pair_anchor_failures_consume_scope_and_require_strict_reopen() {
    let fixture = Fixture::new();
    let selected = ArtifactChainState::new(fixture.definition);

    let finality_layout = TestLayout::new("lower-pair-finality-anchor-failure");
    let ready = fixture
        .provision(&finality_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let finality_anchor_image = directory_image(&finality_layout.finality_anchor);
    let finality_anchor_bytes = &finality_anchor_image
        .iter()
        .find(|(name, _)| name.ends_with(".anchor"))
        .unwrap()
        .1;
    let finality_sequence = u64::from_be_bytes(finality_anchor_bytes[149..157].try_into().unwrap());
    let collision = next_anchor_collision(&finality_layout.finality_anchor, finality_sequence + 1);
    let error = ready
        .run_with_signing_session(|scope| {
            match commit_complete_lower_round_preselection_pair(scope, &fixture, &selected, false) {
                Err(error) => error,
                Ok(_) => panic!("the lower-round pair finality anchor collision must fail closed"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeFinalityErrorV0::Commit(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorFinalityJournalErrorV0::PairedCommit { .. }
                    )
            )
    ));
    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture
            .provision(&finality_layout, 8)
            .open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                    FixedValidatorFinalityJournalErrorV0::AnchorBehind { .. }
                )
            )
    ));

    let signer_layout = TestLayout::new("lower-pair-signer-stop-anchor-failure");
    let ready = fixture
        .provision(&signer_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let vote_anchor_image = directory_image(&signer_layout.vote_anchor);
    let vote_anchor_bytes = &vote_anchor_image
        .iter()
        .find(|(name, _)| name.ends_with(".anchor"))
        .unwrap()
        .1;
    let vote_sequence = u64::from_be_bytes(vote_anchor_bytes[184..192].try_into().unwrap());
    let collision = next_anchor_collision(&signer_layout.vote_anchor, vote_sequence + 1);
    let error = ready
        .run_with_signing_session(|scope| {
            match commit_complete_lower_round_preselection_pair(scope, &fixture, &selected, false) {
                Err(error) => error,
                Ok(_) => panic!("the lower-round pair signer anchor collision must fail closed"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeFinalityErrorV0::SignerStop { halt, source }
                    if halt.kind()
                        == naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
                        && matches!(
                            source.as_ref(),
                            FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                        )
            )
    ));
    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture
            .provision(&signer_layout, 8)
            .open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }
                    )
            )
    ));
}
