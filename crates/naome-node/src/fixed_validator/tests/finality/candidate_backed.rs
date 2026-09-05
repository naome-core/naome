use super::*;

#[test]
fn candidate_backed_children_advance_the_node_without_mutating_sources() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-live-finality");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let first = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let first_target = first_block.id();
            retain_transition_inputs(&mut candidates, &mut payloads, scope.branch(), &first);
            let node_before_first = layout.images();
            let sources_before_first = layout.source_images();
            let (scope, selection) = expect_continuation(
                scope
                    .commit_candidate_backed_finality(
                        &mut candidates,
                        &mut payloads,
                        first_target,
                        first.canonical_envelope_bytes(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let first_state_id = match selection {
                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                    target,
                    position,
                    ancestry_id,
                    envelope_id,
                    state_id,
                } => {
                    assert_eq!(target, first_target);
                    assert_eq!(position, first.position());
                    assert_eq!(ancestry_id, first.value().ancestry_id());
                    assert_eq!(envelope_id, first.envelope_id());
                    state_id
                }
                _ => panic!("the retained child must report candidate-backed finality"),
            };
            let node_after_first = layout.images();
            for (index, (before, after)) in
                node_before_first.iter().zip(&node_after_first).enumerate()
            {
                assert_ne!(before, after, "node durable image {index} did not advance");
            }
            assert_eq!(layout.source_images(), sources_before_first);
            assert_eq!(scope.finality.state_id().unwrap(), first_state_id);
            assert_eq!(
                scope
                    .finality
                    .head()
                    .unwrap()
                    .artifact_snapshot()
                    .head_block_id(),
                first_target
            );
            assert_eq!(
                scope.branch.artifact_snapshot().head_block_id(),
                first_target
            );
            assert_eq!(scope.signing_session.position().height().value(), 2);
            assert_eq!(scope.signing_session.position().round().value(), 0);
            assert_eq!(
                scope.finality.head().unwrap().coordinate(),
                scope.branch.coordinate()
            );

            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 1);
            let second_target = second.value().artifact_block().id();
            retain_transition_inputs(&mut candidates, &mut payloads, scope.branch(), &second);
            let sources_before_second = layout.source_images();
            let (mut scope, selection) = expect_continuation(
                scope
                    .commit_candidate_backed_finality(
                        &mut candidates,
                        &mut payloads,
                        second_target,
                        second.canonical_envelope_bytes(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            let second_state_id = match selection {
                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                    target,
                    position,
                    ancestry_id,
                    envelope_id,
                    state_id,
                } => {
                    assert_eq!(target, second_target);
                    assert_eq!(position, second.position());
                    assert_eq!(ancestry_id, second.value().ancestry_id());
                    assert_eq!(envelope_id, second.envelope_id());
                    state_id
                }
                _ => panic!("the retained child must report candidate-backed finality"),
            };
            let node_after_second = layout.images();
            for (index, (before, after)) in
                node_after_first.iter().zip(&node_after_second).enumerate()
            {
                assert_ne!(before, after, "node durable image {index} did not advance");
            }
            assert_eq!(layout.source_images(), sources_before_second);
            assert_eq!(scope.finality().state_id().unwrap(), second_state_id);
            assert_eq!(
                scope
                    .finality()
                    .head()
                    .unwrap()
                    .artifact_snapshot()
                    .head_block_id(),
                second_target
            );
            assert_eq!(
                scope.branch().artifact_snapshot().head_block_id(),
                second_target
            );
            assert_eq!(scope.signing_session().position().height().value(), 3);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.finality().head().unwrap().coordinate(),
                scope.branch().coordinate()
            );
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn candidate_backed_batches_accept_current_lower_and_higher_bounded_rounds() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-batch-rounds");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let mut selected = ArtifactChainState::new(fixture.definition);

    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let (first, first_control, first_precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                scope.branch(),
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Pairing,
                0,
            );
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let first_target = first_block.id();
            let first_batch = [first_precommit.as_slice()];
            let node_before_first = layout.images();
            let sources_before_first = layout.source_images();
            let (mut scope, selection) = expect_candidate_backed_finality(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        first_target,
                        &first_control,
                        &first_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                    target,
                    position,
                    ancestry_id,
                    envelope_id,
                    ..
                } if target == first_target
                    && position == first.position()
                    && ancestry_id == first.value().ancestry_id()
                    && envelope_id == first.envelope_id()
            ));
            for (index, (before, after)) in
                node_before_first.iter().zip(layout.images()).enumerate()
            {
                assert_ne!(
                    before, &after,
                    "current-round node image {index} did not advance"
                );
            }
            assert_eq!(layout.source_images(), sources_before_first);

            selected.apply_block(&first_block, first_payload).unwrap();
            let second_branch = scope.branch().clone();
            let (second, second_control, second_precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                &second_branch,
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Union,
                1,
            );
            let second_block = second.value().artifact_block();
            let second_payload = second.canonical_artifact_bytes().to_vec();
            let second_target = second_block.id();
            let signer_round_one = round_at(&second_branch, 1);
            advance_signer_round_without_writing(&mut scope, &signer_round_one);
            let signer_round_two = round_at(&second_branch, 2);
            advance_signer_round_without_writing(&mut scope, &signer_round_two);
            let second_batch = [second_precommit.as_slice()];
            let node_before_second = layout.images();
            let sources_before_second = layout.source_images();
            let (scope, selection) = expect_candidate_backed_finality(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        second_target,
                        &second_control,
                        &second_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(2),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                    target,
                    position,
                    ancestry_id,
                    envelope_id,
                    ..
                } if target == second_target
                    && position == second.position()
                    && ancestry_id == second.value().ancestry_id()
                    && envelope_id == second.envelope_id()
            ));
            for (index, (before, after)) in
                node_before_second.iter().zip(layout.images()).enumerate()
            {
                assert_ne!(
                    before, &after,
                    "lower-round node image {index} did not advance"
                );
            }
            assert_eq!(layout.source_images(), sources_before_second);

            selected.apply_block(&second_block, second_payload).unwrap();
            let (third, third_control, third_precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                scope.branch(),
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::PowerSet,
                2,
            );
            let third_target = third.value().artifact_block().id();
            assert_eq!(
                scope.signing_session.position().round(),
                ConsensusRound::new(0)
            );
            let third_batch = [third_precommit.as_slice()];
            let node_before_third = layout.images();
            let sources_before_third = layout.source_images();
            let (mut scope, selection) = expect_candidate_backed_finality(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        third_target,
                        &third_control,
                        &third_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(2),
                            ConsensusRound::new(2),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                    target,
                    position,
                    ancestry_id,
                    envelope_id,
                    ..
                } if target == third_target
                    && position == third.position()
                    && ancestry_id == third.value().ancestry_id()
                    && envelope_id == third.envelope_id()
            ));
            for (index, (before, after)) in
                node_before_third.iter().zip(layout.images()).enumerate()
            {
                assert_ne!(
                    before, &after,
                    "higher-round node image {index} did not advance"
                );
            }
            assert_eq!(layout.source_images(), sources_before_third);
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn candidate_backed_batch_rejections_preserve_scope_for_incremental_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-batch-retry");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let selected = ArtifactChainState::new(fixture.definition);
    let node_before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let block = transition.value().artifact_block();
            let target = block.id();
            let payload = transition.canonical_artifact_bytes().to_vec();
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
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);
            let empty_sources = layout.source_images();

            let (next, rejection) = expect_candidate_backed_finality_rejection(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        target,
                        &[0_u8],
                        &[],
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(9),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCandidateBackedFinalityRejectionV0::RoundWorkLimitExceedsFinality {
                    requested,
                    finality,
                } if requested == ConsensusRound::new(9)
                    && finality == ConsensusRound::new(8)
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), empty_sources);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_candidate_backed_finality_rejection(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        target,
                        &[0_u8],
                        &[],
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCandidateBackedFinalityRejectionV0::EvidenceRoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1)
                    && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), empty_sources);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_candidate_backed_finality_rejection(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        target,
                        &control,
                        &batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCandidateBackedFinalityRejectionV0::CandidateUnavailable {
                    target: actual,
                } if actual == target
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), empty_sources);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let _ = candidates.insert(&block).unwrap();
            let candidate_only_sources = layout.source_images();
            let (next, rejection) = expect_candidate_backed_finality_rejection(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        target,
                        &control,
                        &batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCandidateBackedFinalityRejectionV0::PayloadUnavailable {
                    target: actual,
                } if actual == target
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), candidate_only_sources);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let _ = payloads
                .validate_and_insert_branch_payload(
                    scope.branch().artifact_snapshot(),
                    &block,
                    payload,
                )
                .unwrap();
            let complete_sources = layout.source_images();
            let routed_position = ConsensusPosition::new(
                transition.position().height(),
                ConsensusRound::new(1),
            );
            let routed_precommit = signed_vote_bytes(
                fixture.context,
                routed_position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(transition.value().proposal_signing_root()),
                &fixture.signing_key(),
            );
            let routed_batch = [routed_precommit.as_slice()];
            let (next, rejection) = expect_candidate_backed_finality_rejection(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        target,
                        &control,
                        &routed_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCandidateBackedFinalityRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::ProducerAuthorization(
                            ProducerAuthorizationVerifyError::SnapshotPositionMismatch {
                                authorization,
                                snapshot,
                            }
                        ) if *authorization == transition.position()
                            && *snapshot == routed_position
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), complete_sources);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let duplicate_batch = [precommit.as_slice(), precommit.as_slice()];
            let (next, rejection) = expect_candidate_backed_finality_rejection(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        target,
                        &control,
                        &duplicate_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCandidateBackedFinalityRejectionV0::PrecommitBatch(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                            QuorumCertificateBuildError::DuplicateSigner { signer }
                        ) if *signer == consensus_key(&fixture.signing_key())
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), complete_sources);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (_scope, selection) = expect_candidate_backed_finality(
                scope
                    .commit_candidate_backed_finality_vote_batch(
                        &mut candidates,
                        &mut payloads,
                        target,
                        &control,
                        &batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                    target: actual_target,
                    position,
                    envelope_id,
                    ..
                } if actual_target == target
                    && position == transition.position()
                    && envelope_id == transition.envelope_id()
            ));
            assert_eq!(layout.source_images(), complete_sources);
        })
        .unwrap();
}

#[test]
fn missing_candidate_consumes_the_scope_without_mutating_any_store() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-missing");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let target = transition.value().artifact_block().id();
            let node_before = layout.images();
            let sources_before = layout.source_images();
            assert!(matches!(
                scope.commit_candidate_backed_finality(
                    &mut candidates,
                    &mut payloads,
                    target,
                    transition.canonical_envelope_bytes(),
                    ConsensusRound::new(0),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::CandidateUnavailable { target: actual }
                            if *actual == target
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();
}

#[test]
fn exact_selected_replay_is_no_write_and_returns_the_unchanged_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-replay");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let retained_envelope_id = first.envelope_id();
            let replay = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 1);
            assert_ne!(replay.envelope_id(), retained_envelope_id);
            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            let coordinate = scope.branch().coordinate();
            let position = scope.signing_session.position();
            let before_replay = layout.images();
            let (scope, selection) =
                expect_continuation(scope.commit_verified_finality(replay).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::AlreadyFinalized {
                    height,
                    retained_envelope_id: actual,
                    ..
                } if height.value() == 1 && actual == retained_envelope_id
            ));
            assert_eq!(scope.branch().coordinate(), coordinate);
            assert_eq!(scope.signing_session.position(), position);
            assert_eq!(layout.images(), before_replay);
        })
        .unwrap();
}

#[test]
fn verified_sibling_conflict_returns_only_terminal_signer_stop_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-conflict");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let stopped = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let left = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let right = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 0);
            let (mut scope, _) = expect_continuation(scope.commit_verified_finality(left).unwrap());
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            assert!(matches!(
                scope
                    .signing_session_mut()
                    .prepare_vote(&round, effect)
                    .unwrap(),
                FixedValidatorVotePrepareOutcomeV0::Prepared(_)
            ));
            match scope.commit_verified_finality(right).unwrap() {
                FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(stopped) => *stopped,
                FixedValidatorNodeFinalityOutcomeV0::Continues { .. } => {
                    panic!("a distinct verified sibling must not return signing authority")
                }
            }
        })
        .unwrap();
    assert_eq!(
        stopped.signer_stop().height(),
        stopped.finality_halt().height()
    );
    assert_eq!(
        stopped.signer_stop().finality_state_id(),
        stopped.finality_halt().state_id()
    );
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must preserve the coordinated terminal state"),
    }
}

#[test]
fn candidate_backed_historical_sibling_stops_finality_and_signer_without_mutating_sources() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-finality-conflict");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let stopped = ready
        .run_with_signing_session(|scope| {
            let genesis = scope.branch().clone();
            let mut selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(&genesis, &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let selected_ancestry = first.value().ancestry_id();

            let sibling = fixture.transition(&genesis, &selected, ZfcAxiom::Union, 2);
            let sibling_target = sibling.value().artifact_block().id();
            let sibling_ancestry = sibling.value().ancestry_id();
            let sibling_envelope = sibling.canonical_envelope_bytes().to_vec();
            retain_transition_inputs(&mut candidates, &mut payloads, &genesis, &sibling);

            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::PowerSet, 0);
            let (mut scope, _) =
                expect_continuation(scope.commit_verified_finality(second).unwrap());

            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            assert!(matches!(
                scope
                    .signing_session_mut()
                    .prepare_vote(&round, effect)
                    .unwrap(),
                FixedValidatorVotePrepareOutcomeV0::Prepared(_)
            ));

            let node_before = layout.images();
            let sources_before = layout.source_images();
            let stopped = scope
                .commit_candidate_backed_finality_conflict(
                    &mut candidates,
                    &mut payloads,
                    sibling_target,
                    &sibling_envelope,
                    ConsensusRound::new(2),
                )
                .unwrap();
            let node_after = layout.images();
            for (index, (before, after)) in node_before.iter().zip(&node_after).enumerate() {
                assert_ne!(before, after, "node durable image {index} did not advance");
            }
            assert_eq!(layout.source_images(), sources_before);
            assert_eq!(stopped.finality_halt().height().value(), 1);
            assert_eq!(stopped.finality_halt().first_ancestry(), selected_ancestry);
            assert_eq!(stopped.finality_halt().second_ancestry(), sibling_ancestry);
            assert_eq!(
                stopped.signer_stop().finality_state_id(),
                stopped.finality_halt().state_id()
            );
            stopped
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must preserve the candidate-backed terminal state"),
    }
}

#[test]
fn candidate_backed_historical_sibling_vote_batch_stops_both_anchors_and_strictly_reopens() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-finality-conflict-batch");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let stopped = ready
        .run_with_signing_session(|scope| {
            let genesis = scope.branch().clone();
            let mut selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(&genesis, &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let selected_ancestry = first.value().ancestry_id();

            let (sibling, sibling_control, sibling_precommit) =
                candidate_backed_batch_finality_inputs(
                    &fixture,
                    &genesis,
                    &selected,
                    &mut candidates,
                    &mut payloads,
                    ZfcAxiom::Union,
                    2,
                );
            let sibling_target = sibling.value().artifact_block().id();
            let sibling_ancestry = sibling.value().ancestry_id();
            let sibling_envelope_id = sibling.envelope_id();
            let sibling_batch = [sibling_precommit.as_slice()];

            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::PowerSet, 0);
            let (mut scope, _) =
                expect_continuation(scope.commit_verified_finality(second).unwrap());

            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            assert!(matches!(
                scope
                    .signing_session_mut()
                    .prepare_vote(&round, effect)
                    .unwrap(),
                FixedValidatorVotePrepareOutcomeV0::Prepared(_)
            ));

            let node_before = layout.images();
            let sources_before = layout.source_images();
            let stopped = scope
                .commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    sibling_target,
                    &sibling_control,
                    &sibling_batch,
                    FixedValidatorNodeFinalityRoundRouteV0::new(
                        ConsensusRound::new(2),
                        ConsensusRound::new(2),
                    ),
                )
                .unwrap();
            for (index, (before, after)) in node_before.iter().zip(layout.images()).enumerate() {
                assert_ne!(
                    before, &after,
                    "node authority image {index} did not advance"
                );
            }
            assert_eq!(layout.source_images(), sources_before);
            assert_eq!(stopped.finality_halt().height().value(), 1);
            assert_eq!(stopped.finality_halt().first_ancestry(), selected_ancestry);
            assert_eq!(stopped.finality_halt().second_ancestry(), sibling_ancestry);
            assert_eq!(
                stopped.finality_halt().second_envelope_id(),
                sibling_envelope_id
            );
            assert_eq!(
                stopped.signer_stop().finality_state_id(),
                stopped.finality_halt().state_id()
            );
            stopped
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must preserve the batch-backed terminal state"),
    }
}

#[test]
fn candidate_backed_selected_value_vote_batch_error_consumes_scope_and_reopens_ready() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-finality-conflict-batch-selected");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let (expected_coordinate, expected_position) = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let target = transition.value().artifact_block().id();
            let control = proposal_control_bytes(
                transition.value(),
                transition.position(),
                &fixture.signing_key(),
            );
            let (mut scope, _) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            let expected = signing_scope_diagnostics(&mut scope);
            let node_before = layout.images();
            let sources_before = layout.source_images();
            assert!(matches!(
                scope.commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[],
                    FixedValidatorNodeFinalityRoundRouteV0::new(
                        ConsensusRound::new(0),
                        ConsensusRound::new(0),
                    ),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height }
                            if height.value() == 1
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
            (expected.branch_coordinate, expected.position)
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|scope| {
            assert_eq!(scope.branch().coordinate(), expected_coordinate);
            assert_eq!(scope.signing_session.position(), expected_position);
        })
        .unwrap();
}

#[test]
fn candidate_backed_same_selected_value_consumes_scope_without_source_or_node_writes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-finality-conflict-same-value");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let target = transition.value().artifact_block().id();
            let envelope = transition.canonical_envelope_bytes().to_vec();
            let (scope, _) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            let node_before = layout.images();
            let sources_before = layout.source_images();
            assert!(matches!(
                scope.commit_candidate_backed_finality_conflict(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &envelope,
                    ConsensusRound::new(0),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height }
                            if height.value() == 1
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();
}

#[test]
fn unselected_parent_rejection_changes_no_durable_bytes_and_consumes_the_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-unselected");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let genesis_state = ArtifactChainState::new(fixture.definition);
            let selected = fixture.transition(scope.branch(), &genesis_state, ZfcAxiom::Pairing, 0);
            let unselected_parent =
                fixture.transition(scope.branch(), &genesis_state, ZfcAxiom::Union, 0);
            let unselected_block = unselected_parent.value().artifact_block();
            let unselected_payload = unselected_parent.canonical_artifact_bytes().to_vec();
            let unselected_branch = unselected_parent.into_branch();
            let mut unselected_state = ArtifactChainState::new(fixture.definition);
            unselected_state
                .apply_block(&unselected_block, unselected_payload)
                .unwrap();
            let unreachable_child =
                fixture.transition(&unselected_branch, &unselected_state, ZfcAxiom::PowerSet, 0);

            let (scope, _) = expect_continuation(scope.commit_verified_finality(selected).unwrap());
            let before_rejection = layout.images();
            assert!(matches!(
                scope.commit_verified_finality(unreachable_child),
                Err(FixedValidatorNodeFinalityErrorV0::Commit(source))
                    if matches!(
                        source.as_ref(),
                        FixedValidatorFinalityJournalErrorV0::UnselectedParent { height }
                            if height.value() == 2
                    )
            ));
            assert_eq!(layout.images(), before_rejection);
        })
        .unwrap();
}
