use std::path::{Path, PathBuf};

use naome_storage::{
    CandidateBackedFinalityErrorV0, FixedValidatorAnchoredFinalityJournalErrorV0,
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorFinalityJournalErrorV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::*;

fn expect_continuation(
    outcome: FixedValidatorNodeFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection } => (*scope, selection),
        FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(_) => {
            panic!("expected continued signing authority")
        }
    }
}

fn next_anchor_collision(directory: &Path, sequence: u64) -> PathBuf {
    let anchor_name = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".anchor"))
        .expect("one typed anchor file must exist");
    let collision = directory.join(format!("{anchor_name}.tmp-{sequence:016x}"));
    fs::write(&collision, b"deterministic anchor collision").unwrap();
    collision
}

#[test]
fn new_finality_advances_both_anchors_before_returning_the_next_signer() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-success");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let original_branch = scope.branch().clone();
            let before_first = layout.images();
            let first = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let (scope, selection) =
                expect_continuation(scope.commit_verified_finality(first).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 1
            ));
            assert_eq!(scope.signing_session.position().height().value(), 2);
            assert_eq!(scope.signing_session.position().round().value(), 0);
            assert_eq!(
                scope.finality.head().unwrap().coordinate(),
                scope.branch.coordinate()
            );
            let after_first = layout.images();
            for (index, (before, after)) in before_first.iter().zip(&after_first).enumerate() {
                assert_ne!(before, after, "durable image {index} did not advance");
            }

            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 1);
            let (mut scope, selection) =
                expect_continuation(scope.commit_verified_finality(second).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 2 && position.round().value() == 1
            ));
            assert_eq!(scope.signing_session().position().height().value(), 3);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.finality().head().unwrap().coordinate(),
                scope.branch().coordinate()
            );
            let after_second = layout.images();
            for (index, (before, after)) in after_first.iter().zip(&after_second).enumerate() {
                assert_ne!(before, after, "durable image {index} did not advance");
            }

            let stale_round = original_branch.begin_round_zero().unwrap();
            let current_branch = scope.branch().clone();
            let current_round = current_branch.begin_round_zero().unwrap();
            let session = scope.signing_session();
            let stale_effect = session.decide_prevote_without_proposal().unwrap();
            assert!(session.prepare_vote(&stale_round, stale_effect).is_err());
            let current_effect = session.decide_precommit_without_quorum().unwrap();
            let prepared = match session
                .prepare_vote(&current_round, current_effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the child-height precommit must prepare exactly once"),
            };
            prepare_and_sign(session, &current_round, prepared);
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();
    assert_eq!(signer_position.height().value(), 3);

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
fn one_child_continuation_strictly_reopens_without_signer_catch_up() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-one-child-reopen");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let (mut scope, selection) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 1
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "durable image {index} did not advance");
            }
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

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
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first vote must leave one durable preparation"),
            };
            let node_before = layout.images();
            let sources_before = layout.source_images();
            let finality_state_id = match scope.commit_candidate_backed_finality(
                &mut candidates,
                &mut payloads,
                target,
                transition.canonical_envelope_bytes(),
                ConsensusRound::new(0),
            ) {
                Err(FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                    selection,
                    source,
                }) => {
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
                        _ => panic!("the failure must retain the candidate-backed selection"),
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
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            assert!(matches!(
                scope
                    .signing_session()
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
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session()
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
    let collision = next_anchor_collision(&layout.vote_anchor, 2);
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
            let collision = next_anchor_collision(&layout.vote_anchor, 3);
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
