use std::path::{Path, PathBuf};

use naome_storage::{
    FixedValidatorAnchoredFinalityJournalErrorV0, FixedValidatorAnchoredVoteSafetyJournalErrorV0,
    FixedValidatorFinalityJournalErrorV0, FixedValidatorVoteSafetyJournalErrorV0,
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
