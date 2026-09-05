use super::*;
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

async fn suspend_once() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

fn assert_both_journals_locked(fixture: &Fixture, layout: &TestLayout) {
    assert!(matches!(
        fixture.provision(layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(error))
            if matches!(error.as_ref(), FixedValidatorAnchoredFinalityJournalErrorV0::Journal(source)
                if matches!(source, naome_storage::FixedValidatorFinalityJournalErrorV0::Locked))
    ));
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    assert!(matches!(
        FixedValidatorAnchoredVoteSafetyJournalV0::open(
            &layout.vote_journal,
            &layout.vote_anchor,
            fixture.context,
            branch.fixed_agreement_set_id(),
            fixture.signing_key(),
            FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        ),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(*source, FixedValidatorVoteSafetyJournalErrorV0::Locked)
    ));
}

#[test]
fn async_initial_and_recovered_scopes_lend_across_await_with_non_send_captures() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("async-scope");
    let mut ready = Some(
        fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap(),
    );
    let borrowed = Rc::new(Cell::new(0));
    let mut coordinate = None;
    for recovered in [false, true] {
        let ready = if recovered {
            expect_ready(
                fixture
                    .provision_with_catch_up_limit(&layout, 8, 0)
                    .open(fixture.signing_key())
                    .unwrap(),
            )
        } else {
            ready.take().unwrap()
        };
        let images = layout.images();
        let mut future = Box::pin(ready.run_with_signing_session_async(async |mut scope| {
            let original = scope.branch().coordinate();
            borrowed.set(borrowed.get() + 1);
            suspend_once().await;
            assert_eq!(scope.branch().coordinate(), original);
            assert_eq!(scope.signing_session().position().height().value(), 1);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            (original, Rc::clone(&borrowed))
        }));
        assert!(poll_once(future.as_mut()).is_pending());
        assert_both_journals_locked(&fixture, &layout);
        assert_eq!(layout.images(), images);
        let Poll::Ready(Ok((actual, returned))) = poll_once(future.as_mut()) else {
            panic!("second poll completes the callback")
        };
        assert!(Rc::ptr_eq(&returned, &borrowed));
        if let Some(coordinate) = coordinate {
            assert_eq!(actual, coordinate);
        }
        coordinate = Some(actual);
        drop(future);
        assert_eq!(layout.images(), images);
    }
    assert_eq!(borrowed.get(), 2);
}

#[test]
fn unpolled_and_pending_outer_future_drop_release_both_journals_without_writes() {
    for recovered in [false, true] {
        for poll in [false, true] {
            let fixture = Fixture::new();
            let layout = TestLayout::new("async-drop");
            let initial = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            let ready = if recovered {
                drop(initial);
                expect_ready(
                    fixture
                        .provision(&layout, 8)
                        .open(fixture.signing_key())
                        .unwrap(),
                )
            } else {
                initial
            };
            let images = layout.images();
            let called = Cell::new(false);
            let mut future = Box::pin(ready.run_with_signing_session_async(async |scope| {
                called.set(true);
                std::future::pending::<()>().await;
                drop(scope);
            }));
            assert!(!called.get());
            if poll {
                assert!(poll_once(future.as_mut()).is_pending());
            }
            assert_eq!(called.get(), poll);
            assert_eq!(layout.images(), images);
            assert_both_journals_locked(&fixture, &layout);
            drop(future);
            let reopened = expect_ready(
                fixture
                    .provision_with_catch_up_limit(&layout, 8, 0)
                    .open(fixture.signing_key())
                    .unwrap(),
            );
            reopened
                .run_with_signing_session(|mut scope| {
                    assert!(scope.branch().artifact_snapshot().is_virtual_genesis());
                    assert_eq!(scope.signing_session().position().height().value(), 1);
                    assert_eq!(
                        scope.signing_session().phase(),
                        FixedValidatorLockPhaseV0::Proposal
                    );
                })
                .unwrap();
            assert_eq!(layout.images(), images);
        }
    }
}

#[test]
fn cancellation_and_callback_panic_preserve_a_completed_anchored_vote_for_strict_reopen() {
    for panic_callback in [false, true] {
        let fixture = Fixture::new();
        let layout = TestLayout::new("async-durable-drop");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        let signed = RefCell::new(None);
        let mut future = Box::pin(ready.run_with_signing_session_async(async |scope| {
            suspend_once().await;
            let FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote } = scope
                .sign_prevote_after_current_proposal_close(ConsensusRound::new(8))
                .unwrap()
            else {
                panic!("complete anchored prevote")
            };
            *signed.borrow_mut() = Some(vote);
            assert!(
                !panic_callback,
                "caller callback panic after durable completion"
            );
            std::future::pending::<()>().await;
            drop(scope);
        }));
        assert!(poll_once(future.as_mut()).is_pending());
        assert_eq!(layout.images(), before);
        if panic_callback {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll_once(
                    future.as_mut()
                )))
                .is_err()
            );
        } else {
            assert!(poll_once(future.as_mut()).is_pending());
            assert_both_journals_locked(&fixture, &layout);
        }
        let after_vote = layout.images();
        assert_eq!(&after_vote[..2], &before[..2]);
        assert_ne!(&after_vote[2..], &before[2..]);
        drop(future);
        let vote = signed.into_inner().unwrap();
        let reopened = expect_ready(
            fixture
                .provision_with_catch_up_limit(&layout, 8, 0)
                .open(fixture.signing_key())
                .unwrap(),
        );
        let mut future = Box::pin(reopened.run_with_signing_session_async(async |mut scope| {
            assert_eq!(scope.signing_session().position(), vote.position());
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            suspend_once().await;
            scope.signing_session().position()
        }));
        assert!(poll_once(future.as_mut()).is_pending());
        assert!(
            matches!(poll_once(future.as_mut()), Poll::Ready(Ok(position)) if position == vote.position())
        );
        drop(future);
        assert_eq!(layout.images(), after_vote);
    }
}

#[test]
fn async_recovery_checks_the_complete_height_gap_before_callback_and_catches_up_before_await() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("async-height-catch-up");
    drop(
        fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap(),
    );
    let mut finality = fixture.open_finality(&layout);
    let mut selected = ArtifactChainState::new(fixture.definition);
    for axiom in [ZfcAxiom::Pairing, ZfcAxiom::Union] {
        let transition = fixture.transition(finality.head().unwrap(), &selected, axiom, 0);
        let block = transition.value().artifact_block();
        let payload = transition.canonical_artifact_bytes().to_vec();
        assert!(matches!(
            finality.commit_verified(transition).unwrap(),
            FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
        ));
        selected.apply_block(&block, payload).unwrap();
    }
    let selected_coordinate = finality.head().unwrap().coordinate();
    drop(finality);
    let before = layout.images();
    let called = Cell::new(false);
    let too_low = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 1)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let mut future = Box::pin(too_low.run_with_signing_session_async(async |_scope| {
        called.set(true);
    }));
    assert!(matches!(
        poll_once(future.as_mut()),
        Poll::Ready(Err(
            FixedValidatorNodeStartupErrorV0::SignerCatchUpHeightLimitExceeded {
                required: 2,
                maximum: 1
            }
        ))
    ));
    assert!(!called.get());
    drop(future);
    assert_eq!(layout.images(), before);

    let ready = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 2)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let mut future = Box::pin(ready.run_with_signing_session_async(async |mut scope| {
        called.set(true);
        assert_eq!(scope.branch().coordinate(), selected_coordinate);
        assert_eq!(scope.signing_session().position().height().value(), 3);
        assert_eq!(scope.signing_session().position().round().value(), 0);
        std::future::pending::<()>().await;
        drop(scope);
    }));
    // Construction cannot perform either height handoff.
    assert_eq!(layout.images(), before);
    assert!(poll_once(future.as_mut()).is_pending());
    assert!(called.get());
    let caught_up = layout.images();
    assert_eq!(&caught_up[..2], &before[..2]);
    assert_ne!(&caught_up[2..], &before[2..]);
    assert_both_journals_locked(&fixture, &layout);
    drop(future);
    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position().height().value(), 3);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
        })
        .unwrap();
    assert_eq!(layout.images(), caught_up);
}

#[test]
fn async_recovery_round_ceiling_rejects_before_callback_and_preserves_exact_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("async-round-limit");
    fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap()
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let session = scope.signing_session_mut();
            for precommit in [false, true] {
                let effect = if precommit {
                    session.decide_precommit_without_quorum().unwrap()
                } else {
                    session.decide_prevote_without_proposal().unwrap()
                };
                let FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) =
                    session.prepare_vote(&round_zero, effect).unwrap()
                else {
                    panic!("fresh vote")
                };
                prepare_and_sign(session, &round_zero, prepared);
            }
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            session.advance_round(&round_one).unwrap();
            let effect = session.decide_prevote_without_proposal().unwrap();
            let FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) =
                session.prepare_vote(&round_one, effect).unwrap()
            else {
                panic!("round-one vote")
            };
            prepare_and_sign(session, &round_one, prepared);
        })
        .unwrap();
    let before = layout.images();
    let called = Cell::new(false);
    let too_low = expect_ready(
        fixture
            .provision(&layout, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let mut future = Box::pin(too_low.run_with_signing_session_async(async |_scope| {
        called.set(true);
    }));
    assert!(
        matches!(poll_once(future.as_mut()), Poll::Ready(Err(FixedValidatorNodeStartupErrorV0::Vote(source))) if matches!(*source, FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRoundLimitExceeded { required: 1, maximum: 0 }))
    );
    assert!(!called.get());
    drop(future);
    assert_eq!(layout.images(), before);
    let ready = expect_ready(
        fixture
            .provision(&layout, 1)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let mut future = Box::pin(ready.run_with_signing_session_async(async |mut scope| {
        called.set(true);
        assert_eq!(scope.signing_session().position().round().value(), 1);
        assert_eq!(
            scope.signing_session().phase(),
            FixedValidatorLockPhaseV0::Prevote
        );
        suspend_once().await;
        scope.signing_session().position()
    }));
    assert!(poll_once(future.as_mut()).is_pending());
    assert!(called.get());
    assert!(
        matches!(poll_once(future.as_mut()), Poll::Ready(Ok(position)) if position.round().value() == 1)
    );
    drop(future);
    assert_eq!(layout.images(), before);
}

#[test]
fn first_poll_catch_up_anchor_failure_never_calls_back_and_reopens_only_as_anchor_behind() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("async-catch-up-anchor-failure");
    drop(
        fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap(),
    );
    let mut finality = fixture.open_finality(&layout);
    let mut selected = ArtifactChainState::new(fixture.definition);
    for axiom in [ZfcAxiom::Pairing, ZfcAxiom::Union] {
        let transition = fixture.transition(finality.head().unwrap(), &selected, axiom, 0);
        let block = transition.value().artifact_block();
        let payload = transition.canonical_artifact_bytes().to_vec();
        assert!(matches!(
            finality.commit_verified(transition).unwrap(),
            FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
        ));
        selected.apply_block(&block, payload).unwrap();
    }
    drop(finality);
    let ready = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 2)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let before = layout.images();
    let called = Cell::new(false);
    let mut future = Box::pin(ready.run_with_signing_session_async(async |_scope| {
        called.set(true);
    }));
    assert_eq!(layout.images(), before);
    // Activation and lineage occupy sequences 1 and 2. The first handoff
    // anchors 3; fail the second at 4 after the outer future exists, before poll.
    let anchor_name = fs::read_dir(&layout.vote_anchor)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".anchor"))
        .unwrap();
    let collision = layout
        .vote_anchor
        .join(format!("{anchor_name}.tmp-{:016x}", 4));
    fs::write(&collision, b"deterministic anchor collision").unwrap();
    assert!(
        matches!(poll_once(future.as_mut()), Poll::Ready(Err(FixedValidatorNodeStartupErrorV0::Vote(error)))
        if matches!(*error, FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }))
    );
    assert!(!called.get());
    drop(future);
    fs::remove_file(collision).unwrap();
    let failed = layout.images();
    assert_eq!(&failed[..2], &before[..2]);
    assert_ne!(failed[2], before[2]);
    assert_ne!(failed[3], before[3]);
    for _ in 0..2 {
        assert!(
            matches!(fixture.provision_with_catch_up_limit(&layout, 8, 2).open(fixture.signing_key()),
            Err(FixedValidatorNodeStartupErrorV0::VotePair(error))
            if matches!(error.as_ref(), FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source)
                if matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { anchored_sequence: 3, journal_sequence: 4 })))
        );
        assert_eq!(layout.images(), failed);
    }
}
