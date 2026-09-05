use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

#[test]
fn concurrent_awaited_owners_deliver_over_noise_finalize_and_strictly_reopen() {
    let fixture = Fixture::new();
    let layouts = [
        TestLayout::new("async-source"),
        TestLayout::new("async-receiver"),
    ];
    let mut ready = layouts.iter().enumerate().map(|(index, layout)| {
        provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            layout,
        )
        .create(fixture.keys[index].clone())
        .unwrap()
    });
    let source_ready = ready.next().unwrap();
    let receiver_ready = ready.next().unwrap();
    let payload = pairing_payload();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let source_done = Rc::new(Cell::new(false));
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    executor.block_on(async {
        let (source_network, receiver_network, peer) = connected_pair().await;
        let source_peer = source_network.local_peer_id();
        let source = source_ready.run_with_signing_session_async(async |scope| {
            let mut owner = Runtime::new(
                node_driver(scope),
                source_network,
                vec![peer],
                timeouts(Duration::from_secs(60)),
            )
            .unwrap();
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            tokio::task::yield_now().await;
            assert!(matches!(
                owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: block,
                    canonical_artifact_bytes: payload,
                }),
                Event::ProposalAuthored
            ));
            let mut receipts = 0;
            let mut completed = 0;
            loop {
                match owner.next_event().await {
                    Event::PeerAttempted { started, .. } => assert!(started),
                    Event::PeerCompleted { received, .. } => {
                        assert!(received);
                        receipts += 1;
                    }
                    Event::PublicationComplete(publication) => {
                        assert!(publication.is_complete());
                        assert_eq!(publication.deliveries().count(), 1);
                        assert!(
                            publication
                                .deliveries()
                                .all(|d| matches!(d.state(), Delivery::Received(_)))
                        );
                        completed += 1;
                    }
                    Event::Finality(_) => break,
                    event => check_local(event),
                }
            }
            assert_eq!((receipts, completed), (3, 3));
            source_done.set(true);
            owner
                .driver()
                .unwrap()
                .selected_artifact_history()
                .selected_head_block_id()
                .unwrap()
        });
        let receiver = receiver_ready.run_with_signing_session_async(async |scope| {
            let mut owner = Runtime::new(
                node_driver(scope),
                receiver_network,
                vec![],
                timeouts(Duration::from_secs(60)),
            )
            .unwrap();
            let mut admitted = 0;
            loop {
                match owner.next_event().await {
                    Event::Admission(report) if matches!(report.source, InputSource::Peer(_)) => {
                        assert_eq!(report.source, InputSource::Peer(source_peer));
                        assert_eq!(report.receipt_queued, Some(true));
                        assert!(report.all_admitted());
                        admitted += 1;
                    }
                    Event::Finality(_) => break,
                    event => check_local(event),
                }
            }
            assert_eq!(admitted, 3);
            // Keep the transport owner alive until its final queued receipt
            // actually reaches the sender; finality itself is no receipt.
            while !source_done.get() {
                owner.poll_transport_once().await;
                tokio::task::yield_now().await;
            }
            owner
                .driver()
                .unwrap()
                .selected_artifact_history()
                .selected_head_block_id()
                .unwrap()
        });
        let (source, receiver) = timeout(Duration::from_secs(10), async {
            tokio::join!(source, receiver)
        })
        .await
        .unwrap();
        assert_eq!(source.unwrap(), block.id());
        assert_eq!(receiver.unwrap(), block.id());
    });
    for (index, layout) in layouts.iter().enumerate() {
        let images = layout.authority_images();
        let FixedValidatorNodeStartupV0::Ready(ready) = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            layout,
        )
        .open(fixture.keys[index].clone())
        .unwrap() else {
            panic!("strict reopen")
        };
        executor
            .block_on(ready.run_with_signing_session_async(async |scope| {
                let driver = node_driver(scope);
                tokio::task::yield_now().await;
                assert_eq!(
                    driver
                        .selected_artifact_history()
                        .selected_head_block_id()
                        .unwrap(),
                    block.id()
                );
                assert_eq!(driver.position().height().value(), 2);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            }))
            .unwrap();
        assert_eq!(layout.authority_images(), images);
    }
}

#[test]
fn outer_future_drop_discards_runtime_custody_but_strict_reopen_replays_exact_proposal() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("async-runtime-drop");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let initial = layout.authority_images();
    let payload = pairing_payload();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let original = RefCell::new(None);
    let reached = Cell::new(false);
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    executor.block_on(async {
        let mut future = Box::pin(ready.run_with_signing_session_async(async |scope| {
            let mut owner = Runtime::new(
                node_driver(scope),
                isolated_network(),
                vec![],
                timeouts(Duration::from_secs(60)),
            )
            .unwrap();
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            assert!(matches!(
                owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: block,
                    canonical_artifact_bytes: payload.clone(),
                }),
                Event::ProposalAuthored
            ));
            assert!(matches!(
                owner.next_event().await,
                Event::PublicationPrepared(_)
            ));
            let message = owner
                .pending_publication()
                .unwrap()
                .message()
                .copy_message()
                .unwrap();
            *original.borrow_mut() = Some(copy_message(&message));
            check_local(owner.next_event().await);
            owner.queue_input(message).unwrap();
            assert!(
                owner
                    .pending_publication()
                    .unwrap()
                    .local_admission_attempted()
            );
            assert_eq!(owner.driver().unwrap().current_inbox_len(), 1);
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 1);
            assert!(owner.timer().is_some());
            reached.set(true);
            std::future::pending::<()>().await;
            drop(owner);
        }));
        // Poll exactly to the deliberate suspension, then cancel the owning
        // future itself, not a borrowed next_event future.
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(future.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(reached.get());
        drop(future);
    });
    let durable = layout.authority_images();
    assert_eq!(&durable[..2], &initial[..2]);
    assert_ne!(&durable[2..], &initial[2..]);
    let original = original.into_inner().unwrap();
    let FixedValidatorNodeStartupV0::Ready(ready) = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .open(fixture.keys[0].clone())
    .unwrap() else {
        panic!("completed proposal reopens")
    };
    executor
        .block_on(ready.run_with_signing_session_async(async |scope| {
            let mut owner = Runtime::new(
                node_driver(scope),
                isolated_network(),
                vec![],
                timeouts(Duration::from_secs(60)),
            )
            .unwrap();
            assert!(owner.timer().is_none());
            assert!(owner.pending_publication().is_none());
            assert!(owner.failed_admission().is_none());
            let driver = owner.driver().unwrap();
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.inbox_len(), 0);
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            // Inspect the returned parts before explicitly reusing those owned
            // inputs: neither pending input nor an old deadline was reconstructed.
            let parts = owner.into_parts();
            assert!(parts.pending_network_event.is_none());
            assert!(parts.pending_caller_input.is_none());
            assert!(parts.pending_arm.is_none());
            assert!(parts.rejected_due_ticket.is_none());
            owner = Runtime::new(
                parts.driver.unwrap(),
                parts.network,
                parts.peers,
                parts.timeouts,
            )
            .unwrap();
            tokio::task::yield_now().await;
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            assert!(matches!(
                owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: block,
                    canonical_artifact_bytes: payload,
                }),
                Event::ProposalAuthored
            ));
            assert!(matches!(
                owner.next_event().await,
                Event::PublicationPrepared(_)
            ));
            assert_eq!(
                owner
                    .pending_publication()
                    .unwrap()
                    .message()
                    .copy_message()
                    .unwrap(),
                original
            );
        }))
        .unwrap();
    assert_eq!(layout.authority_images(), durable);
}
