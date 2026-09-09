use super::*;
use naome_network::{Keypair, NetworkEvent, PeerSessionEvent, StaticArtifactNetwork, StaticPeer};
use naome_runtime::FixedValidatorPublicationRetryIntervalV0 as Interval;
use std::collections::{BTreeMap, BTreeSet};

async fn poll_once<'node>(owner: &mut Runtime<'node>) -> Option<Event<'node>> {
    use std::{future::Future, task::Poll};
    std::future::poll_fn(|cx| {
        let mut future = std::pin::pin!(owner.next_event());
        Poll::Ready(match future.as_mut().poll(cx) {
            Poll::Ready(event) => Some(event),
            Poll::Pending => None,
        })
    })
    .await
}

#[test]
fn periodic_retry_receipt_failure_consumes_authority_and_reopens_unacknowledged_original() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("periodic-receipt-failure");
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (network, mut peer, peer_id) = executor.block_on(connected_pair());
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let (id, message, snapshot, backup) = ready.run_with_signing_session(|scope| executor.block_on(async {
        let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id], timeouts(Duration::from_secs(60))).unwrap()
            .with_publication_journal(&layout.candidate_store, true).unwrap()
            .with_publication_retry_interval(Interval::new(Duration::from_millis(100)).unwrap()).unwrap();
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        let payload = pairing_payload();
        let block = ArtifactChainState::new(fixture.definition).prepare_block(artifact_id(&payload)).unwrap();
        assert!(matches!(owner.author_proposal(FixedValidatorProposalSourceV0::Fresh { artifact_block: block, canonical_artifact_bytes: payload }), Event::ProposalAuthored));
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = owner.next_event() => match event {
                        Event::PublicationRecovered { .. } => break,
                        Event::PeerAttempted { .. } | Event::PeerCompleted { received: false, .. }
                        | Event::PublicationComplete(_) | Event::PublicationRetryScheduled { .. }
                        | Event::Finality(_) => {},
                        event => check_local(event),
                    },
                    event = peer.next_event() => if let NetworkEvent::InboundConsensusPush(inbound) = event {
                        drop(inbound);
                    },
                }
            }
        }).await.unwrap();
        let publication = owner.pending_publication().unwrap();
        let id = publication.message().state_id();
        let message = publication.message().copy_message().unwrap();
        assert!(publication.local_admission_skipped());
        assert!(matches!(owner.next_event().await, Event::PeerAttempted { started: true, .. }));
        let authority = layout.authority_images();
        let snapshot = std::fs::read_dir(&layout.candidate_store).unwrap().map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|extension| extension == "deliveries")).unwrap();
        let backup = snapshot.with_extension("backup");
        std::fs::rename(&snapshot, &backup).unwrap();
        std::fs::create_dir(&snapshot).unwrap();
        let mut actually_received = false;
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = owner.next_event() => match event {
                        Event::Fatal(error) => {
                            assert!(matches!(*error, naome_runtime::FixedValidatorRuntimeFailureV0::Publication(_)));
                            break;
                        }
                        Event::Network(_) => {},
                        _ => panic!("ambiguous periodic receipt cannot report successful completion"),
                    },
                    event = peer.next_event() => if let NetworkEvent::InboundConsensusPush(inbound) = event {
                        assert_eq!(inbound.message(), &message);
                        let _ = peer.acknowledge_consensus_push(inbound).unwrap();
                        actually_received = true;
                    },
                }
            }
        }).await.unwrap();
        assert!(actually_received);
        assert!(owner.driver().is_none());
        assert_eq!(layout.authority_images(), authority);
        assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
        (id, message, snapshot, backup)
    })).unwrap();
    drop(peer);
    // Remove only the injected obstruction and put back the last complete
    // synchronized snapshot. No failed receipt is invented or acknowledged.
    std::fs::remove_dir(&snapshot).unwrap();
    std::fs::rename(&backup, &snapshot).unwrap();
    let before = layout.authority_images();
    let FixedValidatorNodeStartupV0::Ready(ready) = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .open(fixture.keys[0].clone())
    .unwrap() else {
        panic!("strict ready")
    };
    ready.run_with_signing_session(|scope| executor.block_on(async {
        let network = StaticArtifactNetwork::new(Keypair::generate_ed25519(), [StaticPeer::new(peer_id, "/ip4/127.0.0.1/tcp/1".parse().unwrap())]).unwrap();
        let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id], timeouts(Duration::from_secs(60))).unwrap()
            .with_publication_journal(&layout.candidate_store, false).unwrap()
            .with_publication_retry_interval(Interval::new(Duration::from_secs(1)).unwrap()).unwrap();
        assert!(matches!(owner.next_event().await, Event::PublicationRecovered { state_id, .. } if state_id == id));
        let recovered = owner.pending_publication().unwrap();
        assert_eq!(recovered.message().copy_message().unwrap(), message);
        assert!(recovered.deliveries().all(|delivery| matches!(delivery.state(), Delivery::NotAttempted)));
        assert_eq!(layout.authority_images(), before);
    })).unwrap();
}

#[test]
fn periodic_retry_delivers_original_proposal_and_both_votes_without_reconnection_or_resigning() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("periodic-publication");
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (network, mut peer, peer_id) = executor.block_on(connected_pair());
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    ready.run_with_signing_session(|scope| executor.block_on(async {
        let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id], timeouts(Duration::from_secs(60))).unwrap()
            .with_publication_journal(&layout.candidate_store, true).unwrap()
            .with_publication_retry_interval(Interval::new(Duration::from_millis(100)).unwrap()).unwrap();
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        let payload = pairing_payload();
        let block = ArtifactChainState::new(fixture.definition).prepare_block(artifact_id(&payload)).unwrap();
        assert!(matches!(owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
            artifact_block: block, canonical_artifact_bytes: payload,
        }), Event::ProposalAuthored));
        let mut originals = BTreeMap::new();
        let mut first_deliveries = BTreeSet::new();
        let mut recovered = BTreeSet::new();
        let mut received = BTreeSet::new();
        let mut retry_images = None;
        let mut finalized = false;
        let mut failures = 0;
        let mut passes = 0;
        timeout(Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    event = owner.next_event() => match event {
                        Event::PublicationPrepared(_) => {
                            let publication = owner.pending_publication().unwrap();
                            assert!(!publication.recovered());
                            assert!(originals.insert(publication.message().state_id(), publication.message().copy_message().unwrap()).is_none());
                        }
                        Event::PublicationRecovered { state_id, .. } => {
                            let publication = owner.pending_publication().unwrap();
                            assert!(publication.recovered());
                            assert!(publication.local_admission_skipped());
                            assert!(!publication.local_admission_attempted());
                            assert_eq!(&publication.message().copy_message().unwrap(), originals.get(&state_id).unwrap());
                            assert!(recovered.insert(state_id), "a receipt must suppress subsequent retries");
                            retry_images = Some(layout.authority_images());
                        }
                        Event::PublicationComplete(publication) => {
                            let id = publication.message().state_id();
                            if publication.recovered() {
                                assert_eq!(layout.authority_images(), retry_images.take().unwrap(), "periodic delivery must not sign, re-admit locally, or advance either anchor");
                                assert!(publication.deliveries().all(|delivery| matches!(delivery.state(), Delivery::Received(_))));
                                received.insert(id);
                            } else {
                                assert!(publication.deliveries().all(|delivery| matches!(delivery.state(), Delivery::Failed(_))));
                            }
                        }
                        Event::PeerCompleted { received, .. } => {
                            if !received { failures += 1; }
                        }
                        Event::PeerAttempted { started, .. } => assert!(started),
                        Event::PublicationRetryScheduled { queued } => {
                            assert!(queued <= 3);
                            passes += 1;
                            if queued == 0 && received.len() == 3 && finalized { break; }
                        }
                        Event::Finality(_) => finalized = true,
                        Event::Admission(report) => {
                            assert!(retry_images.is_none(), "periodic publication must skip local admission");
                            assert_eq!(report.source, InputSource::LocalPublication);
                            assert!(report.all_admitted());
                        }
                        Event::Network(NetworkEvent::PeerSession(_)) => panic!("the original authenticated session must remain established"),
                        Event::Network(_) | Event::TimerArmed(_) | Event::Transitioned { .. } => {},
                        Event::Fatal(error) => panic!("fatal: {error}"),
                        _ => panic!("unexpected periodic runtime event"),
                    },
                    event = peer.next_event() => match event {
                        NetworkEvent::InboundConsensusPush(inbound) => {
                            let (&id, _) = originals.iter().find(|(_, message)| *message == inbound.message()).expect("only exact original messages may arrive");
                            if first_deliveries.insert(id) {
                                // Refuse this stream's receipt without closing the Noise session.
                                drop(inbound);
                            } else {
                                assert!(!received.contains(&id));
                                let _ = peer.acknowledge_consensus_push(inbound).unwrap();
                            }
                        }
                        NetworkEvent::PeerSession(PeerSessionEvent::Established { .. } | PeerSessionEvent::Disconnected { .. }) => panic!("periodic recovery must not rely on reconnection"),
                        _ => {},
                    },
                }
            }
        }).await.unwrap();
        assert_eq!(originals.len(), 3);
        assert_eq!(failures, 3);
        assert_eq!(first_deliveries.len(), 3);
        assert_eq!(received.len(), 3);
        assert!(passes >= 2);
        assert_eq!(owner.driver().unwrap().position().height().value(), 2);
    })).unwrap();
    drop(peer);

    let before = layout.authority_images();
    let FixedValidatorNodeStartupV0::Ready(ready) = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .open(fixture.keys[0].clone())
    .unwrap() else {
        panic!("strict ready")
    };
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                tokio::time::pause();
                let network = StaticArtifactNetwork::new(
                    Keypair::generate_ed25519(),
                    [StaticPeer::new(
                        peer_id,
                        "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                    )],
                )
                .unwrap();
                let mut owner = Runtime::new(
                    node_driver(scope),
                    network,
                    vec![peer_id],
                    timeouts(Duration::from_secs(600)),
                )
                .unwrap()
                .with_publication_journal(&layout.candidate_store, false)
                .unwrap()
                .with_publication_retry_interval(Interval::new(Duration::from_secs(1)).unwrap())
                .unwrap();
                assert_eq!(
                    owner.publication_recovery_remaining(),
                    0,
                    "strict reopen retains all acknowledgements"
                );
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                tokio::time::advance(Duration::from_secs(100)).await;
                let mut scheduled = false;
                for _ in 0..20 {
                    match owner.next_event().await {
                        Event::PublicationRetryScheduled { queued: 0 } => {
                            scheduled = true;
                            break;
                        }
                        Event::Network(_) => {}
                        _ => panic!("acknowledged history must not be republished"),
                    }
                }
                assert!(
                    scheduled,
                    "reopen must observe one coalesced retry expiration"
                );
                assert_eq!(layout.authority_images(), before);
                assert!(owner.pending_publication().is_none());
                // One coalesced expiration starts a fresh interval, never 100 missed ticks.
                for _ in 0..20 {
                    match poll_once(&mut owner).await {
                        None => return,
                        Some(Event::Network(_)) => {}
                        _ => panic!("missed timer ticks must not burst"),
                    }
                }
                panic!("bounded network events should quiesce");
            })
        })
        .unwrap();
}

#[test]
fn periodic_timer_cancellation_empty_passes_and_consensus_deadline_priority() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("periodic-timer-priority");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                tokio::time::pause();
                let mut owner = Runtime::new(
                    node_driver(scope),
                    StaticArtifactNetwork::new(Keypair::generate_ed25519(), []).unwrap(),
                    vec![],
                    timeouts(Duration::from_secs(1)),
                )
                .unwrap()
                .with_publication_journal(&layout.candidate_store, true)
                .unwrap()
                .with_publication_retry_interval(Interval::new(Duration::from_secs(1)).unwrap())
                .unwrap();
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                let before = layout.authority_images();
                for _ in 0..3 {
                    assert!(poll_once(&mut owner).await.is_none());
                }
                tokio::time::advance(Duration::from_secs(1)).await;
                assert!(
                    matches!(
                        owner.next_event().await,
                        Event::TimerDue { result: Ok(_), .. }
                    ),
                    "the exact consensus deadline wins the retry tie"
                );
                assert_eq!(
                    layout.authority_images(),
                    before,
                    "timer observation itself grants no signing authority"
                );
                let mut publications = 0;
                let mut transitions = 0;
                let mut retry_seen = false;
                for _ in 0..40 {
                    match owner.next_event().await {
                        Event::PublicationPrepared(_) => publications += 1,
                        Event::Transitioned { .. } => transitions += 1,
                        Event::PublicationRetryScheduled { queued: 0 } => {
                            retry_seen = true;
                            break;
                        }
                        event => check_local(event),
                    }
                }
                assert!(retry_seen);
                assert!(
                    publications > 0 && transitions > 0,
                    "ordinary consensus work runs before a new pass"
                );
                assert!(poll_once(&mut owner).await.is_none());
            })
        })
        .unwrap();
}

#[test]
fn continuously_due_periodic_ticks_still_poll_and_admit_authenticated_network_input() {
    use std::{future::Future, task::Poll};
    let fixture = Fixture::new();
    let layout = TestLayout::new("periodic-network-opportunity");
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (network, mut peer, peer_id) = executor.block_on(connected_pair());
    let local_id = network.local_peer_id();
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                tokio::time::pause();
                let mut owner = Runtime::new(
                    node_driver(scope),
                    network,
                    vec![peer_id],
                    timeouts(Duration::from_secs(600)),
                )
                .unwrap()
                .with_publication_journal(&layout.candidate_store, true)
                .unwrap()
                .with_publication_retry_interval(Interval::new(Duration::from_nanos(1)).unwrap())
                .unwrap();
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                let before = layout.authority_images();
                let input = ConsensusPushMessage::Vote {
                    canonical_vote: vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES],
                };
                let _ticket = peer.push_consensus(local_id, input).unwrap();
                let mut ticks = 0;
                for _ in 0..1000 {
                    // Every owner poll begins with its retry interval overdue. The
                    // network must still make progress; consensus time remains far away.
                    tokio::time::advance(Duration::from_millis(1)).await;
                    match owner.next_event().await {
                        Event::PublicationRetryScheduled { queued: 0 } => ticks += 1,
                        Event::Admission(report) => {
                            assert_eq!(report.source, InputSource::Peer(peer_id));
                            assert!(
                                !report.all_admitted(),
                                "transport input still requires strict verification"
                            );
                            assert!(ticks > 0);
                            assert_eq!(layout.authority_images(), before);
                            return;
                        }
                        Event::Network(_) => {}
                        _ => panic!("no signing or publication debt exists"),
                    }
                    std::future::poll_fn(|cx| {
                        let mut future = std::pin::pin!(peer.next_event());
                        let _ = future.as_mut().poll(cx);
                        Poll::Ready(())
                    })
                    .await;
                }
                panic!("periodic ticks starved actual authenticated input");
            })
        })
        .unwrap();
}

#[test]
fn live_retry_gaps_admit_input_observe_due_and_transfer_new_vote_before_remaining_debt() {
    for due in [false, true] {
        let fixture = Fixture::new();
        let layout = TestLayout::new("live-retry-gap");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[0].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        ready.run_with_signing_session(|scope| executor.block_on(async {
            tokio::time::pause();
            let peer_id = Keypair::generate_ed25519().public().to_peer_id();
            let network = StaticArtifactNetwork::new(Keypair::generate_ed25519(), [
                StaticPeer::new(peer_id, "/ip4/127.0.0.1/tcp/1".parse().unwrap()),
            ]).unwrap();
            let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id], timeouts(Duration::from_secs(60))).unwrap()
                .with_publication_journal(&layout.candidate_store, true).unwrap()
                .with_publication_retry_interval(Interval::new(Duration::from_secs(1)).unwrap()).unwrap();
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            let payload = pairing_payload();
            let block = ArtifactChainState::new(fixture.definition).prepare_block(artifact_id(&payload)).unwrap();
            assert!(matches!(owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                artifact_block: block, canonical_artifact_bytes: payload,
            }), Event::ProposalAuthored));
            let mut originals = Vec::new();
            for _ in 0..40 {
                match owner.next_event().await {
                    Event::PublicationComplete(publication) => {
                        assert!(!publication.recovered());
                        assert!(publication.deliveries().all(|delivery| matches!(delivery.state(), Delivery::Refused(_))));
                        originals.push((publication.message().state_id(), publication.message().copy_message().unwrap()));
                    }
                    Event::PeerAttempted { started: false, .. } => {},
                    Event::Finality(_) => break,
                    event => check_local(event),
                }
            }
            assert_eq!(originals.len(), 3);
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            assert!(poll_once(&mut owner).await.is_none());
            tokio::time::advance(Duration::from_secs(1)).await;
            let mut scheduled = false;
            for _ in 0..10 {
                match owner.next_event().await {
                    Event::PublicationRetryScheduled { queued: 3 } => { scheduled = true; break; }
                    Event::Network(_) => {},
                    _ => panic!("expected one finite three-message pass"),
                }
            }
            assert!(scheduled);
            let before = layout.authority_images();
            assert!(matches!(owner.next_event().await, Event::PublicationRecovered { state_id, .. } if state_id == originals[0].0));
            assert!(matches!(owner.next_event().await, Event::PeerAttempted { started: false, .. }));
            assert!(matches!(owner.next_event().await, Event::PublicationComplete(_)));
            assert_eq!(owner.publication_recovery_remaining(), 2);
            let raw = ConsensusPushMessage::Vote { canonical_vote: vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES] };
            owner.queue_input(raw).unwrap();
            if due {
                tokio::time::advance(Duration::from_secs(60)).await;
                assert!(matches!(owner.next_event().await, Event::TimerDue { result: Ok(_), .. }), "exact due observation must precede the second historical message and retain input");
            } else {
                let Event::Admission(report) = owner.next_event().await else { panic!("queued input must precede the second historical message") };
                assert_eq!(report.source, InputSource::CallerInput);
                assert!(!report.all_admitted());
                assert!(report.input.is_some());
            }
            assert_eq!(layout.authority_images(), before, "gap input and timer observation alone must not sign");
            assert!(matches!(owner.next_event().await, Event::PublicationRecovered { state_id, .. } if state_id == originals[1].0));
            // A buffered input may be handled while the publication waits, but
            // its exact original bytes and sole publication custody stay intact.
            assert_eq!(owner.pending_publication().unwrap().message().copy_message().unwrap(), originals[1].1);
            for _ in 0..10 {
                match owner.next_event().await {
                    Event::PublicationComplete(_) => break,
                    Event::Admission(report) => assert_eq!(report.source, InputSource::CallerInput),
                    Event::PeerAttempted { started: false, .. } => {},
                    _ => panic!("historical publication must finish without a new driver step"),
                }
            }
            assert_eq!(owner.publication_recovery_remaining(), 1);
            if due {
                assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Prevote, .. }));
                assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)), "new vote command must transfer before the third historical message");
                assert!(!owner.pending_publication().unwrap().recovered());
                for _ in 0..10 {
                    match owner.next_event().await {
                        Event::PublicationComplete(_) => break,
                        Event::PeerAttempted { started: false, .. } => {},
                        event => check_local(event),
                    }
                }
            }
            // An idle ordinary opportunity must not wait for input or a timer.
            assert!(matches!(poll_once(&mut owner).await, Some(Event::PublicationRecovered { state_id, .. }) if state_id == originals[2].0));
            assert_eq!(owner.pending_publication().unwrap().message().copy_message().unwrap(), originals[2].1);
            assert!(matches!(owner.next_event().await, Event::PeerAttempted { started: false, .. }));
            assert!(matches!(owner.next_event().await, Event::PublicationComplete(_)));
            assert_eq!(owner.publication_recovery_remaining(), 0);
        })).unwrap();
    }
}
