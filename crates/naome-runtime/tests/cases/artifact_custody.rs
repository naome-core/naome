use super::*;

#[path = "artifact_lifecycle.rs"]
mod lifecycle;

#[test]
fn explicit_acknowledgement_preserves_original_bytes_without_admission() {
    for close_channel in [false, true] {
        let fixture = Fixture::new();
        let layout = TestLayout::new("runtime-explicit-receipt");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let (mut sender, mut network, peer) = executor.block_on(connected_pair());
        let _entered = executor.enter();
        let sender_peer = sender.local_peer_id();
        let message = ConsensusPushMessage::Vote {
            canonical_vote: vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES],
        };
        let ticket = sender.push_consensus(peer, copy_message(&message)).unwrap();
        let inbound = executor
            .block_on(timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        event = network.next_event() => match event {
                            NetworkEvent::InboundConsensusPush(inbound) => break inbound,
                            NetworkEvent::PeerSession(_) => {},
                            _ => panic!("unexpected receiver event"),
                        },
                        event = sender.next_event() => {
                            assert!(matches!(event, NetworkEvent::PeerSession(_)));
                        },
                    }
                }
            }))
            .unwrap();
        let ConsensusPushMessage::Vote { canonical_vote } = inbound.message() else {
            panic!("vote")
        };
        let original = allocations(canonical_vote);
        let mut sender = Some(sender);
        if close_channel {
            drop(sender.take());
            executor
                .block_on(timeout(Duration::from_secs(10), async {
                    loop {
                        match network.next_event().await {
                            NetworkEvent::InboundConsensusPushFailure { peer_id, .. } => {
                                assert_eq!(peer_id, sender_peer);
                                break;
                            }
                            NetworkEvent::PeerSession(_) => {}
                            _ => panic!("unexpected channel-close event"),
                        }
                    }
                }))
                .unwrap();
        }
        ready.run_with_signing_session(|scope| executor.block_on(async {
            let mut owner = Runtime::new(node_driver(scope), network, vec![], timeouts(Duration::from_secs(60))).unwrap();
            let images = layout.authority_images();
            let result = owner.acknowledge_consensus_push(inbound);
            let received = if close_channel { result.unwrap_err().into_received() } else { result.unwrap() };
            assert_eq!(received.peer_id(), sender_peer);
            assert_eq!(received.message(), &message);
            let ConsensusPushMessage::Vote { canonical_vote } = received.message() else { panic!("received vote") };
            assert_eq!(allocations(canonical_vote), original);
            assert!(owner.driver().unwrap().has_pending_command());
            assert!(owner.timer().is_none());
            assert!(owner.pending_publication().is_none());
            assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
            assert_eq!(layout.authority_images(), images);
            if let Some(mut sender) = sender {
                let receipt = timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            event = sender.next_event() => match event {
                                NetworkEvent::OutboundConsensusPush(event) if ticket.accepts_event(&event) => break event,
                                NetworkEvent::PeerSession(_) => {},
                                _ => panic!("unexpected sender terminal"),
                            },
                            _ = async { owner.poll_transport_once().await; tokio::task::yield_now().await; } => {},
                        }
                    }
                }).await.unwrap();
                assert!(ticket.complete(receipt).unwrap().is_ok());
            }
            let (_, input) = received.into_parts();
            owner.queue_input(input).unwrap();
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            let Event::Admission(report) = owner.next_event().await else { panic!("explicit resubmission") };
            assert_eq!(report.source, InputSource::CallerInput);
            assert_eq!(report.receipt_queued, None);
            assert!(report.routing_error.is_some());
            let Some(ConsensusPushMessage::Vote { canonical_vote }) = report.input else { panic!("original input") };
            assert_eq!(allocations(&canonical_vote), original);
            assert_eq!(layout.authority_images(), images);
        })).unwrap();
    }
}

async fn request(
    client: &mut Runtime<'_>,
    server: &mut Runtime<'_>,
    payload: bool,
) -> NetworkEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = server.next_event() => match event {
                    Event::Network(event @ NetworkEvent::InboundBlockRequest(_)) if !payload => return event,
                    Event::Network(event @ NetworkEvent::InboundArtifactRequest(_)) if payload => return event,
                    Event::Network(NetworkEvent::PeerSession(_)) | Event::TimerArmed(_) => {},
                    _ => panic!("unexpected server event before explicit response"),
                },
                event = client.next_event() => match event {
                    Event::Network(NetworkEvent::PeerSession(_)) | Event::TimerArmed(_) => {},
                    _ => panic!("unexpected client event before explicit response"),
                },
            }
        }
    }).await.expect("inbound artifact request")
}

#[test]
fn wrong_event_and_foreign_runtime_refund_exact_work_and_usable_response_handles() {
    let fixture = Fixture::new();
    let client_layout = TestLayout::new("artifact-refund");
    let server_layout = TestLayout::new("artifact-refund-server");
    let payload = pairing_payload();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let (mut candidates, mut payloads) = sources(&client_layout, &fixture, None);
    let (mut serving_candidates, mut serving_payloads) =
        sources(&server_layout, &fixture, Some(&payload));
    let client_ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &client_layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let server_ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &server_layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (client_network, server_network, peer) = executor.block_on(connected_pair());
    client_ready.run_with_signing_session(|client_scope| {
        server_ready.run_with_signing_session(|server_scope| executor.block_on(async {
            let mut client = Runtime::new(node_driver(client_scope), client_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
            let mut server = Runtime::new(node_driver(server_scope), server_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
            let authority = [client_layout.authority_images(), server_layout.authority_images()];
            let fill = client.start_artifact_block_candidate_ancestry_fill(&mut candidates, peer, block.id()).unwrap().unwrap();
            let inbound = request(&mut client, &mut server, false).await;
            let images = client_layout.source_images();
            let AncestryAdvanceError::Refused { reason, progress: fill, event: inbound } = *client.advance_artifact_block_candidate_ancestry_fill(fill, inbound).unwrap_err() else { panic!("wrong event refund") };
            assert_eq!(reason, AcquisitionRefusal::UnexpectedEvent);
            assert_eq!(fill.pending_block_id(), block.id());
            assert_eq!(client_layout.source_images(), images);
            let NetworkEvent::InboundBlockRequest(inbound) = inbound else { panic!("original response channel") };
            assert_eq!(inbound.request().block_id(), block.id());
            server.respond_block_from_candidate_store(inbound, &mut serving_candidates).unwrap();
            let event = terminal(&mut client, &mut server, &mut serving_candidates, &mut serving_payloads, |event| fill.accepts_event(event)).await;
            let AncestryAdvanceError::Refused { reason, progress: fill, event } = *server.advance_artifact_block_candidate_ancestry_fill(fill, event).unwrap_err() else { panic!("foreign network refund") };
            assert_eq!(reason, AcquisitionRefusal::OtherNetwork);
            assert!(fill.accepts_event(&event));
            assert_eq!(client_layout.source_images(), images);
            assert!(client.advance_artifact_block_candidate_ancestry_fill(fill, event).unwrap().is_none());
            let PayloadProgress::AwaitingResponse(fill) = client.start_artifact_block_candidate_branch_payload_fill(&mut candidates, &mut payloads, peer, block.id(), limits()).unwrap() else { panic!("missing payload") };
            let inbound = request(&mut client, &mut server, true).await;
            let images = client_layout.source_images();
            let PayloadAdvanceError::Refused { reason, progress: fill, event: inbound } = *client.advance_artifact_block_candidate_branch_payload_fill(fill, inbound).unwrap_err() else { panic!("wrong payload event refund") };
            assert_eq!(reason, AcquisitionRefusal::UnexpectedEvent);
            assert_eq!(fill.pending_artifact_id(), block.artifact_id());
            assert_eq!(client_layout.source_images(), images);
            let NetworkEvent::InboundArtifactRequest(inbound) = inbound else { panic!("original payload response channel") };
            assert_eq!(inbound.request().artifact_id(), block.artifact_id());
            server.respond_artifact_from_payload_store(inbound, &mut serving_payloads).unwrap();
            let event = terminal(&mut client, &mut server, &mut serving_candidates, &mut serving_payloads, |event| fill.accepts_event(event)).await;
            let PayloadAdvanceError::Refused { reason, progress: fill, event } = *server.advance_artifact_block_candidate_branch_payload_fill(fill, event).unwrap_err() else { panic!("foreign payload network refund") };
            assert_eq!(reason, AcquisitionRefusal::OtherNetwork);
            assert!(fill.accepts_event(&event));
            assert_eq!(client_layout.source_images(), images);
            assert!(matches!(client.advance_artifact_block_candidate_branch_payload_fill(fill, event).unwrap(), PayloadProgress::Complete(branch) if branch.target_block_id() == block.id()));
            assert_eq!([client_layout.authority_images(), server_layout.authority_images()], authority);
        })).unwrap();
    }).unwrap();
}
