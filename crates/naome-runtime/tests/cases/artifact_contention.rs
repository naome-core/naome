use super::*;

#[test]
fn artifact_requests_share_publication_permits_without_retries_or_token_loss() {
    let fixture = Fixture::new();
    let [proposal, prevote] = higher_messages(&fixture);
    for acquisition_first in [false, true] {
        let layout = TestLayout::new("artifact-contention");
        let server_layout = TestLayout::new("artifact-contention-server");
        let payload = pairing_payload();
        let block = ArtifactChainState::new(fixture.definition)
            .prepare_block(artifact_id(&payload))
            .unwrap();
        let (mut candidates, _payloads) = sources(&layout, &fixture, None);
        let (mut serving_candidates, mut serving_payloads) =
            sources(&server_layout, &fixture, Some(&payload));
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
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
        let (network, server_network, peer) = executor.block_on(connected_pair());
        ready.run_with_signing_session(|scope| {
            server_ready.run_with_signing_session(|server_scope| executor.block_on(async {
                let mut owner = Runtime::new(node_driver(scope), network, vec![peer], timeouts(Duration::from_secs(60))).unwrap();
                let mut server = Runtime::new(node_driver(server_scope), server_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                for input in [&proposal, &prevote] {
                    owner.queue_input(copy_message(input)).unwrap();
                    assert!(matches!(owner.next_event().await, Event::Admission(report) if report.all_admitted()));
                }
                assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Precommit, .. }));
                assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
                let original = token_observation(owner.pending_publication().unwrap());
                let authority = layout.authority_images();
                let source_images = layout.source_images();
                let mut raw = vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES];
                raw.reserve(13);
                let raw_allocation = allocations(&raw);
                owner.queue_input(ConsensusPushMessage::Vote { canonical_vote: raw }).unwrap();
                let fill = if acquisition_first {
                    Some(owner.start_artifact_block_candidate_ancestry_fill(&mut candidates, peer, block.id()).unwrap().unwrap())
                } else { None };
                assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
                assert!(!owner.pending_publication().unwrap().local_admission_attempted());
                assert!(owner.driver().unwrap().has_pending_command());
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                assert!(matches!(owner.next_event().await, Event::Admission(report) if report.source == InputSource::LocalPublication && report.all_admitted()));
                let Event::Admission(report) = owner.next_event().await else { panic!("queued input precedes peer attempt") };
                assert_eq!(report.source, InputSource::CallerInput);
                let Some(ConsensusPushMessage::Vote { canonical_vote }) = report.input else { panic!("original raw input") };
                assert_eq!(allocations(&canonical_vote), raw_allocation);
                assert!(matches!(owner.next_event().await, Event::PeerAttempted { peer_id, started } if peer_id == peer && started != acquisition_first));
                assert_eq!(layout.authority_images(), authority);
                assert_eq!(layout.source_images(), source_images);
                let publication = if let Some(fill) = fill {
                    assert!(owner.pending_publication().unwrap().deliveries().all(|delivery| matches!(delivery.state(), Delivery::Refused(naome_network::ConsensusPushStartFailure::RequestStart(naome_network::RequestStartError::AlreadyPending(actual))) if *actual == peer)));
                    let Event::PublicationComplete(publication) = owner.next_event().await else { panic!("one-shot refusal is terminal") };
                    let event = terminal(&mut owner, &mut server, &mut serving_candidates, &mut serving_payloads, |event| fill.accepts_event(event)).await;
                    assert!(owner.advance_artifact_block_candidate_ancestry_fill(fill, event).unwrap().is_none());
                    assert_eq!(candidates.get(block.id()).unwrap(), Some(block));
                    assert!(publication.deliveries().all(|delivery| matches!(delivery.state(), Delivery::Refused(_))));
                    publication
                } else {
                    assert!(matches!(owner.start_artifact_block_candidate_ancestry_fill(&mut candidates, peer, block.id()), Err(StartError::Ancestry(error)) if matches!(*error, AncestryError::RequestStart { block_id, source: naome_network::RequestStartError::AlreadyPending(actual) } if block_id == block.id() && actual == peer)));
                    assert!(owner.pending_publication().unwrap().deliveries().all(|delivery| matches!(delivery.state(), Delivery::InFlight(_))));
                    let mut received = false;
                    let publication = timeout(Duration::from_secs(10), async {
                        loop {
                            tokio::select! {
                                event = owner.next_event() => match event {
                                    Event::PeerCompleted { received: true, .. } => received = true,
                                    Event::PublicationComplete(publication) => break publication,
                                    Event::Network(NetworkEvent::PeerSession(_)) => {},
                                    _ => panic!("unexpected publisher event"),
                                },
                                event = server.next_event() => match event {
                                    Event::TimerArmed(_) | Event::Network(NetworkEvent::PeerSession(_)) => {},
                                    Event::Admission(report) => {
                                        assert_eq!(report.source, InputSource::Peer(owner.local_peer_id()));
                                        assert_eq!(report.receipt_queued, Some(true));
                                        assert!(report.routing_error.is_some());
                                    },
                                    _ => panic!("unexpected receiver event"),
                                },
                            }
                        }
                    }).await.unwrap();
                    assert!(received);
                    assert!(publication.deliveries().all(|delivery| matches!(delivery.state(), Delivery::Received(_))));
                    assert_eq!(layout.source_images(), source_images);
                    publication
                };
                assert_eq!(token_observation(&publication), original);
                assert!(publication.local_admission_attempted());
                assert!(owner.pending_publication().is_none());
                assert_eq!(layout.authority_images(), authority);
            })).unwrap();
        }).unwrap();
    }
}
