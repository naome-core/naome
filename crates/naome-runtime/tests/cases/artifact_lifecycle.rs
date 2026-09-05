use super::*;
use std::{future::Future, task::Poll};

#[test]
fn exact_due_and_successor_commands_precede_a_buffered_acquisition_terminal() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("artifact-due");
    let server_layout = TestLayout::new("artifact-due-server");
    let payload = pairing_payload();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let (mut candidates, _payloads) = sources(&layout, &fixture, None);
    let (mut serving_candidates, _serving_payloads) =
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
            let mut owner = Runtime::new(node_driver(scope), network, vec![], timeouts(Duration::from_secs(60))).unwrap();
            let mut server = Runtime::new(node_driver(server_scope), server_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
            let fill = owner.start_artifact_block_candidate_ancestry_fill(&mut candidates, peer, block.id()).unwrap().unwrap();
            let NetworkEvent::InboundBlockRequest(inbound) = request(&mut owner, &mut server, false).await else { panic!("request") };
            server.respond_block_from_candidate_store(inbound, &mut serving_candidates).unwrap();
            timeout(Duration::from_secs(10), async {
                loop {
                    let client = owner.poll_transport_once().await;
                    server.poll_transport_once().await;
                    if client == naome_runtime::FixedValidatorRuntimeTransportPollV0::BufferedEvent { break; }
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            let timer = owner.timer().unwrap();
            let images = layout.authority_images();
            let sources_before = layout.source_images();
            tokio::time::pause();
            tokio::time::advance(timer.deadline().saturating_duration_since(tokio::time::Instant::now())).await;
            assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(_) } if ticket == timer.ticket()));
            assert_eq!(layout.authority_images(), images);
            assert_eq!(layout.source_images(), sources_before);
            assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Prevote, .. }));
            assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            assert!(matches!(owner.next_event().await, Event::Admission(report) if report.source == InputSource::LocalPublication));
            assert!(matches!(owner.next_event().await, Event::PublicationComplete(_)));
            let Event::Network(event) = owner.next_event().await else { panic!("original buffered terminal") };
            assert!(fill.accepts_event(&event));
            let after_due_work = layout.authority_images();
            let timer = owner.timer();
            assert!(owner.advance_artifact_block_candidate_ancestry_fill(fill, event).unwrap().is_none());
            assert_eq!(candidates.get(block.id()).unwrap(), Some(block));
            assert_eq!(layout.authority_images(), after_due_work);
            assert_eq!(owner.timer(), timer);
        })).unwrap();
    }).unwrap();
}

#[test]
fn polled_future_drop_and_explicit_fill_cancel_preserve_runtime_and_source_custody() {
    for cancel_fill in [false, true] {
        let fixture = Fixture::new();
        let layout = TestLayout::new("artifact-cancel");
        let server_layout = TestLayout::new("artifact-cancel-server");
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
                let mut owner = Runtime::new(node_driver(scope), network, vec![], timeouts(Duration::from_secs(60))).unwrap();
                let mut server = Runtime::new(node_driver(server_scope), server_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
                let fill = owner.start_artifact_block_candidate_ancestry_fill(&mut candidates, peer, block.id()).unwrap().unwrap();
                let NetworkEvent::InboundBlockRequest(inbound) = request(&mut owner, &mut server, false).await else { panic!("request") };
                let images = layout.authority_images();
                let sources_before = layout.source_images();
                let timer = owner.timer();
                // Actually poll, then drop, while the server withholds its response.
                std::future::poll_fn(|cx| {
                    let mut pending = std::pin::pin!(owner.next_event());
                    assert!(pending.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                }).await;
                assert_eq!(owner.timer(), timer);
                assert_eq!(layout.authority_images(), images);
                assert_eq!(layout.source_images(), sources_before);
                let fill = if cancel_fill { fill.cancel(); None } else { Some(fill) };
                server.respond_block_from_candidate_store(inbound, &mut serving_candidates).unwrap();
                let event = terminal(&mut owner, &mut server, &mut serving_candidates, &mut serving_payloads, |event| matches!(event, NetworkEvent::OutboundBlock(event) if event.request().block_id() == block.id())).await;
                if let Some(fill) = fill {
                    assert!(fill.accepts_event(&event));
                    assert!(owner.advance_artifact_block_candidate_ancestry_fill(fill, event).unwrap().is_none());
                } else {
                    // Physical completion alone cannot insert into the released store.
                    drop(event);
                    assert_eq!(layout.source_images(), sources_before);
                    assert!(candidates.get(block.id()).unwrap().is_none());
                    let fill = owner.start_artifact_block_candidate_ancestry_fill(&mut candidates, peer, block.id()).unwrap().unwrap();
                    let event = terminal(&mut owner, &mut server, &mut serving_candidates, &mut serving_payloads, |event| fill.accepts_event(event)).await;
                    assert!(owner.advance_artifact_block_candidate_ancestry_fill(fill, event).unwrap().is_none());
                }
                assert_eq!(candidates.get(block.id()).unwrap(), Some(block));
                assert_eq!(owner.timer(), timer);
                assert_eq!(layout.authority_images(), images);
            })).unwrap();
        }).unwrap();
    }
}
