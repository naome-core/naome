use super::*;
use naome_network::{
    FinalityProofRequest, FinalityProofResponse, FinalityProofTicket,
    INBOUND_APPLICATION_REQUEST_BURST, InboundFinalityProofRequest, NetworkEvent,
    StaticArtifactNetwork,
};
use naome_runtime::FixedValidatorRuntimeFinalityProofResponseErrorV0 as ResponseError;

async fn capture(
    peer: &mut StaticArtifactNetwork,
    owner: &mut Runtime<'_>,
    context: ConsensusContextV0,
) -> (FinalityProofTicket, InboundFinalityProofRequest) {
    let ticket = peer
        .request_finality_proof(
            owner.local_peer_id(),
            FinalityProofRequest::new(context, naome_consensus::ConsensusHeight::new(1)).unwrap(),
        )
        .unwrap();
    let inbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = owner.next_event() => match event {
                    Event::Network(NetworkEvent::InboundFinalityProof(inbound)) => break inbound,
                    event => check_local(event),
                },
                event = peer.next_event() => assert!(matches!(event, NetworkEvent::PeerSession(_))),
            }
        }
    })
    .await
    .unwrap();
    (ticket, inbound)
}

async fn complete(
    peer: &mut StaticArtifactNetwork,
    network: &mut StaticArtifactNetwork,
    ticket: FinalityProofTicket,
) -> FinalityProofResponse {
    let terminal = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = peer.next_event() => if let NetworkEvent::OutboundFinalityProof(event) = event { break event; },
                _ = network.next_event() => {},
            }
        }
    }).await.unwrap();
    ticket.complete(terminal).unwrap().unwrap().into_response()
}

async fn admit(owner: &mut Runtime<'_>, input: ConsensusPushMessage) {
    owner.queue_input(input).unwrap();
    for _ in 0..16 {
        match owner.next_event().await {
            Event::Admission(report) => {
                assert_eq!(report.source, InputSource::CallerInput);
                assert!(report.all_admitted());
                return;
            }
            event => check_local(event),
        }
    }
    panic!("caller input was not admitted")
}

#[test]
fn finality_provider_preserves_some_publication_queued_input_and_exact_expired_timer() {
    let fixture = Fixture::new();
    let first = make_proof(&fixture, &[], 1, 0);
    let second = make_proof(&fixture, &[&first], 3, 0);
    let current = make_proof(&fixture, &[&first, &second], 2, 1);
    for in_flight in [false, true] {
        let layout = TestLayout::new("finality-provider-custody");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let idle = Keypair::generate_ed25519().public().to_peer_id();
        let (mut peer, network, _) = executor.block_on(connected_pair_with_extra(Some(idle)));
        let peer_id = peer.local_peer_id();
        ready.run_with_signing_session(|scope| executor.block_on(async {
            let mut owner = Runtime::new(node_driver(selected_scope(scope, &[&first, &second])), network, vec![peer_id, idle], timeouts(Duration::from_secs(60))).unwrap();
            let (ticket, inbound) = capture(&mut peer, &mut owner, fixture.context).await;
            // Caller ingress permits preparation while the peer's proof ticket
            // owns its one outbound application slot.
            admit(&mut owner, ConsensusPushMessage::Proposal { canonical_proposal: current.proof.control.clone(), canonical_artifact: current.proof.payload.clone() }).await;
            admit(&mut owner, copy_message(&current.prevote)).await;
            assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Precommit, .. }));
            assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("publication timer") };
            if in_flight {
                check_local(owner.next_event().await);
                loop {
                    match owner.next_event().await {
                        Event::PeerAttempted { peer_id: actual, started } => { assert_eq!(actual, peer_id); assert!(started); break; },
                        Event::Network(_) => {},
                        _ => panic!("outbound publication must start"),
                    }
                }
            }
            let queued = queued_input(&mut owner);
            let token = token_observation(owner.pending_publication().unwrap());
            let driver = owner.driver().unwrap();
            let diagnostic = (driver.position(), driver.phase(), driver.inbox_len(), driver.current_inbox_len(), driver.current_finality_inbox_len(), driver.current_nil_precommit_inbox_len(), driver.has_pending_command(), driver.timeout_is_due());
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(120)).await;
            assert!(timer.deadline() < tokio::time::Instant::now());
            let before = layout.authority_images();
            owner.respond_finality_proof_from_selected_history(inbound).unwrap();
            assert_eq!(owner.timer(), Some(timer));
            let driver = owner.driver().unwrap();
            assert_eq!((driver.position(), driver.phase(), driver.inbox_len(), driver.current_inbox_len(), driver.current_finality_inbox_len(), driver.current_nil_precommit_inbox_len(), driver.has_pending_command(), driver.timeout_is_due()), diagnostic);
            let publication = owner.pending_publication().unwrap();
            assert_eq!(token_observation(publication), token);
            assert_eq!(publication.local_admission_attempted(), in_flight);
            if in_flight { assert_inflight(publication, peer_id, idle); }
            else { assert!(publication.deliveries().all(|d| matches!(d.state(), Delivery::NotAttempted))); }
            assert_eq!(layout.authority_images(), before);
            // Preserve the existing local-admission priority, then the exact
            // expired due event must still precede the queued caller input.
            if !in_flight { check_local(owner.next_event().await); }
            assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(_) } if ticket == timer.ticket()));
            let mut parts = owner.into_parts();
            assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if allocations(&canonical_vote) == queued));
            assert_eq!(token_observation(parts.publication.as_ref().unwrap()), token);
            assert_eq!(layout.authority_images(), before);
            tokio::time::resume();
            let FinalityProofResponse::Found { canonical_envelope, canonical_artifact } = complete(&mut peer, &mut parts.network, ticket).await else { panic!("retained proof") };
            assert_eq!(canonical_envelope, first.envelope);
            assert_eq!(canonical_artifact, first.proof.payload);
        })).unwrap();
    }
}

#[test]
fn finality_provider_lost_driver_refunds_request_without_rate_or_channel_consumption() {
    let fixture = Fixture::new();
    let first = make_proof(&fixture, &[], 1, 0);
    let sibling = make_proof(&fixture, &[], 2, 1);
    let layout = TestLayout::new("finality-provider-refund");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut peer, network, _) = executor.block_on(connected_pair());
    ready.run_with_signing_session(|scope| executor.block_on(async {
        let mut owner = Runtime::new(node_driver(selected_scope(scope, &[&first])), network, vec![], timeouts(Duration::from_secs(60))).unwrap();
        let (ticket, mut inbound) = capture(&mut peer, &mut owner, fixture.context).await;
        let address = (inbound.peer_id(), inbound.request());
        assert!(matches!(submit(&mut owner, &sibling, false), Event::Fatal(error) if matches!(*error, Failure::FinalityStopped(_))));
        assert!(owner.driver().is_none());
        let timer = owner.timer();
        let before = layout.authority_images();
        tokio::time::pause();
        for _ in 0..=INBOUND_APPLICATION_REQUEST_BURST {
            let ResponseError::DriverUnavailable(refunded) = owner.respond_finality_proof_from_selected_history(inbound).unwrap_err() else { panic!("driver refusal before network/history access") };
            inbound = refunded;
            assert_eq!((inbound.peer_id(), inbound.request()), address);
        }
        assert_eq!(owner.timer(), timer);
        assert_eq!(layout.authority_images(), before);
        let mut parts = owner.into_parts();
        assert!(parts.driver.is_none());
        // The caller now owns the raw transport. An opaque unavailable reply
        // proves the refunded channel and rate capacity survived; it reads no
        // halted history and does not re-enable the runtime's provider.
        parts.network.respond_finality_proof(inbound, None).unwrap();
        tokio::time::resume();
        assert!(matches!(complete(&mut peer, &mut parts.network, ticket).await, FinalityProofResponse::Unavailable));
        assert_eq!(layout.authority_images(), before);
    })).unwrap();
}
