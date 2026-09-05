use super::*;
use naome_network::{
    ArtifactBlockCandidateAncestryFillError as AncestryError,
    ArtifactBlockCandidateBranchPayloadFillProgress as PayloadProgress, NetworkEvent,
};
use naome_runtime::{
    FixedValidatorRuntimeAcquisitionRefusalV0 as AcquisitionRefusal,
    FixedValidatorRuntimeAcquisitionStartErrorV0 as StartError,
    FixedValidatorRuntimeAncestryFillAdvanceErrorV0 as AncestryAdvanceError,
    FixedValidatorRuntimePayloadFillAdvanceErrorV0 as PayloadAdvanceError,
};
use naome_storage::{
    ArtifactBlockCandidateStore, CandidateBranchReconstructionLimits, CanonicalArtifactPayloadStore,
};

#[path = "artifact_interleaving.rs"]
mod interleaving;

#[path = "artifact_custody.rs"]
mod custody;

#[path = "artifact_unavailable.rs"]
mod unavailable;

#[path = "artifact_contention.rs"]
mod contention;

fn sibling_proof(fixture: &Fixture) -> Proof {
    let payload = naome_proof::ArtifactPayload::Proof(
        naome_proof::ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, 2]).unwrap(),
    )
    .to_canonical_bytes();
    let [proposal, _, vote] = source_messages_for_payload(fixture, payload);
    proof(fixture, proposal, vote, ConsensusVoteRole::Precommit)
}

fn sources(
    layout: &TestLayout,
    fixture: &Fixture,
    payload: Option<&[u8]>,
) -> (ArtifactBlockCandidateStore, CanonicalArtifactPayloadStore) {
    let (mut candidates, mut payloads) = super::super::store_authoring::sources(layout, fixture);
    if let Some(payload) = payload {
        let selected = ArtifactChainState::new(fixture.definition);
        let block = selected.prepare_block(artifact_id(payload)).unwrap();
        let _ = candidates.insert(&block).unwrap();
        let _ = payloads
            .validate_and_insert_branch_payload(
                &selected.branch_snapshot(),
                &block,
                payload.to_vec(),
            )
            .unwrap();
    }
    (candidates, payloads)
}

fn limits() -> CandidateBranchReconstructionLimits {
    CandidateBranchReconstructionLimits::new(8).unwrap()
}

// Caller routing is explicit on both intact runtime owners. Only incidental
// peer-session events are ignored; unexpected request or response data fails.
async fn terminal(
    client: &mut Runtime<'_>,
    server: &mut Runtime<'_>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    accepts: impl Fn(&NetworkEvent) -> bool,
) -> NetworkEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => match event {
                    Event::Network(event) if accepts(&event) => return event,
                    Event::Network(NetworkEvent::PeerSession(_)) => {},
                    Event::TimerArmed(_) => {},
                    _ => panic!("unexpected client event during explicit artifact exchange"),
                },
                event = server.next_event() => match event {
                    Event::Network(NetworkEvent::InboundBlockRequest(inbound)) => {
                        server.respond_block_from_candidate_store(inbound, candidates).unwrap();
                    }
                    Event::Network(NetworkEvent::InboundArtifactRequest(inbound)) => {
                        server.respond_artifact_from_payload_store(inbound, payloads).unwrap();
                    }
                    Event::Network(NetworkEvent::PeerSession(_)) => {},
                    Event::TimerArmed(_) => {},
                    _ => panic!("unexpected server event during explicit artifact exchange"),
                },
            }
        }
    })
    .await
    .expect("explicit artifact response")
}

#[test]
fn two_runtimes_acquire_serve_author_finalize_and_strictly_reopen() {
    for fallback in [false, true] {
        let fixture = Fixture::new();
        let client_layout = TestLayout::new("artifact-client");
        let server_layout = TestLayout::new("artifact-server");
        let payload = pairing_payload();
        let block = ArtifactChainState::new(fixture.definition)
            .prepare_block(artifact_id(&payload))
            .unwrap();
        let (mut client_candidates, mut client_payloads) = sources(&client_layout, &fixture, None);
        let (mut server_candidates, mut server_payloads) =
            sources(&server_layout, &fixture, Some(&payload));
        let client_ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &client_layout,
        )
        .create(fixture.keys[0].clone())
        .unwrap();
        let server_ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &server_layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let (client_network, server_network, peer) = executor.block_on(connected_pair());
        client_ready.run_with_signing_session(|client_scope| {
            server_ready.run_with_signing_session(|server_scope| executor.block_on(async {
                let mut client = Runtime::new(node_driver(client_scope), client_network, vec![peer], timeouts(Duration::from_secs(60))).unwrap();
                let mut server = Runtime::new(node_driver(server_scope), server_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
                let authority = [client_layout.authority_images(), server_layout.authority_images()];
                let server_sources = server_layout.source_images();
                let empty = client_layout.source_images();
                // Acquisition itself neither transfers the command nor arms its timer.
                let fill = if fallback {
                    client.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(&mut client_candidates, &[peer], block.id())
                } else {
                    client.start_artifact_block_candidate_ancestry_fill(&mut client_candidates, peer, block.id())
                }.unwrap().unwrap();
                assert!(client.driver().unwrap().has_pending_command());
                assert!(client.timer().is_none());
                assert_eq!(client_layout.source_images(), empty);
                let event = terminal(&mut client, &mut server, &mut server_candidates, &mut server_payloads, |event| fill.accepts_event(event)).await;
                let timer = client.timer().unwrap();
                assert!(client.advance_artifact_block_candidate_ancestry_fill(fill, event).unwrap().is_none());
                assert_eq!(client_candidates.get(block.id()).unwrap(), Some(block));
                assert_eq!(client_layout.source_images()[1], empty[1]);
                let progress = if fallback {
                    client.start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(&mut client_candidates, &mut client_payloads, &[peer], block.id(), limits())
                } else {
                    client.start_artifact_block_candidate_branch_payload_fill(&mut client_candidates, &mut client_payloads, peer, block.id(), limits())
                }.unwrap();
                let PayloadProgress::AwaitingResponse(fill) = progress else { panic!("missing payload") };
                let event = terminal(&mut client, &mut server, &mut server_candidates, &mut server_payloads, |event| fill.accepts_event(event)).await;
                let PayloadProgress::Complete(branch) = client.advance_artifact_block_candidate_branch_payload_fill(fill, event).unwrap() else { panic!("complete payload") };
                assert_eq!(branch.target_block_id(), block.id());
                assert_eq!(branch.snapshot().head_block_id(), block.id());
                assert_eq!(branch.snapshot().artifact_set_root(), block.resulting_artifact_set_root());
                assert_eq!(client.timer(), Some(timer));
                assert_eq!([client_layout.authority_images(), server_layout.authority_images()], authority);
                assert_eq!(server_layout.source_images(), server_sources);
                assert_eq!(client_payloads.get(block.artifact_id()).unwrap().unwrap().canonical_artifact_bytes(), payload);
                let acquired = client_layout.source_images();
                // Successful acquisition grants no admission or authoring token.
                assert_eq!(client.driver().unwrap().current_inbox_len(), 0);
                assert_eq!(client.driver().unwrap().current_finality_inbox_len(), 0);
                assert!(matches!(client.author_candidate_backed_fresh_proposal(&mut client_candidates, &mut client_payloads, block.id()), Event::ProposalAuthored));
                assert!(matches!(client.next_event().await, Event::PublicationPrepared(_)));
                let _ = exchange(&mut client, &mut server).await;
                for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
                    prepare_vote(&mut client, role).await;
                    let _ = exchange(&mut client, &mut server).await;
                }
                for owner in [&mut client, &mut server] {
                    loop {
                        match owner.next_event().await {
                            Event::Finality(_) => break,
                            event => check_local(event),
                        }
                    }
                    assert_eq!(owner.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), block.id());
                }
                assert_eq!(client_layout.source_images(), acquired);
                assert_eq!(server_layout.source_images(), server_sources);
            })).unwrap();
        }).unwrap();
        for (index, layout) in [&client_layout, &server_layout].into_iter().enumerate() {
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
            ready
                .run_with_signing_session(|scope| {
                    let driver = node_driver(scope);
                    assert_eq!(
                        driver
                            .selected_artifact_history()
                            .selected_head_block_id()
                            .unwrap(),
                        block.id()
                    );
                    assert_eq!(driver.position().height().value(), 2);
                })
                .unwrap();
            assert_eq!(layout.authority_images(), images);
        }
    }
}
