use std::time::Duration;

use naome::block_exchange::ProofBlockRequest;
use naome::chain_head_exchange::ProofChainHeadRequest;
use naome::proof_exchange::ProofRequest;
use naome_chain::{ProofBlockId, ProofChainId};
use tokio::time::{Instant, timeout};

use super::*;
use crate::tests::{
    TestDirectory, address, apply_fresh_blocks, assert_snapshot, connected_pair, create_journal,
    listening_address, pairing_bytes, snapshot,
};
use crate::{
    NetworkEvent, OutboundProofOutcome, PeerSessionEvent, RespondError, StaticPeer,
    StaticProofNetwork,
};

#[tokio::test]
async fn service_forwards_announcement_without_acknowledging_or_mutating() {
    let (mut sender, mut service, sender_peer_id, service_peer_id) = connected_pair().await;
    let sender_directory = TestDirectory::new("journal-service-announcement-sender");
    let mut sender_journal = create_journal(sender_directory.path()).unwrap();
    apply_fresh_blocks(&mut sender_journal, [pairing_bytes()]);
    let service_directory = TestDirectory::new("journal-service-announcement-service");
    let service_journal = create_journal(service_directory.path()).unwrap();
    let sender_before = snapshot(&sender_directory, &sender_journal);
    let service_before = snapshot(&service_directory, &service_journal);
    let expected_announcement = naome::chain_head_announcement::ProofChainHeadAnnouncement::new(
        sender_journal.chain_id(),
        sender_journal.head_block_id().unwrap(),
    );
    let ticket = sender
        .announce_chain_head_from_journal(service_peer_id, &sender_journal)
        .unwrap();

    let forwarded = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = sender.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(event) = event {
                        panic!("announcement became terminal before caller policy: {event:?}")
                    }
                }
                event = service.next_journal_service_event(&service_journal) => match event {
                    JournalServiceEvent::Network(NetworkEvent::InboundChainHeadAnnouncement(
                        inbound,
                    )) => break inbound,
                    JournalServiceEvent::Network(_) => {}
                    JournalServiceEvent::Served(request) => {
                        panic!("announcement was incorrectly served as {request:?}")
                    }
                    JournalServiceEvent::ServeFailed { request, error } => {
                        panic!("announcement was incorrectly handled as {request:?}: {error}")
                    }
                }
            }
        }
    })
    .await
    .expect("announcement was not forwarded");
    assert_eq!(forwarded.peer_id(), sender_peer_id);
    assert_eq!(forwarded.announcement(), expected_announcement);
    drop(forwarded);

    let terminal = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = sender.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(event) = event {
                        break event;
                    }
                }
                event = service.next_journal_service_event(&service_journal) => match event {
                    JournalServiceEvent::Network(
                        NetworkEvent::InboundChainHeadAnnouncementFailure { peer_id, .. },
                    ) => assert_eq!(peer_id, sender_peer_id),
                    JournalServiceEvent::Network(_) => {}
                    JournalServiceEvent::Served(request) => {
                        panic!("service consumed an unrelated event as {request:?}")
                    }
                    JournalServiceEvent::ServeFailed { request, error } => {
                        panic!("service consumed an unrelated event as {request:?}: {error}")
                    }
                }
            }
        }
    })
    .await
    .expect("unacknowledged announcement did not become terminal");
    let result = ticket.complete(terminal).unwrap();
    assert!(result.is_err(), "forwarding must not imply acknowledgement");
    assert_snapshot(&sender_directory, &sender_journal, &sender_before);
    assert_snapshot(&service_directory, &service_journal, &service_before);
}

#[tokio::test]
async fn closed_response_channel_is_observable_with_exact_request_metadata() {
    let (mut client, mut service, client_peer_id, service_peer_id) = connected_pair().await;
    let directory = TestDirectory::new("journal-service-closed-channel");
    let journal = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &journal);
    let request = ProofRequest::from_wire_bytes(&[0xa7; 32]).unwrap();
    client.request_proof(service_peer_id, request).unwrap();

    let inbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundProof(event) = event {
                        panic!("proof request became terminal before serving: {event:?}")
                    }
                }
                event = service.next_event() => {
                    if let NetworkEvent::InboundProofRequest(inbound) = event {
                        break inbound;
                    }
                }
            }
        }
    })
    .await
    .expect("service did not receive the proof request");
    assert_eq!(inbound.peer_id(), client_peer_id);
    assert_eq!(inbound.request(), request);
    drop(client);

    timeout(Duration::from_secs(10), async {
        loop {
            match service.next_event().await {
                NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id }) => {
                    assert_eq!(peer_id, client_peer_id);
                    break;
                }
                NetworkEvent::InboundProofFailure { peer_id, .. } => {
                    assert_eq!(peer_id, client_peer_id)
                }
                _ => {}
            }
        }
    })
    .await
    .expect("closed client connection was not observed");

    match service.handle_journal_service_event(NetworkEvent::InboundProofRequest(inbound), &journal)
    {
        JournalServiceEvent::ServeFailed {
            request:
                JournalServiceRequest::Proof {
                    peer_id,
                    request: actual,
                },
            error: RespondError::ChannelClosed,
        } => {
            assert_eq!(peer_id, client_peer_id);
            assert_eq!(actual, request);
        }
        event => panic!("closed response channel produced the wrong service event: {event:?}"),
    }
    assert_eq!(
        service.inbound_application_request_budget.tokens(),
        crate::INBOUND_APPLICATION_REQUEST_BURST,
        "a closed response channel must not consume an application token"
    );
    assert_snapshot(&directory, &journal, &before);
}

#[tokio::test]
async fn exhausted_application_budget_rejects_found_proof_before_serving() {
    let (mut client, mut service, client_peer_id, service_peer_id) = connected_pair().await;
    let directory = TestDirectory::new("journal-service-rate-limit");
    let mut journal = create_journal(directory.path()).unwrap();
    let proof_id = apply_fresh_blocks(&mut journal, [pairing_bytes()])[0];
    let before = snapshot(&directory, &journal);
    let request = ProofRequest::new(proof_id);
    client.request_proof(service_peer_id, request).unwrap();

    let inbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundProof(event) = event {
                        panic!("proof request became terminal before rate rejection: {event:?}")
                    }
                }
                event = service.next_event() => {
                    if let NetworkEvent::InboundProofRequest(inbound) = event {
                        break inbound;
                    }
                }
            }
        }
    })
    .await
    .expect("service did not receive the proof request");
    service
        .inbound_application_request_budget
        .exhaust(Instant::now() + Duration::from_secs(60));

    match service.handle_journal_service_event(NetworkEvent::InboundProofRequest(inbound), &journal)
    {
        JournalServiceEvent::ServeFailed {
            request:
                JournalServiceRequest::Proof {
                    peer_id,
                    request: actual,
                },
            error: RespondError::RateLimited,
        } => {
            assert_eq!(peer_id, client_peer_id);
            assert_eq!(actual, request);
        }
        event => panic!("exhausted application budget produced the wrong event: {event:?}"),
    }
    assert_eq!(service.inbound_application_request_budget.tokens(), 0);
    assert_snapshot(&directory, &journal, &before);
}

#[tokio::test]
async fn exhausted_application_budget_rejects_found_block_before_serving() {
    let (mut client, mut service, client_peer_id, service_peer_id) = connected_pair().await;
    let directory = TestDirectory::new("journal-service-block-rate-limit");
    let mut journal = create_journal(directory.path()).unwrap();
    apply_fresh_blocks(&mut journal, [pairing_bytes()]);
    let before = snapshot(&directory, &journal);
    let request = ProofBlockRequest::new(journal.head_block_id().unwrap());
    let _ticket = client.request_block(service_peer_id, request).unwrap();

    let inbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundBlock(event) = event {
                        panic!("block request became terminal before rate rejection: {event:?}")
                    }
                }
                event = service.next_event() => {
                    if let NetworkEvent::InboundBlockRequest(inbound) = event {
                        break inbound;
                    }
                }
            }
        }
    })
    .await
    .expect("service did not receive the block request");
    service
        .inbound_application_request_budget
        .exhaust(Instant::now() + Duration::from_secs(60));

    match service.handle_journal_service_event(NetworkEvent::InboundBlockRequest(inbound), &journal)
    {
        JournalServiceEvent::ServeFailed {
            request:
                JournalServiceRequest::Block {
                    peer_id,
                    request: actual,
                },
            error: RespondError::RateLimited,
        } => {
            assert_eq!(peer_id, client_peer_id);
            assert_eq!(actual, request);
        }
        event => panic!("exhausted application budget produced the wrong event: {event:?}"),
    }
    assert_eq!(service.inbound_application_request_budget.tokens(), 0);
    assert_snapshot(&directory, &journal, &before);
}

#[tokio::test]
async fn exhausted_application_budget_rejects_matching_chain_head_before_serving() {
    let (mut client, mut service, client_peer_id, service_peer_id) = connected_pair().await;
    let directory = TestDirectory::new("journal-service-head-rate-limit");
    let mut journal = create_journal(directory.path()).unwrap();
    apply_fresh_blocks(&mut journal, [pairing_bytes()]);
    let before = snapshot(&directory, &journal);
    let request = ProofChainHeadRequest::new(journal.chain_id());
    let _ticket = client.request_chain_head(service_peer_id, request).unwrap();

    let inbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundChainHead(event) = event {
                        panic!("chain-head request became terminal before rate rejection: {event:?}")
                    }
                }
                event = service.next_event() => {
                    if let NetworkEvent::InboundChainHeadRequest(inbound) = event {
                        break inbound;
                    }
                }
            }
        }
    })
    .await
    .expect("service did not receive the chain-head request");
    service
        .inbound_application_request_budget
        .exhaust(Instant::now() + Duration::from_secs(60));

    match service
        .handle_journal_service_event(NetworkEvent::InboundChainHeadRequest(inbound), &journal)
    {
        JournalServiceEvent::ServeFailed {
            request:
                JournalServiceRequest::ChainHead {
                    peer_id,
                    request: actual,
                },
            error: RespondError::RateLimited,
        } => {
            assert_eq!(peer_id, client_peer_id);
            assert_eq!(actual, request);
        }
        event => panic!("exhausted application budget produced the wrong event: {event:?}"),
    }
    assert_eq!(service.inbound_application_request_budget.tokens(), 0);
    assert_snapshot(&directory, &journal, &before);
}

#[tokio::test]
async fn one_service_node_serves_found_and_unavailable_to_three_neutral_clients() {
    let mut identities = (0..4)
        .map(|_| crate::Keypair::generate_ed25519())
        .collect::<Vec<_>>();
    identities.sort_unstable_by_key(|identity| identity.public().to_peer_id().to_bytes());
    let client_a_identity = identities.remove(0);
    let client_b_identity = identities.remove(0);
    let client_c_identity = identities.remove(0);
    let service_identity = identities.remove(0);
    let client_a_peer_id = client_a_identity.public().to_peer_id();
    let client_b_peer_id = client_b_identity.public().to_peer_id();
    let client_c_peer_id = client_c_identity.public().to_peer_id();
    let service_peer_id = service_identity.public().to_peer_id();

    let mut service = StaticProofNetwork::new(
        service_identity,
        [
            StaticPeer::new(client_a_peer_id, address(1)),
            StaticPeer::new(client_b_peer_id, address(2)),
            StaticPeer::new(client_c_peer_id, address(3)),
        ],
    )
    .unwrap();
    let service_address = listening_address(&mut service).await;
    let mut client_a = StaticProofNetwork::new(
        client_a_identity,
        [StaticPeer::new(service_peer_id, service_address.clone())],
    )
    .unwrap();
    let mut client_b = StaticProofNetwork::new(
        client_b_identity,
        [StaticPeer::new(service_peer_id, service_address.clone())],
    )
    .unwrap();
    let mut client_c = StaticProofNetwork::new(
        client_c_identity,
        [StaticPeer::new(service_peer_id, service_address)],
    )
    .unwrap();

    let mut service_sessions = [false; 3];
    let mut client_sessions = [false; 3];
    timeout(Duration::from_secs(15), async {
        while !service_sessions.iter().all(|established| *established)
            || !client_sessions.iter().all(|established| *established)
        {
            tokio::select! {
                event = service.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        let index = [client_a_peer_id, client_b_peer_id, client_c_peer_id]
                            .iter()
                            .position(|configured| *configured == peer_id)
                            .expect("service authenticated an unconfigured client");
                        service_sessions[index] = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("service unexpectedly dialed {peer_id}")
                    }
                    _ => {}
                },
                event = client_a.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, service_peer_id);
                        client_sessions[0] = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("client A dial to {peer_id} failed")
                    }
                    _ => {}
                },
                event = client_b.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, service_peer_id);
                        client_sessions[1] = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("client B dial to {peer_id} failed")
                    }
                    _ => {}
                },
                event = client_c.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, service_peer_id);
                        client_sessions[2] = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("client C dial to {peer_id} failed")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("all three authenticated sessions did not establish");

    let directory = TestDirectory::new("journal-service-three-clients");
    let mut journal = create_journal(directory.path()).unwrap();
    let proof_bytes = pairing_bytes();
    let proof_id = apply_fresh_blocks(&mut journal, [proof_bytes.clone()])[0];
    let block_id = journal.head_block_id().unwrap();
    let chain_id = journal.chain_id();
    let retained_proof_bytes = journal
        .proof(proof_id)
        .unwrap()
        .unwrap()
        .canonical_proof_bytes()
        .to_vec();
    let retained_block_bytes = journal
        .block(block_id)
        .unwrap()
        .unwrap()
        .to_canonical_bytes()
        .to_vec();
    let before = snapshot(&directory, &journal);
    let proof_request = ProofRequest::new(proof_id);
    let block_request = ProofBlockRequest::new(block_id);
    let head_request = ProofChainHeadRequest::new(chain_id);

    let client_a_directory = TestDirectory::new("journal-service-requester-a");
    let client_a_journal = create_journal(client_a_directory.path()).unwrap();
    let client_a_before = snapshot(&client_a_directory, &client_a_journal);
    let client_b_directory = TestDirectory::new("journal-service-requester-b");
    let client_b_journal = create_journal(client_b_directory.path()).unwrap();
    let client_b_before = snapshot(&client_b_directory, &client_b_journal);
    let client_c_directory = TestDirectory::new("journal-service-requester-c");
    let client_c_journal = create_journal(client_c_directory.path()).unwrap();
    let client_c_before = snapshot(&client_c_directory, &client_c_journal);

    client_a
        .request_proof(service_peer_id, proof_request)
        .unwrap();
    let mut block_ticket = Some(
        client_b
            .request_block(service_peer_id, block_request)
            .unwrap(),
    );
    let mut head_ticket = Some(
        client_c
            .request_chain_head(service_peer_id, head_request)
            .unwrap(),
    );

    let mut served = [false; 3];
    let mut responses = [false; 3];
    timeout(Duration::from_secs(15), async {
        while !served.iter().all(|complete| *complete)
            || !responses.iter().all(|complete| *complete)
        {
            tokio::select! {
                event = service.next_journal_service_event(&journal) => match event {
                    JournalServiceEvent::Served(JournalServiceRequest::Proof { peer_id, request }) => {
                        assert_eq!(peer_id, client_a_peer_id);
                        assert_eq!(request, proof_request);
                        assert!(!served[0], "proof request was reported served twice");
                        served[0] = true;
                    }
                    JournalServiceEvent::Served(JournalServiceRequest::Block { peer_id, request }) => {
                        assert_eq!(peer_id, client_b_peer_id);
                        assert_eq!(request, block_request);
                        assert!(!served[1], "block request was reported served twice");
                        served[1] = true;
                    }
                    JournalServiceEvent::Served(JournalServiceRequest::ChainHead { peer_id, request }) => {
                        assert_eq!(peer_id, client_c_peer_id);
                        assert_eq!(request, head_request);
                        assert!(!served[2], "head request was reported served twice");
                        served[2] = true;
                    }
                    JournalServiceEvent::ServeFailed { request, error } => {
                        panic!("journal service failed {request:?}: {error}")
                    }
                    JournalServiceEvent::Network(NetworkEvent::ListenerError { error, .. }) => {
                        panic!("service listener failed: {error}")
                    }
                    JournalServiceEvent::Network(_) => {}
                },
                event = client_a.next_event() => {
                    if let NetworkEvent::OutboundProof(event) = event {
                        assert!(served[0], "proof response preceded its Served event");
                        assert_eq!(event.peer_id(), service_peer_id);
                        assert_eq!(event.request(), proof_request);
                        assert!(event.failure().is_none());
                        assert!(!event.is_deadline_exceeded());
                        match event.outcome {
                            OutboundProofOutcome::Response { response, .. } => {
                                assert_eq!(response.into_wire_bytes(), proof_bytes);
                            }
                            _ => panic!("proof request did not receive a response"),
                        }
                        responses[0] = true;
                    }
                },
                event = client_b.next_event() => {
                    if let NetworkEvent::OutboundBlock(event) = event {
                        assert!(served[1], "block response preceded its Served event");
                        let response = block_ticket.take().unwrap().complete(event).unwrap().unwrap();
                        assert_eq!(response.into_block().unwrap().id(), block_id);
                        responses[1] = true;
                    }
                },
                event = client_c.next_event() => {
                    if let NetworkEvent::OutboundChainHead(event) = event {
                        assert!(served[2], "head response preceded its Served event");
                        let response = head_ticket.take().unwrap().complete(event).unwrap().unwrap();
                        assert_eq!(response.peer_id(), service_peer_id);
                        assert_eq!(response.request(), head_request);
                        assert_eq!(response.head_block_id(), Some(block_id));
                        responses[2] = true;
                    }
                },
            }
        }
    })
    .await
    .expect("three-client journal service exchange timed out");

    let unavailable_proof_request = ProofRequest::from_wire_bytes(&[0xd1; 32]).unwrap();
    let unavailable_block_request = ProofBlockRequest::new(ProofBlockId::from_bytes([0xd2; 32]));
    let foreign_head_request = ProofChainHeadRequest::new(ProofChainId::from_bytes([0xd3; 32]));
    assert_ne!(unavailable_proof_request, proof_request);
    assert_ne!(unavailable_block_request, block_request);
    assert_ne!(foreign_head_request, head_request);

    client_a
        .request_proof(service_peer_id, unavailable_proof_request)
        .unwrap();
    let mut block_ticket = Some(
        client_b
            .request_block(service_peer_id, unavailable_block_request)
            .unwrap(),
    );
    let mut head_ticket = Some(
        client_c
            .request_chain_head(service_peer_id, foreign_head_request)
            .unwrap(),
    );

    let mut served = [false; 3];
    let mut responses = [false; 3];
    timeout(Duration::from_secs(15), async {
        while !served.iter().all(|complete| *complete)
            || !responses.iter().all(|complete| *complete)
        {
            tokio::select! {
                event = service.next_journal_service_event(&journal) => match event {
                    JournalServiceEvent::Served(JournalServiceRequest::Proof { peer_id, request }) => {
                        assert_eq!(peer_id, client_a_peer_id);
                        assert_eq!(request, unavailable_proof_request);
                        assert!(!served[0], "unavailable proof request was reported served twice");
                        served[0] = true;
                    }
                    JournalServiceEvent::Served(JournalServiceRequest::Block { peer_id, request }) => {
                        assert_eq!(peer_id, client_b_peer_id);
                        assert_eq!(request, unavailable_block_request);
                        assert!(!served[1], "unavailable block request was reported served twice");
                        served[1] = true;
                    }
                    JournalServiceEvent::Served(JournalServiceRequest::ChainHead { peer_id, request }) => {
                        assert_eq!(peer_id, client_c_peer_id);
                        assert_eq!(request, foreign_head_request);
                        assert!(!served[2], "foreign-chain head request was reported served twice");
                        served[2] = true;
                    }
                    JournalServiceEvent::ServeFailed { request, error } => {
                        panic!("journal service failed unavailable {request:?}: {error}")
                    }
                    JournalServiceEvent::Network(NetworkEvent::ListenerError { error, .. }) => {
                        panic!("service listener failed: {error}")
                    }
                    JournalServiceEvent::Network(_) => {}
                },
                event = client_a.next_event() => {
                    if let NetworkEvent::OutboundProof(event) = event {
                        assert!(served[0], "unavailable proof response preceded its Served event");
                        assert_eq!(event.peer_id(), service_peer_id);
                        assert_eq!(event.request(), unavailable_proof_request);
                        assert!(event.failure().is_none());
                        assert!(!event.is_deadline_exceeded());
                        match event.outcome {
                            OutboundProofOutcome::Response { response, .. } => {
                                assert!(response.is_unavailable());
                            }
                            _ => panic!("missing proof request did not receive a response"),
                        }
                        responses[0] = true;
                    }
                },
                event = client_b.next_event() => {
                    if let NetworkEvent::OutboundBlock(event) = event {
                        assert!(served[1], "unavailable block response preceded its Served event");
                        let response = block_ticket.take().unwrap().complete(event).unwrap().unwrap();
                        assert!(response.is_unavailable());
                        responses[1] = true;
                    }
                },
                event = client_c.next_event() => {
                    if let NetworkEvent::OutboundChainHead(event) = event {
                        assert!(served[2], "foreign-chain head response preceded its Served event");
                        let response = head_ticket.take().unwrap().complete(event).unwrap().unwrap();
                        assert_eq!(response.peer_id(), service_peer_id);
                        assert_eq!(response.request(), foreign_head_request);
                        assert!(response.is_unavailable());
                        responses[2] = true;
                    }
                },
            }
        }
    })
    .await
    .expect("three-client unavailable journal service exchange timed out");

    assert_snapshot(&directory, &journal, &before);
    assert_eq!(journal.chain_id(), chain_id);
    assert_eq!(
        journal
            .proof(proof_id)
            .unwrap()
            .unwrap()
            .canonical_proof_bytes(),
        retained_proof_bytes
    );
    assert_eq!(
        journal
            .block(block_id)
            .unwrap()
            .unwrap()
            .to_canonical_bytes()
            .to_vec(),
        retained_block_bytes
    );
    assert_snapshot(&client_a_directory, &client_a_journal, &client_a_before);
    assert_snapshot(&client_b_directory, &client_b_journal, &client_b_before);
    assert_snapshot(&client_c_directory, &client_c_journal, &client_c_before);
}
