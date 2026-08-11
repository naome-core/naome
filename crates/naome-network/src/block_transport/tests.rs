use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::block_exchange::{ProofBlockExchangeWireError, ProofBlockRequest};
use naome::proof_exchange::{ProofRequest, ProofResponse};
use naome_chain::ProofBlockId;
use tokio::time::timeout;

use super::*;
use crate::codec::ProofBlockWireResponse;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, connected_pair, create_journal, pairing_bytes,
    test_network_for_peers,
};
use crate::{
    ExchangeRequestId, Keypair, MAX_PENDING_REQUESTS, NetworkEvent, PendingBudget,
    RequestStartError,
};

fn block_id(byte: u8) -> ProofBlockId {
    ProofBlockId::from_bytes([byte; 32])
}

fn proof_request(byte: u8) -> ProofRequest {
    ProofRequest::from_wire_bytes(&[byte; 32]).unwrap()
}

fn block_response_event(
    network: &mut StaticProofNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> OutboundProofBlockEvent {
    let event = network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(800),
            message: request_response::Message::Response {
                request_id,
                response: ProofBlockWireResponse::new(bytes),
            },
        })
        .expect("the retained block request produces one terminal event");
    let NetworkEvent::OutboundBlock(event) = event else {
        panic!("block response did not produce an outbound block terminal");
    };
    event
}

fn block_failure_event(
    network: &mut StaticProofNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> OutboundProofBlockEvent {
    let event = network
        .handle_block_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(801),
            request_id,
            error,
        })
        .expect("the retained block request produces one terminal event");
    let NetworkEvent::OutboundBlock(event) = event else {
        panic!("block failure did not produce an outbound block terminal");
    };
    event
}

#[test]
fn tagged_request_ids_prevent_cross_protocol_aliasing() {
    let proof_peer = Keypair::generate_ed25519().public().to_peer_id();
    let block_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[proof_peer, block_peer]);

    let proof_request_id = network
        .request_proof(proof_peer, proof_request(0x11))
        .unwrap();
    let block_ticket = network
        .request_block(block_peer, ProofBlockRequest::new(block_id(0x22)))
        .unwrap();

    assert_eq!(proof_request_id, block_ticket.request_id);
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Proof(proof_request_id))
    );
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Block(block_ticket.request_id))
    );
    assert_eq!(network.pending.len(), 2);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

    let proof_event = network
        .handle_proof_exchange_event(request_response::Event::Message {
            peer: proof_peer,
            connection_id: ConnectionId::new_unchecked(799),
            message: request_response::Message::Response {
                request_id: proof_request_id,
                response: ProofResponse::from_wire_bytes(pairing_bytes()).unwrap(),
            },
        })
        .expect("the tagged proof terminal remains independently routable");
    assert!(
        !network
            .pending
            .contains_key(&ExchangeRequestId::Proof(proof_request_id))
    );
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Block(block_ticket.request_id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);
    drop(proof_event);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let block_request_id = block_ticket.request_id;
    let event = block_response_event(&mut network, block_request_id, block_peer, Vec::new());
    assert!(
        !network
            .pending
            .contains_key(&ExchangeRequestId::Block(block_request_id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    assert!(
        block_ticket
            .complete(event)
            .unwrap()
            .unwrap()
            .is_unavailable()
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn ticket_rejects_another_network_even_when_every_wire_field_matches() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let request = ProofBlockRequest::new(block_id(0x31));
    let mut first = test_network_for_peers(&[peer_id]);
    let mut second = test_network_for_peers(&[peer_id]);
    let first_ticket = first.request_block(peer_id, request).unwrap();
    let second_ticket = second.request_block(peer_id, request).unwrap();
    assert_eq!(first_ticket.request_id, second_ticket.request_id);

    let second_event =
        block_response_event(&mut second, second_ticket.request_id, peer_id, Vec::new());
    assert_eq!(first_ticket.peer_id(), second_event.peer_id());
    assert_eq!(first_ticket.request(), second_event.request());
    assert!(!first_ticket.accepts_event(&second_event));

    let mismatch = first_ticket.complete(second_event).unwrap_err();
    let (first_ticket, second_event) = (*mismatch).into_parts();
    assert!(second_ticket.accepts_event(&second_event));
    assert!(
        second_ticket
            .complete(second_event)
            .unwrap()
            .unwrap()
            .is_unavailable()
    );

    drop(first.remove_pending_block(first_ticket.request_id).unwrap());
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn ticket_rejects_a_different_generation_on_the_same_network() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let request = ProofBlockRequest::new(block_id(0x32));
    let mut network = test_network_for_peers(&[peer_id]);
    let first_ticket = network.request_block(peer_id, request).unwrap();
    let first_event =
        block_response_event(&mut network, first_ticket.request_id, peer_id, Vec::new());
    let second_ticket = network.request_block(peer_id, request).unwrap();
    assert_ne!(first_ticket.request_id, second_ticket.request_id);
    assert!(!second_ticket.accepts_event(&first_event));

    let mismatch = second_ticket.complete(first_event).unwrap_err();
    let (second_ticket, first_event) = (*mismatch).into_parts();
    assert!(first_ticket.accepts_event(&first_event));
    assert!(
        first_ticket
            .complete(first_event)
            .unwrap()
            .unwrap()
            .is_unavailable()
    );

    drop(
        network
            .remove_pending_block(second_ticket.request_id)
            .unwrap(),
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn authenticated_peer_mismatch_precedes_response_decoding() {
    let expected = Keypair::generate_ed25519().public().to_peer_id();
    let actual = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[expected, actual]);
    let ticket = network
        .request_block(expected, ProofBlockRequest::new(block_id(0x41)))
        .unwrap();
    let event = block_response_event(&mut network, ticket.request_id, actual, vec![0xff]);

    let failure = ticket.complete(event).unwrap().unwrap_err();
    assert!(matches!(
        failure.as_ref(),
        OutboundProofBlockFailure::PeerMismatch {
            expected: retained,
            actual: received,
        } if *retained == expected && *received == actual
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let failure_ticket = network
        .request_block(expected, ProofBlockRequest::new(block_id(0x42)))
        .unwrap();
    let failure_event = block_failure_event(
        &mut network,
        failure_ticket.request_id,
        actual,
        request_response::OutboundFailure::Timeout,
    );
    let failure = failure_ticket.complete(failure_event).unwrap().unwrap_err();
    assert!(matches!(
        failure.as_ref(),
        OutboundProofBlockFailure::PeerMismatch {
            expected: retained,
            actual: received,
        } if *retained == expected && *received == actual
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn correlated_responses_distinguish_malformed_bytes_from_a_valid_wrong_id() {
    let directory = TestDirectory::new("block-response-classification");
    let mut journal = create_journal(directory.path()).unwrap();
    apply_fresh_blocks(&mut journal, [pairing_bytes()]);
    let actual_block_id = journal.head_block_id().unwrap();
    let block_bytes = journal
        .block(actual_block_id)
        .unwrap()
        .unwrap()
        .to_canonical_bytes();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let requested_block_id = block_id(0x49);
    let wrong_id_ticket = network
        .request_block(peer_id, ProofBlockRequest::new(requested_block_id))
        .unwrap();
    let wrong_id_event = block_response_event(
        &mut network,
        wrong_id_ticket.request_id,
        peer_id,
        block_bytes,
    );
    let wrong_id = wrong_id_ticket
        .complete(wrong_id_event)
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        wrong_id.as_ref(),
        OutboundProofBlockFailure::InvalidResponse {
            source: ProofBlockExchangeWireError::BlockIdMismatch { expected, actual },
        } if *expected == requested_block_id && *actual == actual_block_id
    ));

    let malformed_ticket = network
        .request_block(peer_id, ProofBlockRequest::new(actual_block_id))
        .unwrap();
    let malformed_event = block_response_event(
        &mut network,
        malformed_ticket.request_id,
        peer_id,
        vec![0xff],
    );
    let malformed = malformed_ticket
        .complete(malformed_event)
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        malformed.as_ref(),
        OutboundProofBlockFailure::InvalidResponse {
            source: ProofBlockExchangeWireError::BlockDecode { .. },
        }
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn physical_failure_releases_the_permit_and_unknown_late_events_are_ignored() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let ticket = network
        .request_block(peer_id, ProofBlockRequest::new(block_id(0x4a)))
        .unwrap();
    let request_id = ticket.request_id;
    let failure_event = block_failure_event(
        &mut network,
        request_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(matches!(
        ticket
            .complete(failure_event)
            .unwrap()
            .unwrap_err()
            .as_ref(),
        OutboundProofBlockFailure::Transport(request_response::OutboundFailure::Timeout)
    ));

    assert!(
        network
            .handle_block_exchange_event(request_response::Event::Message {
                peer: peer_id,
                connection_id: ConnectionId::new_unchecked(802),
                message: request_response::Message::Response {
                    request_id,
                    response: ProofBlockWireResponse::new(Vec::new()),
                },
            })
            .is_none()
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn dropping_a_ticket_does_not_cancel_or_release_its_physical_request() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let ticket = network
        .request_block(peer_id, ProofBlockRequest::new(block_id(0x4b)))
        .unwrap();
    let request_id = ticket.request_id;
    drop(ticket);
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Block(request_id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let terminal = block_failure_event(
        &mut network,
        request_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    drop(terminal);
}

#[test]
fn block_request_start_errors_have_stable_precedence() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let budget = Arc::clone(&network.pending_budget);
    let permits = (0..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&budget).unwrap())
        .collect::<Vec<_>>();

    assert!(matches!(
        network.request_block(unknown, ProofBlockRequest::new(block_id(0x4c))),
        Err(RequestStartError::UnknownPeer(actual)) if actual == unknown
    ));
    assert!(matches!(
        network.request_block(peer_id, ProofBlockRequest::new(block_id(0x4d))),
        Err(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS,
        })
    ));
    drop(permits);

    let ticket = network
        .request_block(peer_id, ProofBlockRequest::new(block_id(0x4e)))
        .unwrap();
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);
    assert!(matches!(
        network.request_block(peer_id, ProofBlockRequest::new(block_id(0x4f))),
        Err(RequestStartError::AlreadyPending(actual)) if actual == peer_id
    ));
    drop(network.remove_pending_block(ticket.request_id).unwrap());
    assert!(matches!(
        network.request_block(peer_id, ProofBlockRequest::new(block_id(0x50))),
        Err(RequestStartError::PeerDisconnected(actual)) if actual == peer_id
    ));
}

#[test]
fn proof_and_block_requests_share_each_peer_slot() {
    let block_peer = Keypair::generate_ed25519().public().to_peer_id();
    let proof_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[block_peer, proof_peer]);

    let block_ticket = network
        .request_block(block_peer, ProofBlockRequest::new(block_id(0x51)))
        .unwrap();
    assert_eq!(
        network.request_proof(block_peer, proof_request(0x52)),
        Err(RequestStartError::AlreadyPending(block_peer))
    );

    let proof_request_id = network
        .request_proof(proof_peer, proof_request(0x53))
        .unwrap();
    assert!(matches!(
        network.request_block(
            proof_peer,
            ProofBlockRequest::new(block_id(0x54)),
        ),
        Err(RequestStartError::AlreadyPending(peer_id)) if peer_id == proof_peer
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

    let event = block_response_event(
        &mut network,
        block_ticket.request_id,
        block_peer,
        Vec::new(),
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);
    drop(block_ticket.complete(event).unwrap().unwrap());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(network.remove_pending_proof(proof_request_id).unwrap());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn successful_block_event_holds_the_shared_global_permit_until_completion() {
    let block_peer = Keypair::generate_ed25519().public().to_peer_id();
    let proof_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[block_peer, proof_peer]);
    let block_ticket = network
        .request_block(block_peer, ProofBlockRequest::new(block_id(0x61)))
        .unwrap();
    let budget = Arc::clone(&network.pending_budget);
    let other_permits = (1..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&budget).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 8);

    let event = block_response_event(
        &mut network,
        block_ticket.request_id,
        block_peer,
        Vec::new(),
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 8);
    assert_eq!(
        network.request_proof(proof_peer, proof_request(0x62)),
        Err(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS,
        })
    );

    drop(block_ticket.complete(event).unwrap().unwrap());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 7);
    let proof_request_id = network
        .request_proof(proof_peer, proof_request(0x63))
        .unwrap();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 8);
    drop(network.remove_pending_proof(proof_request_id).unwrap());
    drop(other_permits);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn poisoned_journal_lookup_never_becomes_unavailable() {
    let result = checked_block_lookup(Err(ProofChainJournalError::Poisoned));
    assert!(matches!(
        result,
        Err(RespondError::Journal(ProofChainJournalError::Poisoned))
    ));
}

async fn receive_block(
    client: &mut StaticProofNetwork,
    server: &mut StaticProofNetwork,
    server_journal: &ProofChainJournal,
) -> OutboundProofBlockEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundBlock(event) = event {
                        return event;
                    }
                }
                event = server.next_event() => match event {
                    NetworkEvent::InboundBlockRequest(inbound) => {
                        server.respond_block_from_journal(inbound, server_journal).unwrap();
                    }
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("inbound proof-block exchange failed: {error}");
                    }
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("proof-block exchange timed out")
}

#[tokio::test]
async fn committed_block_found_and_unavailable_round_trip_without_client_mutation() {
    let (mut client, mut server, client_peer_id, server_peer_id) = connected_pair().await;
    let server_directory = TestDirectory::new("block-transport-server");
    let mut server_journal = create_journal(server_directory.path()).unwrap();
    apply_fresh_blocks(&mut server_journal, [pairing_bytes()]);
    let committed_block_id = server_journal.head_block_id().unwrap();
    let expected_block = server_journal
        .block(committed_block_id)
        .unwrap()
        .unwrap()
        .clone();
    let virtual_genesis = expected_block.parent_block_id();

    let client_directory = TestDirectory::new("block-transport-client");
    let client_journal = create_journal(client_directory.path()).unwrap();
    let client_bytes = client_directory.journal_bytes();
    let client_head = client_journal.head_block_id().unwrap();

    let found_request = ProofBlockRequest::new(committed_block_id);
    let found_ticket = client.request_block(server_peer_id, found_request).unwrap();
    let found_event = receive_block(&mut client, &mut server, &server_journal).await;
    assert!(found_ticket.accepts_event(&found_event));
    let found = found_ticket.complete(found_event).unwrap().unwrap();
    assert_eq!(found.into_block(), Some(expected_block));
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(client_journal.head_block_id().unwrap(), client_head);
    assert_eq!(client_directory.journal_bytes(), client_bytes);

    let unavailable_request = ProofBlockRequest::new(virtual_genesis);
    let unavailable_ticket = client
        .request_block(server_peer_id, unavailable_request)
        .unwrap();
    let unavailable_event = receive_block(&mut client, &mut server, &server_journal).await;
    assert!(unavailable_ticket.accepts_event(&unavailable_event));
    assert!(
        unavailable_ticket
            .complete(unavailable_event)
            .unwrap()
            .unwrap()
            .is_unavailable()
    );
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(client_journal.head_block_id().unwrap(), client_head);
    assert_eq!(client_directory.journal_bytes(), client_bytes);

    let reverse_ticket = server
        .request_block(client_peer_id, ProofBlockRequest::new(client_head))
        .unwrap();
    let reverse_event = receive_block(&mut server, &mut client, &client_journal).await;
    assert!(reverse_ticket.accepts_event(&reverse_event));
    assert!(
        reverse_ticket
            .complete(reverse_event)
            .unwrap()
            .unwrap()
            .is_unavailable()
    );
}

#[tokio::test]
async fn simultaneous_bidirectional_block_requests_remain_exactly_correlated() {
    let (mut network_a, mut network_b, peer_a, peer_b) = connected_pair().await;
    let directory_a = TestDirectory::new("bidirectional-block-a");
    let mut journal_a = create_journal(directory_a.path()).unwrap();
    apply_fresh_blocks(&mut journal_a, [pairing_bytes()]);
    let block_a_id = journal_a.head_block_id().unwrap();
    let block_a = journal_a.block(block_a_id).unwrap().unwrap().clone();
    let directory_b = TestDirectory::new("bidirectional-block-b");
    let mut journal_b = create_journal(directory_b.path()).unwrap();
    apply_fresh_blocks(&mut journal_b, [vec![0x00, 0x00, 0x00, 0x01, 0x10, 0x02]]);
    let block_b_id = journal_b.head_block_id().unwrap();
    let block_b = journal_b.block(block_b_id).unwrap().unwrap().clone();

    let ticket_a = network_a
        .request_block(peer_b, ProofBlockRequest::new(block_b_id))
        .unwrap();
    let ticket_b = network_b
        .request_block(peer_a, ProofBlockRequest::new(block_a_id))
        .unwrap();
    let mut outbound_a = None;
    let mut outbound_b = None;
    let mut served_a = false;
    let mut served_b = false;
    timeout(Duration::from_secs(10), async {
        while outbound_a.is_none() || outbound_b.is_none() || !served_a || !served_b {
            tokio::select! {
                event = network_a.next_event(), if outbound_a.is_none() || !served_a => match event {
                    NetworkEvent::InboundBlockRequest(inbound) => {
                        network_a.respond_block_from_journal(inbound, &journal_a).unwrap();
                        served_a = true;
                    }
                    NetworkEvent::OutboundBlock(event) => outbound_a = Some(event),
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("network A inbound block exchange failed: {error}");
                    }
                    _ => {}
                },
                event = network_b.next_event(), if outbound_b.is_none() || !served_b => match event {
                    NetworkEvent::InboundBlockRequest(inbound) => {
                        network_b.respond_block_from_journal(inbound, &journal_b).unwrap();
                        served_b = true;
                    }
                    NetworkEvent::OutboundBlock(event) => outbound_b = Some(event),
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("network B inbound block exchange failed: {error}");
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("simultaneous bidirectional block exchange timed out");

    assert_eq!(
        ticket_a
            .complete(outbound_a.unwrap())
            .unwrap()
            .unwrap()
            .into_block(),
        Some(block_b)
    );
    assert_eq!(
        ticket_b
            .complete(outbound_b.unwrap())
            .unwrap()
            .unwrap()
            .into_block(),
        Some(block_a)
    );
    assert_eq!(network_a.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(network_b.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn proof_and_block_protocols_progress_concurrently_on_one_session() {
    let (mut network_a, mut network_b, peer_a, peer_b) = connected_pair().await;
    let directory_a = TestDirectory::new("mixed-exchange-a");
    let mut journal_a = create_journal(directory_a.path()).unwrap();
    apply_fresh_blocks(&mut journal_a, [pairing_bytes()]);
    let block_a_id = journal_a.head_block_id().unwrap();
    let block_a = journal_a.block(block_a_id).unwrap().unwrap().clone();
    let directory_b = TestDirectory::new("mixed-exchange-b");
    let mut journal_b = create_journal(directory_b.path()).unwrap();
    let proof_b = apply_fresh_blocks(&mut journal_b, [pairing_bytes()])[0];

    network_a
        .request_proof(peer_b, ProofRequest::new(proof_b))
        .unwrap();
    let block_ticket = network_b
        .request_block(peer_a, ProofBlockRequest::new(block_a_id))
        .unwrap();
    let mut proof_event = None;
    let mut block_event = None;
    let mut served_block = false;
    let mut served_proof = false;
    timeout(Duration::from_secs(10), async {
        while proof_event.is_none() || block_event.is_none() || !served_block || !served_proof {
            tokio::select! {
                event = network_a.next_event(), if proof_event.is_none() || !served_block => match event {
                    NetworkEvent::InboundBlockRequest(inbound) => {
                        network_a.respond_block_from_journal(inbound, &journal_a).unwrap();
                        served_block = true;
                    }
                    NetworkEvent::OutboundProof(event) => proof_event = Some(event),
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("mixed inbound block exchange failed: {error}");
                    }
                    _ => {}
                },
                event = network_b.next_event(), if block_event.is_none() || !served_proof => match event {
                    NetworkEvent::InboundProofRequest(inbound) => {
                        network_b
                            .respond_proof_from_journal(inbound, &journal_b)
                            .unwrap();
                        served_proof = true;
                    }
                    NetworkEvent::OutboundBlock(event) => block_event = Some(event),
                    NetworkEvent::InboundProofFailure { error, .. } => {
                        panic!("mixed inbound proof exchange failed: {error}");
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("concurrent proof and block exchange timed out");

    let proof_event = proof_event.unwrap();
    assert_eq!(proof_event.peer_id(), peer_b);
    assert_eq!(proof_event.request(), ProofRequest::new(proof_b));
    assert!(proof_event.failure().is_none());
    assert!(!proof_event.is_deadline_exceeded());
    let crate::OutboundProofOutcome::Response { response, .. } = &proof_event.outcome else {
        panic!("proof exchange did not return a response");
    };
    assert!(!response.is_unavailable());
    drop(proof_event);

    assert_eq!(
        block_ticket
            .complete(block_event.unwrap())
            .unwrap()
            .unwrap()
            .into_block(),
        Some(block_a)
    );
    assert_eq!(network_a.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(network_b.pending_budget.active.load(Ordering::Relaxed), 0);
}
