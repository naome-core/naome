use crate::transport::{ExchangeRequestId, PendingBudget};
use naome_storage::ArtifactChainJournal;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_protocol::artifact_exchange::ArtifactRequest;
use naome_protocol::block_exchange::ArtifactBlockRequest;
use naome_protocol::chain_head_exchange::{ArtifactChainHeadRequest, ArtifactChainHeadResponse};
use tokio::time::timeout;

use super::*;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, connected_pair, create_journal, pairing_bytes,
    test_network_for_peers,
};
use crate::{
    Keypair, MAX_EXCHANGE_STREAMS_PER_CONNECTION, MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION,
    MAX_PENDING_REQUESTS, MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION,
    MAX_YAMUX_STREAMS_PER_CONNECTION, NetworkEvent, RequestStartError,
};

fn chain_id(byte: u8) -> ArtifactChainId {
    ArtifactChainId::from_bytes([byte; 32])
}

fn block_id(byte: u8) -> ArtifactBlockId {
    ArtifactBlockId::from_bytes([byte; 32])
}

fn artifact_request(byte: u8) -> ArtifactRequest {
    ArtifactRequest::from_wire_bytes(&[byte; 32]).unwrap()
}

fn head_response_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    bytes: &[u8],
) -> OutboundArtifactChainHeadEvent {
    let event = network
        .handle_head_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(900),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactChainHeadResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained chain-head request produces one terminal event");
    let NetworkEvent::OutboundChainHead(event) = event else {
        panic!("chain-head response did not produce its outbound terminal")
    };
    event
}

fn head_failure_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> OutboundArtifactChainHeadEvent {
    let event = network
        .handle_head_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(901),
            request_id,
            error,
        })
        .expect("the retained chain-head request produces one terminal event");
    let NetworkEvent::OutboundChainHead(event) = event else {
        panic!("chain-head failure did not produce its outbound terminal")
    };
    event
}

#[test]
fn four_exchange_stream_budgets_fit_below_the_yamux_cap() {
    assert_eq!(MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION, 2);
    assert_eq!(MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION, 1);
    assert_eq!(MAX_EXCHANGE_STREAMS_PER_CONNECTION, 8);
    assert_eq!(MAX_YAMUX_STREAMS_PER_CONNECTION, 8);
}

#[test]
fn tagged_request_ids_isolate_head_block_and_artifact_namespaces() {
    let proof_peer = Keypair::generate_ed25519().public().to_peer_id();
    let block_peer = Keypair::generate_ed25519().public().to_peer_id();
    let head_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[proof_peer, block_peer, head_peer]);

    let proof_id = network
        .request_artifact(proof_peer, artifact_request(0x11))
        .unwrap();
    let _block_ticket = network
        .request_block(block_peer, ArtifactBlockRequest::new(block_id(0x22)))
        .unwrap();
    let block_request_id = network
        .pending
        .keys()
        .find_map(|request_id| match request_id {
            ExchangeRequestId::Block(request_id) => Some(*request_id),
            ExchangeRequestId::Artifact(_)
            | ExchangeRequestId::Head(_)
            | ExchangeRequestId::Announcement(_)
            | ExchangeRequestId::RecoveryBundlePush(_)
            | ExchangeRequestId::ConsensusPush(_) => None,
        })
        .unwrap();
    let request = ArtifactChainHeadRequest::new(chain_id(0x33));
    let head_ticket = network.request_chain_head(head_peer, request).unwrap();

    assert_eq!(proof_id, block_request_id);
    assert_eq!(proof_id, head_ticket.request_id);
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Artifact(proof_id))
    );
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Block(block_request_id))
    );
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Head(head_ticket.request_id))
    );
    assert_eq!(network.pending.len(), 3);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 3);

    assert_eq!(
        network.request_artifact(head_peer, artifact_request(0x44)),
        Err(RequestStartError::AlreadyPending(head_peer))
    );
    assert!(matches!(
        network.request_chain_head(
            block_peer,
            ArtifactChainHeadRequest::new(chain_id(0x45)),
        ),
        Err(RequestStartError::AlreadyPending(peer_id)) if peer_id == block_peer
    ));

    let event = head_response_event(&mut network, head_ticket.request_id, head_peer, &[]);
    assert_eq!(network.pending.len(), 2);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 3);
    let response = head_ticket.complete(event).unwrap().unwrap();
    assert_eq!(response.peer_id(), head_peer);
    assert_eq!(response.request(), request);
    assert!(response.is_unavailable());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

    drop(
        network
            .pending
            .remove(&ExchangeRequestId::Artifact(proof_id))
            .unwrap(),
    );
    drop(
        network
            .pending
            .remove(&ExchangeRequestId::Block(block_request_id))
            .unwrap(),
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn ticket_rejects_other_network_and_later_generation_without_losing_values() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let request = ArtifactChainHeadRequest::new(chain_id(0x51));
    let mut first = test_network_for_peers(&[peer_id]);
    let mut second = test_network_for_peers(&[peer_id]);
    let first_ticket = first.request_chain_head(peer_id, request).unwrap();
    let second_ticket = second.request_chain_head(peer_id, request).unwrap();
    assert_eq!(first_ticket.request_id, second_ticket.request_id);

    let second_event = head_response_event(
        &mut second,
        second_ticket.request_id,
        peer_id,
        block_id(0x52).as_bytes(),
    );
    assert!(!first_ticket.accepts_event(&second_event));
    let mismatch = first_ticket.complete(second_event).unwrap_err();
    let (first_ticket, second_event) = (*mismatch).into_parts();
    assert!(second_ticket.accepts_event(&second_event));
    assert_eq!(
        second_ticket
            .complete(second_event)
            .unwrap()
            .unwrap()
            .head_block_id(),
        Some(block_id(0x52))
    );

    drop(
        first
            .pending
            .remove(&ExchangeRequestId::Head(first_ticket.request_id))
            .unwrap(),
    );
    let first_ticket = first.request_chain_head(peer_id, request).unwrap();
    let first_event = head_response_event(&mut first, first_ticket.request_id, peer_id, &[]);
    let later_ticket = first.request_chain_head(peer_id, request).unwrap();
    assert_ne!(first_ticket.request_id, later_ticket.request_id);
    assert!(!later_ticket.accepts_event(&first_event));
    let mismatch = later_ticket.complete(first_event).unwrap_err();
    let (later_ticket, first_event) = (*mismatch).into_parts();
    assert!(first_ticket.accepts_event(&first_event));
    assert!(
        first_ticket
            .complete(first_event)
            .unwrap()
            .unwrap()
            .is_unavailable()
    );
    drop(
        first
            .pending
            .remove(&ExchangeRequestId::Head(later_ticket.request_id))
            .unwrap(),
    );
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn late_terminals_cannot_consume_a_new_head_request_generation() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let request = ArtifactChainHeadRequest::new(chain_id(0x59));
    let mut network = test_network_for_peers(&[peer_id]);

    let old_ticket = network.request_chain_head(peer_id, request).unwrap();
    let old_request_id = old_ticket.request_id;
    let old_event = head_response_event(&mut network, old_request_id, peer_id, &[]);
    assert!(
        old_ticket
            .complete(old_event)
            .unwrap()
            .unwrap()
            .is_unavailable()
    );

    let current_ticket = network.request_chain_head(peer_id, request).unwrap();
    assert_ne!(old_request_id, current_ticket.request_id);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let late_response = network.handle_head_exchange_event(request_response::Event::Message {
        peer: peer_id,
        connection_id: ConnectionId::new_unchecked(902),
        message: request_response::Message::Response {
            request_id: old_request_id,
            response: ArtifactChainHeadResponse::from_wire_bytes(&[]).unwrap(),
        },
    });
    assert!(late_response.is_none());
    let late_failure =
        network.handle_head_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(903),
            request_id: old_request_id,
            error: request_response::OutboundFailure::Timeout,
        });
    assert!(late_failure.is_none());
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Head(current_ticket.request_id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let current_event = head_response_event(
        &mut network,
        current_ticket.request_id,
        peer_id,
        block_id(0x5a).as_bytes(),
    );
    assert_eq!(
        current_ticket
            .complete(current_event)
            .unwrap()
            .unwrap()
            .head_block_id(),
        Some(block_id(0x5a))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn peer_mismatch_precedes_response_and_failures_release_immediately() {
    let expected = Keypair::generate_ed25519().public().to_peer_id();
    let actual = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[expected, actual]);
    let request = ArtifactChainHeadRequest::new(chain_id(0x61));

    let ticket = network.request_chain_head(expected, request).unwrap();
    let event = head_response_event(&mut network, ticket.request_id, actual, &[]);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(matches!(
        ticket.complete(event).unwrap().unwrap_err().as_ref(),
        OutboundArtifactChainHeadFailure::PeerMismatch {
            expected: retained,
            actual: received,
        } if *retained == expected && *received == actual
    ));

    let ticket = network.request_chain_head(expected, request).unwrap();
    let event = head_failure_event(
        &mut network,
        ticket.request_id,
        actual,
        request_response::OutboundFailure::Timeout,
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(matches!(
        ticket.complete(event).unwrap().unwrap_err().as_ref(),
        OutboundArtifactChainHeadFailure::PeerMismatch {
            expected: retained,
            actual: received,
        } if *retained == expected && *received == actual
    ));

    let ticket = network.request_chain_head(expected, request).unwrap();
    let event = head_failure_event(
        &mut network,
        ticket.request_id,
        expected,
        request_response::OutboundFailure::Timeout,
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(matches!(
        ticket.complete(event).unwrap().unwrap_err().as_ref(),
        OutboundArtifactChainHeadFailure::Transport(request_response::OutboundFailure::Timeout)
    ));
}

#[test]
fn successful_event_holds_permit_until_ticket_completion_or_drop() {
    let head_peer = Keypair::generate_ed25519().public().to_peer_id();
    let other_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[head_peer, other_peer]);
    let request = ArtifactChainHeadRequest::new(chain_id(0x71));
    let ticket = network.request_chain_head(head_peer, request).unwrap();
    let budget = Arc::clone(&network.pending_budget);
    let other_permits = (1..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&budget).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 8);

    let head = block_id(0x72);
    let event = head_response_event(&mut network, ticket.request_id, head_peer, head.as_bytes());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 8);
    assert!(matches!(
        network.request_chain_head(other_peer, request),
        Err(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS,
        })
    ));

    let response = ticket.complete(event).unwrap().unwrap();
    assert_eq!(response.peer_id(), head_peer);
    assert_eq!(response.request(), request);
    assert_eq!(response.head_block_id(), Some(head));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 7);

    let ticket = network.request_chain_head(other_peer, request).unwrap();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 8);
    let event = head_response_event(&mut network, ticket.request_id, other_peer, &[]);
    drop(event);
    drop(ticket);
    drop(other_permits);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn start_precedence_and_ticket_drop_preserve_the_physical_request() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let request = ArtifactChainHeadRequest::new(chain_id(0x81));
    let mut network = test_network_for_peers(&[peer_id]);
    let budget = Arc::clone(&network.pending_budget);
    let permits = (0..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&budget).unwrap())
        .collect::<Vec<_>>();

    assert!(matches!(
        network.request_chain_head(unknown, request),
        Err(RequestStartError::UnknownPeer(actual)) if actual == unknown
    ));
    assert!(matches!(
        network.request_chain_head(peer_id, request),
        Err(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS,
        })
    ));
    drop(permits);

    let ticket = network.request_chain_head(peer_id, request).unwrap();
    let request_id = ticket.request_id;
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);
    assert!(matches!(
        network.request_chain_head(peer_id, request),
        Err(RequestStartError::AlreadyPending(actual)) if actual == peer_id
    ));
    drop(ticket);
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Head(request_id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let event = head_failure_event(
        &mut network,
        request_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    drop(event);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(matches!(
        network.request_chain_head(peer_id, request),
        Err(RequestStartError::PeerDisconnected(actual)) if actual == peer_id
    ));
}

async fn receive_head(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
    server_journal: &ArtifactChainJournal,
) -> OutboundArtifactChainHeadEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundChainHead(event) = event {
                        return event;
                    }
                }
                event = server.next_event() => match event {
                    NetworkEvent::InboundChainHeadRequest(inbound) => {
                        server
                            .respond_chain_head_from_journal(inbound, server_journal)
                            .unwrap();
                    }
                    NetworkEvent::InboundChainHeadFailure { error, .. } => {
                        panic!("inbound chain-head exchange failed: {error}");
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("artifact-chain-head exchange timed out")
}

#[tokio::test]
async fn source_bound_head_observations_never_mutate_either_journal() {
    let (mut client, mut server, _, server_peer_id) = connected_pair().await;
    let server_directory = TestDirectory::new("head-transport-server");
    let mut server_journal = create_journal(server_directory.path()).unwrap();
    let client_directory = TestDirectory::new("head-transport-client");
    let client_journal = create_journal(client_directory.path()).unwrap();
    let client_bytes = client_directory.journal_bytes();
    let client_head = client_journal.head_block_id().unwrap();
    let matching = ArtifactChainHeadRequest::new(server_journal.chain_id());

    let server_bytes = server_directory.journal_bytes();
    let virtual_genesis = server_journal.head_block_id().unwrap();
    let ticket = client.request_chain_head(server_peer_id, matching).unwrap();
    let event = receive_head(&mut client, &mut server, &server_journal).await;
    let response = ticket.complete(event).unwrap().unwrap();
    assert_eq!(response.peer_id(), server_peer_id);
    assert_eq!(response.request(), matching);
    assert_eq!(response.head_block_id(), Some(virtual_genesis));
    assert_eq!(server_directory.journal_bytes(), server_bytes);
    assert_eq!(client_directory.journal_bytes(), client_bytes);
    assert_eq!(client_journal.head_block_id().unwrap(), client_head);

    apply_fresh_blocks(&mut server_journal, [pairing_bytes()]);
    let current_head = server_journal.head_block_id().unwrap();
    let committed_server_bytes = server_directory.journal_bytes();
    let ticket = client.request_chain_head(server_peer_id, matching).unwrap();
    let event = receive_head(&mut client, &mut server, &server_journal).await;
    assert_eq!(
        ticket.complete(event).unwrap().unwrap().head_block_id(),
        Some(current_head)
    );
    assert_eq!(server_directory.journal_bytes(), committed_server_bytes);
    assert_eq!(client_directory.journal_bytes(), client_bytes);

    let mismatched = ArtifactChainHeadRequest::new(chain_id(0xff));
    assert_ne!(mismatched.chain_id(), server_journal.chain_id());
    let ticket = client
        .request_chain_head(server_peer_id, mismatched)
        .unwrap();
    let event = receive_head(&mut client, &mut server, &server_journal).await;
    let response = ticket.complete(event).unwrap().unwrap();
    assert_eq!(response.peer_id(), server_peer_id);
    assert_eq!(response.request(), mismatched);
    assert!(response.is_unavailable());
    assert_eq!(server_directory.journal_bytes(), committed_server_bytes);
    assert_eq!(client_directory.journal_bytes(), client_bytes);
    assert_eq!(client_journal.head_block_id().unwrap(), client_head);
}

#[tokio::test]
async fn head_and_block_exchanges_progress_bidirectionally_on_one_session() {
    let (mut network_a, mut network_b, peer_a, peer_b) = connected_pair().await;
    let directory_a = TestDirectory::new("mixed-head-block-a");
    let mut journal_a = create_journal(directory_a.path()).unwrap();
    apply_fresh_blocks(&mut journal_a, [pairing_bytes()]);
    let block_a_id = journal_a.head_block_id().unwrap();
    let block_a = *journal_a.block(block_a_id).unwrap().unwrap();
    let directory_b = TestDirectory::new("mixed-head-block-b");
    let journal_b = create_journal(directory_b.path()).unwrap();
    let expected_head_b = journal_b.head_block_id().unwrap();

    let head_request = ArtifactChainHeadRequest::new(journal_b.chain_id());
    let head_ticket = network_a.request_chain_head(peer_b, head_request).unwrap();
    let block_ticket = network_b
        .request_block(peer_a, ArtifactBlockRequest::new(block_a_id))
        .unwrap();
    let mut head_event = None;
    let mut block_event = None;
    let mut served_head = false;
    let mut served_block = false;
    timeout(Duration::from_secs(10), async {
        while head_event.is_none() || block_event.is_none() || !served_head || !served_block {
            tokio::select! {
                event = network_a.next_event(), if head_event.is_none() || !served_block => match event {
                    NetworkEvent::InboundBlockRequest(inbound) => {
                        network_a.respond_block_from_journal(inbound, &journal_a).unwrap();
                        served_block = true;
                    }
                    NetworkEvent::OutboundChainHead(event) => head_event = Some(event),
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("mixed inbound block exchange failed: {error}");
                    }
                    _ => {}
                },
                event = network_b.next_event(), if block_event.is_none() || !served_head => match event {
                    NetworkEvent::InboundChainHeadRequest(inbound) => {
                        network_b.respond_chain_head_from_journal(inbound, &journal_b).unwrap();
                        served_head = true;
                    }
                    NetworkEvent::OutboundBlock(event) => block_event = Some(event),
                    NetworkEvent::InboundChainHeadFailure { error, .. } => {
                        panic!("mixed inbound chain-head exchange failed: {error}");
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("mixed head and block exchange timed out");

    assert_eq!(
        head_ticket
            .complete(head_event.unwrap())
            .unwrap()
            .unwrap()
            .head_block_id(),
        Some(expected_head_b)
    );
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
