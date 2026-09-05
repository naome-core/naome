use crate::ArtifactBlockCandidateRetentionError;
use crate::transport::{ExchangeRequestId, PendingBudget};
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome_chain::{ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockDecodeError, ArtifactBlockId};
use naome_protocol::artifact_exchange::{ArtifactRequest, ArtifactResponse};
use naome_protocol::block_exchange::{
    ARTIFACT_BLOCK_RESPONSE_MAX_BYTES, ArtifactBlockExchangeWireError, ArtifactBlockRequest,
};
use naome_storage::ArtifactBlockCandidateStoreLimits;
use tokio::time::timeout;

use super::*;
use crate::codec::ArtifactBlockWireResponse;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, connected_pair, create_journal,
    pairing_bytes, snapshot, test_chain_definition, test_network_for_peers, union_bytes,
};
use crate::{
    INBOUND_APPLICATION_REQUEST_BURST, Keypair, MAX_PENDING_REQUESTS, NetworkEvent,
    RequestStartError,
};

fn block_id(byte: u8) -> ArtifactBlockId {
    ArtifactBlockId::from_bytes([byte; 32])
}

fn artifact_request(byte: u8) -> ArtifactRequest {
    ArtifactRequest::from_wire_bytes(&[byte; 32]).unwrap()
}

fn block_response_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> OutboundArtifactBlockEvent {
    let event = network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(800),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactBlockWireResponse::new(bytes),
            },
        })
        .expect("the retained block request produces one terminal event");
    let NetworkEvent::OutboundBlock(event) = event else {
        panic!("block response did not produce an outbound block terminal");
    };
    event
}

fn block_failure_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> OutboundArtifactBlockEvent {
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

    let artifact_request_id = network
        .request_artifact(proof_peer, artifact_request(0x11))
        .unwrap();
    let block_ticket = network
        .request_block(block_peer, ArtifactBlockRequest::new(block_id(0x22)))
        .unwrap();

    assert_eq!(artifact_request_id, block_ticket.request_id);
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Artifact(artifact_request_id))
    );
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Block(block_ticket.request_id))
    );
    assert_eq!(network.pending.len(), 2);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

    let proof_event = network
        .handle_artifact_exchange_event(request_response::Event::Message {
            peer: proof_peer,
            connection_id: ConnectionId::new_unchecked(799),
            message: request_response::Message::Response {
                request_id: artifact_request_id,
                response: ArtifactResponse::from_wire_bytes(pairing_bytes()).unwrap(),
            },
        })
        .expect("the tagged proof terminal remains independently routable");
    assert!(
        !network
            .pending
            .contains_key(&ExchangeRequestId::Artifact(artifact_request_id))
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
    let request = ArtifactBlockRequest::new(block_id(0x31));
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
    let request = ArtifactBlockRequest::new(block_id(0x32));
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
        .request_block(expected, ArtifactBlockRequest::new(block_id(0x41)))
        .unwrap();
    let event = block_response_event(&mut network, ticket.request_id, actual, vec![0xff]);

    let failure = ticket.complete(event).unwrap().unwrap_err();
    assert!(matches!(
        failure.as_ref(),
        OutboundArtifactBlockFailure::PeerMismatch {
            expected: retained,
            actual: received,
        } if *retained == expected && *received == actual
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let failure_ticket = network
        .request_block(expected, ArtifactBlockRequest::new(block_id(0x42)))
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
        OutboundArtifactBlockFailure::PeerMismatch {
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
        .to_canonical_bytes()
        .to_vec();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let requested_block_id = block_id(0x49);
    let wrong_id_ticket = network
        .request_block(peer_id, ArtifactBlockRequest::new(requested_block_id))
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
        OutboundArtifactBlockFailure::InvalidResponse {
            source: ArtifactBlockExchangeWireError::BlockIdMismatch { expected, actual },
        } if *expected == requested_block_id && *actual == actual_block_id
    ));

    for actual in 1..ARTIFACT_BLOCK_RESPONSE_MAX_BYTES {
        let malformed_ticket = network
            .request_block(peer_id, ArtifactBlockRequest::new(actual_block_id))
            .unwrap();
        let malformed_event = block_response_event(
            &mut network,
            malformed_ticket.request_id,
            peer_id,
            vec![0xff; actual],
        );
        let malformed = malformed_ticket
            .complete(malformed_event)
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            malformed.as_ref(),
            OutboundArtifactBlockFailure::InvalidResponse {
                source: ArtifactBlockExchangeWireError::BlockDecode {
                    source: ArtifactBlockDecodeError::InvalidLength {
                        actual: error_actual,
                        expected,
                    },
                },
            } if *error_actual == actual && *expected == ARTIFACT_BLOCK_BYTES
        ));
    }
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn physical_failure_releases_the_permit_and_unknown_late_events_are_ignored() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let ticket = network
        .request_block(peer_id, ArtifactBlockRequest::new(block_id(0x4a)))
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
        OutboundArtifactBlockFailure::Transport(request_response::OutboundFailure::Timeout)
    ));

    assert!(
        network
            .handle_block_exchange_event(request_response::Event::Message {
                peer: peer_id,
                connection_id: ConnectionId::new_unchecked(802),
                message: request_response::Message::Response {
                    request_id,
                    response: ArtifactBlockWireResponse::new(Vec::new()),
                },
            })
            .is_none()
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn candidate_retention_routes_before_store_access_and_maps_terminal_failures() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let request = ArtifactBlockRequest::new(block_id(0x4b));
    let mut first = test_network_for_peers(&[peer_id]);
    let mut second = test_network_for_peers(&[peer_id]);
    let first_ticket = first.request_block(peer_id, request).unwrap();
    let second_ticket = second.request_block(peer_id, request).unwrap();
    let second_event =
        block_response_event(&mut second, second_ticket.request_id, peer_id, Vec::new());
    let store_directory = TestDirectory::new("candidate-routing");
    let mut store = ArtifactBlockCandidateStore::create(
        store_directory.path(),
        test_chain_definition(),
        ArtifactBlockCandidateStoreLimits::new(1).unwrap(),
    )
    .unwrap();

    let mismatch = first_ticket
        .complete_into_candidate_store(second_event, &mut store)
        .unwrap_err();
    assert!(store.is_empty().unwrap());
    let (first_ticket, second_event) = (*mismatch).into_parts();
    let unavailable = second_ticket
        .complete_into_candidate_store(second_event, &mut store)
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        &unavailable,
        ArtifactBlockCandidateRetentionError::BlockUnavailable {
            peer_id: actual_peer,
            block_id: actual_block,
        } if *actual_peer == peer_id && *actual_block == request.block_id()
    ));
    assert!(unavailable.source().is_none());
    assert!(store.is_empty().unwrap());

    let failure_event = block_failure_event(
        &mut first,
        first_ticket.request_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    let failure = first_ticket
        .complete_into_candidate_store(failure_event, &mut store)
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        &failure,
        ArtifactBlockCandidateRetentionError::RequestFailed {
            peer_id: actual_peer,
            block_id: actual_block,
            source,
        } if *actual_peer == peer_id
            && *actual_block == request.block_id()
            && matches!(
                source.as_ref(),
                OutboundArtifactBlockFailure::Transport(
                    request_response::OutboundFailure::Timeout
                )
            )
    ));
    assert!(failure.source().is_some());
    assert!(store.is_empty().unwrap());
}

#[test]
fn candidate_retention_is_idempotent_and_preserves_store_failures() {
    let first_block = ArtifactBlock::from_canonical_bytes(&[0x11; ARTIFACT_BLOCK_BYTES]).unwrap();
    let first_block_id = first_block.id();
    let second_block = ArtifactBlock::from_canonical_bytes(&[0x22; ARTIFACT_BLOCK_BYTES]).unwrap();
    let second_block_id = second_block.id();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let store_directory = TestDirectory::new("candidate-retention-store");
    let mut store = ArtifactBlockCandidateStore::create(
        store_directory.path(),
        test_chain_definition(),
        ArtifactBlockCandidateStoreLimits::new(1).unwrap(),
    )
    .unwrap();

    for expected in [
        ArtifactBlockCandidateInsertOutcome::Inserted,
        ArtifactBlockCandidateInsertOutcome::AlreadyPresent,
    ] {
        let ticket = network
            .request_block(peer_id, ArtifactBlockRequest::new(first_block_id))
            .unwrap();
        let event = block_response_event(
            &mut network,
            ticket.request_id,
            peer_id,
            first_block.to_canonical_bytes().to_vec(),
        );
        assert_eq!(
            ticket
                .complete_into_candidate_store(event, &mut store)
                .unwrap()
                .unwrap(),
            expected
        );
    }

    let full_ticket = network
        .request_block(peer_id, ArtifactBlockRequest::new(second_block_id))
        .unwrap();
    let full_event = block_response_event(
        &mut network,
        full_ticket.request_id,
        peer_id,
        second_block.to_canonical_bytes().to_vec(),
    );
    let full = full_ticket
        .complete_into_candidate_store(full_event, &mut store)
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        &full,
        ArtifactBlockCandidateRetentionError::CandidateStore {
            block_id,
            source,
        } if *block_id == second_block_id
            && matches!(
                source.as_ref(),
                ArtifactBlockCandidateStoreError::EntryLimitExceeded {
                    actual: 2,
                    maximum: 1,
                }
            )
    ));
    assert!(full.source().is_some());
    assert_eq!(store.len().unwrap(), 1);
}

#[test]
fn dropping_a_ticket_does_not_cancel_or_release_its_physical_request() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let ticket = network
        .request_block(peer_id, ArtifactBlockRequest::new(block_id(0x4b)))
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
        network.request_block(unknown, ArtifactBlockRequest::new(block_id(0x4c))),
        Err(RequestStartError::UnknownPeer(actual)) if actual == unknown
    ));
    assert!(matches!(
        network.request_block(peer_id, ArtifactBlockRequest::new(block_id(0x4d))),
        Err(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS,
        })
    ));
    drop(permits);

    let ticket = network
        .request_block(peer_id, ArtifactBlockRequest::new(block_id(0x4e)))
        .unwrap();
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);
    assert!(matches!(
        network.request_block(peer_id, ArtifactBlockRequest::new(block_id(0x4f))),
        Err(RequestStartError::AlreadyPending(actual)) if actual == peer_id
    ));
    drop(network.remove_pending_block(ticket.request_id).unwrap());
    assert!(matches!(
        network.request_block(peer_id, ArtifactBlockRequest::new(block_id(0x50))),
        Err(RequestStartError::PeerDisconnected(actual)) if actual == peer_id
    ));
}

#[test]
fn proof_and_block_requests_share_each_peer_slot() {
    let block_peer = Keypair::generate_ed25519().public().to_peer_id();
    let proof_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[block_peer, proof_peer]);

    let block_ticket = network
        .request_block(block_peer, ArtifactBlockRequest::new(block_id(0x51)))
        .unwrap();
    assert_eq!(
        network.request_artifact(block_peer, artifact_request(0x52)),
        Err(RequestStartError::AlreadyPending(block_peer))
    );

    let artifact_request_id = network
        .request_artifact(proof_peer, artifact_request(0x53))
        .unwrap();
    assert!(matches!(
        network.request_block(
            proof_peer,
            ArtifactBlockRequest::new(block_id(0x54)),
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
    drop(
        network
            .remove_pending_artifact(artifact_request_id)
            .unwrap(),
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn successful_block_event_holds_the_shared_global_permit_until_completion() {
    let block_peer = Keypair::generate_ed25519().public().to_peer_id();
    let proof_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[block_peer, proof_peer]);
    let block_ticket = network
        .request_block(block_peer, ArtifactBlockRequest::new(block_id(0x61)))
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
        network.request_artifact(proof_peer, artifact_request(0x62)),
        Err(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS,
        })
    );

    drop(block_ticket.complete(event).unwrap().unwrap());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 7);
    let artifact_request_id = network
        .request_artifact(proof_peer, artifact_request(0x63))
        .unwrap();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 8);
    drop(
        network
            .remove_pending_artifact(artifact_request_id)
            .unwrap(),
    );
    drop(other_permits);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

async fn receive_block_with(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
    mut respond: impl FnMut(
        &mut StaticArtifactNetwork,
        InboundArtifactBlockRequest,
    ) -> Result<(), RespondError>,
) -> OutboundArtifactBlockEvent {
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
                        respond(server, inbound).unwrap();
                    }
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("inbound artifact-block exchange failed: {error}");
                    }
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("artifact-block exchange timed out")
}

async fn receive_inbound_block_request(
    client: &mut StaticArtifactNetwork,
    server: &mut StaticArtifactNetwork,
) -> InboundArtifactBlockRequest {
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    if let NetworkEvent::OutboundBlock(event) = event {
                        panic!("block request terminated before reaching the responder: {event:?}");
                    }
                }
                event = server.next_event() => {
                    if let NetworkEvent::InboundBlockRequest(inbound) = event {
                        return inbound;
                    }
                }
            }
        }
    })
    .await
    .expect("inbound artifact-block request timed out")
}

#[tokio::test]
async fn candidate_store_relay_is_exact_durable_and_never_selected() {
    let (mut relay, mut origin, _, origin_peer_id) = connected_pair().await;
    let origin_directory = TestDirectory::new("candidate-relay-origin");
    let mut origin_journal = create_journal(origin_directory.path()).unwrap();
    apply_fresh_blocks(&mut origin_journal, [pairing_bytes()]);
    let target_block_id = origin_journal.head_block_id().unwrap();
    let expected_block = *origin_journal.block(target_block_id).unwrap().unwrap();

    let relay_directory = TestDirectory::new("candidate-relay-store");
    let relay_journal = create_journal(relay_directory.path()).unwrap();
    let relay_selected = snapshot(&relay_directory, &relay_journal);
    let limits = ArtifactBlockCandidateStoreLimits::new(1).unwrap();
    let mut relay_store = ArtifactBlockCandidateStore::create(
        relay_directory.path(),
        test_chain_definition(),
        limits,
    )
    .unwrap();

    let ticket = relay
        .request_block(origin_peer_id, ArtifactBlockRequest::new(target_block_id))
        .unwrap();
    let event = receive_block_with(&mut relay, &mut origin, |origin, inbound| {
        origin.respond_block_from_journal(inbound, &origin_journal)
    })
    .await;
    assert_eq!(
        ticket
            .complete_into_candidate_store(event, &mut relay_store)
            .unwrap()
            .unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    assert_snapshot(&relay_directory, &relay_journal, &relay_selected);
    drop(relay_store);
    drop(relay);
    drop(origin);

    let mut reopened =
        ArtifactBlockCandidateStore::open(relay_directory.path(), test_chain_definition(), limits)
            .unwrap();

    let (mut downstream, mut relay_server, _, relay_peer_id) = connected_pair().await;
    let found_ticket = downstream
        .request_block(relay_peer_id, ArtifactBlockRequest::new(target_block_id))
        .unwrap();
    let found_event = receive_block_with(&mut downstream, &mut relay_server, |server, inbound| {
        server.respond_block_from_candidate_store(inbound, &mut reopened)
    })
    .await;
    assert_eq!(
        found_ticket
            .complete(found_event)
            .unwrap()
            .unwrap()
            .into_block(),
        Some(expected_block)
    );

    let unknown_id = block_id(0xff);
    let unavailable_ticket = downstream
        .request_block(relay_peer_id, ArtifactBlockRequest::new(unknown_id))
        .unwrap();
    let unavailable_event =
        receive_block_with(&mut downstream, &mut relay_server, |server, inbound| {
            server.respond_block_from_candidate_store(inbound, &mut reopened)
        })
        .await;
    assert!(
        unavailable_ticket
            .complete(unavailable_event)
            .unwrap()
            .unwrap()
            .is_unavailable()
    );
    assert_snapshot(&relay_directory, &relay_journal, &relay_selected);
}

#[tokio::test]
async fn candidate_store_read_failure_precedes_the_shared_response_budget() {
    let candidate = ArtifactBlock::from_canonical_bytes(&[0x33; ARTIFACT_BLOCK_BYTES]).unwrap();
    let candidate_id = candidate.id();
    let store_directory = TestDirectory::new("candidate-response-precedence");
    let mut store = ArtifactBlockCandidateStore::create(
        store_directory.path(),
        test_chain_definition(),
        ArtifactBlockCandidateStoreLimits::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.insert(&candidate).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );

    let (mut client, mut server, _, server_peer_id) = connected_pair().await;
    let ticket = client
        .request_block(server_peer_id, ArtifactBlockRequest::new(candidate_id))
        .unwrap();
    let inbound = receive_inbound_block_request(&mut client, &mut server).await;
    std::fs::OpenOptions::new()
        .write(true)
        .open(
            store_directory
                .path()
                .join("artifact-block-candidate-store.log"),
        )
        .unwrap()
        .set_len(0)
        .unwrap();
    for _ in 0..INBOUND_APPLICATION_REQUEST_BURST {
        server.take_inbound_application_request().unwrap();
    }
    assert!(matches!(
        server.take_inbound_application_request(),
        Err(RespondError::RateLimited)
    ));

    let error = server
        .respond_block_from_candidate_store(inbound, &mut store)
        .unwrap_err();
    let RespondError::CandidateStore(source) = &error else {
        panic!("candidate-store read failure lost its source: {error}");
    };
    assert!(matches!(
        source,
        ArtifactBlockCandidateStoreError::Read { .. }
    ));
    assert_eq!(
        error.to_string(),
        format!("cannot read artifact-block candidate store: {source}")
    );
    assert!(error.source().is_some());
    assert!(matches!(
        store.is_empty(),
        Err(ArtifactBlockCandidateStoreError::Poisoned)
    ));
    drop(ticket);
}

#[tokio::test]
async fn committed_block_found_and_unavailable_round_trip_without_client_mutation() {
    let (mut client, mut server, client_peer_id, server_peer_id) = connected_pair().await;
    let server_directory = TestDirectory::new("block-transport-server");
    let mut server_journal = create_journal(server_directory.path()).unwrap();
    apply_fresh_blocks(&mut server_journal, [pairing_bytes()]);
    let committed_block_id = server_journal.head_block_id().unwrap();
    let expected_block = *server_journal.block(committed_block_id).unwrap().unwrap();
    let virtual_genesis = expected_block.parent_block_id();

    let client_directory = TestDirectory::new("block-transport-client");
    let client_journal = create_journal(client_directory.path()).unwrap();
    let client_bytes = client_directory.journal_bytes();
    let client_head = client_journal.head_block_id().unwrap();

    let found_request = ArtifactBlockRequest::new(committed_block_id);
    let found_ticket = client.request_block(server_peer_id, found_request).unwrap();
    let found_event = receive_block_with(&mut client, &mut server, |server, inbound| {
        server.respond_block_from_journal(inbound, &server_journal)
    })
    .await;
    assert!(found_ticket.accepts_event(&found_event));
    let found = found_ticket.complete(found_event).unwrap().unwrap();
    assert_eq!(found.into_block(), Some(expected_block));
    assert_eq!(client.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(client_journal.head_block_id().unwrap(), client_head);
    assert_eq!(client_directory.journal_bytes(), client_bytes);

    let unavailable_request = ArtifactBlockRequest::new(virtual_genesis);
    let unavailable_ticket = client
        .request_block(server_peer_id, unavailable_request)
        .unwrap();
    let unavailable_event = receive_block_with(&mut client, &mut server, |server, inbound| {
        server.respond_block_from_journal(inbound, &server_journal)
    })
    .await;
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
        .request_block(client_peer_id, ArtifactBlockRequest::new(client_head))
        .unwrap();
    let reverse_event = receive_block_with(&mut server, &mut client, |client, inbound| {
        client.respond_block_from_journal(inbound, &client_journal)
    })
    .await;
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
    let block_a = *journal_a.block(block_a_id).unwrap().unwrap();
    let directory_b = TestDirectory::new("bidirectional-block-b");
    let mut journal_b = create_journal(directory_b.path()).unwrap();
    apply_fresh_blocks(&mut journal_b, [union_bytes()]);
    let block_b_id = journal_b.head_block_id().unwrap();
    let block_b = *journal_b.block(block_b_id).unwrap().unwrap();

    let ticket_a = network_a
        .request_block(peer_b, ArtifactBlockRequest::new(block_b_id))
        .unwrap();
    let ticket_b = network_b
        .request_block(peer_a, ArtifactBlockRequest::new(block_a_id))
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
async fn artifact_and_block_protocols_progress_concurrently_on_one_session() {
    let (mut network_a, mut network_b, peer_a, peer_b) = connected_pair().await;
    let directory_a = TestDirectory::new("mixed-exchange-a");
    let mut journal_a = create_journal(directory_a.path()).unwrap();
    apply_fresh_blocks(&mut journal_a, [pairing_bytes()]);
    let block_a_id = journal_a.head_block_id().unwrap();
    let block_a = *journal_a.block(block_a_id).unwrap().unwrap();
    let directory_b = TestDirectory::new("mixed-exchange-b");
    let mut journal_b = create_journal(directory_b.path()).unwrap();
    let artifact_b = apply_fresh_blocks(&mut journal_b, [pairing_bytes()])[0];

    network_a
        .request_artifact(peer_b, ArtifactRequest::new(artifact_b))
        .unwrap();
    let block_ticket = network_b
        .request_block(peer_a, ArtifactBlockRequest::new(block_a_id))
        .unwrap();
    let mut artifact_event = None;
    let mut block_event = None;
    let mut served_block = false;
    let mut served_artifact = false;
    timeout(Duration::from_secs(10), async {
        while artifact_event.is_none() || block_event.is_none() || !served_block || !served_artifact {
            tokio::select! {
                event = network_a.next_event(), if artifact_event.is_none() || !served_block => match event {
                    NetworkEvent::InboundBlockRequest(inbound) => {
                        network_a.respond_block_from_journal(inbound, &journal_a).unwrap();
                        served_block = true;
                    }
                    NetworkEvent::OutboundArtifact(event) => artifact_event = Some(event),
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("mixed inbound block exchange failed: {error}");
                    }
                    _ => {}
                },
                event = network_b.next_event(), if block_event.is_none() || !served_artifact => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        network_b
                            .respond_artifact_from_journal(inbound, &journal_b)
                            .unwrap();
                        served_artifact = true;
                    }
                    NetworkEvent::OutboundBlock(event) => block_event = Some(event),
                    NetworkEvent::InboundArtifactFailure { error, .. } => {
                        panic!("mixed inbound artifact exchange failed: {error}");
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("concurrent artifact and block exchange timed out");

    let artifact_event = artifact_event.unwrap();
    assert_eq!(artifact_event.peer_id(), peer_b);
    assert_eq!(artifact_event.request(), ArtifactRequest::new(artifact_b));
    assert!(artifact_event.failure().is_none());
    assert!(!artifact_event.is_deadline_exceeded());
    let crate::transport::OutboundArtifactOutcome::Response { response, .. } =
        &artifact_event.outcome
    else {
        panic!("artifact exchange did not return a response");
    };
    assert!(!response.is_unavailable());
    drop(artifact_event);

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
