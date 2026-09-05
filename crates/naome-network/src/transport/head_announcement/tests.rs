use crate::transport::{ExchangeRequestId, PendingBudget};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_protocol::artifact_exchange::ArtifactRequest;
use naome_protocol::block_exchange::ArtifactBlockRequest;
use naome_protocol::chain_head_exchange::ArtifactChainHeadRequest;
use tokio::time::timeout;

use super::*;
use crate::codec::ArtifactChainHeadAnnouncementReceipt;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, connected_pair, create_journal,
    pairing_bytes, snapshot, test_network_for_peers, union_bytes,
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

fn announcement_receipt_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
) -> OutboundArtifactChainHeadAnnouncementEvent {
    let event = network
        .handle_head_announcement_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_000),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactChainHeadAnnouncementReceipt,
            },
        })
        .expect("the retained announcement produces one terminal event");
    let NetworkEvent::OutboundChainHeadAnnouncement(event) = event else {
        panic!("announcement receipt did not produce its outbound terminal")
    };
    event
}

fn announcement_failure_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> OutboundArtifactChainHeadAnnouncementEvent {
    let event = network
        .handle_head_announcement_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_001),
            request_id,
            error,
        })
        .expect("the retained announcement produces one terminal event");
    let NetworkEvent::OutboundChainHeadAnnouncement(event) = event else {
        panic!("announcement failure did not produce its outbound terminal")
    };
    event
}

#[test]
fn announcement_stream_and_application_budgets_remain_bounded() {
    assert_eq!(MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION, 2);
    assert_eq!(MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION, 1);
    assert_eq!(MAX_EXCHANGE_STREAMS_PER_CONNECTION, 8);
    assert_eq!(MAX_YAMUX_STREAMS_PER_CONNECTION, 8);
}

#[test]
fn tagged_request_ids_isolate_all_four_application_protocols() {
    let proof_peer = Keypair::generate_ed25519().public().to_peer_id();
    let block_peer = Keypair::generate_ed25519().public().to_peer_id();
    let head_peer = Keypair::generate_ed25519().public().to_peer_id();
    let announcement_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network =
        test_network_for_peers(&[proof_peer, block_peer, head_peer, announcement_peer]);
    let directory = TestDirectory::new("announcement-tagged-namespaces");
    let journal = create_journal(directory.path()).unwrap();

    let proof_id = network
        .request_artifact(proof_peer, artifact_request(0x11))
        .unwrap();
    let block_ticket = network
        .request_block(block_peer, ArtifactBlockRequest::new(block_id(0x22)))
        .unwrap();
    let head_ticket = network
        .request_chain_head(head_peer, ArtifactChainHeadRequest::new(chain_id(0x33)))
        .unwrap();
    let announcement_ticket = network
        .announce_chain_head_from_journal(announcement_peer, &journal)
        .unwrap();
    let block_request_id = network
        .pending
        .keys()
        .find_map(|request_id| match request_id {
            ExchangeRequestId::Block(request_id) => Some(*request_id),
            _ => None,
        })
        .unwrap();
    let head_request_id = network
        .pending
        .keys()
        .find_map(|request_id| match request_id {
            ExchangeRequestId::Head(request_id) => Some(*request_id),
            _ => None,
        })
        .unwrap();

    assert_eq!(proof_id, block_request_id);
    assert_eq!(proof_id, head_request_id);
    assert_eq!(proof_id, announcement_ticket.request_id);
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
            .contains_key(&ExchangeRequestId::Head(head_request_id))
    );
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Announcement(
                announcement_ticket.request_id
            ))
    );
    assert_eq!(network.pending.len(), 4);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 4);

    let event = announcement_receipt_event(
        &mut network,
        announcement_ticket.request_id,
        announcement_peer,
    );
    assert_eq!(network.pending.len(), 3);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 4);
    let receipt = announcement_ticket.complete(event).unwrap().unwrap();
    assert_eq!(receipt.peer_id(), announcement_peer);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 3);

    for key in [
        ExchangeRequestId::Artifact(proof_id),
        ExchangeRequestId::Block(block_request_id),
        ExchangeRequestId::Head(head_request_id),
    ] {
        drop(network.pending.remove(&key).unwrap());
    }
    drop(block_ticket);
    drop(head_ticket);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn start_snapshots_the_healthy_journal_before_network_progress() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let directory = TestDirectory::new("announcement-snapshot");
    let mut journal = create_journal(directory.path()).unwrap();
    apply_fresh_blocks(&mut journal, [pairing_bytes()]);
    let captured_head = journal.head_block_id().unwrap();

    let ticket = network
        .announce_chain_head_from_journal(peer_id, &journal)
        .unwrap();
    assert_eq!(ticket.peer_id(), peer_id);
    assert_eq!(ticket.announcement().chain_id(), journal.chain_id());
    assert_eq!(ticket.announcement().head_block_id(), captured_head);

    apply_fresh_blocks(&mut journal, [union_bytes()]);
    assert_ne!(journal.head_block_id().unwrap(), captured_head);
    assert_eq!(ticket.announcement().head_block_id(), captured_head);

    let request_id = ticket.request_id;
    let event = announcement_receipt_event(&mut network, request_id, peer_id);
    let receipt = ticket.complete(event).unwrap().unwrap();
    assert_eq!(receipt.announcement().head_block_id(), captured_head);
    assert_ne!(
        receipt.announcement().head_block_id(),
        journal.head_block_id().unwrap()
    );

    assert!(matches!(
        network.announce_chain_head_from_journal(unknown, &journal),
        Err(HeadAnnouncementStartError::RequestStart(RequestStartError::UnknownPeer(actual)))
            if actual == unknown
    ));
}

#[test]
fn start_precedence_and_ticket_drop_preserve_bounded_physical_state() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let directory = TestDirectory::new("announcement-start-precedence");
    let journal = create_journal(directory.path()).unwrap();
    let budget = Arc::clone(&network.pending_budget);
    let permits = (0..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&budget).unwrap())
        .collect::<Vec<_>>();

    assert!(matches!(
        network.announce_chain_head_from_journal(unknown, &journal),
        Err(HeadAnnouncementStartError::RequestStart(RequestStartError::UnknownPeer(actual)))
            if actual == unknown
    ));
    assert!(matches!(
        network.announce_chain_head_from_journal(peer_id, &journal),
        Err(HeadAnnouncementStartError::RequestStart(
            RequestStartError::GlobalLimit {
                maximum: MAX_PENDING_REQUESTS,
            }
        ))
    ));
    drop(permits);

    let ticket = network
        .announce_chain_head_from_journal(peer_id, &journal)
        .unwrap();
    let request_id = ticket.request_id;
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);
    assert!(matches!(
        network.announce_chain_head_from_journal(peer_id, &journal),
        Err(HeadAnnouncementStartError::RequestStart(RequestStartError::AlreadyPending(actual)))
            if actual == peer_id
    ));
    drop(ticket);
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::Announcement(request_id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let event = announcement_failure_event(
        &mut network,
        request_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    drop(event);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(matches!(
        network.announce_chain_head_from_journal(peer_id, &journal),
        Err(HeadAnnouncementStartError::RequestStart(RequestStartError::PeerDisconnected(actual)))
            if actual == peer_id
    ));
}

#[test]
fn ticket_rejects_other_network_and_late_generation_without_losing_values() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let directory = TestDirectory::new("announcement-generation");
    let journal = create_journal(directory.path()).unwrap();
    let mut first = test_network_for_peers(&[peer_id]);
    let mut second = test_network_for_peers(&[peer_id]);
    let first_ticket = first
        .announce_chain_head_from_journal(peer_id, &journal)
        .unwrap();
    let second_ticket = second
        .announce_chain_head_from_journal(peer_id, &journal)
        .unwrap();
    assert_eq!(first_ticket.request_id, second_ticket.request_id);
    assert_eq!(first_ticket.announcement(), second_ticket.announcement());

    let second_event = announcement_receipt_event(&mut second, second_ticket.request_id, peer_id);
    assert!(!first_ticket.accepts_event(&second_event));
    let mismatch = first_ticket.complete(second_event).unwrap_err();
    let (first_ticket, second_event) = (*mismatch).into_parts();
    assert!(second_ticket.accepts_event(&second_event));
    let _ = second_ticket.complete(second_event).unwrap().unwrap();
    drop(
        first
            .pending
            .remove(&ExchangeRequestId::Announcement(first_ticket.request_id))
            .unwrap(),
    );

    let old_ticket = first
        .announce_chain_head_from_journal(peer_id, &journal)
        .unwrap();
    let old_event = announcement_receipt_event(&mut first, old_ticket.request_id, peer_id);
    let current_ticket = first
        .announce_chain_head_from_journal(peer_id, &journal)
        .unwrap();
    assert_ne!(old_ticket.request_id, current_ticket.request_id);
    assert!(!current_ticket.accepts_event(&old_event));
    let mismatch = current_ticket.complete(old_event).unwrap_err();
    let (current_ticket, old_event) = (*mismatch).into_parts();
    assert!(old_ticket.accepts_event(&old_event));
    let _ = old_ticket.complete(old_event).unwrap().unwrap();
    drop(
        first
            .pending
            .remove(&ExchangeRequestId::Announcement(current_ticket.request_id))
            .unwrap(),
    );
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn peer_mismatch_precedes_receipt_or_transport_and_failures_release_permits() {
    let expected = Keypair::generate_ed25519().public().to_peer_id();
    let actual = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[expected, actual]);
    let directory = TestDirectory::new("announcement-peer-precedence");
    let journal = create_journal(directory.path()).unwrap();

    let ticket = network
        .announce_chain_head_from_journal(expected, &journal)
        .unwrap();
    let event = announcement_receipt_event(&mut network, ticket.request_id, actual);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(matches!(
        ticket.complete(event).unwrap().unwrap_err().as_ref(),
        OutboundArtifactChainHeadAnnouncementFailure::PeerMismatch {
            expected: retained,
            actual: received,
        } if *retained == expected && *received == actual
    ));

    let ticket = network
        .announce_chain_head_from_journal(expected, &journal)
        .unwrap();
    let event = announcement_failure_event(
        &mut network,
        ticket.request_id,
        actual,
        request_response::OutboundFailure::Timeout,
    );
    assert!(matches!(
        ticket.complete(event).unwrap().unwrap_err().as_ref(),
        OutboundArtifactChainHeadAnnouncementFailure::PeerMismatch {
            expected: retained,
            actual: received,
        } if *retained == expected && *received == actual
    ));

    let ticket = network
        .announce_chain_head_from_journal(expected, &journal)
        .unwrap();
    let event = announcement_failure_event(
        &mut network,
        ticket.request_id,
        expected,
        request_response::OutboundFailure::Timeout,
    );
    assert!(matches!(
        ticket.complete(event).unwrap().unwrap_err().as_ref(),
        OutboundArtifactChainHeadAnnouncementFailure::Transport(
            request_response::OutboundFailure::Timeout
        )
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn unsupported_protocol_is_an_ordinary_source_bound_terminal() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let directory = TestDirectory::new("announcement-unsupported-protocol");
    let journal = create_journal(directory.path()).unwrap();
    let ticket = network
        .announce_chain_head_from_journal(peer_id, &journal)
        .unwrap();

    let event = announcement_failure_event(
        &mut network,
        ticket.request_id,
        peer_id,
        request_response::OutboundFailure::UnsupportedProtocols,
    );

    assert!(ticket.accepts_event(&event));
    assert!(matches!(
        ticket.complete(event).unwrap().unwrap_err().as_ref(),
        OutboundArtifactChainHeadAnnouncementFailure::Transport(
            request_response::OutboundFailure::UnsupportedProtocols
        )
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn successful_terminal_holds_its_shared_permit_until_completion_or_drop() {
    let announcement_peer = Keypair::generate_ed25519().public().to_peer_id();
    let other_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[announcement_peer, other_peer]);
    let directory = TestDirectory::new("announcement-permit");
    let journal = create_journal(directory.path()).unwrap();
    let ticket = network
        .announce_chain_head_from_journal(announcement_peer, &journal)
        .unwrap();
    let budget = Arc::clone(&network.pending_budget);
    let other_permits = (1..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&budget).unwrap())
        .collect::<Vec<_>>();
    let event = announcement_receipt_event(&mut network, ticket.request_id, announcement_peer);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 8);
    assert!(matches!(
        network.announce_chain_head_from_journal(other_peer, &journal),
        Err(HeadAnnouncementStartError::RequestStart(
            RequestStartError::GlobalLimit {
                maximum: MAX_PENDING_REQUESTS,
            }
        ))
    ));

    let receipt = ticket.complete(event).unwrap().unwrap();
    assert_eq!(receipt.peer_id(), announcement_peer);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 7);
    let ticket = network
        .announce_chain_head_from_journal(other_peer, &journal)
        .unwrap();
    let event = announcement_receipt_event(&mut network, ticket.request_id, other_peer);
    drop(event);
    drop(ticket);
    drop(other_permits);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn one_held_announcement_stream_blocks_the_opposite_direction() {
    let (mut sender, mut receiver, sender_peer_id, receiver_peer_id) = connected_pair().await;
    let sender_directory = TestDirectory::new("announcement-stream-cap-sender");
    let sender_journal = create_journal(sender_directory.path()).unwrap();
    let receiver_directory = TestDirectory::new("announcement-stream-cap-receiver");
    let receiver_journal = create_journal(receiver_directory.path()).unwrap();
    let first_ticket = sender
        .announce_chain_head_from_journal(receiver_peer_id, &sender_journal)
        .unwrap();

    let first_inbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = sender.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(event) = event {
                        panic!("first announcement became terminal before acknowledgement: {event:?}")
                    }
                },
                event = receiver.next_event() => {
                    if let NetworkEvent::InboundChainHeadAnnouncement(inbound) = event {
                        assert_eq!(inbound.peer_id(), sender_peer_id);
                        assert_eq!(inbound.announcement(), first_ticket.announcement());
                        break inbound;
                    }
                },
            }
        }
    })
    .await
    .expect("first announcement did not reach the receiver");

    let opposite_ticket = receiver
        .announce_chain_head_from_journal(sender_peer_id, &receiver_journal)
        .unwrap();
    let opposite_terminal = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = sender.next_event() => match event {
                    NetworkEvent::InboundChainHeadAnnouncement(inbound) => {
                        panic!(
                            "opposite announcement bypassed the occupied stream cap: {:?}",
                            inbound.announcement()
                        )
                    }
                    NetworkEvent::OutboundChainHeadAnnouncement(event) => {
                        panic!("held first announcement became terminal unexpectedly: {event:?}")
                    }
                    _ => {}
                },
                event = receiver.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(event) = event {
                        break event;
                    }
                },
            }
        }
    })
    .await
    .expect("opposite announcement did not reach its bounded terminal");

    assert!(opposite_ticket.accepts_event(&opposite_terminal));
    assert!(matches!(
        opposite_ticket
            .complete(opposite_terminal)
            .unwrap()
            .unwrap_err()
            .as_ref(),
        OutboundArtifactChainHeadAnnouncementFailure::Transport(
            request_response::OutboundFailure::Io(_)
        )
    ));

    receiver
        .acknowledge_chain_head_announcement(first_inbound)
        .unwrap();
    let first_terminal = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = sender.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(event) = event {
                        break event;
                    }
                },
                _ = receiver.next_event() => {}
            }
        }
    })
    .await
    .expect("held first announcement did not complete after acknowledgement");

    let receipt = first_ticket.complete(first_terminal).unwrap().unwrap();
    assert_eq!(receipt.peer_id(), receiver_peer_id);
}

#[tokio::test]
async fn explicit_receipt_is_source_bound_snapshotted_and_journal_neutral() {
    let (mut sender, mut receiver, _, receiver_peer_id) = connected_pair().await;
    let sender_directory = TestDirectory::new("announcement-e2e-sender");
    let mut sender_journal = create_journal(sender_directory.path()).unwrap();
    apply_fresh_blocks(&mut sender_journal, [pairing_bytes()]);
    let announced_head = sender_journal.head_block_id().unwrap();
    let receiver_directory = TestDirectory::new("announcement-e2e-receiver");
    let mut receiver_journal = create_journal(receiver_directory.path()).unwrap();
    apply_fresh_blocks(&mut receiver_journal, [union_bytes()]);
    let receiver_before = snapshot(&receiver_directory, &receiver_journal);

    let ticket = sender
        .announce_chain_head_from_journal(receiver_peer_id, &sender_journal)
        .unwrap();
    let announcement = ticket.announcement();
    assert_eq!(announcement.chain_id(), sender_journal.chain_id());
    assert_eq!(announcement.head_block_id(), announced_head);

    apply_fresh_blocks(&mut sender_journal, [union_bytes()]);
    let sender_after_append = snapshot(&sender_directory, &sender_journal);
    assert_ne!(sender_after_append.head, announced_head);

    let outbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = sender.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(event) = event {
                        break event;
                    }
                },
                event = receiver.next_event() => match event {
                    NetworkEvent::InboundChainHeadAnnouncement(inbound) => {
                        assert_eq!(inbound.peer_id(), sender.local_peer_id());
                        assert_eq!(inbound.announcement(), announcement);
                        receiver.acknowledge_chain_head_announcement(inbound).unwrap();
                    }
                    NetworkEvent::InboundChainHeadAnnouncementFailure { error, .. } => {
                        panic!("inbound announcement failed: {error}")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("head announcement timed out");

    assert!(ticket.accepts_event(&outbound));
    let receipt = ticket.complete(outbound).unwrap().unwrap();
    assert_eq!(receipt.peer_id(), receiver_peer_id);
    assert_eq!(receipt.announcement(), announcement);
    assert_snapshot(&sender_directory, &sender_journal, &sender_after_append);
    assert_snapshot(&receiver_directory, &receiver_journal, &receiver_before);
}

#[tokio::test]
async fn declining_an_inbound_announcement_yields_no_receipt_or_state_change() {
    let (mut sender, mut receiver, _, receiver_peer_id) = connected_pair().await;
    let sender_directory = TestDirectory::new("announcement-decline-sender");
    let sender_journal = create_journal(sender_directory.path()).unwrap();
    let sender_before = snapshot(&sender_directory, &sender_journal);
    let receiver_directory = TestDirectory::new("announcement-decline-receiver");
    let receiver_journal = create_journal(receiver_directory.path()).unwrap();
    let receiver_before = snapshot(&receiver_directory, &receiver_journal);
    let ticket = sender
        .announce_chain_head_from_journal(receiver_peer_id, &sender_journal)
        .unwrap();

    let outbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = sender.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(event) = event {
                        break event;
                    }
                },
                event = receiver.next_event() => {
                    if let NetworkEvent::InboundChainHeadAnnouncement(inbound) = event {
                        assert_eq!(inbound.announcement(), ticket.announcement());
                        drop(inbound);
                    }
                },
            }
        }
    })
    .await
    .expect("declined announcement did not become terminal");

    assert!(matches!(
        ticket.complete(outbound).unwrap().unwrap_err().as_ref(),
        OutboundArtifactChainHeadAnnouncementFailure::Transport(_)
    ));
    assert_snapshot(&sender_directory, &sender_journal, &sender_before);
    assert_snapshot(&receiver_directory, &receiver_journal, &receiver_before);
}
