use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use tokio::time::timeout;

use super::*;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, create_journal, pairing_bytes, snapshot,
    test_network_for_peers, union_bytes,
};
use crate::{
    InboundArtifactChainHeadAnnouncement, Keypair, MAX_PENDING_REQUESTS, Multiaddr, NetworkEvent,
    OutboundArtifactChainHeadAnnouncementEvent, PeerSessionEvent, RequestStartError, StaticPeer,
};

fn announcement_request_id(
    network: &StaticArtifactNetwork,
    peer_id: PeerId,
) -> request_response::OutboundRequestId {
    network
        .pending_announcement_for_peer_for_test(peer_id)
        .expect("the peer has one pending announcement")
        .0
}

fn receipt_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
) -> NetworkEvent {
    network
        .handle_head_announcement_event_for_test(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(2_000),
            message: request_response::Message::Response {
                request_id,
                response: (),
            },
        })
        .expect("the retained announcement produces one terminal event")
}

fn failure_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> NetworkEvent {
    network
        .handle_head_announcement_event_for_test(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(2_001),
            request_id,
            error,
        })
        .expect("the retained announcement produces one failure terminal")
}

fn awaiting(progress: ArtifactChainHeadBroadcastProgress) -> ArtifactChainHeadBroadcast {
    let ArtifactChainHeadBroadcastProgress::AwaitingReceipts(broadcast) = progress else {
        panic!("broadcast completed while selected peers remained pending")
    };
    broadcast
}

fn complete(progress: ArtifactChainHeadBroadcastProgress) -> CompletedArtifactChainHeadBroadcast {
    let ArtifactChainHeadBroadcastProgress::Complete(completed) = progress else {
        panic!("broadcast remained pending after every selected peer settled")
    };
    completed
}

fn into_announcement_event(event: NetworkEvent) -> OutboundArtifactChainHeadAnnouncementEvent {
    let NetworkEvent::OutboundChainHeadAnnouncement(event) = event else {
        panic!("expected an outbound chain-head announcement terminal")
    };
    event
}

fn loopback_address(port: u16) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

async fn listening_address(network: &mut StaticArtifactNetwork) -> Multiaddr {
    network.listen_on(loopback_address(0)).unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            match network.next_event().await {
                NetworkEvent::Listening { address } => return address,
                NetworkEvent::ListenerError { error, .. } => {
                    panic!("broadcast receiver listener failed: {error}")
                }
                NetworkEvent::ListenerClosed { reason, .. } => {
                    panic!("broadcast receiver listener closed: {reason:?}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("broadcast receiver listener did not start")
}

async fn acknowledge_and_receive_terminal(
    broadcaster: &mut StaticArtifactNetwork,
    receiver: &mut StaticArtifactNetwork,
    inbound: InboundArtifactChainHeadAnnouncement,
    expected_peer_id: PeerId,
) -> NetworkEvent {
    receiver
        .acknowledge_chain_head_announcement(inbound)
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = broadcaster.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(terminal) = &event {
                        assert_eq!(terminal.peer_id(), expected_peer_id);
                        return event;
                    }
                },
                event = receiver.next_event() => {
                    if let NetworkEvent::InboundChainHeadAnnouncementFailure { error, .. } = event {
                        panic!("acknowledged broadcast announcement failed inbound: {error}")
                    }
                },
            }
        }
    })
    .await
    .expect("acknowledged broadcast announcement did not become terminal")
}

#[test]
fn peer_shape_precedence_is_bounded_and_starts_nothing() {
    assert_eq!(MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS, MAX_STATIC_PEERS);

    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let directory = TestDirectory::new("head-broadcast-shape");
    let journal = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &journal);

    assert!(matches!(
        network.start_chain_head_broadcast_from_journal(&[], &journal),
        Err(ArtifactChainHeadBroadcastStartError::EmptyPeerSet)
    ));

    let oversized = vec![peer_id; MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS + 1];
    assert!(matches!(
        network.start_chain_head_broadcast_from_journal(&oversized, &journal),
        Err(ArtifactChainHeadBroadcastStartError::TooManyPeers {
            actual,
            maximum: MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS,
        }) if actual == MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS + 1
    ));

    assert!(matches!(
        network.start_chain_head_broadcast_from_journal(&[peer_id, peer_id], &journal),
        Err(ArtifactChainHeadBroadcastStartError::DuplicatePeer(actual)) if actual == peer_id
    ));

    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
    assert_snapshot(&directory, &journal, &before);
}

#[test]
fn failed_group_start_does_not_advance_the_transport_request_generation() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let directory = TestDirectory::new("head-broadcast-request-generation");
    let journal = create_journal(directory.path()).unwrap();
    let mut control = test_network_for_peers(&[peer_id]);
    let mut after_failure = test_network_for_peers(&[peer_id]);

    let control_broadcast = control
        .start_chain_head_broadcast_from_journal(&[peer_id], &journal)
        .unwrap();
    let control_id = announcement_request_id(&control, peer_id);

    assert!(matches!(
        after_failure.start_chain_head_broadcast_from_journal(&[peer_id, unknown], &journal),
        Err(ArtifactChainHeadBroadcastStartError::RequestStart(
            RequestStartError::UnknownPeer(actual)
        )) if actual == unknown
    ));
    assert!((after_failure.pending_count_for_test() == 0));
    assert_eq!(after_failure.active_permit_count_for_test(), 0);

    let after_failure_broadcast = after_failure
        .start_chain_head_broadcast_from_journal(&[peer_id], &journal)
        .unwrap();
    let after_failure_id = announcement_request_id(&after_failure, peer_id);
    assert_eq!(after_failure_id, control_id);

    let control_event = failure_event(
        &mut control,
        control_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    let _ = complete(control_broadcast.on_event(control_event).unwrap());
    let after_failure_event = failure_event(
        &mut after_failure,
        after_failure_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    let _ = complete(
        after_failure_broadcast
            .on_event(after_failure_event)
            .unwrap(),
    );
}

#[test]
fn ordered_peer_preflight_rejects_the_group_without_a_queued_prefix() {
    let first = Keypair::generate_ed25519().public().to_peer_id();
    let second = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let directory = TestDirectory::new("head-broadcast-peer-preflight");
    let journal = create_journal(directory.path()).unwrap();

    let mut unknown_network = test_network_for_peers(&[first]);
    assert!(matches!(
        unknown_network.start_chain_head_broadcast_from_journal(
            &[first, unknown, second],
            &journal,
        ),
        Err(ArtifactChainHeadBroadcastStartError::RequestStart(
            RequestStartError::UnknownPeer(actual)
        )) if actual == unknown
    ));
    assert!((unknown_network.pending_count_for_test() == 0));
    assert_eq!(unknown_network.active_permit_count_for_test(), 0);

    let mut disconnected_network = test_network_for_peers(&[first, second]);
    disconnected_network.mark_disconnected_for_test(second);
    assert!(matches!(
        disconnected_network
            .start_chain_head_broadcast_from_journal(&[first, second], &journal),
        Err(ArtifactChainHeadBroadcastStartError::RequestStart(
            RequestStartError::PeerDisconnected(actual)
        )) if actual == second
    ));
    assert!((disconnected_network.pending_count_for_test() == 0));
    assert_eq!(disconnected_network.active_permit_count_for_test(), 0);

    let mut occupied_network = test_network_for_peers(&[first, second]);
    let occupied = occupied_network
        .announce_chain_head_from_journal(second, &journal)
        .unwrap();
    let occupied_request_id = announcement_request_id(&occupied_network, second);
    assert!(matches!(
        occupied_network.start_chain_head_broadcast_from_journal(&[first, second], &journal),
        Err(ArtifactChainHeadBroadcastStartError::RequestStart(
            RequestStartError::AlreadyPending(actual)
        )) if actual == second
    ));
    assert_eq!(occupied_network.pending_count_for_test(), 1);
    assert_eq!(occupied_network.active_permit_count_for_test(), 1);
    let event = failure_event(
        &mut occupied_network,
        occupied_request_id,
        second,
        request_response::OutboundFailure::Timeout,
    );
    assert!(occupied.complete(into_announcement_event(event)).is_ok());
    assert!((occupied_network.pending_count_for_test() == 0));
    assert_eq!(occupied_network.active_permit_count_for_test(), 0);
}

#[test]
fn capacity_reservation_is_atomic_and_follows_peer_preflight() {
    let first = Keypair::generate_ed25519().public().to_peer_id();
    let second = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[first, second]);
    let directory = TestDirectory::new("head-broadcast-capacity");
    let journal = create_journal(directory.path()).unwrap();
    let retained = network.hold_pending_permits_for_test(MAX_PENDING_REQUESTS - 1);

    assert!(matches!(
        network.start_chain_head_broadcast_from_journal(&[first, unknown], &journal),
        Err(ArtifactChainHeadBroadcastStartError::RequestStart(
            RequestStartError::UnknownPeer(actual)
        )) if actual == unknown
    ));
    assert_eq!(network.active_permit_count_for_test(), 7);
    assert!((network.pending_count_for_test() == 0));

    assert!(matches!(
        network.start_chain_head_broadcast_from_journal(&[first, second], &journal),
        Err(ArtifactChainHeadBroadcastStartError::InsufficientCapacity {
            requested: 2,
            available: 1,
            maximum: MAX_PENDING_REQUESTS,
        })
    ));
    assert_eq!(network.active_permit_count_for_test(), 7);
    assert!((network.pending_count_for_test() == 0));

    drop(retained);
    assert_eq!(network.active_permit_count_for_test(), 0);
}

#[test]
fn reverse_order_mixed_terminals_preserve_snapshot_input_order_and_independence() {
    let peers = (0..3)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peers);
    let directory = TestDirectory::new("head-broadcast-mixed-order");
    let mut journal = create_journal(directory.path()).unwrap();
    apply_fresh_blocks(&mut journal, [pairing_bytes()]);
    let snapped_head = journal.head_block_id().unwrap();
    let mut broadcast = network
        .start_chain_head_broadcast_from_journal(&peers, &journal)
        .unwrap();
    let announcement = broadcast.announcement();
    let request_ids = peers
        .iter()
        .map(|&peer_id| announcement_request_id(&network, peer_id))
        .collect::<Vec<_>>();

    assert_eq!(broadcast.peer_count(), 3);
    assert_eq!(broadcast.pending_peer_count(), 3);
    assert_eq!(announcement.chain_id(), journal.chain_id());
    assert_eq!(announcement.head_block_id(), snapped_head);
    assert_eq!(network.pending_count_for_test(), 3);
    assert_eq!(network.active_permit_count_for_test(), 3);

    apply_fresh_blocks(&mut journal, [union_bytes()]);
    let journal_after_append = snapshot(&directory, &journal);
    assert_ne!(journal_after_append.head, snapped_head);
    assert_eq!(broadcast.announcement(), announcement);

    let last_receipt = receipt_event(&mut network, request_ids[2], peers[2]);
    assert!(broadcast.accepts_event(&last_receipt));
    assert_eq!(network.pending_count_for_test(), 2);
    assert_eq!(network.active_permit_count_for_test(), 3);
    broadcast = awaiting(broadcast.on_event(last_receipt).unwrap());
    assert_eq!(broadcast.pending_peer_count(), 2);
    assert_eq!(network.active_permit_count_for_test(), 2);

    let unrelated = NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id: peers[2] });
    let mismatch = broadcast.on_event(unrelated).unwrap_err();
    let (recovered, unrelated) = (*mismatch).into_parts();
    assert!(matches!(
        unrelated,
        NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id })
            if peer_id == peers[2]
    ));
    assert_eq!(recovered.peer_count(), 3);
    assert_eq!(recovered.pending_peer_count(), 2);
    broadcast = recovered;

    let first_failure = failure_event(
        &mut network,
        request_ids[0],
        peers[0],
        request_response::OutboundFailure::Timeout,
    );
    assert!(broadcast.accepts_event(&first_failure));
    assert_eq!(network.pending_count_for_test(), 1);
    assert_eq!(network.active_permit_count_for_test(), 1);
    broadcast = awaiting(broadcast.on_event(first_failure).unwrap());
    assert_eq!(broadcast.pending_peer_count(), 1);

    let middle_receipt = receipt_event(&mut network, request_ids[1], peers[1]);
    assert!(broadcast.accepts_event(&middle_receipt));
    let completed = complete(broadcast.on_event(middle_receipt).unwrap());
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
    assert_eq!(completed.announcement(), announcement);

    let (completed_announcement, results) = completed.into_parts();
    assert_eq!(completed_announcement, announcement);
    assert_eq!(
        results
            .iter()
            .map(|result| result.peer_id())
            .collect::<Vec<_>>(),
        peers
    );
    assert!(matches!(
        results[0].result(),
        Err(OutboundArtifactChainHeadAnnouncementFailure::Transport(
            request_response::OutboundFailure::Timeout
        ))
    ));
    assert!(results[1].result().is_ok());
    assert!(results[2].result().is_ok());
    let mut results = results.into_iter();
    assert!(matches!(
        results.next().unwrap().into_result(),
        Err(failure) if matches!(
            *failure,
            OutboundArtifactChainHeadAnnouncementFailure::Transport(
                request_response::OutboundFailure::Timeout
            )
        )
    ));
    assert!(results.next().unwrap().into_result().is_ok());
    assert!(results.next().unwrap().into_result().is_ok());
    assert!(results.next().is_none());
    assert_snapshot(&directory, &journal, &journal_after_append);
}

#[test]
fn unrelated_cross_network_and_late_generation_events_remain_routable() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let directory = TestDirectory::new("head-broadcast-event-routing");
    let journal = create_journal(directory.path()).unwrap();
    let mut first_network = test_network_for_peers(&[peer_id]);
    let mut second_network = test_network_for_peers(&[peer_id]);
    let first = first_network
        .start_chain_head_broadcast_from_journal(&[peer_id], &journal)
        .unwrap();
    let second = second_network
        .start_chain_head_broadcast_from_journal(&[peer_id], &journal)
        .unwrap();
    let first_id = announcement_request_id(&first_network, peer_id);
    let second_id = announcement_request_id(&second_network, peer_id);
    assert_eq!(first_id, second_id);

    let unrelated = NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id });
    assert!(!first.accepts_event(&unrelated));
    let mismatch = first.on_event(unrelated).unwrap_err();
    let (first, unrelated) = (*mismatch).into_parts();
    assert!(matches!(
        unrelated,
        NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id: actual })
            if actual == peer_id
    ));
    assert_eq!(first.pending_peer_count(), 1);

    let second_event = receipt_event(&mut second_network, second_id, peer_id);
    assert!(!first.accepts_event(&second_event));
    let mismatch = first.on_event(second_event).unwrap_err();
    let (first, second_event) = (*mismatch).into_parts();
    assert!(second.accepts_event(&second_event));
    let _ = complete(second.on_event(second_event).unwrap());

    let first_event = receipt_event(&mut first_network, first_id, peer_id);
    let _ = complete(first.on_event(first_event).unwrap());

    let old = first_network
        .start_chain_head_broadcast_from_journal(&[peer_id], &journal)
        .unwrap();
    let old_id = announcement_request_id(&first_network, peer_id);
    let old_event = receipt_event(&mut first_network, old_id, peer_id);
    let current = first_network
        .start_chain_head_broadcast_from_journal(&[peer_id], &journal)
        .unwrap();
    let current_id = announcement_request_id(&first_network, peer_id);
    assert_ne!(old_id, current_id);
    assert!(!current.accepts_event(&old_event));
    let mismatch = current.on_event(old_event).unwrap_err();
    let (current, old_event) = (*mismatch).into_parts();
    assert!(old.accepts_event(&old_event));
    let _ = complete(old.on_event(old_event).unwrap());

    let current_event = receipt_event(&mut first_network, current_id, peer_id);
    let _ = complete(current.on_event(current_event).unwrap());
    assert_eq!(first_network.active_permit_count_for_test(), 0);
    assert_eq!(second_network.active_permit_count_for_test(), 0);
}

#[test]
fn wrong_authenticated_peer_is_a_source_bound_row_failure() {
    let expected = Keypair::generate_ed25519().public().to_peer_id();
    let actual = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[expected, actual]);
    let directory = TestDirectory::new("head-broadcast-peer-mismatch");
    let journal = create_journal(directory.path()).unwrap();
    let broadcast = network
        .start_chain_head_broadcast_from_journal(&[expected], &journal)
        .unwrap();
    let request_id = announcement_request_id(&network, expected);

    let wrong_peer_receipt = receipt_event(&mut network, request_id, actual);
    assert!(broadcast.accepts_event(&wrong_peer_receipt));
    let completed = complete(broadcast.on_event(wrong_peer_receipt).unwrap());
    let [result] = completed.peer_results() else {
        panic!("one selected peer must produce exactly one result row")
    };
    assert_eq!(result.peer_id(), expected);
    assert!(matches!(
        result.result(),
        Err(OutboundArtifactChainHeadAnnouncementFailure::PeerMismatch {
            expected: retained,
            actual: received,
        }) if *retained == expected && *received == actual
    ));
    assert_eq!(network.active_permit_count_for_test(), 0);
}

#[test]
fn cancellation_leaves_every_physical_request_bounded_until_its_own_drain() {
    let peers = (0..MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peers);
    let directory = TestDirectory::new("head-broadcast-cancel-drain");
    let journal = create_journal(directory.path()).unwrap();
    let broadcast = network
        .start_chain_head_broadcast_from_journal(&peers, &journal)
        .unwrap();
    let announcement = broadcast.announcement();
    let request_ids = peers
        .iter()
        .map(|&peer_id| announcement_request_id(&network, peer_id))
        .collect::<Vec<_>>();

    assert_eq!(
        broadcast.peer_count(),
        MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS
    );
    assert_eq!(
        broadcast.pending_peer_count(),
        MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS
    );
    assert_eq!(
        network.pending_count_for_test(),
        MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS
    );
    assert!(peers.iter().all(|&peer_id| {
        network
            .pending_announcement_for_peer_for_test(peer_id)
            .is_some_and(|(_, retained)| retained == announcement)
    }));
    assert_eq!(
        network.active_permit_count_for_test(),
        MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS
    );

    broadcast.cancel();
    assert_eq!(
        network.pending_count_for_test(),
        MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS
    );
    assert_eq!(
        network.active_permit_count_for_test(),
        MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS
    );

    for (settled, (&request_id, &peer_id)) in request_ids.iter().zip(&peers).enumerate() {
        let event = receipt_event(&mut network, request_id, peer_id);
        let remaining = peers.len() - settled - 1;
        assert_eq!(network.pending_count_for_test(), remaining);
        assert_eq!(network.active_permit_count_for_test(), remaining + 1);
        drop(event);
        assert_eq!(network.active_permit_count_for_test(), remaining);
    }
    assert!((network.pending_count_for_test() == 0));
}

#[test]
fn cancellation_after_one_receipt_keeps_only_the_unsettled_physical_requests() {
    let peers = (0..3)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peers);
    let directory = TestDirectory::new("head-broadcast-partial-cancel");
    let journal = create_journal(directory.path()).unwrap();
    let broadcast = network
        .start_chain_head_broadcast_from_journal(&peers, &journal)
        .unwrap();
    let request_ids = peers
        .iter()
        .map(|&peer_id| announcement_request_id(&network, peer_id))
        .collect::<Vec<_>>();

    let settled = receipt_event(&mut network, request_ids[1], peers[1]);
    let broadcast = awaiting(broadcast.on_event(settled).unwrap());
    assert_eq!(broadcast.pending_peer_count(), 2);
    assert_eq!(network.pending_count_for_test(), 2);
    assert_eq!(network.active_permit_count_for_test(), 2);

    broadcast.cancel();
    assert_eq!(network.pending_count_for_test(), 2);
    assert_eq!(network.active_permit_count_for_test(), 2);

    for index in [0, 2] {
        let event = receipt_event(&mut network, request_ids[index], peers[index]);
        drop(event);
    }
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
}

#[tokio::test]
async fn three_authenticated_receivers_get_one_shared_snapshot_and_caller_ordered_results() {
    let mut identities = (0..4)
        .map(|_| Keypair::generate_ed25519())
        .collect::<Vec<_>>();
    identities.sort_by_key(|identity| identity.public().to_peer_id().to_bytes());
    let broadcaster_identity = identities.remove(0);
    let mut receivers = identities.into_iter();
    let receiver_a_identity = receivers.next().unwrap();
    let receiver_b_identity = receivers.next().unwrap();
    let receiver_c_identity = receivers.next().unwrap();
    assert!(receivers.next().is_none());

    let broadcaster_peer_id = broadcaster_identity.public().to_peer_id();
    let receiver_a_peer_id = receiver_a_identity.public().to_peer_id();
    let receiver_b_peer_id = receiver_b_identity.public().to_peer_id();
    let receiver_c_peer_id = receiver_c_identity.public().to_peer_id();
    let passive_peer = StaticPeer::new(broadcaster_peer_id, loopback_address(1));
    let mut receiver_a =
        StaticArtifactNetwork::new(receiver_a_identity, [passive_peer.clone()]).unwrap();
    let mut receiver_b =
        StaticArtifactNetwork::new(receiver_b_identity, [passive_peer.clone()]).unwrap();
    let mut receiver_c = StaticArtifactNetwork::new(receiver_c_identity, [passive_peer]).unwrap();
    let receiver_a_address = listening_address(&mut receiver_a).await;
    let receiver_b_address = listening_address(&mut receiver_b).await;
    let receiver_c_address = listening_address(&mut receiver_c).await;

    let mut broadcaster = StaticArtifactNetwork::new(
        broadcaster_identity,
        [
            StaticPeer::new(receiver_a_peer_id, receiver_a_address),
            StaticPeer::new(receiver_b_peer_id, receiver_b_address),
            StaticPeer::new(receiver_c_peer_id, receiver_c_address),
        ],
    )
    .unwrap();

    let mut broadcaster_established = [false; 3];
    let mut receiver_established = [false; 3];
    timeout(Duration::from_secs(10), async {
        while !broadcaster_established.iter().all(|established| *established)
            || !receiver_established.iter().all(|established| *established)
        {
            tokio::select! {
                event = broadcaster.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        let index = [receiver_a_peer_id, receiver_b_peer_id, receiver_c_peer_id]
                            .iter()
                            .position(|configured| *configured == peer_id)
                            .expect("broadcaster established only a configured receiver");
                        broadcaster_established[index] = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("managed broadcast dial to {peer_id} failed")
                    }
                    _ => {}
                },
                event = receiver_a.next_event(), if !receiver_established[0] => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        assert_eq!(peer_id, broadcaster_peer_id);
                        receiver_established[0] = true;
                    }
                },
                event = receiver_b.next_event(), if !receiver_established[1] => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        assert_eq!(peer_id, broadcaster_peer_id);
                        receiver_established[1] = true;
                    }
                },
                event = receiver_c.next_event(), if !receiver_established[2] => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        assert_eq!(peer_id, broadcaster_peer_id);
                        receiver_established[2] = true;
                    }
                },
            }
        }
    })
    .await
    .expect("three managed broadcast sessions did not establish");

    let broadcaster_directory = TestDirectory::new("head-broadcast-real-sender");
    let mut broadcaster_journal = create_journal(broadcaster_directory.path()).unwrap();
    apply_fresh_blocks(&mut broadcaster_journal, [pairing_bytes()]);
    let broadcaster_before = snapshot(&broadcaster_directory, &broadcaster_journal);
    let receiver_a_directory = TestDirectory::new("head-broadcast-real-receiver-a");
    let receiver_a_journal = create_journal(receiver_a_directory.path()).unwrap();
    let receiver_a_before = snapshot(&receiver_a_directory, &receiver_a_journal);
    let receiver_b_directory = TestDirectory::new("head-broadcast-real-receiver-b");
    let mut receiver_b_journal = create_journal(receiver_b_directory.path()).unwrap();
    apply_fresh_blocks(&mut receiver_b_journal, [union_bytes()]);
    let receiver_b_before = snapshot(&receiver_b_directory, &receiver_b_journal);
    let receiver_c_directory = TestDirectory::new("head-broadcast-real-receiver-c");
    let mut receiver_c_journal = create_journal(receiver_c_directory.path()).unwrap();
    apply_fresh_blocks(&mut receiver_c_journal, [pairing_bytes(), union_bytes()]);
    let receiver_c_before = snapshot(&receiver_c_directory, &receiver_c_journal);

    let selected_peers = [receiver_c_peer_id, receiver_a_peer_id, receiver_b_peer_id];
    let mut broadcast = broadcaster
        .start_chain_head_broadcast_from_journal(&selected_peers, &broadcaster_journal)
        .unwrap();
    let announcement = broadcast.announcement();
    assert_eq!(announcement.head_block_id(), broadcaster_before.head);

    let mut inbound_a = None;
    let mut inbound_b = None;
    let mut inbound_c = None;
    timeout(Duration::from_secs(10), async {
        while inbound_a.is_none() || inbound_b.is_none() || inbound_c.is_none() {
            tokio::select! {
                event = broadcaster.next_event() => {
                    if let NetworkEvent::OutboundChainHeadAnnouncement(event) = event {
                        panic!("unacknowledged real broadcast became terminal: {event:?}")
                    }
                },
                event = receiver_a.next_event(), if inbound_a.is_none() => {
                    if let NetworkEvent::InboundChainHeadAnnouncement(inbound) = event {
                        assert_eq!(inbound.peer_id(), broadcaster_peer_id);
                        assert_eq!(inbound.announcement(), announcement);
                        inbound_a = Some(inbound);
                    }
                },
                event = receiver_b.next_event(), if inbound_b.is_none() => {
                    if let NetworkEvent::InboundChainHeadAnnouncement(inbound) = event {
                        assert_eq!(inbound.peer_id(), broadcaster_peer_id);
                        assert_eq!(inbound.announcement(), announcement);
                        inbound_b = Some(inbound);
                    }
                },
                event = receiver_c.next_event(), if inbound_c.is_none() => {
                    if let NetworkEvent::InboundChainHeadAnnouncement(inbound) = event {
                        assert_eq!(inbound.peer_id(), broadcaster_peer_id);
                        assert_eq!(inbound.announcement(), announcement);
                        inbound_c = Some(inbound);
                    }
                },
            }
        }
    })
    .await
    .expect("three authenticated receivers did not receive the broadcast");

    let terminal_b = acknowledge_and_receive_terminal(
        &mut broadcaster,
        &mut receiver_b,
        inbound_b.unwrap(),
        receiver_b_peer_id,
    )
    .await;
    assert!(broadcast.accepts_event(&terminal_b));
    broadcast = awaiting(broadcast.on_event(terminal_b).unwrap());
    let terminal_c = acknowledge_and_receive_terminal(
        &mut broadcaster,
        &mut receiver_c,
        inbound_c.unwrap(),
        receiver_c_peer_id,
    )
    .await;
    assert!(broadcast.accepts_event(&terminal_c));
    broadcast = awaiting(broadcast.on_event(terminal_c).unwrap());
    let terminal_a = acknowledge_and_receive_terminal(
        &mut broadcaster,
        &mut receiver_a,
        inbound_a.unwrap(),
        receiver_a_peer_id,
    )
    .await;
    assert!(broadcast.accepts_event(&terminal_a));
    let completed = complete(broadcast.on_event(terminal_a).unwrap());

    assert_eq!(completed.announcement(), announcement);
    assert_eq!(
        completed
            .peer_results()
            .iter()
            .map(|result| result.peer_id())
            .collect::<Vec<_>>(),
        selected_peers
    );
    assert!(
        completed
            .peer_results()
            .iter()
            .all(|result| result.result().is_ok())
    );
    assert_snapshot(
        &broadcaster_directory,
        &broadcaster_journal,
        &broadcaster_before,
    );
    assert_snapshot(
        &receiver_a_directory,
        &receiver_a_journal,
        &receiver_a_before,
    );
    assert_snapshot(
        &receiver_b_directory,
        &receiver_b_journal,
        &receiver_b_before,
    );
    assert_snapshot(
        &receiver_c_directory,
        &receiver_c_journal,
        &receiver_c_before,
    );
}
