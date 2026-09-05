use super::*;
use crate::transport::inbound_retention::InboundRetentionBudget;
use crate::{Keypair, MAX_PENDING_REQUESTS};
use libp2p::swarm::ConnectionId;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::timeout;

fn vote() -> ConsensusPushMessage {
    ConsensusPushMessage::Vote {
        canonical_vote: vec![0xa5; CONSENSUS_PUSH_VOTE_BYTES],
    }
}
fn pointers(message: &ConsensusPushMessage) -> Vec<*const u8> {
    match message {
        ConsensusPushMessage::Proposal {
            canonical_proposal,
            canonical_artifact,
        } => vec![canonical_proposal.as_ptr(), canonical_artifact.as_ptr()],
        ConsensusPushMessage::Vote { canonical_vote } => vec![canonical_vote.as_ptr()],
    }
}
fn terminal(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer: PeerId,
    failure: Option<request_response::OutboundFailure>,
) -> OutboundConsensusPushEvent {
    let event = match failure {
        Some(error) => request_response::Event::OutboundFailure {
            peer,
            connection_id: ConnectionId::new_unchecked(3000),
            request_id,
            error,
        },
        None => request_response::Event::Message {
            peer,
            connection_id: ConnectionId::new_unchecked(3000),
            message: request_response::Message::Response {
                request_id,
                response: ConsensusPushReceipt,
            },
        },
    };
    let Some(NetworkEvent::OutboundConsensusPush(event)) =
        network.handle_consensus_push_event(event)
    else {
        panic!("missing consensus terminal")
    };
    event
}

#[test]
fn invalid_lengths_return_exact_input_before_peer_preflight() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = crate::tests::test_network_for_peers(&[]);
    for message in [
        ConsensusPushMessage::Proposal {
            canonical_proposal: vec![0; CONSENSUS_PUSH_MIN_PROPOSAL_BYTES - 1],
            canonical_artifact: vec![0; 1],
        },
        ConsensusPushMessage::Proposal {
            canonical_proposal: vec![0; CONSENSUS_PUSH_MAX_PROPOSAL_BYTES + 1],
            canonical_artifact: vec![0; 1],
        },
        ConsensusPushMessage::Proposal {
            canonical_proposal: vec![0; CONSENSUS_PUSH_MIN_PROPOSAL_BYTES],
            canonical_artifact: vec![],
        },
        ConsensusPushMessage::Proposal {
            canonical_proposal: vec![0; CONSENSUS_PUSH_MIN_PROPOSAL_BYTES],
            canonical_artifact: vec![0; CONSENSUS_PUSH_MAX_PAYLOAD_BYTES + 1],
        },
        ConsensusPushMessage::Vote {
            canonical_vote: vec![],
        },
        ConsensusPushMessage::Vote {
            canonical_vote: vec![0; CONSENSUS_PUSH_VOTE_BYTES - 1],
        },
        ConsensusPushMessage::Vote {
            canonical_vote: vec![0; CONSENSUS_PUSH_VOTE_BYTES + 1],
        },
    ] {
        let expected = pointers(&message);
        let error = network.push_consensus(peer, message).unwrap_err();
        assert_eq!(pointers(error.message()), expected);
        assert!(matches!(
            error.reason(),
            ConsensusPushStartFailure::Length(_)
        ));
        let (returned, _) = error.into_parts();
        assert_eq!(pointers(&returned), expected);
    }
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn preflight_order_shared_budget_and_dropped_ticket_preserve_request() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = crate::tests::test_network_for_peers(&[peer]);
    let permits: Vec<_> = (0..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&network.pending_budget).unwrap())
        .collect();
    for (target, expected) in [(unknown, 0), (peer, 1)] {
        let input = vote();
        let before = pointers(&input);
        let error = network.push_consensus(target, input).unwrap_err();
        assert_eq!(pointers(error.message()), before);
        assert!(match (expected, error.reason()) {
            (
                0,
                ConsensusPushStartFailure::RequestStart(RequestStartError::UnknownPeer(actual)),
            ) => *actual == unknown,
            (
                1,
                ConsensusPushStartFailure::RequestStart(RequestStartError::GlobalLimit { maximum }),
            ) => *maximum == MAX_PENDING_REQUESTS,
            _ => false,
        });
    }
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer);
    assert!(matches!(
        network.push_consensus(peer, vote()).unwrap_err().reason(),
        ConsensusPushStartFailure::RequestStart(RequestStartError::PeerDisconnected(_))
    ));
    drop(permits);
    let mut network = crate::tests::test_network_for_peers(&[peer]);
    let ticket = network.push_consensus(peer, vote()).unwrap();
    let id = ticket.request_id;
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer);
    assert!(matches!(
        network.push_consensus(peer, vote()).unwrap_err().reason(),
        ConsensusPushStartFailure::RequestStart(RequestStartError::AlreadyPending(_))
    ));
    assert!(matches!(
        network.push_recovery_bundle(peer, vec![1]),
        Err(crate::RecoveryBundlePushStartError::RequestStart(
            RequestStartError::AlreadyPending(_)
        ))
    ));
    drop(ticket);
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::ConsensusPush(id))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let event = terminal(
        &mut network,
        id,
        peer,
        Some(request_response::OutboundFailure::ConnectionClosed),
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    drop(event);
}

#[test]
fn successful_terminal_holds_shared_capacity_but_failure_releases_it() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = crate::tests::test_network_for_peers(&[peer]);
    let ticket = network.push_consensus(peer, vote()).unwrap();
    let rest: Vec<_> = (1..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&network.pending_budget).unwrap())
        .collect();
    let event = terminal(&mut network, ticket.request_id, peer, None);
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        MAX_PENDING_REQUESTS
    );
    assert!(matches!(
        network.push_recovery_bundle(peer, vec![1]),
        Err(crate::RecoveryBundlePushStartError::RequestStart(
            RequestStartError::GlobalLimit { .. }
        ))
    ));
    let receipt = ticket.complete(event).unwrap().unwrap();
    assert_eq!(receipt.peer_id(), peer);
    assert_eq!(receipt.size(), vote().size());
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        MAX_PENDING_REQUESTS - 1
    );
    let ticket = network.push_consensus(peer, vote()).unwrap();
    let event = terminal(
        &mut network,
        ticket.request_id,
        peer,
        Some(request_response::OutboundFailure::Timeout),
    );
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        MAX_PENDING_REQUESTS - 1
    );
    assert!(matches!(
        *ticket.complete(event).unwrap().unwrap_err(),
        OutboundConsensusPushFailure::Transport(request_response::OutboundFailure::Timeout)
    ));
    drop(rest);
    let ticket = network.push_consensus(peer, vote()).unwrap();
    let event = terminal(&mut network, ticket.request_id, peer, None);
    drop(event);
    drop(ticket);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn ticket_correlation_rejects_other_network_stale_peer_and_size_without_losing_custody() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut first = crate::tests::test_network_for_peers(&[peer]);
    let mut second = crate::tests::test_network_for_peers(&[peer]);
    let first_ticket = first.push_consensus(peer, vote()).unwrap();
    let second_ticket = second.push_consensus(peer, vote()).unwrap();
    assert_eq!(first_ticket.request_id, second_ticket.request_id);
    let event = terminal(&mut second, second_ticket.request_id, peer, None);
    let mismatch = first_ticket.complete(event).unwrap_err();
    let (first_ticket, event) = mismatch.into_parts();
    let _ = second_ticket.complete(event).unwrap().unwrap();
    let mut event = terminal(&mut first, first_ticket.request_id, peer, None);
    let original_size = event.size;
    event.size = ConsensusPushSize::Proposal {
        control_bytes: CONSENSUS_PUSH_VOTE_BYTES - 1,
        payload_bytes: 1,
    };
    let (first_ticket, mut event) = first_ticket.complete(event).unwrap_err().into_parts();
    event.size = original_size;
    event.peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (first_ticket, mut event) = first_ticket.complete(event).unwrap_err().into_parts();
    event.peer_id = peer;
    let newer = first.push_consensus(peer, vote()).unwrap();
    let (newer, event) = newer.complete(event).unwrap_err().into_parts();
    let _ = first_ticket.complete(event).unwrap().unwrap();
    let wrong = Keypair::generate_ed25519().public().to_peer_id();
    let event = terminal(&mut first, newer.request_id, wrong, None);
    assert!(
        matches!(*newer.complete(event).unwrap().unwrap_err(), OutboundConsensusPushFailure::PeerMismatch { expected, actual } if expected == peer && actual == wrong)
    );
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn duplicate_peer_cannot_replace_held_inbound_custody() {
    let budget = Arc::new(InboundRetentionBudget::new(
        CONSENSUS_PUSH_MAX_RETAINED_INBOUND_EVENTS,
        CONSENSUS_PUSH_MAX_RETAINED_INBOUND_BYTES,
    ));
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let make = || {
        ConsensusPushRequest::from_inbound(
            vote(),
            InboundRetentionBudget::try_acquire(&budget, CONSENSUS_PUSH_VOTE_BYTES).unwrap(),
        )
    };
    let mut first = make();
    assert!(first.bind_inbound_peer(peer));
    let mut duplicate = make();
    assert!(!duplicate.bind_inbound_peer(peer));
    drop(duplicate);
    let mut still_duplicate = make();
    assert!(!still_duplicate.bind_inbound_peer(peer));
    drop(first);
    assert!(still_duplicate.bind_inbound_peer(peer));
    assert!(!still_duplicate.bind_inbound_peer(peer));
}

#[tokio::test]
async fn authenticated_delivery_preserves_both_opaque_variants_and_exact_allocations() {
    let (mut sender, mut receiver, source, destination) = crate::tests::connected_pair().await;
    for message in [
        vote(),
        ConsensusPushMessage::Proposal {
            canonical_proposal: vec![0xff; CONSENSUS_PUSH_MIN_PROPOSAL_BYTES],
            canonical_artifact: vec![0xff; 1],
        },
    ] {
        let expected_size = message.size();
        let ticket = sender.push_consensus(destination, message).unwrap();
        let received = timeout(Duration::from_secs(10), async {
            let mut received = None;
            loop { tokio::select! {
                event = receiver.next_event() => if let NetworkEvent::InboundConsensusPush(inbound) = event {
                    assert_eq!(inbound.peer_id(), source);
                    let before = pointers(inbound.message());
                    let accepted = receiver.acknowledge_consensus_push(inbound).unwrap();
                    assert_eq!(pointers(accepted.message()), before);
                    received = Some(accepted);
                },
                event = sender.next_event() => if let NetworkEvent::OutboundConsensusPush(event) = event {
                    let receipt = ticket.complete(event).unwrap().unwrap();
                    assert_eq!(receipt.peer_id(), destination); assert_eq!(receipt.size(), expected_size);
                    break received.unwrap();
                },
            }}
        }).await.unwrap();
        assert_eq!(received.peer_id(), source);
        assert_eq!(received.message().size(), expected_size);
    }
}

#[tokio::test]
async fn closed_response_channel_returns_the_same_owned_bytes() {
    let (mut sender, mut receiver, sender_peer, receiver_peer) =
        crate::tests::connected_pair().await;

    let _ticket = sender.push_consensus(receiver_peer, vote()).unwrap();
    let inbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if let NetworkEvent::InboundConsensusPush(inbound) = event {
                        return inbound;
                    }
                }
                _ = sender.next_event() => {}
            }
        }
    })
    .await
    .unwrap();
    let inbound_pointer = pointers(inbound.message());
    drop(sender);
    timeout(Duration::from_secs(10), async {
        while inbound.channel.is_open() {
            let _ = receiver.next_event().await;
        }
    })
    .await
    .unwrap();

    let error = receiver.acknowledge_consensus_push(inbound).unwrap_err();
    assert_eq!(error.received().peer_id(), sender_peer);
    assert_eq!(pointers(error.received().message()), inbound_pointer);
    let recovered = error.into_received();
    assert_eq!(recovered.message(), &vote());
    assert_eq!(pointers(recovered.message()), inbound_pointer);
}

#[test]
fn protocol_request_namespaces_do_not_alias_and_duplicate_terminals_are_ignored() {
    let peers = [
        Keypair::generate_ed25519().public().to_peer_id(),
        Keypair::generate_ed25519().public().to_peer_id(),
    ];
    let mut network = crate::tests::test_network_for_peers(&peers);
    let _recovery = network.push_recovery_bundle(peers[0], vec![1]).unwrap();
    let recovery_id = network
        .pending
        .keys()
        .find_map(|id| match id {
            ExchangeRequestId::RecoveryBundlePush(id) => Some(*id),
            _ => None,
        })
        .unwrap();
    let ticket = network.push_consensus(peers[1], vote()).unwrap();
    assert_eq!(recovery_id, ticket.request_id);
    assert_eq!(network.pending.len(), 2);
    let id = ticket.request_id;
    let event = terminal(&mut network, id, peers[1], None);
    let _ = ticket.complete(event).unwrap().unwrap();
    assert_eq!(network.pending.len(), 1);
    assert!(
        network
            .pending
            .contains_key(&ExchangeRequestId::RecoveryBundlePush(recovery_id))
    );
    assert!(
        network
            .handle_consensus_push_event(request_response::Event::OutboundFailure {
                peer: peers[1],
                connection_id: ConnectionId::new_unchecked(3001),
                request_id: id,
                error: request_response::OutboundFailure::Timeout,
            })
            .is_none()
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
}
