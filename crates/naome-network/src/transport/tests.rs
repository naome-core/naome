use super::*;
use libp2p::{
    core::{Endpoint, transport::PortUse},
    swarm::{ConnectionId, NetworkBehaviour, ToSwarm},
};
use std::task::{Context, Poll, Waker};
pub(crate) fn address(port: u16) -> super::Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

fn peer(identity: &super::Keypair, address: super::Multiaddr) -> StaticPeer {
    StaticPeer::new(identity.public().to_peer_id(), address)
}

fn ordered_identities() -> (super::Keypair, super::Keypair) {
    let first = super::Keypair::generate_ed25519();
    let second = super::Keypair::generate_ed25519();
    if first.public().to_peer_id().to_bytes() < second.public().to_peer_id().to_bytes() {
        (first, second)
    } else {
        (second, first)
    }
}

#[tokio::test]
async fn static_configuration_rejects_local_duplicate_and_excess_peers() {
    let local = super::Keypair::generate_ed25519();
    let local_peer_id = local.public().to_peer_id();
    assert!(matches!(
        StaticArtifactNetwork::build(local.clone(), [StaticPeer::new(local_peer_id, address(1))]),
        Err(BuildError::LocalPeer(peer_id)) if peer_id == local_peer_id
    ));

    let remote = super::Keypair::generate_ed25519();
    let duplicate = peer(&remote, address(2));
    assert!(matches!(
        StaticArtifactNetwork::build(local.clone(), [duplicate.clone(), duplicate]),
        Err(BuildError::DuplicatePeer(peer_id))
            if peer_id == remote.public().to_peer_id()
    ));

    let peers = (0..=MAX_STATIC_PEERS)
        .map(|index| {
            let remote = super::Keypair::generate_ed25519();
            peer(&remote, address(u16::try_from(index + 10).unwrap()))
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        StaticArtifactNetwork::build(local, peers),
        Err(BuildError::TooManyPeers { actual, maximum })
            if actual == MAX_STATIC_PEERS + 1 && maximum == MAX_STATIC_PEERS
    ));
}

#[tokio::test]
async fn composite_session_hooks_reject_wrong_direction_and_stale_dials() {
    let (owner_identity, passive_identity) = ordered_identities();
    let owner_peer_id = owner_identity.public().to_peer_id();
    let passive_peer_id = passive_identity.public().to_peer_id();
    let local_address = address(8);
    let remote_address = address(9);

    let mut owner = StaticArtifactNetwork::build(
        owner_identity,
        [StaticPeer::new(passive_peer_id, remote_address.clone())],
    )
    .unwrap();
    assert!(
        NetworkBehaviour::handle_established_inbound_connection(
            owner.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(500),
            passive_peer_id,
            &local_address,
            &remote_address,
        )
        .is_err()
    );
    assert!(
        !owner
            .swarm
            .behaviour()
            .state_exchange
            .is_connected(&passive_peer_id)
    );

    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let managed_connection_id =
        match NetworkBehaviour::poll(&mut owner.swarm.behaviour_mut().sessions, &mut context) {
            Poll::Ready(ToSwarm::Dial { opts }) => opts.connection_id(),
            _ => panic!("the dial owner did not produce its initial managed dial"),
        };
    let stale_connection_id = ConnectionId::new_unchecked(501);
    assert_ne!(managed_connection_id, stale_connection_id);
    assert!(
        NetworkBehaviour::handle_established_outbound_connection(
            owner.swarm.behaviour_mut(),
            stale_connection_id,
            passive_peer_id,
            &remote_address,
            Endpoint::Dialer,
            PortUse::New,
        )
        .is_err()
    );
    assert!(
        !owner
            .swarm
            .behaviour()
            .state_exchange
            .is_connected(&passive_peer_id)
    );
    assert!(
        NetworkBehaviour::handle_established_outbound_connection(
            owner.swarm.behaviour_mut(),
            managed_connection_id,
            passive_peer_id,
            &remote_address,
            Endpoint::Dialer,
            PortUse::New,
        )
        .is_ok()
    );

    let mut passive = StaticArtifactNetwork::build(
        passive_identity,
        [StaticPeer::new(owner_peer_id, local_address.clone())],
    )
    .unwrap();
    assert!(
        NetworkBehaviour::handle_established_outbound_connection(
            passive.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(502),
            owner_peer_id,
            &local_address,
            Endpoint::Dialer,
            PortUse::New,
        )
        .is_err()
    );
    assert!(
        !passive
            .swarm
            .behaviour()
            .state_exchange
            .is_connected(&owner_peer_id)
    );
    assert!(
        NetworkBehaviour::handle_established_inbound_connection(
            passive.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(503),
            owner_peer_id,
            &remote_address,
            &local_address,
        )
        .is_ok()
    );
}

#[tokio::test]
async fn connection_limit_rejection_does_not_consume_pre_authentication_budget() {
    let local_identity = super::Keypair::generate_ed25519();
    let remote_identity = super::Keypair::generate_ed25519();
    let remote_peer_id = remote_identity.public().to_peer_id();
    let mut network = StaticArtifactNetwork::build(
        local_identity,
        [StaticPeer::new(remote_peer_id, address(9))],
    )
    .unwrap();
    let local_address = address(8);
    let remote_address = address(9);

    for index in 0..MAX_STATIC_PEERS {
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut network.swarm.behaviour_mut().limits,
            ConnectionId::new_unchecked(index),
            &local_address,
            &remote_address,
        )
        .unwrap();
    }
    let tokens_before = network.swarm.behaviour().sessions.inbound_tokens_for_test();
    assert_eq!(tokens_before, super::INBOUND_AUTH_BURST);

    assert!(
        NetworkBehaviour::handle_pending_inbound_connection(
            network.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(MAX_STATIC_PEERS),
            &local_address,
            &remote_address,
        )
        .is_err()
    );
    assert_eq!(
        network.swarm.behaviour().sessions.inbound_tokens_for_test(),
        tokens_before
    );
}
