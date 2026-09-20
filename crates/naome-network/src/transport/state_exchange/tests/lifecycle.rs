use super::super::super::{MAX_PENDING_REQUESTS, PeerSessionEvent};
use super::*;
use libp2p::swarm::ConnectionId;
use std::sync::atomic::Ordering;

// The public constructor accepts only genesis. These fixtures change the peer
// table solely to exercise the shared Noise/session boundary adversarially.
fn configured(identity: identity::Keypair, peers: Vec<StaticPeer>) -> StateNetwork {
    let (genesis, keys) = fixture();
    let mut template = StateNetwork::new_state(keys[0].clone(), &genesis).unwrap();
    let mut config = template.state_exchange.take().unwrap();
    config.context = context();
    let mut network = StateNetwork::build(identity, peers.clone()).unwrap();
    network.swarm.behaviour_mut().state_exchange =
        Behaviour::new(peers.iter().map(StaticPeer::peer_id), Some(&config));
    network.state_exchange = Some(config);
    network
}
fn ordered_keys() -> (identity::Keypair, identity::Keypair) {
    let a = identity::Keypair::generate_ed25519();
    let b = identity::Keypair::generate_ed25519();
    if a.public().to_peer_id().to_bytes() < b.public().to_peer_id().to_bytes() {
        (a, b)
    } else {
        (b, a)
    }
}
fn address(port: u16) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}
async fn listen(network: &mut StateNetwork) -> Multiaddr {
    network.listen_on(address(0)).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkEvent::Listening { address } = network.next_event().await {
                return address;
            }
        }
    })
    .await
    .unwrap()
}
async fn connected(a: &mut StateNetwork, b: &mut StateNetwork) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if a.swarm.is_connected(&b.local_peer_id()) && b.swarm.is_connected(&a.local_peer_id())
            {
                return;
            }
            tokio::select! { _ = a.next_event() => {}, _ = b.next_event() => {} }
        }
    })
    .await
    .expect("both managed sessions connected");
}

#[tokio::test]
async fn disconnected_and_unknown_requests_allocate_nothing_and_cannot_dial_a_passive_peer() {
    let (owner, passive) = ordered_keys();
    let owner_id = owner.public().to_peer_id();
    let mut network = configured(passive, vec![StaticPeer::new(owner_id, address(1))]);
    let unknown = identity::Keypair::generate_ed25519().public().to_peer_id();
    for (peer, expected) in [
        (owner_id, RequestStartError::PeerDisconnected(owner_id)),
        (unknown, RequestStartError::UnknownPeer(unknown)),
    ] {
        assert!(
            matches!(network.request_state(peer, StateRequestBody::Handshake), Err(StateStartError::Transport(actual)) if actual == expected)
        );
    }
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(network.pending.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), network.next_event())
            .await
            .is_err()
    );
    assert!(!network.swarm.is_connected(&owner_id));
}

#[tokio::test]
async fn simultaneous_bidirectional_requests_keep_independent_peer_and_request_correlation() {
    let (mut a, mut b) = pair().await;
    let ta = a
        .request_state(b.local_peer_id(), StateRequestBody::Handshake)
        .unwrap();
    let tb = b
        .request_state(
            a.local_peer_id(),
            StateRequestBody::Proposal(vec![7; 80].into()),
        )
        .unwrap();
    let (mut ea, mut eb) = (None, None);
    tokio::time::timeout(Duration::from_secs(10), async {
        while ea.is_none() || eb.is_none() {
            tokio::select! {
                event = a.next_event() => match event {
                    NetworkEvent::InboundState(inbound) => { assert_eq!(inbound.request().body(), &StateRequestBody::Proposal(vec![7; 80].into())); a.respond_state(inbound, StateResponseBody::Accepted).unwrap(); }
                    NetworkEvent::OutboundState(event) => ea = Some(event),
                    _ => {}
                },
                event = b.next_event() => match event {
                    NetworkEvent::InboundState(inbound) => { assert_eq!(inbound.request().body(), &StateRequestBody::Handshake); b.respond_state(inbound, StateResponseBody::Ready).unwrap(); }
                    NetworkEvent::OutboundState(event) => eb = Some(event),
                    _ => {}
                }
            }
        }
    }).await.unwrap();
    let (ea, eb) = (ea.unwrap(), eb.unwrap());
    assert!(!ta.accepts_event(&eb));
    assert!(!tb.accepts_event(&ea));
    assert_eq!(
        ta.complete(ea).unwrap().unwrap().response().body(),
        &StateResponseBody::Ready
    );
    assert_eq!(
        tb.complete(eb).unwrap().unwrap().response().body(),
        &StateResponseBody::Accepted
    );
}

#[tokio::test]
async fn foreign_network_ticket_and_duplicate_terminal_cannot_release_live_custody() {
    let (mut a, mut b) = pair().await;
    let peer = b.local_peer_id();
    let ticket = a.request_state(peer, StateRequestBody::Handshake).unwrap();
    let event = exchange(&mut a, &mut b, StateResponseBody::Ready).await;
    // Same id, peer, and digest from another transport instance is insufficient.
    let foreign = StateTicket {
        id: ticket.id,
        peer: ticket.peer,
        digest: ticket.digest,
        budget: Arc::new(PendingBudget::default()),
        _custody: Arc::clone(&ticket._custody),
    };
    assert!(!foreign.accepts_event(&event));
    let (_, event) = foreign.complete(event).unwrap_err().into_parts();
    assert_eq!(a.pending_budget.active.load(Ordering::Relaxed), 1);
    assert!(
        a.handle_state_event(request_response::Event::OutboundFailure {
            peer,
            connection_id: ConnectionId::new_unchecked(900),
            request_id: ticket.id,
            error: request_response::OutboundFailure::Timeout,
        })
        .is_none()
    );
    assert_eq!(a.pending_budget.active.load(Ordering::Relaxed), 1);
    let response = ticket.complete(event).unwrap().unwrap();
    assert_eq!(a.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(response);
    assert_eq!(a.pending_budget.active.load(Ordering::Relaxed), 0);
    let ticket = a.request_state(peer, StateRequestBody::Handshake).unwrap();
    drop(ticket);
    assert!(matches!(
        a.request_state(peer, StateRequestBody::Handshake),
        Err(StateStartError::Transport(
            RequestStartError::AlreadyPending(_)
        ))
    ));
    drop(exchange(&mut a, &mut b, StateResponseBody::Ready).await);
    assert_eq!(a.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn retained_completions_share_the_exact_global_eight_slot_bound() {
    let (mut a, mut b) = pair().await;
    let held: Vec<_> = (0..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&a.pending_budget).unwrap())
        .collect();
    assert!(PendingBudget::try_acquire(&a.pending_budget).is_none());
    assert!(matches!(
        a.request_state(b.local_peer_id(), StateRequestBody::Handshake),
        Err(StateStartError::Transport(RequestStartError::GlobalLimit {
            maximum: MAX_PENDING_REQUESTS
        }))
    ));
    drop(held);
    let ticket = a
        .request_state(b.local_peer_id(), StateRequestBody::Handshake)
        .unwrap();
    let event = exchange(&mut a, &mut b, StateResponseBody::Ready).await;
    let response = ticket.complete(event).unwrap().unwrap();
    let held: Vec<_> = (1..MAX_PENDING_REQUESTS)
        .map(|_| PendingBudget::try_acquire(&a.pending_budget).unwrap())
        .collect();
    assert!(PendingBudget::try_acquire(&a.pending_budget).is_none());
    drop(response);
    assert!(PendingBudget::try_acquire(&a.pending_budget).is_some());
    drop(held);
}

#[tokio::test]
async fn closed_response_channel_reports_failure_and_releases_request_custody() {
    let (mut a, mut b) = pair().await;
    let ticket = a
        .request_state(b.local_peer_id(), StateRequestBody::Handshake)
        .unwrap();
    let inbound = tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        _ = a.next_event() => {},
        event = b.next_event() => if let NetworkEvent::InboundState(inbound) = event { break inbound; }
    } } }).await.unwrap();
    a.swarm.disconnect_peer_id(b.local_peer_id()).unwrap();
    let terminal = tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = a.next_event() => if let NetworkEvent::OutboundState(event) = event { break event; },
        _ = b.next_event() => {}
    } } }).await.unwrap();
    assert!(matches!(
        ticket.complete(terminal).unwrap(),
        Err(StateFailure::Transport(_))
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        while inbound.channel.is_open() {
            let _ = b.next_event().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        b.respond_state(inbound, StateResponseBody::Ready),
        Err(StateRespondError::ChannelClosed)
    ));
    assert_eq!(a.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn authenticated_unlisted_peer_cannot_deliver_state_requests() {
    let (attacker, server) = ordered_keys();
    let server_id = server.public().to_peer_id();
    let mut server = configured(server, vec![]);
    let endpoint = listen(&mut server).await;
    let mut attacker = configured(attacker, vec![StaticPeer::new(server_id, endpoint)]);
    let mut ticket = None;
    tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = attacker.next_event() => match event {
            NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                assert_eq!(peer_id, server_id);
                ticket = Some(attacker.request_state(server_id, StateRequestBody::Handshake).unwrap());
            }
            NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id } | PeerSessionEvent::Disconnected { peer_id }) if ticket.is_none() => { assert_eq!(peer_id, server_id); break; }
            NetworkEvent::OutboundState(event) => { assert!(matches!(ticket.take().unwrap().complete(event).unwrap(), Err(StateFailure::Transport(_)))); break; }
            _ => {}
        },
        event = server.next_event() => assert!(!matches!(event, NetworkEvent::InboundState(_) | NetworkEvent::PeerSession(PeerSessionEvent::Established { .. })))
    } } }).await.expect("unlisted Noise key rejected");
    assert!(matches!(
        attacker.request_state(server_id, StateRequestBody::Handshake),
        Err(StateStartError::Transport(
            RequestStartError::PeerDisconnected(_)
        ))
    ));
}

#[tokio::test]
async fn expected_identity_mismatch_fails_then_static_retry_and_reconnect_remain_usable() {
    let (client, server) = ordered_keys();
    let (client_id, server_id) = (client.public().to_peer_id(), server.public().to_peer_id());
    let wrong = loop {
        let key = identity::Keypair::generate_ed25519();
        if key.public().to_peer_id().to_bytes() > client_id.to_bytes()
            && key.public().to_peer_id() != server_id
        {
            break key;
        }
    };
    let mut wrong = configured(wrong, vec![StaticPeer::new(client_id, address(1))]);
    let endpoint = listen(&mut wrong).await;
    let mut client = configured(client, vec![StaticPeer::new(server_id, endpoint.clone())]);
    tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = client.next_event() => if let NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) = event { assert_eq!(peer_id, server_id); break; },
        event = wrong.next_event() => assert!(!matches!(event, NetworkEvent::InboundState(_)))
    } } }).await.expect("wrong Noise identity rejected");
    drop(wrong);
    let mut server = configured(server, vec![StaticPeer::new(client_id, address(1))]);
    server.listen_on(endpoint).unwrap();
    connected(&mut client, &mut server).await;
    let ticket = client
        .request_state(server_id, StateRequestBody::Handshake)
        .unwrap();
    let event = exchange(&mut client, &mut server, StateResponseBody::Ready).await;
    drop(ticket.complete(event).unwrap().unwrap());
    client.swarm.disconnect_peer_id(server_id).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = client.next_event() => if matches!(event, NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { .. })) { break; },
        _ = server.next_event() => {}
    } } }).await.unwrap();
    connected(&mut client, &mut server).await;
    let ticket = client
        .request_state(server_id, StateRequestBody::Handshake)
        .unwrap();
    let event = exchange(&mut client, &mut server, StateResponseBody::Ready).await;
    assert_eq!(
        ticket.complete(event).unwrap().unwrap().response().body(),
        &StateResponseBody::Ready
    );
}

#[tokio::test]
async fn equal_ids_from_distinct_peers_and_a_retained_inbound_do_not_block_other_peer() {
    let (genesis, keys) = fixture();
    let mut a = StateNetwork::new_state(keys[0].clone(), &genesis).unwrap();
    let mut b = StateNetwork::new_state(keys[1].clone(), &genesis).unwrap();
    let mut c = StateNetwork::new_state(keys[2].clone(), &genesis).unwrap();
    for network in [&mut a, &mut b, &mut c] {
        network
            .listen_on(network.state_listen_address().unwrap().clone())
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if a.swarm.is_connected(&b.local_peer_id()) && a.swarm.is_connected(&c.local_peer_id()) && b.swarm.is_connected(&a.local_peer_id()) && c.swarm.is_connected(&a.local_peer_id()) { break; }
            tokio::select! { _ = a.next_event() => {}, _ = b.next_event() => {}, _ = c.next_event() => {} }
        }
    }).await.unwrap();
    let tb = a
        .request_state(b.local_peer_id(), StateRequestBody::Handshake)
        .unwrap();
    let tc = a
        .request_state(c.local_peer_id(), StateRequestBody::Handshake)
        .unwrap();
    assert_eq!(tb.id, tc.id, "each peer owns its request-id counter");
    let mut held = None;
    let event_c = tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = a.next_event() => if let NetworkEvent::OutboundState(event) = event { break event; },
        event = b.next_event() => if let NetworkEvent::InboundState(inbound) = event { assert!(held.replace(inbound).is_none()); },
        event = c.next_event() => if let NetworkEvent::InboundState(inbound) = event { c.respond_state(inbound, StateResponseBody::Ready).unwrap(); }
    } } }).await.unwrap();
    assert!(!tb.accepts_event(&event_c));
    drop(tc.complete(event_c).unwrap().unwrap());
    // Keep B's inbound request and A's matching outbound slot while another
    // complete exchange with C proceeds. B cannot consume C's peer budget.
    if held.is_none() {
        held = Some(tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
            _ = a.next_event() => {},
            event = b.next_event() => if let NetworkEvent::InboundState(inbound) = event { break inbound; },
            _ = c.next_event() => {}
        } } }).await.unwrap());
    }
    assert!(matches!(
        a.request_state(b.local_peer_id(), StateRequestBody::Handshake),
        Err(StateStartError::Transport(
            RequestStartError::AlreadyPending(_)
        ))
    ));
    let tc = a
        .request_state(c.local_peer_id(), StateRequestBody::Handshake)
        .unwrap();
    let event_c = exchange(&mut a, &mut c, StateResponseBody::Ready).await;
    drop(tc.complete(event_c).unwrap().unwrap());
    b.respond_state(held.take().unwrap(), StateResponseBody::Ready)
        .unwrap();
    let event_b = tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = a.next_event() => if let NetworkEvent::OutboundState(event) = event { break event; },
        _ = b.next_event() => {},
        _ = c.next_event() => {}
    } } }).await.unwrap();
    drop(tb.complete(event_b).unwrap().unwrap());
    assert!(a.pending.is_empty());
    assert_eq!(a.pending_budget.active.load(Ordering::Relaxed), 0);
}
