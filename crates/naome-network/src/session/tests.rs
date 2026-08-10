use std::task::Waker;

use super::*;

fn address() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/9".parse().unwrap()
}

fn ordered_peer_ids() -> (PeerId, PeerId) {
    let first = PeerId::random();
    let second = PeerId::random();
    if owns_dial(&first.to_bytes(), second) {
        (first, second)
    } else {
        (second, first)
    }
}

fn owner_behaviour() -> (Behaviour, PeerId) {
    let (owner, passive) = ordered_peer_ids();
    (
        Behaviour::new(owner, [StaticPeer::new(passive, address())]),
        passive,
    )
}

#[test]
fn dial_ownership_is_antisymmetric() {
    for _ in 0..32 {
        let (lower, higher) = ordered_peer_ids();
        assert!(owns_dial(&lower.to_bytes(), higher));
        assert!(!owns_dial(&higher.to_bytes(), lower));
    }
}

#[test]
fn configured_peer_indices_follow_raw_identity_order() {
    let local = PeerId::random();
    let mut hashed_bytes = vec![0x12, 0x20];
    hashed_bytes.extend_from_slice(&[0xa5; 32]);
    let hashed = PeerId::from_bytes(&hashed_bytes).unwrap();
    let mut expected = [PeerId::random(), hashed, PeerId::random()];
    assert!(!expected.contains(&local));
    expected.sort_unstable_by_key(|peer_id| peer_id.to_bytes());
    let configured = [expected[2], expected[0], expected[1]]
        .into_iter()
        .map(|peer_id| StaticPeer::new(peer_id, address()));

    let behaviour = Behaviour::new(local, configured);
    assert_eq!(behaviour.peer_count(), expected.len());
    for (index, peer_id) in expected.into_iter().enumerate() {
        assert_eq!(behaviour.peer_id_at(index), Some(peer_id));
        assert_eq!(behaviour.peer_index(&peer_id), Some(index));
    }
}

#[test]
fn retry_delay_is_exponential_and_capped() {
    let seconds = (1..=9)
        .map(|failures| retry_delay(failures).as_secs())
        .collect::<Vec<_>>();
    assert_eq!(seconds, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    assert_eq!(retry_delay(u32::MAX), DIAL_RETRY_MAX);

    let mut elapsed = Duration::ZERO;
    let attempt_seconds = (1..=8)
        .map(|failures| {
            elapsed += retry_delay(failures);
            elapsed.as_secs()
        })
        .collect::<Vec<_>>();
    assert_eq!(attempt_seconds, vec![1, 3, 7, 15, 31, 63, 123, 183]);
}

#[test]
fn inbound_budget_enforces_burst_refill_and_cap() {
    let start = Instant::now();
    let mut budget = InboundBudget::new(start);
    for _ in 0..INBOUND_AUTH_BURST {
        assert!(budget.try_take(start));
    }
    assert!(!budget.try_take(start));
    assert!(!budget.try_take(start + INBOUND_AUTH_REFILL_INTERVAL / 2));
    assert!(budget.try_take(start + INBOUND_AUTH_REFILL_INTERVAL));
    assert!(!budget.try_take(start + INBOUND_AUTH_REFILL_INTERVAL));

    let later = start + Duration::from_secs(10_000);
    for _ in 0..INBOUND_AUTH_BURST {
        assert!(budget.try_take(later));
    }
    assert!(!budget.try_take(later));

    let mut full_after_idle = InboundBudget::new(start);
    for _ in 0..INBOUND_AUTH_BURST {
        assert!(full_after_idle.try_take(later));
    }
    assert!(!full_after_idle.try_take(later));

    let mut fractional = InboundBudget::new(start);
    for _ in 0..INBOUND_AUTH_BURST {
        assert!(fractional.try_take(start));
    }
    assert!(fractional.try_take(start + INBOUND_AUTH_REFILL_INTERVAL * 3 / 2));
    assert!(
        !fractional.try_take(start + INBOUND_AUTH_REFILL_INTERVAL * 2 - Duration::from_nanos(1))
    );
    assert!(fractional.try_take(start + INBOUND_AUTH_REFILL_INTERVAL * 2));
}

#[test]
fn stale_generations_cannot_change_the_active_dial() {
    let (mut behaviour, peer_id) = owner_behaviour();
    let now = Instant::now();
    let first = behaviour.start_dial(peer_id).connection_id();
    let stale = ConnectionId::new_unchecked(usize::MAX);

    assert!(!behaviour.record_dial_failure(peer_id, stale, now));
    assert!(matches!(
        behaviour.peer(&peer_id).unwrap().link,
        Link::Dialing { connection_id } if connection_id == first
    ));
    assert!(behaviour.record_dial_failure(peer_id, first, now));
    assert_eq!(behaviour.peer(&peer_id).unwrap().failures, 1);
    assert_eq!(behaviour.due_peer(now), None);
    assert_eq!(behaviour.due_peer(now + DIAL_RETRY_BASE), Some(peer_id));

    let second = behaviour.start_dial(peer_id).connection_id();
    assert_ne!(first, second);
    assert!(!behaviour.record_dial_failure(peer_id, first, now + DIAL_RETRY_BASE));
    assert!(behaviour.record_established(peer_id, second, true, now + DIAL_RETRY_BASE));
    assert!(!behaviour.record_closed(peer_id, first, 0, now + DIAL_RETRY_BASE));
    assert!(matches!(
        behaviour.peer(&peer_id).unwrap().link,
        Link::Connected { connection_id, .. } if connection_id == second
    ));
    assert!(behaviour.record_closed(peer_id, second, 0, now + DIAL_RETRY_BASE));
}

#[test]
fn only_an_exactly_stable_session_resets_backoff() {
    let (mut behaviour, peer_id) = owner_behaviour();
    let connected_at = Instant::now();
    let connection_id = ConnectionId::new_unchecked(101);
    {
        let peer = behaviour.peer_mut(&peer_id).unwrap();
        peer.failures = 4;
        peer.link = Link::Dialing { connection_id };
    }
    assert!(behaviour.record_established(peer_id, connection_id, true, connected_at));
    assert!(!behaviour.record_closed(
        peer_id,
        connection_id,
        1,
        connected_at + STABLE_SESSION_DURATION
    ));
    assert!(behaviour.record_closed(
        peer_id,
        connection_id,
        0,
        connected_at + STABLE_SESSION_DURATION - Duration::from_nanos(1)
    ));
    assert_eq!(behaviour.peer(&peer_id).unwrap().failures, 5);
    assert_eq!(
        behaviour.earliest_retry(),
        Some(
            connected_at + STABLE_SESSION_DURATION - Duration::from_nanos(1)
                + Duration::from_secs(16)
        )
    );

    let stable_connection = ConnectionId::new_unchecked(102);
    behaviour.peer_mut(&peer_id).unwrap().link = Link::Dialing {
        connection_id: stable_connection,
    };
    let stable_since = connected_at + Duration::from_secs(120);
    assert!(behaviour.record_established(peer_id, stable_connection, true, stable_since));
    assert!(behaviour.record_closed(
        peer_id,
        stable_connection,
        0,
        stable_since + STABLE_SESSION_DURATION
    ));
    assert_eq!(behaviour.peer(&peer_id).unwrap().failures, 1);
    assert_eq!(
        behaviour.earliest_retry(),
        Some(stable_since + STABLE_SESSION_DURATION + DIAL_RETRY_BASE)
    );
}

#[test]
fn canonical_direction_is_enforced_for_both_roles() {
    let (owner_id, passive_id) = ordered_peer_ids();
    let now = Instant::now();
    let connection_id = ConnectionId::new_unchecked(201);
    let mut owner = Behaviour::new(owner_id, [StaticPeer::new(passive_id, address())]);
    assert!(!owner.record_established(passive_id, connection_id, false, now));
    owner.peer_mut(&passive_id).unwrap().link = Link::Dialing { connection_id };
    assert!(owner.record_established(passive_id, connection_id, true, now));

    let mut passive = Behaviour::new(passive_id, [StaticPeer::new(owner_id, address())]);
    assert!(!passive.record_established(owner_id, connection_id, true, now));
    assert!(passive.record_established(owner_id, connection_id, false, now));
}

#[test]
fn only_the_managed_owner_generation_can_open_an_outbound_connection() {
    let (owner_id, passive_id) = ordered_peer_ids();
    let mut owner = Behaviour::new(owner_id, [StaticPeer::new(passive_id, address())]);
    let unmanaged = ConnectionId::new_unchecked(301);
    assert!(
        NetworkBehaviour::handle_pending_outbound_connection(
            &mut owner,
            unmanaged,
            Some(passive_id),
            &[],
            Endpoint::Dialer,
        )
        .is_err()
    );
    let managed = owner.start_dial(passive_id).connection_id();
    assert!(
        NetworkBehaviour::handle_pending_outbound_connection(
            &mut owner,
            managed,
            Some(passive_id),
            &[],
            Endpoint::Dialer,
        )
        .is_ok()
    );

    let mut passive = Behaviour::new(passive_id, [StaticPeer::new(owner_id, address())]);
    assert!(
        NetworkBehaviour::handle_pending_outbound_connection(
            &mut passive,
            ConnectionId::new_unchecked(302),
            Some(owner_id),
            &[],
            Endpoint::Dialer,
        )
        .is_err()
    );
}

#[test]
fn inbound_hook_rejects_the_ninth_pre_authentication_attempt() {
    let local = PeerId::random();
    let mut behaviour = Behaviour::new(local, []);
    let listen = address();
    let send = address();
    for index in 0..INBOUND_AUTH_BURST {
        assert!(
            NetworkBehaviour::handle_pending_inbound_connection(
                &mut behaviour,
                ConnectionId::new_unchecked(index as usize),
                &listen,
                &send,
            )
            .is_ok()
        );
    }
    assert!(
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut behaviour,
            ConnectionId::new_unchecked(INBOUND_AUTH_BURST as usize),
            &listen,
            &send,
        )
        .is_err()
    );
}

#[test]
fn a_due_retry_precedes_queued_observability_events() {
    let (mut behaviour, peer_id) = owner_behaviour();
    behaviour
        .pending_events
        .push_back(PeerSessionEvent::DialFailed { peer_id });
    behaviour.peer_mut(&peer_id).unwrap().link = Link::Down {
        retry_at: Some(Instant::now()),
    };
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(matches!(
        NetworkBehaviour::poll(&mut behaviour, &mut context),
        Poll::Ready(ToSwarm::Dial { .. })
    ));
    assert!(matches!(
        NetworkBehaviour::poll(&mut behaviour, &mut context),
        Poll::Ready(ToSwarm::GenerateEvent(PeerSessionEvent::DialFailed {
            peer_id: event_peer
        })) if event_peer == peer_id
    ));
}
