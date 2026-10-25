use super::*;

fn peer() -> PeerId {
    identity::Keypair::generate_ed25519().public().to_peer_id()
}
fn connection(index: usize) -> ConnectionId {
    ConnectionId::new_unchecked(index)
}

#[test]
fn rotating_keys_from_one_network_cannot_fill_contact_capacity() {
    let mut book = Book::new(peer(), true, &Config::default());
    let now = Instant::now();
    let address = "/ip4/8.8.8.1/tcp/4001".parse().unwrap();
    for index in 0..crate::resources::limits().contacts / 4 {
        book.admit_connection(connection(index), peer(), &address, false, now)
            .unwrap();
    }
    for index in 100..200 {
        assert!(
            book.admit_connection(connection(index), peer(), &address, false, now)
                .is_err()
        );
    }
    assert_eq!(book.contacts.len(), crate::resources::limits().contacts / 4);
    let other = "/ip4/9.9.9.1/tcp/4001".parse().unwrap();
    book.admit_connection(connection(200), peer(), &other, true, now)
        .unwrap();
}

#[test]
fn incoming_peers_leave_capacity_for_authenticated_outgoing_connections() {
    let mut book = Book::new(peer(), true, &Config::default());
    let now = Instant::now();
    for index in 0..crate::resources::limits().contacts / 4 {
        let address = format!("/ip4/8.{}.1.1/tcp/4001", index + 1)
            .parse()
            .unwrap();
        book.admit_connection(connection(index), peer(), &address, false, now)
            .unwrap();
    }
    let address = "/ip4/9.9.9.1/tcp/4001".parse().unwrap();
    assert!(
        book.admit_connection(connection(100), peer(), &address, false, now)
            .is_err()
    );
    book.admit_connection(connection(101), peer(), &address, true, now)
        .unwrap();
}

#[test]
fn authenticated_peer_replaces_a_poisoned_unreachable_hint_without_exceeding_caps() {
    let mut book = Book::new(peer(), true, &Config::default());
    let now = Instant::now();
    for index in 0..crate::resources::limits().contacts {
        let address = format!("/ip4/8.{}.1.1/tcp/4001", index + 1)
            .parse()
            .unwrap();
        book.hint(peer(), &address, now).unwrap();
    }
    let good = peer();
    let address = "/ip4/9.9.9.1/tcp/4001".parse().unwrap();
    book.admit_connection(connection(1), good, &address, true, now)
        .unwrap();
    assert!(!book.contacts.contains_key(&good));
    book.retain_authenticated(good, now).unwrap();
    assert!(book.contacts[&good].connected);
    assert_eq!(book.contacts.len(), crate::resources::limits().contacts);
    assert_eq!(book.removed.len(), 1);
}

#[test]
fn live_unpinned_identities_have_a_finite_lease_and_handshake_churn_is_bounded() {
    let mut book = Book::new(peer(), true, &Config::default());
    let now = Instant::now();
    let address = "/ip6/2606:4700:4700::1111/tcp/4001".parse().unwrap();
    for _ in 0..crate::resources::limits().request_burst {
        book.incoming_attempt(&address, now).unwrap();
    }
    assert!(book.incoming_attempt(&address, now).is_err());
    book.incoming_attempt(
        &address,
        now + crate::resources::limits().request_rate_window,
    )
    .unwrap();
    let remote = peer();
    book.admit_connection(connection(1), remote, &address, false, now)
        .unwrap();
    assert_eq!(
        book.expired(now + crate::resources::limits().contact_ttl * 4),
        [remote]
    );
    book.closed_connection(connection(1));
    assert!(!book.contacts[&remote].connected);
}

#[test]
fn public_routing_connections_are_transient_until_authenticated_protocol_admission() {
    let mut book = Book::new(peer(), true, &Config::default());
    let now = Instant::now();
    let router = peer();
    let address = "/ip4/8.8.8.1/tcp/4001".parse().unwrap();
    book.admit_connection(connection(1), router, &address, true, now)
        .unwrap();
    assert!(book.contacts.is_empty());
    assert_eq!(book.admission.connections.len(), 1);
    book.closed_connection(connection(1));
    assert!(book.admission.connections.is_empty());
    assert!(book.contacts.is_empty());
}

#[test]
fn circuit_endpoint_is_never_saved_as_the_proof_peers_direct_address() {
    let mut book = Book::new(peer(), true, &Config::default());
    let now = Instant::now();
    let remote = peer();
    let relay = peer();
    book.retain_authenticated(remote, now).unwrap();
    let address = format!("/ip4/8.8.8.1/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{remote}")
        .parse()
        .unwrap();
    book.admit_connection(connection(1), remote, &address, true, now)
        .unwrap();
    assert!(book.contacts[&remote].addresses.is_empty());
    assert!(book.contacts[&remote].connected);
}

#[test]
fn selected_relays_survive_proof_leases_until_their_reservation_is_retired() {
    let mut book = Book::new(peer(), true, &Config::default());
    let now = Instant::now();
    let relay = peer();
    book.retain_authenticated(relay, now).unwrap();
    book.relays.insert(relay);
    let deadline = now + crate::resources::limits().contact_ttl * 4;
    assert!(book.expired(deadline).is_empty());
    book.relays.remove(&relay);
    assert_eq!(book.expired(deadline), [relay]);
}
