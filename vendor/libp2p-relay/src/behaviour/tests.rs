use super::*;

#[test]
fn reservation_admission_enforces_exact_limits_and_allows_existing_renewal() {
    let mut behaviour = Behaviour::new(
        PeerId::random(),
        Config {
            max_reservations: 16,
            max_reservations_per_peer: 1,
            ..Default::default()
        },
    );
    let mut reservations = vec![];
    for i in 0..16 {
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(i);
        assert!(!behaviour.reservation_limit_reached(peer, connection));
        behaviour
            .reservations
            .entry(peer)
            .or_default()
            .insert(connection);
        // The same authenticated peer cannot consume a second slot.
        assert!(behaviour.reservation_limit_reached(peer, ConnectionId::new_unchecked(100 + i)));
        reservations.push((peer, connection));
    }
    assert!(
        behaviour.reservation_limit_reached(PeerId::random(), ConnectionId::new_unchecked(1000))
    );
    for (peer, connection) in &reservations {
        assert!(!behaviour.reservation_limit_reached(*peer, *connection));
    }
    let (peer, connection) = reservations[0];
    behaviour.on_connection_closed(ConnectionClosed {
        peer_id: peer,
        connection_id: connection,
        endpoint: &ConnectedPoint::Dialer {
            address: "/memory/123".parse().unwrap(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        },
        cause: None,
        remaining_established: 0,
    });
    assert!(
        !behaviour.reservation_limit_reached(PeerId::random(), ConnectionId::new_unchecked(1000))
    );
}

#[test]
fn pending_circuits_count_toward_source_and_global_admission() {
    let mut behaviour = Behaviour::new(
        PeerId::random(),
        Config {
            max_circuits: 16,
            max_circuits_per_peer: 4,
            ..Default::default()
        },
    );
    let destination = PeerId::random();
    let mut circuits = vec![];
    for group in 0..4 {
        let source = PeerId::random();
        for i in 0..4 {
            assert!(!behaviour.circuit_limit_reached(source));
            circuits.push(behaviour.circuits.insert(Circuit {
                status: CircuitStatus::Accepting,
                src_peer_id: source,
                dst_peer_id: destination,
                src_connection_id: ConnectionId::new_unchecked(group * 4 + i),
                dst_connection_id: ConnectionId::new_unchecked(100),
            }));
        }
        assert!(behaviour.circuit_limit_reached(source));
    }
    // Destination-only traffic can exceed four, but still consumes global slots.
    assert_eq!(behaviour.circuits.len(), 16);
    assert!(behaviour.circuit_limit_reached(PeerId::random()));
    behaviour.circuits.remove(circuits[0]);
    assert!(!behaviour.circuit_limit_reached(PeerId::random()));
}

#[test]
fn destination_circuits_do_not_consume_source_admission_capacity() {
    let mut behaviour = Behaviour::new(
        PeerId::random(),
        Config {
            max_circuits: 16,
            max_circuits_per_peer: 4,
            ..Default::default()
        },
    );
    let peer = PeerId::random();
    let mut incoming = vec![];
    for i in 0..4 {
        incoming.push(behaviour.circuits.insert(Circuit {
            status: CircuitStatus::Accepting,
            src_peer_id: PeerId::random(),
            dst_peer_id: peer,
            src_connection_id: ConnectionId::new_unchecked(i),
            dst_connection_id: ConnectionId::new_unchecked(100),
        }));
        if i % 2 == 0 {
            behaviour.circuits.accepted(incoming[i]);
        }
    }
    // Receiving four pending/accepted circuits leaves all four source slots free.
    assert!(!behaviour.circuit_limit_reached(peer));
    let mut outgoing = vec![];
    for i in 0..4 {
        assert!(!behaviour.circuit_limit_reached(peer));
        outgoing.push(behaviour.circuits.insert(Circuit {
            status: CircuitStatus::Accepting,
            src_peer_id: peer,
            dst_peer_id: PeerId::random(),
            src_connection_id: ConnectionId::new_unchecked(200 + i),
            dst_connection_id: ConnectionId::new_unchecked(300 + i),
        }));
        if i % 2 == 0 {
            behaviour.circuits.accepted(outgoing[i]);
        }
    }
    assert!(behaviour.circuit_limit_reached(peer));
    assert_eq!(behaviour.circuits.len(), 8);
    // Releasing a destination slot does not release one of this peer's source slots.
    behaviour.circuits.remove(incoming[0]);
    assert!(behaviour.circuit_limit_reached(peer));
    behaviour.circuits.remove(outgoing[0]);
    assert!(!behaviour.circuit_limit_reached(peer));
    // Other sources can fill global capacity without consuming this source's slots.
    let mut other = vec![];
    while behaviour.circuits.len() < 16 {
        other.push(behaviour.circuits.insert(Circuit {
            status: CircuitStatus::Accepting,
            src_peer_id: PeerId::random(),
            dst_peer_id: peer,
            src_connection_id: ConnectionId::new_unchecked(400 + other.len()),
            dst_connection_id: ConnectionId::new_unchecked(100),
        }));
    }
    assert!(behaviour.circuit_limit_reached(peer));
    behaviour.circuits.remove(other[0]);
    assert!(!behaviour.circuit_limit_reached(peer));
}
