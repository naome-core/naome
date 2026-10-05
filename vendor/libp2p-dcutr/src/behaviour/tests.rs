use super::*;
use libp2p_swarm::{behaviour::ConnectionEstablished, DialError};

fn admit_direct(behaviour: &mut Behaviour, peer: PeerId, connection: ConnectionId, inbound: bool) {
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/12345".parse().unwrap();
    let endpoint = if inbound {
        ConnectedPoint::Listener {
            local_addr: address.clone(),
            send_back_addr: address,
        }
    } else {
        ConnectedPoint::Dialer {
            address,
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        }
    };
    behaviour.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
        peer_id: peer,
        connection_id: connection,
        endpoint: &endpoint,
        failed_addresses: &[],
        other_established: 0,
    }));
}

fn establish_direct(
    behaviour: &mut Behaviour,
    peer: PeerId,
    connection: ConnectionId,
    inbound: bool,
) {
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/12345".parse().unwrap();
    if inbound {
        behaviour
            .handle_established_inbound_connection(connection, peer, &address, &address)
            .unwrap();
    } else {
        behaviour
            .handle_established_outbound_connection(
                connection,
                peer,
                &address,
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
    }
    admit_direct(behaviour, peer, connection, inbound);
}

fn negotiate(
    behaviour: &mut Behaviour,
    peer: PeerId,
    circuit: ConnectionId,
    listener: bool,
) -> ConnectionId {
    let remote_addrs = vec!["/ip4/127.0.0.1/tcp/12345".parse().unwrap()];
    let event = if listener {
        handler::relayed::Event::OutboundConnectNegotiated { remote_addrs }
    } else {
        handler::relayed::Event::InboundConnectNegotiated { remote_addrs }
    };
    behaviour.on_connection_handler_event(peer, circuit, Either::Left(event));
    let Some(ToSwarm::Dial { opts }) = behaviour.queued_events.pop_front() else {
        panic!("negotiation must dial")
    };
    opts.connection_id()
}

fn fail(behaviour: &mut Behaviour, peer: Option<PeerId>, direct: ConnectionId) {
    behaviour.on_dial_failure(DialFailure {
        peer_id: peer,
        connection_id: direct,
        error: &DialError::Aborted,
    });
}

fn close(behaviour: &mut Behaviour, peer: PeerId, connection: ConnectionId, relayed: bool) {
    let address = if relayed {
        "/ip4/127.0.0.1/tcp/12345/p2p-circuit"
    } else {
        "/ip4/127.0.0.1/tcp/12345"
    }
    .parse()
    .unwrap();
    behaviour.on_connection_closed(ConnectionClosed {
        peer_id: peer,
        connection_id: connection,
        endpoint: &ConnectedPoint::Dialer {
            address,
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        },
        cause: None,
        remaining_established: 0,
    });
}

#[test]
fn repeated_failed_upgrades_preserve_three_retries_without_historical_entries() {
    let peer = PeerId::random();
    let mut behaviour = Behaviour::new(PeerId::random());
    for cycle in 0..512 {
        let circuit = ConnectionId::new_unchecked(cycle);
        for attempt in 1..=MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
            let direct = negotiate(&mut behaviour, peer, circuit, true);
            assert_eq!(behaviour.direct_to_relayed_connections.len(), 1);
            fail(&mut behaviour, Some(peer), direct);
            assert!(behaviour.direct_to_relayed_connections.is_empty());
            if attempt < MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
                assert!(matches!(
                    behaviour.queued_events.pop_front(),
                    Some(ToSwarm::NotifyHandler { handler: NotifyHandler::One(id), .. })
                        if id == circuit
                ));
                assert_eq!(behaviour.outgoing_direct_connection_attempts.len(), 1);
            } else {
                assert!(matches!(
                    behaviour.queued_events.pop_front(),
                    Some(ToSwarm::GenerateEvent(Event {
                        result: Err(Error {
                            inner: InnerError::AttemptsExceeded(3)
                        }),
                        ..
                    }))
                ));
                assert!(behaviour.outgoing_direct_connection_attempts.is_empty());
            }
        }
        close(&mut behaviour, peer, circuit, true);
        assert!(behaviour.queued_events.is_empty());
    }
}

#[test]
fn failed_inbound_and_peerless_dials_release_pending_state() {
    let peer = PeerId::random();
    let mut behaviour = Behaviour::new(PeerId::random());
    for cycle in 0..512 {
        let circuit = ConnectionId::new_unchecked(cycle);
        let direct = negotiate(&mut behaviour, peer, circuit, false);
        fail(&mut behaviour, Some(peer), direct);
        assert!(behaviour.direct_to_relayed_connections.is_empty());
        let direct = negotiate(&mut behaviour, peer, circuit, true);
        fail(&mut behaviour, None, direct);
        assert!(behaviour.direct_to_relayed_connections.is_empty());
        assert!(behaviour.outgoing_direct_connection_attempts.is_empty());
        assert!(behaviour.queued_events.is_empty());
    }
}

#[test]
fn closed_circuit_cancels_queued_retry_and_preserves_other_circuit() {
    let peer = PeerId::random();
    let mut behaviour = Behaviour::new(PeerId::random());
    let other = ConnectionId::new_unchecked(9999);
    let other_direct = negotiate(&mut behaviour, peer, other, true);
    for cycle in 0..512 {
        let circuit = ConnectionId::new_unchecked(cycle);
        let direct = negotiate(&mut behaviour, peer, circuit, true);
        fail(&mut behaviour, Some(peer), direct);
        close(&mut behaviour, peer, circuit, true);
        assert!(behaviour.queued_events.is_empty());
        assert_eq!(behaviour.direct_to_relayed_connections.len(), 1);
        assert_eq!(
            behaviour.direct_to_relayed_connections[&other_direct],
            other
        );
        assert_eq!(behaviour.outgoing_direct_connection_attempts.len(), 1);
    }
    close(&mut behaviour, peer, other, true);
    assert!(behaviour.direct_to_relayed_connections.is_empty());
    assert!(behaviour.outgoing_direct_connection_attempts.is_empty());
}

#[test]
fn successful_upgrades_and_late_callbacks_do_not_retain_history_or_panic() {
    let peer = PeerId::random();
    let mut behaviour = Behaviour::new(PeerId::random());
    for cycle in 0..512 {
        let circuit = ConnectionId::new_unchecked(cycle);
        let listener = cycle % 2 == 0;
        let direct = negotiate(&mut behaviour, peer, circuit, listener);
        let late = cycle % 3 == 0;
        if late {
            close(&mut behaviour, peer, circuit, true);
        }
        behaviour
            .handle_established_outbound_connection(
                direct,
                peer,
                &"/ip4/127.0.0.1/tcp/12345".parse().unwrap(),
                if listener {
                    Endpoint::Listener
                } else {
                    Endpoint::Dialer
                },
                PortUse::New,
            )
            .unwrap();
        assert!(behaviour.direct_connections.is_empty());
        assert!(behaviour.queued_events.is_empty());
        if !late {
            assert_eq!(behaviour.direct_to_relayed_connections.len(), 1);
        }
        admit_direct(&mut behaviour, peer, direct, false);
        assert!(behaviour.direct_to_relayed_connections.is_empty());
        assert!(behaviour.outgoing_direct_connection_attempts.is_empty());
        if !late {
            assert!(matches!(behaviour.queued_events.pop_front(),
                Some(ToSwarm::GenerateEvent(Event { result: Ok(id), .. })) if id == direct));
        }
        close(&mut behaviour, peer, direct, false);
        close(&mut behaviour, peer, circuit, true);
        assert!(behaviour.direct_connections.is_empty());
        assert!(behaviour.queued_events.is_empty());
    }
}

#[test]
fn terminal_protocol_errors_clear_retry_state() {
    let peer = PeerId::random();
    let mut behaviour = Behaviour::new(PeerId::random());
    for cycle in 0..512 {
        let circuit = ConnectionId::new_unchecked(cycle);
        negotiate(&mut behaviour, peer, circuit, true);
        let event = if cycle % 2 == 0 {
            handler::relayed::Event::OutboundConnectFailed {
                error: protocol::outbound::Error::Unsupported,
            }
        } else {
            handler::relayed::Event::InboundConnectFailed {
                error: protocol::inbound::Error::Io(std::io::ErrorKind::UnexpectedEof.into()),
            }
        };
        behaviour.on_connection_handler_event(peer, circuit, Either::Left(event));
        assert!(behaviour.direct_to_relayed_connections.is_empty());
        assert!(behaviour.outgoing_direct_connection_attempts.is_empty());
        assert!(matches!(
            behaviour.queued_events.pop_front(),
            Some(ToSwarm::GenerateEvent(Event { result: Err(_), .. }))
        ));
        close(&mut behaviour, peer, circuit, true);
    }
}

#[test]
fn outbound_sibling_admission_rejection_preserves_retries_without_success_or_history() {
    let peer = PeerId::random();
    let mut behaviour = Behaviour::new(PeerId::random());
    let accepted = ConnectionId::new_unchecked(1_000_000);
    establish_direct(&mut behaviour, peer, accepted, false);
    for cycle in 0..512 {
        let circuit = ConnectionId::new_unchecked(2_000_000 + cycle);
        for attempt in 1..=MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
            let direct = negotiate(&mut behaviour, peer, circuit, true);
            behaviour
                .handle_established_outbound_connection(
                    direct,
                    peer,
                    &"/ip4/127.0.0.1/tcp/12345".parse().unwrap(),
                    Endpoint::Listener,
                    PortUse::New,
                )
                .unwrap();
            // The Swarm constructs our handler before a later sibling denies
            // the connection. No aggregate ConnectionEstablished follows.
            let premature_success = behaviour
                .queued_events
                .iter()
                .any(|event| matches!(event, ToSwarm::GenerateEvent(Event { result: Ok(_), .. })));
            behaviour.on_swarm_event(FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer),
                connection_id: direct,
                error: &DialError::Denied {
                    cause: ConnectionDenied::new(std::io::Error::other("sibling connection limit")),
                },
            }));
            assert!(
                !premature_success,
                "success was reported before aggregate admission"
            );
            assert_eq!(
                behaviour.direct_connections[&peer],
                HashSet::from([accepted])
            );
            assert!(behaviour.direct_to_relayed_connections.is_empty());
            let event = behaviour
                .queued_events
                .pop_front()
                .expect("retry or terminal error");
            if attempt < MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
                assert!(
                    matches!(event, ToSwarm::NotifyHandler { handler: NotifyHandler::One(id), .. }
                    if id == circuit)
                );
                assert_eq!(behaviour.outgoing_direct_connection_attempts.len(), 1);
            } else {
                assert!(matches!(
                    event,
                    ToSwarm::GenerateEvent(Event { result: Err(_), .. })
                ));
                assert!(behaviour.outgoing_direct_connection_attempts.is_empty());
            }
            assert!(behaviour.queued_events.is_empty());
        }
        close(&mut behaviour, peer, circuit, true);
    }
    close(&mut behaviour, peer, accepted, false);
    assert!(behaviour.direct_connections.is_empty());
}

#[test]
fn inbound_sibling_admission_rejection_does_not_retain_connections_or_emit_success() {
    let peer = PeerId::random();
    let mut behaviour = Behaviour::new(PeerId::random());
    let accepted = ConnectionId::new_unchecked(3_000_000);
    establish_direct(&mut behaviour, peer, accepted, true);
    let local: Multiaddr = "/ip4/127.0.0.1/tcp/12345".parse().unwrap();
    let remote: Multiaddr = "/ip4/127.0.0.1/tcp/23456".parse().unwrap();
    for cycle in 0..512 {
        let rejected = ConnectionId::new_unchecked(4_000_000 + cycle);
        behaviour
            .handle_established_inbound_connection(rejected, peer, &local, &remote)
            .unwrap();
        behaviour.on_swarm_event(FromSwarm::ListenFailure(
            libp2p_swarm::behaviour::ListenFailure {
                connection_id: rejected,
                peer_id: Some(peer),
                local_addr: &local,
                send_back_addr: &remote,
                error: &libp2p_swarm::ListenError::Denied {
                    cause: ConnectionDenied::new(std::io::Error::other("sibling connection limit")),
                },
            },
        ));
        assert_eq!(
            behaviour.direct_connections[&peer],
            HashSet::from([accepted])
        );
        assert!(behaviour.direct_to_relayed_connections.is_empty());
        assert!(behaviour.outgoing_direct_connection_attempts.is_empty());
        assert!(behaviour.queued_events.is_empty());
    }
    close(&mut behaviour, peer, accepted, false);
    assert!(behaviour.direct_connections.is_empty());
}
