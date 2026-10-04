use super::*;
use libp2p_swarm::DialError;

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
