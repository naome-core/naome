//! Operator-run relay infrastructure. This service routes encrypted circuits
//! and discovery hints; it neither owns a proof graph nor checks/adopts proofs.

use crate::{
    discovery, network,
    quota::{Quota, Rate},
};
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder, connection_limits,
    futures::StreamExt,
    identity, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use serde::Deserialize;
use serde_json::json;
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    directory: PathBuf,
    listen: String,
    #[serde(default)]
    external_addresses: Vec<String>,
    #[serde(default)]
    allow_private_addresses: bool,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gate: discovery::Gate,
    limits: connection_limits::Behaviour,
    discovery: discovery::Behaviour,
    relay: relay::Behaviour,
}

fn relay_status(status: relay::StatusCode) -> crate::outcome::RelayStatus {
    use crate::outcome::RelayStatus as Code;
    match status {
        relay::StatusCode::OK => Code::Ok,
        relay::StatusCode::ReservationRefused => Code::ReservationRefused,
        relay::StatusCode::ResourceLimitExceeded => Code::ResourceLimitExceeded,
        relay::StatusCode::PermissionDenied => Code::PermissionDenied,
        relay::StatusCode::ConnectionFailed => Code::ConnectionFailed,
        relay::StatusCode::NoReservation => Code::NoReservation,
        relay::StatusCode::MalformedMessage => Code::MalformedMessage,
        relay::StatusCode::UnexpectedMessage => Code::UnexpectedMessage,
    }
}

fn relay_event(event: relay::Event) -> serde_json::Value {
    use crate::outcome::{NodeEvent, RelayEventKind as Kind};
    match event {
        relay::Event::ReservationReqAccepted {
            src_peer_id,
            renewed,
        } => {
            json!({"event":NodeEvent::RelayService,"kind":Kind::ReservationAccepted,"source":src_peer_id.to_string(),"renewed":renewed})
        }
        relay::Event::ReservationReqDenied {
            src_peer_id,
            status,
        } => {
            json!({"event":NodeEvent::RelayService,"kind":Kind::ReservationDenied,"source":src_peer_id.to_string(),"status":relay_status(status)})
        }
        relay::Event::ReservationClosed { src_peer_id } => {
            json!({"event":NodeEvent::RelayService,"kind":Kind::ReservationClosed,"source":src_peer_id.to_string()})
        }
        relay::Event::ReservationTimedOut { src_peer_id } => {
            json!({"event":NodeEvent::RelayService,"kind":Kind::ReservationTimedOut,"source":src_peer_id.to_string()})
        }
        relay::Event::CircuitReqDenied {
            src_peer_id,
            dst_peer_id,
            status,
        } => {
            json!({"event":NodeEvent::RelayService,"kind":Kind::CircuitDenied,"source":src_peer_id.to_string(),"destination":dst_peer_id.to_string(),"status":relay_status(status)})
        }
        relay::Event::CircuitReqAccepted {
            src_peer_id,
            dst_peer_id,
        } => {
            json!({"event":NodeEvent::RelayService,"kind":Kind::CircuitAccepted,"source":src_peer_id.to_string(),"destination":dst_peer_id.to_string()})
        }
        relay::Event::CircuitClosed {
            src_peer_id,
            dst_peer_id,
            error,
        } => {
            json!({"event":NodeEvent::RelayService,"kind":Kind::CircuitClosed,"source":src_peer_id.to_string(),"destination":dst_peer_id.to_string(),"error":error.map(|error| json!({"kind":crate::outcome::io_fault_kind(&error),"os_code":error.raw_os_error()}))})
        }
    }
}

fn rate_limiter() -> Box<dyn relay::RateLimiter> {
    // The default library limiter retains one bucket per historical identity.
    // Use an explicit count and short finite window for this bounded service.
    let buckets = Arc::new(Mutex::new(BTreeMap::<PeerId, Quota>::new()));
    let rate = Rate {
        burst: crate::resources::limits().relay_request_burst,
        period: crate::resources::limits().relay_rate_window,
    };
    Box::new(move |peer, _: &Multiaddr, now: Instant| {
        let mut buckets = buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        buckets.retain(|_, quota| !quota.expired(now, rate));
        if buckets.len() >= crate::resources::limits().contacts && !buckets.contains_key(&peer) {
            return false;
        }
        buckets
            .entry(peer)
            .or_insert_with(|| Quota::new(now))
            .try_take(now, rate)
    })
}

pub async fn run(path: &Path) -> Result<(), crate::Error> {
    use crate::{InputFault, InputLimit, RuntimeFailure};
    let shutdown = network::shutdown_signal().map_err(|_| RuntimeFailure::RelaySignal)?;
    tokio::pin!(shutdown);
    let mut config: Config = serde_json::from_slice(&crate::store::read_bounded(
        path,
        crate::resources::limits().network_config_bytes,
    )?)
    .map_err(|error| crate::Error::RuntimeContext {
        code: crate::RuntimeFailure::RelayConfigParse,
        cause: Box::new(crate::error::config_decode(error)),
    })?;
    if config.directory.is_relative() {
        config.directory = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&config.directory);
    }
    let _identity_lock = crate::store::Store::open(&config.directory)?;
    let key = identity::Keypair::from_protobuf_encoding(&crate::store::read_bounded(
        &config.directory.join("identity.key"),
        1024,
    )?)
    .map_err(|_| RuntimeFailure::RelayIdentity)?;
    let own = key.public().to_peer_id();
    if config.external_addresses.len() > crate::resources::limits().addresses_per_contact {
        return Err(crate::Error::InputLimit(InputLimit::RelayAddressCapacity));
    }
    let listen: Multiaddr = config
        .listen
        .parse()
        .map_err(|_| crate::Error::InputFault(InputFault::RelayListenAddress))?;
    network::require_tcp_address(&listen)
        .map_err(|_| crate::Error::InputFault(InputFault::RelayListenAddress))?;
    let settings = discovery::Config {
        mdns: false,
        dht: true,
        internet: false,
        allow_private_addresses: config.allow_private_addresses,
        hole_punch: false,
        ..Default::default()
    };
    let mut book = discovery::Book::new(own, true, &settings);
    // Provider records may refer to circuits through this service itself.
    book.relays.insert(own);
    let book = discovery::SharedBook::new(book);
    let mut discovery = discovery::Behaviour::new(&key, &settings, true, true)
        .map_err(|_| RuntimeFailure::RelayDiscovery)?;
    if let Some(kad) = discovery.kad.as_mut() {
        kad.store_mut().set_relays(book.lock().relays.clone());
    }
    let limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(crate::resources::limits().pending_connections))
            .with_max_pending_outgoing(Some(crate::resources::limits().pending_connections))
            .with_max_established(Some(crate::resources::limits().established_connections))
            .with_max_established_per_peer(Some(crate::resources::limits().connections_per_peer)),
    );
    let relay = relay::Behaviour::new(
        own,
        relay::Config {
            max_reservations: crate::resources::limits().relay_reservations,
            max_reservations_per_peer: crate::resources::limits().relay_reservations_per_peer,
            reservation_duration: crate::resources::limits().relay_circuit_duration,
            reservation_rate_limiters: vec![rate_limiter()],
            max_circuits: crate::resources::limits().relay_circuits,
            // The local dependency patch uses inclusive pre-insertion limits.
            // Destination-only circuits retain the global circuit bound.
            max_circuits_per_peer: crate::resources::limits().relay_circuits_per_peer,
            max_circuit_duration: crate::resources::limits().relay_circuit_duration,
            max_circuit_bytes: crate::resources::limits().relay_circuit_bytes,
            circuit_src_rate_limiters: vec![rate_limiter()],
        },
    );
    let tcp_book = book.clone();
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_other_transport(move |key| network::transport::tcp(key, tcp_book))
        .map_err(|_| RuntimeFailure::RelayTransport)?
        .with_behaviour(|_| Behaviour {
            gate: discovery::Gate(book.clone()),
            limits,
            discovery,
            relay,
        })
        .map_err(|_| RuntimeFailure::RelayBehaviour)?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(crate::resources::limits().idle_connection_timeout)
                .with_max_negotiating_inbound_streams(crate::resources::limits().inbound_streams)
        })
        .with_connection_timeout(crate::resources::limits().request_timeout)
        .build();
    swarm
        .listen_on(listen)
        .map_err(|_| RuntimeFailure::RelayListener)?;
    let use_listen_addresses = config.external_addresses.is_empty();
    let mut advertised = BTreeSet::new();
    for address in config.external_addresses {
        let address: Multiaddr = address
            .parse()
            .map_err(|_| crate::Error::InputFault(InputFault::RelayExternalAddress))?;
        let address = discovery::routing_address(&address, own, &BTreeSet::new())
            .map_err(|_| crate::Error::InputFault(InputFault::RelayExternalAddress))?;
        swarm.add_external_address(address.clone());
        advertised.insert(address);
    }
    let mut state = discovery::State::new(book.clone(), settings, true);
    let mut tick = tokio::time::interval(crate::resources::limits().tick_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    network::emit(
        json!({"event":crate::outcome::NodeEvent::RelayStarting, "peer_id":own.to_string(), "compatibility":crate::hex(&crate::compatibility())}),
    );
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    // Relay-v2 reservations must contain at least one relay
                    // endpoint. For local operation advertise bounded concrete
                    // listeners; public mappings use explicit operator hints.
                    if use_listen_addresses && advertised.len() < crate::resources::limits().addresses_per_contact
                        && discovery::routing_address(&address, own, &BTreeSet::new()).is_ok()
                        && advertised.insert(address.clone()) {
                        swarm.add_external_address(address.clone());
                        network::emit(json!({"event":crate::outcome::NodeEvent::RelayAdvertised, "address":address.to_string(), "source":crate::outcome::EventSource::LocalListener}));
                    }
                    network::emit(json!({"event":crate::outcome::NodeEvent::Ready, "address":address.to_string()}));
                },
                SwarmEvent::ListenerError { .. } => return Err(RuntimeFailure::RelayListener.into()),
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                    if let Ok(contact) = book.lock().admit(peer_id, Instant::now()) {
                        contact.connected = true; contact.connected_at.get_or_insert(Instant::now());
                    }
                    network::emit(json!({"event":crate::outcome::NodeEvent::RelayConnected, "peer":peer_id.to_string(), "connection_id":connection_id.to_string()}));
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established:0, .. } => {
                    if let Some(contact) = book.lock().contacts.get_mut(&peer_id) {
                        contact.connected = false; contact.compatible = false; contact.connected_at = None; contact.seen = Instant::now();
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Discovery(event)) => {
                    for action in state.event(event, &mut swarm.behaviour_mut().discovery) {
                        match action {
                            discovery::Action::Contact(peer) | discovery::Action::Compatible(peer) => {
                                let book = book.lock();
                                if let Some(contact) = book.contacts.get(&peer)
                                    && contact.compatible && contact.dht
                                    && let Some(kad) = swarm.behaviour_mut().discovery.kad.as_mut() {
                                    for address in &contact.addresses { kad.add_address(&peer, address.clone()); }
                                }
                            }
                            discovery::Action::Reject(peer) => {
                                if let Some(contact) = book.lock().contacts.get_mut(&peer) { contact.enabled = false; }
                                if let Some(kad) = swarm.behaviour_mut().discovery.kad.as_mut() { kad.remove_peer(&peer); }
                                let _ = swarm.disconnect_peer_id(peer);
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => network::emit(relay_event(event)),
                _ => {}
            },
            _ = tick.tick() => {
                state.tick(&mut swarm.behaviour_mut().discovery);
                let expired = book.lock().expired(Instant::now());
                for peer in expired {
                    book.lock().retire(peer, Instant::now());
                    if let Some(kad) = swarm.behaviour_mut().discovery.kad.as_mut() { kad.remove_peer(&peer); }
                    network::emit(json!({"event":crate::outcome::NodeEvent::ContactExpired, "peer":peer.to_string()}));
                }
                let unidentified: Vec<_> = book.lock().contacts.iter().filter_map(|(peer, contact)| {
                    (contact.connected && !contact.compatible && contact.connected_at.is_some_and(|since| since.elapsed() >= crate::resources::limits().identify_timeout)).then_some(*peer)
                }).collect();
                for peer in unidentified { let _ = swarm.disconnect_peer_id(peer); }
            },
            signal = &mut shutdown => { signal.map_err(|_| RuntimeFailure::RelaySignal)?; break; }
        }
    }
    network::emit(
        json!({"event":crate::outcome::NodeEvent::Stopped, "role":crate::outcome::ServiceRole::Relay}),
    );
    Ok(())
}

#[cfg(test)]
mod tests;
