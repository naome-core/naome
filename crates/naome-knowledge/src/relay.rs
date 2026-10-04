//! Operator-run relay infrastructure. This service routes encrypted circuits
//! and discovery hints; it neither owns a proof graph nor checks/adopts proofs.

use crate::{discovery, network};
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder, connection_limits,
    futures::StreamExt,
    identity, noise, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const MAX_CIRCUITS: usize = 16;
pub const MAX_RESERVATIONS: usize = 16;
pub const MAX_SOURCE_CIRCUITS: usize = 4;
pub const MAX_CIRCUIT_BYTES: u64 = 8 * 1024 * 1024;
pub const CIRCUIT_DURATION: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    directory: PathBuf,
    listen: String,
    #[serde(default)]
    external_addresses: Vec<String>,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gate: discovery::Gate,
    limits: connection_limits::Behaviour,
    discovery: discovery::Behaviour,
    relay: relay::Behaviour,
}

fn rate_limiter() -> Box<dyn relay::RateLimiter> {
    // The default library limiter retains one bucket per historical identity.
    // Use an explicit count and short finite window for this bounded service.
    let buckets = Arc::new(Mutex::new(BTreeMap::<PeerId, (Instant, u8)>::new()));
    Box::new(move |peer, _: &Multiaddr, now: Instant| {
        let mut buckets = buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        buckets.retain(|_, (since, _)| now.duration_since(*since) < Duration::from_secs(2));
        if buckets.len() >= discovery::MAX_CONTACTS && !buckets.contains_key(&peer) {
            return false;
        }
        let (_, tokens) = buckets.entry(peer).or_insert((now, 4));
        if *tokens == 0 {
            return false;
        }
        *tokens -= 1;
        true
    })
}

pub async fn run(path: &Path) -> Result<(), String> {
    let mut config: Config = serde_json::from_slice(&crate::store::read_bounded(
        path,
        network::MAX_CONFIG_BYTES,
    )?)
    .map_err(|error| error.to_string())?;
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
    .map_err(|error| error.to_string())?;
    let own = key.public().to_peer_id();
    if config.external_addresses.len() > discovery::MAX_ADDRESSES {
        return Err("relay advertised address capacity".into());
    }
    let listen: Multiaddr = config
        .listen
        .parse()
        .map_err(|error| format!("relay listen: {error}"))?;
    network::require_tcp_address(&listen)?;
    let settings = discovery::Config {
        mdns: false,
        dht: true,
        hole_punch: false,
        ..Default::default()
    };
    let mut book = discovery::Book::new(own, true, &settings);
    // Provider records may refer to circuits through this service itself.
    book.relays.insert(own);
    let book = discovery::SharedBook::new(book);
    let mut discovery = discovery::Behaviour::new(&key, &settings, true, true)?;
    if let Some(kad) = discovery.kad.as_mut() {
        kad.store_mut().set_relays(book.lock().relays.clone());
    }
    let limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(16))
            .with_max_pending_outgoing(Some(16))
            .with_max_established(Some(32))
            .with_max_established_per_peer(Some(2)),
    );
    let relay = relay::Behaviour::new(
        own,
        relay::Config {
            max_reservations: MAX_RESERVATIONS,
            max_reservations_per_peer: 1,
            reservation_duration: CIRCUIT_DURATION,
            reservation_rate_limiters: vec![rate_limiter()],
            max_circuits: MAX_CIRCUITS,
            // The local dependency patch uses inclusive pre-insertion limits.
            // Destination-only circuits retain the global circuit bound.
            max_circuits_per_peer: MAX_SOURCE_CIRCUITS,
            max_circuit_duration: CIRCUIT_DURATION,
            max_circuit_bytes: MAX_CIRCUIT_BYTES,
            circuit_src_rate_limiters: vec![rate_limiter()],
        },
    );
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            network::yamux_config,
        )
        .map_err(|error| error.to_string())?
        .with_dns()
        .map_err(|error| error.to_string())?
        .with_behaviour(|_| Behaviour {
            gate: discovery::Gate(book.clone()),
            limits,
            discovery,
            relay,
        })
        .map_err(|error| error.to_string())?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(Duration::from_secs(60))
                .with_max_negotiating_inbound_streams(16)
        })
        .with_connection_timeout(network::REQUEST_TIMEOUT)
        .build();
    swarm.listen_on(listen).map_err(|error| error.to_string())?;
    let use_listen_addresses = config.external_addresses.is_empty();
    let mut advertised = BTreeSet::new();
    for address in config.external_addresses {
        let address: Multiaddr = address
            .parse()
            .map_err(|error| format!("relay external address: {error}"))?;
        let address = discovery::routing_address(&address, own, &BTreeSet::new())?;
        swarm.add_external_address(address.clone());
        advertised.insert(address);
    }
    let mut state = discovery::State::new(book.clone(), settings, true);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    network::emit(
        json!({"event":"relay_starting", "peer_id":own.to_string(), "compatibility":crate::hex(&crate::compatibility())}),
    );
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    // Relay-v2 reservations must contain at least one relay
                    // endpoint. For local operation advertise bounded concrete
                    // listeners; public mappings use explicit operator hints.
                    if use_listen_addresses && advertised.len() < discovery::MAX_ADDRESSES
                        && discovery::routing_address(&address, own, &BTreeSet::new()).is_ok()
                        && advertised.insert(address.clone()) {
                        swarm.add_external_address(address.clone());
                        network::emit(json!({"event":"relay_advertised", "address":address.to_string(), "source":"local_listener"}));
                    }
                    network::emit(json!({"event":"ready", "address":address.to_string()}));
                },
                SwarmEvent::ListenerError { error, .. } => return Err(format!("relay listener: {error}")),
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                    if let Ok(contact) = book.lock().admit(peer_id, Instant::now()) {
                        contact.connected = true; contact.connected_at.get_or_insert(Instant::now());
                    }
                    network::emit(json!({"event":"relay_connected", "peer":peer_id.to_string(), "connection_id":connection_id.to_string()}));
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
                SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => network::emit(json!({"event":"relay_service", "detail":format!("{event:?}")})),
                _ => {}
            },
            _ = tick.tick() => {
                state.tick(&mut swarm.behaviour_mut().discovery);
                let expired = book.lock().expired(Instant::now());
                for peer in expired {
                    book.lock().retire(peer, Instant::now());
                    if let Some(kad) = swarm.behaviour_mut().discovery.kad.as_mut() { kad.remove_peer(&peer); }
                    network::emit(json!({"event":"contact_expired", "peer":peer.to_string()}));
                }
                let unidentified: Vec<_> = book.lock().contacts.iter().filter_map(|(peer, contact)| {
                    (contact.connected && !contact.compatible && contact.connected_at.is_some_and(|since| since.elapsed() >= discovery::IDENTIFY_TIMEOUT)).then_some(*peer)
                }).collect();
                for peer in unidentified { let _ = swarm.disconnect_peer_id(peer); }
            },
            signal = network::shutdown_signal() => { signal?; break; }
        }
    }
    network::emit(json!({"event":"stopped", "role":"relay"}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limits_reject_bursts_and_unknown_identities_until_bounded_window_expires() {
        let mut limiter = rate_limiter();
        let address = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
        let peer = || identity::Keypair::generate_ed25519().public().to_peer_id();
        let first = peer();
        let now = Instant::now();
        for _ in 0..4 {
            assert!(limiter.try_next(first, &address, now));
        }
        assert!(!limiter.try_next(first, &address, now));
        for _ in 1..discovery::MAX_CONTACTS {
            assert!(limiter.try_next(peer(), &address, now));
        }
        let extra = peer();
        assert!(!limiter.try_next(extra, &address, now + Duration::from_secs(1)));
        assert!(limiter.try_next(extra, &address, now + Duration::from_secs(2)));
        assert!(limiter.try_next(first, &address, now + Duration::from_secs(2)));
    }
}
