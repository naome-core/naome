//! A pinned rendezvous and circuit relay supplies routes to already authorized peers.
use crate::node::tcp_address;
use anyhow::{Result, ensure};
use libp2p::{
    Multiaddr, PeerId, core::transport::ListenerId, multiaddr::Protocol, relay, rendezvous,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use std::net::IpAddr;

/// Conservatively exclude special-use, local and IP-translation ranges.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0)
                && !(a == 198 && (18..=19).contains(&b))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // Only ordinary global unicast; exclude 6to4, Teredo, special-use
            // 2001::/23, documentation and IPv4-mapped/NAT64 encodings.
            segments[0] & 0xe000 == 0x2000
                && segments[0] != 0x2002
                && !(segments[0] == 0x2001 && segments[1] < 0x200)
                && !(segments[0] == 0x2001 && segments[1] == 0xdb8)
                && !(segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}

pub const MAX_PEERS: usize = 16;
pub const LOOKUP: Duration = Duration::from_secs(4);
pub const TTL: u64 = 60;
pub fn namespace() -> rendezvous::Namespace {
    rendezvous::Namespace::from_static("naome-rep-archive-v2")
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Config {
    Client {
        bootstrap_id: PeerId,
        bootstrap_address: String,
        #[serde(default)]
        external_address: Option<String>,
        #[serde(default = "relay_enabled")]
        use_relay: bool,
        #[serde(default)]
        allow_private_addresses: bool,
    },
    Server {
        clients: Vec<PeerId>,
        external_address: String,
    },
}

fn relay_enabled() -> bool {
    true
}

#[derive(Default)]
pub struct Routing {
    pub bootstrap: Option<(PeerId, Multiaddr)>,
    pub clients: BTreeSet<PeerId>,
    pub external: Option<Multiaddr>,
    pub allow_private: bool,
    pub use_relay: bool,
    pub observed: Option<Multiaddr>,
    pub reservation: Option<ListenerId>,
    pub learned: BTreeMap<PeerId, Vec<Multiaddr>>,
    pub valid_until: Option<Instant>,
    pub lookup_pending: bool,
    pub next_lookup: Option<Instant>,
    pub next_register: Option<Instant>,
}

impl Routing {
    pub fn new(config: Option<Config>, own: PeerId) -> Result<Self> {
        let mut state = Self::default();
        match config {
            Some(Config::Client {
                bootstrap_id,
                bootstrap_address,
                external_address,
                allow_private_addresses,
                use_relay,
            }) => {
                ensure!(
                    bootstrap_id != own,
                    "bootstrap cannot be the local identity"
                );
                state.bootstrap = Some((bootstrap_id, tcp_address(&bootstrap_address, false)?));
                state.external = external_address
                    .map(|s| tcp_address(&s, false))
                    .transpose()?;
                state.allow_private = allow_private_addresses;
                state.use_relay = use_relay;
                if let Some(address) = &state.external {
                    ensure!(
                        state.direct_allowed(address),
                        "invalid external address for discovery policy"
                    );
                }
            }
            Some(Config::Server {
                clients,
                external_address,
            }) => {
                let count = clients.len();
                state.clients.extend(clients);
                ensure!(
                    count > 0
                        && count <= MAX_PEERS
                        && state.clients.len() == count
                        && !state.clients.contains(&own),
                    "invalid routing service client list"
                );
                state.external = Some(tcp_address(&external_address, false)?);
            }
            None => {}
        }
        Ok(state)
    }

    pub fn circuit(&self) -> Option<Multiaddr> {
        if !self.use_relay {
            return None;
        }
        let (relay, addr) = self.bootstrap.as_ref()?;
        Some(
            addr.clone()
                .with(Protocol::P2p(*relay))
                .with(Protocol::P2pCircuit),
        )
    }

    pub fn direct_allowed(&self, address: &Multiaddr) -> bool {
        let mut parts = address.iter();
        let ip: IpAddr = match parts.next() {
            Some(Protocol::Ip4(ip)) if !ip.is_broadcast() => ip.into(),
            Some(Protocol::Ip6(ip)) if ip.to_ipv4_mapped().is_none() => ip.into(),
            _ => return false,
        };
        !ip.is_unspecified()
            && !ip.is_multicast()
            && (self.allow_private || public_ip(ip))
            && matches!(parts.next(), Some(Protocol::Tcp(p)) if p != 0)
            && parts.next().is_none()
    }

    pub fn discovered(
        &mut self,
        registrations: Vec<rendezvous::Registration>,
        peers: &BTreeMap<PeerId, Option<Multiaddr>>,
        now: Instant,
    ) {
        let mut learned = BTreeMap::new();
        let circuit = self.circuit();
        let mut ttl = TTL;
        for registration in registrations {
            let peer = registration.record.peer_id();
            if registration.namespace != namespace()
                || !peers.contains_key(&peer)
                || registration.ttl == 0
            {
                continue;
            }
            ttl = ttl.min(registration.ttl);
            let mut routes = BTreeSet::new();
            let mut reserved = false;
            for raw in registration.record.addresses() {
                if raw.len() > 256 {
                    continue;
                }
                let mut address = raw.clone();
                if matches!(address.iter().last(), Some(Protocol::P2p(id)) if id == peer) {
                    address.pop();
                }
                if Some(&address) == circuit.as_ref() {
                    reserved = true;
                } else if routes.len() < 8 && self.direct_allowed(&address) {
                    routes.insert(address);
                }
            }
            if reserved && let Some(address) = &circuit {
                routes.insert(address.clone());
            }
            if !routes.is_empty() {
                learned.insert(peer, routes.into_iter().collect());
            }
        }
        if self.learned != learned {
            println!("{}", serde_json::json!({"discovered":learned}));
        }
        self.learned = learned;
        self.valid_until = Some(now + Duration::from_secs(ttl));
    }
}

pub fn server_config() -> rendezvous::server::Config {
    rendezvous::server::Config::default()
        .with_min_ttl(TTL)
        .with_max_ttl(TTL)
        .with_max_registration_per_peer(2)
        .with_max_registration_total(MAX_PEERS)
        .with_max_stored_cookies(MAX_PEERS * 4)
}

pub fn relay_config() -> relay::Config {
    relay::Config {
        max_reservations: MAX_PEERS,
        max_reservations_per_peer: 1,
        max_circuits: MAX_PEERS,
        max_circuits_per_peer: 4,
        max_circuit_duration: Duration::from_secs(600),
        max_circuit_bytes: 64 * 1024 * 1024,
        ..Default::default()
    }
}
