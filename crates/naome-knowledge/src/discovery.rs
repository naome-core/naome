//! Volatile, bounded routing hints. Neither discovery nor peer authentication
//! admits mathematical objects or supplies global membership authority.

use libp2p::{
    Multiaddr, PeerId, dcutr, identify, identity, kad, mdns,
    multiaddr::Protocol,
    swarm::{NetworkBehaviour, StreamProtocol, behaviour::toggle::Toggle},
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

pub const MAX_CONTACTS: usize = 16;
pub const MAX_ADDRESSES: usize = 4;
pub const MAX_ADDRESS_BYTES: usize = 512;
pub const CONTACT_TTL: Duration = Duration::from_secs(30);
pub const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(10);
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const PROVIDER_TTL: Duration = Duration::from_secs(30);
pub(crate) const MAX_APPLICATION_QUERIES: usize = 2;
pub(crate) const MDNS_TTL: Duration = Duration::from_secs(20);
pub(crate) const MAX_BOOTSTRAP: usize = 4;
pub(crate) const MAX_RELAYS: usize = 2;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub id: String,
    pub address: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mdns: bool,
    pub dht: bool,
    pub bootstrap: Vec<Peer>,
    pub relays: Vec<Peer>,
    pub hole_punch: bool,
    /// Initiate proof connections through circuits. Disable hole punching to
    /// require circuits for every proof connection, including incoming ones.
    pub relay_only: bool,
    pub external_addresses: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mdns: true,
            dht: false,
            bootstrap: Vec::new(),
            relays: Vec::new(),
            hole_punch: true,
            relay_only: false,
            external_addresses: Vec::new(),
        }
    }
}

pub(crate) fn protocol_version(relay: bool) -> String {
    format!(
        "naome:knowledge:{}:{}",
        crate::hex(&crate::compatibility()),
        if relay { "relay" } else { "proof" }
    )
}

pub(crate) fn provider_key() -> kad::RecordKey {
    let mut bytes = b"naome:knowledge:participants:v1\0".to_vec();
    bytes.extend_from_slice(&crate::compatibility());
    kad::RecordKey::new(&bytes)
}

/// One direct TCP endpoint, optionally followed by its authenticated target,
/// or one circuit through explicitly configured relay infrastructure.
pub(crate) fn routing_address(
    address: &Multiaddr,
    target: PeerId,
    relays: &BTreeSet<PeerId>,
) -> Result<Multiaddr, String> {
    if address.len() > MAX_ADDRESS_BYTES {
        return Err("routing address byte limit".into());
    }
    let parts: Vec<_> = address.iter().collect();
    let host_valid = match parts.first() {
        Some(Protocol::Ip4(ip)) => !ip.is_unspecified() && !ip.is_multicast(),
        Some(Protocol::Ip6(ip)) => !ip.is_unspecified() && !ip.is_multicast(),
        Some(Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host)) => {
            !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
        }
        _ => false,
    };
    if !host_valid || !matches!(parts.get(1), Some(Protocol::Tcp(port)) if *port != 0) {
        return Err("expected a nonzero routable TCP endpoint".into());
    }
    match &parts[2..] {
        [] => Ok(address.clone()),
        [Protocol::P2p(peer)] if *peer == target => {
            let mut address = address.clone();
            address.pop();
            Ok(address)
        }
        [
            Protocol::P2p(relay),
            Protocol::P2pCircuit,
            Protocol::P2p(peer),
        ] if *peer == target && *relay != target && relays.contains(relay) => {
            let mut address = address.clone();
            address.pop();
            Ok(address)
        }
        [Protocol::P2p(relay), Protocol::P2pCircuit]
            if *relay != target && relays.contains(relay) =>
        {
            Ok(address.clone())
        }
        _ => Err("invalid routing target or unconfigured relay".into()),
    }
}

pub(crate) fn is_relayed(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|part| matches!(part, Protocol::P2pCircuit))
}

pub(crate) struct Contact {
    pub addresses: BTreeSet<Multiaddr>,
    pub pinned: bool,
    pub compatible: bool,
    pub infrastructure: bool,
    pub dht: bool,
    pub enabled: bool,
    pub connected: bool,
    pub seen: Instant,
    pub connected_at: Option<Instant>,
    pub retry_at: Instant,
}

pub(crate) struct Book {
    pub own: PeerId,
    pub automatic: bool,
    pub relay_only: bool,
    pub hole_punch: bool,
    pub relays: BTreeSet<PeerId>,
    pub contacts: BTreeMap<PeerId, Contact>,
    retired: BTreeMap<PeerId, Instant>,
}

impl Book {
    pub fn new(own: PeerId, automatic: bool, config: &Config) -> Self {
        Self {
            own,
            automatic,
            relay_only: config.relay_only,
            hole_punch: config.hole_punch,
            relays: BTreeSet::new(),
            contacts: BTreeMap::new(),
            retired: BTreeMap::new(),
        }
    }

    pub fn admit(&mut self, peer: PeerId, now: Instant) -> Result<&mut Contact, String> {
        self.retired.retain(|_, until| *until > now);
        if self.retired.contains_key(&peer) {
            return Err("retired contact backoff".into());
        }
        if peer == self.own {
            return Err("self contact".into());
        }
        if !self.contacts.contains_key(&peer) {
            if !self.automatic || self.contacts.len() >= MAX_CONTACTS {
                return Err("contact capacity or static peer policy".into());
            }
            self.contacts.insert(
                peer,
                Contact {
                    addresses: BTreeSet::new(),
                    pinned: false,
                    compatible: false,
                    infrastructure: false,
                    dht: false,
                    enabled: true,
                    connected: false,
                    seen: now,
                    connected_at: None,
                    retry_at: now,
                },
            );
        }
        let contact = self.contacts.get_mut(&peer).expect("admitted contact");
        if !contact.enabled {
            return Err("contact disabled".into());
        }
        Ok(contact)
    }

    pub fn hint(
        &mut self,
        peer: PeerId,
        address: &Multiaddr,
        now: Instant,
    ) -> Result<bool, String> {
        let address = routing_address(address, peer, &self.relays)?;
        // A peer's direct addresses must not undermine a relay-only dial policy.
        if self.relay_only && !self.relays.contains(&peer) && !is_relayed(&address) {
            return Err("direct proof address disabled".into());
        }
        let contact = self.admit(peer, now)?;
        if !contact.addresses.contains(&address) && contact.addresses.len() >= MAX_ADDRESSES {
            return Err("contact address capacity".into());
        }
        // Repeated untrusted hints must not keep an unreachable identity alive.
        Ok(contact.addresses.insert(address))
    }

    pub fn pin(
        &mut self,
        peer: PeerId,
        address: &Multiaddr,
        infrastructure: bool,
    ) -> Result<(), String> {
        if peer == self.own
            || self.contacts.len() >= MAX_CONTACTS && !self.contacts.contains_key(&peer)
        {
            return Err("pinned contact capacity or self peer".into());
        }
        if infrastructure {
            self.relays.insert(peer);
        }
        let address = routing_address(address, peer, &self.relays)?;
        let now = Instant::now();
        let contact = self.contacts.entry(peer).or_insert(Contact {
            addresses: BTreeSet::new(),
            pinned: true,
            compatible: false,
            infrastructure,
            dht: false,
            enabled: true,
            connected: false,
            seen: now,
            connected_at: None,
            retry_at: now,
        });
        if contact.addresses.len() >= MAX_ADDRESSES && !contact.addresses.contains(&address) {
            return Err("pinned contact address capacity".into());
        }
        contact.pinned = true;
        contact.infrastructure |= infrastructure;
        contact.addresses.insert(address);
        Ok(())
    }

    pub fn accepts_endpoint(&mut self, peer: PeerId, address: &Multiaddr) -> Result<(), String> {
        // Noise supplies the target identity. The inbound remote endpoint may
        // be an ephemeral TCP address, while the outbound endpoint is dialed.
        routing_address(address, peer, &self.relays)?;
        if self.relay_only
            && !self.hole_punch
            && !self.relays.contains(&peer)
            && !is_relayed(address)
        {
            return Err("direct proof connection disabled".into());
        }
        self.admit(peer, Instant::now())?;
        Ok(())
    }

    pub fn accepts_inbound(
        &mut self,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), String> {
        if !is_relayed(local) {
            return self.accepts_endpoint(peer, remote);
        }
        // The relay transport supplies our circuit listener as the local
        // endpoint and only /p2p/<authenticated sender> as the remote endpoint.
        // Noise still binds the sender; the circuit must use configured
        // infrastructure and the same bounded contact admission as TCP.
        routing_address(local, self.own, &self.relays)?;
        if remote.iter().collect::<Vec<_>>() != [Protocol::P2p(peer)] {
            return Err("invalid inbound circuit sender".into());
        }
        self.admit(peer, Instant::now())?;
        Ok(())
    }

    pub fn retire(&mut self, peer: PeerId, now: Instant) -> Option<Contact> {
        let contact = self.contacts.remove(&peer)?;
        self.retired.retain(|_, until| *until > now);
        if self.retired.len() >= MAX_CONTACTS
            && let Some(oldest) = self
                .retired
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(peer, _)| *peer)
        {
            self.retired.remove(&oldest);
        }
        self.retired.insert(peer, now + CONTACT_TTL);
        Some(contact)
    }

    pub fn expired(&self, now: Instant) -> Vec<PeerId> {
        self.contacts
            .iter()
            .filter_map(|(peer, contact)| {
                (!contact.pinned
                    && !contact.connected
                    && now.duration_since(contact.seen) >= CONTACT_TTL)
                    .then_some(*peer)
            })
            .collect()
    }
}

#[derive(Clone)]
pub(crate) struct SharedBook(Arc<Mutex<Book>>);
impl SharedBook {
    pub fn new(book: Book) -> Self {
        Self(Arc::new(Mutex::new(book)))
    }
    pub fn lock(&self) -> MutexGuard<'_, Book> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    pub identify: identify::Behaviour,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub kad: Toggle<kad::Behaviour<Providers>>,
    pub dcutr: Toggle<dcutr::Behaviour>,
}

impl Behaviour {
    pub fn new(
        key: &identity::Keypair,
        config: &Config,
        relay: bool,
        automatic: bool,
    ) -> Result<Self, String> {
        let peer = key.public().to_peer_id();
        let identify = identify::Behaviour::new(
            identify::Config::new(protocol_version(relay), key.public())
                .with_agent_version("naome-knowledge/2".into())
                .with_cache_size(0)
                .with_interval(Duration::from_secs(10))
                .with_push_listen_addr_updates(true)
                .with_hide_listen_addrs(config.relay_only),
        );
        let mdns = if config.mdns && automatic && !relay {
            Some(
                mdns::tokio::Behaviour::new(
                    mdns::Config {
                        ttl: MDNS_TTL,
                        query_interval: DISCOVERY_INTERVAL,
                        enable_ipv6: false,
                    },
                    peer,
                )
                .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
        let kad = if config.dht {
            let protocol = StreamProtocol::try_from_owned(format!(
                "/naome/knowledge/kad/{}/1",
                crate::hex(&crate::compatibility())
            ))
            .map_err(|error| error.to_string())?;
            let mut settings = kad::Config::new(protocol);
            settings
                .set_query_timeout(QUERY_TIMEOUT)
                .set_parallelism(NonZeroUsize::new(2).expect("nonzero"))
                .set_replication_factor(NonZeroUsize::new(8).expect("nonzero"))
                .set_kbucket_size(NonZeroUsize::new(8).expect("nonzero"))
                .set_kbucket_inserts(kad::BucketInserts::Manual)
                .set_record_filtering(kad::StoreInserts::FilterBoth)
                .set_caching(kad::Caching::Disabled)
                .set_replication_interval(None)
                .set_publication_interval(None)
                .set_provider_publication_interval(None)
                .set_periodic_bootstrap_interval(None)
                .set_provider_record_ttl(Some(PROVIDER_TTL))
                .set_substreams_timeout(QUERY_TIMEOUT)
                .set_max_packet_size(4096);
            let mut kad = kad::Behaviour::with_config(peer, Providers::new(peer), settings);
            // Explicitly opted-in DHT participants serve bounded routing hints.
            kad.set_mode(Some(kad::Mode::Server));
            Some(kad)
        } else {
            None
        };
        Ok(Self {
            identify,
            mdns: mdns.into(),
            kad: kad.into(),
            dcutr: (automatic && config.hole_punch && !relay)
                .then(|| dcutr::Behaviour::new(peer))
                .into(),
        })
    }
}

/// Only the compatibility-scoped participation key is stored. Provider data
/// expires locally, addresses stay bounded, and arbitrary DHT values are denied.
pub(crate) struct Providers {
    own: PeerId,
    entries: BTreeMap<PeerId, kad::ProviderRecord>,
    relays: BTreeSet<PeerId>,
}
impl Providers {
    fn new(own: PeerId) -> Self {
        Self {
            own,
            entries: BTreeMap::new(),
            relays: BTreeSet::new(),
        }
    }
    pub fn set_relays(&mut self, relays: BTreeSet<PeerId>) {
        self.relays = relays;
    }
    pub fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, record| !record.is_expired(now));
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
impl kad::store::RecordStore for Providers {
    type RecordsIter<'a> = std::iter::Empty<Cow<'a, kad::Record>>;
    type ProvidedIter<'a> = std::vec::IntoIter<Cow<'a, kad::ProviderRecord>>;
    fn get(&self, _: &kad::RecordKey) -> Option<Cow<'_, kad::Record>> {
        None
    }
    fn put(&mut self, _: kad::Record) -> kad::store::Result<()> {
        Err(kad::store::Error::ValueTooLarge)
    }
    fn remove(&mut self, _: &kad::RecordKey) {}
    fn records(&self) -> Self::RecordsIter<'_> {
        std::iter::empty()
    }
    fn add_provider(&mut self, mut record: kad::ProviderRecord) -> kad::store::Result<()> {
        let now = Instant::now();
        self.prune(now);
        if record.key != provider_key() || record.addresses.len() > MAX_ADDRESSES {
            return Err(kad::store::Error::ValueTooLarge);
        }
        if !self.entries.contains_key(&record.provider) && self.entries.len() >= MAX_CONTACTS {
            return Err(kad::store::Error::MaxProvidedKeys);
        }
        for address in &mut record.addresses {
            *address = routing_address(address, record.provider, &self.relays)
                .map_err(|_| kad::store::Error::ValueTooLarge)?;
        }
        record.expires = Some(record.expires.map_or(now + PROVIDER_TTL, |expires| {
            expires.min(now + PROVIDER_TTL)
        }));
        self.entries.insert(record.provider, record);
        Ok(())
    }
    fn providers(&self, key: &kad::RecordKey) -> Vec<kad::ProviderRecord> {
        if *key != provider_key() {
            return Vec::new();
        }
        self.entries
            .values()
            .filter(|record| !record.is_expired(Instant::now()))
            .cloned()
            .collect()
    }
    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.entries
            .get(&self.own)
            .filter(|record| !record.is_expired(Instant::now()))
            .map(Cow::Borrowed)
            .into_iter()
            .collect::<Vec<_>>()
            .into_iter()
    }
    fn remove_provider(&mut self, key: &kad::RecordKey, peer: &PeerId) {
        if *key == provider_key() {
            self.entries.remove(peer);
        }
    }
}

pub(crate) enum Action {
    Contact(PeerId),
    Compatible(PeerId),
    Reject(PeerId),
}

pub(crate) struct State {
    pub book: SharedBook,
    pub config: Config,
    pub relay: bool,
    resolve: VecDeque<PeerId>,
    next_query: Instant,
    next_provide: Instant,
}

impl State {
    pub fn new(book: SharedBook, config: Config, relay: bool) -> Self {
        Self {
            book,
            config,
            relay,
            resolve: VecDeque::new(),
            next_query: Instant::now(),
            next_provide: Instant::now(),
        }
    }

    pub fn tick(&mut self, behaviour: &mut Behaviour) {
        let Some(kad) = behaviour.kad.as_mut() else {
            return;
        };
        let now = Instant::now();
        kad.store_mut().prune(now);
        // libp2p can also own one automatic bootstrap query. Count that query
        // before starting application work; its finite timeout is unchanged.
        if kad.iter_queries().count() >= MAX_APPLICATION_QUERIES {
            return;
        }
        if !self.relay && now >= self.next_provide {
            let _ = kad.start_providing(provider_key());
            self.next_provide = now + Duration::from_secs(10);
        } else if let Some(peer) = self.resolve.pop_front() {
            kad.get_closest_peers(peer);
        } else if !self.relay && now >= self.next_query {
            kad.get_providers(provider_key());
            self.next_query = now + DISCOVERY_INTERVAL;
        }
    }

    fn hint(&self, peer: PeerId, address: &Multiaddr, source: &str) -> Option<Action> {
        match self.book.lock().hint(peer, address, Instant::now()) {
            Ok(new) => {
                if new {
                    crate::network::emit(serde_json::json!({"event":"discovered", "source":source,
                    "peer":peer.to_string(), "address":address.to_string()}));
                }
                Some(Action::Contact(peer))
            }
            Err(error) => {
                crate::network::emit(
                    serde_json::json!({"event":"discovery_rejected", "source":source,
                "peer":peer.to_string(), "error":error}),
                );
                None
            }
        }
    }

    pub fn event(&mut self, event: BehaviourEvent, behaviour: &mut Behaviour) -> Vec<Action> {
        let mut actions = Vec::new();
        match event {
            BehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                for (peer, address) in peers {
                    if let Some(action) = self.hint(peer, &address, "mdns") {
                        actions.push(action);
                    } else if let Some(mdns) = behaviour.mdns.as_mut() {
                        expire_mdns(mdns, &peer);
                    }
                }
            }
            BehaviourEvent::Mdns(mdns::Event::Expired(peers)) => {
                for (peer, _) in peers {
                    crate::network::emit(
                        serde_json::json!({"event":"mdns_expired", "peer":peer.to_string()}),
                    );
                }
            }
            BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                let proof = info.protocol_version == protocol_version(false)
                    && info
                        .protocols
                        .iter()
                        .any(|protocol| protocol.as_ref() == crate::wire::PROTOCOL.as_ref());
                let relay = info.protocol_version == protocol_version(true)
                    && self.book.lock().relays.contains(&peer_id);
                let valid = info.public_key.to_peer_id() == peer_id
                    && info.listen_addrs.len() <= 16
                    && info.protocols.len() <= 32
                    && info
                        .protocols
                        .iter()
                        .all(|protocol| protocol.as_ref().len() <= 256)
                    && info.agent_version.len() <= 256
                    && (proof
                        || relay
                        || self.relay && info.protocol_version == protocol_version(false));
                if !valid {
                    crate::network::emit(
                        serde_json::json!({"event":"incompatible_peer", "peer":peer_id.to_string()}),
                    );
                    actions.push(Action::Reject(peer_id));
                } else {
                    if let Ok(contact) = self.book.lock().admit(peer_id, Instant::now()) {
                        contact.compatible = true;
                        contact.dht = info.protocols.iter().any(|protocol| {
                            protocol.as_ref()
                                == format!(
                                    "/naome/knowledge/kad/{}/1",
                                    crate::hex(&crate::compatibility())
                                )
                        });
                        contact.seen = Instant::now();
                    }
                    for address in info.listen_addrs {
                        if let Some(action) = self.hint(peer_id, &address, "identify") {
                            actions.push(action);
                        }
                    }
                    crate::network::emit(
                        serde_json::json!({"event":"identified", "peer":peer_id.to_string(), "proof_peer":proof, "relay":relay}),
                    );
                    actions.push(Action::Compatible(peer_id));
                }
            }
            BehaviourEvent::Kad(kad::Event::InboundRequest {
                request:
                    kad::InboundRequest::AddProvider {
                        record: Some(record),
                    },
            }) => {
                if let Some(kad) = behaviour.kad.as_mut() {
                    use kad::store::RecordStore;
                    let provider = record.provider;
                    let accepted = kad.store_mut().add_provider(record).is_ok();
                    crate::network::emit(
                        serde_json::json!({"event":"provider_hint", "peer":provider.to_string(), "accepted":accepted}),
                    );
                }
            }
            BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { result, .. }) => match result
            {
                kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                    key,
                    providers,
                })) if key == provider_key() => {
                    for peer in providers {
                        if peer != self.book.lock().own
                            && self.resolve.len() < MAX_CONTACTS
                            && !self.resolve.contains(&peer)
                        {
                            self.resolve.push_back(peer);
                            crate::network::emit(
                                serde_json::json!({"event":"dht_participant", "peer":peer.to_string()}),
                            );
                        }
                    }
                }
                kad::QueryResult::GetClosestPeers(result) => {
                    let peers = match result {
                        Ok(result) => result.peers,
                        Err(kad::GetClosestPeersError::Timeout { peers, .. }) => peers,
                    };
                    for peer in peers.into_iter().take(MAX_CONTACTS) {
                        for address in peer.addrs.into_iter().take(MAX_ADDRESSES) {
                            if let Some(action) = self.hint(peer.peer_id, &address, "dht") {
                                actions.push(action);
                            }
                        }
                    }
                }
                _ => {}
            },
            BehaviourEvent::Kad(kad::Event::RoutingUpdated {
                peer, addresses, ..
            }) => {
                // Kademlia may append a connected endpoint itself. Reconcile
                // that library cache against the single bounded contact book.
                let book = self.book.lock();
                if let Some(kad) = behaviour.kad.as_mut() {
                    for address in addresses.iter() {
                        let valid = book.contacts.get(&peer).is_some_and(|contact| {
                            routing_address(address, peer, &book.relays)
                                .is_ok_and(|address| contact.addresses.contains(&address))
                        });
                        if !valid {
                            kad.remove_address(&peer, address);
                        }
                    }
                }
            }
            BehaviourEvent::Dcutr(event) => {
                crate::network::emit(
                    serde_json::json!({"event":"hole_punch_result", "peer":event.remote_peer_id.to_string(),
                    "success":event.result.is_ok(), "connection_id":event.result.as_ref().ok().map(ToString::to_string),
                    "error":event.result.err().map(|error| error.to_string())}),
                );
            }
            _ => {}
        }
        actions
    }
}

// The pinned mDNS version exposes no replacement for removing a rejected
// peer from its cache. Keep this bounded-cache operation explicit.
#[allow(deprecated)]
pub(crate) fn expire_mdns(mdns: &mut mdns::tokio::Behaviour, peer: &PeerId) {
    mdns.expire_node(peer);
}

mod gate;
pub(crate) use gate::Gate;

#[cfg(test)]
mod tests;
