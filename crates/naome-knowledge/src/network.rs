//! Bounded configured-peer transport. Gossip is a hint; inventory/content catch-up
//! uses the independently checked durable graph rather than the gossip cache.

use crate::{
    Envelope, Graph, hex,
    object::id_bytes,
    wire::{Body, Codec, Frame, INVENTORY_PAGE, PROTOCOL},
};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, allow_block_list, connection_limits,
    futures::StreamExt,
    gossipsub, identity, noise, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use naome_proof::ProofId;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

pub const MAX_PEERS: usize = 16;
pub const MAX_FETCHES: usize = 128;
pub const MAX_FLIGHTS: usize = 16;
pub const MAX_FLIGHTS_PER_PEER: usize = 2;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
const AUTOMATIC_REQUEST_INTERVAL: Duration = Duration::from_millis(200);
const COMMAND_BYTES: usize = 2 * crate::MAX_PROOF_BYTES + 2048;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub directory: PathBuf,
    pub listen: String,
    pub peers: Vec<Peer>,
    /// A finite independently operated source queue, attempted once per second.
    #[serde(default)]
    pub producer_sources: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub id: String,
    pub address: String,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    allowed: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    limits: connection_limits::Behaviour,
    gossip: gossipsub::Behaviour,
    exchange: request_response::Behaviour<Codec>,
}

struct Wanted {
    since: Instant,
    retry: Instant,
    attempts: usize,
}
enum Flight {
    Inventory {
        peer: PeerId,
        after: Option<[u8; 32]>,
        pages: usize,
    },
    Get {
        id: ProofId,
        peer: PeerId,
    },
    Offer {
        peer: PeerId,
    },
}
struct Bucket {
    tokens: usize,
    reset: Instant,
}
#[derive(Clone, Copy, Default)]
struct InventoryProgress {
    after: Option<[u8; 32]>,
    pages: usize,
}
struct Node {
    graph: Graph,
    swarm: Swarm<Behaviour>,
    topic: gossipsub::IdentTopic,
    configured: BTreeMap<PeerId, Multiaddr>,
    enabled: BTreeSet<PeerId>,
    wanted: BTreeMap<ProofId, Wanted>,
    flights: HashMap<request_response::OutboundRequestId, Flight>,
    next_inventory: BTreeMap<PeerId, Instant>,
    inventory_progress: BTreeMap<PeerId, InventoryProgress>,
    next_automatic_request: BTreeMap<PeerId, Instant>,
    buckets: BTreeMap<PeerId, Bucket>,
    test_controls: bool,
    producer_sources: VecDeque<String>,
    next_production: Instant,
}

pub async fn run(config: Config, test_controls: bool) -> Result<(), String> {
    if config.peers.len() > MAX_PEERS {
        return Err("peer count limit".into());
    }
    if config.producer_sources.len() > 32
        || config
            .producer_sources
            .iter()
            .map(String::len)
            .sum::<usize>()
            > crate::MAX_PROOF_BYTES
    {
        return Err("producer queue capacity".into());
    }
    let graph = Graph::open(&config.directory)?;
    let key = identity::Keypair::from_protobuf_encoding(&crate::store::read_bounded(
        &config.directory.join("identity.key"),
        1024,
    )?)
    .map_err(|error| error.to_string())?;
    let own_id = key.public().to_peer_id();
    let mut configured = BTreeMap::new();
    for peer in config.peers {
        let id: PeerId = peer
            .id
            .parse()
            .map_err(|error| format!("peer ID: {error}"))?;
        let address: Multiaddr = peer
            .address
            .parse()
            .map_err(|error| format!("peer address: {error}"))?;
        require_tcp_address(&address)?;
        if id == own_id || configured.insert(id, address).is_some() {
            return Err("duplicate or self peer".into());
        }
    }
    let listen: Multiaddr = config
        .listen
        .parse()
        .map_err(|error| format!("listen address: {error}"))?;
    require_tcp_address(&listen)?;
    let mut allowed = allow_block_list::Behaviour::default();
    for id in configured.keys() {
        allowed.allow_peer(*id);
    }
    let limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(16))
            .with_max_pending_outgoing(Some(16))
            .with_max_established(Some(32))
            .with_max_established_per_peer(Some(2)),
    );
    let gossip_config = gossipsub::ConfigBuilder::default()
        .max_transmit_size(1024)
        .heartbeat_interval(Duration::from_secs(1))
        .build()
        .map_err(|error| error.to_string())?;
    let mut gossip = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossip_config,
    )
    .map_err(|error| error.to_string())?;
    let topic = gossipsub::IdentTopic::new("naome-knowledge-v1");
    gossip
        .subscribe(&topic)
        .map_err(|error| error.to_string())?;
    let exchange = request_response::Behaviour::with_codec(
        Codec::default(),
        [(PROTOCOL, request_response::ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(4),
    );
    let behaviour = Behaviour {
        allowed,
        limits,
        gossip,
        exchange,
    };
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            || {
                let mut config = yamux::Config::default();
                config.set_max_num_streams(8);
                config
            },
        )
        .map_err(|error| error.to_string())?
        .with_behaviour(|_| behaviour)
        .map_err(|error| error.to_string())?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(Duration::from_secs(60))
                .with_max_negotiating_inbound_streams(8)
        })
        .with_connection_timeout(REQUEST_TIMEOUT)
        .build();
    swarm.listen_on(listen).map_err(|error| error.to_string())?;
    let enabled = configured.keys().copied().collect();
    let mut node = Node {
        graph,
        swarm,
        topic,
        configured,
        enabled,
        wanted: BTreeMap::new(),
        flights: HashMap::new(),
        next_inventory: BTreeMap::new(),
        inventory_progress: BTreeMap::new(),
        next_automatic_request: BTreeMap::new(),
        buckets: BTreeMap::new(),
        test_controls,
        producer_sources: config.producer_sources.into(),
        next_production: Instant::now() + Duration::from_secs(1),
    };
    let (sender, mut commands) = mpsc::channel(8);
    // Tokio stdin uses an uncancellable blocking task that can keep runtime
    // shutdown waiting on an open producer pipe. A detached OS input thread
    // leaves acceptance/network state on this runtime and cannot hold its exit.
    std::thread::spawn(move || read_commands(sender));
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    emit(
        json!({"event":"starting", "peer_id":own_id.to_string(), "compatibility":hex(&crate::compatibility())}),
    );
    loop {
        tokio::select! {
            event = node.swarm.select_next_some() => node.event(event)?,
            command = commands.recv() => {
                match command {
                    Some(Ok(value)) => if !node.command(value) { break; },
                    Some(Err(error)) => emit(json!({"event":"command_error", "error":error})),
                    None => break,
                }
            },
            _ = tick.tick() => node.tick(),
            signal = shutdown_signal() => { signal?; break; }
        }
        if let Some(error) = node.graph.storage_error() {
            return Err(format!(
                "durable storage failed; restart must reverify: {error}"
            ));
        }
    }
    emit(json!({"event":"stopped", "root":hex(&node.graph.content_root())}));
    Ok(())
}

fn require_tcp_address(address: &Multiaddr) -> Result<(), String> {
    use libp2p::multiaddr::Protocol;
    let mut protocols = address.iter();
    if !matches!(protocols.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
        || !matches!(protocols.next(), Some(Protocol::Tcp(_)))
        || protocols.next().is_some()
    {
        return Err("expected /ip4 or /ip6 address with one TCP endpoint".into());
    }
    Ok(())
}

fn read_commands(sender: mpsc::Sender<Result<Value, String>>) {
    use std::io::{BufRead, Read};
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut bytes = Vec::new();
        let read = (&mut input)
            .take(COMMAND_BYTES as u64 + 1)
            .read_until(b'\n', &mut bytes);
        match read {
            Ok(0) => break,
            Ok(_) if bytes.len() > COMMAND_BYTES || bytes.last() != Some(&b'\n') => {
                let _ =
                    sender.blocking_send(Err("command byte limit or missing final newline".into()));
                break;
            }
            Ok(_) => {
                if sender
                    .blocking_send(
                        serde_json::from_slice(&bytes).map_err(|error| error.to_string()),
                    )
                    .is_err()
                {
                    break;
                }
            }
            Err(error) => {
                let _ = sender.blocking_send(Err(error.to_string()));
                break;
            }
        }
    }
}

fn emit(value: Value) {
    println!("{value}");
}

async fn shutdown_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|error| error.to_string())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(|error|error.to_string()),
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .map_err(|error| error.to_string())
}

impl Node {
    fn flight_count(&self, target: PeerId) -> usize {
        self.flights
            .values()
            .filter(|flight| match flight {
                Flight::Inventory { peer, .. }
                | Flight::Get { peer, .. }
                | Flight::Offer { peer } => *peer == target,
            })
            .count()
    }
    fn want(&mut self, id: ProofId) -> bool {
        if self.graph.contains(id) || self.graph.waiting(id) || self.wanted.contains_key(&id) {
            return true;
        }
        if self.wanted.len() >= MAX_FETCHES {
            return false;
        }
        self.wanted.insert(
            id,
            Wanted {
                since: Instant::now(),
                retry: Instant::now(),
                attempts: 0,
            },
        );
        true
    }

    fn automatic_request_ready(&self, peer: PeerId, now: Instant) -> bool {
        self.next_automatic_request
            .get(&peer)
            .is_none_or(|next| *next <= now)
    }

    fn charge_automatic_request(&mut self, peer: PeerId, now: Instant) {
        self.next_automatic_request
            .insert(peer, now + AUTOMATIC_REQUEST_INTERVAL);
    }

    fn ingest(&mut self, object: Envelope, source: &str) -> Result<Value, String> {
        let result = self.graph.ingest(object, Instant::now())?;
        self.wanted.remove(&result.id);
        for id in &result.admitted {
            self.wanted.remove(id);
            let mut announcement = crate::compatibility().to_vec();
            announcement.extend_from_slice(id.as_bytes());
            let _ = self
                .swarm
                .behaviour_mut()
                .gossip
                .publish(self.topic.clone(), announcement);
            emit(
                json!({"event":"accepted", "id":hex(id.as_bytes()), "source":source, "root":hex(&self.graph.content_root())}),
            );
        }
        for (id, error) in result.rejected {
            emit(
                json!({"event":"rejected", "id":hex(id.as_bytes()), "error":error, "source":"pending"}),
            );
        }
        for dependency in self.graph.missing() {
            self.want(dependency);
        }
        let value = json!({"status":result.status, "id":hex(result.id.as_bytes())});
        emit(json!({"event":"ingest", "result":value, "source":source}));
        Ok(value)
    }

    fn command(&mut self, value: Value) -> bool {
        let request = value.get("request").cloned().unwrap_or(Value::Null);
        let result: Result<Value, String> = (|| match value
            .get("command")
            .and_then(Value::as_str)
            .ok_or("command missing")?
        {
            "status" => Ok(
                json!({"ids":self.graph.ids().iter().map(|id|hex(id.as_bytes())).collect::<Vec<_>>(),
                    "root":hex(&self.graph.content_root()), "pending":self.graph.pending_ids().iter().map(|id|hex(id.as_bytes())).collect::<Vec<_>>(),
                    "connected":self.swarm.connected_peers().map(ToString::to_string).collect::<Vec<_>>(),
                    "compatibility":hex(&crate::compatibility())}),
            ),
            "produce" => {
                let source = value
                    .get("source")
                    .and_then(Value::as_str)
                    .ok_or("source missing")?;
                let object = self.graph.author(source)?;
                let result = self.ingest(object.clone(), "producer")?;
                Ok(json!({"result":result,"object":object}))
            }
            "ingest" => {
                let object =
                    serde_json::from_value(value.get("object").cloned().ok_or("object missing")?)
                        .map_err(|error| error.to_string())?;
                self.ingest(object, "local")
            }
            "object" => Ok(
                json!({"object":self.graph.get(value.get("id").and_then(Value::as_str).ok_or("id missing")?)?}),
            ),
            "links" => {
                let peers: Vec<String> =
                    serde_json::from_value(value.get("peers").cloned().ok_or("peers missing")?)
                        .map_err(|error| error.to_string())?;
                let desired: BTreeSet<PeerId> = peers
                    .into_iter()
                    .map(|id| id.parse().map_err(|error| format!("peer: {error}")))
                    .collect::<Result<_, _>>()?;
                if !desired.iter().all(|id| self.configured.contains_key(id)) {
                    return Err("unconfigured peer".into());
                }
                for peer in self.configured.keys() {
                    if desired.contains(peer) {
                        self.swarm.behaviour_mut().allowed.allow_peer(*peer);
                    } else {
                        self.swarm.behaviour_mut().allowed.disallow_peer(*peer);
                        let _ = self.swarm.disconnect_peer_id(*peer);
                    }
                }
                self.enabled = desired;
                self.next_inventory.clear();
                Ok(
                    json!({"enabled":self.enabled.iter().map(ToString::to_string).collect::<Vec<_>>()}),
                )
            }
            "announce" => {
                let id = ProofId::from_bytes(id_bytes(
                    value
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or("id missing")?,
                )?);
                if !self.graph.contains(id) {
                    return Err("only accepted proofs can be announced".into());
                }
                let mut bytes = crate::compatibility().to_vec();
                bytes.extend_from_slice(id.as_bytes());
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossip
                    .publish(self.topic.clone(), bytes);
                Ok(json!({"announced":hex(id.as_bytes())}))
            }
            "offer" | "test_offer" => {
                if self.flights.len() >= MAX_FLIGHTS {
                    return Err("request capacity".into());
                }
                let peer: PeerId = value
                    .get("peer")
                    .and_then(Value::as_str)
                    .ok_or("peer missing")?
                    .parse()
                    .map_err(|error| format!("peer: {error}"))?;
                if !self.enabled.contains(&peer) || !self.swarm.is_connected(&peer) {
                    return Err("peer not connected and enabled".into());
                }
                if self.flight_count(peer) >= MAX_FLIGHTS_PER_PEER {
                    return Err("peer request capacity".into());
                }
                let object = if value["command"] == "test_offer" {
                    if !self.test_controls {
                        return Err("test controls disabled".into());
                    }
                    serde_json::from_value(value.get("object").cloned().ok_or("object missing")?)
                        .map_err(|error| error.to_string())?
                } else {
                    self.graph
                        .get(
                            value
                                .get("id")
                                .and_then(Value::as_str)
                                .ok_or("id missing")?,
                        )?
                        .ok_or("object not accepted")?
                        .clone()
                };
                let mut frame = Frame::new(Body::Offer { object });
                if let Some(compat) = value.get("test_compatibility") {
                    if !self.test_controls {
                        return Err("test controls disabled".into());
                    }
                    frame.message.compatibility =
                        id_bytes(compat.as_str().ok_or("compatibility string")?)?;
                }
                let id = self
                    .swarm
                    .behaviour_mut()
                    .exchange
                    .send_request(&peer, frame);
                self.flights.insert(id, Flight::Offer { peer });
                Ok(json!({"sent":true}))
            }
            "stop" => Ok(json!({"stopping":true})),
            _ => Err("unknown command".into()),
        })();
        match result {
            Ok(result) => emit(json!({"event":"response","request":request,"result":result})),
            Err(error) => emit(json!({"event":"response","request":request,"error":error})),
        }
        value.get("command").and_then(Value::as_str) != Some("stop")
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if now >= self.next_production
            && let Some(source) = self.producer_sources.pop_front()
        {
            self.next_production = now + Duration::from_secs(1);
            let result = self
                .graph
                .author(&source)
                .and_then(|object| self.ingest(object, "deterministic_producer"));
            match result {
                Ok(result) => emit(json!({"event":"producer_result", "result":result})),
                Err(error) => emit(json!({"event":"producer_rejected", "error":error})),
            }
        }
        for id in self.graph.expire(now) {
            emit(json!({"event":"dependency_timeout", "id":hex(id.as_bytes())}));
        }
        self.wanted.retain(|_, wanted| {
            now.duration_since(wanted.since) < crate::PENDING_TTL && wanted.attempts < 16
        });
        for id in self.graph.missing() {
            self.want(id);
        }
        let enabled: Vec<_> = self.enabled.iter().copied().collect();
        for peer in enabled {
            if !self.swarm.is_connected(&peer) {
                if self
                    .next_inventory
                    .get(&peer)
                    .is_none_or(|next| *next <= now)
                {
                    let _ = self.swarm.dial(
                        libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
                            .addresses(vec![self.configured[&peer].clone()])
                            .build(),
                    );
                    self.next_inventory.insert(peer, now + RECONCILE_INTERVAL);
                }
            } else if self.flights.len() < MAX_FLIGHTS
                && self.flight_count(peer) < MAX_FLIGHTS_PER_PEER
                && self.automatic_request_ready(peer, now)
                && MAX_FETCHES - self.wanted.len() >= INVENTORY_PAGE
                && self
                    .next_inventory
                    .get(&peer)
                    .is_none_or(|next| *next <= now)
                && !self
                    .flights
                    .values()
                    .any(|flight| matches!(flight,Flight::Inventory { peer:p,.. } if *p==peer))
            {
                let progress = self
                    .inventory_progress
                    .get(&peer)
                    .copied()
                    .unwrap_or_default();
                self.inventory(peer, progress.after, progress.pages);
                self.charge_automatic_request(peer, now);
            }
        }
        let peers: Vec<_> = self
            .enabled
            .iter()
            .copied()
            .filter(|peer| self.swarm.is_connected(peer))
            .collect();
        if peers.is_empty() {
            return;
        }
        let ids: Vec<_> = self
            .wanted
            .iter()
            .filter_map(|(id, wanted)| {
                (wanted.retry <= now
                    && !self
                        .flights
                        .values()
                        .any(|flight| matches!(flight,Flight::Get { id:p,.. } if p==id)))
                .then_some(*id)
            })
            .collect();
        for id in ids {
            if self.flights.len() >= MAX_FLIGHTS {
                break;
            }
            let attempts = self.wanted[&id].attempts;
            let peer = peers
                .iter()
                .cycle()
                .skip(attempts % peers.len())
                .take(peers.len())
                .find(|peer| {
                    self.flight_count(**peer) < MAX_FLIGHTS_PER_PEER
                        && self.automatic_request_ready(**peer, now)
                })
                .copied();
            let Some(peer) = peer else {
                break;
            };
            let wanted = self.wanted.get_mut(&id).expect("queued fetch");
            wanted.attempts += 1;
            wanted.retry = now + RECONCILE_INTERVAL;
            let request = self
                .swarm
                .behaviour_mut()
                .exchange
                .send_request(&peer, Frame::new(Body::Get { id: *id.as_bytes() }));
            self.flights.insert(request, Flight::Get { id, peer });
            self.charge_automatic_request(peer, now);
        }
    }

    fn inventory(&mut self, peer: PeerId, after: Option<[u8; 32]>, pages: usize) {
        let id = self
            .swarm
            .behaviour_mut()
            .exchange
            .send_request(&peer, Frame::new(Body::Inventory { after }));
        self.flights
            .insert(id, Flight::Inventory { peer, after, pages });
        self.next_inventory
            .insert(peer, Instant::now() + RECONCILE_INTERVAL);
    }

    fn charge(&mut self, peer: PeerId) -> bool {
        let now = Instant::now();
        let bucket = self.buckets.entry(peer).or_insert(Bucket {
            tokens: 8,
            reset: now,
        });
        if now.duration_since(bucket.reset) >= Duration::from_secs(1) {
            bucket.tokens = 8;
            bucket.reset = now;
        }
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }

    fn event(&mut self, event: SwarmEvent<BehaviourEvent>) -> Result<(), String> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                emit(json!({"event":"ready","address":address.to_string()}))
            }
            SwarmEvent::ListenerError { error, .. } => return Err(format!("listener: {error}")),
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.next_inventory.remove(&peer_id);
                emit(json!({"event":"connected","peer":peer_id.to_string()}));
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => emit(
                json!({"event":"disconnected","peer":peer_id.to_string(),"cause":format!("{cause:?}")}),
            ),
            SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) => {
                if self.enabled.contains(&propagation_source)
                    && self.charge(propagation_source)
                    && message.data.len() == 64
                    && message.data[..32] == crate::compatibility()
                {
                    let id = ProofId::from_bytes(
                        message.data[32..].try_into().expect("announcement width"),
                    );
                    emit(json!({"event":"announcement","id":hex(id.as_bytes())}));
                    self.want(id);
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(request_response::Event::Message {
                peer,
                message,
                ..
            })) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    let body = if !self.enabled.contains(&peer) {
                        Body::Error {
                            reason: "peer disabled".into(),
                        }
                    } else if request.message.compatibility != crate::compatibility() {
                        Body::Error {
                            reason: "compatibility mismatch".into(),
                        }
                    } else if !self.charge(peer) {
                        Body::Error {
                            reason: "peer rate limit".into(),
                        }
                    } else {
                        self.request(request.message.body)
                    };
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .exchange
                        .send_response(channel, Frame::new(body));
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some(flight) = self.flights.remove(&request_id)
                        && self.enabled.contains(&peer)
                        && response.message.compatibility == crate::compatibility()
                    {
                        self.response(flight, response.message.body);
                    }
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                self.flights.remove(&request_id);
                emit(json!({"event":"request_failed","error":error.to_string()}));
            }
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                request_response::Event::InboundFailure { error, .. },
            )) => emit(json!({"event":"inbound_failed","error":error.to_string()})),
            _ => {}
        }
        Ok(())
    }

    fn request(&mut self, body: Body) -> Body {
        match body {
            Body::Inventory { after } => {
                let ids = self
                    .graph
                    .ids()
                    .into_iter()
                    .filter(|id| after.is_none_or(|after| *id.as_bytes() > after))
                    .take(INVENTORY_PAGE)
                    .map(|id| *id.as_bytes())
                    .collect();
                Body::InventoryResult { ids }
            }
            Body::Get { id } => self
                .graph
                .object(ProofId::from_bytes(id))
                .map(|object| Body::Object {
                    object: object.clone(),
                })
                .unwrap_or(Body::Missing),
            Body::Offer { object } => match self.ingest(object, "peer_offer") {
                Ok(result) => Body::Receipt {
                    status: result["status"].as_str().expect("ingest status").into(),
                },
                Err(error) => {
                    let event = if self.graph.storage_error().is_some() {
                        "storage_error"
                    } else {
                        "rejected"
                    };
                    emit(json!({"event":event,"error":error}));
                    Body::Error { reason: error }
                }
            },
            _ => Body::Error {
                reason: "unexpected request kind".into(),
            },
        }
    }

    fn response(&mut self, flight: Flight, body: Body) {
        match (flight, body) {
            (Flight::Inventory { peer, after, pages }, Body::InventoryResult { ids }) => {
                if ids.len() > INVENTORY_PAGE
                    || !ids.windows(2).all(|pair| pair[0] < pair[1])
                    || ids
                        .first()
                        .is_some_and(|id| after.is_some_and(|after| *id <= after))
                {
                    emit(json!({"event":"rejected","error":"invalid inventory"}));
                    return;
                }
                // Keep the cursor until every ID is retained or already known.
                // Queue pressure, throttling, failure and disconnect must not
                // restart a scan at its prefix or silently discard its tail.
                let mut retained = true;
                for id in &ids {
                    retained &= self.want(ProofId::from_bytes(*id));
                }
                if retained {
                    if ids.len() == INVENTORY_PAGE
                        && pages + 1 < crate::MAX_OBJECTS / INVENTORY_PAGE
                    {
                        self.inventory_progress.insert(
                            peer,
                            InventoryProgress {
                                after: ids.last().copied(),
                                pages: pages + 1,
                            },
                        );
                    } else {
                        self.inventory_progress.remove(&peer);
                    }
                }
                emit(json!({"event":"inventory_page", "peer":peer.to_string(),
                    "after":after.map(|id|hex(&id)), "page":pages,
                    "count":ids.len(), "retained":retained,
                    "last":ids.last().map(|id|hex(id))}));
            }
            (Flight::Get { id: expected, .. }, Body::Object { object }) => {
                if object.proof_id != hex(expected.as_bytes()) {
                    emit(json!({"event":"rejected","error":"retrieval ID mismatch"}));
                    return;
                }
                if let Err(error) = self.ingest(object, "fetch") {
                    let event = if self.graph.storage_error().is_some() {
                        "storage_error"
                    } else {
                        "rejected"
                    };
                    emit(json!({"event":event,"error":error}));
                }
            }
            (Flight::Offer { .. }, Body::Receipt { status }) => {
                emit(json!({"event":"offer_result","status":status}))
            }
            (_, Body::Error { reason }) => emit(json!({"event":"peer_error","error":reason})),
            (_, Body::Missing) => {}
            _ => emit(json!({"event":"rejected","error":"unexpected response kind"})),
        }
    }
}

pub fn read_config(path: &Path) -> Result<Config, String> {
    let mut config: Config = serde_json::from_slice(&crate::store::read_bounded(path, 16_384)?)
        .map_err(|error| error.to_string())?;
    if config.directory.is_relative() {
        config.directory = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&config.directory);
    }
    Ok(config)
}
