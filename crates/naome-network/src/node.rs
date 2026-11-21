use crate::{
    lifecycle::{self, Control, Status, SyncStatus},
    quota::{Quota, Rate},
    wire::{Codec, PROTOCOL, Request, Response, TOPIC},
};
use anyhow::{Context, Result, bail, ensure};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, allow_block_list, connection_limits,
    futures::StreamExt,
    gossipsub, identity,
    multiaddr::Protocol,
    noise, request_response as rr,
    swarm::{
        NetworkBehaviour, SwarmEvent,
        dial_opts::{DialOpts, PeerCondition},
    },
    tcp, yamux,
};
use naome_protocol::{
    store::{
        Archive,
        sharing::{MAX_RELEASES, Replica},
    },
    wire::Id,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    time::{Duration, Instant},
};

const MAX_PEERS: usize = 16;
const RATE: Rate = Rate {
    burst: 96,
    period: Duration::from_secs(1),
};
const RECONCILE: Duration = Duration::from_secs(4);
const REDIAL: Duration = Duration::from_secs(2);
const TIMEOUT: Duration = Duration::from_secs(10);
const STREAMS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    listen: String,
    peers: Vec<Peer>,
    #[serde(default)]
    review: Option<naome_protocol::learning::TrainingRequest>,
    #[serde(default)]
    trace_object_frames: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    id: String,
    address: String,
}

fn tcp_address(value: &str, listen: bool) -> Result<Multiaddr> {
    let addr: Multiaddr = value.parse()?;
    let mut parts = addr.iter();
    ensure!(
        matches!(parts.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
            && matches!(parts.next(), Some(Protocol::Tcp(port)) if listen || port != 0)
            && parts.next().is_none(),
        "expected an IP/TCP address"
    );
    Ok(addr)
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    allowed: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    gossip: gossipsub::Behaviour,
    exchange: rr::Behaviour<Codec>,
}

fn swarm(
    key: identity::Keypair,
    peers: &BTreeMap<PeerId, Multiaddr>,
    trace_object_frames: bool,
) -> Result<Swarm<Behaviour>> {
    let mut allowed = allow_block_list::Behaviour::default();
    let limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(8))
            .with_max_pending_outgoing(Some(8))
            .with_max_established(Some(MAX_PEERS as u32))
            .with_max_established_per_peer(Some(1)),
    );
    let config = gossipsub::ConfigBuilder::default()
        .max_transmit_size(4096)
        .heartbeat_interval(Duration::from_millis(500))
        .build()?;
    let mut gossip =
        gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(key.clone()), config)
            .map_err(anyhow::Error::msg)?;
    gossip.subscribe(&gossipsub::IdentTopic::new(TOPIC))?;
    for peer in peers.keys() {
        allowed.allow_peer(*peer);
        gossip.add_explicit_peer(peer);
    }
    let exchange = rr::Behaviour::with_codec(
        Codec {
            trace_object_frames,
        },
        [(PROTOCOL, rr::ProtocolSupport::Full)],
        rr::Config::default()
            .with_request_timeout(TIMEOUT)
            .with_max_concurrent_streams(STREAMS),
    );
    Ok(SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            || {
                let mut config = yamux::Config::default();
                config.set_max_num_streams(STREAMS);
                config
            },
        )?
        .with_behaviour(|_| Behaviour {
            limits,
            allowed,
            gossip,
            exchange,
        })?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(Duration::from_secs(60))
                .with_max_negotiating_inbound_streams(STREAMS)
        })
        .with_connection_timeout(TIMEOUT)
        .build())
}

struct Transfer {
    supplier: PeerId,
    head: Id,
    replica: Option<Replica>,
    started: Instant,
    next_read: Instant,
}

struct Node {
    archive: Archive,
    swarm: Swarm<Behaviour>,
    peers: BTreeMap<PeerId, Multiaddr>,
    known: BTreeSet<Id>,
    available: BTreeSet<Id>,
    announced: BTreeSet<Id>,
    queue: VecDeque<(PeerId, Id)>,
    transfer: Option<Transfer>,
    pending: HashMap<rr::OutboundRequestId, (PeerId, Request)>,
    inbound: BTreeMap<PeerId, Quota>,
    last_poll: BTreeMap<PeerId, Instant>,
    catalogs: BTreeMap<PeerId, BTreeSet<Id>>,
    next_dial: Instant,
    next_refresh: Instant,
}

impl Node {
    fn status(&self) -> Status {
        let connected: BTreeSet<_> = self.swarm.connected_peers().copied().collect();
        let listen_addresses: Vec<_> = self.swarm.listeners().map(ToString::to_string).collect();
        let state = if self.transfer.is_some() || !self.queue.is_empty() {
            "replicating"
        } else if self.peers.is_empty() {
            "standalone"
        } else if self
            .catalogs
            .values()
            .any(|heads| !heads.is_subset(&self.known))
        {
            "missing_heads"
        } else if connected.len() < self.peers.len() {
            "peers_offline"
        } else if connected
            .iter()
            .any(|peer| !self.catalogs.contains_key(peer))
        {
            "checking_catalogs"
        } else {
            "caught_up"
        };
        Status {
            running: !listen_addresses.is_empty(),
            pid: Some(std::process::id()),
            peer_id: Some(self.swarm.local_peer_id().to_string()),
            listen_addresses,
            configured_peers: self.peers.keys().map(ToString::to_string).collect(),
            connected_peers: connected.iter().map(ToString::to_string).collect(),
            sync: Some(SyncStatus {
                state: state.into(),
                available_heads: self.available.clone(),
                queued_heads: self.queue.len(),
                active_head: self.transfer.as_ref().map(|transfer| transfer.head),
                pending_requests: self.pending.len(),
                peers_with_catalog: self.catalogs.keys().map(ToString::to_string).collect(),
            }),
        }
    }

    fn request(&mut self, peer: PeerId, request: Request) {
        let id = self
            .swarm
            .behaviour_mut()
            .exchange
            .send_request(&peer, request.clone());
        self.pending.insert(id, (peer, request));
    }

    fn offer(&mut self, peer: PeerId, head: Id, source: &str) {
        if head.format().is_some()
            || self.known.contains(&head)
            || self
                .transfer
                .as_ref()
                .is_some_and(|x| x.head == head && x.supplier == peer)
            || self.queue.contains(&(peer, head))
            || self.queue.iter().filter(|(p, _)| *p == peer).count() >= MAX_RELEASES
        {
            return;
        }
        println!(
            "{}",
            json!({"queued":head,"supplier":peer.to_string(),"source":source})
        );
        self.queue.push_back((peer, head));
    }

    fn tick(&mut self, now: Instant) -> Result<()> {
        if now >= self.next_dial {
            self.next_dial = now + REDIAL;
            for (peer, addr) in &self.peers {
                if !self.swarm.is_connected(peer) {
                    let opts = DialOpts::peer_id(*peer)
                        .addresses(vec![addr.clone()])
                        .condition(PeerCondition::DisconnectedAndNotDialing)
                        .build();
                    let _ = self.swarm.dial(opts);
                }
            }
        }
        if now >= self.next_refresh {
            self.next_refresh = now + Duration::from_millis(300);
            self.known = self.archive.observed_releases()?;
            self.available = self.archive.releases()?;
            for head in self
                .available
                .difference(&self.announced)
                .copied()
                .collect::<Vec<_>>()
            {
                if self
                    .swarm
                    .behaviour_mut()
                    .gossip
                    .publish(gossipsub::IdentTopic::new(TOPIC), head.to_string())
                    .is_ok()
                {
                    self.announced.insert(head);
                    println!("{}", json!({"announced":head}));
                }
            }
        }
        let connected: Vec<_> = self.swarm.connected_peers().copied().collect();
        for peer in connected {
            if self
                .last_poll
                .get(&peer)
                .is_none_or(|t| now.duration_since(*t) >= RECONCILE)
                && !self
                    .pending
                    .values()
                    .any(|(p, request)| *p == peer && matches!(request, Request::Heads))
            {
                self.last_poll.insert(peer, now);
                self.request(peer, Request::Heads);
            }
        }
        if self.known.len() == MAX_RELEASES
            || self
                .pending
                .values()
                .any(|(_, request)| !matches!(request, Request::Heads))
        {
            return Ok(());
        }
        if self
            .transfer
            .as_ref()
            .is_some_and(|t| now.duration_since(t.started) >= Duration::from_secs(90))
        {
            self.transfer = None;
        }
        while self.transfer.is_none() {
            let Some((supplier, head)) = self.queue.pop_front() else {
                return Ok(());
            };
            if !self.known.contains(&head) && self.swarm.is_connected(&supplier) {
                self.transfer = Some(Transfer {
                    supplier,
                    head,
                    replica: None,
                    started: now,
                    next_read: now,
                });
            }
        }
        let transfer = self.transfer.as_ref().expect("selected transfer");
        if now < transfer.next_read {
            return Ok(());
        }
        let head = transfer.head;
        let request = match &transfer.replica {
            None => Request::Manifest { head },
            Some(r) => Request::Object {
                head,
                id: r.next_member().context("completed transfer pending")?,
            },
        };
        self.request(transfer.supplier, request);
        Ok(())
    }

    fn serve(&self, request: Request) -> Result<Response> {
        Ok(match request {
            Request::Heads => Response::Heads(self.archive.releases()?.into_iter().collect()),
            Request::Manifest { head } => Response::Manifest(self.archive.released_manifest(head)?),
            Request::Object { head, id } => {
                Response::Object(self.archive.released_member(head, id)?)
            }
        })
    }

    fn receive(&mut self, peer: PeerId, request: Request, response: Response) -> Result<()> {
        if matches!(request, Request::Heads) {
            if let Response::Heads(heads) = response {
                ensure!(heads.len() <= MAX_RELEASES, "oversized catalog");
                self.catalogs.insert(peer, heads.iter().copied().collect());
                for head in heads {
                    self.offer(peer, head, "catalog");
                }
            }
            return Ok(());
        }
        let t = self.transfer.as_mut().context("no active transfer")?;
        ensure!(t.supplier == peer, "unexpected supplier");
        match (request, response) {
            (_, Response::Busy) => t.next_read = Instant::now() + RATE.period,
            (Request::Manifest { head }, Response::Manifest(s)) if head == t.head => {
                t.replica = Some(Replica::new(head, s)?);
            }
            (Request::Object { head, id }, Response::Object(packet)) if head == t.head => {
                let replica = t.replica.as_mut().context("missing manifest")?;
                replica.accept(id, packet)?;
                if replica.next_member().is_none() {
                    let head = t
                        .replica
                        .take()
                        .expect("checked replica")
                        .commit(&self.archive)?;
                    self.known.insert(head);
                    self.available.insert(head);
                    println!("{}", json!({"mirrored":head,"supplier":peer.to_string()}));
                    self.transfer = None;
                }
            }
            _ => bail!("unavailable or unexpected release response"),
        }
        Ok(())
    }

    fn event(&mut self, event: SwarmEvent<BehaviourEvent>) -> Result<()> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => println!(
                "{}",
                json!({"listening":address.to_string(),"peer":self.swarm.local_peer_id().to_string()})
            ),
            SwarmEvent::ListenerClosed { reason, .. } => bail!("listener closed: {reason:?}"),
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.last_poll.remove(&peer_id);
                self.catalogs.remove(&peer_id);
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                self.catalogs.remove(&peer_id);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) if message.topic == gossipsub::IdentTopic::new(TOPIC).hash()
                && message.data.len() < 100 =>
            {
                if let Some(supplier) = message.source
                    && self.peers.contains_key(&supplier)
                    && self.swarm.is_connected(&supplier)
                    && let Some(head) = std::str::from_utf8(&message.data)
                        .ok()
                        .and_then(|text| text.parse().ok())
                {
                    println!(
                        "{}",
                        json!({"hint":head,"via":propagation_source.to_string()})
                    );
                    self.offer(supplier, head, "gossip");
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(rr::Event::Message {
                peer,
                message,
                ..
            })) => match message {
                rr::Message::Request {
                    request, channel, ..
                } => {
                    let now = Instant::now();
                    let bucket = self.inbound.entry(peer).or_insert_with(|| Quota::new(now));
                    let answer = if bucket.try_take(now, RATE) {
                        self.serve(request).unwrap_or(Response::Unavailable)
                    } else {
                        Response::Busy
                    };
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .exchange
                        .send_response(channel, answer);
                }
                rr::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some((expected, request)) = self.pending.remove(&request_id) {
                        let catalog = matches!(request, Request::Heads);
                        let result = if expected == peer {
                            self.receive(peer, request, response)
                        } else {
                            Err(anyhow::anyhow!("peer does not match request"))
                        };
                        if let Err(error) = result {
                            if !catalog {
                                self.transfer = None;
                            }
                            eprintln!("Rejected release response from {peer}: {error:#}");
                        }
                    }
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(rr::Event::OutboundFailure {
                request_id,
                ..
            })) => {
                if let Some((_, Request::Manifest { .. } | Request::Object { .. })) =
                    self.pending.remove(&request_id)
                {
                    self.transfer = None;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

pub async fn run(
    archive: Archive,
    archive_path: std::path::PathBuf,
    key: identity::Keypair,
    config: Config,
    control: Control,
) -> Result<std::os::unix::net::UnixStream> {
    let own = key.public().to_peer_id();
    ensure!(config.peers.len() <= MAX_PEERS, "peer limit exceeded");
    let mut peers = BTreeMap::new();
    for p in config.peers {
        let id = p.id.parse()?;
        ensure!(
            id != own && peers.insert(id, tcp_address(&p.address, false)?).is_none(),
            "self or duplicate peer"
        );
    }
    let mut swarm = swarm(key, &peers, config.trace_object_frames)?;
    swarm.listen_on(tcp_address(&config.listen, true)?)?;
    let now = Instant::now();
    let mut node = Node {
        swarm,
        peers,
        known: archive.observed_releases()?,
        available: archive.releases()?,
        archive,
        announced: BTreeSet::new(),
        queue: VecDeque::new(),
        transfer: None,
        pending: HashMap::new(),
        inbound: BTreeMap::new(),
        last_poll: BTreeMap::new(),
        catalogs: BTreeMap::new(),
        next_dial: now,
        next_refresh: now,
    };
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // One archive worker coalesces catalog changes. The REP crate owns all
    // policy, dependency and training decisions. Startup replays missed work.
    let (catalog, changes) = tokio::sync::watch::channel(node.available.clone());
    let reviewer = config
        .review
        .map(|review| tokio::spawn(watch_training(archive_path, review, changes)));
    let stop_client = loop {
        tokio::select! {
            _ = interval.tick() => {
                node.tick(Instant::now())?;
                catalog.send_if_modified(|previous| {
                    if *previous == node.available { return false; }
                    previous.clone_from(&node.available);
                    true
                });
            },
            event = node.swarm.select_next_some() => node.event(event)?,
            connection = control.status.accept() => {
                lifecycle::reply(connection?.0, &node.status()).await;
            }
            connection = control.stop.accept() => break connection?.0.into_std()?,
        }
    };
    let final_catalog = node.archive.releases()?;
    catalog.send_if_modified(|previous| {
        if *previous == final_catalog {
            return false;
        }
        *previous = final_catalog;
        true
    });
    drop(node);
    drop(catalog);
    if let Some(reviewer) = reviewer {
        reviewer.await?;
    }
    Ok(stop_client)
}

async fn watch_training(
    path: std::path::PathBuf,
    review: naome_protocol::learning::TrainingRequest,
    mut changes: tokio::sync::watch::Receiver<BTreeSet<Id>>,
) {
    loop {
        changes.borrow_and_update();
        let archive_path = path.clone();
        let request = review.clone();
        let result = tokio::task::spawn_blocking(move || {
            Archive::open(archive_path)?.review_releases(&request)
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result);
        match result {
            Ok(review) => {
                println!(
                    "{}",
                    serde_json::to_string(&review).expect("serializable training review")
                );
                if changes.changed().await.is_err() {
                    return;
                }
            }
            Err(error) => {
                eprintln!("Local training review pending: {error:#}");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {},
                    status = changes.changed() => { if status.is_err() { return; } }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authenticated_but_unconfigured_identity_is_denied_before_exchange() -> Result<()> {
        let mut listener = swarm(
            identity::Keypair::generate_ed25519(),
            &BTreeMap::new(),
            false,
        )?;
        let listener_id = *listener.local_peer_id();
        listener.listen_on(tcp_address("/ip4/127.0.0.1/tcp/0", true)?)?;
        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = listener.select_next_some().await {
                break address;
            }
        };
        let mut other = swarm(
            identity::Keypair::generate_ed25519(),
            &[(listener_id, address.clone())].into(),
            false,
        )?;
        let other_id = *other.local_peer_id();
        other.dial(
            DialOpts::peer_id(listener_id)
                .addresses(vec![address])
                .build(),
        )?;
        tokio::time::timeout(TIMEOUT, async {
            loop {
                tokio::select! {
                    _ = other.select_next_some() => {}
                    event = listener.select_next_some() => match event {
                        SwarmEvent::IncomingConnectionError {peer_id:Some(id),error:libp2p::swarm::ListenError::Denied{..},..} => {
                            assert_eq!(id,other_id);
                            break;
                        }
                        SwarmEvent::ConnectionEstablished{..} | SwarmEvent::Behaviour(BehaviourEvent::Exchange(_)) => panic!("unconfigured peer reached exchange"),
                        _ => {}
                    }
                }
            }
        }).await?;
        Ok(())
    }
}
