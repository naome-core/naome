//! Bounded question-first proof transport with static or discovered peers.
//! Gossip and inventory are hints; receiver approval precedes certificate fetch,
//! and only a completely checked root closure reaches the durable graph.

use crate::{
    Envelope, Graph,
    corpus::{InventoryCursor, InventorySnapshot},
    discovery, hex,
    object::{Metadata, id_bytes},
    outcome::{OfferStatus, PeerFailure, WireFailure},
    quota::{Quota, Rate},
    wire::{Body, Codec, Frame, PROTOCOL},
};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, allow_block_list, connection_limits, gossipsub,
    identity, noise, relay, request_response,
    swarm::{ConnectionId, NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle},
    yamux,
};
use naome_proof::ArtifactId;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
mod command;
mod exchange;
mod inventory;
mod program_read;
use inventory::response as inventory_response;
use program_read::ProgramRead;
mod worker;
use std::sync::{Arc, atomic::Ordering};

// JSON may encode one source byte as six bytes (for example, a control byte).
// Leave additional bounded space for peer metadata and formatting.
// Space every automatic read, including metadata and inventory. Separate
// sender/receiver bucket epochs must not turn a refill into a read burst.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub directory: PathBuf,
    pub listen: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub discovery: Option<discovery::Config>,
    /// A finite independently operated source queue, attempted once per second.
    #[serde(default)]
    pub producer_artifacts: Vec<String>,
    /// Optional native question fixed while the node is stopped. It follows
    /// ordinary finding, admission, solving and checked publication.
    #[serde(default)]
    pub formal_goal: Option<String>,
}
pub use crate::discovery::{Config as DiscoveryConfig, Peer};

/// Operator-visible routing settings and local resource limits. These do not
/// change the mathematical compatibility fingerprint or proof admission.
pub fn routing_contract() -> Value {
    json!({
        "corpus_fingerprint":{"produced":crate::CORPUS_ROOT_FORMAT,"incompatible":"Rejected without conversion or reset"},
        "question_exchange":{
            "protocol":crate::wire::PROTOCOL.as_ref(), "topic":crate::wire::TOPIC,
            "selection":"Exact checked definitions and their required witnesses may be fetched to compile a question. Explicit local positive selection precedes its proof fetch and commit.",
            "metadata":"Canonical question with exact definition references when available. The description carries no proof bytes.",
            "limits":{"active_roots":1,"queued_metadata":crate::resources::active_limits().queued_metadata,
                "closure_objects":crate::resources::limits().closure_objects,"closure_bytes":crate::resources::limits().closure_bytes,
                "closure_steps":crate::resources::limits().closure_steps,"checker_work_bytes":crate::resources::limits().closure_work_bytes,
                "root_lifetime_seconds":crate::resources::limits().root_timeout.as_secs(),"outgoing_request_burst_per_peer":crate::resources::limits().request_burst,"outgoing_request_refill_ms":crate::resources::limits().request_rate_window.as_millis()}
        },
        "identify_protocol":discovery::protocol_version(false),
        "dht_protocol":discovery::internet::dht_protocol(true),
        "public_bootstrap":discovery::internet::bootstrap(),
        "participation_key":hex(discovery::provider_key().as_ref()),
        "privacy":{"proof_graph":"Public to compatible peers",
            "research_offers":"Unresolved questions and participation are disclosed to contacted peers",
            "discovery":"Public IP/peer identity/participation metadata; mDNS is unencrypted LAN discovery",
            "transport":"Noise authenticated encryption, including relay circuits"},
        "defaults":DiscoveryConfig::default(),
        "limits":{
            "contacts":crate::resources::limits().contacts,"addresses_per_contact":crate::resources::limits().addresses_per_contact,
            "address_bytes":crate::resources::limits().address_bytes,"bootstrap":crate::resources::limits().bootstrap_peers,
            "relays":crate::resources::limits().relay_peers,"contact_ttl_seconds":crate::resources::limits().contact_ttl.as_secs(),
            "identify_timeout_seconds":crate::resources::limits().identify_timeout.as_secs(),
            "mdns_ttl_seconds":crate::resources::limits().mdns_ttl.as_secs(),
            "discovery_interval_seconds":crate::resources::limits().discovery_interval.as_secs(),
            "provider_records":crate::resources::limits().contacts,"provider_ttl_seconds":crate::resources::limits().provider_ttl.as_secs(),
            "application_queries":crate::resources::active_limits().application_queries,
            "query_timeout_seconds":crate::resources::limits().query_timeout.as_secs(),
            "established_connections":crate::resources::limits().established_connections,"connections_per_peer":crate::resources::limits().connections_per_peer,"connections_per_peer_with_upgrade":crate::resources::limits().upgrade_connections_per_peer
        },
        "query_limit_scope":"Count all current queries before starting application work; libp2p may add one automatic bootstrap query",
        "relay_service":{
            "reservations":crate::resources::limits().relay_reservations,"reservations_per_peer":crate::resources::limits().relay_reservations_per_peer,
            "circuits":crate::resources::limits().relay_circuits,"source_circuits":crate::resources::limits().relay_circuits_per_peer,
            "circuit_bytes":crate::resources::limits().relay_circuit_bytes,
            "duration_seconds":crate::resources::limits().relay_circuit_duration.as_secs()
        }
    })
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    allowed: Toggle<allow_block_list::Behaviour<allow_block_list::AllowedPeers>>,
    discovery: discovery::Behaviour,
    relay: relay::client::Behaviour,
    gossip: gossipsub::Behaviour,
    exchange: exchange::Exchange,
    // Admission records are committed only after every other behaviour accepts.
    gate: discovery::Gate,
}

struct Wanted {
    since: Instant,
    retry: Instant,
    attempts: usize,
    last_supplier: Option<PeerId>,
}

fn inventory_preempts_description(next: Option<Instant>, now: Instant) -> bool {
    next.is_none_or(|deadline| {
        now.saturating_duration_since(deadline) >= crate::resources::limits().reconcile_interval
            && now >= deadline
    })
}

fn description_supplier(
    peers: &[PeerId],
    last_supplier: Option<PeerId>,
    mut request_ready: impl FnMut(PeerId) -> bool,
    mut automatic_ready: impl FnMut(PeerId) -> bool,
) -> Option<PeerId> {
    let next = last_supplier
        .and_then(|last| peers.iter().position(|peer| *peer == last))
        .map_or(0, |index| index + 1);
    let peer = peers
        .iter()
        .cycle()
        .skip(next % peers.len().max(1))
        .take(peers.len())
        .find(|peer| request_ready(**peer))
        .copied()?;
    // Inventory may have just used this supplier's automatic-read window.
    // Wait for it without consuming the turn or retrying the previous supplier.
    automatic_ready(peer).then_some(peer)
}

enum Flight {
    Work {
        started: Instant,
        peer: PeerId,
    },
    Inventory {
        started: Instant,
        peer: PeerId,
        known: Option<[u8; 32]>,
        request: inventory::Request,
    },
    Get {
        started: Instant,
        root: ArtifactId,
        id: ArtifactId,
        peer: PeerId,
    },
    Describe {
        started: Instant,
        id: ArtifactId,
        peer: PeerId,
    },
    Offer {
        peer: PeerId,
        started: Instant,
    },
    Program {
        started: Instant,
        read: ProgramRead,
        peer: PeerId,
    },
}
#[derive(Clone, Copy, Default)]
struct InventoryProgress {
    after: Option<InventoryCursor>,
    pages: usize,
}
struct PeerLearning {
    client: crate::jobs::Client,
    cursor: u64,
}
struct WorkOffer {
    peer: PeerId,
    goal: naome_checker::question::Identity,
    question: String,
    expires: Instant,
    requested: Option<ArtifactId>,
    _memory: Arc<crate::resources::MemoryLease>,
}
type WorkKey = (
    PeerId,
    naome_checker::question::Identity,
    naome_checker::question::Identity,
);
fn update_work_status(
    versions: &mut BTreeMap<WorkKey, u64>,
    members: &mut BTreeMap<WorkKey, Instant>,
    key: WorkKey,
    sequence: u64,
    active: bool,
    expires: Instant,
) -> bool {
    if sequence == 0
        || versions
            .get(&key)
            .is_some_and(|previous| *previous >= sequence)
    {
        return false;
    }
    versions.insert(key, sequence);
    if active {
        members.insert(key, expires);
    } else {
        members.remove(&key);
    }
    true
}
struct Node {
    learning: Option<PeerLearning>,
    computation: Arc<crate::resources::Computation>,
    primary_listener: libp2p::core::transport::ListenerId,
    ready: bool,
    graph: Graph,
    swarm: worker::SharedSwarm,
    transport_epoch: u64,
    topic: gossipsub::IdentTopic,
    configured: BTreeMap<PeerId, Multiaddr>,
    discovery: discovery::State,
    connections: BTreeMap<ConnectionId, (PeerId, bool)>,
    relay_listeners: BTreeMap<PeerId, libp2p::core::transport::ListenerId>,
    next_relay_attempt: BTreeMap<PeerId, Instant>,
    enabled: BTreeSet<PeerId>,
    wanted: BTreeMap<ArtifactId, Wanted>,
    flights: HashMap<request_response::OutboundRequestId, Flight>,
    next_inventory: BTreeMap<PeerId, Instant>,
    inventory_progress: BTreeMap<PeerId, InventoryProgress>,
    inventory_summaries: BTreeMap<PeerId, ([u8; 32], [u8; 32])>,
    next_automatic_request: BTreeMap<PeerId, Instant>,
    buckets: BTreeMap<PeerId, Quota>,
    outgoing: BTreeMap<PeerId, Quota>,
    intake: crate::intake::Intake,
    test_objects: BTreeMap<ArtifactId, (Metadata, Option<Envelope>)>,
    test_controls: bool,
    producer_artifacts: VecDeque<String>,
    next_production: Instant,
    cooperation_enabled: bool,
    work_offers: VecDeque<WorkOffer>,
    work_sent: BTreeMap<WorkKey, Instant>,
    work_members: BTreeMap<WorkKey, Instant>,
    work_versions: BTreeMap<WorkKey, u64>,
    next_work_offer: Instant,
}

/// Autonomous ordinary operation owns its control, schedule and selection future.
/// It accepts no manual developer operations. Runtime owns the transient
/// startup stdin lifeline and releases it only after checked readiness.
#[cfg(unix)]
pub(crate) async fn run_autonomous(
    config: Config,
    intervals: crate::autonomous::Intervals,
    startup: crate::runtime::Startup,
) -> Result<(), crate::Error> {
    let (handle, admin, inbox) = crate::question::channel();
    drop(handle);
    drop(admin);
    let (sender, commands) = mpsc::channel(crate::resources::active_limits().cli_commands);
    drop(sender);
    run_inner(
        config,
        false,
        inbox,
        None::<
            fn(
                naome_checker::question::ResearchQuestion,
            ) -> std::future::Ready<Result<bool, String>>,
        >,
        commands,
        Some((intervals, startup)),
    )
    .await
}

/// Ordinary peers use the node's automatic research selection.
pub async fn run(config: Config, test_controls: bool) -> Result<(), crate::Error> {
    let (handle, admin, inbox) = crate::question::channel();
    drop(handle);
    drop(admin);
    let (sender, commands) = mpsc::channel(crate::resources::active_limits().cli_commands);
    std::thread::spawn(move || read_commands(sender));
    run_inner(
        config,
        test_controls,
        inbox,
        Some(crate::mocks::select_question as fn(_) -> _),
        commands,
        None,
    )
    .await
}

/// Runs the existing Gossip node with a bounded Rust-only local question inbox.
/// The separately supplied selection future must be nonblocking and own all its
/// effects without detaching work. It is polled inside this node's lifetime;
/// shutdown, cancellation or the fixed deadline drops it. No proof-validity
/// condition depends on selection. Peer proof exchange always requires positive
/// question selection before full certificate retrieval.
pub async fn run_with_questions<F, Fut>(
    config: Config,
    test_controls: bool,
    inbox: crate::question::QuestionInbox,
    selection: F,
) -> Result<(), crate::Error>
where
    F: Fn(naome_checker::question::ResearchQuestion) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<bool, String>> + Send + 'static,
{
    let (sender, commands) = mpsc::channel(crate::resources::active_limits().cli_commands);
    drop(sender);
    run_inner(
        config,
        test_controls,
        inbox,
        Some(selection),
        commands,
        None,
    )
    .await
}

/// Runs local question intake without a selection provider. The formal result
/// remains available to assessment; admission reports NotInserted/NotRun.
/// Embeddings must explicitly supply positive selection to admit a question.
pub async fn run_with_questions_without_selection(
    config: Config,
    test_controls: bool,
    inbox: crate::question::QuestionInbox,
) -> Result<(), crate::Error> {
    let (sender, commands) = mpsc::channel(crate::resources::active_limits().cli_commands);
    drop(sender);
    run_inner(
        config,
        test_controls,
        inbox,
        None::<
            fn(
                naome_checker::question::ResearchQuestion,
            ) -> std::future::Ready<Result<bool, String>>,
        >,
        commands,
        None,
    )
    .await
}

pub(crate) async fn run_inner<F, Fut>(
    config: Config,
    test_controls: bool,
    inbox: crate::question::QuestionInbox,
    selection: Option<F>,
    commands: mpsc::Receiver<Result<QueuedCommand, crate::Error>>,
    autonomy: Option<(crate::autonomous::Intervals, crate::runtime::Startup)>,
) -> Result<(), crate::Error>
where
    F: Fn(naome_checker::question::ResearchQuestion) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<bool, String>> + Send + 'static,
{
    let (stop, cancel) = tokio::sync::oneshot::channel();
    let (reply, result) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("naome-state-owner".into())
        .spawn(move || {
            let outcome = (|| {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .max_blocking_threads(crate::resources::active_limits().control_clients)
                    .thread_name("naome-transport")
                    .enable_all()
                    .build()
                    .map_err(|_| crate::RuntimeFailure::OwnerLaunch)?;
                runtime.block_on(run_owner(
                    config,
                    test_controls,
                    inbox,
                    selection,
                    commands,
                    autonomy,
                    cancel,
                ))
            })();
            let _ = reply.send(outcome);
        })
        .map_err(|_| crate::RuntimeFailure::OwnerLaunch)?;
    let mut owner = worker::OwnerThread {
        thread: Some(thread),
        stop: Some(stop),
    };
    let outcome = result
        .await
        .unwrap_or(Err(crate::RuntimeFailure::OwnerReceipt.into()));
    owner.join()?;
    outcome
}

fn validate_config(config: &Config, native: bool) -> Result<(), crate::Error> {
    if config.formal_goal.is_some() && !native {
        return Err(crate::Error::InputFault(
            crate::InputFault::FormalGoalRequiresNative,
        ));
    }
    if config.peers.len() > crate::resources::limits().configured_peers {
        return Err(crate::Error::InputLimit(crate::InputLimit::ConfiguredPeers));
    }
    let bytes = config
        .producer_artifacts
        .iter()
        .try_fold(0usize, |total, source| total.checked_add(source.len()));
    if config.producer_artifacts.len() > crate::resources::limits().producer_artifacts
        || bytes.is_none_or(|bytes| bytes > 2 * crate::resources::limits().producer_bytes)
    {
        return Err(crate::Error::InputLimit(crate::InputLimit::ProducerQueue));
    }
    Ok(())
}

fn checked_formal_goal(
    source: &str,
    graph: &Graph,
) -> Result<naome_checker::question::ResearchQuestion, crate::Error> {
    let question = naome_checker::question::ResearchQuestion::from_hex_with_context(
        source,
        graph.checked_context(),
    )?;
    if !question.dependencies().is_empty() {
        naome_checker::question::ResearchQuestion::from_formula(question.formula().clone())?;
    }
    Ok(question)
}

pub(crate) async fn run_owner<F, Fut>(
    config: Config,
    test_controls: bool,
    mut inbox: crate::question::QuestionInbox,
    selection: Option<F>,
    mut commands: mpsc::Receiver<Result<QueuedCommand, crate::Error>>,
    autonomy: Option<(crate::autonomous::Intervals, crate::runtime::Startup)>,
    mut cancel: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), crate::Error>
where
    F: Fn(naome_checker::question::ResearchQuestion) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<bool, String>> + Send + 'static,
{
    // Register before publishing readiness or performing synchronous owner work.
    let shutdown = shutdown_signal()?;
    tokio::pin!(shutdown);
    let (autonomy, startup) = match autonomy {
        Some((intervals, startup)) => (Some(intervals), Some(startup)),
        None => (None, None),
    };
    validate_config(
        &config,
        autonomy.is_some_and(|intervals| intervals.jobs.native_proof_learning),
    )?;
    if let Some(startup) = &startup {
        startup.phase(crate::outcome::StartupPhase::Begin);
    }
    // One resource owner spans synchronous checked replay and the live loop.
    // Refresh at replay boundaries instead of freezing its initial quantum.
    let mut resources = autonomy
        .as_ref()
        .map(|_| crate::resources::adaptive::Controller::open(&config.directory))
        .transpose()?;
    let graph = if let Some(resources) = &mut resources {
        Graph::open_observed(&config.directory, &mut || resources.refresh())
    } else {
        Graph::open(&config.directory)
    }
    .map_err(checked_replay_error)?;
    let formal_goal = config
        .formal_goal
        .as_deref()
        .map(|source| checked_formal_goal(source, &graph))
        .transpose()?;
    if let Some(startup) = &startup {
        startup.phase(crate::outcome::StartupPhase::Checked);
    }
    let directory = config.directory.clone();
    let key = identity::Keypair::from_protobuf_encoding(&crate::store::read_bounded(
        &config.directory.join("identity.key"),
        1024,
    )?)
    .map_err(|_| crate::InputFault::IdentityKeyDecode)?;
    let own_id = key.public().to_peer_id();
    #[cfg(unix)]
    let control = if autonomy.is_some() {
        Some(Arc::new(crate::runtime::Control::bind_owned(
            &config.directory,
            startup,
            graph.ownership(),
        )?))
    } else {
        None
    };
    let automatic = config
        .discovery
        .as_ref()
        .is_some_and(|settings| settings.mdns || settings.dht || !settings.relays.is_empty())
        || config.discovery.is_none() && config.peers.is_empty();
    let mut settings = config.discovery.unwrap_or_else(|| discovery::Config {
        mdns: config.peers.is_empty(),
        dht: config.peers.is_empty(),
        internet: config.peers.is_empty(),
        ..Default::default()
    });
    if automatic && settings.internet && settings.dht && settings.bootstrap.is_empty() {
        settings.bootstrap = discovery::internet::bootstrap();
    }
    if settings.bootstrap.len() > crate::resources::limits().bootstrap_peers
        || settings.relays.len() > crate::resources::limits().relay_peers
        || settings.external_addresses.len() > crate::resources::limits().addresses_per_contact
    {
        return Err(crate::InputLimit::NetworkDiscoveryCapacity.into());
    }
    if settings.relay_only && (settings.relays.is_empty() || settings.mdns) {
        return Err(crate::InputFault::NetworkRelayPolicy.into());
    }
    let mut book = discovery::Book::new(own_id, automatic, &settings);
    let mut configured = BTreeMap::new();
    for peer in &settings.relays {
        let id: PeerId = peer
            .id
            .parse()
            .map_err(|_| crate::InputFault::NetworkRelayId)?;
        let address: Multiaddr = peer
            .address
            .parse()
            .map_err(|_| crate::InputFault::NetworkRelayAddress)?;
        book.pin(id, &address, true)?;
    }
    for peer in &settings.bootstrap {
        let id: PeerId = peer
            .id
            .parse()
            .map_err(|_| crate::InputFault::NetworkBootstrapId)?;
        let address: Multiaddr = peer
            .address
            .parse()
            .map_err(|_| crate::InputFault::NetworkBootstrapAddress)?;
        book.pin(id, &address, false)?;
    }
    for peer in config.peers {
        let id: PeerId = peer
            .id
            .parse()
            .map_err(|_| crate::InputFault::NetworkPeerId)?;
        let address: Multiaddr = peer
            .address
            .parse()
            .map_err(|_| crate::InputFault::NetworkPeerAddress)?;
        book.pin(id, &address, false)?;
        if configured.insert(id, address).is_some() {
            return Err(crate::InputFault::NetworkDuplicatePeer.into());
        }
    }
    let listen: Multiaddr = config
        .listen
        .parse()
        .map_err(|_| crate::InputFault::NetworkListenAddress)?;
    require_tcp_address(&listen)?;
    let mut allowed = allow_block_list::Behaviour::default();
    for id in book.contacts.keys() {
        allowed.allow_peer(*id);
    }
    let book = discovery::SharedBook::new(book);
    let mut discovery_behaviour = discovery::Behaviour::new(&key, &settings, false, automatic)?;
    if let Some(kad) = discovery_behaviour.kad.as_mut() {
        kad.store_mut().set_relays(book.lock().relays.clone());
    }
    let limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(crate::resources::limits().pending_connections))
            .with_max_pending_outgoing(Some(crate::resources::limits().pending_connections))
            .with_max_established(Some(crate::resources::limits().established_connections))
            .with_max_established_per_peer(Some(
                if settings.hole_punch && !settings.relays.is_empty() {
                    crate::resources::limits().upgrade_connections_per_peer
                } else {
                    crate::resources::limits().connections_per_peer
                },
            )),
    );
    let gossip_config = gossipsub::ConfigBuilder::default()
        .max_transmit_size(crate::resources::limits().gossip_packet_bytes)
        .heartbeat_interval(crate::resources::limits().gossip_heartbeat)
        .build()
        .map_err(|_| crate::RuntimeFailure::NetworkGossipConfig)?;
    let mut gossip = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossip_config,
    )
    .map_err(|_| crate::RuntimeFailure::NetworkGossipBehaviour)?;
    let topic = gossipsub::IdentTopic::new(crate::wire::TOPIC);
    gossip
        .subscribe(&topic)
        .map_err(|_| crate::RuntimeFailure::NetworkGossipSubscribe)?;
    let exchange = exchange::Exchange::new(
        request_response::Behaviour::with_codec(
            Codec::default(),
            [(PROTOCOL, request_response::ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(crate::resources::limits().request_timeout)
                .with_max_concurrent_streams(crate::resources::limits().exchange_streams),
        ),
        book.clone(),
    );
    let tcp_book = book.clone();
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_other_transport(move |key| transport::tcp(key, tcp_book))
        .map_err(|_| crate::RuntimeFailure::NetworkTransport)?
        .with_relay_client(noise::Config::new, yamux_config)
        .map_err(|_| crate::RuntimeFailure::NetworkRelayTransport)?
        .with_behaviour(|_, relay| Behaviour {
            gate: discovery::Gate(book.clone()),
            allowed: (!automatic).then_some(allowed).into(),
            discovery: discovery_behaviour,
            relay,
            limits,
            gossip,
            exchange,
        })
        .map_err(|_| crate::RuntimeFailure::NetworkBehaviour)?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(crate::resources::limits().idle_connection_timeout)
                .with_max_negotiating_inbound_streams(crate::resources::limits().inbound_streams)
        })
        .with_connection_timeout(crate::resources::limits().request_timeout)
        .build();
    let primary_listener = swarm
        .listen_on(listen)
        .map_err(|_| crate::RuntimeFailure::NetworkListener)?;
    for address in &settings.external_addresses {
        let address: Multiaddr = address
            .parse()
            .map_err(|_| crate::InputFault::NetworkExternalAddress)?;
        let address = discovery::routing_address(&address, own_id, &book.lock().relays)?;
        if settings.relay_only && !discovery::is_relayed(&address) {
            return Err(crate::InputFault::NetworkDirectAdvertisement.into());
        }
        swarm.add_external_address(address);
    }
    let (swarm, mut events, mut transport) = worker::Transport::spawn(swarm, primary_listener);
    let enabled = BTreeSet::new();
    let mut node = Node {
        learning: None,
        computation: control
            .as_ref()
            .map_or_else(Arc::default, |control| control.computation.clone()),
        primary_listener,
        ready: false,
        graph,
        swarm,
        transport_epoch: 0,
        topic,
        configured,
        discovery: discovery::State::new(book, settings, false),
        connections: BTreeMap::new(),
        relay_listeners: BTreeMap::new(),
        next_relay_attempt: BTreeMap::new(),
        enabled,
        wanted: BTreeMap::new(),
        flights: HashMap::new(),
        next_inventory: BTreeMap::new(),
        inventory_progress: BTreeMap::new(),
        inventory_summaries: BTreeMap::new(),
        next_automatic_request: BTreeMap::new(),
        buckets: BTreeMap::new(),
        outgoing: BTreeMap::new(),
        intake: crate::intake::Intake::default(),
        test_objects: BTreeMap::new(),
        test_controls,
        producer_artifacts: config.producer_artifacts.into(),
        next_production: Instant::now() + crate::resources::active_limits().production_interval,
        cooperation_enabled: autonomy.is_some(),
        work_offers: VecDeque::new(),
        work_sent: BTreeMap::new(),
        work_members: BTreeMap::new(),
        work_versions: BTreeMap::new(),
        next_work_offer: Instant::now(),
    };
    let mut tick = tokio::time::interval(crate::resources::limits().tick_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut command_input_open = true;
    let mut question_input_open = true;
    let (mut research, mut autonomous, mut questions) = if let Some(intervals) = autonomy {
        use sha2::Digest;
        let entropy = sha2::Sha256::digest(own_id.to_bytes());
        let cursor = entropy[0] as u64;
        let seed = u64::from_be_bytes(entropy[..8].try_into().expect("digest seed width"));
        let (service, client, recovery) = crate::jobs::Service::open(
            &directory,
            intervals.jobs,
            cursor,
            node.computation.clone(),
        )?;
        if intervals.jobs.native_proof_learning {
            node.learning = Some(PeerLearning {
                client: client.clone(),
                cursor: recovery.peer_cursor,
            });
        }
        let questions = crate::question::LocalQuestions::<F>::managed(
            client.clone(),
            &directory,
            Duration::from_millis(intervals.jobs.selection.limits.horizon_ms),
            &node.graph,
        )?;
        let unanswered = questions.restored_unanswered(&node.graph);
        let mut autonomous =
            crate::autonomous::Autonomous::new(intervals, client, recovery, unanswered);
        autonomous.attach_frontier(&directory, &node.graph, seed)?;
        autonomous.formal_goal(formal_goal);
        (Some(service), Some(autonomous), questions)
    } else {
        let mut questions = crate::question::LocalQuestions::new(selection);
        questions.attach_persistence(&directory, &node.graph)?;
        (None, None, questions)
    };
    questions.recover_publications(&node.graph)?;
    let published = Arc::new(worker::PublishedStatus::default());
    published
        .count
        .store(node.graph.accepted_count(), Ordering::Release);
    let mut stop_watch = control.as_ref().map(|control| control.stop_watch());
    let authority = control
        .clone()
        .map(|control| control as Arc<dyn crate::publication::LocalAuthority>);
    let mut stopping = false;
    if let Some(control) = &control {
        control.publish()?;
    }
    let mut controls = worker::Controls::spawn(control.clone(), published.clone());
    emit(
        json!({"event":crate::outcome::NodeEvent::Starting, "peer_id":own_id.to_string(), "compatibility":hex(&crate::compatibility())}),
    );
    let owner_busy = node.swarm.busy.clone();
    let outcome:Result<(),crate::Error>=worker::while_polled(owner_busy, async {
    loop {
        if let Some(resources)=&mut resources {resources.refresh()?;}
        let period = crate::resources::active_limits().tick_interval;
        if tick.period() != period { tick = tokio::time::interval(period); tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip); }
        let work = node.computation.try_enter();
        if let Some(control) = &control
            && questions.select(control.selection().ok()) {
            node.intake.invalidate_selection();
            node.inventory_summaries.clear();
        }
        node.graph.set_commit_guard(crate::publication::CommitGuard::new(
            node.swarm.epoch.clone(), node.transport_epoch, authority.clone(), questions.revision(&node.graph).selection,
        ));
        // A cold peer may stay quiet after its response. Wake at the next
        // paced request deadline instead of quantizing reads to the tick.
        crate::resources::feedback::network_backlog(node.wanted.len().saturating_add(node.flights.len()));
        let request_now = Instant::now();
        let automatic_wake = node
            .next_automatic_request
            .values()
            .filter(|until| **until > request_now)
            .min()
            .copied();
        tokio::select! {
            _=tokio::time::sleep(crate::resources::adaptive::work_delay()),if work.is_some()&&(node.intake.program_busy()||autonomous.as_ref().is_some_and(crate::autonomous::Autonomous::program_busy))&&!stopping=>{},
            _ = &mut cancel => break,
            _ = async {
                if let Some(until) = automatic_wake {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if !stopping => {},
            event = events.recv() => {
                let event = event.ok_or("proof transport stopped or exceeded its event capacity")?;
                node.transport_epoch = event.epoch;
                node.graph.set_commit_guard(crate::publication::CommitGuard::new(
                    node.swarm.epoch.clone(), node.transport_epoch, authority.clone(), questions.revision(&node.graph).selection,
                ));
                node.event(event.event, event.grant)?;
                published.ready.store(node.ready, Ordering::Release);
                if node.ready && let Some(control) = &control {
                    control.startup_ready();
                }
            },
            command = commands.recv(), if command_input_open && !stopping => {
                match command {
                    Some(Ok(command)) => {
                        match command.parse() {
                            Err(error) => emit(json!({"event":crate::outcome::NodeEvent::CommandError,"error":error})),
                            Ok((value, _parsed_memory)) => { if !node.command(value) { break; } },
                        }
                    },
                    Some(Err(error)) => emit(json!({"event":crate::outcome::NodeEvent::CommandError, "error":error})),
                    None => {
                        command_input_open = false;
                        emit(json!({"event":crate::outcome::NodeEvent::CommandInputClosed}));
                    },
                }
            },
            _ = tick.tick() => { node.tick(); },
            command = inbox.receive(), if work.is_some() && question_input_open && !stopping => {
                match command {
                    Some(command) => { if !questions.process(command, &node.graph) { break; } },
                    None => question_input_open = false,
                }
            },
            selection = questions.completed(),if work.is_some() && !stopping => {
                if let Some(control)=&control
                    && questions.select(control.selection().ok()){node.intake.invalidate_selection(); node.inventory_summaries.clear();}
                questions.finish(&node.graph, selection);
            },
            _=crate::runtime::requested_stop(&mut stop_watch),if !stopping=>{
                stopping=true;

                if let Some(service)=&mut research{service.begin_shutdown()?;}
            },
            signal = &mut shutdown => { signal?; break; }
        }
        published.count.store(node.graph.accepted_count(), Ordering::Release);
        if let Some(error)=node.graph.storage_error(){return Err(error);}
        if let Some(error)=questions.storage_error(){return Err(error);}
        if let Some(error)=research.as_ref().and_then(crate::jobs::Service::error){return Err(crate::Error::RuntimeContext { code: crate::RuntimeFailure::ResearchService, cause: Box::new(error) });}
        if stopping {
            break;
        }
        // Reclaim caches even while productive work is suspended. These
        // maintenance owners check the same budget before starting compaction.
        node.graph
            .maintain_checked_storage_with_admission(node.intake.preparing_program_admission())?;
        questions.maintain_registry()?;
        if work.is_none() {
            continue;
        }
        if let Some(control)=&control
                && questions.select(control.selection().ok()){node.intake.invalidate_selection(); node.inventory_summaries.clear();}
        node.graph.set_commit_guard(crate::publication::CommitGuard::new(
            node.swarm.epoch.clone(), node.transport_epoch, authority.clone(), questions.revision(&node.graph).selection,
        ));
        questions.cancel_closed();
        if let Some(request) = node.intake.helper_definition_request(&node.graph) {
            let id = ArtifactId::from_definition_id(request.definition);
            let grant = node.swarm.grant(request.peer, id);
            if let Err(error) = node.intake.request_question_definition(request, &node.graph, Some(grant)) {
                node.graph.program_failure(&error);
            }
        }
        match node.intake.advance(&mut node.graph, &mut questions) {
            crate::intake::Progress::Waiting => {}
            crate::intake::Progress::Skipped(id, error) => {
                emit(json!({"event":crate::outcome::NodeEvent::ProofSkipped,"id":hex(id.as_bytes()),"error":error}));
            }
            crate::intake::Progress::Accepted(ids) => {
                node.publish_admitted(&ids, crate::outcome::EventSource::Fetch);
                // Earlier explicit owner ingestion can now resolve. This is
                // not part of the approved peer closure or its atomic batch.
                let (admitted, rejected) = node.graph.resolve_pending()?;
                node.publish_admitted(&admitted, crate::outcome::EventSource::LocalPending);
                for (id, error) in rejected {
                    emit(
                        json!({"event":crate::outcome::NodeEvent::Rejected, "id":hex(id.as_bytes()),"source":crate::outcome::EventSource::LocalPending,"error":error}),
                    );
                }
            }
        }
        questions.cancel_closed();
        if let Some(autonomous) = &mut autonomous {
            if let Some(mut offer) = node.work_offers.pop_front()
                && Instant::now() < offer.expires
                && node.enabled.contains(&offer.peer)
            {
                if let Some(id) = offer.requested && !node.graph.contains(id)? {
                    if node.intake.definition_active() {
                        node.work_offers.push_back(offer);
                    }
                } else {
                    match naome_checker::question::ResearchQuestion::from_hex_with_context(&offer.question, node.graph.checked_context()) {
                        Ok(_) => { autonomous.offer_work(offer.peer, offer.goal, &offer.question, &node.graph, &mut questions); }
                        Err(naome_proof::QuestionError::MissingDefinition(definition)) => {
                            if node.intake.definition_active() {
                                node.work_offers.push_back(offer);
                            } else {
                                let id = ArtifactId::from_definition_id(definition);
                                let grant = node.swarm.grant(offer.peer, id);
                                let request = crate::intake::DefinitionRequest {
                                    peer: offer.peer, definition, question_proof: None,
                                    helper_deadline: Some(offer.expires),
                                };
                                if node.intake.request_question_definition(request, &node.graph, Some(grant)).is_ok() {
                                    offer.requested = Some(id);
                                    node.work_offers.push_back(offer);
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            let admitted = autonomous.advance(&mut node.graph, &mut questions);
            node.publish_admitted(&admitted,if node.learning.is_some(){crate::outcome::EventSource::NativeSolver}else{crate::outcome::EventSource::MockProducer});
            if let Some((goal, question)) = autonomous.cooperation().wanted() {
                node.offer_work(goal, question);
            }
            if let Some((peer, goal, question, active, sequence, expires)) = autonomous.cooperation().take_notice()
                && !node.work_notice(peer, goal, question, active, sequence) {
                autonomous.cooperation().defer_notice((peer, goal, question, active, sequence, expires));
            }
            if let Some(error) = autonomous.error() { return Err(error.clone()); }
        }
        if !stopping && work.is_some() && let Some(learning) = &mut node.learning {
            learning.advance(&node.graph, questions.formal_context(&node.graph).binding())?;
        }
        if let Some(error) = questions.storage_error() { return Err(error); }
        node.requests();
        published.count.store(node.graph.accepted_count(), Ordering::Release);
        if let Some(error) = node.graph.storage_error() {
            return Err(error);
        }
        if let Some(cause) = crate::runtime::log_error() {
            return Err(crate::Error::RuntimeContext { code: crate::RuntimeFailure::Log, cause: Box::new(cause) });
        }
    }
    Ok(())
    }).await;
    // Every ordinary loop/error path drains the owner before releasing Graph's
    // exclusive directory lock. Pending controls own no independent tasks.
    let control_cleanup = controls.shutdown().await;
    let transport_cleanup = transport.shutdown().await;
    let cleanup = match &mut research {
        Some(service) => service.shutdown().await,
        None => Ok(()),
    };
    let cleanup = combine_shutdown(cleanup, control_cleanup, transport_cleanup);
    match (outcome, cleanup) {
        (Err(primary), Err(error)) => {
            emit(json!({"event":crate::outcome::NodeEvent::ShutdownFailed,"error":error}));
            return Err(primary);
        }
        (Err(error), _) => return Err(error),
        (_, Err(error)) => return Err(error),
        _ => {}
    }
    emit(
        json!({"event":crate::outcome::NodeEvent::Stopped, "root":hex(&node.graph.content_root())}),
    );
    Ok(())
}

fn combine_shutdown(
    research: Result<(), crate::Error>,
    control: Result<(), crate::Error>,
    transport: Result<(), crate::Error>,
) -> Result<(), crate::Error> {
    let mut failure = None;
    for error in [research, control, transport]
        .into_iter()
        .filter_map(Result::err)
    {
        failure = Some(match failure {
            Some(primary) => crate::Error::RuntimeCombined {
                primary: Box::new(primary),
                cleanup: Box::new(error),
            },
            None => error,
        });
    }
    failure.map_or(Ok(()), Err)
}

pub(crate) fn require_tcp_address(address: &Multiaddr) -> Result<(), crate::Error> {
    use libp2p::multiaddr::Protocol;
    let mut protocols = address.iter();
    if !matches!(protocols.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
        || !matches!(protocols.next(), Some(Protocol::Tcp(_)))
        || protocols.next().is_some()
    {
        return Err(crate::InputFault::NetworkListenAddress.into());
    }
    Ok(())
}

pub(crate) fn yamux_config() -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(crate::resources::limits().inbound_streams);
    config
}

fn body_position(body: &Body) -> Option<u64> {
    match body {
        Body::ProgramGet { start, .. } => Some(*start),
        Body::ProgramData { chunk, .. } => Some(chunk.start),
        _ => None,
    }
}
fn body_id(body: &Body) -> Option<String> {
    match body {
        Body::Get { id, .. } | Body::Describe { id } => Some(hex(id)),
        Body::ProgramGet { id, .. } | Body::ProgramData { id, .. } => Some(hex(id)),
        Body::ProgramDescription { metadata, .. } | Body::ProgramOffer { metadata } => {
            Some(hex(metadata.manifest.artifact_id().as_bytes()))
        }
        Body::Object { object, .. } => Some(object.artifact_id.clone()),
        Body::Offer { metadata } | Body::Description { metadata } => {
            Some(metadata.artifact_id.clone())
        }
        _ => None,
    }
}

fn body_root(body: &Body) -> Option<String> {
    match body {
        Body::Get { root, .. } | Body::Object { root, .. } => Some(hex(root)),
        Body::ProgramGet { root, .. } | Body::ProgramData { root, .. } => Some(hex(root)),
        Body::ProgramDescription {
            root: Some(root), ..
        } => Some(hex(root)),
        _ => None,
    }
}

/// Queues retain bounded source bytes, never expanded JSON trees. The lease
/// follows the entry through parsing and command execution on the state owner.
pub(crate) struct QueuedCommand {
    bytes: Vec<u8>,
    _memory: std::sync::Arc<crate::resources::MemoryLease>,
}
impl QueuedCommand {
    #[cfg(test)]
    pub(crate) fn from_value(value: Value) -> Self {
        let bytes = serde_json::to_vec(&value).unwrap();
        let memory = crate::resources::MemoryLease::acquire_control(bytes.len() * 2).unwrap();
        Self {
            bytes,
            _memory: memory,
        }
    }
}

fn read_commands(sender: mpsc::Sender<Result<QueuedCommand, crate::Error>>) {
    use std::io::{BufRead, Read};
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        let memory = match crate::resources::MemoryLease::acquire_control(
            crate::resources::limits().command_bytes * 2 + 2,
        ) {
            Ok(memory) => memory,
            Err(error) => {
                let _ = sender.blocking_send(Err(error));
                break;
            }
        };
        let mut bytes = Vec::new();
        let read = (&mut input)
            .take(crate::resources::limits().command_bytes as u64 + 1)
            .read_until(b'\n', &mut bytes);
        match read {
            Ok(0) => break,
            Ok(_)
                if bytes.len() > crate::resources::limits().command_bytes
                    || bytes.last() != Some(&b'\n') =>
            {
                let fault = if bytes.len() > crate::resources::limits().command_bytes {
                    crate::InputFault::CommandFrameLimit
                } else {
                    crate::InputFault::CommandFrameIncomplete
                };
                let _ = sender.blocking_send(Err(crate::Error::InputFault(fault)));
                break;
            }
            Ok(_) => {
                if sender
                    .blocking_send(Ok(QueuedCommand {
                        bytes,
                        _memory: memory,
                    }))
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => {
                let _ = sender.blocking_send(Err(crate::Error::InputFault(
                    crate::InputFault::CommandRead,
                )));
                break;
            }
        }
    }
}

fn connection_endpoint(endpoint: &libp2p::core::ConnectedPoint) -> Value {
    use crate::outcome::{ConnectionEndpoint as Kind, ConnectionPort as Port};
    use libp2p::core::{ConnectedPoint, Endpoint, transport::PortUse};
    match endpoint {
        ConnectedPoint::Dialer {
            address,
            role_override,
            port_use,
        } => json!({
            "kind":Kind::Dialer, "address":address.to_string(),
            "role":match role_override { Endpoint::Dialer => Kind::Dialer, Endpoint::Listener => Kind::Listener },
            "port":match port_use { PortUse::New => Port::New, PortUse::Reuse => Port::Reused },
        }),
        ConnectedPoint::Listener {
            local_addr,
            send_back_addr,
        } => json!({
            "kind":Kind::Listener, "local":local_addr.to_string(), "remote":send_back_addr.to_string(),
        }),
    }
}

fn connection_close(cause: Option<&libp2p::swarm::ConnectionError>) -> Option<Value> {
    use crate::outcome::ConnectionClose as Code;
    cause.map(|cause| match cause {
        libp2p::swarm::ConnectionError::IO(error) => json!({"kind":Code::Io,"io_kind":crate::outcome::io_fault_kind(error),"os_code":error.raw_os_error()}),
        libp2p::swarm::ConnectionError::KeepAliveTimeout => json!({"kind":Code::KeepAliveTimeout}),
    })
}

fn relay_client_event(event: relay::client::Event) -> Value {
    use crate::outcome::{NodeEvent, RelayClientEvent as Kind};
    macro_rules! limit_value {
        ($limit:expr) => { $limit.map(|limit| json!({"duration":limit.duration().map(|duration| json!({"seconds":duration.as_secs(),"nanoseconds":duration.subsec_nanos()})),"bytes":limit.data_in_bytes()})) };
    }
    match event {
        relay::client::Event::ReservationReqAccepted {
            relay_peer_id,
            renewal,
            limit,
        } => {
            json!({"event":NodeEvent::RelayClient,"kind":Kind::ReservationAccepted,"peer":relay_peer_id.to_string(),"renewed":renewal,"limit":limit_value!(limit)})
        }
        relay::client::Event::OutboundCircuitEstablished {
            relay_peer_id,
            limit,
        } => {
            json!({"event":NodeEvent::RelayClient,"kind":Kind::OutboundCircuit,"peer":relay_peer_id.to_string(),"limit":limit_value!(limit)})
        }
        relay::client::Event::InboundCircuitEstablished { src_peer_id, limit } => {
            json!({"event":NodeEvent::RelayClient,"kind":Kind::InboundCircuit,"peer":src_peer_id.to_string(),"limit":limit_value!(limit)})
        }
    }
}

pub(crate) fn emit(value: Value) {
    if crate::runtime::emit_log(&value) {
        return;
    }
    println!("{value}");
}

pub(crate) fn shutdown_signal()
-> Result<impl std::future::Future<Output = Result<(), crate::Error>>, crate::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        Ok(async move {
            tokio::select! {
                _ = interrupt.recv() => Ok(()),
                _ = terminate.recv() => Ok(()),
            }
        })
    }
    #[cfg(not(unix))]
    Ok(async { tokio::signal::ctrl_c().await.map_err(crate::Error::from) })
}

fn dial_failure(error: &libp2p::swarm::DialError) -> WireFailure {
    use libp2p::swarm::DialError;
    match error {
        DialError::LocalPeerId { .. } => WireFailure::SelfConnection,
        DialError::NoAddresses => WireFailure::NoAddress,
        DialError::DialPeerConditionFalse(_) => WireFailure::DialCondition,
        DialError::Aborted => WireFailure::Aborted,
        DialError::WrongPeerId { .. } => WireFailure::IdentityMismatch,
        DialError::Denied { cause } => admission_failure(cause),
        DialError::Transport(_) => WireFailure::TransportNegotiation,
    }
}

fn dial_cause(error: &libp2p::swarm::DialError) -> Option<&crate::Error> {
    let libp2p::swarm::DialError::Denied { cause } = error else {
        return None;
    };
    admission_cause(cause)
}

fn admission_cause(cause: &libp2p::swarm::ConnectionDenied) -> Option<&crate::Error> {
    cause
        .downcast_ref::<std::io::Error>()?
        .get_ref()?
        .downcast_ref::<crate::Error>()
}

fn admission_failure(cause: &libp2p::swarm::ConnectionDenied) -> WireFailure {
    cause
        .downcast_ref::<WireFailure>()
        .copied()
        .unwrap_or(WireFailure::AdmissionDenied)
}

fn peer_failure(error: &crate::Error) -> PeerFailure {
    if error.fatal() {
        PeerFailure::RequestFailed
    } else if error.retryable() {
        PeerFailure::ResourceUnavailable
    } else {
        PeerFailure::InvalidRequest
    }
}

fn retryable_publication(error: &crate::Error) -> bool {
    error.retryable()
}

impl PeerLearning {
    fn advance(
        &mut self,
        graph: &Graph,
        binding: crate::jobs::Binding,
    ) -> Result<(), crate::Error> {
        let page = match graph.peer_learning_page(self.cursor) {
            Ok(page) => page,
            Err(error) if error.retryable() => return Ok(()),
            Err(error) => return Err(error),
        };
        for (ordinal, id, peer) in page {
            match graph.learning_definition(id) {
                Ok(Some(definition)) => {
                    if self
                        .client
                        .definition_verified(ordinal, definition)
                        .is_err()
                    {
                        break;
                    }
                    self.cursor = ordinal;
                    continue;
                }
                Ok(None) => {}
                Err(error) if error.retryable() => break,
                Err(error) => return Err(error),
            }
            let Some(peer) = peer else {
                let packet = match graph.learning_certificate(id) {
                    Ok(packet) => packet,
                    Err(error) if error.retryable() => break,
                    Err(error) => return Err(error),
                };
                let observed = if let Some(packet) = packet {
                    self.client
                        .theorem_verified(ordinal, crate::learning::knowledge::Entry { packet })
                } else {
                    self.client.peer_cursor(ordinal)
                };
                if observed.is_err() {
                    break;
                }
                self.cursor = ordinal;
                continue;
            };
            let question = match graph.learning_question(id) {
                Ok(q) => q,
                Err(error) if error.retryable() => break,
                Err(error) => return Err(error),
            };
            use crate::learning::peer::Source;
            let evidence = graph
                .program_manifest(id)
                .and_then(|manifest| match manifest {
                    Some(manifest) => graph
                        .peer_program(manifest)
                        .map(|packet| packet.map(Box::new).map(Source::Program)),
                    None => graph
                        .learning_certificate(id)
                        .map(|packet| packet.map(Source::Certificate)),
                });
            let evidence = match evidence {
                Ok(value) => value,
                Err(error) if error.retryable() => break,
                Err(error) => return Err(error),
            };
            let admission = crate::jobs::PeerAdmission {
                evidence,
                ordinal,
                artifact: hex(id.as_bytes()),
                peer: peer.to_string(),
                question: question.map(|q| q.to_hex()),
                binding: binding.clone(),
            };
            if self.client.peer_verified(admission).is_err() {
                break;
            }
            self.cursor = ordinal;
        }
        Ok(())
    }
}

impl Node {
    fn offer_work(
        &mut self,
        goal: naome_checker::question::Identity,
        question: &naome_checker::question::ResearchQuestion,
    ) {
        let now = Instant::now();
        if now < self.next_work_offer {
            return;
        }
        self.work_sent.retain(|(peer, _, _), at| {
            self.enabled.contains(peer)
                && now.duration_since(*at) < crate::resources::limits().pending_retry
        });
        self.work_versions
            .retain(|key, _| self.work_sent.contains_key(key));
        self.work_members
            .retain(|(peer, _, _), until| self.enabled.contains(peer) && *until > now);
        if self.work_sent.len() >= crate::resources::active_limits().queued_metadata {
            return;
        }
        if self
            .work_members
            .keys()
            .filter(|(_, member_goal, id)| *member_goal == goal && id == question.resolution_id())
            .count()
            >= crate::resources::active_limits().queued_metadata.min(2)
        {
            return;
        }
        let peer = self.enabled.iter().copied().find(|peer| {
            self.request_ready(*peer, now)
                && self.automatic_request_ready(*peer, now)
                && !self
                    .work_sent
                    .contains_key(&(*peer, goal, *question.resolution_id()))
        });
        let Some(peer) = peer else {
            return;
        };
        let source = question.to_hex();
        let id = *question.resolution_id();
        let request = self.swarm.behaviour_mut().exchange.send_request(
            &peer,
            Frame::new(Body::WorkOffer {
                goal,
                question: source,
            }),
        );
        self.flights
            .insert(request, Flight::Work { started: now, peer });
        self.work_sent.insert((peer, goal, id), now);
        self.charge_automatic_request(peer, now);
        self.charge_outgoing(peer, now);
        self.next_work_offer = now + crate::resources::limits().automatic_request_interval;
    }

    fn work_notice(
        &mut self,
        peer: PeerId,
        goal: naome_checker::question::Identity,
        question: naome_checker::question::Identity,
        active: bool,
        sequence: u64,
    ) -> bool {
        let now = Instant::now();
        if !self.enabled.contains(&peer) {
            return true;
        }
        if !self.request_ready(peer, now) || !self.automatic_request_ready(peer, now) {
            return false;
        }
        let request = self.swarm.behaviour_mut().exchange.send_request(
            &peer,
            Frame::new(Body::WorkStatus {
                goal,
                question,
                active,
                sequence,
            }),
        );
        self.flights
            .insert(request, Flight::Work { started: now, peer });
        self.charge_automatic_request(peer, now);
        self.charge_outgoing(peer, now);
        true
    }

    fn flight_count(&self, target: PeerId) -> usize {
        self.flights
            .values()
            .filter(|flight| match flight {
                Flight::Inventory { peer, .. }
                | Flight::Work { peer, .. }
                | Flight::Get { peer, .. }
                | Flight::Describe { peer, .. }
                | Flight::Program { peer, .. }
                | Flight::Offer { peer, .. } => *peer == target,
            })
            .count()
    }
    fn want(&mut self, id: ArtifactId) -> Result<bool, String> {
        if self.graph.contains(id)? || self.intake.contains(id) || self.wanted.contains_key(&id) {
            return Ok(true);
        }
        if self.wanted.len() >= crate::resources::active_limits().fetches {
            return Ok(false);
        }
        self.wanted.insert(
            id,
            Wanted {
                since: Instant::now(),
                retry: Instant::now(),
                attempts: 0,
                last_supplier: None,
            },
        );
        Ok(true)
    }

    fn automatic_request_ready(&self, peer: PeerId, now: Instant) -> bool {
        self.next_automatic_request
            .get(&peer)
            .is_none_or(|next| *next <= now)
    }

    fn charge_automatic_request(&mut self, peer: PeerId, now: Instant) {
        self.next_automatic_request.insert(
            peer,
            now + crate::resources::limits().automatic_request_interval,
        );
    }

    fn ingest(
        &mut self,
        object: Envelope,
        source: crate::outcome::EventSource,
    ) -> Result<Value, crate::Error> {
        let result = self.graph.ingest(object, Instant::now())?;
        self.ingested(result, source)
    }
    fn ingested(
        &mut self,
        result: crate::Ingest,
        source: crate::outcome::EventSource,
    ) -> Result<Value, crate::Error> {
        self.wanted.remove(&result.id);
        self.publish_admitted(&result.admitted, source);
        for (id, error) in result.rejected {
            emit(
                json!({"event":crate::outcome::NodeEvent::Rejected, "id":hex(id.as_bytes()), "error":error, "source":crate::outcome::EventSource::Pending}),
            );
        }
        let value = json!({"status":result.status, "id":hex(result.id.as_bytes())});
        emit(json!({"event":crate::outcome::NodeEvent::Ingest, "result":value, "source":source}));
        Ok(value)
    }

    fn publish_admitted(&mut self, ids: &[ArtifactId], source: crate::outcome::EventSource) {
        for id in ids {
            self.wanted.remove(id);
            let mut announcement = crate::compatibility().to_vec();
            announcement.extend_from_slice(id.as_bytes());
            let _ = self
                .swarm
                .behaviour_mut()
                .gossip
                .publish(self.topic.clone(), announcement);
            emit(
                json!({"event":crate::outcome::NodeEvent::Accepted, "id":hex(id.as_bytes()), "source":source, "root":hex(&self.graph.content_root())}),
            );
        }
    }

    fn command(&mut self, value: Value) -> bool {
        let request = value.get("request").cloned().unwrap_or(Value::Null);
        let result: Result<Value, crate::Error> = (|| -> Result<Value, crate::Error> {
            match value
                .get("command")
                .and_then(Value::as_str)
                .ok_or("command missing")?
            {
                "status" => {
                    let after = value
                        .get("after")
                        .filter(|after| !after.is_null())
                        .map(|after| {
                            id_bytes(after.as_str().ok_or("after must be a proof ID")?)
                                .map(ArtifactId::from_bytes)
                        })
                        .transpose()?;
                    let status_page = crate::resources::active_limits().status_page;
                    let ids = self.graph.ids_page(after, status_page)?;
                    let next_after = (ids.len() == status_page)
                        .then(|| ids.last().map(|id| hex(id.as_bytes())))
                        .flatten();
                    Ok(
                        json!({"ids":ids.iter().map(|id|hex(id.as_bytes())).collect::<Vec<_>>(),
                    "next_after":next_after,"status_page_ids":status_page,"accepted_artifacts":self.graph.accepted_count(),
                    "root":hex(&self.graph.content_root()), "root_format":crate::CORPUS_ROOT_FORMAT, "pending_count":self.graph.pending_count()?, "pending":self.graph.pending_ids()?.iter().map(|id|hex(id.as_bytes())).collect::<Vec<_>>(),
                    "connected":self.swarm.connected_peers().map(|peer| peer.to_string()).collect::<Vec<_>>(),
                    "compatibility":hex(&crate::compatibility()),
                    "contacts":self.contact_status(),
                    "provider_records":self.swarm.behaviour_mut().discovery.kad.as_mut().map(|kad|kad.store_mut().len()).unwrap_or(0),
                    "proof_peers":self.enabled.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "connections":self.connections.iter().map(|(id,(peer,relayed))|json!({"id":id.to_string(),"peer":peer.to_string(),"relayed":relayed})).collect::<Vec<_>>() }),
                    )
                }
                "produce" => {
                    let source = value
                        .get("artifact")
                        .and_then(Value::as_str)
                        .ok_or("artifact missing")?;
                    let (object, ingestion) = self.graph.produce(source)?;
                    let id = ingestion.id;
                    let result = self.ingested(ingestion, crate::outcome::EventSource::Producer)?;
                    let metadata = self.graph.describe(id);
                    if let Some(error) = self.graph.storage_error() {
                        return Err(error);
                    }
                    Ok(json!({"result":result,"object":object,
                    "metadata":metadata.as_ref().ok().and_then(Option::as_ref),
                    "metadata_error":metadata.as_ref().err()}))
                }
                "ingest" => {
                    let object = serde_json::from_value(
                        value.get("object").cloned().ok_or("object missing")?,
                    )
                    .map_err(|error| error.to_string())?;
                    self.ingest(object, crate::outcome::EventSource::Local)
                }
                "object" => Ok(
                    json!({"object":self.graph.get(value.get("id").and_then(Value::as_str).ok_or("id missing")?)?}),
                ),
                "test_check" => {
                    if !self.test_controls {
                        return Err("test controls disabled".into());
                    }
                    Ok(
                        json!({"object":self.graph.author(value.get("artifact").and_then(Value::as_str).ok_or("artifact missing")?)?}),
                    )
                }
                "test_descriptor" => {
                    if !self.test_controls {
                        return Err("test controls disabled".into());
                    }
                    let metadata: Metadata = serde_json::from_value(
                        value.get("metadata").cloned().ok_or("metadata missing")?,
                    )
                    .map_err(|error| error.to_string())?;
                    let (id, _, _) = metadata.compile(self.graph.checked_context())?;
                    if self.test_objects.len() >= crate::resources::limits().developer_objects
                        && !self.test_objects.contains_key(&id)
                    {
                        return Err("test object capacity".into());
                    }
                    self.test_objects.insert(id, (metadata, None));
                    Ok(json!({"installed":true}))
                }
                "describe" => Ok(
                    json!({"metadata":self.graph.describe(ArtifactId::from_bytes(id_bytes(value.get("id").and_then(Value::as_str).ok_or("id missing")?)?))?}),
                ),
                "links" => {
                    if self.discovery.book.lock().automatic {
                        return Err("links requires static discovery mode".into());
                    }
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
                            if let Some(allowed) = self.swarm.behaviour_mut().allowed.as_mut() {
                                allowed.allow_peer(*peer);
                            }
                            if let Some(contact) = self.discovery.book.lock().contacts.get_mut(peer)
                            {
                                contact.enabled = true;
                            }
                        } else {
                            self.intake.disconnected(*peer);
                            self.outgoing.remove(peer);
                            if let Some(allowed) = self.swarm.behaviour_mut().allowed.as_mut() {
                                allowed.disallow_peer(*peer);
                            }
                            if let Some(contact) = self.discovery.book.lock().contacts.get_mut(peer)
                            {
                                contact.enabled = false;
                            }
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
                    crate::resources::require_work_admission()?;
                    let id = ArtifactId::from_bytes(id_bytes(
                        value
                            .get("id")
                            .and_then(Value::as_str)
                            .ok_or("id missing")?,
                    )?);
                    if !self.graph.contains(id)? {
                        return Err("only accepted artifacts can be announced".into());
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
                    crate::resources::require_work_admission()?;
                    if self.flights.len()
                        >= crate::resources::adaptive::network(crate::resources::limits().flights)
                    {
                        return Err(crate::Error::ExecutionLimit);
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
                    if self.flight_count(peer) >= crate::resources::limits().flights_per_peer {
                        return Err(crate::Error::ExecutionLimit);
                    }
                    let now = Instant::now();
                    if !self.outgoing_ready(peer, now) {
                        return Err(crate::Error::ExecutionLimit);
                    }
                    let metadata = if value["command"] == "test_offer" {
                        if !self.test_controls {
                            return Err("test controls disabled".into());
                        }
                        let metadata: Metadata = serde_json::from_value(
                            value.get("metadata").cloned().ok_or("metadata missing")?,
                        )
                        .map_err(|error| error.to_string())?;
                        if let Some(object) = value.get("object") {
                            if self.test_objects.len()
                                >= crate::resources::limits().developer_objects
                            {
                                return Err("test object capacity".into());
                            }
                            let object: Envelope = serde_json::from_value(object.clone())
                                .map_err(|error| error.to_string())?;
                            if object.payload.len() > 2 * crate::resources::limits().proof_bytes {
                                return Err("test proof byte limit".into());
                            }
                            self.test_objects.insert(
                                ArtifactId::from_bytes(id_bytes(&metadata.artifact_id)?),
                                (metadata.clone(), Some(object)),
                            );
                        }
                        metadata
                    } else {
                        let id = ArtifactId::from_bytes(id_bytes(
                            value
                                .get("id")
                                .and_then(Value::as_str)
                                .ok_or("id missing")?,
                        )?);
                        self.graph
                            .describe(id)?
                            .ok_or("object not supported for question exchange")?
                    };
                    let mut frame = Frame::new(Body::Offer { metadata });
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
                    self.flights.insert(
                        id,
                        Flight::Offer {
                            started: Instant::now(),
                            peer,
                        },
                    );
                    self.charge_outgoing(peer, now);
                    Ok(json!({"sent":true}))
                }
                "stop" => Ok(json!({"stopping":true})),
                _ => Err("unknown command".into()),
            }
        })();
        match result {
            Ok(result) => emit(
                json!({"event":crate::outcome::NodeEvent::Response,"request":request,"result":result}),
            ),
            Err(error) => emit(
                json!({"event":crate::outcome::NodeEvent::Response,"request":request,"retryable":retryable_publication(&error),"error":error}),
            ),
        }
        value.get("command").and_then(Value::as_str) != Some("stop")
    }

    fn tick(&mut self) {
        let now = Instant::now();
        self.discovery_tick(now);
        let work = self.computation.try_enter();
        if work.is_some()
            && crate::resources::adaptive::batch(1) > 0
            && now >= self.next_production
            && let Some(source) = self.producer_artifacts.pop_front()
        {
            self.next_production = now + crate::resources::active_limits().production_interval;
            let result = self.graph.produce(&source).and_then(|(_, result)| {
                self.ingested(result, crate::outcome::EventSource::DeterministicProducer)
            });
            match result {
                Ok(result) => emit(
                    json!({"event":crate::outcome::NodeEvent::ProducerResult, "result":result}),
                ),
                Err(error) if retryable_publication(&error) => {
                    self.producer_artifacts.push_back(source);
                    emit(
                        json!({"event":crate::outcome::NodeEvent::ProducerDeferred, "error":error}),
                    );
                }
                Err(error) => emit(
                    json!({"event":crate::outcome::NodeEvent::ProducerRejected, "error":error}),
                ),
            }
        }
        if work.is_some() {
            match self.graph.resolve_pending() {
                Ok((admitted, rejected)) => {
                    self.publish_admitted(&admitted, crate::outcome::EventSource::LocalBacklog);
                    for (id, error) in rejected {
                        emit(
                            json!({"event":crate::outcome::NodeEvent::Rejected,"id":hex(id.as_bytes()),"source":crate::outcome::EventSource::LocalBacklog,"error":error}),
                        );
                    }
                }
                Err(error) => emit(
                    json!({"event":crate::outcome::NodeEvent::ProofBacklogError,"error":error}),
                ),
            }
        }
        let wanted_before = self.wanted.len();
        self.wanted.retain(|_, wanted| {
            now.duration_since(wanted.since) < crate::resources::limits().pending_retry
                && wanted.attempts < crate::resources::limits().wanted_attempts
        });
        if self.wanted.len() < wanted_before {
            self.inventory_summaries.clear();
        }
    }

    fn request_rate() -> Rate {
        Rate {
            burst: crate::resources::limits().request_burst,
            period: crate::resources::limits().request_rate_window,
        }
    }
    fn outgoing_ready(&self, peer: PeerId, now: Instant) -> bool {
        self.outgoing
            .get(&peer)
            .is_none_or(|quota| quota.available(now, Self::request_rate()))
    }
    fn charge_outgoing(&mut self, peer: PeerId, now: Instant) {
        let quota = self.outgoing.entry(peer).or_insert_with(|| Quota::new(now));
        assert!(
            quota.try_take(now, Self::request_rate()),
            "outgoing request requires rate admission"
        );
    }

    fn request_ready(&self, peer: PeerId, now: Instant) -> bool {
        self.enabled.contains(&peer)
            && self.swarm.is_connected(&peer)
            && self.flights.len()
                < crate::resources::adaptive::network(crate::resources::limits().flights)
            && self.flight_count(peer) < crate::resources::limits().flights_per_peer
            && self.outgoing_ready(peer, now)
    }

    fn finish_description(
        &mut self,
        peer: PeerId,
        artifact: ArtifactId,
        grant: Option<crate::publication::PeerGrant>,
        result: Result<OfferStatus, crate::Error>,
    ) -> Result<OfferStatus, crate::Error> {
        let Err(crate::Error::MissingQuestionDefinition(definition)) = result else {
            return result;
        };
        // Retain only the ordinary bounded inventory hint. After each checked
        // definition is admitted, a fresh description supplies the next one.
        if !self.want(artifact)? {
            return Err(crate::Error::ExecutionLimit);
        }
        self.intake.request_question_definition(
            crate::intake::DefinitionRequest {
                peer,
                definition,
                question_proof: Some(artifact),
                helper_deadline: None,
            },
            &self.graph,
            grant,
        )?;
        Ok(OfferStatus::AwaitingDefinition)
    }

    fn fetch_grant(&self, peer: PeerId, root: ArtifactId) -> crate::publication::PeerGrant {
        self.intake
            .definition_capability(peer, root)
            .unwrap_or_else(|| self.swarm.grant(peer, root))
    }

    fn proof_fetch_error(&mut self, root: ArtifactId, error: crate::Error) {
        self.graph.program_failure(&error);
        let event = if error.retryable() {
            crate::outcome::NodeEvent::ProofDeferred
        } else {
            self.intake.abort(root);
            crate::outcome::NodeEvent::ProofSkipped
        };
        emit(json!({"event":event, "id":hex(root.as_bytes()),"error":error}));
    }

    fn requests(&mut self) {
        self.intake.trim_certificates();
        let Some(_work) = self.computation.try_enter() else {
            return;
        };
        let now = Instant::now();
        for (preferred, id) in self.intake.program_refresh_needed() {
            let peer = std::iter::once(preferred)
                .chain(
                    self.enabled
                        .iter()
                        .copied()
                        .filter(|peer| *peer != preferred),
                )
                .find(|peer| {
                    self.request_ready(*peer, now) && self.automatic_request_ready(*peer, now)
                });
            if let Some(peer) = peer
                && !self.flights.values().any(
                    |flight| matches!(flight,Flight::Describe{id:requested,..}if *requested==id),
                )
            {
                let request = self
                    .swarm
                    .behaviour_mut()
                    .exchange
                    .send_request(&peer, Frame::new(Body::Describe { id: *id.as_bytes() }));
                self.flights.insert(
                    request,
                    Flight::Describe {
                        started: Instant::now(),
                        id,
                        peer,
                    },
                );
                self.charge_automatic_request(peer, now);
                self.charge_outgoing(peer, now);
            }
        }
        match self.intake.program_request(&self.graph) {
            Ok(Some((peer, root, id, start, limit)))
                if self.request_ready(peer, now)
                    && self.automatic_request_ready(peer, now)
                    && !self
                        .flights
                        .values()
                        .any(|flight| matches!(flight,Flight::Program{read,..}if read.id==id)) =>
            {
                let read = ProgramRead {
                    root,
                    id,
                    start,
                    limit,
                };
                let frame = Frame::new(read.body());
                let request = self
                    .swarm
                    .request_granted(peer, frame, self.fetch_grant(peer, root));
                self.flights.insert(
                    request,
                    Flight::Program {
                        started: Instant::now(),
                        read,
                        peer,
                    },
                );
                self.charge_automatic_request(peer, now);
                self.charge_outgoing(peer, now);
            }
            Err(error) => self.graph.program_failure(&error),
            _ => {}
        }
        for (peer, id) in self.intake.refresh_needed() {
            if self.request_ready(peer, now)
                && self.automatic_request_ready(peer, now)
                && !self.flights.values().any(
                    |flight| matches!(flight,Flight::Describe{id:requested,..} if *requested==id),
                )
            {
                let request = self
                    .swarm
                    .behaviour_mut()
                    .exchange
                    .send_request(&peer, Frame::new(Body::Describe { id: *id.as_bytes() }));
                self.flights.insert(
                    request,
                    Flight::Describe {
                        started: Instant::now(),
                        id,
                        peer,
                    },
                );
                self.charge_automatic_request(peer, now);
                self.charge_outgoing(peer, now);
            }
        }
        // Get consumes a selected proof's checked closure or an exact question
        // definition's bounded preflight. Graph.pending never issues Get.
        for (peer, root, id) in self.intake.needed() {
            match self.intake.reuse_certificate(peer, root, id, &self.graph) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    self.proof_fetch_error(root, error);
                    continue;
                }
            }
            if self.request_ready(peer, now) && self.automatic_request_ready(peer, now) && self.intake.authorizes(peer, root, id)
                && !self.flights.values().any(|flight| matches!(flight, Flight::Get { id: requested, .. } if *requested == id))
            {
                let request = self.swarm.request_granted(peer, Frame::new(Body::Get { root: *root.as_bytes(), id: *id.as_bytes() }), self.fetch_grant(peer, root));
                self.flights.insert(request, Flight::Get { started: Instant::now(), root, id, peer });
                self.charge_automatic_request(peer, now);
                self.charge_outgoing(peer, now);
            }
        }
        let enabled: Vec<_> = self.enabled.iter().copied().collect();
        // Give queued descriptions the next request window, but reserve an
        // overdue inventory window so a continuous queue cannot starve discovery.
        let inventory_room = crate::resources::active_limits()
            .fetches
            .saturating_sub(self.wanted.len())
            >= crate::resources::active_limits().inventory_page;
        let inventory_urgent: BTreeSet<_> = enabled
            .iter()
            .copied()
            .filter(|peer| {
                inventory_room
                    && inventory_preempts_description(self.next_inventory.get(peer).copied(), now)
                    && !self.flights.values().any(
                        |flight| matches!(flight, Flight::Inventory { peer: p, .. } if p == peer),
                    )
            })
            .collect();
        let mut remaining = self.intake.description_capacity().saturating_sub(
            self.flights
                .values()
                .filter(|flight| matches!(flight, Flight::Describe { .. }))
                .count(),
        );
        let ids: Vec<_> = self
            .wanted
            .iter()
            .filter_map(|(id, wanted)| {
                (wanted.retry <= now
                    && !self.intake.contains(*id)
                    && !self
                        .flights
                        .values()
                        .any(|flight| matches!(flight,Flight::Describe { id:p,.. } if p==id)))
                .then_some(*id)
            })
            .collect();
        for id in ids {
            if remaining == 0 {
                break;
            }
            let last_supplier = self.wanted[&id].last_supplier;
            let Some(peer) = description_supplier(
                &enabled,
                last_supplier,
                |peer| self.request_ready(peer, now),
                |peer| self.automatic_request_ready(peer, now) && !inventory_urgent.contains(&peer),
            ) else {
                continue;
            };
            let wanted = self.wanted.get_mut(&id).expect("queued description");
            wanted.attempts += 1;
            wanted.last_supplier = Some(peer);
            wanted.retry = now + crate::resources::limits().reconcile_interval;
            let request = self
                .swarm
                .behaviour_mut()
                .exchange
                .send_request(&peer, Frame::new(Body::Describe { id: *id.as_bytes() }));
            self.flights.insert(
                request,
                Flight::Describe {
                    started: Instant::now(),
                    id,
                    peer,
                },
            );
            self.charge_automatic_request(peer, now);
            self.charge_outgoing(peer, now);
            remaining -= 1;
        }
        for peer in &enabled {
            if self.request_ready(*peer, now)
                && self.automatic_request_ready(*peer, now)
                && crate::resources::active_limits()
                    .fetches
                    .saturating_sub(self.wanted.len())
                    >= crate::resources::active_limits().inventory_page
                && self
                    .next_inventory
                    .get(peer)
                    .is_none_or(|next| *next <= now)
                && !self
                    .flights
                    .values()
                    .any(|flight| matches!(flight,Flight::Inventory { peer:p,.. } if p==peer))
            {
                let progress = self
                    .inventory_progress
                    .get(peer)
                    .copied()
                    .unwrap_or_default();
                self.inventory(*peer, progress.after, progress.pages);
                self.charge_automatic_request(*peer, now);
                self.charge_outgoing(*peer, now);
            }
        }
    }

    fn charge(&mut self, peer: PeerId) -> bool {
        let now = Instant::now();
        self.buckets
            .entry(peer)
            .or_insert_with(|| Quota::new(now))
            .try_take(now, Self::request_rate())
    }

    fn event(
        &mut self,
        event: SwarmEvent<BehaviourEvent>,
        grant: Option<crate::publication::PeerGrant>,
    ) -> Result<(), crate::Error> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.ready = true;
                emit(
                    json!({"event":crate::outcome::NodeEvent::Ready,"address":address.to_string(), "relayed":discovery::is_relayed(&address)}),
                );
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                if let Some(peer) = self
                    .relay_listeners
                    .iter()
                    .find_map(|(peer, id)| (*id == listener_id).then_some(*peer))
                {
                    self.relay_failed(peer);
                    self.swarm.remove_listener(listener_id);
                    emit(
                        json!({"event":crate::outcome::NodeEvent::RelayListenFailed, "peer":peer.to_string(), "error":crate::wire::stream_failure(&error)}),
                    );
                } else if listener_id == self.primary_listener {
                    return Err(crate::RuntimeFailure::Listener.into());
                } else {
                    emit(
                        json!({"event":crate::outcome::NodeEvent::RetiredListenerError, "error":crate::wire::stream_failure(&error)}),
                    );
                }
            }
            SwarmEvent::ListenerClosed { listener_id, .. } => {
                if let Some(peer) = self
                    .relay_listeners
                    .iter()
                    .find_map(|(peer, id)| (*id == listener_id).then_some(*peer))
                {
                    self.relay_failed(peer);
                } else if listener_id == self.primary_listener {
                    return Err("proof listener closed".into());
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                num_established,
                endpoint,
                ..
            } => {
                let relayed = endpoint.is_relayed();
                self.connections.insert(connection_id, (peer_id, relayed));
                if let Some(contact) = self.discovery.book.lock().contacts.get_mut(&peer_id) {
                    contact.connected = true;
                    contact.connected_at.get_or_insert(Instant::now());
                }
                self.next_inventory.remove(&peer_id);
                emit(
                    json!({"event":crate::outcome::NodeEvent::Connected, "peer":peer_id.to_string(), "connection_id":connection_id.to_string(),
                    "connections":num_established.get(), "relayed":relayed, "endpoint":connection_endpoint(&endpoint)}),
                );
                if relayed && self.discovery.config.hole_punch {
                    emit(
                        json!({"event":crate::outcome::NodeEvent::HolePunchAttempt, "peer":peer_id.to_string(), "relayed_connection_id":connection_id.to_string()}),
                    );
                }
            }
            SwarmEvent::IncomingConnectionError {
                connection_id,
                local_addr,
                send_back_addr,
                error,
                ..
            } => {
                use libp2p::swarm::ListenError;
                let code = match &error {
                    ListenError::Aborted => WireFailure::Aborted,
                    ListenError::WrongPeerId { .. } => WireFailure::IdentityMismatch,
                    ListenError::LocalPeerId { .. } => WireFailure::SelfConnection,
                    ListenError::Denied { cause } => admission_failure(cause),
                    ListenError::Transport(_) => WireFailure::TransportNegotiation,
                };
                let cause = match &error {
                    ListenError::Denied { cause } => admission_cause(cause),
                    _ => None,
                };
                emit(
                    json!({"event":crate::outcome::NodeEvent::IncomingConnectionFailed, "connection_id":connection_id.to_string(),
                    "local":local_addr.to_string(), "remote":send_back_addr.to_string(), "error":code, "cause":cause}),
                );
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                cause,
                num_established,
                ..
            } => {
                self.connections.remove(&connection_id);
                if num_established == 0 {
                    self.enabled.remove(&peer_id);
                    self.intake.disconnected(peer_id);
                    if let Some(contact) = self.discovery.book.lock().contacts.get_mut(&peer_id) {
                        contact.connected = false;
                        contact.compatible = false;
                        contact.connected_at = None;
                        contact.seen = Instant::now();
                    }
                }
                emit(
                    json!({"event":crate::outcome::NodeEvent::Disconnected, "peer":peer_id.to_string(), "connection_id":connection_id.to_string(),
                    "connections":num_established, "cause":connection_close(cause.as_ref())}),
                );
            }
            SwarmEvent::NewExternalAddrCandidate { address } => {
                // Identify observations are DCUtR candidates, not evidence of
                // public reachability and not automatically confirmed addresses.
                emit(
                    json!({"event":crate::outcome::NodeEvent::ExternalCandidate, "address":address.to_string()}),
                );
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                self.discovery.addresses_changed();
                emit(
                    json!({"event":crate::outcome::NodeEvent::ExternalConfirmed, "address":address.to_string()}),
                );
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                self.discovery.addresses_changed();
                emit(
                    json!({"event":crate::outcome::NodeEvent::ExternalExpired, "address":address.to_string()}),
                );
            }
            SwarmEvent::Behaviour(BehaviourEvent::Discovery(event)) => {
                let upgrade = match &event {
                    discovery::BehaviourEvent::Dcutr(event) => event
                        .result
                        .as_ref()
                        .ok()
                        .map(|connection| (event.remote_peer_id, *connection)),
                    _ => None,
                };
                let actions = self
                    .discovery
                    .event(event, &mut self.swarm.behaviour_mut().discovery);
                for action in actions {
                    self.discovery_action(action);
                }
                if let Some((peer, direct)) = upgrade {
                    let circuits: Vec<_> = self
                        .connections
                        .iter()
                        .filter_map(|(id, (owner, relayed))| {
                            (*owner == peer && *relayed && *id != direct).then_some(*id)
                        })
                        .collect();
                    for circuit in circuits {
                        self.swarm.close_connection(circuit);
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => {
                emit(relay_client_event(event));
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => emit(
                json!({"event":crate::outcome::NodeEvent::DialFailed,"peer":peer_id.map(|peer|peer.to_string()),
                    "stage":crate::outcome::DialStage::Transport, "error":dial_failure(&error), "cause":dial_cause(&error)}),
            ),
            SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) => {
                if self.enabled.contains(&propagation_source)
                    && message.data.len() == 64
                    && message.data[..32] == crate::compatibility()
                {
                    let id = ArtifactId::from_bytes(
                        message.data[32..].try_into().expect("announcement width"),
                    );
                    if self.graph.contains(id)? || !self.charge(propagation_source) {
                        return Ok(());
                    }
                    emit(
                        json!({"event":crate::outcome::NodeEvent::Announcement,"id":hex(id.as_bytes())}),
                    );
                    self.want(id)?;
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(request_response::Event::Message {
                peer,
                message,
                connection_id,
            })) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    emit(
                        json!({"event":crate::outcome::NodeEvent::ExchangeRequest, "peer":peer.to_string(), "connection_id":connection_id.to_string(),
                        "relayed":self.connections.get(&connection_id).map(|(_, relayed)|*relayed), "kind":request.message.body.kind(),
                        "object_id":body_id(&request.message.body),"root_id":body_root(&request.message.body),"position":body_position(&request.message.body)}),
                    );
                    let body = if !self.enabled.contains(&peer) {
                        Body::Error {
                            code: PeerFailure::Disabled,
                        }
                    } else if request.message.compatibility != crate::compatibility() {
                        Body::Error {
                            code: PeerFailure::Incompatible,
                        }
                    } else if !self.charge(peer) {
                        Body::Error {
                            code: PeerFailure::RateLimited,
                        }
                    } else {
                        self.request(peer, request.message.body, grant)?
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
                    emit(
                        json!({"event":crate::outcome::NodeEvent::ExchangeResponse, "peer":peer.to_string(), "connection_id":connection_id.to_string(),
                        "relayed":self.connections.get(&connection_id).map(|(_, relayed)|*relayed), "kind":response.message.body.kind(),
                        "object_id":body_id(&response.message.body),"root_id":body_root(&response.message.body),"position":body_position(&response.message.body)}),
                    );
                    if let Some(flight) = self.flights.remove(&request_id) {
                        let started = match &flight {
                            Flight::Inventory { started, .. }
                            | Flight::Work { started, .. }
                            | Flight::Get { started, .. }
                            | Flight::Describe { started, .. }
                            | Flight::Offer { started, .. }
                            | Flight::Program { started, .. } => *started,
                        };
                        crate::resources::feedback::record(
                            crate::resources::feedback::Kind::Network,
                            1,
                            started.elapsed(),
                        );
                        if self.enabled.contains(&peer)
                            && response.message.compatibility == crate::compatibility()
                        {
                            self.response(peer, flight, response.message.body, grant)?;
                        } else if let Flight::Get { root, .. } = flight {
                            self.intake.abort(root);
                            emit(
                                json!({"event":crate::outcome::NodeEvent::ProofSkipped,"id":hex(root.as_bytes()),"error":WireFailure::ResponsePeerMismatch}),
                            );
                        }
                    }
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                crate::resources::feedback::network_failure();
                if let Some(Flight::Program { read, peer, .. }) = self.flights.get(&request_id) {
                    self.intake.program_failed(*peer, read.id);
                }
                if let Some(Flight::Get { root, .. }) = self.flights.remove(&request_id) {
                    self.intake.abort(root);
                    emit(
                        json!({"event":crate::outcome::NodeEvent::ProofSkipped, "id":hex(root.as_bytes()),"error":WireFailure::StreamIo}),
                    );
                }
                use request_response::OutboundFailure as Failure;
                let code = match &error {
                    Failure::DialFailure => WireFailure::DialFailed,
                    Failure::Timeout => WireFailure::TimedOut,
                    Failure::ConnectionClosed => WireFailure::ConnectionClosed,
                    Failure::UnsupportedProtocols => WireFailure::UnsupportedProtocols,
                    Failure::Io(error) => crate::wire::stream_failure(error),
                };
                emit(json!({"event":crate::outcome::NodeEvent::RequestFailed,"error":code}));
            }
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                request_response::Event::InboundFailure { error, .. },
            )) => {
                use request_response::InboundFailure as Failure;
                let code = match &error {
                    Failure::Timeout => WireFailure::TimedOut,
                    Failure::ConnectionClosed => WireFailure::ConnectionClosed,
                    Failure::UnsupportedProtocols => WireFailure::UnsupportedProtocols,
                    Failure::ResponseOmission => WireFailure::ResponseOmitted,
                    Failure::Io(error) => crate::wire::stream_failure(error),
                };
                emit(json!({"event":crate::outcome::NodeEvent::InboundFailed,"error":code}));
            }
            _ => {}
        }
        Ok(())
    }

    fn request(
        &mut self,
        peer: PeerId,
        body: Body,
        grant: Option<crate::publication::PeerGrant>,
    ) -> Result<Body, crate::Error> {
        let _work = if matches!(&body, Body::Offer { .. } | Body::ProgramOffer { .. }) {
            match self.computation.try_enter() {
                Some(work) => Some(work),
                None => {
                    return Ok(Body::Error {
                        code: PeerFailure::ComputationPaused,
                    });
                }
            }
        } else {
            None
        };
        let response = match body {
            Body::WorkOffer { goal, question } => {
                if !self.cooperation_enabled
                    || question.len() > 2 * naome_checker::question::QUESTION_BYTES
                    || self.work_offers.len() >= crate::resources::active_limits().queued_metadata
                    || self.work_offers.iter().any(|offer| offer.peer == peer)
                {
                    Body::Error {
                        code: PeerFailure::WorkOfferUnavailable,
                    }
                } else if let Ok(memory) = crate::resources::MemoryLease::acquire(
                    question.len().saturating_mul(2).saturating_add(256),
                ) {
                    self.work_offers.push_back(WorkOffer {
                        peer,
                        goal,
                        question,
                        expires: Instant::now() + crate::resources::limits().selection_timeout,
                        requested: None,
                        _memory: memory,
                    });
                    Body::Receipt {
                        status: OfferStatus::Queued,
                    }
                } else {
                    Body::Error {
                        code: PeerFailure::WorkOfferCapacity,
                    }
                }
            }
            Body::WorkStatus {
                goal,
                question,
                active,
                sequence,
            } => {
                let key = (peer, goal, question);
                if sequence > 0
                    && self.work_sent.get(&key).is_some_and(|at| {
                        Instant::now().duration_since(*at)
                            < crate::resources::limits().pending_retry
                    })
                {
                    if !update_work_status(
                        &mut self.work_versions,
                        &mut self.work_members,
                        key,
                        sequence,
                        active,
                        Instant::now() + crate::resources::limits().pending_retry,
                    ) {
                        return Ok(Body::Receipt {
                            status: OfferStatus::Stale,
                        });
                    }
                    emit(
                        json!({"event":crate::outcome::NodeEvent::WorkgroupMember, "peer":peer.to_string(), "goal":hex(&goal), "resolution_id":hex(&question), "active":active}),
                    );
                    Body::Receipt {
                        status: OfferStatus::Recorded,
                    }
                } else {
                    Body::Error {
                        code: PeerFailure::UnknownWorkOffer,
                    }
                }
            }
            Body::Inventory {
                known,
                after,
                limit,
            } => match inventory_response(&self.graph, known, after, limit) {
                Ok(body) => body,
                Err(error) if !error.fatal() => Body::Error {
                    code: peer_failure(&error),
                },
                Err(error) => return Err(error),
            },
            Body::Describe { id } => match self.graph.description(ArtifactId::from_bytes(id)) {
                Ok(Some(crate::object::ProofDescription::Program(metadata))) => {
                    Body::ProgramDescription {
                        root: None,
                        metadata,
                    }
                }
                Ok(Some(crate::object::ProofDescription::Certificate(metadata))) => {
                    Body::Description {
                        metadata: self
                            .test_objects
                            .get(&ArtifactId::from_bytes(id))
                            .filter(|_| self.test_controls)
                            .map_or(metadata, |(metadata, _)| metadata.clone()),
                    }
                }
                Ok(None) => self
                    .test_controls
                    .then(|| self.test_objects.get(&ArtifactId::from_bytes(id)))
                    .flatten()
                    .map(|(metadata, _)| Body::Description {
                        metadata: metadata.clone(),
                    })
                    .unwrap_or(Body::Missing),
                Err(error) => Body::Error {
                    code: peer_failure(&error),
                },
            },
            Body::ProgramGet {
                root,
                id,
                start,
                limit,
            } => {
                if crate::resources::adaptive::network(1) == 0 {
                    Body::Error {
                        code: PeerFailure::ProgramResourcesPaused,
                    }
                } else {
                    let maximum = (crate::resources::limits().proof_bytes / 2)
                        .clamp(256, naome_proof::program::CHUNK_BYTES);
                    match self.graph.program_chunk(
                        ArtifactId::from_bytes(id),
                        start,
                        limit,
                        maximum,
                    ) {
                        Ok(Some(chunk)) => Body::ProgramData { root, id, chunk },
                        Ok(None) => Body::Missing,
                        Err(error) => Body::Error {
                            code: peer_failure(&error),
                        },
                    }
                }
            }
            Body::ProgramOffer { metadata } => {
                let id = metadata.manifest.artifact_id();
                let queued =
                    self.intake
                        .enqueue_program(peer, metadata, &self.graph, grant.clone());
                match self.finish_description(peer, id, grant, queued) {
                    Ok(status) => Body::Receipt { status },
                    Err(error) => Body::Error {
                        code: peer_failure(&error),
                    },
                }
            }
            Body::Get { root, id } => match self.graph.transfer(ArtifactId::from_bytes(id))? {
                Some(crate::object::ArtifactTransfer::Program(metadata)) => {
                    Body::ProgramDescription {
                        root: Some(root),
                        metadata,
                    }
                }
                Some(crate::object::ArtifactTransfer::Certificate { object, question }) => {
                    Body::Object {
                        root,
                        object,
                        question: question.filter(|_| root != id),
                    }
                }
                None => self
                    .test_controls
                    .then(|| {
                        self.test_objects
                            .get(&ArtifactId::from_bytes(id))
                            .and_then(|(_, object)| object.clone())
                    })
                    .flatten()
                    .map(|object| Body::Object {
                        root,
                        object,
                        question: None,
                    })
                    .unwrap_or(Body::Missing),
            },
            Body::Offer { metadata } => {
                let queued = id_bytes(&metadata.artifact_id).and_then(|id| {
                    let queued =
                        self.intake
                            .enqueue_with_grant(peer, metadata, &self.graph, grant.clone());
                    self.finish_description(peer, ArtifactId::from_bytes(id), grant, queued)
                });
                match queued {
                    Ok(status) => Body::Receipt { status },
                    Err(error) => {
                        let event = if self.graph.storage_error().is_some() {
                            crate::outcome::NodeEvent::StorageError
                        } else {
                            crate::outcome::NodeEvent::Rejected
                        };
                        emit(json!({"event":event,"error":error}));
                        Body::Error {
                            code: peer_failure(&error),
                        }
                    }
                }
            }
            _ => Body::Error {
                code: PeerFailure::UnexpectedRequest,
            },
        };
        if let Some(error) = self.graph.storage_error() {
            return Err(error);
        }
        Ok(response)
    }

    fn response(
        &mut self,
        peer: PeerId,
        flight: Flight,
        body: Body,
        grant: Option<crate::publication::PeerGrant>,
    ) -> Result<(), crate::Error> {
        // In-flight replies remain bounded by their original transport limits.
        // Dropped payloads can be requested again; no unchecked input is adopted.
        let Some(_work) = self.computation.try_enter() else {
            return Ok(());
        };
        let expected_peer = match &flight {
            Flight::Inventory { peer, .. }
            | Flight::Work { peer, .. }
            | Flight::Get { peer, .. }
            | Flight::Describe { peer, .. }
            | Flight::Program { peer, .. }
            | Flight::Offer { peer, .. } => *peer,
        };
        if peer != expected_peer {
            emit(
                json!({"event":crate::outcome::NodeEvent::Rejected, "error":WireFailure::ResponsePeerMismatch}),
            );
            return Ok(());
        }
        match (flight, body) {
            (
                Flight::Describe { id, .. },
                Body::ProgramDescription {
                    root: None,
                    metadata,
                },
            ) => {
                if metadata.manifest.artifact_id() != id {
                    emit(
                        json!({"event":crate::outcome::NodeEvent::Rejected,"error":WireFailure::DescriptionIdentityMismatch}),
                    );
                } else {
                    let queued =
                        self.intake
                            .enqueue_program(peer, metadata, &self.graph, grant.clone());
                    match self.finish_description(peer, id, grant, queued) {
                        Ok(OfferStatus::Duplicate) => {
                            self.wanted.remove(&id);
                        }
                        Ok(_) => {}
                        Err(error) => {
                            emit(json!({"event":crate::outcome::NodeEvent::Rejected,"error":error}))
                        }
                    }
                }
            }
            (
                Flight::Get {
                    root: expected_root,
                    id,
                    ..
                },
                Body::ProgramDescription {
                    root: Some(root),
                    metadata,
                },
            ) => {
                let result = if root != *expected_root.as_bytes() {
                    Err(crate::InputFault::ProgramDescriptionRoot.into())
                } else if metadata.manifest.artifact_id() != id {
                    Err(crate::InputFault::ProgramDescriptionId.into())
                } else {
                    self.intake
                        .enqueue_program_helper(peer, expected_root, metadata, &self.graph)
                };
                if let Err(error) = result {
                    self.graph.program_failure(&error);
                    emit(json!({"event":crate::outcome::NodeEvent::Rejected,"error":error}));
                }
            }
            (Flight::Program { read, .. }, Body::ProgramData { root, id, chunk }) => {
                let expected_root = read.root;
                let expected_id = read.id;
                let result = if let Err(error) = read.check_reply(root, id, &chunk) {
                    Err(error.into())
                } else {
                    self.intake.program_payload(
                        peer,
                        expected_root,
                        expected_id,
                        chunk,
                        &self.graph,
                    )
                };
                if let Err(error) = result {
                    self.graph.program_failure(&error);
                    self.intake.program_failed(peer, expected_id);
                    emit(
                        json!({"event":crate::outcome::NodeEvent::ProgramChunkRejected,"id":hex(expected_id.as_bytes()),"error":error}),
                    );
                }
            }
            (Flight::Program { read, .. }, body) => {
                let id = read.id;
                self.intake.program_failed(peer, id);
                let error = match body {
                    Body::Error { code } => code,
                    Body::Missing => PeerFailure::RequiredPayloadMissing,
                    _ => PeerFailure::UnexpectedResponse,
                };
                emit(
                    json!({"event":crate::outcome::NodeEvent::ProgramTransferDeferred,"id":hex(id.as_bytes()),"error":error}),
                );
            }
            (
                Flight::Inventory {
                    peer,
                    known,
                    request,
                    ..
                },
                Body::InventoryUnchanged { root },
            ) => {
                if request.after.is_some() || known != Some(root) {
                    emit(
                        json!({"event":crate::outcome::NodeEvent::Rejected,"error":WireFailure::UnsolicitedInventory}),
                    );
                } else {
                    self.inventory_progress.remove(&peer);
                    self.inventory_summaries
                        .insert(peer, (root, self.graph.content_root()));
                    emit(
                        json!({"event":crate::outcome::NodeEvent::InventoryUnchanged,"peer":peer.to_string(),"root":hex(&root)}),
                    );
                }
            }
            (
                Flight::Inventory { peer, request, .. },
                Body::InventoryResult {
                    snapshot,
                    ids,
                    next,
                },
            ) => {
                self.received_inventory(peer, request, snapshot, ids, next)?;
            }
            (
                Flight::Inventory {
                    peer,
                    request: inventory::Request { after: Some(_), .. },
                    ..
                },
                Body::InventoryRestart,
            ) => {
                self.inventory_progress.remove(&peer);
                self.inventory_summaries.remove(&peer);
            }
            (Flight::Describe { id, .. }, Body::Description { metadata }) => {
                if metadata.artifact_id != hex(id.as_bytes()) {
                    emit(
                        json!({"event":crate::outcome::NodeEvent::Rejected,"error":WireFailure::DescriptionIdentityMismatch}),
                    );
                    return Ok(());
                }
                let queued =
                    self.intake
                        .enqueue_with_grant(peer, metadata, &self.graph, grant.clone());
                match self.finish_description(peer, id, grant, queued) {
                    Ok(OfferStatus::Duplicate) => {
                        self.wanted.remove(&id);
                    }
                    // Preserve attempts and the original bounded hint epoch
                    // through queued/declined assessment. Otherwise a wrong
                    // descriptor can monopolize retries for the same ArtifactId.
                    Ok(_) => {}
                    Err(error) => {
                        emit(json!({"event":crate::outcome::NodeEvent::Rejected,"error":error}))
                    }
                }
            }
            (
                Flight::Get {
                    root: expected_root,
                    id,
                    ..
                },
                Body::Object {
                    root,
                    object,
                    question,
                },
            ) => {
                let result = if root != *expected_root.as_bytes() {
                    Err("response root mismatch".into())
                } else {
                    self.intake.payload_with_question(
                        peer,
                        expected_root,
                        id,
                        object,
                        question,
                        &self.graph,
                    )
                };
                if let Err(error) = result {
                    self.proof_fetch_error(expected_root, error);
                }
            }
            (Flight::Offer { .. }, Body::Receipt { status }) => {
                emit(json!({"event":crate::outcome::NodeEvent::OfferResult,"status":status}))
            }
            (Flight::Work { .. }, Body::Receipt { status }) => {
                emit(json!({"event":crate::outcome::NodeEvent::WorkgroupReceipt,"status":status}))
            }
            (
                Flight::Get { root, .. },
                Body::Error {
                    code: PeerFailure::OwnerBusy,
                },
            ) => {
                // Keep the existing approved closure and its original grant.
                // Automatic request pacing retries without renewing authority.
                emit(
                    json!({"event":crate::outcome::NodeEvent::ProofDeferred, "id":hex(root.as_bytes()),"error":PeerFailure::OwnerBusy}),
                );
            }
            (Flight::Get { root, .. }, Body::Error { code }) => {
                self.intake.abort(root);
                emit(
                    json!({"event":crate::outcome::NodeEvent::ProofSkipped, "id":hex(root.as_bytes()),"error":code}),
                );
            }
            (Flight::Get { root, .. }, Body::Missing) => {
                self.intake.abort(root);
                emit(
                    json!({"event":crate::outcome::NodeEvent::ProofSkipped, "id":hex(root.as_bytes()),"error":PeerFailure::RequiredPayloadMissing}),
                );
            }
            (_, Body::Error { code }) => {
                emit(json!({"event":crate::outcome::NodeEvent::PeerError,"error":code}))
            }
            // Keep the bounded attempt counter so the next retry rotates to
            // another peer. A missing descriptor is no decline authority.
            (Flight::Describe { .. }, Body::Missing) => {}
            (Flight::Get { root, .. }, _) => {
                self.intake.abort(root);
                emit(
                    json!({"event":crate::outcome::NodeEvent::ProofSkipped,"id":hex(root.as_bytes()),"error":PeerFailure::UnexpectedResponse}),
                );
            }
            _ => emit(
                json!({"event":crate::outcome::NodeEvent::Rejected,"error":WireFailure::ResponseScopeMismatch}),
            ),
        }
        if let Some(error) = self.graph.storage_error() {
            return Err(error);
        }
        Ok(())
    }
}

fn checked_replay_error(error: crate::Error) -> crate::Error {
    match error {
        crate::Error::Runtime(_) | crate::Error::UncertainDurability(_) => error,
        error if error.retryable() => error,
        cause => crate::Error::RuntimeContext {
            code: crate::RuntimeFailure::CheckedStorageReplay,
            cause: Box::new(cause),
        },
    }
}

pub fn read_config(path: &Path) -> Result<Config, crate::Error> {
    let mut config: Config = serde_json::from_slice(&crate::store::read_bounded(
        path,
        crate::resources::limits().network_config_bytes,
    )?)
    .map_err(|error| crate::Error::RuntimeContext {
        code: crate::RuntimeFailure::NetworkConfigParse,
        cause: Box::new(crate::error::config_decode(error)),
    })?;
    if config.directory.is_relative() {
        config.directory = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&config.directory);
    }
    Ok(config)
}

mod discovery_runtime;
pub(crate) mod transport;

#[cfg(test)]
mod tests;
