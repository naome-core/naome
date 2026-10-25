//! Bounded question-first proof transport with static or discovered peers.
//! Gossip and inventory are hints; receiver approval precedes certificate fetch,
//! and only a completely checked root closure reaches the durable graph.

use crate::{
    Envelope, Graph, discovery, hex,
    object::{Metadata, id_bytes},
    wire::{Body, Codec, Frame, PROTOCOL},
};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, allow_block_list, connection_limits,
    futures::StreamExt,
    gossipsub, identity, noise, relay, request_response,
    swarm::{ConnectionId, NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle},
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
mod command;
mod exchange;
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
    pub producer_sources: Vec<String>,
}
pub use crate::discovery::{Config as DiscoveryConfig, Peer};

/// Operator-visible routing settings and local resource limits. These do not
/// change the mathematical compatibility fingerprint or proof admission.
pub fn routing_contract() -> Value {
    json!({
        "corpus_fingerprint":{"produced":crate::CORPUS_ROOT_FORMAT,"catalog_schema":crate::store::CATALOG_SCHEMA_VERSION,"incompatible":"Rejected without conversion or reset"},
        "question_exchange":{
            "protocol":"/naome/knowledge/5", "topic":"naome-knowledge-v5",
            "interest":"Explicit local positive selection before root fetch and before commit",
            "metadata":"Newly derived resolution obligation; no recovered original source or proof bytes",
            "limits":{"active_roots":1,"queued_metadata":crate::resources::limits().queued_metadata,
                "closure_objects":crate::resources::limits().closure_objects,"closure_bytes":crate::resources::limits().closure_bytes,
                "closure_steps":crate::resources::limits().closure_steps,"checker_work_bytes":crate::resources::limits().closure_work_bytes,
                "root_lifetime_seconds":crate::resources::limits().root_timeout.as_secs(),"outgoing_request_burst_per_peer":crate::resources::limits().request_burst,"outgoing_request_refill_ms":crate::resources::limits().request_rate_window.as_millis()}
        },
        "identify_protocol":discovery::protocol_version(false),
        "dht_protocol":format!("/naome/knowledge/kad/{}/1", hex(&crate::compatibility())),
        "participation_key":hex(discovery::provider_key().as_ref()),
        "defaults":DiscoveryConfig::default(),
        "limits":{
            "contacts":crate::resources::limits().contacts,"addresses_per_contact":crate::resources::limits().addresses_per_contact,
            "address_bytes":crate::resources::limits().address_bytes,"bootstrap":crate::resources::limits().bootstrap_peers,
            "relays":crate::resources::limits().relay_peers,"contact_ttl_seconds":crate::resources::limits().contact_ttl.as_secs(),
            "identify_timeout_seconds":crate::resources::limits().identify_timeout.as_secs(),
            "mdns_ttl_seconds":crate::resources::limits().mdns_ttl.as_secs(),
            "discovery_interval_seconds":crate::resources::limits().discovery_interval.as_secs(),
            "provider_records":crate::resources::limits().contacts,"provider_ttl_seconds":crate::resources::limits().provider_ttl.as_secs(),
            "application_queries":crate::resources::limits().application_queries,
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
    gate: discovery::Gate,
    allowed: Toggle<allow_block_list::Behaviour<allow_block_list::AllowedPeers>>,
    discovery: discovery::Behaviour,
    relay: relay::client::Behaviour,
    limits: connection_limits::Behaviour,
    gossip: gossipsub::Behaviour,
    exchange: exchange::Exchange,
}

struct Wanted {
    since: Instant,
    retry: Instant,
    attempts: usize,
}

fn description_supplier(
    peers: &[PeerId],
    attempts: usize,
    mut request_ready: impl FnMut(PeerId) -> bool,
    mut automatic_ready: impl FnMut(PeerId) -> bool,
) -> Option<PeerId> {
    let peer = peers
        .iter()
        .cycle()
        .skip(attempts % peers.len().max(1))
        .take(peers.len())
        .find(|peer| request_ready(**peer))
        .copied()?;
    // Inventory may have just used this supplier's automatic-read window.
    // Wait for it without consuming the turn or retrying the previous supplier.
    automatic_ready(peer).then_some(peer)
}

enum Flight {
    Inventory {
        peer: PeerId,
        known: Option<[u8; 32]>,
        after: Option<[u8; 32]>,
        pages: usize,
    },
    Get {
        root: ProofId,
        id: ProofId,
        peer: PeerId,
    },
    Describe {
        id: ProofId,
        peer: PeerId,
    },
    Offer {
        peer: PeerId,
    },
    Program {
        root: ProofId,
        id: ProofId,
        start: u64,
        peer: PeerId,
    },
}
struct Bucket {
    tokens: usize,
    reset: Instant,
}
#[derive(Clone, Copy, Default)]
struct InventoryProgress {
    root: Option<[u8; 32]>,
    after: Option<[u8; 32]>,
    pages: usize,
}
struct Node {
    computation: Arc<crate::resources::Computation>,
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
    wanted: BTreeMap<ProofId, Wanted>,
    flights: HashMap<request_response::OutboundRequestId, Flight>,
    next_inventory: BTreeMap<PeerId, Instant>,
    inventory_progress: BTreeMap<PeerId, InventoryProgress>,
    inventory_summaries: BTreeMap<PeerId, ([u8; 32], [u8; 32])>,
    next_automatic_request: BTreeMap<PeerId, Instant>,
    buckets: BTreeMap<PeerId, Bucket>,
    outgoing: BTreeMap<PeerId, Bucket>,
    intake: crate::intake::Intake,
    test_objects: BTreeMap<ProofId, (Metadata, Option<Envelope>)>,
    test_controls: bool,
    producer_sources: VecDeque<String>,
    next_production: Instant,
}

pub async fn run(config: Config, test_controls: bool) -> Result<(), String> {
    run_with_interest(config, test_controls, None).await
}

/// Autonomous ordinary operation owns its control, schedule and interest future.
/// It accepts no manual developer operations. Runtime owns the transient
/// startup stdin lifeline and releases it only after checked readiness.
#[cfg(unix)]
pub(crate) async fn run_autonomous(
    config: Config,
    intervals: crate::autonomous::Intervals,
    startup: crate::runtime::Startup,
) -> Result<(), String> {
    let (handle, admin, inbox) = crate::question::channel();
    drop(handle);
    drop(admin);
    let (sender, commands) = mpsc::channel(crate::resources::limits().cli_commands);
    drop(sender);
    run_inner(
        config,
        false,
        inbox,
        None::<fn(naome_authoring::CompiledQuestion) -> std::future::Ready<Result<bool, String>>>,
        commands,
        Some((intervals, startup)),
    )
    .await
}

/// Explicit local mathematical interest policy for the CLI. Neither selection
/// nor a peer's metadata makes an obligation valid or novel.
pub enum InterestSelection {
    AllSupported,
    Questions(Vec<naome_authoring::CompiledQuestion>),
}

impl InterestSelection {
    fn accepts(&self, question: &naome_authoring::CompiledQuestion) -> bool {
        match self {
            Self::AllSupported => true,
            Self::Questions(questions) => questions.iter().any(|selected| {
                selected.resolution_id() == question.resolution_id()
                    && selected.canonical_core() == question.canonical_core()
                    && selected.core() == question.core()
            }),
        }
    }
}

pub async fn run_with_interest(
    config: Config,
    test_controls: bool,
    selection: Option<InterestSelection>,
) -> Result<(), String> {
    let (handle, admin, inbox) = crate::question::channel();
    drop(handle);
    drop(admin);
    let (sender, commands) = mpsc::channel(crate::resources::limits().cli_commands);
    // Preserve the existing CLI input reader only for the CLI-oriented wrapper.
    std::thread::spawn(move || read_commands(sender));
    run_inner(
        config,
        test_controls,
        inbox,
        selection
            .map(|selection| move |question| std::future::ready(Ok(selection.accepts(&question)))),
        commands,
        None,
    )
    .await
}

/// Runs the existing Gossip node with a bounded Rust-only local question inbox.
/// The separately supplied interest future must be nonblocking and own all its
/// effects without detaching work. It is polled inside this node's lifetime;
/// shutdown, cancellation or the fixed deadline drops it. No proof-validity
/// condition depends on interest. Peer proof exchange always requires positive
/// question selection before full certificate retrieval.
pub async fn run_with_questions<F, Fut>(
    config: Config,
    test_controls: bool,
    inbox: crate::question::QuestionInbox,
    interest: F,
) -> Result<(), String>
where
    F: Fn(naome_authoring::CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<bool, String>> + Send + 'static,
{
    let (sender, commands) = mpsc::channel(crate::resources::limits().cli_commands);
    drop(sender);
    run_inner(config, test_controls, inbox, Some(interest), commands, None).await
}

/// Runs local question intake without an interest provider. The formal result
/// remains available to assessment; admission reports NotInserted/NotRun.
/// Embeddings must explicitly supply positive selection to admit a question.
pub async fn run_with_questions_without_interest(
    config: Config,
    test_controls: bool,
    inbox: crate::question::QuestionInbox,
) -> Result<(), String> {
    let (sender, commands) = mpsc::channel(crate::resources::limits().cli_commands);
    drop(sender);
    run_inner(
        config,
        test_controls,
        inbox,
        None::<fn(naome_authoring::CompiledQuestion) -> std::future::Ready<Result<bool, String>>>,
        commands,
        None,
    )
    .await
}

pub(crate) async fn run_inner<F, Fut>(
    config: Config,
    test_controls: bool,
    inbox: crate::question::QuestionInbox,
    interest: Option<F>,
    commands: mpsc::Receiver<Result<QueuedCommand, String>>,
    autonomy: Option<(crate::autonomous::Intervals, crate::runtime::Startup)>,
) -> Result<(), String>
where
    F: Fn(naome_authoring::CompiledQuestion) -> Fut + Send + Sync + 'static,
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
                    .max_blocking_threads(crate::resources::limits().control_clients)
                    .thread_name("naome-transport")
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                runtime.block_on(run_owner(
                    config,
                    test_controls,
                    inbox,
                    interest,
                    commands,
                    autonomy,
                    cancel,
                ))
            })();
            let _ = reply.send(outcome);
        })
        .map_err(|e| e.to_string())?;
    let mut owner = worker::OwnerThread {
        thread: Some(thread),
        stop: Some(stop),
    };
    let outcome = result
        .await
        .unwrap_or_else(|_| Err("node state owner stopped without a receipt".into()));
    owner.join()?;
    outcome
}

pub(crate) async fn run_owner<F, Fut>(
    config: Config,
    test_controls: bool,
    mut inbox: crate::question::QuestionInbox,
    interest: Option<F>,
    mut commands: mpsc::Receiver<Result<QueuedCommand, String>>,
    autonomy: Option<(crate::autonomous::Intervals, crate::runtime::Startup)>,
    mut cancel: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String>
where
    F: Fn(naome_authoring::CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<bool, String>> + Send + 'static,
{
    let (autonomy, startup) = match autonomy {
        Some((intervals, startup)) => (Some(intervals), Some(startup)),
        None => (None, None),
    };
    if config.peers.len() > crate::resources::limits().configured_peers {
        return Err("peer count limit".into());
    }
    if config.producer_sources.len() > crate::resources::limits().producer_sources
        || config
            .producer_sources
            .iter()
            .map(String::len)
            .sum::<usize>()
            > crate::resources::limits().producer_bytes
    {
        return Err("producer queue capacity".into());
    }
    if let Some(startup) = &startup {
        startup.phase("begin");
    }
    let graph = Graph::open(&config.directory)?;
    if let Some(startup) = &startup {
        startup.phase("checked");
    }
    let directory = config.directory.clone();
    let key = identity::Keypair::from_protobuf_encoding(&crate::store::read_bounded(
        &config.directory.join("identity.key"),
        1024,
    )?)
    .map_err(|error| error.to_string())?;
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
    let settings = config.discovery.unwrap_or_else(|| discovery::Config {
        mdns: config.peers.is_empty(),
        ..Default::default()
    });
    if settings.bootstrap.len() > crate::resources::limits().bootstrap_peers
        || settings.relays.len() > crate::resources::limits().relay_peers
        || settings.external_addresses.len() > crate::resources::limits().addresses_per_contact
    {
        return Err("discovery configuration capacity".into());
    }
    if settings.relay_only && (settings.relays.is_empty() || settings.mdns) {
        return Err("relay-only mode requires configured relays and disables mDNS".into());
    }
    let mut book = discovery::Book::new(own_id, automatic, &settings);
    let mut configured = BTreeMap::new();
    for peer in &settings.relays {
        let id: PeerId = peer
            .id
            .parse()
            .map_err(|error| format!("relay ID: {error}"))?;
        let address: Multiaddr = peer
            .address
            .parse()
            .map_err(|error| format!("relay address: {error}"))?;
        book.pin(id, &address, true)?;
    }
    for peer in &settings.bootstrap {
        let id: PeerId = peer
            .id
            .parse()
            .map_err(|error| format!("bootstrap ID: {error}"))?;
        let address: Multiaddr = peer
            .address
            .parse()
            .map_err(|error| format!("bootstrap address: {error}"))?;
        book.pin(id, &address, false)?;
    }
    for peer in config.peers {
        let id: PeerId = peer
            .id
            .parse()
            .map_err(|error| format!("peer ID: {error}"))?;
        let address: Multiaddr = peer
            .address
            .parse()
            .map_err(|error| format!("peer address: {error}"))?;
        book.pin(id, &address, false)?;
        if configured.insert(id, address).is_some() {
            return Err("duplicate peer".into());
        }
    }
    let listen: Multiaddr = config
        .listen
        .parse()
        .map_err(|error| format!("listen address: {error}"))?;
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
        .map_err(|error| error.to_string())?;
    let mut gossip = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossip_config,
    )
    .map_err(|error| error.to_string())?;
    let topic = gossipsub::IdentTopic::new("naome-knowledge-v5");
    gossip
        .subscribe(&topic)
        .map_err(|error| error.to_string())?;
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
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux_config,
        )
        .map_err(|error| error.to_string())?
        .with_dns()
        .map_err(|error| error.to_string())?
        .with_relay_client(noise::Config::new, yamux_config)
        .map_err(|error| error.to_string())?
        .with_behaviour(|_, relay| Behaviour {
            gate: discovery::Gate(book.clone()),
            allowed: (!automatic).then_some(allowed).into(),
            discovery: discovery_behaviour,
            relay,
            limits,
            gossip,
            exchange,
        })
        .map_err(|error| error.to_string())?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(crate::resources::limits().idle_connection_timeout)
                .with_max_negotiating_inbound_streams(crate::resources::limits().inbound_streams)
        })
        .with_connection_timeout(crate::resources::limits().request_timeout)
        .build();
    let primary_listener = swarm.listen_on(listen).map_err(|error| error.to_string())?;
    for address in &settings.external_addresses {
        let address: Multiaddr = address
            .parse()
            .map_err(|error| format!("external address: {error}"))?;
        let address = discovery::routing_address(&address, own_id, &book.lock().relays)?;
        if settings.relay_only && !discovery::is_relayed(&address) {
            return Err("relay-only mode must not advertise direct endpoints".into());
        }
        swarm.add_external_address(address);
    }
    let (swarm, mut events, mut transport) = worker::Transport::spawn(swarm, primary_listener);
    let enabled = BTreeSet::new();
    let mut node = Node {
        computation: control
            .as_ref()
            .map_or_else(Arc::default, |control| control.computation.clone()),
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
        producer_sources: config.producer_sources.into(),
        next_production: Instant::now() + crate::resources::limits().production_interval,
    };
    let mut tick = tokio::time::interval(crate::resources::limits().tick_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut command_input_open = true;
    let mut question_input_open = true;
    let (mut research, mut autonomous, mut questions) = if let Some(intervals) = autonomy {
        use sha2::Digest;
        let cursor = sha2::Sha256::digest(own_id.to_bytes())[0] as u64;
        let (service, client, recovery) = crate::jobs::Service::open(
            &directory,
            intervals.jobs,
            cursor,
            node.computation.clone(),
        )?;
        let questions = crate::question::LocalQuestions::<F>::managed(
            client.clone(),
            &directory,
            Duration::from_millis(intervals.jobs.interest.limits.horizon_ms),
        )?;
        let unanswered = questions.restored_unanswered(&node.graph);
        let autonomous =
            crate::autonomous::Autonomous::new(intervals, client, recovery, unanswered);
        (Some(service), Some(autonomous), questions)
    } else {
        let mut questions = crate::question::LocalQuestions::new(interest);
        questions.attach_persistence(&directory)?;
        (None, None, questions)
    };
    questions.recover_publications(&node.graph)?;
    let published = Arc::new(worker::PublishedStatus::default());
    published
        .count
        .store(node.graph.accepted_count(), Ordering::Release);
    let mut controls = worker::Controls::spawn(control.clone(), published.clone());
    let mut stop_watch = control.as_ref().map(|control| control.stop_watch());
    let mut stopping = false;
    let mut next_profile_check = Instant::now();
    let mut resources = control
        .as_ref()
        .map(|_| crate::resources::adaptive::history::Controller::open(&directory))
        .transpose()?;
    emit(
        json!({"event":"starting", "peer_id":own_id.to_string(), "compatibility":hex(&crate::compatibility())}),
    );
    // Keep signal receivers alive while another branch processes synchronous work.
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let owner_busy = node.swarm.busy.clone();
    let outcome:Result<(),String>=worker::while_polled(owner_busy, async {
    loop {
        if let Some(resources)=&mut resources {resources.refresh()?;}
        let work = node.computation.try_enter();
        // Read the validated owner epoch before polling any final admission.
        // An error invalidates old selection; stop remains available.
        if let Some(control)=&control
            && (control.selection_changed() || Instant::now()>=next_profile_check) {
                next_profile_check=Instant::now()+crate::resources::limits().profile_poll_interval;
                if questions.select(control.selection().ok()) {
                node.intake.invalidate_interest(); node.inventory_summaries.clear();
                }
            }
        node.graph.set_commit_guard(crate::graph::CommitGuard::new(
            node.swarm.epoch.clone(), node.transport_epoch, control.clone(), questions.revision(&node.graph).3,
        ));
        // A cold peer may stay quiet after its response. Wake at the next
        // paced request deadline instead of quantizing reads to the tick.
        let request_now = Instant::now();
        let automatic_wake = node
            .next_automatic_request
            .values()
            .filter(|until| **until > request_now)
            .min()
            .copied();
        tokio::select! {
            _=tokio::time::sleep(Duration::from_millis(crate::resources::adaptive::current().map_or(5,|snapshot|if snapshot.budget.paused.is_some(){250}else{snapshot.budget.yield_ms.max(1)}))),if work.is_some()&&(node.intake.program_busy()||autonomous.as_ref().is_some_and(crate::autonomous::Autonomous::program_busy))&&!stopping=>{},
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
                node.graph.set_commit_guard(crate::graph::CommitGuard::new(
                    node.swarm.epoch.clone(), node.transport_epoch, control.clone(), questions.revision(&node.graph).3,
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
                            Err(error) => emit(json!({"event":"command_error","error":error})),
                            Ok((value, _parsed_memory)) => { if !node.command(value) { break; } },
                        }
                    },
                    Some(Err(error)) => emit(json!({"event":"command_error", "error":error})),
                    None => {
                        command_input_open = false;
                        emit(json!({"event":"command_input_closed"}));
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
            interest = questions.completed(),if work.is_some() && !stopping => {
                if let Some(control)=&control
                    && questions.select(control.selection().ok()){node.intake.invalidate_interest(); node.inventory_summaries.clear();}
                questions.finish(&node.graph, interest);
            },
            _=crate::runtime::requested_stop(&mut stop_watch),if !stopping=>{
                stopping=true;

                if let Some(service)=&mut research{service.begin_shutdown()?;}
            },
            signal = &mut shutdown => { signal?; break; }
        }
        published.count.store(node.graph.accepted_count(), Ordering::Release);
        if let Some(error)=node.graph.storage_error(){return Err(format!(
            "durable storage failed; restart must reverify: {error}"));}
        if let Some(error)=questions.storage_error(){return Err(error.to_owned());}
        if let Some(error)=research.as_ref().and_then(crate::jobs::Service::error){return Err(error);}
        if stopping {
            break;
        }
        if work.is_none() {
            continue;
        }
        if let Some(control)=&control
            && (control.selection_changed() || node.intake.selection_boundary_ready()
                || autonomous.as_ref().is_some_and(crate::autonomous::Autonomous::selection_boundary_ready))
                && questions.select(control.selection().ok()){node.intake.invalidate_interest(); node.inventory_summaries.clear();}
        node.graph.set_commit_guard(crate::graph::CommitGuard::new(
            node.swarm.epoch.clone(), node.transport_epoch, control.clone(), questions.revision(&node.graph).3,
        ));
        node.graph.maintain_checked_storage()?;
        questions.maintain_registry()?;
        questions.cancel_closed();
        match node.intake.advance(&mut node.graph, &mut questions) {
            crate::intake::Progress::Waiting => {}
            crate::intake::Progress::Skipped(id, error) => {
                emit(json!({"event":"proof_skipped","id":hex(id.as_bytes()),"error":error}));
            }
            crate::intake::Progress::Accepted(ids) => {
                node.publish_admitted(&ids, "fetch");
                // Earlier explicit owner ingestion can now resolve. This is
                // not part of the approved peer closure or its atomic batch.
                let (admitted, rejected) = node.graph.resolve_pending()?;
                node.publish_admitted(&admitted, "local_pending");
                for (id, error) in rejected {
                    emit(
                        json!({"event":"rejected", "id":hex(id.as_bytes()),"source":"local_pending","error":error}),
                    );
                }
            }
        }
        questions.cancel_closed();
        if let Some(autonomous) = &mut autonomous {
            let admitted = autonomous.advance(&mut node.graph, &mut questions);
            node.publish_admitted(&admitted, "mock_producer");
            if let Some(error)=autonomous.error(){return Err(error.to_owned());}
        }
        if let Some(error) = questions.storage_error() { return Err(error.to_owned()); }
        node.requests();
        published.count.store(node.graph.accepted_count(), Ordering::Release);
        if let Some(error) = node.graph.storage_error() {
            return Err(format!(
                "durable storage failed; restart must reverify: {error}"
            ));
        }
        if let Some(error) = crate::runtime::log_error() {
            return Err(format!("runtime log failed: {error}"));
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
    let cleanup = cleanup.and(control_cleanup).and(transport_cleanup);
    match (outcome, cleanup) {
        (Err(primary), Err(cleanup)) => {
            return Err(format!(
                "research cleanup failed: {cleanup}; node failure: {primary}"
            ));
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
        _ => {}
    }
    emit(json!({"event":"stopped", "root":hex(&node.graph.content_root())}));
    Ok(())
}

pub(crate) fn require_tcp_address(address: &Multiaddr) -> Result<(), String> {
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

pub(crate) fn yamux_config() -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(crate::resources::limits().inbound_streams);
    config
}

fn body_kind(body: &Body) -> &'static str {
    match body {
        Body::Inventory { .. } => "inventory",
        Body::InventoryResult { .. } => "inventory_result",
        Body::InventoryUnchanged { .. } => "inventory_unchanged",
        Body::Get { .. } => "get",
        Body::Describe { .. } => "describe",
        Body::Description { .. } => "description",
        Body::Object { .. } => "object",
        Body::Offer { .. } => "offer",
        Body::Receipt { .. } => "receipt",
        Body::Missing => "missing",
        Body::Error { .. } => "error",
        Body::ProgramDescription { .. } => "program_description",
        Body::ProgramOffer { .. } => "program_offer",
        Body::ProgramGet { .. } => "program_get",
        Body::ProgramData { .. } => "program_data",
    }
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
            Some(hex(metadata.manifest.proof_id().as_bytes()))
        }
        Body::Object { object, .. } => Some(object.proof_id.clone()),
        Body::Offer { metadata } | Body::Description { metadata } => {
            Some(metadata.proof_id.clone())
        }
        _ => None,
    }
}

fn inventory_response(
    graph: &Graph,
    known: Option<[u8; 32]>,
    after: Option<[u8; 32]>,
    limit: usize,
) -> Result<Body, crate::Error> {
    let root = graph.content_root();
    if after.is_none() && known == Some(root) {
        return Ok(Body::InventoryUnchanged { root });
    }
    if limit == 0 {
        return Err("inventory page limit must be positive".into());
    }
    let limit = limit.min(crate::resources::limits().inventory_page);
    let ids: Vec<_> = graph
        .ids_page(after.map(ProofId::from_bytes), limit)?
        .into_iter()
        .map(|id| *id.as_bytes())
        .collect();
    let next = if ids.len() == limit {
        ids.last().copied()
    } else {
        None
    };
    Ok(Body::InventoryResult { root, ids, next })
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

fn read_commands(sender: mpsc::Sender<Result<QueuedCommand, String>>) {
    use std::io::{BufRead, Read};
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        let memory = match crate::resources::MemoryLease::acquire_control(
            crate::resources::limits().command_bytes * 2 + 2,
        ) {
            Ok(memory) => memory,
            Err(error) => {
                let _ = sender.blocking_send(Err(error.to_string()));
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
                let _ =
                    sender.blocking_send(Err("command byte limit or missing final newline".into()));
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
            Err(error) => {
                let _ = sender.blocking_send(Err(error.to_string()));
                break;
            }
        }
    }
}

pub(crate) fn emit(value: Value) {
    if crate::runtime::emit_log(&value) {
        return;
    }
    println!("{value}");
}

pub(crate) async fn shutdown_signal() -> Result<(), String> {
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

fn retryable_publication(error: &crate::Error) -> bool {
    error.retryable()
}

impl Node {
    fn flight_count(&self, target: PeerId) -> usize {
        self.flights
            .values()
            .filter(|flight| match flight {
                Flight::Inventory { peer, .. }
                | Flight::Get { peer, .. }
                | Flight::Describe { peer, .. }
                | Flight::Program { peer, .. }
                | Flight::Offer { peer } => *peer == target,
            })
            .count()
    }
    fn want(&mut self, id: ProofId) -> Result<bool, String> {
        if self.graph.contains(id)? || self.intake.contains(id) || self.wanted.contains_key(&id) {
            return Ok(true);
        }
        if self.wanted.len() >= crate::resources::limits().fetches {
            return Ok(false);
        }
        self.wanted.insert(
            id,
            Wanted {
                since: Instant::now(),
                retry: Instant::now(),
                attempts: 0,
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

    fn ingest(&mut self, object: Envelope, source: &str) -> Result<Value, crate::Error> {
        let result = self.graph.ingest(object, Instant::now())?;
        self.ingested(result, source)
    }
    fn ingested(&mut self, result: crate::Ingest, source: &str) -> Result<Value, crate::Error> {
        self.wanted.remove(&result.id);
        self.publish_admitted(&result.admitted, source);
        for (id, error) in result.rejected {
            emit(
                json!({"event":"rejected", "id":hex(id.as_bytes()), "error":error, "source":"pending"}),
            );
        }
        let value = json!({"status":result.status, "id":hex(result.id.as_bytes())});
        emit(json!({"event":"ingest", "result":value, "source":source}));
        Ok(value)
    }

    fn publish_admitted(&mut self, ids: &[ProofId], source: &str) {
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
                json!({"event":"accepted", "id":hex(id.as_bytes()), "source":source, "root":hex(&self.graph.content_root())}),
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
                                .map(ProofId::from_bytes)
                        })
                        .transpose()?;
                    let ids = self
                        .graph
                        .ids_page(after, crate::resources::limits().status_page)?;
                    let next_after = (ids.len() == crate::resources::limits().status_page)
                        .then(|| ids.last().map(|id| hex(id.as_bytes())))
                        .flatten();
                    Ok(
                        json!({"ids":ids.iter().map(|id|hex(id.as_bytes())).collect::<Vec<_>>(),
                    "next_after":next_after,"accepted_proofs":self.graph.accepted_count(),
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
                        .get("source")
                        .and_then(Value::as_str)
                        .ok_or("source missing")?;
                    let (object, ingestion) = self.graph.produce(source)?;
                    let id = ingestion.id;
                    let result = self.ingested(ingestion, "producer")?;
                    let metadata = self.graph.describe(id);
                    if let Some(error) = self.graph.storage_error() {
                        return Err(error.into());
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
                    self.ingest(object, "local")
                }
                "object" => Ok(
                    json!({"object":self.graph.get(value.get("id").and_then(Value::as_str).ok_or("id missing")?)?}),
                ),
                "test_compile" => {
                    if !self.test_controls {
                        return Err("test controls disabled".into());
                    }
                    Ok(
                        json!({"object":self.graph.author(value.get("source").and_then(Value::as_str).ok_or("source missing")?)?}),
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
                    let (id, _, _) = metadata.compile()?;
                    if self.test_objects.len() >= crate::resources::limits().developer_objects
                        && !self.test_objects.contains_key(&id)
                    {
                        return Err("test object capacity".into());
                    }
                    self.test_objects.insert(id, (metadata, None));
                    Ok(json!({"installed":true}))
                }
                "describe" => Ok(
                    json!({"metadata":self.graph.describe(ProofId::from_bytes(id_bytes(value.get("id").and_then(Value::as_str).ok_or("id missing")?)?))?}),
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
                    let id = ProofId::from_bytes(id_bytes(
                        value
                            .get("id")
                            .and_then(Value::as_str)
                            .ok_or("id missing")?,
                    )?);
                    if !self.graph.contains(id)? {
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
                    crate::resources::require_work_admission()?;
                    if self.flights.len()
                        >= crate::resources::adaptive::network(crate::resources::limits().flights)
                    {
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
                    if self.flight_count(peer) >= crate::resources::limits().flights_per_peer {
                        return Err("peer request capacity".into());
                    }
                    let now = Instant::now();
                    if !self.outgoing_ready(peer, now) {
                        return Err("outgoing peer request rate".into());
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
                            if object.proof.len() > 2 * crate::resources::limits().proof_bytes {
                                return Err("test proof byte limit".into());
                            }
                            self.test_objects.insert(
                                ProofId::from_bytes(id_bytes(&metadata.proof_id)?),
                                (metadata.clone(), Some(object)),
                            );
                        }
                        metadata
                    } else {
                        let id = ProofId::from_bytes(id_bytes(
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
                    self.flights.insert(id, Flight::Offer { peer });
                    self.charge_outgoing(peer, now);
                    Ok(json!({"sent":true}))
                }
                "stop" => Ok(json!({"stopping":true})),
                _ => Err("unknown command".into()),
            }
        })();
        match result {
            Ok(result) => emit(json!({"event":"response","request":request,"result":result})),
            Err(error) => emit(
                json!({"event":"response","request":request,"retryable":retryable_publication(&error),"error":error}),
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
            && let Some(source) = self.producer_sources.pop_front()
        {
            self.next_production = now + crate::resources::limits().production_interval;
            let result = self
                .graph
                .produce(&source)
                .and_then(|(_, result)| self.ingested(result, "deterministic_producer"));
            match result {
                Ok(result) => emit(json!({"event":"producer_result", "result":result})),
                Err(error) if retryable_publication(&error) => {
                    self.producer_sources.push_back(source);
                    emit(json!({"event":"producer_deferred", "error":error}));
                }
                Err(error) => emit(json!({"event":"producer_rejected", "error":error})),
            }
        }
        if work.is_some() {
            match self.graph.resolve_pending() {
                Ok((admitted, rejected)) => {
                    self.publish_admitted(&admitted, "local_backlog");
                    for (id, error) in rejected {
                        emit(
                            json!({"event":"rejected","id":hex(id.as_bytes()),"source":"local_backlog","error":error}),
                        );
                    }
                }
                Err(error) => emit(json!({"event":"proof_backlog_error","error":error})),
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

    fn outgoing_ready(&self, peer: PeerId, now: Instant) -> bool {
        self.outgoing.get(&peer).is_none_or(|bucket| {
            bucket.tokens > 0
                || now.duration_since(bucket.reset)
                    >= crate::resources::limits().request_rate_window
        })
    }

    fn charge_outgoing(&mut self, peer: PeerId, now: Instant) {
        let bucket = self.outgoing.entry(peer).or_insert(Bucket {
            tokens: crate::resources::limits().request_burst,
            reset: now,
        });
        if now.duration_since(bucket.reset) >= crate::resources::limits().request_rate_window {
            bucket.tokens = crate::resources::limits().request_burst;
            bucket.reset = now;
        }
        bucket.tokens -= 1;
    }

    fn request_ready(&self, peer: PeerId, now: Instant) -> bool {
        self.enabled.contains(&peer)
            && self.swarm.is_connected(&peer)
            && self.flights.len()
                < crate::resources::adaptive::network(crate::resources::limits().flights)
            && self.flight_count(peer) < crate::resources::limits().flights_per_peer
            && self.outgoing_ready(peer, now)
    }

    fn requests(&mut self) {
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
                self.flights.insert(request, Flight::Describe { id, peer });
                self.charge_automatic_request(peer, now);
                self.charge_outgoing(peer, now);
            }
        }
        match self.intake.program_request(&self.graph) {
            Ok(Some((peer, root, id, start, limit)))
                if self.request_ready(peer, now)
                    && self.automatic_request_ready(peer, now)
                    && !self.flights.values().any(
                        |flight| matches!(flight,Flight::Program{id:requested,..}if *requested==id),
                    ) =>
            {
                let frame = Frame::new(Body::ProgramGet {
                    root: *root.as_bytes(),
                    id: *id.as_bytes(),
                    start,
                    limit,
                });
                let request = self
                    .swarm
                    .request_granted(peer, frame, self.swarm.grant(peer, root));
                self.flights.insert(
                    request,
                    Flight::Program {
                        root,
                        id,
                        start,
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
                self.flights.insert(request, Flight::Describe { id, peer });
                self.charge_automatic_request(peer, now);
                self.charge_outgoing(peer, now);
            }
        }
        // The sole path to Get consumes a private approved root's actual
        // committed dependency closure. Hints and Graph.pending never issue Get.
        for (peer, root, id) in self.intake.needed() {
            if self.request_ready(peer, now) && self.automatic_request_ready(peer, now) && self.intake.authorizes(peer, root, id)
                && !self.flights.values().any(|flight| matches!(flight, Flight::Get { root:r, id:i, .. } if *r == root && *i == id))
            {
                let request = self.swarm.request_granted(peer, Frame::new(Body::Get { root: *root.as_bytes(), id: *id.as_bytes() }), self.swarm.grant(peer, root));
                self.flights.insert(request, Flight::Get { root, id, peer });
                self.charge_automatic_request(peer, now);
                self.charge_outgoing(peer, now);
            }
        }
        let enabled: Vec<_> = self.enabled.iter().copied().collect();
        for peer in &enabled {
            if self.request_ready(*peer, now)
                && self.automatic_request_ready(*peer, now)
                && crate::resources::limits().fetches - self.wanted.len()
                    >= crate::resources::limits().inventory_page
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
            let attempts = self.wanted[&id].attempts;
            let Some(peer) = description_supplier(
                &enabled,
                attempts,
                |peer| self.request_ready(peer, now),
                |peer| self.automatic_request_ready(peer, now),
            ) else {
                continue;
            };
            let wanted = self.wanted.get_mut(&id).expect("queued description");
            wanted.attempts += 1;
            wanted.retry = now + crate::resources::limits().reconcile_interval;
            let request = self
                .swarm
                .behaviour_mut()
                .exchange
                .send_request(&peer, Frame::new(Body::Describe { id: *id.as_bytes() }));
            self.flights.insert(request, Flight::Describe { id, peer });
            self.charge_automatic_request(peer, now);
            self.charge_outgoing(peer, now);
            remaining -= 1;
        }
    }

    fn inventory(&mut self, peer: PeerId, after: Option<[u8; 32]>, pages: usize) {
        let local = self.graph.content_root();
        let known = after.is_none().then(|| {
            self.inventory_summaries
                .get(&peer)
                .filter(|(_, observed_local)| *observed_local == local)
                .map_or(local, |(remote, _)| *remote)
        });
        let id = self.swarm.behaviour_mut().exchange.send_request(
            &peer,
            Frame::new(Body::Inventory {
                known,
                after,
                limit: crate::resources::limits().inventory_page,
            }),
        );
        self.flights.insert(
            id,
            Flight::Inventory {
                peer,
                known,
                after,
                pages,
            },
        );
        self.next_inventory.insert(
            peer,
            Instant::now() + crate::resources::limits().reconcile_interval,
        );
    }

    fn charge(&mut self, peer: PeerId) -> bool {
        let now = Instant::now();
        let bucket = self.buckets.entry(peer).or_insert(Bucket {
            tokens: crate::resources::limits().request_burst,
            reset: now,
        });
        if now.duration_since(bucket.reset) >= crate::resources::limits().request_rate_window {
            bucket.tokens = crate::resources::limits().request_burst;
            bucket.reset = now;
        }
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }

    fn event(
        &mut self,
        event: SwarmEvent<BehaviourEvent>,
        grant: Option<crate::graph::PeerGrant>,
    ) -> Result<(), String> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.ready = true;
                emit(
                    json!({"event":"ready","address":address.to_string(), "relayed":discovery::is_relayed(&address)}),
                );
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                if let Some(peer) = self
                    .relay_listeners
                    .iter()
                    .find_map(|(peer, id)| (*id == listener_id).then_some(*peer))
                {
                    self.relay_listeners.remove(&peer);
                    self.next_relay_attempt.insert(
                        peer,
                        Instant::now() + crate::resources::limits().reconcile_interval,
                    );
                    self.swarm.remove_listener(listener_id);
                    emit(
                        json!({"event":"relay_listen_failed", "peer":peer.to_string(), "error":error.to_string()}),
                    );
                } else {
                    return Err(format!("listener: {error}"));
                }
            }
            SwarmEvent::ListenerClosed { listener_id, .. } => {
                if let Some(peer) = self
                    .relay_listeners
                    .iter()
                    .find_map(|(peer, id)| (*id == listener_id).then_some(*peer))
                {
                    self.relay_listeners.remove(&peer);
                    self.next_relay_attempt.insert(
                        peer,
                        Instant::now() + crate::resources::limits().reconcile_interval,
                    );
                } else {
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
                if let Ok(contact) = self.discovery.book.lock().admit(peer_id, Instant::now()) {
                    contact.connected = true;
                    contact.connected_at.get_or_insert(Instant::now());
                }
                self.next_inventory.remove(&peer_id);
                emit(
                    json!({"event":"connected", "peer":peer_id.to_string(), "connection_id":connection_id.to_string(),
                    "connections":num_established.get(), "relayed":relayed, "endpoint":format!("{endpoint:?}")}),
                );
                if relayed && self.discovery.config.hole_punch {
                    emit(
                        json!({"event":"hole_punch_attempt", "peer":peer_id.to_string(), "relayed_connection_id":connection_id.to_string()}),
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
                emit(
                    json!({"event":"incoming_connection_failed", "connection_id":connection_id.to_string(),
                    "local":local_addr.to_string(), "remote":send_back_addr.to_string(),
                    "error":error.to_string(), "detail":format!("{error:?}")}),
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
                    json!({"event":"disconnected", "peer":peer_id.to_string(), "connection_id":connection_id.to_string(),
                    "connections":num_established, "cause":format!("{cause:?}")}),
                );
            }
            SwarmEvent::NewExternalAddrCandidate { address } => {
                // Identify observations are DCUtR candidates, not evidence of
                // public reachability and not automatically confirmed addresses.
                emit(json!({"event":"external_candidate", "address":address.to_string()}));
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
                emit(json!({"event":"relay_client", "detail":format!("{event:?}")}));
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => emit(
                json!({"event":"dial_failed","peer":peer_id.map(|peer|peer.to_string()),
                    "stage":"transport", "error":error.to_string(), "detail":format!("{error:?}")}),
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
                    let id = ProofId::from_bytes(
                        message.data[32..].try_into().expect("announcement width"),
                    );
                    if self.graph.contains(id)? || !self.charge(propagation_source) {
                        return Ok(());
                    }
                    emit(json!({"event":"announcement","id":hex(id.as_bytes())}));
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
                        json!({"event":"exchange_request", "peer":peer.to_string(), "connection_id":connection_id.to_string(),
                        "relayed":self.connections.get(&connection_id).map(|(_, relayed)|*relayed), "kind":body_kind(&request.message.body),
                        "object_id":body_id(&request.message.body),"root_id":body_root(&request.message.body),"position":body_position(&request.message.body)}),
                    );
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
                        json!({"event":"exchange_response", "peer":peer.to_string(), "connection_id":connection_id.to_string(),
                        "relayed":self.connections.get(&connection_id).map(|(_, relayed)|*relayed), "kind":body_kind(&response.message.body),
                        "object_id":body_id(&response.message.body),"root_id":body_root(&response.message.body),"position":body_position(&response.message.body)}),
                    );
                    if let Some(flight) = self.flights.remove(&request_id) {
                        if self.enabled.contains(&peer)
                            && response.message.compatibility == crate::compatibility()
                        {
                            self.response(peer, flight, response.message.body, grant)?;
                        } else if let Flight::Get { root, .. } = flight {
                            self.intake.abort(root);
                            emit(
                                json!({"event":"proof_skipped","id":hex(root.as_bytes()),"error":"payload response peer or compatibility revoked"}),
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
                if let Some(Flight::Program { id, peer, .. }) = self.flights.get(&request_id) {
                    self.intake.program_failed(*peer, *id);
                }
                if let Some(Flight::Get { root, .. }) = self.flights.remove(&request_id) {
                    self.intake.abort(root);
                    emit(
                        json!({"event":"proof_skipped", "id":hex(root.as_bytes()),"error":"required payload request failed"}),
                    );
                }
                emit(json!({"event":"request_failed","error":error.to_string()}));
            }
            SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                request_response::Event::InboundFailure { error, .. },
            )) => emit(json!({"event":"inbound_failed","error":error.to_string()})),
            _ => {}
        }
        Ok(())
    }

    fn request(
        &mut self,
        peer: PeerId,
        body: Body,
        grant: Option<crate::graph::PeerGrant>,
    ) -> Result<Body, String> {
        let _work = if matches!(&body, Body::Offer { .. } | Body::ProgramOffer { .. }) {
            match self.computation.try_enter() {
                Some(work) => Some(work),
                None => {
                    return Ok(Body::Error {
                        reason: "computation paused".into(),
                    });
                }
            }
        } else {
            None
        };
        let response = match body {
            Body::Inventory {
                known,
                after,
                limit,
            } => inventory_response(&self.graph, known, after, limit)?,
            Body::Describe { id } => match self.graph.description(ProofId::from_bytes(id)) {
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
                            .get(&ProofId::from_bytes(id))
                            .filter(|_| self.test_controls)
                            .map_or(metadata, |(metadata, _)| metadata.clone()),
                    }
                }
                Ok(None) => self
                    .test_controls
                    .then(|| self.test_objects.get(&ProofId::from_bytes(id)))
                    .flatten()
                    .map(|(metadata, _)| Body::Description {
                        metadata: metadata.clone(),
                    })
                    .unwrap_or(Body::Missing),
                Err(error) => Body::Error {
                    reason: error.to_string(),
                },
            },
            Body::ProgramGet {
                root,
                id,
                start,
                limit,
            } => {
                if crate::resources::adaptive::network(1) == 0
                    || crate::resources::adaptive::batch(1) == 0
                {
                    Body::Error {
                        reason: "program resources paused".into(),
                    }
                } else {
                    let maximum = (crate::resources::limits().proof_bytes / 2)
                        .clamp(256, naome_proof::program::CHUNK_BYTES);
                    match self
                        .graph
                        .program_chunk(ProofId::from_bytes(id), start, limit, maximum)
                    {
                        Ok(Some(chunk)) => Body::ProgramData { root, id, chunk },
                        Ok(None) => Body::Missing,
                        Err(error) => Body::Error {
                            reason: error.to_string(),
                        },
                    }
                }
            }
            Body::ProgramOffer { metadata } => {
                match self
                    .intake
                    .enqueue_program(peer, metadata, &self.graph, grant)
                {
                    Ok(status) => Body::Receipt {
                        status: status.into(),
                    },
                    Err(error) => Body::Error {
                        reason: error.to_string(),
                    },
                }
            }
            Body::Get { root, id } => match self.graph.transfer(ProofId::from_bytes(id))? {
                Some(crate::object::ProofTransfer::Program(metadata)) => Body::ProgramDescription {
                    root: Some(root),
                    metadata,
                },
                Some(crate::object::ProofTransfer::Certificate(object)) => {
                    Body::Object { root, object }
                }
                None => self
                    .test_controls
                    .then(|| {
                        self.test_objects
                            .get(&ProofId::from_bytes(id))
                            .and_then(|(_, object)| object.clone())
                    })
                    .flatten()
                    .map(|object| Body::Object { root, object })
                    .unwrap_or(Body::Missing),
            },
            Body::Offer { metadata } => {
                match self
                    .intake
                    .enqueue_with_grant(peer, metadata.clone(), &self.graph, grant)
                {
                    Ok(status) => Body::Receipt {
                        status: status.into(),
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
                }
            }
            _ => Body::Error {
                reason: "unexpected request kind".into(),
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
        grant: Option<crate::graph::PeerGrant>,
    ) -> Result<(), String> {
        // In-flight replies remain bounded by their original transport limits.
        // Dropped payloads can be requested again; no unchecked input is adopted.
        let Some(_work) = self.computation.try_enter() else {
            return Ok(());
        };
        let expected_peer = match &flight {
            Flight::Inventory { peer, .. }
            | Flight::Get { peer, .. }
            | Flight::Describe { peer, .. }
            | Flight::Program { peer, .. }
            | Flight::Offer { peer } => *peer,
        };
        if peer != expected_peer {
            emit(json!({"event":"rejected", "error":"response peer mismatch"}));
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
                if metadata.manifest.proof_id() != id {
                    emit(json!({"event":"rejected","error":"program description ID mismatch"}));
                } else {
                    match self
                        .intake
                        .enqueue_program(peer, metadata, &self.graph, grant)
                    {
                        Ok("duplicate") => {
                            self.wanted.remove(&id);
                        }
                        Ok(_) => {}
                        Err(error) => emit(json!({"event":"rejected","error":error.to_string()})),
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
                let result = if root != *expected_root.as_bytes()
                    || metadata.manifest.proof_id() != id
                {
                    Err(crate::Error::InvalidInput(
                        "cited program description scope mismatch".into(),
                    ))
                } else {
                    self.intake
                        .enqueue_program_helper(peer, expected_root, metadata, &self.graph)
                };
                if let Err(error) = result {
                    self.graph.program_failure(&error);
                    emit(json!({"event":"rejected","error":error.to_string()}));
                }
            }
            (
                Flight::Program {
                    root: expected_root,
                    id: expected_id,
                    start,
                    ..
                },
                Body::ProgramData { root, id, chunk },
            ) => {
                let result = if root != *expected_root.as_bytes()
                    || id != *expected_id.as_bytes()
                    || chunk.start != start
                {
                    Err(crate::Error::InvalidInput(
                        "program response scope mismatch".into(),
                    ))
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
                        json!({"event":"program_chunk_rejected","id":hex(expected_id.as_bytes()),"error":error.to_string()}),
                    );
                }
            }
            (Flight::Program { id, .. }, body) => {
                self.intake.program_failed(peer, id);
                let error = match body {
                    Body::Error { reason } => reason,
                    Body::Missing => "program input unavailable".into(),
                    _ => "unexpected program response".into(),
                };
                emit(
                    json!({"event":"program_transfer_deferred","id":hex(id.as_bytes()),"error":error}),
                );
            }
            (
                Flight::Inventory {
                    peer, known, after, ..
                },
                Body::InventoryUnchanged { root },
            ) => {
                if after.is_some() || known != Some(root) {
                    emit(json!({"event":"rejected","error":"unsolicited inventory summary"}));
                } else {
                    self.inventory_progress.remove(&peer);
                    self.inventory_summaries
                        .insert(peer, (root, self.graph.content_root()));
                    emit(
                        json!({"event":"inventory_unchanged","peer":peer.to_string(),"root":hex(&root)}),
                    );
                }
            }
            (
                Flight::Inventory {
                    peer, after, pages, ..
                },
                Body::InventoryResult { root, ids, next },
            ) => {
                if after.is_some()
                    && self.inventory_progress.get(&peer).and_then(|p| p.root) != Some(root)
                {
                    self.inventory_progress.remove(&peer);
                    self.inventory_summaries.remove(&peer);
                    return Ok(());
                }
                if ids.len() > crate::resources::limits().inventory_page
                    || next.is_some_and(|next| Some(&next) != ids.last())
                    || !ids.windows(2).all(|pair| pair[0] < pair[1])
                    || ids
                        .first()
                        .is_some_and(|id| after.is_some_and(|after| *id <= after))
                {
                    emit(json!({"event":"rejected","error":"invalid inventory"}));
                    return Ok(());
                }
                // Keep the cursor until every ID is retained or already known.
                // Queue pressure, throttling, failure and disconnect must not
                // restart a scan at its prefix or silently discard its tail.
                let mut retained = true;
                for id in &ids {
                    retained &= self.want(ProofId::from_bytes(*id))?;
                }
                if retained {
                    if next.is_some() {
                        self.inventory_progress.insert(
                            peer,
                            InventoryProgress {
                                root: Some(root),
                                after: next,
                                pages: pages.saturating_add(1),
                            },
                        );
                    } else {
                        self.inventory_progress.remove(&peer);
                        self.inventory_summaries
                            .insert(peer, (root, self.graph.content_root()));
                    }
                }
                emit(json!({"event":"inventory_page", "peer":peer.to_string(),
                    "after":after.map(|id|hex(&id)), "page":pages,
                    "count":ids.len(), "retained":retained,
                    "last":ids.last().map(|id|hex(id))}));
            }
            (Flight::Describe { id, .. }, Body::Description { metadata }) => {
                if metadata.proof_id != hex(id.as_bytes()) {
                    emit(json!({"event":"rejected","error":"description ID mismatch"}));
                    return Ok(());
                }
                match self
                    .intake
                    .enqueue_with_grant(peer, metadata.clone(), &self.graph, grant)
                {
                    Ok("duplicate") => {
                        self.wanted.remove(&id);
                    }
                    // Preserve attempts and the original bounded hint epoch
                    // through queued/declined assessment. Otherwise a wrong
                    // descriptor can monopolize retries for the same ProofId.
                    Ok(_) => {}
                    Err(error) => emit(json!({"event":"rejected","error":error})),
                }
            }
            (
                Flight::Get {
                    root: expected_root,
                    id,
                    ..
                },
                Body::Object { root, object },
            ) => {
                let result = if root != *expected_root.as_bytes() {
                    Err("response root mismatch".into())
                } else {
                    self.intake
                        .payload(peer, expected_root, id, object, &self.graph)
                };
                if let Err(error) = result {
                    self.intake.abort(expected_root);
                    emit(
                        json!({"event":"proof_skipped", "id":hex(expected_root.as_bytes()),"error":error}),
                    );
                }
            }
            (Flight::Offer { .. }, Body::Receipt { status }) => {
                emit(json!({"event":"offer_result","status":status}))
            }
            (Flight::Get { root, .. }, Body::Error { reason }) => {
                self.intake.abort(root);
                emit(json!({"event":"proof_skipped", "id":hex(root.as_bytes()),"error":reason}));
            }
            (Flight::Get { root, .. }, Body::Missing) => {
                self.intake.abort(root);
                emit(
                    json!({"event":"proof_skipped", "id":hex(root.as_bytes()),"error":"required dependency missing"}),
                );
            }
            (_, Body::Error { reason }) => emit(json!({"event":"peer_error","error":reason})),
            // Keep the bounded attempt counter so the next retry rotates to
            // another peer. A missing descriptor is no decline authority.
            (Flight::Describe { .. }, Body::Missing) => {}
            (Flight::Get { root, .. }, _) => {
                self.intake.abort(root);
                emit(
                    json!({"event":"proof_skipped","id":hex(root.as_bytes()),"error":"unexpected required payload response"}),
                );
            }
            _ => emit(json!({"event":"rejected","error":"unexpected response kind"})),
        }
        if let Some(error) = self.graph.storage_error() {
            return Err(error);
        }
        Ok(())
    }
}

pub fn read_config(path: &Path) -> Result<Config, String> {
    let mut config: Config = serde_json::from_slice(&crate::store::read_bounded(
        path,
        crate::resources::limits().network_config_bytes,
    )?)
    .map_err(|error| error.to_string())?;
    if config.directory.is_relative() {
        config.directory = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&config.directory);
    }
    Ok(config)
}

mod discovery_runtime;

#[cfg(test)]
mod tests;
