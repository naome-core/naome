//! Bounded question-first proof transport with static or discovered peers.
//! Gossip and inventory are hints; receiver approval precedes certificate fetch,
//! and only a completely checked root closure reaches the durable graph.

use crate::{
    Envelope, Graph, discovery, hex,
    object::{Metadata, id_bytes},
    wire::{Body, Codec, Frame, INVENTORY_PAGE, PROTOCOL},
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

pub const MAX_PEERS: usize = 16;
// JSON may encode one source byte as six bytes (for example, a control byte).
// Leave additional bounded space for peer metadata and formatting.
pub const MAX_CONFIG_BYTES: usize = 8 * crate::MAX_PROOF_BYTES;
pub const MAX_FETCHES: usize = 128;
pub const MAX_FLIGHTS: usize = 16;
pub const MAX_FLIGHTS_PER_PEER: usize = 2;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
const AUTOMATIC_REQUEST_INTERVAL: Duration = Duration::from_millis(200);
pub const MAX_COMMAND_BYTES: usize = 8 * crate::MAX_PROOF_BYTES;

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
        "question_exchange":{
            "protocol":"/naome/knowledge/2", "topic":"naome-knowledge-v2",
            "interest":"Explicit local positive selection before root fetch and before commit",
            "metadata":"Newly derived resolution obligation; no recovered original source or proof bytes",
            "limits":{"active_roots":1,"queued_metadata":crate::intake::MAX_QUEUED_METADATA,
                "closure_objects":crate::intake::MAX_CLOSURE_OBJECTS,"closure_bytes":crate::intake::MAX_CLOSURE_BYTES,
                "closure_steps":crate::intake::MAX_CLOSURE_STEPS,"checker_work_bytes":crate::intake::MAX_CLOSURE_CHECKER_WORK_BYTES,
                "root_lifetime_seconds":crate::intake::ROOT_TTL.as_secs(),"outgoing_request_burst_per_peer":7,"outgoing_request_refill_seconds":1}
        },
        "identify_protocol":discovery::protocol_version(false),
        "dht_protocol":format!("/naome/knowledge/kad/{}/1", hex(&crate::compatibility())),
        "participation_key":hex(discovery::provider_key().as_ref()),
        "defaults":DiscoveryConfig::default(),
        "limits":{
            "contacts":discovery::MAX_CONTACTS,"addresses_per_contact":discovery::MAX_ADDRESSES,
            "address_bytes":discovery::MAX_ADDRESS_BYTES,"bootstrap":discovery::MAX_BOOTSTRAP,
            "relays":discovery::MAX_RELAYS,"contact_ttl_seconds":discovery::CONTACT_TTL.as_secs(),
            "identify_timeout_seconds":discovery::IDENTIFY_TIMEOUT.as_secs(),
            "mdns_ttl_seconds":discovery::MDNS_TTL.as_secs(),
            "discovery_interval_seconds":discovery::DISCOVERY_INTERVAL.as_secs(),
            "provider_records":discovery::MAX_CONTACTS,"provider_ttl_seconds":discovery::PROVIDER_TTL.as_secs(),
            "application_queries":discovery::MAX_APPLICATION_QUERIES,
            "query_timeout_seconds":discovery::QUERY_TIMEOUT.as_secs(),
            "established_connections":32,"connections_per_peer":2,"connections_per_peer_with_upgrade":3
        },
        "query_limit_scope":"Count all current queries before starting application work; libp2p may add one automatic bootstrap query",
        "relay_service":{
            "reservations":crate::relay::MAX_RESERVATIONS,"reservations_per_peer":1,
            "circuits":crate::relay::MAX_CIRCUITS,"source_circuits":crate::relay::MAX_SOURCE_CIRCUITS,
            "circuit_bytes":crate::relay::MAX_CIRCUIT_BYTES,
            "duration_seconds":crate::relay::CIRCUIT_DURATION.as_secs()
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
    ready: bool,
    graph: Graph,
    swarm: Swarm<Behaviour>,
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
/// It never reads stdin or accepts manual developer operations.
#[cfg(unix)]
pub(crate) async fn run_autonomous(
    config: Config,
    intervals: crate::autonomous::Intervals,
) -> Result<(), String> {
    let (handle, admin, inbox) = crate::question::channel();
    drop(handle);
    drop(admin);
    let (sender, commands) = mpsc::channel(8);
    drop(sender);
    run_inner(
        config,
        false,
        inbox,
        Some(crate::mocks::assess_interest),
        commands,
        Some(intervals),
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
    let (sender, commands) = mpsc::channel(8);
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
    let (sender, commands) = mpsc::channel(8);
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
    let (sender, commands) = mpsc::channel(8);
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
    mut inbox: crate::question::QuestionInbox,
    interest: Option<F>,
    mut commands: mpsc::Receiver<Result<Value, String>>,
    autonomy: Option<crate::autonomous::Intervals>,
) -> Result<(), String>
where
    F: Fn(naome_authoring::CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<bool, String>> + Send + 'static,
{
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
    let directory = config.directory.clone();
    let key = identity::Keypair::from_protobuf_encoding(&crate::store::read_bounded(
        &config.directory.join("identity.key"),
        1024,
    )?)
    .map_err(|error| error.to_string())?;
    let own_id = key.public().to_peer_id();
    #[cfg(unix)]
    let control = if autonomy.is_some() {
        Some(crate::runtime::Control::bind(&config.directory)?)
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
    if settings.bootstrap.len() > discovery::MAX_BOOTSTRAP
        || settings.relays.len() > discovery::MAX_RELAYS
        || settings.external_addresses.len() > discovery::MAX_ADDRESSES
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
            .with_max_pending_incoming(Some(16))
            .with_max_pending_outgoing(Some(16))
            .with_max_established(Some(32))
            .with_max_established_per_peer(Some(
                if settings.hole_punch && !settings.relays.is_empty() {
                    3
                } else {
                    2
                },
            )),
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
    let topic = gossipsub::IdentTopic::new("naome-knowledge-v2");
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
                .with_idle_connection_timeout(Duration::from_secs(60))
                .with_max_negotiating_inbound_streams(16)
        })
        .with_connection_timeout(REQUEST_TIMEOUT)
        .build();
    swarm.listen_on(listen).map_err(|error| error.to_string())?;
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
    let enabled = BTreeSet::new();
    let mut node = Node {
        ready: false,
        graph,
        swarm,
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
        next_automatic_request: BTreeMap::new(),
        buckets: BTreeMap::new(),
        outgoing: BTreeMap::new(),
        intake: crate::intake::Intake::default(),
        test_objects: BTreeMap::new(),
        test_controls,
        producer_sources: config.producer_sources.into(),
        next_production: Instant::now() + Duration::from_secs(1),
    };
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut command_input_open = true;
    let mut question_input_open = true;
    let (mut research, mut autonomous, mut questions) = if let Some(intervals) = autonomy {
        use sha2::Digest;
        let cursor = sha2::Sha256::digest(own_id.to_bytes())[0] as u64;
        let (service, client, recovery) =
            crate::jobs::Service::open(&directory, intervals.jobs, cursor)?;
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
        (None, None, crate::question::LocalQuestions::new(interest))
    };
    let mut controls = libp2p::futures::stream::FuturesUnordered::new();
    let mut stop_watch = control.as_ref().map(crate::runtime::Control::stop_watch);
    let mut stopping = false;
    let mut next_profile_check = Instant::now();
    let mut drain_deadline = None;
    emit(
        json!({"event":"starting", "peer_id":own_id.to_string(), "compatibility":hex(&crate::compatibility())}),
    );
    // Keep signal receivers alive while another branch processes synchronous work.
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let outcome:Result<(),String>=async {
    loop {
        // Read the validated owner epoch before polling any final admission.
        // An error invalidates old selection; stop remains available.
        if let Some(control)=&control
            && (control.selection_changed() || Instant::now()>=next_profile_check) {
                next_profile_check=Instant::now()+Duration::from_secs(1);
                if questions.select(control.selection().ok()) {
                node.intake.invalidate_interest();
                }
            }
        tokio::select! {
            event = node.swarm.select_next_some() => node.event(event)?,
            command = commands.recv(), if command_input_open && !stopping => {
                match command {
                    Some(Ok(value)) => if !node.command(value) { break; },
                    Some(Err(error)) => emit(json!({"event":"command_error", "error":error})),
                    None => {
                        command_input_open = false;
                        emit(json!({"event":"command_input_closed"}));
                    },
                }
            },
            _ = tick.tick() => node.tick(),
            command = inbox.receive(), if question_input_open && !stopping => {
                match command {
                    Some(command) => if !questions.process(command, &node.graph) { break; },
                    None => question_input_open = false,
                }
            },
            interest = questions.completed(),if !stopping => {
                if let Some(control)=&control
                    && questions.select(control.selection().ok()){node.intake.invalidate_interest();}
                questions.finish(&node.graph, interest);
            },
            socket = crate::runtime::accept(&control),if !stopping && controls.len()<8 => {
                let socket = socket?;
                controls.push(control.as_ref().expect("accepted runtime control").respond(socket,node.graph.ids().len(),node.ready));
            },
            response=controls.next(),if !controls.is_empty()=>if let Some(response)=response {
                match response {
                    Ok(true) => break,
                    Ok(false) => {},
                    Err(error) => emit(json!({"event":"control_rejected","error":error})),
                }
            },
            _=crate::runtime::requested_stop(&mut stop_watch),if !stopping=>{
                stopping=true;
                drain_deadline=Some(Instant::now()+Duration::from_secs(2));
                if let Some(service)=&mut research{service.begin_shutdown()?;}
            },
            signal = &mut shutdown => { signal?; break; }
        }
        if let Some(error)=questions.storage_error(){return Err(error.to_owned());}
        if let Some(error)=research.as_ref().and_then(crate::jobs::Service::error){return Err(error);}
        if stopping {
            if controls.is_empty() || drain_deadline.is_some_and(|until|Instant::now()>=until){break;}
            continue;
        }
        if let Some(control)=&control
            && (control.selection_changed() || node.intake.selection_boundary_ready()
                || autonomous.as_ref().is_some_and(crate::autonomous::Autonomous::selection_boundary_ready))
                && questions.select(control.selection().ok()){node.intake.invalidate_interest();}
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
                let (admitted, rejected) = node.graph.resolve_pending();
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
        node.requests();
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
    }.await;
    // Every ordinary loop/error path drains the owner before releasing Graph's
    // exclusive directory lock. Pending controls own no independent tasks.
    let cleanup = match &mut research {
        Some(service) => service.shutdown().await,
        None => Ok(()),
    };
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
    config.set_max_num_streams(16);
    config
}

// The pinned request-response implementation automatically retains discovery
// hints. Its removal API is necessary to reconcile that cache with our caps.
#[allow(deprecated)]
fn remove_exchange_address(
    exchange: &mut request_response::Behaviour<Codec>,
    peer: &PeerId,
    address: &Multiaddr,
) {
    exchange.remove_address(peer, address);
}
#[allow(deprecated)]
fn add_exchange_address(
    exchange: &mut request_response::Behaviour<Codec>,
    peer: &PeerId,
    address: Multiaddr,
) {
    exchange.add_address(peer, address);
}

fn body_kind(body: &Body) -> &'static str {
    match body {
        Body::Inventory { .. } => "inventory",
        Body::InventoryResult { .. } => "inventory_result",
        Body::Get { .. } => "get",
        Body::Describe { .. } => "describe",
        Body::Description { .. } => "description",
        Body::Object { .. } => "object",
        Body::Offer { .. } => "offer",
        Body::Receipt { .. } => "receipt",
        Body::Missing => "missing",
        Body::Error { .. } => "error",
    }
}
fn body_id(body: &Body) -> Option<String> {
    match body {
        Body::Get { id, .. } | Body::Describe { id } => Some(hex(id)),
        Body::Object { object, .. } => Some(object.proof_id.clone()),
        Body::Offer { metadata } | Body::Description { metadata } => {
            Some(metadata.proof_id.clone())
        }
        _ => None,
    }
}

fn body_root(body: &Body) -> Option<String> {
    match body {
        Body::Get { root, .. } | Body::Object { root, .. } => Some(hex(root)),
        _ => None,
    }
}

fn read_commands(sender: mpsc::Sender<Result<Value, String>>) {
    use std::io::{BufRead, Read};
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        let mut bytes = Vec::new();
        let read = (&mut input)
            .take(MAX_COMMAND_BYTES as u64 + 1)
            .read_until(b'\n', &mut bytes);
        match read {
            Ok(0) => break,
            Ok(_) if bytes.len() > MAX_COMMAND_BYTES || bytes.last() != Some(&b'\n') => {
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

impl Node {
    fn flight_count(&self, target: PeerId) -> usize {
        self.flights
            .values()
            .filter(|flight| match flight {
                Flight::Inventory { peer, .. }
                | Flight::Get { peer, .. }
                | Flight::Describe { peer, .. }
                | Flight::Offer { peer } => *peer == target,
            })
            .count()
    }
    fn want(&mut self, id: ProofId) -> bool {
        if self.graph.contains(id) || self.intake.contains(id) || self.wanted.contains_key(&id) {
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
        let result: Result<Value, String> = (|| match value
            .get("command")
            .and_then(Value::as_str)
            .ok_or("command missing")?
        {
            "status" => Ok(
                json!({"ids":self.graph.ids().iter().map(|id|hex(id.as_bytes())).collect::<Vec<_>>(),
                    "root":hex(&self.graph.content_root()), "pending":self.graph.pending_ids().iter().map(|id|hex(id.as_bytes())).collect::<Vec<_>>(),
                    "connected":self.swarm.connected_peers().map(ToString::to_string).collect::<Vec<_>>(),
                    "compatibility":hex(&crate::compatibility()),
                    "contacts":self.contact_status(),
                    "provider_records":self.swarm.behaviour_mut().discovery.kad.as_mut().map(|kad|kad.store_mut().len()).unwrap_or(0),
                    "proof_peers":self.enabled.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "connections":self.connections.iter().map(|(id,(peer,relayed))|json!({"id":id.to_string(),"peer":peer.to_string(),"relayed":relayed})).collect::<Vec<_>>() }),
            ),
            "produce" => {
                let source = value
                    .get("source")
                    .and_then(Value::as_str)
                    .ok_or("source missing")?;
                let object = self.graph.author(source)?;
                let id = ProofId::from_bytes(id_bytes(&object.proof_id)?);
                let result = self.ingest(object.clone(), "producer")?;
                let metadata = self.graph.describe(id);
                Ok(json!({"result":result,"object":object,
                    "metadata":metadata.as_ref().ok().and_then(Option::as_ref),
                    "metadata_error":metadata.as_ref().err()}))
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
                if self.test_objects.len() >= 8 && !self.test_objects.contains_key(&id) {
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
                        if let Some(contact) = self.discovery.book.lock().contacts.get_mut(peer) {
                            contact.enabled = true;
                        }
                    } else {
                        self.intake.disconnected(*peer);
                        self.outgoing.remove(peer);
                        if let Some(allowed) = self.swarm.behaviour_mut().allowed.as_mut() {
                            allowed.disallow_peer(*peer);
                        }
                        if let Some(contact) = self.discovery.book.lock().contacts.get_mut(peer) {
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
                        if self.test_objects.len() >= 8 {
                            return Err("test object capacity".into());
                        }
                        let object: Envelope = serde_json::from_value(object.clone())
                            .map_err(|error| error.to_string())?;
                        if object.proof.len() > 2 * crate::MAX_PROOF_BYTES {
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
        })();
        match result {
            Ok(result) => emit(json!({"event":"response","request":request,"result":result})),
            Err(error) => emit(json!({"event":"response","request":request,"error":error})),
        }
        value.get("command").and_then(Value::as_str) != Some("stop")
    }

    fn tick(&mut self) {
        let now = Instant::now();
        self.discovery_tick(now);
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
    }

    fn outgoing_ready(&self, peer: PeerId, now: Instant) -> bool {
        self.outgoing.get(&peer).is_none_or(|bucket| {
            bucket.tokens > 0 || now.duration_since(bucket.reset) >= Duration::from_secs(1)
        })
    }

    fn charge_outgoing(&mut self, peer: PeerId, now: Instant) {
        let bucket = self.outgoing.entry(peer).or_insert(Bucket {
            tokens: 7,
            reset: now,
        });
        if now.duration_since(bucket.reset) >= Duration::from_secs(1) {
            bucket.tokens = 7;
            bucket.reset = now;
        }
        bucket.tokens -= 1;
    }

    fn request_ready(&self, peer: PeerId, now: Instant) -> bool {
        self.enabled.contains(&peer)
            && self.swarm.is_connected(&peer)
            && self.flights.len() < MAX_FLIGHTS
            && self.flight_count(peer) < MAX_FLIGHTS_PER_PEER
            && self.outgoing_ready(peer, now)
    }

    fn requests(&mut self) {
        let now = Instant::now();
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
                let request = self.swarm.behaviour_mut().exchange.send_request(&peer, Frame::new(Body::Get { root: *root.as_bytes(), id: *id.as_bytes() }));
                self.flights.insert(request, Flight::Get { root, id, peer });
                self.charge_automatic_request(peer, now);
                self.charge_outgoing(peer, now);
            }
        }
        let enabled: Vec<_> = self.enabled.iter().copied().collect();
        for peer in &enabled {
            if self.request_ready(*peer, now)
                && MAX_FETCHES - self.wanted.len() >= INVENTORY_PAGE
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
            let Some(peer) = enabled
                .iter()
                .cycle()
                .skip(attempts % enabled.len().max(1))
                .take(enabled.len())
                .find(|peer| self.request_ready(**peer, now))
                .copied()
            else {
                continue;
            };
            let wanted = self.wanted.get_mut(&id).expect("queued description");
            wanted.attempts += 1;
            wanted.retry = now + RECONCILE_INTERVAL;
            let request = self
                .swarm
                .behaviour_mut()
                .exchange
                .send_request(&peer, Frame::new(Body::Describe { id: *id.as_bytes() }));
            self.flights.insert(request, Flight::Describe { id, peer });
            self.charge_outgoing(peer, now);
            remaining -= 1;
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
                    self.next_relay_attempt
                        .insert(peer, Instant::now() + RECONCILE_INTERVAL);
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
                    self.next_relay_attempt
                        .insert(peer, Instant::now() + RECONCILE_INTERVAL);
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
            SwarmEvent::NewExternalAddrOfPeer { peer_id, address } => {
                let book = self.discovery.book.lock();
                // The library may retain the same hint with a /p2p suffix.
                // Keep only the exact normalized addresses owned by the book;
                // otherwise retirement could leave a second cache entry behind.
                let retained = book
                    .contacts
                    .get(&peer_id)
                    .is_some_and(|contact| contact.addresses.contains(&address));
                if !retained {
                    remove_exchange_address(
                        &mut self.swarm.behaviour_mut().exchange,
                        &peer_id,
                        &address,
                    );
                }
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
                    if self.graph.contains(id) || !self.charge(propagation_source) {
                        return Ok(());
                    }
                    emit(json!({"event":"announcement","id":hex(id.as_bytes())}));
                    self.want(id);
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
                        "object_id":body_id(&request.message.body),"root_id":body_root(&request.message.body)}),
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
                        self.request(peer, request.message.body)
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
                        "object_id":body_id(&response.message.body),"root_id":body_root(&response.message.body)}),
                    );
                    if let Some(flight) = self.flights.remove(&request_id) {
                        if self.enabled.contains(&peer)
                            && response.message.compatibility == crate::compatibility()
                        {
                            self.response(peer, flight, response.message.body);
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

    fn request(&mut self, peer: PeerId, body: Body) -> Body {
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
            Body::Describe { id } => match if self.test_controls {
                self.test_objects
                    .get(&ProofId::from_bytes(id))
                    .map(|(metadata, _)| Ok(Some(metadata.clone())))
                    .unwrap_or_else(|| self.graph.describe(ProofId::from_bytes(id)))
            } else {
                self.graph.describe(ProofId::from_bytes(id))
            } {
                Ok(Some(metadata)) => Body::Description { metadata },
                Ok(None) => Body::Missing,
                Err(reason) => Body::Error { reason },
            },
            Body::Get { root, id } => self
                .graph
                .object(ProofId::from_bytes(id))
                .or_else(|| {
                    self.test_controls
                        .then(|| {
                            self.test_objects
                                .get(&ProofId::from_bytes(id))
                                .and_then(|(_, object)| object.as_ref())
                        })
                        .flatten()
                })
                .map(|object| Body::Object {
                    root,
                    object: object.clone(),
                })
                .unwrap_or(Body::Missing),
            Body::Offer { metadata } => match self.intake.enqueue(peer, metadata, &self.graph) {
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
            },
            _ => Body::Error {
                reason: "unexpected request kind".into(),
            },
        }
    }

    fn response(&mut self, peer: PeerId, flight: Flight, body: Body) {
        let expected_peer = match &flight {
            Flight::Inventory { peer, .. }
            | Flight::Get { peer, .. }
            | Flight::Describe { peer, .. }
            | Flight::Offer { peer } => *peer,
        };
        if peer != expected_peer {
            emit(json!({"event":"rejected", "error":"response peer mismatch"}));
            return;
        }
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
            (Flight::Describe { id, .. }, Body::Description { metadata }) => {
                if metadata.proof_id != hex(id.as_bytes()) {
                    emit(json!({"event":"rejected","error":"description ID mismatch"}));
                    return;
                }
                match self.intake.enqueue(peer, metadata, &self.graph) {
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
    }
}

pub fn read_config(path: &Path) -> Result<Config, String> {
    let mut config: Config =
        serde_json::from_slice(&crate::store::read_bounded(path, MAX_CONFIG_BYTES)?)
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
