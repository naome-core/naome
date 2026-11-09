use super::*;
#[cfg(feature = "system-tests")]
mod automatic_pause;
mod defined_exchange;
#[cfg(feature = "system-tests")]
mod definitions;
#[cfg(unix)]
mod typed_proof;
mod workgroups;
use libp2p::{futures::StreamExt, tcp};
use naome_checker::question::ResearchQuestion;
use std::sync::atomic::{AtomicU64, Ordering};

struct ConfigFile(PathBuf);

impl ConfigFile {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-knowledge-config-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> PathBuf {
        self.0.join("config.json")
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn suppliers() -> [PeerId; 3] {
    [
        "12D3KooWKbDekbeDkPxZCzqd8wFXxCYocro6mba7FBqJ89fDMujR",
        "12D3KooWNaGsF3B8EzRMdDjsrVd5mAdyM7exb2eRtawS6Ztxu8eQ",
        "12D3KooWN85tWa9uREnea7nhmAXr8a1Do4MipuBHWw5X9tdYno7E",
    ]
    .map(|peer| peer.parse().unwrap())
}

#[test]
fn overdue_inventory_retains_a_request_window() {
    let now = Instant::now();
    let interval = crate::resources::limits().reconcile_interval;
    assert!(inventory_preempts_description(None, now));
    assert!(!inventory_preempts_description(Some(now + interval), now));
    assert!(!inventory_preempts_description(Some(now), now));
    assert!(inventory_preempts_description(Some(now - interval), now));
}

#[test]
fn description_rotation_waits_for_the_next_suppliers_pacing_window() {
    let [bad, good, _] = suppliers();
    let peers = [bad, good];
    let now = Instant::now();
    let available_at = now + crate::resources::limits().automatic_request_interval;
    let select_at = |time| {
        description_supplier(
            &peers,
            Some(bad),
            |_| true,
            |peer| peer != good || time >= available_at,
        )
    };
    // The bad description was declined. An inventory request has just used
    // Good's window; repeating Bad must not consume Good's next turn.
    assert_eq!(select_at(now), None);
    assert_eq!(select_at(available_at), Some(good));
}

#[test]
fn description_rotation_keeps_alternating_when_inventory_and_retry_clocks_align() {
    let [first, second, _] = suppliers();
    let peers = [first, second];
    let mut last = None;
    for expected in [first, second, first, second] {
        // At every retry deadline the next supplier has just sent inventory.
        // Its short cooldown must defer the request, not select its neighbour.
        assert_eq!(
            description_supplier(&peers, last, |_| true, |peer| peer != expected),
            None
        );
        assert_eq!(
            description_supplier(&peers, last, |_| true, |_| true),
            Some(expected)
        );
        last = Some(expected);
    }
}

#[test]
fn description_rotation_skips_unavailable_transports_and_respects_pacing() {
    let [first, unavailable, third] = suppliers();
    let peers = [first, unavailable, third];
    assert_eq!(
        description_supplier(&peers, Some(first), |peer| peer != unavailable, |_| true),
        Some(third)
    );
    assert_eq!(
        description_supplier(
            &peers,
            Some(first),
            |peer| peer != unavailable,
            |peer| peer != third
        ),
        None
    );
    assert_eq!(
        description_supplier(&peers, Some(first), |_| false, |_| true),
        None
    );
    assert_eq!(
        description_supplier(&[], Some(first), |_| true, |_| true),
        None
    );
}

#[test]
fn description_rotation_advances_after_the_supplier_actually_used() {
    let [first, second, _] = suppliers();
    let peers = [first, second];
    // First is unavailable at the initial attempt, so the second peer is used.
    assert_eq!(
        description_supplier(&peers, None, |peer| peer != first, |_| true),
        Some(second)
    );
    // When First becomes available, the next turn must not repeat Second.
    assert_eq!(
        description_supplier(&peers, Some(second), |_| true, |_| true),
        Some(first)
    );
}

#[test]
fn full_producer_queue_loads_with_worst_case_json_escaping() {
    let file = ConfigFile::new();
    let sources = vec!["\u{0001}".repeat(crate::resources::limits().proof_bytes / 32); 32];
    let encoded = serde_json::to_vec_pretty(&json!({
        "directory": "node",
        "listen": "/ip4/127.0.0.1/tcp/0",
        "peers": [],
        "producer_artifacts": sources
    }))
    .unwrap();
    assert!(encoded.len() > 6 * crate::resources::limits().proof_bytes);
    assert!(encoded.len() < crate::resources::limits().network_config_bytes);
    std::fs::write(file.path(), &encoded).unwrap();
    let loaded = read_config(&file.path()).unwrap();
    assert_eq!(loaded.producer_artifacts, sources);
    assert_eq!(loaded.directory, file.0.join("node"));
}

#[test]
fn oversized_configuration_still_rejects_before_decoding() {
    let file = ConfigFile::new();
    std::fs::write(
        file.path(),
        vec![b' '; crate::resources::limits().network_config_bytes + 1],
    )
    .unwrap();
    assert!(matches!(
        read_config(&file.path()),
        Err(crate::Error::InputLimit(
            crate::InputLimit::BoundedFileBytes
        ))
    ));
}

#[test]
fn node_config_rejects_each_bound_with_a_distinct_code() {
    let mut config = Config {
        directory: PathBuf::new(),
        listen: String::new(),
        peers: vec![],
        discovery: None,
        producer_artifacts: vec![],
        formal_goal: None,
    };
    assert!(validate_config(&config, false).is_ok());
    config.formal_goal = Some(crate::mocks::create_question(0));
    assert!(matches!(
        validate_config(&config, false),
        Err(crate::Error::InputFault(
            crate::InputFault::FormalGoalRequiresNative
        ))
    ));
    assert!(validate_config(&config, true).is_ok());
    config.formal_goal = None;
    config.peers = vec![
        Peer {
            id: String::new(),
            address: String::new()
        };
        crate::resources::limits().configured_peers + 1
    ];
    assert!(matches!(
        validate_config(&config, false),
        Err(crate::Error::InputLimit(crate::InputLimit::ConfiguredPeers))
    ));
    config.peers.clear();
    config.producer_artifacts =
        vec![String::new(); crate::resources::limits().producer_artifacts + 1];
    assert!(matches!(
        validate_config(&config, false),
        Err(crate::Error::InputLimit(crate::InputLimit::ProducerQueue))
    ));
    config.producer_artifacts = vec!["a".repeat(2 * crate::resources::limits().producer_bytes + 1)];
    assert!(matches!(
        validate_config(&config, false),
        Err(crate::Error::InputLimit(crate::InputLimit::ProducerQueue))
    ));
}

#[test]
fn formal_goal_keeps_the_question_checker_failure() {
    let graph = Graph::default();
    let valid = crate::mocks::create_question(0);
    assert_eq!(checked_formal_goal(&valid, &graph).unwrap().to_hex(), valid);
    let expected = crate::Error::from(
        naome_checker::question::ResearchQuestion::from_hex_with_context(
            "04",
            graph.checked_context(),
        )
        .unwrap_err(),
    );
    let actual = checked_formal_goal("04", &graph).unwrap_err();
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn configuration_failures_preserve_read_and_parse_codes() {
    let file = ConfigFile::new();
    std::fs::write(file.path(), b"{").unwrap();
    let error = read_config(&file.path()).err().unwrap();
    let json = serde_json::to_value(&error).unwrap();
    assert_eq!(
        json["code"],
        u32::from(crate::RuntimeFailure::NetworkConfigParse)
    );
    assert_eq!(json["cause"]["reason"], u32::from(crate::JsonFault::Eof));
    assert_eq!(json["cause"]["line"], 1);
    assert!(
        matches!(error, crate::Error::RuntimeContext { code: crate::RuntimeFailure::NetworkConfigParse, cause } if matches!(*cause, crate::Error::ConfigDecode { reason: crate::JsonFault::Eof, .. }))
    );
    assert!(matches!(
        read_config(&file.0),
        Err(crate::Error::InputFault(
            crate::InputFault::RegularFileRequired
        ))
    ));
    std::fs::remove_file(file.path()).unwrap();
    assert!(matches!(
        read_config(&file.path()),
        Err(crate::Error::RuntimeContext { code: crate::RuntimeFailure::BoundedFileOpen, cause }) if matches!(*cause, crate::Error::StorageIo { operation: crate::StorageIoOperation::OpenInput, kind: crate::IoFaultKind::NotFound, .. })
    ));
}

#[tokio::test]
async fn cli_peer_disable_cancels_final_selection_before_parent_commit() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize},
    };
    use tokio::sync::Notify;
    struct FinalSelection {
        dropped: Arc<AtomicBool>,
        notify: Arc<Notify>,
        peer: PeerId,
    }
    impl Drop for FinalSelection {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
            println!("test_final_selection_dropped peer={}", self.peer);
            self.notify.notify_one();
        }
    }
    let directory = ConfigFile::new();
    let sender_dir = directory.0.join("sender");
    let receiver_dir = directory.0.join("receiver");
    let make_identity = |path: &Path| {
        std::fs::create_dir_all(path).unwrap();
        let key = identity::Keypair::generate_ed25519();
        std::fs::write(
            path.join("identity.key"),
            key.to_protobuf_encoding().unwrap(),
        )
        .unwrap();
        key.public().to_peer_id()
    };
    let sender_peer = make_identity(&sender_dir);
    let receiver_peer = make_identity(&receiver_dir);
    let available_port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let sender_port = available_port();
    let receiver_port = available_port();
    let config = |path: PathBuf, port, peer: PeerId, remote_port| Config {
        directory: path,
        listen: format!("/ip4/127.0.0.1/tcp/{port}"),
        peers: vec![Peer {
            id: peer.to_string(),
            address: format!("/ip4/127.0.0.1/tcp/{remote_port}"),
        }],
        discovery: Some(DiscoveryConfig {
            mdns: false,
            dht: false,
            ..Default::default()
        }),
        producer_artifacts: Vec::new(),
        formal_goal: None,
    };
    let mut sender_graph = Graph::open(&sender_dir).unwrap();
    let object = sender_graph
        .author(
            &crate::mocks::create_proof(
                &ResearchQuestion::from_hex(&crate::mocks::create_question(0)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let root = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    sender_graph.ingest(object, Instant::now()).unwrap();
    let target = *sender_graph
        .describe(root)
        .unwrap()
        .unwrap()
        .compile(sender_graph.checked_context())
        .unwrap()
        .2
        .resolution_id();
    drop(sender_graph);
    let (sender_handle, sender_admin, sender_inbox) = crate::question::channel();
    let sender = tokio::spawn(run_with_questions(
        config(sender_dir, sender_port, receiver_peer, receiver_port),
        false,
        sender_inbox,
        |_| std::future::ready(Ok(true)),
    ));
    let (receiver_handle, receiver_admin, receiver_inbox) = crate::question::channel();
    let (commands, input) = mpsc::channel(8);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let final_started = Arc::new(Notify::new());
    let started = final_started.clone();
    let released = Arc::new(Notify::new());
    let release = released.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let observed_drop = dropped.clone();
    let drop_notify = Arc::new(Notify::new());
    let notify = drop_notify.clone();
    let receiver = tokio::spawn(run_inner(
        config(
            receiver_dir.clone(),
            receiver_port,
            sender_peer,
            sender_port,
        ),
        false,
        receiver_inbox,
        Some(move |question: naome_checker::question::ResearchQuestion| {
            let selected = *question.resolution_id() == target;
            let first = selected && observed.fetch_add(1, Ordering::SeqCst) == 0;
            let started = started.clone();
            let release = release.clone();
            let dropped = observed_drop.clone();
            let notify = notify.clone();
            async move {
                if !selected {
                    return Ok(false);
                }
                if first {
                    return Ok(true);
                }
                let _owned = FinalSelection {
                    dropped,
                    notify,
                    peer: sender_peer,
                };
                started.notify_one();
                release.notified().await;
                Ok(true)
            }
        }),
        input,
        None,
    ));
    tokio::time::timeout(Duration::from_secs(15), final_started.notified())
        .await
        .unwrap();
    assert_eq!(
        receiver_handle.context().await.unwrap().checked_artifacts,
        0
    );
    commands
        .send(Ok(QueuedCommand::from_value(
            json!({"command":"links","peers":[],"request":"disable-during-final"}),
        )))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), drop_notify.notified())
        .await
        .unwrap();
    assert!(dropped.load(Ordering::SeqCst));
    released.notify_waiters();
    let context = receiver_handle.context().await.unwrap();
    assert_eq!(context.checked_artifacts, 0);
    assert_eq!(context.registered_questions, 0);
    receiver_admin.stop().await.unwrap();
    sender_admin.stop().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), sender)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(sender_handle);
    assert!(Graph::open(&receiver_dir).unwrap().ids().is_empty());
    let catalog =
        rusqlite::Connection::open(receiver_dir.join(crate::store::DATABASE_FILE)).unwrap();
    let count: i64 = catalog
        .query_row("SELECT count(*) FROM artifacts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

fn isolated_transport() -> Swarm<Behaviour> {
    let key = identity::Keypair::generate_ed25519();
    let settings = DiscoveryConfig {
        mdns: false,
        dht: false,
        ..Default::default()
    };
    let book = discovery::SharedBook::new(discovery::Book::new(
        key.public().to_peer_id(),
        true,
        &settings,
    ));
    let discovery = discovery::Behaviour::new(&key, &settings, false, false).unwrap();
    let gossip = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub::ConfigBuilder::default().build().unwrap(),
    )
    .unwrap();
    let exchange = exchange::Exchange::new(
        request_response::Behaviour::with_codec(
            Codec::default(),
            [(PROTOCOL, request_response::ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
        book.clone(),
    );
    SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux_config)
        .unwrap()
        .with_relay_client(noise::Config::new, yamux_config)
        .unwrap()
        .with_behaviour(|_, relay| Behaviour {
            gate: discovery::Gate(book),
            allowed: None.into(),
            discovery,
            relay,
            limits: connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default(),
            ),
            gossip,
            exchange,
        })
        .unwrap()
        .build()
}

#[tokio::test]
async fn changing_from_proof_peer_to_public_router_revokes_existing_publication_grants() {
    let mut swarm = isolated_transport();
    let listener = swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let (shared, _events, mut transport) = worker::Transport::spawn(swarm, listener);
    let remote = identity::Keypair::generate_ed25519();
    let peer = remote.public().to_peer_id();
    let grant = shared.grant(peer, ArtifactId::from_bytes([31; 32]));
    let other = shared.grant(PeerId::random(), ArtifactId::from_bytes([32; 32]));
    let mut info = libp2p::identify::Info {
        public_key: remote.public(),
        protocol_version: discovery::protocol_version(false),
        signed_peer_record: None,
        agent_version: "fixture".into(),
        listen_addrs: vec!["/ip4/8.8.8.1/tcp/4001".parse().unwrap()],
        protocols: vec![
            PROTOCOL,
            libp2p::swarm::StreamProtocol::new("/ipfs/kad/1.0.0"),
        ],
        observed_addr: "/ip4/9.9.9.1/tcp/4001".parse().unwrap(),
    };
    shared.revoke_on_identify(peer, &info);
    assert!(grant.check().is_ok());
    info.protocol_version = "public-router".into();
    shared.revoke_on_identify(peer, &info);
    assert_eq!(grant.check().unwrap_err(), crate::Error::StaleAuthority);
    assert!(other.check().is_ok());
    transport.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_connection_flood_backpressures_and_recovers_without_halting() {
    let mut swarm = isolated_transport();
    let listener = swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let (_shared, mut events, mut transport) = worker::Transport::spawn(swarm, listener);
    let ready = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap();
    let SwarmEvent::NewListenAddr { address, .. } = ready.event else {
        panic!("listener readiness required")
    };
    let libp2p::multiaddr::Protocol::Tcp(port) = address.iter().nth(1).unwrap() else {
        panic!("TCP listener required")
    };
    // Deliberately leave the state owner stopped while remote sockets produce
    // more real events than the complete bounded handoff can hold.
    tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..crate::resources::limits().transport_events * 2 {
            drop(
                tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap(),
            );
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // The former overflow path closed the channel at its capacity. Receiving
    // beyond that capacity proves that polling recovers after backpressure.
    tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..crate::resources::limits().transport_events + 8 {
            events
                .recv()
                .await
                .expect("remote pressure must not terminate transport");
        }
    })
    .await
    .unwrap();
    transport.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_checked_write_keeps_real_transport_and_control_responsive_and_revokes_commit() {
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixStream,
    };
    let directory = ConfigFile::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let owner_lifetime = Arc::downgrade(&graph.ownership());
    fn pattern(leaves: usize) -> naome_foundation::Formula {
        let x = naome_foundation::FreeVariable::new(0);
        if leaves == 1 {
            return naome_foundation::Formula::equal(x, x);
        }
        naome_foundation::Formula::implies(pattern(leaves / 2), pattern(leaves - leaves / 2))
    }
    let x = naome_foundation::FreeVariable::new(0);
    let y = naome_foundation::FreeVariable::new(1);
    let checked = naome_checker::normalize_and_check(
        naome_proof::ProofCertificate::new(vec![
            naome_proof::ProofStep::EqualitySubstitution {
                from: x,
                to: y,
                body: pattern(5000).into(),
            },
            naome_proof::ProofStep::Generalization {
                premise: 0,
                variable: y,
            },
            naome_proof::ProofStep::Generalization {
                premise: 1,
                variable: x,
            },
        ])
        .unwrap(),
    )
    .unwrap();
    let proof_bytes = checked.normal_form().canonical_bytes().len();
    assert!(
        proof_bytes > crate::resources::limits().proof_bytes * 3 / 4
            && proof_bytes <= crate::resources::limits().proof_bytes
    );
    let object = crate::object::BinaryArtifact::from_checked(&checked)
        .unwrap()
        .envelope();
    let control =
        Arc::new(crate::runtime::Control::bind_test(&directory.0, graph.ownership()).unwrap());
    let mut server = isolated_transport();
    let server_peer = *server.local_peer_id();
    let primary_listener = server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let (shared, mut events, mut transport) = worker::Transport::spawn(server, primary_listener);
    let address = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = events.recv().await.unwrap().event {
                break address;
            }
        }
    })
    .await
    .unwrap();
    let mut client = isolated_transport();
    client
        .dial(
            libp2p::swarm::dial_opts::DialOpts::peer_id(server_peer)
                .addresses(vec![address])
                .build(),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let SwarmEvent::ConnectionEstablished { peer_id, .. } =
                client.select_next_some().await
            {
                assert_eq!(peer_id, server_peer);
                break;
            }
        }
    })
    .await
    .unwrap();
    let status = Arc::new(worker::PublishedStatus::default());
    status.ready.store(true, Ordering::Release);
    let mut controls = worker::Controls::spawn(Some(control.clone()), status);
    let (started, observed) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    graph.set_commit_guard(crate::publication::CommitGuard::new(
        Arc::new(AtomicU64::new(0)),
        0,
        Some(control.clone()),
        Some(control.selection().unwrap()),
    ));
    let offered = Metadata {
        artifact_id: object.artifact_id.clone(),
        proof_id: hex(object.proof_id().unwrap().unwrap().as_bytes()),
        statement_id: object.statement_id.clone().unwrap(),
        question: "040001000000000100000000".into(),
    };
    let busy = shared.busy.clone();
    let owner = std::thread::spawn(move || {
        Graph::delay_next_write(started, wait);
        libp2p::futures::executor::block_on(worker::while_polled(busy, async move {
            let result = graph.ingest(object, Instant::now());
            (result, graph.accepted_count(), graph.storage_error())
        }))
    });
    tokio::task::spawn_blocking(move || observed.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
    let stalled = Instant::now();
    let endpoint: Value =
        serde_json::from_slice(&std::fs::read(directory.0.join("control.json")).unwrap()).unwrap();
    async fn request(endpoint: &Value, operation: Value) -> Value {
        let mut stream = UnixStream::connect(endpoint["socket"].as_str().unwrap())
            .await
            .unwrap();
        let mut bytes = serde_json::to_vec(
            &json!({"version":1,"token":endpoint["token"],"operation":operation}),
        )
        .unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).await.unwrap();
        let mut response = Vec::new();
        BufReader::new(stream)
            .read_until(b'\n', &mut response)
            .await
            .unwrap();
        serde_json::from_slice(&response).unwrap()
    }
    let measure = Instant::now();
    let status = tokio::time::timeout(Duration::from_secs(2), request(&endpoint, json!("status")))
        .await
        .unwrap();
    let status_seconds = measure.elapsed().as_secs_f64();
    assert_eq!(status["report"]["kind"], "status");
    assert_eq!(status["report"]["status"]["accepted_artifacts"], 0);
    tokio::time::sleep(crate::resources::limits().transport_busy_grace * 2).await;
    let measure = Instant::now();
    let id = client.behaviour_mut().exchange.send_request(
        &server_peer,
        Frame::new(Body::Inventory {
            known: None,
            after: None,
            limit: 1,
        }),
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = client.select_next_some().await
            {
                assert_eq!(request_id, id);
                assert!(matches!(
                    response.message.body,
                    Body::Error {
                        code: PeerFailure::OwnerBusy
                    }
                ));
                break;
            }
        }
    })
    .await
    .unwrap();
    let network_seconds = measure.elapsed().as_secs_f64();
    // Metadata is retained in the bounded handoff while expensive checking is
    // stalled. A state-dependent inventory probe above still gets a prompt error.
    let offer_id = client.behaviour_mut().exchange.send_request(
        &server_peer,
        Frame::new(Body::Offer {
            metadata: offered.clone(),
        }),
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                _ = client.select_next_some() => {},
                event = events.recv() => {
                    if let SwarmEvent::Behaviour(BehaviourEvent::Exchange(request_response::Event::Message {
                        message: request_response::Message::Request { request, channel, .. }, ..
                    })) = event.unwrap().event {
                        assert!(matches!(request.message.body, Body::Offer { metadata } if metadata == offered));
                        shared.behaviour_mut().exchange.send_response(channel, Frame::new(Body::Receipt { status: OfferStatus::Queued })).unwrap();
                        break;
                    }
                }
            }
        }
    }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = client.select_next_some().await
            {
                assert_eq!(request_id, offer_id);
                assert!(matches!(response.message.body, Body::Receipt { .. }));
                break;
            }
        }
    })
    .await
    .unwrap();

    let measure = Instant::now();
    let _ = tokio::time::timeout(Duration::from_secs(2), request(&endpoint, json!("stop")))
        .await
        .unwrap();
    let stop_seconds = measure.elapsed().as_secs_f64();
    assert!(control.stopping());
    assert!(
        !owner.is_finished(),
        "real checked write remains stalled throughout every probe"
    );
    let stalled_seconds = stalled.elapsed().as_secs_f64();
    release.send(()).unwrap();
    let (result, count, fault) = tokio::task::spawn_blocking(move || owner.join().unwrap())
        .await
        .unwrap();
    assert_eq!(result.unwrap_err(), crate::publication::STALE_COMMIT);
    assert_eq!(count, 0);
    assert_eq!(fault, None);
    controls.shutdown().await.unwrap();
    transport.shutdown().await.unwrap();
    drop(control);
    assert!(
        owner_lifetime.upgrade().is_none(),
        "joined shutdown retained an in-process directory owner"
    );
    assert_eq!(Graph::open(&directory.0).unwrap().accepted_count(), 0);
    println!(
        "OWNER_LATENCY_METRICS {}",
        json!({"status_seconds":status_seconds,"network_seconds":network_seconds,"stop_seconds":stop_seconds,"stalled_write_seconds":stalled_seconds,"published_proofs":count,"proof_bytes":proof_bytes})
    );
}

#[tokio::test]
async fn transport_queue_failure_permanently_revokes_publication() {
    let mut swarm = isolated_transport();
    let primary_listener = swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let (shared, events, mut transport) = worker::Transport::spawn(swarm, primary_listener);
    let guard = crate::publication::CommitGuard::new(shared.epoch.clone(), 0, None, None);
    drop(events);
    tokio::time::timeout(Duration::from_secs(2), async {
        while shared.epoch.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), transport.shutdown())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(guard.check().unwrap_err(), crate::publication::STALE_COMMIT);
    let terminal = shared.epoch.load(Ordering::Acquire);
    assert_eq!(terminal, u64::MAX);
    let later_guard =
        crate::publication::CommitGuard::new(shared.epoch.clone(), terminal, None, None);
    assert_eq!(
        later_guard.check().unwrap_err(),
        crate::publication::STALE_COMMIT
    );
}

#[cfg(unix)]
#[test]
fn shutdown_receivers_capture_signals_before_the_future_is_polled() {
    const PROBE: &str = "NAOME_SHUTDOWN_REGISTRATION_PROBE";
    if let Ok(signal) = std::env::var(PROBE) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let shutdown = shutdown_signal().unwrap();
            let signal = match signal.as_str() {
                "terminate" => nix::sys::signal::Signal::SIGTERM,
                "interrupt" => nix::sys::signal::Signal::SIGINT,
                _ => panic!("unknown signal probe"),
            };
            nix::sys::signal::kill(nix::unistd::getpid(), signal).unwrap();
            tokio::time::timeout(Duration::from_secs(5), shutdown)
                .await
                .expect("registered shutdown signal")
                .unwrap();
        });
        return;
    }
    for signal in ["terminate", "interrupt"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "network::tests::shutdown_receivers_capture_signals_before_the_future_is_polled",
                "--nocapture",
            ])
            .env(PROBE, signal)
            .output()
            .unwrap();
        assert!(output.status.success(), "{signal}: {output:?}");
    }
}

#[tokio::test]
async fn oversized_learning_context_advances_the_durable_cursor() {
    const CASE: &str = "network::tests::oversized_learning_context_advances_the_durable_cursor";
    if std::env::var("NAOME_PEER_LEARNING_CAPACITY_CASE").as_deref() != Ok(CASE) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_PEER_LEARNING_CAPACITY_CASE", CASE)
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    crate::resources::configure(crate::resources::ResourceProfile {
        memory_bytes: 2 * 1024 * 1024 * 1024,
        ..Default::default()
    })
    .unwrap();

    use naome_foundation::Formula;
    use naome_proof::{DefinedFormula, DefinitionCertificate, ProofFormula, ProofStep};
    let directory = ConfigFile::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let x = crate::test_inputs::variable(0);
    let mut body = Formula::member(x, x);
    let mut relations = Vec::new();
    for _ in 0..=crate::learning::definitions::CAPACITY {
        let certificate =
            DefinitionCertificate::relation(1, DefinedFormula::from_primitive(&body).unwrap())
                .unwrap();
        graph
            .produce(&crate::test_inputs::definition(&certificate))
            .unwrap();
        relations.push(DefinedFormula::defined_relation(
            certificate.definition_id(),
            [x],
        ));
        body = Formula::negate(body);
    }
    let antecedent = relations
        .into_iter()
        .reduce(DefinedFormula::conjunction)
        .unwrap();
    let source = crate::test_inputs::proof(vec![ProofStep::Simplification {
        antecedent: ProofFormula::from_defined(DefinedFormula::for_all(x, antecedent)).unwrap(),
        consequent: crate::test_inputs::member_self().into(),
    }]);
    let peer = PeerId::random();
    graph.set_commit_guard(
        crate::publication::CommitGuard::new(Arc::default(), 0, None, None)
            .with_peer(crate::publication::PeerGrant::new().with_origin(peer)),
    );
    let oversized = graph.produce(&source).unwrap().1.id;
    assert_eq!(
        graph.direct_dependencies(oversized).unwrap().len(),
        crate::learning::definitions::CAPACITY + 1
    );
    assert!(graph.learning_certificate(oversized).unwrap().is_none());

    let settings = crate::jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let skipped_ordinal = graph.accepted_count() as u64;
    assert_eq!(
        graph.peer_learning_page(skipped_ordinal - 1).unwrap(),
        vec![(skipped_ordinal, oversized, Some(peer))],
    );
    let binding = crate::jobs::Binding::new([0; 32], [0; 32]);
    let (mut service, client, recovery) =
        crate::jobs::Service::open(&directory.0, settings, 0, Arc::default()).unwrap();
    let mut learning = PeerLearning {
        client,
        cursor: recovery.peer_cursor,
    };
    for _ in 0..skipped_ordinal {
        if learning.cursor == skipped_ordinal {
            break;
        }
        learning.advance(&graph, binding.clone()).unwrap();
        // The response follows any queued observations on the journal owner.
        learning
            .client
            .recover(0, recovery.archive_end)
            .unwrap()
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(learning.cursor, skipped_ordinal);
    service.shutdown().await.unwrap();
    drop(graph);

    let mut graph = Graph::open(&directory.0).unwrap();
    assert!(graph.contains(oversized).unwrap());
    let later = graph
        .produce(&crate::learning::tests::own_solution().source)
        .unwrap()
        .1
        .id;
    assert!(graph.learning_certificate(later).unwrap().is_some());
    let (mut service, client, recovery) =
        crate::jobs::Service::open(&directory.0, settings, 0, Arc::default()).unwrap();
    assert_eq!(recovery.peer_cursor, skipped_ordinal);
    let mut learning = PeerLearning {
        client,
        cursor: recovery.peer_cursor,
    };
    learning.advance(&graph, binding).unwrap();
    learning
        .client
        .recover(0, recovery.archive_end)
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(learning.cursor, skipped_ordinal + 1);
    service.shutdown().await.unwrap();

    let (mut service, _, recovery) =
        crate::jobs::Service::open(&directory.0, settings, 0, Arc::default()).unwrap();
    assert_eq!(recovery.peer_cursor, skipped_ordinal + 1);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn control_remains_responsive_with_incomplete_clients() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let directory = ConfigFile::new();
    let graph = Graph::open(&directory.0).unwrap();
    let control =
        Arc::new(crate::runtime::Control::bind_test(&directory.0, graph.ownership()).unwrap());
    let endpoint: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.0.join("control.json")).unwrap()).unwrap();
    let socket = endpoint["socket"].as_str().unwrap();
    let status = Arc::new(worker::PublishedStatus::default());
    status.ready.store(true, Ordering::Release);
    let mut controls = worker::Controls::spawn(Some(control), status);
    let mut slow = Vec::new();
    for _ in 0..crate::resources::active_limits().control_clients {
        let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
        stream.write_all(b"{").await.unwrap();
        slow.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let request = format!(
        "{{\"version\":1,\"token\":\"{}\",\"operation\":\"status\"}}\n",
        "01".repeat(32)
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        Duration::from_millis(700),
        BufReader::new(stream).read_line(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    let result: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(result["report"]["status"]["running"], true);
    drop(slow);
    controls.shutdown().await.unwrap();
}

#[test]
fn transport_events_keep_endpoint_close_and_relay_client_context_structured() {
    use crate::outcome::{
        ConnectionClose, ConnectionEndpoint, ConnectionPort, IoFaultKind, NodeEvent,
        RelayClientEvent,
    };
    use libp2p::core::{ConnectedPoint, Endpoint, transport::PortUse};
    let address = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
    let dialer = connection_endpoint(&ConnectedPoint::Dialer {
        address,
        role_override: Endpoint::Listener,
        port_use: PortUse::Reuse,
    });
    assert_eq!(dialer["kind"], u32::from(ConnectionEndpoint::Dialer));
    assert_eq!(dialer["role"], u32::from(ConnectionEndpoint::Listener));
    assert_eq!(dialer["port"], u32::from(ConnectionPort::Reused));
    let listener = connection_endpoint(&ConnectedPoint::Listener {
        local_addr: "/ip4/127.0.0.1/tcp/12".parse().unwrap(),
        send_back_addr: "/ip4/127.0.0.1/tcp/13".parse().unwrap(),
    });
    assert_eq!(listener["kind"], u32::from(ConnectionEndpoint::Listener));
    assert_eq!(listener["remote"], "/ip4/127.0.0.1/tcp/13");
    assert!(connection_close(None).is_none());
    let cause = libp2p::swarm::ConnectionError::IO(std::io::Error::from(
        std::io::ErrorKind::ConnectionReset,
    ));
    let value = connection_close(Some(&cause)).unwrap();
    assert_eq!(value["kind"], u32::from(ConnectionClose::Io));
    assert_eq!(value["io_kind"], u32::from(IoFaultKind::ConnectionReset));
    assert_eq!(
        connection_close(Some(&libp2p::swarm::ConnectionError::KeepAliveTimeout)).unwrap()["kind"],
        u32::from(ConnectionClose::KeepAliveTimeout)
    );
    let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
    for (event, code) in [
        (
            relay::client::Event::ReservationReqAccepted {
                relay_peer_id: peer,
                renewal: true,
                limit: None,
            },
            RelayClientEvent::ReservationAccepted,
        ),
        (
            relay::client::Event::OutboundCircuitEstablished {
                relay_peer_id: peer,
                limit: None,
            },
            RelayClientEvent::OutboundCircuit,
        ),
        (
            relay::client::Event::InboundCircuitEstablished {
                src_peer_id: peer,
                limit: None,
            },
            RelayClientEvent::InboundCircuit,
        ),
    ] {
        let event = relay_client_event(event);
        assert_eq!(event["event"], u32::from(NodeEvent::RelayClient));
        assert_eq!(event["kind"], u32::from(code));
        assert_eq!(event["peer"], peer.to_string());
        assert!(event["limit"].is_null());
        assert!(event.get("detail").is_none());
    }
}

#[test]
fn checked_replay_preserves_failure_and_retry_classification() {
    let cause = crate::Error::from(crate::InputFault::CatalogSchemaMismatch);
    let error = checked_replay_error(cause.clone());
    assert!(error.fatal());
    assert!(
        matches!(error, crate::Error::RuntimeContext { code: crate::RuntimeFailure::CheckedStorageReplay, cause: actual } if *actual == cause)
    );
    assert_eq!(
        checked_replay_error(crate::Error::ExecutionLimit),
        crate::Error::ExecutionLimit
    );
}
