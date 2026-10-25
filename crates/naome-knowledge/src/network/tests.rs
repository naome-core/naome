use super::*;
use naome_authoring::CompiledQuestion;
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
fn description_rotation_waits_for_the_next_suppliers_pacing_window() {
    let [bad, good, _] = suppliers();
    let peers = [bad, good];
    let now = Instant::now();
    let available_at = now + crate::resources::limits().automatic_request_interval;
    let select_at = |time| {
        description_supplier(
            &peers,
            1,
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
    for (attempt, expected) in [first, second, first, second].into_iter().enumerate() {
        // At every retry deadline the next supplier has just sent inventory.
        // Its short cooldown must defer the request, not select its neighbour.
        assert_eq!(
            description_supplier(&peers, attempt, |_| true, |peer| peer != expected),
            None
        );
        assert_eq!(
            description_supplier(&peers, attempt, |_| true, |_| true),
            Some(expected)
        );
    }
}

#[test]
fn description_rotation_skips_unavailable_transports_and_respects_pacing() {
    let [first, unavailable, third] = suppliers();
    let peers = [first, unavailable, third];
    assert_eq!(
        description_supplier(&peers, 1, |peer| peer != unavailable, |_| true),
        Some(third)
    );
    assert_eq!(
        description_supplier(&peers, 1, |peer| peer != unavailable, |peer| peer != third),
        None
    );
    assert_eq!(description_supplier(&peers, 1, |_| false, |_| true), None);
    assert_eq!(description_supplier(&[], 1, |_| true, |_| true), None);
}

#[test]
fn full_producer_queue_loads_with_worst_case_json_escaping() {
    let file = ConfigFile::new();
    let sources = vec!["\u{0001}".repeat(crate::resources::limits().proof_bytes / 32); 32];
    let encoded = serde_json::to_vec_pretty(&json!({
        "directory": "node",
        "listen": "/ip4/127.0.0.1/tcp/0",
        "peers": [],
        "producer_sources": sources
    }))
    .unwrap();
    assert!(encoded.len() > 6 * crate::resources::limits().proof_bytes);
    assert!(encoded.len() < crate::resources::limits().network_config_bytes);
    std::fs::write(file.path(), &encoded).unwrap();
    let loaded = read_config(&file.path()).unwrap();
    assert_eq!(loaded.producer_sources, sources);
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
    assert_eq!(read_config(&file.path()).err().unwrap(), "file byte limit");
}

#[tokio::test]
async fn cli_peer_disable_cancels_final_interest_before_parent_commit() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize},
    };
    use tokio::sync::Notify;
    struct FinalInterest {
        dropped: Arc<AtomicBool>,
        notify: Arc<Notify>,
        peer: PeerId,
    }
    impl Drop for FinalInterest {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
            println!("test_final_interest_dropped peer={}", self.peer);
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
        producer_sources: Vec::new(),
    };
    let mut sender_graph = Graph::open(&sender_dir).unwrap();
    let object = sender_graph
        .author(
            &crate::mocks::create_proof(
                &CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let root = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
    sender_graph.ingest(object, Instant::now()).unwrap();
    let target = *sender_graph
        .describe(root)
        .unwrap()
        .unwrap()
        .compile()
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
        Some(move |question: naome_authoring::CompiledQuestion| {
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
                let _owned = FinalInterest {
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
    assert_eq!(receiver_handle.context().await.unwrap().checked_proofs, 0);
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
    assert_eq!(context.checked_proofs, 0);
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
        .query_row("SELECT count(*) FROM proofs", [], |row| row.get(0))
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
    let object = crate::object::BinaryProof::from_checked(&checked)
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
        proof_id: object.proof_id.clone(),
        statement_id: object.statement_id.clone(),
        question: "goal = all(x,eq(x,x))".into(),
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
    assert_eq!(status["report"]["status"]["accepted_proofs"], 0);
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
    tokio::time::timeout(Duration::from_secs(2),async{
        loop{
            if let SwarmEvent::Behaviour(BehaviourEvent::Exchange(request_response::Event::Message{message:request_response::Message::Response{request_id,response},..}))=client.select_next_some().await{
                assert_eq!(request_id,id);
                assert!(matches!(response.message.body,Body::Error{reason} if reason=="node state owner busy"));break;
            }
        }
    }).await.unwrap();
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
                        shared.behaviour_mut().exchange.send_response(channel, Frame::new(Body::Receipt { status: "queued".into() })).unwrap();
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
    let changed = tokio::time::timeout(
        Duration::from_secs(2),
        request(&endpoint, json!({"interest":"revoked during slow commit"})),
    )
    .await
    .unwrap();
    let interest_seconds = measure.elapsed().as_secs_f64();
    assert_eq!(changed["report"]["kind"], "status");
    assert_eq!(
        changed["report"]["status"]["interest"],
        "revoked during slow commit"
    );
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
        json!({"status_seconds":status_seconds,"network_seconds":network_seconds,"interest_seconds":interest_seconds,"stop_seconds":stop_seconds,"stalled_write_seconds":stalled_seconds,"published_proofs":count,"proof_bytes":proof_bytes})
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

#[test]
fn inventory_summary_stops_unchanged_rounds_and_changed_corpora_resume_pages() {
    let mut graph = Graph::default();
    let empty = graph.content_root();
    assert!(
        matches!(inventory_response(&graph, Some(empty), None, 1).unwrap(), Body::InventoryUnchanged { root } if root == empty)
    );
    let (_, result) = graph
        .produce("goal=all(x,eq(x,x)) proof: a=refl(x) b=gen(a,x) return b")
        .unwrap();
    let root = graph.content_root();
    assert_ne!(root, empty);
    assert!(
        matches!(inventory_response(&graph, Some(empty), None, 1).unwrap(), Body::InventoryResult { root: observed, ids, .. } if observed == root && ids == [*result.id.as_bytes()])
    );
    for _ in 0..8 {
        assert!(matches!(
            inventory_response(&graph, Some(root), None, 1).unwrap(),
            Body::InventoryUnchanged { .. }
        ));
    }
    assert!(
        matches!(inventory_response(&graph, Some(root), Some(*result.id.as_bytes()), 1).unwrap(), Body::InventoryResult { ids, next: None, .. } if ids.is_empty())
    );
}
