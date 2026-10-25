use super::*;
use crate::resources::adaptive::{self, Budget, Observed, Selection, Snapshot};
use naome_proof::program::{CHUNK_BYTES, Command};

fn program(graph: &mut Graph) -> naome_proof::program::Manifest {
    let mut work =
        crate::proof_work::Work::open(&graph.ownership().directory().join("fixture.sqlite3"))
            .unwrap();
    let budget = Budget {
        memory_bytes: 512 * 1024 * 1024,
        cache_bytes: 4 * 1024 * 1024,
        concurrency: 1,
        batch_steps: 64,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    work.append_group(&[
        Command::Reflexivity { variable: 0 },
        Command::Generalization {
            premise: 0,
            variable: 0,
        },
        Command::Seal { proof: 1 },
    ])
    .unwrap();
    while work.advance(&budget, graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget).unwrap() {}
    let checked = work.into_checked().unwrap();
    let proof = checked.proof().unwrap();
    let manifest = proof.manifest().clone();
    let store = graph.ownership();
    store.start_program(&manifest).unwrap();
    store
        .append_program(&manifest, &proof.input_chunk(0, 64, CHUNK_BYTES).unwrap())
        .unwrap();
    let mut admission = graph.begin_program_admission(&checked).unwrap();
    while !admission.advance(graph, &checked, 64).unwrap() {}
    let batch = admission.finish(graph, &checked).unwrap();
    graph
        .commit_batch(
            manifest.proof_id(),
            batch,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
    manifest
}

fn answer_background(client: &mut Swarm<Behaviour>, event: SwarmEvent<BehaviourEvent>) {
    if let SwarmEvent::Behaviour(BehaviourEvent::Exchange(request_response::Event::Message {
        message: request_response::Message::Request { channel, .. },
        ..
    })) = event
    {
        client
            .behaviour_mut()
            .exchange
            .send_response(channel, Frame::new(Body::Missing))
            .unwrap();
    }
}

async fn connected(client: &mut Swarm<Behaviour>, server: PeerId, address: Multiaddr) {
    let topic = gossipsub::IdentTopic::new("naome-knowledge-v6");
    client.behaviour_mut().gossip.subscribe(&topic).unwrap();
    client
        .dial(
            libp2p::swarm::dial_opts::DialOpts::peer_id(server)
                .addresses(vec![address.clone()])
                .build(),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = client.select_next_some().await;
            if matches!(&event, SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Subscribed { peer_id, topic: subscribed })) if *peer_id == server && *subscribed == topic.hash()) {
                break;
            }
            if matches!(&event, SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), .. } if *peer == server) {
                tokio::time::sleep(Duration::from_millis(20)).await;
                client.dial(libp2p::swarm::dial_opts::DialOpts::peer_id(server)
                    .addresses(vec![address.clone()]).build()).unwrap();
            }
            answer_background(client, event);
        }
    }).await.expect("the server must peer and subscribe even during a computation pause");
}

async fn request(client: &mut Swarm<Behaviour>, server: PeerId, body: Body) -> Body {
    let body = serde_json::to_value(body).unwrap();
    let mut id = client.behaviour_mut().exchange.send_request(
        &server,
        Frame::new(serde_json::from_value(body.clone()).unwrap()),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = client.select_next_some().await;
            if let SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = event
            {
                if request_id == id {
                    if let Body::Error { reason } = &response.message.body {
                        let delay = match reason.as_str() {
                            "peer disabled" | "node state owner busy" => {
                                Some(crate::resources::limits().transport_busy_grace)
                            }
                            "peer rate limit" => {
                                Some(crate::resources::limits().request_rate_window)
                            }
                            _ => None,
                        };
                        if let Some(delay) = delay {
                            tokio::time::sleep(delay).await;
                            id = client.behaviour_mut().exchange.send_request(
                                &server,
                                Frame::new(serde_json::from_value(body.clone()).unwrap()),
                            );
                            continue;
                        }
                    }
                    return response.message.body;
                }
            } else {
                answer_background(client, event);
            }
        }
    })
    .await
    .expect("paused computation must not block checked-data service")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_cpu_pause_preserves_new_peering_gossip_and_checked_program_delivery() {
    const CASE: &str = "network::tests::automatic_pause::automatic_cpu_pause_preserves_new_peering_gossip_and_checked_program_delivery";
    if std::env::var_os("NAOME_AUTOMATIC_PAUSE_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_AUTOMATIC_PAUSE_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = ConfigFile::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let manifest = program(&mut graph);
    let root = graph.content_root();
    let candidate = graph
        .author("goal=all(x,eq(x,x)) proof:p0=refl(x) p1=gen(p0,x) return p1")
        .unwrap();
    drop(graph);
    let key = identity::Keypair::generate_ed25519();
    let server = key.public().to_peer_id();
    std::fs::write(
        directory.0.join("identity.key"),
        key.to_protobuf_encoding().unwrap(),
    )
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", port.local_addr().unwrap().port())
        .parse()
        .unwrap();
    drop(port);
    let mut first = isolated_transport();
    let mut late = isolated_transport();
    let config = Config {
        directory: directory.0.clone(),
        listen: address.to_string(),
        peers: [*first.local_peer_id(), *late.local_peer_id()]
            .into_iter()
            .enumerate()
            .map(|(index, id)| Peer {
                id: id.to_string(),
                address: format!("/ip4/127.0.0.1/tcp/{}", index + 1),
            })
            .collect(),
        discovery: Some(DiscoveryConfig {
            mdns: false,
            dht: false,
            internet: false,
            ..Default::default()
        }),
        producer_sources: Vec::new(),
    };
    let (_handle, _admin, inbox) = crate::question::channel();
    let (commands, input) = mpsc::channel(4);
    let running = tokio::spawn(run_inner(
        config,
        false,
        inbox,
        Some(|_: CompiledQuestion| std::future::ready(Ok(true))),
        input,
        None,
    ));
    // Let the actual owner finish replay and open its listener before publishing
    // the synthetic observation. No production control or injection hook exists.
    tokio::time::sleep(Duration::from_millis(100)).await;
    connected(&mut first, server, address.clone()).await;
    let mut paused = Snapshot::derive(
        Selection::default(),
        Observed {
            memory_total: 8 << 30,
            memory_limit: 8 << 30,
            memory_available: 6 << 30,
            process_rss: 16 << 20,
            cpu_millis: 8000,
            disk_available: 1 << 30,
            ..Default::default()
        },
        crate::resources::limits().memory_bytes as u64,
    )
    .unwrap();
    paused.budget.paused = Some("sustained external CPU pressure".into());
    paused.budget.concurrency = 0;
    paused.budget.batch_steps = 0;
    paused.budget.network_requests = 1;
    adaptive::publish(paused.clone());
    let gate = Arc::new(crate::resources::Computation::default());
    assert!(gate.try_enter().is_none());
    assert_eq!(gate.state(), crate::resources::ComputationState::Paused);
    connected(&mut late, server, address).await;

    let description = request(
        &mut late,
        server,
        Body::Describe {
            id: *manifest.proof_id().as_bytes(),
        },
    )
    .await;
    let Body::ProgramDescription {
        root: None,
        metadata,
    } = description
    else {
        panic!("checked program metadata must remain available: {description:?}");
    };
    assert_eq!(metadata.manifest, manifest);
    let mut verifier =
        naome_checker::program::Engine::open(rusqlite::Connection::open_in_memory().unwrap())
            .unwrap();
    let mut position = 0;
    while position < manifest.commands {
        let Body::ProgramData { root, id, chunk } = request(
            &mut late,
            server,
            Body::ProgramGet {
                root: *manifest.proof_id().as_bytes(),
                id: *manifest.proof_id().as_bytes(),
                start: position,
                limit: 1,
            },
        )
        .await
        else {
            panic!("the paused node must serve every requested chunk");
        };
        assert_eq!(root, *manifest.proof_id().as_bytes());
        assert_eq!(id, root);
        assert_eq!(chunk.records.len(), 1);
        verifier.append_group(&chunk.records).unwrap();
        position += chunk.records.len() as u64;
    }
    let context = naome_checker::ArtifactState::new();
    while verifier.advance(64, 4096, &context).unwrap() {}
    while !verifier.prepare_export(64).unwrap() {}
    assert_eq!(verifier.checked().unwrap().manifest(), &manifest);
    for offer in [
        Body::ProgramOffer { metadata },
        Body::Offer {
            metadata: Metadata {
                proof_id: candidate.proof_id,
                statement_id: candidate.statement_id,
                question: "goal=all(x,eq(x,x))".into(),
            },
        },
    ] {
        assert!(matches!(request(&mut late, server, offer).await,
            Body::Error { reason } if reason == "computation paused"));
    }

    let topic = gossipsub::IdentTopic::new("naome-knowledge-v6");
    let mut announcement = crate::compatibility().to_vec();
    announcement.extend_from_slice(&[99; 32]);
    // Keep both clients polled while gossip builds its ordinary heartbeat mesh.
    let settle = tokio::time::sleep(crate::resources::limits().gossip_heartbeat * 2);
    tokio::pin!(settle);
    loop {
        tokio::select! {
            _ = &mut settle => break,
            event = first.select_next_some() => answer_background(&mut first,event),
            event = late.select_next_some() => answer_background(&mut late,event),
        }
    }
    first
        .behaviour_mut()
        .gossip
        .publish(topic, announcement.clone())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = first.select_next_some() => answer_background(&mut first,event),
        event = late.select_next_some() => {
            if let SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Message { propagation_source, message, .. })) = &event
                && *propagation_source == server && message.data == announcement { break; }
            answer_background(&mut late,event);
        },
    } } }).await.expect("the paused node must continue forwarding signed gossip");
    assert_eq!(adaptive::current().unwrap().budget, paused.budget);
    assert!(gate.try_enter().is_none());
    commands
        .send(Ok(QueuedCommand::from_value(json!({"command":"stop"}))))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let resumed = Snapshot::derive(
        Selection::default(),
        paused.observed,
        crate::resources::limits().memory_bytes as u64,
    )
    .unwrap();
    adaptive::publish(resumed);
    assert!(gate.try_enter().is_some());
    let graph = Graph::open(&directory.0).unwrap();
    assert_eq!(graph.content_root(), root);
    assert_eq!(
        graph.accepted_count(),
        1,
        "declined offers cannot enter the graph"
    );
}
