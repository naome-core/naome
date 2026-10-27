use super::*;
use crate::resources::adaptive::Budget;
use naome_proof::program::{CHUNK_BYTES, Command};

#[tokio::test]
async fn two_nodes_exchange_definitions_and_programs_then_recheck_and_reuse_them() {
    const CASE: &str = "network::tests::definitions::two_nodes_exchange_definitions_and_programs_then_recheck_and_reuse_them";
    if std::env::var("NAOME_DEFINITION_NETWORK_CASE").as_deref() != Ok(CASE) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_DEFINITION_NETWORK_CASE", CASE)
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
    let sender = ConfigFile::new();
    let receiver = ConfigFile::new();
    let mut graph = Graph::open(&sender.0).unwrap();
    let (relation, _) = graph
        .produce("def self_equal = relation(x): eq(x,x)")
        .unwrap();
    let digits: String =
        include_str!("../../../../naome-checker/src/tests/fixtures/identity_unique.proof.hex")
            .split_whitespace()
            .collect();
    let certificate =
        naome_proof::ProofCertificate::from_canonical_bytes(&crate::unhex(&digits).unwrap())
            .unwrap();
    let witness = crate::object::BinaryArtifact::from_checked(
        &naome_checker::normalize_and_check(certificate).unwrap(),
    )
    .unwrap()
    .envelope();
    graph.ingest(witness, Instant::now()).unwrap();
    let (function, _) = graph
        .produce("def identity = function(input,output): eq(output,input)")
        .unwrap();
    let mut work =
        crate::proof_work::Work::open(&sender.0.join("definition-program.sqlite3")).unwrap();
    work.append_group(&[
        Command::DefinedRelation {
            definition_id: *relation.definition_id().unwrap().unwrap().as_bytes(),
            arguments: vec![0],
        },
        Command::DefinedRelation {
            definition_id: *function.definition_id().unwrap().unwrap().as_bytes(),
            arguments: vec![0, 0],
        },
        Command::Implies {
            antecedent: 0,
            consequent: 1,
        },
        Command::Separation {
            predicate: 2,
            element: 0,
            source: 1,
            result: 2,
        },
        Command::Seal { proof: 3 },
    ])
    .unwrap();
    let budget = Budget {
        memory_bytes: 256 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: crate::resources::limits().checked_cache_bytes as u64,
        batch_steps: 128,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    while work.advance(&budget, graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget).unwrap() {}
    let checked = work.into_checked().unwrap();
    let proof = checked.proof().unwrap();
    let manifest = proof.manifest().clone();
    let store = graph.ownership();
    store.start_program(&manifest).unwrap();
    let chunk = proof.input_chunk(0, 128, CHUNK_BYTES).unwrap();
    store.append_program(&manifest, &chunk).unwrap();
    let mut registration = graph.begin_program_admission(&checked).unwrap();
    while !registration.advance(&graph, &checked, 128).unwrap() {}
    let batch = registration.finish(&graph, &checked).unwrap();
    graph
        .commit_batch(
            manifest.artifact_id(),
            batch,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let expected_root = graph.content_root();
    crate::resources::adaptive::publish(crate::resources::adaptive::Snapshot {
        selection: Default::default(),
        observed: Default::default(),
        budget,
        timestamp_ms: 0,
        pid: std::process::id(),
    });
    drop((store, checked, graph));
    drop(
        Graph::open(&sender.0)
            .expect("source must reverify definitions and streamed references before networking"),
    );

    let identity = |path: &std::path::Path| {
        let key = libp2p::identity::Keypair::generate_ed25519();
        std::fs::write(
            path.join("identity.key"),
            key.to_protobuf_encoding().unwrap(),
        )
        .unwrap();
        key.public().to_peer_id()
    };
    let sender_id = identity(&sender.0);
    let receiver_id = identity(&receiver.0);
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let sender_port = first.local_addr().unwrap().port();
    let receiver_port = second.local_addr().unwrap().port();
    drop((first, second));
    let config = |directory, port, peer: PeerId, remote_port| Config {
        formal_goal: None,
        directory,
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
    let (sender_handle, sender_admin, inbox) = crate::question::channel();
    let sender_task = tokio::spawn(run_with_questions(
        config(sender.0.clone(), sender_port, receiver_id, receiver_port),
        false,
        inbox,
        crate::mocks::select_question,
    ));
    let (receiver_handle, receiver_admin, inbox) = crate::question::channel();
    let receiver_task = tokio::spawn(run_with_questions(
        config(receiver.0.clone(), receiver_port, sender_id, sender_port),
        false,
        inbox,
        crate::mocks::select_question,
    ));
    let received = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            assert!(!sender_task.is_finished(), "sender stopped during startup");
            if receiver_handle.context().await.unwrap().checked_artifacts == 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    sender_admin.stop().await.unwrap();
    receiver_admin.stop().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), sender_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), receiver_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop((sender_handle, receiver_handle));
    assert!(
        received.is_ok(),
        "definition closure must traverse real peer transport"
    );
    let mut replayed = Graph::open(&receiver.0).unwrap();
    assert_eq!(replayed.content_root(), expected_root);
    for definition in [relation, function] {
        let id = definition.definition_id().unwrap().unwrap();
        let alias = if definition.obligation_proof.is_some() {
            "eq(d(x),x)"
        } else {
            "d(x)"
        };
        let source = format!(
            "defs: d=\"{}\" goal=all(x,imp({alias},imp({alias},{alias}))) proof: p0=simp({alias},{alias}) p1=gen(p0,x) return p1",
            crate::hex(id.as_bytes())
        );
        assert_eq!(replayed.produce(&source).unwrap().1.status, "accepted");
    }
}
