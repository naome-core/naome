use super::*;
use crate::{network, object::ProofTransfer};
use std::{path::PathBuf, sync::atomic::AtomicU64};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-composed-program-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn large(graph: &Graph, implication: bool) -> CheckedWork {
    let mut work =
        crate::proof_work::Work::open(&graph.ownership().directory().join(if implication {
            "fixture-implication.sqlite3"
        } else {
            "fixture-premise.sqlite3"
        }))
        .unwrap();
    let mut commands = vec![
        Command::Equal { left: 0, right: 0 },
        Command::Separation {
            predicate: 0,
            element: 0,
            source: 1,
            result: 2,
        },
    ];
    let mut root = 1;
    for _ in 0..520 {
        let next = commands.len() as u64;
        commands.push(Command::Generalization {
            premise: root,
            variable: 3,
        });
        root = next;
    }
    if implication {
        let axiom = commands.len() as u64;
        commands.push(Command::Simplification {
            antecedent: 1,
            consequent: root,
        });
        root = commands.len() as u64;
        commands.push(Command::ModusPonens {
            premise: 1,
            implication: axiom,
        });
    }
    commands.push(Command::Seal { proof: root });
    work.append_group(&commands).unwrap();
    while work.advance(&budget(), graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget()).unwrap() {}
    let checked = work.into_checked().unwrap();
    assert!(checked.proof().unwrap().conclusion().is_none());
    checked
}

fn populated(path: &std::path::Path) -> (Graph, [Manifest; 3], ProgramMetadata) {
    let mut graph = Graph::open(path).unwrap();
    let premise = large(&graph, false);
    let first = premise.proof().unwrap().manifest().clone();
    publish(&mut graph, &premise);
    drop(premise);
    let implication = large(&graph, true);
    let second = implication.proof().unwrap().manifest().clone();
    publish(&mut graph, &implication);
    drop(implication);
    let mut work =
        crate::proof_work::Work::open(&path.join("fixture-composition.sqlite3")).unwrap();
    work.append_group(&[
        Command::ProofReference {
            proof_id: *first.proof_id().as_bytes(),
        },
        Command::ProofReference {
            proof_id: *second.proof_id().as_bytes(),
        },
        Command::ModusPonens {
            premise: 0,
            implication: 1,
        },
        Command::Seal { proof: 2 },
    ])
    .unwrap();
    while work.advance(&budget(), graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget()).unwrap() {}
    let checked = work.into_checked().unwrap();
    let third = checked.proof().unwrap().manifest().clone();
    assert_eq!(third.commands, 4);
    assert!(checked.proof().unwrap().conclusion().is_some());
    publish(&mut graph, &checked);
    drop(checked);
    let crate::object::ProofDescription::Program(metadata) =
        graph.description(third.proof_id()).unwrap().unwrap()
    else {
        panic!("program root description");
    };
    assert!(metadata.question.is_some());
    (graph, [first, second, third], metadata)
}

#[tokio::test]
async fn program_root_fetches_large_lemmas_and_publishes_the_whole_checked_closure_atomically() {
    const CASE: &str = "intake::program::tests::composition::program_root_fetches_large_lemmas_and_publishes_the_whole_checked_closure_atomically";
    if isolated(CASE) {
        return;
    }
    let sender = Directory::new();
    let receiver = Directory::new();
    let (source, manifests, metadata) = populated(&sender.0);
    let root = manifests[2].proof_id();
    let mut graph = Graph::open(&receiver.0).unwrap();
    let mut questions = LocalQuestions::new(Some(accepting as fn(_) -> _));
    let peer = PeerId::random();
    let mut intake = Intake::default();
    assert_eq!(
        intake
            .enqueue_program(peer, metadata.clone(), &graph, None)
            .unwrap(),
        "queued"
    );
    let mut fetched = BTreeSet::new();
    let mut accepted = None;
    for _ in 0..5000 {
        match intake.advance(&mut graph, &mut questions) {
            Progress::Accepted(ids) => {
                accepted = Some(ids);
                break;
            }
            Progress::Skipped(_, error) => panic!("composition rejected: {error}"),
            Progress::Waiting => {}
        }
        assert_eq!(
            graph.accepted_count(),
            0,
            "necessary helpers cannot be published before their selected parent"
        );
        if !questions.available() {
            let result = questions.completed().await;
            questions.finish(&graph, result);
        }
        for (_, parent, id) in intake.needed() {
            assert_eq!(parent, root);
            match source
                .transfer(id)
                .unwrap()
                .expect("necessary source proof")
            {
                ProofTransfer::Program(metadata) => intake
                    .enqueue_program_helper(peer, root, metadata, &graph)
                    .unwrap(),
                ProofTransfer::Certificate(object) => {
                    intake.payload(peer, root, id, object, &graph).unwrap()
                }
            }
        }
        if let Some((_, parent, id, start, records)) = intake.program_request(&graph).unwrap() {
            assert_eq!(parent, root);
            let chunk = source
                .program_chunk(id, start, records, CHUNK_BYTES)
                .unwrap()
                .unwrap();
            fetched.insert(id);
            intake
                .program_payload(peer, parent, id, chunk, &graph)
                .unwrap();
        }
        for (_, id) in intake.program_refresh_needed() {
            assert_eq!(id, root);
            intake
                .enqueue_program(peer, metadata.clone(), &graph, None)
                .unwrap();
        }
    }
    let expected: BTreeSet<_> = manifests.iter().map(Manifest::proof_id).collect();
    assert_eq!(
        accepted
            .expect("finite compositional checking must finish")
            .into_iter()
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(fetched, expected);
    assert_eq!(graph.accepted_count(), 3);
    assert_eq!(
        graph
            .checked_context()
            .proof_dependency_depth(root)
            .unwrap(),
        Some(2)
    );
    let content_root = graph.content_root();
    drop(intake);
    drop(graph);
    let replayed = Graph::open(&receiver.0).unwrap();
    assert_eq!(replayed.content_root(), content_root);
    assert_eq!(
        replayed.ids().into_iter().collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        replayed
            .checked_context()
            .proof_dependency_depth(root)
            .unwrap(),
        Some(2)
    );
}

#[cfg(feature = "system-tests")]
#[tokio::test]
async fn real_nodes_exchange_a_program_with_large_lemma_dependencies_and_reverify_after_restart() {
    const CASE: &str = "intake::program::tests::composition::real_nodes_exchange_a_program_with_large_lemma_dependencies_and_reverify_after_restart";
    if isolated(CASE) {
        return;
    }
    let sender = Directory::new();
    let receiver = Directory::new();
    let (graph, manifests, _) = populated(&sender.0);
    let expected_root = graph.content_root();
    drop(graph);
    let identity = |directory: &std::path::Path| {
        let key = libp2p::identity::Keypair::generate_ed25519();
        std::fs::write(
            directory.join("identity.key"),
            key.to_protobuf_encoding().unwrap(),
        )
        .unwrap();
        key.public().to_peer_id()
    };
    let sender_peer = identity(&sender.0);
    let receiver_peer = identity(&receiver.0);
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let sender_port = first.local_addr().unwrap().port();
    let receiver_port = second.local_addr().unwrap().port();
    drop((first, second));
    let config = |directory: PathBuf, port, peer: PeerId, remote_port| network::Config {
        directory,
        listen: format!("/ip4/127.0.0.1/tcp/{port}"),
        peers: vec![network::Peer {
            id: peer.to_string(),
            address: format!("/ip4/127.0.0.1/tcp/{remote_port}"),
        }],
        discovery: Some(network::DiscoveryConfig {
            mdns: false,
            dht: false,
            ..Default::default()
        }),
        producer_sources: Vec::new(),
    };
    let (sender_handle, sender_admin, inbox) = crate::question::channel();
    let sender_task = tokio::spawn(network::run_with_questions(
        config(sender.0.clone(), sender_port, receiver_peer, receiver_port),
        false,
        inbox,
        accepting as fn(_) -> _,
    ));
    let (receiver_handle, receiver_admin, inbox) = crate::question::channel();
    let receiver_task = tokio::spawn(network::run_with_questions(
        config(receiver.0.clone(), receiver_port, sender_peer, sender_port),
        false,
        inbox,
        accepting as fn(_) -> _,
    ));
    let reached = tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            let count = receiver_handle.context().await.unwrap().checked_proofs;
            assert!(
                count == 0 || count == 3,
                "transport cannot publish a partial necessary closure"
            );
            if count == 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    sender_admin.stop().await.unwrap();
    receiver_admin.stop().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), sender_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), receiver_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop((sender_handle, receiver_handle));
    reached.expect("actual transport must fetch and compose large cited lemmas");
    let replayed = Graph::open(&receiver.0).unwrap();
    assert_eq!(replayed.content_root(), expected_root);
    assert_eq!(
        replayed.ids().into_iter().collect::<BTreeSet<_>>(),
        manifests.iter().map(Manifest::proof_id).collect()
    );
    drop(replayed);
    crate::store::corrupt_payload(&receiver.0, &crate::hex(manifests[0].proof_id().as_bytes()));
    assert!(
        Graph::open(&receiver.0).is_err(),
        "restart must authenticate every cited lemma again"
    );
}
