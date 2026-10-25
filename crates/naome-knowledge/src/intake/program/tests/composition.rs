use super::*;
#[cfg(feature = "system-tests")]
use crate::network;
use crate::object::ProofTransfer;
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
    receive(
        &source,
        &receiver.0,
        metadata,
        manifests.iter().map(Manifest::proof_id).collect(),
        2,
        false,
    )
    .await;
}

#[tokio::test]
async fn a_composed_program_retains_its_checked_lemmas_across_pressure_and_graph_growth() {
    const CASE: &str = "intake::program::tests::composition::a_composed_program_retains_its_checked_lemmas_across_pressure_and_graph_growth";
    if isolated(CASE) {
        return;
    }
    let sender = Directory::new();
    let receiver = Directory::new();
    let (source, manifests, metadata) = populated(&sender.0);
    receive(
        &source,
        &receiver.0,
        metadata,
        manifests.iter().map(Manifest::proof_id).collect(),
        2,
        true,
    )
    .await;
}

fn work_selection() -> crate::resources::adaptive::Selection {
    use crate::resources::adaptive::{Custom, Profile, Selection};
    let work = budget();
    Selection {
        profile: Profile::Custom,
        custom: Some(Custom {
            memory_bytes: crate::resources::limits().memory_bytes as u64,
            concurrency: work.concurrency,
            cache_bytes: crate::resources::limits().checked_cache_bytes as u64,
            batch_steps: work.batch_steps,
            network_requests: work.network_requests,
        }),
    }
}

#[test]
fn startup_replay_refreshes_the_owner_budget_between_program_quanta() {
    const CASE: &str = "intake::program::tests::composition::startup_replay_refreshes_the_owner_budget_between_program_quanta";
    if isolated(CASE) {
        return;
    }
    use crate::resources::adaptive::{self, Snapshot};
    let directory = Directory::new();
    let (graph, manifests, _) = populated(&directory.0);
    let expected = graph.content_root();
    drop(graph);
    let mut selection = work_selection();
    selection.custom.as_mut().unwrap().batch_steps = 1;
    let initial = Snapshot::derive(
        selection,
        adaptive::sample(&directory.0).unwrap(),
        crate::resources::limits().memory_bytes as u64,
    )
    .unwrap();
    let mut grown = initial.clone();
    grown.selection.custom.as_mut().unwrap().batch_steps = 128;
    grown.budget.batch_steps = 128;
    grown.timestamp_ms += 1;
    adaptive::publish(initial);
    let before = crate::resources::feedback::statistics().check.units;
    let mut observations = 0;
    let replayed = Graph::open_observed(&directory.0, &mut || {
        observations += 1;
        if crate::resources::feedback::statistics().check.units > before {
            adaptive::publish(grown.clone());
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(replayed.content_root(), expected);
    assert_eq!(replayed.accepted_count(), 3);
    let work = directory.0.join(".program-work").join(format!(
        "{}.sqlite3",
        crate::hex(manifests[0].proof_id().as_bytes())
    ));
    let connection =
        rusqlite::Connection::open_with_flags(work, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = connection
        .prepare("SELECT snapshot FROM budget ORDER BY sequence")
        .unwrap();
    let quanta = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|bytes| {
            serde_json::from_slice::<Snapshot>(&bytes.unwrap())
                .unwrap()
                .budget
                .batch_steps
        })
        .collect::<Vec<_>>();
    assert_eq!(quanta.first(), Some(&1));
    assert!(
        quanta.contains(&128),
        "startup retained its initial budget: {quanta:?}"
    );
    assert!(observations > 2);
}

async fn receive(
    source: &Graph,
    directory: &std::path::Path,
    metadata: ProgramMetadata,
    expected: BTreeSet<ProofId>,
    depth: usize,
    rebind: bool,
) {
    use crate::resources::adaptive::{self, Snapshot};
    // These isolated mathematical/atomic-publication cases count calls using
    // the shared work fixture's quantum, rather than host load or recovery time.
    // Native governor recovery has separate coverage; real memory and disk
    // leases still apply here, including the registration-pressure assertion.
    let work = budget();
    let capacity = crate::resources::limits().memory_bytes as u64;
    let snapshot = Snapshot::derive(
        work_selection(),
        adaptive::sample(directory).unwrap(),
        capacity,
    )
    .unwrap();
    assert!(snapshot.budget.paused.is_none(), "{snapshot:?}");
    adaptive::publish(snapshot.clone());
    let root = metadata.manifest.proof_id();
    let mut graph = Graph::open(directory).unwrap();
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
    let mut unrelated = None;
    let mut pressured = false;
    let mut publication_pressured = false;
    for _ in 0..5000 {
        if rebind
            && !publication_pressured
            && intake.programs.active.as_ref().is_some_and(|root| {
                matches!(&root.stage, Stage::Prepare(prepared) if prepared.ready())
                    && root.authority.ready(SelectionStage::Final)
            })
        {
            // Final question admission can refuse a transferred checked batch.
            // Recovery must rebuild its private helper prefix before retrying.
            let mut constrained = snapshot.clone();
            constrained.budget.cache_bytes = work.cache_bytes;
            adaptive::publish(constrained);
            let retained = intake.programs.active.as_ref().unwrap();
            assert!(matches!(
                questions.prepare_exchange(
                    &graph,
                    retained.authority.question(),
                    retained.authority.selected().unwrap(),
                ),
                Err(crate::Error::ExecutionLimit)
            ));
            assert!(matches!(
                intake.advance(&mut graph, &mut questions),
                Progress::Waiting
            ));
            let retained = intake.programs.active.as_ref().unwrap();
            assert!(matches!(&retained.stage, Stage::Prepare(prepared) if prepared.pending()));
            assert!(
                !retained.closure.ready(),
                "a transferred batch's helper prefix must be rebuilt after backpressure"
            );
            assert_eq!(graph.accepted_count(), usize::from(unrelated.is_some()));
            adaptive::publish(snapshot.clone());
            publication_pressured = true;
        }
        if rebind
            && !pressured
            && intake.programs.active.as_ref().is_some_and(|root| {
                matches!(&root.stage, Stage::Prepare(prepared) if prepared.pending())
                    && root.closure.ready()
                    && root.closure.member_count() > 1
            })
        {
            let retained = crate::resources::with_disk_available(0, || {
                intake.advance(&mut graph, &mut questions)
            });
            assert!(matches!(retained, Progress::Waiting));
            pressured = true;
        }
        match intake.advance(&mut graph, &mut questions) {
            Progress::Accepted(ids) => {
                accepted = Some(ids);
                break;
            }
            Progress::Skipped(_, error) => panic!("composition rejected: {error}"),
            Progress::Waiting => {}
        }
        if rebind
            && unrelated.is_none()
            && intake.programs.active.as_ref().is_some_and(
                |root| matches!(&root.stage, Stage::Prepare(prepared) if prepared.ready()),
            )
        {
            let (_, admission) = graph
                .produce("goal=all(x,eq(x,x)) proof: p=refl(x) q=gen(p,x) return q")
                .unwrap();
            unrelated = Some(admission.id);
        }
        assert_eq!(
            graph.accepted_count(),
            usize::from(unrelated.is_some()),
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
                    fetched.insert(id);
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
    let accepted = accepted.unwrap_or_else(|| {
        panic!(
            "finite compositional checking must finish; budget={:?}; progress={:?}",
            adaptive::current().map(|snapshot| snapshot.budget),
            intake.programs.active.as_ref().map(|root| (
                match &root.stage {
                    Stage::Start => "start",
                    Stage::Fetch => "fetch",
                    Stage::Check(_) => "check",
                    Stage::Prepare(_) => "prepare",
                },
                root.scanned,
                root.input_complete,
                root.closure.busy(),
                root.closure.ready(),
            )),
        )
    });
    assert_eq!(accepted.into_iter().collect::<BTreeSet<_>>(), expected);
    assert_eq!(fetched, expected);
    assert_eq!(
        unrelated.is_some(),
        rebind,
        "the final checked closure must encounter a changed predecessor"
    );
    assert_eq!(
        pressured, rebind,
        "registration must encounter real disk admission pressure"
    );
    assert_eq!(publication_pressured, rebind);
    let mut all_expected = expected.clone();
    all_expected.extend(unrelated);
    assert_eq!(graph.accepted_count(), all_expected.len());
    assert_eq!(
        graph
            .checked_context()
            .proof_dependency_depth(root)
            .unwrap(),
        Some(depth)
    );
    let content_root = graph.content_root();
    drop(intake);
    drop(graph);
    let replayed = Graph::open(directory).unwrap();
    assert_eq!(replayed.content_root(), content_root);
    assert_eq!(
        replayed.ids().into_iter().collect::<BTreeSet<_>>(),
        all_expected
    );
    assert_eq!(
        replayed
            .checked_context()
            .proof_dependency_depth(root)
            .unwrap(),
        Some(depth)
    );
}

#[tokio::test]
async fn program_roots_fetch_mixed_certificate_and_program_dependencies_as_one_private_closure() {
    const CASE: &str = "intake::program::tests::composition::program_roots_fetch_mixed_certificate_and_program_dependencies_as_one_private_closure";
    if isolated(CASE) {
        return;
    }
    let sender = Directory::new();
    let receiver = Directory::new();
    let mut source = Graph::open(&sender.0).unwrap();
    let (_, admission) = source
        .produce("goal=all(x0,eq(x0,x0)) proof: p0=refl(x0) p1=gen(p0,x0) return p1")
        .unwrap();
    assert_eq!(admission.status, "accepted");
    let certificate = admission.id;
    let mut work =
        crate::proof_work::Work::open(&sender.0.join("mixed-implication.sqlite3")).unwrap();
    work.append_group(&[
        Command::Equal { left: 0, right: 0 },
        Command::Separation {
            predicate: 0,
            element: 0,
            source: 1,
            result: 2,
        },
        Command::ProofReference {
            proof_id: *certificate.as_bytes(),
        },
        Command::Simplification {
            antecedent: 1,
            consequent: 2,
        },
        Command::ModusPonens {
            premise: 1,
            implication: 3,
        },
        Command::Seal { proof: 4 },
    ])
    .unwrap();
    while work.advance(&budget(), source.checked_context()).unwrap() {}
    while !work.prepare_export(&budget()).unwrap() {}
    let proof = work.into_checked().unwrap();
    let implication = proof.proof().unwrap().manifest().proof_id();
    publish(&mut source, &proof);
    drop(proof);
    let mut work =
        crate::proof_work::Work::open(&sender.0.join("mixed-composition.sqlite3")).unwrap();
    work.append_group(&[
        Command::ProofReference {
            proof_id: *certificate.as_bytes(),
        },
        Command::ProofReference {
            proof_id: *implication.as_bytes(),
        },
        Command::ModusPonens {
            premise: 0,
            implication: 1,
        },
        Command::Seal { proof: 2 },
    ])
    .unwrap();
    while work.advance(&budget(), source.checked_context()).unwrap() {}
    while !work.prepare_export(&budget()).unwrap() {}
    let proof = work.into_checked().unwrap();
    let root = proof.proof().unwrap().manifest().proof_id();
    publish(&mut source, &proof);
    drop(proof);
    let crate::object::ProofDescription::Program(metadata) =
        source.description(root).unwrap().unwrap()
    else {
        panic!("program root description");
    };
    receive(
        &source,
        &receiver.0,
        metadata,
        [certificate, implication, root].into_iter().collect(),
        3,
        false,
    )
    .await;
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
    // Pin the embedding's work quantum while retaining native observations,
    // pressure pauses, memory leases and the existing transport deadline.
    let selection = work_selection();
    for directory in [&sender.0, &receiver.0] {
        std::fs::write(
            directory.join("resource-profile.json"),
            serde_json::to_vec(&selection).unwrap(),
        )
        .unwrap();
    }
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
    assert!(
        reached.is_ok(),
        "actual transport must fetch and compose large cited lemmas: {reached:?}; selection={selection:?}",
    );
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
