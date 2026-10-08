use super::*;
use crate::{Envelope, object::id_bytes};
use naome_authoring::CompiledQuestion;
use naome_proof::ProofId;
use std::sync::atomic::{AtomicU64, Ordering};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-runtime-api-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn closure() -> (Envelope, Envelope, CompiledQuestion) {
    let mut producer = Graph::default();
    let helper = producer
        .author(
            &crate::mocks::create_proof(
                &CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    producer.ingest(helper.clone(), Instant::now()).unwrap();
    let a = "forall(x,equal(x,x))";
    let b = "forall(y,member(y,y))";
    let root=producer.author(&format!("foundation = \"naome:zfc\" statement = implies({b},{a}) proof: p0 = cite(\"{}\") p1 = simplification({a},{b}) p2 = modus_ponens(p0,p1) return p2",helper.proof_id)).unwrap();
    let question = CompiledQuestion::compile(&format!(
        "foundation = \"naome:zfc\" statement = implies({b},{a})"
    ))
    .unwrap();
    (helper, root, question)
}

#[tokio::test]
async fn versioned_authoring_matches_autonomous_mock_roots_and_replays_checked_storage() {
    let sources = [
        (
            "nao 1 goal=all(x,eq(x,x))",
            "nao 1 goal=all(x,eq(x,x)) proof: p0=refl(x) p1=gen(p0,x) return p1",
        ),
        (
            "nao 1 let: A=mem(x,x) goal=all(x,imp(A,A))",
            "nao 1 let: A=mem(x,x) B=imp(A,A) goal=all(x,B) proof: p0=simp(A,A) p1=simp(A,B) p2=frege(A,B,A) p3=mp(p1,p2) p4=mp(p0,p3) p5=gen(p4,x) return p5",
        ),
        (
            "nao 1 goal=all([x,y,set],imp(eq(x,y),imp(mem(x,set),mem(y,set))))",
            "nao 1 goal=all([x,y,set],imp(eq(x,y),imp(mem(x,set),mem(y,set)))) proof: p0=subst(x,y,mem(x,set)) p1=gen(p0,set) p2=gen(p1,y) p3=gen(p2,x) return p3",
        ),
    ];
    for (cursor, (source, proof)) in sources.into_iter().enumerate() {
        let directory = Directory::new();
        let mut graph = Graph::open(&directory.0).unwrap();
        let legacy =
            CompiledQuestion::compile(&crate::mocks::create_question(cursor as u64)).unwrap();
        let original_bytes = legacy.to_canonical_bytes().unwrap();
        let question = CompiledQuestion::compile(source).unwrap();
        assert_eq!(question.proved_target(), legacy.proved_target());
        assert_eq!(question.refuted_target(), legacy.refuted_target());
        assert_eq!(question.resolution_id(), legacy.resolution_id());
        assert_ne!(question.source_hash(), legacy.source_hash());
        let before = graph
            .author(&crate::mocks::create_proof(&legacy).unwrap())
            .unwrap();
        let envelope = graph.author(proof).unwrap();
        assert_eq!(envelope, before);
        let mut questions =
            crate::question::LocalQuestions::new(Some(crate::mocks::assess_interest as fn(_) -> _));
        let (_, response) = questions.begin_exchange(
            &graph,
            question.clone(),
            Instant::now() + Duration::from_secs(5),
        );
        let interest = tokio::time::timeout(Duration::from_secs(5), questions.completed())
            .await
            .unwrap();
        questions.finish(&graph, interest);
        let assessment = response.await.unwrap();
        assert!(assessment.prefilter.passed());
        assert!(assessment.novelty().is_some());
        let candidate = envelope.clone().prepare().unwrap();
        let root = candidate.id;
        let batch = graph
            .prepare_batch(root, [(root, candidate)].into(), &question)
            .unwrap();
        let delta = questions
            .prepare_exchange(&graph, &question, &assessment)
            .unwrap();
        graph.persist_batch(root, &batch).unwrap();
        assert_eq!(graph.apply_batch(batch), vec![root]);
        questions.apply_exchange(delta);
        drop(graph);
        let mut replayed = Graph::open(&directory.0).unwrap();
        assert_eq!(replayed.ids(), vec![root]);
        assert_eq!(
            replayed.ingest(envelope, Instant::now()).unwrap().status,
            "duplicate"
        );
        assert_eq!(
            CompiledQuestion::from_canonical_bytes(&original_bytes).unwrap(),
            legacy
        );
        assert_eq!(
            CompiledQuestion::from_canonical_bytes(&question.to_canonical_bytes().unwrap())
                .unwrap(),
            question
        );
    }
}

#[tokio::test]
async fn status_counts_only_unique_checked_closure_members_running_stopped_and_recovered() {
    let directory = Directory::new();
    let (helper, root, question) = closure();
    let root_id = ProofId::from_bytes(id_bytes(&root.proof_id).unwrap());
    let mut graph = Graph::open(&directory.0).unwrap();
    assert_eq!(
        graph.ingest(root.clone(), Instant::now()).unwrap().status,
        "waiting"
    );
    assert_eq!(graph.ids().len(), 0);
    let incomplete = [(root_id, root.clone().prepare().unwrap())].into();
    assert!(graph.prepare_batch(root_id, incomplete, &question).is_err());
    drop(graph);
    assert_eq!(
        stopped_status(&directory.0).await.unwrap(),
        Status {
            running: false,
            accepted_proofs: 0
        }
    );
    let mut graph = Graph::open(&directory.0).unwrap();
    let helper_id = ProofId::from_bytes(id_bytes(&helper.proof_id).unwrap());
    let candidates = [
        (root_id, root.clone().prepare().unwrap()),
        (helper_id, helper.clone().prepare().unwrap()),
    ]
    .into();
    let batch = graph.prepare_batch(root_id, candidates, &question).unwrap();
    assert!(
        graph.ids().is_empty(),
        "checked staging has no published count"
    );
    graph.persist_batch(root_id, &batch).unwrap();
    assert_eq!(graph.apply_batch(batch).len(), 2);
    assert_eq!(
        graph.ingest(root.clone(), Instant::now()).unwrap().status,
        "duplicate"
    );
    assert_eq!(
        graph.ingest(helper.clone(), Instant::now()).unwrap().status,
        "duplicate"
    );
    let mut invalid = root.clone();
    invalid.proof = "ff".into();
    assert!(graph.ingest(invalid, Instant::now()).is_err());
    assert_eq!(graph.ids().len(), 2);
    let control = Control::bind_token(&directory.0, "ab".repeat(32)).unwrap();
    let (served, response) = tokio::join!(
        async {
            let (stream, _) = control.listener.accept().await.unwrap();
            control
                .respond(stream, graph.ids().len(), true)
                .await
                .unwrap()
        },
        request(&directory.0, Operation::Status, None)
    );
    assert!(!served);
    assert_eq!(
        response.unwrap().unwrap(),
        Status {
            running: true,
            accepted_proofs: 2
        }
    );
    drop(control);
    drop(graph);
    assert_eq!(
        status(&directory.0).await.unwrap(),
        Status {
            running: false,
            accepted_proofs: 2
        }
    );
    let recovered = Graph::open(&directory.0).unwrap();
    assert_eq!(
        recovered
            .ids()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [helper_id, root_id].into()
    );
    drop(recovered);
    let batch = fs::read_dir(directory.0.join("objects/batches"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(batch.join(format!("{}.json", helper.proof_id)), b"{}").unwrap();
    assert!(
        status(&directory.0).await.is_err(),
        "corrupt durable content cannot return a proof count"
    );
}

#[tokio::test]
async fn stop_waits_through_denied_and_live_group_observations_until_confirmed_exit() {
    let directory = Directory::new();
    let (helper, _, _) = closure();
    let mut graph = Graph::open(&directory.0).unwrap();
    graph.ingest(helper, Instant::now()).unwrap();
    drop(graph);
    let mut observations = [
        Err(nix::errno::Errno::EPERM),
        Ok(()),
        Err(nix::errno::Errno::ESRCH),
    ]
    .into_iter();
    let mut observed = 0;
    let status = wait_for_stop(&directory.0, Instant::now() + LIFECYCLE_TIMEOUT, || {
        observed += 1;
        observations.next().expect("unexpected further observation")
    })
    .await
    .unwrap();
    assert_eq!(
        observed, 3,
        "neither denied nor live observation proves exit"
    );
    assert_eq!(
        status,
        Status {
            running: false,
            accepted_proofs: 1
        }
    );
}

#[tokio::test]
async fn stop_fails_closed_when_group_exit_remains_denied_at_the_deadline() {
    let directory = Directory::new();
    drop(Graph::open(&directory.0).unwrap());
    let mut observed = 0;
    let error = wait_for_stop(
        &directory.0,
        Instant::now() + Duration::from_secs(1),
        || {
            observed += 1;
            Err(nix::errno::Errno::EPERM)
        },
    )
    .await
    .unwrap_err();
    assert!(
        observed > 1,
        "denied observation must be retried until the deadline"
    );
    assert!(
        error.contains("process group exit is unconfirmed"),
        "{error}"
    );
}

#[tokio::test]
async fn stop_requires_graph_release_and_revalidation_after_confirmed_group_exit() {
    let directory = Directory::new();
    let graph = Graph::open(&directory.0).unwrap();
    let held = wait_for_stop(&directory.0, Instant::now(), || {
        Err(nix::errno::Errno::ESRCH)
    })
    .await
    .unwrap_err();
    assert!(held.contains("knowledge directory already owned"), "{held}");
    drop(graph);
    let (helper, _, _) = closure();
    let mut graph = Graph::open(&directory.0).unwrap();
    graph.ingest(helper.clone(), Instant::now()).unwrap();
    drop(graph);
    let member = directory
        .0
        .join("objects")
        .join(format!("{}.json", helper.proof_id));
    fs::write(member, b"{}").unwrap();
    let corrupt = wait_for_stop(&directory.0, Instant::now(), || {
        Err(nix::errno::Errno::ESRCH)
    })
    .await
    .unwrap_err();
    assert!(corrupt.starts_with("node did not release its directory:"));
    assert!(status(&directory.0).await.is_err());
}

#[test]
fn retained_logs_are_bounded_after_oversized_restart_rotation_and_large_events() {
    let directory = Directory::new();
    for name in ["node.log", "node.log.previous"] {
        let mut file = File::create(directory.0.join(name)).unwrap();
        let line = b"{\"event\":\"historical\"}\n";
        for _ in 0..3 * MAX_LOG_BYTES as usize / line.len() {
            file.write_all(line).unwrap();
        }
    }
    let mut log = Log::open(&directory.0).unwrap();
    for _ in 0..4 {
        log.write(&serde_json::json!({"event":"bounded","detail":"x".repeat(900*1024)}))
            .unwrap();
    }
    assert!(
        log.write(&serde_json::json!({"detail":"x".repeat(MAX_LOG_BYTES as usize)}))
            .is_err()
    );
    for name in ["node.log", "node.log.previous"] {
        let path = directory.0.join(name);
        assert!(path.metadata().unwrap().len() <= MAX_LOG_BYTES);
        for line in fs::read_to_string(path).unwrap().lines() {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }
}

#[test]
fn diagnostic_symlinks_cannot_modify_a_foreign_file() {
    let directory = Directory::new();
    let foreign = Directory::new();
    let destination = foreign.0.join("unrelated.data");
    let original = vec![b'x'; MAX_LOG_BYTES as usize + 1024];
    fs::write(&destination, &original).unwrap();
    std::os::unix::fs::symlink(&destination, directory.0.join("node.log")).unwrap();
    assert!(Log::open(&directory.0).is_err());
    assert_eq!(fs::read(&destination).unwrap(), original);
    fs::remove_file(directory.0.join("node.log")).unwrap();
    std::os::unix::fs::symlink(&destination, directory.0.join("node.log.previous")).unwrap();
    assert!(Log::open(&directory.0).is_err());
    assert_eq!(fs::read(&destination).unwrap(), original);
}

#[tokio::test]
async fn first_start_can_seed_identity_but_lost_changed_or_corrupt_identity_never_rotates() {
    let directory = Directory::new();
    let question = CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap();
    let mut graph = Graph::open(&directory.0).unwrap();
    let proof = graph
        .author(&crate::mocks::create_proof(&question).unwrap())
        .unwrap();
    graph.ingest(proof.clone(), Instant::now()).unwrap();
    drop(graph);
    initialize(&directory.0).unwrap();
    let key = fs::read(directory.0.join("identity.key")).unwrap();
    let receipt = fs::read(directory.0.join("identity.json")).unwrap();
    fs::remove_file(directory.0.join("identity.key")).unwrap();
    assert!(
        initialize(&directory.0)
            .unwrap_err()
            .contains("refusing to replace")
    );
    assert!(!directory.0.join("identity.key").exists());
    assert_eq!(
        fs::read(directory.0.join("identity.json")).unwrap(),
        receipt
    );
    assert_eq!(
        stopped_status(&directory.0).await.unwrap().accepted_proofs,
        1
    );
    let other = identity::Keypair::generate_ed25519()
        .to_protobuf_encoding()
        .unwrap();
    fs::write(directory.0.join("identity.key"), other).unwrap();
    assert!(
        initialize(&directory.0)
            .unwrap_err()
            .contains("does not match")
    );
    fs::write(directory.0.join("identity.key"), b"invalid").unwrap();
    assert!(initialize(&directory.0).is_err());
    fs::write(directory.0.join("identity.key"), &key).unwrap();
    initialize(&directory.0).unwrap();
    assert_eq!(fs::read(directory.0.join("identity.key")).unwrap(), key);
    assert_eq!(
        fs::read(
            directory
                .0
                .join("objects")
                .join(format!("{}.json", proof.proof_id))
        )
        .unwrap(),
        serde_json::to_vec(&proof).unwrap()
    );
}
