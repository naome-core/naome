use super::*;
mod computation;
mod publication;

use crate::{Envelope, object::id_bytes};
use naome_authoring::CompiledQuestion;
use naome_proof::ArtifactId;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct Directory(pub(super) PathBuf);
impl Directory {
    pub(super) fn new() -> Self {
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
    let a = CompiledQuestion::compile(&crate::mocks::create_question(0))
        .unwrap()
        .proved_target()
        .to_source();
    let b = "all(y,mem(y,y))";
    let root=producer.author(&format!("goal = imp({b},{a}) proof: p0 = cite(\"{}\") p1 = simp({a},{b}) p2 = mp(p0,p1) return p2",crate::hex(helper.proof_id().unwrap().unwrap().as_bytes()))).unwrap();
    let question = CompiledQuestion::compile(&format!("goal = imp({b},{a})")).unwrap();
    (helper, root, question)
}

#[tokio::test]
async fn current_authoring_matches_autonomous_mock_roots_and_replays_checked_storage() {
    for cursor in 0..3 {
        let directory = Directory::new();
        let mut graph = Graph::open(&directory.0).unwrap();
        let catalog_question =
            CompiledQuestion::compile(&crate::mocks::create_question(cursor as u64)).unwrap();
        let original_bytes = catalog_question.to_canonical_bytes().unwrap();
        let source = format!(
            "# Alternate source presentation\n{}\n",
            catalog_question.source()
        );
        let proof = format!(
            "# Alternate proof presentation\n{}\n",
            crate::mocks::create_proof(&catalog_question).unwrap()
        );
        let question = CompiledQuestion::compile(&source).unwrap();
        assert_eq!(question.proved_target(), catalog_question.proved_target());
        assert_eq!(question.refuted_target(), catalog_question.refuted_target());
        assert_eq!(question.resolution_id(), catalog_question.resolution_id());
        assert_ne!(question.source_hash(), catalog_question.source_hash());
        let before = graph
            .author(&crate::mocks::create_proof(&catalog_question).unwrap())
            .unwrap();
        let envelope = graph.author(&proof).unwrap();
        assert_eq!(envelope, before);
        let mut questions =
            crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
        let (_, response) = questions.begin_exchange(
            &graph,
            question.clone(),
            Instant::now() + Duration::from_secs(5),
        );
        let selection = tokio::time::timeout(Duration::from_secs(5), questions.completed())
            .await
            .unwrap();
        questions.finish(&graph, selection);
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
        assert_eq!(
            graph
                .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
                .unwrap(),
            vec![root]
        );
        questions.apply_exchange(delta).unwrap();
        drop(graph);
        let mut replayed = Graph::open(&directory.0).unwrap();
        assert_eq!(replayed.ids(), vec![root]);
        assert_eq!(
            replayed.ingest(envelope, Instant::now()).unwrap().status,
            "duplicate"
        );
        assert_eq!(
            CompiledQuestion::from_canonical_bytes(&original_bytes).unwrap(),
            catalog_question
        );
        assert_eq!(
            CompiledQuestion::from_canonical_bytes(&question.to_canonical_bytes().unwrap())
                .unwrap(),
            question
        );
    }
}

#[tokio::test]
async fn status_distinguishes_live_checked_counts_from_recorded_offline_admissions() {
    let directory = Directory::new();
    let (helper, root, question) = closure();
    let root_id = ArtifactId::from_bytes(id_bytes(&root.artifact_id).unwrap());
    let mut graph = Graph::open(&directory.0).unwrap();
    assert_eq!(
        graph.ingest(root.clone(), Instant::now()).unwrap().status,
        "waiting"
    );
    assert_eq!(graph.accepted_count(), 0);
    let incomplete = [(root_id, root.clone().prepare().unwrap())].into();
    assert!(graph.prepare_batch(root_id, incomplete, &question).is_err());
    drop(graph);
    assert_eq!(
        stopped_status(&directory.0).await.unwrap(),
        Status {
            running: false,
            computation: crate::resources::ComputationState::Stopped,
            computation_reason: None,
            accepted_artifacts: 0,
            artifact_verification: ArtifactVerification::NotRun,
        }
    );
    let mut graph = Graph::open(&directory.0).unwrap();
    let helper_id = ArtifactId::from_bytes(id_bytes(&helper.artifact_id).unwrap());
    let candidates = [
        (root_id, root.clone().prepare().unwrap()),
        (helper_id, helper.clone().prepare().unwrap()),
    ]
    .into();
    let batch = graph.prepare_batch(root_id, candidates, &question).unwrap();
    assert!(
        graph.accepted_count() == 0,
        "checked staging has no published count"
    );
    assert_eq!(
        graph
            .commit_batch(root_id, batch, Instant::now() + Duration::from_secs(5))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        graph.ingest(root.clone(), Instant::now()).unwrap().status,
        "duplicate"
    );
    assert_eq!(
        graph.ingest(helper.clone(), Instant::now()).unwrap().status,
        "duplicate"
    );
    let mut invalid = root.clone();
    invalid.payload = "ff".into();
    assert!(graph.ingest(invalid, Instant::now()).is_err());
    assert_eq!(graph.accepted_count(), 2);
    let control = Control::bind_token(&directory.0, "ab".repeat(32)).unwrap();
    let (served, response) = tokio::join!(
        async {
            let (stream, _) = control.listener.accept().await.unwrap();
            control
                .respond(stream, graph.accepted_count(), true)
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
            computation: crate::resources::ComputationState::Running,
            computation_reason: None,
            accepted_artifacts: 2,
            artifact_verification: ArtifactVerification::Checked,
        }
    );
    drop(control);
    drop(graph);
    assert_eq!(
        status(&directory.0).await.unwrap(),
        Status {
            running: false,
            computation: crate::resources::ComputationState::Stopped,
            computation_reason: None,
            accepted_artifacts: 2,
            artifact_verification: ArtifactVerification::NotRun,
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
    crate::store::corrupt_payload(&directory.0, &helper.artifact_id);
    let recorded = status(&directory.0).await.unwrap();
    assert_eq!(recorded.accepted_artifacts, 2);
    assert_eq!(recorded.artifact_verification, ArtifactVerification::NotRun);
    assert!(
        Graph::open(&directory.0).is_err(),
        "corruption cannot become checked knowledge"
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
    let status = wait_for_stop(
        &directory.0,
        Instant::now() + crate::resources::limits().lifecycle_timeout,
        || {
            observed += 1;
            observations.next().expect("unexpected further observation")
        },
    )
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
            computation: crate::resources::ComputationState::Stopped,
            computation_reason: None,
            accepted_artifacts: 1,
            artifact_verification: ArtifactVerification::NotRun,
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
async fn stop_requires_directory_release_and_reports_offline_admissions_without_revalidation() {
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
    crate::store::corrupt_payload(&directory.0, &helper.artifact_id);
    let recorded = wait_for_stop(&directory.0, Instant::now(), || {
        Err(nix::errno::Errno::ESRCH)
    })
    .await
    .unwrap();
    assert_eq!(recorded.accepted_artifacts, 1);
    assert_eq!(recorded.artifact_verification, ArtifactVerification::NotRun);
    assert!(Graph::open(&directory.0).is_err());
}

#[test]
fn retained_logs_are_bounded_after_oversized_restart_rotation_and_large_events() {
    let directory = Directory::new();
    for name in ["node.log", "node.log.previous"] {
        let mut file = File::create(directory.0.join(name)).unwrap();
        let line = b"{\"event\":\"historical\"}\n";
        for _ in 0..3 * crate::resources::limits().log_segment_bytes as usize / line.len() {
            file.write_all(line).unwrap();
        }
    }
    let mut log = Log::open(&directory.0).unwrap();
    for _ in 0..4 {
        log.write(&serde_json::json!({"event":"bounded","detail":"x".repeat(900*1024)}))
            .unwrap();
    }
    assert!(
        log.write(&serde_json::json!({"detail":"x".repeat(crate::resources::limits().log_segment_bytes as usize)}))
            .is_err()
    );
    for name in ["node.log", "node.log.previous"] {
        let path = directory.0.join(name);
        assert!(path.metadata().unwrap().len() <= crate::resources::limits().log_segment_bytes);
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
    let original = vec![b'x'; crate::resources::limits().log_segment_bytes as usize + 1024];
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
        stopped_status(&directory.0)
            .await
            .unwrap()
            .accepted_artifacts,
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
        crate::store::payload_bytes(&directory.0, &proof.artifact_id),
        crate::unhex(&proof.payload).unwrap()
    );
}

#[test]
fn identity_receipt_corruption_or_loss_never_changes_an_established_key() {
    let directory = Directory::new();
    initialize(&directory.0).unwrap();
    let key = fs::read(directory.0.join("identity.key")).unwrap();
    let receipt_path = directory.0.join("identity.json");
    let receipt = fs::read(&receipt_path).unwrap();
    fs::write(directory.0.join("node.log"), b"").unwrap();
    for invalid in [
        b"{".as_slice(),
        br#"{"version":1}"#,
        br#"{"version":1,"peer_id":42}"#,
    ] {
        fs::write(&receipt_path, invalid).unwrap();
        assert!(initialize(&directory.0).is_err());
        assert_eq!(fs::read(&receipt_path).unwrap(), invalid);
        assert_eq!(fs::read(directory.0.join("identity.key")).unwrap(), key);
    }
    fs::remove_file(&receipt_path).unwrap();
    assert!(
        initialize(&directory.0)
            .unwrap_err()
            .contains("receipt is missing")
    );
    assert!(!receipt_path.exists());
    assert_eq!(fs::read(directory.0.join("identity.key")).unwrap(), key);
    fs::write(&receipt_path, &receipt).unwrap();
    initialize(&directory.0).unwrap();
    assert_eq!(fs::read(&receipt_path).unwrap(), receipt);
}

#[test]
fn interrupted_identity_receipt_publication_reuses_the_existing_peer_key() {
    let directory = Directory::new();
    let key = identity::Keypair::generate_ed25519();
    let encoded = key.to_protobuf_encoding().unwrap();
    fs::write(directory.0.join("identity.key"), &encoded).unwrap();
    let incoming = directory.0.join(".identity-receipt-incoming");
    fs::write(&incoming, b"partial publication").unwrap();
    initialize(&directory.0).unwrap();
    assert!(!incoming.exists());
    assert_eq!(fs::read(directory.0.join("identity.key")).unwrap(), encoded);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.0.join("identity.json")).unwrap()).unwrap();
    assert_eq!(
        receipt,
        serde_json::json!({
            "version": 1,
            "peer_id": key.public().to_peer_id().to_string(),
        })
    );
    initialize(&directory.0).unwrap();
    assert_eq!(fs::read(directory.0.join("identity.key")).unwrap(), encoded);
}

// Real process boundaries for the maintained abort owner. These source tests
// are not native qualification of installed CLI/Guardian/resource behavior.
#[test]
fn handoff_abort_process_fixture() {
    let Ok(mode) = std::env::var("NAOME_TEST_HANDOFF_ABORT_FIXTURE") else {
        return;
    };
    if mode == "detach" {
        nix::unistd::setsid().unwrap();
    }
    // No work/descendants precede setsid,matching the daemon's entry invariant.
    std::thread::sleep(Duration::from_secs(60));
}

#[tokio::test]
async fn handoff_abort_stabilizes_inherited_child_without_inventing_group_absence() {
    let inherited = (nix::unistd::getpgrp(), nix::unistd::getsid(None).unwrap());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime::tests::handoff_abort_process_fixture",
            "--nocapture",
        ])
        .env("NAOME_TEST_HANDOFF_ABORT_FIXTURE", "inherited")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let report = abort_owned_handoff(
        &mut child,
        Instant::now() + Duration::from_millis(500),
        Some(inherited),
    )
    .await
    .unwrap();
    assert_eq!(report["complete"], true, "{report}");
    assert_eq!(report["original_child_reaped"], true);
    assert_eq!(report["session_state"], "CONFIRMED_STOPPED_BEFORE_DETACH");
    assert!(report["owned_group_empty"].is_null());
}

#[tokio::test]
async fn handoff_abort_handles_the_actual_setsid_race_while_original_child_is_held() {
    let inherited = (nix::unistd::getpgrp(), nix::unistd::getsid(None).unwrap());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime::tests::handoff_abort_process_fixture",
            "--nocapture",
        ])
        .env("NAOME_TEST_HANDOFF_ABORT_FIXTURE", "detach")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let report = abort_owned_handoff(
        &mut child,
        Instant::now() + Duration::from_millis(500),
        Some(inherited),
    )
    .await
    .unwrap();
    assert_eq!(report["complete"], true, "{report}");
    assert_eq!(report["original_child_reaped"], true);
    match report["session_state"].as_str().unwrap() {
        "CONFIRMED_STOPPED_DETACHED_SESSION" => assert_eq!(report["owned_group_empty"], true),
        "CONFIRMED_STOPPED_BEFORE_DETACH" => assert!(report["owned_group_empty"].is_null()),
        other => panic!("unproved session cannot complete: {other};{report}"),
    }
}

mod offline;
