use super::*;
use crate::resources::adaptive::Budget;
use naome_proof::program::{CHUNK_BYTES, Command, Manifest, command_hash, stream_hash};
use std::{
    future::{Ready, ready},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

// These cases sample actual process RSS. A separate harness process keeps
// unrelated concurrent library tests out of the node's resource observation.
fn isolated(case: &str) -> bool {
    if std::env::var("NAOME_PROGRAM_INTAKE_CASE").as_deref() == Ok(case) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", case, "--nocapture"])
        .env("NAOME_PROGRAM_INTAKE_CASE", case)
        .output()
        .unwrap();
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}
fn question_source() -> String {
    crate::mocks::create_question(0)
}

fn progress_state(intake: &Intake) -> String {
    let program = intake.programs.active.as_ref().map(|root| {
        let stage = match &root.stage {
            Stage::Start => "start",
            Stage::Fetch => "fetch",
            Stage::Check(_) => "check",
            Stage::Prepare(prepared) if prepared.ready() => "ready",
            Stage::Prepare(_) => "prepare",
        };
        (
            stage,
            root.allowed,
            root.refresh,
            root.input_complete,
            root.scanned,
            root.authority.ready(SelectionStage::Initial),
            root.authority.ready(SelectionStage::Final),
            &root.budget,
            &root.closure,
        )
    });
    let certificate = intake.active.as_ref().map(|root| {
        let stage = match &root.phase {
            super::super::Phase::Initial => "initial",
            super::super::Phase::Fetch => "fetch",
            super::super::Phase::Final(_) => "final",
        };
        (stage, &root.closure)
    });
    format!("program={program:?}, certificate={certificate:?}")
}
fn accepting(_: CompiledQuestion) -> Ready<Result<bool, String>> {
    ready(Ok(true))
}
fn budget() -> Budget {
    Budget {
        memory_bytes: 8 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 32768,
        batch_steps: 128,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    }
}
fn source(graph: &Graph) -> CheckedWork {
    let mut work =
        crate::proof_work::Work::open(&graph.ownership().directory().join("source.sqlite3"))
            .unwrap();
    work.append(&Command::Equal { left: 0, right: 0 }).unwrap();
    work.append(&Command::Separation {
        predicate: 0,
        element: 0,
        source: 1,
        result: 2,
    })
    .unwrap();
    for position in 2..512 {
        work.append(&Command::Generalization {
            premise: position - 1,
            variable: 1,
        })
        .unwrap();
    }
    work.append(&Command::Seal { proof: 1 }).unwrap();
    while work.advance(&budget(), graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget()).unwrap() {}
    work.into_checked().unwrap()
}
fn metadata(proof: &CheckedWork) -> ProgramMetadata {
    ProgramMetadata {
        manifest: proof.proof().unwrap().manifest().clone(),
        question: Some(question_source()),
    }
}
fn publish(graph: &mut Graph, proof: &CheckedWork) {
    let checked = proof.proof().unwrap();
    let manifest = checked.manifest();
    let store = graph.ownership();
    store.start_program(manifest).unwrap();
    loop {
        let progress = store.program_progress(manifest).unwrap();
        if progress.commands == manifest.commands {
            break;
        }
        store
            .append_program(
                manifest,
                &checked
                    .input_chunk(progress.commands, 128, CHUNK_BYTES)
                    .unwrap(),
            )
            .unwrap();
    }
    let mut admission = graph.begin_program_admission(proof).unwrap();
    while !admission.advance(graph, proof, 128).unwrap() {}
    let batch = admission.finish(graph, proof).unwrap();
    graph
        .commit_batch(
            manifest.artifact_id(),
            batch,
            Instant::now() + std::time::Duration::from_secs(60),
        )
        .unwrap();
}

#[test]
fn typed_program_description_and_transfer_preserve_manifest_and_avoid_duplicate_lookup() {
    if isolated(
        "intake::program::tests::typed_program_description_and_transfer_preserve_manifest_and_avoid_duplicate_lookup",
    ) {
        return;
    }
    let mut graph = Graph::default();
    let proof = source(&graph);
    publish(&mut graph, &proof);
    let manifest = proof.proof().unwrap().manifest().clone();
    let envelope = graph.object(manifest.artifact_id()).unwrap().unwrap();
    assert_eq!(envelope.proof_id().unwrap(), Some(manifest.proof_id()));
    assert_eq!(envelope.definition_id().unwrap(), None);
    let before = crate::store::manifest_reads();
    let Some(crate::object::ProofDescription::Program(description)) =
        graph.description(manifest.artifact_id()).unwrap()
    else {
        panic!("program description missing")
    };
    assert_eq!(crate::store::manifest_reads() - before, 1);
    assert_eq!(description.manifest, manifest);
    assert!(description.question().unwrap().is_some());
    let before = crate::store::manifest_reads();
    let Some(crate::object::ArtifactTransfer::Program(transfer)) =
        graph.transfer(manifest.artifact_id()).unwrap()
    else {
        panic!("program transfer missing")
    };
    assert_eq!(crate::store::manifest_reads(), before);
    assert_eq!(transfer, description);
    assert!(
        graph
            .description(ArtifactId::from_bytes([0; 32]))
            .unwrap()
            .is_none()
    );
}

#[test]
#[ignore = "Manual matched architecture measurement"]
fn measure_program_description() {
    use sha2::{Digest, Sha256};
    let mut graph = Graph::default();
    let proof = source(&graph);
    publish(&mut graph, &proof);
    let id = proof.proof().unwrap().manifest().artifact_id();
    let before = crate::store::manifest_reads();
    let start = Instant::now();
    let mut digest = [0; 32];
    for _ in 0..100 {
        let Some(crate::object::ProofDescription::Program(description)) =
            graph.description(id).unwrap()
        else {
            panic!("program absent")
        };
        digest = Sha256::digest(serde_json::to_vec(&description).unwrap()).into();
    }
    println!(
        "architecture_description requests=100 manifest_reads={} elapsed_ms={:.3} payload_hash={}",
        crate::store::manifest_reads() - before,
        start.elapsed().as_secs_f64() * 1000.0,
        crate::hex(&digest)
    );
}

#[test]
fn published_program_survives_catalog_validation_and_fresh_mathematical_replay() {
    if isolated(
        "intake::program::tests::published_program_survives_catalog_validation_and_fresh_mathematical_replay",
    ) {
        return;
    }
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let directory = std::env::temp_dir().join(format!(
        "naome-durable-program-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut graph = Graph::open(&directory).unwrap();
    let proof = source(&graph);
    publish(&mut graph, &proof);
    let id = proof.proof().unwrap().manifest().artifact_id();
    let root = graph.content_root();
    drop(proof);
    drop(graph);
    let reopened = Graph::open(&directory).unwrap();
    assert!(reopened.contains(id).unwrap());
    assert_eq!(reopened.accepted_count(), 1);
    assert_eq!(reopened.content_root(), root);
    assert_eq!(
        reopened
            .program_manifest(id)
            .unwrap()
            .unwrap()
            .artifact_id(),
        id
    );
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn each_chunk_authenticates_before_persistence_and_complete_transfer_is_independently_checked()
 {
    if isolated(
        "intake::program::tests::each_chunk_authenticates_before_persistence_and_complete_transfer_is_independently_checked",
    ) {
        return;
    }
    receive_program(false).await;
}

#[tokio::test]
async fn paused_program_polling_yields_to_resource_release_within_the_original_work_budget() {
    if isolated(
        "intake::program::tests::paused_program_polling_yields_to_resource_release_within_the_original_work_budget",
    ) {
        return;
    }
    receive_program(true).await;
}

async fn receive_program(pause_once: bool) {
    if pause_once {
        crate::resources::tests::budget(false);
    }
    let producer = Graph::default();
    let source = source(&producer);
    let metadata = metadata(&source);
    let id = metadata.manifest.artifact_id();
    let peer = PeerId::random();
    let mut receiver = Graph::default();
    let mut questions = LocalQuestions::new(Some(accepting as fn(_) -> _));
    let mut intake = Intake::default();
    intake
        .enqueue_program(peer, metadata.clone(), &receiver, None)
        .unwrap();
    let first = source
        .proof()
        .unwrap()
        .input_chunk(0, 64, CHUNK_BYTES)
        .unwrap();
    assert!(
        intake
            .program_payload(peer, id, id, first.clone(), &receiver)
            .is_err()
    );
    let mut release = None;
    for _ in 0..10000 {
        let paused_input = if pause_once
            && release.is_none()
            && intake
                .programs
                .active
                .as_ref()
                .is_some_and(|root| matches!(root.stage, Stage::Fetch))
        {
            let before = receiver
                .ownership()
                .program_progress(&metadata.manifest)
                .unwrap();
            crate::resources::tests::budget(true);
            // The release is ready on this same runtime. A synchronous poll
            // loop must not starve it while spending the finite work budget.
            release = Some(tokio::spawn(async {
                crate::resources::tests::budget(false);
            }));
            Some(before)
        } else {
            None
        };
        match intake.advance(&mut receiver, &mut questions) {
            Progress::Accepted(ids) => {
                assert_eq!(ids, vec![id]);
                assert!(receiver.contains(id).unwrap());
                if pause_once {
                    let release = release.expect("the transfer must encounter resource pressure");
                    assert!(release.is_finished());
                    release.await.unwrap();
                }
                return;
            }
            Progress::Skipped(_, error) => panic!("valid program declined: {error}"),
            Progress::Waiting => {}
        }
        if let Some(before) = paused_input {
            assert!(
                crate::resources::adaptive::current()
                    .unwrap()
                    .budget
                    .paused
                    .is_some()
            );
            assert!(intake.program_request(&receiver).unwrap().is_none());
            assert_eq!(
                receiver
                    .ownership()
                    .program_progress(&metadata.manifest)
                    .unwrap(),
                before,
                "resource pause cannot authenticate or persist another chunk"
            );
            assert_eq!(receiver.accepted_count(), 0);
        }
        if !questions.available() {
            let completed = questions.completed().await;
            questions.finish(&receiver, completed);
        }
        if let Some((owner, root, requested, start, limit)) =
            intake.program_request(&receiver).unwrap()
        {
            assert_eq!((owner, root, requested), (peer, id, id));
            let chunk = source
                .proof()
                .unwrap()
                .input_chunk(start, limit.min(64), CHUNK_BYTES)
                .unwrap();
            let before = receiver
                .ownership()
                .program_progress(&metadata.manifest)
                .unwrap();
            let mut corrupt = chunk.clone();
            corrupt.records[0] = Command::Equal { left: 7, right: 7 };
            assert!(
                intake
                    .program_payload(peer, id, id, corrupt, &receiver)
                    .is_err()
            );
            assert_eq!(
                receiver
                    .ownership()
                    .program_progress(&metadata.manifest)
                    .unwrap(),
                before
            );
            intake
                .program_payload(peer, id, id, chunk, &receiver)
                .unwrap();
            assert!(
                !receiver.contains(id).unwrap(),
                "input authentication alone creates no checked membership"
            );
        }
        // Match the node's cooperative cadence; a resource hold is wall-clock
        // state and may need another runtime task before work can resume.
        tokio::time::sleep(crate::resources::adaptive::work_delay()).await;
    }
    panic!(
        "incremental program did not finish: {}",
        progress_state(&intake)
    );
}

#[tokio::test]
async fn authenticated_but_mathematically_invalid_input_never_enters_the_graph() {
    if isolated(
        "intake::program::tests::authenticated_but_mathematically_invalid_input_never_enters_the_graph",
    ) {
        return;
    }
    // Native pressure is exercised by governor/process tests. This case owns
    // the exact pause-before-input boundary and subsequent mathematical error.
    let commands = [
        Command::Equal { left: 0, right: 0 },
        Command::Seal { proof: 0 },
    ];
    let encoded = commands
        .iter()
        .map(|command| serde_json::to_vec(command).unwrap())
        .collect::<Vec<_>>();
    let question = CompiledQuestion::compile(&question_source()).unwrap();
    let statement = naome_proof::StatementId::of_canonical_formula(
        &question.positive_target().encode_canonical().unwrap(),
    )
    .unwrap();
    let manifest = Manifest {
        commands: 2,
        input_bytes: encoded.iter().map(|bytes| bytes.len() as u64).sum(),
        program_hash: encoded
            .iter()
            .fold([0; 32], |previous, bytes| command_hash(previous, bytes)),
        stream_root: encoded
            .iter()
            .rev()
            .fold([0; 32], |next, bytes| stream_hash(bytes, next)),
        conclusion: naome_proof::program::formula_hash(question.positive_target()),
        statement: *statement.as_bytes(),
    };
    let id = manifest.artifact_id();
    let peer = PeerId::random();
    let mut graph = Graph::default();
    let mut questions = LocalQuestions::new(Some(accepting as fn(_) -> _));
    let mut intake = Intake::default();
    intake
        .enqueue_program(
            peer,
            ProgramMetadata {
                manifest: manifest.clone(),
                question: Some(question_source()),
            },
            &graph,
            None,
        )
        .unwrap();
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    let completed = questions.completed().await;
    questions.finish(&graph, completed);
    intake.programs.active.as_mut().unwrap().budget =
        Observer::fixed_for_test(crate::resources::tests::snapshot(true));
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    assert!(intake.programs.active.as_ref().unwrap().allowed);
    assert!(intake.program_request(&graph).unwrap().is_none());
    assert!(graph.ownership().program_progress(&manifest).is_err());
    crate::resources::tests::budget(false);
    for _ in 0..1000 {
        match intake.advance(&mut graph, &mut questions) {
            Progress::Skipped(rejected, _) => {
                assert_eq!(rejected, id);
                assert!(!graph.contains(id).unwrap());
                assert_eq!(graph.accepted_count(), 0);
                return;
            }
            Progress::Accepted(_) => panic!("unproved formula was accepted"),
            Progress::Waiting => {}
        }
        if !questions.available() {
            let completed = questions.completed().await;
            questions.finish(&graph, completed);
        }
        if intake.program_request(&graph).unwrap().is_some() {
            intake
                .program_payload(
                    peer,
                    id,
                    id,
                    Chunk {
                        start: 0,
                        previous: [0; 32],
                        next: [0; 32],
                        records: commands.to_vec(),
                    },
                    &graph,
                )
                .unwrap();
        }
    }
    panic!("invalid program was not rejected");
}

#[tokio::test]
async fn cited_program_and_parent_commit_together_and_final_decline_publishes_neither() {
    if isolated(
        "intake::program::tests::cited_program_and_parent_commit_together_and_final_decline_publishes_neither",
    ) {
        return;
    }
    for decline in [false, true] {
        let mut producer = Graph::default();
        let proof = source(&producer);
        publish(&mut producer, &proof);
        let helper = proof.proof().unwrap().manifest().artifact_id();
        let statement = CompiledQuestion::compile(&question_source())
            .unwrap()
            .positive_target()
            .to_source();
        let parent=producer.author(&format!("goal = imp(all(y,mem(y,y)),{statement}) proof: p0 = cite(\"{}\") p1 = simp({statement},all(y,mem(y,y))) p2 = mp(p0,p1) return p2",crate::hex(proof.proof().unwrap().manifest().proof_id().as_bytes()))).unwrap();
        let root = ArtifactId::from_bytes(crate::object::id_bytes(&parent.artifact_id).unwrap());
        producer.ingest(parent.clone(), Instant::now()).unwrap();
        let mut receiver = Graph::default();
        let mut intake = Intake::default();
        let peer = PeerId::random();
        let calls = Arc::new(AtomicUsize::new(0));
        let decisions = calls.clone();
        let mut questions = LocalQuestions::new(Some(move |_: CompiledQuestion| {
            ready(Ok(!decline || decisions.fetch_add(1, Ordering::SeqCst) == 0))
        }));
        intake
            .enqueue_with_grant(
                peer,
                producer.describe(root).unwrap().unwrap(),
                &receiver,
                None,
            )
            .unwrap();
        let mut parent_sent = false;
        let mut helper_described = false;
        let mut terminal = false;
        for _ in 0..10000 {
            match intake.advance(&mut receiver, &mut questions) {
                Progress::Accepted(ids) => {
                    assert!(!decline);
                    assert_eq!(ids, vec![helper, root]);
                    assert!(receiver.contains(helper).unwrap() && receiver.contains(root).unwrap());
                    terminal = true;
                    break;
                }
                Progress::Skipped(_, error) => {
                    assert!(decline, "parent declined unexpectedly: {error}");
                    assert_eq!(receiver.accepted_count(), 0);
                    terminal = true;
                    break;
                }
                Progress::Waiting => {}
            }
            assert_eq!(
                receiver.accepted_count(),
                0,
                "a helper cannot be published early"
            );
            if !questions.available() {
                let completed = questions.completed().await;
                questions.finish(&receiver, completed);
            }
            for (owner, parent_id, id) in intake.needed() {
                if id == root && !parent_sent {
                    intake
                        .payload(owner, parent_id, id, parent.clone(), &receiver)
                        .unwrap();
                    parent_sent = true;
                } else if id == helper && !helper_described {
                    let mut metadata = metadata(&proof);
                    metadata.question = None;
                    intake
                        .enqueue_program_helper(owner, parent_id, metadata, &receiver)
                        .unwrap();
                    helper_described = true;
                }
            }
            if let Some((owner, parent_id, id, start, limit)) =
                intake.program_request(&receiver).unwrap()
            {
                assert_eq!((owner, parent_id, id), (peer, root, helper));
                let chunk = proof
                    .proof()
                    .unwrap()
                    .input_chunk(start, limit.min(128), CHUNK_BYTES)
                    .unwrap();
                intake
                    .program_payload(owner, parent_id, id, chunk, &receiver)
                    .unwrap();
            }
            tokio::time::sleep(crate::resources::adaptive::work_delay()).await;
        }
        assert!(
            terminal && parent_sent && helper_described,
            "terminal={terminal}, parent_sent={parent_sent}, helper_described={helper_described}: {}",
            progress_state(&intake)
        );
    }
}

mod composition;

mod grants;
