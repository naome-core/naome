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

fn question_source() -> String {
    crate::mocks::create_question(0)
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
    while work.advance(&budget()).unwrap() {}
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
            manifest.proof_id(),
            batch,
            Instant::now() + std::time::Duration::from_secs(60),
        )
        .unwrap();
}

#[test]
fn published_program_survives_catalog_validation_and_fresh_mathematical_replay() {
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
    let id = proof.proof().unwrap().manifest().proof_id();
    let root = graph.content_root();
    drop(proof);
    drop(graph);
    let reopened = Graph::open(&directory).unwrap();
    assert!(reopened.contains(id).unwrap());
    assert_eq!(reopened.accepted_count(), 1);
    assert_eq!(reopened.content_root(), root);
    assert_eq!(
        reopened.program_manifest(id).unwrap().unwrap().proof_id(),
        id
    );
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn each_chunk_authenticates_before_persistence_and_complete_transfer_is_independently_checked()
 {
    let producer = Graph::default();
    let source = source(&producer);
    let metadata = metadata(&source);
    let id = metadata.manifest.proof_id();
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
    for _ in 0..10000 {
        match intake.advance(&mut receiver, &mut questions) {
            Progress::Accepted(ids) => {
                assert_eq!(ids, vec![id]);
                assert!(receiver.contains(id).unwrap());
                return;
            }
            Progress::Skipped(_, error) => panic!("valid program declined: {error}"),
            Progress::Waiting => {}
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
    }
    panic!("incremental program did not finish");
}

#[tokio::test]
async fn authenticated_but_mathematically_invalid_input_never_enters_the_graph() {
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
    let id = manifest.proof_id();
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
    for decline in [false, true] {
        let mut producer = Graph::default();
        let proof = source(&producer);
        publish(&mut producer, &proof);
        let helper = proof.proof().unwrap().manifest().proof_id();
        let statement = CompiledQuestion::compile(&question_source())
            .unwrap()
            .positive_target()
            .to_source();
        let parent=producer.author(&format!("goal = imp(all(y,mem(y,y)),{statement}) proof: p0 = cite(\"{}\") p1 = simp({statement},all(y,mem(y,y))) p2 = mp(p0,p1) return p2",crate::hex(helper.as_bytes()))).unwrap();
        let root = ProofId::from_bytes(crate::object::id_bytes(&parent.proof_id).unwrap());
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
        }
        assert!(terminal && parent_sent && helper_described);
    }
}
