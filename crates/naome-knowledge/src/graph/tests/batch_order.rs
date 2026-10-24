use super::*;

#[test]
fn typed_certificate_projection_preserves_exact_envelope_and_derived_question() {
    let mut graph = Graph::default();
    let object = introduce(&mut graph);
    let id = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
    let Some(crate::object::ProofTransfer::Certificate(transferred)) = graph.transfer(id).unwrap()
    else {
        panic!("certificate transfer missing")
    };
    assert_eq!(transferred, object);
    let Some(crate::object::ProofDescription::Certificate(description)) =
        graph.description(id).unwrap()
    else {
        panic!("certificate description missing")
    };
    let (described, statement, question) = description.compile().unwrap();
    assert_eq!(described, id);
    assert_eq!(
        statement.as_bytes(),
        &id_bytes(&object.statement_id).unwrap()
    );
    assert_eq!(
        question.resolution_id(),
        naome_authoring::CompiledQuestion::compile("goal=all(x,eq(x,x))")
            .unwrap()
            .resolution_id()
    );
}

#[test]
fn reverse_arrival_dependency_chain_is_checked_once_and_published_atomically() {
    let mut producer = Graph::default();
    let mut objects = vec![introduce(&mut producer)];
    for _ in 1..32 {
        let next = citation(&producer, objects.last().unwrap());
        producer.ingest(next.clone(), Instant::now()).unwrap();
        objects.push(next);
    }
    let root = ProofId::from_bytes(id_bytes(&objects.last().unwrap().proof_id).unwrap());
    let mut receiver = Graph::default();
    let question = naome_authoring::CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let candidates = objects
        .iter()
        .rev()
        .cloned()
        .map(|object| {
            let candidate = object.prepare().unwrap();
            (candidate.id, candidate)
        })
        .collect();
    let visits = batch::dependency_visits();
    let batch = receiver.prepare_batch(root, candidates, &question).unwrap();
    assert_eq!(batch::dependency_visits() - visits, 31);
    assert_eq!(receiver.accepted_count(), 0);
    assert_eq!(receiver.checker_calls(), (0, 32));
    let admitted = receiver
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_eq!(admitted.len(), 32);
    assert_eq!(receiver.content_root(), producer.content_root());
    for object in objects {
        let id = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
        assert_eq!(receiver.object(id).unwrap(), Some(object));
    }
}

#[test]
#[ignore = "Manual matched architecture measurement"]
fn measure_dependency_batch_and_startup() {
    for size in [16, 64, 128] {
        let mut producer = Graph::default();
        let mut objects = vec![introduce(&mut producer)];
        for _ in 1..size {
            let next = citation(&producer, objects.last().unwrap());
            producer.ingest(next.clone(), Instant::now()).unwrap();
            objects.push(next);
        }
        let expected = producer.content_root();
        let directory = producer.ownership().directory().to_owned();
        // Keep this original owner for the bounded batch fixtures; reopening
        // measures a separate directory so ownership never overlaps.
        let question = naome_authoring::CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
        let root = ProofId::from_bytes(id_bytes(&objects.last().unwrap().proof_id).unwrap());
        for repeat in 0..3 {
            let receiver = Graph::default();
            let candidates = objects
                .iter()
                .rev()
                .cloned()
                .map(|object| {
                    let candidate = object.prepare().unwrap();
                    (candidate.id, candidate)
                })
                .collect();
            let visits = batch::dependency_visits();
            let start = Instant::now();
            let batch = receiver.prepare_batch(root, candidates, &question).unwrap();
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(receiver.accepted_count(), 0);
            assert_eq!(receiver.checker_calls(), (0, size as u64));
            drop(batch);
            println!(
                "architecture_batch size={size} repeat={repeat} prepare_ms={elapsed_ms:.3} dependency_visits={}",
                batch::dependency_visits() - visits
            );
        }
        // Copy canonical history to an owned fixture because Graph::default
        // intentionally removes its temporary directory on last-owner drop.
        let replay_directory =
            directory.with_file_name(format!("architecture-replay-{}-{size}", std::process::id()));
        std::fs::create_dir(&replay_directory).unwrap();
        {
            let mut receiver = Graph::open(&replay_directory).unwrap();
            for object in objects {
                receiver.ingest(object, Instant::now()).unwrap();
            }
        }
        for repeat in 0..3 {
            let scans = crate::store::set_scan_count();
            let reads = crate::store::payload_reads();
            let start = Instant::now();
            let reopened = Graph::open(&replay_directory).unwrap();
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(reopened.content_root(), expected);
            println!(
                "architecture_startup size={size} repeat={repeat} open_ms={elapsed_ms:.3} integrity_passes={} payload_reads={}",
                crate::store::set_scan_count() - scans,
                crate::store::payload_reads() - reads
            );
            drop(reopened);
        }
        std::fs::remove_dir_all(replay_directory).unwrap();
    }
}
