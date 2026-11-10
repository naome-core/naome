use super::*;
use crate::resources::adaptive::{self, Budget, Observed, Selection, Snapshot};
use naome_proof::program::Command;
mod storage;

#[test]
fn bounded_input_import_preserves_single_step_checking_and_pause() {
    const CASE: &str =
        "graph::program::tests::bounded_input_import_preserves_single_step_checking_and_pause";
    if std::env::var_os("NAOME_PROGRAM_IMPORT_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_PROGRAM_IMPORT_TEST", "1")
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

    let source = Graph::default();
    let mut work = Work::open(&source.ownership().directory().join("source.sqlite3")).unwrap();
    let mut commands = vec![
        Command::Equal { left: 0, right: 0 },
        Command::Separation {
            predicate: 0,
            element: 0,
            source: 1,
            result: 2,
        },
    ];
    for premise in 1..257 {
        commands.push(Command::Generalization {
            premise,
            variable: 1,
        });
    }
    commands.push(Command::Seal { proof: 1 });
    work.append_group(&commands).unwrap();
    let mut budget = Budget {
        memory_bytes: 256 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 32768,
        batch_steps: 128,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    while work.advance(&budget, source.checked_context()).unwrap() {}
    while !work.prepare_export(&budget).unwrap() {}
    let proof = work.into_checked().unwrap();
    let manifest = proof.proof().unwrap().manifest().clone();
    let directory = crate::checkpoint::tests::Directory::new();
    let receiver = Graph::open(&directory.0).unwrap();
    let store = receiver.ownership();
    store.start_program(&manifest).unwrap();
    let chunk = proof
        .proof()
        .unwrap()
        .input_chunk(0, CHUNK_RECORDS, CHUNK_BYTES)
        .unwrap();
    assert_eq!(chunk.records.len(), commands.len());
    let mut position = 0;
    while position < manifest.commands {
        let part = proof
            .proof()
            .unwrap()
            .input_chunk(position, 64, CHUNK_BYTES)
            .unwrap();
        position = store.append_program(&manifest, &part).unwrap().commands;
    }
    for start in [
        0,
        1,
        15,
        16,
        17,
        63,
        64,
        65,
        127,
        128,
        manifest.commands - 1,
        manifest.commands,
    ] {
        for records in [1, 7, CHUNK_RECORDS] {
            assert_eq!(
                store
                    .program_chunk(&manifest, start, records, CHUNK_BYTES)
                    .unwrap(),
                proof
                    .proof()
                    .unwrap()
                    .input_chunk(start, records, CHUNK_BYTES)
                    .unwrap(),
            );
        }
    }
    let mut check = ProgramCheck::open(&receiver, manifest.clone()).unwrap();

    budget.batch_steps = 1;
    let mut snapshot = Snapshot {
        selection: Selection::default(),
        observed: Observed::default(),
        budget,
        timestamp_ms: 0,
        pid: std::process::id(),
    };
    snapshot.budget.paused = Some(crate::PauseReason::MemoryPressure);
    adaptive::publish(snapshot.clone());
    assert!(
        check
            .advance(&receiver, receiver.checked_context())
            .unwrap()
            .is_none()
    );
    assert_eq!(check.work.as_ref().unwrap().status().unwrap().commands, 0);

    snapshot.budget.paused = None;
    adaptive::publish(snapshot);
    assert!(
        check
            .advance(&receiver, receiver.checked_context())
            .unwrap()
            .is_none()
    );
    let imported = check.work.as_ref().unwrap().status().unwrap();
    assert_eq!(
        imported.commands,
        commands.len() as u64,
        "one bounded input group must not become one transaction per checker step"
    );
    assert_eq!(imported.checked_commands, 0);
    assert!(!receiver.contains(manifest.artifact_id()).unwrap());

    // Reopening retains imported input without treating it as a checked proof.
    drop(check);
    let mut check = ProgramCheck::open(&receiver, manifest.clone()).unwrap();
    assert_eq!(
        check.work.as_ref().unwrap().status().unwrap().commands,
        commands.len() as u64
    );
    assert!(
        check
            .advance(&receiver, receiver.checked_context())
            .unwrap()
            .is_none()
    );
    assert!(
        check
            .work
            .as_ref()
            .unwrap()
            .status()
            .unwrap()
            .checked_commands
            <= 1
    );
    let checked = (0..10_000)
        .find_map(|_| {
            check
                .advance(&receiver, receiver.checked_context())
                .unwrap()
        })
        .expect("single-step mathematical checking completes");
    assert_eq!(checked.proof().unwrap().manifest(), &manifest);
    assert!(!receiver.contains(manifest.artifact_id()).unwrap());
    drop(checked);
    drop(check);
    drop(store);
    drop(receiver);
    let database =
        rusqlite::Connection::open(directory.0.join(crate::store::DATABASE_FILE)).unwrap();
    let original: Vec<u8> = database
        .query_row(
            "SELECT chunk FROM program_input WHERE position=0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    database
        .execute(
            "UPDATE program_input SET chunk=zeroblob(length(chunk)) WHERE position=0",
            [],
        )
        .unwrap();
    drop(database);
    assert!(matches!(
        Graph::open(&directory.0),
        Err(crate::Error::InputFault(
            crate::InputFault::CatalogProgramInputHash
        ))
    ));
    let database =
        rusqlite::Connection::open(directory.0.join(crate::store::DATABASE_FILE)).unwrap();
    database
        .execute(
            "UPDATE program_input SET chunk=?1,input_before=input_before+1 WHERE position=0",
            [&original],
        )
        .unwrap();
    drop(database);
    assert!(matches!(
        Graph::open(&directory.0),
        Err(crate::Error::InputFault(
            crate::InputFault::CatalogProgramInputHash
        ))
    ));
}

#[test]
fn learning_keeps_the_exact_checked_program_without_projecting_a_certificate() {
    let mut graph = Graph::default();
    let source = crate::learning::tests::own_solution();
    let question = crate::learning::tests::own_question();
    let q = naome_checker::question::ResearchQuestion::from_hex(&question).unwrap();
    let (root, batch) = graph
        .prepare_generated(&source.source, &source.helpers, &q)
        .unwrap();
    graph
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
        .unwrap();
    let mut work = Work::open(
        &graph
            .ownership()
            .directory()
            .join("learning-program.sqlite3"),
    )
    .unwrap();
    let unused = (0..1800)
        .map(|i| Command::Equal { left: i, right: i })
        .collect::<Vec<_>>();
    for group in unused.chunks(128) {
        work.append_group(group).unwrap();
    }
    work.append_group(&[
        Command::ProofReference {
            proof_id: crate::object::id_bytes(&source.proof_id).unwrap(),
        },
        Command::Seal { proof: 1800 },
    ])
    .unwrap();
    let budget = Budget {
        memory_bytes: 256 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 32768,
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
    assert!(manifest.input_bytes > 8 * 1024);
    let store = graph.ownership();
    store.start_program(&manifest).unwrap();
    loop {
        let progress = store.program_progress(&manifest).unwrap();
        if progress.commands == manifest.commands {
            break;
        }
        store
            .append_program(
                &manifest,
                &proof
                    .input_chunk(progress.commands, 128, CHUNK_BYTES)
                    .unwrap(),
            )
            .unwrap();
    }
    let mut admission = graph.begin_program_admission(&checked).unwrap();
    while !admission.advance(&graph, &checked, 128).unwrap() {}
    let batch = admission.finish(&graph, &checked).unwrap();
    graph
        .commit_batch(
            manifest.artifact_id(),
            batch,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
    assert!(
        graph
            .learning_certificate(manifest.artifact_id())
            .unwrap()
            .is_none()
    );
    let packet = graph
        .peer_program(manifest.clone())
        .unwrap()
        .expect("bounded native program");
    assert_eq!(packet.manifest, manifest);
    assert_eq!(packet.commands().unwrap().len(), 1802);
    assert_eq!(packet.target().unwrap(), *q.proved_target());
    let mut damaged = packet;
    damaged.manifest.stream_root[0] ^= 1;
    assert!(damaged.target().is_err());
}

#[test]
fn program_preparation_defers_new_checked_copies_until_admission_releases() {
    if std::env::var_os("NAOME_PROGRAM_COMPACTION_TEST").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "graph::program::tests::program_preparation_defers_new_checked_copies_until_admission_releases",
                "--nocapture",
            ])
            .env("NAOME_PROGRAM_COMPACTION_TEST", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
        );
        return;
    }
    let mut graph = Graph {
        next_compaction: 0,
        ..Graph::default()
    };
    let initial = graph.checked_storage.clone();
    let epoch = initial.copy_epoch().unwrap();

    // A new copy would invalidate a live preparation before its next quantum.
    graph.maintain_checked_storage_with_admission(true).unwrap();
    assert!(graph.compaction.is_none());
    assert!(std::sync::Arc::ptr_eq(&initial, &graph.checked_storage));
    assert_eq!(initial.copy_epoch().unwrap(), epoch);

    for _ in 0..32 {
        graph
            .maintain_checked_storage_with_admission(false)
            .unwrap();
        if !std::sync::Arc::ptr_eq(&initial, &graph.checked_storage) {
            return;
        }
    }
    panic!("copy should start after the program releases admission");
}
