use super::*;
use crate::resources::adaptive::{self, Budget, Observed, Selection, Snapshot};
use naome_proof::program::Command;

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
    let receiver = Graph::default();
    let store = receiver.ownership();
    store.start_program(&manifest).unwrap();
    let chunk = proof
        .proof()
        .unwrap()
        .input_chunk(0, CHUNK_RECORDS, CHUNK_BYTES)
        .unwrap();
    assert_eq!(chunk.records.len(), commands.len());
    store.append_program(&manifest, &chunk).unwrap();
    let mut check = ProgramCheck::open(&receiver, manifest.clone()).unwrap();

    budget.batch_steps = 1;
    let mut snapshot = Snapshot {
        selection: Selection::default(),
        observed: Observed::default(),
        budget,
        timestamp_ms: 0,
        pid: std::process::id(),
    };
    snapshot.budget.paused = Some("test pressure".into());
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
    assert!(!receiver.contains(manifest.proof_id()).unwrap());

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
    assert!(!receiver.contains(manifest.proof_id()).unwrap());
}
