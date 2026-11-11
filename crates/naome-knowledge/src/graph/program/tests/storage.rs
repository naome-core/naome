use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
#[ignore = "Manual matched program storage measurement"]
fn measure_program_storage() {
    use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS};
    let root = std::env::temp_dir().join(format!("naome-program-measure-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let source = Graph::open(&root.join("source")).unwrap();
    let mut work = Work::open(&root.join("work.sqlite3")).unwrap();
    work.append_group(&[
        Command::Equal { left: 0, right: 0 },
        Command::Separation {
            predicate: 0,
            element: 0,
            source: 1,
            result: 2,
        },
    ])
    .unwrap();
    for group in (0..1798)
        .map(|i| Command::Equal { left: i, right: i })
        .collect::<Vec<_>>()
        .chunks(128)
    {
        work.append_group(group).unwrap();
    }
    work.append_group(&[Command::Seal { proof: 1 }]).unwrap();
    let budget = Budget {
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
    let checked = work.into_checked().unwrap();
    let proof = checked.proof().unwrap();
    let manifest = proof.manifest().clone();
    let receiver_path = root.join("receiver");
    let receiver = Graph::open(&receiver_path).unwrap();
    let store = receiver.ownership();
    let empty_bytes = program_directory_bytes(&receiver_path);
    let peak = Arc::new(AtomicU64::new(empty_bytes));
    let temporary_peak = Arc::new(AtomicU64::new(0));
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let (path, peak, temporary_peak, done) = (
            receiver_path.clone(),
            peak.clone(),
            temporary_peak.clone(),
            done.clone(),
        );
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                peak.fetch_max(program_directory_bytes(&path), Ordering::Relaxed);
                temporary_peak.fetch_max(program_temporary_bytes(&path), Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let start = Instant::now();
    store.start_program(&manifest).unwrap();
    let mut position = 0;
    while position < manifest.commands {
        let chunk = proof.input_chunk(position, 128, CHUNK_BYTES).unwrap();
        position = store.append_program(&manifest, &chunk).unwrap().commands;
    }
    let write_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    let mut position = 0;
    while position < manifest.commands {
        let chunk = store
            .program_chunk(&manifest, position, CHUNK_RECORDS, CHUNK_BYTES)
            .unwrap();
        assert!(!chunk.records.is_empty());
        position += chunk.records.len() as u64;
    }
    let read_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    for position in (0..manifest.commands).step_by(29).take(64) {
        assert_eq!(
            store
                .program_chunk(&manifest, position, 1, CHUNK_BYTES)
                .unwrap()
                .records
                .len(),
            1
        );
    }
    let small_reads_ms = start.elapsed().as_secs_f64() * 1000.0;
    let allocated_bytes = program_directory_bytes(&receiver_path);
    drop(store);
    drop(receiver);
    let start = Instant::now();
    let reopened = Graph::open(&receiver_path).unwrap();
    assert_eq!(
        reopened
            .ownership()
            .program_progress(&manifest)
            .unwrap()
            .commands,
        manifest.commands
    );
    let reopen_ms = start.elapsed().as_secs_f64() * 1000.0;
    done.store(true, Ordering::Relaxed);
    sampler.join().unwrap();
    println!(
        "program_storage {}",
        serde_json::json!({"commands":manifest.commands,"input_bytes":manifest.input_bytes,"write_ms":write_ms,"read_ms":read_ms,"small_reads_64_ms":small_reads_ms,"reopen_ms":reopen_ms,"empty_bytes":empty_bytes,"allocated_bytes":allocated_bytes,"sampled_peak_bytes":peak.load(Ordering::Relaxed),"sampled_temporary_peak_bytes":temporary_peak.load(Ordering::Relaxed)})
    );
    drop(reopened);
    drop(checked);
    drop(source);
    std::fs::remove_dir_all(root).unwrap();
}

fn program_directory_bytes(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.blocks() * 512)
        .sum()
}

fn program_temporary_bytes(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with(".checked-context-")
                || name.ends_with("-journal")
                || name.ends_with("-wal")
        })
        .filter_map(|entry| entry.metadata().ok())
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.blocks() * 512)
        .sum()
}

fn staged_fixture(references: usize) -> (Manifest, Chunk) {
    use naome_proof::program::{command_hash, encode_command, stream_hash};
    let mut commands = vec![Command::ProofReference { proof_id: [7; 32] }; references];
    commands.push(Command::Seal { proof: 0 });
    let encoded: Vec<_> = commands
        .iter()
        .map(|command| encode_command(command).unwrap())
        .collect();
    let manifest = Manifest {
        commands: commands.len() as u64,
        input_bytes: encoded.iter().map(|bytes| bytes.len() as u64).sum(),
        program_hash: encoded
            .iter()
            .fold([0; 32], |hash, bytes| command_hash(hash, bytes)),
        stream_root: encoded
            .iter()
            .rev()
            .fold([0; 32], |hash, bytes| stream_hash(bytes, hash)),
        conclusion: [0; 32],
        statement: [0; 32],
    };
    (
        manifest,
        Chunk {
            start: 0,
            previous: [0; 32],
            next: [0; 32],
            records: commands,
        },
    )
}

#[test]
fn interrupted_program_append_recovers_previous_prefix() {
    const CASE: &str =
        "graph::program::tests::storage::interrupted_program_append_recovers_previous_prefix";
    let (manifest, chunk) = staged_fixture(20);
    if let Some(path) = std::env::var_os("NAOME_TEST_PROGRAM_APPEND_DIRECTORY") {
        let graph = Graph::open(std::path::Path::new(&path)).unwrap();
        let store = graph.ownership();
        store.start_program(&manifest).unwrap();
        store.append_program(&manifest, &chunk).unwrap();
        panic!("append interruption did not occur");
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CASE, "--nocapture"])
        .env("NAOME_TEST_PROGRAM_APPEND_DIRECTORY", &directory.0)
        .env("NAOME_TEST_EXIT_PROGRAM_APPEND", "1")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(77));
    let graph = Graph::open(&directory.0).unwrap();
    let store = graph.ownership();
    assert_eq!(store.program_progress(&manifest).unwrap().commands, 0);
    store
        .append_program(&manifest, &chunk)
        .unwrap()
        .require_complete(&manifest)
        .unwrap();
    assert_eq!(
        store
            .program_chunk(&manifest, 0, CHUNK_RECORDS, CHUNK_BYTES)
            .unwrap(),
        chunk
    );
    drop(store);
    drop(graph);
    let reopened = Graph::open(&directory.0).unwrap();
    reopened
        .ownership()
        .program_progress(&manifest)
        .unwrap()
        .require_complete(&manifest)
        .unwrap();
}

#[test]
fn full_program_catalog_preserves_previous_prefix() {
    let directory = crate::checkpoint::tests::Directory::new();
    let graph = Graph::open(&directory.0).unwrap();
    let store = graph.ownership();
    let (manifest, chunk) = staged_fixture(512);
    store.start_program(&manifest).unwrap();
    let before = store.program_progress(&manifest).unwrap();
    store.limit_current_pages();
    assert!(matches!(
        store.append_program(&manifest, &chunk),
        Err(crate::Error::ExecutionLimit)
    ));
    assert_eq!(store.program_progress(&manifest).unwrap(), before);
    drop(store);
    drop(graph);
    let reopened = Graph::open(&directory.0).unwrap();
    assert_eq!(
        reopened.ownership().program_progress(&manifest).unwrap(),
        before
    );
}
