use super::*;

#[test]
fn only_the_last_generation_releases_ownership_despite_an_inherited_descriptor() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    // A concurrent spawn can temporarily inherit a CLOEXEC descriptor. That
    // descriptor is not a live disposable-index generation or a worker lease.
    let inherited = storage._lease.0.file().try_clone().unwrap();
    let successor = storage.successor().unwrap();
    drop(storage);
    assert_eq!(
        IndexStorage::open(&directory.0, "questions").err().unwrap(),
        crate::Error::from(crate::InputFault::DisposableIndexOwned),
    );
    successor.write([1; 32], b"still owned").unwrap();
    drop(successor);
    let reopened = IndexStorage::open(&directory.0, "questions").unwrap();
    reopened.write([2; 32], b"new owner").unwrap();
    assert!(inherited.metadata().unwrap().is_file());
}

#[test]
fn startup_prunes_only_marked_generations_and_preserves_unrelated_files() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    storage.write([1; 32], b"current disposable bytes").unwrap();
    let root = storage.path.parent().unwrap();
    let abandoned = root.join(".disposable-questions-abandoned.index");
    fs::copy(&storage.path, &abandoned).unwrap();
    let foreign = root.join(".disposable-questions-unrelated.index");
    fs::write(&foreign, b"unrelated file with a different header").unwrap();
    let before = fs::read(&foreign).unwrap();
    let incomplete = root.join(".disposable-questions-incomplete.index");
    fs::write(&incomplete, b"untouched bytes").unwrap();
    drop(storage);
    let _successor = IndexStorage::open(&directory.0, "questions").unwrap();
    assert!(!abandoned.exists());
    assert_eq!(fs::read(&foreign).unwrap(), before);
    assert_eq!(fs::read(&incomplete).unwrap(), b"untouched bytes");
}

fn address(index: u64) -> [u8; 32] {
    let mut value = [0; 32];
    value[..8].copy_from_slice(&index.to_be_bytes());
    value
}

#[test]
fn growing_index_preserves_values_and_rejects_conflicting_writes() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    for i in 0u64..1024 {
        let value = i.to_be_bytes();
        storage.write(address(i), &value).unwrap();
    }
    for i in (0u64..1024).rev() {
        assert_eq!(storage.read(address(i), 8).unwrap(), i.to_be_bytes());
    }
    storage.write(address(10), &10u64.to_be_bytes()).unwrap();
    assert_eq!(
        storage.write(address(10), b"wrong"),
        Err(ContextError::Corrupt)
    );
    assert_eq!(storage.read(address(10), 7), Err(ContextError::Limit));
}

#[test]
fn concurrent_writers_and_readers_preserve_all_inserted_values() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    std::thread::scope(|scope| {
        for worker in 0u64..4 {
            let storage = storage.clone();
            scope.spawn(move || {
                for sequence in 0u64..128 {
                    let id = worker * 128 + sequence;
                    storage.write(address(id), &id.to_be_bytes()).unwrap();
                    assert_eq!(storage.read(address(id), 8).unwrap(), id.to_be_bytes());
                }
            });
        }
    });
    for id in 0u64..512 {
        assert_eq!(storage.read(address(id), 8).unwrap(), id.to_be_bytes());
    }
}

#[test]
fn growth_refuses_an_exhausted_reservation_before_changing_the_index() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    for i in 0u64..52 {
        storage.write(address(i), &i.to_be_bytes()).unwrap();
    }
    let before = storage.allocated_bytes().unwrap();
    crate::resources::with_disk_available(0, || {
        assert_eq!(storage.write(address(52), b"new"), Err(ContextError::Limit));
    });
    assert_eq!(storage.allocated_bytes().unwrap(), before);
    assert_eq!(storage.read(address(51), 8).unwrap(), 51u64.to_be_bytes());
    storage.write(address(52), b"new").unwrap();
    assert_eq!(storage.read(address(52), 3).unwrap(), b"new");
}

#[test]
fn failed_record_write_halts_the_generation() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    storage
        .write(address(1), b"durable within this generation")
        .unwrap();
    TEST_FAIL_AFTER_RECORD.with(|fail| fail.set(true));
    let error = storage.write(address(2), b"partial").unwrap_err();
    assert!(
        matches!(&error, ContextError::Storage(naome_proof::ContextStorageFailure::System(Some(code))) if *code == nix::libc::ENOSPC)
    );
    assert_eq!(storage.read(address(1), 128), Err(error));
}

#[test]
fn value_corruption_is_detected_even_if_metadata_is_unchanged_to_the_reader() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    storage.write(address(1), b"checked value").unwrap();
    {
        let mut guard = storage.state.lock().unwrap();
        let state = guard.as_mut().unwrap();
        state.file.write_all_at(b"X", state.end - 1).unwrap();
        // Simulate damage that is not observable through metadata alone.
        state.generation = crate::storage::FileGeneration::of(&state.file.metadata().unwrap());
    }
    assert_eq!(storage.read(address(1), 32), Err(ContextError::Corrupt));
}

#[test]
fn content_addressed_records_detect_corruption_without_a_second_digest() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    let value = b"authenticated registry bytes";
    let mut hash = Sha256::new();
    hash.update(b"naome:checked-map:storage:v1\0");
    hash.update(value);
    let key: [u8; 32] = hash.finalize().into();
    storage.write(key, value).unwrap();
    assert_eq!(storage.read(key, value.len()).unwrap(), value);
    {
        let mut guard = storage.state.lock().unwrap();
        let state = guard.as_mut().unwrap();
        state.file.write_all_at(b"X", state.end - 1).unwrap();
        state.generation = crate::storage::FileGeneration::of(&state.file.metadata().unwrap());
    }
    assert_eq!(storage.read(key, value.len()), Err(ContextError::Corrupt));
}

#[test]
fn malformed_record_header_is_rejected_before_reading_the_value() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    let key = address(1);
    storage.write(key, b"record").unwrap();
    {
        let mut guard = storage.state.lock().unwrap();
        let state = guard.as_mut().unwrap();
        let offset = state.find(&key).unwrap().unwrap().offset;
        state.file.write_all_at(&[2], offset + 40).unwrap();
        state.generation = crate::storage::FileGeneration::of(&state.file.metadata().unwrap());
    }
    assert_eq!(storage.read(key, 6), Err(ContextError::Corrupt));
}

#[test]
fn fingerprint_collisions_compare_the_complete_address() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    let (first, second) = {
        let guard = storage.state.lock().unwrap();
        let state = guard.as_ref().unwrap();
        let first = address(0);
        let bucket = state.hash.hash_one(first) & (INITIAL_SLOTS - 1);
        let second = (1..10_000)
            .map(address)
            .find(|candidate| state.hash.hash_one(candidate) & (INITIAL_SLOTS - 1) == bucket)
            .unwrap();
        (first, second)
    };
    storage.write(first, b"first").unwrap();
    storage.write(second, b"second").unwrap();
    {
        let mut guard = storage.state.lock().unwrap();
        let state = guard.as_mut().unwrap();
        let segment = state.segments[0];
        let (bucket, _) = state
            .lookup(segment.table, segment.capacity, &first)
            .unwrap();
        let fingerprint = ((state.hash.hash_one(second) >> 32) as u32).to_be_bytes();
        state
            .file
            .write_all_at(
                &fingerprint,
                state.slot_offset(segment.table, bucket).unwrap(),
            )
            .unwrap();
        state.generation = crate::storage::FileGeneration::of(&state.file.metadata().unwrap());
    }
    assert_eq!(storage.read(second, 6).unwrap(), b"second");
}

#[test]
fn long_collision_runs_grow_before_exceeding_the_lookup_limit() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    let (key, previous_segments) = {
        let mut guard = storage.state.lock().unwrap();
        let state = guard.as_mut().unwrap();
        while state.segments[state.segment_count - 1].capacity < 2048 {
            state.grow().unwrap();
        }
        let active = state.segments[state.segment_count - 1];
        let mut run = vec![0; 512 * SLOT_BYTES as usize];
        for slot in run.chunks_exact_mut(SLOT_BYTES as usize) {
            slot[11] = 1;
        }
        state
            .file
            .write_all_at(&run, state.slot_offset(active.table, 1).unwrap())
            .unwrap();
        state
            .file
            .write_all_at(
                &run[..511 * SLOT_BYTES as usize],
                state
                    .slot_offset(active.table, active.capacity - 511)
                    .unwrap(),
            )
            .unwrap();
        state.segments[state.segment_count - 1].count = MAX_PROBES - 1;
        state.generation = crate::storage::FileGeneration::of(&state.file.metadata().unwrap());
        let key = (0..100_000)
            .map(address)
            .find(|candidate| {
                let hash = state.hash.hash_one(candidate);
                hash & (active.capacity - 1) == 0 && hash >> 32 != 0
            })
            .unwrap();
        (key, state.segment_count)
    };
    storage.write(key, b"reachable").unwrap();
    assert_eq!(
        storage
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .segment_count,
        previous_segments + 1
    );
    assert_eq!(storage.read(key, 9).unwrap(), b"reachable");
}

#[test]
fn external_file_changes_are_rejected_before_reading() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    storage.write(address(1), b"checked value").unwrap();
    let file = OpenOptions::new().write(true).open(&storage.path).unwrap();
    file.set_len(file.metadata().unwrap().len() + 1).unwrap();
    assert_eq!(storage.read(address(1), 32), Err(ContextError::Corrupt));
}

#[test]
fn interrupted_index_write_is_discarded_and_a_new_generation_opens() {
    const CASE: &str =
        "index_storage::tests::interrupted_index_write_is_discarded_and_a_new_generation_opens";
    if let Some(path) = std::env::var_os("NAOME_TEST_INDEX_DIRECTORY") {
        let storage = IndexStorage::open(Path::new(&path), "questions").unwrap();
        for i in 0u64..52 {
            storage.write(address(i), &i.to_be_bytes()).unwrap();
        }
        let marker = std::env::var_os("NAOME_TEST_EXIT_INDEX_WRITE").unwrap();
        fs::write(marker, b"cut").unwrap();
        storage.write(address(52), b"interrupted").unwrap();
        panic!("index interruption did not occur");
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CASE, "--nocapture"])
        .env("NAOME_TEST_INDEX_DIRECTORY", &directory.0)
        .env("NAOME_TEST_EXIT_INDEX_WRITE", directory.0.join("cut"))
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(79));
    let root = directory.0.join("research");
    assert_eq!(
        fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|s| s == "index"))
            .count(),
        1
    );
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    assert_eq!(
        fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|s| s == "index"))
            .count(),
        1
    );
    storage.write(address(2), b"rebuilt").unwrap();
    assert_eq!(storage.read(address(2), 16).unwrap(), b"rebuilt");
}

#[test]
fn dropping_a_replaced_index_never_deletes_the_replacement() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    let path = storage.path.clone();
    let replacement = directory.0.join("replacement");
    fs::write(&replacement, b"unrelated replacement").unwrap();
    fs::rename(&replacement, &path).unwrap();
    assert_eq!(storage.read([1; 32], 4096), Err(ContextError::Corrupt));
    drop(storage);
    assert_eq!(fs::read(&path).unwrap(), b"unrelated replacement");
}
