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
    for i in 0u64..32 {
        storage.write(address(i), &i.to_be_bytes()).unwrap();
    }
    let before = storage.allocated_bytes().unwrap();
    crate::resources::with_disk_available(0, || {
        assert_eq!(storage.write(address(32), b"new"), Err(ContextError::Limit));
    });
    assert_eq!(storage.allocated_bytes().unwrap(), before);
    assert_eq!(storage.read(address(31), 8).unwrap(), 31u64.to_be_bytes());
    storage.write(address(32), b"new").unwrap();
    assert_eq!(storage.read(address(32), 3).unwrap(), b"new");
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
        for i in 0u64..32 {
            storage.write(address(i), &i.to_be_bytes()).unwrap();
        }
        let marker = std::env::var_os("NAOME_TEST_EXIT_INDEX_WRITE").unwrap();
        fs::write(marker, b"cut").unwrap();
        storage.write(address(32), b"interrupted").unwrap();
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
