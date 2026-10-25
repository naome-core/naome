use super::*;

#[test]
fn startup_prunes_only_marked_generations_and_preserves_unrelated_files() {
    let directory = crate::checkpoint::tests::Directory::new();
    let storage = IndexStorage::open(&directory.0, "questions").unwrap();
    storage.write([1; 32], b"current disposable bytes").unwrap();
    let root = storage.path.parent().unwrap();
    let abandoned = root.join(".disposable-questions-abandoned.sqlite3");
    fs::copy(&storage.path, &abandoned).unwrap();
    let foreign = root.join(".disposable-questions-unrelated.sqlite3");
    let connection = Connection::open(&foreign).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('preserve');",
        )
        .unwrap();
    drop(connection);
    let before = fs::read(&foreign).unwrap();
    let incomplete = root.join(".disposable-questions-incomplete.sqlite3");
    fs::write(&incomplete, b"untouched bytes").unwrap();
    drop(storage);
    let _successor = IndexStorage::open(&directory.0, "questions").unwrap();
    assert!(!abandoned.exists());
    assert_eq!(fs::read(&foreign).unwrap(), before);
    assert_eq!(fs::read(&incomplete).unwrap(), b"untouched bytes");
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
