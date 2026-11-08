use super::*;
#[test]
fn spilled_checkpoint_chunks_restore_exactly_and_corruption_fails_artifact_checking() {
    let path = std::env::temp_dir().join(format!(
        "naome-matched-artifacts-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let bytes = vec![19; 1_100_003];
    let mut store = Store::default();
    let blob = artifact::save(&mut store, &bytes).unwrap();
    spill(&mut store, &path);
    assert!(store.inner.0.is_empty());
    restore(&mut store, &path);
    assert_eq!(artifact::load(&mut store, &blob).unwrap(), bytes);
    store.inner.0.clear();
    let chunk = path.join(format!("{}-0.bin", blob.sha256));
    let mut corrupted = std::fs::read(&chunk).unwrap();
    corrupted[0] ^= 1;
    std::fs::write(chunk, corrupted).unwrap();
    restore(&mut store, &path);
    assert!(artifact::load(&mut store, &blob).is_err());
    std::fs::remove_dir_all(path).unwrap();
}
