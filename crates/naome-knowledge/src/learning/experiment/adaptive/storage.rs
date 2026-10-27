//! Spill exact retained blobs between training and final inference.
use super::*;
pub(super) fn spill(store: &mut Store, path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    let mut entries = Vec::new();
    for ((hash, index), bytes) in std::mem::take(&mut store.inner.0) {
        let name = format!("{hash}-{index}.bin");
        std::fs::write(path.join(&name), bytes).unwrap();
        entries.push((hash, index, name));
    }
    write(&path.join("manifest.json"), &entries);
}
pub(super) fn restore(store: &mut Store, path: &Path) {
    assert!(store.inner.0.is_empty());
    let entries: Vec<(String, usize, String)> =
        serde_json::from_slice(&std::fs::read(path.join("manifest.json")).unwrap()).unwrap();
    for (hash, index, name) in entries {
        assert_eq!(name, format!("{hash}-{index}.bin"));
        assert!(
            store
                .inner
                .0
                .insert((hash, index), std::fs::read(path.join(name)).unwrap())
                .is_none()
        );
    }
}

#[cfg(test)]
mod tests;
