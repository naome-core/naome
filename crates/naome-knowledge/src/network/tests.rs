use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct ConfigFile(PathBuf);

impl ConfigFile {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-knowledge-config-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> PathBuf {
        self.0.join("config.json")
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn full_producer_queue_loads_with_worst_case_json_escaping() {
    let file = ConfigFile::new();
    let sources = vec!["\u{0001}".repeat(crate::MAX_PROOF_BYTES / 32); 32];
    let encoded = serde_json::to_vec_pretty(&json!({
        "directory": "node",
        "listen": "/ip4/127.0.0.1/tcp/0",
        "peers": [],
        "producer_sources": sources
    }))
    .unwrap();
    assert!(encoded.len() > 6 * crate::MAX_PROOF_BYTES);
    assert!(encoded.len() < MAX_CONFIG_BYTES);
    std::fs::write(file.path(), &encoded).unwrap();
    let loaded = read_config(&file.path()).unwrap();
    assert_eq!(loaded.producer_sources, sources);
    assert_eq!(loaded.directory, file.0.join("node"));
}

#[test]
fn oversized_configuration_still_rejects_before_decoding() {
    let file = ConfigFile::new();
    std::fs::write(file.path(), vec![b' '; MAX_CONFIG_BYTES + 1]).unwrap();
    assert_eq!(read_config(&file.path()).err().unwrap(), "file byte limit");
}
