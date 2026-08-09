use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_storage::{JournalError, ProofDagJournal};

const LOCK_PROBE_ENV: &str = "NAOME_JOURNAL_LOCK_PROBE";
static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-storage-lock-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!("temporary test directory failed: {source}"),
            }
        }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

#[test]
fn exclusive_lock_child_probe() {
    let Some(path) = env::var_os(LOCK_PROBE_ENV) else {
        return;
    };
    assert!(matches!(
        ProofDagJournal::open(PathBuf::from(path)),
        Err(JournalError::Locked)
    ));
    println!("NAOME_JOURNAL_LOCK_PROBE_OK");
}

#[test]
fn exclusive_lock_is_enforced_across_processes() {
    let directory = TestDirectory::new();
    let journal = ProofDagJournal::create(&directory.path).unwrap();
    let output = Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg("exclusive_lock_child_probe")
        .arg("--nocapture")
        .env(LOCK_PROBE_ENV, &directory.path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("NAOME_JOURNAL_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(journal);
    assert!(ProofDagJournal::open(&directory.path).is_ok());
}
