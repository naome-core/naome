use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_chain::ArtifactChainDefinition;
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError,
    ArtifactBlockCandidateStoreLimits, ArtifactChainJournal, ArtifactChainJournalError,
    ArtifactPayloadStoreLimits, CanonicalArtifactPayloadStore, CanonicalArtifactPayloadStoreError,
};

const LOCK_PROBE_ENV: &str = "NAOME_ARTIFACT_CHAIN_JOURNAL_LOCK_PROBE";
const PAYLOAD_LOCK_PROBE_ENV: &str = "NAOME_ARTIFACT_PAYLOAD_STORE_LOCK_PROBE";
const CANDIDATE_LOCK_PROBE_ENV: &str = "NAOME_ARTIFACT_BLOCK_CANDIDATE_STORE_LOCK_PROBE";
const CHAIN_ID_BYTE: u8 = 0x11;
static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

// Isolate complete parent lifetimes: a peer test's child spawn must not
// overlap another test's open/drop/reopen boundary. The child probes remain
// separate processes and still require Locked while their parent owns storage.
static PARENT_LOCK_TESTS: Mutex<()> = Mutex::new(());

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-artifact-chain-storage-lock-{}-{sequence}",
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

fn chain_definition() -> ArtifactChainDefinition {
    ArtifactChainDefinition::new([CHAIN_ID_BYTE; 32])
}

fn payload_limits() -> ArtifactPayloadStoreLimits {
    ArtifactPayloadStoreLimits::new(1, 1).unwrap()
}

fn candidate_limits() -> ArtifactBlockCandidateStoreLimits {
    ArtifactBlockCandidateStoreLimits::new(1).unwrap()
}

#[test]
fn exclusive_lock_child_probe() {
    let Some(path) = env::var_os(LOCK_PROBE_ENV) else {
        return;
    };
    assert!(matches!(
        ArtifactChainJournal::open_recovering_unverified(PathBuf::from(path), chain_definition()),
        Err(ArtifactChainJournalError::Locked)
    ));
    println!("NAOME_ARTIFACT_CHAIN_JOURNAL_LOCK_PROBE_OK");
}

#[test]
fn exclusive_lock_is_enforced_across_processes() {
    let _parent_test = PARENT_LOCK_TESTS.lock().unwrap();
    let directory = TestDirectory::new();
    let journal = ArtifactChainJournal::create(&directory.path, chain_definition()).unwrap();
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
        String::from_utf8_lossy(&output.stdout)
            .contains("NAOME_ARTIFACT_CHAIN_JOURNAL_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(journal);
    drop(
        ArtifactChainJournal::open_recovering_unverified(&directory.path, chain_definition())
            .expect("journal lock must be released after its owner drops"),
    );
}

#[test]
fn payload_store_lock_child_probe() {
    let Some(path) = env::var_os(PAYLOAD_LOCK_PROBE_ENV) else {
        return;
    };
    assert!(matches!(
        CanonicalArtifactPayloadStore::open(PathBuf::from(path), payload_limits()),
        Err(CanonicalArtifactPayloadStoreError::Locked)
    ));
    println!("NAOME_ARTIFACT_PAYLOAD_STORE_LOCK_PROBE_OK");
}

#[test]
fn payload_store_lock_is_enforced_across_processes() {
    let _parent_test = PARENT_LOCK_TESTS.lock().unwrap();
    let directory = TestDirectory::new();
    let store = CanonicalArtifactPayloadStore::create(&directory.path, payload_limits()).unwrap();
    let output = Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg("payload_store_lock_child_probe")
        .arg("--nocapture")
        .env(PAYLOAD_LOCK_PROBE_ENV, &directory.path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("NAOME_ARTIFACT_PAYLOAD_STORE_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(store);
    drop(
        CanonicalArtifactPayloadStore::open(&directory.path, payload_limits())
            .expect("payload-store lock must be released after its owner drops"),
    );
}

#[test]
fn candidate_store_lock_child_probe() {
    let Some(path) = env::var_os(CANDIDATE_LOCK_PROBE_ENV) else {
        return;
    };
    assert!(matches!(
        ArtifactBlockCandidateStore::open(
            PathBuf::from(path),
            chain_definition(),
            candidate_limits(),
        ),
        Err(ArtifactBlockCandidateStoreError::Locked)
    ));
    println!("NAOME_ARTIFACT_BLOCK_CANDIDATE_STORE_LOCK_PROBE_OK");
}

#[test]
fn candidate_store_lock_is_enforced_across_processes() {
    let _parent_test = PARENT_LOCK_TESTS.lock().unwrap();
    let directory = TestDirectory::new();
    let store = ArtifactBlockCandidateStore::create(
        &directory.path,
        chain_definition(),
        candidate_limits(),
    )
    .unwrap();
    let output = Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg("candidate_store_lock_child_probe")
        .arg("--nocapture")
        .env(CANDIDATE_LOCK_PROBE_ENV, &directory.path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("NAOME_ARTIFACT_BLOCK_CANDIDATE_STORE_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(store);
    drop(
        ArtifactBlockCandidateStore::open(&directory.path, chain_definition(), candidate_limits())
            .expect("candidate-store lock must be released after its owner drops"),
    );
}
