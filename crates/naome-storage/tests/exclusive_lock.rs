use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_chain::ProofChainDefinition;
use naome_storage::{
    CanonicalProofPayloadStore, CanonicalProofPayloadStoreError, ProofBlockCandidateStore,
    ProofBlockCandidateStoreError, ProofBlockCandidateStoreLimits, ProofChainJournal,
    ProofChainJournalError, ProofPayloadStoreLimits,
};

const LOCK_PROBE_ENV: &str = "NAOME_PROOF_CHAIN_JOURNAL_LOCK_PROBE";
const PAYLOAD_LOCK_PROBE_ENV: &str = "NAOME_PROOF_PAYLOAD_STORE_LOCK_PROBE";
const CANDIDATE_LOCK_PROBE_ENV: &str = "NAOME_PROOF_BLOCK_CANDIDATE_STORE_LOCK_PROBE";
const CHAIN_ID_BYTE: u8 = 0x11;
static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-proof-chain-storage-lock-{}-{sequence}",
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

fn chain_definition() -> ProofChainDefinition {
    ProofChainDefinition::new([CHAIN_ID_BYTE; 32])
}

fn payload_limits() -> ProofPayloadStoreLimits {
    ProofPayloadStoreLimits::new(1, 1).unwrap()
}

fn candidate_limits() -> ProofBlockCandidateStoreLimits {
    ProofBlockCandidateStoreLimits::new(1).unwrap()
}

#[test]
fn exclusive_lock_child_probe() {
    let Some(path) = env::var_os(LOCK_PROBE_ENV) else {
        return;
    };
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(PathBuf::from(path), chain_definition()),
        Err(ProofChainJournalError::Locked)
    ));
    println!("NAOME_PROOF_CHAIN_JOURNAL_LOCK_PROBE_OK");
}

#[test]
fn exclusive_lock_is_enforced_across_processes() {
    let directory = TestDirectory::new();
    let journal = ProofChainJournal::create(&directory.path, chain_definition()).unwrap();
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
        String::from_utf8_lossy(&output.stdout).contains("NAOME_PROOF_CHAIN_JOURNAL_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(journal);
    assert!(
        ProofChainJournal::open_recovering_unverified(&directory.path, chain_definition()).is_ok()
    );
}

#[test]
fn payload_store_lock_child_probe() {
    let Some(path) = env::var_os(PAYLOAD_LOCK_PROBE_ENV) else {
        return;
    };
    assert!(matches!(
        CanonicalProofPayloadStore::open(PathBuf::from(path), payload_limits()),
        Err(CanonicalProofPayloadStoreError::Locked)
    ));
    println!("NAOME_PROOF_PAYLOAD_STORE_LOCK_PROBE_OK");
}

#[test]
fn payload_store_lock_is_enforced_across_processes() {
    let directory = TestDirectory::new();
    let store = CanonicalProofPayloadStore::create(&directory.path, payload_limits()).unwrap();
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
        String::from_utf8_lossy(&output.stdout).contains("NAOME_PROOF_PAYLOAD_STORE_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(store);
    assert!(CanonicalProofPayloadStore::open(&directory.path, payload_limits()).is_ok());
}

#[test]
fn candidate_store_lock_child_probe() {
    let Some(path) = env::var_os(CANDIDATE_LOCK_PROBE_ENV) else {
        return;
    };
    assert!(matches!(
        ProofBlockCandidateStore::open(PathBuf::from(path), chain_definition(), candidate_limits(),),
        Err(ProofBlockCandidateStoreError::Locked)
    ));
    println!("NAOME_PROOF_BLOCK_CANDIDATE_STORE_LOCK_PROBE_OK");
}

#[test]
fn candidate_store_lock_is_enforced_across_processes() {
    let directory = TestDirectory::new();
    let store =
        ProofBlockCandidateStore::create(&directory.path, chain_definition(), candidate_limits())
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
            .contains("NAOME_PROOF_BLOCK_CANDIDATE_STORE_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(store);
    assert!(
        ProofBlockCandidateStore::open(&directory.path, chain_definition(), candidate_limits(),)
            .is_ok()
    );
}
