use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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

const PROBE_PHASE_ENV: &str = "NAOME_LOCK_PROBE_PHASE";
const PROBE_CYCLES: usize = 8;

fn probe_command(test: &str) -> Command {
    let mut command = Command::new(env::current_exe().unwrap());
    command.arg("--exact").arg(test).arg("--nocapture");
    command
}

fn run_probe(command: &mut Command, phase: &str) {
    let mut child = command
        .env(PROBE_PHASE_ENV, phase)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let timed_out = loop {
        if child.try_wait().unwrap().is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            // Always reap the child before its parent's temporary directory drops.
            let _ = child.kill();
            break true;
        }
        // Poll only for process completion; storage acquisition is never retried.
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !timed_out && output.status.success(),
        "{phase} child timed_out={timed_out} status={} stdout={stdout} stderr={stderr}",
        output.status
    );
    let marker = format!("NAOME_LOCK_PROBE_{phase}_OK");
    assert!(
        stdout.lines().any(|line| line == marker),
        "{phase} probe did not execute: stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn exclusive_lock_child_probe() {
    let Some(path) = env::var_os(LOCK_PROBE_ENV) else {
        return;
    };
    let phase = env::var(PROBE_PHASE_ENV).expect("lock probe phase is required");
    let result =
        ArtifactChainJournal::open_recovering_unverified(PathBuf::from(path), chain_definition())
            .map(drop);
    match phase.as_str() {
        "locked" => assert!(
            matches!(result, Err(ArtifactChainJournalError::Locked)),
            "expected Locked, got {result:?}"
        ),
        "released" => result.expect("released owner must permit first-attempt child acquisition"),
        other => panic!("unknown lock probe phase: {other}"),
    }
    // Serial libtest prints its test-name prefix without a trailing newline.
    println!("\nNAOME_LOCK_PROBE_{phase}_OK");
}

#[test]
fn exclusive_lock_is_enforced_across_processes() {
    for _ in 0..PROBE_CYCLES {
        let directory = TestDirectory::new();
        let owner = ArtifactChainJournal::create(&directory.path, chain_definition()).unwrap();
        let mut command = probe_command("exclusive_lock_child_probe");
        command.env(LOCK_PROBE_ENV, &directory.path);
        run_probe(&mut command, "locked");
        drop(owner);
        drop(
            ArtifactChainJournal::open_recovering_unverified(&directory.path, chain_definition())
                .expect("owner drop must permit immediate parent reopen"),
        );
        run_probe(&mut command, "released");
    }
}

#[test]
fn payload_store_lock_child_probe() {
    let Some(path) = env::var_os(PAYLOAD_LOCK_PROBE_ENV) else {
        return;
    };
    let phase = env::var(PROBE_PHASE_ENV).expect("lock probe phase is required");
    let result =
        CanonicalArtifactPayloadStore::open(PathBuf::from(path), payload_limits()).map(drop);
    match phase.as_str() {
        "locked" => assert!(
            matches!(result, Err(CanonicalArtifactPayloadStoreError::Locked)),
            "expected Locked, got {result:?}"
        ),
        "released" => result.expect("released owner must permit first-attempt child acquisition"),
        other => panic!("unknown lock probe phase: {other}"),
    }
    // Serial libtest prints its test-name prefix without a trailing newline.
    println!("\nNAOME_LOCK_PROBE_{phase}_OK");
}

#[test]
fn payload_store_lock_is_enforced_across_processes() {
    for _ in 0..PROBE_CYCLES {
        let directory = TestDirectory::new();
        let owner =
            CanonicalArtifactPayloadStore::create(&directory.path, payload_limits()).unwrap();
        let mut command = probe_command("payload_store_lock_child_probe");
        command.env(PAYLOAD_LOCK_PROBE_ENV, &directory.path);
        run_probe(&mut command, "locked");
        drop(owner);
        drop(
            CanonicalArtifactPayloadStore::open(&directory.path, payload_limits())
                .expect("owner drop must permit immediate parent reopen"),
        );
        run_probe(&mut command, "released");
    }
}

#[test]
fn candidate_store_lock_child_probe() {
    let Some(path) = env::var_os(CANDIDATE_LOCK_PROBE_ENV) else {
        return;
    };
    let phase = env::var(PROBE_PHASE_ENV).expect("lock probe phase is required");
    let result = ArtifactBlockCandidateStore::open(
        PathBuf::from(path),
        chain_definition(),
        candidate_limits(),
    )
    .map(drop);
    match phase.as_str() {
        "locked" => assert!(
            matches!(result, Err(ArtifactBlockCandidateStoreError::Locked)),
            "expected Locked, got {result:?}"
        ),
        "released" => result.expect("released owner must permit first-attempt child acquisition"),
        other => panic!("unknown lock probe phase: {other}"),
    }
    // Serial libtest prints its test-name prefix without a trailing newline.
    println!("\nNAOME_LOCK_PROBE_{phase}_OK");
}

#[test]
fn candidate_store_lock_is_enforced_across_processes() {
    for _ in 0..PROBE_CYCLES {
        let directory = TestDirectory::new();
        let owner = ArtifactBlockCandidateStore::create(
            &directory.path,
            chain_definition(),
            candidate_limits(),
        )
        .unwrap();
        let mut command = probe_command("candidate_store_lock_child_probe");
        command.env(CANDIDATE_LOCK_PROBE_ENV, &directory.path);
        run_probe(&mut command, "locked");
        drop(owner);
        drop(
            ArtifactBlockCandidateStore::open(
                &directory.path,
                chain_definition(),
                candidate_limits(),
            )
            .expect("owner drop must permit immediate parent reopen"),
        );
        run_probe(&mut command, "released");
    }
}
