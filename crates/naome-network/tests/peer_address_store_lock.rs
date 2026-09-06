use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use naome_network::{
    Keypair, LocalPeerRecordIssuer, LocalPeerRecordIssuerError, PeerAddressStore,
    PeerAddressStoreError, PeerId,
};

const LOCK_PROBE_PATH_ENV: &str = "NAOME_ADDRESS_STORE_LOCK_PROBE_PATH";
const LOCK_PROBE_PEER_ENV: &str = "NAOME_ADDRESS_STORE_LOCK_PROBE_PEER";
const ISSUER_LOCK_PROBE_PATH_ENV: &str = "NAOME_ISSUER_LOCK_PROBE_PATH";
const ISSUER_LOCK_PROBE_SEED_ENV: &str = "NAOME_ISSUER_LOCK_PROBE_SEED";
static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        loop {
            let sequence = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "naome-address-store-lock-{}-{sequence}",
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
fn peer_address_store_lock_child_probe() {
    let Some(path) = env::var_os(LOCK_PROBE_PATH_ENV) else {
        return;
    };
    let peer_id = env::var_os(LOCK_PROBE_PEER_ENV).expect("lock probe identity is required");
    let peer_id: PeerId = peer_id.to_str().unwrap().parse().unwrap();
    let phase = env::var(PROBE_PHASE_ENV).expect("lock probe phase is required");
    let result = PeerAddressStore::open(PathBuf::from(path), peer_id, []).map(drop);
    match phase.as_str() {
        "locked" => assert!(
            matches!(result, Err(PeerAddressStoreError::Locked)),
            "expected Locked, got {result:?}"
        ),
        "released" => result.expect("released owner must permit first-attempt child acquisition"),
        other => panic!("unknown lock probe phase: {other}"),
    }
    // Serial libtest prints its test-name prefix without a trailing newline.
    println!("\nNAOME_LOCK_PROBE_{phase}_OK");
}

#[test]
fn peer_address_store_lock_is_enforced_across_processes() {
    for _ in 0..PROBE_CYCLES {
        let directory = TestDirectory::new();
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let owner = PeerAddressStore::create(&directory.path, peer_id, []).unwrap();
        let mut command = probe_command("peer_address_store_lock_child_probe");
        command
            .env(LOCK_PROBE_PATH_ENV, &directory.path)
            .env(LOCK_PROBE_PEER_ENV, peer_id.to_string());
        run_probe(&mut command, "locked");
        drop(owner);
        drop(
            PeerAddressStore::open(&directory.path, peer_id, [])
                .expect("owner drop must permit immediate parent reopen"),
        );
        run_probe(&mut command, "released");
    }
}

#[test]
fn local_peer_record_issuer_lock_child_probe() {
    let Some(path) = env::var_os(ISSUER_LOCK_PROBE_PATH_ENV) else {
        return;
    };
    let seed = env::var_os(ISSUER_LOCK_PROBE_SEED_ENV).expect("lock probe identity is required");
    let seed: u8 = seed.to_str().unwrap().parse().unwrap();
    let identity = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    let phase = env::var(PROBE_PHASE_ENV).expect("lock probe phase is required");
    let result = LocalPeerRecordIssuer::open(PathBuf::from(path), &identity).map(drop);
    match phase.as_str() {
        "locked" => assert!(
            matches!(result, Err(LocalPeerRecordIssuerError::Locked)),
            "expected Locked, got {result:?}"
        ),
        "released" => result.expect("released owner must permit first-attempt child acquisition"),
        other => panic!("unknown lock probe phase: {other}"),
    }
    // Serial libtest prints its test-name prefix without a trailing newline.
    println!("\nNAOME_LOCK_PROBE_{phase}_OK");
}

#[test]
fn local_peer_record_issuer_lock_is_enforced_across_processes() {
    for _ in 0..PROBE_CYCLES {
        let directory = TestDirectory::new();
        let seed = 77_u8;
        let identity = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        let owner = LocalPeerRecordIssuer::create(&directory.path, &identity, 0).unwrap();
        let mut command = probe_command("local_peer_record_issuer_lock_child_probe");
        command
            .env(ISSUER_LOCK_PROBE_PATH_ENV, &directory.path)
            .env(ISSUER_LOCK_PROBE_SEED_ENV, seed.to_string());
        run_probe(&mut command, "locked");
        drop(owner);
        drop(
            LocalPeerRecordIssuer::open(&directory.path, &identity)
                .expect("owner drop must permit immediate parent reopen"),
        );
        run_probe(&mut command, "released");
    }
}
