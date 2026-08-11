use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

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

#[test]
fn peer_address_store_lock_child_probe() {
    let (Some(path), Some(peer_id)) = (
        env::var_os(LOCK_PROBE_PATH_ENV),
        env::var_os(LOCK_PROBE_PEER_ENV),
    ) else {
        return;
    };
    let peer_id: PeerId = peer_id.to_str().unwrap().parse().unwrap();
    assert!(matches!(
        PeerAddressStore::open(PathBuf::from(path), peer_id, []),
        Err(PeerAddressStoreError::Locked)
    ));
    println!("NAOME_ADDRESS_STORE_LOCK_PROBE_OK");
}

#[test]
fn peer_address_store_lock_is_enforced_across_processes() {
    let directory = TestDirectory::new();
    let local_peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let store = PeerAddressStore::create(&directory.path, local_peer_id, []).unwrap();
    let output = Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg("peer_address_store_lock_child_probe")
        .arg("--nocapture")
        .env(LOCK_PROBE_PATH_ENV, &directory.path)
        .env(LOCK_PROBE_PEER_ENV, local_peer_id.to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("NAOME_ADDRESS_STORE_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(store);
    assert!(PeerAddressStore::open(&directory.path, local_peer_id, []).is_ok());
}

#[test]
fn local_peer_record_issuer_lock_child_probe() {
    let (Some(path), Some(seed)) = (
        env::var_os(ISSUER_LOCK_PROBE_PATH_ENV),
        env::var_os(ISSUER_LOCK_PROBE_SEED_ENV),
    ) else {
        return;
    };
    let seed: u8 = seed.to_str().unwrap().parse().unwrap();
    let identity = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    assert!(matches!(
        LocalPeerRecordIssuer::open(PathBuf::from(path), &identity),
        Err(LocalPeerRecordIssuerError::Locked)
    ));
    println!("NAOME_ISSUER_LOCK_PROBE_OK");
}

#[test]
fn local_peer_record_issuer_lock_is_enforced_across_processes() {
    let directory = TestDirectory::new();
    let seed = 77_u8;
    let identity = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    let issuer = LocalPeerRecordIssuer::create(&directory.path, &identity, 0).unwrap();
    let output = Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg("local_peer_record_issuer_lock_child_probe")
        .arg("--nocapture")
        .env(ISSUER_LOCK_PROBE_PATH_ENV, &directory.path)
        .env(ISSUER_LOCK_PROBE_SEED_ENV, seed.to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("NAOME_ISSUER_LOCK_PROBE_OK"),
        "child lock probe did not execute: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(issuer);
    assert!(LocalPeerRecordIssuer::open(&directory.path, &identity).is_ok());
}
