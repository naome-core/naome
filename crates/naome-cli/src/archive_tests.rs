use super::*;
use ed25519_dalek::SigningKey;
use naome_ledger::{
    AccountId,
    profile::{Profile, STATE_CHECKER_PROFILE, ValidatorRegistration},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

// The consensus fixture uses public deterministic seeds. No operator key files
// are required by the archive reader, including on platforms without signing.
fn genesis() -> Genesis {
    let account = |i: u8| SigningKey::from_bytes(&[i + 1; 32]);
    let retirement_registrations: Vec<_> = (0..4)
        .map(|i| ValidatorRegistration {
            owner: AccountId::for_key(account(i).verifying_key().as_bytes()),
            consensus_key: SigningKey::from_bytes(&[i + 101; 32])
                .verifying_key()
                .to_bytes(),
            transport_key: SigningKey::from_bytes(&[i + 201; 32])
                .verifying_key()
                .to_bytes(),
            endpoint: format!("127.0.0.1:{}", 42000 + u16::from(i)),
        })
        .collect();
    let retirement_order = [2, 0, 3, 1]
        .map(|i| retirement_registrations[i].id())
        .to_vec();
    Genesis::new(
        Profile::short_test(),
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        100,
        [9; 32],
        (0..6)
            .map(|i| account(i).verifying_key().to_bytes())
            .collect(),
        retirement_registrations,
        retirement_order,
    )
    .unwrap()
}
fn vector(name: &str) -> Vec<u8> {
    let line = include_str!("../../naome-consensus/src/state/tests/golden-current.txt")
        .lines()
        .find(|line| line.split_whitespace().next() == Some(name))
        .unwrap();
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let bytes = fields[2]
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(bytes.len(), fields[1].parse::<usize>().unwrap());
    bytes
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "naome-archive-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let g = genesis();
        let branch = StateBranch::from_genesis(LedgerState::new(g.clone())).unwrap();
        let frame = vector("finality");
        let checked = branch.decode_finality(&frame, 32).unwrap();
        assert_eq!(
            checked.branch().commitment().as_slice(),
            vector("branch-commitment")
        );
        let manifest = Manifest {
            version: 1,
            genesis: hex(g.id().as_bytes()),
            head: hex(checked.branch().state().head().as_bytes()),
            state: hex(checked.branch().state().commitment().as_bytes()),
            height: 1,
            maximum_round: 32,
        };
        fs::write(root.join("genesis.bin"), g.encode()).unwrap();
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(root.join("00000001.finality"), frame).unwrap();
        Self(root)
    }
    fn verify(&self) -> Result<Value> {
        verify(&self.0.join("genesis.bin"), &self.0)
    }
    fn image(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn independent_archive_replays_authenticated_golden_without_writing_or_keys() {
    let fixture = Fixture::new();
    let before = fixture.image();
    let report = fixture.verify().unwrap();
    assert_eq!(report["height"], 1);
    assert_eq!(
        report["consensus_commitment"],
        hex(&vector("branch-commitment"))
    );
    assert_eq!(fixture.image(), before);
}

#[test]
fn archive_corruption_context_and_bounds_fail_without_repair() {
    let fixture = Fixture::new();
    let frame = vector("finality");
    let path = fixture.0.join("00000001.finality");
    for index in [0, 5, 13, frame.len() / 2, frame.len() - 1] {
        let mut corrupt = frame.clone();
        corrupt[index] ^= 1;
        fs::write(&path, &corrupt).unwrap();
        let before = fixture.image();
        assert!(fixture.verify().is_err(), "accepted corrupt byte {index}");
        assert_eq!(fixture.image(), before);
    }
    fs::write(&path, &frame).unwrap();
    let manifest_path = fixture.0.join("manifest.json");
    let original = fs::read(&manifest_path).unwrap();
    for (field, value) in [
        ("version", json!(0)),
        ("genesis", json!("00".repeat(32))),
        ("head", json!("00".repeat(32))),
        ("state", json!("00".repeat(32))),
        ("height", json!(u64::MAX)),
        ("maximum_round", json!(u64::MAX)),
    ] {
        let mut manifest: Value = serde_json::from_slice(&original).unwrap();
        manifest[field] = value;
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let before = fixture.image();
        assert!(fixture.verify().is_err(), "accepted bad {field}");
        assert_eq!(fixture.image(), before);
    }
    fs::write(&manifest_path, original).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(fixture.verify().is_err());
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn archive_reader_refuses_symlink_and_oversized_regular_input() {
    let fixture = Fixture::new();
    let path = fixture.0.join("00000001.finality");
    let real = fixture.0.join("real.finality");
    fs::rename(&path, &real).unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();
    assert!(fixture.verify().is_err());
    fs::remove_file(&path).unwrap();
    let file = fs::File::create(&path).unwrap();
    file.set_len(genesis().profile().limits().transport_frame_bytes + 1)
        .unwrap();
    assert!(fixture.verify().is_err());
}

#[cfg(unix)]
#[test]
fn archive_fifo_is_rejected_before_a_blocking_open() {
    let fixture = Fixture::new();
    let fifo = fixture.0.join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = sender.send(read(&fifo, 16).is_err());
    });
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("FIFO open blocked")
    );
    worker.join().unwrap();
}

#[cfg(windows)]
#[test]
fn archive_device_namespaces_aliases_and_streams_are_rejected_before_open() {
    for path in [
        r"\\.\NUL",
        r"\\.\pipe\naome-test",
        r"\\server\pipe\naome-test",
        "NUL",
        "nul.txt",
        "CON",
        "COM1",
        "LPT9",
        "COM¹",
        "CONIN$",
        "file:stream",
    ] {
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = sender.send(read(Path::new(path), 16).is_err());
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("device path open blocked"),
            "accepted {path}"
        );
        worker.join().unwrap();
    }
}
