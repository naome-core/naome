//! Actual portable verifier: public fixtures only, no private keys or node stores.
#![cfg(any(unix, windows))]
use ed25519_dalek::SigningKey;
use naome_consensus::state::StateBranch;
use naome_ledger::{
    AccountId, LedgerState,
    profile::{Genesis, Profile, STATE_CHECKER_PROFILE, ValidatorRegistration},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
const BIN: &str = env!("CARGO_BIN_EXE_naome-verifier");
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn vector(name: &str) -> Vec<u8> {
    let line = include_str!("../../naome-consensus/src/state/tests/golden-v3.txt")
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
struct Archive(PathBuf);
impl Archive {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "naome-public-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let account = |i: u8| SigningKey::from_bytes(&[i + 1; 32]);
        let genesis = Genesis::new(
            Profile::short_test(),
            "naome:zfc".into(),
            STATE_CHECKER_PROFILE.into(),
            naome_ledger::profile::STATE_PROTOCOL_VERSION,
            100,
            [9; 32],
            (0..6)
                .map(|i| account(i).verifying_key().to_bytes())
                .collect(),
            (0..4)
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
                .collect(),
        )
        .unwrap();
        let branch = StateBranch::from_genesis(LedgerState::new(genesis.clone())).unwrap();
        let frame = vector("finality");
        let checked = branch.decode_finality(&frame, 32).unwrap();
        let manifest = json!({"version":1,"genesis":hex(genesis.id().as_bytes()),"head":hex(checked.branch().state().head().as_bytes()),"state":hex(checked.branch().state().commitment().as_bytes()),"height":1,"maximum_round":32});
        fs::write(root.join("genesis.bin"), genesis.encode()).unwrap();
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(root.join("00000001.finality"), frame).unwrap();
        Self(root)
    }
    fn image(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| {
                let p = entry.unwrap().path();
                let b = fs::read(&p).unwrap();
                (p, b)
            })
            .collect()
    }
    fn run(&self) -> Output {
        invoke(&[
            "verify".as_ref(),
            self.0.join("genesis.bin").as_os_str(),
            self.0.as_os_str(),
        ])
    }
}
impl Drop for Archive {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn wait(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("verifier process blocked");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn invoke(args: &[&std::ffi::OsStr]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait(&mut child);
    child.wait_with_output().unwrap()
}
#[test]
fn canonical_verifier_replays_public_golden_and_rejects_corruption_without_writes() {
    let archive = Archive::new();
    let original = archive.image();
    assert_eq!(original.len(), 3, "no private files required");
    let output = archive.run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["height"], 1);
    assert_eq!(
        report["consensus_commitment"],
        hex(&vector("branch-commitment"))
    );
    assert_eq!(archive.image(), original);
    let frame = archive.0.join("00000001.finality");
    let mut damaged = fs::read(&frame).unwrap();
    damaged[0] ^= 1;
    fs::write(&frame, damaged).unwrap();
    let before = archive.image();
    assert!(!archive.run().status.success());
    assert_eq!(archive.image(), before);
}
#[test]
fn canonical_verifier_rejects_directories_oversize_and_legacy_interfaces() {
    let archive = Archive::new();
    let frame = archive.0.join("00000001.finality");
    fs::remove_file(&frame).unwrap();
    fs::create_dir(&frame).unwrap();
    assert!(!archive.run().status.success());
    assert!(frame.is_dir());
    fs::remove_dir(&frame).unwrap();
    let file = fs::File::create(&frame).unwrap();
    file.set_len(Profile::short_test().limits().transport_frame_bytes + 1)
        .unwrap();
    drop(file);
    let original = archive.image();
    assert!(!archive.run().status.success());
    for command in ["state", "start", "setup", "import", "create", "open"] {
        assert!(
            !invoke(&[command.as_ref(), archive.0.as_os_str()])
                .status
                .success()
        );
        assert_eq!(archive.image(), original);
    }
    let path = archive.0.join("legacy.toml");
    fs::write(&path, b"mode = \"create\"\n").unwrap();
    let original = archive.image();
    assert!(!invoke(&[path.as_os_str()]).status.success());
    assert_eq!(archive.image(), original);
}
#[test]
fn canonical_verifier_rejects_symlink_archive_frames() {
    let archive = Archive::new();
    let frame = archive.0.join("00000001.finality");
    let saved = archive.0.join("original.finality");
    fs::rename(&frame, &saved).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&saved, &frame).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&saved, &frame).unwrap();
    let original = archive.image();
    assert!(!archive.run().status.success());
    assert_eq!(archive.image(), original);
}
#[cfg(windows)]
#[test]
fn canonical_windows_verifier_rejects_devices_pipes_and_alternate_streams() {
    let archive = Archive::new();
    let original = archive.image();
    for path in [
        "NUL",
        "CON",
        "COM1",
        "LPT9",
        "CONIN$",
        r"\\.\pipe\naome-verifier-never-open",
        r"\\localhost\pipe\naome-verifier-never-open",
        "genesis.bin:alternate",
    ] {
        assert!(
            !invoke(&[
                "verify".as_ref(),
                std::path::Path::new(path).as_os_str(),
                archive.0.as_os_str()
            ])
            .status
            .success()
        );
        assert_eq!(archive.image(), original);
    }
}
#[cfg(unix)]
#[test]
fn canonical_verifier_exits_when_report_output_is_stalled() {
    use std::{
        io::Write,
        os::{fd::OwnedFd, unix::net::UnixStream},
    };
    let archive = Archive::new();
    let original = archive.image();
    let (mut writer, _reader) = UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    let mut count = 0;
    loop {
        match writer.write(&[0; 8192]) {
            Ok(n) => {
                count += n;
                assert!(count < 16 * 1024 * 1024);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("{e}"),
        }
    }
    writer.set_nonblocking(false).unwrap();
    let mut child = Command::new(BIN)
        .arg("verify")
        .arg(archive.0.join("genesis.bin"))
        .arg(&archive.0)
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait(&mut child);
    assert!(!child.wait().unwrap().success());
    assert_eq!(archive.image(), original);
}
