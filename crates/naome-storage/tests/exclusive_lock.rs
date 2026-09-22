//! Canonical owner and external-anchor custody, including immediate release.
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use naome_ledger::{
    AccountId,
    profile::{Genesis, Profile, STATE_CHECKER_PROFILE, ValidatorRegistration},
};
#[cfg(unix)]
use naome_storage::state::StateSigner;
use naome_storage::state::{StateHistory, StateStorageError};

const HISTORY_ENV: &str = "NAOME_STATE_LOCK_PROBE_HISTORY";
const ANCHOR_ENV: &str = "NAOME_STATE_LOCK_PROBE_ANCHOR";
const KIND_ENV: &str = "NAOME_STATE_LOCK_PROBE_KIND";
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

fn genesis() -> Genesis {
    let accounts: Vec<_> = (0..6)
        .map(|i| {
            SigningKey::from_bytes(&[i + 1; 32])
                .verifying_key()
                .to_bytes()
        })
        .collect();
    Genesis::new(
        Profile::short_test(),
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        100,
        [81; 32],
        accounts.clone(),
        (0..4)
            .map(|i| ValidatorRegistration {
                owner: AccountId::for_key(&accounts[i]),
                consensus_key: SigningKey::from_bytes(&[i as u8 + 101; 32])
                    .verifying_key()
                    .to_bytes(),
                transport_key: SigningKey::from_bytes(&[i as u8 + 201; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 47000 + i),
            })
            .collect(),
    )
    .unwrap()
}
fn open(
    history: &std::path::Path,
    anchors: &std::path::Path,
    kind: &str,
) -> Result<(), StateStorageError> {
    let g = genesis();
    let maximum = g.profile().limits().consensus_rounds;
    match kind {
        "history" => StateHistory::open(history, anchors, g, maximum).map(drop),
        #[cfg(unix)]
        "signer" => StateSigner::open(
            history,
            anchors,
            g,
            SigningKey::from_bytes(&[101; 32]),
            maximum,
        )
        .map(drop),
        _ => panic!("unsupported probe kind"),
    }
}
#[test]
fn canonical_lock_child_probe() {
    let Some(history) = env::var_os(HISTORY_ENV) else {
        return;
    };
    let anchors = env::var_os(ANCHOR_ENV).expect("anchor path");
    let kind = env::var(KIND_ENV).expect("kind");
    let phase = env::var(PROBE_PHASE_ENV).expect("phase");
    let result = open(&PathBuf::from(history), &PathBuf::from(anchors), &kind);
    match phase.as_str() {
        "locked" => assert!(
            matches!(result, Err(StateStorageError::Locked)),
            "expected Locked, got {result:?}"
        ),
        "released" => result.expect("first-attempt child reopen after release"),
        _ => panic!("unknown probe phase"),
    }
    println!("\nNAOME_LOCK_PROBE_{phase}_OK");
}
fn verify_locks(kind: &str, independent_anchor: bool) {
    for _ in 0..PROBE_CYCLES {
        let history = TestDirectory::new();
        let anchors = TestDirectory::new();
        let alternate = TestDirectory::new();
        let g = genesis();
        let maximum = g.profile().limits().consensus_rounds;
        let owner: Box<dyn std::any::Any> = match kind {
            "history" => {
                Box::new(StateHistory::create(&history.path, &anchors.path, g, maximum).unwrap())
            }
            #[cfg(unix)]
            "signer" => Box::new(
                StateSigner::create(
                    &history.path,
                    &anchors.path,
                    g,
                    SigningKey::from_bytes(&[101; 32]),
                    maximum,
                )
                .unwrap(),
            ),
            _ => panic!("unsupported store kind"),
        };
        let selected = if independent_anchor {
            // Give the probe a distinct owner-lock path and an exact copy of
            // the initialized public journal. Only the anchor lock is shared.
            for entry in fs::read_dir(&history.path).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|ext| ext == "journal") {
                    fs::copy(&path, alternate.path.join(path.file_name().unwrap())).unwrap();
                }
            }
            &alternate.path
        } else {
            &history.path
        };
        let mut command = probe_command("canonical_lock_child_probe");
        command
            .env(HISTORY_ENV, selected)
            .env(ANCHOR_ENV, &anchors.path)
            .env(KIND_ENV, kind);
        run_probe(&mut command, "locked");
        drop(owner);
        open(&history.path, &anchors.path, kind)
            .expect("immediate parent reopen after explicit unlock");
        run_probe(&mut command, "released");
    }
}
#[test]
fn canonical_history_owner_lock_is_enforced_across_processes() {
    verify_locks("history", false);
}
#[test]
fn canonical_history_anchor_lock_is_independently_enforced_across_processes() {
    verify_locks("history", true);
}
#[cfg(unix)]
#[test]
fn canonical_signer_owner_lock_is_enforced_across_processes() {
    verify_locks("signer", false);
}
#[cfg(unix)]
#[test]
fn canonical_signer_anchor_lock_is_independently_enforced_across_processes() {
    verify_locks("signer", true);
}
