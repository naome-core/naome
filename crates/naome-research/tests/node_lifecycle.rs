//! Real offline CLI processes; configured provider executable never exists.

use naome_research::{
    journal::write_new,
    node::{
        Config, Node,
        budget::{Allowance, Budgets, Period},
    },
    provider::ProviderConfig,
    run::Interests,
    state::PoolConfig,
};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

struct Fixture {
    root: PathBuf,
    config: Config,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "naome-node-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let identity_file = root.join("key.json");
        write_new(&identity_file, &[39u8; 32]).unwrap();
        let config = Config {
            version: 2,
            directory: root.join("node"),
            identity_file,
            run_label: "offline-cli-node".into(),
            interests: Interests {
                topics: vec!["Formal logic".into()],
                context: "Offline CLI fixture".into(),
            },
            provider: ProviderConfig {
                codex_binary: root.join("provider-never-created"),
                codex_home: root.join("never-authenticated"),
                model: "offline-model".into(),
                timeout_seconds: 1,
                max_output_bytes: 4096,
                disabled_registries: Default::default(),
                pure_js: None,
            },
            budgets: Budgets {
                timezone: "Europe/Berlin".into(),
                research: Allowance {
                    amount: 0,
                    period: Period::Day,
                },
                discoveries: Allowance {
                    amount: 0,
                    period: Period::Hour,
                },
                evaluations: Allowance {
                    amount: 0,
                    period: Period::Hour,
                },
            },
            credit: 1,
            pool: PoolConfig::default(),
        };
        let path = root.join("config.json");
        write_new(&path, &config).unwrap();
        Self { root, config, path }
    }
    fn command(&self, verb: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_naome-research"));
        c.arg(verb).arg(&self.path).stdin(Stdio::null());
        c
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn cli_run_requires_existing_initialized_store_and_snapshot_is_read_only() {
    let f = Fixture::new();
    let output = f.command("node-run").output().unwrap();
    assert!(!output.status.success());
    assert!(!f.config.directory.exists());
    let node = Node::initialize(f.config.clone(), 1_790_841_600).unwrap();
    let before = node.checkpoint().clone();
    let output = f.command("node-status").output().unwrap();
    assert!(output.status.success());
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["attempts_admitted"], 0);
    assert_eq!(node.checkpoint(), &before);
    // An independent reader is permitted; another writer cannot acquire this store.
    let output = f.command("node-run").output().unwrap();
    assert!(!output.status.success());
    assert_eq!(node.checkpoint(), &before);
}

#[cfg(unix)]
#[test]
fn dormant_cli_sigterm_stops_and_restart_preserves_checkpoint_and_single_identity() {
    let f = Fixture::new();
    assert!(f.command("init-node").output().unwrap().status.success());
    let before = f.command("node-status").output().unwrap();
    let before: Value = serde_json::from_slice(&before.stdout).unwrap();
    let mut child = f
        .command("node-run")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if Node::open(f.config.clone()).is_err() {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "CLI must take the writer lock"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // The signal listener registers before this bounded offline observation.
    std::thread::sleep(Duration::from_millis(80));
    let snapshot = f.command("node-status").output().unwrap();
    assert!(snapshot.status.success());
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("dormant signal stop watchdog");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stopped: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(stopped["lifecycle"], "stopped");
    assert_eq!(stopped["attempts_admitted"], 0);
    let reopened = Node::open(f.config.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(reopened.checkpoint()).unwrap(),
        before["checkpoint"]
    );
    assert_eq!(stopped["profile"], before["profile"]);
    assert!(!f.config.provider.codex_home.exists());
}
