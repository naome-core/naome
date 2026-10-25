//! Ordinary nodes construct and exchange large programs without manual proof control.
use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

fn name(label: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "naome-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(all(unix, feature = "developer-tools"))]
#[test]
fn autonomous_program_transfer_resumes_after_receiver_crash_and_rechecks_on_restart() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = root
        .join("../../.local/proof-network")
        .join(name("program-replication"));
    let result = Command::new("python3")
        .arg(root.join("tests/support/program_replication.py"))
        .args(["--binary", env!("CARGO_BIN_EXE_naome"), "--output"])
        .arg(&output)
        .args([
            "--timeout",
            "240",
            "--profile",
            if cfg!(debug_assertions) {
                "test"
            } else {
                "release"
            },
        ])
        .output()
        .expect("ordinary autonomous program process fixture");
    assert!(
        result.status.success(),
        "program replication evidence at {}\n{}\n{}",
        output.display(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn ordinary_cli_rejects_removed_commands_without_creating_node_state() {
    let directory = std::env::temp_dir().join(name("autonomous-only-cli"));
    fs::create_dir(&directory).unwrap();
    let work = directory.join("manual.sqlite3");
    for args in [
        vec!["proof", "new", work.to_str().unwrap()],
        vec!["proof", "run", work.to_str().unwrap()],
        vec!["proof", "append", work.to_str().unwrap(), "commands.ndjson"],
        vec!["proof", "publish", work.to_str().unwrap()],
        vec!["proof", "follow", "00"],
        vec!["proof", "unfollow", "00"],
        vec!["resources"],
        vec!["resources", "history"],
        vec!["resources", "history", "1"],
        vec!["wallet"],
        vec!["wallet", "address"],
        vec!["wallet", "challenge", "test-verifier"],
        vec!["wallet", "prove", "challenge.json"],
        vec![
            "wallet",
            "verify",
            "address",
            "challenge.json",
            "proof.json",
        ],
    ] {
        for json in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_naome"));
            command
                .env("NAOME_NODE_DIR", directory.join("node"))
                .env_remove("NAOME_EFFECTIVE_RESOURCES")
                .env_remove("NAOME_RESOURCE_CONFIG");
            if json {
                command.arg("--json");
            }
            let output = command.args(&args).output().unwrap();
            assert!(
                !output.status.success(),
                "unexpected removed operation: {args:?}"
            );
            assert!(output.stdout.is_empty());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(
                error.contains("usage: naome [--json] start | stop | status | interest <text>"),
                "{error}"
            );
            assert!(!directory.join("node").exists());
        }
    }
    assert!(!work.exists());
    fs::remove_dir_all(directory).unwrap();
}
