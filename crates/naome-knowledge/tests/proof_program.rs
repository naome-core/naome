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
fn ordinary_cli_rejects_invalid_arguments_without_creating_node_state() {
    let directory = std::env::temp_dir().join(name("autonomous-only-cli"));
    fs::create_dir(&directory).unwrap();
    for args in [
        vec!["unknown"],
        vec!["unknown", "argument"],
        vec!["start", "extra"],
        vec!["stop", "extra"],
        vec!["status", "extra"],
        vec!["start", "stop"],
        vec!["status", "--json"],
        vec!["--unknown"],
        vec!["--json", "--json", "status"],
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
                "unexpected invalid operation: {args:?}"
            );
            assert!(output.stdout.is_empty());
            let event: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(
                event,
                serde_json::json!({
                    "event": 0x00170017, // FatalError
                    "error": {
                        "code": u32::from(naome_knowledge::RuntimeFailure::Arguments),
                        "fatal": true,
                        "retryable": false,
                        "cause": {
                            "code": u32::from(naome_knowledge::InputFault::CliArgumentsInvalid),
                            "fatal": false,
                            "retryable": false,
                        },
                    },
                }),
                "invalid operation: {args:?} (JSON mode: {json})"
            );
            assert!(!directory.join("node").exists());
        }
    }
    fs::remove_dir_all(directory).unwrap();
}
