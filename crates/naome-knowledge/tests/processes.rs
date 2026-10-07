use std::{path::PathBuf, process::Command};

static ACTIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn four_process_proof_graph_partition_dependencies_and_restart() {
    run_driver(false, false);
}

#[test]
fn ten_page_inventory_fetches_every_checked_object() {
    run_driver(true, false);
}

#[test]
fn closed_stdin_keeps_autonomous_production_and_listener_alive() {
    run_driver(false, true);
}

#[test]
fn mdns_discovers_unlisted_lan_nodes_and_retires_stale_contacts() {
    run_discovery("mdns");
}

#[test]
fn bootstrap_dht_discovers_participants_and_recovers_late_and_restarted_nodes() {
    run_discovery("dht");
}

#[test]
fn relay_circuit_transfers_checked_proofs_without_direct_shortcuts() {
    run_discovery("relay");
}

#[test]
fn dcutr_reports_a_real_local_circuit_upgrade_outcome() {
    run_discovery("upgrade");
}

#[test]
fn direct_exchange_selects_questions_before_payloads_and_commits_parent_helpers() {
    run_question_exchange("direct");
}

#[test]
fn relay_exchange_selects_questions_before_payloads_and_commits_parent_helpers() {
    run_question_exchange("relay");
}

fn run_question_exchange(mode: &str) {
    let _active = ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = root.join(".local/proof-network").join(format!(
        "questions-{mode}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new("python3")
        .arg(root.join("crates/naome-knowledge/tests/support/proof_question_exchange.py"))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_naome-knowledge"),
            "--output",
        ])
        .arg(&directory)
        .args([
            "--mode",
            mode,
            "--timeout",
            "90",
            "--profile",
            if cfg!(debug_assertions) {
                "test"
            } else {
                "release"
            },
        ])
        .output()
        .expect("run bounded real question exchange process driver");
    assert!(
        output.status.success(),
        "question exchange evidence at {}\n{}\n{}",
        directory.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn one_shot_signals_stop_busy_nodes_and_relays() {
    let _active = ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = root.join(".local/proof-network").join(format!(
        "shutdown-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new("python3")
        .arg(root.join("crates/naome-knowledge/tests/support/proof_network_shutdown.py"))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_naome-knowledge"),
            "--output",
        ])
        .arg(&directory)
        .args([
            "--timeout",
            "45",
            "--profile",
            if cfg!(debug_assertions) {
                "test"
            } else {
                "release"
            },
        ])
        .output()
        .expect("run finite POSIX shutdown driver");
    assert!(
        output.status.success(),
        "shutdown evidence at {}\n{}\n{}",
        directory.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_discovery(mode: &str) {
    let _active = ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve the checked-out repository");
    let directory = root.join(".local/proof-network").join(format!(
        "{mode}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut command = if mode == "mdns" && std::env::var("NAOME_MDNS_CI_ROOT").as_deref() == Ok("1")
    {
        if !cfg!(target_os = "macos") {
            panic!("privileged mDNS fixture is limited to hosted macOS CI");
        }
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        let python = std::env::var("NAOME_MDNS_CI_PYTHON")
            .expect("hosted macOS mDNS requires the preflight's resolved Python");
        assert!(PathBuf::from(&python).is_absolute());
        let mut command = Command::new("sudo");
        command
            .args([
                "-n",
                "--",
                "/usr/bin/env",
                "GITHUB_ACTIONS=true",
                "NAOME_MDNS_CI_ROOT=1",
                "GIT_CONFIG_COUNT=1",
                "GIT_CONFIG_KEY_0=safe.directory",
            ])
            .arg(format!("GIT_CONFIG_VALUE_0={}", root.display()));
        for key in [
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "ImageOS",
            "ImageVersion",
        ] {
            if let Ok(value) = std::env::var(key) {
                command.arg(format!("{key}={value}"));
            }
        }
        command
            .arg(python)
            .arg(root.join("crates/naome-knowledge/tests/support/mdns_ci_probe.py"))
            .arg("--run-driver");
        command
    } else {
        Command::new(if cfg!(windows) { "python" } else { "python3" })
    };
    let output = command
        .arg(root.join("crates/naome-knowledge/tests/support/proof_network_discovery.py"))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_naome-knowledge"),
            "--output",
        ])
        .arg(&directory)
        .args([
            "--mode",
            mode,
            "--timeout",
            "180",
            "--profile",
            if cfg!(debug_assertions) {
                "test"
            } else {
                "release"
            },
        ])
        .output()
        .expect("run finite discovery process driver");
    assert!(
        output.status.success(),
        "{mode} process evidence at {}\n{}\n{}",
        directory.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_driver(large_inventory: bool, closed_input: bool) {
    // Each measured trial owns its process/IO workload. Running both drivers
    // concurrently adds two nodes to the four-node fixture and contaminates
    // its bounded connection/recovery deadlines on shared CI runners.
    let _active = ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = root.join(".local/proof-network").join(format!(
        "{}-{}-{}",
        if closed_input { "service" } else { "test" },
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let python = if cfg!(windows) { "python" } else { "python3" };
    let mut command = Command::new(python);
    command
        .arg(root.join(if closed_input {
            "crates/naome-knowledge/tests/support/proof_network_service.py"
        } else {
            "crates/naome-knowledge/tests/support/proof_network.py"
        }))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_naome-knowledge"),
            "--output",
        ])
        .arg(&directory)
        .args([
            "--timeout",
            if large_inventory {
                "240"
            } else if closed_input {
                "30"
            } else {
                "120"
            },
            "--profile",
            if cfg!(debug_assertions) {
                "test"
            } else {
                "release"
            },
        ]);
    if large_inventory {
        command.arg("--large-inventory");
    }
    let output = command
        .output()
        .expect("run finite Python standard-library process driver");
    assert!(
        output.status.success(),
        "four-process evidence at {}\n{}\n{}",
        directory.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
