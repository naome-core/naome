use std::{path::PathBuf, process::Command};

static ACTIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(all(unix, feature = "developer-tools"))]
#[test]
#[ignore = "Bounded public produce/compaction mechanism screen"]
fn public_produce_observes_compaction_handoff_with_4096_large_proofs() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "this ignored screen requires Release"
    );
    let _active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = std::env::temp_dir().join(format!(
        "naome-public-produce-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new("python3")
        .arg(root.join("crates/naome-knowledge/tests/support/public_produce_compaction.py"))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_naome-knowledge-dev"),
            "--output",
        ])
        .arg(&directory)
        .args(["--timeout", "600", "--profile", "release"])
        .output()
        .expect("finite public produce process screen");
    assert!(
        output.status.success(),
        "public produce screen (exit 2 is INCONCLUSIVE) at {}\n{}\n{}",
        directory.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(all(unix, feature = "developer-tools"))]
#[test]
#[ignore = "Bounded larger public produce/generation screen"]
fn public_produce_observes_large_generation_handoff_with_12288_large_proofs() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "this ignored screen requires Release"
    );
    let _active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = std::env::temp_dir().join(format!(
        "naome-public-produce-12288-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new("python3")
        .arg(root.join("crates/naome-knowledge/tests/support/public_produce_compaction.py"))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_naome-knowledge-dev"),
            "--output",
        ])
        .arg(&directory)
        .args([
            "--timeout",
            "600",
            "--profile",
            "release",
            "--count",
            "12288",
        ])
        .output()
        .expect("finite public produce process screen");
    assert!(
        output.status.success(),
        "public produce screen (exit 2 is INCONCLUSIVE) at {}\n{}\n{}",
        directory.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(all(unix, feature = "developer-tools"))]
#[test]
fn ordinary_long_jobs_preserve_responsive_peer_control_and_crash_budgets() {
    let _active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    for mode in ["roles", "recovery", "limits", "faults", "basic"] {
        let directory = root.join(".local/proof-network").join(format!(
            "long-jobs-{mode}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let output = Command::new("python3")
            .arg(root.join("crates/naome-knowledge/tests/support/long_jobs.py"))
            .args(["--binary", env!("CARGO_BIN_EXE_naome"), "--output"])
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
            .expect("finite ordinary long-jobs process driver");
        assert!(
            output.status.success(),
            "long-jobs {mode} evidence at {}\n{}\n{}",
            directory.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn ordinary_owner_interest_is_exact_durable_and_serialized() {
    run_autonomous("interest");
}

#[cfg(all(unix, feature = "developer-tools", feature = "system-tests"))]
#[test]
fn automatic_resource_pause_preserves_provider_budgets_and_control() {
    run_autonomous("pause");
}

#[cfg(all(unix, feature = "developer-tools", feature = "system-tests"))]
#[test]
fn native_provider_feedback_reaches_owner_without_changing_job_allowances() {
    run_autonomous("provider-feedback");
}

#[cfg(unix)]
#[test]
fn ordinary_lifecycle_generates_exchanges_and_recovers_checked_artifacts() {
    run_autonomous("direct");
}

#[cfg(unix)]
#[test]
fn ordinary_autonomous_nodes_exchange_after_mdns_discovery() {
    run_autonomous("mdns");
}

#[cfg(unix)]
#[test]
fn ordinary_autonomous_nodes_exchange_after_bootstrap_dht_discovery() {
    run_autonomous("dht");
}

#[cfg(all(unix, feature = "developer-tools"))]
#[test]
fn ordinary_autonomous_nodes_exchange_over_configured_relay() {
    run_autonomous("relay");
}

#[cfg(all(unix, feature = "developer-tools"))]
#[test]
fn ordinary_driver_loss_guardian_stops_owned_daemon_and_relay() {
    run_autonomous("guardian-probe");
}

#[cfg(unix)]
#[test]
#[ignore = "Finite 1M native learning, gossip, resource pause and checkpoint screen; requires Release"]
fn native_learning_uses_checked_own_and_peer_solutions_and_resumes_model_and_adam() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "native 1M process qualification requires Release"
    );
    run_autonomous("native");
}

#[cfg(unix)]
fn run_autonomous(mode: &str) {
    let _active = ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve the checked-out repository");
    let directory = root.join(".local/proof-network").join(format!(
        "autonomous-{mode}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut command = python_driver(&root, mode);
    command
        .arg(root.join(match mode {
            "interest" => "crates/naome-knowledge/tests/support/owner_interest.py",
            "pause" => "crates/naome-knowledge/tests/support/automatic_computation.py",
            "provider-feedback" => "crates/naome-knowledge/tests/support/provider_feedback.py",
            "startup" => "crates/naome-knowledge/tests/support/startup_lifecycle.py",
            "native" => "crates/naome-knowledge/tests/support/native_learning.py",
            _ => "crates/naome-knowledge/tests/support/autonomous_lifecycle.py",
        }))
        .args(["--binary", env!("CARGO_BIN_EXE_naome"), "--output"])
        .arg(&directory)
        .args([
            "--timeout",
            match mode {
                "mdns" => "180",
                "direct" => "60",
                "guardian-probe" => "45",
                "startup" => "50",
                "native" => "480",
                "pause" => "120",
                _ => "90",
            },
            "--profile",
            if cfg!(debug_assertions) {
                "test"
            } else {
                "release"
            },
        ]);
    if mode == "guardian-probe" {
        command.arg("--guardian-loss-probe");
    } else {
        command.args(["--mode", mode]);
    }
    #[cfg(feature = "developer-tools")]
    if matches!(mode, "relay" | "guardian-probe") {
        command.args(["--relay-binary", env!("CARGO_BIN_EXE_naome-knowledge-dev")]);
    }
    let output = command
        .output()
        .expect("run bounded ordinary autonomous lifecycle process driver");
    assert!(
        output.status.success(),
        "autonomous {mode} lifecycle evidence at {}\n{}\n{}",
        directory.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn startup_lifeline_requires_checked_ack_and_reaps_internal_refusals() {
    run_autonomous("startup");
}

fn python_driver(root: &std::path::Path, mode: &str) -> Command {
    if mode == "mdns" && std::env::var("NAOME_MDNS_CI_ROOT").as_deref() == Ok("1") {
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
        Command::new("python3")
    }
}

#[cfg(feature = "developer-tools")]
mod developer_transport {
    use super::*;

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
    fn relay_circuit_transfers_checked_artifacts_without_direct_shortcuts() {
        run_discovery("relay");
    }

    #[test]
    fn dcutr_reports_a_real_local_circuit_upgrade_outcome() {
        run_discovery("upgrade");
    }

    #[test]
    fn hostile_identities_cannot_fill_contact_slots_or_block_trusted_exchange() {
        run_discovery("hostile");
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
                env!("CARGO_BIN_EXE_naome-knowledge-dev"),
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
                env!("CARGO_BIN_EXE_naome-knowledge-dev"),
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
        let mut command = python_driver(&root, mode);
        let output = command
            .arg(root.join("crates/naome-knowledge/tests/support/proof_network_discovery.py"))
            .args([
                "--binary",
                env!("CARGO_BIN_EXE_naome-knowledge-dev"),
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
        let mut command = Command::new("python3");
        command
            .arg(root.join(if closed_input {
                "crates/naome-knowledge/tests/support/proof_network_service.py"
            } else {
                "crates/naome-knowledge/tests/support/proof_network.py"
            }))
            .args([
                "--binary",
                env!("CARGO_BIN_EXE_naome-knowledge-dev"),
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
}
