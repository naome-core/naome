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
            "devnet/proof_network_service.py"
        } else {
            "devnet/proof_network.py"
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
