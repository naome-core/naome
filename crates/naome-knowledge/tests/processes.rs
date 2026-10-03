use std::{path::PathBuf, process::Command};

#[test]
fn four_process_proof_graph_partition_dependencies_and_restart() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = root.join(".local/proof-network").join(format!(
        "test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let python = if cfg!(windows) { "python" } else { "python3" };
    let output = Command::new(python)
        .arg(root.join("devnet/proof_network.py"))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_naome-knowledge"),
            "--output",
        ])
        .arg(&directory)
        .args([
            "--timeout",
            "120",
            "--profile",
            if cfg!(debug_assertions) {
                "test"
            } else {
                "release"
            },
        ])
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
