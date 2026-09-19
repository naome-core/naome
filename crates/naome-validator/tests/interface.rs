#![cfg(unix)]
use std::{fs, process::Command};
#[test]
fn validator_only_reopens_canonical_state_and_never_dispatches_setup_or_v0() {
    let binary = env!("CARGO_BIN_EXE_naome-validator");
    let root =
        std::env::temp_dir().join(format!("naome-validator-interface-{}", std::process::id()));
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert_eq!(help.stdout, b"Usage: naome-validator start CONFIG\n");
    assert!(!root.exists());
    for prefix in [
        vec!["setup"],
        vec!["state", "setup"],
        vec!["create"],
        vec!["open"],
        vec!["status"],
        vec!["verify"],
    ] {
        let output = Command::new(binary)
            .args(prefix)
            .arg(&root)
            .args(["short-test", "128", "44100", "compact"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("only supports: start CONFIG"));
        assert!(!root.exists());
    }
    fs::write(&root, b"mode = \"create\"\n").unwrap();
    let output = Command::new(binary).arg(&root).output().unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(&root).unwrap(), b"mode = \"create\"\n");
    fs::remove_file(root).unwrap();
}
