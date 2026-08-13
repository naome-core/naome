use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const STATEMENT_ID: &str = "f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19";
const DERIVATION_ID: &str = "59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb";
const PROOF_ID: &str = "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73";
const PROOF_BYTES: &str = "000000020600000000210000000000000000";

static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(0);

#[test]
fn compile_command_emits_the_exact_checked_identity_vector() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/self-equality.nao");
    let output = Command::new(env!("CARGO_BIN_EXE_naome"))
        .args(["proof", "compile"])
        .arg(example)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "statement_id {STATEMENT_ID}\nderivation_id {DERIVATION_ID}\nproof_id {PROOF_ID}\ncanonical_proof {PROOF_BYTES}\n"
        )
    );
}

#[test]
fn compile_failure_is_nonzero_and_emits_no_partial_identity_output() {
    let source = TemporarySource::new("foundation \"wrong\";");
    let output = Command::new(env!("CARGO_BIN_EXE_naome"))
        .args(["proof", "compile"])
        .arg(&source.path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("naome: "));
    assert!(stderr.contains("Foundation"));
}

struct TemporarySource {
    path: PathBuf,
}

impl TemporarySource {
    fn new(source: &str) -> Self {
        let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "naome-authoring-cli-{}-{sequence}.nao",
            std::process::id()
        ));
        fs::write(&path, source).unwrap();
        Self { path }
    }
}

impl Drop for TemporarySource {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
