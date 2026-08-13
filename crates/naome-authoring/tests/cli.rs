use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const STATEMENT_ID: &str = "f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19";
const DERIVATION_ID: &str = "59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb";
const PROOF_ID: &str = "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73";
const PROOF_BYTES: &str = "000000020600000000210000000000000000";
const IMPLICATION_STATEMENT_ID: &str =
    "6c7296d3c7adb7ee99b71caec2e6851c31360e2811bd1335b526c7b74525a48b";
const IMPLICATION_DERIVATION_ID: &str =
    "fd46e6233815bd4cb5188f5358b8afb852179c62b7fb512b798302b0f01fdd94";
const IMPLICATION_PROOF_ID: &str =
    "dad1eccea41c54d5618a35bff0bc3b8fb52e0489017fd9a444cdae14355b6285";
const IMPLICATION_PROOF_BYTES: &str = "00000006000000000b00000000000000000000000000000b0000000000000000000000000000000b0000000000000000000000000000170300000000000000000000000000000000000000000000010000000b00000000000000000000000000001703000000000000000000000000000000000000000000000000000b0000000000000000000000200000000100000002200000000000000003210000000400000000";
const QUANTIFIER_STATEMENT_ID: &str =
    "f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19";
const QUANTIFIER_DERIVATION_ID: &str =
    "a85928e52c4c2833d30640cb2eaba82602ccbc39b6afea340b5b0b8d06061972";
const QUANTIFIER_PROOF_ID: &str =
    "6e35a728527633573509b24fa20cb2359a14c1f93e9f6b6f1500f8650f731720";
const QUANTIFIER_PROOF_BYTES: &str = "0000000506000000002100000000000000000500000000000000010000000b0000000000000000000000200000000100000002210000000300000001";

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
fn compile_command_emits_the_exact_implication_identity_vector() {
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/implication-identity.nao");
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
            "statement_id {IMPLICATION_STATEMENT_ID}\nderivation_id {IMPLICATION_DERIVATION_ID}\nproof_id {IMPLICATION_PROOF_ID}\ncanonical_proof {IMPLICATION_PROOF_BYTES}\n"
        )
    );
}

#[test]
fn compile_command_emits_the_exact_quantifier_identity_vector() {
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/quantifier-instantiation.nao");
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
            "statement_id {QUANTIFIER_STATEMENT_ID}\nderivation_id {QUANTIFIER_DERIVATION_ID}\nproof_id {QUANTIFIER_PROOF_ID}\ncanonical_proof {QUANTIFIER_PROOF_BYTES}\n"
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

#[test]
fn invalid_modus_ponens_is_nonzero_and_emits_no_partial_identity_output() {
    let source = TemporarySource::new(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/implication-identity.nao"),
        )
        .unwrap()
        .replace(
            "(modus-ponens keep_implication distribute)",
            "(modus-ponens distribute keep_implication)",
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_naome"))
        .args(["proof", "compile"])
        .arg(&source.path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("naome: "));
    assert!(stderr.contains("modus ponens"));
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
