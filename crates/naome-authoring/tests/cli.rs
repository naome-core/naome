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
const SUBSTITUTION_STATEMENT_ID: &str =
    "0d6570e2a5031b6a1b3664fb990c1cdf4ff4079364ad9dd08e4f9123662c5772";
const SUBSTITUTION_DERIVATION_ID: &str =
    "107a35fa6ec1677c01560c743c627a5d231315d605fa50083e18dd529a8861b5";
const SUBSTITUTION_PROOF_ID: &str =
    "e89dcbf998af185fd368a2531e2f0ee4953cc2232ec93da38ed3e89e21cede71";
const SUBSTITUTION_PROOF_BYTES: &str = "000000040700000000000000010000000b0100000000000000000002210000000000000002210000000100000001210000000200000000";
const EXTENSIONALITY_STATEMENT_ID: &str =
    "d5badb94fde79367c1ee93516c9260d031335c23502e3fcf36513ac768cc9db9";
const EXTENSIONALITY_DERIVATION_ID: &str =
    "5507c036519883b871a080036e5e9a5332784501f1982e17e4f9a363b7369b9c";
const EXTENSIONALITY_PROOF_ID: &str =
    "7db633cf3f2a73749e143c3f26a0083b17c39e8a24c8940f64471cf6b49d515d";
const EXTENSIONALITY_PROOF_BYTES: &str = "000000011000";
const SEPARATION_STATEMENT_ID: &str =
    "cdc8f561c1e6d36cb437da9cfce5f97ab9079f5985f769c02c67ab2ff803f9a3";
const SEPARATION_DERIVATION_ID: &str =
    "073ae5f13c159cda79b6fe31ed033eb8bb1b79ffcd21fa617adc5aea139408a6";
const SEPARATION_PROOF_ID: &str =
    "426fcca7bbf116adebfa819e0eaf7c465c0215d3b367d5446c3882b1f1a7697c";
const SEPARATION_PROOF_BYTES: &str =
    "00000001110000000b01000000000000000000010000000000000002000000030000000100000001";
const REPLACEMENT_STATEMENT_ID: &str =
    "4d12c8f960638ff317e561e8861808875f18dfd22910c38712e05112e26724f5";
const REPLACEMENT_DERIVATION_ID: &str =
    "72d5c8f81af4a2bcbe1eb7ed9fc1963ecbc1fedf91edf20d85f55c84051c93ec";
const REPLACEMENT_PROOF_ID: &str =
    "7c5a06a3e764c6b6e372334645050bd314f8a7e64c96633e3d3aff90ca2bd156";
const REPLACEMENT_PROOF_BYTES: &str =
    "00000001120000000b0000000000000000000001000000000000000100000002000000030000000400000000";

static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(0);

#[test]
fn compile_command_emits_exact_identities_from_primitive_and_derived_sources() {
    for (file, statement_id, derivation_id, proof_id, proof_bytes) in [
        (
            "self-equality.nao",
            STATEMENT_ID,
            DERIVATION_ID,
            PROOF_ID,
            PROOF_BYTES,
        ),
        (
            "implication-identity.nao",
            IMPLICATION_STATEMENT_ID,
            IMPLICATION_DERIVATION_ID,
            IMPLICATION_PROOF_ID,
            IMPLICATION_PROOF_BYTES,
        ),
        (
            "quantifier-instantiation.nao",
            QUANTIFIER_STATEMENT_ID,
            QUANTIFIER_DERIVATION_ID,
            QUANTIFIER_PROOF_ID,
            QUANTIFIER_PROOF_BYTES,
        ),
        (
            "equality-substitution.nao",
            SUBSTITUTION_STATEMENT_ID,
            SUBSTITUTION_DERIVATION_ID,
            SUBSTITUTION_PROOF_ID,
            SUBSTITUTION_PROOF_BYTES,
        ),
        (
            "extensionality.nao",
            EXTENSIONALITY_STATEMENT_ID,
            EXTENSIONALITY_DERIVATION_ID,
            EXTENSIONALITY_PROOF_ID,
            EXTENSIONALITY_PROOF_BYTES,
        ),
        (
            "separation.nao",
            SEPARATION_STATEMENT_ID,
            SEPARATION_DERIVATION_ID,
            SEPARATION_PROOF_ID,
            SEPARATION_PROOF_BYTES,
        ),
        (
            "replacement.nao",
            REPLACEMENT_STATEMENT_ID,
            REPLACEMENT_DERIVATION_ID,
            REPLACEMENT_PROOF_ID,
            REPLACEMENT_PROOF_BYTES,
        ),
    ] {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(file);
        let output = Command::new(env!("CARGO_BIN_EXE_naome"))
            .args(["proof", "compile"])
            .arg(example)
            .output()
            .unwrap();

        assert!(output.status.success(), "{file}: {output:?}");
        assert!(output.stderr.is_empty(), "{file}: {output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "statement_id {statement_id}\nderivation_id {derivation_id}\nproof_id {proof_id}\ncanonical_proof {proof_bytes}\n"
            ),
            "{file}"
        );
    }
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

#[test]
fn compile_command_has_no_hidden_proof_reference_state() {
    let source = TemporarySource::new(&format!(
        "foundation \"naome:zfc\"; theorem cited {{ statement (forall x (equal x x)); proof {{ step known = (proof-reference {PROOF_ID}); result known; }} }}"
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_naome"))
        .args(["proof", "compile"])
        .arg(&source.path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("naome: "));
    assert!(stderr.contains("references an unknown proof"));
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
