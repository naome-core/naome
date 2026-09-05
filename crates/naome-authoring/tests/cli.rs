#[path = "support/hex_decode.rs"]
mod hex_decode;
use hex_decode::hex32;

#[path = "support/hex_encode.rs"]
mod hex_encode;
use hex_encode::hex_string;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_authoring::{AUTHORING_SOURCE_MAX_BYTES, compile};
use naome_proof::{ArtifactId, ProofId};

#[path = "support/golden.rs"]
mod golden;
use golden::*;

const SELF_EQUAL_DEFINITION_ID: &str =
    "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035";
const SELF_EQUAL_ARTIFACT_ID: &str =
    "c4c4e0c00f0df475ae34fe8cff4d2cbe78ecb20c6c7b91ae9509ca537876f796";
const SELF_EQUAL_DEFINITION_BYTES: &str = "00000000010000000b0000000000000000000000";

static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(0);

#[test]
fn proof_command_emits_exact_identities_from_primitive_derived_and_bound_sources() {
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
            .arg("proof")
            .arg(example)
            .output()
            .unwrap();

        assert!(output.status.success(), "{file}: {output:?}");
        assert!(output.stderr.is_empty(), "{file}: {output:?}");
        let artifact_id = proof_artifact_id_hex(proof_id);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "statement_id {statement_id}\nderivation_id {derivation_id}\nproof_id {proof_id}\nartifact_id {artifact_id}\ncanonical_proof {proof_bytes}\n"
            ),
            "{file}"
        );
    }
}

#[test]
fn proof_command_emits_the_exact_typed_definition_output() {
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/reflexive-relation.nao");
    let output = Command::new(env!("CARGO_BIN_EXE_naome"))
        .arg("proof")
        .arg(example)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "definition_id {SELF_EQUAL_DEFINITION_ID}\nartifact_id {SELF_EQUAL_ARTIFACT_ID}\ncanonical_definition {SELF_EQUAL_DEFINITION_BYTES}\n"
        )
    );
}

#[test]
fn compile_failure_is_nonzero_and_emits_no_partial_identity_output() {
    let source = TemporarySource::new("foundation = \"wrong\"");
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "naome: {}:1:14: error[NAO0003]: unsupported Foundation identifier; expected \"naome:zfc\"\n",
            source.path.display(),
        )
    );
}

#[test]
fn invalid_modus_ponens_is_nonzero_and_emits_no_partial_identity_output() {
    let source = TemporarySource::new(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/implication-identity.nao"),
        )
        .unwrap()
        .replace("modus_ponens(p1, p2)", "modus_ponens(p2, p1)"),
    );
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "naome: {}:14:5: error[NAO0010]: step \"p3\" violates Foundation logic: modus ponens requires an implication whose antecedent equals the premise\n",
            source.path.display(),
        )
    );
}

#[test]
fn proof_command_has_no_hidden_citation_state() {
    let source = TemporarySource::new(&format!(
        "foundation = \"naome:zfc\" statement = forall(x, equal(x, x)) proof: p0 = cite(\"{PROOF_ID}\") return p0"
    ));
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let column = fs::read_to_string(&source.path)
        .unwrap()
        .find("p0 =")
        .unwrap()
        + 1;
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "naome: {}:1:{column}: error[NAO0010]: step \"p0\" references an unknown proof\n",
            source.path.display(),
        )
    );
}

#[test]
fn standalone_command_cannot_authorize_definition_dependencies_from_local_files() {
    for (file, position, diagnostic) in [
        (
            "identity-function.nao",
            "3:1",
            "error[NAO0021]: definition obligation statement 31a017582bf7e6314670d35aeb7d206d060a12bc4df139163297a139161e01a1 is absent from selected state",
        ),
        (
            "reflexive-relation-alias.nao",
            "4:5",
            "error[NAO0018]: definition alias is absent from selected chain state",
        ),
    ] {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(file);
        let output = run_proof(&example);

        assert_eq!(output.status.code(), Some(1), "{file}: {output:?}");
        assert!(output.stdout.is_empty(), "{file}: {output:?}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("naome: {}:{position}: {diagnostic}\n", example.display()),
            "{file}"
        );
    }
}

#[test]
fn legacy_source_syntax_is_rejected_without_a_compatibility_parser() {
    let source = TemporarySource::new(
        "foundation \"naome:zfc\"; theorem old { statement (forall x (equal x x)); proof { step p0 = (equality-reflexivity x); result p0; } }",
    );
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "naome: {}:1:12: error[NAO0002]: expected `=`\n",
            source.path.display(),
        )
    );
}

#[test]
fn diagnostics_treat_lf_crlf_and_bare_cr_as_one_line_boundary() {
    for line_break in ["\n", "\r\n", "\r"] {
        let source = TemporarySource::new(&format!("{line_break}foundation = \"wrong\""));
        let output = run_proof(&source.path);

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!(
                "naome: {}:2:14: error[NAO0003]: unsupported Foundation identifier; expected \"naome:zfc\"\n",
                source.path.display(),
            )
        );
    }
}

#[test]
fn eof_diagnostic_uses_the_next_line_and_an_empty_source_span() {
    let source = TemporarySource::new("foundation = \"naome:zfc\"\n");
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "naome: {}:2:1: error[NAO0002]: expected a name\n",
            source.path.display(),
        )
    );
}

#[test]
fn checker_diagnostic_retains_the_source_step_after_dependency_reordering() {
    let source = TemporarySource::new(
        "foundation = \"naome:zfc\"\nstatement = equal(x, x)\nproof:\n  a0 = equality_reflexivity(x)\n  a1 = simplification(equal(x, x), equal(x, x))\n  broken_result = modus_ponens(a1, a0)\n  b0 = equality_reflexivity(y)\n  root = modus_ponens(b0, broken_result)\n  return root",
    );
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "naome: {}:6:3: error[NAO0010]: step \"broken_result\" violates Foundation logic: modus ponens requires an implication whose antecedent equals the premise\n",
            source.path.display(),
        )
    );
}

#[test]
fn source_too_long_is_global_and_has_no_invented_position() {
    let source = TemporarySource::new(&" ".repeat(AUTHORING_SOURCE_MAX_BYTES + 1));
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "naome: {}: error[NAO0001]: source exceeds the {AUTHORING_SOURCE_MAX_BYTES}-byte limit\n",
            source.path.display(),
        )
    );
}

#[test]
fn long_step_name_is_bounded_in_stderr_but_complete_in_its_source_span() {
    let long_name = "x".repeat(8 * 1024);
    let source_text = format!(
        "foundation = \"naome:zfc\"\nstatement = forall(x, equal(x, x))\nproof:\n  p0 = equality_reflexivity(x)\n  p1 = generalization({long_name}, x)\n  return p1"
    );
    let error = compile(&source_text).unwrap_err();
    let span = error.diagnostic(&source_text).primary_span().unwrap();
    assert_eq!(&source_text[span.start()..span.end()], long_name);

    let source = TemporarySource::new(&source_text);
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let prefix = format!(
        "naome: {}:5:23: error[NAO0005]: unknown or forward step \"",
        source.path.display(),
    );
    assert!(stderr.starts_with(&prefix));
    assert!(stderr.ends_with(&format!("{}...\"\n", "x".repeat(64))));
    assert_eq!(stderr.len(), prefix.len() + 64 + "...\"\n".len());
    assert!(!stderr.contains(&long_name));
    assert_eq!(stderr.bytes().filter(|byte| *byte == b'\n').count(), 1);
}

#[cfg(unix)]
#[test]
fn diagnostic_escapes_path_controls_instead_of_injecting_lines() {
    let source = TemporarySource::named(
        "proof\\literal\ninjected\r\u{2028}\u{2029}.nao",
        "foundation = \"wrong\"",
    );
    let output = run_proof(&source.path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        format!(
            "naome: {}/proof\\literal\\ninjected\\r\\u{{2028}}\\u{{2029}}.nao:1:14: error[NAO0003]: unsupported Foundation identifier; expected \"naome:zfc\"\n",
            source.directory.display(),
        )
    );
    assert_eq!(stderr.bytes().filter(|byte| *byte == b'\n').count(), 1);
    assert!(!stderr.trim_end_matches('\n').contains('\r'));
    assert!(!stderr.contains('\u{2028}'));
    assert!(!stderr.contains('\u{2029}'));
}

#[test]
fn proof_path_is_opaque_even_when_it_matches_a_command_word() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/self-equality.nao"),
    )
    .unwrap();
    let source = TemporarySource::named("compile", &source);

    let output = Command::new(env!("CARGO_BIN_EXE_naome"))
        .args(["proof", "compile"])
        .current_dir(&source.directory)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "statement_id {STATEMENT_ID}\nderivation_id {DERIVATION_ID}\nproof_id {PROOF_ID}\nartifact_id {}\ncanonical_proof {PROOF_BYTES}\n",
            proof_artifact_id_hex(PROOF_ID),
        )
    );
}

#[test]
fn legacy_compile_command_is_rejected_without_a_compatibility_alias() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/self-equality.nao");
    let output = Command::new(env!("CARGO_BIN_EXE_naome"))
        .args(["proof", "compile"])
        .arg(example)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "naome: usage: naome proof <proof.nao>\n"
    );
}

struct TemporarySource {
    directory: PathBuf,
    path: PathBuf,
}

fn run_proof(path: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_naome"))
        .arg("proof")
        .arg(path)
        .output()
        .unwrap()
}

fn proof_artifact_id_hex(proof_id: &str) -> String {
    let proof_id = ProofId::from_bytes(hex32(proof_id));
    hex_string(ArtifactId::from_proof_id(proof_id).as_bytes())
}

impl TemporarySource {
    fn new(source: &str) -> Self {
        Self::named("proof.nao", source)
    }

    fn named(file_name: &str, source: &str) -> Self {
        let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "naome-authoring-cli-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join(file_name);
        fs::write(&path, source).unwrap();
        Self { directory, path }
    }
}

impl Drop for TemporarySource {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
