#[path = "support/hex_decode.rs"]
mod hex_decode;
use hex_decode::hex_bytes;

#[path = "support/hex_encode.rs"]
mod hex_encode;
use hex_encode::hex_string;

use std::{fs, path::Path};

use naome_authoring::{
    AUTHORING_SOURCE_MAX_BYTES, CompileDiagnostic, CompiledArtifact, CompiledQuestion,
    DiagnosticCode, QUESTION_SOURCE_MAX_BYTES, QuestionError, compile, compile_artifact,
};
use naome_proof::ArtifactId;

#[path = "support/golden.rs"]
mod golden;
use golden::*;

const SELF_EQUAL_DEFINITION_ID: &str =
    "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035";
const SELF_EQUAL_ARTIFACT_ID: &str =
    "c4c4e0c00f0df475ae34fe8cff4d2cbe78ecb20c6c7b91ae9509ca537876f796";
const SELF_EQUAL_DEFINITION_BYTES: &str = "00000000010000000b0000000000000000000000";

fn fixture(file: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(file),
    )
    .unwrap()
}

fn diagnostic(source: &str) -> CompileDiagnostic {
    compile_artifact(source).unwrap_err().diagnostic(source)
}

fn assert_diagnostic(
    source: &str,
    code: DiagnosticCode,
    position: Option<(usize, usize)>,
    message: &str,
) {
    let diagnostic = diagnostic(source);
    assert_eq!(diagnostic.code(), code);
    assert_eq!(
        diagnostic
            .primary_position()
            .map(|position| (position.line(), position.column())),
        position
    );
    assert_eq!(diagnostic.message(), message);
}

#[test]
fn typed_proofs_preserve_exact_primitive_derived_and_bound_identities() {
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
        let proof = compile(&fixture(file)).unwrap();
        assert_eq!(
            hex_string(proof.statement_id().as_bytes()),
            statement_id,
            "{file}"
        );
        assert_eq!(
            hex_string(proof.derivation_id().as_bytes()),
            derivation_id,
            "{file}"
        );
        assert_eq!(hex_string(proof.proof_id().as_bytes()), proof_id, "{file}");
        assert_eq!(
            proof.canonical_proof_bytes(),
            hex_bytes(proof_bytes),
            "{file}"
        );
        assert_eq!(
            compile_artifact(&fixture(file)).unwrap().artifact_id(),
            ArtifactId::from_proof_id(proof.proof_id()),
            "{file}"
        );
    }
}

#[test]
fn typed_definition_preserves_exact_identity_and_bytes() {
    let CompiledArtifact::Definition(definition) =
        compile_artifact(&fixture("reflexive-relation.nao")).unwrap()
    else {
        panic!("expected the checked relation definition");
    };
    assert_eq!(
        hex_string(definition.definition_id().as_bytes()),
        SELF_EQUAL_DEFINITION_ID
    );
    assert_eq!(
        hex_string(definition.artifact_id().as_bytes()),
        SELF_EQUAL_ARTIFACT_ID
    );
    assert_eq!(
        definition.canonical_definition_bytes(),
        hex_bytes(SELF_EQUAL_DEFINITION_BYTES)
    );
}

#[test]
fn typed_compile_rejects_the_wrong_foundation() {
    assert_diagnostic(
        "foundation = \"wrong\"",
        DiagnosticCode::Syntax,
        Some((1, 1)),
        "expected goal",
    );
}

#[test]
fn typed_checker_rejects_invalid_modus_ponens() {
    assert_diagnostic(
        &fixture("implication-identity.nao").replace("mp(p1, p2)", "mp(p2, p1)"),
        DiagnosticCode::Check,
        Some((14, 5)),
        "step \"p3\" violates Foundation logic: modus ponens requires an implication whose antecedent equals the premise",
    );
}

#[test]
fn typed_standalone_compilation_has_no_hidden_citation_state() {
    let source = format!("goal = all(x, eq(x, x)) proof: p0 = cite(\"{PROOF_ID}\") return p0");
    assert_diagnostic(
        &source,
        DiagnosticCode::Check,
        Some((1, source.find("p0 =").unwrap() + 1)),
        "step \"p0\" references an unknown proof",
    );
}

#[test]
fn typed_standalone_compilation_cannot_authorize_definition_dependencies() {
    for (file, code, position, message) in [
        (
            "identity-function.nao",
            DiagnosticCode::DefinitionCheck,
            (3, 1),
            "definition obligation statement 31a017582bf7e6314670d35aeb7d206d060a12bc4df139163297a139161e01a1 is absent from selected state",
        ),
        (
            "reflexive-relation-alias.nao",
            DiagnosticCode::DefinitionNotSelected,
            (4, 5),
            "definition alias is absent from selected chain state",
        ),
    ] {
        assert_diagnostic(&fixture(file), code, Some(position), message);
    }
}

#[test]
fn typed_compile_rejects_legacy_source_syntax() {
    assert_diagnostic(
        "foundation \"naome:zfc\"; theorem old { statement (forall x (equal x x)); proof { step p0 = (equality-reflexivity x); result p0; } }",
        DiagnosticCode::Syntax,
        Some((1, 1)),
        "expected goal",
    );
}

#[test]
fn typed_diagnostics_treat_lf_crlf_and_bare_cr_as_one_line_boundary() {
    for line_break in ["\n", "\r\n", "\r"] {
        assert_diagnostic(
            &format!("{line_break}foundation = \"wrong\""),
            DiagnosticCode::Syntax,
            Some((2, 1)),
            "expected goal",
        );
    }
}

#[test]
fn typed_eof_diagnostic_has_next_line_and_empty_source_span() {
    let source = "\n";
    assert_diagnostic(
        source,
        DiagnosticCode::Syntax,
        Some((2, 1)),
        "expected a name",
    );
    assert!(diagnostic(source).primary_span().unwrap().is_empty());
}

#[test]
fn typed_checker_diagnostic_retains_source_step_after_dependency_reordering() {
    let source = "goal = eq(x, x)\nproof:\n  a0 = refl(x)\n  a1 = simp(eq(x, x), eq(x, x))\n  broken_result = mp(a1, a0)\n  b0 = refl(y)\n  root = mp(b0, broken_result)\n  return root";
    assert_diagnostic(
        source,
        DiagnosticCode::Check,
        Some((5, 3)),
        "step \"broken_result\" violates Foundation logic: modus ponens requires an implication whose antecedent equals the premise",
    );
}

#[test]
fn typed_source_limit_is_global_and_has_no_invented_position() {
    let source = " ".repeat(AUTHORING_SOURCE_MAX_BYTES + 1);
    assert_diagnostic(
        &source,
        DiagnosticCode::SourceTooLong,
        None,
        &format!(
            "source has {} bytes; the limit is {AUTHORING_SOURCE_MAX_BYTES}",
            AUTHORING_SOURCE_MAX_BYTES + 1
        ),
    );
    assert_eq!(diagnostic(&source).primary_span(), None);
}

#[test]
fn typed_long_step_name_is_bounded_in_diagnostic_and_complete_in_source_span() {
    let long_name = "x".repeat(8 * 1024);
    let source = format!(
        "goal = all(x, eq(x, x))\nproof:\n  p0 = refl(x)\n  p1 = gen({long_name}, x)\n  return p1"
    );
    let diagnostic = diagnostic(&source);
    let span = diagnostic.primary_span().unwrap();
    assert_eq!(&source[span.start()..span.end()], long_name);
    assert_eq!(diagnostic.code(), DiagnosticCode::UnknownStep);
    assert_eq!(
        diagnostic
            .primary_position()
            .map(|position| (position.line(), position.column())),
        Some((4, 12))
    );
    assert_eq!(
        diagnostic.message(),
        format!("unknown or forward step \"{}...\"", "x".repeat(64))
    );
    assert!(!diagnostic.message().contains(&long_name));
    assert!(!diagnostic.message().contains('\n'));
}

#[test]
fn typed_questions_preserve_source_codec_and_oriented_targets() {
    for (formula, source_hash, parity, canonical) in [
        (
            "all(x,eq(x,x))",
            "15f08bf3b018ed691db79719172476cdc3a7d7fe95e4045eef4f066b8457921a",
            false,
            "0100000016676f616c203d20616c6c28782c657128782c7829290a",
        ),
        (
            "not(all(x,eq(x,x)))",
            "4d98fa5f7b43e0dcb71bd9c29e19905adec99e338706d2f7754e363a9830c914",
            true,
            "010000001b676f616c203d206e6f7428616c6c28782c657128782c782929290a",
        ),
    ] {
        let question = CompiledQuestion::compile(&format!("goal = {formula}\n")).unwrap();
        assert_eq!(question.source_hash(), &hex_decode::hex32(source_hash));
        assert_eq!(
            hex_string(question.resolution_id()),
            "8cb7976f42b68e2ecd89e610bac06630c872ae961b02a8863ef3712e89583dcf"
        );
        assert_eq!(question.negation_parity(), parity);
        assert_eq!(
            question.canonical_core(),
            hex_bytes("040001000000000100000000")
        );
        assert_eq!(question.to_canonical_bytes().unwrap(), hex_bytes(canonical));
    }
}

#[test]
fn typed_questions_reject_free_variables_proofs_and_source_fields() {
    for source in [
        "goal = eq(x,x)",
        "goal = all(x,eq(x,x)) proof: return p",
        "assumptions = [] goal = all(x,eq(x,x))",
        "foundation = \"other\" goal = all(x,eq(x,x))",
    ] {
        assert!(CompiledQuestion::compile(source).is_err(), "{source}");
    }
}

#[test]
fn typed_question_compiler_bounds_source_bytes() {
    assert_eq!(
        CompiledQuestion::compile(&" ".repeat(QUESTION_SOURCE_MAX_BYTES + 1)),
        Err(QuestionError::Limit("question source bytes"))
    );
}

#[cfg(feature = "developer-tools")]
mod developer_cli {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(0);

    fn run(command: &str, path: &Path) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_naome-author"))
            .arg(command)
            .arg(path)
            .output()
            .unwrap()
    }

    #[test]
    fn developer_writer_emits_checked_proof_definition_and_question_fields() {
        for (file, expected) in [
            (
                "self-equality.nao",
                format!(
                    "statement_id {STATEMENT_ID}\nderivation_id {DERIVATION_ID}\nproof_id {PROOF_ID}\nartifact_id {}\ncanonical_proof {PROOF_BYTES}\n",
                    hex_string(
                        compile_artifact(&fixture("self-equality.nao"))
                            .unwrap()
                            .artifact_id()
                            .as_bytes()
                    )
                ),
            ),
            (
                "reflexive-relation.nao",
                format!(
                    "definition_id {SELF_EQUAL_DEFINITION_ID}\nartifact_id {SELF_EQUAL_ARTIFACT_ID}\ncanonical_definition {SELF_EQUAL_DEFINITION_BYTES}\n"
                ),
            ),
        ] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(file);
            let output = run("proof", &path);
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
        }
        let source = TemporarySource::new("goal = all(x,eq(x,x))\n");
        let output = run("question", &source.path);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "source_hash 15f08bf3b018ed691db79719172476cdc3a7d7fe95e4045eef4f066b8457921a\nresolution_id 8cb7976f42b68e2ecd89e610bac06630c872ae961b02a8863ef3712e89583dcf\nnegation_parity false\ncanonical_core 040001000000000100000000\ncanonical_question 0100000016676f616c203d20616c6c28782c657128782c7829290a\n"
        );
    }

    #[test]
    fn developer_compile_failure_is_nonzero_without_partial_identity_output() {
        let source = TemporarySource::new("foundation = \"wrong\"");
        let output = run("proof", &source.path);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!(
                "naome-author: {}:1:1: error[NAO0002]: expected goal\n",
                source.path.display()
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn developer_diagnostic_escapes_path_controls() {
        let source = TemporarySource::named(
            "proof\\literal\ninjected\r\u{2028}\u{2029}.nao",
            "foundation = \"wrong\"",
        );
        let output = run("proof", &source.path);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            stderr,
            format!(
                "naome-author: {}/proof\\literal\\ninjected\\r\\u{{2028}}\\u{{2029}}.nao:1:1: error[NAO0002]: expected goal\n",
                source.directory.display()
            )
        );
        assert_eq!(stderr.bytes().filter(|byte| *byte == b'\n').count(), 1);
        assert!(!stderr.trim_end_matches('\n').contains('\r'));
        assert!(!stderr.contains('\u{2028}'));
        assert!(!stderr.contains('\u{2029}'));
    }

    #[test]
    fn developer_reader_bounds_question_bytes_before_utf8_decoding() {
        let source = TemporarySource::new("");
        let mut bytes = vec![b' '; QUESTION_SOURCE_MAX_BYTES];
        bytes.push(0xff);
        fs::write(&source.path, bytes).unwrap();
        let output = run("question", &source.path);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr).unwrap().contains(&format!(
            "source exceeds the {QUESTION_SOURCE_MAX_BYTES}-byte limit"
        )));
    }

    #[test]
    fn developer_path_is_opaque_when_it_matches_a_command_word() {
        let source = TemporarySource::named("compile", &fixture("self-equality.nao"));
        let output = Command::new(env!("CARGO_BIN_EXE_naome-author"))
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
                hex_string(
                    compile_artifact(&fixture("self-equality.nao"))
                        .unwrap()
                        .artifact_id()
                        .as_bytes()
                )
            )
        );
    }

    #[test]
    fn developer_legacy_compile_command_has_no_compatibility_alias() {
        let example =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/self-equality.nao");
        let output = Command::new(env!("CARGO_BIN_EXE_naome-author"))
            .args(["proof", "compile"])
            .arg(example)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "naome-author: usage: naome-author proof <proof.nao> | question <question.nao>\n"
        );
    }

    #[test]
    fn json_authoring_checks_exact_outputs_and_original_source_errors() {
        for (command, source) in [
            (
                "proof",
                "goal=all(x,eq(x,x)) proof: a=refl(x) b=gen(a,x) return b",
            ),
            ("proof", "def R=relation(x):eq(x,x)"),
            ("question", "goal=not(all(x,eq(x,x)))"),
        ] {
            let file = TemporarySource::new(source);
            let output = Command::new(env!("CARGO_BIN_EXE_naome-author"))
                .args([command, "--json"])
                .arg(&file.path)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty());
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["schema_version"], 1);
            assert_eq!(json["ok"], true);
            if command == "question" {
                let question = CompiledQuestion::compile(source).unwrap();
                assert_eq!(
                    json["canonical_core"],
                    hex_string(question.canonical_core())
                );
                assert_eq!(
                    json["proved_target"],
                    hex_string(&question.proved_target().encode_canonical().unwrap())
                );
                assert_eq!(
                    json["refuted_target"],
                    hex_string(&question.refuted_target().encode_canonical().unwrap())
                );
                assert_eq!(
                    json["canonical_question"],
                    hex_string(&question.to_canonical_bytes().unwrap())
                );
            } else if json["kind"] == "proof" {
                assert_eq!(json["canonical_proof"], PROOF_BYTES);
                assert_eq!(json["proof_id"], PROOF_ID);
            } else {
                assert_eq!(json["canonical_definition"], SELF_EQUAL_DEFINITION_BYTES);
                assert_eq!(json["definition_id"], SELF_EQUAL_DEFINITION_ID);
            }
        }
        for (command, source, code, token) in [
            (
                "proof",
                "# ä\r\ngoal=all(x,eq(x,x)) proof: a=refl(x) b=gen(missing,x) return b",
                "NAO0005",
                "missing",
            ),
            (
                "question",
                "# ä\r\nlet: A=eq(x,x) goal=all(x,missing)",
                "NAO0030",
                "missing",
            ),
            ("proof", "nao 2 goal=all(x,eq(x,x))", "NAO0002", "nao"),
        ] {
            let file = TemporarySource::new(source);
            let output = Command::new(env!("CARGO_BIN_EXE_naome-author"))
                .args([command, "--json"])
                .arg(&file.path)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(json["ok"], false);
            assert_eq!(json["diagnostic"]["code"], code);
            let start = json["diagnostic"]["span"]["start"].as_u64().unwrap() as usize;
            let end = json["diagnostic"]["span"]["end"].as_u64().unwrap() as usize;
            assert_eq!(&source[start..end], token);
        }
    }

    #[test]
    fn json_flag_requires_one_source_and_raw_limit_keeps_its_code() {
        for args in [
            vec!["proof", "--json"],
            vec!["question", "--json"],
            vec!["proof", "--json", "--json", "file.nao"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_naome-author"))
                .args(args)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(json["phase"], "input");
        }
        let file = TemporarySource::new(&" ".repeat(QUESTION_SOURCE_MAX_BYTES + 1));
        let output = Command::new(env!("CARGO_BIN_EXE_naome-author"))
            .args(["question", "--json"])
            .arg(&file.path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(json["diagnostic"]["code"], "NAO0001");
        assert!(json["diagnostic"]["span"].is_null());
    }

    struct TemporarySource {
        directory: PathBuf,
        path: PathBuf,
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
}
