//! The single source language is checked against canonical consumers and fixed bytes.

use naome_authoring::{
    AUTHORING_SOURCE_MAX_BYTES, CompileError, CompiledArtifact, CompiledQuestion, DiagnosticCode,
    QUESTION_SOURCE_MAX_BYTES, compile, compile_against_proof_context, compile_artifact,
    compile_artifact_against_proof_context,
};
use naome_checker::{ArtifactState, check_definition_with_state, check_normal_form_with_state};
use naome_proof::{ArtifactPayload, ProofCertificate};
use std::{fs, path::Path};

#[allow(dead_code)]
#[path = "support/golden.rs"]
mod golden;
#[path = "support/hex_encode.rs"]
mod hex_encode;

const SIMPLE: &str = "goal=all(x,eq(x,x))\nproof: a=refl(x) b=gen(a,x) return b";

fn fixture(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn register(state: &mut ArtifactState, artifact: &CompiledArtifact) {
    match ArtifactPayload::from_canonical_bytes(&artifact.canonical_artifact_bytes()).unwrap() {
        ArtifactPayload::Proof(certificate) => {
            let checked =
                check_normal_form_with_state(certificate.into_unchecked_normal_form(), state)
                    .unwrap();
            let _ = state.register_proof(checked).unwrap();
        }
        ArtifactPayload::Definition(certificate) => {
            let checked = check_definition_with_state(certificate, state).unwrap();
            state.register_definition(checked).unwrap();
        }
    }
}

fn context() -> ArtifactState {
    let mut state = ArtifactState::new();
    for name in [
        "identity-function-obligation.nao",
        "self-equality.nao",
        "quantifier-instantiation.nao",
        "implication-identity.nao",
        "equality-substitution.nao",
        "extensionality.nao",
        "reflexive-relation.nao",
        "membership-relation.nao",
        "same-members-relation.nao",
        "identity-function.nao",
    ] {
        let artifact = compile_artifact_against_proof_context(&fixture(name), &state).unwrap();
        register(&mut state, &artifact);
    }
    state
}

#[test]
fn literal_vectors_remain_exact_for_proof_definition_and_question() {
    let proof = compile(SIMPLE).unwrap();
    assert_eq!(
        hex_encode::hex_string(proof.canonical_proof_bytes()),
        golden::PROOF_BYTES
    );
    assert_eq!(
        hex_encode::hex_string(proof.proof_id().as_bytes()),
        golden::PROOF_ID
    );
    assert_eq!(
        hex_encode::hex_string(proof.statement_id().as_bytes()),
        golden::STATEMENT_ID
    );
    assert_eq!(
        hex_encode::hex_string(proof.derivation_id().as_bytes()),
        golden::DERIVATION_ID
    );
    let CompiledArtifact::Definition(definition) =
        compile_artifact("def self_equal=relation(x):eq(x,x)").unwrap()
    else {
        panic!("definition")
    };
    assert_eq!(
        hex_encode::hex_string(definition.definition_id().as_bytes()),
        "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035"
    );
    assert_eq!(
        hex_encode::hex_string(definition.canonical_definition_bytes()),
        "00000000010000000b0000000000000000000000"
    );
    let question = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    assert_eq!(
        hex_encode::hex_string(question.canonical_core()),
        "040001000000000100000000"
    );
    assert_eq!(
        hex_encode::hex_string(question.resolution_id()),
        "8cb7976f42b68e2ecd89e610bac06630c872ae961b02a8863ef3712e89583dcf"
    );
}

fn assert_same_question(old: &str, new: &str) {
    let old = CompiledQuestion::compile(old).unwrap();
    let new = CompiledQuestion::compile(new).unwrap();
    assert_eq!(old.formula(), new.formula());
    assert_eq!(old.core(), new.core());
    assert_eq!(old.canonical_core(), new.canonical_core());
    assert_eq!(old.resolution_id(), new.resolution_id());
    assert_eq!(old.negation_parity(), new.negation_parity());
    assert_eq!(old.proved_target(), new.proved_target());
    assert_eq!(old.refuted_target(), new.refuted_target());
    let bytes = old.to_canonical_bytes().unwrap();
    assert_eq!(CompiledQuestion::from_canonical_bytes(&bytes).unwrap(), old);
    assert_eq!(
        CompiledQuestion::from_canonical_bytes(&new.to_canonical_bytes().unwrap()).unwrap(),
        new
    );
    assert_ne!(old.source_hash(), new.source_hash());
    assert_ne!(bytes, new.to_canonical_bytes().unwrap());
}

#[test]
fn ordered_binders_and_question_bindings_preserve_capture_shadowing_and_orientation() {
    for (old, new) in [
        (
            "all(x,all(y,imp(mem(x,y),eq(y,x))))",
            "all([x,y],imp(mem(x,y),eq(y,x)))",
        ),
        ("all(x,all(x,eq(x,x)))", "all([x,x],eq(x,x))"),
        (
            "all(x,ex(y,ex(z,and(eq(x,y),mem(y,z)))))",
            "all(x,ex([y,z],and(eq(x,y),mem(y,z))))",
        ),
        (
            "not(all(y,all(x,imp(eq(x,x),eq(x,x)))))",
            "not(all([y,x],A))",
        ),
    ] {
        let bindings = if new.contains('A') {
            "let: E=eq(x,x) A=imp(E,E) "
        } else {
            ""
        };
        assert_same_question(&format!("goal={old}"), &format!("{bindings}goal={new}"));
    }
    let first = CompiledQuestion::compile("goal=all([x,y],mem(x,y))").unwrap();
    let swapped = CompiledQuestion::compile("goal=all([y,x],mem(x,y))").unwrap();
    assert_ne!(first.canonical_core(), swapped.canonical_core());
    let proof =
        compile("let: A=eq(x,x) goal=all([y,x],A) proof: p=refl(x) q=gen(p,x) r=gen(q,y) return r")
            .unwrap();
    assert_eq!(
        proof,
        compile("goal=all(y,all(x,eq(x,x))) proof: p=refl(x) q=gen(p,x) r=gen(q,y) return r")
            .unwrap()
    );
}

#[test]
fn exact_typed_references_are_resolved_only_by_the_caller_context() {
    let mut state = ArtifactState::new();
    let helper = compile_artifact(SIMPLE).unwrap();
    register(&mut state, &helper);
    let before = state.snapshot_id();
    let input = format!(
        "refs: H=\"{}\" goal=all(x,eq(x,x)) proof: p=cite(H) return p",
        golden::PROOF_ID
    );
    let old = format!(
        "goal=all(x,eq(x,x)) proof: p=cite(\"{}\") return p",
        golden::PROOF_ID
    );
    assert_eq!(
        compile_against_proof_context(&input, &state).unwrap(),
        compile_against_proof_context(&old, &state).unwrap()
    );
    assert!(compile(&input).is_err());
    for wrong in [
        "0".repeat(64),
        "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035".to_owned(),
        hex_encode::hex_string(helper.artifact_id().as_bytes()),
        golden::PROOF_ID.to_uppercase(),
    ] {
        assert!(
            compile_against_proof_context(&input.replace(golden::PROOF_ID, &wrong), &state)
                .is_err()
        );
    }
    let pruned = format!(
        "refs: unused=\"{}\" goal=all(x,eq(x,x)) proof: dead=cite(unused) a=refl(x) b=gen(a,x) return b",
        "0".repeat(64)
    );
    assert_eq!(compile(&pruned).unwrap(), compile(SIMPLE).unwrap());
    assert_eq!(before, state.snapshot_id());
}

#[test]
fn old_headers_long_spellings_and_complete_input_boundaries_fail_closed() {
    for bad in [
        format!("nao 1 {SIMPLE}"),
        format!("nao 2 {SIMPLE}"),
        format!("foundation=\"naome:zfc\" {SIMPLE}"),
        SIMPLE.replace("goal=", "statement="),
        SIMPLE.replace("eq(x,x)", "equal(x,x)"),
        SIMPLE.replace("refl(x)", "equality_reflexivity(x)"),
        format!("{SIMPLE} {SIMPLE}"),
        format!("{SIMPLE} garbage"),
        SIMPLE.replace("return b", "return a"),
        SIMPLE.replace("all(x,", "all([],"),
        SIMPLE.replace("all(x,", "all([x,,],"),
        SIMPLE.replace("a=refl(x)", "a=gen(future,x)"),
        SIMPLE.replace("goal=", "let: eq=eq(x,x) goal="),
        SIMPLE.replace("goal=", "let: A=A goal="),
        SIMPLE.replace("goal=", "let: A=eq(x,x) A=eq(x,x) goal="),
        SIMPLE.replace("goal=", "refs: H=\"00\" goal="),
        SIMPLE.replace("a=refl(x)", "a=cite(missing)"),
        SIMPLE.replace("eq(x,x)", "e\u{0431}(x,x)"),
        SIMPLE.replace("refl(x)", "refl(\"x\")"),
    ] {
        assert!(compile(&bad).is_err(), "accepted {bad}");
    }
    for bad in [
        "goal=all([],eq(x,x))",
        "let: A=A goal=all(x,A)",
        "let: A=eq(x,x) A=eq(x,x) goal=all(x,A)",
        "let: eq=eq(x,x) goal=all(x,eq)",
        "goal=all(x,eq(x,y))",
        "goal=all(x,eq(f(x),x))",
        "refs: H=\"00\" goal=all(x,eq(x,x))",
        "defs: H=\"00\" goal=all(x,eq(x,x))",
        "goal=all(x,eq(x,x)) proof: p=refl(x) return p",
        "goal=all(x,eq(x,x)) goal=all(x,eq(x,x))",
    ] {
        assert!(CompiledQuestion::compile(bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn comments_literals_and_original_source_diagnostics_are_not_rewritten() {
    for ending in ["\n", "\r\n"] {
        let source = format!(
            "# nao 999 refs UTF8 \u{202e}ä{ending}{} # unknown macros ~eq",
            SIMPLE.replace('\n', ending)
        );
        assert_eq!(compile(&source).unwrap(), compile(SIMPLE).unwrap());
    }
    assert_eq!(
        compile(&SIMPLE.replace('\n', "\r")).unwrap(),
        compile(SIMPLE).unwrap()
    );
    assert!(compile(&format!("# comment\r{SIMPLE}")).is_err()); // comments end at LF
    let source = SIMPLE.replace("refl(x)", "cite(\"refl#~eq\")");
    assert!(compile(&source).is_err());
    let source = "# ä\r\ngoal=all(x,eq(x,x))\rproof: good=refl(x) bad=gen(missing,x) return bad";
    let error = compile(source).unwrap_err().diagnostic(source);
    assert_eq!(error.code(), DiagnosticCode::UnknownStep);
    let span = error.primary_span().unwrap();
    assert_eq!(&source[span.start()..span.end()], "missing");
    assert_eq!(error.primary_position().unwrap().line(), 3);
    let source = "# ä\r\nlet: A=eq(x,x)\rgoal=all(x,missing)";
    let error = CompiledQuestion::compile_with_diagnostic(source).unwrap_err();
    assert_eq!(error.diagnostic().code(), DiagnosticCode::QuestionSyntax);
    let span = error.diagnostic().primary_span().unwrap();
    assert_eq!(&source[span.start()..span.end()], "missing");
    assert_eq!(error.diagnostic().primary_position().unwrap().line(), 3);
    let eof = "goal=all(x,eq(x,x)";
    assert_eq!(
        CompiledQuestion::compile_with_diagnostic(eof)
            .unwrap_err()
            .diagnostic()
            .primary_span()
            .unwrap()
            .start(),
        eof.len()
    );
}

#[test]
fn raw_expanded_and_retained_formula_budgets_precede_allocation() {
    assert!(matches!(
        compile(&" ".repeat(AUTHORING_SOURCE_MAX_BYTES + 1)),
        Err(CompileError::SourceTooLong { .. })
    ));
    assert_eq!(
        CompiledQuestion::compile_with_diagnostic(&" ".repeat(QUESTION_SOURCE_MAX_BYTES + 1))
            .unwrap_err()
            .diagnostic()
            .code(),
        DiagnosticCode::SourceTooLong
    );
    let mut input = "let: A=eq(x,x)".to_owned();
    for (next, prev) in [("B", "A"), ("C", "B"), ("D", "C"), ("E", "D"), ("F", "E")] {
        input.push_str(&format!(" {next}=iff({prev},{prev})"));
    }
    input.push_str(" goal=all(x,F)");
    assert_eq!(
        CompiledQuestion::compile_with_diagnostic(&input)
            .unwrap_err()
            .diagnostic()
            .code(),
        DiagnosticCode::QuestionLimit
    );
    assert!(
        CompiledQuestion::compile(&format!(
            "goal={}all(x,eq(x,x)){}",
            "not(".repeat(300),
            ")".repeat(300)
        ))
        .is_err()
    );
    assert!(
        compile(&SIMPLE.replace(
            "eq(x,x)",
            &format!("{}eq(x,x){}", "not(".repeat(300), ")".repeat(300))
        ))
        .is_err()
    );
}

#[test]
fn function_term_preflight_preserves_boundary_and_rejects_hostile_recursion() {
    let state = context();
    for nesting in [1, 42] {
        let term = format!("{}x{}", "identity(".repeat(nesting), ")".repeat(nesting));
        let atom = format!("eq({term},x)");
        let old = format!(
            "defs: identity=\"1b976399f4226292fdea6b89c496e976cbcd86eb1458bc265cdd14e04d1cf854\" goal=all(x,imp({atom},imp({atom},{atom}))) proof: p=simp({atom},{atom}) q=gen(p,x) return q"
        );
        let checked = compile_against_proof_context(&old, &state).unwrap();
        assert_eq!(
            checked,
            compile_against_proof_context(&old.replace("identity(", "identity( "), &state).unwrap()
        );
    }
    let source = format!(
        "defs: identity=\"1b976399f4226292fdea6b89c496e976cbcd86eb1458bc265cdd14e04d1cf854\" goal=all(x,eq({}x{},x)) proof: p=refl(x) q=gen(p,x) return q",
        "identity(".repeat(4000),
        ")".repeat(4000)
    );
    std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(move || {
            assert!(matches!(
                compile_against_proof_context(&source, &state),
                Err(CompileError::FormulaDepthLimitExceeded { .. })
            ));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn checker_valid_wrong_target_is_rejected_and_exact_question_orientation_matches() {
    let proof = compile(SIMPLE).unwrap();
    let certificate =
        ProofCertificate::from_canonical_bytes(proof.canonical_proof_bytes()).unwrap();
    let checked = check_normal_form_with_state(
        certificate.into_unchecked_normal_form(),
        &ArtifactState::new(),
    )
    .unwrap();
    let odd = CompiledQuestion::compile("goal=not(all(x,eq(x,x)))").unwrap();
    assert_eq!(
        odd.classify_checked_proof(&checked).unwrap(),
        naome_authoring::QuestionOutcome::Refuted
    );
    let unrelated = CompiledQuestion::compile("goal=all(x,imp(eq(x,x),eq(x,x)))").unwrap();
    assert!(unrelated.classify_checked_proof(&checked).is_err());
    let wrong = SIMPLE.replace("all(x,eq(x,x))", "all(x,imp(eq(x,x),eq(x,x)))");
    assert!(matches!(
        compile(&wrong),
        Err(CompileError::StatementMismatch { .. })
    ));
}

#[test]
fn source_bearing_question_codec_rejects_unsupported_source_without_translation() {
    for unsupported in [
        "foundation=\"naome:zfc\" statement=forall(x,equal(x,x))",
        "nao 1 goal=all(x,eq(x,x))",
        "statement=all(x,eq(x,x))",
        "goal=forall(x,equal(x,x))",
    ] {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(unsupported.len() as u32).to_be_bytes());
        bytes.extend_from_slice(unsupported.as_bytes());
        assert!(CompiledQuestion::from_canonical_bytes(&bytes).is_err());
    }
    let current = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    assert_eq!(
        CompiledQuestion::from_canonical_bytes(&current.to_canonical_bytes().unwrap()).unwrap(),
        current
    );
}
