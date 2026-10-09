//! Executable generation-prompt examples and exact fixed-axiom catalogue.
use naome_authoring::{
    CompileError, CompiledArtifact, CompiledQuestion, QuestionOutcome, compile_artifact,
    compile_artifact_against_proof_context,
};
use naome_checker::{ArtifactState, check_definition_with_state, check_normal_form_with_state};
use naome_foundation::{Formula, FreeVariable, Separation, ZfcAxiom};
use naome_proof::ArtifactPayload;

const NATIVE_INSTRUCTIONS: &str =
    include_str!("../../naome-knowledge/src/generation/native_authoring.txt");
const QUESTION_INSTRUCTIONS: &str =
    include_str!("../../naome-knowledge/src/generation/question.txt");
const PROOF_INSTRUCTIONS: &str = include_str!("../../naome-knowledge/src/generation/proof.txt");

#[test]
fn complete_prompt_examples_check_in_their_explicit_offline_context() {
    let mut state = ArtifactState::new();
    let mut examples = 0;
    for section in NATIVE_INSTRUCTIONS.split("<!-- nao-example: ").skip(1) {
        let (kind, rest) = section.split_once(" -->").unwrap();
        let source = rest
            .split_once("```nao\n")
            .unwrap()
            .1
            .split_once("\n```")
            .unwrap()
            .0;
        examples += 1;
        let before = state.snapshot_id();
        if kind == "question" {
            let question = CompiledQuestion::compile(source).unwrap();
            let x = FreeVariable::new(0);
            let a = Formula::equal(x, x);
            let core = Formula::for_all(x, Formula::implies(a.clone(), a));
            assert_eq!(question.core(), &core);
            assert!(question.negation_parity());
            assert_eq!(question.refuted_target(), &core);
            assert_eq!(
                CompiledQuestion::from_canonical_bytes(&question.to_canonical_bytes().unwrap())
                    .unwrap(),
                question
            );
            continue;
        }
        let artifact = compile_artifact_against_proof_context(source, &state)
            .unwrap_or_else(|error| panic!("prompt example {examples}: {error}"));
        assert_eq!(
            state.snapshot_id(),
            before,
            "compilation must not mutate the supplied context"
        );
        if matches!(examples, 9 | 10) {
            assert!(
                compile_artifact(source).is_err(),
                "the declared dependencies cannot be supplied by the standalone CLI"
            );
        }
        match ArtifactPayload::from_canonical_bytes(&artifact.canonical_artifact_bytes()).unwrap() {
            ArtifactPayload::Proof(certificate) => {
                assert_eq!(kind, "proof");
                assert!(matches!(artifact, CompiledArtifact::Proof(_)));
                let checked =
                    check_normal_form_with_state(certificate.into_unchecked_normal_form(), &state)
                        .unwrap();
                assert!(checked.conclusion().is_closed());
                let _ = state.register_proof(checked).unwrap();
            }
            ArtifactPayload::Definition(certificate) => {
                assert_eq!(kind, "definition");
                assert!(matches!(artifact, CompiledArtifact::Definition(_)));
                let checked = check_definition_with_state(certificate, &state).unwrap();
                state.register_definition(checked).unwrap();
            }
        }
    }
    assert_eq!(examples, 11);
}

#[test]
fn prompt_axiom_catalogue_matches_every_fixed_mathematical_axiom() {
    for (heading, axiom) in [
        ("Extensionality:", ZfcAxiom::Extensionality),
        ("Pairing:", ZfcAxiom::Pairing),
        ("Union:", ZfcAxiom::Union),
        ("Power set:", ZfcAxiom::PowerSet),
        ("Infinity:", ZfcAxiom::Infinity),
        ("Foundation:", ZfcAxiom::Foundation),
        (
            "Choice (the checker uses the pairwise-disjoint-family formulation):",
            ZfcAxiom::Choice,
        ),
    ] {
        let section = NATIVE_INSTRUCTIONS.split_once(heading).unwrap().1;
        let formula = section
            .split_once("```text\n")
            .unwrap()
            .1
            .split_once("\n```")
            .unwrap()
            .0;
        let source = format!("goal={formula}");
        let question =
            CompiledQuestion::compile(&source).unwrap_or_else(|error| panic!("{heading}: {error}"));
        assert_eq!(question.formula(), &axiom.formula(), "{heading}");
    }
}

fn marked_sources<'source>(
    instructions: &'source str,
    marker: &str,
) -> Vec<(&'source str, &'source str)> {
    instructions
        .split(marker)
        .skip(1)
        .map(|section| {
            let (kind, rest) = section.split_once(" -->").unwrap();
            let source = rest
                .split_once("```nao\n")
                .unwrap()
                .1
                .split_once("\n```")
                .unwrap()
                .0;
            (kind, source)
        })
        .collect()
}

#[test]
fn question_role_examples_preserve_scope_order_orientation_and_schema_meaning() {
    let sources = marked_sources(QUESTION_INSTRUCTIONS, "<!-- nao-example: ");
    assert_eq!(sources.len(), 3);
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let transport = Formula::for_all(
        x,
        Formula::for_all(
            y,
            Formula::implies(
                Formula::equal(x, y),
                Formula::implies(Formula::member(x, y), Formula::member(y, y)),
            ),
        ),
    );
    let p = Formula::member(x, y);
    let identity = Formula::for_all(x, Formula::for_all(y, Formula::implies(p.clone(), p)));
    let s = FreeVariable::new(0);
    let r = FreeVariable::new(1);
    let e = FreeVariable::new(2);
    let separation = Separation {
        predicate: Formula::negate(Formula::member(e, e)),
        element: e,
        source: s,
        result: r,
        parameters: Vec::new(),
    }
    .formula()
    .unwrap();
    for ((kind, source), (core, negative)) in
        sources
            .into_iter()
            .zip([(transport, false), (identity, true), (separation, false)])
    {
        assert_eq!(kind, "question");
        let question = CompiledQuestion::compile(source).unwrap();
        assert_eq!(question.core(), &core);
        assert_eq!(question.negation_parity(), negative);
        let negated = Formula::negate(core.clone());
        assert_eq!(question.positive_target(), &core);
        assert_eq!(question.negative_target(), &negated);
        assert_eq!(
            question.proved_target(),
            if negative { &negated } else { &core }
        );
    }
}

#[test]
fn proof_role_example_really_resolves_its_exact_question() {
    let sources = marked_sources(PROOF_INSTRUCTIONS, "<!-- nao-example: ");
    assert_eq!(sources.len(), 1);
    let (kind, source) = sources[0];
    assert_eq!(kind, "proof");
    let artifact = compile_artifact(source).unwrap();
    let ArtifactPayload::Proof(certificate) =
        ArtifactPayload::from_canonical_bytes(&artifact.canonical_artifact_bytes()).unwrap()
    else {
        panic!("proof role example must compile to a proof")
    };
    let checked = check_normal_form_with_state(
        certificate.into_unchecked_normal_form(),
        &ArtifactState::new(),
    )
    .unwrap();
    let question =
        CompiledQuestion::compile("goal=all([x,y,s],imp(eq(x,y),imp(mem(x,s),mem(y,s))))").unwrap();
    assert_eq!(
        question.classify_checked_proof(&checked).unwrap(),
        QuestionOutcome::Proved
    );
    let changed =
        CompiledQuestion::compile("goal=all([y,x,s],imp(eq(x,y),imp(mem(x,s),mem(y,s))))").unwrap();
    assert!(changed.classify_checked_proof(&checked).is_err());
}

#[test]
fn role_rejection_examples_fail_through_the_actual_compiler_and_checker() {
    let questions = marked_sources(QUESTION_INSTRUCTIONS, "<!-- nao-rejection: ");
    assert_eq!(questions.len(), 2);
    for (kind, source) in questions {
        assert_eq!(kind, "question");
        assert!(CompiledQuestion::compile(source).is_err());
    }
    let proofs = marked_sources(PROOF_INSTRUCTIONS, "<!-- nao-rejection: ");
    assert_eq!(proofs.len(), 2);
    let (kind, source) = proofs[0];
    assert_eq!(kind, "proof");
    assert!(matches!(
        compile_artifact(source),
        Err(CompileError::StatementMismatch { .. })
    ));
    let (kind, source) = proofs[1];
    assert_eq!(kind, "proof");
    assert!(matches!(
        compile_artifact(source),
        Err(CompileError::Check { .. })
    ));
}
