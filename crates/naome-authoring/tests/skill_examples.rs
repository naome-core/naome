//! Executable self-contained guide examples and exact fixed-axiom catalogue.
use naome_authoring::{
    CompiledArtifact, CompiledQuestion, compile_artifact, compile_artifact_against_proof_context,
};
use naome_checker::{ArtifactState, check_definition_with_state, check_normal_form_with_state};
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_proof::ArtifactPayload;

const GUIDE: &str = include_str!("../../../NAO_SKILL.md");

#[test]
fn complete_skill_examples_check_in_their_explicit_offline_context() {
    let mut state = ArtifactState::new();
    let mut examples = 0;
    for section in GUIDE.split("<!-- nao-example: ").skip(1) {
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
            .unwrap_or_else(|error| panic!("guide example {examples}: {error}"));
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
fn skill_axiom_catalogue_matches_every_fixed_mathematical_axiom() {
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
        let section = GUIDE.split_once(heading).unwrap().1;
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
