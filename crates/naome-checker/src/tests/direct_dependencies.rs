use naome_proof::{ArtifactId, DefinitionKind};

use super::*;

fn select_relation(state: &mut ArtifactState, body: DefinedFormula) -> DefinitionId {
    let checked = check_definition_with_state(
        DefinitionCertificate::relation(1, body).expect("the relation definition is valid"),
        state,
    )
    .expect("the relation definition checks");
    let definition_id = checked.definition_id();
    state
        .register_definition(checked)
        .expect("the relation definition is selected once");
    definition_id
}

fn select_closed_proof(state: &mut ArtifactState) -> (ProofId, Formula) {
    let variable = FreeVariable::new(7);
    let checked = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]))
    .expect("the closed proof checks");
    let proof_id = checked.proof_id();
    let conclusion = checked.conclusion().clone();
    state
        .register_proof(checked)
        .expect("the closed proof is selected once");
    (proof_id, conclusion)
}

#[test]
fn dependency_free_checked_proof_returns_an_empty_set() {
    let variable = FreeVariable::new(9);
    let checked = normalize_and_check(certificate(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ]))
    .unwrap();

    assert!(checked.direct_artifact_dependencies().is_empty());
}

#[test]
fn repeated_direct_proof_references_collapse_to_one_artifact() {
    let mut state = ArtifactState::new();
    let (proof_id, theorem) = select_closed_proof(&mut state);
    let checked = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference { proof_id },
            ProofStep::ProofReference { proof_id },
            ProofStep::Simplification {
                antecedent: theorem.clone().into(),
                consequent: theorem.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 3,
            },
        ]),
        &state,
    )
    .unwrap();

    assert_eq!(
        checked.direct_artifact_dependencies().as_ref(),
        &[ArtifactId::from_proof_id(proof_id)]
    );
}

#[test]
fn repeated_direct_definition_references_collapse_to_one_artifact() {
    let variable = FreeVariable::new(11);
    let mut state = ArtifactState::new();
    let definition_id = select_relation(
        &mut state,
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    );
    let defined = DefinedFormula::defined_relation(definition_id, [variable]);
    let checked = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::Simplification {
                antecedent: proof_formula(defined.clone()),
                consequent: proof_formula(defined),
            },
            ProofStep::Generalization {
                premise: 0,
                variable,
            },
        ]),
        &state,
    )
    .unwrap();

    assert_eq!(
        checked.direct_artifact_dependencies().as_ref(),
        &[ArtifactId::from_definition_id(definition_id)]
    );
}

#[test]
fn mixed_dependencies_are_sorted_independently_of_source_step_order() {
    let variable = FreeVariable::new(13);
    let mut state = ArtifactState::new();
    let (proof_id, theorem) = select_closed_proof(&mut state);
    let definition_id = select_relation(
        &mut state,
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    );
    let defined = || DefinedFormula::defined_relation(definition_id, [variable]);
    let implication = || ProofStep::Simplification {
        antecedent: theorem.clone().into(),
        consequent: proof_formula(defined()),
    };
    let proof_first = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference { proof_id },
            implication(),
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::Generalization {
                premise: 2,
                variable,
            },
        ]),
        &state,
    )
    .unwrap();
    let definition_first = normalize_and_check_with_state(
        certificate(vec![
            implication(),
            ProofStep::ProofReference { proof_id },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 0,
            },
            ProofStep::Generalization {
                premise: 2,
                variable,
            },
        ]),
        &state,
    )
    .unwrap();
    let mut expected = vec![
        ArtifactId::from_proof_id(proof_id),
        ArtifactId::from_definition_id(definition_id),
    ];
    expected.sort_unstable();

    assert_eq!(
        proof_first.direct_artifact_dependencies().as_ref(),
        expected.as_slice()
    );
    assert_eq!(
        definition_first.direct_artifact_dependencies().as_ref(),
        expected.as_slice()
    );
}

#[test]
fn unreachable_raw_references_are_excluded() {
    let unknown_proof = ProofId::from_bytes([0x11; 32]);
    let unknown_definition = DefinitionId::from_bytes([0x22; 32]);
    let variable = FreeVariable::new(15);
    let unreachable = DefinedFormula::defined_relation(unknown_definition, [variable]);
    let checked = normalize_and_check(certificate(vec![
        ProofStep::ProofReference {
            proof_id: unknown_proof,
        },
        ProofStep::Simplification {
            antecedent: proof_formula(unreachable.clone()),
            consequent: proof_formula(unreachable),
        },
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 2,
            variable,
        },
    ]))
    .expect("normalization prunes unreachable raw references before checking");

    assert_eq!(checked.normal_form().certificate().steps().len(), 2);
    assert!(checked.direct_artifact_dependencies().is_empty());
}

#[test]
fn direct_proof_dependencies_do_not_expand_to_transitive_ancestors() {
    let mut state = ArtifactState::new();
    let (base_id, theorem) = select_closed_proof(&mut state);
    let intermediate = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::ProofReference { proof_id: base_id },
            ProofStep::Simplification {
                antecedent: theorem.into(),
                consequent: ZfcAxiom::Extensionality.formula().into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]),
        &state,
    )
    .unwrap();
    let intermediate_id = intermediate.proof_id();
    state.register_proof(intermediate).unwrap();
    let checked = normalize_and_check_with_state(
        certificate(vec![ProofStep::ProofReference {
            proof_id: intermediate_id,
        }]),
        &state,
    )
    .unwrap();
    let dependencies = checked.direct_artifact_dependencies();

    assert_eq!(
        dependencies.as_ref(),
        &[ArtifactId::from_proof_id(intermediate_id)]
    );
    assert!(!dependencies.contains(&ArtifactId::from_proof_id(base_id)));
}

#[test]
fn direct_definition_dependencies_do_not_expand_authoring_ancestors() {
    let variable = FreeVariable::new(17);
    let formal = FreeVariable::new(0);
    let mut state = ArtifactState::new();
    let base_id = select_relation(&mut state, DefinedFormula::equal(formal, formal));
    let use_base = || DefinedFormula::defined_relation(base_id, [formal]);
    let alias = normalize_and_check_definition_with_state(
        DefinitionKind::Relation { arity: 1 },
        DefinedFormula::conjunction(use_base(), use_base()),
        &state,
    )
    .unwrap();
    let alias_id = alias.definition_id();
    state.register_definition(alias).unwrap();
    let defined = DefinedFormula::defined_relation(alias_id, [variable]);
    let checked = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::Simplification {
                antecedent: proof_formula(defined.clone()),
                consequent: proof_formula(defined),
            },
            ProofStep::Generalization {
                premise: 0,
                variable,
            },
        ]),
        &state,
    )
    .unwrap();
    let dependencies = checked.direct_artifact_dependencies();

    assert_ne!(alias_id, base_id);
    assert_eq!(
        dependencies.as_ref(),
        &[ArtifactId::from_definition_id(alias_id)]
    );
    assert!(!dependencies.contains(&ArtifactId::from_definition_id(base_id)));
}
