use naome_proof::{DefinitionKind, DefinitionResolver};

use super::*;

fn identity_unique_certificate() -> ProofCertificate {
    let digits = include_str!("fixtures/identity_unique.proof.hex")
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    assert_eq!(digits.len(), 12_554);
    let bytes = digits
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect::<Vec<_>>();
    ProofCertificate::from_canonical_bytes(&bytes).expect("the frozen 75-step proof is canonical")
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("fixture contains a non-hex byte"),
    }
}

fn identity_obligation() -> Formula {
    let input = FreeVariable::new(0);
    let output = FreeVariable::new(1);
    let witness = FreeVariable::new(2);
    Formula::for_all(
        input,
        Formula::exists(
            output,
            Formula::conjunction(
                Formula::equal(output, input),
                Formula::for_all(
                    witness,
                    Formula::implies(
                        Formula::equal(witness, input),
                        Formula::equal(witness, output),
                    ),
                ),
            ),
        ),
    )
}

fn select_identity_obligation(state: &mut ArtifactState) -> ProofId {
    let certificate = identity_unique_certificate();
    assert_eq!(certificate.steps().len(), 75);
    let proof = normalize_and_check(certificate).expect("the current calculus proves identity");
    assert_eq!(proof.conclusion(), &identity_obligation());
    assert_eq!(
        proof.proof_id(),
        ProofId::from_bytes([
            0x29, 0x8a, 0x10, 0x15, 0x56, 0x46, 0x1a, 0xe8, 0x9f, 0x89, 0x1c, 0x92, 0x8d, 0x4e,
            0x5e, 0x02, 0x90, 0x70, 0x94, 0x52, 0xd9, 0x3d, 0xea, 0x60, 0x19, 0xc7, 0x56, 0x8e,
            0x89, 0xa1, 0x09, 0x70,
        ])
    );
    let proof_id = proof.proof_id();
    state.register_proof(proof).unwrap();
    proof_id
}

fn self_relation() -> DefinitionCertificate {
    let value = FreeVariable::new(0);
    DefinitionCertificate::relation(1, DefinedFormula::equal(value, value)).unwrap()
}

fn select_definition(
    state: &mut ArtifactState,
    certificate: DefinitionCertificate,
) -> DefinitionId {
    let checked = check_definition_with_state(certificate, state).unwrap();
    let definition_id = checked.definition_id();
    state.register_definition(checked).unwrap();
    definition_id
}

#[test]
fn relation_definitions_expand_only_from_selected_state_and_cache_dependencies() {
    let mut state = ArtifactState::new();
    let base_id = select_definition(&mut state, self_relation());
    let parameter = FreeVariable::new(0);
    let alias =
        DefinitionCertificate::relation(1, DefinedFormula::defined_relation(base_id, [parameter]))
            .unwrap();
    let alias_id = select_definition(&mut state, alias);

    let x = FreeVariable::new(8);
    let compact = DefinedFormula::defined_relation(alias_id, [x]);
    let proof = certificate(vec![
        ProofStep::Simplification {
            antecedent: proof_formula(compact.clone()),
            consequent: proof_formula(compact),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]);
    let checked = normalize_and_check_with_state(proof, &state).unwrap();
    let normalized = FreeVariable::new(0);
    assert_eq!(
        checked.conclusion(),
        &Formula::for_all(
            normalized,
            Logic::simplification(
                Formula::equal(normalized, normalized),
                Formula::equal(normalized, normalized),
            ),
        )
    );
}

#[test]
fn dependent_definition_resolution_exposes_graph_data_without_a_second_identity() {
    let mut state = ArtifactState::new();
    let base_id = select_definition(&mut state, self_relation());
    let parameter = FreeVariable::new(0);
    let alias =
        DefinitionCertificate::relation(1, DefinedFormula::defined_relation(base_id, [parameter]))
            .unwrap();
    let alias_id = alias.definition_id();
    let expanded_cache =
        DefinitionCertificate::relation(1, DefinedFormula::equal(parameter, parameter)).unwrap();
    assert_ne!(alias_id, expanded_cache.definition_id());

    assert_eq!(select_definition(&mut state, alias), alias_id);
    let resolution = DefinitionResolver::resolve_definition(&state, alias_id).unwrap();

    assert_eq!(resolution.relation_arity(), 1);
    assert_eq!(resolution.body(), expanded_cache.body());
    assert_eq!(
        state.definition_kind(alias_id),
        Some(DefinitionKind::Relation { arity: 1 })
    );
}

#[test]
fn proof_expansion_is_identity_transparent_but_proof_id_retains_definition_use() {
    let mut state = ArtifactState::new();
    let definition_id = select_definition(&mut state, self_relation());
    let x = FreeVariable::new(20);
    let compact = DefinedFormula::defined_relation(definition_id, [x]);
    let defined = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::Simplification {
                antecedent: proof_formula(compact.clone()),
                consequent: proof_formula(compact),
            },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]),
        &state,
    )
    .unwrap();
    let primitive = normalize_and_check(certificate(vec![
        ProofStep::Simplification {
            antecedent: Formula::equal(x, x).into(),
            consequent: Formula::equal(x, x).into(),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
    ]))
    .unwrap();

    assert_eq!(defined.conclusion(), primitive.conclusion());
    assert_eq!(defined.statement_id(), primitive.statement_id());
    assert_eq!(defined.derivation_id(), primitive.derivation_id());
    assert_ne!(defined.proof_id(), primitive.proof_id());
}

#[test]
fn definition_expansion_is_capture_safe_under_call_site_and_body_binders() {
    let formal = FreeVariable::new(0);
    let inner = FreeVariable::new(1);
    let body = DefinedFormula::for_all(inner, DefinedFormula::member(formal, inner));
    let mut state = ArtifactState::new();
    let definition_id = select_definition(
        &mut state,
        DefinitionCertificate::relation(1, body).unwrap(),
    );
    let outer = FreeVariable::new(7);
    let compact = DefinedFormula::for_all(
        outer,
        DefinedFormula::defined_relation(definition_id, [outer]),
    );
    let expected = Formula::for_all(
        outer,
        Formula::for_all(inner, Formula::member(outer, inner)),
    );

    assert_eq!(
        check_with_canonical_conclusion(
            &certificate(vec![ProofStep::Simplification {
                antecedent: proof_formula(compact.clone()),
                consequent: proof_formula(compact),
            }]),
            &state,
            IdentityMode::OmitDerivation,
        )
        .map(|value| value.0),
        Ok(Logic::simplification(expected.clone(), expected))
    );
}

#[test]
fn missing_and_wrong_arity_definition_references_fail_at_the_rule_step() {
    let unknown = DefinitionId::from_bytes([0x44; 32]);
    let x = FreeVariable::new(3);
    let unknown_formula = DefinedFormula::defined_relation(unknown, [x]);
    let proof = certificate(vec![ProofStep::Simplification {
        antecedent: proof_formula(unknown_formula.clone()),
        consequent: proof_formula(unknown_formula),
    }]);
    assert_eq!(
        check(&proof),
        Err(CheckError::DefinitionExpansion {
            step: 0,
            source: DefinitionExpansionError::UnknownDefinition {
                definition_id: unknown,
            },
        })
    );

    let mut state = ArtifactState::new();
    let definition_id = select_definition(&mut state, self_relation());
    let wrong_arity = DefinedFormula::defined_relation(definition_id, []);
    let proof = certificate(vec![ProofStep::Simplification {
        antecedent: proof_formula(wrong_arity.clone()),
        consequent: proof_formula(wrong_arity),
    }]);
    assert_eq!(
        check_with_canonical_conclusion(&proof, &state, IdentityMode::OmitDerivation),
        Err(CheckError::DefinitionExpansion {
            step: 0,
            source: DefinitionExpansionError::ArityMismatch {
                definition_id,
                expected: 1,
                actual: 0,
            },
        })
    );
}

#[test]
fn definition_check_error_precedence_is_dependency_expansion_then_obligation() {
    let missing_definition = DefinitionId::from_bytes([0x51; 32]);
    let missing_proof = ProofId::from_bytes([0x52; 32]);
    let body = DefinedFormula::defined_relation(missing_definition, [FreeVariable::new(1)]);
    let certificate = DefinitionCertificate::function(1, body, missing_proof).unwrap();
    assert_eq!(
        check_definition_with_state(certificate, &ArtifactState::new()),
        Err(DefinitionCheckError::UnknownDefinitionDependency {
            definition_id: missing_definition,
        })
    );

    let body = DefinedFormula::equal(FreeVariable::new(1), FreeVariable::new(0));
    let certificate = DefinitionCertificate::function(1, body, missing_proof).unwrap();
    assert_eq!(
        check_definition_with_state(certificate, &ArtifactState::new()),
        Err(DefinitionCheckError::UnknownObligationProof {
            proof_id: missing_proof,
        })
    );
}

#[test]
fn constants_and_functions_require_the_exact_selected_obligation_conclusion() {
    let wrong = normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(
        ZfcAxiom::Extensionality,
    )]))
    .unwrap();
    let wrong_id = wrong.proof_id();
    let mut state = ArtifactState::new();
    state.register_proof(wrong).unwrap();

    let constant = DefinitionCertificate::constant(
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
        wrong_id,
    )
    .unwrap();
    assert_eq!(
        check_definition_with_state(constant, &state),
        Err(DefinitionCheckError::ObligationConclusionMismatch { proof_id: wrong_id })
    );

    let function = DefinitionCertificate::function(
        1,
        DefinedFormula::equal(FreeVariable::new(1), FreeVariable::new(0)),
        wrong_id,
    )
    .unwrap();
    assert_eq!(
        check_definition_with_state(function, &state),
        Err(DefinitionCheckError::ObligationConclusionMismatch { proof_id: wrong_id })
    );
}

#[test]
fn real_identity_proof_admits_a_function_definition_and_use_in_a_proof() {
    let mut state = ArtifactState::new();
    let obligation_id = select_identity_obligation(&mut state);
    let input = FreeVariable::new(0);
    let output = FreeVariable::new(1);
    let definition =
        DefinitionCertificate::function(1, DefinedFormula::equal(output, input), obligation_id)
            .unwrap();
    let definition_id = select_definition(&mut state, definition);

    let graph = DefinedFormula::defined_relation(definition_id, [input, output]);
    let checked = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::Simplification {
                antecedent: proof_formula(graph.clone()),
                consequent: proof_formula(graph),
            },
            ProofStep::Generalization {
                premise: 0,
                variable: input,
            },
            ProofStep::Generalization {
                premise: 1,
                variable: output,
            },
        ]),
        &state,
    )
    .unwrap();
    assert!(state.contains_definition(definition_id));
    assert!(checked.conclusion().is_closed());
}

#[test]
fn registration_revalidates_proof_definition_and_obligation_dependencies() {
    let mut source = ArtifactState::new();
    let base_id = select_definition(&mut source, self_relation());
    let parameter = FreeVariable::new(0);
    let alias =
        DefinitionCertificate::relation(1, DefinedFormula::defined_relation(base_id, [parameter]))
            .unwrap();
    let checked_alias = check_definition_with_state(alias, &source).unwrap();
    assert_eq!(
        ArtifactState::new().register_definition(checked_alias),
        Err(ArtifactStateError::MissingDefinitionDependency {
            definition_id: base_id,
        })
    );

    let compact = DefinedFormula::defined_relation(base_id, [parameter]);
    let checked_proof = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::Simplification {
                antecedent: proof_formula(compact.clone()),
                consequent: proof_formula(compact),
            },
            ProofStep::Generalization {
                premise: 0,
                variable: parameter,
            },
        ]),
        &source,
    )
    .unwrap();
    assert_eq!(
        ArtifactState::new().register_proof(checked_proof),
        Err(ArtifactStateError::MissingDefinitionDependency {
            definition_id: base_id,
        })
    );

    let obligation_id = select_identity_obligation(&mut source);
    let function = DefinitionCertificate::function(
        1,
        DefinedFormula::equal(FreeVariable::new(1), FreeVariable::new(0)),
        obligation_id,
    )
    .unwrap();
    let checked_function = check_definition_with_state(function, &source).unwrap();
    assert_eq!(
        ArtifactState::new().register_definition(checked_function),
        Err(ArtifactStateError::MissingDefinitionObligation {
            proof_id: obligation_id,
        })
    );
}

#[test]
fn generated_obligation_arity_is_bounded_before_large_construction() {
    let wrong =
        normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)])).unwrap();
    let proof_id = wrong.proof_id();
    let mut state = ArtifactState::new();
    state.register_proof(wrong).unwrap();
    let function = DefinitionCertificate::new(
        DefinitionKind::Function {
            input_arity: u32::MAX - 1,
            total_unique_proof: proof_id,
        },
        DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
    )
    .unwrap();
    assert_eq!(
        check_definition_with_state(function, &state),
        Err(DefinitionCheckError::ObligationFormula(
            FormulaCodecError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            },
        ))
    );
}

#[test]
fn duplicate_definition_registration_is_fail_closed() {
    let certificate = self_relation();
    let definition_id = certificate.definition_id();
    let mut state = ArtifactState::new();
    let checked = check_definition_with_state(certificate.clone(), &state).unwrap();
    assert_eq!(state.register_definition(checked), Ok(()));
    assert!(state.contains_definition(definition_id));
    let duplicate = check_definition_with_state(certificate, &state).unwrap();
    assert_eq!(
        state.validate_definition_registration(&duplicate),
        Err(ArtifactStateError::DuplicateDefinition { definition_id })
    );
    assert_eq!(
        state.register_definition(duplicate),
        Err(ArtifactStateError::DuplicateDefinition { definition_id })
    );
}

#[test]
fn unreachable_definition_references_are_pruned_before_check_and_registration() {
    let unknown = DefinitionId::from_bytes([0x91; 32]);
    let variable = FreeVariable::new(6);
    let unreachable = DefinedFormula::defined_relation(unknown, [variable]);
    let source = certificate(vec![
        ProofStep::Simplification {
            antecedent: proof_formula(unreachable.clone()),
            consequent: proof_formula(unreachable),
        },
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 1,
            variable,
        },
    ]);
    assert_eq!(
        check(&source),
        Err(CheckError::DefinitionExpansion {
            step: 0,
            source: DefinitionExpansionError::UnknownDefinition {
                definition_id: unknown,
            },
        })
    );

    let checked = normalize_and_check(source).unwrap();
    assert_eq!(checked.normal_form().certificate().steps().len(), 2);
    ArtifactState::new().register_proof(checked).unwrap();
}

#[test]
fn repeated_selected_definition_dependencies_are_admissible() {
    let mut state = ArtifactState::new();
    let base_id = select_definition(&mut state, self_relation());
    let parameter = FreeVariable::new(0);
    let use_base = || DefinedFormula::defined_relation(base_id, [parameter]);
    let alias =
        DefinitionCertificate::relation(1, DefinedFormula::conjunction(use_base(), use_base()))
            .unwrap();
    let alias_id = select_definition(&mut state, alias);

    let repeated = DefinedFormula::conjunction(
        DefinedFormula::defined_relation(alias_id, [parameter]),
        DefinedFormula::defined_relation(alias_id, [parameter]),
    );
    let checked = normalize_and_check_with_state(
        certificate(vec![
            ProofStep::Simplification {
                antecedent: proof_formula(repeated.clone()),
                consequent: proof_formula(repeated),
            },
            ProofStep::Generalization {
                premise: 0,
                variable: parameter,
            },
        ]),
        &state,
    )
    .unwrap();
    state.register_proof(checked).unwrap();
}

#[test]
fn every_formula_bearing_foundation_rule_expands_before_rule_execution() {
    let variable = FreeVariable::new(11);
    let replacement = FreeVariable::new(12);
    let primitive = closed_equality(variable);
    let mut state = ArtifactState::new();
    let definition_id = select_definition(
        &mut state,
        DefinitionCertificate::relation(0, DefinedFormula::from_primitive(&primitive).unwrap())
            .unwrap(),
    );
    let defined = || DefinedFormula::defined_relation(definition_id, []);
    let cases = [
        (
            ProofStep::Simplification {
                antecedent: proof_formula(defined()),
                consequent: proof_formula(defined()),
            },
            Logic::simplification(primitive.clone(), primitive.clone()),
        ),
        (
            ProofStep::Frege {
                first: proof_formula(defined()),
                second: proof_formula(defined()),
                third: proof_formula(defined()),
            },
            Logic::frege(primitive.clone(), primitive.clone(), primitive.clone()),
        ),
        (
            ProofStep::ClassicalContraposition {
                antecedent: proof_formula(defined()),
                consequent: proof_formula(defined()),
            },
            Logic::classical_contraposition(primitive.clone(), primitive.clone()),
        ),
        (
            ProofStep::UniversalDistribution {
                variable,
                antecedent: proof_formula(defined()),
                consequent: proof_formula(defined()),
            },
            Logic::universal_distribution(variable, primitive.clone(), primitive.clone()),
        ),
        (
            ProofStep::VacuousUniversal {
                formula: proof_formula(defined()),
            },
            Logic::vacuous_universal(primitive.clone()),
        ),
        (
            ProofStep::UniversalInstantiation {
                variable,
                replacement,
                body: proof_formula(defined()),
            },
            Logic::universal_instantiation(variable, replacement, primitive.clone()),
        ),
    ];
    for (step, expected) in cases {
        assert_eq!(
            check_with_canonical_conclusion(
                &certificate(vec![step]),
                &state,
                IdentityMode::OmitDerivation,
            )
            .map(|value| value.0),
            Ok(expected)
        );
    }

    let equality = certificate(vec![
        ProofStep::EqualitySubstitution {
            from: variable,
            to: replacement,
            body: proof_formula(defined()),
        },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
        ProofStep::Generalization {
            premise: 1,
            variable: replacement,
        },
    ]);
    assert_eq!(
        check_with_canonical_conclusion(&equality, &state, IdentityMode::OmitDerivation)
            .map(|value| value.0),
        Ok(Logic::generalization(
            replacement,
            Logic::generalization(
                variable,
                Logic::equality_substitution(variable, replacement, primitive),
            ),
        ))
    );
}

#[test]
fn zfc_schema_predicates_expand_before_unchanged_schema_validation() {
    let element = FreeVariable::new(0);
    let source = FreeVariable::new(1);
    let result = FreeVariable::new(2);
    let output = FreeVariable::new(1);
    let uniqueness_witness = FreeVariable::new(2);
    let replacement_source = FreeVariable::new(3);
    let replacement_result = FreeVariable::new(4);
    let mut state = ArtifactState::new();
    let member_id = select_definition(
        &mut state,
        DefinitionCertificate::relation(2, DefinedFormula::member(element, source)).unwrap(),
    );
    let equal_id = select_definition(
        &mut state,
        DefinitionCertificate::relation(2, DefinedFormula::equal(element, source)).unwrap(),
    );

    let separation = Separation {
        predicate: Formula::member(element, source),
        element,
        source,
        result,
        parameters: Vec::new(),
    };
    let expected = separation.formula().unwrap();
    let step = ProofStep::Separation(ProofSeparation {
        predicate: proof_formula(DefinedFormula::defined_relation(
            member_id,
            [element, source],
        )),
        element,
        source,
        result,
        parameters: Vec::new(),
    });
    assert_eq!(
        check_with_canonical_conclusion(
            &certificate(vec![step]),
            &state,
            IdentityMode::OmitDerivation,
        )
        .map(|value| value.0),
        Ok(expected)
    );

    let replacement = Replacement {
        predicate: Formula::equal(element, output),
        input: element,
        output,
        uniqueness_witness,
        source: replacement_source,
        result: replacement_result,
        parameters: Vec::new(),
    };
    let expected = replacement.formula().unwrap();
    let step = ProofStep::Replacement(ProofReplacement {
        predicate: proof_formula(DefinedFormula::defined_relation(
            equal_id,
            [element, output],
        )),
        input: element,
        output,
        uniqueness_witness,
        source: replacement_source,
        result: replacement_result,
        parameters: Vec::new(),
    });
    assert_eq!(
        check_with_canonical_conclusion(
            &certificate(vec![step]),
            &state,
            IdentityMode::OmitDerivation,
        )
        .map(|value| value.0),
        Ok(expected)
    );
}
