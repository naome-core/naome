use super::*;

#[test]
fn checked_proof_couples_a_nontrivial_hilbert_derivation_to_its_conclusion() {
    let x = FreeVariable::new(27);
    let y = FreeVariable::new(42);
    let proposition = Formula::member(x, y);
    let self_implication = Formula::implies(proposition.clone(), proposition.clone());
    let proof = certificate(vec![
        ProofStep::Simplification {
            antecedent: proposition.clone().into(),
            consequent: proposition.clone().into(),
        },
        ProofStep::Simplification {
            antecedent: proposition.clone().into(),
            consequent: self_implication.clone().into(),
        },
        ProofStep::Frege {
            first: proposition.clone().into(),
            second: self_implication.into(),
            third: proposition.clone().into(),
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 3,
        },
        ProofStep::Generalization {
            premise: 4,
            variable: x,
        },
        ProofStep::Generalization {
            premise: 5,
            variable: y,
        },
    ]);
    let expected = Logic::generalization(
        y,
        Logic::generalization(x, Formula::implies(proposition.clone(), proposition)),
    );

    let checked = normalize_and_check(proof).unwrap();

    assert_eq!(checked.normal_form().certificate().steps().len(), 7);
    assert_eq!(checked.conclusion(), &expected);
    assert_eq!(check(checked.normal_form().certificate()), Ok(expected));
}

#[test]
fn equality_substitution_closes_only_through_explicit_generalization() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let body = Formula::member(x, x);
    let substitution = Logic::equality_substitution(x, y, body.clone());
    let after_x = Logic::generalization(x, substitution);
    let expected = Logic::generalization(y, after_x);
    let proof = certificate(vec![
        ProofStep::EqualitySubstitution {
            from: x,
            to: y,
            body: body.into(),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: x,
        },
        ProofStep::Generalization {
            premise: 1,
            variable: y,
        },
    ]);

    assert_eq!(check(&proof), Ok(expected));
}

#[test]
fn every_fixed_zfc_axiom_reconstructs_its_foundation_formula() {
    let axioms = [
        ZfcAxiom::Extensionality,
        ZfcAxiom::Pairing,
        ZfcAxiom::Union,
        ZfcAxiom::PowerSet,
        ZfcAxiom::Infinity,
        ZfcAxiom::Foundation,
        ZfcAxiom::Choice,
    ];

    for axiom in axioms {
        assert_eq!(
            check(&certificate(vec![ProofStep::ZfcAxiom(axiom)])),
            Ok(axiom.formula())
        );
    }
}

#[test]
fn valid_separation_and_replacement_reconstruct_exact_schema_formulas() {
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let parameter = FreeVariable::new(4);
    let second_parameter = FreeVariable::new(5);
    let separation = Separation {
        predicate: Formula::conjunction(
            Formula::member(element, source),
            Formula::conjunction(
                Formula::equal(parameter, parameter),
                Formula::equal(second_parameter, second_parameter),
            ),
        ),
        element,
        source,
        result,
        parameters: vec![parameter, second_parameter],
    };
    let separation_formula = separation
        .formula()
        .expect("the Separation instance is valid");

    assert_eq!(
        check(&certificate(vec![
            ProofStep::Separation(separation.into(),)
        ])),
        Ok(separation_formula)
    );

    let input = FreeVariable::new(10);
    let output = FreeVariable::new(11);
    let uniqueness_witness = FreeVariable::new(12);
    let replacement_source = FreeVariable::new(13);
    let replacement_result = FreeVariable::new(14);
    let replacement_parameter = FreeVariable::new(15);
    let second_replacement_parameter = FreeVariable::new(16);
    let replacement = Replacement {
        predicate: Formula::conjunction(
            Formula::equal(input, output),
            Formula::conjunction(
                Formula::equal(replacement_parameter, replacement_parameter),
                Formula::equal(second_replacement_parameter, second_replacement_parameter),
            ),
        ),
        input,
        output,
        uniqueness_witness,
        source: replacement_source,
        result: replacement_result,
        parameters: vec![replacement_parameter, second_replacement_parameter],
    };
    let replacement_formula = replacement
        .formula()
        .expect("the Replacement instance is valid");

    assert_eq!(
        check(&certificate(vec![ProofStep::Replacement(
            replacement.into(),
        )])),
        Ok(replacement_formula)
    );
}

#[test]
fn modus_ponens_returns_the_exact_closed_consequent() {
    let premise = ZfcAxiom::Extensionality.formula();
    let nested_antecedent = ZfcAxiom::Pairing.formula();
    let proof = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Extensionality),
        ProofStep::Simplification {
            antecedent: premise.clone().into(),
            consequent: nested_antecedent.clone().into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ]);

    assert_eq!(
        check(&proof),
        Ok(Formula::implies(nested_antecedent, premise))
    );
}

#[test]
fn results_remain_live_through_their_last_consumer() {
    let premise = ZfcAxiom::Extensionality.formula();
    let nested_antecedent = ZfcAxiom::Choice.formula();
    let steps = vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Extensionality),
        ProofStep::Simplification {
            antecedent: premise.clone().into(),
            consequent: nested_antecedent.clone().into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ];

    assert_eq!(last_uses(&steps), [Some(3), Some(3), None, None]);
    assert_eq!(
        ProofStep::ModusPonens {
            premise: 7,
            implication: 7,
        }
        .local_references(),
        [Some(7), Some(7)]
    );
    assert_eq!(
        check(&certificate(steps)),
        Ok(Formula::implies(nested_antecedent, premise))
    );
}

#[test]
fn normalization_discards_invalid_unreachable_steps_before_checking() {
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let root = FreeVariable::new(4);
    let invalid = Separation {
        predicate: Formula::equal(result, result),
        element,
        source,
        result,
        parameters: Vec::new(),
    };
    let proof = certificate(vec![
        ProofStep::Separation(invalid.into()),
        ProofStep::EqualityReflexivity { variable: root },
        ProofStep::Generalization {
            premise: 1,
            variable: root,
        },
    ]);

    assert_eq!(
        check(&proof),
        Err(CheckError::Schema {
            step: 0,
            source: SchemaError::ForbiddenPredicateVariable(result),
        })
    );
    let checked = normalize_and_check(proof).unwrap();
    assert_eq!(checked.normal_form().certificate().steps().len(), 2);
    assert_eq!(checked.conclusion(), &closed_equality(root));
}

#[test]
fn normalization_reports_reachable_errors_in_normalized_coordinates() {
    let x = FreeVariable::new(10);
    let y = FreeVariable::new(11);
    let proof = certificate(vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Simplification {
            antecedent: Formula::equal(y, y).into(),
            consequent: closed_equality(x).into(),
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
    ]);

    assert_eq!(
        normalize_and_check(proof),
        Err(CheckError::Logic {
            step: 2,
            source: LogicError::ModusPonensMismatch,
        })
    );

    let element = FreeVariable::new(40);
    let source = FreeVariable::new(50);
    let result = FreeVariable::new(60);
    let proof = certificate(vec![ProofStep::Separation(
        Separation {
            predicate: Formula::equal(result, result),
            element,
            source,
            result,
            parameters: Vec::new(),
        }
        .into(),
    )]);

    assert_eq!(
        normalize_and_check(proof),
        Err(CheckError::Schema {
            step: 0,
            source: SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
        })
    );
}

#[test]
fn checker_localizes_invalid_replacement_and_modus_ponens() {
    let input = FreeVariable::new(1);
    let output = FreeVariable::new(2);
    let uniqueness_witness = FreeVariable::new(3);
    let source = FreeVariable::new(4);
    let result = FreeVariable::new(5);
    let invalid_replacement = Replacement {
        predicate: Formula::equal(uniqueness_witness, output),
        input,
        output,
        uniqueness_witness,
        source,
        result,
        parameters: Vec::new(),
    };

    assert_eq!(
        check(&certificate(vec![ProofStep::Replacement(
            invalid_replacement.into()
        )])),
        Err(CheckError::Schema {
            step: 0,
            source: SchemaError::ForbiddenPredicateVariable(uniqueness_witness),
        })
    );

    let x = FreeVariable::new(10);
    let y = FreeVariable::new(11);
    let proof = certificate(vec![
        ProofStep::EqualityReflexivity { variable: x },
        ProofStep::Simplification {
            antecedent: Formula::equal(y, y).into(),
            consequent: closed_equality(x).into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ]);

    assert_eq!(
        check(&proof),
        Err(CheckError::Logic {
            step: 2,
            source: LogicError::ModusPonensMismatch,
        })
    );
}

#[test]
fn check_errors_expose_their_step_context_and_sources() {
    let variable = FreeVariable::new(9);
    let reference = CheckError::UnknownProofReference {
        step: 0,
        proof_id: ProofId::from_bytes([0x11; 32]),
    };
    let logic = CheckError::Logic {
        step: 1,
        source: LogicError::ModusPonensMismatch,
    };
    let schema = CheckError::Schema {
        step: 2,
        source: SchemaError::DuplicateParameter(variable),
    };
    let derived = CheckError::DerivedFormula {
        step: 3,
        source: FormulaCodecError::DepthLimitExceeded {
            maximum: FORMULA_MAX_DEPTH,
        },
    };
    let work = CheckError::FormulaWorkLimitExceeded {
        step: 4,
        actual: 5,
        maximum: 4,
    };
    let open = CheckError::OpenConclusion { step: 5 };

    assert!(
        logic
            .source()
            .unwrap()
            .downcast_ref::<LogicError>()
            .is_some()
    );
    assert!(
        schema
            .source()
            .unwrap()
            .downcast_ref::<SchemaError>()
            .is_some()
    );
    assert!(
        derived
            .source()
            .unwrap()
            .downcast_ref::<FormulaCodecError>()
            .is_some()
    );
    assert!(reference.source().is_none());
    assert!(work.source().is_none());
    assert!(open.source().is_none());

    for (error, fragments) in [
        (&reference, &["step 0", "unknown proof"][..]),
        (&logic, &["step 1", "modus ponens"][..]),
        (&schema, &["step 2", "variable 9"][..]),
        (&derived, &["step 3", "limit of 256"][..]),
        (&work, &["step 4", "5 bytes", "limit is 4"][..]),
        (&open, &["step 5", "not closed"][..]),
    ] {
        let rendered = error.to_string();
        for fragment in fragments {
            assert!(
                rendered.contains(fragment),
                "{rendered:?} lacks {fragment:?}"
            );
        }
    }
}

#[test]
fn normalization_preserves_a_valid_proof_conclusion() {
    let x = FreeVariable::new(1);
    let proof = identity_proof(x, false);
    let expected = check(&proof).unwrap();
    let checked = normalize_and_check(proof).unwrap();

    assert_eq!(checked.conclusion(), &expected);
    assert_eq!(check(checked.normal_form().certificate()), Ok(expected));
}
