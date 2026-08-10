use super::*;

#[test]
fn checker_rejects_an_open_conclusion_but_allows_open_intermediate_steps() {
    let x = FreeVariable::new(1);
    let open = certificate(vec![ProofStep::EqualityReflexivity { variable: x }]);

    assert_eq!(check(&open), Err(CheckError::OpenConclusion { step: 0 }));
    assert_eq!(
        normalize_and_check(open),
        Err(CheckError::OpenConclusion { step: 0 })
    );

    assert!(
        check(&certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]))
        .is_ok()
    );
}

#[test]
fn checker_enforces_derived_depth_and_node_limits() {
    let x = FreeVariable::new(1);
    let mut depth_steps = vec![ProofStep::EqualityReflexivity { variable: x }];
    for premise in 0..FORMULA_MAX_DEPTH {
        depth_steps.push(ProofStep::Generalization {
            premise,
            variable: x,
        });
    }

    assert_eq!(
        check(&certificate(depth_steps)),
        Err(CheckError::DerivedFormula {
            step: FORMULA_MAX_DEPTH,
            source: FormulaCodecError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            },
        })
    );

    let large = balanced_closed_formula(12, x);
    let node_proof = certificate(vec![ProofStep::Frege {
        first: large.clone(),
        second: large.clone(),
        third: large,
    }]);

    assert_eq!(
        check(&node_proof),
        Err(CheckError::DerivedFormula {
            step: 0,
            source: FormulaCodecError::NodeLimitExceeded {
                maximum: FORMULA_MAX_NODES,
            },
        })
    );
}

#[test]
fn schema_depth_preflight_has_an_exact_boundary_and_precedes_schema_errors() {
    let parameters = (0..FORMULA_MAX_DEPTH)
        .map(|offset| FreeVariable::new(1_000 + offset))
        .collect::<Vec<_>>();
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let below_limit = parameters[..parameters.len() - 1].to_vec();

    assert_eq!(
        check(&certificate(vec![ProofStep::Separation(Separation {
            predicate: Formula::equal(result, result),
            element,
            source,
            result,
            parameters: below_limit,
        })])),
        Err(CheckError::Schema {
            step: 0,
            source: SchemaError::ForbiddenPredicateVariable(result),
        })
    );

    let depth_error = Err(CheckError::DerivedFormula {
        step: 0,
        source: FormulaCodecError::DepthLimitExceeded {
            maximum: FORMULA_MAX_DEPTH,
        },
    });

    assert_eq!(
        check(&certificate(vec![ProofStep::Separation(Separation {
            predicate: Formula::equal(result, result),
            element,
            source,
            result,
            parameters: parameters.clone(),
        })])),
        depth_error
    );

    let uniqueness_witness = FreeVariable::new(4);
    assert_eq!(
        check(&certificate(vec![ProofStep::Replacement(Replacement {
            predicate: Formula::equal(uniqueness_witness, source),
            input: element,
            output: source,
            uniqueness_witness,
            source: FreeVariable::new(5),
            result: FreeVariable::new(6),
            parameters,
        })])),
        depth_error
    );
}

#[test]
fn formula_work_limit_is_exact_and_inclusive() {
    assert_eq!(CHECKER_MAX_FORMULA_WORK_BYTES, 4_194_304);

    let mut remaining = CHECKER_MAX_FORMULA_WORK_BYTES;
    assert_eq!(
        charge_formula_work(7, CHECKER_MAX_FORMULA_WORK_BYTES, &mut remaining),
        Ok(())
    );
    assert_eq!(remaining, 0);
    assert_eq!(
        charge_formula_work(8, 1, &mut remaining),
        Err(CheckError::FormulaWorkLimitExceeded {
            step: 8,
            actual: CHECKER_MAX_FORMULA_WORK_BYTES + 1,
            maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
        })
    );
}

#[test]
fn formula_work_budget_enforces_result_and_error_precedence() {
    let axiom = ZfcAxiom::Choice;
    let axiom_length = canonical_length(&axiom.formula());
    let filler_count = CHECKER_MAX_FORMULA_WORK_BYTES / axiom_length;
    let used = filler_count * axiom_length;
    let remaining = CHECKER_MAX_FORMULA_WORK_BYTES - used;
    let fillers = vec![ProofStep::ZfcAxiom(axiom); filler_count];
    let step = u32::try_from(filler_count).unwrap();
    assert!(filler_count >= 2);
    assert!(filler_count < CERTIFICATE_MAX_STEPS);

    let mut result_overflow = fillers.clone();
    result_overflow.push(ProofStep::ZfcAxiom(axiom));
    assert_eq!(
        check(&certificate(result_overflow)),
        Err(CheckError::FormulaWorkLimitExceeded {
            step,
            actual: used + axiom_length,
            maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
        })
    );

    let mut invalid_modus_ponens = fillers.clone();
    invalid_modus_ponens.push(ProofStep::ModusPonens {
        premise: 0,
        implication: 1,
    });
    assert_eq!(
        check(&certificate(invalid_modus_ponens)),
        Err(CheckError::FormulaWorkLimitExceeded {
            step,
            actual: used + 2 * axiom_length,
            maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
        })
    );

    let x = FreeVariable::new(1);
    let open_length = canonical_length(&Logic::equality_reflexivity(x));
    assert!(open_length <= remaining);
    assert!(2 * open_length > remaining);
    let mut open_conclusion = fillers.clone();
    open_conclusion.push(ProofStep::EqualityReflexivity { variable: x });
    assert_eq!(
        check(&certificate(open_conclusion)),
        Err(CheckError::FormulaWorkLimitExceeded {
            step,
            actual: used + 2 * open_length,
            maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
        })
    );

    let large = balanced_closed_formula(12, x);
    let mut invalid_derived = fillers;
    invalid_derived.push(ProofStep::Frege {
        first: large.clone(),
        second: large.clone(),
        third: large,
    });
    assert_eq!(
        check(&certificate(invalid_derived)),
        Err(CheckError::DerivedFormula {
            step,
            source: FormulaCodecError::NodeLimitExceeded {
                maximum: FORMULA_MAX_NODES,
            },
        })
    );
}

#[test]
fn repeated_large_antecedent_modus_ponens_charges_both_operands() {
    let small = ZfcAxiom::Extensionality.formula();
    let large = ZfcAxiom::Choice.formula();
    let implication = Logic::simplification(small.clone(), large.clone());
    let reduced_implication = Formula::implies(large.clone(), small.clone());
    let small_length = canonical_length(&small);
    let large_length = canonical_length(&large);
    let implication_length = canonical_length(&implication);
    let reduced_length = canonical_length(&reduced_implication);
    let mut used = small_length + large_length + implication_length;
    used += small_length + implication_length + reduced_length;
    assert!(used < CHECKER_MAX_FORMULA_WORK_BYTES);

    let mut steps = vec![
        ProofStep::ZfcAxiom(ZfcAxiom::Extensionality),
        ProofStep::ZfcAxiom(ZfcAxiom::Choice),
        ProofStep::Simplification {
            antecedent: small,
            consequent: large,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
    ];
    let (expected_step, expected_actual) = loop {
        let step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::ModusPonens {
            premise: 1,
            implication: 3,
        });

        let referenced = large_length + reduced_length;
        if used + referenced > CHECKER_MAX_FORMULA_WORK_BYTES {
            break (step, used + referenced);
        }
        used += referenced;

        if used + small_length > CHECKER_MAX_FORMULA_WORK_BYTES {
            break (step, used + small_length);
        }
        used += small_length;
    };

    assert!(steps.len() < CERTIFICATE_MAX_STEPS);
    assert_eq!(
        check(&certificate(steps)),
        Err(CheckError::FormulaWorkLimitExceeded {
            step: expected_step,
            actual: expected_actual,
            maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
        })
    );
}

#[test]
fn generalization_charges_its_premise_before_execution() {
    let axiom = ZfcAxiom::Choice;
    let premise_length = canonical_length(&axiom.formula());
    let filler_count = (CHECKER_MAX_FORMULA_WORK_BYTES - premise_length) / premise_length;
    let used = (filler_count + 1) * premise_length;
    let mut steps = vec![ProofStep::ZfcAxiom(axiom); filler_count + 1];
    let expected_step = u32::try_from(steps.len()).unwrap();
    steps.push(ProofStep::Generalization {
        premise: 0,
        variable: FreeVariable::new(u32::MAX),
    });

    assert!(steps.len() < CERTIFICATE_MAX_STEPS);
    assert_eq!(
        check(&certificate(steps)),
        Err(CheckError::FormulaWorkLimitExceeded {
            step: expected_step,
            actual: used + premise_length,
            maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
        })
    );
}

#[test]
fn proof_reference_result_charge_is_exact() {
    let source =
        normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Choice)])).unwrap();
    let proof_id = source.proof_id();
    let referenced_length = source.canonical_conclusion_length;
    let filler_count = CHECKER_MAX_FORMULA_WORK_BYTES / referenced_length;
    let used = filler_count * referenced_length;
    let expected_step = u32::try_from(filler_count).unwrap();
    let mut state = ProofState::new();
    state.register(source).unwrap();
    let mut steps = vec![ProofStep::ZfcAxiom(ZfcAxiom::Choice); filler_count];
    steps.push(ProofStep::ProofReference { proof_id });

    assert!(used + referenced_length > CHECKER_MAX_FORMULA_WORK_BYTES);
    assert!(steps.len() < CERTIFICATE_MAX_STEPS);
    assert_eq!(
        check_with_canonical_conclusion(&certificate(steps), &state, IdentityMode::OmitDerivation,),
        Err(CheckError::FormulaWorkLimitExceeded {
            step: expected_step,
            actual: used + referenced_length,
            maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
        })
    );
}
