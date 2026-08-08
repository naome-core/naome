//! Deterministic mathematical checking for Foundation V0 proof certificates.
//!
//! The checker reconstructs every certificate step through the executable
//! Foundation V0 rules, enforces deterministic formula-processing limits, and
//! accepts only a closed final formula. It is deliberately in-memory and has
//! no chain state, external proof dependencies, hashing, or source parsing.

use std::error::Error;
use std::fmt;

use naome_foundation::{
    FORMULA_V0_MAX_DEPTH, Formula, FormulaCodecError, LogicError, LogicV0, SchemaError,
};
use naome_proof::{CERTIFICATE_V0_MAX_BYTES, ProofCertificateV0, ProofStepV0};

/// Maximum cumulative canonical formula work admitted by Checker V0.
///
/// Each reconstructed result is charged once. Formulas referenced by modus
/// ponens or generalization are charged before executing that rule, and the
/// conclusion is charged once more before checking closure. This value matches
/// the maximum encoded certificate length and provides one deterministic bound
/// for retained formulas and repeated inference work.
pub const CHECKER_V0_MAX_FORMULA_WORK_BYTES: usize = CERTIFICATE_V0_MAX_BYTES;

/// Checks one structurally valid Foundation V0 proof certificate.
///
/// Every step is reconstructed in order, including unused or duplicate steps.
/// On success, the returned formula is the certificate's closed conclusion.
pub fn check(certificate: &ProofCertificateV0) -> Result<Formula, CheckError> {
    let steps = certificate.steps();
    let final_step = u32::try_from(steps.len() - 1)
        .expect("ProofCertificateV0 is non-empty and has a bounded step count");
    let last_uses = last_uses(steps);
    let mut results: Vec<Option<(Formula, usize)>> = Vec::with_capacity(steps.len());
    let mut remaining_work = CHECKER_V0_MAX_FORMULA_WORK_BYTES;

    for (position, step) in steps.iter().enumerate() {
        let position = u32::try_from(position)
            .expect("ProofCertificateV0 limits make every step index representable");

        let formula = derive_step(position, step, &results, &mut remaining_work)?;
        for reference in references(step).into_iter().flatten() {
            let reference = reference as usize;
            if last_uses[reference] == Some(position) {
                results[reference] = None;
            }
        }

        let canonical_length = formula
            .encode_canonical_v0()
            .map_err(|source| CheckError::DerivedFormula {
                step: position,
                source,
            })?
            .len();
        charge_formula_work(position, canonical_length, &mut remaining_work)?;
        let retain = position == final_step || last_uses[position as usize].is_some();
        results.push(retain.then_some((formula, canonical_length)));
    }

    let (conclusion, canonical_length) = results
        .pop()
        .flatten()
        .expect("every ProofCertificateV0 has at least one reconstructed step");
    charge_formula_work(final_step, canonical_length, &mut remaining_work)?;

    if !conclusion.is_closed() {
        return Err(CheckError::OpenConclusion { step: final_step });
    }

    Ok(conclusion)
}

fn last_uses(steps: &[ProofStepV0]) -> Vec<Option<u32>> {
    let mut last_uses = vec![None; steps.len()];

    for (position, step) in steps.iter().enumerate() {
        let position = u32::try_from(position)
            .expect("ProofCertificateV0 limits make every step index representable");
        for reference in references(step).into_iter().flatten() {
            last_uses[reference as usize] = Some(position);
        }
    }

    last_uses
}

fn references(step: &ProofStepV0) -> [Option<u32>; 2] {
    match step {
        ProofStepV0::ModusPonens {
            premise,
            implication,
        } => [Some(*premise), Some(*implication)],
        ProofStepV0::Generalization { premise, .. } => [Some(*premise), None],
        _ => [None, None],
    }
}

fn preflight_schema_depth(step: u32, parameter_count: usize) -> Result<(), CheckError> {
    if parameter_count >= FORMULA_V0_MAX_DEPTH as usize {
        return Err(CheckError::DerivedFormula {
            step,
            source: FormulaCodecError::DepthLimitExceeded {
                maximum: FORMULA_V0_MAX_DEPTH,
            },
        });
    }

    Ok(())
}

fn derive_step(
    step: u32,
    proof_step: &ProofStepV0,
    results: &[Option<(Formula, usize)>],
    remaining_work: &mut usize,
) -> Result<Formula, CheckError> {
    match proof_step {
        ProofStepV0::Simplification {
            antecedent,
            consequent,
        } => Ok(LogicV0::simplification(
            antecedent.clone(),
            consequent.clone(),
        )),
        ProofStepV0::Frege {
            first,
            second,
            third,
        } => Ok(LogicV0::frege(first.clone(), second.clone(), third.clone())),
        ProofStepV0::ClassicalContraposition {
            antecedent,
            consequent,
        } => Ok(LogicV0::classical_contraposition(
            antecedent.clone(),
            consequent.clone(),
        )),
        ProofStepV0::UniversalDistribution {
            variable,
            antecedent,
            consequent,
        } => Ok(LogicV0::universal_distribution(
            *variable,
            antecedent.clone(),
            consequent.clone(),
        )),
        ProofStepV0::VacuousUniversal { formula } => {
            Ok(LogicV0::vacuous_universal(formula.clone()))
        }
        ProofStepV0::UniversalInstantiation {
            variable,
            replacement,
            body,
        } => Ok(LogicV0::universal_instantiation(
            *variable,
            *replacement,
            body.clone(),
        )),
        ProofStepV0::EqualityReflexivity { variable } => {
            Ok(LogicV0::equality_reflexivity(*variable))
        }
        ProofStepV0::EqualitySubstitution { from, to, body } => {
            Ok(LogicV0::equality_substitution(*from, *to, body.clone()))
        }
        ProofStepV0::ZfcAxiom(axiom) => Ok(axiom.formula()),
        ProofStepV0::Separation(schema) => {
            preflight_schema_depth(step, schema.parameters.len())?;
            schema
                .formula()
                .map_err(|source| CheckError::Schema { step, source })
        }
        ProofStepV0::Replacement(schema) => {
            preflight_schema_depth(step, schema.parameters.len())?;
            schema
                .formula()
                .map_err(|source| CheckError::Schema { step, source })
        }
        ProofStepV0::ModusPonens {
            premise,
            implication,
        } => {
            let premise = result(results, *premise);
            let implication = result(results, *implication);
            let referenced_work = premise
                .1
                .checked_add(implication.1)
                .expect("two V0 formula lengths fit usize");
            charge_formula_work(step, referenced_work, remaining_work)?;
            LogicV0::modus_ponens(&premise.0, &implication.0)
                .map_err(|source| CheckError::Logic { step, source })
        }
        ProofStepV0::Generalization { premise, variable } => {
            let premise = result(results, *premise);
            charge_formula_work(step, premise.1, remaining_work)?;
            Ok(LogicV0::generalization(*variable, premise.0.clone()))
        }
    }
}

fn result(results: &[Option<(Formula, usize)>], reference: u32) -> &(Formula, usize) {
    results
        .get(reference as usize)
        .and_then(Option::as_ref)
        .expect("ProofCertificateV0 guarantees references to earlier steps")
}

fn charge_formula_work(step: u32, amount: usize, remaining: &mut usize) -> Result<(), CheckError> {
    if amount > *remaining {
        let actual = (CHECKER_V0_MAX_FORMULA_WORK_BYTES - *remaining)
            .checked_add(amount)
            .expect("V0 formula work charges fit usize");
        return Err(CheckError::FormulaWorkLimitExceeded {
            step,
            actual,
            maximum: CHECKER_V0_MAX_FORMULA_WORK_BYTES,
        });
    }

    *remaining -= amount;
    Ok(())
}

/// A mathematical or deterministic-resource failure while checking a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckError {
    /// A logical axiom side condition or primitive inference rule failed.
    Logic { step: u32, source: LogicError },
    /// A ZFC axiom-schema side condition failed.
    Schema { step: u32, source: SchemaError },
    /// A reconstructed formula exceeded the canonical Formula V0 limits.
    DerivedFormula {
        step: u32,
        source: FormulaCodecError,
    },
    /// Cumulative deterministic formula work exceeded the Checker V0 limit.
    FormulaWorkLimitExceeded {
        step: u32,
        actual: usize,
        maximum: usize,
    },
    /// The final reconstructed formula still contains a free variable.
    OpenConclusion { step: u32 },
}

impl fmt::Display for CheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Logic { step, source } => {
                write!(
                    formatter,
                    "proof step {step} violates Foundation V0 logic: {source}"
                )
            }
            Self::Schema { step, source } => {
                write!(
                    formatter,
                    "proof step {step} violates a ZFC schema: {source}"
                )
            }
            Self::DerivedFormula { step, source } => write!(
                formatter,
                "proof step {step} derives a formula outside Formula V0 limits: {source}"
            ),
            Self::FormulaWorkLimitExceeded {
                step,
                actual,
                maximum,
            } => write!(
                formatter,
                "proof step {step} raises formula work to {actual} bytes; the Checker V0 limit is {maximum}"
            ),
            Self::OpenConclusion { step } => {
                write!(formatter, "proof conclusion at step {step} is not closed")
            }
        }
    }
}

impl Error for CheckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Logic { source, .. } => Some(source),
            Self::Schema { source, .. } => Some(source),
            Self::DerivedFormula { source, .. } => Some(source),
            Self::FormulaWorkLimitExceeded { .. } | Self::OpenConclusion { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use naome_foundation::{
        FORMULA_V0_MAX_DEPTH, FORMULA_V0_MAX_NODES, Formula, FormulaCodecError, FreeVariable,
        LogicError, LogicV0, Replacement, SchemaError, Separation, ZfcAxiom,
    };
    use naome_proof::{CERTIFICATE_V0_MAX_STEPS, ProofCertificateV0, ProofStepV0};

    use super::{
        CHECKER_V0_MAX_FORMULA_WORK_BYTES, CheckError, charge_formula_work, check, last_uses,
        references,
    };

    fn certificate(steps: Vec<ProofStepV0>) -> ProofCertificateV0 {
        ProofCertificateV0::new(steps).expect("the test certificate is structurally valid")
    }

    fn closed_equality(variable: FreeVariable) -> Formula {
        Formula::for_all(variable, Formula::equal(variable, variable))
    }

    fn canonical_length(formula: &Formula) -> usize {
        formula
            .encode_canonical_v0()
            .expect("the test formula is within Formula V0 limits")
            .len()
    }

    #[test]
    fn logical_axiom_steps_reconstruct_exact_foundation_formulas() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let z = FreeVariable::new(3);
        let first = closed_equality(x);
        let second = Formula::for_all(y, Formula::member(y, y));
        let third = Formula::negate(closed_equality(z));
        let quantified_antecedent = Formula::equal(x, x);
        let quantified_consequent = Formula::member(x, x);

        let cases = [
            (
                ProofStepV0::Simplification {
                    antecedent: first.clone(),
                    consequent: second.clone(),
                },
                LogicV0::simplification(first.clone(), second.clone()),
            ),
            (
                ProofStepV0::Frege {
                    first: first.clone(),
                    second: second.clone(),
                    third: third.clone(),
                },
                LogicV0::frege(first.clone(), second.clone(), third.clone()),
            ),
            (
                ProofStepV0::ClassicalContraposition {
                    antecedent: first.clone(),
                    consequent: second.clone(),
                },
                LogicV0::classical_contraposition(first.clone(), second.clone()),
            ),
            (
                ProofStepV0::UniversalDistribution {
                    variable: x,
                    antecedent: quantified_antecedent.clone(),
                    consequent: quantified_consequent.clone(),
                },
                LogicV0::universal_distribution(x, quantified_antecedent, quantified_consequent),
            ),
        ];

        for (step, expected) in cases {
            assert_eq!(check(&certificate(vec![step])), Ok(expected));
        }
    }

    #[test]
    fn vacuous_universal_reconstructs_the_nameless_binder() {
        let zero = FreeVariable::new(0);
        let body = Formula::equal(zero, zero);
        let vacuous = LogicV0::vacuous_universal(body.clone());
        let expected = LogicV0::generalization(zero, vacuous);
        let proof = certificate(vec![
            ProofStepV0::VacuousUniversal { formula: body },
            ProofStepV0::Generalization {
                premise: 0,
                variable: zero,
            },
        ]);

        assert_eq!(check(&proof), Ok(expected));
    }

    #[test]
    fn universal_instantiation_maps_binder_and_replacement_fields() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let body = Formula::member(x, x);
        let instantiation = LogicV0::universal_instantiation(x, y, body.clone());
        let expected = LogicV0::generalization(y, instantiation);
        let proof = certificate(vec![
            ProofStepV0::UniversalInstantiation {
                variable: x,
                replacement: y,
                body,
            },
            ProofStepV0::Generalization {
                premise: 0,
                variable: y,
            },
        ]);

        assert_eq!(check(&proof), Ok(expected));
    }

    #[test]
    fn equality_reflexivity_generalization_round_trips_from_canonical_bytes() {
        let x = FreeVariable::new(0x0102_0304);
        let direct = certificate(vec![
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Generalization {
                premise: 0,
                variable: x,
            },
        ]);
        let decoded = ProofCertificateV0::from_canonical_bytes(&direct.to_canonical_bytes())
            .expect("the canonical certificate round-trips");

        assert_eq!(check(&direct), check(&decoded));
        assert_eq!(check(&decoded), Ok(closed_equality(x)));
    }

    #[test]
    fn equality_substitution_closes_only_through_explicit_generalization() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let body = Formula::member(x, x);
        let substitution = LogicV0::equality_substitution(x, y, body.clone());
        let after_x = LogicV0::generalization(x, substitution);
        let expected = LogicV0::generalization(y, after_x);
        let proof = certificate(vec![
            ProofStepV0::EqualitySubstitution {
                from: x,
                to: y,
                body,
            },
            ProofStepV0::Generalization {
                premise: 0,
                variable: x,
            },
            ProofStepV0::Generalization {
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
                check(&certificate(vec![ProofStepV0::ZfcAxiom(axiom)])),
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
            check(&certificate(vec![ProofStepV0::Separation(separation)])),
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
            check(&certificate(vec![ProofStepV0::Replacement(replacement)])),
            Ok(replacement_formula)
        );
    }

    #[test]
    fn modus_ponens_returns_the_exact_closed_consequent() {
        let premise = ZfcAxiom::Extensionality.formula();
        let nested_antecedent = ZfcAxiom::Pairing.formula();
        let proof = certificate(vec![
            ProofStepV0::ZfcAxiom(ZfcAxiom::Extensionality),
            ProofStepV0::Simplification {
                antecedent: premise.clone(),
                consequent: nested_antecedent.clone(),
            },
            ProofStepV0::ModusPonens {
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
            ProofStepV0::ZfcAxiom(ZfcAxiom::Extensionality),
            ProofStepV0::Simplification {
                antecedent: premise.clone(),
                consequent: nested_antecedent.clone(),
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ];

        assert_eq!(last_uses(&steps), [Some(3), Some(3), None, None]);
        assert_eq!(
            references(&ProofStepV0::ModusPonens {
                premise: 7,
                implication: 7,
            }),
            [Some(7), Some(7)]
        );
        assert_eq!(
            check(&certificate(steps)),
            Ok(Formula::implies(nested_antecedent, premise))
        );
    }

    #[test]
    fn checker_reports_the_first_invalid_step_even_when_it_is_unused() {
        let element = FreeVariable::new(1);
        let source = FreeVariable::new(2);
        let result = FreeVariable::new(3);
        let invalid = Separation {
            predicate: Formula::equal(result, result),
            element,
            source,
            result,
            parameters: Vec::new(),
        };
        let proof = certificate(vec![
            ProofStepV0::Separation(invalid),
            ProofStepV0::ZfcAxiom(ZfcAxiom::Extensionality),
        ]);

        assert_eq!(
            check(&proof),
            Err(CheckError::Schema {
                step: 0,
                source: SchemaError::ForbiddenPredicateVariable(result),
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
            check(&certificate(vec![ProofStepV0::Replacement(
                invalid_replacement
            )])),
            Err(CheckError::Schema {
                step: 0,
                source: SchemaError::ForbiddenPredicateVariable(uniqueness_witness),
            })
        );

        let x = FreeVariable::new(10);
        let y = FreeVariable::new(11);
        let proof = certificate(vec![
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Simplification {
                antecedent: Formula::equal(y, y),
                consequent: closed_equality(x),
            },
            ProofStepV0::ModusPonens {
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
                maximum: FORMULA_V0_MAX_DEPTH,
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
        assert!(work.source().is_none());
        assert!(open.source().is_none());

        for (error, fragments) in [
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
    fn checker_rejects_an_open_conclusion_but_allows_open_intermediate_steps() {
        let x = FreeVariable::new(1);

        assert_eq!(
            check(&certificate(vec![ProofStepV0::EqualityReflexivity {
                variable: x
            }])),
            Err(CheckError::OpenConclusion { step: 0 })
        );

        assert!(
            check(&certificate(vec![
                ProofStepV0::EqualityReflexivity { variable: x },
                ProofStepV0::Generalization {
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
        let mut depth_steps = vec![ProofStepV0::EqualityReflexivity { variable: x }];
        for premise in 0..FORMULA_V0_MAX_DEPTH {
            depth_steps.push(ProofStepV0::Generalization {
                premise,
                variable: x,
            });
        }

        assert_eq!(
            check(&certificate(depth_steps)),
            Err(CheckError::DerivedFormula {
                step: FORMULA_V0_MAX_DEPTH,
                source: FormulaCodecError::DepthLimitExceeded {
                    maximum: FORMULA_V0_MAX_DEPTH,
                },
            })
        );

        let large = balanced_closed_formula(12, x);
        let node_proof = certificate(vec![ProofStepV0::Frege {
            first: large.clone(),
            second: large.clone(),
            third: large,
        }]);

        assert_eq!(
            check(&node_proof),
            Err(CheckError::DerivedFormula {
                step: 0,
                source: FormulaCodecError::NodeLimitExceeded {
                    maximum: FORMULA_V0_MAX_NODES,
                },
            })
        );
    }

    #[test]
    fn schema_depth_preflight_has_an_exact_boundary_and_precedes_schema_errors() {
        let parameters = (0..FORMULA_V0_MAX_DEPTH)
            .map(|offset| FreeVariable::new(1_000 + offset))
            .collect::<Vec<_>>();
        let element = FreeVariable::new(1);
        let source = FreeVariable::new(2);
        let result = FreeVariable::new(3);
        let below_limit = parameters[..parameters.len() - 1].to_vec();

        assert_eq!(
            check(&certificate(vec![ProofStepV0::Separation(Separation {
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
                maximum: FORMULA_V0_MAX_DEPTH,
            },
        });

        assert_eq!(
            check(&certificate(vec![ProofStepV0::Separation(Separation {
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
            check(&certificate(vec![ProofStepV0::Replacement(Replacement {
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
        assert_eq!(CHECKER_V0_MAX_FORMULA_WORK_BYTES, 4_194_304);

        let mut remaining = CHECKER_V0_MAX_FORMULA_WORK_BYTES;
        assert_eq!(
            charge_formula_work(7, CHECKER_V0_MAX_FORMULA_WORK_BYTES, &mut remaining),
            Ok(())
        );
        assert_eq!(remaining, 0);
        assert_eq!(
            charge_formula_work(8, 1, &mut remaining),
            Err(CheckError::FormulaWorkLimitExceeded {
                step: 8,
                actual: CHECKER_V0_MAX_FORMULA_WORK_BYTES + 1,
                maximum: CHECKER_V0_MAX_FORMULA_WORK_BYTES,
            })
        );
    }

    #[test]
    fn formula_work_budget_enforces_result_and_error_precedence() {
        let axiom = ZfcAxiom::Choice;
        let axiom_length = canonical_length(&axiom.formula());
        let filler_count = CHECKER_V0_MAX_FORMULA_WORK_BYTES / axiom_length;
        let used = filler_count * axiom_length;
        let remaining = CHECKER_V0_MAX_FORMULA_WORK_BYTES - used;
        let fillers = vec![ProofStepV0::ZfcAxiom(axiom); filler_count];
        let step = u32::try_from(filler_count).unwrap();
        assert!(filler_count >= 2);
        assert!(filler_count < CERTIFICATE_V0_MAX_STEPS);

        let mut result_overflow = fillers.clone();
        result_overflow.push(ProofStepV0::ZfcAxiom(axiom));
        assert_eq!(
            check(&certificate(result_overflow)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step,
                actual: used + axiom_length,
                maximum: CHECKER_V0_MAX_FORMULA_WORK_BYTES,
            })
        );

        let mut invalid_modus_ponens = fillers.clone();
        invalid_modus_ponens.push(ProofStepV0::ModusPonens {
            premise: 0,
            implication: 1,
        });
        assert_eq!(
            check(&certificate(invalid_modus_ponens)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step,
                actual: used + 2 * axiom_length,
                maximum: CHECKER_V0_MAX_FORMULA_WORK_BYTES,
            })
        );

        let x = FreeVariable::new(1);
        let open_length = canonical_length(&LogicV0::equality_reflexivity(x));
        assert!(open_length <= remaining);
        assert!(2 * open_length > remaining);
        let mut open_conclusion = fillers.clone();
        open_conclusion.push(ProofStepV0::EqualityReflexivity { variable: x });
        assert_eq!(
            check(&certificate(open_conclusion)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step,
                actual: used + 2 * open_length,
                maximum: CHECKER_V0_MAX_FORMULA_WORK_BYTES,
            })
        );

        let large = balanced_closed_formula(12, x);
        let mut invalid_derived = fillers;
        invalid_derived.push(ProofStepV0::Frege {
            first: large.clone(),
            second: large.clone(),
            third: large,
        });
        assert_eq!(
            check(&certificate(invalid_derived)),
            Err(CheckError::DerivedFormula {
                step,
                source: FormulaCodecError::NodeLimitExceeded {
                    maximum: FORMULA_V0_MAX_NODES,
                },
            })
        );
    }

    #[test]
    fn repeated_large_antecedent_modus_ponens_charges_both_operands() {
        let small = ZfcAxiom::Extensionality.formula();
        let large = ZfcAxiom::Choice.formula();
        let implication = LogicV0::simplification(small.clone(), large.clone());
        let reduced_implication = Formula::implies(large.clone(), small.clone());
        let small_length = canonical_length(&small);
        let large_length = canonical_length(&large);
        let implication_length = canonical_length(&implication);
        let reduced_length = canonical_length(&reduced_implication);
        let mut used = small_length + large_length + implication_length;
        used += small_length + implication_length + reduced_length;
        assert!(used < CHECKER_V0_MAX_FORMULA_WORK_BYTES);

        let mut steps = vec![
            ProofStepV0::ZfcAxiom(ZfcAxiom::Extensionality),
            ProofStepV0::ZfcAxiom(ZfcAxiom::Choice),
            ProofStepV0::Simplification {
                antecedent: small,
                consequent: large,
            },
            ProofStepV0::ModusPonens {
                premise: 0,
                implication: 2,
            },
        ];
        let (expected_step, expected_actual) = loop {
            let step = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStepV0::ModusPonens {
                premise: 1,
                implication: 3,
            });

            let referenced = large_length + reduced_length;
            if used + referenced > CHECKER_V0_MAX_FORMULA_WORK_BYTES {
                break (step, used + referenced);
            }
            used += referenced;

            if used + small_length > CHECKER_V0_MAX_FORMULA_WORK_BYTES {
                break (step, used + small_length);
            }
            used += small_length;
        };

        assert!(steps.len() < CERTIFICATE_V0_MAX_STEPS);
        assert_eq!(
            check(&certificate(steps)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step: expected_step,
                actual: expected_actual,
                maximum: CHECKER_V0_MAX_FORMULA_WORK_BYTES,
            })
        );
    }

    #[test]
    fn generalization_charges_its_premise_before_execution() {
        let axiom = ZfcAxiom::Choice;
        let premise_length = canonical_length(&axiom.formula());
        let filler_count = (CHECKER_V0_MAX_FORMULA_WORK_BYTES - premise_length) / premise_length;
        let used = (filler_count + 1) * premise_length;
        let mut steps = vec![ProofStepV0::ZfcAxiom(axiom); filler_count + 1];
        let expected_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStepV0::Generalization {
            premise: 0,
            variable: FreeVariable::new(u32::MAX),
        });

        assert!(steps.len() < CERTIFICATE_V0_MAX_STEPS);
        assert_eq!(
            check(&certificate(steps)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step: expected_step,
                actual: used + premise_length,
                maximum: CHECKER_V0_MAX_FORMULA_WORK_BYTES,
            })
        );
    }

    fn balanced_closed_formula(depth: u32, variable: FreeVariable) -> Formula {
        if depth == 0 {
            return closed_equality(variable);
        }

        let child = balanced_closed_formula(depth - 1, variable);
        Formula::implies(child.clone(), child)
    }
}
