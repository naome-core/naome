use super::*;

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
            ProofStep::Simplification {
                antecedent: first.clone().into(),
                consequent: second.clone().into(),
            },
            Logic::simplification(first.clone(), second.clone()),
        ),
        (
            ProofStep::Frege {
                first: first.clone().into(),
                second: second.clone().into(),
                third: third.clone().into(),
            },
            Logic::frege(first.clone(), second.clone(), third.clone()),
        ),
        (
            ProofStep::ClassicalContraposition {
                antecedent: first.clone().into(),
                consequent: second.clone().into(),
            },
            Logic::classical_contraposition(first.clone(), second.clone()),
        ),
        (
            ProofStep::UniversalDistribution {
                variable: x,
                antecedent: quantified_antecedent.clone().into(),
                consequent: quantified_consequent.clone().into(),
            },
            Logic::universal_distribution(x, quantified_antecedent, quantified_consequent),
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
    let vacuous = Logic::vacuous_universal(body.clone());
    let expected = Logic::generalization(zero, vacuous);
    let proof = certificate(vec![
        ProofStep::VacuousUniversal {
            formula: body.into(),
        },
        ProofStep::Generalization {
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
    let instantiation = Logic::universal_instantiation(x, y, body.clone());
    let expected = Logic::generalization(y, instantiation);
    let proof = certificate(vec![
        ProofStep::UniversalInstantiation {
            variable: x,
            replacement: y,
            body: body.into(),
        },
        ProofStep::Generalization {
            premise: 0,
            variable: y,
        },
    ]);

    assert_eq!(check(&proof), Ok(expected));
}
