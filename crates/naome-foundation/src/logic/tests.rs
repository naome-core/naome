use super::{Logic, LogicError};
use crate::{Formula, FreeVariable};

#[test]
fn logical_axiom_constructors_match_primitive_golden_structures() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let first = Formula::equal(x, x);
    let second = Formula::member(x, y);
    let third = Formula::equal(y, y);

    let instances = [
        (
            "L1",
            Logic::simplification(first.clone(), second.clone()),
            "imp(eq(f1,f1),imp(mem(f1,f2),eq(f1,f1)))",
        ),
        (
            "L2",
            Logic::frege(first.clone(), second.clone(), third),
            "imp(imp(eq(f1,f1),imp(mem(f1,f2),eq(f2,f2))),imp(imp(eq(f1,f1),mem(f1,f2)),imp(eq(f1,f1),eq(f2,f2))))",
        ),
        (
            "L3",
            Logic::classical_contraposition(first.clone(), second.clone()),
            "imp(imp(not(mem(f1,f2)),not(eq(f1,f1))),imp(eq(f1,f1),mem(f1,f2)))",
        ),
        (
            "Q1",
            Logic::universal_distribution(x, first.clone(), second.clone()),
            "imp(all(imp(eq(b0,b0),mem(b0,f2))),imp(all(eq(b0,b0)),all(mem(b0,f2))))",
        ),
        (
            "Q2",
            Logic::vacuous_universal(first.clone()),
            "imp(eq(f1,f1),all(eq(f1,f1)))",
        ),
        (
            "Q3",
            Logic::universal_instantiation(x, y, second),
            "imp(all(mem(b0,f2)),mem(f2,f2))",
        ),
        ("E1", Logic::equality_reflexivity(x), "eq(f1,f1)"),
        (
            "E2",
            Logic::equality_substitution(x, y, first),
            "imp(eq(f1,f2),imp(eq(f1,f1),eq(f2,f2)))",
        ),
    ];

    for (label, instance, expected) in instances {
        assert_eq!(instance.primitive_structure(), expected, "{label}");
    }
}

#[test]
fn vacuous_universal_preserves_existing_binders() {
    let x = FreeVariable::new(1);
    let body = Formula::for_all(x, Formula::equal(x, x));

    let instance = Logic::vacuous_universal(body);

    assert_eq!(
        instance.primitive_structure(),
        "imp(all(eq(b0,b0)),all(all(eq(b0,b0))))"
    );
}

#[test]
fn universal_instantiation_is_capture_free() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let z = FreeVariable::new(3);
    let body = Formula::for_all(z, Formula::member(x, z));

    let instance = Logic::universal_instantiation(x, y, body);
    let free_variables = instance.free_variables();

    assert!(free_variables.contains(&y));
    assert!(!free_variables.contains(&x));
}

#[test]
fn modus_ponens_accepts_alpha_equivalent_antecedents() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let premise = Formula::for_all(x, Formula::equal(x, x));
    let equal_but_separate_premise = Formula::for_all(y, Formula::equal(y, y));
    let consequent = Formula::member(x, y);
    let implication = Formula::implies(equal_but_separate_premise, consequent.clone());

    assert_eq!(Logic::modus_ponens(&premise, &implication), Ok(consequent));
}

#[test]
fn modus_ponens_rejects_invalid_inputs() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let premise = Formula::equal(x, x);
    let non_implication = Formula::member(x, y);
    let mismatched_implication = Formula::implies(Formula::equal(y, y), Formula::member(x, y));

    for invalid in [&non_implication, &mismatched_implication] {
        assert_eq!(
            Logic::modus_ponens(&premise, invalid),
            Err(LogicError::ModusPonensMismatch)
        );
    }
}

#[test]
fn generalization_binds_without_capturing_an_existing_binder() {
    let x = FreeVariable::new(1);
    let y = FreeVariable::new(2);
    let z = FreeVariable::new(3);
    let premise = Formula::for_all(
        z,
        Formula::implies(Formula::member(x, z), Formula::equal(y, z)),
    );

    let generalized = Logic::generalization(x, premise);

    assert_eq!(
        generalized.primitive_structure(),
        "all(all(imp(mem(b1,b0),eq(f2,b0))))"
    );
    let free_variables = generalized.free_variables();
    assert_eq!(free_variables.len(), 1);
    assert!(free_variables.contains(&y));
}

#[test]
fn generalization_allows_a_vacuous_shadowed_variable() {
    let x = FreeVariable::new(1);
    let premise = Formula::for_all(x, Formula::equal(x, x));

    let generalized = Logic::generalization(x, premise);

    assert_eq!(generalized.primitive_structure(), "all(all(eq(b0,b0)))");
    assert!(generalized.is_closed());
}
