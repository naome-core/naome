use super::{Replacement, SchemaError, Separation, ZfcAxiom};
use crate::{Formula, FreeVariable};

const FIXED_AXIOM_GOLDENS: [(ZfcAxiom, &str); 7] = [
    (
        ZfcAxiom::Extensionality,
        "all(all(imp(all(not(imp(imp(mem(b0,b2),mem(b0,b1)),not(imp(mem(b0,b1),mem(b0,b2)))))),eq(b1,b0))))",
    ),
    (
        ZfcAxiom::Pairing,
        "all(all(not(all(not(all(not(imp(imp(mem(b0,b1),imp(not(eq(b0,b3)),eq(b0,b2))),not(imp(imp(not(eq(b0,b3)),eq(b0,b2)),mem(b0,b1)))))))))))",
    ),
    (
        ZfcAxiom::Union,
        "all(not(all(not(all(not(imp(imp(mem(b0,b1),not(all(not(not(imp(mem(b1,b0),not(mem(b0,b3)))))))),not(imp(not(all(not(not(imp(mem(b1,b0),not(mem(b0,b3))))))),mem(b0,b1))))))))))",
    ),
    (
        ZfcAxiom::PowerSet,
        "all(not(all(not(all(not(imp(imp(mem(b0,b1),all(imp(mem(b0,b1),mem(b0,b3)))),not(imp(all(imp(mem(b0,b1),mem(b0,b3))),mem(b0,b1))))))))))",
    ),
    (
        ZfcAxiom::Infinity,
        "not(all(not(not(imp(not(all(not(not(imp(all(not(mem(b0,b1))),not(mem(b0,b1))))))),not(all(imp(mem(b0,b1),not(all(not(not(imp(all(not(imp(imp(mem(b0,b1),imp(not(mem(b0,b2)),eq(b0,b2))),not(imp(imp(not(mem(b0,b2)),eq(b0,b2)),mem(b0,b1)))))),not(mem(b0,b2)))))))))))))))",
    ),
    (
        ZfcAxiom::Foundation,
        "all(imp(not(all(not(mem(b0,b1)))),not(all(not(not(imp(mem(b0,b1),not(all(imp(mem(b0,b1),not(mem(b0,b2))))))))))))",
    ),
    (
        ZfcAxiom::Choice,
        "all(imp(not(imp(all(imp(mem(b0,b1),not(all(not(mem(b0,b1)))))),not(all(all(imp(not(imp(not(imp(mem(b1,b2),not(mem(b0,b2)))),not(not(eq(b1,b0))))),not(not(all(not(not(imp(mem(b0,b2),not(mem(b0,b1)))))))))))))),not(all(not(all(imp(mem(b0,b2),not(all(not(not(imp(not(imp(mem(b0,b1),not(mem(b0,b2)))),not(all(imp(not(imp(mem(b0,b2),not(mem(b0,b3)))),eq(b0,b1))))))))))))))))",
    ),
];

const SEPARATION_GOLDEN: &str = "all(all(not(all(not(all(not(imp(imp(mem(b0,b1),not(imp(mem(b0,b2),not(mem(b0,b3))))),not(imp(not(imp(mem(b0,b2),not(mem(b0,b3)))),mem(b0,b1)))))))))))";

const REPLACEMENT_GOLDEN: &str = "all(all(imp(all(imp(mem(b0,b1),not(all(not(not(imp(not(imp(eq(b1,b0),not(mem(b1,b3)))),not(all(imp(not(imp(eq(b2,b0),not(mem(b2,b4)))),eq(b0,b1))))))))))),not(all(not(all(not(imp(imp(mem(b0,b1),not(all(not(not(imp(mem(b0,b3),not(not(imp(eq(b0,b1),not(mem(b0,b4))))))))))),not(imp(not(all(not(not(imp(mem(b0,b3),not(not(imp(eq(b0,b1),not(mem(b0,b4)))))))))),mem(b0,b1))))))))))))";

#[test]
fn fixed_axioms_match_primitive_golden_structures() {
    for (axiom, expected) in FIXED_AXIOM_GOLDENS {
        let formula = axiom.formula();
        assert_eq!(formula.primitive_structure(), expected, "{axiom:?}");
        assert!(formula.is_closed(), "{axiom:?}");
    }
}

#[test]
fn fixed_axioms_have_distinct_formulas() {
    for (index, (axiom, _)) in FIXED_AXIOM_GOLDENS.iter().enumerate() {
        for (other, _) in &FIXED_AXIOM_GOLDENS[index + 1..] {
            assert_ne!(axiom.formula(), other.formula());
        }
    }
}

#[test]
fn separation_closes_declared_parameters() {
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let parameter = FreeVariable::new(4);
    let instance = Separation {
        predicate: Formula::member(element, parameter),
        element,
        source,
        result,
        parameters: vec![parameter],
    };

    let formula = instance.formula().expect("schema instance is valid");

    assert_eq!(formula.primitive_structure(), SEPARATION_GOLDEN);
    assert!(formula.is_closed());
}

#[test]
fn separation_rejects_an_undeclared_parameter() {
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let undeclared = FreeVariable::new(4);
    let instance = Separation {
        predicate: Formula::member(element, undeclared),
        element,
        source,
        result,
        parameters: vec![],
    };

    assert_eq!(
        instance.formula(),
        Err(SchemaError::UndeclaredPredicateVariable(undeclared))
    );
}

#[test]
fn separation_rejects_a_result_variable_in_the_predicate() {
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let instance = Separation {
        predicate: Formula::member(element, result),
        element,
        source,
        result,
        parameters: vec![],
    };

    assert_eq!(
        instance.formula(),
        Err(SchemaError::ForbiddenPredicateVariable(result))
    );
}

#[test]
fn separation_rejects_colliding_schema_roles() {
    let element = FreeVariable::new(1);
    let source_and_result = FreeVariable::new(2);
    let instance = Separation {
        predicate: Formula::member(element, source_and_result),
        element,
        source: source_and_result,
        result: source_and_result,
        parameters: vec![],
    };

    assert_eq!(
        instance.formula(),
        Err(SchemaError::RoleVariableCollision(source_and_result))
    );
}

#[test]
fn separation_rejects_duplicate_parameters() {
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let parameter = FreeVariable::new(4);
    let instance = Separation {
        predicate: Formula::member(element, parameter),
        element,
        source,
        result,
        parameters: vec![parameter, parameter],
    };

    assert_eq!(
        instance.formula(),
        Err(SchemaError::DuplicateParameter(parameter))
    );
}

#[test]
fn separation_rejects_parameters_that_collide_with_roles() {
    let element = FreeVariable::new(1);
    let source = FreeVariable::new(2);
    let result = FreeVariable::new(3);
    let instance = Separation {
        predicate: Formula::member(element, source),
        element,
        source,
        result,
        parameters: vec![source],
    };

    assert_eq!(
        instance.formula(),
        Err(SchemaError::ParameterCollidesWithRole(source))
    );
}

#[test]
fn replacement_builds_a_closed_functional_image_axiom() {
    let input = FreeVariable::new(1);
    let output = FreeVariable::new(2);
    let uniqueness_witness = FreeVariable::new(3);
    let source = FreeVariable::new(4);
    let result = FreeVariable::new(5);
    let parameter = FreeVariable::new(6);
    let instance = Replacement {
        predicate: Formula::conjunction(
            Formula::equal(input, output),
            Formula::member(input, parameter),
        ),
        input,
        output,
        uniqueness_witness,
        source,
        result,
        parameters: vec![parameter],
    };

    let formula = instance.formula().expect("schema instance is valid");

    assert_eq!(formula.primitive_structure(), REPLACEMENT_GOLDEN);
    assert!(formula.is_closed());
}

#[test]
fn replacement_rejects_a_non_fresh_uniqueness_witness() {
    let input = FreeVariable::new(1);
    let output = FreeVariable::new(2);
    let uniqueness_witness = FreeVariable::new(3);
    let source = FreeVariable::new(4);
    let result = FreeVariable::new(5);
    let instance = Replacement {
        predicate: Formula::member(input, uniqueness_witness),
        input,
        output,
        uniqueness_witness,
        source,
        result,
        parameters: vec![],
    };

    assert_eq!(
        instance.formula(),
        Err(SchemaError::ForbiddenPredicateVariable(uniqueness_witness))
    );
}
