//! The ZFC axioms and axiom schemas selected by Foundation.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::{Formula, FreeVariable};

/// Identifies one of the seven fixed ZFC axioms in Foundation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZfcAxiom {
    /// Sets with the same elements are equal.
    Extensionality,
    /// For any two sets, a set containing exactly those sets exists.
    Pairing,
    /// Every set has a union.
    Union,
    /// Every set has a power set.
    PowerSet,
    /// An inductive set exists.
    Infinity,
    /// Every non-empty set has an element disjoint from it.
    Foundation,
    /// Every pairwise-disjoint family of non-empty sets has a choice set.
    Choice,
}

impl ZfcAxiom {
    /// Expands this axiom into the primitive Foundation formula language.
    #[must_use]
    pub fn formula(self) -> Formula {
        match self {
            Self::Extensionality => extensionality(),
            Self::Pairing => pairing(),
            Self::Union => union(),
            Self::PowerSet => power_set(),
            Self::Infinity => infinity(),
            Self::Foundation => foundation(),
            Self::Choice => choice(),
        }
    }
}

/// A requested instance of the Separation axiom schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Separation {
    /// The formula selecting elements from `source`.
    pub predicate: Formula,
    /// The free variable used for the candidate element.
    pub element: FreeVariable,
    /// The free variable used for the source set.
    pub source: FreeVariable,
    /// The fresh free variable used for the result set.
    pub result: FreeVariable,
    /// Explicit additional predicate parameters, in quantifier order.
    pub parameters: Vec<FreeVariable>,
}

impl Separation {
    /// Validates side conditions and expands this schema instance.
    pub fn formula(&self) -> Result<Formula, SchemaError> {
        validate_schema(
            &self.predicate,
            &[self.element, self.source, self.result],
            &[self.element, self.source],
            &[self.result],
            &self.parameters,
        )?;

        let membership = member(self.element, self.result);
        let selected =
            Formula::conjunction(member(self.element, self.source), self.predicate.clone());
        let body = Formula::for_all(self.element, Formula::biconditional(membership, selected));
        let body = Formula::exists(self.result, body);
        let body = Formula::for_all(self.source, body);
        Ok(close_parameters(&self.parameters, body))
    }
}

/// A requested instance of the Replacement axiom schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replacement {
    /// The formula relating an input to its output.
    pub predicate: Formula,
    /// The free variable used for an input element.
    pub input: FreeVariable,
    /// The free variable used for the related output.
    pub output: FreeVariable,
    /// A fresh variable used to express output uniqueness.
    pub uniqueness_witness: FreeVariable,
    /// The free variable used for the source set.
    pub source: FreeVariable,
    /// The fresh free variable used for the result set.
    pub result: FreeVariable,
    /// Explicit additional predicate parameters, in quantifier order.
    pub parameters: Vec<FreeVariable>,
}

impl Replacement {
    /// Validates side conditions and expands this schema instance.
    pub fn formula(&self) -> Result<Formula, SchemaError> {
        validate_schema(
            &self.predicate,
            &[
                self.input,
                self.output,
                self.uniqueness_witness,
                self.source,
                self.result,
            ],
            &[self.input, self.output, self.source],
            &[self.uniqueness_witness, self.result],
            &self.parameters,
        )?;

        let alternate_predicate = self
            .predicate
            .clone()
            .substitute_free(self.output, self.uniqueness_witness);
        let uniqueness = Formula::for_all(
            self.uniqueness_witness,
            Formula::implies(
                alternate_predicate,
                Formula::equal(self.uniqueness_witness, self.output),
            ),
        );
        let unique_output = Formula::exists(
            self.output,
            Formula::conjunction(self.predicate.clone(), uniqueness),
        );
        let total_on_source = Formula::for_all(
            self.input,
            Formula::implies(member(self.input, self.source), unique_output),
        );

        let has_preimage = Formula::exists(
            self.input,
            Formula::conjunction(member(self.input, self.source), self.predicate.clone()),
        );
        let image = Formula::for_all(
            self.output,
            Formula::biconditional(member(self.output, self.result), has_preimage),
        );
        let result_exists = Formula::exists(self.result, image);
        let body = Formula::for_all(
            self.source,
            Formula::implies(total_on_source, result_exists),
        );
        Ok(close_parameters(&self.parameters, body))
    }
}

fn extensionality() -> Formula {
    let x = variable(0);
    let y = variable(1);
    let z = variable(2);
    let same_members = Formula::for_all(z, Formula::biconditional(member(z, x), member(z, y)));
    close_for_all(&[x, y], Formula::implies(same_members, equal(x, y)))
}

fn pairing() -> Formula {
    let x = variable(0);
    let y = variable(1);
    let pair = variable(2);
    let z = variable(3);
    let pair_member = Formula::disjunction(equal(z, x), equal(z, y));
    let body = Formula::for_all(z, Formula::biconditional(member(z, pair), pair_member));
    close_for_all(&[x, y], Formula::exists(pair, body))
}

fn union() -> Formula {
    let source = variable(0);
    let union = variable(1);
    let element = variable(2);
    let member_set = variable(3);
    let appears_in_member = Formula::exists(
        member_set,
        Formula::conjunction(member(element, member_set), member(member_set, source)),
    );
    let body = Formula::for_all(
        element,
        Formula::biconditional(member(element, union), appears_in_member),
    );
    Formula::for_all(source, Formula::exists(union, body))
}

fn power_set() -> Formula {
    let source = variable(0);
    let power = variable(1);
    let subset = variable(2);
    let element = variable(3);
    let is_subset = Formula::for_all(
        element,
        Formula::implies(member(element, subset), member(element, source)),
    );
    let body = Formula::for_all(
        subset,
        Formula::biconditional(member(subset, power), is_subset),
    );
    Formula::for_all(source, Formula::exists(power, body))
}

fn infinity() -> Formula {
    let inductive = variable(0);
    let empty = variable(1);
    let element = variable(2);
    let successor = variable(3);
    let candidate = variable(4);

    let is_empty = Formula::for_all(candidate, Formula::negate(member(candidate, empty)));
    let contains_empty = Formula::exists(
        empty,
        Formula::conjunction(is_empty, member(empty, inductive)),
    );
    let is_successor = Formula::for_all(
        candidate,
        Formula::biconditional(
            member(candidate, successor),
            Formula::disjunction(member(candidate, element), equal(candidate, element)),
        ),
    );
    let contains_successor = Formula::exists(
        successor,
        Formula::conjunction(is_successor, member(successor, inductive)),
    );
    let successor_closed = Formula::for_all(
        element,
        Formula::implies(member(element, inductive), contains_successor),
    );
    Formula::exists(
        inductive,
        Formula::conjunction(contains_empty, successor_closed),
    )
}

fn foundation() -> Formula {
    let set = variable(0);
    let element = variable(1);
    let nested = variable(2);
    let is_non_empty = Formula::exists(element, member(element, set));
    let is_disjoint = Formula::for_all(
        nested,
        Formula::implies(
            member(nested, element),
            Formula::negate(member(nested, set)),
        ),
    );
    let has_minimal_element = Formula::exists(
        element,
        Formula::conjunction(member(element, set), is_disjoint),
    );
    Formula::for_all(set, Formula::implies(is_non_empty, has_minimal_element))
}

fn choice() -> Formula {
    let family = variable(0);
    let first_set = variable(1);
    let second_set = variable(2);
    let element = variable(3);
    let choice_set = variable(4);
    let other_element = variable(5);

    let non_empty_family = Formula::for_all(
        first_set,
        Formula::implies(
            member(first_set, family),
            Formula::exists(element, member(element, first_set)),
        ),
    );

    let both_family_members = Formula::conjunction(
        Formula::conjunction(member(first_set, family), member(second_set, family)),
        Formula::negate(equal(first_set, second_set)),
    );
    let shared_element = Formula::exists(
        element,
        Formula::conjunction(member(element, first_set), member(element, second_set)),
    );
    let pairwise_disjoint = close_for_all(
        &[first_set, second_set],
        Formula::implies(both_family_members, Formula::negate(shared_element)),
    );

    let other_is_chosen = Formula::conjunction(
        member(other_element, first_set),
        member(other_element, choice_set),
    );
    let unique = Formula::for_all(
        other_element,
        Formula::implies(other_is_chosen, equal(other_element, element)),
    );
    let exactly_one = Formula::exists(
        element,
        Formula::conjunction(
            Formula::conjunction(member(element, first_set), member(element, choice_set)),
            unique,
        ),
    );
    let meets_every_member = Formula::for_all(
        first_set,
        Formula::implies(member(first_set, family), exactly_one),
    );
    let has_choice_set = Formula::exists(choice_set, meets_every_member);

    Formula::for_all(
        family,
        Formula::implies(
            Formula::conjunction(non_empty_family, pairwise_disjoint),
            has_choice_set,
        ),
    )
}

fn validate_schema(
    predicate: &Formula,
    role_variables: &[FreeVariable],
    allowed_roles: &[FreeVariable],
    forbidden_roles: &[FreeVariable],
    parameters: &[FreeVariable],
) -> Result<(), SchemaError> {
    let mut distinct_roles = BTreeSet::new();
    for variable in role_variables {
        if !distinct_roles.insert(*variable) {
            return Err(SchemaError::RoleVariableCollision(*variable));
        }
    }

    let mut declared_parameters = BTreeSet::new();
    for parameter in parameters {
        if distinct_roles.contains(parameter) {
            return Err(SchemaError::ParameterCollidesWithRole(*parameter));
        }
        if !declared_parameters.insert(*parameter) {
            return Err(SchemaError::DuplicateParameter(*parameter));
        }
    }

    let mut allowed = declared_parameters;
    allowed.extend(allowed_roles.iter().copied());
    for variable in predicate.free_variables() {
        if forbidden_roles.contains(&variable) {
            return Err(SchemaError::ForbiddenPredicateVariable(variable));
        }
        if !allowed.contains(&variable) {
            return Err(SchemaError::UndeclaredPredicateVariable(variable));
        }
    }

    Ok(())
}

fn variable(identifier: u32) -> FreeVariable {
    FreeVariable::new(identifier)
}

fn equal(left: FreeVariable, right: FreeVariable) -> Formula {
    Formula::equal(left, right)
}

fn member(element: FreeVariable, set: FreeVariable) -> Formula {
    Formula::member(element, set)
}

fn close_for_all(variables: &[FreeVariable], body: Formula) -> Formula {
    Formula::for_all_many(variables, body)
}

fn close_parameters(parameters: &[FreeVariable], body: Formula) -> Formula {
    close_for_all(parameters, body)
}

/// An invalid ZFC axiom-schema instantiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// Two required schema roles use the same variable.
    RoleVariableCollision(FreeVariable),
    /// A parameter uses a variable reserved for a schema role.
    ParameterCollidesWithRole(FreeVariable),
    /// A parameter is declared more than once.
    DuplicateParameter(FreeVariable),
    /// A result or freshness variable occurs in the predicate.
    ForbiddenPredicateVariable(FreeVariable),
    /// A free predicate variable is not declared by the schema instance.
    UndeclaredPredicateVariable(FreeVariable),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variable = |variable: &FreeVariable| variable.identifier();
        match self {
            Self::RoleVariableCollision(value) => write!(
                formatter,
                "variable {} is assigned to more than one schema role",
                variable(value)
            ),
            Self::ParameterCollidesWithRole(value) => write!(
                formatter,
                "parameter variable {} is reserved for a schema role",
                variable(value)
            ),
            Self::DuplicateParameter(value) => write!(
                formatter,
                "parameter variable {} is declared more than once",
                variable(value)
            ),
            Self::ForbiddenPredicateVariable(value) => write!(
                formatter,
                "variable {} must not occur free in the predicate",
                variable(value)
            ),
            Self::UndeclaredPredicateVariable(value) => write!(
                formatter,
                "free predicate variable {} is not declared by the schema instance",
                variable(value)
            ),
        }
    }
}

impl Error for SchemaError {}

#[cfg(test)]
mod tests {
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
}
