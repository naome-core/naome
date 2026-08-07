//! The primitive logical calculus selected by Foundation V0.

use std::error::Error;
use std::fmt;

use crate::{Formula, FreeVariable};

/// Identifies a primitive rule for assumption-free Foundation V0 derivations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InferenceRule {
    /// Derive `B` from earlier derived formulas `A` and `A → B`.
    ModusPonens,
    /// From an earlier derived `A`, bind `x` and derive `∀x A`.
    Generalization,
}

/// Constructs logical axiom instances and applies primitive inference rules.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogicV0;

impl LogicV0 {
    /// Instantiates `A → (B → A)`.
    #[must_use]
    pub fn simplification(antecedent: Formula, consequent: Formula) -> Formula {
        Formula::implies(antecedent.clone(), Formula::implies(consequent, antecedent))
    }

    /// Instantiates the Frege implication schema.
    #[must_use]
    pub fn frege(first: Formula, second: Formula, third: Formula) -> Formula {
        Formula::implies(
            Formula::implies(
                first.clone(),
                Formula::implies(second.clone(), third.clone()),
            ),
            Formula::implies(
                Formula::implies(first.clone(), second),
                Formula::implies(first, third),
            ),
        )
    }

    /// Instantiates the classical contraposition schema.
    #[must_use]
    pub fn classical_contraposition(antecedent: Formula, consequent: Formula) -> Formula {
        Formula::implies(
            Formula::implies(
                Formula::negate(consequent.clone()),
                Formula::negate(antecedent.clone()),
            ),
            Formula::implies(antecedent, consequent),
        )
    }

    /// Instantiates universal distribution.
    #[must_use]
    pub fn universal_distribution(
        variable: FreeVariable,
        antecedent: Formula,
        consequent: Formula,
    ) -> Formula {
        Formula::implies(
            Formula::for_all(
                variable,
                Formula::implies(antecedent.clone(), consequent.clone()),
            ),
            Formula::implies(
                Formula::for_all(variable, antecedent),
                Formula::for_all(variable, consequent),
            ),
        )
    }

    /// Instantiates `A → ∀x A` when `x` is not free in `A`.
    pub fn vacuous_universal(
        variable: FreeVariable,
        formula: Formula,
    ) -> Result<Formula, LogicError> {
        if formula.free_variables().contains(&variable) {
            return Err(LogicError::VariableMustNotBeFree(variable));
        }

        Ok(Formula::implies(
            formula.clone(),
            Formula::for_all(variable, formula),
        ))
    }

    /// Instantiates `∀x A → A[x := y]`.
    #[must_use]
    pub fn universal_instantiation(
        variable: FreeVariable,
        replacement: FreeVariable,
        body: Formula,
    ) -> Formula {
        Formula::implies(
            Formula::for_all(variable, body.clone()),
            body.substitute_free(variable, replacement),
        )
    }

    /// Instantiates equality reflexivity.
    #[must_use]
    pub const fn equality_reflexivity(variable: FreeVariable) -> Formula {
        Formula::equal(variable, variable)
    }

    /// Instantiates substitutivity of equality in an arbitrary formula.
    #[must_use]
    pub fn equality_substitution(from: FreeVariable, to: FreeVariable, body: Formula) -> Formula {
        Formula::implies(
            Formula::equal(from, to),
            Formula::implies(body.clone(), body.substitute_free(from, to)),
        )
    }

    /// Derives `B` from `A` and `A → B`.
    pub fn modus_ponens(premise: &Formula, implication: &Formula) -> Result<Formula, LogicError> {
        implication
            .implication_consequent_for(premise)
            .ok_or(LogicError::ModusPonensMismatch)
    }

    /// Universally quantifies a selected free variable in an earlier formula.
    #[must_use]
    pub fn generalization(variable: FreeVariable, premise: Formula) -> Formula {
        Formula::for_all(variable, premise)
    }
}

/// An invalid logical axiom-schema instantiation or inference-rule application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicError {
    /// A variable required to be absent occurs free in the formula.
    VariableMustNotBeFree(FreeVariable),
    /// Modus ponens did not receive matching `A` and `A → B` formulas.
    ModusPonensMismatch,
}

impl fmt::Display for LogicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VariableMustNotBeFree(variable) => write!(
                formatter,
                "variable {} must not occur free in this axiom instance",
                variable.identifier()
            ),
            Self::ModusPonensMismatch => formatter.write_str(
                "modus ponens requires an implication whose antecedent equals the premise",
            ),
        }
    }
}

impl Error for LogicError {}

#[cfg(test)]
mod tests {
    use super::{LogicError, LogicV0};
    use crate::{Formula, FreeVariable};

    #[test]
    fn logical_axiom_constructors_match_primitive_golden_structures() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let unused = FreeVariable::new(3);
        let first = Formula::equal(x, x);
        let second = Formula::member(x, y);
        let third = Formula::equal(y, y);

        let instances = [
            (
                "L1",
                LogicV0::simplification(first.clone(), second.clone()),
                "imp(eq(f1,f1),imp(mem(f1,f2),eq(f1,f1)))",
            ),
            (
                "L2",
                LogicV0::frege(first.clone(), second.clone(), third),
                "imp(imp(eq(f1,f1),imp(mem(f1,f2),eq(f2,f2))),imp(imp(eq(f1,f1),mem(f1,f2)),imp(eq(f1,f1),eq(f2,f2))))",
            ),
            (
                "L3",
                LogicV0::classical_contraposition(first.clone(), second.clone()),
                "imp(imp(not(mem(f1,f2)),not(eq(f1,f1))),imp(eq(f1,f1),mem(f1,f2)))",
            ),
            (
                "Q1",
                LogicV0::universal_distribution(x, first.clone(), second.clone()),
                "imp(all(imp(eq(b0,b0),mem(b0,f2))),imp(all(eq(b0,b0)),all(mem(b0,f2))))",
            ),
            (
                "Q2",
                LogicV0::vacuous_universal(unused, first.clone())
                    .expect("the side condition is satisfied"),
                "imp(eq(f1,f1),all(eq(f1,f1)))",
            ),
            (
                "Q3",
                LogicV0::universal_instantiation(x, y, second),
                "imp(all(mem(b0,f2)),mem(f2,f2))",
            ),
            ("E1", LogicV0::equality_reflexivity(x), "eq(f1,f1)"),
            (
                "E2",
                LogicV0::equality_substitution(x, y, first),
                "imp(eq(f1,f2),imp(eq(f1,f1),eq(f2,f2)))",
            ),
        ];

        for (label, instance, expected) in instances {
            assert_eq!(instance.primitive_structure(), expected, "{label}");
        }
    }

    #[test]
    fn vacuous_universal_rejects_a_free_quantified_variable() {
        let x = FreeVariable::new(1);
        let body = Formula::equal(x, x);

        assert_eq!(
            LogicV0::vacuous_universal(x, body),
            Err(LogicError::VariableMustNotBeFree(x))
        );
    }

    #[test]
    fn universal_instantiation_is_capture_free() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let z = FreeVariable::new(3);
        let body = Formula::for_all(z, Formula::member(x, z));

        let instance = LogicV0::universal_instantiation(x, y, body);

        assert!(instance.free_variables().contains(&y));
        assert!(!instance.free_variables().contains(&x));
    }

    #[test]
    fn modus_ponens_accepts_alpha_equivalent_antecedents() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let premise = Formula::for_all(x, Formula::equal(x, x));
        let equal_but_separate_premise = Formula::for_all(y, Formula::equal(y, y));
        let consequent = Formula::member(x, y);
        let implication = Formula::implies(equal_but_separate_premise, consequent.clone());

        assert_eq!(
            LogicV0::modus_ponens(&premise, &implication),
            Ok(consequent)
        );
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
                LogicV0::modus_ponens(&premise, invalid),
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

        let generalized = LogicV0::generalization(x, premise);

        assert_eq!(
            generalized.primitive_structure(),
            "all(all(imp(mem(b1,b0),eq(f2,b0))))"
        );
        assert_eq!(generalized.free_variables().len(), 1);
        assert!(generalized.free_variables().contains(&y));
    }

    #[test]
    fn generalization_allows_a_vacuous_shadowed_variable() {
        let x = FreeVariable::new(1);
        let premise = Formula::for_all(x, Formula::equal(x, x));

        let generalized = LogicV0::generalization(x, premise);

        assert_eq!(generalized.primitive_structure(), "all(all(eq(b0,b0)))");
        assert!(generalized.is_closed());
    }
}
