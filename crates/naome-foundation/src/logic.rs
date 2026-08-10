//! The primitive logical calculus selected by Foundation.

use std::error::Error;
use std::fmt;

use crate::{Formula, FreeVariable};

/// Constructs logical axiom instances and applies primitive inference rules.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Logic;

impl Logic {
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

    /// Instantiates `A → ∀x A` with a fresh nameless binder.
    #[must_use]
    pub fn vacuous_universal(formula: Formula) -> Formula {
        Formula::implies(formula.clone(), Formula::vacuous_for_all(formula))
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

/// An invalid primitive inference-rule application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicError {
    /// Modus ponens did not receive matching `A` and `A → B` formulas.
    ModusPonensMismatch,
}

impl fmt::Display for LogicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModusPonensMismatch => formatter.write_str(
                "modus ponens requires an implication whose antecedent equals the premise",
            ),
        }
    }
}

impl Error for LogicError {}

#[cfg(test)]
mod tests;
