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
        crate::construction::simplification(antecedent, consequent).evaluate()
    }

    /// Instantiates the Frege implication schema.
    #[must_use]
    pub fn frege(first: Formula, second: Formula, third: Formula) -> Formula {
        crate::construction::frege(first, second, third).evaluate()
    }

    /// Instantiates the classical contraposition schema.
    #[must_use]
    pub fn classical_contraposition(antecedent: Formula, consequent: Formula) -> Formula {
        crate::construction::contraposition(antecedent, consequent).evaluate()
    }

    /// Instantiates universal distribution.
    #[must_use]
    pub fn universal_distribution(
        variable: FreeVariable,
        antecedent: Formula,
        consequent: Formula,
    ) -> Formula {
        crate::construction::distribution(variable, antecedent, consequent).evaluate()
    }

    /// Instantiates `A → ∀x A` with a fresh nameless binder.
    #[must_use]
    pub fn vacuous_universal(formula: Formula) -> Formula {
        crate::construction::vacuous(formula).evaluate()
    }

    /// Instantiates `∀x A → A[x := y]`.
    #[must_use]
    pub fn universal_instantiation(
        variable: FreeVariable,
        replacement: FreeVariable,
        body: Formula,
    ) -> Formula {
        crate::construction::instantiation(variable, replacement, body).evaluate()
    }

    /// Instantiates equality reflexivity.
    #[must_use]
    pub const fn equality_reflexivity(variable: FreeVariable) -> Formula {
        Formula::equal(variable, variable)
    }

    /// Instantiates substitutivity of equality in an arbitrary formula.
    #[must_use]
    pub fn equality_substitution(from: FreeVariable, to: FreeVariable, body: Formula) -> Formula {
        crate::construction::substitution(from, to, body).evaluate()
    }

    /// Derives `B` from `A` and `A → B`.
    pub fn modus_ponens(premise: &Formula, implication: &Formula) -> Result<Formula, LogicError> {
        let (antecedent, consequent) = implication
            .view()
            .implication_parts()
            .ok_or(LogicError::ExpectedImplication)?;
        if antecedent != *premise {
            return Err(LogicError::AntecedentMismatch);
        }
        Ok(consequent.to_owned())
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
    /// The implication operand has another outer constructor.
    ExpectedImplication,
    /// The implication's antecedent differs from the proved premise.
    AntecedentMismatch,
}

impl fmt::Display for LogicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedImplication | Self::AntecedentMismatch => formatter.write_str(
                "modus ponens requires an implication whose antecedent equals the premise",
            ),
        }
    }
}

impl Error for LogicError {}

#[cfg(test)]
mod tests;
