//! The primitive logical calculus selected by Foundation V0.

use std::error::Error;
use std::fmt;

use crate::{Formula, FormulaError, FreeVariable};

/// Identifies a logical axiom schema in Foundation V0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogicalAxiomSchema {
    /// `A → (B → A)`.
    Simplification,
    /// `(A → (B → C)) → ((A → B) → (A → C))`.
    Frege,
    /// `(¬B → ¬A) → (A → B)`.
    ClassicalContraposition,
    /// `∀x(A → B) → (∀x A → ∀x B)`.
    UniversalDistribution,
    /// `A → ∀x A`, where `x` is not free in `A`.
    VacuousUniversal,
    /// `∀x A → A[x := y]`.
    UniversalInstantiation,
    /// `x = x`.
    EqualityReflexivity,
    /// `x = y → (A → A[x := y])`.
    EqualitySubstitution,
}

/// The complete ordered set of Foundation V0 logical axiom schemas.
pub const LOGICAL_AXIOM_SCHEMAS: [LogicalAxiomSchema; 8] = [
    LogicalAxiomSchema::Simplification,
    LogicalAxiomSchema::Frege,
    LogicalAxiomSchema::ClassicalContraposition,
    LogicalAxiomSchema::UniversalDistribution,
    LogicalAxiomSchema::VacuousUniversal,
    LogicalAxiomSchema::UniversalInstantiation,
    LogicalAxiomSchema::EqualityReflexivity,
    LogicalAxiomSchema::EqualitySubstitution,
];

/// Identifies a primitive inference rule in Foundation V0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InferenceRule {
    /// Derive `B` from `A` and `A → B`.
    ModusPonens,
    /// Derive `∀x A` from `A`.
    Generalization,
}

/// The complete ordered set of Foundation V0 inference rules.
pub const INFERENCE_RULES: [InferenceRule; 2] =
    [InferenceRule::ModusPonens, InferenceRule::Generalization];

/// Constructors for instances of the Foundation V0 logical axiom schemas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogicV0;

impl LogicV0 {
    /// Instantiates `A → (B → A)`.
    pub fn simplification(antecedent: Formula, consequent: Formula) -> Result<Formula, LogicError> {
        validate_formulas([&antecedent, &consequent])?;
        Ok(Formula::implies(
            antecedent.clone(),
            Formula::implies(consequent, antecedent),
        ))
    }

    /// Instantiates the Frege implication schema.
    pub fn frege(first: Formula, second: Formula, third: Formula) -> Result<Formula, LogicError> {
        validate_formulas([&first, &second, &third])?;
        Ok(Formula::implies(
            Formula::implies(
                first.clone(),
                Formula::implies(second.clone(), third.clone()),
            ),
            Formula::implies(
                Formula::implies(first.clone(), second),
                Formula::implies(first, third),
            ),
        ))
    }

    /// Instantiates the classical contraposition schema.
    pub fn classical_contraposition(
        antecedent: Formula,
        consequent: Formula,
    ) -> Result<Formula, LogicError> {
        validate_formulas([&antecedent, &consequent])?;
        Ok(Formula::implies(
            Formula::implies(
                Formula::negate(consequent.clone()),
                Formula::negate(antecedent.clone()),
            ),
            Formula::implies(antecedent, consequent),
        ))
    }

    /// Instantiates universal distribution.
    pub fn universal_distribution(
        variable: FreeVariable,
        antecedent: Formula,
        consequent: Formula,
    ) -> Result<Formula, LogicError> {
        validate_formulas([&antecedent, &consequent])?;
        Ok(Formula::implies(
            Formula::for_all(
                variable,
                Formula::implies(antecedent.clone(), consequent.clone()),
            ),
            Formula::implies(
                Formula::for_all(variable, antecedent),
                Formula::for_all(variable, consequent),
            ),
        ))
    }

    /// Instantiates `A → ∀x A` when `x` is not free in `A`.
    pub fn vacuous_universal(
        variable: FreeVariable,
        formula: Formula,
    ) -> Result<Formula, LogicError> {
        formula.validate()?;
        if formula.free_variables().contains(&variable) {
            return Err(LogicError::VariableMustNotBeFree(variable));
        }

        Ok(Formula::implies(
            formula.clone(),
            Formula::for_all(variable, formula),
        ))
    }

    /// Instantiates `∀x A → A[x := y]`.
    pub fn universal_instantiation(
        variable: FreeVariable,
        replacement: FreeVariable,
        body: Formula,
    ) -> Result<Formula, LogicError> {
        body.validate()?;
        Ok(Formula::implies(
            Formula::for_all(variable, body.clone()),
            body.substitute_free(variable, replacement),
        ))
    }

    /// Instantiates equality reflexivity.
    #[must_use]
    pub fn equality_reflexivity(variable: FreeVariable) -> Formula {
        Formula::equal(variable.into(), variable.into())
    }

    /// Instantiates substitutivity of equality in an arbitrary formula.
    pub fn equality_substitution(
        from: FreeVariable,
        to: FreeVariable,
        body: Formula,
    ) -> Result<Formula, LogicError> {
        body.validate()?;
        Ok(Formula::implies(
            Formula::equal(from.into(), to.into()),
            Formula::implies(body.clone(), body.substitute_free(from, to)),
        ))
    }
}

fn validate_formulas<'a>(
    formulas: impl IntoIterator<Item = &'a Formula>,
) -> Result<(), LogicError> {
    for formula in formulas {
        formula.validate()?;
    }
    Ok(())
}

/// An invalid logical axiom-schema instantiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicError {
    /// The supplied formula is structurally invalid.
    InvalidFormula(FormulaError),
    /// A variable required to be absent occurs free in the formula.
    VariableMustNotBeFree(FreeVariable),
}

impl fmt::Display for LogicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormula(error) => write!(formatter, "invalid formula: {error}"),
            Self::VariableMustNotBeFree(variable) => write!(
                formatter,
                "variable {} must not occur free in this axiom instance",
                variable.identifier()
            ),
        }
    }
}

impl Error for LogicError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidFormula(error) => Some(error),
            Self::VariableMustNotBeFree(_) => None,
        }
    }
}

impl From<FormulaError> for LogicError {
    fn from(error: FormulaError) -> Self {
        Self::InvalidFormula(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{LogicError, LogicV0};
    use crate::{Formula, FreeVariable};

    #[test]
    fn every_logical_axiom_constructor_produces_a_well_formed_formula() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let unused = FreeVariable::new(3);
        let first = Formula::equal(x.into(), x.into());
        let second = Formula::member(x.into(), y.into());
        let third = Formula::equal(y.into(), y.into());

        let instances = [
            LogicV0::simplification(first.clone(), second.clone()),
            LogicV0::frege(first.clone(), second.clone(), third.clone()),
            LogicV0::classical_contraposition(first.clone(), second.clone()),
            LogicV0::universal_distribution(x, first.clone(), second.clone()),
            LogicV0::vacuous_universal(unused, first.clone()),
            LogicV0::universal_instantiation(x, y, second.clone()),
            Ok(LogicV0::equality_reflexivity(x)),
            LogicV0::equality_substitution(x, y, first),
        ];

        for instance in instances {
            assert_eq!(
                instance.expect("axiom instance is valid").validate(),
                Ok(())
            );
        }
    }

    #[test]
    fn vacuous_universal_rejects_a_free_quantified_variable() {
        let x = FreeVariable::new(1);
        let body = Formula::equal(x.into(), x.into());

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
        let body = Formula::for_all(z, Formula::member(x.into(), z.into()));

        let instance =
            LogicV0::universal_instantiation(x, y, body).expect("the formula is well formed");

        assert_eq!(instance.validate(), Ok(()));
        assert!(instance.free_variables().contains(&y));
        assert!(!instance.free_variables().contains(&x));
    }
}
