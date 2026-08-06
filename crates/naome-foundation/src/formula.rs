//! Primitive first-order formulas for set theory.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

/// Identifies a free object-language variable.
///
/// Names are presentation data. The numeric identifier is the stable identity
/// used while constructing formulas and schema instances.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FreeVariable(u32);

impl FreeVariable {
    /// Creates a free variable with the given identifier.
    #[must_use]
    pub const fn new(identifier: u32) -> Self {
        Self(identifier)
    }

    /// Returns the numeric identifier.
    #[must_use]
    pub const fn identifier(self) -> u32 {
        self.0
    }
}

/// A term in the primitive language of set theory.
///
/// ZFC has no primitive constants or function symbols, so every term is a
/// variable. Bound variables use De Bruijn indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Term {
    /// A variable bound by an enclosing quantifier. Index zero refers to the
    /// nearest enclosing binder.
    Bound(u32),
    /// A free variable used as an explicit parameter.
    Free(FreeVariable),
}

impl From<FreeVariable> for Term {
    fn from(variable: FreeVariable) -> Self {
        Self::Free(variable)
    }
}

/// A formula in the primitive language of first-order set theory.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Formula {
    /// Equality between two set terms.
    Equal(Term, Term),
    /// Set membership between two set terms.
    Member(Term, Term),
    /// Logical negation.
    Not(Box<Self>),
    /// Material implication.
    Implies(Box<Self>, Box<Self>),
    /// Universal quantification. The binder is represented by De Bruijn index
    /// zero in the body.
    ForAll(Box<Self>),
}

impl Formula {
    /// Constructs an equality formula.
    #[must_use]
    pub const fn equal(left: Term, right: Term) -> Self {
        Self::Equal(left, right)
    }

    /// Constructs a membership formula.
    #[must_use]
    pub const fn member(element: Term, set: Term) -> Self {
        Self::Member(element, set)
    }

    /// Constructs a negation.
    #[must_use]
    pub fn negate(formula: Self) -> Self {
        Self::Not(Box::new(formula))
    }

    /// Constructs an implication.
    #[must_use]
    pub fn implies(antecedent: Self, consequent: Self) -> Self {
        Self::Implies(Box::new(antecedent), Box::new(consequent))
    }

    /// Constructs conjunction as `¬(A → ¬B)`.
    #[must_use]
    pub fn conjunction(left: Self, right: Self) -> Self {
        Self::negate(Self::implies(left, Self::negate(right)))
    }

    /// Constructs disjunction as `¬A → B`.
    #[must_use]
    pub fn disjunction(left: Self, right: Self) -> Self {
        Self::implies(Self::negate(left), right)
    }

    /// Constructs a biconditional from conjunction and implication.
    #[must_use]
    pub fn biconditional(left: Self, right: Self) -> Self {
        Self::conjunction(
            Self::implies(left.clone(), right.clone()),
            Self::implies(right, left),
        )
    }

    /// Universally quantifies a free variable in a formula.
    ///
    /// Occurrences of `variable` become De Bruijn references to the newly
    /// introduced binder. Existing bound references retain their binders.
    #[must_use]
    pub fn for_all(variable: FreeVariable, body: Self) -> Self {
        Self::ForAll(Box::new(body.bind_free(variable, 0)))
    }

    /// Existentially quantifies a free variable using `¬∀x¬A`.
    #[must_use]
    pub fn exists(variable: FreeVariable, body: Self) -> Self {
        Self::negate(Self::for_all(variable, Self::negate(body)))
    }

    /// Replaces all occurrences of one free variable with another.
    ///
    /// Free and bound variables have separate representations, so this
    /// operation cannot capture the replacement variable.
    #[must_use]
    pub fn substitute_free(self, from: FreeVariable, to: FreeVariable) -> Self {
        match self {
            Self::Equal(left, right) => Self::Equal(
                substitute_term(left, from, to),
                substitute_term(right, from, to),
            ),
            Self::Member(element, set) => Self::Member(
                substitute_term(element, from, to),
                substitute_term(set, from, to),
            ),
            Self::Not(formula) => Self::Not(Box::new(formula.substitute_free(from, to))),
            Self::Implies(antecedent, consequent) => Self::Implies(
                Box::new(antecedent.substitute_free(from, to)),
                Box::new(consequent.substitute_free(from, to)),
            ),
            Self::ForAll(body) => Self::ForAll(Box::new(body.substitute_free(from, to))),
        }
    }

    /// Returns the free variables occurring in this formula.
    #[must_use]
    pub fn free_variables(&self) -> BTreeSet<FreeVariable> {
        let mut variables = BTreeSet::new();
        self.collect_free_variables(&mut variables);
        variables
    }

    /// Returns `true` when the formula contains no free variables.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.free_variables().is_empty()
    }

    /// Validates that every bound-variable reference has an enclosing binder.
    pub fn validate(&self) -> Result<(), FormulaError> {
        self.validate_at_depth(0)
    }

    fn bind_free(self, variable: FreeVariable, depth: u32) -> Self {
        match self {
            Self::Equal(left, right) => Self::Equal(
                bind_term(left, variable, depth),
                bind_term(right, variable, depth),
            ),
            Self::Member(element, set) => Self::Member(
                bind_term(element, variable, depth),
                bind_term(set, variable, depth),
            ),
            Self::Not(formula) => Self::Not(Box::new(formula.bind_free(variable, depth))),
            Self::Implies(antecedent, consequent) => Self::Implies(
                Box::new(antecedent.bind_free(variable, depth)),
                Box::new(consequent.bind_free(variable, depth)),
            ),
            Self::ForAll(body) => {
                Self::ForAll(Box::new(body.bind_free(variable, depth.saturating_add(1))))
            }
        }
    }

    fn collect_free_variables(&self, variables: &mut BTreeSet<FreeVariable>) {
        match self {
            Self::Equal(left, right) | Self::Member(left, right) => {
                collect_term_free_variable(*left, variables);
                collect_term_free_variable(*right, variables);
            }
            Self::Not(formula) | Self::ForAll(formula) => {
                formula.collect_free_variables(variables);
            }
            Self::Implies(antecedent, consequent) => {
                antecedent.collect_free_variables(variables);
                consequent.collect_free_variables(variables);
            }
        }
    }

    fn validate_at_depth(&self, binder_depth: u32) -> Result<(), FormulaError> {
        match self {
            Self::Equal(left, right) | Self::Member(left, right) => {
                validate_term(*left, binder_depth)?;
                validate_term(*right, binder_depth)
            }
            Self::Not(formula) => formula.validate_at_depth(binder_depth),
            Self::Implies(antecedent, consequent) => {
                antecedent.validate_at_depth(binder_depth)?;
                consequent.validate_at_depth(binder_depth)
            }
            Self::ForAll(body) => body.validate_at_depth(binder_depth.saturating_add(1)),
        }
    }
}

fn bind_term(term: Term, variable: FreeVariable, depth: u32) -> Term {
    match term {
        Term::Free(candidate) if candidate == variable => Term::Bound(depth),
        _ => term,
    }
}

fn substitute_term(term: Term, from: FreeVariable, to: FreeVariable) -> Term {
    match term {
        Term::Free(candidate) if candidate == from => Term::Free(to),
        _ => term,
    }
}

fn collect_term_free_variable(term: Term, variables: &mut BTreeSet<FreeVariable>) {
    if let Term::Free(variable) = term {
        variables.insert(variable);
    }
}

fn validate_term(term: Term, binder_depth: u32) -> Result<(), FormulaError> {
    if let Term::Bound(index) = term
        && index >= binder_depth
    {
        return Err(FormulaError::DanglingBoundVariable {
            index,
            binder_depth,
        });
    }

    Ok(())
}

/// A structural formula validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormulaError {
    /// A De Bruijn index does not identify an enclosing quantifier.
    DanglingBoundVariable {
        /// The invalid index.
        index: u32,
        /// The number of enclosing quantifiers at the occurrence.
        binder_depth: u32,
    },
}

impl fmt::Display for FormulaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DanglingBoundVariable {
                index,
                binder_depth,
            } => write!(
                formatter,
                "bound-variable index {index} is invalid at binder depth {binder_depth}"
            ),
        }
    }
}

impl Error for FormulaError {}

#[cfg(test)]
mod tests {
    use super::{Formula, FormulaError, FreeVariable, Term};

    #[test]
    fn alpha_renamed_binders_have_the_same_representation() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);

        let with_x = Formula::for_all(x, Formula::equal(x.into(), x.into()));
        let with_y = Formula::for_all(y, Formula::equal(y.into(), y.into()));

        assert_eq!(with_x, with_y);
    }

    #[test]
    fn nested_binders_retain_their_correct_indices() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let formula = Formula::for_all(x, Formula::for_all(y, Formula::member(x.into(), y.into())));

        assert_eq!(
            formula,
            Formula::ForAll(Box::new(Formula::ForAll(Box::new(Formula::Member(
                Term::Bound(1),
                Term::Bound(0),
            )))))
        );
        assert_eq!(formula.validate(), Ok(()));
        assert!(formula.is_closed());
    }

    #[test]
    fn dangling_bound_variables_are_rejected() {
        let formula = Formula::equal(Term::Bound(0), Term::Bound(0));

        assert_eq!(
            formula.validate(),
            Err(FormulaError::DanglingBoundVariable {
                index: 0,
                binder_depth: 0,
            })
        );
    }

    #[test]
    fn free_substitution_does_not_modify_bound_variables() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let formula = Formula::ForAll(Box::new(Formula::member(Term::Bound(0), x.into())));

        let substituted = formula.substitute_free(x, y);

        assert_eq!(
            substituted,
            Formula::ForAll(Box::new(Formula::member(Term::Bound(0), y.into(),)))
        );
    }

    #[test]
    fn derived_connectives_use_only_primitive_nodes() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let left = Formula::equal(x.into(), x.into());
        let right = Formula::member(x.into(), y.into());

        assert_eq!(
            Formula::disjunction(left.clone(), right.clone()),
            Formula::implies(Formula::negate(left), right)
        );
    }
}
