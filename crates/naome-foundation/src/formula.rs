//! Primitive first-order formulas for set theory.

use std::collections::BTreeSet;

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

/// A well-formed formula in the primitive language of first-order set theory.
///
/// The internal tree is private so dangling De Bruijn indices cannot enter the
/// public API. Formulas are constructed with free variables and quantifier
/// constructors bind those variables structurally.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Formula(Node);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Node {
    Equal(Variable, Variable),
    Member(Variable, Variable),
    Not(Box<Self>),
    Implies(Box<Self>, Box<Self>),
    ForAll(Box<Self>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Variable {
    Bound(u32),
    Free(FreeVariable),
}

impl Formula {
    /// Constructs equality between two free set variables.
    #[must_use]
    pub const fn equal(left: FreeVariable, right: FreeVariable) -> Self {
        Self(Node::Equal(Variable::Free(left), Variable::Free(right)))
    }

    /// Constructs membership between two free set variables.
    #[must_use]
    pub const fn member(element: FreeVariable, set: FreeVariable) -> Self {
        Self(Node::Member(Variable::Free(element), Variable::Free(set)))
    }

    /// Constructs a negation.
    #[must_use]
    pub fn negate(formula: Self) -> Self {
        Self(Node::Not(Box::new(formula.0)))
    }

    /// Constructs an implication.
    #[must_use]
    pub fn implies(antecedent: Self, consequent: Self) -> Self {
        Self(Node::Implies(
            Box::new(antecedent.0),
            Box::new(consequent.0),
        ))
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
        Self(Node::ForAll(Box::new(bind_free(body.0, variable, 0))))
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
        Self(substitute_free(self.0, from, to))
    }

    /// Returns the free variables occurring in this formula.
    #[must_use]
    pub fn free_variables(&self) -> BTreeSet<FreeVariable> {
        let mut variables = BTreeSet::new();
        collect_free_variables(&self.0, &mut variables);
        variables
    }

    /// Returns `true` when the formula contains no free variables.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.free_variables().is_empty()
    }
}

fn bind_free(node: Node, variable: FreeVariable, depth: u32) -> Node {
    match node {
        Node::Equal(left, right) => Node::Equal(
            bind_variable(left, variable, depth),
            bind_variable(right, variable, depth),
        ),
        Node::Member(element, set) => Node::Member(
            bind_variable(element, variable, depth),
            bind_variable(set, variable, depth),
        ),
        Node::Not(formula) => Node::Not(Box::new(bind_free(*formula, variable, depth))),
        Node::Implies(antecedent, consequent) => Node::Implies(
            Box::new(bind_free(*antecedent, variable, depth)),
            Box::new(bind_free(*consequent, variable, depth)),
        ),
        Node::ForAll(body) => Node::ForAll(Box::new(bind_free(
            *body,
            variable,
            depth.saturating_add(1),
        ))),
    }
}

fn substitute_free(node: Node, from: FreeVariable, to: FreeVariable) -> Node {
    match node {
        Node::Equal(left, right) => Node::Equal(
            substitute_variable(left, from, to),
            substitute_variable(right, from, to),
        ),
        Node::Member(element, set) => Node::Member(
            substitute_variable(element, from, to),
            substitute_variable(set, from, to),
        ),
        Node::Not(formula) => Node::Not(Box::new(substitute_free(*formula, from, to))),
        Node::Implies(antecedent, consequent) => Node::Implies(
            Box::new(substitute_free(*antecedent, from, to)),
            Box::new(substitute_free(*consequent, from, to)),
        ),
        Node::ForAll(body) => Node::ForAll(Box::new(substitute_free(*body, from, to))),
    }
}

fn collect_free_variables(node: &Node, variables: &mut BTreeSet<FreeVariable>) {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            collect_free_variable(*left, variables);
            collect_free_variable(*right, variables);
        }
        Node::Not(formula) | Node::ForAll(formula) => {
            collect_free_variables(formula, variables);
        }
        Node::Implies(antecedent, consequent) => {
            collect_free_variables(antecedent, variables);
            collect_free_variables(consequent, variables);
        }
    }
}

fn bind_variable(value: Variable, variable: FreeVariable, depth: u32) -> Variable {
    match value {
        Variable::Free(candidate) if candidate == variable => Variable::Bound(depth),
        _ => value,
    }
}

fn substitute_variable(value: Variable, from: FreeVariable, to: FreeVariable) -> Variable {
    match value {
        Variable::Free(candidate) if candidate == from => Variable::Free(to),
        _ => value,
    }
}

fn collect_free_variable(value: Variable, variables: &mut BTreeSet<FreeVariable>) {
    if let Variable::Free(variable) = value {
        variables.insert(variable);
    }
}

#[cfg(test)]
mod tests {
    use super::{Formula, FreeVariable, Node, Variable};

    #[test]
    fn alpha_renamed_binders_have_the_same_representation() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);

        let with_x = Formula::for_all(x, Formula::equal(x, x));
        let with_y = Formula::for_all(y, Formula::equal(y, y));

        assert_eq!(with_x, with_y);
    }

    #[test]
    fn nested_binders_retain_their_correct_indices() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let formula = Formula::for_all(x, Formula::for_all(y, Formula::member(x, y)));

        assert_eq!(
            formula,
            Formula(Node::ForAll(Box::new(Node::ForAll(Box::new(
                Node::Member(Variable::Bound(1), Variable::Bound(0)),
            )))))
        );
        assert!(formula.is_closed());
    }

    #[test]
    fn free_substitution_does_not_modify_bound_variables() {
        let bound = FreeVariable::new(1);
        let from = FreeVariable::new(2);
        let to = FreeVariable::new(3);
        let formula = Formula::for_all(bound, Formula::member(bound, from));

        let substituted = formula.substitute_free(from, to);
        let expected = Formula::for_all(bound, Formula::member(bound, to));

        assert_eq!(substituted, expected);
    }

    #[test]
    fn derived_connectives_use_only_primitive_nodes() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let left = Formula::equal(x, x);
        let right = Formula::member(x, y);

        assert_eq!(
            Formula::disjunction(left.clone(), right.clone()),
            Formula::implies(Formula::negate(left), right)
        );
    }
}
