//! Primitive first-order formulas for set theory.

mod canonical_v0;

pub use canonical_v0::{
    FORMULA_V0_MAX_BYTES, FORMULA_V0_MAX_DEPTH, FORMULA_V0_MAX_NODES, FormulaCodecError,
};

use std::collections::{BTreeMap, BTreeSet};

/// Identifies a free object-language variable.
///
/// Names are presentation data. The numeric identifier is the stable identity
/// used while constructing formulas and schema instances. Its `u32` width is
/// a resource limit of this Rust implementation, not of the abstract language.
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
    pub fn for_all(variable: FreeVariable, mut body: Self) -> Self {
        bind_free(&mut body.0, 0, &|candidate| {
            (candidate == variable).then_some(0)
        });
        Self(Node::ForAll(Box::new(body.0)))
    }

    pub(crate) fn for_all_many(variables: &[FreeVariable], mut body: Self) -> Self {
        if variables.is_empty() {
            return body;
        }

        let binder_count = u32::try_from(variables.len())
            .expect("the number of binders must fit a De Bruijn index");
        let mut binders = BTreeMap::new();
        for (position, variable) in variables.iter().enumerate() {
            let position = u32::try_from(position).expect("the binder count was checked above");
            binders.insert(*variable, binder_count - position - 1);
        }

        bind_free(&mut body.0, 0, &|variable| binders.get(&variable).copied());
        for _ in variables {
            body = Self(Node::ForAll(Box::new(body.0)));
        }
        body
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
    pub fn substitute_free(mut self, from: FreeVariable, to: FreeVariable) -> Self {
        if from == to {
            return self;
        }

        substitute_free(&mut self.0, from, to);
        self
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
        !has_matching_free_variable(&self.0, &|_| true)
    }

    pub(crate) fn vacuous_for_all(body: Self) -> Self {
        Self(Node::ForAll(Box::new(body.0)))
    }

    pub(crate) fn implication_consequent_for(&self, premise: &Self) -> Option<Self> {
        match &self.0 {
            Node::Implies(antecedent, consequent) if antecedent.as_ref() == &premise.0 => {
                Some(Self(consequent.as_ref().clone()))
            }
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn primitive_structure(&self) -> String {
        let mut output = String::new();
        render_node(&self.0, &mut output);
        output
    }
}

#[cfg(test)]
fn render_node(node: &Node, output: &mut String) {
    match node {
        Node::Equal(left, right) => render_binary("eq", *left, *right, output),
        Node::Member(element, set) => render_binary("mem", *element, *set, output),
        Node::Not(formula) => {
            output.push_str("not(");
            render_node(formula, output);
            output.push(')');
        }
        Node::Implies(antecedent, consequent) => {
            output.push_str("imp(");
            render_node(antecedent, output);
            output.push(',');
            render_node(consequent, output);
            output.push(')');
        }
        Node::ForAll(body) => {
            output.push_str("all(");
            render_node(body, output);
            output.push(')');
        }
    }
}

#[cfg(test)]
fn render_binary(name: &str, left: Variable, right: Variable, output: &mut String) {
    output.push_str(name);
    output.push('(');
    render_variable(left, output);
    output.push(',');
    render_variable(right, output);
    output.push(')');
}

#[cfg(test)]
fn render_variable(variable: Variable, output: &mut String) {
    let (prefix, identifier) = match variable {
        Variable::Bound(index) => ('b', index),
        Variable::Free(variable) => ('f', variable.identifier()),
    };
    output.push(prefix);
    output.push_str(&identifier.to_string());
}

fn bind_free(node: &mut Node, depth: u32, binding_index: &impl Fn(FreeVariable) -> Option<u32>) {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            *left = bind_variable(*left, depth, binding_index);
            *right = bind_variable(*right, depth, binding_index);
        }
        Node::Not(formula) => bind_free(formula, depth, binding_index),
        Node::Implies(antecedent, consequent) => {
            bind_free(antecedent, depth, binding_index);
            bind_free(consequent, depth, binding_index);
        }
        Node::ForAll(body) => {
            let nested_depth = depth
                .checked_add(1)
                .expect("formula nesting exceeds the representable De Bruijn index");

            bind_free(body, nested_depth, binding_index);
        }
    }
}

fn substitute_free(node: &mut Node, from: FreeVariable, to: FreeVariable) {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            *left = substitute_variable(*left, from, to);
            *right = substitute_variable(*right, from, to);
        }
        Node::Not(formula) | Node::ForAll(formula) => substitute_free(formula, from, to),
        Node::Implies(antecedent, consequent) => {
            substitute_free(antecedent, from, to);
            substitute_free(consequent, from, to);
        }
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

fn has_matching_free_variable(node: &Node, matches: &impl Fn(FreeVariable) -> bool) -> bool {
    match node {
        Node::Equal(left, right) | Node::Member(left, right) => {
            let matches_free = |variable| match variable {
                Variable::Free(variable) => matches(variable),
                Variable::Bound(_) => false,
            };

            matches_free(*left) || matches_free(*right)
        }
        Node::Not(formula) | Node::ForAll(formula) => has_matching_free_variable(formula, matches),
        Node::Implies(antecedent, consequent) => {
            has_matching_free_variable(antecedent, matches)
                || has_matching_free_variable(consequent, matches)
        }
    }
}

fn bind_variable(
    value: Variable,
    depth: u32,
    binding_index: &impl Fn(FreeVariable) -> Option<u32>,
) -> Variable {
    match value {
        Variable::Free(variable) if let Some(index) = binding_index(variable) => Variable::Bound(
            index
                .checked_add(depth)
                .expect("formula nesting exceeds the representable De Bruijn index"),
        ),
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
    use super::{Formula, FreeVariable, Node, Variable, bind_free};

    #[test]
    #[should_panic(expected = "formula nesting exceeds the representable De Bruijn index")]
    fn binding_fails_closed_when_de_bruijn_depth_overflows() {
        let x = FreeVariable::new(1);
        let mut body = Node::ForAll(Box::new(Node::Equal(Variable::Free(x), Variable::Free(x))));

        bind_free(&mut body, u32::MAX, &|candidate| {
            (candidate == x).then_some(0)
        });
    }

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
    fn multiple_binders_match_repeated_binding_with_nesting_and_duplicates() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let z = FreeVariable::new(3);
        let variables = [x, y, x];
        let body = Formula::for_all(
            z,
            Formula::implies(Formula::member(x, z), Formula::equal(y, x)),
        );
        let expected = variables
            .iter()
            .rev()
            .fold(body.clone(), |formula, variable| {
                Formula::for_all(*variable, formula)
            });

        assert_eq!(Formula::for_all_many(&variables, body), expected);
    }

    #[test]
    fn closure_check_finds_a_free_variable_under_a_binder() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let formula = Formula::for_all(
            x,
            Formula::implies(Formula::equal(x, x), Formula::member(y, x)),
        );

        assert!(!formula.is_closed());
    }

    #[test]
    fn free_substitution_changes_only_matching_free_variables_across_the_tree() {
        let bound = FreeVariable::new(1);
        let from = FreeVariable::new(2);
        let to = FreeVariable::new(3);
        let untouched = FreeVariable::new(4);
        let formula = Formula::for_all(
            bound,
            Formula::implies(
                Formula::negate(Formula::member(bound, from)),
                Formula::implies(Formula::equal(from, untouched), Formula::member(to, from)),
            ),
        );

        let substituted = formula.substitute_free(from, to);
        let expected = Formula::for_all(
            bound,
            Formula::implies(
                Formula::negate(Formula::member(bound, to)),
                Formula::implies(Formula::equal(to, untouched), Formula::member(to, to)),
            ),
        );

        assert_eq!(substituted, expected);
    }

    #[test]
    fn free_substitution_is_a_no_op_for_absent_or_identical_variables() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let absent = FreeVariable::new(3);
        let formula = Formula::member(x, y);

        assert_eq!(formula.clone().substitute_free(absent, x), formula);
        assert_eq!(formula.clone().substitute_free(x, x), formula);
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
