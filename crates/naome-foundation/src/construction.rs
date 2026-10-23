//! Representation-independent recipes for Foundation's logical axioms and schemas.
//!
//! Recipes have fixed structural size. Their inputs can be ordinary trees or
//! disk-backed formula handles; evaluating a recipe does not inspect its inputs.
use crate::{Formula, FreeVariable};

#[derive(Clone, Debug)]
pub enum Expression<F> {
    Input(F),
    Equal(FreeVariable, FreeVariable),
    Member(FreeVariable, FreeVariable),
    Not(Box<Self>),
    Implies(Box<Self>, Box<Self>),
    ForAll(FreeVariable, Box<Self>),
    Vacuous(Box<Self>),
    Substitute(FreeVariable, FreeVariable, Box<Self>),
}

impl<F> Expression<F> {
    pub fn negate(self) -> Self {
        Self::Not(Box::new(self))
    }
    pub fn implies(self, right: Self) -> Self {
        Self::Implies(Box::new(self), Box::new(right))
    }
    pub fn for_all(self, variable: FreeVariable) -> Self {
        Self::ForAll(variable, Box::new(self))
    }
    pub fn exists(self, variable: FreeVariable) -> Self {
        self.negate().for_all(variable).negate()
    }
    pub fn conjunction(self, right: Self) -> Self {
        self.implies(right.negate()).negate()
    }
    pub fn substitute(self, from: FreeVariable, to: FreeVariable) -> Self {
        Self::Substitute(from, to, Box::new(self))
    }
}
impl<F: Clone> Expression<F> {
    pub fn biconditional(self, right: Self) -> Self {
        self.clone()
            .implies(right.clone())
            .conjunction(right.implies(self))
    }
}
impl Expression<Formula> {
    pub(crate) fn evaluate(self) -> Formula {
        match self {
            Self::Input(value) => value,
            Self::Equal(a, b) => Formula::equal(a, b),
            Self::Member(a, b) => Formula::member(a, b),
            Self::Not(a) => Formula::negate(a.evaluate()),
            Self::Implies(a, b) => Formula::implies(a.evaluate(), b.evaluate()),
            Self::ForAll(v, a) => Formula::for_all(v, a.evaluate()),
            Self::Vacuous(a) => Formula::vacuous_for_all(a.evaluate()),
            Self::Substitute(a, b, value) => value.evaluate().substitute_free(a, b),
        }
    }
}

pub fn simplification<F: Clone>(a: F, b: F) -> Expression<F> {
    let a = Expression::Input(a);
    let b = Expression::Input(b);
    a.clone().implies(b.implies(a))
}
pub fn frege<F: Clone>(a: F, b: F, c: F) -> Expression<F> {
    let a = Expression::Input(a);
    let b = Expression::Input(b);
    let c = Expression::Input(c);
    a.clone()
        .implies(b.clone().implies(c.clone()))
        .implies(a.clone().implies(b).implies(a.implies(c)))
}
pub fn contraposition<F: Clone>(a: F, b: F) -> Expression<F> {
    let a = Expression::Input(a);
    let b = Expression::Input(b);
    b.clone()
        .negate()
        .implies(a.clone().negate())
        .implies(a.implies(b))
}
pub fn distribution<F: Clone>(v: FreeVariable, a: F, b: F) -> Expression<F> {
    let a = Expression::Input(a);
    let b = Expression::Input(b);
    a.clone()
        .implies(b.clone())
        .for_all(v)
        .implies(a.for_all(v).implies(b.for_all(v)))
}
pub fn vacuous<F: Clone>(a: F) -> Expression<F> {
    let a = Expression::Input(a);
    a.clone().implies(Expression::Vacuous(Box::new(a)))
}
pub fn instantiation<F: Clone>(v: FreeVariable, replacement: FreeVariable, a: F) -> Expression<F> {
    let a = Expression::Input(a);
    a.clone().for_all(v).implies(a.substitute(v, replacement))
}
pub fn substitution<F: Clone>(from: FreeVariable, to: FreeVariable, body: F) -> Expression<F> {
    let body = Expression::Input(body);
    Expression::Equal(from, to).implies(body.clone().implies(body.substitute(from, to)))
}

/// The base schema leaves additional predicate parameters free. They may be
/// universally closed by generalization. Callers enforce freshness/role rules.
pub fn separation<F: Clone>(
    predicate: F,
    element: FreeVariable,
    source: FreeVariable,
    result: FreeVariable,
) -> Expression<F> {
    Expression::Member(element, result)
        .biconditional(
            Expression::Member(element, source).conjunction(Expression::Input(predicate)),
        )
        .for_all(element)
        .exists(result)
        .for_all(source)
}
pub fn replacement<F: Clone>(
    predicate: F,
    input: FreeVariable,
    output: FreeVariable,
    witness: FreeVariable,
    source: FreeVariable,
    result: FreeVariable,
) -> Expression<F> {
    let predicate = Expression::Input(predicate);
    let uniqueness = predicate
        .clone()
        .substitute(output, witness)
        .implies(Expression::Equal(witness, output))
        .for_all(witness);
    let unique = predicate.clone().conjunction(uniqueness).exists(output);
    let total = Expression::Member(input, source)
        .implies(unique)
        .for_all(input);
    let preimage = Expression::Member(input, source)
        .conjunction(predicate)
        .exists(input);
    let image = Expression::Member(output, result)
        .biconditional(preimage)
        .for_all(output);
    total.implies(image.exists(result)).for_all(source)
}
