//! Fixed Hilbert certificate schemas. These are recipes, never trusted facts:
//! every instantiated result still passes through the mathematical checker.
//!
//! The first schema derives double-negation elimination using K/S/C, uses it
//! to transfer `not(not(A)) -> not(B)` from `A -> not(B)`, and applies C to
//! obtain `B -> not(A)`. The deduction theorem discharges the input implication.
//! The second combines double-negation elimination/introduction with C to
//! derive forward contraposition. No hypotheses remain in either certificate.
use super::*;

enum Term {
    A,
    B,
    Not(usize),
    Implies(usize, usize),
}
enum Step {
    K(usize, usize),
    S(usize, usize, usize),
    C(usize, usize),
    Mp(usize, usize),
}
struct Schema {
    terms: &'static [Term],
    steps: &'static [Step],
}
use Step::*;
use Term::*;
mod commutation;
mod contraposition;

pub(super) fn commutation(
    plan: &mut Plan,
    a: &Formula,
    b: &Formula,
    work: &mut Work,
) -> Result<Theorem, Failure> {
    instantiate(&commutation::COMMUTATION, plan, a, b, work)
}

pub(super) fn contraposition(
    plan: &mut Plan,
    a: &Formula,
    b: &Formula,
    work: &mut Work,
) -> Result<Theorem, Failure> {
    instantiate(&contraposition::CONTRAPOSITION, plan, a, b, work)
}

fn instantiate(
    schema: &Schema,
    plan: &mut Plan,
    a: &Formula,
    b: &Formula,
    work: &mut Work,
) -> Result<Theorem, Failure> {
    work.charge(
        schema
            .terms
            .len()
            .checked_mul(64)
            .and_then(|n| n.checked_add(schema.steps.len() * 64))
            .ok_or(LIMIT)?,
    )
    .map_err(|_| LIMIT)?;
    let mut terms: Vec<Formula> = Vec::new();
    for term in schema.terms {
        let formula = match *term {
            A => {
                reserve(&[a], work)?;
                a.clone()
            }
            B => {
                reserve(&[b], work)?;
                b.clone()
            }
            Not(index) => {
                reserve(&[&terms[index]], work)?;
                Formula::negate(terms[index].clone())
            }
            Implies(left, right) => {
                reserve(&[&terms[left], &terms[right]], work)?;
                Formula::implies(terms[left].clone(), terms[right].clone())
            }
        };
        terms.push(formula);
    }
    let mut outputs: Vec<Theorem> = Vec::new();
    for step in schema.steps {
        let theorem = match *step {
            K(a, b) => {
                reserve(&[&terms[a], &terms[b]], work)?;
                axiom(
                    plan,
                    ProofStep::Simplification {
                        antecedent: terms[a].clone().into(),
                        consequent: terms[b].clone().into(),
                    },
                    Logic::simplification(terms[a].clone(), terms[b].clone()),
                    work,
                )?
            }
            S(a, b, c) => {
                reserve(&[&terms[a], &terms[b], &terms[c]], work)?;
                axiom(
                    plan,
                    ProofStep::Frege {
                        first: terms[a].clone().into(),
                        second: terms[b].clone().into(),
                        third: terms[c].clone().into(),
                    },
                    Logic::frege(terms[a].clone(), terms[b].clone(), terms[c].clone()),
                    work,
                )?
            }
            C(a, b) => {
                reserve(&[&terms[a], &terms[b]], work)?;
                axiom(
                    plan,
                    ProofStep::ClassicalContraposition {
                        antecedent: terms[a].clone().into(),
                        consequent: terms[b].clone().into(),
                    },
                    Logic::classical_contraposition(terms[a].clone(), terms[b].clone()),
                    work,
                )?
            }
            Mp(premise, implication) => {
                apply(plan, &outputs[premise], &outputs[implication], work)?
            }
        };
        outputs.push(theorem);
    }
    outputs.pop().ok_or(INVALID)
}
