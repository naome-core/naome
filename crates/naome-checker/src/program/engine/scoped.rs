//! Elaborate scoped inferences to the ordinary disk-backed operations. While
//! assumptions are open the available rules are axiom instances and modus
//! ponens. The deduction theorem then gives the ordered implication chain.
//! No local assumption or result gets a position in the checked program.
use super::{Error, Operation, compile, push};
use crate::derived::{COMMUTATION, Step, Term};
use naome_foundation::construction::{self as recipe, Expression};
use naome_proof::program::ScopedAction;

pub(super) fn instantiate(
    operations: &mut Vec<Operation>,
    universal: usize,
    replacement: u32,
) -> (usize, usize) {
    let opened = push(operations, Operation::OpenUniversal(universal, replacement));
    let axiom = push(operations, Operation::Implies(universal, opened));
    (axiom, apply(operations, universal, axiom))
}

pub(super) fn compile_scope(
    operations: &mut Vec<Operation>,
    assumptions: &[u64],
    actions: &[ScopedAction],
    result: u32,
) -> Result<(), Error> {
    let mut facts: Vec<_> = assumptions
        .iter()
        .map(|&node| push(operations, Operation::Input(node)))
        .collect();
    for action in actions {
        let next = match action {
            ScopedAction::Instantiate {
                universal,
                replacement,
                premises,
            } => {
                let universal = fact(&facts, *universal)?;
                let (_, mut result) = instantiate(operations, universal, *replacement);
                for &premise in premises {
                    result = apply(operations, fact(&facts, premise)?, result);
                }
                result
            }
            ScopedAction::Conjoin { left, right } => {
                conjoin(operations, fact(&facts, *left)?, fact(&facts, *right)?)
            }
        };
        facts.push(next);
    }
    let mut result = fact(&facts, result)?;
    for &assumption in facts[..assumptions.len()].iter().rev() {
        result = push(operations, Operation::Implies(assumption, result));
    }
    Ok(())
}

fn fact(facts: &[usize], position: u32) -> Result<usize, Error> {
    facts
        .get(position as usize)
        .copied()
        .ok_or_else(|| "fact is outside the earlier deduction scope".into())
}

fn apply(operations: &mut Vec<Operation>, premise: usize, implication: usize) -> usize {
    push(
        operations,
        Operation::Apply {
            premise,
            implication,
        },
    )
}

fn axiom(operations: &mut Vec<Operation>, expression: Expression<usize>) -> usize {
    compile(expression, operations, &|register, _| register)
}

fn identity(operations: &mut Vec<Operation>, a: usize) -> usize {
    let aa = push(operations, Operation::Implies(a, a));
    let frege = axiom(operations, recipe::frege(a, aa, a));
    let first = axiom(operations, recipe::simplification(a, aa));
    let second = axiom(operations, recipe::simplification(a, a));
    let partial = apply(operations, first, frege);
    apply(operations, second, partial)
}

/// Derive not(A -> not(B)) from A and B. Lift A under H = (A -> not(B)),
/// use Frege and H -> H to obtain H -> not(B), then apply the checked
/// commutation schema (H -> not(B)) -> (B -> not(H)).
fn conjoin(operations: &mut Vec<Operation>, a: usize, b: usize) -> usize {
    let not_b = push(operations, Operation::Not(b));
    let h = push(operations, Operation::Implies(a, not_b));
    let hh = identity(operations, h);
    let lift = axiom(operations, recipe::simplification(a, h));
    let ha = apply(operations, a, lift);
    let frege = axiom(operations, recipe::frege(h, a, not_b));
    let partial = apply(operations, hh, frege);
    let h_not_b = apply(operations, ha, partial);
    let commuted = commutation(operations, h, b);
    let b_not_h = apply(operations, h_not_b, commuted);
    apply(operations, b, b_not_h)
}

fn commutation(operations: &mut Vec<Operation>, a: usize, b: usize) -> usize {
    let mut formulas = Vec::with_capacity(COMMUTATION.terms.len());
    for term in COMMUTATION.terms {
        formulas.push(match *term {
            Term::A => a,
            Term::B => b,
            Term::Not(i) => push(operations, Operation::Not(formulas[i])),
            Term::Implies(i, j) => push(operations, Operation::Implies(formulas[i], formulas[j])),
        });
    }
    let mut facts = Vec::with_capacity(COMMUTATION.steps.len());
    for step in COMMUTATION.steps {
        let f = |i: usize| formulas[i];
        let result = match *step {
            Step::K(a, b) => axiom(operations, recipe::simplification(f(a), f(b))),
            Step::S(a, b, c) => axiom(operations, recipe::frege(f(a), f(b), f(c))),
            Step::C(a, b) => axiom(operations, recipe::contraposition(f(a), f(b))),
            Step::Mp(a, b) => apply(operations, facts[a], facts[b]),
        };
        facts.push(result);
    }
    *facts.last().expect("nonempty Hilbert schema")
}
