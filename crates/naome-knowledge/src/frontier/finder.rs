//! Goal-directed helper construction and generic relation exploration.
//! Questions contain no proofs or truth labels. The formal owner still checks
//! every admission and every resulting proof independently.
use super::{CompiledQuestion, Formula, FreeVariable};
use std::collections::{BTreeSet, VecDeque};
mod model;
pub(super) use model::Model;
mod semantics;
pub(super) use semantics::{independent_goal, key, meaningful, relevance};
#[cfg(test)]
mod tests;

fn close(mut formula: Formula) -> Formula {
    for variable in formula.free_variables().into_iter().rev() {
        formula = Formula::for_all(variable, formula);
    }
    formula
}
fn open(formula: &Formula) -> Option<Formula> {
    let fresh = formula
        .free_variables()
        .last()
        .map_or(Some(0), |v| v.identifier().checked_add(1))?;
    formula.open_outer_universal(FreeVariable::new(fresh))
}
fn relation(formula: &Formula, a: FreeVariable, b: FreeVariable) -> Option<Formula> {
    let free = formula.free_variables().into_iter().collect::<Vec<_>>();
    if free.len() != 2 {
        return None;
    }
    Some(
        formula
            .clone()
            .map_free_variables(|v| if v == free[0] { a } else { b }),
    )
}
fn property(seed: &Formula, operator: u64) -> Option<Formula> {
    let a = FreeVariable::new(0);
    let b = FreeVariable::new(1);
    let c = FreeVariable::new(2);
    let r = |x, y| relation(seed, x, y);
    let body = match operator % 10 {
        0 => r(a, a)?,
        1 => Formula::negate(r(a, a)?),
        2 => Formula::implies(r(a, b)?, r(b, a)?),
        3 => Formula::implies(
            Formula::conjunction(r(a, b)?, r(b, a)?),
            Formula::equal(a, b),
        ),
        4 => Formula::implies(Formula::conjunction(r(a, b)?, r(b, c)?), r(a, c)?),
        5 => Formula::disjunction(r(a, b)?, r(b, a)?),
        6 => Formula::exists(b, r(a, b)?),
        7 => Formula::exists(a, r(a, b)?),
        8 => Formula::exists(a, Formula::for_all(b, r(a, b)?)),
        _ => Formula::implies(
            Formula::for_all(c, Formula::biconditional(r(c, a)?, r(c, b)?)),
            Formula::equal(a, b),
        ),
    };
    Some(close(body))
}
fn inclusion(seed: &Formula) -> Option<Formula> {
    let a = FreeVariable::new(0);
    let b = FreeVariable::new(1);
    let x = FreeVariable::new(2);
    Some(Formula::for_all(
        x,
        Formula::implies(relation(seed, x, a)?, relation(seed, x, b)?),
    ))
}
/// Proper subgoals are generalized with their original variable relationships.
/// A helper may be stronger than the goal; no inference is claimed by proposing it.
fn helpers(goal: &CompiledQuestion, cursor: u64) -> Vec<CompiledQuestion> {
    let mut body = goal.formula().clone();
    while let Some(opened) = open(&body) {
        body = opened;
    }
    if let Some((left, negative_right)) = body.view().negated().and_then(|f| f.implication_parts())
        && let Some(right) = negative_right.negated()
    {
        // Solving the actual conjuncts suffices; unrelated strengthenings or
        // negated premises add work without supplying these prerequisites.
        let mut result = [left.to_owned(), right.to_owned()]
            .into_iter()
            .filter_map(|f| CompiledQuestion::from_formula(close(f)).ok())
            .filter(|q| meaningful(q) && q.resolution_id() != goal.resolution_id())
            .collect::<Vec<_>>();
        if !result.is_empty() {
            let len = result.len();
            result.rotate_left(cursor as usize % len);
        }
        return result;
    }
    let mut pending = vec![goal.formula().clone()];
    let mut found = Vec::new();
    for _ in 0..32 {
        let Some(part) = pending.pop() else {
            break;
        };
        if let Some(body) = open(&part) {
            pending.push(body);
            continue;
        }
        if let Some((a, b)) = part.implication_parts() {
            for child in [a.clone(), b.clone(), Formula::negate(a.clone())] {
                if let Ok(question) = CompiledQuestion::from_formula(close(child))
                    && meaningful(&question)
                    && key(&question) != key(goal)
                    && question.resolution_id() != goal.resolution_id()
                {
                    found.push(question);
                }
            }
            pending.push(a);
            pending.push(b);
        } else if let Some(body) = part.view().negated() {
            // Conjunction and existence are encoded through negation. Retain
            // the positive proper subgoal as well as its surrounding syntax.
            if let Ok(question) = CompiledQuestion::from_formula(close(body.to_owned()))
                && meaningful(&question)
                && question.resolution_id() != goal.resolution_id()
                && key(&question) != key(goal)
            {
                found.push(question);
            }
            pending.push(body.to_owned());
        }
    }
    if !found.is_empty() {
        let length = found.len();
        found.rotate_left(cursor as usize % length);
    }
    found
}
/// The cursor rotates construction operators, not a bank of theorem strings.
/// Checked fragments and earlier unresolved goals supply the changing context.
pub(super) fn questions(
    cursor: u64,
    seeds: &VecDeque<Formula>,
    goals: &VecDeque<CompiledQuestion>,
    maximum: usize,
    bytes: usize,
) -> Vec<CompiledQuestion> {
    let mut all = Vec::new();
    for goal in goals.iter().rev().take(4) {
        all.extend(helpers(goal, cursor));
    }
    let a = FreeVariable::new(0);
    let b = FreeVariable::new(1);
    let mut relations = vec![Formula::member(a, b), Formula::equal(a, b)];
    relations.extend(
        seeds
            .iter()
            .filter(|f| f.free_variables().len() == 2 && f.view().node_count_and_depth().0 <= 24)
            .take(4)
            .cloned(),
    );
    let primitive = relations.clone();
    relations.extend(primitive.iter().filter_map(inclusion));
    for offset in 0..20 {
        let seed = &relations[(cursor as usize + offset) % relations.len()];
        if let Some(formula) = property(seed, cursor / relations.len() as u64 + offset as u64)
            && let Ok(question) = CompiledQuestion::from_formula(formula)
        {
            all.push(question);
        }
    }
    bounded(all, maximum, bytes)
}
pub(super) fn for_goal(
    cursor: u64,
    goal: &CompiledQuestion,
    maximum: usize,
    bytes: usize,
) -> Vec<CompiledQuestion> {
    bounded(helpers(goal, cursor), maximum, bytes)
}
fn bounded(all: Vec<CompiledQuestion>, maximum: usize, bytes: usize) -> Vec<CompiledQuestion> {
    let mut seen = BTreeSet::new();
    let mut retained = 0;
    let mut result = Vec::new();
    for question in all {
        let cost = question.source().len() * 8 + 256;
        if result.len() >= maximum.min(12) {
            break;
        }
        if meaningful(&question)
            && crate::learning::State::eligible(question.source())
            && retained + cost <= bytes
            && seen.insert(key(&question))
        {
            retained += cost;
            result.push(question);
        }
    }
    result
}
