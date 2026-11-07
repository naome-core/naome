//! Goal-directed helper construction and generic relation exploration.
//! Questions contain no proofs or truth labels. The formal owner still checks
//! every admission and every resulting proof independently.
use super::{CompiledQuestion, Formula, FreeVariable};
use std::collections::{BTreeSet, VecDeque};
mod model;
pub(super) use model::Model;
mod analysis;
pub(super) use analysis::Cache;
mod learning;
pub(super) use learning::{Learning, Recipe};
#[cfg(test)]
pub(in crate::frontier) mod reference;
mod semantics;
#[cfg(test)]
use semantics::relevance;
pub(super) use semantics::{independent_goal, key, meaningful};
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
/// Exact invertible AND obligations; proposing them grants no validity.
pub(super) fn conjuncts(goal: &CompiledQuestion) -> Option<Vec<CompiledQuestion>> {
    let mut body = goal.formula().clone();
    while let Some(opened) = open(&body) {
        body = opened;
    }
    let (left, negative_right) = body.view().negated()?.implication_parts()?;
    let right = negative_right.negated()?;
    Some(
        [left.to_owned(), right.to_owned()]
            .into_iter()
            .filter_map(|f| CompiledQuestion::from_formula(close(f)).ok())
            .filter(|q| meaningful(q) && q.resolution_id() != goal.resolution_id())
            .collect(),
    )
}
/// Proper subgoals are generalized with their original variable relationships.
/// A helper may be stronger than the goal; no inference is claimed by proposing it.
fn helpers(goal: &CompiledQuestion, cursor: u64) -> Vec<CompiledQuestion> {
    if let Some(mut result) = conjuncts(goal) {
        if !result.is_empty() {
            let len = result.len();
            result.rotate_left(cursor as usize % len);
        }
        return result;
    }
    let mut pending = vec![goal.formula().clone()];
    let mut found = Vec::new();
    let goal_key = key(goal);
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
                    && key(&question) != goal_key
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
                && key(&question) != goal_key
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
/// A recipe changes one bounded structural construction parameter. Formal
/// admission remains with the supplied owner; rejection never grants more work.
pub(super) struct Proposal {
    pub question: CompiledQuestion,
    pub recipe: Option<Recipe>,
}
pub(super) struct PageBudget {
    pub questions: usize,
    pub bytes: usize,
}
fn varied(seed: &Formula, other: &Formula, recipe: Recipe) -> Option<Formula> {
    if recipe.level == 0 {
        return Some(seed.clone());
    }
    if recipe.level == 1 {
        return inclusion(seed);
    }
    let a = FreeVariable::new(0);
    let b = FreeVariable::new(1);
    let c = FreeVariable::new(2);
    let left = |x, y| relation(seed, x, y);
    let right = |x, y| relation(other, x, y);
    Some(match recipe.operator % 3 {
        0 => Formula::conjunction(left(a, b)?, right(a, b)?),
        1 => Formula::exists(c, Formula::conjunction(left(a, c)?, right(c, b)?)),
        _ => Formula::implies(left(a, b)?, right(b, a)?),
    })
}
pub(super) fn proposals(
    cursor: u64,
    seeds: &VecDeque<Formula>,
    goals: &VecDeque<CompiledQuestion>,
    learning: &Learning,
    draw: u64,
    budget: PageBudget,
    eligible: &mut dyn FnMut(&CompiledQuestion) -> bool,
) -> Vec<Proposal> {
    let mut groups = Vec::new();
    for goal in goals
        .iter()
        .rev()
        .cycle()
        .skip(cursor as usize % goals.len().max(1))
        .take(goals.len().min(4))
    {
        groups.push(VecDeque::from(helpers(goal, cursor)));
    }
    let a = FreeVariable::new(0);
    let b = FreeVariable::new(1);
    let mut relations = vec![Formula::member(a, b), Formula::equal(a, b)];
    let checked = seeds
        .iter()
        .filter(|f| f.free_variables().len() == 2 && f.view().node_count_and_depth().0 <= 24)
        .collect::<Vec<_>>();
    relations.extend(
        checked
            .iter()
            .cycle()
            .skip(cursor as usize % checked.len().max(1))
            .take(checked.len().min(4))
            .map(|f| (*f).clone()),
    );
    let mut recipes = std::collections::BTreeMap::new();
    let mut checked_questions = VecDeque::new();
    let mut free_questions = VecDeque::new();
    for (offset, recipe) in learning.recipes(cursor, draw).into_iter().enumerate() {
        let index = (cursor as usize + offset) % relations.len();
        let other = &relations[(index + 1 + offset % 2) % relations.len()];
        if let Some(seed) = varied(&relations[index], other, recipe)
            && let Some(formula) = property(&seed, u64::from(recipe.operator))
            && let Ok(question) = CompiledQuestion::from_formula(formula)
        {
            recipes.entry(*question.resolution_id()).or_insert(recipe);
            if index < 2 {
                free_questions.push_back(question);
            } else {
                checked_questions.push_back(question);
            }
        }
    }
    groups.extend([checked_questions, free_questions]);
    let length = groups.len();
    groups.rotate_left(cursor as usize % length);
    let mut all = Vec::new();
    while groups.iter().any(|g| !g.is_empty()) {
        for group in &mut groups {
            if let Some(q) = group.pop_front() {
                all.push(q);
            }
        }
    }
    bounded_eligible(all, budget.questions, budget.bytes, eligible)
        .into_iter()
        .map(|question| Proposal {
            recipe: recipes.get(question.resolution_id()).copied(),
            question,
        })
        .collect()
}
#[cfg(test)]
pub(super) fn questions(
    cursor: u64,
    seeds: &VecDeque<Formula>,
    goals: &VecDeque<CompiledQuestion>,
    maximum: usize,
    bytes: usize,
    eligible: &mut dyn FnMut(&CompiledQuestion) -> bool,
) -> Vec<CompiledQuestion> {
    proposals(
        cursor,
        seeds,
        goals,
        &Learning::fresh("00".repeat(32)),
        0,
        PageBudget {
            questions: maximum,
            bytes,
        },
        eligible,
    )
    .into_iter()
    .map(|p| p.question)
    .collect()
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
    bounded_eligible(all, maximum, bytes, &mut |_| true)
}
fn bounded_eligible(
    all: Vec<CompiledQuestion>,
    maximum: usize,
    bytes: usize,
    eligible: &mut dyn FnMut(&CompiledQuestion) -> bool,
) -> Vec<CompiledQuestion> {
    let mut seen = BTreeSet::new();
    let mut retained = 0;
    let mut result = Vec::new();
    let mut checks = 0;
    for question in all {
        let cost = question.source().len() * 8 + 256;
        if result.len() >= maximum.min(12) || checks >= 20 {
            break;
        }
        if meaningful(&question)
            && crate::learning::State::eligible(question.source())
            && retained + cost <= bytes
            && seen.insert(key(&question))
        {
            checks += 1;
            if eligible(&question) {
                retained += cost;
                result.push(question);
            }
        }
    }
    result
}

/// Closed conditional cut questions extracted from actual stalled branches.
/// Branch facts are only premises of a proposed theorem and confer no authority.
pub(crate) fn from_frontier(
    goal: &CompiledQuestion,
    report: &crate::learning::SearchFrontier,
    maximum: usize,
    bytes: usize,
) -> Vec<CompiledQuestion> {
    if !crate::learning::State::eligible(goal.source()) || report.validate(goal).is_err() {
        return Vec::new();
    }
    let Ok(contexts) = report.contexts() else {
        return Vec::new();
    };
    let mut body = goal.formula().clone();
    while let Some(opened) = open(&body) {
        body = opened;
    }
    if body
        .view()
        .negated()
        .and_then(|f| f.implication_parts())
        .is_some_and(|(_, b)| b.negated().is_some())
    {
        return bounded(helpers(goal, 0), maximum.min(4), bytes);
    }
    let mut all = Vec::new();
    for context in contexts {
        for negative in &context.facts {
            let Some(conclusion) = negative.view().negated().map(|f| f.to_owned()) else {
                continue;
            };
            // A useful cut names a proper remaining conclusion, not the entire
            // original problem under precisely the same assumptions.
            let mut premises = context.assumptions.clone();
            for fact in &context.facts {
                if fact == negative
                    || fact == &Formula::negate(context.goal.clone())
                    || fact
                        .view()
                        .equality_variables()
                        .is_some_and(|(a, b)| a == b)
                {
                    continue;
                }
                if matches!(
                    fact.view().graph_node(),
                    naome_foundation::graph::Node::Equal(..)
                        | naome_foundation::graph::Node::Member(..)
                ) && !premises.contains(fact)
                    && premises.len() < 6
                {
                    premises.push(fact.clone());
                }
            }
            if premises.is_empty() || premises.contains(&conclusion) {
                continue;
            }
            let mut conditional = conclusion;
            for premise in premises.into_iter().rev() {
                conditional = Formula::implies(premise, conditional);
            }
            if let Ok(q) = CompiledQuestion::from_formula(close(conditional))
                && q.resolution_id() != goal.resolution_id()
                && key(&q) != key(goal)
                && q.formula().view().node_count_and_depth().0
                    < goal.formula().view().node_count_and_depth().0
                && independent_goal(&q, goal)
            {
                all.push(q);
            }
        }
    }
    bounded(all, maximum.min(4), bytes)
}
