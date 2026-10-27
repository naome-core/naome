//! Question-only compositional construction guided by observed solver outcomes.
//! It never imports a question bank, constructs a proof or assigns truth labels.
use super::{CompiledQuestion, Formula, FreeVariable, Random};
use std::collections::VecDeque;

mod model;
pub(super) use model::Model;
#[cfg(test)]
mod tests;

const PREDICATE_NODES: usize = 24;
const PREDICATE_DEPTH: usize = 8;

fn close(mut formula: Formula) -> Formula {
    for variable in formula.free_variables().into_iter().rev() {
        formula = Formula::for_all(variable, formula);
    }
    formula
}

fn small(formula: &Formula) -> bool {
    let (nodes, depth) = formula.view().node_count_and_depth();
    nodes <= PREDICATE_NODES && depth <= PREDICATE_DEPTH
}

fn atom(random: &mut Random) -> Formula {
    let a = FreeVariable::new(random.below(3) as u32);
    let b = FreeVariable::new(random.below(3) as u32);
    if random.below(4) == 0 {
        Formula::equal(a, b)
    } else {
        Formula::member(a, b)
    }
}

fn predicate(random: &mut Random, seeds: &VecDeque<Formula>) -> Formula {
    let mut pool = (0..4).map(|_| atom(random)).collect::<Vec<_>>();
    pool.extend(seeds.iter().filter(|f| small(f)).take(4).cloned());
    for _ in 0..1 + random.below(5) {
        let left = pool[random.below(pool.len() as u64) as usize].clone();
        let right = pool[random.below(pool.len() as u64) as usize].clone();
        let variable = FreeVariable::new(random.below(3) as u32);
        let formula = match random.below(7) {
            0 => Formula::negate(left),
            1 => Formula::implies(left, right),
            2 => Formula::conjunction(left, right),
            3 => Formula::disjunction(left, right),
            4 => Formula::for_all(variable, left),
            5 => Formula::exists(variable, left),
            _ => Formula::biconditional(left, right),
        };
        if small(&formula) {
            pool.push(formula);
        }
    }
    pool.pop().expect("primitive predicate pool is nonempty")
}

fn conjecture(random: &mut Random, seeds: &VecDeque<Formula>) -> Option<CompiledQuestion> {
    let left = predicate(random, seeds);
    let right = predicate(random, seeds);
    let formula = match random.below(5) {
        0 => left,
        1 => Formula::implies(left, right),
        2 => {
            let consequence = match random.below(4) {
                0 => Formula::conjunction(left.clone(), right.clone()),
                1 => Formula::disjunction(left.clone(), right.clone()),
                2 => Formula::implies(right.clone(), left.clone()),
                _ => Formula::negate(Formula::negate(left.clone())),
            };
            Formula::implies(left, Formula::implies(right, consequence))
        }
        // The schema is used as a construction of questions only. The solver
        // must independently derive an exact target and the checker must accept it.
        _ => comprehension(left),
    };
    CompiledQuestion::from_formula(close(formula)).ok()
}

fn comprehension(predicate: Formula) -> Formula {
    let x = FreeVariable::new(0);
    let mut used = predicate.free_variables();
    used.insert(x);
    let mut fresh = (0..=u32::MAX)
        .map(FreeVariable::new)
        .filter(|v| !used.contains(v));
    let source = fresh.next().expect("bounded predicate leaves fresh source");
    let result = fresh.next().expect("bounded predicate leaves fresh result");
    let body = Formula::biconditional(
        Formula::member(x, result),
        Formula::conjunction(Formula::member(x, source), predicate),
    );
    Formula::for_all(source, Formula::exists(result, Formula::for_all(x, body)))
}

/// Generate a bounded page from primitives and checked local fragments. The
/// cursor, context and persisted predictor determine the page across restart.
pub(super) fn questions(
    cursor: u64,
    seeds: &VecDeque<Formula>,
    model: &Model,
    maximum: usize,
    bytes: usize,
) -> Vec<CompiledQuestion> {
    let mut random = Random::new(cursor.wrapping_add(1).wrapping_mul(0x9e3779b97f4a7c15));
    let mut questions: Vec<CompiledQuestion> = Vec::new();
    let mut retained = 0;
    for _ in 0..maximum.min(12) {
        let alternatives = (0..4)
            .filter_map(|_| conjecture(&mut random, seeds))
            .filter(|q| crate::learning::State::eligible(q.source()))
            .collect::<Vec<_>>();
        if alternatives.is_empty() {
            continue;
        }
        let explore = random.below(5) == 0;
        let weights = alternatives
            .iter()
            .map(|q| if explore { 1024 } else { model.weight(q) })
            .collect::<Vec<_>>();
        let question = &alternatives[crate::sampling::draw(&mut random, &weights)];
        let cost = question.source().len() * 8 + 256;
        if retained + cost <= bytes
            && questions
                .iter()
                .all(|q| q.resolution_id() != question.resolution_id())
        {
            retained += cost;
            questions.push(question.clone());
        }
    }
    questions
}
