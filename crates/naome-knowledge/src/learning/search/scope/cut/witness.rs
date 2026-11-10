//! Conditional transport of one existential witness through local rules.
use super::{ACTION_PREMISES, ACTIONS, FACTS, Formula, FreeVariable, SCOPE_ASSUMPTIONS, Scope};
use crate::learning::{construction::logic::existential, proof};
use naome_checker::question::ResearchQuestion;
use std::collections::HashMap;

struct Rule {
    index: usize,
    premises: Vec<Formula>,
    result: Formula,
}

pub(super) struct Cut {
    pub(super) opened: Formula,
    pub(super) inputs: Vec<u32>,
    pub(super) question: ResearchQuestion,
}

fn rule(index: usize, assumption: &Formula, witness: FreeVariable) -> Option<Rule> {
    let opened = assumption.open_outer_universal(witness)?;
    let mut result = opened.view();
    let mut premises = Vec::new();
    while let Some((premise, next)) = result.implication_parts() {
        let premise = premise.to_owned();
        if premises.len() == ACTION_PREMISES
            || !super::demand::atomic(&premise)
            || !premise.free_variables().contains(&witness)
        {
            return None;
        }
        premises.push(premise);
        result = next;
    }
    let result = result.to_owned();
    (result.free_variables().contains(&witness)
        && !premises.is_empty()
        && super::demand::atomic(&result))
    .then_some(Rule {
        index,
        premises,
        result,
    })
}

fn support<'a>(
    goal: &Formula,
    source: &Formula,
    source_index: usize,
    rules: impl Iterator<Item = &'a Rule> + Clone,
) -> Option<u32> {
    let mut facts = HashMap::from([(source, 1u32 << source_index)]);
    // Every fact is derived from this one witness. The other existential
    // assumptions do not supply facts about it.
    for _ in 0..ACTIONS {
        let before = facts.len();
        for rule in rules.clone() {
            if facts.len() == FACTS || facts.contains_key(&rule.result) {
                continue;
            }
            let Some(mask) = rule
                .premises
                .iter()
                .try_fold(1u32 << rule.index, |mask, premise| {
                    Some(mask | facts.get(premise)?)
                })
            else {
                continue;
            };
            if mask.count_ones() as usize <= ACTION_PREMISES {
                facts.insert(&rule.result, mask);
            }
        }
        if let Some(&mask) = facts.get(goal) {
            return Some(mask);
        }
        if facts.len() == before {
            break;
        }
    }
    None
}

pub(super) fn cuts(scope: &Scope) -> Vec<Cut> {
    if scope.assumptions.len() >= SCOPE_ASSUMPTIONS
        || !super::super::super::focus::existential(&scope.goal)
    {
        return Vec::new();
    }
    let witness = super::super::super::fresh(
        scope
            .assumptions
            .iter()
            .cloned()
            .chain([scope.goal.clone()]),
    )
    .expect("bounded witness scope");
    let Some(goal) = existential(&scope.goal, witness).filter(super::demand::atomic) else {
        return Vec::new();
    };
    let rules = scope
        .assumptions
        .iter()
        .enumerate()
        .filter_map(|(index, assumption)| rule(index, assumption, witness))
        .collect::<Vec<_>>();
    let mut masks = Vec::new();
    for (index, assumption) in scope.assumptions.iter().enumerate() {
        let Some(source) = existential(assumption, witness).filter(super::demand::atomic) else {
            continue;
        };
        masks.extend(support(&goal, &source, index, rules.iter()));
        masks.extend(support(&goal, &source, index, rules.iter().rev()));
    }
    masks.sort_unstable_by_key(|mask| (mask.count_ones(), *mask));
    masks.dedup();
    let mut cuts = Vec::<Cut>::new();
    for mask in masks.into_iter().filter(|mask| {
        let count = mask.count_ones() as usize;
        count > 1 && count < scope.assumptions.len()
    }) {
        let inputs = (0..scope.assumptions.len() as u32)
            .filter(|index| mask & (1u32 << index) != 0)
            .collect::<Vec<_>>();
        let opened = inputs
            .iter()
            .rev()
            .fold(scope.goal.clone(), |body, &premise| {
                Formula::implies(scope.assumptions[premise as usize].clone(), body)
            });
        if let Ok(question) = ResearchQuestion::from_formula(proof::close(opened.clone()))
            && cuts
                .iter()
                .all(|cut| cut.question.resolution_id() != question.resolution_id())
        {
            cuts.push(Cut {
                opened,
                inputs,
                question,
            });
        }
        if cuts.len() == 4 {
            break;
        }
    }
    cuts
}
