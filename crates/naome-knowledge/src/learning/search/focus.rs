//! Prefer executable, non-branching consequences in existential tableau search.
use super::super::model::{Decision, Rule};
use naome_foundation::{Formula, FormulaView, graph::Node};
use std::collections::HashSet;

pub(super) fn existential(goal: &Formula) -> bool {
    goal.view()
        .negated()
        .is_some_and(|body| matches!(body.graph_node(), Node::ForAll(_)))
}

pub(super) fn instance_tier<'a>(
    instance: FormulaView<'a>,
    fused: bool,
    present: impl Fn(FormulaView<'a>) -> bool,
    denied: impl Fn(FormulaView<'a>) -> bool,
) -> u8 {
    if let Some((left, right)) = instance.negated().and_then(FormulaView::implication_parts) {
        // This instance exposes both A and ¬B without a split. Check their
        // exact variable wiring.
        if denied(left) || present(right) {
            4
        } else if !present(left) || !denied(right) {
            2
        } else {
            0
        }
    } else if fused
        || instance
            .implication_parts()
            .is_some_and(|(left, right)| present(left) && !present(right))
    {
        2
    } else {
        0
    }
}

pub(in crate::learning) fn rank(decision: &Decision, scores: &mut [f32]) {
    if scores.len() != decision.candidates.len()
        || scores.len() < 2
        || scores.iter().any(|score| !score.is_finite())
        || !existential(&decision.goal)
    {
        return;
    }

    let facts = decision
        .context
        .iter()
        .map(|fact| fact.formula.view())
        .collect::<HashSet<_>>();
    let negatives = facts
        .iter()
        .filter_map(|fact| fact.negated())
        .collect::<HashSet<_>>();
    let opposite = |formula: FormulaView<'_>| {
        negatives.contains(&formula) || formula.negated().is_some_and(|body| facts.contains(&body))
    };
    let mut order = decision
        .candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let tier = if candidate.rule != Rule::ImplicationBranch
                && candidate.consequences.iter().any(|f| opposite(f.view()))
            {
                5
            } else {
                match candidate.rule {
                    Rule::ExistentialWitness => 4,
                    Rule::DoubleNegation | Rule::NegatedImplication | Rule::ModusPonens => 3,
                    Rule::UniversalInstance => candidate
                        .consequences
                        .iter()
                        .map(|formula| {
                            instance_tier(
                                formula.view(),
                                candidate.premises.len() == 2,
                                |f| facts.contains(&f),
                                |f| negatives.contains(&f),
                            )
                        })
                        .max()
                        .unwrap_or(0),
                    _ => 0,
                }
            };
            (index, tier)
        })
        .collect::<Vec<_>>();
    if order.iter().all(|(_, tier)| *tier == order[0].1) {
        return;
    }
    // Record the effective ordering for deterministic trace replay. The neural
    // scores still decide between candidates with the same structural tier.
    order.sort_by(|&(a, a_tier), &(b, b_tier)| {
        b_tier
            .cmp(&a_tier)
            .then_with(|| scores[b].total_cmp(&scores[a]))
            .then(a.cmp(&b))
    });
    let count = order.len();
    for (rank, (index, _)) in order.into_iter().enumerate() {
        scores[index] = (count - rank) as f32;
    }
}

#[cfg(test)]
mod tests;
