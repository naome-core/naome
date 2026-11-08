//! Backward demand over atomic implications in an opened local scope.
use super::{Formula, FormulaNode, FreeVariable, ScopedAction};
use naome_foundation::{FormulaView, graph::Variable};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Atom {
    member: bool,
    operands: [u32; 2],
}

impl Atom {
    fn read(formula: FormulaView<'_>) -> Option<Self> {
        match formula.graph_node() {
            FormulaNode::Member(Variable::Free(a), Variable::Free(b)) => Some(Self {
                member: true,
                operands: [a, b],
            }),
            FormulaNode::Equal(Variable::Free(a), Variable::Free(b)) => Some(Self {
                member: false,
                operands: [a, b],
            }),
            _ => None,
        }
    }

    fn replacement(self, wanted: Self, binder: u32) -> Option<u32> {
        if self.member != wanted.member {
            return None;
        }
        let position = self.operands.iter().position(|value| *value == binder)?;
        let replacement = wanted.operands[position];
        (self.instantiated(binder, replacement) == wanted).then_some(replacement)
    }

    fn instantiated(self, binder: u32, replacement: u32) -> Self {
        Self {
            operands: self
                .operands
                .map(|value| if value == binder { replacement } else { value }),
            ..self
        }
    }

    fn formula(self) -> Formula {
        let [a, b] = self.operands.map(FreeVariable::new);
        if self.member {
            Formula::member(a, b)
        } else {
            Formula::equal(a, b)
        }
    }
}

pub(super) fn offers(goal: &Formula, facts: &[Formula]) -> Vec<(ScopedAction, Formula)> {
    let Some(goal) = Atom::read(goal.view()) else {
        return Vec::new();
    };
    let used = facts
        .iter()
        .flat_map(|fact| fact.free_variables())
        .chain(goal.operands.map(FreeVariable::new))
        .collect::<std::collections::BTreeSet<_>>();
    let binder = (0..=u32::MAX)
        .map(FreeVariable::new)
        .find(|variable| !used.contains(variable))
        .expect("bounded scope variables");
    let mut known = BTreeMap::new();
    let mut rules = Vec::new();
    for (index, fact) in facts.iter().enumerate() {
        if let Some(atom) = Atom::read(fact.view()) {
            known.entry(atom).or_insert(index as u32);
        }
        if let Some(opened) = fact.open_outer_universal(binder)
            && let Some((premise, result)) = opened.view().implication_parts()
            && let (Some(premise), Some(result)) = (Atom::read(premise), Atom::read(result))
            && premise.operands.contains(&binder.identifier())
        {
            rules.push((index as u32, premise, result));
        }
    }
    if known.is_empty() || rules.is_empty() {
        return Vec::new();
    }
    let binder = binder.identifier();
    let mut needed = vec![(goal, 0)];
    let mut offered = Vec::new();
    let mut reached_depth = None;
    // Keep the same active fact and candidate bounds as the forward search.
    for cursor in 0..super::FACTS {
        let Some(&(wanted, depth)) = needed.get(cursor) else {
            break;
        };
        if reached_depth.is_some_and(|reached| depth > reached) {
            break;
        }
        if known.contains_key(&wanted) {
            continue;
        }
        for &(universal, premise, result) in &rules {
            let Some(replacement) = result.replacement(wanted, binder) else {
                continue;
            };
            let premise = premise.instantiated(binder, replacement);
            if let Some(&premise) = known.get(&premise) {
                reached_depth = Some(depth);
                offered.push((
                    ScopedAction::Instantiate {
                        universal,
                        replacement,
                        premises: vec![premise],
                    },
                    wanted.formula(),
                ));
                if offered.len() == super::OFFERS {
                    return offered;
                }
            } else if reached_depth.is_none()
                && needed.len() < super::FACTS
                && !needed.iter().any(|(atom, _)| *atom == premise)
            {
                needed.push((premise, depth + 1));
            }
        }
    }
    offered
}
