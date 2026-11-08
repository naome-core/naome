//! Bounded closed antecedents of exact proof paths.
use naome_checker::question::ResearchQuestion;
use naome_foundation::{Formula, FreeVariable};

fn fresh_opening(formula: &Formula) -> Option<FreeVariable> {
    formula
        .free_variables()
        .last()
        .map_or(Some(0), |v| v.identifier().checked_add(1))
        .map(FreeVariable::new)
}

pub(crate) struct CutRoutes {
    pub exact: Vec<(Formula, usize)>,
    pub quantified: Vec<(Formula, usize)>,
    pairs: Vec<[Formula; 2]>,
}

/// Closed witnesses on short backward paths through assumptions.
pub(crate) fn closed_cut_routes(goal: &Formula, allow_instances: bool) -> CutRoutes {
    fn sources(
        body: &Formula,
        rules: &[(Formula, Formula)],
        quantified: &[(usize, Formula, FreeVariable)],
    ) -> Vec<(Formula, usize)> {
        let mut reachable = vec![(body, 0usize)];
        let mut cursor = 0;
        while let Some((wanted, distance)) = reachable.get(cursor).copied() {
            for (antecedent, consequent) in rules {
                if consequent == wanted && !reachable.iter().any(|(seen, _)| *seen == antecedent) {
                    reachable.push((antecedent, distance + 1));
                }
            }
            // The Solver can close this final instance directly. Selecting
            // an intermediate instance would also require prioritizing its
            // downstream implications inside the bounded construction search.
            if distance == 0 && !quantified.is_empty() {
                let variables = wanted.free_variables();
                for (index, opened, binder) in quantified {
                    let universal = &rules[*index].1;
                    if !reachable.iter().any(|(seen, _)| *seen == universal)
                        && (opened == wanted
                            || variables.iter().take(16).any(|variable| {
                                opened.clone().substitute_free(*binder, *variable) == *wanted
                            }))
                    {
                        reachable.push((universal, distance + 1));
                    }
                }
            }
            cursor += 1;
        }
        reachable
            .into_iter()
            .skip(1)
            .filter(|(formula, _)| formula.is_closed())
            .map(|(formula, distance)| (formula.clone(), distance))
            .collect()
    }

    let mut body = goal.clone();
    while let Some(opened) =
        fresh_opening(&body).and_then(|binder| body.open_outer_universal(binder))
    {
        body = opened;
    }
    let mut rules = Vec::new();
    for _ in 0..16 {
        let Some((premise, conclusion)) = body.implication_parts() else {
            break;
        };
        if let Some((antecedent, consequent)) = premise.implication_parts() {
            rules.push((antecedent, consequent));
        }
        body = conclusion;
    }
    let quantified = rules
        .iter()
        .take(if allow_instances { rules.len() } else { 0 })
        .enumerate()
        .filter_map(|(index, (_, consequent))| {
            let binder = fresh_opening(consequent)?;
            consequent
                .open_outer_universal(binder)
                .map(|opened| (index, opened, binder))
        })
        .collect::<Vec<_>>();
    let exact = sources(&body, &rules, &[]);
    let quantified = if quantified.is_empty() {
        Vec::new()
    } else {
        sources(&body, &rules, &quantified)
    };
    let pairs = if allow_instances {
        closed_pairs(&body, &rules)
    } else {
        Vec::new()
    };
    CutRoutes {
        exact,
        quantified,
        pairs,
    }
}

/// Direct Horn assumptions can consume two independently provable closed
/// premises. Prefer the pair that activates fewer rules in the first two
/// rounds of forward search, which spend from the same root allowance.
fn closed_pairs(goal: &Formula, rules: &[(Formula, Formula)]) -> Vec<[Formula; 2]> {
    let mut pairs = Vec::<(usize, [Formula; 2])>::new();
    for (first, suffix) in rules {
        let Some((second, conclusion)) = suffix.implication_parts() else {
            continue;
        };
        if &conclusion != goal || !first.is_closed() || !second.is_closed() || first == &second {
            continue;
        }
        if pairs
            .iter()
            .any(|(_, [a, b])| (a == first && b == &second) || (b == first && a == &second))
        {
            continue;
        }
        let pair = [first.clone(), second];
        let mut facts = pair.iter().collect::<Vec<_>>();
        let mut activated = 0u16;
        for _ in 0..2 {
            let mut round = Vec::new();
            for (index, (premise, consequence)) in rules.iter().enumerate() {
                let bit = 1 << index;
                if activated & bit == 0 && facts.contains(&premise) {
                    activated |= bit;
                    round.push(consequence);
                }
            }
            facts.extend(round);
        }
        pairs.push((activated.count_ones() as usize, pair));
    }
    pairs.sort_by_key(|(cost, _)| *cost);
    pairs.into_iter().map(|(_, pair)| pair).collect()
}

impl CutRoutes {
    pub(crate) fn pair_questions(&self) -> impl Iterator<Item = Vec<ResearchQuestion>> + '_ {
        self.pairs.iter().filter_map(|pair| {
            pair.iter()
                .map(|formula| ResearchQuestion::from_formula(formula.clone()).ok())
                .collect::<Option<Vec<_>>>()
        })
    }

    pub(crate) fn contains(&self, formula: &Formula) -> bool {
        self.exact
            .iter()
            .chain(&self.quantified)
            .any(|(antecedent, _)| antecedent == formula)
    }
}
