//! Bounded closed antecedents of exact proof paths.
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
    CutRoutes { exact, quantified }
}

impl CutRoutes {
    pub(crate) fn contains(&self, formula: &Formula) -> bool {
        self.exact
            .iter()
            .chain(&self.quantified)
            .any(|(antecedent, _)| antecedent == formula)
    }
}
