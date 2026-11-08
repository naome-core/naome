//! Bounded forward actions over the checked program's local deduction vocabulary.
use super::*;
use naome_foundation::graph::Node as FormulaNode;
use naome_proof::{
    ProofFormula,
    program::{Command, Projection, SCOPE_ASSUMPTIONS, ScopedAction},
};

pub(crate) mod cut;
mod demand;
#[cfg(test)]
mod tests;

const ACTIONS: usize = 8;
const FACTS: usize = 32;
const OFFERS: usize = 16;
const GENERAL_ASSUMPTIONS: usize = 8;

struct Scope {
    binders: Vec<FreeVariable>,
    assumptions: Vec<Formula>,
    goal: Formula,
}

impl Scope {
    fn open(target: &Formula) -> Result<Option<Self>, String> {
        let mut goal = target.clone();
        let mut binders = Vec::new();
        loop {
            let mut used = goal.free_variables();
            used.extend(binders.iter().copied());
            let variable = (0..=u32::MAX)
                .map(FreeVariable::new)
                .find(|variable| !used.contains(variable))
                .ok_or("scope binder capacity")?;
            let Some(body) = goal.open_outer_universal(variable) else {
                break;
            };
            binders.push(variable);
            goal = body;
        }
        let mut assumptions = Vec::new();
        while let Some((premise, result)) = goal.view().implication_parts() {
            let (premise, result) = (premise.to_owned(), result.to_owned());
            assumptions.push(premise);
            goal = result;
        }
        if assumptions.is_empty()
            || assumptions.len() > SCOPE_ASSUMPTIONS.min(FACTS)
            || !assumptions
                .iter()
                .any(|f| matches!(f.view().graph_node(), FormulaNode::ForAll(_)))
        {
            return Ok(None);
        }
        Ok(Some(Self {
            binders,
            assumptions,
            goal,
        }))
    }

    fn offers(&self, facts: &[Formula]) -> (Vec<(ScopedAction, Formula)>, bool) {
        let demanded = demand::offers(&self.goal, facts);
        if self.assumptions.len() > GENERAL_ASSUMPTIONS {
            return (demanded, true);
        }
        if demanded.is_empty() {
            return (self.general_offers(facts), false);
        }
        // Keep the existing scored menu for a closing step already offered
        // at the start of an ordinary narrow scope.
        if facts.len() == self.assumptions.len() && demanded[0].1 == self.goal {
            let general = self.general_offers(facts);
            if general.iter().any(|(action, result)| {
                result == &self.goal && demanded.iter().any(|(candidate, _)| candidate == action)
            }) {
                return (general, false);
            }
        }
        (demanded, true)
    }

    fn general_offers(&self, facts: &[Formula]) -> Vec<(ScopedAction, Formula)> {
        let mut offered = Vec::new();
        let mut variables = self.goal.free_variables();
        for fact in facts {
            variables.extend(fact.free_variables());
        }
        if variables.is_empty() {
            variables.insert(FreeVariable::new(0));
        }
        for (index, universal) in facts.iter().enumerate() {
            for &replacement in variables.iter().take(8) {
                let Some(instance) = universal.open_outer_universal(replacement) else {
                    break;
                };
                let mut add = |formula, premises| {
                    if !facts.contains(&formula) {
                        offered.push((
                            ScopedAction::Instantiate {
                                universal: index as u32,
                                replacement: replacement.identifier(),
                                premises,
                            },
                            formula,
                        ));
                    }
                };
                if let Some((antecedent, consequent)) = instance.view().implication_parts()
                    && let Some(premise) = facts.iter().position(|f| f.view() == antecedent)
                {
                    add(consequent.to_owned(), vec![premise as u32]);
                }
                add(instance, Vec::new());
            }
        }
        if let Some((a, b)) = super::super::construction::logic::conjunction(&self.goal)
            && let Some(left) = facts.iter().position(|f| f == &a)
            && let Some(right) = facts.iter().position(|f| f == &b)
        {
            offered.push((
                ScopedAction::Conjoin {
                    left: left as u32,
                    right: right as u32,
                },
                self.goal.clone(),
            ));
        }
        // Ensure a closing inference stays available even when there are
        // more legal instances than the model's existing decision envelope.
        offered.sort_by_key(|(_, result)| *result != self.goal);
        offered.truncate(OFFERS);
        offered
    }

    fn decision(
        &self,
        facts: &[Formula],
        offers: &[(ScopedAction, Formula)],
        expert: usize,
        compact: bool,
    ) -> Decision {
        let mut candidates: Vec<_> = offers
            .iter()
            .map(|(action, result)| {
                let (rule, premises) = match action {
                    ScopedAction::Instantiate {
                        universal,
                        premises,
                        ..
                    } => (
                        Rule::UniversalInstance,
                        std::iter::once(*universal)
                            .chain(premises.iter().copied())
                            .map(|i| i as usize)
                            .collect(),
                    ),
                    ScopedAction::Conjoin { left, right } => (
                        Rule::ConstructionPlan,
                        vec![*left as usize, *right as usize],
                    ),
                };
                Candidate {
                    rule,
                    premises,
                    consequences: vec![result.clone()],
                }
            })
            .collect();
        let positions = if compact {
            candidates
                .iter()
                .flat_map(|candidate| candidate.premises.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            (0..facts.len()).collect()
        };
        if compact {
            for candidate in &mut candidates {
                for premise in &mut candidate.premises {
                    *premise = positions.binary_search(premise).expect("offered operand");
                }
            }
        }
        Decision {
            goal: self.goal.clone(),
            context: positions
                .into_iter()
                .map(|position| Binding {
                    formula: facts[position].clone(),
                })
                .collect(),
            candidates,
            expert,
        }
    }
}

pub(in crate::learning) fn search(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
    started: Instant,
) -> Result<(Option<Tree>, usize), String> {
    let Some(scope) = Scope::open(target)? else {
        return Ok((None, 0));
    };
    let mut facts = scope.assumptions.clone();
    let mut actions = Vec::new();
    let allowance = maximum.min(ACTIONS).min(FACTS - facts.len());
    for _ in 0..allowance {
        if started.elapsed() >= Duration::from_millis(2500) {
            break;
        }
        let (offered, compact) = scope.offers(&facts);
        if offered.is_empty() {
            break;
        }
        let selected = if offered.len() == 1 {
            0
        } else {
            let scores = match ranker.scores(&scope.decision(&facts, &offered, 0, compact)) {
                Ok(scores) => scores,
                Err(error) if error == "formula_graph_capacity" => break,
                Err(error) => return Err(error),
            };
            if scores.len() != offered.len() || scores.iter().any(|score| !score.is_finite()) {
                return Err("scope ranker scores differ from the offered actions".into());
            }
            (0..offered.len())
                .max_by(|a, b| scores[*a].total_cmp(&scores[*b]).then(b.cmp(a)))
                .unwrap()
        };
        let (action, result) = offered.into_iter().nth(selected).unwrap();
        actions.push(action);
        if result == scope.goal {
            let work = actions.len();
            let target = target.encode_canonical().map_err(|e| e.to_string())?;
            return Ok((Some(Tree::Scoped { target, actions }), work));
        }
        facts.push(result);
    }
    Ok((None, actions.len()))
}

pub(super) fn compile(
    target: &Formula,
    actions: &[ScopedAction],
) -> Result<(Term, Vec<Graph>), String> {
    let (scope, graphs) =
        decision_graphs(target, actions)?.ok_or("scope trace action was not offered")?;
    let result = scope.assumptions.len() + actions.len() - 1;
    let mut term = deduce(&scope.assumptions, actions, result as u32)?;
    for variable in scope.binders.into_iter().rev() {
        term = Term::Generalize(variable, Box::new(term));
    }
    Ok((term, graphs))
}

fn decision_graphs(
    target: &Formula,
    actions: &[ScopedAction],
) -> Result<Option<(Scope, Vec<Graph>)>, String> {
    let scope = Scope::open(target)?.ok_or("scope trace target differs")?;
    if actions.is_empty() || actions.len() > ACTIONS.min(FACTS - scope.assumptions.len()) {
        return Ok(None);
    }
    let mut facts = scope.assumptions.clone();
    let mut graphs = Vec::new();
    let target_bytes = target
        .encode_canonical()
        .map_err(|error| error.to_string())?;
    for (offset, action) in actions.iter().enumerate() {
        let (offered, compact) = scope.offers(&facts);
        let Some(selected) = offered.iter().position(|(choice, _)| choice == action) else {
            return Ok(None);
        };
        if offered.len() > 1 {
            let mut graph =
                match Graph::encode(&scope.decision(&facts, &offered, selected, compact)) {
                    Ok(graph) => graph,
                    Err(error) if error == "formula_graph_capacity" => return Ok(None),
                    Err(error) => return Err(error),
                };
            graph.binding = super::super::digest(&(&target_bytes, &actions[..offset]));
            graphs.push(graph);
        }
        facts.push(offered[selected].1.clone());
    }
    if facts.last() != Some(&scope.goal) {
        return Err("scope trace conclusion differs".into());
    }
    Ok(Some((scope, graphs)))
}

pub(crate) fn program_graphs(target: &Formula, records: &[Command]) -> Result<Vec<Graph>, String> {
    let Some(actions) = records.iter().find_map(|record| match record {
        Command::Deduce { actions, .. } => Some(actions),
        _ => None,
    }) else {
        return Ok(Vec::new());
    };
    if actions.is_empty()
        || actions.len() > ACTIONS
        || Scope::open(target)?.is_none()
        || commands(target, actions)? != records
    {
        return Ok(Vec::new());
    }
    // An independently valid program may use a wider or different action
    // menu. Only reproduce examples that the current search can offer.
    Ok(decision_graphs(target, actions)?.map_or_else(Vec::new, |(_, graphs)| graphs))
}

pub(crate) fn verified(
    target: &[u8],
    actions: &[ScopedAction],
) -> Result<super::super::proof::Verified, String> {
    let target = Formula::decode_canonical(target).map_err(|error| error.to_string())?;
    let (term, _) = compile(&target, actions)?;
    super::super::proof::verify(&term, &target)
}

pub(crate) fn commands(target: &Formula, actions: &[ScopedAction]) -> Result<Vec<Command>, String> {
    let scope = Scope::open(target)?.ok_or("scope program target differs")?;
    let result = scope.assumptions.len() + actions.len() - 1;
    let assumptions = scope
        .assumptions
        .into_iter()
        .map(ProofFormula::from)
        .collect::<Vec<_>>();
    Ok(Projection::scoped(
        &assumptions,
        actions,
        result as u32,
        &scope.binders,
    ))
}

/// Rebuild the selected local actions as ordinary inference for training.
pub(crate) fn deduce(
    assumptions: &[Formula],
    actions: &[ScopedAction],
    result: u32,
) -> Result<Term, String> {
    let mut names = Names::default();
    let locals = assumptions
        .iter()
        .cloned()
        .map(|formula| names.assumption(formula))
        .collect::<Vec<_>>();
    let mut facts = locals
        .iter()
        .map(|(_, term)| term.clone())
        .collect::<Vec<_>>();
    for action in actions {
        let fact = |handle: u32| {
            facts
                .get(handle as usize)
                .cloned()
                .ok_or("scope operand is not an earlier fact".to_owned())
        };
        let term = match action {
            ScopedAction::Instantiate {
                universal,
                replacement,
                premises,
            } => {
                let mut result =
                    c::instantiate(fact(*universal)?, FreeVariable::new(*replacement))?;
                for premise in premises {
                    result = c::app(result, fact(*premise)?)?;
                }
                result
            }
            ScopedAction::Conjoin { left, right } => {
                super::super::construction::logic::join(fact(*left)?, fact(*right)?, &mut names)?
            }
        };
        facts.push(term);
    }
    let mut term = facts
        .get(result as usize)
        .cloned()
        .ok_or("scope result is not an earlier fact")?;
    for (id, assumption) in locals.into_iter().rev() {
        term = Term::Lambda(id, assumption.formula(), Box::new(term));
    }
    Ok(term)
}
