//! Bounded forward actions over the checked program's local deduction vocabulary.
use super::*;
use naome_foundation::graph::Node as FormulaNode;
use naome_proof::{
    ProofFormula,
    program::{Command, Projection, SCOPE_ASSUMPTIONS, ScopedAction},
};

pub(crate) mod cut;
mod demand;

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
    fn open(target: &Formula) -> Result<Option<Self>, crate::Error> {
        Self::open_with(target, None)
    }

    fn open_with(target: &Formula, lemma: Option<&Formula>) -> Result<Option<Self>, crate::Error> {
        let mut goal = target.clone();
        let mut binders = Vec::new();
        loop {
            let mut used = goal.free_variables();
            used.extend(binders.iter().copied());
            let variable = (0..=u32::MAX)
                .map(FreeVariable::new)
                .find(|variable| !used.contains(variable))
                .ok_or(crate::ResearchFailure::ScopeBinderCapacity)?;
            let Some(body) = goal.open_outer_universal(variable) else {
                break;
            };
            binders.push(variable);
            goal = body;
        }
        let mut assumptions = lemma.into_iter().cloned().collect::<Vec<_>>();
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

    fn program(
        &self,
        actions: &[ScopedAction],
        references: &[naome_proof::ProofId],
    ) -> Option<Vec<Command>> {
        let used = used_facts(self.assumptions.len(), actions)?;
        let mut positions: Vec<_> = (0..self.assumptions.len() as u32).collect();
        let mut retained = Vec::new();
        for (index, action) in actions.iter().enumerate() {
            if !used[self.assumptions.len() + index] {
                positions.push(0);
                continue;
            }
            let operand = |index: u32| positions[index as usize];
            retained.push(match action {
                ScopedAction::Instantiate {
                    universal,
                    replacement,
                    premises,
                } => ScopedAction::Instantiate {
                    universal: operand(*universal),
                    replacement: *replacement,
                    premises: premises.iter().copied().map(operand).collect(),
                },
                ScopedAction::Conjoin { left, right } => ScopedAction::Conjoin {
                    left: operand(*left),
                    right: operand(*right),
                },
            });
            positions.push((self.assumptions.len() + retained.len() - 1) as u32);
        }
        let assumptions = self
            .assumptions
            .iter()
            .cloned()
            .map(ProofFormula::from)
            .collect::<Vec<_>>();
        Some(Projection::scoped_with_references(
            &assumptions,
            &retained,
            (self.assumptions.len() + retained.len() - 1) as u32,
            &self.binders,
            references,
        ))
    }

    fn apply(&self, facts: &[Formula], action: &ScopedAction) -> Option<Formula> {
        match action {
            ScopedAction::Instantiate {
                universal,
                replacement,
                premises,
            } => {
                let mut formula = instantiation::Universal::new(facts.get(*universal as usize)?)?
                    .instance(FreeVariable::new(*replacement));
                for premise in premises {
                    let (antecedent, result) = formula.view().implication_parts()?;
                    if antecedent != facts.get(*premise as usize)?.view() {
                        return None;
                    }
                    formula = result.to_owned();
                }
                Some(formula)
            }
            ScopedAction::Conjoin { left, right } => Some(Formula::conjunction(
                facts.get(*left as usize)?.clone(),
                facts.get(*right as usize)?.clone(),
            )),
        }
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
        let first = *variables.first().expect("scope variable");
        let mut known = HashMap::with_capacity(facts.len());
        for (index, fact) in facts.iter().enumerate() {
            known.entry(fact.view()).or_insert(index as u32);
        }
        for (index, formula) in facts.iter().enumerate() {
            let Some(universal) = instantiation::Universal::new(formula) else {
                continue;
            };
            let mut add = |replacement: FreeVariable, formula: Formula, premises| {
                if !known.contains_key(&formula.view()) {
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
            for (premise, replacement) in universal.applications(facts, first) {
                if let Some(mut conclusion) = universal.consequence(replacement) {
                    let mut premises = vec![premise as u32];
                    add(replacement, conclusion.clone(), premises.clone());
                    while premises.len() < naome_proof::program::ACTION_PREMISES {
                        let Some((antecedent, consequent)) = conclusion.view().implication_parts()
                        else {
                            break;
                        };
                        let Some(&position) = known.get(&antecedent) else {
                            break;
                        };
                        premises.push(position);
                        conclusion = consequent.to_owned();
                        add(replacement, conclusion.clone(), premises.clone());
                    }
                }
            }
            let wanted = universal.wanted(&self.goal, first);
            let instances = wanted.into_iter().chain(
                variables
                    .iter()
                    .copied()
                    .filter(|v| Some(*v) != wanted)
                    .take(8),
            );
            for replacement in instances {
                add(replacement, universal.instance(replacement), Vec::new());
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
        // Preserve closing and immediately applicable inferences when bare
        // instances compete for the bounded decision menu.
        offered.sort_by_key(|(action, result)| {
            let bare =
                matches!(action, ScopedAction::Instantiate { premises, .. } if premises.is_empty());
            (*result != self.goal, bare)
        });
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
                    replacement: match action {
                        ScopedAction::Instantiate { replacement, .. } => {
                            Some(FreeVariable::new(*replacement))
                        }
                        ScopedAction::Conjoin { .. } => None,
                    },
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

/// Establish applicability from the exact local premises, without a model or
/// a proof of the target. The checker still validates any generated program.
pub(in crate::learning) fn lemma_closes(
    target: &Formula,
    lemma: &Formula,
) -> Result<bool, crate::Error> {
    if target == lemma {
        return Ok(true);
    }
    let Some(scope) = Scope::open_with(target, Some(lemma))? else {
        return Ok(false);
    };
    let (offered, _) = scope.offers(&scope.assumptions);
    Ok(offered.into_iter().any(|(action, result)| {
        result == scope.goal
            && match action {
                ScopedAction::Instantiate {
                    universal,
                    premises,
                    ..
                } => universal == 0 || premises.contains(&0),
                ScopedAction::Conjoin { left, right } => left == 0 || right == 0,
            }
    }))
}

pub(in crate::learning) fn search(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
    started: Instant,
) -> Result<(Option<Tree>, usize), crate::Error> {
    let Some(scope) = Scope::open(target)? else {
        return Ok((None, 0));
    };
    let (actions, work) = search_scope(&scope, ranker, maximum, started)?;
    let tree = actions
        .map(|actions| {
            Ok::<_, crate::Error>(Tree::Scoped {
                target: target.encode_canonical()?,
                actions,
            })
        })
        .transpose()?;
    Ok((tree, work))
}

pub(in crate::learning) fn search_with_lemma(
    target: &Formula,
    proof: naome_proof::ProofId,
    lemma: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
    started: Instant,
) -> Result<(Option<Vec<Command>>, usize), crate::Error> {
    if !lemma.is_closed() {
        return Err(crate::ResearchFailure::ScopeLemmaNotClosed.into());
    }
    let Some(scope) = Scope::open_with(target, Some(lemma))? else {
        return Ok((None, 0));
    };
    let (actions, work) = search_scope(&scope, ranker, maximum, started)?;
    let commands = actions.and_then(|actions| {
        if !used_facts(scope.assumptions.len(), &actions)?[0] {
            return None;
        }
        scope.program(&actions, &[proof])
    });
    Ok((commands, work))
}

fn used_facts(assumptions: usize, actions: &[ScopedAction]) -> Option<Vec<bool>> {
    if actions.is_empty() {
        return None;
    }
    let result = assumptions + actions.len() - 1;
    let mut used = vec![false; result + 1];
    used[result] = true;
    for (index, action) in actions.iter().enumerate().rev() {
        let position = assumptions + index;
        let mut operand = |operand: u32| {
            let operand = operand as usize;
            if operand >= position {
                return None;
            }
            if used[position] {
                used[operand] = true;
            }
            Some(())
        };
        match action {
            ScopedAction::Instantiate {
                universal,
                premises,
                ..
            } => {
                operand(*universal)?;
                for &premise in premises {
                    operand(premise)?;
                }
            }
            ScopedAction::Conjoin { left, right } => {
                operand(*left)?;
                operand(*right)?;
            }
        }
    }
    Some(used)
}

fn search_scope(
    scope: &Scope,
    ranker: &mut dyn Ranker,
    maximum: usize,
    started: Instant,
) -> Result<(Option<Vec<ScopedAction>>, usize), crate::Error> {
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
        let selected = if offered.len() == 1 || offered[0].1 == scope.goal {
            0
        } else {
            let scores = match ranker.scores(&scope.decision(&facts, &offered, 0, compact)) {
                Ok(scores) => scores,
                Err(crate::Error::LearningGraph(crate::LearningGraphFailure::Capacity)) => break,
                Err(error) => return Err(error),
            };
            if scores.len() != offered.len() || scores.iter().any(|score| !score.is_finite()) {
                return Err(crate::ResearchFailure::ScopeInvalidScores.into());
            }
            (0..offered.len())
                .max_by(|a, b| scores[*a].total_cmp(&scores[*b]).then(b.cmp(a)))
                .unwrap()
        };
        let (action, result) = offered.into_iter().nth(selected).unwrap();
        actions.push(action);
        if result == scope.goal {
            let work = actions.len();
            return Ok((Some(actions), work));
        }
        facts.push(result);
    }
    Ok((None, actions.len()))
}

pub(super) fn compile(
    target: &Formula,
    actions: &[ScopedAction],
) -> Result<(Term, Vec<Graph>), crate::Error> {
    let (scope, graphs) = decision_graphs(
        Scope::open(target)?.ok_or(crate::ResearchFailure::ScopeTraceTarget)?,
        target,
        actions,
        false,
    )?
    .ok_or(crate::ResearchFailure::ScopeReplayOperand)?;
    let result = scope.assumptions.len() + actions.len() - 1;
    let mut term = deduce(&scope.assumptions, actions, result as u32)?;
    for variable in scope.binders.into_iter().rev() {
        term = Term::Generalize(variable, Box::new(term));
    }
    Ok((term, graphs))
}

fn decision_graphs(
    scope: Scope,
    target: &Formula,
    actions: &[ScopedAction],
    checked_reference: bool,
) -> Result<Option<(Scope, Vec<Graph>)>, crate::Error> {
    if actions.is_empty() || actions.len() > ACTIONS.min(FACTS - scope.assumptions.len()) {
        return Ok(None);
    }
    let mut facts = scope.assumptions.clone();
    let mut graphs = Vec::new();
    let target_bytes = target.encode_canonical().map_err(crate::Error::from)?;
    for (offset, action) in actions.iter().enumerate() {
        let (mut offered, compact) = scope.offers(&facts);
        let selected = if let Some(index) = offered.iter().position(|(choice, _)| choice == action)
        {
            index
        } else if checked_reference {
            // A replayed citation supplies the checked action when its
            // operands are outside the bounded search menu.
            let result = scope
                .apply(&facts, action)
                .ok_or(crate::ResearchFailure::ScopeReplayOperand)?;
            offered.truncate(15);
            offered.push((action.clone(), result));
            offered.len() - 1
        } else {
            return Ok(None);
        };
        if offered.len() > 1 {
            match Graph::encode(&scope.decision(&facts, &offered, selected, compact)) {
                Ok(mut graph) => {
                    graph.binding = super::super::digest(&(&target_bytes, &actions[..offset]));
                    graphs.push(graph);
                }
                Err(crate::LearningGraphFailure::Capacity) if !checked_reference => {
                    return Ok(None);
                }
                Err(
                    crate::LearningGraphFailure::Capacity
                    | crate::LearningGraphFailure::ActionArity,
                ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        facts.push(offered[selected].1.clone());
    }
    if facts.last() != Some(&scope.goal) {
        return Err(crate::ResearchFailure::ScopeConclusion.into());
    }
    Ok(Some((scope, graphs)))
}

pub(crate) fn program_graphs(
    target: &Formula,
    records: &[Command],
    context: &dyn naome_checker::ContextView,
) -> Result<Vec<Graph>, crate::Error> {
    let Some(actions) = records.iter().find_map(|record| match record {
        Command::Deduce { actions, .. } => Some(actions),
        _ => None,
    }) else {
        return Ok(Vec::new());
    };
    if actions.is_empty() || actions.len() > ACTIONS {
        return Ok(Vec::new());
    }
    if let Some(scope) = Scope::open(target)?
        && scope.program(actions, &[]).as_deref() == Some(records)
    {
        return Ok(decision_graphs(scope, target, actions, false)?
            .map_or_else(Vec::new, |(_, graphs)| graphs));
    }
    let mut references = records.iter().filter_map(|record| match record {
        Command::ProofReference { proof_id } => Some(naome_proof::ProofId::from_bytes(*proof_id)),
        _ => None,
    });
    let (Some(reference), None) = (references.next(), references.next()) else {
        return Ok(Vec::new());
    };
    let Some(header) = context
        .proof_header(reference)
        .map_err(crate::Error::from)?
    else {
        return Err(crate::ResearchFailure::ScopeCitationMissing.into());
    };
    if header.canonical_length() > naome_checker::question::QUESTION_BYTES {
        return Ok(Vec::new());
    }
    let Some(formula) = context
        .proof_formula(header, header.canonical_length())
        .map_err(crate::Error::from)?
    else {
        return Err(crate::ResearchFailure::ScopeCitationFormulaMissing.into());
    };
    if let Some(scope) = Scope::open_with(target, Some(formula.as_ref()))?
        && scope.program(actions, &[reference]).as_deref() == Some(records)
    {
        return Ok(decision_graphs(scope, target, actions, true)?
            .map_or_else(Vec::new, |(_, graphs)| graphs));
    }
    Ok(Vec::new())
}

pub(crate) fn verified(
    target: &[u8],
    actions: &[ScopedAction],
) -> Result<super::super::proof::Verified, crate::Error> {
    let target = Formula::decode_canonical(target).map_err(crate::Error::from)?;
    let (term, _) = compile(&target, actions)?;
    super::super::proof::verify(&term, &target)
}

pub(crate) fn commands(
    target: &Formula,
    actions: &[ScopedAction],
) -> Result<Vec<Command>, crate::Error> {
    let scope = Scope::open(target)?.ok_or(crate::ResearchFailure::ScopeProgramTarget)?;
    scope
        .program(actions, &[])
        .ok_or_else(|| crate::ResearchFailure::ScopeProgramOperands.into())
}

/// Rebuild the selected local actions as ordinary inference for training.
pub(crate) fn deduce(
    assumptions: &[Formula],
    actions: &[ScopedAction],
    result: u32,
) -> Result<Term, crate::Error> {
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
                .ok_or(crate::ResearchFailure::ScopeOperandOrder)
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
        .ok_or(crate::ResearchFailure::ScopeResultOrder)?;
    for (id, assumption) in locals.into_iter().rev() {
        term = Term::Lambda(id, assumption.formula(), Box::new(term));
    }
    Ok(term)
}

#[cfg(test)]
mod tests;
