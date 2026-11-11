//! Bounded classical tableau with checked, replayable proof reconstruction.
pub mod core;
pub(crate) mod derivation;
pub(super) mod focus;
pub(crate) mod frontier;
mod instantiation;
pub(super) mod scope;
pub(crate) mod trace;
use super::calculus::{self as c, Names};
use super::{
    experience::{Budget, Capacity, TerminalEvidence},
    graph::Graph,
    model::{Binding, Candidate, Decision, Plan, Ranker, Rule},
    proof::Term,
};
use crate::outcome::GenerationOutcome;
use naome_foundation::{Formula, FreeVariable};
use naome_proof::ProofStep;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    time::{Duration, Instant},
};

pub(super) const TIME_LIMIT: Duration = Duration::from_millis(2500);
const FACT_LIMIT: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Action {
    Double(usize),
    NotImp(usize),
    Mp(usize, usize),
    Beta(usize),
    Instantiate(usize, u32),
    InstantiateApply(usize, u32, usize),
    Witness(usize, u32),
    Substitute(usize, usize),
    Cite(usize),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Tree {
    Scoped {
        target: Vec<u8>,
        actions: Vec<naome_proof::program::ScopedAction>,
    },
    Knowledge {
        entries: Vec<super::knowledge::Entry>,
        target: Vec<u8>,
        proof: Box<Self>,
    },
    Constructed {
        packet: Vec<u8>,
        selection: Option<super::construction::selection::Selection>,
    },
    Composed {
        packet: Vec<u8>,
        inputs: Vec<String>,
        work: usize,
    },
    Definitions {
        entries: Vec<super::definitions::Entry>,
        selected: usize,
        available: usize,
        proof: Box<Self>,
    },
    Axiom(u8),
    Certificate(Vec<u8>),
    Program(Box<super::peer::Packet>),
    Stored {
        coverage: super::coverage::Profile,
        steps: usize,
        bytes: usize,
        binding: String,
    },
    Close(usize, usize),
    Step {
        action: Action,
        children: Vec<Self>,
    },
}
impl Tree {
    pub(crate) fn composition(&self) -> Option<&[String]> {
        match self {
            Self::Composed { inputs, .. } => Some(inputs),
            Self::Definitions { proof, .. } => proof.composition(),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct State {
    facts: Vec<Formula>,
    goal: Formula,
    knowledge: Vec<Formula>,
    knowledge_context: Vec<String>,
    used: BTreeSet<Action>,
    domain: Vec<FreeVariable>,
}
enum Wrap {
    Universal(FreeVariable),
    Assumption(Formula),
    DoubleNegation,
}
struct Prepared {
    body: Formula,
    wrap: Vec<Wrap>,
    state: State,
}

fn fresh(formulas: impl Iterator<Item = Formula>) -> Result<FreeVariable, crate::Error> {
    let used: BTreeSet<_> = formulas.flat_map(|f| f.free_variables()).collect();
    (0..=u32::MAX)
        .map(FreeVariable::new)
        .find(|v| !used.contains(v))
        .ok_or_else(|| crate::ResearchFailure::SearchFreshVariableExhausted.into())
}

fn prepare(target: &Formula) -> Result<Prepared, crate::Error> {
    let mut body = target.clone();
    let mut wrap = Vec::new();
    let mut facts = Vec::new();
    loop {
        if let Some(inner) = body.view().negated().and_then(|f| f.negated()) {
            body = inner.to_owned();
            wrap.push(Wrap::DoubleNegation);
            continue;
        }
        let variable = fresh(facts.iter().cloned().chain(std::iter::once(body.clone())))?;
        if let Some(opened) = body.open_outer_universal(variable) {
            body = opened;
            wrap.push(Wrap::Universal(variable));
        } else if let Some((a, b)) = body.view().implication_parts() {
            let a = a.to_owned();
            let b = b.to_owned();
            facts.push(a.clone());
            wrap.push(Wrap::Assumption(a));
            body = b;
        } else {
            break;
        }
    }
    let mut domain = body.free_variables();
    for f in &facts {
        domain.extend(f.free_variables());
    }
    if domain.is_empty() {
        domain.insert(FreeVariable::new(0));
    }
    facts.push(c::not(body.clone()));
    for v in &domain {
        let f = Formula::equal(*v, *v);
        if !facts.contains(&f) {
            facts.push(f);
        }
    }
    Ok(Prepared {
        body: body.clone(),
        wrap,
        state: State {
            facts,
            goal: body.clone(),
            knowledge: Vec::new(),
            knowledge_context: Vec::new(),
            used: BTreeSet::new(),
            domain: domain.into_iter().collect(),
        },
    })
}

fn close(state: &State) -> Option<(usize, usize)> {
    for (i, f) in state.facts.iter().enumerate() {
        if let Some(p) = f.view().negated()
            && let Some(j) = state.facts.iter().position(|g| g.view() == p)
        {
            return Some((j, i));
        }
    }
    None
}

fn actions(state: &State) -> Vec<Action> {
    offers(state)
        .into_iter()
        .map(|offer| offer.action)
        .collect()
}

fn offers(state: &State) -> Vec<Offer> {
    let mut index = HashMap::with_capacity(state.facts.len());
    for (position, fact) in state.facts.iter().enumerate() {
        index.entry(fact.view()).or_insert(position);
    }
    let already_closed = close(state).is_some();
    // If an existing implication concludes the denied goal, supplying its
    // exact missing premise enables a one-step contradiction in the child.
    let closing_premises = state
        .facts
        .iter()
        .filter_map(|fact| fact.view().implication_parts())
        .filter(|(premise, result)| *result == state.goal.view() && !index.contains_key(premise))
        .map(|(premise, _)| premise)
        .collect::<std::collections::HashSet<_>>();
    let mut result = Vec::new();
    let mut fused_actions = Vec::new();
    for (i, f) in state.facts.iter().enumerate() {
        if f.view().negated().and_then(|g| g.negated()).is_some() {
            result.push(Action::Double(i));
        } else if f
            .view()
            .negated()
            .and_then(|g| g.implication_parts())
            .is_some()
        {
            result.push(Action::NotImp(i));
        } else if let Some(universal) = f.view().negated()
            && matches!(
                universal.graph_node(),
                naome_foundation::graph::Node::ForAll(_)
            )
        {
            if !state
                .used
                .iter()
                .any(|a| matches!(a, Action::Witness(j, _) if *j == i))
            {
                let variable = fresh(state.facts.iter().cloned()).expect("bounded fresh variable");
                result.push(Action::Witness(i, variable.identifier()));
            }
        } else if let Some((a, b)) = f.view().implication_parts() {
            if !index.contains_key(&b) {
                if let Some(j) = index.get(&a).copied() {
                    result.push(Action::Mp(i, j));
                } else {
                    result.push(Action::Beta(i));
                }
            }
        } else if let Some(universal) = instantiation::Universal::new(f) {
            let first = state
                .domain
                .first()
                .copied()
                .unwrap_or(FreeVariable::new(0));
            let mut fused = BTreeSet::new();
            for (premise, replacement) in universal.applications(&state.facts, first) {
                if state.domain.contains(&replacement) && fused.insert(replacement) {
                    fused_actions.push(Action::InstantiateApply(
                        i,
                        replacement.identifier(),
                        premise,
                    ));
                }
            }
            for v in &state.domain {
                result.push(Action::Instantiate(i, v.identifier()));
            }
        }
        if let Some((from, to)) = f.view().equality_variables()
            && from != to
        {
            result.extend((0..state.facts.len()).map(|j| Action::Substitute(i, j)));
        }
    }
    for (i, formula) in state.knowledge.iter().enumerate() {
        if !state.facts.contains(formula) {
            result.push(Action::Cite(i));
        }
    }
    let target_fragments = super::knowledge::fragments(&state.goal);
    let negatives = focus::existential(&state.goal).then(|| {
        state
            .facts
            .iter()
            .filter_map(|fact| fact.view().negated())
            .collect::<std::collections::HashSet<_>>()
    });
    let mut relevance_cache = HashMap::new();
    type RankedOffer = ((bool, bool, u8, usize), Offer);
    let mut ranked: Vec<RankedOffer> = Vec::new();
    let mut best_by_rule: [Option<RankedOffer>; 8] = Default::default();
    let mut direct_close = false;
    for action in result.into_iter().chain(fused_actions) {
        let fused = matches!(action, Action::InstantiateApply(..));
        if (fused && direct_close) || state.used.contains(&action) {
            continue;
        }
        let Ok(delta) = transition(state, &action, &index) else {
            continue;
        };
        if delta.branches().iter().all(Vec::is_empty) {
            continue;
        }
        let closes = already_closed
            || delta.branches().iter().all(|added| {
                added.iter().any(|fact| {
                    let negative = Formula::negate(fact.clone());
                    fact.view().negated().is_some_and(|body| {
                        index.contains_key(&body) || added.iter().any(|a| a.view() == body)
                    }) || index.contains_key(&negative.view())
                        || added.contains(&negative)
                })
            });
        if fused && !closes {
            continue;
        }
        direct_close |= !fused && closes;
        let prepares_close = delta.count == 1
            && state.facts.len() + delta.additions[0].len() <= FACT_LIMIT
            && delta.additions[0]
                .iter()
                .any(|fact| closing_premises.contains(&fact.view()));
        let relevance = delta
            .branches()
            .iter()
            .flatten()
            .map(|formula| {
                *relevance_cache.entry(formula.clone()).or_insert_with(|| {
                    super::knowledge::fragments(formula)
                        .intersection(&target_fragments)
                        .map(Vec::len)
                        .sum::<usize>()
                })
            })
            .max()
            .unwrap_or(0);
        // Preserve executable instances before the menu is truncated.
        let instance_tier = negatives
            .as_ref()
            .filter(|_| matches!(action, Action::Instantiate(..)))
            .map_or(0, |negatives| {
                delta.additions[0]
                    .iter()
                    .map(|formula| {
                        focus::instance_tier(
                            formula.view(),
                            false,
                            |f| index.contains_key(&f),
                            |f| negatives.contains(&f),
                        )
                    })
                    .max()
                    .unwrap_or(0)
            });
        let score = (
            closes,
            prepares_close,
            instance_tier,
            relevance * 4 + usize::from(!matches!(action, Action::Beta(_))),
        );
        let kind = match action {
            Action::Double(_) => 0,
            Action::NotImp(_) => 1,
            Action::Mp(..) => 2,
            Action::Beta(_) => 3,
            Action::Instantiate(..) | Action::InstantiateApply(..) => 4,
            Action::Witness(..) => 5,
            Action::Substitute(..) => 6,
            Action::Cite(_) => 7,
        };
        let candidate = (
            score,
            Offer {
                action,
                delta,
                closes,
                prepares_close,
            },
        );
        let compare =
            |a: &RankedOffer, b: &RankedOffer| b.0.cmp(&a.0).then(a.1.action.cmp(&b.1.action));
        let best = &mut best_by_rule[kind];
        if best
            .as_ref()
            .is_none_or(|old| compare(&candidate, old).is_lt())
        {
            *best = Some(candidate.clone());
        }
        let position = ranked.partition_point(|old| compare(old, &candidate).is_lt());
        if position < 16 {
            if ranked.len() == 16 {
                ranked.pop();
            }
            ranked.insert(position, candidate);
        }
    }
    let mut selected: Vec<_> = best_by_rule.into_iter().flatten().collect();
    for candidate in ranked {
        if selected.len() == 16 {
            break;
        }
        if !selected
            .iter()
            .any(|(_, offer)| offer.action == candidate.1.action)
        {
            selected.push(candidate);
        }
    }
    // Capacity preferences affect admission only. Keep the menu order for
    // learned ranking and checked replay consistent.
    selected.sort_by(
        |((a_close, _, _, a_relevance), a), ((b_close, _, _, b_relevance), b)| {
            (b_close, b_relevance)
                .cmp(&(a_close, a_relevance))
                .then(a.action.cmp(&b.action))
        },
    );
    selected.into_iter().map(|(_, offer)| offer).collect()
}

#[derive(Clone)]
struct Offer {
    action: Action,
    delta: Delta,
    closes: bool,
    prepares_close: bool,
}

#[derive(Clone)]
struct Delta {
    additions: [Vec<Formula>; 2],
    count: usize,
    witness: Option<FreeVariable>,
}
impl Delta {
    fn branches(&self) -> &[Vec<Formula>] {
        &self.additions[..self.count]
    }

    fn apply(&self, state: &State, action: &Action) -> Vec<State> {
        self.branches()
            .iter()
            .map(|added| {
                let mut child = state.clone();
                child.used.insert(action.clone());
                child.facts.extend(added.iter().cloned());
                child.domain.extend(self.witness);
                child
            })
            .collect()
    }
}

fn decision(
    goal: &Formula,
    state: &State,
    actions: &[Action],
    expert: usize,
) -> Result<Decision, crate::Error> {
    let index = state
        .facts
        .iter()
        .enumerate()
        .map(|(i, f)| (f.view(), i))
        .collect();
    let offers = actions
        .iter()
        .map(|action| {
            Ok(Offer {
                action: action.clone(),
                closes: false,
                prepares_close: false,
                delta: transition(state, action, &index)?,
            })
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;
    decision_for(goal, state, &offers, expert)
}

fn decision_for(
    goal: &Formula,
    state: &State,
    offers: &[Offer],
    expert: usize,
) -> Result<Decision, crate::Error> {
    let mut context: Vec<_> = state
        .facts
        .iter()
        .map(|formula| Binding {
            formula: formula.clone(),
        })
        .collect();
    let mut candidates = Vec::new();
    for offer in offers {
        let (rule, premises) = match offer.action {
            Action::Double(i) => (Rule::DoubleNegation, vec![i]),
            Action::NotImp(i) => (Rule::NegatedImplication, vec![i]),
            Action::Mp(i, j) => (Rule::ModusPonens, vec![i, j]),
            Action::Beta(i) => (Rule::ImplicationBranch, vec![i]),
            Action::Instantiate(i, _) => (Rule::UniversalInstance, vec![i]),
            Action::InstantiateApply(i, _, premise) => (Rule::UniversalInstance, vec![i, premise]),
            Action::Witness(i, _) => (Rule::ExistentialWitness, vec![i]),
            Action::Substitute(i, j) => (Rule::EqualitySubstitution, vec![i, j]),
            Action::Cite(i) => {
                let formula = state
                    .knowledge
                    .get(i)
                    .ok_or(crate::ResearchFailure::SearchTheoremIndex)?;
                let index = context
                    .iter()
                    .position(|b| b.formula == *formula)
                    .unwrap_or_else(|| {
                        context.push(Binding {
                            formula: formula.clone(),
                        });
                        context.len() - 1
                    });
                (Rule::LemmaReference, vec![index])
            }
        };
        let mut consequences = Vec::new();
        // Features are derived from the same bounded transition used by live
        // search and proof replay. They contain no future proof or label.
        for formula in offer.delta.branches().iter().flatten() {
            if !consequences.contains(formula) {
                consequences.push(formula.clone());
            }
        }
        candidates.push(Candidate {
            rule,
            premises,
            replacement: match offer.action {
                Action::Instantiate(_, value)
                | Action::InstantiateApply(_, value, _)
                | Action::Witness(_, value) => Some(FreeVariable::new(value)),
                _ => None,
            },
            consequences,
        });
    }
    Ok(Decision {
        context,
        goal: goal.clone(),
        candidates,
        expert,
    })
}

fn next(state: &State, action: &Action) -> Result<Vec<State>, crate::Error> {
    let index = state
        .facts
        .iter()
        .enumerate()
        .map(|(i, f)| (f.view(), i))
        .collect();
    Ok(transition(state, action, &index)?.apply(state, action))
}

fn transition(
    state: &State,
    action: &Action,
    index: &HashMap<naome_foundation::FormulaView<'_>, usize>,
) -> Result<Delta, crate::Error> {
    let mut delta = Delta {
        additions: Default::default(),
        count: 1,
        witness: None,
    };
    let mut add = |branch: usize, formula: Formula| {
        let added = &mut delta.additions[branch];
        if !index.contains_key(&formula.view()) && !added.contains(&formula) {
            added.push(formula);
        }
    };
    match *action {
        Action::Cite(i) => {
            let formula = state
                .knowledge
                .get(i)
                .ok_or(crate::ResearchFailure::SearchTheoremIndex)?
                .clone();
            add(0, formula);
        }
        Action::Double(i) => {
            let f = state.facts[i]
                .view()
                .negated()
                .and_then(|g| g.negated())
                .ok_or(crate::ResearchFailure::SearchDoubleAction)?
                .to_owned();
            add(0, f);
        }
        Action::NotImp(i) => {
            let (a, b) = state.facts[i]
                .view()
                .negated()
                .and_then(|g| g.implication_parts())
                .ok_or(crate::ResearchFailure::SearchNegatedImplication)?;
            let a = a.to_owned();
            let b = c::not(b.to_owned());
            add(0, a);
            add(0, b);
        }
        Action::Mp(i, j) => {
            let (a, b) = state.facts[i]
                .view()
                .implication_parts()
                .ok_or(crate::ResearchFailure::SearchModusPonens)?;
            if a != state.facts[j].view() {
                return Err(crate::ResearchFailure::SearchPremise.into());
            }
            let b = b.to_owned();
            add(0, b);
        }
        Action::Beta(i) => {
            let (a, b) = state.facts[i]
                .view()
                .implication_parts()
                .ok_or(crate::ResearchFailure::SearchBranchAction)?;
            let a = c::not(a.to_owned());
            let b = b.to_owned();
            add(0, a);
            add(1, b);
            delta.count = 2;
        }
        Action::Instantiate(i, v) | Action::InstantiateApply(i, v, _) => {
            let f = &state.facts[i];
            let variable = FreeVariable::new(v);
            let f = if let Some(instance) = f.open_outer_universal(variable) {
                instance
            } else {
                let x = fresh(std::iter::once(f.clone()))?;
                f.open_outer_universal(x)
                    .ok_or(crate::ResearchFailure::SearchUniversalAction)?
                    .substitute_free(x, variable)
            };
            let result = if let Action::InstantiateApply(_, _, premise) = *action {
                let (antecedent, consequent) = f
                    .view()
                    .implication_parts()
                    .ok_or(crate::ResearchFailure::SearchInstantiationShape)?;
                if state
                    .facts
                    .get(premise)
                    .is_none_or(|fact| fact.view() != antecedent)
                {
                    return Err(crate::ResearchFailure::SearchInstantiationPremise.into());
                }
                consequent.to_owned()
            } else {
                f
            };
            add(0, result);
        }
        Action::Witness(i, v) => {
            let variable = FreeVariable::new(v);
            if state
                .facts
                .iter()
                .any(|f| f.free_variables().contains(&variable))
            {
                return Err(crate::ResearchFailure::SearchWitnessFreshness.into());
            }
            let universal = state.facts[i]
                .view()
                .negated()
                .ok_or(crate::ResearchFailure::SearchWitnessNegation)?
                .to_owned();
            let opened = universal
                .open_outer_universal(variable)
                .ok_or(crate::ResearchFailure::SearchWitnessUniversal)?;
            add(0, c::not(opened));
            add(0, Formula::equal(variable, variable));
            delta.witness = Some(variable);
        }
        Action::Substitute(i, j) => {
            let (a, b) = state.facts[i]
                .view()
                .equality_variables()
                .ok_or(crate::ResearchFailure::SearchEqualityAction)?;
            let f = state.facts[j].clone().substitute_free(a, b);
            add(0, f);
        }
    }
    Ok(delta)
}

pub struct ResultTree {
    pub tree: Option<Tree>,
    pub expansions: usize,
    pub failure: Option<GenerationOutcome>,
    pub frontier: Option<frontier::Frontier>,
    pub terminal: TerminalEvidence,
    pub execution: Option<trace::Trace>,
}
struct Search<'a> {
    ranker: &'a mut dyn Ranker,
    goal: Formula,
    started: Instant,
    expansions: usize,
    maximum: usize,
    limit: usize,
    considered_repair: bool,
    deferred: bool,
    repair: Option<(usize, usize)>,
    failure: Option<GenerationOutcome>,
    exhausted: BTreeSet<String>,
    frontier: Option<frontier::Frontier>,
    terminal: TerminalEvidence,
    recorder: Option<trace::Recorder>,
}
impl Search<'_> {
    fn prove(&mut self, state: &State, depth: usize) -> Result<Option<Tree>, crate::Error> {
        self.branch(state, depth, None, None)
    }
    fn expansion_limit(&mut self) {
        if self.limit < self.maximum {
            self.deferred = true;
        } else {
            self.failure = Some(GenerationOutcome::SearchBudget);
            self.terminal
                .include(TerminalEvidence::Budget(Budget::Expansions));
        }
    }

    fn branch(
        &mut self,
        state: &State,
        depth: usize,
        parent: Option<trace::Branch>,
        incoming: Option<(&super::model::Plan, usize)>,
    ) -> Result<Option<Tree>, crate::Error> {
        if self.started.elapsed() > TIME_LIMIT || depth > 32 {
            if let Some(report) = &mut self.frontier {
                report.observe(state, depth);
            }
            self.failure = Some(GenerationOutcome::SearchBudget);
            self.terminal
                .include(TerminalEvidence::Budget(if depth > 32 {
                    Budget::Depth
                } else {
                    Budget::Time
                }));
            return Ok(None);
        }
        if let Some((a, b)) = close(state) {
            return Ok(Some(Tree::Close(a, b)));
        }
        // Recognizing the terminal state after the last permitted transition
        // consumes no additional expansion. Never admit another action here.
        if self.expansions >= self.limit {
            if let Some(report) = &mut self.frontier {
                report.observe(state, depth);
            }
            self.expansion_limit();
            return Ok(None);
        }
        if state.facts.len() > FACT_LIMIT {
            self.failure = Some(GenerationOutcome::FactLimit);
            self.terminal
                .include(TerminalEvidence::Unsupported(Capacity::Facts));
            return Ok(None);
        }
        let state_binding = trace::binding(state)?;
        let offers = offers(state);
        let actions: Vec<_> = offers.iter().map(|offer| offer.action.clone()).collect();
        let offered = super::digest(&actions);
        if actions.is_empty() {
            if let Some(report) = &mut self.frontier {
                report.observe(state, depth);
            }
            return Ok(None);
        }
        // A one- or two-step closure has concrete operands and needs no
        // learned ordering or successor memory.
        let closing = (depth < 32)
            .then(|| offers.iter().position(|offer| offer.closes))
            .flatten();
        let forced = closing.or_else(|| {
            (depth < 31 && self.limit - self.expansions >= 2)
                .then(|| offers.iter().position(|offer| offer.prepares_close))
                .flatten()
        });
        let (plan, key) = if let Some(index) = forced {
            let mut ranks = vec![0.; actions.len()];
            ranks[index] = 1.;
            (Plan::scores(ranks), None)
        } else {
            let memory = incoming
                .map(|(plan, selected)| {
                    plan.child(selected, state_binding.clone(), offered.clone())
                })
                .transpose()?
                .flatten();
            let key = super::digest(&(
                &state_binding,
                32usize.saturating_sub(depth),
                self.ranker.identity(),
                memory.as_ref(),
            ));
            if self.exhausted.contains(&key) {
                return Ok(None);
            }
            let d = decision_for(&self.goal, state, &offers, 0)?;
            let plan = match self
                .ranker
                .plan(&d, &state_binding, &offered, memory.as_ref())
            {
                Ok(plan) => plan,
                Err(crate::Error::LearningGraph(
                    crate::LearningGraphFailure::Capacity
                    | crate::LearningGraphFailure::ActionArity
                    | crate::LearningGraphFailure::BoundIndexWidth
                    | crate::LearningGraphFailure::DanglingBoundVariable
                    | crate::LearningGraphFailure::DecisionCapacity
                    | crate::LearningGraphFailure::MissingExpert
                    | crate::LearningGraphFailure::MissingPremise,
                )) => {
                    if let Some(report) = &mut self.frontier {
                        report.observe(state, depth);
                    }
                    self.failure = Some(GenerationOutcome::GraphLimit);
                    self.terminal
                        .include(TerminalEvidence::Unsupported(Capacity::Graph));
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            (plan, Some(key))
        };
        let scores = &plan.scores;
        if scores.len() != actions.len() || scores.iter().any(|s| !s.is_finite()) {
            return Err(crate::ResearchFailure::InvalidActionScores.into());
        }
        let mut order: Vec<_> = (0..actions.len()).collect();
        order.sort_by(|a, b| scores[*b].total_cmp(&scores[*a]).then(a.cmp(b)));
        if forced.is_some() {
            order.truncate(1);
        }
        // Give the first genuinely ambiguous decision room to try an
        // alternative before a single descent consumes the whole job.
        let first_limit = self.maximum.div_ceil(3);
        let repair_site = !self.considered_repair
            && order.len() > 1
            && self.maximum >= 24
            && self.expansions + 1 < first_limit;
        self.considered_repair |= repair_site;
        let mut failed_alternative = None;
        for (attempt, selected) in order.into_iter().enumerate() {
            if self.expansions >= self.limit {
                self.expansion_limit();
                break;
            }
            let event_started = Instant::now();
            let previous_repair = self.repair;
            let event = self
                .recorder
                .as_mut()
                .map(|recorder| {
                    recorder.begin(
                        &state_binding,
                        &offered,
                        selected,
                        (actions.len() > 1).then_some(scores.as_slice()),
                        parent,
                        self.expansions,
                    )
                })
                .transpose()?
                .flatten();
            self.expansions += 1;
            let mut children = Vec::new();
            let mut success = true;
            let mut attempted = 0;
            let offer = &offers[selected];
            if repair_site && attempt == 0 {
                self.limit = first_limit;
            }
            for (index, child) in offer
                .delta
                .apply(state, &offer.action)
                .into_iter()
                .enumerate()
            {
                attempted += 1;
                // Each alternative and sibling starts from the same saved
                // selected-parent memory, never the preceding failed branch.
                if let Some(tree) = self.branch(
                    &child,
                    depth + 1,
                    event.map(|event| trace::Branch {
                        event,
                        child: index,
                    }),
                    Some((&plan, selected)),
                )? {
                    children.push(tree)
                } else {
                    success = false;
                    break;
                }
            }
            if repair_site && attempt == 0 {
                self.limit = self.maximum;
            }
            if let Some(recorder) = &mut self.recorder {
                recorder.finish(
                    event,
                    attempted,
                    self.expansions,
                    success,
                    event_started.elapsed(),
                );
            }
            if success {
                if let Some(failed) = failed_alternative {
                    self.repair = Some((failed, selected));
                }
                return Ok(Some(Tree::Step {
                    action: actions[selected].clone(),
                    children,
                }));
            }
            self.repair = previous_repair;
            failed_alternative = failed_alternative.or(event);
        }
        if let Some(key) = key
            && self.expansions < self.limit
            && self.started.elapsed() <= TIME_LIMIT
            && self.exhausted.len() < 256
        {
            self.exhausted.insert(key);
        }
        if let Some(report) = &mut self.frontier {
            report.observe(state, depth);
        }
        Ok(None)
    }
}

#[cfg(test)]
pub fn solve(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
) -> Result<ResultTree, crate::Error> {
    solve_started(target, ranker, maximum, Instant::now())
}
#[cfg(test)]
pub fn solve_started(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
    started: Instant,
) -> Result<ResultTree, crate::Error> {
    solve_with_knowledge(target, ranker, maximum, started, &[])
}
pub fn solve_with_knowledge(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
    started: Instant,
    knowledge: &[super::knowledge::Entry],
) -> Result<ResultTree, crate::Error> {
    solve_recording(target, ranker, maximum, started, knowledge, true)
}
fn solve_recording(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
    started: Instant,
    knowledge: &[super::knowledge::Entry],
    capture: bool,
) -> Result<ResultTree, crate::Error> {
    if maximum == 0 {
        return Ok(ResultTree {
            execution: None,
            tree: None,
            expansions: 0,
            failure: Some(GenerationOutcome::SearchBudget),
            frontier: None,
            terminal: TerminalEvidence::Budget(Budget::Expansions),
        });
    }
    if let Some((index, _)) = AXIOMS
        .iter()
        .enumerate()
        .find(|(_, axiom)| axiom.formula() == *target)
    {
        return Ok(ResultTree {
            execution: None,
            tree: Some(Tree::Axiom(index as u8)),
            expansions: 1,
            failure: None,
            frontier: None,
            terminal: TerminalEvidence::Unknown,
        });
    }
    let checked = super::knowledge::checked_entries(knowledge)?;
    let mut p = prepare(target)?;
    p.state.knowledge_context = knowledge.iter().map(super::digest).collect();
    p.state.knowledge = checked.iter().map(|entry| entry.target.clone()).collect();
    let mut s = Search {
        recorder: capture
            .then(|| trace::Recorder::new(target, &checked))
            .transpose()?,
        ranker,
        goal: p.body,
        started,
        expansions: 0,
        maximum,
        limit: maximum,
        considered_repair: false,
        deferred: false,
        repair: None,
        failure: None,
        exhausted: BTreeSet::new(),
        frontier: frontier::Frontier::new(target),
        terminal: TerminalEvidence::Unknown,
    };
    let mut tree = s.prove(&p.state, 0)?;
    if let Some(proof) = &tree {
        if let (Some(recorder), Some((failed, selected))) = (&mut s.recorder, s.repair) {
            recorder.retain_repair(failed, selected, proof)?;
        }
    } else if s.deferred && s.failure.is_none() {
        s.failure = Some(GenerationOutcome::SearchBudget);
        s.terminal
            .include(TerminalEvidence::Budget(Budget::BranchExpansions));
    } else if s.failure.is_none() && s.expansions > 0 {
        s.terminal = TerminalEvidence::PolicyExhausted;
    }
    if !knowledge.is_empty() {
        tree = tree.map(|proof| Tree::Knowledge {
            entries: knowledge.to_vec(),
            target: target.encode_canonical().expect("checked input formula"),
            proof: Box::new(proof),
        });
    }
    Ok(ResultTree {
        execution: s.recorder.map(trace::Recorder::into_trace),
        frontier: if tree.is_none() {
            s.frontier.filter(|f| !f.empty())
        } else {
            None
        },
        tree,
        expansions: s.expansions,
        failure: s.failure,
        terminal: s.terminal,
    })
}

fn add_term(facts: &mut Vec<Term>, term: Term) {
    if !facts.iter().any(|f| f.formula() == term.formula()) {
        facts.push(term)
    }
}

fn replay(
    tree: &Tree,
    state: &State,
    facts: &[Term],
    names: &mut Names,
    graphs: &mut Vec<Graph>,
    knowledge: &[Term],
    depth: usize,
) -> Result<(Term, Term), crate::Error> {
    let goal = &state.goal;
    if depth > 40 {
        return Err(crate::ResearchFailure::ReplayDepth.into());
    }
    if facts.iter().map(Term::formula).collect::<Vec<_>>() != state.facts {
        return Err(crate::ResearchFailure::ReplayState.into());
    }
    if let Tree::Close(a, b) = tree {
        let p = facts
            .get(*a)
            .ok_or(crate::ResearchFailure::ReplayPositiveIndex)?;
        let n = facts
            .get(*b)
            .ok_or(crate::ResearchFailure::ReplayNegativeIndex)?;
        if n.formula() != c::not(p.formula()) {
            return Err(crate::ResearchFailure::ReplayClosure.into());
        }
        return Ok((p.clone(), n.clone()));
    }
    let Tree::Step { action, children } = tree else {
        return Err(crate::ResearchFailure::ReplayNestedAxiom.into());
    };
    let offered = actions(state);
    let expert = offered
        .iter()
        .position(|a| a == action)
        .ok_or(crate::ResearchFailure::ReplayAction)?;
    if offered.len() > 1 {
        let mut graph = Graph::encode(&decision(goal, state, &offered, expert)?)?;
        graph.binding = trace::binding(state)?;
        graphs.push(graph);
    }
    let states = next(state, action)?;
    if states.len() != children.len() {
        return Err(crate::ResearchFailure::ReplayArity.into());
    }
    let mut updated = facts.to_vec();
    match *action {
        Action::Cite(i) => add_term(
            &mut updated,
            knowledge
                .get(i)
                .ok_or(crate::ResearchFailure::ReplayTheoremIndex)?
                .clone(),
        ),
        Action::Double(i) => add_term(&mut updated, c::double_elim(facts[i].clone(), names)?),
        Action::NotImp(i) => {
            let (a, b) = c::not_implies(facts[i].clone(), names)?;
            add_term(&mut updated, a);
            add_term(&mut updated, b);
        }
        Action::Mp(i, j) => add_term(&mut updated, c::app(facts[i].clone(), facts[j].clone())?),
        Action::Instantiate(i, v) => add_term(
            &mut updated,
            c::instantiate(facts[i].clone(), FreeVariable::new(v))?,
        ),
        Action::InstantiateApply(i, v, premise) => add_term(
            &mut updated,
            c::app(
                c::instantiate(facts[i].clone(), FreeVariable::new(v))?,
                facts[premise].clone(),
            )?,
        ),
        Action::Witness(i, v) => {
            let variable = FreeVariable::new(v);
            let universal = facts[i]
                .formula()
                .view()
                .negated()
                .ok_or(crate::ResearchFailure::ReplayWitness)?
                .to_owned();
            let opened = universal
                .open_outer_universal(variable)
                .ok_or(crate::ResearchFailure::ReplayWitnessBody)?;
            let (id, witness) = names.assumption(c::not(opened.clone()));
            add_term(&mut updated, witness);
            add_term(
                &mut updated,
                c::axiom(ProofStep::EqualityReflexivity { variable })?,
            );
            let (positive, negative) = replay(
                &children[0],
                &states[0],
                &updated,
                names,
                graphs,
                knowledge,
                depth + 1,
            )?;
            let body = c::raa(opened, id, positive, negative, names)?;
            let all = Term::Generalize(variable, Box::new(body));
            if all.formula() != universal {
                return Err(crate::ResearchFailure::ReplayWitnessDischarge.into());
            }
            return Ok((all, facts[i].clone()));
        }
        Action::Substitute(i, j) => {
            let f = facts[i].formula();
            let (a, b) = f
                .view()
                .equality_variables()
                .ok_or(crate::ResearchFailure::ReplayEquality)?;
            add_term(
                &mut updated,
                c::substitute(facts[i].clone(), facts[j].clone(), a, b)?,
            );
        }
        Action::Beta(i) => {
            let f = facts[i].formula();
            let (a, b) = f
                .view()
                .implication_parts()
                .ok_or(crate::ResearchFailure::ReplayBranch)?;
            let a = a.to_owned();
            let b = b.to_owned();
            let (id, na) = names.assumption(c::not(a.clone()));
            let mut left = facts.to_vec();
            add_term(&mut left, na);
            let (p, n) = replay(
                &children[0],
                &states[0],
                &left,
                names,
                graphs,
                knowledge,
                depth + 1,
            )?;
            let a = c::raa(a, id, p, n, names)?;
            let (j, bv) = names.assumption(b.clone());
            let mut right = facts.to_vec();
            add_term(&mut right, bv);
            let (p, n) = replay(
                &children[1],
                &states[1],
                &right,
                names,
                graphs,
                knowledge,
                depth + 1,
            )?;
            let nb = c::neg_intro(j, b, p, n, names)?;
            return Ok((c::app(facts[i].clone(), a)?, nb));
        }
    }
    replay(
        &children[0],
        &states[0],
        &updated,
        names,
        graphs,
        knowledge,
        depth + 1,
    )
}

pub fn compile(target: &Formula, tree: &Tree) -> Result<(Term, Vec<Graph>), crate::Error> {
    if let Tree::Scoped {
        target: encoded,
        actions,
    } = tree
    {
        if target.encode_canonical().map_err(crate::Error::from)? != *encoded {
            return Err(crate::ResearchFailure::ReplayScopedTarget.into());
        }
        return scope::compile(target, actions);
    }
    if let Tree::Knowledge {
        entries,
        target: encoded,
        proof,
    } = tree
    {
        if target.encode_canonical().map_err(crate::Error::from)? != *encoded {
            return Err(crate::ResearchFailure::ReplayTheoremTarget.into());
        }
        super::knowledge::validate(entries)?;
        return compile_tableau(target, proof, entries);
    }
    if let Tree::Definitions {
        entries,
        selected,
        available,
        proof,
    } = tree
    {
        if *available > entries.len() {
            return Err(crate::ResearchFailure::ReplayDefinitionAvailability.into());
        }
        let entry = entries
            .get(*selected)
            .ok_or(crate::ResearchFailure::ReplayDefinitionIndex)?;
        let _ = super::definitions::context(entries)?;
        let (term, mut graphs) = compile(target, proof)?;
        if super::construction::composition::scoped_operands(target, proof, entry)?.is_some() {
            if entries.len() > 1 {
                graphs.push(super::definitions::decision(target, entries, *selected)?);
            }
            return Ok((term, graphs));
        }
        let verified = super::proof::verify(&term, target)?;
        let mut definitions = verified.definitions.clone();
        if !definitions.contains(entry) {
            definitions.push(entry.clone());
        }
        let source = super::proof::source_with_definitions(&verified, &definitions)?;
        let context = super::proof::lemma_context(&definitions, &verified.lemmas)?;
        let checked = crate::learning::proof::check_artifact(&source, &context)?;
        if !checked
            .direct_artifact_dependencies()
            .contains(&entry.address()?)
        {
            return Err(crate::ResearchFailure::ReplayDefinitionUnused.into());
        }
        if entries.len() > 1 {
            graphs.push(super::definitions::decision(target, entries, *selected)?);
        }
        return Ok((
            Term::Native {
                lemmas: verified.lemmas,
                certificate: checked.normal_form().certificate().clone(),
                target: target.clone(),
                definitions,
            },
            graphs,
        ));
    }
    if matches!(tree, Tree::Stored { .. }) {
        return Err(crate::ResearchFailure::ReplayOwnedSnapshot.into());
    }
    if let Tree::Composed {
        packet,
        inputs,
        work,
        ..
    } = tree
    {
        super::construction::composition::validate(packet, inputs, *work)?;
        // A deterministic composition has no neural action label to invent.
        return Ok((super::evidence::compile(target, packet)?, Vec::new()));
    }
    if let Tree::Constructed { packet, selection } = tree {
        let (term, mut graphs) = super::peer::compile_dag(target, packet)?;
        if let Some(selection) = selection {
            let verified = super::proof::verify(&term, target)?;
            if let Some(graph) =
                super::construction::selection::graph(target, selection, &verified)?
            {
                graphs.push(graph);
            }
        }
        return Ok((term, graphs));
    }
    if let Tree::Certificate(bytes) = tree {
        return super::peer::compile(target, bytes);
    }
    if let Tree::Axiom(index) = tree {
        let axiom = *AXIOMS
            .get(*index as usize)
            .ok_or(crate::ResearchFailure::ReplayAxiomIndex)?;
        if axiom.formula() != *target {
            return Err(crate::ResearchFailure::ReplayAxiomTarget.into());
        }
        return Ok((c::axiom(ProofStep::ZfcAxiom(axiom))?, Vec::new()));
    }
    compile_tableau(target, tree, &[])
}
fn compile_tableau(
    target: &Formula,
    tree: &Tree,
    entries: &[super::knowledge::Entry],
) -> Result<(Term, Vec<Graph>), crate::Error> {
    let knowledge = entries
        .iter()
        .map(super::knowledge::Entry::term)
        .collect::<Result<Vec<_>, _>>()?;
    let mut p = prepare(target)?;
    p.state.knowledge_context = entries.iter().map(super::digest).collect();
    p.state.knowledge = knowledge.iter().map(Term::formula).collect();
    let mut names = Names::default();
    let mut facts = Vec::new();
    let mut assumption_ids = Vec::new();
    for w in &p.wrap {
        if let Wrap::Assumption(f) = w {
            let (id, term) = names.assumption(f.clone());
            facts.push(term);
            assumption_ids.push(id);
        }
    }
    let (root, ng) = names.assumption(c::not(p.body.clone()));
    facts.push(ng);
    for v in &p.state.domain {
        let f = Formula::equal(*v, *v);
        if !facts.iter().any(|t| t.formula() == f) {
            facts.push(c::axiom(ProofStep::EqualityReflexivity { variable: *v })?);
        }
    }
    let mut graphs = Vec::new();
    let (a, b) = replay(
        tree,
        &p.state,
        &facts,
        &mut names,
        &mut graphs,
        &knowledge,
        0,
    )?;
    let mut term = if a.formula() == p.body && !a.free_assumptions().contains_key(&root) {
        a
    } else {
        c::raa(p.body, root, a, b, &mut names)?
    };
    for wrap in p.wrap.into_iter().rev() {
        term = match wrap {
            Wrap::Universal(variable) => Term::Generalize(variable, Box::new(term)),
            Wrap::Assumption(formula) => Term::Lambda(
                assumption_ids
                    .pop()
                    .ok_or(crate::ResearchFailure::ReplayAssumptionWrapper)?,
                formula,
                Box::new(term),
            ),
            Wrap::DoubleNegation => c::double_intro(term, &mut names)?,
        };
    }
    if term.formula() != *target {
        return Err(crate::ResearchFailure::ReplayCompiledTarget.into());
    }
    Ok((term, graphs))
}

pub(super) const AXIOMS: [naome_foundation::ZfcAxiom; 7] = [
    naome_foundation::ZfcAxiom::Extensionality,
    naome_foundation::ZfcAxiom::Pairing,
    naome_foundation::ZfcAxiom::Union,
    naome_foundation::ZfcAxiom::PowerSet,
    naome_foundation::ZfcAxiom::Infinity,
    naome_foundation::ZfcAxiom::Foundation,
    naome_foundation::ZfcAxiom::Choice,
];

#[cfg(test)]
mod witness_tests {
    use super::*;
    #[test]
    fn invalid_native_axiom_index_has_registered_failure() {
        let target = Formula::equal(FreeVariable::new(0), FreeVariable::new(0));
        let error = compile(&target, &Tree::Axiom(u8::MAX)).err().unwrap();
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::ResearchFailure::ReplayAxiomIndex)
        );
    }

    struct Ordered;
    impl Ranker for Ordered {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, crate::Error> {
            Ok(vec![0.; d.candidates.len()])
        }
    }

    #[test]
    fn nested_goal_double_negations_use_checked_introductions_without_search() {
        struct UnexpectedInference;
        impl Ranker for UnexpectedInference {
            fn scores(&mut self, _: &Decision) -> Result<Vec<f32>, crate::Error> {
                Err("goal introductions must not invoke inference".into())
            }
        }

        let [x, y] = [0, 1].map(FreeVariable::new);
        let p = Formula::member(x, x);
        let q = Formula::member(y, x);
        let double = |formula| Formula::negate(Formula::negate(formula));
        let nested = Formula::for_all(y, Formula::implies(q, double(p.clone())));
        let target = double(Formula::for_all(x, Formula::implies(p, double(nested))));
        let result = solve(&target, &mut UnexpectedInference, 1).unwrap();
        assert_eq!(result.expansions, 0);
        let (term, graphs) = compile(&target, &result.tree.unwrap()).unwrap();
        assert!(graphs.is_empty());
        super::super::proof::verify(&term, &target).unwrap();
    }

    #[test]
    fn equality_substitution_can_prepare_a_checked_two_step_closure() {
        struct UnexpectedInference;
        impl Ranker for UnexpectedInference {
            fn scores(&mut self, _: &Decision) -> Result<Vec<f32>, crate::Error> {
                Err("a two-step closure must not invoke inference".into())
            }
        }

        let [x, y, z] = [0, 1, 2].map(FreeVariable::new);
        let premise = Formula::member(x, z);
        let intermediate = Formula::member(y, z);
        let goal = Formula::member(z, y);
        let rule = Formula::implies(intermediate, goal.clone());
        let target = Formula::implies(
            Formula::equal(x, y),
            Formula::implies(
                premise,
                Formula::implies(rule, Formula::negate(Formula::negate(goal))),
            ),
        );
        let result = solve(&target, &mut UnexpectedInference, 2).unwrap();
        assert_eq!(result.expansions, 2);
        let tree = result.tree.unwrap();
        assert!(matches!(
            tree,
            Tree::Step {
                action: Action::Substitute(..),
                ..
            }
        ));
        let (term, _) = compile(&target, &tree).unwrap();
        super::super::proof::verify(&term, &target).unwrap();
        let limited = solve(&target, &mut Ordered, 1).unwrap();
        assert!(limited.tree.is_none());
        assert_eq!(limited.expansions, 1);
    }

    #[test]
    fn the_last_allowed_transition_can_close_without_spending_another_expansion() {
        struct UnexpectedInference;
        impl Ranker for UnexpectedInference {
            fn scores(&mut self, _: &Decision) -> Result<Vec<f32>, crate::Error> {
                Err("a directly closing action must not invoke inference".into())
            }
        }
        let question = naome_checker::question::ResearchQuestion::from_hex(
            "040403020001000000010100000000030401010000000001000000020101000000000100000001",
        )
        .unwrap();
        let result = solve_with_knowledge(
            question.proved_target(),
            &mut UnexpectedInference,
            1,
            Instant::now(),
            &[],
        )
        .unwrap();
        assert_eq!(result.expansions, 1);
        let tree = result
            .tree
            .expect("the permitted universal instantiation closes the sequent");
        let _ = core::checked(question.proved_target(), &tree).unwrap();
        assert!(
            solve_with_knowledge(
                question.proved_target(),
                &mut Ordered,
                0,
                Instant::now(),
                &[]
            )
            .unwrap()
            .tree
            .is_none()
        );
        let expired = solve_with_knowledge(
            question.proved_target(),
            &mut Ordered,
            1,
            Instant::now() - Duration::from_millis(2501),
            &[],
        )
        .unwrap();
        assert!(expired.tree.is_none());
        assert_eq!(expired.expansions, 0);
    }
    #[test]
    fn existential_transport_discharges_its_fresh_witness_in_the_native_checker() {
        let q = naome_checker::question::ResearchQuestion::from_hex(
            "04030204020101000000000100000001020402030201010000000001000000010001000000000100000001",
        )
        .unwrap();
        let found = solve(q.proved_target(), &mut Ordered, 128).unwrap();
        let tree = found.tree.expect("existential witness transport");
        let (_, _, checked) = core::checked(q.proved_target(), &tree).unwrap();
        let source = super::super::proof::source(&checked);
        assert_eq!(
            crate::learning::proof::check_artifact(&source, &naome_checker::ArtifactState::new())
                .unwrap()
                .proof_id(),
            checked.native_id
        );
        let invalid = naome_checker::question::ResearchQuestion::from_hex(
            "04030204020101000000000100000001040101000000000100000001",
        )
        .unwrap();
        assert!(
            solve(invalid.proved_target(), &mut Ordered, 128)
                .unwrap()
                .tree
                .is_none()
        );
    }
    #[test]
    fn reused_eigenvariables_and_unchanged_instantiations_are_not_offered() {
        let x = FreeVariable::new(0);
        let y = FreeVariable::new(1);
        let body = Formula::member(y, x);
        let universal = Formula::for_all(y, body.clone());
        let state = State {
            goal: universal.clone(),
            facts: vec![universal.clone(), body, c::not(universal)],
            knowledge: Vec::new(),
            knowledge_context: Vec::new(),
            used: BTreeSet::new(),
            domain: vec![y],
        };
        assert!(!actions(&state).contains(&Action::Instantiate(0, 1)));
        let error = next(&state, &Action::Witness(2, 0)).err().unwrap();
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::ResearchFailure::SearchWitnessFreshness)
        );
        let action = actions(&state)
            .into_iter()
            .find(|a| matches!(a, Action::Witness(..)))
            .unwrap();
        let after = next(&state, &action).unwrap().remove(0);
        assert!(
            !actions(&after)
                .iter()
                .any(|a| matches!(a, Action::Witness(2, _)))
        );
    }
}

#[cfg(test)]
mod frontier_tests {
    use super::*;
    #[test]
    fn a_late_closing_action_survives_the_bounded_candidate_envelope() {
        let v = FreeVariable::new;
        let goal = Formula::member(v(0), v(1));
        let mut facts = (2..24)
            .map(|i| Formula::implies(Formula::member(v(i), v(0)), Formula::member(v(i), v(1))))
            .collect::<Vec<_>>();
        facts.push(Formula::negate(goal.clone()));
        facts.push(Formula::member(v(1), v(0)));
        facts.push(Formula::implies(Formula::member(v(1), v(0)), goal.clone()));
        let state = State {
            facts,
            goal,
            knowledge: vec![],
            knowledge_context: Vec::new(),
            used: BTreeSet::new(),
            domain: vec![v(0), v(1)],
        };
        let offered = actions(&state);
        assert!(offered.len() <= 16);
        assert!(offered.contains(&Action::Mp(24, 23)));
        assert!(
            next(&state, &Action::Mp(24, 23))
                .unwrap()
                .iter()
                .all(|s| close(s).is_some())
        );
    }
}

#[cfg(test)]
mod transposition_tests {
    use super::*;
    #[test]
    fn depth_limited_failure_does_not_poison_a_later_shallower_subgoal() {
        struct Ordered;
        impl Ranker for Ordered {
            fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, crate::Error> {
                Ok(vec![0.; d.candidates.len()])
            }
        }
        let x = FreeVariable::new(0);
        let y = FreeVariable::new(1);
        let p = Formula::member(x, y);
        let q = Formula::member(y, x);
        let state = State {
            facts: vec![Formula::implies(p.clone(), q.clone()), p, c::not(q.clone())],
            goal: q.clone(),
            knowledge: vec![],
            knowledge_context: Vec::new(),
            used: BTreeSet::new(),
            domain: vec![x, y],
        };
        let mut search = Search {
            recorder: None,
            terminal: TerminalEvidence::Unknown,
            ranker: &mut Ordered,
            goal: q,
            started: Instant::now(),
            expansions: 0,
            maximum: 16,
            limit: 16,
            considered_repair: false,
            deferred: false,
            repair: None,
            failure: None,
            exhausted: BTreeSet::new(),
            frontier: None,
        };
        assert!(search.prove(&state, 32).unwrap().is_none());
        assert!(
            search.prove(&state, 0).unwrap().is_some(),
            "the same subgoal with remaining depth must still be explored"
        );
    }
}

#[cfg(test)]
mod memory_tests;
