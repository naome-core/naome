//! Bounded classical tableau with checked, replayable proof reconstruction.
use super::calculus::{self as c, Names};
use super::{
    graph::Graph,
    model::{Binding, Candidate, Decision, Ranker, Rule},
    proof::Term,
};
use naome_foundation::{Formula, FreeVariable};
use naome_proof::ProofStep;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Action {
    Double(usize),
    NotImp(usize),
    Mp(usize, usize),
    Beta(usize),
    Instantiate(usize, u32),
    Substitute(usize, usize),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Tree {
    Axiom(u8),
    Close(usize, usize),
    Step { action: Action, children: Vec<Self> },
}
#[derive(Clone)]
struct State {
    facts: Vec<Formula>,
    used: BTreeSet<Action>,
    domain: Vec<FreeVariable>,
}
enum Wrap {
    Universal(FreeVariable),
    Assumption(Formula),
}
struct Prepared {
    body: Formula,
    wrap: Vec<Wrap>,
    state: State,
    double: usize,
}

fn insert(state: &mut State, f: Formula) {
    if !state.facts.contains(&f) {
        state.facts.push(f)
    }
}
fn fresh(formulas: impl Iterator<Item = Formula>) -> Result<FreeVariable, String> {
    let used: BTreeSet<_> = formulas.flat_map(|f| f.free_variables()).collect();
    (0..=u32::MAX)
        .map(FreeVariable::new)
        .find(|v| !used.contains(v))
        .ok_or("fresh variable space".into())
}

fn prepare(target: &Formula) -> Result<Prepared, String> {
    let mut body = target.clone();
    let mut double = 0;
    while let Some(inner) = body.view().negated().and_then(|f| f.negated()) {
        body = inner.to_owned();
        double += 1;
    }
    let mut wrap = Vec::new();
    let mut facts = Vec::new();
    loop {
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
        body,
        wrap,
        state: State {
            facts,
            used: BTreeSet::new(),
            domain: domain.into_iter().collect(),
        },
        double,
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
    let mut result = Vec::new();
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
        } else if let Some((a, b)) = f.view().implication_parts() {
            if !state.facts.iter().any(|g| g.view() == b) {
                if let Some(j) = state.facts.iter().position(|g| g.view() == a) {
                    result.push(Action::Mp(i, j));
                } else {
                    result.push(Action::Beta(i));
                }
            }
        } else if matches!(
            f.view().graph_node(),
            naome_foundation::graph::Node::ForAll(_)
        ) {
            for v in &state.domain {
                result.push(Action::Instantiate(i, v.identifier()));
            }
        }
        if let Some((from, to)) = f.view().equality_variables()
            && from != to
        {
            for (j, g) in state.facts.iter().enumerate() {
                let substituted = g.clone().substitute_free(from, to);
                if substituted != *g && !state.facts.contains(&substituted) {
                    result.push(Action::Substitute(i, j));
                }
            }
        }
    }
    result.retain(|a| !state.used.contains(a));
    result.truncate(16);
    result
}

fn decision(
    goal: &Formula,
    state: &State,
    actions: &[Action],
    expert: usize,
) -> Result<Decision, String> {
    let context: Vec<_> = state
        .facts
        .iter()
        .map(|formula| Binding {
            formula: formula.clone(),
        })
        .collect();
    let mut candidates = Vec::new();
    for a in actions {
        let (rule, premises) = match *a {
            Action::Double(i) => (Rule::DoubleNegation, vec![i]),
            Action::NotImp(i) => (Rule::NegatedImplication, vec![i]),
            Action::Mp(i, j) => (Rule::ModusPonens, vec![i, j]),
            Action::Beta(i) => (Rule::ImplicationBranch, vec![i]),
            Action::Instantiate(i, _) => (Rule::UniversalInstance, vec![i]),
            Action::Substitute(i, j) => (Rule::EqualitySubstitution, vec![i, j]),
        };
        let mut consequences = Vec::new();
        // Features are derived from the same bounded transition used by live
        // search and proof replay. They contain no future proof or label.
        for child in next(state, a)? {
            for formula in child.facts.into_iter().skip(state.facts.len()) {
                if !consequences.contains(&formula) {
                    consequences.push(formula);
                }
            }
        }
        candidates.push(Candidate {
            rule,
            premises,
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

fn next(state: &State, action: &Action) -> Result<Vec<State>, String> {
    let mut state = state.clone();
    state.used.insert(action.clone());
    match *action {
        Action::Double(i) => {
            let f = state.facts[i]
                .view()
                .negated()
                .and_then(|g| g.negated())
                .ok_or("double action mismatch")?
                .to_owned();
            insert(&mut state, f);
        }
        Action::NotImp(i) => {
            let (a, b) = state.facts[i]
                .view()
                .negated()
                .and_then(|g| g.implication_parts())
                .ok_or("not implication action mismatch")?;
            let a = a.to_owned();
            let b = c::not(b.to_owned());
            insert(&mut state, a);
            insert(&mut state, b);
        }
        Action::Mp(i, j) => {
            let (a, b) = state.facts[i]
                .view()
                .implication_parts()
                .ok_or("MP action mismatch")?;
            if a != state.facts[j].view() {
                return Err("MP premise mismatch".into());
            }
            let b = b.to_owned();
            insert(&mut state, b);
        }
        Action::Beta(i) => {
            let (a, b) = state.facts[i]
                .view()
                .implication_parts()
                .ok_or("beta action mismatch")?;
            let a = c::not(a.to_owned());
            let b = b.to_owned();
            let mut other = state.clone();
            insert(&mut state, a);
            insert(&mut other, b);
            return Ok(vec![state, other]);
        }
        Action::Instantiate(i, v) => {
            let f = &state.facts[i];
            let x = fresh(std::iter::once(f.clone()))?;
            let f = f
                .open_outer_universal(x)
                .ok_or("universal action mismatch")?
                .substitute_free(x, FreeVariable::new(v));
            insert(&mut state, f);
        }
        Action::Substitute(i, j) => {
            let (a, b) = state.facts[i]
                .view()
                .equality_variables()
                .ok_or("equality action mismatch")?;
            let f = state.facts[j].clone().substitute_free(a, b);
            insert(&mut state, f);
        }
    }
    Ok(vec![state])
}

pub struct ResultTree {
    pub tree: Option<Tree>,
    pub expansions: usize,
    pub failure: Option<String>,
}
struct Search<'a> {
    ranker: &'a mut dyn Ranker,
    goal: Formula,
    started: Instant,
    expansions: usize,
    maximum: usize,
    failure: Option<String>,
}
impl Search<'_> {
    fn prove(&mut self, state: &State, depth: usize) -> Result<Option<Tree>, String> {
        if self.expansions >= self.maximum
            || self.started.elapsed() > Duration::from_millis(2500)
            || depth > 32
        {
            self.failure = Some("search_budget".into());
            return Ok(None);
        }
        if let Some((a, b)) = close(state) {
            return Ok(Some(Tree::Close(a, b)));
        }
        if state.facts.len() > 32 {
            self.failure = Some("fact_resource".into());
            return Ok(None);
        }
        let actions = actions(state);
        if actions.is_empty() {
            return Ok(None);
        }
        let d = decision(&self.goal, state, &actions, 0)?;
        if let Err(e) = Graph::encode(&d) {
            self.failure = Some(e);
            return Ok(None);
        }
        let scores = if actions.len() > 1 {
            self.ranker.scores(&d)?
        } else {
            vec![0.]
        };
        if scores.len() != actions.len() || scores.iter().any(|s| !s.is_finite()) {
            return Err("invalid native action scores".into());
        }
        let mut order: Vec<_> = (0..actions.len()).collect();
        order.sort_by(|a, b| scores[*b].total_cmp(&scores[*a]).then(a.cmp(b)));
        for selected in order {
            if self.expansions >= self.maximum {
                self.failure = Some("search_budget".into());
                break;
            }
            self.expansions += 1;
            let mut children = Vec::new();
            let mut success = true;
            for child in next(state, &actions[selected])? {
                if let Some(tree) = self.prove(&child, depth + 1)? {
                    children.push(tree)
                } else {
                    success = false;
                    break;
                }
            }
            if success {
                return Ok(Some(Tree::Step {
                    action: actions[selected].clone(),
                    children,
                }));
            }
        }
        Ok(None)
    }
}

pub fn solve(
    target: &Formula,
    ranker: &mut dyn Ranker,
    maximum: usize,
) -> Result<ResultTree, String> {
    if let Some((index, _)) = AXIOMS
        .iter()
        .enumerate()
        .find(|(_, axiom)| axiom.formula() == *target)
    {
        return Ok(ResultTree {
            tree: Some(Tree::Axiom(index as u8)),
            expansions: 1,
            failure: None,
        });
    }
    let p = prepare(target)?;
    let mut s = Search {
        ranker,
        goal: p.body,
        started: Instant::now(),
        expansions: 0,
        maximum,
        failure: None,
    };
    let tree = s.prove(&p.state, 0)?;
    Ok(ResultTree {
        tree,
        expansions: s.expansions,
        failure: s.failure,
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
    goal: &Formula,
    names: &mut Names,
    graphs: &mut Vec<Graph>,
    depth: usize,
) -> Result<(Term, Term), String> {
    if depth > 40 {
        return Err("native replay depth".into());
    }
    if facts.iter().map(Term::formula).collect::<Vec<_>>() != state.facts {
        return Err("replay formula state mismatch".into());
    }
    if let Tree::Close(a, b) = tree {
        let p = facts.get(*a).ok_or("closing positive index")?;
        let n = facts.get(*b).ok_or("closing negative index")?;
        if n.formula() != c::not(p.formula()) {
            return Err("forged tableau closure".into());
        }
        return Ok((p.clone(), n.clone()));
    }
    let Tree::Step { action, children } = tree else {
        return Err("unsupported nested axiom trace".into());
    };
    let offered = actions(state);
    let expert = offered
        .iter()
        .position(|a| a == action)
        .ok_or("replay action not offered")?;
    if offered.len() > 1 {
        graphs.push(Graph::encode(&decision(goal, state, &offered, expert)?)?);
    }
    let states = next(state, action)?;
    if states.len() != children.len() {
        return Err("replay branch arity mismatch".into());
    }
    let mut updated = facts.to_vec();
    match *action {
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
        Action::Substitute(i, j) => {
            let f = facts[i].formula();
            let (a, b) = f.view().equality_variables().ok_or("replay equality")?;
            add_term(
                &mut updated,
                c::substitute(facts[i].clone(), facts[j].clone(), a, b)?,
            );
        }
        Action::Beta(i) => {
            let f = facts[i].formula();
            let (a, b) = f.view().implication_parts().ok_or("replay beta")?;
            let a = a.to_owned();
            let b = b.to_owned();
            let (id, na) = names.assumption(c::not(a.clone()));
            let mut left = facts.to_vec();
            add_term(&mut left, na);
            let (p, n) = replay(
                &children[0],
                &states[0],
                &left,
                goal,
                names,
                graphs,
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
                goal,
                names,
                graphs,
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
        goal,
        names,
        graphs,
        depth + 1,
    )
}

pub fn compile(target: &Formula, tree: &Tree) -> Result<(Term, Vec<Graph>), String> {
    if let Tree::Axiom(index) = tree {
        let axiom = *AXIOMS.get(*index as usize).ok_or("unknown native axiom")?;
        if axiom.formula() != *target {
            return Err("axiom target differs".into());
        }
        return Ok((c::axiom(ProofStep::ZfcAxiom(axiom))?, Vec::new()));
    }
    let p = prepare(target)?;
    let mut names = Names::default();
    let mut facts = Vec::new();
    let mut wrappers = Vec::new();
    for w in &p.wrap {
        match w {
            Wrap::Universal(v) => wrappers.push((Some(*v), 0, None)),
            Wrap::Assumption(f) => {
                let (id, t) = names.assumption(f.clone());
                facts.push(t);
                wrappers.push((None, id, Some(f.clone())));
            }
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
    let (a, b) = replay(tree, &p.state, &facts, &p.body, &mut names, &mut graphs, 0)?;
    let mut term = if a.formula() == p.body && !a.free_assumptions().contains_key(&root) {
        a
    } else {
        c::raa(p.body, root, a, b, &mut names)?
    };
    for (v, id, f) in wrappers.into_iter().rev() {
        term = if let Some(v) = v {
            Term::Generalize(v, Box::new(term))
        } else {
            Term::Lambda(id, f.ok_or("assumption wrapper")?, Box::new(term))
        };
    }
    for _ in 0..p.double {
        term = c::double_intro(term, &mut names)?;
    }
    if term.formula() != *target {
        return Err("compiled native target mismatch".into());
    }
    Ok((term, graphs))
}

const AXIOMS: [naome_foundation::ZfcAxiom; 7] = [
    naome_foundation::ZfcAxiom::Extensionality,
    naome_foundation::ZfcAxiom::Pairing,
    naome_foundation::ZfcAxiom::Union,
    naome_foundation::ZfcAxiom::PowerSet,
    naome_foundation::ZfcAxiom::Infinity,
    naome_foundation::ZfcAxiom::Foundation,
    naome_foundation::ZfcAxiom::Choice,
];
pub fn axiom_name(a: naome_foundation::ZfcAxiom) -> &'static str {
    use naome_foundation::ZfcAxiom::*;
    match a {
        Extensionality => "extensionality",
        Pairing => "pairing",
        Union => "union",
        PowerSet => "power_set",
        Infinity => "infinity",
        Foundation => "foundation",
        Choice => "choice",
    }
}
