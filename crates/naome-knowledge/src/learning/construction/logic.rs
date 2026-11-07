//! Focused first-order subgoal search. These recipes are untrusted generators.
use super::super::{
    calculus as c,
    proof::{self, Term},
};
use c::Names;
use naome_foundation::{Formula, FreeVariable, graph::Node};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

pub fn conjunction(f: &Formula) -> Option<(Formula, Formula)> {
    let (a, nb) = f.view().negated()?.implication_parts()?;
    Some((a.to_owned(), nb.negated()?.to_owned()))
}
fn contains(formula: &Formula, wanted: &Formula) -> bool {
    if formula == wanted {
        return true;
    }
    match formula.view().graph_node() {
        Node::Not(a) => contains(&a.to_owned(), wanted),
        Node::Implies(a, b) => contains(&a.to_owned(), wanted) || contains(&b.to_owned(), wanted),
        _ => false,
    }
}
pub fn existential(f: &Formula, v: FreeVariable) -> Option<Formula> {
    let universal = f.view().negated()?.to_owned();
    let used = universal.free_variables();
    let binder = (0..=u32::MAX)
        .map(FreeVariable::new)
        .find(|x| *x != v && !used.contains(x))?;
    universal
        .open_outer_universal(binder)?
        .substitute_free(binder, v)
        .view()
        .negated()
        .map(|f| f.to_owned())
}

fn fresh(context: &[Term], goal: &Formula) -> FreeVariable {
    let mut used = goal.free_variables();
    for t in context {
        used.extend(t.formula().free_variables());
    }
    (0..=u32::MAX)
        .map(FreeVariable::new)
        .find(|v| !used.contains(v))
        .unwrap()
}

/// A checked closed sublemma becomes opaque to bracket abstraction, preventing
/// repeated discharge from expanding its derivation. The final checker still
/// checks every emitted primitive step.
fn seal(term: Term) -> Result<Term, String> {
    if !term.free_assumptions().is_empty() {
        return Err("open construction lemma".into());
    }
    let formula = term.formula();
    let verified = proof::verify(&term, &formula)?;
    let mut term = Term::Lemma {
        certificate: verified.certificate,
        target: verified.target,
        dependencies: verified.lemmas,
    };
    for v in formula.free_variables() {
        term = c::instantiate(term, v)?;
    }
    if term.formula() != formula {
        return Err("construction lemma instantiation".into());
    }
    Ok(term)
}
fn project(value: Term, second: bool, names: &mut Names) -> Result<Term, String> {
    let formula = value.formula();
    let (a, b) = conjunction(&formula).ok_or("conjunction projection")?;
    let (id, assumed) = names.assumption(formula.clone());
    let (left, nnb) = c::not_implies(assumed, names)?;
    let result = if second {
        c::double_elim(nnb, names)?
    } else {
        left
    };
    let law = seal(Term::Lambda(id, formula, Box::new(result)))?;
    let result = c::app(law, value)?;
    if result.formula() != if second { b } else { a } {
        return Err("projection result".into());
    }
    Ok(result)
}
fn join(a: Term, b: Term, names: &mut Names) -> Result<Term, String> {
    let af = a.formula();
    let bf = b.formula();
    let (i, av) = names.assumption(af.clone());
    let (j, bv) = names.assumption(bf.clone());
    let implication = Formula::implies(af.clone(), c::not(bf.clone()));
    let (k, h) = names.assumption(implication.clone());
    let nb = c::app(h, av)?;
    let result = c::neg_intro(k, implication, bv, nb, names)?;
    let law = seal(Term::Lambda(
        i,
        af,
        Box::new(Term::Lambda(j, bf, Box::new(result))),
    ))?;
    c::app(c::app(law, a)?, b)
}
fn exists_intro(
    goal: &Formula,
    v: FreeVariable,
    body: Term,
    names: &mut Names,
) -> Result<Term, String> {
    let bf = body.formula();
    let (j, b) = names.assumption(bf.clone());
    let all = goal.view().negated().ok_or("existential goal")?.to_owned();
    let (i, h) = names.assumption(all.clone());
    let negative = c::instantiate(h, v)?;
    let result = c::neg_intro(i, all, b, negative, names)?;
    let law = seal(Term::Lambda(j, bf, Box::new(result)))?;
    c::app(law, body)
}
fn eliminate(
    value: Term,
    v: FreeVariable,
    id: usize,
    result: Term,
    names: &mut Names,
) -> Result<Term, String> {
    let goal = result.formula();
    let body = existential(&value.formula(), v).ok_or("existential premise")?;
    let (i, ng) = names.assumption(c::not(goal.clone()));
    let negative = c::neg_intro(id, body, result, ng, names)?;
    let all = Term::Generalize(v, Box::new(negative));
    c::raa(goal, i, all, value, names)
}
fn exists_elim(
    value: Term,
    v: FreeVariable,
    id: usize,
    result: Term,
    names: &mut Names,
) -> Result<Term, String> {
    let goal = result.formula();
    if goal.free_variables().contains(&v) {
        return Err("existential eigenvariable escapes".into());
    }
    let body = existential(&value.formula(), v).ok_or("existential elimination")?;
    let bridge = Term::Generalize(
        v,
        Box::new(Term::Lambda(id, body.clone(), Box::new(result))),
    );
    let all = bridge.formula();
    let (i, h) = names.assumption(all.clone());
    let ef = value.formula();
    let (j, e) = names.assumption(ef.clone());
    let (k, p) = names.assumption(body);
    let consequence = c::app(c::instantiate(h, v)?, p)?;
    let result = eliminate(e, v, k, consequence, names)?;
    let law = seal(Term::Lambda(
        i,
        all,
        Box::new(Term::Lambda(j, ef, Box::new(result))),
    ))?;
    c::app(c::app(law, bridge)?, value)
}

fn instances(
    term: &Term,
    domain: &BTreeSet<FreeVariable>,
    goal: &Formula,
) -> Result<Vec<Term>, String> {
    let original = term.formula().free_variables();
    let wanted = goal.free_variables();
    let mut choices = Vec::new();
    for v in domain {
        let instance = c::instantiate(term.clone(), *v)?;
        let shared = instance
            .formula()
            .free_variables()
            .intersection(&wanted)
            .count();
        choices.push((shared, !original.contains(v), v.identifier(), instance));
    }
    choices.sort_by_key(|b| std::cmp::Reverse((b.0, b.1, b.2)));
    Ok(choices
        .into_iter()
        .take(16)
        .map(|(_, _, _, term)| term)
        .collect())
}

pub struct Search {
    pub work: usize,
    maximum: usize,
    started: Instant,
    names: Names,
}
impl Search {
    pub fn new(maximum: usize, started: Instant) -> Self {
        Self {
            work: 0,
            maximum,
            started,
            names: Names::default(),
        }
    }
    fn spend(&mut self, depth: usize) -> bool {
        if self.work >= self.maximum
            || depth > 32
            || self.started.elapsed() > Duration::from_millis(2500)
        {
            return false;
        }
        self.work += 1;
        true
    }
    pub fn prove(&mut self, goal: &Formula, context: &[Term]) -> Result<Option<Term>, String> {
        self.visit(goal, context, BTreeSet::new(), 0)
    }
    fn visit(
        &mut self,
        goal: &Formula,
        context: &[Term],
        used: BTreeSet<Vec<u8>>,
        depth: usize,
    ) -> Result<Option<Term>, String> {
        if !self.spend(depth) || context.len() > 32 {
            return Ok(None);
        }
        #[cfg(test)]
        if std::env::var_os("NAOME_CONSTRUCTION_TRACE").is_some() {
            eprintln!(
                "visit {} depth={depth} context={} goal={}",
                self.work,
                context.len(),
                goal.to_source()
            );
        }
        if let Some(t) = context.iter().find(|t| t.formula() == *goal) {
            return Ok(Some(t.clone()));
        }
        if let Some((a, b)) = goal.view().equality_variables()
            && a == b
        {
            return Ok(Some(c::axiom(
                naome_proof::ProofStep::EqualityReflexivity { variable: a },
            )?));
        }
        // Invertible left rules preserve the complete original context.
        for t in context {
            let f = t.formula();
            if let Some((a, b)) = conjunction(&f)
                && contains(&f, goal)
            {
                let mut next = context.to_vec();
                for (part, second) in [(a, false), (b, true)] {
                    if !next.iter().any(|t| t.formula() == part) {
                        next.push(project(t.clone(), second, &mut self.names)?);
                    }
                }
                if next.len() > context.len() {
                    return self.visit(goal, &next, used, depth + 1);
                }
            }
            if let Some((a, b)) = f.view().implication_parts()
                && !context.iter().any(|t| t.formula().view() == b)
                && let Some(p) = context.iter().find(|t| t.formula().view() == a)
            {
                let mut next = context.to_vec();
                next.push(c::app(t.clone(), p.clone())?);
                return self.visit(goal, &next, used, depth + 1);
            }
        }
        let v = fresh(context, goal);
        let mut domain = goal.free_variables();
        for t in context {
            domain.extend(t.formula().free_variables());
        }
        if domain.is_empty() {
            domain.insert(v);
        }
        // Use a relevant available lemma before decomposing its conclusion.
        for t in context.iter().rev() {
            if matches!(t.formula().view().graph_node(), Node::ForAll(_)) {
                for instance in instances(t, &domain, goal)? {
                    let f = instance.formula();
                    if contains(&f, goal) && !context.iter().any(|t| t.formula() == f) {
                        let mut next = context.to_vec();
                        next.push(instance);
                        if let Some(result) = self.visit(goal, &next, used.clone(), depth + 1)? {
                            return Ok(Some(result));
                        }
                    }
                }
            }
        }
        if let Some(body) = goal.open_outer_universal(v) {
            return Ok(self
                .visit(&body, context, used, depth + 1)?
                .map(|t| Term::Generalize(v, Box::new(t))));
        }
        if let Some((a, b)) = goal.view().implication_parts() {
            let a = a.to_owned();
            let b = b.to_owned();
            let (id, t) = self.names.assumption(a.clone());
            let mut next = context.to_vec();
            next.push(t);
            return Ok(self
                .visit(&b, &next, used, depth + 1)?
                .map(|t| Term::Lambda(id, a, Box::new(t))));
        }
        if let Some((a, b)) = conjunction(goal) {
            if let Some(left) = self.visit(&a, context, used.clone(), depth + 1)?
                && let Some(right) = self.visit(&b, context, used.clone(), depth + 1)?
            {
                return Ok(Some(join(left, right, &mut self.names)?));
            }
            return Ok(None);
        }
        for t in context {
            if let Some(body) = existential(&t.formula(), v) {
                let key = t.formula().encode_canonical().map_err(|e| e.to_string())?;
                if used.contains(&key) {
                    continue;
                }
                let mut next_used = used.clone();
                next_used.insert(key);
                let (id, witness) = self.names.assumption(body);
                let mut next = context.to_vec();
                next.push(witness);
                if let Some(result) = self.visit(goal, &next, next_used, depth + 1)? {
                    return Ok(Some(exists_elim(
                        t.clone(),
                        v,
                        id,
                        result,
                        &mut self.names,
                    )?));
                }
            }
        }
        // Backward chaining keeps irrelevant universal instances out of the
        // bounded fact set. Candidate variables come only from this sequent.
        if existential(goal, v).is_some() {
            for d in domain.iter().rev() {
                let body = existential(goal, *d).ok_or("existential opening")?;
                if let Some(term) = self.visit(&body, context, used.clone(), depth + 1)? {
                    return Ok(Some(exists_intro(goal, *d, term, &mut self.names)?));
                }
            }
        }
        for t in context.iter().rev() {
            if let Some((a, b)) = t.formula().view().implication_parts()
                && b == goal.view()
                && let Some(a) = self.visit(&a.to_owned(), context, used.clone(), depth + 1)?
            {
                return Ok(Some(c::app(t.clone(), a)?));
            }
            if matches!(t.formula().view().graph_node(), Node::ForAll(_)) {
                for instance in instances(t, &domain, goal)? {
                    let f = instance.formula();
                    if context.iter().any(|t| t.formula() == f) {
                        continue;
                    }
                    // Prefer instances whose eventual consequent is the goal.
                    let relevant = contains(&f, goal)
                        || (existential(goal, v).is_some()
                            && (existential(&f, v).is_some()
                                || matches!(f.view().graph_node(), Node::ForAll(_))));
                    if !relevant {
                        continue;
                    }
                    let mut next = context.to_vec();
                    next.push(instance);
                    if let Some(result) = self.visit(goal, &next, used.clone(), depth + 1)? {
                        return Ok(Some(result));
                    }
                }
            }
        }
        for p in context {
            if let Some(n) = context.iter().find(|n| n.formula() == c::not(p.formula())) {
                return Ok(Some(c::explosion(
                    p.clone(),
                    n.clone(),
                    goal.clone(),
                    &mut self.names,
                )?));
            }
        }
        Ok(None)
    }
}
