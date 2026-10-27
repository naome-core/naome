//! Goal-derived ZFC schema proposals and independently checked subgoal search.
//! No theorem name, question identity, or natural-number recipe is recognized.
pub(super) mod evidence;
mod logic;
mod representation;
use super::{calculus as c, proof};
use naome_foundation::{
    Formula, FreeVariable, Separation,
    graph::{Node, Variable},
};
use naome_proof::ProofStep;

fn fresh(formula: &Formula, extra: &[FreeVariable]) -> FreeVariable {
    let mut used = formula.free_variables();
    used.extend(extra);
    (0..=u32::MAX)
        .map(FreeVariable::new)
        .find(|v| !used.contains(v))
        .unwrap()
}
fn predicates(goal: &Formula, result: &mut Vec<(Formula, FreeVariable)>, work: &mut usize) {
    *work += 1;
    if *work > 2048 || result.len() >= 16 {
        return;
    }
    let v = fresh(goal, &[]);
    if let Some((a, b)) = logic::conjunction(goal)
        && let Some((member, predicate)) = a.view().implication_parts()
        && b == Formula::implies(predicate.to_owned(), member.to_owned())
        && let Node::Member(Variable::Free(x), Variable::Free(set)) = member.graph_node()
        && !predicate
            .to_owned()
            .free_variables()
            .contains(&FreeVariable::new(set))
    {
        let element = FreeVariable::new(x);
        if let Some((left, right)) = logic::conjunction(&predicate.to_owned()) {
            for part in [left, right] {
                let candidate = (part, element);
                if !result.contains(&candidate) {
                    result.push(candidate);
                }
            }
        }
        let candidate = (predicate.to_owned(), element);
        if !result.contains(&candidate) {
            result.push(candidate);
        }
    }
    match goal.view().graph_node() {
        Node::Not(a) => predicates(&a.to_owned(), result, work),
        Node::Implies(a, b) => {
            predicates(&a.to_owned(), result, work);
            predicates(&b.to_owned(), result, work);
        }
        Node::ForAll(_) => {
            if let Some(body) = goal.open_outer_universal(v) {
                predicates(&body, result, work);
            }
        }
        _ => {}
    }
}

fn fragments(
    formula: &Formula,
    output: &mut std::collections::BTreeMap<Vec<u8>, usize>,
    work: &mut usize,
) {
    *work += 1;
    if *work > 2048 {
        return;
    }
    let mut names = std::collections::BTreeMap::new();
    let canonical = formula.clone().map_free_variables(|v| {
        let next = names.len() as u32;
        *names.entry(v).or_insert(FreeVariable::new(next))
    });
    if let Ok(bytes) = canonical.encode_canonical() {
        output.insert(bytes, canonical.view().node_count_and_depth().0);
    }
    match formula.view().graph_node() {
        Node::Not(a) => fragments(&a.to_owned(), output, work),
        Node::Implies(a, b) => {
            fragments(&a.to_owned(), output, work);
            fragments(&b.to_owned(), output, work);
        }
        Node::ForAll(_) => {
            if let Some(body) = formula.open_outer_universal(fresh(formula, &[])) {
                fragments(&body, output, work);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
pub fn solve(target: &Formula, maximum: usize) -> Result<(Option<proof::Verified>, usize), String> {
    construct(target, maximum, std::time::Instant::now())
}
pub fn construct(
    target: &Formula,
    maximum: usize,
    started: std::time::Instant,
) -> Result<(Option<proof::Verified>, usize), String> {
    if maximum == 0 {
        return Ok((None, 0));
    }
    let mut proposals = Vec::new();
    predicates(target, &mut proposals, &mut 0);
    if proposals.is_empty() {
        return Ok((None, 0));
    }
    let definitions = super::definitions::discover_many(target, super::definitions::CAPACITY)?;
    let mut schemas = Vec::new();
    for (predicate, element) in proposals {
        let source = fresh(&predicate, &[element]);
        let result = fresh(&predicate, &[element, source]);
        let parameters: Vec<_> = predicate
            .free_variables()
            .into_iter()
            .filter(|v| *v != element)
            .collect();
        let term = c::axiom(ProofStep::Separation(
            Separation {
                predicate,
                element,
                source,
                result,
                parameters,
            }
            .into(),
        ))?;
        if term.formula() == *target {
            return Ok((
                Some(representation::apply(
                    proof::verify(&term, target)?,
                    &definitions,
                )?),
                1,
            ));
        }
        schemas.push(term);
    }
    let mut target_fragments = std::collections::BTreeMap::new();
    fragments(target, &mut target_fragments, &mut 0);
    let mut axioms: Vec<_> = super::search::AXIOMS
        .into_iter()
        .map(|axiom| {
            let mut parts = std::collections::BTreeMap::new();
            fragments(&axiom.formula(), &mut parts, &mut 0);
            let score = parts
                .iter()
                .filter(|(key, _)| target_fragments.contains_key(*key))
                .map(|(_, n)| *n)
                .max()
                .unwrap_or(0);
            (score, axiom)
        })
        .collect();
    axioms.sort_by_key(|b| std::cmp::Reverse(b.0));
    let mut assumptions = target.clone();
    while let Some(body) = assumptions.open_outer_universal(fresh(&assumptions, &[])) {
        assumptions = body;
    }
    let has_bound = assumptions
        .view()
        .implication_parts()
        .is_some_and(|(a, _)| {
            let a = a.to_owned();
            logic::existential(&a, fresh(&a, &[])).is_some()
        });
    let mut work = 0;
    for term in schemas {
        let mut contexts = vec![vec![term.clone()]];
        for (_, axiom) in &axioms {
            contexts.push(vec![term.clone(), c::axiom(ProofStep::ZfcAxiom(*axiom))?]);
        }
        for (position, context) in contexts.into_iter().enumerate() {
            let allowance = if position == 0 && !has_bound {
                16.min(maximum.saturating_sub(work))
            } else {
                maximum.saturating_sub(work)
            };
            let mut search = logic::Search::new(allowance, started);
            let found = search.prove(target, &context)?;
            work += search.work;
            if let Some(term) = found {
                let proof = representation::apply(proof::verify(&term, target)?, &definitions)?;
                return Ok((Some(proof), work));
            }
            if work >= maximum {
                return Ok((None, work));
            }
        }
    }
    Ok((None, work))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separation_is_instantiated_from_the_goal_instead_of_a_named_theorem() {
        let q = naome_authoring::CompiledQuestion::compile(
            "goal=all(a,ex(b,all(x,iff(mem(x,b),and(mem(x,a),not(mem(x,x)))))))",
        )
        .unwrap();
        let (proof, work) = solve(q.proved_target(), 128).unwrap();
        let proof = proof.expect("goal-derived bounded comprehension");
        eprintln!(
            "construction work={work} steps={} bytes={}",
            proof.certificate.steps().len(),
            proof.payload_bytes
        );
        let source = proof::source(&proof).unwrap();
        let compiled = naome_authoring::compile_against_proof_context(
            &source,
            &naome_checker::ArtifactState::new(),
        )
        .unwrap();
        assert_eq!(compiled.proof_id(), proof.native_id);
    }
    #[test]
    fn natural_number_class_gets_a_set_bound_from_zfc_without_a_supplied_witness() {
        let i = FreeVariable::new(9);
        let x = FreeVariable::new(17);
        let w = FreeVariable::new(23);
        let inductive =
            logic::existential(&naome_foundation::ZfcAxiom::Infinity.formula(), i).unwrap();
        let predicate = Formula::for_all(i, Formula::implies(inductive, Formula::member(x, i)));
        let target = Formula::exists(
            w,
            Formula::for_all(x, Formula::biconditional(Formula::member(x, w), predicate)),
        );
        let (proof, work) = solve(&target, 128).unwrap();
        let proof = proof.expect("ZFC must construct a set for the intersection predicate");
        eprintln!(
            "Nat construction work={work} steps={} lemmas={} definitions={} bytes={}",
            proof.certificate.steps().len(),
            proof.lemmas.len(),
            proof.definitions.len(),
            proof.payload_bytes
        );
        assert!(proof.payload_bytes <= crate::resources::limits().proof_bytes);
        let packet = evidence::pack(&proof).unwrap();
        let mut corrupt = packet.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(evidence::compile(&target, &corrupt).is_err());
        let mut oversized = packet.clone();
        oversized[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(evidence::compile(&target, &oversized).is_err());
        let term = evidence::compile(&target, &packet).unwrap();
        assert_eq!(
            proof::verify(&term, &target).unwrap().native_id,
            proof.native_id
        );
        let helpers = evidence::helpers(&packet).unwrap();
        let source = proof::source(&proof).unwrap();
        let size = source.len() + helpers.iter().map(String::len).sum::<usize>();
        eprintln!(
            "Nat closure objects={} source_bytes={size} packet_bytes={}",
            helpers.len() + 1,
            packet.len()
        );
        assert!(
            helpers
                .iter()
                .all(|s| s.len() <= crate::resources::limits().proof_bytes)
        );
        assert!(size <= crate::resources::limits().closure_bytes);
        let question = naome_authoring::CompiledQuestion::from_formula(target.clone()).unwrap();
        let mut graph = crate::Graph::default();
        assert!(
            graph
                .prepare_generated(&source, &helpers[..helpers.len() - 1], &question)
                .is_err()
        );
        assert!(graph.ids().is_empty());
        let (root, batch) = graph
            .prepare_generated(&source, &helpers, &question)
            .unwrap();
        assert!(graph.ids().is_empty());
        graph
            .commit_batch(
                root,
                batch,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            )
            .unwrap();
        assert!(graph.contains(root).unwrap());
        assert!(!proof.definitions.is_empty());
        let wrong = naome_authoring::CompiledQuestion::compile("goal=all(x,not(eq(x,x)))").unwrap();
        assert!(evidence::compile(wrong.proved_target(), &packet).is_err());
        assert_eq!(solve(&target, 0).unwrap().1, 0);
    }

    #[test]
    fn a_different_nonempty_class_is_bounded_without_a_fixed_zfc_witness() {
        let q=naome_authoring::CompiledQuestion::compile("goal=all(a,imp(ex(i,mem(a,i)),ex(w,all(x,iff(mem(x,w),all(i,imp(mem(a,i),mem(x,i))))))))").unwrap();
        let (proof, work) = solve(q.proved_target(), 128).unwrap();
        eprintln!("generic class work={work}");
        let proof = proof.expect("generic nonempty class intersection");
        eprintln!(
            "class construction work={work} steps={} lemmas={} bytes={}",
            proof.certificate.steps().len(),
            proof.lemmas.len(),
            proof.payload_bytes
        );
    }
    #[test]
    fn unbounded_comprehension_is_not_inferred_from_separation() {
        let q = naome_authoring::CompiledQuestion::compile(
            "goal=ex(w,all(x,iff(mem(x,w),not(mem(x,x)))))",
        )
        .unwrap();
        assert!(solve(q.proved_target(), 128).unwrap().0.is_none());
    }
}
