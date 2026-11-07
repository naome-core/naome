//! Replayable choices of goal-derived schemas and checked sources.
use super::super::{
    definitions,
    graph::Graph,
    knowledge,
    model::{Binding, Candidate, Decision, Ranker, Rule},
};
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub known: Vec<knowledge::Entry>,
    pub definitions: Vec<definitions::Entry>,
    pub selected: usize,
}
pub struct Offer {
    pub context: Vec<proof::Term>,
    pub schema_only: bool,
    group: usize,
    priority: usize,
}
pub fn offers(target: &Formula, known: &[knowledge::Entry]) -> Result<Vec<Offer>, String> {
    knowledge::validate(known)?;
    let mut proposals = Vec::new();
    predicates(target, &mut proposals, &mut 0);
    let mut target_fragments = std::collections::BTreeMap::new();
    fragments(target, &mut target_fragments, &mut 0);
    let mut axioms: Vec<_> = super::super::search::AXIOMS
        .into_iter()
        .map(|a| {
            let mut parts = std::collections::BTreeMap::new();
            fragments(&a.formula(), &mut parts, &mut 0);
            let score = parts
                .iter()
                .filter(|(k, _)| target_fragments.contains_key(*k))
                .map(|(_, n)| *n)
                .max()
                .unwrap_or(0);
            (score, a)
        })
        .collect();
    axioms.sort_by_key(|v| std::cmp::Reverse(v.0));
    let mut offers = Vec::new();
    let sources = known
        .iter()
        .map(knowledge::Entry::term)
        .collect::<Result<Vec<_>, _>>()?;
    // A closed conjunction can require more than one independently checked
    // source. Offer their bounded joint context to the existing constructor;
    // source identities, primitive checking and work accounting are unchanged.
    if let Some((a, b)) = super::logic::conjunction(target)
        && a != b
        && let Some(left) = sources.iter().find(|t| t.formula() == a)
        && let Some(right) = sources.iter().find(|t| t.formula() == b)
    {
        offers.push(Offer {
            priority: usize::MAX,
            context: vec![left.clone(), right.clone()],
            schema_only: false,
            group: usize::MAX,
        });
    }
    if proposals.is_empty() {
        for (group, source) in sources.into_iter().enumerate() {
            offers.push(Offer {
                priority: knowledge::relevance(&source.formula(), target),
                context: vec![source],
                schema_only: false,
                group,
            });
        }
    } else {
        for (group, (predicate, element)) in proposals.into_iter().enumerate() {
            let source = fresh(&predicate, &[element]);
            let result = fresh(&predicate, &[element, source]);
            let parameters = predicate
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
            offers.push(Offer {
                priority: knowledge::relevance(&term.formula(), target),
                context: vec![term.clone()],
                schema_only: true,
                group,
            });
            for source in &sources {
                offers.push(Offer {
                    priority: knowledge::relevance(&source.formula(), target),
                    context: vec![term.clone(), source.clone()],
                    schema_only: false,
                    group,
                });
            }
            for (priority, axiom) in &axioms {
                offers.push(Offer {
                    priority: *priority,
                    context: vec![term.clone(), c::axiom(ProofStep::ZfcAxiom(*axiom))?],
                    schema_only: false,
                    group,
                });
            }
        }
    }
    // Bound complete plans before neural scoring; each source/schema remains a
    // primitive generator or an independently checked, closed theorem.
    let mut ranked: Vec<_> = offers.into_iter().enumerate().collect();
    ranked.sort_by(|a, b| b.1.priority.cmp(&a.1.priority).then(a.0.cmp(&b.0)));
    let mut groups = std::collections::BTreeSet::new();
    let mut selected = std::collections::BTreeSet::new();
    for (i, offer) in &ranked {
        if groups.insert(offer.group) && selected.len() < 16 {
            selected.insert(*i);
        }
    }
    for (i, _) in &ranked {
        if selected.len() >= 16 {
            break;
        }
        selected.insert(*i);
    }
    Ok(ranked
        .into_iter()
        .filter(|(i, _)| selected.contains(i))
        .map(|(_, offer)| offer)
        .collect())
}
fn features(target: &Formula, offers: &[Offer], selected: usize) -> Decision {
    let mut context: Vec<Binding> = Vec::new();
    let mut candidates = Vec::new();
    for offer in offers {
        let mut premises = Vec::new();
        for term in &offer.context {
            let formula = term.formula();
            let i = context
                .iter()
                .position(|b| b.formula == formula)
                .unwrap_or_else(|| {
                    context.push(Binding { formula });
                    context.len() - 1
                });
            premises.push(i);
        }
        candidates.push(Candidate {
            rule: Rule::ConstructionPlan,
            premises,
            consequences: Vec::new(),
        });
    }
    Decision {
        context,
        candidates,
        goal: target.clone(),
        expert: selected,
    }
}
pub fn order(
    target: &Formula,
    offers: &[Offer],
    ranker: &mut dyn Ranker,
) -> Result<Vec<usize>, String> {
    let mut order: Vec<_> = (0..offers.len()).collect();
    if offers.len() > 1 {
        let decision = features(target, offers, 0);
        if Graph::encode(&decision).is_ok() {
            let scores = ranker.scores(&decision)?;
            if scores.len() != offers.len() || scores.iter().any(|s| !s.is_finite()) {
                return Err("construction plan scores differ".into());
            }
            order.sort_by(|a, b| scores[*b].total_cmp(&scores[*a]).then(a.cmp(b)));
        }
    }
    Ok(order)
}
fn key(f: &Formula) -> Vec<u8> {
    let mut names = std::collections::BTreeMap::new();
    f.clone()
        .map_free_variables(|v| {
            let next = FreeVariable::new(names.len() as u32);
            *names.entry(v).or_insert(next)
        })
        .encode_canonical()
        .expect("bounded checked formula")
}
pub fn used(selected: &Offer, verified: &proof::Verified) -> Result<bool, String> {
    let context = proof::lemma_context(&verified.definitions, &verified.lemmas)?;
    for term in &selected.context {
        let used = match term {
            proof::Term::Kernel(kernel) => {
                let wanted = key(&kernel.formula());
                verified
                    .lemmas
                    .iter()
                    .chain(std::iter::once(&verified.certificate))
                    .flat_map(|c| c.steps())
                    .any(|step| {
                        proof::Kernel::with_context(step.clone(), &context)
                            .is_ok_and(|k| key(&k.formula()) == wanted)
                    })
            }
            proof::Term::Native { target, .. } => {
                let id = proof::verify(term, target)?.native_id;
                verified.native_id == id || verified.lemmas.iter().chain(std::iter::once(&verified.certificate)).flat_map(|c| c.steps()).any(|step|
                    matches!(step, ProofStep::ProofReference { proof_id } if *proof_id == id))
            }
            _ => return Err("construction plan source is not closed".into()),
        };
        if !used {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn graph(
    target: &Formula,
    selection: &Selection,
    verified: &proof::Verified,
) -> Result<Option<Graph>, String> {
    let _ = definitions::context(&selection.definitions)?;
    let offers = offers(target, &selection.known)?;
    let selected = offers
        .get(selection.selected)
        .ok_or("construction plan index")?;
    if !used(selected, verified)? {
        return Ok(None);
    }
    if offers.len() < 2 {
        return Ok(None);
    }
    let decision = features(target, &offers, selection.selected);
    let Ok(mut graph) = Graph::encode(&decision) else {
        return Ok(None);
    };
    graph.binding = super::super::digest(&(
        target.encode_canonical().map_err(|e| e.to_string())?,
        &selection.known,
        &selection.definitions,
    ));
    Ok(Some(graph))
}

#[cfg(test)]
mod tests;
