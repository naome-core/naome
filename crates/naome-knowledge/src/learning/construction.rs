//! Goal-derived ZFC schema proposals and independently checked subgoal search.
//! No theorem name, question identity, or natural-number recipe is recognized.
use super::evidence;
pub(super) mod composition;
pub(in crate::learning) mod logic;
mod repair;
mod representation;
pub(super) mod selection;
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
#[cfg(test)]
pub fn construct(
    target: &Formula,
    maximum: usize,
    started: std::time::Instant,
) -> Result<(Option<proof::Verified>, usize), String> {
    struct Ordered;
    impl super::model::Ranker for Ordered {
        fn scores(&mut self, d: &super::model::Decision) -> Result<Vec<f32>, String> {
            Ok(vec![0.; d.candidates.len()])
        }
    }
    let (proof, work, _) = construct_with(target, maximum, started, &mut Ordered, &[], &[])?;
    Ok((proof, work))
}
pub fn construct_with(
    target: &Formula,
    maximum: usize,
    started: std::time::Instant,
    ranker: &mut dyn super::model::Ranker,
    known: &[super::knowledge::Entry],
    definitions: &[super::definitions::Entry],
) -> Result<(Option<proof::Verified>, usize, Option<selection::Selection>), String> {
    let choices = super::definitions::construction_choices(target, definitions)?;
    let protected = super::knowledge::proof_ids(known)?;
    construct_candidate(
        target,
        maximum,
        started,
        ranker,
        ConstructionContext {
            known,
            definitions,
            native: false,
        },
        |term, offer, direct| {
            let verified = proof::verify(term, target)?;
            if !direct && !selection::used(offer, &verified)? {
                return Ok(None);
            }
            if direct || verified.definitions.is_empty() {
                return representation::apply(verified, &choices, &protected).map(Some);
            }
            Ok(Some(verified))
        },
    )
}

pub(super) struct ProgramCandidate {
    pub packet: super::peer::Packet,
    pub helpers: Vec<String>,
}

pub(super) fn construct_program(
    target: &Formula,
    maximum: usize,
    started: std::time::Instant,
    ranker: &mut dyn super::model::Ranker,
    known: &[super::knowledge::Entry],
    definitions: &[super::definitions::Entry],
) -> Result<(Option<ProgramCandidate>, usize), String> {
    let choices = super::definitions::construction_choices(target, definitions)?;
    let (candidate, work, _) = construct_candidate(
        target,
        maximum,
        started,
        ranker,
        ConstructionContext {
            known,
            definitions,
            native: true,
        },
        |term, offer, direct| {
            let mut recipe = proof::recipe(term, target)?;
            if !direct && !selection::used_recipe(offer, &recipe)? {
                return Ok(None);
            }
            for entry in &choices {
                if !recipe.definitions.contains(entry) {
                    recipe.definitions.push(entry.clone());
                }
            }
            program_from_recipe(target, recipe).map(Some)
        },
    )?;
    Ok((candidate, work))
}

pub(super) fn program_from_recipe(
    target: &Formula,
    recipe: proof::Recipe,
) -> Result<ProgramCandidate, String> {
    program_from_recipe_with_inputs(target, recipe, &[], [], None)
}

pub(super) fn program_from_recipe_with_inputs(
    target: &Formula,
    recipe: proof::Recipe,
    programs: &[super::peer::Packet],
    inputs: impl IntoIterator<Item = std::sync::Arc<[u8]>>,
    inline: Option<naome_proof::ProofId>,
) -> Result<ProgramCandidate, String> {
    let (steps, helpers) = program_recipe(recipe, inline)?;
    let commands = naome_proof::program::Projection::from_inference_steps(&steps)?.into_commands();
    let artifacts = helpers
        .iter()
        .map(|source| {
            crate::unhex(source)
                .map(std::sync::Arc::from)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let packet = super::peer::Packet::compose(
        target,
        &commands,
        programs,
        inputs.into_iter().chain(artifacts),
    )?;
    Ok(ProgramCandidate { packet, helpers })
}

// Newly synthesized helper derivations can share the root's native command
// graph. Original bounded artifact references keep their concrete identity.
fn program_recipe(
    recipe: proof::Recipe,
    inline: Option<naome_proof::ProofId>,
) -> Result<(Vec<ProofStep>, Vec<String>), String> {
    use std::collections::{BTreeMap, BTreeSet};
    fn append(
        output: &mut Vec<ProofStep>,
        input: &[ProofStep],
        aliases: &BTreeMap<naome_proof::ProofId, u32>,
    ) -> Result<u32, String> {
        let mut positions = Vec::with_capacity(input.len());
        for step in input {
            let at = |index: u32| {
                positions
                    .get(index as usize)
                    .copied()
                    .ok_or("native helper forward operand")
            };
            let step = match step {
                ProofStep::ProofReference { proof_id } if aliases.contains_key(proof_id) => {
                    positions.push(aliases[proof_id]);
                    continue;
                }
                ProofStep::ModusPonens {
                    premise,
                    implication,
                } => ProofStep::ModusPonens {
                    premise: at(*premise)?,
                    implication: at(*implication)?,
                },
                ProofStep::Generalization { premise, variable } => ProofStep::Generalization {
                    premise: at(*premise)?,
                    variable: *variable,
                },
                other => other.clone(),
            };
            positions.push(u32::try_from(output.len()).map_err(|_| "native helper operand width")?);
            output.push(step);
        }
        positions
            .last()
            .copied()
            .ok_or("empty native helper recipe".into())
    }
    let mut context = super::definitions::context(&recipe.definitions)?;
    let mut output = Vec::new();
    let mut aliases = BTreeMap::new();
    let mut kept = Vec::new();
    for certificate in recipe.lemmas {
        let checked = proof::check(certificate, &context).map_err(|error| error.to_string())?;
        let id = checked.proof_id();
        if context.contains_proof(id) {
            continue;
        }
        let certificate = checked.normal_form().certificate();
        let needs_inlined = certificate.steps().iter().any(|step| {
            matches!(step, ProofStep::ProofReference { proof_id } if aliases.contains_key(proof_id))
        });
        if inline == Some(id)
            || needs_inlined
            || checked.normal_form().canonical_bytes().len() + 1
                > crate::resources::limits().proof_bytes
        {
            let commands = proof::define_steps(certificate.steps(), &recipe.definitions)?;
            let position = append(&mut output, &commands, &aliases)?;
            aliases.insert(id, position);
        } else {
            kept.push(certificate.clone());
        }
        context
            .register_proof_for_replication(checked)
            .map_err(|error| error.to_string())?;
    }
    let root = proof::define_steps(&recipe.steps, &recipe.definitions)?;
    let conclusion = append(&mut output, &root, &aliases)?;
    if conclusion as usize + 1 != output.len() {
        return Err("native helper root differs".into());
    }
    let used = output
        .iter()
        .chain(kept.iter().flat_map(|proof| proof.steps()))
        .flat_map(ProofStep::definition_references)
        .collect::<BTreeSet<_>>();
    let definitions = recipe
        .definitions
        .into_iter()
        .filter(|entry| {
            entry
                .certificate()
                .is_ok_and(|definition| used.contains(&definition.definition_id()))
        })
        .collect::<Vec<_>>();
    let mut helpers = Vec::new();
    super::definitions::append_artifacts(&definitions, &mut helpers)?;
    for lemma in proof::lemma_sources(&definitions, &kept)? {
        if !helpers.contains(&lemma) {
            helpers.push(lemma);
        }
    }
    Ok((output, helpers))
}

struct ConstructionContext<'a> {
    known: &'a [super::knowledge::Entry],
    definitions: &'a [super::definitions::Entry],
    native: bool,
}

fn construct_candidate<T>(
    target: &Formula,
    maximum: usize,
    started: std::time::Instant,
    ranker: &mut dyn super::model::Ranker,
    context: ConstructionContext<'_>,
    mut finish: impl FnMut(&proof::Term, &selection::Offer, bool) -> Result<Option<T>, String>,
) -> Result<(Option<T>, usize, Option<selection::Selection>), String> {
    if maximum == 0 {
        return Ok((None, 0, None));
    }
    let offers = selection::offers(target, context.known)?;
    if offers.is_empty() {
        return Ok((None, 0, None));
    }
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
    for selected in selection::order(target, &offers, ranker)? {
        let offer = &offers[selected];
        let selection = selection::Selection {
            known: context.known.to_vec(),
            definitions: context.definitions.to_vec(),
            selected,
        };
        if let Some(term) = offer.context.iter().find(|t| t.formula() == *target)
            && let Some(candidate) = finish(term, offer, true)?
        {
            return Ok((Some(candidate), work + 1, Some(selection)));
        }
        let allowance = if offer.schema_only && !has_bound {
            16.min(maximum.saturating_sub(work))
        } else {
            maximum.saturating_sub(work)
        };
        let mut search = logic::Search::new(allowance, started);
        if context.native {
            search = search.native();
        }
        let found = search.prove(target, &offer.context)?;
        work += search.work;
        if let Some(term) = found
            && let Some(candidate) = finish(&term, offer, false)?
        {
            return Ok((Some(candidate), work, Some(selection)));
        }
        if work >= maximum {
            break;
        }
    }
    Ok((None, work, None))
}

/// Preserve the original packet when it fits. Spend only the unused construction
/// allowance to repair a checked proof with an oversized mathematical object.
pub(super) fn pack_candidate(
    verified: &proof::Verified,
    selection: Option<&selection::Selection>,
    started: std::time::Instant,
    remaining: &mut usize,
) -> Result<Vec<u8>, String> {
    let error = match evidence::pack(verified) {
        Ok(packet) => return Ok(packet),
        Err(error) => error,
    };
    let limit = crate::resources::limits().proof_bytes;
    if verified.payload_bytes <= limit
        && verified
            .lemmas
            .iter()
            .all(|lemma| lemma.to_canonical_bytes().len() <= limit)
    {
        return Err(error);
    }
    let mut budget = repair::Budget::new(started, *remaining);
    let result = repair::portable_packet(verified, selection, &mut budget);
    *remaining -= budget.spent();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separation_is_instantiated_from_the_goal_instead_of_a_named_theorem() {
        let q = naome_checker::question::ResearchQuestion::from_hex(
            "040204020402030301010000000001000000010203010100000000010000000202020101000000000100000000020302030101000000000100000002020201010000000001000000000101000000000100000001",
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
        let compiled =
            crate::learning::proof::check_artifact(&source, &naome_checker::ArtifactState::new())
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
        let tree = super::super::search::Tree::Constructed {
            packet: packet.clone(),
            selection: None,
        };
        let (_, graphs) = super::super::search::compile(&target, &tree).unwrap();
        let question =
            naome_checker::question::ResearchQuestion::from_formula(target.clone()).unwrap();
        eprintln!(
            "Nat native DAG decisions={} eligible_new_lineage={} packet_bytes={}",
            graphs.len(),
            super::super::State::eligible(&question.to_hex()),
            packet.len()
        );
        assert!(
            !graphs.is_empty(),
            "checked construction decisions must reach the learner"
        );
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
        let size = (source.len() + helpers.iter().map(String::len).sum::<usize>()) / 2;
        eprintln!(
            "Nat closure objects={} source_bytes={size} packet_bytes={}",
            helpers.len() + 1,
            packet.len()
        );
        assert!(
            helpers
                .iter()
                .all(|s| s.len() / 2 <= crate::resources::limits().proof_bytes)
        );
        assert!(size <= crate::resources::limits().closure_bytes);
        let question =
            naome_checker::question::ResearchQuestion::from_formula(target.clone()).unwrap();
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
        let mut state = super::super::State::fresh();
        let example = super::super::Example {
            origin: super::super::Origin::Local,
            job: 1,
            question: question.to_hex(),
            proof_id: crate::hex(proof.native_id.as_bytes()),
            refuted: false,
            tree: tree.clone(),
        };
        assert!(
            state.accept(example).unwrap(),
            "an admitted novel construction is eligible to teach its actual decisions"
        );
        let restored: super::super::State =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        restored.validate().unwrap();
        let evidence = super::super::Evidence {
            job: 1,
            proof_id: crate::hex(proof.native_id.as_bytes()),
            trace: tree,
        };
        assert!(
            !restored
                .training_pool(std::slice::from_ref(&evidence))
                .unwrap()
                .is_empty()
        );
        let mut job = restored.job();
        job.training = true;
        job.evidence.push(evidence);
        job.validate().unwrap();
        job.evidence[0].proof_id = "ff".repeat(32);
        assert!(job.validate().is_err());
        let wrong =
            naome_checker::question::ResearchQuestion::from_hex("04020001000000000100000000")
                .unwrap();
        assert!(evidence::compile(wrong.proved_target(), &packet).is_err());
        assert_eq!(solve(&target, 0).unwrap().1, 0);
    }

    #[test]
    fn a_different_nonempty_class_is_bounded_without_a_fixed_zfc_witness() {
        let q=naome_checker::question::ResearchQuestion::from_hex("0403020402010100000001010000000002040204020303010100000000010000000104030101000000030100000000010100000001010000000002030403010100000003010000000001010000000101000000000101000000000100000001").unwrap();
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
        let q = naome_checker::question::ResearchQuestion::from_hex(
            "02040204020303010100000000010000000102010100000000010000000002030201010000000001000000000101000000000100000001",
        )
        .unwrap();
        assert!(solve(q.proved_target(), 128).unwrap().0.is_none());
    }
}
