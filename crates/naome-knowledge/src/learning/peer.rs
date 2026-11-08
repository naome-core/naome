//! Replay used native DAG edges, without searching again for their conclusion.
use super::{
    Solution,
    graph::Graph,
    model::{Binding, Candidate, Decision, Rule},
    proof::{self, Kernel, Term},
    search::Tree,
};
use naome_foundation::Formula;
use naome_proof::{ProofCertificate, ProofStep};
use sha2::{Digest, Sha256};

mod program;
pub(crate) use program::{Packet, contributing_proofs};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    Certificate(Vec<u8>),
    Program(Box<Packet>),
}
impl Source {
    pub(crate) fn validate_width(&self) -> Result<(), String> {
        match self {
            Self::Certificate(bytes) if bytes.len() > super::knowledge::BYTES => {
                Err("peer compressed admission capacity".into())
            }
            Self::Certificate(_) => Ok(()),
            Self::Program(packet) => packet.validate_width(),
        }
    }
    pub(crate) fn certificate(&self) -> Option<&[u8]> {
        match self {
            Self::Certificate(bytes) => Some(bytes),
            Self::Program(_) => None,
        }
    }
}

pub(crate) fn extract_source(
    question: &str,
    artifact: &str,
    source: &Source,
) -> Result<Solution, String> {
    let Source::Program(packet) = source else {
        return extract(
            question,
            artifact,
            source.certificate().expect("certificate source"),
        );
    };
    let meter = crate::resources::feedback::Meter::start();
    let question =
        super::ResearchQuestion::from_hex(question).map_err(|error| error.to_string())?;
    if crate::hex(packet.manifest.artifact_id().as_bytes()) != artifact {
        return Err("peer program artifact identity differs".into());
    }
    let replay = packet.replay(question.proved_target())?;
    if replay.graphs.is_empty() {
        return Err("peer program has no supported ambiguous inference".into());
    }
    let sample = meter.finish(0, true);
    let steps = packet.manifest.commands as usize;
    Ok(Solution {
        cost: Box::new(super::GenerationCost {
            original_steps: steps,
            useful_steps: steps,
            unique_states: replay.graphs.unique(),
            core_work: steps,
            generation_micros: sample.elapsed_nanos / 1000,
            process_peak_rss_bytes: sample.peak_rss_bytes,
            ..super::GenerationCost::default()
        }),
        source: String::new(),
        helpers: Vec::new(),
        proof_id: crate::hex(packet.manifest.proof_id().as_bytes()),
        refuted: false,
        tree: Tree::Program(packet.clone()),
    })
}

fn program_binding(
    question: &str,
    artifact: &str,
    packet: &Packet,
    solution: &Solution,
) -> Result<super::ResearchQuestion, crate::Error> {
    let question = super::ResearchQuestion::from_hex(question)?;
    if solution.refuted
        || !solution.source.is_empty()
        || !solution.helpers.is_empty()
        || crate::hex(packet.manifest.artifact_id().as_bytes()) != artifact
        || crate::hex(packet.manifest.proof_id().as_bytes()) != solution.proof_id
        || packet.manifest.conclusion
            != naome_proof::program::formula_hash(question.proved_target())
        || !matches!(&solution.tree, Tree::Program(actual) if **actual == *packet)
    {
        return Err("peer replay source differs from checked program".into());
    }
    Ok(question)
}

/// A retained worker checkpoint binds the exact bytes and claimed result.
/// The journal checks the proof independently before accepting replay.
pub(crate) fn validate_job_source(
    question: &str,
    artifact: &str,
    source: &Source,
    solution: &Solution,
) -> Result<(), crate::Error> {
    match source {
        Source::Program(packet) => {
            program_binding(question, artifact, packet, solution).map(|_| ())
        }
        Source::Certificate(bytes) => {
            validate_solution(question, artifact, bytes, solution).map_err(Into::into)
        }
    }
}

pub(crate) fn validate_source(
    question: &str,
    artifact: &str,
    source: &Source,
    solution: &Solution,
) -> Result<(), crate::Error> {
    let Source::Program(packet) = source else {
        return validate_job_source(question, artifact, source, solution);
    };
    let question = program_binding(question, artifact, packet, solution)?;
    let replay = packet.replay(question.proved_target())?;
    if replay.graphs.is_empty() {
        return Err("peer program has no supported ambiguous inference".into());
    }
    Ok(())
}

pub(super) fn program_graphs(target: &Formula, packet: &Packet) -> Result<Vec<Graph>, String> {
    Ok(packet.replay(target)?.graphs.materialize())
}
pub(super) fn program_states(target: &Formula, packet: &Packet) -> Result<usize, String> {
    Ok(packet.replay(target)?.graphs.unique())
}
pub(super) fn program_definitions(
    target: &Formula,
    packet: &Packet,
) -> Result<Vec<naome_proof::DefinitionId>, String> {
    Ok(packet.replay(target)?.definitions.clone())
}

std::thread_local! { static VERIFIED: std::cell::RefCell<std::collections::BTreeSet<String>> = const { std::cell::RefCell::new(std::collections::BTreeSet::new()) }; }
pub fn validate_solution(
    question: &str,
    artifact: &str,
    bytes: &[u8],
    solution: &Solution,
) -> Result<(), String> {
    let key = super::digest(&(question, artifact, bytes, solution));
    if VERIFIED.with(|cache| cache.borrow().contains(&key)) {
        return Ok(());
    }
    let expected = extract(question, artifact, bytes)?;
    if solution.refuted
        || !matches_artifact(&solution.proof_id, artifact, bytes)?
        || super::digest(&solution.tree) != super::digest(&expected.tree)
        || crate::hex(solution.checked()?.proof_id().as_bytes()) != solution.proof_id
    {
        return Err("peer replay source differs from checked native DAG".into());
    }
    VERIFIED.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= 128 {
            cache.pop_first();
        }
        cache.insert(key);
    });
    Ok(())
}
#[cfg(test)]
pub fn pack(bytes: &[u8], definitions: &[super::definitions::Entry]) -> Result<Vec<u8>, String> {
    pack_closure(bytes, &[], definitions)
}
#[cfg(test)]
pub fn pack_closure(
    bytes: &[u8],
    lemmas: &[ProofCertificate],
    definitions: &[super::definitions::Entry],
) -> Result<Vec<u8>, String> {
    let certificate = ProofCertificate::from_canonical_bytes(bytes).map_err(|e| e.to_string())?;
    let context = proof::lemma_context(definitions, lemmas)?;
    let checked =
        crate::learning::proof::check(certificate, &context).map_err(|e| e.to_string())?;
    let verified = proof::verify(
        &Term::Native {
            certificate: checked.normal_form().certificate().clone(),
            lemmas: lemmas.to_vec(),
            definitions: definitions.to_vec(),
            target: checked.conclusion().clone(),
        },
        checked.conclusion(),
    )?;
    let packed = super::evidence::pack(&verified)?;
    if packed.len() > 8 * 1024 {
        return Err("peer compressed replay capacity".into());
    }
    Ok(packed)
}
pub fn definitions(bytes: &[u8]) -> Result<Vec<super::definitions::Entry>, String> {
    super::evidence::selected(bytes)
}
pub fn step_count(bytes: &[u8]) -> usize {
    super::evidence::steps(bytes).unwrap_or(0)
}
pub fn compile(target: &Formula, bytes: &[u8]) -> Result<(Term, Vec<Graph>), String> {
    if bytes.len() > 8 * 1024 {
        return Err("peer certificate replay capacity".into());
    }
    compile_dag(target, bytes)
}
pub(super) fn compile_dag(target: &Formula, bytes: &[u8]) -> Result<(Term, Vec<Graph>), String> {
    let evidence = super::evidence::decode(bytes)?;
    if super::evidence::steps(bytes)? + evidence.definitions.len()
        > crate::resources::limits().closure_steps
    {
        return Err("native DAG replay closure capacity".into());
    }
    let definitions = evidence.definitions;
    let lemmas = evidence
        .lemmas
        .iter()
        .map(|b| ProofCertificate::from_canonical_bytes(b).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let context = proof::lemma_context(&definitions, &lemmas)?;
    let certificate = evidence.certificate;
    let certificate =
        ProofCertificate::from_canonical_bytes(&certificate).map_err(|e| e.to_string())?;
    let checked = crate::learning::proof::check(certificate, &context)
        .map_err(|e| format!("peer certificate unsupported: {e}"))?;
    if checked.conclusion() != target {
        return Err("peer certificate conclusion differs".into());
    }
    let mut graphs = Vec::new();
    let mut earlier = Vec::new();
    for lemma in &lemmas {
        let context = proof::lemma_context(&definitions, &earlier)?;
        let checked =
            crate::learning::proof::check(lemma.clone(), &context).map_err(|e| e.to_string())?;
        graphs.extend(replay_steps(
            checked.normal_form().certificate().steps(),
            checked.conclusion(),
            &context,
            &earlier,
        )?);
        earlier.push(lemma.clone());
    }
    graphs.extend(replay_steps(
        checked.normal_form().certificate().steps(),
        target,
        &context,
        &lemmas,
    )?);
    if graphs.iter().map(Graph::work_bytes).sum::<usize>()
        > super::MODEL_REQUIREMENTS.work_bytes / 16
    {
        return Err("native DAG replay work capacity".into());
    }
    let term = Term::Native {
        lemmas,
        definitions,
        certificate: checked.normal_form().certificate().clone(),
        target: target.clone(),
    };
    let verified = proof::verify(&term, target)?;
    if verified.native_id != checked.proof_id() {
        return Err("peer DAG reconstruction identity differs".into());
    }
    Ok((term, graphs))
}
fn replay_steps(
    steps: &[ProofStep],
    target: &Formula,
    context: &naome_checker::ArtifactState,
    lemmas: &[ProofCertificate],
) -> Result<Vec<Graph>, String> {
    if steps.len() > crate::resources::limits().closure_steps.min(16_384) {
        return Err("peer DAG replay step capacity".into());
    }
    let mut formulas: Vec<Formula> = Vec::new();
    let mut graphs = Vec::new();
    let mut graph_bytes = 0usize;
    let mut prefix = Sha256::new();
    prefix.update(target.encode_canonical().map_err(|e| e.to_string())?);
    let goal_parts = super::knowledge::fragments(target);
    for step in steps {
        let formula = match step {
            ProofStep::ModusPonens {
                premise,
                implication,
            } => {
                let a = *premise as usize;
                let b = *implication as usize;
                let implication = formulas.get(b).ok_or("peer implication index")?;
                let (antecedent, consequent) = implication
                    .view()
                    .implication_parts()
                    .ok_or("peer MP implication")?;
                if formulas.get(a).ok_or("peer premise index")?.view() != antecedent {
                    return Err("peer MP premise differs".into());
                }
                let conclusion = consequent.to_owned();
                let first = formulas.len().saturating_sub(32);
                let earlier = formulas[first..].iter().enumerate().map(|(i, formula)| {
                    let index = first + i;
                    let rule = match &steps[index] {
                        ProofStep::UniversalInstantiation { .. } => Rule::UniversalInstance,
                        ProofStep::EqualitySubstitution { .. } => Rule::EqualitySubstitution,
                        ProofStep::ProofReference { .. } => Rule::LemmaReference,
                        _ => Rule::ModusPonens,
                    };
                    (index, formula, rule)
                });
                if let Some(mut graph) = checked_mp(target, &goal_parts, earlier, (a, b))? {
                    graph.binding = crate::hex(&prefix.clone().finalize());
                    graph_bytes = graph_bytes
                        .checked_add(graph.work_bytes())
                        .ok_or("peer graph work overflow")?;
                    if graph_bytes > super::MODEL_REQUIREMENTS.work_bytes / 16 {
                        return Err("peer graph work capacity".into());
                    }
                    graphs.push(graph);
                }
                conclusion
            }
            ProofStep::Generalization { premise, variable } => Formula::for_all(
                *variable,
                formulas
                    .get(*premise as usize)
                    .ok_or("peer generalization index")?
                    .clone(),
            ),
            ProofStep::ProofReference { proof_id } => {
                let mut available = Vec::new();
                let mut selected = None;
                for lemma in lemmas {
                    let known = crate::learning::proof::check(lemma.clone(), context)
                        .map_err(|e| e.to_string())?;
                    if known.conclusion() == target {
                        continue;
                    }
                    if available.len() >= 16 {
                        break;
                    }
                    if known.proof_id() == *proof_id {
                        selected = Some(available.len());
                    }
                    available.push(known.conclusion().clone());
                }
                if let Some(expert) = selected.filter(|_| available.len() > 1) {
                    let decision = Decision {
                        context: available
                            .iter()
                            .map(|f| Binding { formula: f.clone() })
                            .collect(),
                        goal: target.clone(),
                        expert,
                        candidates: available
                            .iter()
                            .enumerate()
                            .map(|(i, f)| Candidate {
                                rule: Rule::LemmaReference,
                                premises: vec![i],
                                replacement: None,
                                consequences: vec![f.clone()],
                            })
                            .collect(),
                    };
                    if let Ok(mut graph) = Graph::encode(&decision) {
                        graph.binding = crate::hex(&prefix.clone().finalize());
                        graphs.push(graph);
                    }
                }
                use naome_checker::ContextView;
                let header = context
                    .proof_header(*proof_id)
                    .map_err(|e| e.to_string())?
                    .ok_or("peer cited proof missing")?;
                context
                    .proof_formula(header, crate::resources::limits().closure_bytes)
                    .map_err(|e| e.to_string())?
                    .ok_or("peer cited statement missing")?
                    .into_owned()
            }
            _ => Kernel::with_context(step.clone(), context)?.formula(),
        };
        let encoded = formula.encode_canonical().map_err(|e| e.to_string())?;
        prefix.update((encoded.len() as u64).to_le_bytes());
        prefix.update(encoded);
        formulas.push(formula);
    }
    Ok(graphs)
}
// Only earlier proved facts contribute candidate features. The observed
// inference supplies the label only if it is present in the bounded offer.
fn checked_mp<'a>(
    target: &Formula,
    goal_parts: &std::collections::BTreeSet<Vec<u8>>,
    facts: impl Iterator<Item = (usize, &'a Formula, Rule)>,
    observed: (usize, usize),
) -> Result<Option<Graph>, String> {
    let facts = facts.collect::<Vec<_>>();
    if !facts.iter().any(|fact| fact.0 == observed.0)
        || !facts.iter().any(|fact| fact.0 == observed.1)
    {
        return Ok(None);
    }
    let mut offered = Vec::new();
    let mut relevance = std::collections::HashMap::new();
    for (i, (implication, formula, rule)) in facts.iter().enumerate() {
        if let Some((antecedent, consequent)) = formula.view().implication_parts() {
            for (j, (premise, other, _)) in facts.iter().enumerate() {
                if antecedent == other.view() {
                    let consequence = consequent.to_owned();
                    let score = *relevance.entry(consequence.clone()).or_insert_with(|| {
                        super::knowledge::fragments(&consequence)
                            .intersection(goal_parts)
                            .map(Vec::len)
                            .sum::<usize>()
                    });
                    offered.push((
                        score,
                        *implication,
                        *premise,
                        Candidate {
                            rule: *rule,
                            premises: vec![i, j],
                            replacement: None,
                            consequences: vec![consequence],
                        },
                    ));
                }
            }
        }
    }
    offered.sort_by(|a, b| b.0.cmp(&a.0).then((a.1, a.2).cmp(&(b.1, b.2))));
    offered.truncate(16);
    let witness = offered
        .iter()
        .position(|(_, implication, premise, _)| (*premise, *implication) == observed);
    let Some(expert) = witness.filter(|_| offered.len() > 1) else {
        return Ok(None);
    };
    let decision = Decision {
        goal: target.clone(),
        context: facts
            .into_iter()
            .map(|(_, formula, _)| Binding {
                formula: formula.clone(),
            })
            .collect(),
        candidates: offered
            .into_iter()
            .map(|(_, _, _, candidate)| candidate)
            .collect(),
        expert,
    };
    Ok(Graph::encode(&decision).ok())
}

pub fn extract(question: &str, artifact: &str, bytes: &[u8]) -> Result<Solution, String> {
    let started = std::time::Instant::now();
    let q =
        naome_checker::question::ResearchQuestion::from_hex(question).map_err(|e| e.to_string())?;
    let (term, graphs) = compile(q.proved_target(), bytes)?;
    if graphs.is_empty() {
        return Err("peer DAG has no supported ambiguous inference".into());
    }
    let verified = proof::verify(&term, q.proved_target())?;
    if !matches_artifact(&crate::hex(verified.native_id.as_bytes()), artifact, bytes)? {
        return Err("peer artifact identity differs".into());
    }
    Ok(Solution {
        helpers: super::evidence::helpers(bytes)?,
        cost: Box::new(super::GenerationCost {
            search_expansions: 0,
            original_steps: verified.certificate.steps().len(),
            useful_steps: verified.certificate.steps().len(),
            unique_states: graphs
                .iter()
                .map(Graph::key)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            core_work: verified.certificate.steps().len(),
            generation_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            ..super::GenerationCost::default()
        }),
        source: proof::source(&verified)?,
        proof_id: crate::hex(verified.native_id.as_bytes()),
        refuted: false,
        tree: Tree::Certificate(bytes.to_vec()),
    })
}

/// A certificate retains its own checked artifact identity.
pub fn matches_artifact(proof_id: &str, artifact: &str, bytes: &[u8]) -> Result<bool, String> {
    let evidence = super::evidence::decode(bytes)?;
    let certificate =
        ProofCertificate::from_canonical_bytes(&evidence.certificate).map_err(|e| e.to_string())?;
    let context = super::evidence::context(bytes)?;
    let checked = proof::check(certificate, &context).map_err(|e| e.to_string())?;
    if crate::hex(checked.proof_id().as_bytes()) != proof_id {
        return Ok(false);
    }
    Ok(crate::hex(checked.artifact_id().as_bytes()) == artifact)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_dag_edges_are_extracted_without_goal_search_and_remain_bound_to_the_artifact() {
        let solution = super::super::tests::own_solution();
        let question = super::super::tests::own_question();
        let original = crate::learning::proof::check_artifact(
            &solution.source,
            &naome_checker::ArtifactState::new(),
        )
        .unwrap();
        let compressed = pack(original.normal_form().canonical_bytes(), &[]).unwrap();
        let extracted = extract(
            &question,
            &crate::hex(original.artifact_id().as_bytes()),
            &compressed,
        )
        .unwrap();
        assert_eq!(extracted.cost.search_expansions, 0);
        assert!(extracted.cost.unique_states > 0);
        assert_eq!(
            crate::learning::proof::check_artifact(
                &extracted.source,
                &naome_checker::ArtifactState::new()
            )
            .unwrap()
            .proof_id(),
            original.proof_id()
        );
        let target = naome_checker::question::ResearchQuestion::from_hex(&question).unwrap();
        let (_, graphs) = compile(target.proved_target(), &compressed).unwrap();
        assert!(!graphs.is_empty());
        assert!(graphs.iter().all(|g| {
            g.candidates.iter().all(|c| {
                [
                    Rule::ModusPonens,
                    Rule::UniversalInstance,
                    Rule::EqualitySubstitution,
                    Rule::LemmaReference,
                ]
                .iter()
                .any(|rule| g.nodes[*c].kind == rule.kind())
            })
        }));
        assert!(extract(&question, &"ff".repeat(32), &compressed).is_err());
        assert!(super::super::evidence::decode(&u32::MAX.to_le_bytes()).is_err());
        let mut corrupted = compressed.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(
            extract(
                &question,
                &crate::hex(original.artifact_id().as_bytes()),
                &corrupted
            )
            .is_err()
        );
        eprintln!(
            "peer_dag original_bytes={} compressed_bytes={} steps={} useful_states={}",
            original.normal_form().canonical_bytes().len(),
            compressed.len(),
            extracted.cost.original_steps,
            graphs.len()
        );
    }
    #[test]
    fn admitted_definition_references_keep_exact_native_identity_during_peer_replay() {
        let solution = super::super::tests::own_solution();
        let question = super::super::tests::own_question();
        let q = naome_checker::question::ResearchQuestion::from_hex(&question).unwrap();
        let naome_proof::ArtifactPayload::Definition(definition) =
            naome_proof::ArtifactPayload::from_canonical_bytes(
                &crate::unhex("0100000000020000000b0000000000000000000001").unwrap(),
            )
            .unwrap()
        else {
            panic!("definition")
        };
        let entry = super::super::definitions::Entry {
            certificate: definition.canonical_bytes().to_vec(),
            obligation: None,
        };
        let tree = Tree::Definitions {
            entries: vec![entry.clone()],
            selected: 0,
            available: 0,
            proof: Box::new(solution.tree),
        };
        let (_, _, checked) =
            super::super::search::core::checked(q.proved_target(), &tree).unwrap();
        let source = proof::source(&checked).unwrap();
        let helpers = super::super::definitions::helpers(&tree).unwrap();
        let mut graph = crate::Graph::default();
        let (root, batch) = graph.prepare_generated(&source, &helpers, &q).unwrap();
        graph
            .commit_batch(
                root,
                batch,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .unwrap();
        let packet = graph
            .learning_certificate(root)
            .unwrap()
            .expect("bounded definition closure");
        assert!(packet.len() <= 8 * 1024);
        let extracted = extract(&question, &crate::hex(root.as_bytes()), &packet).unwrap();
        assert_eq!(extracted.proof_id, crate::hex(checked.native_id.as_bytes()));
        assert_ne!(extracted.proof_id, solution.proof_id);
        assert_eq!(extracted.checked().unwrap().proof_id(), checked.native_id);
        validate_solution(&question, &crate::hex(root.as_bytes()), &packet, &extracted).unwrap();
        let bytes = checked.certificate.to_canonical_bytes();
        assert!(pack(&bytes, &[]).is_err());
        let wrong = super::super::definitions::discover(q.proved_target()).unwrap();
        if let Some(wrong) = wrong {
            assert!(pack(&bytes, &[wrong]).is_err());
        }
    }
}
