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
                // Only already checked earlier conclusions are available. The
                // witness and the final conclusion are never candidate features.
                let first = formulas.len().saturating_sub(32);
                let context: Vec<_> = formulas[first..]
                    .iter()
                    .map(|f| Binding { formula: f.clone() })
                    .collect();
                let mut offered = Vec::new();
                let goal_parts = super::knowledge::fragments(target);
                let mut relevance = std::collections::HashMap::new();
                for (i, f) in context.iter().enumerate() {
                    if let Some((antecedent, consequent)) = f.formula.view().implication_parts() {
                        for (j, p) in context.iter().enumerate() {
                            if antecedent == p.formula.view() {
                                let consequence = consequent.to_owned();
                                let score =
                                    *relevance.entry(consequence.clone()).or_insert_with(|| {
                                        super::knowledge::fragments(&consequence)
                                            .intersection(&goal_parts)
                                            .map(Vec::len)
                                            .sum::<usize>()
                                    });
                                let rule = match &steps[first + i] {
                                    ProofStep::UniversalInstantiation { .. } => {
                                        Rule::UniversalInstance
                                    }
                                    ProofStep::EqualitySubstitution { .. } => {
                                        Rule::EqualitySubstitution
                                    }
                                    ProofStep::ProofReference { .. } => Rule::LemmaReference,
                                    _ => Rule::ModusPonens,
                                };
                                offered.push((
                                    score,
                                    first + i,
                                    first + j,
                                    Candidate {
                                        rule,
                                        premises: vec![i, j],
                                        consequences: vec![consequence],
                                    },
                                ));
                            }
                        }
                    }
                }
                offered.sort_by(|a, b| b.0.cmp(&a.0).then((a.1, a.2).cmp(&(b.1, b.2))));
                offered.truncate(16);
                let witness = offered.iter().position(|(_, i, j, _)| *i == b && *j == a);
                let candidates = offered
                    .into_iter()
                    .map(|(_, _, _, c)| c)
                    .collect::<Vec<_>>();
                if let Some(expert) = witness.filter(|_| candidates.len() > 1) {
                    let decision = Decision {
                        goal: target.clone(),
                        context,
                        candidates,
                        expert,
                    };
                    if let Ok(mut graph) = Graph::encode(&decision) {
                        graph.binding = crate::hex(&prefix.clone().finalize());
                        graph_bytes = graph_bytes
                            .checked_add(graph.work_bytes())
                            .ok_or("peer graph work overflow")?;
                        if graph_bytes > super::MODEL_REQUIREMENTS.work_bytes / 16 {
                            return Err("peer graph work capacity".into());
                        }
                        graphs.push(graph);
                    }
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
pub fn extract(question: &str, artifact: &str, bytes: &[u8]) -> Result<Solution, String> {
    let started = std::time::Instant::now();
    let q = naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
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

/// Native certificates keep identity; projected programs retain their source
/// identity and a separately checked translated certificate identity.
pub fn matches_artifact(proof_id: &str, artifact: &str, bytes: &[u8]) -> Result<bool, String> {
    let evidence = super::evidence::decode(bytes)?;
    let certificate =
        ProofCertificate::from_canonical_bytes(&evidence.certificate).map_err(|e| e.to_string())?;
    let context = super::evidence::context(bytes)?;
    let checked = proof::check(certificate, &context).map_err(|e| e.to_string())?;
    if crate::hex(checked.proof_id().as_bytes()) != proof_id {
        return Ok(false);
    }
    let term = super::evidence::compile(checked.conclusion(), bytes)?;
    let verified = proof::verify(&term, checked.conclusion())?;
    if let Some(origin) = evidence.program {
        super::program::validate(&origin, &verified)?;
        Ok(crate::hex(origin.manifest.artifact_id().as_bytes()) == artifact)
    } else {
        Ok(
            crate::hex(naome_proof::ArtifactId::from_proof_id(verified.native_id).as_bytes())
                == artifact,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_dag_edges_are_extracted_without_goal_search_and_remain_bound_to_the_artifact() {
        let solution = super::super::tests::own_solution();
        let question = super::super::tests::own_question();
        let original = naome_authoring::compile(&solution.source).unwrap();
        let compressed = pack(original.canonical_proof_bytes(), &[]).unwrap();
        let extracted = extract(
            &question,
            &crate::hex(original.artifact_id().as_bytes()),
            &compressed,
        )
        .unwrap();
        assert_eq!(extracted.cost.search_expansions, 0);
        assert!(extracted.cost.unique_states > 0);
        assert_eq!(
            naome_authoring::compile(&extracted.source)
                .unwrap()
                .proof_id(),
            original.proof_id()
        );
        let target = naome_authoring::CompiledQuestion::compile(&question).unwrap();
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
            original.canonical_proof_bytes().len(),
            compressed.len(),
            extracted.cost.original_steps,
            graphs.len()
        );
    }
    #[test]
    fn admitted_definition_references_keep_exact_native_identity_during_peer_replay() {
        let solution = super::super::tests::own_solution();
        let question = super::super::tests::own_question();
        let q = naome_authoring::CompiledQuestion::compile(&question).unwrap();
        let naome_authoring::CompiledArtifact::Definition(definition) =
            naome_authoring::compile_artifact("def equal=relation(x,y): eq(x,y)").unwrap()
        else {
            panic!("definition");
        };
        let entry = super::super::definitions::Entry {
            certificate: definition.canonical_definition_bytes().to_vec(),
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
