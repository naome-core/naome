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
        || crate::hex(crate::object::proof_address(&solution.proof_id)?.as_bytes()) != artifact
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
pub fn pack(bytes: &[u8], definitions: &[super::definitions::Entry]) -> Result<Vec<u8>, String> {
    let _ = super::definitions::context(definitions)?;
    let mut payload = (bytes.len() as u32).to_le_bytes().to_vec();
    payload.extend_from_slice(bytes);
    payload.extend(serde_json::to_vec(definitions).map_err(|e| e.to_string())?);
    if payload.len()
        > crate::resources::limits()
            .proof_bytes
            .min(crate::resources::limits().closure_bytes)
    {
        return Err("peer certificate decoded capacity".into());
    }
    let mut packed = (payload.len() as u32).to_le_bytes().to_vec();
    packed.extend(lz4_flex::block::compress(&payload));
    if packed.len() > 8 * 1024 {
        return Err("peer compressed replay capacity".into());
    }
    Ok(packed)
}
fn unpack(bytes: &[u8]) -> Result<(Vec<u8>, Vec<super::definitions::Entry>), String> {
    if bytes.len() > 8 * 1024 || bytes.len() < 4 {
        return Err("peer compressed replay capacity".into());
    }
    let size =
        u32::from_le_bytes(bytes[..4].try_into().map_err(|_| "peer decoded length")?) as usize;
    if size
        > crate::resources::limits()
            .proof_bytes
            .min(crate::resources::limits().closure_bytes)
    {
        return Err("peer decoded capacity".into());
    }
    let mut result = vec![0; size];
    let actual =
        lz4_flex::block::decompress_into(&bytes[4..], &mut result).map_err(|e| e.to_string())?;
    if actual != size || result.len() < 4 {
        return Err("peer compressed encoding differs".into());
    }
    let length = u32::from_le_bytes(
        result[..4]
            .try_into()
            .map_err(|_| "peer certificate length")?,
    ) as usize;
    let end = 4usize
        .checked_add(length)
        .filter(|end| *end <= result.len())
        .ok_or("peer certificate extent")?;
    let certificate = result[4..end].to_vec();
    let definitions = serde_json::from_slice::<Vec<super::definitions::Entry>>(&result[end..])
        .map_err(|e| e.to_string())?;
    if pack(&certificate, &definitions)? != bytes {
        return Err("peer compressed encoding differs".into());
    }
    Ok((certificate, definitions))
}
pub fn definitions(bytes: &[u8]) -> Result<Vec<super::definitions::Entry>, String> {
    Ok(unpack(bytes)?.1)
}
pub fn step_count(bytes: &[u8]) -> usize {
    unpack(bytes)
        .ok()
        .and_then(|(b, _)| ProofCertificate::from_canonical_bytes(&b).ok())
        .map_or(0, |c| c.steps().len())
}
pub fn compile(target: &Formula, bytes: &[u8]) -> Result<(Term, Vec<Graph>), String> {
    if bytes.len() > 8 * 1024 {
        return Err("peer certificate replay capacity".into());
    }
    let (certificate, definitions) = unpack(bytes)?;
    let context = super::definitions::context(&definitions)?;
    let certificate =
        ProofCertificate::from_canonical_bytes(&certificate).map_err(|e| e.to_string())?;
    let checked = naome_checker::normalize_and_check_with_state(certificate, &context)
        .map_err(|e| format!("peer certificate unsupported: {e}"))?;
    let mut supplied = definitions
        .iter()
        .map(super::definitions::Entry::address)
        .collect::<Result<Vec<_>, _>>()?;
    supplied.sort_unstable();
    supplied.dedup();
    if checked.direct_artifact_dependencies().as_ref() != supplied.as_slice() {
        return Err("peer definition closure differs".into());
    }
    if checked.conclusion() != target {
        return Err("peer certificate conclusion differs".into());
    }
    let steps = checked.normal_form().certificate().steps();
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
                let mut candidates = Vec::new();
                let mut witness = None;
                for (i, f) in context.iter().enumerate() {
                    if let Some((antecedent, consequent)) = f.formula.view().implication_parts() {
                        for (j, p) in context.iter().enumerate() {
                            if antecedent == p.formula.view() && candidates.len() < 16 {
                                if first + i == b && first + j == a {
                                    witness = Some(candidates.len());
                                }
                                candidates.push(Candidate {
                                    rule: Rule::ModusPonens,
                                    premises: vec![i, j],
                                    consequences: vec![consequent.to_owned()],
                                });
                            }
                        }
                    }
                }
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
            _ => Kernel::with_context(step.clone(), &context)?.formula(),
        };
        let encoded = formula.encode_canonical().map_err(|e| e.to_string())?;
        prefix.update((encoded.len() as u64).to_le_bytes());
        prefix.update(encoded);
        formulas.push(formula);
    }
    let term = Term::Native {
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
pub fn extract(question: &str, artifact: &str, bytes: &[u8]) -> Result<Solution, String> {
    let started = std::time::Instant::now();
    let q = naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
    let (term, graphs) = compile(q.proved_target(), bytes)?;
    if graphs.is_empty() {
        return Err("peer DAG has no supported ambiguous inference".into());
    }
    let verified = proof::verify(&term, q.proved_target())?;
    if crate::hex(naome_proof::ArtifactId::from_proof_id(verified.native_id).as_bytes()) != artifact
    {
        return Err("peer artifact identity differs".into());
    }
    Ok(Solution {
        helpers: Vec::new(),
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
        tree: Tree::Certificate(pack(
            &verified.certificate.to_canonical_bytes(),
            &verified.definitions,
        )?),
    })
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
            g.candidates
                .iter()
                .all(|c| g.nodes[*c].kind == Rule::ModusPonens.kind())
        }));
        assert!(extract(&question, &"ff".repeat(32), &compressed).is_err());
        assert!(unpack(&u32::MAX.to_le_bytes()).is_err());
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
        assert!(compile(q.proved_target(), &pack(&bytes, &[]).unwrap()).is_err());
        let wrong = super::super::definitions::discover(q.proved_target()).unwrap();
        if let Some(wrong) = wrong {
            assert!(compile(q.proved_target(), &pack(&bytes, &[wrong]).unwrap()).is_err());
        }
    }
}
