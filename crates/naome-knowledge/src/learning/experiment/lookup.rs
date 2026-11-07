//! Evaluation-only reference-use witnesses. These never enter replay or promotion.
use super::*;
use naome_foundation::{Formula, FreeVariable};
use naome_proof::{DefinedFormula, DefinitionCertificate};

fn natural_definitions() -> Vec<definitions::Entry> {
    let mut graph = crate::Graph::default();
    let (empty, _) = graph
        .produce("def empty=relation(x): all(y,not(mem(y,x)))")
        .unwrap();
    let (successor, _) = graph
        .produce("def successor=relation(x,s): all(y,iff(mem(y,s),or(mem(y,x),eq(y,x))))")
        .unwrap();
    let source = format!(
        "defs: e=\"{}\" s=\"{}\" def inductive=relation(i): and(ex(z,and(e(z),mem(z,i))),all(n,imp(mem(n,i),ex(t,and(s(n,t),mem(t,i))))))",
        crate::hex(empty.definition_id().unwrap().unwrap().as_bytes()),
        crate::hex(successor.definition_id().unwrap().unwrap().as_bytes())
    );
    let (inductive, _) = graph.produce(&source).unwrap();
    let (natural, _) = graph
        .produce(&format!(
            "defs: i=\"{}\" def natural=relation(n): all(s,imp(i(s),mem(n,s)))",
            crate::hex(inductive.definition_id().unwrap().unwrap().as_bytes())
        ))
        .unwrap();
    [empty, successor, inductive, natural]
        .iter()
        .map(|e| {
            graph
                .learning_definition(naome_proof::ArtifactId::from_definition_id(
                    e.definition_id().unwrap().unwrap(),
                ))
                .unwrap()
                .unwrap()
        })
        .collect()
}
pub fn evaluate(
    model: &Checkpoint,
    known: &[definitions::Entry],
    engine: &mut Engine,
    io: &mut MemoryStore,
) -> Vec<serde_json::Value> {
    let mut results = Vec::new();
    for (track, base) in [
        ("known_definition_new_context", known.to_vec()),
        (
            "unseen_definition_natural_predicates",
            natural_definitions(),
        ),
    ] {
        let mut choices = base.clone();
        for entry in &base {
            if choices.len() >= definitions::CAPACITY {
                break;
            }
            let certificate = entry.certificate().unwrap();
            let body = DefinedFormula::negate(certificate.body().clone());
            let counter = definitions::Entry {
                certificate: DefinitionCertificate::relation(certificate.relation_arity(), body)
                    .unwrap()
                    .to_canonical_bytes(),
                obligation: None,
            };
            if !choices.contains(&counter)
                && choices.iter().map(definitions::Entry::bytes).sum::<usize>() + counter.bytes()
                    <= definitions::BYTES
            {
                choices.push(counter);
            }
        }
        for (index, entry) in base.iter().enumerate() {
            for style in 0..3 {
                let mut candidates = choices.clone();
                let count = candidates.len();
                if count == 0 {
                    continue;
                }
                candidates.rotate_left((index * 3 + style) % count);
                let body = entry.body().unwrap();
                let query = match style {
                    0 => body,
                    1 => Formula::negate(body),
                    _ => Formula::implies(
                        body,
                        Formula::member(FreeVariable::new(40), FreeVariable::new(41)),
                    ),
                };
                let term = calculus::identity(query.clone(), &mut calculus::Names::default());
                let proof = proof::verify(&term, &Formula::implies(query.clone(), query)).unwrap();
                let mut valid = Vec::new();
                let mut witnesses = Vec::new();
                for (i, candidate) in candidates.iter().enumerate() {
                    let source =
                        proof::source_with_definitions(&proof, std::slice::from_ref(candidate))
                            .unwrap();
                    let context = definitions::context(std::slice::from_ref(candidate)).unwrap();
                    let checked = naome_authoring::compile_against_proof_context(&source, &context)
                        .unwrap()
                        .into_checked_proof();
                    if checked
                        .direct_artifact_dependencies()
                        .contains(&candidate.address().unwrap())
                    {
                        valid.push(i);
                        witnesses.push(serde_json::json!({"index":i,"proof_id":crate::hex(checked.proof_id().as_bytes()),"source":source}));
                    }
                }
                let graph = definitions::decision(&proof.target, &candidates, 0);
                let started = Instant::now();
                let prediction = match &graph {
                    Ok(graph) => engine
                        .with(model, io, |runtime| runtime.scores_graph(graph))
                        .map(|scores| {
                            (0..scores.len())
                                .max_by(|a, b| scores[*a].total_cmp(&scores[*b]).then(b.cmp(a)))
                                .unwrap()
                        }),
                    Err(error) => Err(error.clone()),
                };
                let selected = prediction.as_ref().ok().copied();
                results.push(serde_json::json!({
                    "track":track,"id":digest(&(track,index,style,&proof.target.encode_canonical().unwrap())),
                    "query":proof.target.to_source(),
                    "definition_ids":candidates.iter().map(|e|crate::hex(e.certificate().unwrap().definition_id().as_bytes())).collect::<Vec<_>>(),
                    "definitions":candidates,"valid_indices":valid,"reference_use_witnesses":witnesses,
                    "selected_index":selected,"correct":selected.is_some_and(|i|valid.contains(&i)),
                    "diagnostic":prediction.err(),"graph_nodes":graph.ok().map(|g|g.nodes.len()),"elapsed_micros":started.elapsed().as_micros(),
                }));
            }
        }
    }
    results
}
