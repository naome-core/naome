//! Bounded read-only observation of the actual focused training pool.
use super::{Engine, Graph, UPDATES_PER_UNIT};
use crate::learning::{Job, Origin, curriculum, digest, search};
use serde::Serialize;
use std::collections::BTreeMap;
pub(in crate::learning) mod activation;
pub(in crate::learning) mod sequence_audit;

pub(in crate::learning) struct Source {
    job: u64,
    proof: String,
    graphs: Vec<Graph>,
}
pub(in crate::learning) fn own_sources(job: &Job) -> Vec<Source> {
    job.base
        .training_sources()
        .map(|example| {
            assert!(matches!(example.origin, Origin::Local));
            assert!(curriculum::owned::case(&example.question).is_some());
            let question = naome_authoring::CompiledQuestion::compile(&example.question).unwrap();
            let target = if example.refuted {
                question.refuted_target()
            } else {
                question.proved_target()
            };
            let (core, _, checked) =
                search::core::checked(target, example.trajectory(&job.evidence).unwrap()).unwrap();
            assert_eq!(crate::hex(checked.native_id.as_bytes()), example.proof_id);
            Source {
                job: example.job,
                proof: example.proof_id.clone(),
                graphs: search::compile(target, &core).unwrap().1,
            }
        })
        .collect()
}

#[derive(Serialize)]
pub(in crate::learning) struct Observed {
    graph_key: String,
    successes: Vec<usize>,
    pub(super) occurrences: u64,
}
pub(in crate::learning) type Decisions = BTreeMap<String, Observed>;

pub(in crate::learning) fn coverage(
    sources: &[Source],
    available: &Decisions,
    sampled: &Decisions,
) -> serde_json::Value {
    let rows = sources.iter().map(|source| {
        let decisions = source.graphs.iter().map(|graph| {
            let key = graph.key();
            let matches = |item: &&Observed| item.graph_key == key && item.successes.contains(&graph.expert);
            serde_json::json!({"graph_key":key,"original_expert":graph.expert,
                "available":available.values().any(|item| matches(&item)),
                "sampled_occurrences":sampled.values().filter(matches).map(|item|item.occurrences).sum::<u64>()})
        }).collect::<Vec<_>>();
        serde_json::json!({"job":source.job,"proof_id":source.proof,"decision_occurrences":decisions.len(),
            "has_decision_states":!decisions.is_empty(),
            "all_original_actions_available":(!decisions.is_empty()).then(||decisions.iter().all(|d|d["available"].as_bool().unwrap())),
            "all_original_actions_sampled":(!decisions.is_empty()).then(||decisions.iter().all(|d|d["sampled_occurrences"].as_u64().unwrap()>0)),
            "decisions":decisions})
    }).collect::<Vec<_>>();
    serde_json::json!({"sources":rows,"interpretation":"Decision graphs and witnessed actions can be shared by multiple sources; this is not exclusive sampled-proof attribution or certified search success."})
}
pub(in crate::learning) fn record(
    graph: &Graph,
    catalogue: &mut Decisions,
    increment: u64,
) -> String {
    let graph_key = graph.key();
    let key = digest(&(&graph_key, &graph.successes));
    let entry = catalogue.entry(key.clone()).or_insert_with(|| Observed {
        graph_key,
        successes: graph.successes.clone(),
        occurrences: 0,
    });
    entry.occurrences += increment;
    key
}

pub(in crate::learning) fn consumed(
    engine: &Engine,
    before: u64,
    after: u64,
    available: &mut Decisions,
    sampled: &mut Decisions,
) -> Vec<Vec<String>> {
    let (_, pool, _) = engine
        .pool
        .as_ref()
        .expect("actual completed training pool");
    for graph in pool.graphs() {
        record(graph, available, 0);
    }
    let mut cursor = before;
    let batches = (0..UPDATES_PER_UNIT)
        .map(|_| {
            pool.sequence_batch(&mut cursor)
                .into_iter()
                .filter(|sample| !sample.auxiliary || engine.rich_targets())
                .map(|sample| {
                    record(
                        &pool.target_graph(sample.graph, engine.rich_targets()),
                        sampled,
                        1,
                    )
                })
                .collect()
        })
        .collect();
    assert_eq!(cursor, after);
    assert_eq!(after.wrapping_sub(before), 16 * UPDATES_PER_UNIT);
    batches
}
