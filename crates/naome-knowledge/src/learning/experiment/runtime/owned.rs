//! Read-only paired diagnosis on owned, independently rechecked proof decisions.
use super::*;
#[path = "owned/retention.rs"]
mod retention;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    parent_state: String,
    current_state: String,
    parent_evidence: String,
    current_evidence: String,
    parent_checkpoint: String,
    candidate_checkpoint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnosis {
    original_sha256: BTreeMap<String, String>,
    cases: Vec<Case>,
}

fn records(state: &State) -> BTreeMap<String, &Example> {
    state
        .training_sources()
        .map(|e| {
            assert!(matches!(e.origin, Origin::Local));
            (e.proof_id.clone(), e)
        })
        .collect()
}

fn proof_graphs(state: &State, evidence: &[Evidence], proof: &str) -> Vec<graph::Graph> {
    let mut selected = state.clone();
    selected.replay.retain(|e| e.proof_id == proof);
    selected.anchors.retain(|e| e.proof_id == proof);
    // This temporary view selects data only; it is never admitted or persisted as
    // a replacement State. The maintained compiler rechecks each full trajectory.
    let pool = selected.training_pool_for(evidence, true).unwrap();
    assert!(!pool.is_empty());
    pool.graphs().to_vec()
}

#[test]
#[ignore = "Explicit read-only owned-decision continuation diagnosis; no updates or proof queries"]
fn owned_decision_continuation_diagnosis() {
    let input = std::env::var("NAOME_OWNED_DIAGNOSIS_INPUT").expect("frozen owned input");
    let output = std::env::var("NAOME_OWNED_DIAGNOSIS_OUTPUT").expect("fresh diagnosis output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve earlier diagnoses");
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let meter = crate::resources::feedback::Meter::start();
    let diagnosis: Diagnosis = read(&input);
    assert!((1..=12).contains(&diagnosis.cases.len()));
    for (path, expected) in &diagnosis.original_sha256 {
        assert_eq!(
            crate::hex(&Sha256::digest(std::fs::read(path).unwrap())),
            *expected
        );
    }
    let mut results = Vec::new();
    for case in &diagnosis.cases {
        limits(started, cpu);
        let previous: State = read(&case.parent_state);
        let current: State = read(&case.current_state);
        previous.validate().unwrap();
        current.validate().unwrap();
        assert_eq!(previous.model, current.model);
        assert_eq!(digest(&previous.knowledge), digest(&current.knowledge));
        assert_eq!(digest(&previous.definitions), digest(&current.definitions));
        let old_evidence: Vec<Evidence> = read(&case.parent_evidence);
        let new_evidence: Vec<Evidence> = read(&case.current_evidence);
        let old = records(&previous);
        let new = records(&current);
        let mut proofs = Vec::new();
        for (id, e) in &old {
            proofs.push((
                id.clone(),
                e.job,
                if new.contains_key(id) {
                    "old_retained"
                } else {
                    "old_dropped"
                },
                proof_graphs(&previous, &old_evidence, id),
            ));
        }
        for (id, e) in &new {
            if !old.contains_key(id) {
                proofs.push((
                    id.clone(),
                    e.job,
                    "new",
                    proof_graphs(&current, &new_evidence, id),
                ));
            }
        }
        let mut known: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        for (_, _, _, graphs) in &proofs {
            for graph in graphs {
                known
                    .entry(graph.key())
                    .or_default()
                    .extend(&graph.successes);
            }
        }
        let mut store = Store::default();
        let parent = checkpoint(&case.parent_checkpoint, &mut store);
        let candidate = checkpoint(&case.candidate_checkpoint, &mut store);
        assert_eq!(parent, previous.model);
        assert_eq!(parent.updates, 250);
        assert_eq!(candidate.updates, 500);
        assert_eq!(parent.seed, candidate.seed);
        assert_eq!(parent.specification, candidate.specification);
        let mut engine = Engine::default();
        let mut rows = Vec::new();
        for (proof, job, group, graphs) in proofs {
            limits(started, cpu);
            let mut union = graphs.clone();
            for graph in &mut union {
                graph.successes = known[&graph.key()].iter().copied().collect();
            }
            let mut comparisons = Vec::new();
            for (name, model) in [("parent", &parent), ("candidate", &candidate)] {
                comparisons.push(serde_json::json!({"model":name,
                    "original_witness":decision_metrics(model, &graphs, &mut engine, &mut store.inner),
                    "all_known_successes":decision_metrics(model, &union, &mut engine, &mut store.inner)}));
            }
            rows.push(serde_json::json!({"proof_id":proof,"job":job,"group":group,
                "shared_decision_keys":graphs.iter().filter(|g|known[&g.key()].len()>g.successes.len()).count(),
                "comparisons":comparisons}));
        }
        assert_eq!(engine.snapshot(&parent, &mut store.inner).unwrap(), parent);
        assert_eq!(
            engine.snapshot(&candidate, &mut store.inner).unwrap(),
            candidate
        );
        results.push(
            serde_json::json!({"case":case.name,"parent":parent,"candidate":candidate,
            "old_sources":old.len(),"new_sources":new.len(),"unique_decision_states":known.len(),
            "proofs":rows,"model_and_adam_unchanged_after_inference":true}),
        );
    }
    limits(started, cpu);
    let resources = meter.finish(0, true);
    assert!(resources.peak_rss_bytes.unwrap() <= MODEL_REQUIREMENTS.work_bytes as u64);
    write(
        output,
        &serde_json::json!({"scope":"Owned checked decision diagnosis only; no held-out proof-outcome claim.",
        "cases":results,"optimizer_updates":0,"new_proof_queries":0,
        "elapsed_cpu_micros":meta::cpu_micros().unwrap()-cpu,"elapsed_wall_micros":started.elapsed().as_micros(),
        "peak_rss_bytes":resources.peak_rss_bytes,"model_and_adam_unchanged":true}),
    );
}
