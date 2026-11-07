//! Symmetric canonical-answer readback, distinct from explicit root generation.
use super::*;

#[test]
#[ignore = "explicit independent readback of a complete frozen comparison"]
fn canonical_answer_readback() {
    let root = std::path::PathBuf::from(std::env::var("NAOME_CANONICAL_ANSWER_INPUT").unwrap());
    let output = std::path::PathBuf::from(std::env::var("NAOME_CANONICAL_ANSWER_OUTPUT").unwrap());
    assert!(!output.exists());
    let rows: Vec<Value> =
        serde_json::from_slice(&std::fs::read(root.join("results.json")).unwrap()).unwrap();
    assert!(
        root.join("summary.json").exists(),
        "partial comparisons are not qualification"
    );
    let limits = budget::limits();
    let mut results = Vec::new();
    let mut counts = BTreeMap::<String, usize>::new();
    for row in rows {
        let Some(arms) = row["arms"].as_object() else {
            continue;
        };
        let seed = row["seed"].as_u64().unwrap();
        let id = row["id"].as_str().unwrap();
        let question = CompiledQuestion::compile(row["question"].as_str().unwrap()).unwrap();
        for (name, arm) in arms {
            // This prefix was already paid by the original arm. Reconstruct it
            // independently for readback; do not call this extra diagnostic
            // execution part of its original physical runtime.
            let reconstruction = Instant::now();
            let reconstruction_cpu = meta::cpu_micros().unwrap();
            let mut graph = crate::Graph::default();
            let events: Vec<Value> = serde_json::from_slice(
                &std::fs::read(
                    root.join(seed.to_string())
                        .join(id)
                        .join(name)
                        .join("events.json"),
                )
                .unwrap(),
            )
            .unwrap();
            let mut admitted = 0;
            for event in events {
                if event["solution"].is_null() {
                    continue;
                }
                let solution: Solution = serde_json::from_value(event["solution"].clone()).unwrap();
                let source =
                    CompiledQuestion::compile(event["question"].as_str().unwrap()).unwrap();
                admitted += usize::from(admit_discovery(&mut graph, &source, &solution).unwrap());
            }
            let reconstruction_cpu = meta::cpu_micros().unwrap() - reconstruction_cpu;
            let reconstruction_wall = reconstruction.elapsed().as_micros();
            let mut owner = crate::question::LocalQuestions::new(Some(
                crate::mocks::select_question as fn(_) -> _,
            ));
            let started = Instant::now();
            let cpu = meta::cpu_micros().unwrap();
            let decision = owner.assess(&graph, &question);
            let query_cpu = meta::cpu_micros().unwrap() - cpu;
            let query_wall = started.elapsed().as_micros() as u64;
            let within = arm["cost"]["within_budget"] == true
                && arm["cost"]["cpu_micros"].as_u64().unwrap() + query_cpu
                    <= limits["cpu_micros"].as_u64().unwrap()
                && arm["cost"]["wall_micros"].as_u64().unwrap() + query_wall
                    <= limits["wall_micros"].as_u64().unwrap();
            let counted = decision.has_answer() && within;
            *counts.entry(name.clone()).or_default() += usize::from(counted);
            assert!(
                !(arm["counted_solution"] == true && within) || decision.has_answer(),
                "explicit checked root missing from the canonical answer view"
            );
            results.push(json!({"seed":seed,"id":id,"family":row["family"],"shape":row["shape"],"arm":name,
                "explicit_root_solution":arm["counted_solution"],"canonical_answer":decision.has_answer(),
                "counted_canonical_answer":counted,"answer_rule":decision.rule,"reason":format!("{:?}",decision.reason),
                "within_total_with_query":within,"query_cpu_micros":query_cpu,"query_wall_micros":query_wall,
                "original_cost":arm["cost"],"independently_admitted_solutions":admitted,
                "diagnostic_reconstruction_cpu_micros":reconstruction_cpu,"diagnostic_reconstruction_wall_micros":reconstruction_wall}));
        }
        write(
            &output,
            &json!({"counts":counts,"rows":results,"complete":false}),
        );
    }
    write(
        &output,
        &json!({"counts":counts,"rows":results,"complete":true,
        "contract":"Symmetric independent canonical-answer readback for every arm, frozen before fresh inference. Exact emitted sources reconstruct the already paid canonical prefix; this diagnostic reconstruction is recorded separately. The one actual answer query is added to original total CPU/wall cost. Existing checker answers count for every arm; exporting an existing witness is never an additional explicit generated-root proof."}),
    );
}
