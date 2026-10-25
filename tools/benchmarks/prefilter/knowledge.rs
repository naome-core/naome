//! Identical source overlaid on baseline and candidate for the matched comparison.
use super::*;
use std::{hint::black_box, time::Instant};

#[test]
#[ignore = "run tools/benchmarks/prefilter.py for a matched baseline comparison"]
fn measure_prefilter_cache() {
    let graph = Graph::default();
    let inputs: Vec<_> = (0..8)
        .map(|index| {
            CompiledQuestion::compile(&format!(
                "goal=all(x,{}mem(x,x){})",
                "not(".repeat(index),
                ")".repeat(index),
            ))
            .unwrap()
        })
        .collect();
    for group in ["cache_repeated", "cache_alternating", "cache_fresh"] {
        let mut local = LocalQuestions::new(Some(|_| async { Ok(true) }));
        let evaluations = 4096;
        let started = Instant::now();
        for index in 0..evaluations {
            let input = &inputs[if group == "cache_repeated" {
                0
            } else {
                index % inputs.len()
            }];
            let result = black_box(if group == "cache_fresh" {
                local.evaluate(&graph, input, false)
            } else {
                local.assess(&graph, input)
            });
            assert!(
                result.passed(),
                "comparison workload must remain unanswered: {result:?}"
            );
        }
        let elapsed_ns = started.elapsed().as_nanos();
        println!(
            "PREFILTER_MEASUREMENT {}",
            serde_json::json!({"group":group,"unique_cases":if group=="cache_repeated" {1} else {8},"evaluations":evaluations,"computations":local.computation_count(),"elapsed_ns":elapsed_ns})
        );
    }
}
