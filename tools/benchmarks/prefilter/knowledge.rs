//! Identical source overlaid on baseline and candidate for the matched comparison.
use super::*;
use std::{hint::black_box, time::Instant};

#[test]
#[ignore = "run tools/benchmarks/prefilter.py for a matched baseline comparison"]
fn measure_prefilter_cache() {
    let graph = Graph::default();
    let inputs: Vec<_> = (0..8)
        .map(|index| {
            use naome_foundation::{Formula, FreeVariable};
            let x = FreeVariable::new(0);
            let body = (0..index).fold(Formula::member(x, x), |body, _| Formula::negate(body));
            ResearchQuestion::from_formula(Formula::for_all(x, body)).unwrap()
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

#[tokio::test]
#[ignore = "run tools/benchmarks/prefilter.py for a matched baseline comparison"]
async fn measure_prefilter_node_api() {
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let directory = Directory(
        std::env::temp_dir().join(format!("naome-prefilter-comparison-{}", std::process::id(),)),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let identity = libp2p::identity::Keypair::generate_ed25519();
    std::fs::write(
        directory.0.join("identity.key"),
        identity.to_protobuf_encoding().unwrap(),
    )
    .unwrap();
    let config = crate::network::Config {
        directory: directory.0.clone(),
        listen: "/ip4/127.0.0.1/tcp/0".into(),
        peers: Vec::new(),
        discovery: Some(crate::network::DiscoveryConfig {
            mdns: false,
            dht: false,
            ..Default::default()
        }),
        producer_artifacts: Vec::new(),
    };
    let (handle, admin, inbox) = channel();
    let task = tokio::spawn(crate::network::run_with_questions(
        config,
        false,
        inbox,
        |_| async { Ok(true) },
    ));
    let initial = tokio::time::timeout(Duration::from_secs(10), handle.context())
        .await
        .unwrap()
        .unwrap();
    let inputs: Vec<_> = (0..8)
        .map(|index| {
            use naome_foundation::{Formula, FreeVariable};
            let x = FreeVariable::new(0);
            let body = (0..index).fold(Formula::member(x, x), |body, _| Formula::negate(body));
            ResearchQuestion::from_formula(Formula::for_all(x, body)).unwrap()
        })
        .collect();
    let evaluations = 2048;
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(30), async {
        for index in 0..evaluations {
            let result = handle
                .assess(inputs[index % inputs.len()].clone())
                .await
                .unwrap();
            assert!(result.prefilter.passed());
            assert_eq!(result.selection_result, SelectionAssessment::Assessed(true));
            black_box(result);
        }
    })
    .await
    .expect("the bounded local API workload must finish within 30 seconds");
    let elapsed_ns = started.elapsed().as_nanos();
    assert_eq!(handle.context().await.unwrap(), initial);
    assert_eq!(initial.registered_questions, 0);
    assert_eq!(initial.checked_artifacts, 0);
    admin.stop().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    println!(
        "PREFILTER_MEASUREMENT {}",
        serde_json::json!({"group":"node_api_alternating","unique_cases":inputs.len(),"evaluations":evaluations,"selection_assessments":evaluations,"elapsed_ns":elapsed_ns})
    );
}
