#![cfg(all(unix, feature = "developer-tools"))]
use naome_knowledge::{Graph, training};
use std::{
    fs,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn developer_training_command_exports_recheckable_targets_from_a_stopped_node() {
    let directory = std::env::temp_dir().join(format!(
        "naome-training-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let node = directory.join("node");
    let mut graph = Graph::open(&node).unwrap();
    let mut expected = 0;
    for n in 1..=12 {
        let mut formula = "eq(v0,v0)".to_owned();
        let mut proof = "p0=refl(v0)".to_owned();
        for i in 0..n {
            formula = format!("all(v{i},{formula})");
            proof.push_str(&format!(" p{}=gen(p{i},v{i})", i + 1));
        }
        let question =
            naome_authoring::CompiledQuestion::compile(&format!("goal={formula}")).unwrap();
        expected += usize::from(training::partition(&question) == training::Partition::Training);
        let envelope = graph
            .author(&format!("goal={formula} proof: {proof} return p{n}"))
            .unwrap();
        graph.ingest(envelope, Instant::now()).unwrap();
    }
    assert!(expected > 0);
    let request = training::Request {
        solver: training::Solver {
            checkpoint: naome_knowledge::hex(&[3; 32]),
            budget: training::SearchBudget {
                horizon_ms: 100,
                work_units: 4,
            },
        },
        training_roots: vec![],
        development: None,
        previous_development: None,
        after: None,
        scan: 16,
        take: 16,
        seed: 23,
        random_only: false,
    };
    let input = directory.join("request.json");
    fs::write(
        &input,
        serde_json::to_vec(&training::Command::Select { request }).unwrap(),
    )
    .unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_naome-knowledge-dev"))
            .arg("training")
            .arg(&node)
            .arg(&input)
            .output()
            .unwrap()
    };
    // A second process must not borrow the live node's store ownership.
    assert!(!run().status.success());
    let root = graph.content_root();
    drop(graph);
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let batch: training::Batch = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(batch.examples.len(), expected);
    assert_eq!(batch.knowledge, naome_knowledge::hex(&root));
    let receiver = directory.join("receiver");
    let mut graph = Graph::open(&receiver).unwrap();
    for example in batch.examples {
        assert!(example.input.context.is_empty());
        graph.ingest(example.target.proof, Instant::now()).unwrap();
    }
    assert_eq!(graph.accepted_count(), expected);
    drop(graph);
    fs::write(&input, br#"{"operation":"questions","partition":"reserved","after":null,"scan":16,"unexpected":true}"#).unwrap();
    assert!(!run().status.success());
    let graph = Graph::open(&node).unwrap();
    assert_eq!(graph.content_root(), root);
    drop(graph);
    fs::remove_dir_all(directory).unwrap();
}
