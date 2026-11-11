#![cfg(unix)]
use naome_knowledge::{Graph, training};
use std::{
    fs,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn training_selection_exports_recheckable_targets_from_the_checked_graph() {
    let directory = std::env::temp_dir().join(format!(
        "naome-training-selection-{}-{}",
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
        use naome_foundation::{Formula, FreeVariable};
        use naome_proof::{ProofCertificate, ProofStep};
        let x = FreeVariable::new(0);
        let mut formula = Formula::equal(x, x);
        let mut steps = vec![ProofStep::EqualityReflexivity { variable: x }];
        for premise in 0..n {
            let variable = FreeVariable::new(premise);
            formula = Formula::for_all(variable, formula);
            steps.push(ProofStep::Generalization { premise, variable });
        }
        let question = naome_checker::question::ResearchQuestion::from_formula(formula).unwrap();
        expected += usize::from(training::partition(&question) == training::Partition::Training);
        let bytes = ProofCertificate::new(steps).unwrap().to_canonical_bytes();
        let envelope = graph
            .author(&format!("00{}", naome_knowledge::hex(&bytes)))
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
    let root = graph.content_root();
    let training::Response::Batch(batch) =
        training::execute(&graph, &training::Command::Select { request }).unwrap()
    else {
        panic!("selection must return a batch");
    };
    assert_eq!(graph.content_root(), root);
    drop(graph);
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
    fs::remove_dir_all(directory).unwrap();
}
