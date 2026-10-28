use super::*;
use crate::learning::tests::MemoryStore;

fn graph() -> Graph {
    let example = crate::learning::tests::own_example();
    let question = naome_authoring::CompiledQuestion::compile(&example.question).unwrap();
    crate::learning::search::compile(question.proved_target(), &example.tree)
        .unwrap()
        .1
        .into_iter()
        .find(|g| g.candidates.len() > 1)
        .unwrap()
}

#[test]
fn repeated_scores_preserve_bits_and_still_validate_current_inputs() {
    let mut io = MemoryStore::default();
    let runtime = Runtime::load(&Checkpoint::fresh(), &mut io).unwrap();
    let mut graph = graph();
    let expected = runtime.scores_graph(&graph).unwrap();
    assert_eq!(runtime.scores_graph(&graph).unwrap(), expected);
    assert_eq!(runtime.scores.borrow().hits, 1);
    graph.expert = (graph.expert + 1) % graph.candidates.len();
    graph.successes = vec![graph.expert];
    assert_eq!(runtime.scores_graph(&graph).unwrap(), expected);
    assert_eq!(runtime.scores.borrow().hits, 2);
    graph.successes = vec![graph.candidates.len()];
    assert!(
        runtime.scores_graph(&graph).is_err(),
        "a hit must not bypass binding checks"
    );
    graph.successes = vec![0];
    graph.nodes[graph.goal].role ^= 1;
    let reference = Runtime::load(&Checkpoint::fresh(), &mut io).unwrap();
    assert_eq!(
        runtime.scores_graph(&graph).unwrap(),
        reference.scores_graph(&graph).unwrap()
    );
    assert_eq!(runtime.scores.borrow().misses, 2);
}

#[test]
fn an_actual_adam_update_invalidates_all_parent_predictions() {
    let graph = graph();
    let pool = Pool::from_graphs(std::slice::from_ref(&graph));
    let mut io = MemoryStore::default();
    let fresh = Checkpoint::fresh();
    let mut runtime = Runtime::load(&fresh, &mut io).unwrap();
    let before = runtime.scores_graph(&graph).unwrap();
    runtime.train(&pool, &mut 71, 1).unwrap();
    assert!(runtime.scores.borrow().values.is_empty());
    let checkpoint = runtime.checkpoint(&fresh, 1, &mut io).unwrap();
    let reference = Runtime::load(&checkpoint, &mut io).unwrap();
    let after = runtime.scores_graph(&graph).unwrap();
    assert_ne!(before, after);
    assert_eq!(after, reference.scores_graph(&graph).unwrap());
    assert_eq!(runtime.scores_graph(&graph).unwrap(), after);
    assert_eq!(runtime.checkpoint(&fresh, 1, &mut io).unwrap(), checkpoint);
}

#[test]
fn inference_storage_remains_bounded_through_eviction() {
    let mut graph = graph();
    let mut io = MemoryStore::default();
    let runtime = Runtime::load(&Checkpoint::fresh(), &mut io).unwrap();
    let expected = runtime.scores_graph(&graph).unwrap();
    for index in 0..=INFERENCE_ENTRIES {
        graph.binding = index.to_string();
        assert_eq!(runtime.scores_graph(&graph).unwrap(), expected);
        assert!(runtime.scores.borrow().values.len() <= INFERENCE_ENTRIES);
    }
}
