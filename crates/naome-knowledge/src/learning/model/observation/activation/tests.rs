use super::*;
use crate::learning::{self as native, graph::Batch, model::Pool, tests::MemoryStore};

fn graph() -> Graph {
    let solution = native::tests::own_solution();
    let q = naome_authoring::CompiledQuestion::compile(&native::tests::own_question()).unwrap();
    native::search::compile(q.proved_target(), &solution.tree)
        .unwrap()
        .1
        .remove(0)
}

#[test]
fn detached_activation_observation_preserves_scores_and_next_adam_update() {
    let g = graph();
    let pool = Pool::from_graphs(std::slice::from_ref(&g));
    let fresh = Checkpoint::fresh();
    let mut io = MemoryStore::default();
    let mut observed = Runtime::load(&fresh, &mut io).unwrap();
    let mut silent = Runtime::load(&fresh, &mut io).unwrap();
    let mut observed_cursor = 193;
    let mut silent_cursor = 193;
    observed.train(&pool, &mut observed_cursor, 1).unwrap();
    silent.train(&pool, &mut silent_cursor, 1).unwrap();
    let checkpoint = observed.checkpoint(&fresh, 1, &mut io).unwrap();
    assert_eq!(checkpoint, silent.checkpoint(&fresh, 1, &mut io).unwrap());
    let expected = observed
        .scores_graph(&g)
        .unwrap()
        .iter()
        .map(|v| v.to_bits())
        .collect::<Vec<_>>();
    let first = observed
        .policy
        .valid()
        .activations(
            &[&g],
            &observed.device.clone().inner(),
            observed.recurrent(),
        )
        .unwrap();
    let second = observed
        .policy
        .valid()
        .activations(
            &[&g],
            &observed.device.clone().inner(),
            observed.recurrent(),
        )
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first[0].score_bits, expected);
    assert_eq!(first[0].graph, g.key());
    assert_eq!(first[0].state, g.binding);
    assert_eq!(first[0].actions.len(), g.candidates.len());
    assert_eq!(first[0].node_count, g.nodes.len() - 1);
    assert!(serde_json::to_vec(&first).unwrap().len() < 32 * 1024);
    assert_eq!(
        observed.checkpoint(&checkpoint, 0, &mut io).unwrap(),
        checkpoint
    );
    let observed_loss = observed.train(&pool, &mut observed_cursor, 1).unwrap();
    let silent_loss = silent.train(&pool, &mut silent_cursor, 1).unwrap();
    assert_eq!(observed_cursor, silent_cursor);
    assert_eq!(observed_loss.0.to_bits(), silent_loss.0.to_bits());
    assert_eq!(observed_loss.1.to_bits(), silent_loss.1.to_bits());
    assert_eq!(
        observed.checkpoint(&checkpoint, 1, &mut io).unwrap(),
        silent.checkpoint(&checkpoint, 1, &mut io).unwrap()
    );
    let mut state = native::State::fresh();
    state.accept(native::tests::own_example()).unwrap();
    let job = state.job();
    let report = inspect(&job, &checkpoint, &mut io).unwrap();
    assert!(!report["measurements"].as_array().unwrap().is_empty());
    assert_eq!(report["checkpoint_binding"], digest(&checkpoint));
    assert_eq!(report["job_binding"], digest(&job));
}

#[test]
fn observer_maps_disjoint_graphs_without_sentinel_or_candidate_padding() {
    let g = graph();
    let mut larger = g.clone();
    larger.binding = "fa".repeat(32);
    while larger.nodes.len() < 64 {
        larger.nodes.push(native::graph::Node {
            kind: 6,
            left: 0,
            right: 0,
            role: 2,
        });
        larger.context.push(larger.nodes.len() - 1);
    }
    let mut single = g.clone();
    single.context.clear();
    single.candidates.truncate(1);
    single.expert = 0;
    single.successes = vec![0];
    let graphs = [&g, &larger, &single];
    let mut io = MemoryStore::default();
    let runtime = Runtime::load(&Checkpoint::fresh(), &mut io).unwrap();
    let batch = Batch::from_graphs(&graphs, &runtime.device.clone().inner()).unwrap();
    for recurrent in [false, true] {
        let expected = runtime
            .policy
            .valid()
            .independent(&batch, recurrent)
            .into_data()
            .try_to_vec::<f32>()
            .unwrap();
        let actual = runtime
            .policy
            .valid()
            .activations(&graphs, &runtime.device.clone().inner(), recurrent)
            .unwrap();
        let c = batch.candidates.dims()[1];
        for (i, g) in graphs.iter().enumerate() {
            assert_eq!(
                actual[i].score_bits,
                expected[i * c..i * c + g.candidates.len()]
                    .iter()
                    .map(|v| v.to_bits())
                    .collect::<Vec<_>>()
            );
            assert_eq!(actual[i].node_count, g.nodes.len() - 1);
            assert_eq!(actual[i].candidate_count, g.candidates.len());
            assert_eq!(actual[i].actions.len(), g.candidates.len());
            let separate = runtime
                .policy
                .valid()
                .activations(&[*g], &runtime.device.clone().inner(), recurrent)
                .unwrap();
            assert_eq!(actual[i].embedding_nodes, separate[0].embedding_nodes);
            assert_eq!(
                actual[i].message_three_nodes,
                separate[0].message_three_nodes
            );
        }
    }
    assert!(
        runtime
            .policy
            .activations(&graphs, &runtime.device, true)
            .is_err()
    );
    let too_many = vec![&g; 9];
    assert!(
        runtime
            .policy
            .valid()
            .activations(&too_many, &runtime.device.clone().inner(), true)
            .is_err()
    );
}
