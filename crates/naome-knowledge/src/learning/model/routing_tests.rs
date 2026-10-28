use super::*;
use crate::learning::tests::MemoryStore;

#[test]
fn row_routing_preserves_logits_and_the_complete_adam_update_bitwise() {
    let solution = crate::learning::tests::own_solution();
    let question =
        naome_authoring::CompiledQuestion::compile(&crate::learning::tests::own_question())
            .unwrap();
    let graph = crate::learning::search::compile(question.proved_target(), &solution.tree)
        .unwrap()
        .1
        .remove(0);
    let mut larger = graph.clone();
    while larger.nodes.len() < 64 {
        larger.nodes.push(crate::learning::graph::Node {
            kind: 6,
            left: 0,
            right: 0,
            role: 2,
        });
        larger.context.push(larger.nodes.len() - 1);
    }
    let mut single = graph.clone();
    single.context.clear();
    single.candidates.truncate(1);
    single.expert = 0;
    single.successes = vec![0];
    let shapes = [graph, larger, single];
    for seed in [41, 73] {
        for count in [1, 3, 16] {
            let graphs = (0..count)
                .map(|i| shapes[i % shapes.len()].clone())
                .collect::<Vec<_>>();
            let mut fresh = Checkpoint::fresh();
            fresh.seed = seed;
            let mut io = MemoryStore::default();
            let mut reference = Runtime::load(&fresh, &mut io).unwrap();
            let mut indexed = Runtime::load(&fresh, &mut io).unwrap();
            let plain = Batch::from_graphs(&graphs, &indexed.device.clone().inner()).unwrap();
            let expected_plain = reference
                .policy
                .valid()
                .forward_reference(&plain)
                .into_data()
                .try_to_vec::<f32>()
                .unwrap();
            let actual_plain = indexed
                .policy
                .valid()
                .forward(&plain)
                .into_data()
                .try_to_vec::<f32>()
                .unwrap();
            assert_eq!(
                expected_plain
                    .iter()
                    .map(|v| v.to_bits())
                    .collect::<Vec<_>>(),
                actual_plain.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                "routing changed inference logits for seed {seed}, batch {count}"
            );
            let batch = Batch::from_graphs(&graphs, &indexed.device).unwrap();
            let expected = reference.policy.forward_reference(&batch);
            let actual = indexed.policy.forward(&batch);
            assert_eq!(
                expected
                    .clone()
                    .into_data()
                    .try_to_vec::<f32>()
                    .unwrap()
                    .iter()
                    .map(|v| v.to_bits())
                    .collect::<Vec<_>>(),
                actual
                    .clone()
                    .into_data()
                    .try_to_vec::<f32>()
                    .unwrap()
                    .iter()
                    .map(|v| v.to_bits())
                    .collect::<Vec<_>>(),
                "routing changed logits for seed {seed}, batch {count}"
            );
            // Exact checkpoint identities also cover gradient accumulation,
            // parameter updates and Adam continuation, not just predictions.
            for (runtime, logits) in [(&mut reference, expected), (&mut indexed, actual)] {
                let probability = burn::tensor::activation::log_softmax(logits, 1).exp();
                let loss = -(probability * batch.successes.clone())
                    .sum_dim(1)
                    .clamp_min(1e-12)
                    .log()
                    .mean();
                let gradients = GradientsParams::from_grads(loss.backward(), &runtime.policy);
                runtime.policy = runtime
                    .optimizer
                    .step(0.001, runtime.policy.clone(), gradients);
            }
            assert_eq!(
                reference.checkpoint(&fresh, 1, &mut io).unwrap(),
                indexed.checkpoint(&fresh, 1, &mut io).unwrap(),
                "routing changed model or Adam bytes for seed {seed}, batch {count}"
            );
        }
    }
}
