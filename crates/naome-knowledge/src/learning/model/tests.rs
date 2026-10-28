use super::super::tests::MemoryStore;
use super::*;
#[test]
fn plain_inference_preserves_parameters_and_stable_float32_choices() {
    let example = super::super::tests::own_example();
    let q = naome_authoring::CompiledQuestion::compile(&example.question).unwrap();
    let graph = super::super::search::compile(q.proved_target(), &example.tree)
        .unwrap()
        .1
        .remove(0);
    let mut io = MemoryStore::default();
    let fresh = Checkpoint::fresh();
    let runtime = Runtime::load(&fresh, &mut io).unwrap();
    let before = runtime.checkpoint(&fresh, 0, &mut io).unwrap();
    let batch = Batch::from_graphs(
        std::slice::from_ref(&graph),
        &runtime.device.clone().inner(),
    )
    .unwrap();
    let reference = runtime
        .policy
        .valid()
        .forward(&batch)
        .into_data()
        .try_to_vec::<f32>()
        .unwrap();
    let actual = runtime.scores_graph(&graph).unwrap();
    assert_eq!(
        actual, reference,
        "canonical inference uses the detached input path"
    );
    let batch = Batch::from_graphs(std::slice::from_ref(&graph), &runtime.device).unwrap();
    let autodiff = runtime
        .policy
        .valid()
        .forward(&batch)
        .into_data()
        .try_to_vec::<f32>()
        .unwrap();
    for (a, b) in actual.iter().zip(&autodiff) {
        assert!((a - b).abs() <= 32.0 * f32::EPSILON * (1.0 + a.abs().max(b.abs())));
    }
    let selected = |scores: &[f32]| {
        (0..scores.len())
            .max_by(|a, b| scores[*a].total_cmp(&scores[*b]).then(b.cmp(a)))
            .unwrap()
    };
    assert_eq!(
        selected(&actual),
        selected(&autodiff),
        "well-separated choices are stable; near ties may change with float32 routing"
    );
    assert_eq!(runtime.checkpoint(&fresh, 0, &mut io).unwrap(), before);
}

#[test]
#[ignore = "Finite matched inference lifetime memory screen; run in an isolated process"]
fn matched_inference_device_memory_screen() {
    use super::super::graph::{Graph, Node};
    let legacy = std::env::var_os("NAOME_INFERENCE_AUTODIFF_INPUTS").is_some();
    let mut io = MemoryStore::default();
    let runtime = Runtime::load(&Checkpoint::fresh(), &mut io).unwrap();
    let meter = crate::resources::feedback::Meter::start();
    for iteration in 0..4096 {
        let count = 48 + iteration % 209;
        let graph = Graph {
            binding: String::new(),
            nodes: (0..count)
                .map(|i| Node {
                    kind: if i == 0 { 0 } else { 1 + (i % 7) as i32 },
                    left: i / 2,
                    right: i / 3,
                    role: 2,
                })
                .collect(),
            goal: count - 1,
            context: (1..33).collect(),
            candidates: (32..48).collect(),
            expert: 0,
            successes: vec![0],
        };
        let scores = if legacy {
            let batch = Batch::from_graphs(std::slice::from_ref(&graph), &runtime.device).unwrap();
            runtime
                .policy
                .valid()
                .forward(&batch)
                .into_data()
                .try_to_vec::<f32>()
                .unwrap()
        } else {
            let batch = Batch::from_graphs(
                std::slice::from_ref(&graph),
                &runtime.device.clone().inner(),
            )
            .unwrap();
            runtime
                .policy
                .valid()
                .forward(&batch)
                .into_data()
                .try_to_vec::<f32>()
                .unwrap()
        };
        assert_eq!(scores.len(), 16);
        assert!(scores.iter().all(|v| v.is_finite()));
    }
    let sample = meter.finish(0, true);
    eprintln!(
        "native_inference_lifetime legacy_autodiff_inputs={legacy} calls=4096 sample={sample:?}"
    );
    if !legacy {
        assert!(sample.peak_rss_bytes.unwrap() <= REQUIREMENTS.work_bytes as u64);
    }
}
#[test]
#[ignore = "Bounded maximum-shape native model memory measurement"]
fn maximum_supported_batch_memory_is_bounded() {
    use super::super::graph::{Graph, Node};
    let nodes = (0..256)
        .map(|i| Node {
            kind: if i == 0 { 0 } else { 1 + (i % 7) as i32 },
            left: i / 2,
            right: i / 3,
            role: if i == 255 { 1 } else { 2 },
        })
        .collect();
    let graph = Graph {
        binding: String::new(),
        nodes,
        goal: 255,
        context: (1..33).collect(),
        candidates: (32..48).collect(),
        expert: 0,
        successes: vec![0],
    };
    let mut io = MemoryStore::default();
    let fresh = Checkpoint::fresh();
    let mut rng = 71;
    let meter = crate::resources::feedback::Meter::start();
    let mut runtime = Runtime::load(&fresh, &mut io).unwrap();
    runtime
        .train(
            &Pool::from_graphs(std::slice::from_ref(&graph)),
            &mut rng,
            1,
        )
        .unwrap();
    let trained = runtime.checkpoint(&fresh, 1, &mut io).unwrap();
    let mut candidate = Runtime::load(&trained, &mut io).unwrap();
    let pool = Pool::from_graphs(&[graph]);
    candidate
        .train_using(
            &pool,
            &mut rng,
            1,
            super::super::meta::Phase {
                focused: true,
                rehearsal: true,
                ranking_quarters: 2,
                gentle_rate: true,
            },
            Some((&pool, 0)),
            preservation::Mode::default(),
        )
        .unwrap();
    candidate.checkpoint(&trained, 1, &mut io).unwrap();
    assert!(candidate.preservation_micros > 0);
    let sample = meter.finish(0, true);
    assert!(sample.peak_rss_bytes.unwrap() <= REQUIREMENTS.work_bytes as u64);
    eprintln!(
        "native_maximum_shape batch=16 nodes=256 candidates=16 parameters={} sample={:?}",
        PARAMETERS, sample
    );
}
#[test]
fn sparse_packed_graphs_preserve_the_dense_sixteen_graph_adam_update() {
    let solution = super::super::tests::own_solution();
    let q =
        naome_authoring::CompiledQuestion::compile(&super::super::tests::own_question()).unwrap();
    let graph = super::super::search::compile(q.proved_target(), &solution.tree)
        .unwrap()
        .1
        .remove(0);
    let mut larger = graph.clone();
    while larger.nodes.len() < graph.nodes.len().next_power_of_two() + 1 {
        larger.nodes.push(super::super::graph::Node {
            kind: 6,
            left: 0,
            right: 0,
            role: 2,
        });
        larger.context.push(larger.nodes.len() - 1);
    }
    let mut empty_context = graph.clone();
    empty_context.context.clear();
    let pool = Pool::from_graphs(&[graph.clone(), larger, empty_context]);
    let sample = pool.batch(&mut 0);
    let fresh = Checkpoint::fresh();
    let mut io = MemoryStore::default();
    let mut dense = Runtime::load(&fresh, &mut io).unwrap();
    let mut sparse = Runtime::load(&fresh, &mut io).unwrap();
    let batch = Batch::from_graphs(&sample, &dense.device).unwrap();
    let joint = sparse
        .policy
        .valid()
        .forward(&batch)
        .into_data()
        .try_to_vec::<f32>()
        .unwrap();
    let width = batch.candidates.dims()[1];
    for (index, graph) in sample.iter().enumerate() {
        let separate = sparse.scores_graph(graph).unwrap();
        for (action, value) in separate.iter().enumerate() {
            assert!(
                (joint[index * width + action] - value).abs() < 1e-4,
                "an unrelated graph changed this graph's action score"
            );
        }
    }
    let probability =
        burn::tensor::activation::log_softmax(dense.policy.forward_dense(&batch), 1).exp();
    let loss = -(probability * batch.successes)
        .sum_dim(1)
        .clamp_min(1e-12)
        .log()
        .mean();
    let expected_loss = loss.clone().into_data().try_to_vec::<f32>().unwrap()[0];
    let gradients = GradientsParams::from_grads(loss.backward(), &dense.policy);
    dense.policy = dense.optimizer.step(0.001, dense.policy.clone(), gradients);
    let (actual_loss, _) = sparse.train(&pool, &mut 0, 1).unwrap();
    assert!((expected_loss - actual_loss).abs() < 1e-5);
    let a = dense.scores_graph(&graph).unwrap();
    let b = sparse.scores_graph(&graph).unwrap();
    let maximum = a
        .iter()
        .zip(b)
        .map(|(a, b)| (a - b).abs())
        .fold(0f32, f32::max);
    assert!(
        maximum < 1e-4,
        "sparse parent prediction difference {maximum}"
    );
}
#[test]
fn zero_update_snapshot_preserves_fresh_predictions_and_optimizer_continuation() {
    let solution = super::super::tests::own_solution();
    let q =
        naome_authoring::CompiledQuestion::compile(&super::super::tests::own_question()).unwrap();
    let graph = super::super::search::compile(q.proved_target(), &solution.tree)
        .unwrap()
        .1
        .remove(0);
    let mut io = MemoryStore::default();
    let fresh = Checkpoint::fresh();
    let runtime = Runtime::load(&fresh, &mut io).unwrap();
    let expected = runtime.scores_graph(&graph).unwrap();
    let saved = Engine::default().snapshot(&fresh, &mut io).unwrap();
    assert_eq!(saved.updates, 0);
    assert_eq!(
        Runtime::load(&saved, &mut io)
            .unwrap()
            .scores_graph(&graph)
            .unwrap(),
        expected
    );
    let from_seed = test_update(&fresh, std::slice::from_ref(&graph), &mut 91, &mut io).unwrap();
    let from_saved = test_update(&saved, &[graph], &mut 91, &mut io).unwrap();
    assert_eq!(
        from_seed, from_saved,
        "initial binary model and optimizer must reproduce the same first real update"
    );
}
#[test]
fn research_policy_trains_and_restores_both_million_parameter_model_and_adam() {
    let source = super::super::tests::own_question();
    struct Ordered;
    impl Ranker for Ordered {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(vec![0.; d.candidates.len()])
        }
    }
    let solution = super::super::search_question(&source, &mut Ordered, 128)
        .unwrap()
        .0
        .expect("own checked trace");
    let q = naome_authoring::CompiledQuestion::compile(&source).unwrap();
    let (_, graphs) = super::super::search::compile(q.proved_target(), &solution.tree).unwrap();
    assert!(!graphs.is_empty());
    let graphs = vec![graphs.into_iter().min_by_key(|g| g.nodes.len()).unwrap()];
    let mut io = MemoryStore::default();
    let fresh = Checkpoint::fresh();
    let mut rng = 17;
    let started = std::time::Instant::now();
    let mut runtime = Runtime::load(&fresh, &mut io).unwrap();
    let (first, last) = runtime
        .train(&Pool::from_graphs(&graphs), &mut rng, 1)
        .unwrap();
    let trained = runtime.checkpoint(&fresh, 1, &mut io).unwrap();
    assert_eq!(trained.updates, 1);
    assert!(first.is_finite() && last.is_finite());
    assert_ne!(fresh, trained);
    assert!(trained.model.as_ref().unwrap().bytes >= PARAMETERS * 4);
    assert!(trained.optimizer.as_ref().unwrap().bytes >= PARAMETERS * 8);
    assert!(serde_json::to_vec(&trained).unwrap().len() < 1024);
    let mut resumed = Runtime::load(&trained, &mut io).unwrap();
    let mut continued_rng = rng;
    runtime
        .train(&Pool::from_graphs(&graphs), &mut continued_rng, 1)
        .unwrap();
    let continued = runtime.checkpoint(&trained, 1, &mut io).unwrap();
    resumed
        .train(&Pool::from_graphs(&graphs), &mut rng, 1)
        .unwrap();
    let restored = resumed.checkpoint(&trained, 1, &mut io).unwrap();
    assert_eq!(
        continued, restored,
        "resume must preserve weights and Adam moments exactly"
    );
    let blob = trained.model.as_ref().unwrap();
    io.0.get_mut(&(blob.sha256.clone(), 0)).unwrap()[0] ^= 1;
    assert!(
        Engine::default()
            .with(&trained, &mut io, |_| Ok(()))
            .is_err(),
        "corruption cannot silently initialize new weights"
    );
    eprintln!(
        "native_model_operation parameters={} model_bytes={} optimizer_bytes={} updates={} elapsed_seconds={:.3}",
        PARAMETERS,
        trained.model.unwrap().bytes,
        trained.optimizer.unwrap().bytes,
        continued.updates,
        started.elapsed().as_secs_f64()
    );
}
