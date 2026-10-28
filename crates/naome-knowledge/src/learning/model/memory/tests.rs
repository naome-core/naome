use super::*;
use crate::learning::{self as native, search};

fn observed() -> (search::derivation::Derivation, search::trace::Trace) {
    struct Ordered;
    impl Ranker for Ordered {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(d.candidates
                .iter()
                .map(|c| if c.rule == Rule::ModusPonens { 1. } else { 0. })
                .collect())
        }
    }
    // Keep an unused double-negation choice at the descendant. Its checked
    // action label is then an actual reference state, not a single-choice tail.
    let question = naome_authoring::CompiledQuestion::compile("goal=all(a,all(b,all(c,all(d,imp(imp(mem(a,a),mem(b,b)),imp(imp(mem(b,b),mem(c,c)),imp(mem(a,a),imp(not(not(mem(d,d))),mem(c,c)))))))))").unwrap();
    let found = search::solve(question.proved_target(), &mut Ordered, 128).unwrap();
    let tree = found.tree.unwrap();
    let (term, _) = search::compile(question.proved_target(), &tree).unwrap();
    let checked = native::proof::verify(&term, question.proved_target()).unwrap();
    let derivation = search::derivation::checked(
        question.proved_target(),
        &tree,
        &crate::hex(checked.native_id.as_bytes()),
    )
    .unwrap();
    assert!(derivation.steps.len() >= 2);
    (derivation, found.execution.unwrap())
}

#[test]
fn native_memory_binds_real_symbolic_successors_and_exact_checkpoint() {
    let (derived, _) = observed();
    let mut io = native::tests::MemoryStore::default();
    let fresh = Checkpoint::fresh();
    let original = Runtime::load(&fresh, &mut io).unwrap();
    let saved = original.checkpoint(&fresh, 0, &mut io).unwrap();
    let runtime = Runtime::load(&saved, &mut io).unwrap();
    let (child_index, child) = derived
        .steps
        .iter()
        .enumerate()
        .find(|(_, s)| s.parent.is_some())
        .unwrap();
    let (parent_index, _) = child.parent.unwrap();
    assert!(parent_index < child_index);
    let parent = &derived.steps[parent_index];
    let plan = runtime
        .plan_graph(&parent.graph, &parent.offered, None)
        .unwrap();
    let memory = plan
        .child(
            parent.graph.expert,
            child.graph.binding.clone(),
            child.offered.clone(),
        )
        .unwrap()
        .unwrap();
    let carried = runtime
        .plan_graph(&child.graph, &child.offered, Some(&memory))
        .unwrap();
    let reset = runtime
        .plan_graph(&child.graph, &child.offered, None)
        .unwrap();
    assert_ne!(
        carried.scores, reset.scores,
        "actual predecessor state must influence the next decision"
    );
    let restored = Runtime::load(&saved, &mut io).unwrap();
    assert_eq!(
        restored
            .plan_graph(&child.graph, &child.offered, Some(&memory))
            .unwrap()
            .scores,
        carried.scores
    );
    assert_eq!(
        runtime.checkpoint(&saved, 0, &mut io).unwrap(),
        saved,
        "working memory never updates weights or Adam"
    );
    for change in 0..5 {
        let mut wrong = memory.clone();
        match change {
            0 => wrong.model = "ef".repeat(32),
            1 => wrong.state = "ef".repeat(32),
            2 => wrong.offered = "ef".repeat(32),
            3 => wrong.values.pop().map(drop).unwrap(),
            _ => wrong.values[0] = f32::NAN,
        }
        assert!(
            runtime
                .plan_graph(&child.graph, &child.offered, Some(&wrong))
                .is_err()
        );
    }
    let mut reset_runtime = Runtime::load(&saved, &mut io).unwrap();
    reset_runtime.recurrence = Recurrence::Reset;
    let reset_plan = reset_runtime
        .plan_graph(&parent.graph, &parent.offered, None)
        .unwrap();
    assert_eq!(
        reset_plan.scores, plan.scores,
        "equal internal work starts from the same zero state"
    );
    assert_eq!(
        reset_plan.successors, plan.successors,
        "the compute control also calculates every candidate transition"
    );
    assert!(
        reset_plan
            .child(
                parent.graph.expert,
                child.graph.binding.clone(),
                child.offered.clone()
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn only_observed_predecessors_carry_training_state_and_gradient() {
    let (derived, trace) = observed();
    let windows = trace.windows(&[(0, &derived)]).unwrap();
    let window = windows.iter().max_by_key(|w| w.len()).unwrap();
    assert!(window.len() >= 2);
    let (mut omitted, _) = observed();
    omitted
        .steps
        .retain(|s| s.graph.binding == derived.steps[window.last().unwrap().1].graph.binding);
    assert!(
        trace
            .windows(&[(0, &omitted)])
            .unwrap()
            .iter()
            .all(|w| w.len() == 1),
        "an unavailable predecessor cuts the gradient window"
    );
    let sample: Vec<_> = window
        .iter()
        .enumerate()
        .map(|(i, (_, step))| native::pool::Sample {
            graph: &derived.steps[*step].graph,
            selected: derived.steps[*step].graph.expert,
            parent: (i > 0).then(|| i - 1),
            auxiliary: false,
        })
        .collect();
    let graphs: Vec<_> = sample.iter().map(|s| s.graph).collect();
    let mut io = native::tests::MemoryStore::default();
    let fresh = Checkpoint::fresh();
    let carry = Runtime::load(&fresh, &mut io).unwrap();
    let mut reset = Runtime::load(&fresh, &mut io).unwrap();
    reset.recurrence = Recurrence::Reset;
    let batch = Batch::from_graphs(&graphs, &carry.device).unwrap();
    let carried = carry.sequence_scores(&batch, &sample).unwrap();
    let independent = reset.sequence_scores(&batch, &sample).unwrap();
    let actual = carried.clone().into_data().try_to_vec::<f32>().unwrap();
    let control = independent.clone().into_data().try_to_vec::<f32>().unwrap();
    let width = batch.candidates.dims()[1];
    assert_eq!(&actual[..width], &control[..width]);
    assert_ne!(&actual[width..], &control[width..]);
    let mut future = sample.last().unwrap().graph.clone();
    let future_node = future.candidates[future.expert];
    future.nodes[future_node].role = (future.nodes[future_node].role + 1) % 4;
    let mut changed_inputs = graphs.clone();
    *changed_inputs.last_mut().unwrap() = &future;
    let changed_batch = Batch::from_graphs(&changed_inputs, &carry.device).unwrap();
    let changed = carry
        .sequence_scores(&changed_batch, &sample)
        .unwrap()
        .into_data()
        .try_to_vec::<f32>()
        .unwrap();
    assert_eq!(
        &changed[..width],
        &actual[..width],
        "packed future nodes cannot influence the predecessor representation"
    );
    let end = (sample.len() - 1)..sample.len();
    // A final decision loss backpropagates through the actual predecessor's
    // chosen action state. Both controls have the same parameter layout.
    let carry_gradient = GradientsParams::from_grads(
        carried.slice([end.clone(), 0..width]).sum().backward(),
        &carry.policy,
    );
    let reset_gradient = GradientsParams::from_grads(
        independent.slice([end.clone(), 0..width]).sum().backward(),
        &reset.policy,
    );
    let mut carry_updated = carry;
    carry_updated.policy =
        carry_updated
            .optimizer
            .step(0.001, carry_updated.policy.clone(), carry_gradient);
    reset.policy = reset
        .optimizer
        .step(0.001, reset.policy.clone(), reset_gradient);
    assert_ne!(
        carry_updated.checkpoint(&fresh, 1, &mut io).unwrap().model,
        reset.checkpoint(&fresh, 1, &mut io).unwrap().model
    );
}

#[test]
fn batch_observation_preserves_actual_model_adam_loss_and_cursor() {
    let (derived, _) = observed();
    let mut pool = Pool::default();
    pool.add(
        false,
        "actual-training-family",
        "actual-training-dependency",
        derived.source_proof.as_ref().unwrap(),
        derived
            .steps
            .iter()
            .filter(|s| s.graph.candidates.len() > 1)
            .map(|s| s.graph.clone())
            .collect(),
    )
    .unwrap();
    pool.add_derivation(derived, true).unwrap();
    let fresh = Checkpoint::fresh();
    let mut io = native::tests::MemoryStore::default();
    let mut observed = Runtime::load(&fresh, &mut io).unwrap();
    let mut silent = Runtime::load(&fresh, &mut io).unwrap();
    silent.observe_batches = false;
    let mut observed_cursor = 71;
    let mut silent_cursor = 71;
    let observed_loss = observed.train(&pool, &mut observed_cursor, 1).unwrap();
    let silent_loss = silent.train(&pool, &mut silent_cursor, 1).unwrap();
    assert_eq!(observed_loss.0.to_bits(), silent_loss.0.to_bits());
    assert_eq!(observed_loss.1.to_bits(), silent_loss.1.to_bits());
    assert_eq!(observed_cursor, silent_cursor);
    assert_eq!(
        observed.checkpoint(&fresh, 1, &mut io).unwrap(),
        silent.checkpoint(&fresh, 1, &mut io).unwrap()
    );
    assert_eq!(observed.measurements.slots, 16);
    assert!(observed.measurements.cost_targets > 0);
    assert_eq!(silent.measurements.slots, 0);
    assert!(
        crate::checkpoint::encode(&observed.measurements)
            .unwrap()
            .len()
            < 2048
    );
    let mut total = TrainingMeasurements::default();
    total.include(&observed.measurements).unwrap();
    let first = crate::checkpoint::encode(&total).unwrap();
    let mut restored: TrainingMeasurements = crate::checkpoint::decode(&first).unwrap();
    total.include(&observed.measurements).unwrap();
    restored.include(&observed.measurements).unwrap();
    assert_eq!(
        crate::checkpoint::encode(&total).unwrap(),
        crate::checkpoint::encode(&restored).unwrap()
    );
    assert_eq!(total.slots, 32);
    assert_ne!(total.input_digest, observed.measurements.input_digest);
}

#[test]
fn preservation_uses_current_checked_context_and_keeps_the_flat_control_exact() {
    let (derived, _) = observed();
    let mut pool = Pool::default();
    pool.add(
        false,
        "own",
        "own",
        derived.source_proof.as_ref().unwrap(),
        derived
            .steps
            .iter()
            .filter(|s| s.graph.candidates.len() > 1)
            .map(|s| s.graph.clone())
            .collect(),
    )
    .unwrap();
    pool.add_derivation(derived, true).unwrap();
    let fresh = Checkpoint::fresh();
    let mut io = native::tests::MemoryStore::default();
    let mut original = Runtime::load(&fresh, &mut io).unwrap();
    let mut flat = Runtime::load(&fresh, &mut io).unwrap();
    flat.independent_preservation = true;
    let mut contextual = Runtime::load(&fresh, &mut io).unwrap();
    let mut old_cursor = 71;
    let graphs = pool.batch(&mut old_cursor);
    let original_batch = Batch::from_graphs(&graphs, &original.device).unwrap();
    let memory = Some(Tensor::zeros([16, policy::WIDTH], &original.device));
    let original_scores = original
        .policy
        .readout(original.policy.encode(&original_batch), memory)
        .0;
    let mut flat_cursor = 71;
    let (flat_batch, flat_scores) = flat.preservation_scores(&pool, &mut flat_cursor).unwrap();
    assert_eq!(flat_cursor, old_cursor);
    assert_eq!(
        original_scores.clone().into_data(),
        flat_scores.clone().into_data()
    );
    let mut context_cursor = 71;
    let (context_batch, context_scores) = contextual
        .preservation_scores(&pool, &mut context_cursor)
        .unwrap();
    assert_eq!(context_cursor, old_cursor);
    assert_eq!(contextual.measurements.reference_slots, 16);
    assert!(contextual.measurements.reference_replayed_edges > 0);
    assert!((2..=4).contains(&contextual.measurements.reference_max_depth));
    assert_eq!(flat.measurements.reference_replayed_edges, 0);
    assert_eq!(contextual.measurements.slots, 0);
    assert_eq!(contextual.sampled_sequence_edges, 0);
    assert_ne!(
        contextual.measurements.reference_digest,
        flat.measurements.reference_digest
    );
    let update = |runtime: &mut Runtime, batch, scores| {
        let gradient = GradientsParams::from_grads(
            checked_marginal(scores, &batch).backward(),
            &runtime.policy,
        );
        runtime.policy = runtime
            .optimizer
            .step(0.001, runtime.policy.clone(), gradient);
    };
    update(&mut original, original_batch, original_scores);
    update(&mut flat, flat_batch, flat_scores);
    update(&mut contextual, context_batch, context_scores);
    let original = original.checkpoint(&fresh, 1, &mut io).unwrap();
    let flat = flat.checkpoint(&fresh, 1, &mut io).unwrap();
    let contextual = contextual.checkpoint(&fresh, 1, &mut io).unwrap();
    assert_eq!(
        flat, original,
        "the control reproduces the original full Adam update"
    );
    assert_ne!(
        contextual.model, flat.model,
        "checked reference context changes actual gradients"
    );
    assert_ne!(contextual.optimizer, flat.optimizer);
}
