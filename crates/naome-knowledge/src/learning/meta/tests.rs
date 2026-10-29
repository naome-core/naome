use super::*;
#[path = "tests/feedback.rs"]
mod feedback;
fn experience(context: u16, plan: Plan, before: u16, after: u16) -> Experience {
    let mut features = [0; CONTEXT];
    features[0] = context;
    Experience {
        job: 1,
        context: features,
        plan,
        source_model: "11".repeat(32),
        selected_model: if after > before { "22" } else { "11" }.repeat(32),
        candidate_model: Some("22".repeat(32)),
        source_epoch: 8,
        before,
        after,
        protected_loss: false,
        anchor_loss: false,
        transfer: super::super::transfer::Summary {
            before: super::super::transfer::Summary::prefix(before as usize / 5),
            after: super::super::transfer::Summary::prefix(after as usize / 5),
            observed: super::super::transfer::Summary::prefix(super::super::transfer::CASES),
        },
        lower_cpu_micros: 18_000_000,
        lower_wall_micros: 20_000_000,
    }
}
#[test]
fn neural_gradient_matches_finite_difference_and_outcomes_are_not_features() {
    let e = experience(700, Plan::mixture(), 24, 60);
    let n = model::Network::fresh(31);
    let (_, g) = n.gradient(&e);
    for i in [0, 19, 57, 696, 707, 708, 731, 732, 733, 734, 751, 752] {
        let mut plus = n.clone();
        let mut minus = n.clone();
        plus.weights[i] += 0.001;
        minus.weights[i] -= 0.001;
        let actual = (plus.gradient(&e).0 - minus.gradient(&e).0) / 0.002;
        assert!((actual - g[i]).abs() < 0.002, "{i}: {actual} != {}", g[i]);
    }
    let mut changed = e.clone();
    changed.after = 0;
    changed.protected_loss = true;
    changed.lower_cpu_micros = 170_000_000;
    assert_eq!(e.features(), changed.features());
    assert_ne!(e.targets(), changed.targets());
    let mut ordered = Plan::mixture();
    ordered.phases.swap(0, 2);
    assert_ne!(Plan::mixture().features(), ordered.features());
}
#[test]
fn real_neural_updates_learn_opposite_plan_effects_in_different_contexts() {
    let data = [
        experience(0, Plan::balanced(), 30, 78),
        experience(0, Plan::mixture(), 78, 30),
        experience(1000, Plan::balanced(), 78, 30),
        experience(1000, Plan::mixture(), 30, 78),
    ];
    let batch = data.iter().collect::<Vec<_>>();
    let mut n = model::Network::fresh(113);
    for _ in 0..900 {
        n.update(&batch).unwrap();
    }
    let predicted = data
        .iter()
        .map(|e| utility(n.forward(&e.features()).1))
        .collect::<Vec<_>>();
    assert!(
        predicted[0] > 0.25 && predicted[1] < -0.25 && predicted[2] < -0.25 && predicted[3] > 0.25,
        "{predicted:?}"
    );
    assert!(utility([0.1, 0.8, 0.1]) < utility([0.08, 0., 0.1]));
    assert!(utility([0.1, 0., 1.5]) < utility([0.1, 0., 0.1]));
}
#[test]
fn exact_paired_meta_adam_restore_preserves_the_next_real_update() {
    let e = experience(300, Plan::mixture(), 30, 60);
    let mut n = model::Network::fresh(71);
    for _ in 0..7 {
        n.update(&[&e]).unwrap();
    }
    let (w, o) = n.encode();
    let mut restored = model::Network::decode(&w, &o, 7).unwrap();
    n.update(&[&e]).unwrap();
    restored.update(&[&e]).unwrap();
    assert_eq!(n.encode(), restored.encode());
    assert!(model::Network::decode(&w, &o, 8).is_err());
    let mut corrupt = w.clone();
    corrupt[..4].copy_from_slice(&f32::NAN.to_le_bytes());
    assert!(model::Network::decode(&corrupt, &o, 7).is_err());
    assert!(model::Network::decode(&w, &o[..o.len() - 1], 7).is_err());
}
#[test]
fn maximum_typed_meta_memory_fits_its_existing_state_headroom() {
    let mut state = State::fresh();
    state.trials = u64::MAX / UPDATES;
    state.draw = u64::MAX;
    state.model.seed = u64::MAX;
    state.model.updates = state.trials * UPDATES;
    let mut optimizer = vec![0; 8 + PARAMETERS * 8];
    optimizer[..8].copy_from_slice(&state.model.updates.to_le_bytes());
    state.model.weights = Some(Blob::of(&vec![0; PARAMETERS * 4]));
    state.model.optimizer = Some(Blob::of(&optimizer));
    for i in 0..MEMORY {
        let mut e = experience(1000, Plan::balanced(), 120, 120);
        e.job = u64::MAX - i as u64;
        e.context = [1000; CONTEXT];
        e.source_epoch = u64::MAX;
        e.lower_cpu_micros = u64::MAX;
        e.lower_wall_micros = u64::MAX;
        state.memory.push(e);
    }
    state.validate().unwrap();
    let bytes = serde_json::to_vec(&state).unwrap();
    assert!(bytes.len() <= STATE_BYTES);
    let restored: State = serde_json::from_slice(&bytes).unwrap();
    restored.validate().unwrap();
    assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
    for (actual, expected) in restored.memory.iter().zip(&state.memory) {
        assert_eq!(
            serde_json::to_vec(actual).unwrap(),
            serde_json::to_vec(expected).unwrap()
        );
    }
    eprintln!(
        "maximum complete upper metadata: {} bytes, allowance {STATE_BYTES}",
        bytes.len()
    );
    let mut lower = super::super::State::fresh();
    lower.meta = state;
    assert_eq!(context(&lower)[31], 1000);
}
#[test]
fn meta_checkpoint_update_restores_and_scores_the_following_generated_plan() {
    let mut state = super::super::State::fresh();
    let mut engine = Engine::default();
    let mut io = super::super::tests::MemoryStore::default();
    let selection = engine.select(&state, &mut io).unwrap();
    let mut e = experience(500, selection.plan.clone(), 30, 45);
    e.context = selection.context;
    e.source_model = super::super::digest(&state.model);
    e.source_epoch = state.epoch;
    let update = engine.learn(&state, &selection, e, &mut io).unwrap();
    assert_eq!(update.model.updates, UPDATES);
    assert_eq!(update.model.weights.as_ref().unwrap().bytes, PARAMETERS * 4);
    state.meta.model = update.model;
    state.meta.memory = vec![update.experience];
    state.meta.trials = 1;
    state.meta.draw = update.draw;
    state.meta.validate().unwrap();
    let a = engine.select(&state, &mut io).unwrap();
    let b = Engine::default().select(&state, &mut io).unwrap();
    assert_eq!(
        serde_json::to_vec(&a).unwrap(),
        serde_json::to_vec(&b).unwrap()
    );
    assert_ne!(a.prediction, [0.; 3]);
    let mut ids = std::collections::BTreeSet::new();
    let mut random = 19;
    for _ in 0..64 {
        let p = Plan::random(&mut random);
        p.validate().unwrap();
        ids.insert(super::super::digest(&p));
    }
    assert!(
        ids.len() > 48,
        "grammar explores compositions, not only a fixed strategy table"
    );
}

#[test]
fn improving_development_proxy_does_not_replace_transfer_targets() {
    let mut e = experience(500, Plan::targeted(), 45, 49);
    e.transfer = super::super::transfer::Summary {
        before: 3,
        after: 12,
        observed: super::super::transfer::Summary::prefix(super::super::transfer::CASES),
    };
    assert_eq!(e.targets()[0], 0.);
    assert!(e.targets()[1] > 0.);
    assert!(!e.transfer.accepts());
    let input = e.features();
    e.transfer.after = 7;
    e.selected_model = e.candidate_model.clone().unwrap();
    assert_eq!(input, e.features());
    assert!(e.targets()[0] > 0.);
    assert_eq!(e.targets()[1], 0.);
}

#[test]
fn meta_learning_rejects_substituted_context_plan_or_original_model() {
    let state = super::super::State::fresh();
    let mut io = super::super::tests::MemoryStore::default();
    let selection = Engine::default().select(&state, &mut io).unwrap();
    let mut original = experience(500, selection.plan.clone(), 30, 45);
    original.context = selection.context;
    original.source_model = super::super::digest(&state.model);
    original.source_epoch = state.epoch;
    for mutation in 0..4 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.context[12] = (changed.context[12] + 1) % 1001,
            1 => changed.plan.phases[0].focused = !changed.plan.phases[0].focused,
            2 => changed.source_model = "33".repeat(32),
            _ => changed.source_epoch += 1,
        }
        assert!(
            Engine::default()
                .learn(&state, &selection, changed, &mut io)
                .is_err()
        );
        assert!(
            io.0.is_empty(),
            "reject before any optimizer artifact write"
        );
    }
}
