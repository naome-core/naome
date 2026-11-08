use super::*;

fn learned_state() -> (State, MemoryStore, meta::Engine) {
    let mut state = State::fresh();
    let mut io = MemoryStore::default();
    // Transport-only native blobs; this fixture never loads a Solver runtime.
    state.model.model = Some(artifact::save(&mut io, b"native parameter transport").unwrap());
    state.model.optimizer = Some(artifact::save(&mut io, b"native Adam transport").unwrap());
    state.feedback = crate::training::ability::Feedback::fresh(digest(&state.model));
    state.accept(crate::learning::tests::own_example()).unwrap();
    let mut engine = meta::Engine::default();
    let selection = engine.select(&state, &mut io).unwrap();
    let experience = meta::Experience {
        job: 1,
        context: selection.context,
        plan: selection.plan.clone(),
        source_model: digest(&state.model),
        selected_model: digest(&state.model),
        candidate_model: None,
        source_epoch: state.epoch,
        before: 0,
        after: 0,
        protected_loss: false,
        anchor_loss: false,
        transfer: crate::learning::transfer::Summary::default(),
        lower_cpu_micros: 18_000_000,
        lower_wall_micros: 20_000_000,
    };
    let update = engine
        .learn(&state, &selection, experience, &mut io)
        .unwrap();
    state.meta.model = update.model;
    state.meta.memory.push(update.experience);
    state.meta.draw = update.draw;
    state.meta.trials = 1;
    state.validate().unwrap();
    (state, io, engine)
}

#[test]
fn complete_checkpoint_restores_all_four_blobs_and_the_next_meta_update() {
    let directory = Directory::new();
    let path = directory.0.join("selected");
    let (state, mut io, mut engine) = learned_state();
    let exported = export(&path, &state, &mut io).unwrap();
    let (restored, mut reloaded, imported) = import(&path).unwrap();
    assert_eq!(exported.bytes, imported.bytes);
    assert_eq!(exported.operations, 5);
    assert_eq!(imported.operations, 5);
    assert_eq!(digest(&state), digest(&restored));
    assert_eq!(state.blobs().count(), 4);
    for blob in state.blobs() {
        assert_eq!(
            artifact::load(&mut io, blob).unwrap(),
            artifact::load(&mut reloaded, blob).unwrap()
        );
    }
    let before = engine.select(&state, &mut io).unwrap();
    let mut cold = meta::Engine::default();
    let after = cold.select(&restored, &mut reloaded).unwrap();
    assert_eq!(
        serde_json::to_vec(&before).unwrap(),
        serde_json::to_vec(&after).unwrap()
    );
    let mut experience = state.meta.memory[0].clone();
    experience.job = 2;
    experience.context = before.context;
    experience.plan = before.plan.clone();
    experience.lower_cpu_micros /= 2;
    let a = engine
        .learn(&state, &before, experience.clone(), &mut io)
        .unwrap();
    let b = cold
        .learn(&restored, &after, experience, &mut reloaded)
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&a).unwrap(),
        serde_json::to_vec(&b).unwrap()
    );
    assert_eq!(b.model.updates, 16);
    assert!(export(&path, &state, &mut io).is_err());
}

#[test]
fn missing_truncated_or_corrupt_meta_adam_cannot_reopen_a_selected_state() {
    let directory = Directory::new();
    let path = directory.0.join("selected");
    let (state, mut io, _) = learned_state();
    export(&path, &state, &mut io).unwrap();
    let blob = state.meta.model.optimizer.as_ref().unwrap();
    let file = path.join("blobs").join(&blob.sha256);
    let original = std::fs::read(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    assert!(import(&path).is_err());
    std::fs::write(&file, &original[..original.len() - 1]).unwrap();
    assert!(import(&path).is_err());
    let mut corrupt = original.clone();
    corrupt[8] ^= 1;
    std::fs::write(&file, corrupt).unwrap();
    assert!(import(&path).is_err());
    std::fs::write(&file, &original).unwrap();
    assert!(import(&path).is_ok());
    std::fs::write(&file, [original, vec![0]].concat()).unwrap();
    assert!(import(&path).is_err());
}

#[test]
#[ignore = "explicit actual-state persistence audit; no new Solver inference or optimization"]
fn reopen_actual_continuation_states() {
    let input = std::path::PathBuf::from(std::env::var("NAOME_STATE_REOPEN_INPUT").unwrap());
    let recovered = std::path::PathBuf::from(std::env::var("NAOME_STATE_REOPEN_META").unwrap());
    let output = std::path::PathBuf::from(std::env::var("NAOME_STATE_REOPEN_OUTPUT").unwrap());
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let mut rows = Vec::new();
    for arm in ["joint", "uniform_finder", "frozen_solver"] {
        let source = input.join(format!("2309-{arm}"));
        let mut original_reads = Cost::default();
        let state: State = serde_json::from_slice(
            &read(
                &source.join("final-state.json"),
                128 * 1024,
                &mut original_reads,
            )
            .unwrap(),
        )
        .unwrap();
        state.validate().unwrap();
        let (native, mut io) =
            confirmation::import_model(&source.join("round-2/selected-model")).unwrap();
        assert_eq!(native, state.model);
        let recovered_meta: meta::State = serde_json::from_slice(
            &read(
                &recovered.join(arm).join("meta.json"),
                16 * 1024,
                &mut original_reads,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(digest(&state.meta), digest(&recovered_meta));
        for (name, blob) in [
            ("weights", &state.meta.model.weights),
            ("optimizer", &state.meta.model.optimizer),
        ] {
            if let Some(blob) = blob {
                let bytes = read(
                    &recovered.join(arm).join(format!("{name}.bpk")),
                    blob.bytes,
                    &mut original_reads,
                )
                .unwrap();
                assert_eq!(Blob::of(&bytes), *blob);
                assert_eq!(artifact::save(&mut io, &bytes).unwrap(), *blob);
            }
        }
        // Both runtimes are opened from actual paired native bytes. Snapshot
        // serializes parameters/Adam without a Solver forward or update.
        assert_eq!(
            Engine::default().snapshot(&state.model, &mut io).unwrap(),
            state.model
        );
        let expected = meta::Engine::default().select(&state, &mut io).unwrap();
        let path = output.join(arm);
        let written = export(&path, &state, &mut io).unwrap();
        let (restored, mut cold, loaded) = import(&path).unwrap();
        assert_eq!(digest(&state), digest(&restored));
        assert_eq!(
            Engine::default()
                .snapshot(&restored.model, &mut cold)
                .unwrap(),
            state.model
        );
        let actual = meta::Engine::default()
            .select(&restored, &mut cold)
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&expected).unwrap(),
            serde_json::to_vec(&actual).unwrap()
        );
        rows.push(
            json!({"arm":arm,"state_sha256":digest(&state),"model":state.model,
            "meta_model":state.meta.model,"blob_count":state.blobs().count(),
            "exact_native_runtime_snapshots":2,"exact_next_meta_selection":true,
            "checkpoint_written_bytes":written.bytes,"checkpoint_read_bytes":loaded.bytes,
            "solver_forward_calls":0,"solver_optimizer_updates":0,"meta_forward_selections":2}),
        );
    }
    write(
        &output.join("result.json"),
        &json!({"complete":true,"arms":rows,
        "new_meta_trials":0,"solver_forward_calls":0,"solver_optimizer_updates":0,
        "scope":"Actual paired native/Meta model-state reopen, not a new learning-quality result or a full history/Finder restart"}),
    );
}
