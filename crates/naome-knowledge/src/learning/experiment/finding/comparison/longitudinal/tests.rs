use super::*;

#[test]
fn failed_or_missing_calibration_cannot_construct_a_candidate_design() {
    let actual_negative = json!({"complete":true,"feasible":false,
        "reason":"track lemma_composition lacks three calibrated bands"});
    let error = design::Design::read(b"{}", &serde_json::to_vec(&actual_negative).unwrap())
        .err()
        .unwrap();
    assert!(error.contains("does not admit a trajectory"));
    let rates = [[1.; 6]; 3];
    let bands = [[1, 2, 3]; 3];
    let forged = json!({"complete":true,"feasible":true,"rates":rates,"bands":bands,"assessment_model_calls":0,"candidate_optimizer_updates":0});
    assert!(design::Design::read(b"{}", &serde_json::to_vec(&forged).unwrap()).is_err());
}

#[test]
fn single_step_quantified_demands_have_room_for_whole_family_splits() {
    let mut groups = BTreeSet::new();
    for root in 0..256 {
        for case in bank::cases(1, 1, root).unwrap() {
            groups.insert(case.construction);
        }
    }
    // The split needs32 whole families before old-source exclusions. Four
    // predicate styles produced only16, regardless of repeated root names.
    assert!(
        groups.len() >= 64,
        "insufficient actual predicate variation: {}",
        groups.len()
    );
}

#[test]
fn reference_calibration_rejects_a_ceiling_and_selects_the_frozen_first_triple() {
    assert!(calibration::bands(&[[1.0; 6]; 3]).is_err());
    assert!(calibration::bands(&[[0.0; 6]; 3]).is_err());
    let rates = [[0.9, 0.6, 0.4, 0.2, 0.15, 0.1]; 3];
    assert_eq!(calibration::bands(&rates).unwrap(), [[1, 2, 4]; 3]);
}

#[test]
fn question_family_groups_premise_order_and_keeps_demands_separate_from_answers() {
    let q = CompiledQuestion::compile("goal=all(x,all(y,imp(mem(x,y),imp(eq(x,y),mem(y,x)))))")
        .unwrap();
    let r = CompiledQuestion::compile("goal=all(x,all(y,imp(eq(x,y),imp(mem(x,y),mem(y,x)))))")
        .unwrap();
    assert_ne!(q.resolution_id(), r.resolution_id());
    assert_eq!(bank::near_family(&q), bank::near_family(&r));
    let bytes=serde_json::to_vec(&json!({"cases":[{"source":q.source(),"family":curriculum::owned::family(q.proved_target()),"resolution":crate::hex(q.resolution_id()),"lineage":"test construction"}]})).unwrap();
    let holdout = lineage::Holdout::read(&bytes, &crate::hex(&Sha256::digest(&bytes))).unwrap();
    assert!(
        holdout.question(&r, None).is_err(),
        "a premise-order alias must be rejected before model access"
    );
    for track in 0..TRACKS.len() {
        for recipe in 1..=6 {
            // Construction itself executes no solver, teacher or optimizer.
            let cases = bank::cases(track, recipe, 1057).unwrap();
            for case in cases {
                let q = CompiledQuestion::compile(&case.source).unwrap();
                assert_eq!(case.resolution, crate::hex(q.resolution_id()));
                assert_eq!(case.construction, bank::near_family(&q));
                assert!(State::eligible(q.source()));
            }
        }
    }
}

#[test]
fn assessment_barrier_requires_distinct_seeds_complete_arms_and_all_phases() {
    let identity = json!({"protocol":"test-only transport identity"});
    let mut matrix = Vec::new();
    for seed in SEEDS {
        for arm in [Arm::Adaptive, Arm::FrozenWeights, Arm::FixedChoices] {
            matrix.push(json!({"seed":seed,"arm":arm.name(),"complete":true,"assessment_model_calls":0,
            "design":identity,"phases":(1..=PHASES).map(|p|json!({"phase":p})).collect::<Vec<_>>(),
            "initial_state_sha256":"transport fixture","initial_model":seed,"initial_meta":seed,"initial_finder":seed}));
        }
    }
    barrier::headers(&matrix, &SEEDS, &identity).unwrap();
    let mut missing = matrix.clone();
    missing[3]["phases"].as_array_mut().unwrap().pop();
    assert!(barrier::headers(&missing, &SEEDS, &identity).is_err());
    assert!(barrier::headers(&matrix[..8], &SEEDS, &identity).is_err());
    let mut duplicate = matrix.clone();
    duplicate[3] = duplicate[0].clone();
    assert!(barrier::headers(&duplicate, &SEEDS, &identity).is_err());
    let mut unpaired = matrix.clone();
    unpaired[1]["initial_meta"] = json!("different Adam binding");
    assert!(barrier::headers(&unpaired, &SEEDS, &identity).is_err());
    assert!(barrier::headers(&matrix, &[SEEDS[0]; 3], &identity).is_err());
}

#[test]
fn early_knowledge_probe_preserves_the_selected_state_and_common_foundations() {
    let entry = |axiom: naome_foundation::ZfcAxiom| {
        let term =
            crate::learning::calculus::axiom(naome_proof::ProofStep::ZfcAxiom(axiom)).unwrap();
        let verified = proof::verify(&term, &axiom.formula()).unwrap();
        crate::learning::knowledge::Entry {
            packet: crate::learning::evidence::pack(&verified).unwrap(),
        }
    };
    let common = entry(naome_foundation::ZfcAxiom::Infinity);
    let early = entry(naome_foundation::ZfcAxiom::Pairing);
    let mut initial = State::fresh();
    initial.remember_theorem(common.clone()).unwrap();
    let mut later = initial.clone();
    later.remember_theorem(early.clone()).unwrap();
    let states = [
        initial,
        later.clone(),
        later.clone(),
        later.clone(),
        later.clone(),
        later,
    ];
    let before = digest(&states[PHASES]);
    let provenance = BTreeMap::from([
        (
            crate::hex(common.verified().unwrap().native_id.as_bytes()),
            0,
        ),
        (
            crate::hex(early.verified().unwrap().native_id.as_bytes()),
            1,
        ),
    ]);
    let removed = assessment::early_knowledge(&states[PHASES], &provenance).unwrap();
    assert_eq!(
        removed,
        BTreeSet::from([crate::hex(early.verified().unwrap().native_id.as_bytes())])
    );
    assert_eq!(
        assessment::without_early(&states[PHASES], &removed).unwrap(),
        vec![common]
    );
    assert_eq!(digest(&states[PHASES]), before);
}

#[test]
fn admitted_design_recomputes_complete_reference_coverage_and_all_family_splits() {
    let bank = bank::build(&[]).unwrap();
    let mut rows = Vec::new();
    for reference in 0..2 {
        let mut count = BTreeMap::new();
        for case in &bank.calibration {
            let position = count.entry((case.track, case.recipe)).or_insert(0usize);
            let successes = match case.recipe {
                1 => 9,
                2 => 6,
                3 => 3,
                _ => 0,
            };
            rows.push(json!({"reference":reference,"case":case,"solved":*position<successes}));
            *position += 1;
        }
    }
    // Parser fixture only: these declared outcomes are not an experiment and
    // are never exported as native calibration or candidate-quality evidence.
    let mut calibration = json!({"complete":true,"feasible":true,"rates":([[0.75,0.5,0.25,0.,0.,0.];3]),
        "bands":([[1,2,3];3]),"rows":rows,"assessment_model_calls":0,"candidate_optimizer_updates":0});
    let encoded = serde_json::to_vec(&bank).unwrap();
    let design =
        design::Design::read(&encoded, &serde_json::to_vec(&calibration).unwrap()).unwrap();
    assert_eq!(assessment::selected(&design, false).unwrap().len(), 216);
    assert_eq!(assessment::selected(&design, true).unwrap().len(), 108);
    for case in &design.bank.acquisition {
        let q = CompiledQuestion::compile(&case.source).unwrap();
        design.holdout.question(&q, None).unwrap();
    }
    calibration["rows"].as_array_mut().unwrap().pop();
    assert!(design::Design::read(&encoded, &serde_json::to_vec(&calibration).unwrap()).is_err());
}

#[test]
fn six_whole_checkpoints_reopen_native_meta_adam_and_finder_without_training() {
    for arm in [Arm::FrozenWeights, Arm::FixedChoices] {
        let directory = Directory::new();
        let mut state = State::fresh();
        let mut engine = Engine::default();
        let mut blobs = MemoryStore::default();
        state.model = engine.snapshot(&state.model, &mut blobs).unwrap();
        state.feedback = crate::training::ability::Feedback::fresh(digest(&state.model));
        state.meta.model = engine.meta.snapshot(&state.meta.model, &mut blobs).unwrap();
        state.validate().unwrap();
        let initial = digest(&state);
        let mut io = sources::history::Io::journal(blobs, &directory.0);
        let mut graph = crate::Graph::default();
        std::fs::create_dir(directory.0.join("finder")).unwrap();
        let mut finder = Frontier::open(
            &directory.0.join("finder"),
            &graph,
            state.model.seed,
            jobs::Settings {
                native_proof_learning: true,
                ..Default::default()
            },
        )
        .unwrap();
        finder.initial_parameters(97).unwrap();
        arm.finder(&mut finder);
        let mut meter = Meter::start().unwrap();
        for phase in 0..=PHASES {
            finder = checkpoint::save(
                &mut state,
                &mut graph,
                &mut io,
                &mut meter,
                finder,
                &directory.0,
                &directory.0.join(format!("phase-{phase}")),
                phase,
                arm,
            )
            .unwrap();
            assert_eq!(digest(&state), initial);
            assert_eq!(state.blobs().count(), 4);
            assert_eq!(engine.snapshot(&state.model, &mut io).unwrap(), state.model);
            assert_eq!(
                engine.meta.snapshot(&state.meta.model, &mut io).unwrap(),
                state.meta.model
            );
        }
        assert_eq!(state.model.updates, 0);
        assert_eq!(state.meta.model.updates, 0);
    }
}
