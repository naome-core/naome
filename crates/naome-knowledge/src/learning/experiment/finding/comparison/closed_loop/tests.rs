use super::*;

#[test]
fn completion_feedback_compacts_before_the_next_actual_source_snapshot() {
    let directory = Directory::new();
    let held = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let bytes = serde_json::to_vec(&json!({"cases":[{"source":held.source(),
        "resolution":crate::hex(held.resolution_id()),
        "family":curriculum::owned::family(held.proved_target()),"lineage":"held-fixture"}]}))
    .unwrap();
    let holdout = lineage::Holdout::read(&bytes, &crate::hex(&Sha256::digest(&bytes))).unwrap();
    let q = CompiledQuestion::compile(&crate::learning::tests::own_question()).unwrap();
    let mut solution = crate::learning::tests::own_solution();
    let mut state = State::fresh();
    state.accept(crate::learning::tests::own_example()).unwrap();
    state
        .remember_theorem(solution.theorem(&q).unwrap().unwrap())
        .unwrap();
    state.replay.push(state.replay[0].clone());
    let capacity = crate::resources::limits().closure_bytes.min(128 * 1024) / 4;
    let mut slack = capacity - crate::checkpoint::encode(&state).unwrap().len() - 1;
    for example in &mut state.replay {
        let padding =
            slack.min(naome_authoring::QUESTION_SOURCE_MAX_BYTES - example.question.len());
        example.question.push_str(&" ".repeat(padding));
        slack -= padding;
    }
    assert_eq!(slack, 0);
    state.validate().unwrap();
    let frozen = digest(&(
        &state.model,
        &state.meta,
        &state.anchors,
        &state.knowledge,
        state.sample_counts(),
        state.accepted,
        state.epoch,
    ));
    let cost = GenerationCost::default();
    solution.cost = Box::new(cost.clone());
    let generation = Generation {
        terminal: experience::TerminalEvidence::certified(&solution),
        solution: Some(solution.clone()),
        diagnostic: String::new(),
        cost,
        frontier: None,
        executions: Vec::new(),
    };
    let job = 42;
    let completion = completed_search(&state, &q, job, &generation, context(&state), SEARCH, 0);
    let mut control = state.clone();
    control.observe_result(q.source(), true, "", 0, SEARCH as u32);
    assert!(
        control.validate().is_err(),
        "fixture must cross the actual existing byte boundary"
    );
    let mut io = sources::history::Io::journal(MemoryStore::default(), &directory.0);
    let mut meter = Meter::start().unwrap();
    let mut ledger = lineage::Ledger::new(&holdout);
    let mut questions = BTreeSet::from([crate::hex(q.resolution_id())]);
    let mut proofs = BTreeSet::from([solution.proof_id]);
    let row = record(
        &mut state,
        &mut crate::Graph::default(),
        &mut io,
        &mut meter,
        &q,
        generation,
        completion,
        job,
        "fixture",
        &mut ledger,
        &holdout,
        &mut questions,
        &mut proofs,
        &directory.0,
    )
    .unwrap();
    state.validate().unwrap();
    assert!(crate::checkpoint::encode(&state).unwrap().len() <= capacity);
    assert_eq!(
        frozen,
        digest(&(
            &state.model,
            &state.meta,
            &state.anchors,
            &state.knowledge,
            state.sample_counts(),
            state.accepted,
            state.epoch
        ))
    );
    assert_eq!(state.feedback.attempts, control.feedback.attempts);
    assert_eq!(row["accepted_training"], false);
    assert!(state.replay.len() < control.replay.len());
    assert_eq!(io.episodes().len(), 1);
}

#[test]
#[ignore = "read-only diagnosis of actual failed current-contract source states"]
fn audit_actual_capacity_failures() {
    let input = std::path::PathBuf::from(std::env::var("NAOME_JOINT_FAILED_INPUT").unwrap());
    let output = std::path::PathBuf::from(std::env::var("NAOME_JOINT_CAPACITY_AUDIT").unwrap());
    assert!(!output.exists());
    let mut rows = Vec::new();
    for label in ["2101-joint", "2203-joint", "2203-uniform_finder"] {
        let mut state: State = serde_json::from_slice(
            &std::fs::read(input.join(label).join("final-state.json")).unwrap(),
        )
        .unwrap();
        let before = crate::checkpoint::encode(&state).unwrap().len();
        let frozen = digest(&(
            &state.model,
            &state.meta,
            &state.anchors,
            &state.knowledge,
            &state.definitions,
            &state.feedback,
            state.sample_counts(),
            state.accepted,
            state.epoch,
            state.trained,
            state.attempted,
        ));
        let error = state.validate().unwrap_err();
        let old_replay = state.replay.len();
        state.compact().unwrap();
        state.validate().unwrap();
        assert_eq!(
            frozen,
            digest(&(
                &state.model,
                &state.meta,
                &state.anchors,
                &state.knowledge,
                &state.definitions,
                &state.feedback,
                state.sample_counts(),
                state.accepted,
                state.epoch,
                state.trained,
                state.attempted
            ))
        );
        rows.push(json!({"arm":label,"before_bytes":before,
            "after_bytes":crate::checkpoint::encode(&state).unwrap().len(),"old_replay":old_replay,
            "new_replay":state.replay.len(),"error":error,"validation_after_compact":"passed",
            "model_updates":state.model.updates,"frozen_preserved_fields_sha256":frozen,
            "source_files_rewritten":0,"optimizer_updates":0,"neural_calls":0}));
    }
    write(&output, &rows);
}

#[test]
fn live_sources_keep_their_actual_context_and_lifetime_admission() {
    let directory = Directory::new();
    let held = CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let bytes = serde_json::to_vec(&json!({"cases":[{"source":held.source(),
        "resolution":crate::hex(held.resolution_id()),
        "family":curriculum::owned::family(held.proved_target()),"lineage":"held-fixture"}]}))
    .unwrap();
    let holdout = lineage::Holdout::read(&bytes, &crate::hex(&Sha256::digest(&bytes))).unwrap();
    let mut state = State::fresh();
    let mut io = sources::history::Io::journal(MemoryStore::default(), &directory.0);
    let mut meter = Meter::start().unwrap();
    let mut graph = crate::Graph::default();
    let mut ledger = lineage::Ledger::new(&holdout);
    let mut questions = BTreeSet::new();
    let mut proofs = BTreeSet::new();
    let q = CompiledQuestion::compile(&crate::learning::tests::own_question()).unwrap();
    let original = state.clone();
    for job in 1..=2 {
        // A deterministic checker fixture, without neural calls or a claimed
        // measured search. The production source/record validators still run.
        let mut solution = crate::learning::tests::own_solution();
        let cost = GenerationCost::default();
        solution.cost = Box::new(cost.clone());
        let generation = Generation {
            terminal: experience::TerminalEvidence::certified(&solution),
            solution: Some(solution),
            diagnostic: String::new(),
            cost,
            frontier: None,
            executions: Vec::new(),
        };
        let completion = completed_search(&state, &q, job, &generation, context(&state), SEARCH, 0);
        let row = record(
            &mut state,
            &mut graph,
            &mut io,
            &mut meter,
            &q,
            generation,
            completion,
            job,
            "fixture",
            &mut ledger,
            &holdout,
            &mut questions,
            &mut proofs,
            &directory.0,
        )
        .unwrap();
        assert_eq!(row["new_resolution"], job == 1);
        assert_eq!(row["accepted_training"], job == 1);
        assert!(
            !state.knowledge.is_empty(),
            "admitted theorem must survive without model promotion"
        );
    }
    assert_eq!(state.model, original.model);
    assert_eq!(state.sample_counts(), (1, 0));
    let episodes = io.episodes();
    assert!(
        episodes[1].validate_context(&original).is_err(),
        "later acquisition must not be rebound to the initial common state"
    );
    let request = history::Request {
        lane: history::Lane::Records,
        after: None,
        horizon: 2,
    };
    let receipt = io.history(&request).unwrap();
    let page: history::Page =
        crate::checkpoint::decode(&artifact::load(&mut io, &receipt.blob).unwrap()).unwrap();
    assert_eq!(
        page.records
            .iter()
            .filter(|r| r.observation.is_some())
            .count(),
        1
    );
    assert_eq!(page.records.len(), 2);
    let path = directory.0.join("source-state-1.json");
    let original_bytes = std::fs::read(&path).unwrap();
    write(&path, &state);
    assert!(io.history(&request).unwrap_err().contains("substituted"));
    std::fs::write(path, original_bytes).unwrap();
    let mut request = request;
    request.lane = history::Lane::Sources;
    let receipt = io.history(&request).unwrap();
    let page: history::Page =
        crate::checkpoint::decode(&artifact::load(&mut io, &receipt.blob).unwrap()).unwrap();
    assert_eq!(
        page.sources.len(),
        1,
        "one owned proof is not two independent sources"
    );
    assert_eq!(page.sources[0].job, 1);
    assert!(io.epoch(0).is_err());
    assert!(io.append(episodes[0].clone(), original).is_err());
}
