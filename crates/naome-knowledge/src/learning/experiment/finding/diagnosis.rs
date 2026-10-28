//! Exact recorded-cost replay before any finder-utility feedback is available.
use super::*;

#[test]
fn compacted_replay_requires_the_original_checked_proof_and_binding() {
    let example = crate::learning::tests::own_example();
    let mut state = State::fresh();
    state.accept(example.clone()).unwrap();
    let q = CompiledQuestion::compile(&example.question).unwrap();
    let (_, _, proof) = search::core::checked(q.proved_target(), &example.tree).unwrap();
    let steps = proof.certificate.steps().len()
        + proof.lemmas.iter().map(|p| p.steps().len()).sum::<usize>();
    for entry in state.replay.iter_mut().chain(&mut state.anchors) {
        entry.tree = search::Tree::Stored {
            steps,
            bytes: serde_json::to_vec(&example.tree).unwrap().len(),
            binding: digest(&example.tree),
        };
    }
    state.validate().unwrap();
    assert!(owned_evidence(&state, &[]).is_err());
    let source = Evidence {
        job: example.job,
        proof_id: example.proof_id,
        trace: example.tree,
    };
    assert_eq!(
        owned_evidence(&state, std::slice::from_ref(&source))
            .unwrap()
            .len(),
        1
    );
    let mut corrupt = source;
    corrupt.trace = search::Tree::Close(0, 0);
    assert!(owned_evidence(&state, &[corrupt]).is_err());
}

fn replay(
    seed: u64,
    treatment: Treatment,
    common: &State,
    blobs: &MemoryStore,
    initial: &[(String, Solution, u64)],
    expected: &Value,
    path: &Path,
) -> Value {
    std::fs::create_dir_all(path).unwrap();
    let mut state = common.clone();
    let mut graph = crate::Graph::default();
    for (source, solution, _) in initial {
        let q = CompiledQuestion::compile(source).unwrap();
        let (root, batch) = graph
            .prepare_generated(&solution.source, &solution.helpers, &q)
            .unwrap();
        graph
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
            .unwrap();
    }
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let directory = Directory::new();
    let mut finder = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    finder.treatment(treatment);
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let mut io = Store {
        inner: MemoryStore(blobs.0.clone()),
        ..Default::default()
    };
    let mut engine = Engine::default();
    let mut rows = Vec::new();
    for (index, expected) in expected["rounds"][0]["events"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        finder.feedback(Some(state.feedback()));
        finder
            .refresh(&graph, |q| owner.assess(&graph, q).passed())
            .unwrap();
        let candidates = finder.candidate_page(index as u64, |q| owner.assess(&graph, q).passed());
        let refs = candidates.iter().collect::<Vec<_>>();
        let selected = finder
            .choose(&refs, &graph, settings.solving, false)
            .unwrap()
            .unwrap();
        let q = &candidates[selected];
        assert_eq!(
            crate::hex(q.resolution_id()),
            expected["resolution"],
            "recorded-cost selection diverged at seed {seed}, attempt {index}"
        );
        let job = 10_001 + index as u64;
        let generated = solve(&state, &mut engine, &mut io, q, job);
        assert_eq!(
            generated.solution.is_some(),
            expected["solved"].as_bool().unwrap(),
            "native outcome did not reproduce"
        );
        let recorded = expected["cost"]["generation_micros"].as_u64().unwrap();
        finder
            .attempted(
                q,
                &graph,
                &jobs::Completion {
                    id: job,
                    model_checkpoint: Some(digest(&state.model)),
                    binding: jobs::Binding::new([0; 32], [0; 32]),
                    spent_ms: recorded / 1000,
                    reserved_units: 1,
                    state: jobs::State::Complete,
                    result: Ok(jobs::Output::Native {
                        solution: generated.solution.clone(),
                        diagnostic: generated.diagnostic.clone(),
                        frontier: generated.frontier.clone(),
                    }),
                },
                if generated.solution.is_some() {
                    Outcome::Candidate
                } else {
                    Outcome::NoCandidate
                },
            )
            .unwrap();
        let mut accepted = false;
        if let Some(solution) = &generated.solution {
            accepted = accept(&mut state, &mut graph, q, solution, job, path);
            let root = crate::object::proof_address(&solution.proof_id).unwrap();
            finder.prepared(q, job, root).unwrap();
            finder.verified(q, &graph, job, root).unwrap();
        }
        assert_eq!(accepted, expected["accepted_training"].as_bool().unwrap());
        state.observe_result(
            q.source(),
            generated.solution.is_some(),
            &generated.diagnostic,
            recorded,
            SEARCH as u32,
        );
        rows.push(json!({"attempt":index,"question":q.source(),"resolution":crate::hex(q.resolution_id()),"recorded_generation_micros":recorded,"actual_cost":generated.cost,"solution":generated.solution,"accepted_training":accepted}));
        write(&path.join("trace.json"), &rows);
    }
    assert_eq!(
        finder.learning_snapshot()["model"]["utility_observations"],
        0
    );
    write(&path.join("state-before-training.json"), &state);
    export_model(&path.join("initial-model"), &state.model, &io.inner);
    let sources = initial
        .iter()
        .map(|(_, s, job)| Evidence {
            job: *job,
            proof_id: s.proof_id.clone(),
            trace: s.tree.clone(),
        })
        .chain(rows.iter().filter_map(|r| {
            r["solution"].as_object().map(|_| Evidence {
                job: 10_001 + r["attempt"].as_u64().unwrap(),
                proof_id: r["solution"]["proof_id"].as_str().unwrap().into(),
                trace: serde_json::from_value(r["solution"]["tree"].clone()).unwrap(),
            })
        }))
        .collect::<Vec<_>>();
    let training = train(&mut state, &mut engine, &mut io, 100_000, path, &sources);
    assert_eq!(training["status"], "complete");
    assert_eq!(
        state.model,
        serde_json::from_value::<Checkpoint>(expected["rounds"][0]["model"].clone()).unwrap(),
        "selected model/Adam pair did not reproduce the reference"
    );
    let original = &training["progress"]["original_score"];
    assert_eq!(
        original,
        &expected["rounds"][0]["training"]["progress"]["original_score"]
    );
    export_model(&path.join("selected-model"), &state.model, &io.inner);
    let result = json!({"seed":seed,"arm":label(treatment),"events":rows,"training":training,"selected_model":state.model,"original_score":original,"finder":finder.learning_snapshot()});
    write(&path.join("result.json"), &result);
    result
}

#[test]
#[ignore = "explicit recorded-cost native replay; preserves first-run evidence"]
fn recorded_costs_reproduce_the_first_selected_model() {
    let reference =
        std::path::PathBuf::from(std::env::var("NAOME_FINDER_REPLAY_REFERENCE").unwrap());
    let output = std::path::PathBuf::from(std::env::var("NAOME_FINDER_REPLAY_OUTPUT").unwrap());
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let mut observer = crate::resources::adaptive::Observer::default();
    let observed = observer.refresh(&output).unwrap().clone();
    write(&output.join("resources.json"), &observed);
    assert!(observed.budget.paused.is_none());
    write(
        &output.join("manifest.json"),
        &json!({"seeds":[73,101],"arms":["without_utility","full"],"source_contract":input_specification(),"reference":reference,"scope":"Exact first-round replay with recorded reference cost labels; actual work and costs remain charged. No utility label is available before this first training trial. Same model, optimizer, source proofs, solver and promotion rules."}),
    );
    let mut results = Vec::new();
    for seed in [73, 101] {
        let seed_path = output.join(seed.to_string());
        let expected: Value = serde_json::from_slice(
            &std::fs::read(
                reference
                    .join(seed.to_string())
                    .join("without_utility/result.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let common: State = serde_json::from_slice(
            &std::fs::read(reference.join(seed.to_string()).join("initial-state.json")).unwrap(),
        )
        .unwrap();
        common.validate().unwrap();
        let (fresh, blobs, initial, preparation) = prepare(seed, &seed_path.join("preparation"));
        assert_eq!(fresh.model, common.model);
        let originals = common
            .examples()
            .map(|e| e.proof_id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            initial
                .iter()
                .map(|(_, s, _)| s.proof_id.clone())
                .collect::<BTreeSet<_>>(),
            originals
        );
        for treatment in [Treatment::FamilyReplayNoUtility, Treatment::FamilyReplay] {
            results.push(replay(
                seed,
                treatment,
                &common,
                &blobs,
                &initial,
                &expected,
                &seed_path.join(label(treatment)),
            ));
            write(
                &output.join("results.json"),
                &json!({"preparation":preparation,"results":results}),
            );
        }
    }
}
