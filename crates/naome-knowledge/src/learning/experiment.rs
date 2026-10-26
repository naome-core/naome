//! Explicitly invoked finite research consumer of the maintained native learner.
//! Only fresh model self-search and checker-admitted native solutions train it.
use super::tests::MemoryStore;
use super::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};

fn write(path: &Path, value: &impl Serialize) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn shuffled_learning(seed: u64) -> Vec<&'static curriculum::Case> {
    let mut groups: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for q in curriculum::CORPUS.cases.iter().filter(|q| !q.development) {
        groups.entry(&q.dependency).or_default().push(q);
    }
    for cases in groups.values_mut() {
        cases.sort_by_key(|q| Sha256::digest(format!("{seed}:{}", q.id).as_bytes()));
    }
    let mut schedule = Vec::new();
    for index in 0..groups.values().map(Vec::len).max().unwrap() {
        for cases in groups.values() {
            if let Some(q) = cases.get(index) {
                schedule.push(*q);
            }
        }
    }
    schedule
}
fn evaluate(
    model: &Checkpoint,
    cases: &[&curriculum::Case],
    engine: &mut Engine,
    io: &mut MemoryStore,
    budget: usize,
) -> Vec<serde_json::Value> {
    cases.iter().enumerate().map(|(i,q)| {
        let started=Instant::now();
        let (solution,diagnostic)=engine.with(model,io,|runtime|solve(&q.source,runtime,budget,900_000+i as u64)).unwrap();
        serde_json::json!({"id":q.id,"dependency":q.dependency,"family":q.family,"solved":solution.is_some(),"proof_id":solution.as_ref().map(|s|s.proof_id.clone()),"proof_source":solution.as_ref().map(|s|s.source.clone()),"refuted":solution.as_ref().map(|s|s.refuted),"diagnostic":diagnostic,"elapsed_ms":started.elapsed().as_millis()})
    }).collect()
}
fn decision_metrics(
    model: &Checkpoint,
    graphs: &[graph::Graph],
    engine: &mut Engine,
    io: &mut MemoryStore,
) -> serde_json::Value {
    engine.with(model,io,|runtime| {
        let mut loss=0f64;let mut correct=0usize;
        for graph in graphs {
            let scores=runtime.scores_graph(graph)?;
            let maximum=scores.iter().copied().fold(f32::NEG_INFINITY,f32::max);
            let sum=scores.iter().map(|s|f64::from(*s-maximum).exp()).sum::<f64>();
            loss+=sum.ln()-(graph.successes.iter().map(|i|f64::from(scores[*i]-maximum).exp()).sum::<f64>()).ln();
            let selected=(0..scores.len()).max_by(|a,b|scores[*a].total_cmp(&scores[*b]).then(b.cmp(a))).unwrap();
            correct+=usize::from(graph.successes.contains(&selected));
        }
        Ok(serde_json::json!({"graphs":graphs.len(),"top_one":correct,"mean_cross_entropy":loss/graphs.len().max(1) as f64}))
    }).unwrap()
}
fn export_model(path: &Path, model: &Checkpoint, io: &MemoryStore) {
    std::fs::create_dir_all(path).unwrap();
    write(&path.join("checkpoint.json"), model);
    for (name, blob) in [("model", &model.model), ("optimizer", &model.optimizer)] {
        if let Some(blob) = blob {
            let mut data = Vec::with_capacity(blob.bytes);
            for index in 0..blob.chunks() {
                data.extend_from_slice(&io.0[&(blob.sha256.clone(), index)]);
            }
            assert_eq!(Blob::of(&data), *blob);
            std::fs::write(path.join(format!("{name}.bpk")), data).unwrap();
        }
    }
}
fn train_seed(
    seed: u64,
    rounds: usize,
    output: &Path,
) -> (State, MemoryStore, Vec<serde_json::Value>, Checkpoint) {
    std::fs::create_dir_all(output).unwrap();
    let mut state = State::fresh();
    state.model.seed = seed;
    let mut engine = Engine::default();
    let mut io = MemoryStore::default();
    state.model = engine.snapshot(&state.model, &mut io).unwrap();
    let initial = state.model.clone();
    export_model(&output.join("initial"), &initial, &io);
    let schedule = shuffled_learning(seed);
    write(
        &output.join("learning-schedule.json"),
        &schedule
            .iter()
            .take(rounds * 128)
            .map(|q| &q.id)
            .collect::<Vec<_>>(),
    );
    let mut seen = BTreeSet::new();
    let mut graph = crate::Graph::default();
    let mut events = Vec::new();
    for round in 0..rounds {
        let mut acquisitions = Vec::new();
        for (index, q) in schedule.iter().skip(round * 128).take(128).enumerate() {
            assert!(!q.development);
            assert!(seen.insert(q.id.clone()));
            let job = 1 + round as u64 * 128 + index as u64;
            let (solution, diagnostic) = engine
                .with(&state.model, &mut io, |runtime| {
                    solve(&q.source, runtime, 128, job)
                })
                .unwrap();
            let mut accepted = false;
            if let Some(solution) = solution {
                let question = CompiledQuestion::compile(&q.source).unwrap();
                let (root, batch) = graph
                    .prepare_generated(&solution.source, &[], &question)
                    .unwrap();
                graph
                    .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
                    .unwrap();
                assert_eq!(crate::hex(root.as_bytes()), solution.proof_id);
                assert!(graph.contains(root).unwrap());
                accepted = state
                    .accept(Example {
                        origin: Origin::Local,
                        job,
                        question: q.source.clone(),
                        proof_id: solution.proof_id,
                        refuted: solution.refuted,
                        tree: solution.tree,
                    })
                    .unwrap();
            }
            acquisitions.push(serde_json::json!({"id":q.id,"dependency":q.dependency,"accepted":accepted,"diagnostic":diagnostic}));
            if index % 16 == 15 {
                eprintln!(
                    "native_learning_progress seed={seed} round={round} attempts={} accepted={} replay={}",
                    index + 1,
                    state.accepted,
                    state.replay.len()
                );
            }
        }
        write(
            &output.join(format!("round-{round}-acquisitions.json")),
            &acquisitions,
        );
        let graphs = state.training_graphs().unwrap();
        let before = decision_metrics(&state.model, &graphs, &mut engine, &mut io);
        let mut candidate_metrics = serde_json::Value::Null;
        let mut gate = serde_json::Value::Null;
        if state.needs_training() {
            let mut job = state.job();
            job.training = true;
            state.attempted(state.accepted);
            for unit in 1..=job.units() {
                job.execute(unit, None, 100_000 + seed, &mut engine, &mut io)
                    .unwrap();
                if unit == model::TRAINING_UNITS {
                    let candidate = job.progress.as_ref().unwrap().candidate.as_ref().unwrap();
                    candidate_metrics = decision_metrics(candidate, &graphs, &mut engine, &mut io);
                    export_model(
                        &output.join(format!("round-{round}-candidate")),
                        candidate,
                        &io,
                    );
                }
                let keep: BTreeSet<_> = job
                    .blobs()
                    .into_iter()
                    .chain(initial.blobs())
                    .map(|b| b.sha256.clone())
                    .collect();
                io.0.retain(|(hash, _), _| keep.contains(hash));
            }
            let p = job.progress.as_ref().unwrap();
            gate = serde_json::json!({"diagnostic":p.diagnostic,"incumbent":p.incumbent_score,"candidate":p.candidate_score,"anchor_regression":p.anchor_regression,"first_loss":p.first_loss,"last_loss":p.last_loss});
            assert!(state.qualify(&job));
            state.validate().unwrap();
        }
        let event = serde_json::json!({"round":round,"accepted":state.accepted,"replay":state.replay.len(),"decision_before":before,"decision_candidate":candidate_metrics,"qualification":gate,"retained_updates":state.model.updates});
        eprintln!("{event}");
        events.push(event);
        export_model(
            &output.join(format!("round-{round}-selected")),
            &state.model,
            &io,
        );
        write(&output.join(format!("round-{round}-state.json")), &state);
        let examples = state
            .examples()
            .map(|e| {
                let q = CompiledQuestion::compile(&e.question).unwrap();
                let target = if e.refuted {
                    q.refuted_target()
                } else {
                    q.proved_target()
                };
                let term = search::compile(target, &e.tree).unwrap().0;
                let verified = proof::verify(&term, target).unwrap();
                assert_eq!(crate::hex(verified.native_id.as_bytes()), e.proof_id);
                serde_json::json!({"example":e,"source":proof::source(&verified).unwrap()})
            })
            .collect::<Vec<_>>();
        write(
            &output.join(format!("round-{round}-checked-examples.json")),
            &examples,
        );
        write(&output.join("rounds.json"), &events);
    }
    (state, io, events, initial)
}

#[test]
#[ignore = "Explicit finite native learning progress experiment; requires Release"]
fn native_learning_progress_experiment() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "requires Release"
    );
    let output = std::path::PathBuf::from(
        std::env::var("NAOME_PROGRESS_OUTPUT").expect("explicit experiment output required"),
    );
    assert!(
        !output.exists(),
        "never overwrite prior experimental evidence"
    );
    std::fs::create_dir_all(&output).unwrap();
    let executable = std::env::current_exe().unwrap();
    let bytes = std::fs::read(&executable).unwrap();
    write(
        &output.join("run-source.json"),
        &serde_json::json!({
            "git_commit":std::env::var("NAOME_PROGRESS_COMMIT").expect("explicit frozen source commit required"),
            "binary_sha256":crate::hex(&Sha256::digest(&bytes)),
            "protocol_sha256":crate::hex(&Sha256::digest(include_bytes!("progress-protocol.json"))),
            "corpus_sha256":crate::hex(&Sha256::digest(include_bytes!("curriculum.json")))
        }),
    );
    drop(bytes);
    let pilot = std::env::var("NAOME_PROGRESS_PILOT").as_deref() == Ok("1");
    let seeds = if pilot {
        vec![653]
    } else {
        vec![809, 907, 1009]
    };
    let rounds = if pilot { 1 } else { 2 };
    let selection: BTreeSet<_> = curriculum::development()
        .iter()
        .map(|q| q.id.clone())
        .collect();
    let cases = curriculum::CORPUS
        .cases
        .iter()
        .filter(|q| q.development && (pilot == selection.contains(&q.id)))
        .collect::<Vec<_>>();
    write(
        &output.join("schedule.json"),
        &serde_json::json!({"pilot":pilot,"seeds":seeds,"rounds":rounds,"acquisitions_per_round":128,"evaluation_ids":cases.iter().map(|q|&q.id).collect::<Vec<_>>(),"search_expansions":[32,128],"claim":"Prospective comparison within the existing original-TRAIN development corpus, not independent external-test qualification"}),
    );
    write(
        &output.join("protocol.json"),
        &serde_json::from_str::<serde_json::Value>(include_str!("progress-protocol.json")).unwrap(),
    );
    // Every requested seed finishes learning before the first confirmation query.
    let trained = seeds
        .iter()
        .map(|seed| train_seed(*seed, rounds, &output.join(format!("seed-{seed}"))))
        .collect::<Vec<_>>();
    let mut results = Vec::new();
    for (seed, (state, mut io, events, fresh)) in seeds.iter().zip(trained) {
        assert_eq!(fresh.seed, *seed);
        assert_eq!(fresh.updates, 0);
        let mut engine = Engine::default();
        let before = evaluate(&fresh, &cases, &mut engine, &mut io, 32);
        let after = evaluate(&state.model, &cases, &mut engine, &mut io, 32);
        let before_128 = evaluate(&fresh, &cases, &mut engine, &mut io, 128);
        let after_128 = evaluate(&state.model, &cases, &mut engine, &mut io, 128);
        let count =
            |rows: &[serde_json::Value]| rows.iter().filter(|q| q["solved"] == true).count();
        let result = serde_json::json!({"seed":seed,"questions":cases.len(),"before_solved":count(&before),"after_solved":count(&after),"retained_updates":state.model.updates,"rounds":events,"before":before,"after":after,"secondary_128":{"before_solved":count(&before_128),"after_solved":count(&after_128),"before":before_128,"after":after_128}});
        eprintln!(
            "native_learning_progress_result seed={seed} before={} after={} questions={}",
            count(&before),
            count(&after),
            cases.len()
        );
        results.push(result);
        write(&output.join("results.json"), &results);
    }
}

#[test]
#[ignore = "Finite selection-gate diagnosis; no model training or confirmation evaluation"]
fn selection_gate_headroom() {
    struct Ordered;
    impl model::Ranker for Ordered {
        fn scores(&mut self, d: &model::Decision) -> Result<Vec<f32>, String> {
            Ok(vec![0.; d.candidates.len()])
        }
    }
    let mut rows = Vec::new();
    for q in curriculum::development() {
        let mut observations = Vec::new();
        for budget in [32, 128, 256] {
            let start = Instant::now();
            let (solution, diagnostic) = search_question(&q.source, &mut Ordered, budget).unwrap();
            observations.push(serde_json::json!({"budget":budget,"solved":solution.is_some(),"diagnostic":diagnostic,"elapsed_ms":start.elapsed().as_millis()}));
        }
        rows.push(serde_json::json!({"id":q.id,"dependency":q.dependency,"family":q.family,"source":q.source,"symbolic":observations}));
    }
    eprintln!("{}", serde_json::to_string_pretty(&rows).unwrap());
}
