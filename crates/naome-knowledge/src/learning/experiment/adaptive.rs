//! A finite factorial consumer of the actual frontier, checked replay and gate.
use super::*;
use crate::frontier::{Frontier, evidence::Outcome};
use knowledge::{Store, acquire, admit_discovery, evidence_for};
use nix::sys::{
    resource::{UsageWho, getrusage},
    time::TimeValLike,
};

fn cpu_micros() -> u64 {
    let usage = getrusage(UsageWho::RUSAGE_SELF).expect("process CPU accounting");
    (usage.user_time().num_microseconds() + usage.system_time().num_microseconds()) as u64
}
struct Clock {
    wall: Instant,
    cpu: u64,
}
impl Clock {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu_micros(),
        }
    }
    fn elapsed(&self) -> serde_json::Value {
        serde_json::json!({"wall_micros":self.wall.elapsed().as_micros(),"cpu_micros":cpu_micros()-self.cpu})
    }
    fn exhausted(&self) -> bool {
        self.wall.elapsed() >= Duration::from_secs(240) || cpu_micros() - self.cpu >= 180_000_000
    }
}
struct Run {
    seed: u64,
    arm: &'static str,
    state: State,
    initial: Checkpoint,
    store: Store,
    summary: serde_json::Value,
}
struct Common {
    state: State,
    store: Store,
    evidence: Vec<Evidence>,
    rows: Vec<serde_json::Value>,
    cost: serde_json::Value,
}
#[derive(Clone, Copy)]
struct Arm {
    name: &'static str,
    random_only: bool,
    preparation: Preparation,
}
fn fork_store(source: &Store) -> Store {
    Store {
        inner: MemoryStore(source.inner.0.clone()),
        ..Store::default()
    }
}
fn collect(store: &mut Store, initial: &Checkpoint, job: Option<&Job>, selected: &Checkpoint) {
    let keep = initial
        .blobs()
        .chain(selected.blobs())
        .chain(job.into_iter().flat_map(|j| j.blobs()))
        .map(|b| b.sha256.clone())
        .collect::<BTreeSet<_>>();
    store.inner.0.retain(|(hash, _), _| keep.contains(hash));
}
fn common(seed: u64, path: &Path) -> Common {
    std::fs::create_dir_all(path).unwrap();
    let clock = Clock::start();
    let mut state = State::fresh();
    state.model.seed = seed;
    let mut engine = Engine::default();
    let mut store = Store::default();
    state.model = engine.snapshot(&state.model, &mut store).unwrap();
    state.feedback = crate::training::ability::Feedback::fresh(digest(&state.model));
    export_model(&path.join("initial"), &state.model, &store.inner);
    let mut graph = crate::Graph::default();
    let mut evidence = Vec::new();
    let mut rows = Vec::new();
    for (i, q) in curriculum::composition::BANK.helpers.iter().enumerate() {
        rows.push(acquire(
            &mut state,
            &q.source,
            1 + i as u64,
            &mut engine,
            &mut store,
            &mut graph,
            (&mut evidence, true),
        ));
    }
    state.validate().unwrap();
    write(&path.join("state.json"), &state);
    write(&path.join("evidence.json"), &evidence);
    write(&path.join("acquisitions.json"), &rows);
    let cost = clock.elapsed();
    write(&path.join("cost.json"), &cost);
    Common {
        state,
        store,
        evidence,
        rows,
        cost,
    }
}
fn train(seed: u64, definition: Arm, common: &Common, rounds: usize, path: &Path) -> Run {
    std::fs::create_dir_all(path).unwrap();
    let clock = Clock::start();
    let Arm {
        name: arm,
        random_only,
        preparation,
    } = definition;
    let mut state = common.state.clone();
    state.preparation = preparation;
    let initial = state.model.clone();
    let mut store = fork_store(&common.store);
    let mut engine = Engine::default();
    let mut graph = crate::Graph::default();
    for row in &common.rows {
        if !row["solution"].is_null() {
            let solution: Solution = serde_json::from_value(row["solution"].clone()).unwrap();
            let question = CompiledQuestion::compile(row["question"].as_str().unwrap()).unwrap();
            admit_discovery(&mut graph, &question, &solution).unwrap();
        }
    }
    let directory = path.join("frontier");
    std::fs::create_dir_all(&directory).unwrap();
    let settings = crate::jobs::Settings {
        native_proof_learning: true,
        ..crate::jobs::Settings::default()
    };
    let mut frontier = Frontier::open(&directory, &graph, seed, settings).unwrap();
    let mut formal =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let dictionary = digest(&state.knowledge);
    let meanings = digest(&state.definitions);
    let mut all = common.evidence.clone();
    let mut seen = BTreeSet::new();
    let mut events = Vec::new();
    let mut stop = "round_limit";
    for round in 0..rounds {
        let mut rows = Vec::new();
        for index in 0..48 {
            if clock.exhausted() {
                stop = "compute_limit";
                break;
            }
            frontier.feedback(Some(state.feedback()));
            let mut eligible = |q: &CompiledQuestion| {
                !seen.contains(&crate::hex(q.resolution_id()))
                    && State::eligible(q.source())
                    && formal.assess(&graph, q).passed()
            };
            frontier.refresh(&graph, &mut eligible).unwrap();
            let candidates = frontier
                .candidates()
                .into_iter()
                .filter(&mut eligible)
                .collect::<Vec<_>>();
            let references = candidates.iter().collect::<Vec<_>>();
            let Some(selected) = frontier
                .choose(&references, &graph, settings.solving, random_only)
                .unwrap()
            else {
                stop = "no_eligible_candidate";
                break;
            };
            let q = &candidates[selected];
            let id = crate::hex(q.resolution_id());
            assert!(seen.insert(id.clone()));
            let feedback_before = state.feedback();
            let job = 10_000 + round as u64 * 48 + index as u64;
            let mut row = acquire(
                &mut state,
                q.source(),
                job,
                &mut engine,
                &mut store,
                &mut graph,
                (&mut all, false),
            );
            let solution: Option<Solution> =
                serde_json::from_value(row["solution"].clone()).unwrap();
            let output = solution
                .as_ref()
                .map_or(crate::jobs::Output::NoCandidate, |s| {
                    crate::jobs::Output::Native {
                        solution: Some(s.clone()),
                        diagnostic: "certified_candidate".into(),
                    }
                });
            let completion = crate::jobs::Completion {
                id: job,
                binding: crate::jobs::Binding::new([0; 32], [0; 32]),
                spent_ms: row["elapsed_micros"].as_u64().unwrap() / 1000,
                reserved_units: 1,
                state: crate::jobs::State::Complete,
                result: Ok(output),
            };
            frontier
                .attempted(
                    q,
                    &graph,
                    &completion,
                    if solution.is_some() {
                        Outcome::Candidate
                    } else {
                        Outcome::NoCandidate
                    },
                )
                .unwrap();
            if let Some(solution) = &solution {
                let root = crate::object::proof_address(&solution.proof_id).unwrap();
                // The shared acquisition helper already committed the checked
                // artifact; acknowledge that exact candidate through both
                // canonical frontier receipts before selecting more work.
                frontier.prepared(q, job, root).unwrap();
                frontier.verified(q, &graph, job, root).unwrap();
            }
            state.observe_result(
                q.source(),
                solution.is_some(),
                row["diagnostic"].as_str().unwrap(),
                row["elapsed_micros"].as_u64().unwrap(),
                128,
            );
            state.compact().unwrap();
            state.validate().unwrap();
            let case = curriculum::owned::case(q.source()).unwrap();
            row["id"] = serde_json::json!(id);
            row["family"] = serde_json::json!(case.family);
            row["dependency"] = serde_json::json!(case.dependency);
            row["candidate_page"] = serde_json::json!(
                candidates
                    .iter()
                    .map(|q| crate::hex(q.resolution_id()))
                    .collect::<Vec<_>>()
            );
            row["feedback_before"] = serde_json::to_value(feedback_before).unwrap();
            rows.push(row);
            write(
                &path.join(format!("round-{round}-acquisitions.json")),
                &rows,
            );
        }
        assert_eq!(dictionary, digest(&state.knowledge));
        assert_eq!(meanings, digest(&state.definitions));
        let evidence = evidence_for(&state, &all);
        let pool = state.training_pool(&evidence).unwrap();
        let before = decision_metrics(&state.model, pool.graphs(), &mut engine, &mut store.inner);
        let mut gate = serde_json::Value::Null;
        let mut metrics = serde_json::Value::Null;
        let mut completed = false;
        let mut performed = 0;
        if state.needs_training() && !clock.exhausted() {
            let mut job = state.job();
            job.training = true;
            job.evidence = evidence.clone();
            job.validate().unwrap();
            state.attempted(state.learning_epoch());
            let training_clock = Clock::start();
            let io_before = store.read_bytes + store.written_bytes;
            for unit in 1..=job.units() {
                if clock.exhausted() {
                    stop = "compute_limit";
                    break;
                }
                job.execute(unit, None, 700_000 + seed, &mut engine, &mut store)
                    .unwrap();
                job.validate().unwrap();
                performed = unit;
                if unit == model::TRAINING_UNITS {
                    let candidate = job.progress.as_ref().unwrap().candidate.as_ref().unwrap();
                    metrics =
                        decision_metrics(candidate, pool.graphs(), &mut engine, &mut store.inner);
                    export_model(
                        &path.join(format!("round-{round}-candidate")),
                        candidate,
                        &store.inner,
                    );
                }
                collect(&mut store, &initial, Some(&job), &state.model);
            }
            assert!(
                store.read_bytes + store.written_bytes - io_before
                    <= model::REQUIREMENTS.io_bytes as u64
            );
            if performed == job.units() {
                completed = state.qualify(&job);
                assert!(completed);
                state.validate().unwrap();
            }
            let p = job.progress.as_ref();
            gate = serde_json::json!({"completed":completed,"performed_units":performed,"required_units":job.units(),"elapsed":training_clock.elapsed(),
                "progress":p,"input_evidence_sha256":digest(&evidence),"base_hash":job.base_hash,"io_bytes":job.io_bytes});
            write(&path.join(format!("round-{round}-job.json")), &job);
        }
        frontier.feedback(Some(state.feedback()));
        let next_page=frontier.candidates().into_iter().filter(|q|!seen.contains(&crate::hex(q.resolution_id()))&&State::eligible(q.source())&&formal.assess(&graph,q).passed()).map(|q|serde_json::json!({"id":crate::hex(q.resolution_id()),"priority":state.feedback.priority(&q,128)})).collect::<Vec<_>>();
        let event = serde_json::json!({"round":round,"attempts":rows.len(),"accepted":state.accepted,"replay":state.replay.len(),"pool_graphs":pool.graphs().len(),
            "decision_before":before,"decision_candidate":metrics,"qualification":gate,"retained_updates":state.model.updates,"feedback_after":state.feedback,
            "next_page":next_page,"elapsed":clock.elapsed()});
        eprintln!(
            "{}",
            serde_json::json!({"event":"adaptive_round_completed","seed":seed,"arm":arm,"round":round,"accepted":state.accepted,"completed":completed,"units":performed,"updates":state.model.updates,"elapsed":clock.elapsed()})
        );
        events.push(event);
        write(&path.join("rounds.json"), &events);
        export_model(
            &path.join(format!("round-{round}-selected")),
            &state.model,
            &store.inner,
        );
        write(&path.join(format!("round-{round}-state.json")), &state);
        write(&path.join(format!("round-{round}-evidence.json")), &all);
        collect(&mut store, &initial, None, &state.model);
        if clock.exhausted() {
            stop = "compute_limit";
            break;
        }
    }
    let summary = serde_json::json!({"seed":seed,"arm":arm,"random_only":random_only,"preparation":preparation,"stop":stop,"elapsed":clock.elapsed(),"rounds":events,
        "initial":initial,"selected":state.model,"distinct_questions":seen.len(),"read_bytes":store.read_bytes,"written_bytes":store.written_bytes,"read_operations":store.reads,"write_operations":store.writes});
    write(&path.join("summary.json"), &summary);
    Run {
        seed,
        arm,
        state,
        initial,
        store,
        summary,
    }
}
fn evaluate(
    run: &mut Run,
    model: &Checkpoint,
    cases: &[curriculum::Case],
    budget: usize,
    empty: bool,
    path: &Path,
) -> Vec<serde_json::Value> {
    let mut engine = Engine::default();
    let mut rows = Vec::new();
    for (i, q) in cases.iter().enumerate() {
        let clock = Clock::start();
        let target = CompiledQuestion::compile(&q.source).unwrap();
        assert!(
            run.state
                .knowledge
                .iter()
                .all(|entry| !knowledge::contains_question(entry, &target)),
            "no exact confirmation answer in any dictionary dependency"
        );
        let (solution, diagnostic, cost) = engine
            .with(model, &mut run.store, |runtime| {
                solve_with_definitions(
                    &q.source,
                    runtime,
                    budget,
                    900_000 + i as u64,
                    if empty { &[] } else { &run.state.definitions },
                    if empty { &[] } else { &run.state.knowledge },
                )
            })
            .unwrap();
        if let Some(s) = &solution {
            let _ = s.checked().unwrap();
        }
        rows.push(serde_json::json!({"id":q.id,"dependency":q.dependency,"family":q.family,"solved":solution.is_some(),"solution":solution,"diagnostic":diagnostic,"cost":cost,"elapsed":clock.elapsed()}));
    }
    write(path, &rows);
    rows
}

#[test]
#[ignore = "Explicit finite adaptive learning comparison; Release only"]
fn matched_adaptive_learning_experiment() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release required"
    );
    let output = std::env::var("NAOME_ADAPTIVE_OUTPUT").expect("explicit output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve previous attempts");
    std::fs::create_dir_all(output).unwrap();
    let pilot = std::env::var_os("NAOME_ADAPTIVE_PILOT").is_some();
    let seeds = if pilot {
        vec![2089]
    } else {
        vec![2203, 2309, 2411]
    };
    let rounds = if pilot { 1 } else { 2 };
    let clock = Clock::start();
    let bank = &*curriculum::adaptive::BANK;
    let bank_cost = clock.elapsed();
    write(
        &output.join("bank.json"),
        &serde_json::json!({"learning":bank.learning,"development":bank.development,"confirmation":bank.confirmation}),
    );
    let protocol: serde_json::Value =
        serde_json::from_str(include_str!("../adaptive-protocol.json")).unwrap();
    write(&output.join("protocol.json"), &protocol);
    let mut runs = Vec::new();
    let mut common_cost = Vec::new();
    write(
        &output.join("run-source.json"),
        &serde_json::json!({"source_commit":std::env::var("NAOME_ADAPTIVE_COMMIT").unwrap_or_else(|_|"unfrozen-engineering-pilot".into()),
        "specification":Checkpoint::fresh().specification,"bank_sha256":digest(&(&bank.learning,&bank.development,&bank.confirmation)),"protocol_sha256":crate::hex(&Sha256::digest(include_bytes!("../adaptive-protocol.json"))),"pilot":pilot,"seeds":seeds,"rounds":rounds,"parameters":model::PARAMETERS}),
    );
    for (index, seed) in seeds.iter().enumerate() {
        let path = output.join(format!("seed-{seed}"));
        let common = common(*seed, &path.join("common"));
        common_cost.push(serde_json::json!({"seed":seed,"cost":common.cost}));
        let mut arms = vec![
            ("random_balanced", true, Preparation::Balanced),
            ("adaptive_balanced", false, Preparation::Balanced),
            ("random_targeted", true, Preparation::Targeted),
            ("adaptive_targeted", false, Preparation::Targeted),
        ];
        arms.rotate_left(index % 4);
        for (arm, random, preparation) in arms {
            runs.push(train(
                *seed,
                Arm {
                    name: arm,
                    random_only: random,
                    preparation,
                },
                &common,
                rounds,
                &path.join(arm),
            ));
        }
    }
    let learning_finished = clock.elapsed();
    let mut results = Vec::new();
    for run in &mut runs {
        let cases = if pilot {
            &bank.development
        } else {
            &bank.confirmation
        };
        let path = output.join(format!("seed-{}", run.seed)).join(run.arm);
        let initial = run.initial.clone();
        let selected = run.state.model.clone();
        let mut evaluations = Vec::new();
        for (name, model, empty, budget) in [
            ("initial", &initial, false, 32),
            ("selected", &selected, false, 32),
            ("selected", &selected, false, 128),
            ("initial", &initial, false, 128),
            ("initial_empty", &initial, true, 32),
            ("selected_empty", &selected, true, 32),
        ] {
            let rows = evaluate(
                run,
                model,
                cases,
                budget,
                empty,
                &path.join(format!("{name}-{budget}.json")),
            );
            eprintln!(
                "{}",
                serde_json::json!({"event":"adaptive_confirmation","seed":run.seed,"arm":run.arm,"model":name,"budget":budget,"solved":rows.iter().filter(|r|r["solved"]==true).count(),"total":rows.len()})
            );
            evaluations.push(serde_json::json!({"model":name,"budget":budget,"rows":rows}));
        }
        results.push(serde_json::json!({"seed":run.seed,"arm":run.arm,"training":run.summary,"evaluations":evaluations}));
        write(&output.join("results.json"), &results);
    }
    write(
        &output.join("completed.json"),
        &serde_json::json!({"all_training_finished_before_confirmation":true,"learning_finished":learning_finished,"elapsed":clock.elapsed(),"bank_cost":bank_cost,"common_cost":common_cost,"runs":results.len()}),
    );
}
