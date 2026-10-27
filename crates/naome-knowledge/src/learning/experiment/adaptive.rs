//! Finite outer trial learning and independent matched lower-learner controls.
use super::*;
use crate::frontier::{Frontier, evidence::Outcome};
use knowledge::{Store, acquire, admit_discovery, evidence_for};
use nix::sys::{
    resource::{UsageWho, getrusage},
    time::TimeValLike,
};
const META_HEADROOM: usize = meta::STATE_BYTES;

fn cpu_micros() -> u64 {
    let usage = getrusage(UsageWho::RUSAGE_SELF).expect("process CPU accounting");
    (usage.user_time().num_microseconds() + usage.system_time().num_microseconds()) as u64
}
struct Clock {
    wall: Instant,
    cpu: u64,
    charged_cpu: u64,
    charged_wall: u64,
}
impl Clock {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu_micros(),
            charged_cpu: 0,
            charged_wall: 0,
        }
    }
    fn elapsed(&self) -> serde_json::Value {
        serde_json::json!({"wall_micros":self.wall.elapsed().as_micros(),"cpu_micros":cpu_micros()-self.cpu})
    }
    fn exhausted(&self) -> bool {
        self.wall.elapsed().as_micros() as u64 + self.charged_wall >= 240_000_000
            || cpu_micros() - self.cpu + self.charged_cpu >= 180_000_000
    }
}
struct Run {
    seed: u64,
    arm: &'static str,
    state: State,
    initial: Checkpoint,
    store: Store,
    summary: serde_json::Value,
    bootstrap: Option<(Vec<Evidence>, Vec<serde_json::Value>)>,
}
struct Common {
    state: State,
    store: Store,
    evidence: Vec<Evidence>,
    rows: Vec<serde_json::Value>,
    cost: serde_json::Value,
    bootstrap: Vec<serde_json::Value>,
    bootstrap_cost: serde_json::Value,
}
#[derive(Clone, Copy)]
struct Arm {
    name: &'static str,
    random_only: bool,
    preparation: Preparation,
    acquisition_only: bool,
}
struct MetaSeed {
    state: meta::State,
    io: MemoryStore,
}
fn export_meta(path: &Path, c: &meta::Checkpoint, io: &MemoryStore) {
    std::fs::create_dir_all(path).unwrap();
    write(&path.join("checkpoint.json"), c);
    for (name, blob) in [("weights", &c.weights), ("optimizer", &c.optimizer)] {
        if let Some(blob) = blob {
            let mut bytes = Vec::new();
            for index in 0..blob.chunks() {
                bytes.extend_from_slice(&io.0[&(blob.sha256.clone(), index)]);
            }
            assert_eq!(Blob::of(&bytes), *blob);
            std::fs::write(path.join(format!("{name}.bin")), bytes).unwrap();
        }
    }
}
fn copy_meta(from: &MemoryStore, to: &mut Store, state: &meta::State) {
    for blob in state.model.blobs() {
        let mut io = MemoryStore(from.0.clone());
        let bytes = artifact::load(&mut io, blob).unwrap();
        assert_eq!(*blob, artifact::save(to, &bytes).unwrap());
    }
}
fn meta_partition(source: &str, training: bool) -> bool {
    static PREREQUISITES: std::sync::LazyLock<BTreeSet<String>> = std::sync::LazyLock::new(|| {
        curriculum::composition::BANK
            .helpers
            .iter()
            .filter_map(|q| curriculum::owned::case(&q.source).map(|c| c.dependency))
            .collect()
    });
    let Some(case) = curriculum::owned::case(source) else {
        return false;
    };
    // Both stages declare the same seven checked prerequisites. Their derived
    // continuations cannot be counted as novel outer-test data.
    if PREREQUISITES.contains(&case.dependency) {
        return false;
    }
    let bytes = Sha256::digest(case.dependency.as_bytes());
    (bytes[0] % 3 != 2) == training
}
fn train_meta(path: &Path, pilot: bool) -> MetaSeed {
    std::fs::create_dir_all(path).unwrap();
    let all_clock = Clock::start();
    let contexts = if pilot {
        vec![3607]
    } else {
        vec![4507, 4603, 4703, 4801, 4903, 5003]
    };
    let trials = if pilot { 2 } else { 8 };
    let mut controller = meta::State::fresh();
    let mut meta_io = MemoryStore::default();
    let mut summaries = Vec::new();
    for (context, seed) in contexts.into_iter().enumerate() {
        let dir = path.join(format!("context-{context}"));
        let mut common = common(seed, &dir.join("common"));
        let acquisition_clock = Clock::start();
        let mut engine = Engine::default();
        let mut graph = crate::Graph::default();
        for row in &common.rows {
            if !row["solution"].is_null() {
                let s: Solution = serde_json::from_value(row["solution"].clone()).unwrap();
                let q = CompiledQuestion::compile(row["question"].as_str().unwrap()).unwrap();
                admit_discovery(&mut graph, &q, &s).unwrap();
            }
        }
        let mut cases = curriculum::adaptive::BANK
            .learning
            .iter()
            .filter(|q| meta_partition(&q.source, true))
            .collect::<Vec<_>>();
        cases.sort_by_key(|q| Sha256::digest(format!("{seed}:{}", q.id).as_bytes()));
        // Contexts vary observed source structure without supplying witnesses.
        if context >= 3 {
            let wanted = format!("adaptive-operation-{}", 1 + (context - 3) % 3);
            cases.sort_by_key(|q| q.family != wanted);
        }
        for (i, q) in cases.into_iter().take(32).enumerate() {
            let row = acquire(
                &mut common.state,
                &q.source,
                100 + i as u64,
                &mut engine,
                &mut common.store,
                &mut graph,
                (&mut common.evidence, false),
            );
            common.state.observe_result(
                &q.source,
                !row["solution"].is_null(),
                row["diagnostic"].as_str().unwrap(),
                row["elapsed_micros"].as_u64().unwrap(),
                128,
            );
            common.rows.push(row);
        }
        common
            .state
            .compact_with_meta_headroom(META_HEADROOM)
            .unwrap();
        assert!(
            common.state.needs_training(),
            "outer context must have a genuine diverse checked pool"
        );
        write(&dir.join("source-state.json"), &common.state);
        write(&dir.join("source-evidence.json"), &common.evidence);
        write(&dir.join("source-acquisitions.json"), &common.rows);
        write(&dir.join("source-cost.json"), &acquisition_clock.elapsed());
        let mut observed = common.state.feedback.development.clone();
        for trial in 0..trials {
            assert!(
                all_clock.wall.elapsed() < Duration::from_secs(10_800)
                    && cpu_micros() - all_clock.cpu < 7_200_000_000,
                "finite outer training resource bound"
            );
            let trial_dir = dir.join(format!("trial-{trial}"));
            std::fs::create_dir_all(&trial_dir).unwrap();
            let mut state = common.state.clone();
            state.meta = controller.clone();
            state.preparation = Preparation::Meta;
            state.feedback.development = observed.clone();
            let initial = state.model.clone();
            let mut store = fork_store(&common.store);
            copy_meta(&meta_io, &mut store, &controller);
            let evidence = evidence_for(&state, &common.evidence);
            let mut job = state.job();
            job.training = true;
            job.evidence = evidence;
            let clock = Clock::start();
            let io_start = store.read_bytes + store.written_bytes;
            let mut engine = Engine::default();
            for unit in 1..=job.units() {
                assert!(
                    clock.wall.elapsed() < Duration::from_secs(120)
                        && cpu_micros() - clock.cpu < 90_000_000,
                    "bounded complete outer trial"
                );
                job.execute(
                    unit,
                    None,
                    9_000_000 + context as u64 * 100 + trial as u64,
                    &mut engine,
                    &mut store,
                )
                .unwrap();
                job.validate().unwrap();
                if unit == model::TRAINING_UNITS {
                    export_model(
                        &trial_dir.join("candidate"),
                        job.progress.as_ref().unwrap().candidate.as_ref().unwrap(),
                        &store.inner,
                    );
                }
                collect(&mut store, &initial, Some(&job), &state);
            }
            assert!(
                store.read_bytes + store.written_bytes - io_start
                    <= model::REQUIREMENTS.io_bytes as u64
            );
            observed = job.progress.as_ref().unwrap().development_before.clone();
            assert!(state.qualify(&job));
            state.validate().unwrap();
            controller = state.meta.clone();
            meta_io.0.clear();
            for blob in controller.model.blobs() {
                for index in 0..blob.chunks() {
                    meta_io.0.insert(
                        (blob.sha256.clone(), index),
                        store.inner.0[&(blob.sha256.clone(), index)].clone(),
                    );
                }
            }
            export_meta(&trial_dir.join("meta"), &controller.model, &meta_io);
            write(&trial_dir.join("job.json"), &job);
            write(&trial_dir.join("state.json"), &state);
            let summary = serde_json::json!({"context":context,"seed":seed,"trial":trial,"elapsed":clock.elapsed(),"io_bytes":store.read_bytes+store.written_bytes-io_start,"plan":job.progress.as_ref().unwrap().plan,"outcome":job.progress.as_ref().unwrap().meta_update,"meta_state":controller});
            summaries.push(summary);
            write(&path.join("trials.json"), &summaries);
            eprintln!(
                "{}",
                serde_json::json!({"event":"outer_meta_trial_completed","context":context,"trial":trial,"meta_updates":controller.model.updates,"elapsed":all_clock.elapsed()})
            );
        }
    }
    write(
        &path.join("completed.json"),
        &serde_json::json!({"experiences":summaries.len(),"elapsed":all_clock.elapsed(),"controller":controller}),
    );
    MetaSeed {
        state: controller,
        io: meta_io,
    }
}
fn fork_store(source: &Store) -> Store {
    Store {
        inner: MemoryStore(source.inner.0.clone()),
        ..Store::default()
    }
}
fn collect(store: &mut Store, initial: &Checkpoint, job: Option<&Job>, selected: &State) {
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
        bootstrap: Vec::new(),
        bootstrap_cost: serde_json::json!({"cpu_micros":0,"wall_micros":0}),
    }
}
fn train(
    seed: u64,
    definition: Arm,
    common: &Common,
    rounds: usize,
    path: &Path,
    meta_seed: Option<&MetaSeed>,
) -> Run {
    std::fs::create_dir_all(path).unwrap();
    let mut clock = Clock::start();
    let Arm {
        name: arm,
        random_only,
        preparation,
        acquisition_only,
    } = definition;
    clock.charged_cpu = common.bootstrap_cost["cpu_micros"].as_u64().unwrap();
    clock.charged_wall = common.bootstrap_cost["wall_micros"].as_u64().unwrap();
    let mut state = common.state.clone();
    state.preparation = preparation;
    let initial = state.model.clone();
    let mut store = fork_store(&common.store);
    state.meta.draw ^= seed;
    if preparation == Preparation::Meta {
        let trained = meta_seed.expect("frozen outer learner");
        state.meta = trained.state.clone();
        state.meta.draw ^= seed;
        copy_meta(&trained.io, &mut store, &state.meta);
    }
    state.validate().unwrap();
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
    let mut seen = common
        .bootstrap
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    let mut events = Vec::new();
    let mut stop = "round_limit";
    for round in 0..rounds {
        let shared = round == 0 && !common.bootstrap.is_empty();
        let mut rows = if shared {
            common.bootstrap.clone()
        } else {
            Vec::new()
        };
        for index in 0..if shared { 0 } else { 48 } {
            if clock.exhausted() {
                stop = "compute_limit";
                break;
            }
            frontier.feedback(Some(state.feedback()));
            let mut eligible = |q: &CompiledQuestion| {
                !seen.contains(&crate::hex(q.resolution_id()))
                    && meta_partition(q.source(), false)
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
        write(
            &path.join(format!("round-{round}-acquisitions.json")),
            &rows,
        );
        assert_eq!(dictionary, digest(&state.knowledge));
        assert_eq!(meanings, digest(&state.definitions));
        if acquisition_only {
            let summary = serde_json::json!({"seed":seed,"distinct_questions":seen.len(),"elapsed":clock.elapsed(),"optimizer_updates":0});
            write(&path.join("summary.json"), &summary);
            write(&path.join("state.json"), &state);
            write(&path.join("evidence.json"), &all);
            return Run {
                seed,
                arm,
                state,
                initial,
                store,
                summary,
                bootstrap: Some((all, rows)),
            };
        }
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
                job.execute(
                    unit,
                    None,
                    700_000 + seed * 10 + round as u64,
                    &mut engine,
                    &mut store,
                )
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
                collect(&mut store, &initial, Some(&job), &state);
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
            if let Some(update) = job.progress.as_ref().and_then(|p| p.meta_update.as_ref()) {
                export_meta(
                    &path.join(format!("round-{round}-meta")),
                    &update.model,
                    &store.inner,
                );
            }
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
        collect(&mut store, &initial, None, &state);
        if clock.exhausted() {
            stop = "compute_limit";
            break;
        }
    }
    let summary = serde_json::json!({"seed":seed,"arm":arm,"random_only":random_only,"preparation":preparation,"stop":stop,"elapsed":clock.elapsed(),"rounds":events,
        "initial":initial,"selected":state.model,"distinct_questions":seen.len(),"shared_acquisition_cost":common.bootstrap_cost,"read_bytes":store.read_bytes,"written_bytes":store.written_bytes,"read_operations":store.reads,"write_operations":store.writes});
    write(&path.join("summary.json"), &summary);
    Run {
        seed,
        arm,
        state,
        initial,
        store,
        summary,
        bootstrap: None,
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
        vec![3511]
    } else {
        vec![2411, 3203, 3301]
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
    write(
        &output.join("split-audit.json"),
        &serde_json::json!({"old_confirmation":bank.prior_confirmation,"excluded_roots":bank.excluded_roots,"confirmation_roots":bank.confirmation_roots,"new_core_extra_steps":3,"outer_split":"novel acquisition dependency SHA-256 byte0 modulo3: 0/1 meta-train,2 final; shared seven prerequisites excluded from novel acquisitions"}),
    );
    write(
        &output.join("run-source.json"),
        &serde_json::json!({"source_commit":std::env::var("NAOME_ADAPTIVE_COMMIT").unwrap_or_else(|_|"unfrozen-engineering-pilot".into()),
        "specification":Checkpoint::fresh().specification,"bank_sha256":digest(&(&bank.learning,&bank.development,&bank.confirmation)),"protocol_sha256":crate::hex(&Sha256::digest(include_bytes!("../adaptive-protocol.json"))),"pilot":pilot,"seeds":seeds,"rounds":rounds,"parameters":model::PARAMETERS,"meta_parameters":meta::PARAMETERS,"meta_specification":meta::Checkpoint::fresh().specification}),
    );
    let trained_meta = train_meta(&output.join("outer-learning"), pilot);
    let mut runs = Vec::new();
    let mut common_cost = Vec::new();
    for (index, seed) in seeds.iter().enumerate() {
        let path = output.join(format!("seed-{seed}"));
        let common = common(*seed, &path.join("common"));
        common_cost.push(serde_json::json!({"seed":seed,"cost":common.cost}));
        let shared_clock = Clock::start();
        let mut shared = train(
            *seed,
            Arm {
                name: "shared_acquisition",
                random_only: false,
                preparation: Preparation::Targeted,
                acquisition_only: true,
            },
            &common,
            1,
            &path.join("shared-acquisition"),
            None,
        );
        let (evidence, bootstrap) = shared.bootstrap.take().unwrap();
        let mut shared_rows = common.rows.clone();
        shared_rows.extend(bootstrap.clone());
        shared
            .state
            .compact_with_meta_headroom(META_HEADROOM)
            .unwrap();
        let shared_cost = shared_clock.elapsed();
        write(
            &path.join("shared-acquisition/matched-input.json"),
            &serde_json::json!({"state":shared.state,"meta_headroom_bytes":META_HEADROOM,"charged_cost":shared_cost}),
        );
        let adaptive_common = Common {
            state: shared.state,
            store: shared.store,
            evidence,
            rows: shared_rows,
            cost: common.cost.clone(),
            bootstrap,
            bootstrap_cost: shared_cost,
        };
        let mut arms = vec![
            ("random_balanced", true, Preparation::Balanced),
            ("adaptive_balanced", false, Preparation::Balanced),
            ("adaptive_reference", false, Preparation::ReferenceTargeted),
            ("adaptive_targeted", false, Preparation::Targeted),
            ("adaptive_fixed_mixture", false, Preparation::FixedMixture),
            ("adaptive_random_mixture", false, Preparation::RandomMixture),
            ("adaptive_meta", false, Preparation::Meta),
        ];
        let arm_count = arms.len();
        arms.rotate_left(index % arm_count);
        for (arm, random, preparation) in arms {
            runs.push(train(
                *seed,
                Arm {
                    name: arm,
                    random_only: random,
                    preparation,
                    acquisition_only: false,
                },
                if random { &common } else { &adaptive_common },
                rounds,
                &path.join(arm),
                Some(&trained_meta),
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
