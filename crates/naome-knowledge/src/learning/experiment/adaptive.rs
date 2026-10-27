//! Finite outer trial learning and independent matched lower-learner controls.
use super::*;
mod acquisition;
mod storage;
use crate::frontier::{Frontier, evidence::Outcome};
use acquisition::Frozen;
use knowledge::{Store, acquire, admit_discovery, evidence_for};
use nix::sys::{
    resource::{UsageWho, getrusage},
    time::TimeValLike,
};
const META_HEADROOM: usize = meta::STATE_BYTES;

// Reserve structural metadata before fixing the shared lower source pool. This
// envelope is never inserted as observed ability or supplied to a learner.
fn development_capacity_profile(checkpoint: String) -> crate::training::ability::Profile {
    let mut profile = crate::training::ability::Profile::new(checkpoint);
    for case in curriculum::development()
        .into_iter()
        .chain(&curriculum::adaptive::BANK.transfer)
    {
        let question = CompiledQuestion::compile(&case.source).unwrap();
        // Every actual cell has at most one observation per question. These
        // three passes bound all outcome counters and saturate measured cost,
        // while preserving the exact syntax cells and coverage sketches.
        for solved in [Some(true), Some(false), None] {
            profile.observe(&question, 32, solved, u64::MAX);
        }
    }
    profile
}
fn outer_metadata_headroom(state: &State) -> usize {
    let maximum = development_capacity_profile(state.feedback.checkpoint.clone());
    META_HEADROOM
        + crate::checkpoint::encode(&maximum)
            .unwrap()
            .len()
            .saturating_sub(
                crate::checkpoint::encode(&state.feedback.development)
                    .unwrap()
                    .len(),
            )
}
#[test]
fn prospective_outer_profile_reserve_bounds_actual_qualification_outcomes() {
    let checkpoint = digest(&Checkpoint::fresh());
    let maximum = development_capacity_profile(checkpoint.clone());
    maximum.validate().unwrap();
    let capacity = crate::checkpoint::encode(&maximum).unwrap().len();
    for mode in 0..4 {
        let mut actual = crate::training::ability::Profile::new(checkpoint.clone());
        for (index, case) in curriculum::development()
            .into_iter()
            .chain(&curriculum::adaptive::BANK.transfer)
            .enumerate()
        {
            let question = CompiledQuestion::compile(&case.source).unwrap();
            let outcome = match mode {
                0 => Some(true),
                1 => Some(false),
                2 => None,
                _ => [Some(true), Some(false), None][index % 3],
            };
            actual.observe(&question, 32, outcome, u64::MAX);
        }
        actual.validate().unwrap();
        assert!(crate::checkpoint::encode(&actual).unwrap().len() <= capacity);
    }
}

fn resource_boundary() -> u64 {
    let sample = crate::resources::feedback::Meter::start().finish(0, true);
    let peak = sample.peak_rss_bytes.expect("native peak RSS observation");
    assert!(
        peak <= model::REQUIREMENTS.work_bytes as u64,
        "whole experiment RSS {peak} exceeds unchanged native work reservation"
    );
    peak
}

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
    preparation: Preparation,
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
fn prepare_meta_source(seed: u64, context: usize, dir: &Path) -> Common {
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
    let metadata_headroom = outer_metadata_headroom(&common.state);
    common
        .state
        .compact_with_meta_headroom(metadata_headroom)
        .unwrap();
    write(&dir.join("source-state.json"), &common.state);
    write(&dir.join("source-evidence.json"), &common.evidence);
    write(&dir.join("source-acquisitions.json"), &common.rows);
    write(&dir.join("source-cost.json"), &acquisition_clock.elapsed());
    write(
        &dir.join("source-capacity.json"),
        &serde_json::json!({"meta_bytes":META_HEADROOM,"total_metadata_headroom":metadata_headroom,
            "state_bytes":crate::checkpoint::encode(&common.state).unwrap().len(),
            "development_capacity_bytes":crate::checkpoint::encode(&development_capacity_profile(common.state.feedback.checkpoint.clone())).unwrap().len()}),
    );
    assert!(
        common.state.needs_training(),
        "outer context must have a genuine diverse checked pool"
    );
    common
}
#[test]
#[ignore = "Explicit six-context cold capacity qualification; no optimizer or final inference"]
fn outer_source_layout_preflight() {
    let output = std::env::var("NAOME_META_SOURCE_OUTPUT").expect("fresh source output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve prior source qualification");
    std::fs::create_dir_all(output).unwrap();
    let clock = Clock::start();
    for (context, seed) in [4507, 4603, 4703, 4801, 4903, 5003].into_iter().enumerate() {
        let directory = output.join(format!("context-{context}"));
        let source = prepare_meta_source(seed, context, &directory);
        assert!(source.state.needs_training());
        source.state.validate().unwrap();
    }
    write(
        &output.join("completed.json"),
        &serde_json::json!({"contexts":6,"elapsed":clock.elapsed(),"optimizer_updates":0,"final_inferences":0}),
    );
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
    // Validate every fixed source context before spending the first trial.
    let sources = contexts
        .into_iter()
        .enumerate()
        .map(|(context, seed)| {
            let dir = path.join(format!("context-{context}"));
            let common = prepare_meta_source(seed, context, &dir);
            (context, seed, dir, common)
        })
        .collect::<Vec<_>>();
    write(
        &path.join("sources-ready.json"),
        &serde_json::json!({"contexts":sources.len(),"elapsed":all_clock.elapsed()}),
    );
    for (context, seed, dir, common) in sources {
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
            state.validate().unwrap();
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
            resource_boundary();
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
    }
}
fn train(
    seed: u64,
    definition: Arm,
    common: &Common,
    frozen: &Frozen,
    rounds: usize,
    path: &Path,
    meta_seed: Option<&MetaSeed>,
) -> Run {
    std::fs::create_dir_all(path).unwrap();
    let mut clock = Clock::start();
    let Arm {
        name: arm,
        preparation,
    } = definition;
    clock.charged_cpu = frozen.cost["cpu_micros"].as_u64().unwrap();
    clock.charged_wall = frozen.cost["wall_micros"].as_u64().unwrap();
    let mut state = common.state.clone();
    state.preparation = preparation;
    let initial = state.model.clone();
    let mut store = fork_store(&frozen.store);
    state.meta.draw ^= seed;
    if preparation == Preparation::Meta {
        let trained = meta_seed.expect("frozen outer learner");
        state.meta = trained.state.clone();
        state.meta.draw ^= seed;
        copy_meta(&trained.io, &mut store, &state.meta);
    }
    state.validate().unwrap();
    let mut engine = Engine::default();
    let mut events = Vec::new();
    let mut stop = "round_limit";
    for (round, input) in frozen.rounds.iter().take(rounds).enumerate() {
        state = acquisition::bind(input, &state);
        state.validate().unwrap();
        let all = &input.evidence;
        let rows = &input.rows;
        let manifest = digest(&(&state.replay, &state.anchors, all));
        write(
            &path.join(format!("round-{round}-matched-input.json")),
            &serde_json::json!({"source_sha256":manifest,"state":state,"evidence":all,
                "acquisitions_sha256":digest(rows),"producer_model":input.state.model}),
        );
        write(&path.join(format!("round-{round}-acquisitions.json")), rows);
        let evidence = evidence_for(&state, all);
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
        let event = serde_json::json!({"round":round,"attempts":rows.len(),"accepted":state.accepted,"replay":state.replay.len(),"pool_graphs":pool.graphs().len(),
            "decision_before":before,"decision_candidate":metrics,"qualification":gate,"retained_updates":state.model.updates,"feedback_after":state.feedback,
            "matched_input_sha256":manifest,"elapsed":clock.elapsed()});
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
        write(&path.join(format!("round-{round}-evidence.json")), all);
        collect(&mut store, &initial, None, &state);
        if clock.exhausted() {
            stop = "compute_limit";
            break;
        }
    }
    storage::spill(&mut store, &path.join("retained-artifacts"));
    let peak_rss_bytes = resource_boundary();
    let summary = serde_json::json!({"seed":seed,"arm":arm,"random_only":true,"preparation":preparation,"stop":stop,"peak_rss_bytes":peak_rss_bytes,"elapsed":clock.elapsed(),"rounds":events,
        "initial":initial,"selected":state.model,"distinct_questions":rounds*48,"shared_acquisition_cost":frozen.cost,"read_bytes":store.read_bytes,"written_bytes":store.written_bytes,"read_operations":store.reads,"write_operations":store.writes});
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
        vec![3511]
    } else {
        vec![2411, 3203, 3301]
    };
    let rounds = 2;
    let clock = Clock::start();
    let bank = &*curriculum::adaptive::BANK;
    let bank_cost = clock.elapsed();
    write(
        &output.join("bank.json"),
        &serde_json::json!({"learning":bank.learning,"development":bank.development,"transfer":bank.transfer,"confirmation":bank.confirmation}),
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
        "specification":Checkpoint::fresh().specification,"bank_sha256":digest(&(&bank.learning,&bank.development,&bank.transfer,&bank.confirmation)),"protocol_sha256":crate::hex(&Sha256::digest(include_bytes!("../adaptive-protocol.json"))),"pilot":pilot,"seeds":seeds,"rounds":rounds,"parameters":model::PARAMETERS,"meta_parameters":meta::PARAMETERS,"meta_specification":meta::Checkpoint::fresh().specification}),
    );
    let mut sources = Vec::new();
    for seed in &seeds {
        let path = output.join(format!("seed-{seed}"));
        let common = common(*seed, &path.join("common"));
        let frozen = acquisition::freeze(*seed, &common, rounds, &path.join("shared-acquisition"));
        sources.push((*seed, common, frozen));
    }
    write(
        &output.join("sources-ready.json"),
        &serde_json::json!({"contexts":sources.len(),"rounds":rounds,"optimizer_updates":0,"elapsed":clock.elapsed()}),
    );
    let trained_meta = train_meta(&output.join("outer-learning"), pilot);
    let mut runs = Vec::new();
    let mut common_cost = Vec::new();
    for (index, (seed, common, frozen)) in sources.into_iter().enumerate() {
        let path = output.join(format!("seed-{seed}"));
        common_cost.push(serde_json::json!({"seed":seed,"cost":common.cost}));
        let mut arms = vec![
            ("random_balanced", Preparation::Balanced),
            ("adaptive_balanced", Preparation::Balanced),
            ("adaptive_reference", Preparation::ReferenceTargeted),
            ("adaptive_targeted", Preparation::Targeted),
            ("adaptive_fixed_mixture", Preparation::FixedMixture),
            ("adaptive_random_mixture", Preparation::RandomMixture),
            ("adaptive_meta", Preparation::Meta),
        ];
        let arm_count = arms.len();
        arms.rotate_left(index % arm_count);
        for (arm, preparation) in arms {
            runs.push(train(
                seed,
                Arm {
                    name: arm,
                    preparation,
                },
                &common,
                &frozen,
                rounds,
                &path.join(arm),
                Some(&trained_meta),
            ));
        }
    }
    for seed in &seeds {
        let plain = runs
            .iter()
            .find(|r| r.seed == *seed && r.arm == "random_balanced")
            .unwrap();
        let adaptive = runs
            .iter()
            .find(|r| r.seed == *seed && r.arm == "adaptive_balanced")
            .unwrap();
        assert_eq!(
            plain.state.model, adaptive.state.model,
            "identical balanced methods and complete matched data must retain identical weights/Adam"
        );
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
        storage::restore(&mut run.store, &path.join("retained-artifacts"));
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
        run.store.inner.0.clear();
        resource_boundary();
        results.push(serde_json::json!({"seed":run.seed,"arm":run.arm,"training":run.summary,"evaluations":evaluations}));
        write(&output.join("results.json"), &results);
    }
    write(
        &output.join("completed.json"),
        &serde_json::json!({"all_training_finished_before_confirmation":true,"learning_finished":learning_finished,"elapsed":clock.elapsed(),"bank_cost":bank_cost,"common_cost":common_cost,"peak_rss_bytes":resource_boundary(),"runs":results.len()}),
    );
}
