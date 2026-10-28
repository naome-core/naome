//! Finite matched finder comparisons on one current native solver contract.
//! This known development material is not independent final qualification.
use super::*;
use crate::{
    checkpoint::tests::Directory,
    frontier::{Frontier, Treatment, evidence::Outcome},
    jobs,
};
use serde_json::{Value, json};
mod confirmation;
mod diagnosis;

const SEEDS: [u64; 3] = [41, 73, 101];
const ARMS: [Treatment; 6] = [
    Treatment::Previous,
    Treatment::Uniform,
    Treatment::NoGeneration,
    Treatment::NoUtility,
    Treatment::NoReplay,
    Treatment::Full,
];
const ATTEMPTS: usize = 12;
const SEARCH: usize = 128;
const TRAIN_CPU: u64 = 90_000_000;
const TRAIN_WALL: u64 = 120_000_000;

#[derive(Default)]
struct Store {
    inner: MemoryStore,
    bytes: u64,
    operations: u64,
}
impl ArtifactIo for Store {
    fn read(&mut self, blob: &Blob, range: std::ops::Range<usize>) -> Result<Vec<u8>, String> {
        let bytes = self.inner.read(blob, range)?;
        self.bytes += bytes.len() as u64;
        self.operations += 1;
        Ok(bytes)
    }
    fn write(
        &mut self,
        blob: &Blob,
        range: std::ops::Range<usize>,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        self.bytes += bytes.len() as u64;
        self.operations += 1;
        self.inner.write(blob, range, bytes)
    }
}
fn label(t: Treatment) -> &'static str {
    match t {
        Treatment::Previous => "previous",
        Treatment::Uniform => "uniform",
        Treatment::NoGeneration => "without_generation",
        Treatment::NoUtility => "without_utility",
        Treatment::NoReplay => "without_replay",
        Treatment::FamilyReplay => "family_replay",
        Treatment::FamilyReplayNoUtility => "family_replay_without_utility",
        Treatment::Full => "full",
    }
}
fn solve(
    state: &State,
    engine: &mut Engine,
    io: &mut Store,
    q: &CompiledQuestion,
    job: u64,
) -> Generation {
    engine
        .with(&state.model, io, |runtime| {
            solve_with_report(
                q.source(),
                runtime,
                SEARCH,
                job,
                SolveContext {
                    definitions: &state.definitions,
                    theorems: &state.knowledge,
                    required: &[],
                    prerequisites: None,
                },
            )
        })
        .unwrap()
}
fn accept(
    state: &mut State,
    graph: &mut crate::Graph,
    q: &CompiledQuestion,
    solution: &Solution,
    job: u64,
    path: &Path,
) -> bool {
    drop(solution.checked().unwrap());
    let (root, batch) = graph
        .prepare_generated(&solution.source, &solution.helpers, q)
        .unwrap();
    graph
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
        .unwrap();
    std::fs::write(path.join(format!("proof-{job}.nao")), &solution.source).unwrap();
    state
        .accept(Example {
            origin: Origin::Local,
            job,
            question: q.source().into(),
            proof_id: solution.proof_id.clone(),
            refuted: solution.refuted,
            tree: solution.tree.clone(),
        })
        .unwrap()
}
fn retained(io: &mut Store, blobs: Vec<&Blob>) {
    let keys = blobs
        .into_iter()
        .map(|b| b.sha256.clone())
        .collect::<BTreeSet<_>>();
    io.inner.0.retain(|(id, _), _| keys.contains(id));
}
fn prepare(seed: u64, path: &Path) -> (State, MemoryStore, Vec<(String, Solution, u64)>, Value) {
    std::fs::create_dir_all(path).unwrap();
    let mut state = State::fresh();
    state.model.seed = seed;
    let mut engine = Engine::default();
    let mut io = Store::default();
    state.model = engine.snapshot(&state.model, &mut io).unwrap();
    state.feedback = crate::training::ability::Feedback::fresh(digest(&state.model));
    let mut graph = crate::Graph::default();
    let mut accepted = Vec::new();
    let mut rows = Vec::new();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    for (index, case) in shuffled_learning(seed).into_iter().take(64).enumerate() {
        let q = CompiledQuestion::compile(&case.source).unwrap();
        let job = 1 + index as u64;
        let result = solve(&state, &mut engine, &mut io, &q, job);
        let success = if let Some(solution) = &result.solution {
            let added = accept(&mut state, &mut graph, &q, solution, job, path);
            if added {
                accepted.push((q.source().to_owned(), solution.clone(), job));
            }
            added
        } else {
            false
        };
        state.observe_result(
            q.source(),
            result.solution.is_some(),
            &result.diagnostic,
            result.cost.generation_micros,
            SEARCH as u32,
        );
        rows.push(
            json!({"source":q.source(),"case":case.id,"accepted":success,"cost":result.cost}),
        );
        if state.needs_training() {
            break;
        }
    }
    let report = json!({"seed":seed,"initial_model":state.model,"accepted":accepted.len(),"training_ready":state.needs_training(),"cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),"model_io_bytes":io.bytes,"events":rows});
    write(&path.join("preparation.json"), &report);
    (state, io.inner, accepted, report)
}
fn evaluation(state: &State, engine: &mut Engine, io: &mut Store, job: u64) -> Value {
    let mut rows = Vec::new();
    // Existing development cases remain outside gradient/training sources.
    // They also participate in native promotion: this is development evidence.
    let cases = curriculum::development();
    for (index, case) in cases
        .iter()
        .step_by((cases.len() / 12).max(1))
        .take(12)
        .enumerate()
    {
        let result = engine
            .with(&state.model, io, |runtime| {
                solve_with_report(
                    &case.source,
                    runtime,
                    32,
                    job + index as u64,
                    SolveContext {
                        definitions: &state.definitions,
                        theorems: &[],
                        required: &[],
                        prerequisites: None,
                    },
                )
            })
            .unwrap();
        rows.push(json!({"id":case.id,"family":case.family,"solved":result.solution.is_some(),"cost":result.cost}));
    }
    json!(rows)
}
fn train(state: &mut State, engine: &mut Engine, io: &mut Store, job: u64, path: &Path) -> Value {
    if !state.needs_training() {
        return json!({"status":"not_ready","selected_model":state.model});
    }
    let mut observer = crate::resources::adaptive::Observer::default();
    let observed = observer.refresh(path).unwrap().clone();
    if observed.budget.paused.is_some() {
        return json!({"status":"paused_by_resource_owner","resources":observed,"selected_model":state.model});
    }
    state.attempted(state.learning_epoch());
    let mut native = state.job();
    native.training = true;
    let cpu = meta::cpu_micros().unwrap();
    let wall = Instant::now();
    let bytes = io.bytes;
    let before = state.model.clone();
    let mut complete = true;
    let mut stopped = None;
    let mut stopped_reason = None;
    for unit in 1..=native.units() {
        if observer.due(Instant::now()) {
            let observed = observer.refresh(path).unwrap();
            if let Some(reason) = &observed.budget.paused {
                complete = false;
                stopped = Some(unit);
                stopped_reason = Some(reason.clone());
                break;
            }
        }
        if let Err(error) = native.execute(unit, None, job, engine, io) {
            complete = false;
            stopped = Some(unit);
            stopped_reason = Some(error);
            break;
        }
        retained(io, native.blobs());
        if meta::cpu_micros().unwrap() - cpu > TRAIN_CPU
            || wall.elapsed().as_micros() > u128::from(TRAIN_WALL)
            || io.bytes - bytes > 2 * 1024 * 1024 * 1024
        {
            complete = false;
            stopped = Some(unit);
            break;
        }
    }
    let qualified = complete && state.qualify(&native);
    if complete {
        assert!(
            qualified,
            "completed native trial must retain its actual selected state"
        );
    }
    let result = json!({"status":if complete {"complete"} else if stopped_reason.is_some(){"interrupted"}else{"budget_exhausted"},"stopped_unit":stopped,"stopped_reason":stopped_reason,"qualified":qualified,"source_model":before,"selected_model":state.model,"cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":wall.elapsed().as_micros(),"model_io_bytes":io.bytes-bytes,"progress":native.progress});
    write(&path.join(format!("learning-{job}.json")), &result);
    retained(io, state.blobs().collect());
    result
}
fn arm(
    seed: u64,
    treatment: Treatment,
    coupled: bool,
    common: &State,
    blobs: &MemoryStore,
    initial: &[(String, Solution, u64)],
    path: &Path,
) -> Value {
    std::fs::create_dir_all(path).unwrap();
    let directory = Directory::new();
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
    let mut finder = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    finder.treatment(treatment);
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let mut io = Store {
        inner: MemoryStore(blobs.0.clone()),
        ..Default::default()
    };
    let mut engine = Engine::default();
    let start = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let mut job = 10_000;
    let mut cursor = 0;
    let mut rows = Vec::new();
    let mut unique = BTreeSet::new();
    let mut completed = 0;
    let mut solved = 0;
    let mut expansions = 0;
    let rounds = if coupled { 3 } else { 6 };
    let before = evaluation(&state, &mut engine, &mut io, 900_000);
    for round in 0..rounds {
        let mut events = Vec::new();
        let round_cpu = meta::cpu_micros().unwrap();
        for _ in 0..ATTEMPTS {
            finder.feedback(Some(state.feedback()));
            finder
                .refresh(&graph, |q| owner.assess(&graph, q).passed())
                .unwrap();
            let candidates = finder.candidate_page(cursor, |q| owner.assess(&graph, q).passed());
            cursor += 1;
            let refs = candidates.iter().collect::<Vec<_>>();
            let Some(index) = finder
                .choose(&refs, &graph, settings.solving, false)
                .unwrap()
            else {
                events.push(json!({"empty_page":true}));
                continue;
            };
            let q = &candidates[index];
            assert!(owner.assess(&graph, q).passed());
            job += 1;
            let model = digest(&state.model);
            let result = solve(&state, &mut engine, &mut io, q, job);
            completed += 1;
            expansions += result.cost.search_expansions;
            unique.insert(crate::hex(q.resolution_id()));
            let output = jobs::Output::Native {
                solution: result.solution.clone(),
                diagnostic: result.diagnostic.clone(),
                frontier: result.frontier.clone(),
            };
            finder
                .attempted(
                    q,
                    &graph,
                    &jobs::Completion {
                        id: job,
                        model_checkpoint: Some(model),
                        binding: jobs::Binding::new([0; 32], [0; 32]),
                        spent_ms: result.cost.generation_micros / 1000,
                        reserved_units: 1,
                        state: jobs::State::Complete,
                        result: Ok(output),
                    },
                    if result.solution.is_some() {
                        Outcome::Candidate
                    } else {
                        Outcome::NoCandidate
                    },
                )
                .unwrap();
            let mut accepted = false;
            if let Some(solution) = &result.solution {
                accepted = accept(&mut state, &mut graph, q, solution, job, path);
                let root = crate::object::proof_address(&solution.proof_id).unwrap();
                finder.prepared(q, job, root).unwrap();
                finder.verified(q, &graph, job, root).unwrap();
                solved += 1;
            }
            state.observe_result(
                q.source(),
                result.solution.is_some(),
                &result.diagnostic,
                result.cost.generation_micros,
                SEARCH as u32,
            );
            events.push(json!({"question":q.source(),"resolution":crate::hex(q.resolution_id()),"solved":result.solution.is_some(),"accepted_training":accepted,"cost":result.cost}));
        }
        let training = if coupled {
            train(
                &mut state,
                &mut engine,
                &mut io,
                100_000 + round as u64,
                path,
            )
        } else {
            json!({"status":"frozen_solver"})
        };
        let after = evaluation(&state, &mut engine, &mut io, 910_000 + round as u64 * 100);
        // Reopen the actual durable research state after every round.
        drop(finder);
        finder = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
        finder.treatment(treatment);
        let row = json!({"round":round,"events":events,"training":training,"evaluation":after,"round_cpu_micros":meta::cpu_micros().unwrap()-round_cpu,"model":state.model,"finder_learning":finder.learning_snapshot(),"feedback":state.feedback()});
        rows.push(row);
        write(&path.join("rounds.json"), &rows);
        eprintln!(
            "{}",
            json!({"event":"finder_study_round","seed":seed,"arm":label(treatment),"round":round+1,"completed":completed,"solved":solved})
        );
    }
    let result = json!({"seed":seed,"arm":label(treatment),"coupled":coupled,"initial_model":common.model,"final_model":state.model,"initial_evaluation":before,"rounds":rows,"completed_attempts":completed,"checked_solutions":solved,"distinct_questions":unique.len(),"search_expansions":expansions,"cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":start.elapsed().as_micros(),"model_io_bytes":io.bytes,"model_io_operations":io.operations});
    write(&path.join("result.json"), &result);
    result
}

#[test]
#[ignore = "explicit finite matched native finder study; run alone"]
fn matched_continual_finder_study() {
    let output = std::path::PathBuf::from(std::env::var("NAOME_FINDER_NATIVE_OUTPUT").unwrap());
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let coupled = std::env::var("NAOME_FINDER_NATIVE_PHASE").unwrap() == "coupled";
    let mut observer = crate::resources::adaptive::Observer::default();
    let observed = observer.refresh(&output).unwrap().clone();
    write(&output.join("initial-resources.json"), &observed);
    assert!(
        observed.budget.paused.is_none(),
        "native study obeys the installed resource pause: {:?}",
        observed.budget.paused
    );
    let arms = if coupled {
        vec![Treatment::Previous, Treatment::NoUtility, Treatment::Full]
    } else {
        ARMS.to_vec()
    };
    write(
        &output.join("manifest.json"),
        &json!({"source_contract":input_specification(),"seeds":SEEDS,"arms":arms.iter().map(|t|label(*t)).collect::<Vec<_>>(),"rounds":if coupled{3}else{6},"attempts_per_round":ATTEMPTS,"search_expansions_per_attempt":SEARCH,"native_learning_cpu_limit":TRAIN_CPU,"native_learning_wall_limit":TRAIN_WALL,"scope":"Known development comparison. Same source/model starts and native learning/promotion rules. Actual costs include preparation, generation, checking, replay, utility and full qualification. Equal attempt/search/job ceilings are not a claim of equal realized CPU."}),
    );
    let mut results = Vec::new();
    for (seed_index, seed) in SEEDS.into_iter().enumerate() {
        let seed_path = output.join(seed.to_string());
        let (common, blobs, initial, preparation) = prepare(seed, &seed_path.join("preparation"));
        write(&seed_path.join("initial-state.json"), &common);
        for offset in 0..arms.len() {
            let treatment = arms[(seed_index + offset) % arms.len()];
            let result = arm(
                seed,
                treatment,
                coupled,
                &common,
                &blobs,
                &initial,
                &seed_path.join(label(treatment)),
            );
            results.push(json!({"preparation":preparation,"result":result}));
            write(&output.join("results.json"), &results);
        }
    }
}
