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
type Clock = BTreeMap<(String, String, u64), u64>;

fn reference_clock(reference: &Value) -> Clock {
    let mut model: Checkpoint = serde_json::from_value(reference["initial_model"].clone()).unwrap();
    let mut occurrences = BTreeMap::new();
    let mut result = BTreeMap::new();
    for round in reference["rounds"].as_array().unwrap() {
        let stamp = digest(&model);
        for event in round["events"].as_array().unwrap() {
            if event.get("empty_page").is_some() {
                continue;
            }
            let id = event["resolution"].as_str().unwrap().to_owned();
            let index = occurrences.entry((stamp.clone(), id.clone())).or_insert(0);
            result.insert(
                (stamp.clone(), id, *index),
                event["cost"]["generation_micros"].as_u64().unwrap(),
            );
            *index += 1;
        }
        model = serde_json::from_value(round["model"].clone()).unwrap();
    }
    result
}

fn frozen_clock(path: &Path) -> Clock {
    let rows: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut clock = Clock::new();
    for row in rows {
        let key = (
            row["model"].as_str().unwrap().to_owned(),
            row["question"].as_str().unwrap().to_owned(),
            row["occurrence"].as_u64().unwrap(),
        );
        assert!(clock.insert(key, row["micros"].as_u64().unwrap()).is_none());
    }
    clock
}

fn assert_control_reproduced(expected: &Value, actual: &Value) {
    // Both sides must cross the same JSON parser. In-memory f32 values widened
    // into JSON numbers otherwise differ from the identical persisted decimal
    // value read through serde_json's default floating-point parser.
    let persisted: Value = serde_json::from_slice(&serde_json::to_vec(actual).unwrap()).unwrap();
    let actual = &persisted;
    assert_eq!(expected["initial_model"], actual["initial_model"]);
    assert_eq!(expected["final_model"], actual["final_model"]);
    let expected = expected["rounds"].as_array().unwrap();
    let actual = actual["rounds"].as_array().unwrap();
    assert_eq!(expected.len(), actual.len());
    for (a, b) in expected.iter().zip(actual) {
        assert_eq!(
            a["model"], b["model"],
            "control model/Adam state did not reproduce"
        );
        let finder = |round: &Value| {
            let mut value = round["finder_learning"].clone();
            // This receipt also binds diagnostic CPU/wall measurements. The
            // learned labels and complete model state below must still match.
            value["curriculum"]
                .as_object_mut()
                .unwrap()
                .remove("utility_receipt");
            value
        };
        assert_eq!(
            finder(a),
            finder(b),
            "control finder state did not reproduce"
        );
        let events = |r: &Value| {
            r["events"].as_array().unwrap().iter().map(|e| {
            json!({"resolution":e["resolution"],"solved":e["solved"],"accepted_training":e["accepted_training"],"feedback_cost_micros":e["feedback_cost_micros"],"empty_page":e["empty_page"]})
        }).collect::<Vec<_>>()
        };
        assert_eq!(
            events(a),
            events(b),
            "recorded control trajectory did not reproduce"
        );
        let outcomes = |r: &Value| {
            r["evaluation"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| json!({"id":e["id"],"solved":e["solved"]}))
                .collect::<Vec<_>>()
        };
        assert_eq!(outcomes(a), outcomes(b));
        assert_eq!(a["training"]["status"], b["training"]["status"]);
        assert_eq!(
            a["training"]["progress"]["original_score"],
            b["training"]["progress"]["original_score"]
        );
    }
}

fn assert_control_prefix_reproduced(expected: &Value, actual: &Value) {
    let mut prefix = actual.clone();
    let length = expected["rounds"].as_array().unwrap().len();
    let rounds = prefix["rounds"].as_array_mut().unwrap();
    assert!(rounds.len() >= length);
    rounds.truncate(length);
    let model = rounds.last().unwrap()["model"].clone();
    prefix["final_model"] = model;
    assert_control_reproduced(expected, &prefix);
}

struct Start<'a> {
    state: &'a State,
    blobs: &'a MemoryStore,
    initial: &'a [(String, Solution, u64)],
    reserved: &'a BTreeSet<String>,
    feedback_reference: Option<&'a Value>,
}

fn finder_feedback(
    mut actual: crate::training::ability::Feedback,
    reference: Option<&Value>,
) -> crate::training::ability::Feedback {
    let Some(reference) = reference else {
        return actual;
    };
    for round in reference["rounds"].as_array().unwrap() {
        let expected: crate::training::ability::Feedback =
            serde_json::from_value(round["feedback"].clone()).unwrap();
        if actual.checkpoint != expected.checkpoint {
            continue;
        }
        let without_costs = |profile: &crate::training::ability::Profile| {
            let mut value = serde_json::to_value(profile).unwrap();
            for cell in value["cells"].as_object_mut().unwrap().values_mut() {
                cell.as_array_mut().unwrap()[2] = json!(0);
            }
            value
        };
        if without_costs(&actual.development) != without_costs(&expected.development) {
            continue;
        }
        // Only the read-only finder scheduling view receives recorded costs.
        // State, native qualification, labels, weights and actual resource
        // accounting retain their real values from this execution.
        actual.development = expected.development;
        actual.validate().unwrap();
        break;
    }
    actual
}

fn assert_feedback_reproduced(expected: &Value, reference: &Value) {
    for rounds in expected["rounds"].as_array().unwrap().windows(2) {
        let feedback = finder_feedback(
            serde_json::from_value(rounds[0]["feedback"].clone()).unwrap(),
            Some(reference),
        );
        let receipt = digest(&(
            &feedback.checkpoint,
            &feedback.development,
            &feedback.gains,
            &feedback.regressions,
        ));
        assert_eq!(
            rounds[1]["finder_learning"]["curriculum"]["progress_receipt"], receipt,
            "declared feedback view differs from the recorded control input"
        );
    }
}

#[test]
fn recorded_finder_cost_view_is_distinct_from_measured_native_feedback() {
    let q = CompiledQuestion::compile("goal=all(a,eq(a,a))").unwrap();
    let mut measured = crate::training::ability::Feedback::fresh("11".repeat(32));
    measured.development.observe(&q, 32, Some(true), 9000);
    let mut recorded = measured.clone();
    recorded.development = crate::training::ability::Profile::new(recorded.checkpoint.clone());
    recorded.development.observe(&q, 32, Some(true), 1000);
    let reference = json!({"rounds":[{"feedback":recorded}]});
    let view = finder_feedback(measured.clone(), Some(&reference));
    assert_eq!(view, recorded);
    assert_ne!(view.development, measured.development);
    assert_eq!(finder_feedback(measured.clone(), None), measured);
    let receipt = digest(&(
        &view.checkpoint,
        &view.development,
        &view.gains,
        &view.regressions,
    ));
    let control = json!({"rounds":[{"feedback":measured},{"finder_learning":{"curriculum":{"progress_receipt":receipt}}}]});
    assert_feedback_reproduced(&control, &reference);
    let wrong_reference = json!({"rounds":[{"feedback":measured}]});
    assert!(
        std::panic::catch_unwind(|| assert_feedback_reproduced(&control, &wrong_reference))
            .is_err()
    );
    let mut different = measured.clone();
    different.development.observe(&q, 32, Some(false), 0);
    assert_eq!(
        finder_feedback(different.clone(), Some(&reference)),
        different
    );
}

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
        Treatment::OutcomeReplay => "outcome_replay",
        Treatment::CensoredReplay => "censored_replay",
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
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
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
fn owned_evidence(state: &State, sources: &[Evidence]) -> Result<Vec<Evidence>, String> {
    let mut result = Vec::new();
    for example in state
        .examples()
        .filter(|e| matches!(e.tree, search::Tree::Stored { .. }))
    {
        if result
            .iter()
            .any(|e: &Evidence| e.job == example.job && e.proof_id == example.proof_id)
        {
            continue;
        }
        let source = sources
            .iter()
            .find(|e| e.job == example.job && e.proof_id == example.proof_id)
            .ok_or("harness owned replay source missing")?;
        let trace = example.trajectory(std::slice::from_ref(source))?;
        let q = CompiledQuestion::compile(&example.question).map_err(|e| e.to_string())?;
        let target = if example.refuted {
            q.refuted_target()
        } else {
            q.proved_target()
        };
        let (_, _, verified) = search::core::checked(target, trace)?;
        if crate::hex(verified.native_id.as_bytes()) != example.proof_id {
            return Err("harness owned replay proof differs".into());
        }
        result.push(source.clone());
    }
    Ok(result)
}
fn train(
    state: &mut State,
    engine: &mut Engine,
    io: &mut Store,
    job: u64,
    path: &Path,
    sources: &[Evidence],
) -> Value {
    if !state.needs_training() {
        return json!({"status":"not_ready","selected_model":state.model});
    }
    let mut observer = crate::resources::adaptive::Observer::default();
    let observed = observer.refresh(path).unwrap().clone();
    if observed.budget.paused.is_some() {
        return json!({"status":"paused_by_resource_owner","resources":observed,"selected_model":state.model});
    }
    state.attempted(state.learning_epoch());
    let cpu = meta::cpu_micros().unwrap();
    let wall = Instant::now();
    let bytes = io.bytes;
    let mut native = state.job();
    native.training = true;
    native.evidence = owned_evidence(state, sources).unwrap();
    let before = state.model.clone();
    let mut complete = true;
    let mut stopped = None;
    let mut stopped_reason = None;
    for unit in 1..=native.units() {
        if meta::cpu_micros().unwrap() - cpu >= TRAIN_CPU
            || wall.elapsed().as_micros() >= u128::from(TRAIN_WALL)
            || io.bytes - bytes > 2 * 1024 * 1024 * 1024
        {
            complete = false;
            stopped = Some(unit);
            break;
        }
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
    rounds: usize,
    start_state: Start<'_>,
    path: &Path,
    mut clock: Option<&mut Clock>,
) -> Value {
    let start = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let Start {
        state: common,
        blobs,
        initial,
        reserved,
        feedback_reference,
    } = start_state;
    std::fs::create_dir_all(path).unwrap();
    let directory = Directory::new();
    let mut state = common.clone();
    let mut graph = crate::Graph::default();
    let mut sources = initial
        .iter()
        .map(|(_, s, job)| Evidence {
            job: *job,
            proof_id: s.proof_id.clone(),
            trace: s.tree.clone(),
        })
        .collect::<Vec<_>>();
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
    let mut observer = crate::resources::adaptive::Observer::default();
    let mut job = 10_000;
    let mut cursor = 0;
    let mut rows = Vec::new();
    let mut unique = BTreeSet::new();
    let mut completed = 0;
    let mut solved = 0;
    let mut expansions = 0;
    let mut occurrences = BTreeMap::new();
    let before = evaluation(&state, &mut engine, &mut io, 900_000);
    for round in 0..rounds {
        if observer.due(Instant::now()) {
            let observed = observer.refresh(path).unwrap();
            if let Some(reason) = &observed.budget.paused {
                write(
                    &path.join("interrupted.json"),
                    &json!({"round":round,"reason":reason,"resources":observed,"cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":start.elapsed().as_micros()}),
                );
                panic!("finder study paused by installed resource owner: {reason}");
            }
        }
        let mut events = Vec::new();
        let round_cpu = meta::cpu_micros().unwrap();
        for _ in 0..ATTEMPTS {
            finder.feedback(Some(finder_feedback(state.feedback(), feedback_reference)));
            finder
                .refresh(&graph, |q| {
                    !reserved.contains(&curriculum::owned::family(q.proved_target()))
                        && owner.assess(&graph, q).passed()
                })
                .unwrap();
            let candidates = finder.candidate_page(cursor, |q| {
                !reserved.contains(&curriculum::owned::family(q.proved_target()))
                    && owner.assess(&graph, q).passed()
            });
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
            let id = crate::hex(q.resolution_id());
            let occurrence = occurrences.entry((model.clone(), id.clone())).or_insert(0);
            let label_micros = if let Some(clock) = clock.as_deref_mut() {
                *clock
                    .entry((model.clone(), id, *occurrence))
                    .or_insert(result.cost.generation_micros)
            } else {
                result.cost.generation_micros
            };
            *occurrence += 1;
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
                        spent_ms: label_micros / 1000,
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
                sources.push(Evidence {
                    job,
                    proof_id: solution.proof_id.clone(),
                    trace: solution.tree.clone(),
                });
                sources.retain(|source| {
                    state
                        .examples()
                        .any(|e| e.job == source.job && e.proof_id == source.proof_id)
                });
                let root = crate::object::proof_address(&solution.proof_id).unwrap();
                finder.prepared(q, job, root).unwrap();
                finder.verified(q, &graph, job, root).unwrap();
                solved += 1;
            }
            state.observe_result(
                q.source(),
                result.solution.is_some(),
                &result.diagnostic,
                label_micros,
                SEARCH as u32,
            );
            events.push(json!({"question":q.source(),"resolution":crate::hex(q.resolution_id()),"solved":result.solution.is_some(),"accepted_training":accepted,"cost":result.cost,"diagnostic":result.diagnostic,"feedback_cost_micros":label_micros}));
        }
        let training = if coupled {
            train(
                &mut state,
                &mut engine,
                &mut io,
                100_000 + round as u64,
                path,
                &sources,
            )
        } else {
            json!({"status":"frozen_solver"})
        };
        assert!(
            !coupled || training["status"] == "complete" || training["status"] == "not_ready",
            "native learning stopped; preserve the partial study without qualification"
        );
        let after = evaluation(&state, &mut engine, &mut io, 910_000 + round as u64 * 100);
        // Reopen the actual durable research state after every round.
        drop(finder);
        finder = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
        finder.treatment(treatment);
        let row = json!({"round":round,"events":events,"training":training,"evaluation":after,"round_cpu_micros":meta::cpu_micros().unwrap()-round_cpu,"model":state.model,"finder_learning":finder.learning_snapshot(),"feedback":state.feedback(),"next_finder_feedback":finder_feedback(state.feedback(), feedback_reference)});
        rows.push(row);
        write(&path.join("rounds.json"), &rows);
        eprintln!(
            "{}",
            json!({"event":"finder_study_round","seed":seed,"arm":label(treatment),"round":round+1,"completed":completed,"solved":solved})
        );
    }
    if clock.is_some() {
        write(&path.join("state-final.json"), &state);
        export_model(&path.join("selected-model"), &state.model, &io.inner);
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
    let phase = std::env::var("NAOME_FINDER_NATIVE_PHASE").unwrap();
    let repair = matches!(
        phase.as_str(),
        "repair"
            | "repair_support"
            | "repair_yield"
            | "repair_observation"
            | "repair_screen"
            | "confirmation_models"
    );
    let screen = phase == "repair_screen";
    let paired = matches!(
        phase.as_str(),
        "repair_support" | "repair_yield" | "repair_observation"
    );
    let coupled = phase == "coupled" || repair && !screen;
    let rounds = std::env::var("NAOME_FINDER_NATIVE_ROUNDS")
        .ok()
        .map_or(if coupled { 3 } else { 6 }, |value| {
            value.parse::<usize>().unwrap()
        });
    assert!(matches!(rounds, 3 | 6));
    let mut observer = crate::resources::adaptive::Observer::default();
    let observed = observer.refresh(&output).unwrap().clone();
    write(&output.join("initial-resources.json"), &observed);
    assert!(
        observed.budget.paused.is_none(),
        "native study obeys the installed resource pause: {:?}",
        observed.budget.paused
    );
    let mut arms = if screen {
        vec![
            Treatment::Previous,
            Treatment::CensoredReplay,
            Treatment::NoGeneration,
            Treatment::Uniform,
            Treatment::Full,
        ]
    } else if repair {
        vec![
            Treatment::Previous,
            if matches!(
                phase.as_str(),
                "repair_yield" | "repair_observation" | "confirmation_models"
            ) {
                Treatment::CensoredReplay
            } else {
                Treatment::OutcomeReplay
            },
            Treatment::Full,
        ]
    } else if coupled {
        vec![Treatment::Previous, Treatment::NoUtility, Treatment::Full]
    } else {
        ARMS.to_vec()
    };
    if matches!(phase.as_str(), "repair_observation" | "confirmation_models") {
        arms.insert(2, Treatment::Uniform);
    }
    let reserved = if repair {
        let path =
            std::path::PathBuf::from(std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap());
        let bank: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        bank["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| {
                let q = CompiledQuestion::compile(case["source"].as_str().unwrap()).unwrap();
                let family = curriculum::owned::family(q.proved_target());
                assert_eq!(case["family"], family);
                assert!(!curriculum::owned::original_exclusions().contains(&family));
                family
            })
            .collect()
    } else {
        BTreeSet::new()
    };
    let seeds = if phase == "confirmation_models" {
        vec![173, 251, 389]
    } else {
        SEEDS.to_vec()
    };
    let selected_seed = std::env::var("NAOME_FINDER_NATIVE_SEED")
        .ok()
        .map(|value| value.parse::<u64>().unwrap());
    let selected_arm = std::env::var("NAOME_FINDER_NATIVE_ARM").ok();
    assert!(selected_seed.is_none_or(|seed| seeds.contains(&seed)));
    assert!(
        selected_arm
            .as_ref()
            .is_none_or(|arm| arms.iter().any(|t| label(*t) == arm))
    );
    write(
        &output.join("manifest.json"),
        &json!({"source_contract":input_specification(),"seeds":seeds,"arms":arms.iter().map(|t|label(*t)).collect::<Vec<_>>(),"rounds":rounds,"attempts_per_round":ATTEMPTS,"search_expansions_per_attempt":SEARCH,"native_learning_cpu_limit":TRAIN_CPU,"native_learning_wall_limit":TRAIN_WALL,"feedback_clock":if repair{"shared recorded costs by exact checkpoint, question and occurrence; first actual observation fills missing entries"}else{"actual elapsed generation time"},"reserved_confirmation_families":reserved.len(),"scope":"Known development acquisition and promotion only. Confirmation outcomes remain unavailable throughout training. Same source/model starts and native learning/promotion rules. Actual costs include preparation, generation, checking, replay, utility and full qualification. Equal attempt/search/job ceilings are not a claim of equal realized CPU."}),
    );
    write(
        &output.join("segment.json"),
        &json!({"seed":selected_seed,"arm":selected_arm,"scope":"Only whole independent seed/arm trials may be selected. Each starts from the same recorded common state and original complete job limits; no partial native job is resumed. Canonical arm rotation is retained. Failed attempts remain separate charged evidence."}),
    );
    let mut results = Vec::new();
    for (seed_index, seed) in seeds.into_iter().enumerate() {
        if selected_seed.is_some_and(|selected| selected != seed) {
            continue;
        }
        let seed_path = output.join(seed.to_string());
        let (mut common, blobs, initial, preparation) =
            prepare(seed, &seed_path.join("preparation"));
        let mut clock = Clock::new();
        if phase == "repair" || paired || screen {
            let reference =
                std::path::PathBuf::from(std::env::var("NAOME_FINDER_REPLAY_REFERENCE").unwrap())
                    .join(seed.to_string());
            let original: State = serde_json::from_slice(
                &std::fs::read(reference.join("initial-state.json")).unwrap(),
            )
            .unwrap();
            original.validate().unwrap();
            assert_eq!(common.model, original.model);
            assert_eq!(
                initial
                    .iter()
                    .map(|(_, s, _)| s.proof_id.clone())
                    .collect::<BTreeSet<_>>(),
                original
                    .examples()
                    .map(|e| e.proof_id.clone())
                    .collect::<BTreeSet<_>>()
            );
            common = original;
            if paired || screen {
                clock = frozen_clock(&reference.join("reference-costs.json"));
            } else {
                let original: Value = serde_json::from_slice(
                    &std::fs::read(reference.join("without_utility/result.json")).unwrap(),
                )
                .unwrap();
                clock = reference_clock(&original);
            }
        }
        write(&seed_path.join("initial-state.json"), &common);
        if repair {
            export_model(&seed_path.join("initial-model"), &common.model, &blobs);
        }
        for offset in 0..arms.len() {
            let treatment = arms[(seed_index + offset) % arms.len()];
            if selected_arm
                .as_ref()
                .is_some_and(|arm| arm != label(treatment))
            {
                continue;
            }
            let historical = paired
                && matches!(
                    treatment,
                    Treatment::Previous | Treatment::CensoredReplay | Treatment::OutcomeReplay
                );
            let feedback_reference = if paired {
                let reference = std::path::PathBuf::from(
                    std::env::var("NAOME_FINDER_FEEDBACK_REFERENCE").unwrap(),
                );
                let reference_arm = if treatment == Treatment::Previous {
                    "previous"
                } else {
                    "full"
                };
                Some(
                    serde_json::from_slice::<Value>(
                        &std::fs::read(
                            reference
                                .join(seed.to_string())
                                .join(reference_arm)
                                .join("result.json"),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            if historical {
                let reference = std::path::PathBuf::from(
                    std::env::var("NAOME_FINDER_REPLAY_REFERENCE").unwrap(),
                );
                let name = if treatment == Treatment::Previous {
                    "previous"
                } else {
                    "full"
                };
                let expected: Value = serde_json::from_slice(
                    &std::fs::read(
                        reference
                            .join(seed.to_string())
                            .join(name)
                            .join("result.json"),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_feedback_reproduced(&expected, feedback_reference.as_ref().unwrap());
            }
            let result = arm(
                seed,
                treatment,
                coupled,
                rounds,
                Start {
                    state: &common,
                    blobs: &blobs,
                    initial: &initial,
                    reserved: &reserved,
                    feedback_reference: feedback_reference.as_ref(),
                },
                &seed_path.join(label(treatment)),
                repair.then_some(&mut clock),
            );
            if historical {
                let reference = std::path::PathBuf::from(
                    std::env::var("NAOME_FINDER_REPLAY_REFERENCE").unwrap(),
                );
                let original_arm = if treatment == Treatment::Previous {
                    label(treatment)
                } else {
                    "full"
                };
                let expected: Value = serde_json::from_slice(
                    &std::fs::read(
                        reference
                            .join(seed.to_string())
                            .join(original_arm)
                            .join("result.json"),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_control_prefix_reproduced(&expected, &result);
                write(
                    &seed_path
                        .join(label(treatment))
                        .join("control-reproduced.json"),
                    &json!({"reference":reference,"arm":original_arm,"matched_rounds":expected["rounds"].as_array().unwrap().len(),"matched":"Every question, feedback cost, outcome, accepted source, finder state, native model/Adam checkpoint and reference score across the complete recorded reference horizon."}),
                );
            }
            results.push(json!({"preparation":preparation,"result":result}));
            write(&output.join("results.json"), &results);
            if repair {
                write(&seed_path.join("reference-costs.json"), &clock.iter().map(|((model,question,occurrence),micros)|json!({"model":model,"question":question,"occurrence":occurrence,"micros":micros})).collect::<Vec<_>>());
            }
        }
    }
}
