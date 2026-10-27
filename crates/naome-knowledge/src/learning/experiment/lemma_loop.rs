//! A finite, preregistered native-engine comparison with aggregate work ceilings.
//! Run explicitly; ordinary unit tests never execute this experiment.
use super::knowledge::{Store, admit_discovery};
use super::*;
use crate::frontier::evidence::Outcome;
use crate::jobs;
use serde_json::{Value, json};

const EXPANSIONS: usize = 512;
const SLICE: usize = 128;
const CPU_MICROS: u64 = 2_500_000;
const WALL_MICROS: u64 = 5_000_000;
const CHECKER_CALLS: u64 = 10_000;
const CHECKER_STEPS: u64 = 2_000_000;
const IO_BYTES: u64 = 8_000_000;
const IO_OPERATIONS: u64 = 512;

struct Meter {
    wall: Instant,
    cpu: u64,
    checking: proof::CheckingWork,
    expansions: usize,
}
impl Meter {
    fn new() -> Self {
        Self {
            wall: Instant::now(),
            cpu: meta::cpu_micros().unwrap(),
            checking: proof::checking_work(),
            expansions: 0,
        }
    }
    fn remaining(&self) -> usize {
        EXPANSIONS.saturating_sub(self.expansions)
    }
    fn within(&self, io: &Store) -> bool {
        let checking = proof::checking_work();
        self.expansions <= EXPANSIONS
            && meta::cpu_micros().unwrap().saturating_sub(self.cpu) <= CPU_MICROS
            && self.wall.elapsed().as_micros() <= u128::from(WALL_MICROS)
            && checking.calls.saturating_sub(self.checking.calls) <= CHECKER_CALLS
            && checking.steps.saturating_sub(self.checking.steps) <= CHECKER_STEPS
            && io.read_bytes + io.written_bytes <= IO_BYTES
            && io.reads + io.writes <= IO_OPERATIONS
    }
    fn receipt(&self, io: &Store) -> Value {
        let checking = proof::checking_work();
        json!({"search_expansions":self.expansions,"cpu_micros":meta::cpu_micros().unwrap().saturating_sub(self.cpu),"wall_micros":self.wall.elapsed().as_micros(),"checker_calls":checking.calls.saturating_sub(self.checking.calls),"submitted_checker_steps":checking.steps.saturating_sub(self.checking.steps),"model_read_bytes":io.read_bytes,"model_written_bytes":io.written_bytes,"model_reads":io.reads,"model_writes":io.writes,"within_budget":self.within(io)})
    }
}
struct Session<'a> {
    state: &'a State,
    engine: &'a mut Engine,
    io: &'a mut Store,
    meter: &'a mut Meter,
}
impl Session<'_> {
    fn generate(
        &mut self,
        q: &CompiledQuestion,
        cap: usize,
        job: u64,
        required: &[String],
    ) -> Generation {
        let allowance = cap.min(self.meter.remaining());
        let generated = self
            .engine
            .with(&self.state.model, self.io, |runtime| {
                solve_with_report(
                    q.source(),
                    runtime,
                    allowance,
                    job,
                    &self.state.definitions,
                    &self.state.knowledge,
                    required,
                )
            })
            .unwrap();
        self.meter.expansions += generated.cost.search_expansions;
        generated
    }
}
fn completion(job: u64, generated: &Generation) -> jobs::Completion {
    jobs::Completion {
        id: job,
        binding: jobs::Binding::new([0; 32], [0; 32]),
        spent_ms: generated.cost.generation_micros / 1000,
        reserved_units: 1,
        state: jobs::State::Complete,
        result: Ok(jobs::Output::Native {
            solution: generated.solution.clone(),
            diagnostic: generated.diagnostic.clone(),
            frontier: generated.frontier.clone(),
        }),
    }
}
fn checked(
    q: &CompiledQuestion,
    generated: &Generation,
    graph: &mut crate::Graph,
    path: &Path,
    name: &str,
) -> Option<String> {
    let solution = generated.solution.as_ref()?;
    admit_discovery(graph, q, solution).unwrap();
    std::fs::write(path.join(format!("{name}.nao")), &solution.source).unwrap();
    for (i, helper) in solution.helpers.iter().enumerate() {
        std::fs::write(path.join(format!("{name}-helper-{i}.nao")), helper).unwrap();
    }
    Some(solution.proof_id.clone())
}
fn event(q: &CompiledQuestion, generated: &Generation, role: &str) -> Value {
    json!({"role":role,"question":q.source(),"cost":generated.cost,"diagnostic":generated.diagnostic,"solution":generated.solution,"open_branches":generated.frontier})
}
fn arm(
    q: &CompiledQuestion,
    kind: &str,
    common: &State,
    common_io: &MemoryStore,
    path: &Path,
) -> Value {
    std::fs::create_dir_all(path).unwrap();
    let mut state = common.clone();
    let mut io = Store {
        inner: MemoryStore(common_io.0.clone()),
        ..Store::default()
    };
    let mut engine = Engine::default();
    let mut graph = crate::Graph::default();
    let mut meter = Meter::new();
    let mut events = Vec::new();
    let first = Session {
        state: &state,
        engine: &mut engine,
        io: &mut io,
        meter: &mut meter,
    }
    .generate(q, if kind == "direct" { EXPANSIONS } else { SLICE }, 1, &[]);
    let first_failed = first.solution.is_none();
    let mut result = checked(q, &first, &mut graph, path, "initial-goal");
    events.push(event(q, &first, "initial_goal"));
    let mut finder_owner = None;
    let mut required = Vec::new();
    let mut retry_allowance = 0;
    let mut used_helpers = Vec::new();
    if result.is_none() && meter.within(&io) && kind == "loop" {
        let settings = jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        };
        let mut finder = crate::frontier::Frontier::open(path, &graph, 41, settings).unwrap();
        finder
            .attempted(q, &graph, &completion(1, &first), Outcome::NoCandidate)
            .unwrap();
        // The production plan, prefilter, ranking, checker and retained theorem
        // owner are used here; no supplied theorem or proof teacher is present.
        let mut pending = finder.loop_work(q, &graph).unwrap().pending;
        let mut questions =
            crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
        let mut job = 10;
        while !pending.is_empty() && meter.within(&io) && meter.remaining() > 0 {
            pending.retain(|helper| questions.assess(&graph, helper).passed());
            if pending.is_empty() {
                break;
            }
            let references = pending.iter().collect::<Vec<_>>();
            let Some(index) = finder
                .choose(&references, &graph, settings.solving, false)
                .unwrap()
            else {
                break;
            };
            let helper = pending.remove(index);
            let generated = Session {
                state: &state,
                engine: &mut engine,
                io: &mut io,
                meter: &mut meter,
            }
            .generate(&helper, SLICE, job, &[]);
            let outcome = if generated.solution.is_some() {
                Outcome::Candidate
            } else {
                Outcome::NoCandidate
            };
            finder
                .attempted(&helper, &graph, &completion(job, &generated), outcome)
                .unwrap();
            if let Some(id) = checked(
                &helper,
                &generated,
                &mut graph,
                path,
                &format!("lemma-{job}"),
            ) {
                let root = crate::object::proof_address(&id).unwrap();
                finder.prepared(&helper, job, root).unwrap();
                finder.verified(&helper, &graph, job, root).unwrap();
                let entry = super::super::knowledge::Entry {
                    packet: graph.learning_certificate(root).unwrap().unwrap(),
                };
                let retained = state.remember_theorem(entry).unwrap();
                events.push(json!({"role":"retention","proof_id":id,"retained":retained}));
            }
            events.push(event(&helper, &generated, "helper"));
            job += 1;
        }
        required = finder.loop_work(q, &graph).unwrap().required;
        if state.require_theorems(&required).is_err() {
            events.push(json!({"role":"required_prerequisites_unavailable"}));
            required.clear();
        }
        finder_owner = Some(finder);
    }
    if result.is_none() && kind != "direct" && meter.within(&io) && meter.remaining() > 0 {
        retry_allowance = meter.remaining();
        let retry = Session {
            state: &state,
            engine: &mut engine,
            io: &mut io,
            meter: &mut meter,
        }
        .generate(q, retry_allowance, 100, &required);
        if let Some(finder) = &mut finder_owner {
            finder
                .attempted(
                    q,
                    &graph,
                    &completion(100, &retry),
                    if retry.solution.is_some() {
                        Outcome::Candidate
                    } else {
                        Outcome::NoCandidate
                    },
                )
                .unwrap();
        }
        result = checked(q, &retry, &mut graph, path, "retried-goal");
        if let Some(id) = &result {
            let root = crate::object::proof_address(id).unwrap();
            if let Some(finder) = &mut finder_owner {
                finder.prepared(q, 100, root).unwrap();
                finder.verified(q, &graph, 100, root).unwrap();
            }
            let dependencies = graph.direct_dependencies(root).unwrap();
            used_helpers = required
                .iter()
                .filter(|id| dependencies.contains(&crate::object::proof_address(id).unwrap()))
                .cloned()
                .collect();
        }
        events.push(event(q, &retry, "retried_goal"));
    }
    // All generation, extraction, selection, persistence and checking above is
    // charged. Late results are retained as evidence and never count as success.
    let costs = meter.receipt(&io);
    let counted = result.is_some() && meter.within(&io);
    let final_model = digest(&state.model);
    write(&path.join("events.json"), &events);
    json!({"arm":kind,"first_failed":first_failed,"counted_solution":counted,"proof_id":result,"required_lemmas":required,"used_helpers":used_helpers,"retry_allowance":retry_allowance,"cost":costs,"initial_model":digest(&common.model),"final_model":final_model,"retained_weight_updates":state.model.updates.saturating_sub(common.model.updates),"lower_training_enabled":false,"finder_support_events":finder_owner.as_ref().map(|f|f.support_updates())})
}

#[test]
#[ignore = "explicit finite matched native lemma-loop experiment"]
fn matched_closed_lemma_loop() {
    let path = std::path::PathBuf::from(
        std::env::var("NAOME_LEMMA_LOOP_OUTPUT").expect("explicit output directory"),
    );
    let inputs = std::path::PathBuf::from(
        std::env::var("NAOME_LEMMA_LOOP_INPUTS").expect("frozen question input list"),
    );
    std::fs::create_dir_all(&path).unwrap();
    let sources: Vec<String> = serde_json::from_slice(&std::fs::read(&inputs).unwrap()).unwrap();
    assert!(!sources.is_empty() && sources.len() <= 24);
    let questions = sources
        .iter()
        .map(|s| CompiledQuestion::compile(s).unwrap())
        .collect::<Vec<_>>();
    // Eligibility is part of the frozen common starting fixture for every arm.
    let gate_graph = crate::Graph::default();
    let mut gate_owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let gates = questions
        .iter()
        .map(|q| {
            let gate = gate_owner.assess(&gate_graph, q);
            json!({"passed":gate.passed(),"rule":gate.rule,"reason":format!("{:?}",gate.reason)})
        })
        .collect::<Vec<_>>();
    let mut common = State::fresh();
    common.model.seed = 41;
    let mut common_io = MemoryStore::default();
    common.model = Engine::default()
        .snapshot(&common.model, &mut common_io)
        .unwrap();
    export_model(&path.join("common-model"), &common.model, &common_io);
    let manifest = json!({"questions":questions.iter().map(|q|json!({"source":q.source(),"resolution_id":crate::hex(q.resolution_id()),"eligible":State::eligible(q.source())})).collect::<Vec<_>>(),"initial_admission_gates":gates,"model":digest(&common.model),"seed":41,"arms":["direct","restart","loop"],"aggregate_limits":{"search_expansions":EXPANSIONS,"cpu_micros":CPU_MICROS,"wall_micros":WALL_MICROS,"checker_calls":CHECKER_CALLS,"submitted_checker_steps":CHECKER_STEPS,"model_io_bytes":IO_BYTES,"model_io_operations":IO_OPERATIONS},"shared_live_resource_limits":format!("{:?}",crate::resources::active_limits()),"job_seeds":{"initial":1,"helpers_start":10,"retry":100},"first_slice":SLICE,"helper_slice":SLICE,"max_helpers":4,"stopping_rule":"one pass over all frozen questions; no case replacement or parameter search","success_criterion":"loop initial failure, both full-budget controls unsolved, checked goal within aggregate ceilings, actual generated-helper dependency and failure on helper removal at the identical retry seed and allowance","limitations":"one fresh native checkpoint and one seed; local in-process owner cycle; no learning-weight or general mathematical novelty claim"});
    write(&path.join("frozen-manifest.json"), &manifest);
    let mut rows = Vec::new();
    for (index, q) in questions.iter().enumerate() {
        let id = crate::hex(q.resolution_id());
        if !State::eligible(q.source()) {
            rows.push(json!({"id":id,"excluded":"protected dependency split"}));
            continue;
        }
        if gates[index]["passed"] != true {
            rows.push(
                json!({"id":id,"excluded":"initial formal admission","assessment":gates[index]}),
            );
            continue;
        }
        let mut results = BTreeMap::new();
        let order = ["direct", "restart", "loop"];
        for offset in 0..3 {
            let kind = order[(index + offset) % 3];
            let result = arm(q, kind, &common, &common_io, &path.join(&id).join(kind));
            results.insert(kind, result);
        }
        let candidate = &results["loop"];
        let potential = candidate["first_failed"] == true
            && candidate["counted_solution"] == true
            && results["direct"]["counted_solution"] == false
            && results["restart"]["counted_solution"] == false
            && !candidate["used_helpers"].as_array().unwrap().is_empty();
        let mut removal = Value::Null;
        if potential {
            // A separate diagnostic replay is reported outside the comparison's
            // work ledger; it cannot add a counted target solution.
            let mut io = Store {
                inner: MemoryStore(common_io.0.clone()),
                ..Store::default()
            };
            let mut meter = Meter::new();
            let retry = Session {
                state: &common,
                engine: &mut Engine::default(),
                io: &mut io,
                meter: &mut meter,
            }
            .generate(
                q,
                candidate["retry_allowance"].as_u64().unwrap() as usize,
                100,
                &[],
            );
            removal = json!({"solved":retry.solution.is_some(),"diagnostic":retry.diagnostic,"cost":meter.receipt(&io),"comparison_budget":"separate causal audit; excluded from target yield"});
        }
        let gain = potential && removal["solved"] == false;
        let row = json!({"id":id,"question":q.source(),"arms":results,"helper_removal":removal,"qualifying_gain":gain});
        eprintln!(
            "{}",
            json!({"event":"matched_lemma_loop_goal","id":id,"qualifying_gain":gain})
        );
        rows.push(row);
        write(&path.join("results.json"), &rows);
    }
    write(&path.join("results.json"), &rows);
    let eligible = rows.iter().filter(|r| r.get("arms").is_some()).count();
    let gains = rows.iter().filter(|r| r["qualifying_gain"] == true).count();
    let summary = json!({"frozen_questions":questions.len(),"eligible":eligible,"qualifying_gains":gains,"rows":rows,"claim":if gains>0 {"bounded native helper gain on the reported inputs only"} else {"no qualifying helper gain measured"}});
    write(&path.join("summary.json"), &summary);
    eprintln!(
        "{}",
        json!({"event":"matched_lemma_loop_complete","eligible":eligible,"qualifying_gains":gains})
    );
}
