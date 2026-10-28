use super::*;
use crate::{frontier::evidence::Outcome, jobs};
pub(super) const ARMS: [&str; 5] = [
    "direct",
    "restart",
    "multi_restart",
    "flat_loop",
    "recursive_loop",
];
struct Session<'a> {
    state: &'a State,
    engine: &'a mut Engine,
    io: &'a mut Store,
    meter: &'a mut Meter,
    graph: Option<&'a crate::Graph>,
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
        let full = self.graph.and_then(|g| g.prerequisites(required).unwrap());
        if let Some(full) = &full {
            let bytes = serde_json::to_vec(full).unwrap().len();
            if !full.is_empty() {
                self.io.read_bytes += bytes as u64;
                self.io.reads += 1;
            }
        }
        let generated = self
            .engine
            .with(&self.state.model, self.io, |runtime| {
                solve_with_report(
                    q.source(),
                    runtime,
                    allowance,
                    job,
                    SolveContext {
                        definitions: &self.state.definitions,
                        theorems: &self.state.knowledge,
                        required,
                        prerequisites: full.as_ref(),
                    },
                )
            })
            .unwrap();
        self.meter.charge(generated.cost.search_expansions);
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
fn event(
    q: &CompiledQuestion,
    generated: &Generation,
    role: &str,
    job: u64,
    required: &[String],
) -> Value {
    json!({"role":role,"job_seed":job,"question":q.source(),"required":required,"cost":generated.cost,"diagnostic":generated.diagnostic,"solution":generated.solution,"open_branches":generated.frontier})
}
fn outcome(generated: &Generation) -> Outcome {
    if generated.solution.is_some() {
        Outcome::Candidate
    } else {
        Outcome::NoCandidate
    }
}
pub(super) fn arm(
    q: &CompiledQuestion,
    kind: &str,
    seed: u64,
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
        graph: (kind == "recursive_loop").then_some(&graph),
    }
    .generate(q, if kind == "direct" { EXPANSIONS } else { SLICE }, 1, &[]);
    let first_failed = first.solution.is_none();
    let mut result = checked(q, &first, &mut graph, path, "initial-goal");
    events.push(event(q, &first, "initial_goal", 1, &[]));
    let mut finder_owner = None;
    let mut required = Vec::new();
    let mut acquired = Vec::new();
    let mut retry_allowance = 0;
    let mut audit_debit = Value::Null;
    if result.is_none()
        && meter.within(&io)
        && matches!(kind, "flat_loop" | "recursive_loop" | "recursive_control")
    {
        let settings = jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        };
        let mut finder = crate::frontier::Frontier::open(path, &graph, seed, settings).unwrap();
        finder
            .attempted(q, &graph, &completion(1, &first), Outcome::NoCandidate)
            .unwrap();
        let mut questions =
            crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
        let mut job = 10;
        let mut declined = BTreeSet::new();
        loop {
            if !meter.within(&io) || meter.remaining() == 0 {
                break;
            }
            let mut available = |helper: &CompiledQuestion| {
                let gate = questions.assess(&graph, helper);
                if !gate.passed() && declined.insert(*helper.resolution_id()) {
                    events.push(json!({"role":"helper_intake_unavailable","question":helper.source(),"rule":gate.rule,"reason":format!("{:?}",gate.reason),"has_answer":gate.has_answer()}));
                }
                gate.passed()
            };
            let work = if kind == "flat_loop" {
                finder.flat_loop_work(q, &graph)
            } else if kind == "recursive_control" {
                finder.previous_loop_work(q, &graph, &mut available)
            } else {
                finder.loop_work(q, &graph, &mut available)
            }
            .unwrap();
            let pending = work
                .pending
                .iter()
                .filter(|helper| available(helper))
                .collect::<Vec<_>>();
            if pending.is_empty() {
                required = work.required;
                break;
            }
            let Some(index) = finder
                .choose(&pending, &graph, settings.solving, false)
                .unwrap()
            else {
                break;
            };
            let helper = (*pending[index]).clone();
            let needed = if helper.resolution_id() == work.target.resolution_id() {
                work.required
            } else {
                vec![]
            };
            let offered = if kind == "recursive_loop" {
                graph
                    .prerequisites(&needed)
                    .unwrap()
                    .unwrap_or_default()
                    .require(&state, &needed)
            } else {
                state.require_theorems(&needed)
            };
            if offered.is_err() {
                finder.exhaust_helpers(&helper).unwrap();
                events.push(json!({"role":"required_prerequisites_unavailable","question":helper.source(),"required":needed}));
                continue;
            }
            let generated = Session {
                state: &state,
                engine: &mut engine,
                io: &mut io,
                meter: &mut meter,
                graph: (kind == "recursive_loop").then_some(&graph),
            }
            .generate(&helper, SLICE, job, &needed);
            finder
                .attempted(
                    &helper,
                    &graph,
                    &completion(job, &generated),
                    outcome(&generated),
                )
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
                let retained = if let Some(packet) = graph.learning_certificate(root).unwrap() {
                    state
                        .remember_theorem(super::super::super::knowledge::Entry { packet })
                        .unwrap()
                } else {
                    // A checked graph artifact need not fit the bounded neural
                    // view. Preserve its proof and cost without enlarging it.
                    false
                };
                events.push(json!({"role":"retention","proof_id":id,"retained":retained}));
                acquired.push(id);
            }
            let role = if helper.resolution_id() == work.target.resolution_id() {
                "parent_retry"
            } else if work.target.resolution_id() != q.resolution_id() {
                "descendant"
            } else {
                "helper"
            };
            events.push(event(&helper, &generated, role, job, &needed));
            job += 1;
            assert!(
                job <= 16,
                "a four-member depth-two plan has at most six helper attempts"
            );
        }
        let offered = if kind == "recursive_loop" {
            graph
                .prerequisites(&required)
                .unwrap()
                .unwrap_or_default()
                .require(&state, &required)
        } else {
            state.require_theorems(&required)
        };
        if offered.is_err() {
            events.push(json!({"role":"required_prerequisites_unavailable","required":required}));
            if kind != "recursive_loop" {
                required.clear();
            }
        }
        finder_owner = Some(finder);
    }
    let retry_seeds: &[u64] = if kind == "multi_restart" {
        &[100, 101, 102]
    } else if kind == "direct" {
        &[]
    } else {
        &[100]
    };
    for &job in retry_seeds {
        if result.is_some() || !meter.within(&io) || meter.remaining() == 0 {
            break;
        }
        retry_allowance = if kind == "multi_restart" {
            SLICE.min(meter.remaining())
        } else {
            meter.remaining()
        };
        audit_debit = meter.receipt(&io);
        let retry = Session {
            state: &state,
            engine: &mut engine,
            io: &mut io,
            meter: &mut meter,
            graph: (kind == "recursive_loop").then_some(&graph),
        }
        .generate(q, retry_allowance, job, &required);
        if let Some(finder) = &mut finder_owner {
            finder
                .attempted(q, &graph, &completion(job, &retry), outcome(&retry))
                .unwrap();
        }
        result = checked(q, &retry, &mut graph, path, &format!("retried-goal-{job}"));
        if let (Some(finder), Some(id)) = (&mut finder_owner, &result) {
            let root = crate::object::proof_address(id).unwrap();
            finder.prepared(q, job, root).unwrap();
            finder.verified(q, &graph, job, root).unwrap();
        }
        events.push(event(q, &retry, "retried_goal", job, &required));
    }
    let used_helpers = if let Some(id) = &result {
        let dependencies = graph
            .direct_dependencies(crate::object::proof_address(id).unwrap())
            .unwrap();
        acquired
            .iter()
            .filter(|id| dependencies.contains(&crate::object::proof_address(id).unwrap()))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        vec![]
    };
    let final_model = digest(&state.model);
    let costs = meter.receipt(&io);
    let counted = result.is_some() && costs["within_budget"] == true;
    write(&path.join("events.json"), &events);
    json!({"arm":kind,"first_failed":first_failed,"counted_solution":counted,"proof_id":result,"required_lemmas":required,"acquired_helpers":acquired,"used_helpers":used_helpers,"retry_allowance":retry_allowance,"audit_debit":audit_debit,"cost":costs,"initial_model":digest(&common.model),"final_model":final_model,"retained_weight_updates":state.model.updates.saturating_sub(common.model.updates),"lower_training_enabled":false,"finder_support_events":finder_owner.as_ref().map(|f|f.support_updates())})
}
pub(super) fn removal(
    q: &CompiledQuestion,
    candidate: &Value,
    common: &State,
    common_io: &MemoryStore,
    path: &Path,
) -> Value {
    std::fs::create_dir_all(path).unwrap();
    // Every model/snapshot/Graph/cache is fresh from before helper acquisition.
    // All previous attempt and helper costs remain charged in this counterfactual.
    let mut io = Store {
        inner: MemoryStore(common_io.0.clone()),
        ..Store::default()
    };
    let mut graph = crate::Graph::default();
    let mut engine = Engine::default();
    let audit_cpu = meta::cpu_micros().unwrap();
    let audit_wall = Instant::now();
    // The charged prefix already paid for loading this same frozen model.
    // Recreate that warm model cache without double-charging its read bytes;
    // no question or theorem is supplied during this diagnostic preparation.
    engine.with(&common.model, &mut io, |_| Ok(())).unwrap();
    let preparation = json!({"model_read_bytes":io.read_bytes,"cpu_micros":meta::cpu_micros().unwrap().saturating_sub(audit_cpu),"wall_micros":audit_wall.elapsed().as_micros()});
    io.read_bytes = 0;
    io.written_bytes = 0;
    io.reads = 0;
    io.writes = 0;
    let mut meter = Meter::debited(candidate["audit_debit"].clone());
    let retry = Session {
        state: common,
        engine: &mut engine,
        io: &mut io,
        meter: &mut meter,
        graph: None,
    }
    .generate(
        q,
        candidate["retry_allowance"].as_u64().unwrap() as usize,
        100,
        &[],
    );
    let proof = checked(q, &retry, &mut graph, path, "without-helpers");
    let costs = meter.receipt(&io);
    let counted = proof.is_some() && costs["within_budget"] == true;
    write(
        &path.join("events.json"),
        &vec![event(q, &retry, "helper_removal", 100, &[])],
    );
    json!({"counted_solution":counted,"proof_id":proof,"diagnostic":retry.diagnostic,"charged_prefix":candidate["audit_debit"],"cost":costs,"diagnostic_preparation":preparation,"actual_audit_cpu_micros":meta::cpu_micros().unwrap().saturating_sub(audit_cpu),"actual_audit_wall_micros":audit_wall.elapsed().as_micros(),"comparison_budget":"Separate diagnostic execution; original prefix costs virtually charged; cannot add a target solution"})
}
