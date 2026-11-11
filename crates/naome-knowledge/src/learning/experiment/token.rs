//! Paired qualification of a single typed token policy in both native searches.
use super::*;
use crate::learning::model::{Decision, Memory, Plan, Ranker};
use crate::learning::search::scope::generation;
use naome_foundation::{Formula, FreeVariable};
use serde_json::json;

mod policy;
use policy::Policy;

const SEED: u64 = 0x0054_4f4b_454e;
const TRAIN_QUESTIONS: usize = 48;
const TRAIN_UNITS: u64 = 4;
const TRAIN_BUDGET: usize = 64;
const GENERAL_BUDGET: usize = 128;

/// Both arms use the installed symbolic ordering and the same deterministic
/// search configuration. The token policy supplies all learned scores in its arm.
struct Focused<'a> {
    model: &'a mut dyn Ranker,
    calls: usize,
}

impl Ranker for Focused<'_> {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, crate::Error> {
        self.calls += 1;
        self.model.scores(decision)
    }

    fn plan(
        &mut self,
        decision: &Decision,
        graph: &graph::Graph,
        offered: &str,
        memory: Option<&Memory>,
    ) -> Result<Plan, crate::Error> {
        self.calls += 1;
        let mut plan = self.model.plan(decision, graph, offered, memory)?;
        search::focus::rank(decision, &mut plan.scores);
        Ok(plan)
    }

    fn identity(&self) -> Option<String> {
        self.model.identity()
    }
}

fn solve(
    question: &ResearchQuestion,
    policy: &mut dyn Ranker,
    budget: usize,
    context: SolveContext<'_>,
) -> Result<(Generation, usize), crate::Error> {
    let started = Instant::now();
    let (candidate, typed) = generation::attempt(
        question.proved_target(),
        policy,
        budget,
        started,
        &context,
        None,
    )?;
    let typed_generation = (typed.actions != 0 || typed.model_decisions != 0).then_some(typed);
    if let Some(candidate) = candidate {
        let result = program_generation(
            candidate.packet,
            candidate.helpers,
            question.proved_target(),
            false,
            GenerationCost {
                search_expansions: typed.actions,
                typed_generation,
                ..Default::default()
            },
            Vec::new(),
        )?;
        return Ok((result, 0));
    }
    let mut focused = Focused {
        model: policy,
        calls: 0,
    };
    let mut result = search_compiled_question(
        question,
        &mut focused,
        budget.saturating_sub(typed.actions),
        &context,
        Some(started),
    )?;
    result.cost.search_expansions += typed.actions;
    result.cost.typed_generation = typed_generation;
    Ok((result, focused.calls))
}

fn transport(width: u32, chain: bool, equality: bool) -> ResearchQuestion {
    let [x, s, t, u] = [20, 21, 22, 23].map(FreeVariable::new);
    let before = |a| Formula::member(a, s);
    let middle = |a| Formula::member(a, t);
    let after = |a| {
        if equality {
            Formula::equal(a, u)
        } else {
            Formula::member(a, u)
        }
    };
    let first = if chain { middle(x) } else { after(x) };
    let mut premises = vec![Formula::for_all(x, Formula::implies(before(x), first))];
    if chain {
        premises.push(Formula::for_all(x, Formula::implies(middle(x), after(x))));
    }
    let pairs = (0..width)
        .map(FreeVariable::new)
        .map(|a| {
            premises.push(before(a));
            Formula::conjunction(after(a), before(a))
        })
        .collect::<Vec<_>>();
    let goal = pairs.into_iter().reduce(Formula::conjunction).unwrap();
    let target = premises
        .into_iter()
        .rev()
        .fold(goal, |body, premise| Formula::implies(premise, body));
    ResearchQuestion::from_formula(proof::close(target)).unwrap()
}

fn training_pool(engine: &mut Engine, io: &mut MemoryStore, initial: &Checkpoint) -> pool::Pool {
    let mut state = State::fresh();
    let mut evidence = Vec::new();
    let demonstrations = [transport(2, false, false), transport(3, false, false)];
    let mut questions: Vec<_> = demonstrations
        .iter()
        .map(ResearchQuestion::to_hex)
        .collect();
    questions.extend(
        shuffled_learning(SEED)
            .into_iter()
            .take(TRAIN_QUESTIONS)
            .map(|case| case.source.clone()),
    );
    for (index, source) in questions.iter().enumerate() {
        let question = ResearchQuestion::from_hex(source).unwrap();
        assert!(!curriculum::reserved(&crate::hex(question.resolution_id())));
        let job = index as u64 + 1;
        let result = engine
            .with_error(initial, io, |runtime| {
                solve_with_report_typed(
                    source,
                    runtime,
                    TRAIN_BUDGET,
                    job,
                    SolveContext {
                        native_programs: true,
                        ..Default::default()
                    },
                )
            })
            .unwrap();
        if let Some(solution) = result.solution {
            verify(&question, &solution);
            if state
                .accept(Example {
                    origin: Origin::Local,
                    job,
                    question: source.clone(),
                    proof_id: solution.proof_id.clone(),
                    refuted: solution.refuted,
                    tree: solution.tree.clone(),
                })
                .unwrap()
            {
                evidence.push(Evidence {
                    job,
                    proof_id: solution.proof_id,
                    trace: solution.tree,
                });
            }
        }
    }
    let pool = state.training_pool(&evidence).unwrap();
    assert!(!pool.is_empty());
    println!(
        "TOKEN_TRAIN_SET {}",
        json!({
            "questions": questions.len(), "checked_examples": evidence.len(), "decisions": pool.graphs().len(),
            "schedule": digest(&questions), "pool": digest(&pool.graphs()),
        })
    );
    pool
}

fn verify(question: &ResearchQuestion, solution: &Solution) {
    std::thread::scope(|scope| {
        scope
            .spawn(|| solution.check_target(question))
            .join()
            .unwrap()
    })
    .unwrap();
}

struct Case {
    group: &'static str,
    question: ResearchQuestion,
    budget: usize,
}

fn cases() -> Vec<Case> {
    let mut cases: Vec<_> = curriculum::development()
        .into_iter()
        .map(|case| Case {
            group: "protected",
            question: ResearchQuestion::from_hex(&case.source).unwrap(),
            budget: usize::from(transfer::ALLOWANCE),
        })
        .collect();
    assert_eq!(cases.len(), curriculum::DEVELOPMENT);
    let mut families = BTreeMap::new();
    for case in curriculum::CORPUS
        .cases
        .iter()
        .filter(|case| case.development)
    {
        let lowest = families.entry(&case.family).or_insert(case);
        if case.id < lowest.id {
            *lowest = case;
        }
    }
    cases.extend(families.values().map(|case| Case {
        group: "corpus",
        question: ResearchQuestion::from_hex(&case.source).unwrap(),
        budget: GENERAL_BUDGET,
    }));
    for (width, chain, equality) in [
        (2, false, true),
        (3, false, true),
        (2, true, false),
        (2, true, true),
        (3, true, true),
    ] {
        cases.push(Case {
            group: "typed",
            question: transport(width, chain, equality),
            budget: 8,
        });
    }
    cases
}

#[derive(Clone, Copy)]
enum Arm {
    GraphInitial,
    GraphTrained,
    Token,
}
impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::GraphInitial => "graph_initial",
            Self::GraphTrained => "graph_trained",
            Self::Token => "token_trained",
        }
    }
}

#[derive(Serialize)]
struct Measurement {
    outcome: &'static str,
    proof: Option<String>,
    expansions: usize,
    typed_calls: usize,
    typed_actions: usize,
    search_calls: usize,
    cpu_us: u64,
    wall_us: u64,
}

fn measure(case: &Case, ranker: &mut dyn Ranker) -> Result<Measurement, crate::Error> {
    let start = Instant::now();
    let cpu = meta::cpu_micros()?;
    let (result, search_calls) = solve(
        &case.question,
        ranker,
        case.budget,
        SolveContext {
            native_programs: true,
            ..Default::default()
        },
    )?;
    let cpu_us = meta::cpu_micros()?.saturating_sub(cpu);
    let wall_us = start.elapsed().as_micros() as u64;
    assert!(result.cost.search_expansions <= case.budget);
    let mut outcome = "open";
    let mut proof = None;
    if let Some(solution) = result.solution {
        verify(&case.question, &solution);
        outcome = if solution.refuted {
            "refuted"
        } else {
            "proved"
        };
        proof = Some(solution.proof_id);
    }
    let typed = result.cost.typed_generation.unwrap_or_default();
    Ok(Measurement {
        outcome,
        proof,
        expansions: result.cost.search_expansions,
        typed_calls: typed.model_decisions,
        typed_actions: typed.actions,
        search_calls,
        cpu_us,
        wall_us,
    })
}

/// The full protected corpus is always evaluated at the qualification allowance.
/// Each completed pair independently checks every proof and refutation.
#[test]
#[ignore = "explicit matched token-policy qualification over the complete protected corpus"]
fn paired_typed_token_policy() {
    let mut engine = Engine::default();
    let mut io = MemoryStore::default();
    let initial = Checkpoint::fresh();
    let pool = training_pool(&mut engine, &mut io, &initial);
    let mut trained = initial.clone();
    let mut token = Policy::default();
    let mut graph_draw = SEED;
    let mut token_draw = graph_draw;
    let graph_cpu = meta::cpu_micros().unwrap();
    for _ in 0..TRAIN_UNITS {
        trained = engine
            .train(&trained, &pool, &mut graph_draw, &mut io)
            .unwrap()
            .0;
    }
    let graph_cpu = meta::cpu_micros().unwrap() - graph_cpu;
    let token_cpu = meta::cpu_micros().unwrap();
    let mut losses = Vec::new();
    for _ in 0..TRAIN_UNITS * model::UPDATES_PER_UNIT {
        let sample = pool.sequence_batch(&mut token_draw);
        let batch = sample.iter().map(|entry| entry.graph).collect::<Vec<_>>();
        losses.push(token.update(&batch).unwrap());
    }
    assert_eq!(graph_draw, token_draw);
    println!(
        "TOKEN_TRAIN_DONE {}",
        json!({
            "updates_per_model": trained.updates, "graph_cpu_us": graph_cpu,
            "token_cpu_us": meta::cpu_micros().unwrap() - token_cpu,
            "token_first_loss": losses.first(), "token_last_loss": losses.last(),
        })
    );
    let cases = cases();
    let mut typed_calls = 0;
    let mut search_calls = 0;
    let mut protected_losses = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let mut arms = [Arm::GraphInitial, Arm::GraphTrained, Arm::Token];
        arms.rotate_left(index % 3);
        let mut graph_solved = false;
        let mut token_solved = false;
        let id = crate::hex(case.question.resolution_id());
        for arm in arms {
            let result =
                std::thread::scope(|scope| {
                    scope
                        .spawn(|| match arm {
                            Arm::GraphInitial => engine
                                .with_error(&initial, &mut io, |runtime| measure(case, runtime)),
                            Arm::GraphTrained => engine
                                .with_error(&trained, &mut io, |runtime| measure(case, runtime)),
                            Arm::Token => measure(case, &mut token),
                        })
                        .join()
                        .unwrap()
                })
                .unwrap();
            if matches!(arm, Arm::Token) {
                token_solved = result.proof.is_some();
                typed_calls += result.typed_calls;
                search_calls += result.search_calls;
            } else {
                graph_solved |= result.proof.is_some();
            }
            println!(
                "TOKEN_PAIR {}",
                json!({
                    "group": case.group, "id": id, "budget": case.budget, "arm": arm.name(), "result": result,
                })
            );
        }
        if case.group == "protected" && graph_solved && !token_solved {
            protected_losses.push(id);
        }
    }
    assert!(typed_calls > 0 && search_calls > 0);
    assert!(token.calls >= typed_calls + search_calls);
    println!(
        "TOKEN_DONE {}",
        json!({
            "cases": cases.len(), "typed_calls": typed_calls, "search_calls": search_calls,
            "protected_losses": protected_losses,
        })
    );
}
