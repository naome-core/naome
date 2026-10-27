//! Reproducible local comparison using the installed deterministic provider and
//! the real checker. CPU includes filtering, selection, evidence and checking;
//! a result completed after the common deadline is not counted.
use super::*;
use crate::checkpoint::tests::Directory;
use nix::sys::{
    resource::{UsageWho, getrusage},
    time::TimeValLike,
};
use serde_json::json;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

fn cpu_nanos() -> u64 {
    let usage = getrusage(UsageWho::RUSAGE_SELF).expect("read process CPU");
    (usage.user_time().num_microseconds() + usage.system_time().num_microseconds()) as u64 * 1000
}
fn pool() -> Vec<CompiledQuestion> {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let atoms = [
        Formula::equal(x, x),
        Formula::equal(x, y),
        Formula::negate(Formula::equal(x, x)),
    ];
    let mut questions = (0..2)
        .map(|i| CompiledQuestion::compile(&crate::mocks::create_question(i)).unwrap())
        .collect::<Vec<_>>();
    for left in &atoms {
        for right in &atoms {
            for predicate in [
                Formula::implies(left.clone(), right.clone()),
                Formula::conjunction(left.clone(), right.clone()),
            ] {
                let parameters = predicate
                    .free_variables()
                    .into_iter()
                    .filter(|v| *v != x)
                    .collect();
                let formula = Separation {
                    predicate,
                    element: x,
                    source: FreeVariable::new(2),
                    result: FreeVariable::new(3),
                    parameters,
                }
                .formula()
                .unwrap();
                questions.push(CompiledQuestion::from_formula(formula).unwrap());
            }
        }
    }
    let z = FreeVariable::new(2);
    let close = |variables: &[FreeVariable], mut formula: Formula| {
        for variable in variables.iter().rev() {
            formula = Formula::for_all(*variable, formula);
        }
        CompiledQuestion::from_formula(formula).unwrap()
    };
    questions.extend([
        close(&[x], Formula::member(x, x)),
        close(&[x, y], Formula::member(x, y)),
        close(
            &[x, y],
            Formula::implies(Formula::member(x, y), Formula::member(y, x)),
        ),
        close(
            &[x, y],
            Formula::implies(Formula::member(x, y), Formula::negate(Formula::equal(x, y))),
        ),
        close(
            &[x, y, z],
            Formula::implies(
                Formula::conjunction(Formula::member(x, y), Formula::member(y, z)),
                Formula::member(x, z),
            ),
        ),
        close(&[x], Formula::exists(y, Formula::member(x, y))),
        CompiledQuestion::from_formula(Formula::exists(
            x,
            Formula::for_all(y, Formula::member(y, x)),
        ))
        .unwrap(),
        close(
            &[x, y],
            Formula::implies(Formula::equal(x, y), Formula::member(x, y)),
        ),
    ]);
    let mut seen = BTreeSet::new();
    questions.retain(|q| seen.insert(*q.resolution_id()));
    questions
}
fn held_out() -> Vec<CompiledQuestion> {
    let x = FreeVariable::new(0);
    let y = FreeVariable::new(1);
    let mut questions = vec![CompiledQuestion::compile(&crate::mocks::create_question(2)).unwrap()];
    for predicate in [
        Formula::member(x, y),
        Formula::implies(Formula::member(x, x), Formula::member(y, x)),
        Formula::negate(Formula::member(y, x)),
    ] {
        let formula = Separation {
            parameters: vec![y],
            predicate,
            element: x,
            source: FreeVariable::new(2),
            result: FreeVariable::new(3),
        }
        .formula()
        .unwrap();
        questions.push(CompiledQuestion::from_formula(formula).unwrap());
    }
    questions
}
#[derive(Default, Serialize)]
struct Metrics {
    new_verified_solutions: usize,
    verified_families: usize,
    explored_families: usize,
    verified_structural_signals: usize,
    completed_attempts: u64,
    unsuccessful_attempts: u64,
    solver_work_units: u64,
    completed_cpu_nanos: u64,
    actual_cpu_nanos: u64,
    selection_cpu_nanos: u64,
    wall_nanos: u64,
    held_out_solved: usize,
    held_out_total: usize,
}
fn arm(seed: u64, random_only: bool, budget: u64) -> Metrics {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let mut frontier =
        Frontier::open(&directory.0, &graph, seed, jobs::RoleSettings::default()).unwrap();
    let mut questions =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let pool = pool();
    let held_out = held_out();
    assert!(
        held_out
            .iter()
            .all(|a| pool.iter().all(|b| a.resolution_id() != b.resolution_id()))
    );
    let mut metrics = Metrics::default();
    let mut solutions = BTreeSet::new();
    let mut verified_families = BTreeSet::new();
    let mut explored_families = BTreeSet::new();
    let mut verified_signals = [false; SIGNALS];
    let mut attempts = 0;
    let mut unsuccessful = 0;
    let mut selection_cpu = 0;
    let wall = Instant::now();
    let start = cpu_nanos();
    while cpu_nanos().saturating_sub(start) < budget {
        frontier.refresh(&graph).unwrap();
        let candidates = pool
            .iter()
            .filter(|question| questions.assess(&graph, question).passed())
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            break;
        }
        let selection_start = cpu_nanos();
        let index = frontier
            .choose(
                &candidates,
                &graph,
                jobs::RoleSettings::default(),
                random_only,
            )
            .unwrap()
            .unwrap();
        selection_cpu += cpu_nanos().saturating_sub(selection_start);
        let target = candidates[index];
        let features = Features::of(target);
        attempts += 1;
        explored_families.insert(features.family);
        let output = crate::mocks::create_proof(target)
            .map(|source| jobs::Output::Proof {
                source,
                helpers: vec![],
            })
            .unwrap_or(jobs::Output::NoCandidate);
        let completion = jobs::Completion {
            id: attempts,
            binding: jobs::Binding::new([1; 32], [2; 32]),
            spent_ms: 0,
            reserved_units: 1,
            state: jobs::State::Complete,
            result: Ok(output.clone()),
        };
        let outcome = if matches!(output, jobs::Output::NoCandidate) {
            Outcome::NoCandidate
        } else {
            Outcome::Candidate
        };
        frontier
            .attempted(target, &graph, &completion, outcome)
            .unwrap();
        if let jobs::Output::Proof { source, helpers } = output {
            let (root, batch) = graph.prepare_generated(&source, &helpers, target).unwrap();
            frontier.prepared(target, attempts, root).unwrap();
            graph
                .commit_batch(root, batch, Instant::now() + Duration::from_secs(30))
                .unwrap();
            frontier.verified(target, &graph, attempts, root).unwrap();
            solutions.insert(*target.resolution_id());
            verified_families.insert(features.family);
            for (present, count) in verified_signals.iter_mut().zip(features.counts) {
                *present |= count > 0;
            }
        } else {
            unsuccessful += 1;
        }
        let elapsed = cpu_nanos().saturating_sub(start);
        if elapsed <= budget {
            metrics.new_verified_solutions = solutions.len();
            metrics.verified_families = verified_families.len();
            metrics.explored_families = explored_families.len();
            metrics.verified_structural_signals = verified_signals.iter().filter(|v| **v).count();
            metrics.completed_attempts = attempts;
            metrics.unsuccessful_attempts = unsuccessful;
            metrics.solver_work_units = attempts;
            metrics.completed_cpu_nanos = elapsed;
            metrics.selection_cpu_nanos = selection_cpu;
        }
    }
    metrics.actual_cpu_nanos = cpu_nanos().saturating_sub(start);
    metrics.wall_nanos = wall.elapsed().as_nanos() as u64;
    // The selector does not train or alter the provider. This is a separate
    // held-out membership-predicate Separation family, with the same fixed solving cap.
    metrics.held_out_total = held_out.len();
    for target in held_out {
        if let Some(source) = crate::mocks::create_proof(&target) {
            let _ = graph.prepare_generated(&source, &[], &target).unwrap();
            metrics.held_out_solved += 1;
        }
    }
    metrics
}

#[test]
#[ignore = "explicit CPU-budget comparison; run alone with --test-threads=1"]
fn equal_cpu_budget_against_uniform_random() {
    let budget_ms = std::env::var("NAOME_FRONTIER_BUDGET_MS")
        .ok()
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(100);
    let seeds = std::env::var("NAOME_FRONTIER_SEEDS")
        .ok()
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(32);
    assert!(budget_ms > 0 && budget_ms <= 10_000 && seeds > 0 && seeds <= 256);
    let mut trials = Vec::new();
    for seed in 1..=seeds {
        // Alternate order to avoid assigning all warm-cache runs to one arm.
        let (structural, random) = if seed % 2 == 0 {
            let random = arm(seed, true, budget_ms * 1_000_000);
            (arm(seed, false, budget_ms * 1_000_000), random)
        } else {
            let structural = arm(seed, false, budget_ms * 1_000_000);
            (structural, arm(seed, true, budget_ms * 1_000_000))
        };
        assert!(structural.completed_cpu_nanos <= budget_ms * 1_000_000);
        assert!(random.completed_cpu_nanos <= budget_ms * 1_000_000);
        assert_eq!(structural.held_out_solved, random.held_out_solved);
        trials.push(json!({"seed": seed, "structural": structural, "random": random}));
    }
    let report = json!({"source": std::env::var("NAOME_FRONTIER_SOURCE_SHA256").ok(),
        "provider": "naome-deterministic-mocks-v1", "checker": crate::object::CHECKER_ID,
        "budget_cpu_ms_per_arm": budget_ms, "candidate_targets": pool().iter().map(|q| crate::hex(q.resolution_id())).collect::<Vec<_>>(),
        "held_out_targets": held_out().iter().map(|q| crate::hex(q.resolution_id())).collect::<Vec<_>>(),
        "baseline": "uniform random over the same formally eligible targets; confirmed duplicates excluded in both arms",
        "completion_rule": "include only outcomes fully checked and recorded by the common CPU deadline; actual CPU includes the last bounded overrun",
        "limits": "local deterministic-provider fixtures, no learned selector, no solver training, no claim about general mathematical performance",
        "trials": trials});
    if let Ok(path) = std::env::var("NAOME_FRONTIER_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!("FRONTIER_COMPARISON {}", report);
}

#[test]
fn comparison_has_eligible_structural_breadth_and_disjoint_held_out_targets() {
    let graph = Graph::default();
    let mut questions =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let pool = pool();
    let families = pool
        .iter()
        .filter(|target| questions.assess(&graph, target).passed())
        .map(|target| Features::of(target).family)
        .collect::<BTreeSet<_>>();
    assert!(
        families.len() >= 4,
        "the experiment needs distinct eligible structures"
    );
    assert!(
        held_out()
            .iter()
            .all(|a| pool.iter().all(|b| a.resolution_id() != b.resolution_id()))
    );
}
