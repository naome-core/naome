use super::*;
use crate::learning::{
    Exploring, construction, curriculum, meta::cpu_micros, model, peer::Packet, pool, proof,
    tests::MemoryStore,
};
use naome_checker::question::ResearchQuestion;
use serde_json::json;

const STRATEGIES: [Strategy; 2] = [Strategy::BestFirst, Strategy::Htps];

struct Ordered;
impl Ranker for Ordered {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, crate::Error> {
        Ok((0..decision.candidates.len())
            .map(|i| -(i as f32))
            .collect())
    }
}

fn with_assumptions(mut goal: Formula, assumptions: Vec<Formula>) -> Formula {
    for assumption in assumptions.into_iter().rev() {
        goal = Formula::implies(assumption, goal);
    }
    for variable in goal.free_variables().into_iter().rev() {
        goal = Formula::for_all(variable, goal);
    }
    goal
}

fn disjunctive_case(complete: bool) -> Formula {
    let [a, b, c] = [0, 1, 2].map(FreeVariable::new);
    let left = Formula::member(a, b);
    let right = Formula::member(b, a);
    let goal = Formula::member(c, a);
    let mut assumptions = vec![
        Formula::disjunction(left.clone(), right.clone()),
        Formula::implies(left, goal.clone()),
    ];
    if complete {
        assumptions.push(Formula::implies(right, goal.clone()));
    }
    with_assumptions(goal, assumptions)
}

fn has_split(tree: &Tree) -> bool {
    match tree {
        Tree::Step { children, .. } => children.len() > 1 || children.iter().any(has_split),
        _ => false,
    }
}

#[test]
fn planner_requires_every_branch_and_replays_the_chosen_typed_actions() {
    for strategy in STRATEGIES {
        let target = disjunctive_case(true);
        let planned = solve(
            &target,
            &mut Ordered,
            192,
            SearchClock::wall(Instant::now()),
            &[],
            strategy,
        )
        .unwrap();
        let tree = planned.tree.unwrap();
        assert!(has_split(&tree));
        let (_, _, proof) = core::checked(&target, &tree).unwrap();
        assert_eq!(proof.target, target);

        let incomplete = disjunctive_case(false);
        let attempted = solve(
            &incomplete,
            &mut Ordered,
            192,
            SearchClock::wall(Instant::now()),
            &[],
            strategy,
        )
        .unwrap();
        assert!(attempted.tree.is_none());
    }
}

#[test]
fn planner_stops_before_offering_an_action_at_the_cpu_deadline() {
    let target = disjunctive_case(true);
    let clock = SearchClock {
        started: Instant::now(),
        cpu_deadline: Some(0),
    };
    for strategy in STRATEGIES {
        let result = solve(&target, &mut Ordered, 16, clock, &[], strategy).unwrap();
        assert_eq!(result.expansions, 0);
        assert!(result.tree.is_none());
    }
}

#[derive(Clone, Copy)]
enum Arm {
    Recursive,
    Planner(Strategy),
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Recursive => "recursive",
            Self::Planner(Strategy::BestFirst) => "best_first",
            Self::Planner(Strategy::Htps) => "htps",
        }
    }
}

fn atoms(mut rng: u64) -> Vec<Formula> {
    let variables = [0, 1, 2, 3, 4].map(FreeVariable::new);
    let mut atoms = variables
        .into_iter()
        .flat_map(|a| {
            variables
                .into_iter()
                .filter(move |&b| a != b)
                .map(move |b| Formula::member(a, b))
        })
        .collect::<Vec<_>>();
    for i in (1..atoms.len()).rev() {
        atoms.swap(i, model::random(&mut rng) as usize % (i + 1));
    }
    atoms
}

fn edge(atoms: &[Formula], a: usize, b: usize) -> Formula {
    Formula::implies(atoms[a].clone(), atoms[b].clone())
}

fn generated(family: usize, seed: usize) -> Formula {
    let atoms = atoms(1087 + 51 * family as u64 + seed as u64);
    let mut assumptions = Vec::new();
    let target = match family {
        0 => {
            let end = 5 + seed % 4;
            assumptions.push(atoms[0].clone());
            assumptions.extend((0..end).map(|i| edge(&atoms, i, i + 1)));
            atoms[end].clone()
        }
        1 => {
            // Both independently reachable conclusions are required.
            let length = 4 + seed % 3;
            assumptions.extend([atoms[0].clone(), atoms[6].clone()]);
            assumptions.extend((0..length).map(|i| edge(&atoms, i, i + 1)));
            assumptions.extend((6..6 + length).map(|i| edge(&atoms, i, i + 1)));
            Formula::conjunction(atoms[length].clone(), atoms[6 + length].clone())
        }
        2 => {
            // A complete proof needs separate cases, with a shared suffix.
            assumptions.push(Formula::disjunction(atoms[0].clone(), atoms[4].clone()));
            for i in [0, 1, 2, 4, 5, 6] {
                assumptions.push(edge(&atoms, i, i + 1));
            }
            assumptions.extend([edge(&atoms, 3, 8), edge(&atoms, 7, 8), edge(&atoms, 8, 9)]);
            atoms[9].clone()
        }
        _ => {
            // Two levels of case splits must establish the same conclusion.
            assumptions.push(Formula::disjunction(
                Formula::disjunction(atoms[0].clone(), atoms[4].clone()),
                atoms[8].clone(),
            ));
            for start in [0, 4, 8] {
                for offset in 0..2 + seed % 2 {
                    assumptions.push(edge(&atoms, start + offset, start + offset + 1));
                }
                assumptions.push(edge(&atoms, start + 2 + seed % 2, 12));
            }
            atoms[12].clone()
        }
    };
    for offset in 0..3 {
        assumptions.push(edge(&atoms, (seed + offset) % 8, 15 + offset));
    }
    let rotate = seed % assumptions.len();
    assumptions.rotate_left(rotate);
    with_assumptions(target, assumptions)
}

fn benchmark_cases() -> Vec<(String, Formula)> {
    let mut cases = Vec::new();
    for (family, label) in ["chain", "conjunction", "cases", "nested_cases"]
        .into_iter()
        .enumerate()
    {
        for seed in 0..6 {
            cases.push((format!("{label}/{seed}"), generated(family, seed)));
        }
    }
    // Select the widest existing development statements before running any arm.
    let mut existing = curriculum::development()
        .into_iter()
        .filter_map(|case| {
            let question = ResearchQuestion::from_hex(&case.source).ok()?;
            let target = question.proved_target().clone();
            let width = target.view().node_count_and_depth().0;
            Some((width, &case.id, &case.family, target))
        })
        .collect::<Vec<_>>();
    existing.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    let mut families = BTreeSet::new();
    cases.extend(
        existing
            .into_iter()
            .filter(|case| families.insert(case.2))
            .take(12)
            .map(|(_, id, _, target)| (format!("development/{id}"), target)),
    );
    let mut unique = BTreeSet::new();
    assert!(
        cases
            .iter()
            .all(|(_, formula)| unique.insert(formula.encode_canonical().unwrap()))
    );
    cases
}

fn checked_packet(target: &Formula, tree: &Tree) -> Result<Option<Packet>, crate::Error> {
    let (term, _) = compile(target, tree)?;
    proof::recipe_within_capacity(&term, target)?
        .map(|recipe| {
            construction::program_from_authored_recipe(target, recipe, &[])
                .map(|candidate| candidate.packet)
        })
        .transpose()
}

fn run_arm(
    arm: Arm,
    target: &Formula,
    ranker: &mut dyn Ranker,
    limit: usize,
    clock: SearchClock,
) -> Result<Planned, crate::Error> {
    match arm {
        Arm::Recursive => {
            let result = solve_clocked(target, ranker, limit, clock, &[], false)?;
            Ok(Planned {
                tree: result.tree,
                expansions: result.expansions,
                states: 0,
                reused: 0,
            })
        }
        Arm::Planner(strategy) => solve(target, ranker, limit, clock, &[], strategy),
    }
}

fn common_native_search(
    target: &Formula,
    ranker: &mut dyn Ranker,
    limit: usize,
    clock: SearchClock,
) -> Result<(Option<Packet>, usize), crate::Error> {
    let (scoped, work) = scope::search(target, ranker, limit, clock.started)?;
    if let Some(Tree::Scoped { actions, .. }) = scoped {
        let commands = scope::commands(target, &actions)?;
        return Ok((Some(Packet::compose(target, &commands, &[], [])?), work));
    }
    if work >= limit || clock.expired()? {
        return Ok((None, work));
    }
    let (candidate, constructed, _) =
        construction::construct_program(target, limit - work, clock.started, ranker, &[], &[])?;
    Ok((
        candidate.map(|candidate| candidate.packet),
        work + constructed,
    ))
}

fn independent_check(packet: &Packet, target: &Formula) -> Result<(), crate::Error> {
    let checked = std::thread::scope(|threads| {
        threads
            .spawn(|| packet.target())
            .join()
            .expect("independent checker")
    })?;
    assert_eq!(&checked, target);
    Ok(())
}

#[test]
#[ignore = "Finite comparison with one frozen trained model and real CPU deadlines"]
fn matched_cpu_subgoal_planning() {
    const LIMIT: usize = 768;
    let budgets = std::env::var("NAOME_SUBGOAL_CPU_BUDGET_US").map_or_else(
        |_| vec![300_000, 2_500_000],
        |budget| {
            vec![
                budget
                    .parse::<u64>()
                    .expect("positive CPU budget in microseconds"),
            ]
        },
    );
    assert!(
        budgets
            .iter()
            .all(|budget| *budget > 0 && *budget <= 2_500_000)
    );
    let example = crate::learning::tests::own_example();
    let question = ResearchQuestion::from_hex(&example.question).unwrap();
    let (_, training) = compile(question.proved_target(), &example.tree).unwrap();
    let mut store = MemoryStore::default();
    let mut rng = 17;
    let (checkpoint, _, _) = model::Engine::default()
        .train(
            &model::Checkpoint::fresh(),
            &pool::Pool::from_graphs(&training),
            &mut rng,
            &mut store,
        )
        .unwrap();
    let cases = benchmark_cases();
    assert!(
        cases
            .iter()
            .all(|(_, target)| target != question.proved_target())
    );
    let mut source_ids = Vec::new();
    for (case, target) in &cases {
        source_ids.push((case, crate::hex(&target.encode_canonical().unwrap())));
    }
    println!(
        "PLANNING_INPUT {}",
        json!({
            "questions":cases.len(), "cases_sha256":super::super::super::digest(&source_ids),
            "model":checkpoint.model, "adam":checkpoint.optimizer, "updates":checkpoint.updates,
            "specification":checkpoint.specification, "expansion_cap":LIMIT, "cpu_budgets_us":budgets
        })
    );
    for (mode, budget) in ["tableau", "native"]
        .into_iter()
        .flat_map(|mode| budgets.iter().copied().map(move |budget| (mode, budget)))
    {
        for (index, (label, target)) in cases.iter().enumerate() {
            let mut arms = [
                Arm::Recursive,
                Arm::Planner(Strategy::BestFirst),
                Arm::Planner(Strategy::Htps),
            ];
            arms.rotate_left(index % 3);
            for arm in arms {
                let mut engine = model::Engine::default();
                let (planned, prefix, work, started) = engine
                    .with_error(&checkpoint, &mut store, |runtime| {
                        let mut ranker = Exploring {
                            model: runtime,
                            seed: 0,
                            explore: false,
                        };
                        let started = cpu_micros()?;
                        let clock = SearchClock {
                            started: Instant::now(),
                            cpu_deadline: Some(started + budget),
                        };
                        let (prefix, work) = if mode == "native" {
                            common_native_search(target, &mut ranker, LIMIT, clock)?
                        } else {
                            (None, 0)
                        };
                        let planned = if prefix.is_none() && !clock.expired()? && work < LIMIT {
                            Some(run_arm(arm, target, &mut ranker, LIMIT - work, clock)?)
                        } else {
                            None
                        };
                        Ok((planned, prefix, work, started))
                    })
                    .unwrap();
                let search = cpu_micros().unwrap() - started;
                let tree = planned.as_ref().and_then(|run| run.tree.as_ref());
                let native_prefix = prefix.is_some();
                let (packet, error) = if let Some(packet) = prefix {
                    (Some(packet), None)
                } else if let Some(tree) = tree {
                    match checked_packet(target, tree) {
                        Ok(Some(packet)) => (Some(packet), None),
                        Ok(None) => (None, Some(json!("recipe_capacity"))),
                        Err(failure) => (None, Some(json!(failure))),
                    }
                } else {
                    (None, None)
                };
                let (mut proof, mut bytes, mut commands) = (None, None, None);
                let mut error = error;
                if let Some(packet) = packet {
                    match independent_check(&packet, target) {
                        Ok(()) => {
                            proof = Some(crate::hex(packet.manifest.artifact_id().as_bytes()));
                            bytes = Some(packet.retained_bytes());
                            commands = Some(packet.manifest.commands);
                        }
                        Err(failure) => error = Some(json!(failure)),
                    }
                }
                let total = cpu_micros().unwrap() - started;
                println!(
                    "PLANNING_CASE {}",
                    json!({
                        "case":label, "arm":arm.name(), "mode":mode, "budget_us":budget,
                        "search_us":search, "cpu_us":total,
                        "expansions":work + planned.as_ref().map_or(0, |run| run.expansions),
                        "states":planned.as_ref().map(|run| run.states),
                        "reused":planned.as_ref().map(|run| run.reused),
                        "tableau_found":tree.is_some(),"native_prefix":native_prefix,
                        "accepted":proof.is_some() && total <= budget,"proof":proof,"late":total > budget,
                        "commands":commands,"packet_bytes":bytes,
                        "split":tree.is_some_and(has_split),"error":error
                    })
                );
            }
        }
    }
}
