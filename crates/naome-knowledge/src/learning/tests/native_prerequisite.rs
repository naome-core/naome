use super::*;
use crate::{
    frontier::{Frontier, evidence},
    jobs,
};
use naome_foundation::Logic;
use naome_proof::{
    ProofStep,
    program::{Command, Projection},
};

fn donor(pattern: u32) -> (Formula, peer::Packet, peer::Packet) {
    donor_with_guard(pattern, false)
}

fn donor_with_guard(pattern: u32, reflexive: bool) -> (Formula, peer::Packet, peer::Packet) {
    let [a, b, c] = [10, 11, 12].map(FreeVariable::new);
    let atom = |bit, left, right| {
        if pattern & (1u32 << bit) == 0u32 {
            Formula::member(left, right)
        } else {
            Formula::equal(left, right)
        }
    };
    let first = Formula::implies(atom(0, a, b), Formula::negate(atom(1, b, c)));
    let second = Formula::conjunction(atom(2, c, a), atom(3, a, a));
    let third = Formula::implies(atom(4, a, c), atom(5, c, b));
    let primitive = Logic::frege(first.clone(), second.clone(), third.clone());
    let mut steps = vec![ProofStep::Frege {
        first: first.into(),
        second: second.into(),
        third: third.into(),
    }];
    for (premise, variable) in [c, b, a].into_iter().enumerate() {
        steps.push(ProofStep::Generalization {
            premise: premise as u32,
            variable,
        });
    }
    let base = proof::close(primitive);
    let commands = Projection::from_inference_steps(&steps)
        .unwrap()
        .into_commands();
    let foundation = peer::Packet::compose(&base, &commands, &[], []).unwrap();
    let foundation_id = foundation.manifest.proof_id();
    let guard = if reflexive {
        base.clone()
    } else {
        proof::close(Formula::implies(atom(0, a, b), atom(5, c, b)))
    };
    let target = Formula::implies(guard.clone(), base.clone());
    let nested = Projection::from_inference_steps(&[
        ProofStep::ProofReference {
            proof_id: foundation_id,
        },
        ProofStep::Simplification {
            antecedent: base.into(),
            consequent: guard.into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
    ])
    .unwrap()
    .into_commands();
    let packet =
        peer::Packet::compose(&target, &nested, std::slice::from_ref(&foundation), []).unwrap();
    assert_eq!(packet.target().unwrap(), target);
    (target, packet, foundation)
}

fn attempt(
    question: &ResearchQuestion,
    packet: Option<peer::Packet>,
    seed: u64,
    budget: usize,
) -> Result<Generation, String> {
    let required = packet
        .as_ref()
        .map(|proof| crate::hex(proof.manifest.proof_id().as_bytes()))
        .into_iter()
        .collect::<Vec<_>>();
    let inputs =
        Prerequisites::from_inputs(Vec::new(), packet.into_iter().collect(), None).unwrap();
    solve(question, &required, &inputs, seed, budget)
}

fn solve(
    question: &ResearchQuestion,
    required: &[String],
    inputs: &Prerequisites,
    seed: u64,
    budget: usize,
) -> Result<Generation, String> {
    let mut engine = Engine::default();
    engine.with(
        &Checkpoint::fresh(),
        &mut MemoryStore::default(),
        |runtime| {
            solve_with_report(
                &question.to_hex(),
                runtime,
                budget,
                seed,
                SolveContext {
                    required,
                    prerequisites: Some(inputs),
                    native_programs: true,
                    ..Default::default()
                },
            )
        },
    )
}

fn register_program(graph: &mut crate::Graph, packet: &peer::Packet) {
    use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS};
    use std::time::{Duration, Instant};

    let root = packet.manifest.artifact_id();
    let mut work = crate::proof_work::Work::open(
        &graph
            .ownership()
            .directory()
            .join(format!("{}.sqlite3", crate::hex(root.as_bytes()))),
    )
    .unwrap();
    for group in packet.commands().unwrap().chunks(CHUNK_RECORDS) {
        work.append_group(group).unwrap();
    }
    let budget = crate::resources::tests::snapshot(false).budget;
    while work.advance(&budget, graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget).unwrap() {}
    let checked = work.into_checked().unwrap();
    let proof = checked.proof().unwrap();
    assert_eq!(proof.manifest(), &packet.manifest);
    let store = graph.ownership();
    let mut progress = store.start_program(proof.manifest()).unwrap();
    while progress.commands < proof.manifest().commands {
        let chunk = proof
            .input_chunk(progress.commands, CHUNK_RECORDS, CHUNK_BYTES)
            .unwrap();
        store.append_program(proof.manifest(), &chunk).unwrap();
        progress = store.program_progress(proof.manifest()).unwrap();
    }
    let mut admission = graph.begin_program_admission(&checked).unwrap();
    while !admission.advance(graph, &checked, 128).unwrap() {}
    let batch = admission.finish(graph, &checked).unwrap();
    graph
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert!(graph.contains(root).unwrap());
}

#[test]
fn a_nested_native_prerequisite_unlocks_a_distinct_goal_within_the_same_budget() {
    const TEST: &str = "learning::tests::native_prerequisite::a_nested_native_prerequisite_unlocks_a_distinct_goal_within_the_same_budget";
    if std::env::var_os("NAOME_NATIVE_PREREQUISITE_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_NATIVE_PREREQUISITE_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let mut proof_ids = std::collections::BTreeSet::new();
    let mut derived = Vec::new();
    let mut continuation = None;
    for (index, (relevant, decoy)) in [(21, 38), (54, 9), (15, 49)].into_iter().enumerate() {
        // The direct controls have a structural closing step. The remaining
        // case needs the checked prerequisite under the same search budget.
        let (lemma, donor, base) = donor_with_guard(relevant, index != 1);
        let (_, decoy, decoy_base) = self::donor(decoy);
        let donor_id = donor.manifest.proof_id();
        let decoy_id = decoy.manifest.proof_id();
        for id in [
            donor_id,
            base.manifest.proof_id(),
            decoy_id,
            decoy_base.manifest.proof_id(),
        ] {
            assert!(proof_ids.insert(id));
        }
        let x = FreeVariable::new(0);
        let y = FreeVariable::new(1);
        let conclusion = Formula::member(x, y);
        let target = proof::close(Formula::implies(
            Formula::implies(lemma, conclusion.clone()),
            conclusion,
        ));
        let question = ResearchQuestion::from_formula(target).unwrap();
        let seed = 1981 + index as u64;
        let budget = if index == 0 { 8 } else { 5 };
        if index == 1 {
            let mut graph = crate::Graph::default();
            for program in [&base, &donor, &decoy_base, &decoy] {
                register_program(&mut graph, program);
            }
            let directory = crate::checkpoint::tests::Directory::new();
            let frontier = crate::frontier::Frontier::open(
                &directory.0,
                &graph,
                seed,
                crate::jobs::Settings {
                    native_proof_learning: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let (required, inputs) = frontier.solving_inputs(&graph, &question, &[]).unwrap();
            assert_eq!(required, [crate::hex(donor_id.as_bytes())]);
            assert!(inputs.has_programs());
            let selected = solve(&question, &required, &inputs, seed, budget).unwrap();
            let selected = selected
                .solution
                .expect("Finder selected a useful native proof");
            let search::Tree::Program(first) = &selected.tree else {
                panic!("the first generation must remain native");
            };
            register_program(&mut graph, first);
            let first_id = first.manifest.proof_id();
            let middle = Formula::member(x, y);
            let conclusion = Formula::member(y, x);
            let target = proof::close(Formula::implies(
                Formula::implies(question.proved_target().clone(), middle.clone()),
                Formula::implies(Formula::implies(middle, conclusion.clone()), conclusion),
            ));
            let second = ResearchQuestion::from_formula(target).unwrap();
            let (required, inputs) = frontier.solving_inputs(&graph, &second, &[]).unwrap();
            assert_eq!(required, [crate::hex(first_id.as_bytes())]);
            let continuation_budget = 8;
            let control = attempt(&second, None, seed, continuation_budget).unwrap();
            assert!(control.solution.is_none());
            let next = solve(&second, &required, &inputs, seed, continuation_budget).unwrap();
            eprintln!(
                "continuation without={:?} with={:?} expansions={}",
                control.diagnostic, next.diagnostic, next.cost.search_expansions
            );
            assert!(next.cost.search_expansions <= continuation_budget);
            let next = next
                .solution
                .unwrap_or_else(|| panic!("{:?}", next.diagnostic));
            continuation = Some((second, next, first_id));
            let mut with_unused = first.commands().unwrap();
            let seal = with_unused.pop().unwrap();
            with_unused.push(Command::ProofReference {
                proof_id: *decoy_id.as_bytes(),
            });
            with_unused.push(seal);
            let with_unused = peer::Packet::compose(
                question.proved_target(),
                &with_unused,
                &[donor.clone(), decoy.clone()],
                [],
            )
            .unwrap();
            register_program(&mut graph, &with_unused);
            assert_eq!(
                graph
                    .learning_proof_dependencies(with_unused.manifest.artifact_id())
                    .unwrap()
                    .as_ref(),
                &[donor.manifest.artifact_id()]
            );
            let decoy_formula = decoy.target().unwrap();
            let formula_only = peer::Packet::compose(
                &Formula::implies(decoy_formula.clone(), decoy_formula),
                &[
                    Command::ProofReference {
                        proof_id: *decoy_id.as_bytes(),
                    },
                    Command::Deduce {
                        assumptions: vec![0],
                        actions: Vec::new(),
                        result: 0,
                    },
                    Command::Seal { proof: 1 },
                ],
                std::slice::from_ref(&decoy),
                [],
            )
            .unwrap();
            register_program(&mut graph, &formula_only);
            assert!(
                graph
                    .learning_proof_dependencies(formula_only.manifest.artifact_id())
                    .unwrap()
                    .is_empty()
            );
            derived.push((question.clone(), selected, donor_id));
        }
        let wrong = attempt(&question, Some(decoy), seed, budget);
        let empty = attempt(&question, None, seed, budget);
        let right = attempt(&question, Some(donor), seed, budget);
        let outcome = |trial: &Result<Generation, String>| match trial {
            Ok(g) => format!(
                "{:?}:{}:{}",
                g.diagnostic,
                g.cost.search_expansions,
                g.solution.is_some()
            ),
            Err(error) => format!("error:{error}"),
        };
        eprintln!(
            "family={index} wrong={} empty={} relevant={}",
            outcome(&wrong),
            outcome(&empty),
            outcome(&right)
        );
        let wrong = wrong.unwrap();
        let empty = empty.unwrap();
        let right = right.unwrap();
        if index != 0 {
            assert!(wrong.solution.is_none());
        }
        if index == 1 {
            assert!(empty.solution.is_none());
        } else {
            let direct = empty
                .solution
                .expect("the closing step proves the goal directly");
            direct.check_target(&question).unwrap();
            let search::Tree::Program(program) = direct.tree else {
                panic!("the direct proof must remain native");
            };
            assert!(
                program
                    .commands()
                    .unwrap()
                    .iter()
                    .all(|command| { !matches!(command, Command::ProofReference { .. }) })
            );
        }
        assert!(wrong.cost.search_expansions <= budget);
        assert!(empty.cost.search_expansions <= budget);
        assert!(right.cost.search_expansions <= budget);
        if let Some(solution) = wrong.solution {
            let search::Tree::Program(program) = solution.tree else {
                panic!("a checked native control result is required");
            };
            assert!(!program.commands().unwrap().iter().any(|command| {
                matches!(command, Command::ProofReference { proof_id } if proof_id == decoy_id.as_bytes())
            }));
        }
        let solution = right
            .solution
            .unwrap_or_else(|| panic!("{:?}", right.diagnostic));
        if index != 1 {
            derived.push((question, solution, donor_id));
        } else {
            assert_eq!(derived[1].1.proof_id, solution.proof_id);
        }
    }

    derived.push(continuation.expect("the catalog supplied the previous result to the next goal"));

    // A fresh checker thread has no prior packet replay cache.
    std::thread::spawn(move || {
        let mut state = State::fresh();
        let mut evidence = Vec::new();
        for (index, (question, solution, donor_id)) in derived.into_iter().enumerate() {
            solution.check_target(&question).unwrap();
            let search::Tree::Program(program) = &solution.tree else {
                panic!("a checked native result is required");
            };
            assert_ne!(program.manifest.proof_id(), donor_id);
            assert!(program.commands().unwrap().iter().any(|command| {
                matches!(command, Command::ProofReference { proof_id } if proof_id == donor_id.as_bytes())
            }));
            let graphs = peer::program_graphs(question.proved_target(), program).unwrap();
            eprintln!(
                "family={index} checked={} replay_graphs={} bytes={}",
                solution.proof_id,
                graphs.len(),
                program.retained_bytes()
            );
            let example = Example {
                origin: Origin::Local,
                job: index as u64 + 1,
                question: question.to_hex(),
                proof_id: solution.proof_id,
                refuted: false,
                tree: solution.tree,
            };
            evidence.push(Evidence {
                job: example.job,
                proof_id: example.proof_id.clone(),
                trace: example.tree.clone(),
            });
            assert!(state.accept(example).unwrap());
        }
        assert_eq!(state.sample_counts(), (4, 0));
        assert!(state.has_training_graphs(&evidence).unwrap());
    })
    .join()
    .unwrap();
}

#[test]
fn finder_uses_only_the_shorter_checked_universal_route() {
    const TEST: &str = "learning::tests::native_prerequisite::finder_uses_only_the_shorter_checked_universal_route";
    if std::env::var_os("NAOME_NATIVE_QUANTIFIED_ROUTE_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_NATIVE_QUANTIFIED_ROUTE_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let (short, fast, fast_base) = donor(34);
    let (long, slow, slow_base) = donor(12);
    let [x, y, z] = [0, 1, 2].map(FreeVariable::new);
    let target = Formula::member(x, y);
    let first = Formula::member(y, x);
    let second = Formula::member(x, x);
    let rules = [
        Formula::implies(short.clone(), Formula::for_all(z, Formula::member(z, y))),
        Formula::implies(long.clone(), first.clone()),
        Formula::implies(first, second.clone()),
        Formula::implies(second, target.clone()),
    ];
    let target = rules.into_iter().rev().fold(target, |goal, assumption| {
        Formula::implies(assumption, goal)
    });
    let question = ResearchQuestion::from_formula(proof::close(target)).unwrap();

    let mut graph = crate::Graph::default();
    for program in [&slow_base, &slow] {
        register_program(&mut graph, program);
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let seed = 6715;
    let frontier = crate::frontier::Frontier::open(
        &directory.0,
        &graph,
        seed,
        crate::jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        },
    )
    .unwrap();
    let budget = 9;
    let slow_id = crate::hex(slow.manifest.proof_id().as_bytes());
    let (required, inputs) = frontier.solving_inputs(&graph, &question, &[]).unwrap();
    assert_eq!(required.as_slice(), std::slice::from_ref(&slow_id));
    let longer = solve(&question, &required, &inputs, seed, budget).unwrap();
    assert!(longer.solution.is_none());
    assert_eq!(longer.cost.search_expansions, budget);

    for program in [&fast_base, &fast] {
        register_program(&mut graph, program);
    }
    let (required, inputs) = frontier.solving_inputs(&graph, &question, &[]).unwrap();
    let fast_id = fast.manifest.proof_id();
    assert_eq!(required, [crate::hex(fast_id.as_bytes())]);
    let shorter = solve(&question, &required, &inputs, seed, budget).unwrap();
    assert!(shorter.cost.search_expansions <= budget);
    let solution = shorter.solution.expect("shorter checked route fits");
    let copy = question.clone();
    std::thread::spawn(move || {
        solution.check_target(&copy).unwrap();
        let search::Tree::Program(program) = &solution.tree else {
            panic!("native solution expected");
        };
        assert!(program.commands().unwrap().iter().any(|command| {
            matches!(command, Command::ProofReference { proof_id } if proof_id == fast_id.as_bytes())
        }));
    })
    .join()
    .unwrap();

    let (planned, _) = frontier
        .solving_inputs(&graph, &question, std::slice::from_ref(&slow_id))
        .unwrap();
    assert_eq!(planned.as_slice(), std::slice::from_ref(&slow_id));

    let (x, y) = (y, x);
    let goal = Formula::member(x, y);
    let first = Formula::member(y, x);
    let second = Formula::member(x, x);
    let hinge = Formula::equal(x, y);
    let alternative = Formula::equal(y, x);
    let rules = [
        Formula::implies(hinge, goal.clone()),
        Formula::implies(short, Formula::for_all(z, Formula::equal(z, y))),
        Formula::implies(long, first.clone()),
        Formula::implies(first, second.clone()),
        Formula::implies(second, alternative.clone()),
        Formula::implies(alternative, goal.clone()),
    ];
    let target = rules
        .into_iter()
        .rev()
        .fold(goal, |goal, assumption| Formula::implies(assumption, goal));
    let deeper = ResearchQuestion::from_formula(proof::close(target)).unwrap();
    let (required, inputs) = frontier.solving_inputs(&graph, &deeper, &[]).unwrap();
    assert_eq!(required.as_slice(), std::slice::from_ref(&slow_id));
    let result = solve(&deeper, &required, &inputs, seed, 13).unwrap();
    assert!(result.cost.search_expansions <= 13);
    let solution = result.solution.expect("the original direct chain fits");
    std::thread::spawn(move || solution.check_target(&deeper))
        .join()
        .unwrap()
        .unwrap();
}

fn stage_publication(
    frontier: &mut Frontier,
    graph: &mut crate::Graph,
    question: &ResearchQuestion,
    generation: Generation,
    job: u64,
) -> naome_proof::ArtifactId {
    let solution = generation.solution.expect("native solution");
    assert!(!solution.refuted);
    let search::Tree::Program(program) = &solution.tree else {
        panic!("a native program is required");
    };
    let root = program.manifest.artifact_id();
    register_program(graph, program);
    let completion = jobs::Completion {
        experience: None,
        model_checkpoint: None,
        id: job,
        binding: jobs::Binding::new([0; 32], [0; 32]),
        spent_ms: 1,
        reserved_units: 1,
        state: jobs::State::Complete,
        result: Ok(jobs::Output::Native {
            terminal: Box::new(generation.terminal),
            solution: Some(solution),
            frontier: generation.frontier,
        }),
    };
    frontier
        .attempted(question, graph, &completion, evidence::Outcome::Candidate)
        .unwrap();
    frontier.prepared(question, job, root).unwrap();
    root
}

fn publish(
    frontier: &mut Frontier,
    graph: &mut crate::Graph,
    question: &ResearchQuestion,
    generation: Generation,
    job: u64,
) -> naome_proof::ArtifactId {
    let root = stage_publication(frontier, graph, question, generation, job);
    frontier.verified(question, graph, job, root).unwrap();
    root
}

#[test]
fn an_observed_open_cut_schedules_one_helper_and_learns_from_its_checked_use() {
    const TEST: &str = "learning::tests::native_prerequisite::an_observed_open_cut_schedules_one_helper_and_learns_from_its_checked_use";
    if std::env::var_os("NAOME_NATIVE_OPEN_CUT_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_NATIVE_OPEN_CUT_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let (_, alternatives) = super::helper_goal();
    let [a, b, c, d, z] = [0, 1, 2, 3, 10].map(FreeVariable::new);
    let target = Formula::member(a, b);
    let consequent = Formula::for_all(z, Formula::member(z, b));
    let rules = [
        Formula::implies(alternatives[0].proved_target().clone(), consequent.clone()),
        Formula::implies(alternatives[1].proved_target().clone(), consequent),
        Formula::implies(Formula::member(b, a), Formula::equal(a, b)),
        Formula::implies(Formula::equal(a, b), Formula::member(c, b)),
        Formula::implies(Formula::member(c, b), Formula::equal(c, a)),
        Formula::implies(Formula::equal(c, a), Formula::member(b, d)),
    ];
    let formula = rules.into_iter().rev().fold(target, |goal, assumption| {
        Formula::implies(assumption, goal)
    });
    let goal = ResearchQuestion::from_formula(proof::close(formula)).unwrap();
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = crate::Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let seed = 1401;
    let budget = 14;
    let capacity_directory = crate::checkpoint::tests::Directory::new();
    let mut capacity = Frontier::open(&capacity_directory.0, &graph, seed, settings).unwrap();
    let before = capacity.learning_snapshot();
    let blocked = evidence::observed_completion(
        &goal,
        1,
        experience::TerminalEvidence::Unsupported(experience::Capacity::Facts),
        budget,
        None,
    );
    capacity
        .attempted(&goal, &graph, &blocked, evidence::Outcome::NoCandidate)
        .unwrap();
    assert_eq!(capacity.learning_snapshot(), before);
    let (_, work) = capacity.loop_focus(&graph, |_| true).unwrap().unwrap();
    assert_eq!(
        work.pending.as_slice(),
        std::slice::from_ref(&alternatives[0])
    );
    drop(work);
    drop(capacity);

    let mut frontier = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    let miss = attempt(&goal, None, seed, budget).unwrap();
    assert!(miss.solution.is_none());
    assert!(
        miss.terminal
            .observed_search_failure(miss.cost.search_expansions)
    );
    let completion =
        evidence::observed_completion(&goal, 1, miss.terminal, miss.cost.search_expansions, None);
    frontier
        .attempted(&goal, &graph, &completion, evidence::Outcome::NoCandidate)
        .unwrap();
    drop(frontier);

    let mut frontier = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    let (open, work) = frontier.loop_focus(&graph, |_| true).unwrap().unwrap();
    assert_eq!(open.resolution_id(), goal.resolution_id());
    assert_eq!(work.planned.len(), 2);
    assert_eq!(
        work.pending.as_slice(),
        std::slice::from_ref(&alternatives[0])
    );
    assert!(work.required.is_empty());
    drop(work);
    let helper = &alternatives[0];
    let generation = attempt(helper, None, seed, budget).unwrap();
    let helper_root = publish(&mut frontier, &mut graph, helper, generation, 2);
    let (open, work) = frontier.loop_focus(&graph, |_| true).unwrap().unwrap();
    assert_eq!(open.resolution_id(), goal.resolution_id());
    assert!(work.pending.is_empty());
    assert_eq!(work.required.len(), 1);
    let (required, inputs) = frontier
        .solving_inputs(&graph, &open, &work.required)
        .unwrap();
    let result = solve(&open, &required, &inputs, seed, budget).unwrap();
    assert!(result.cost.search_expansions <= budget);
    let root = publish(&mut frontier, &mut graph, &open, result, 3);
    assert_eq!(
        graph.learning_proof_dependencies(root).unwrap().as_ref(),
        &[helper_root]
    );
    assert_eq!(frontier.support_updates(), 1);
    assert!(frontier.loop_focus(&graph, |_| true).unwrap().is_none());
    drop(work);
    drop(frontier);
    let reopened = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    assert_eq!(reopened.support_updates(), 1);
}

#[test]
fn a_closed_pair_releases_an_open_goal_only_after_both_checked_helpers() {
    const TEST: &str = "learning::tests::native_prerequisite::a_closed_pair_releases_an_open_goal_only_after_both_checked_helpers";
    if std::env::var_os("NAOME_NATIVE_CLOSED_PAIR_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_NATIVE_CLOSED_PAIR_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }

    let (_, helpers) = super::helper_goal();
    let (left, crossed, left_base) = donor(21);
    let (right, _, _) = donor(38);
    let [a, b] = [0, 1].map(FreeVariable::new);
    let result = Formula::member(a, b);
    let rule = |first, second| Formula::implies(first, Formula::implies(second, result.clone()));
    let preferred = rule(
        helpers[0].proved_target().clone(),
        helpers[1].proved_target().clone(),
    );
    let distractor = Formula::implies(left.clone(), Formula::equal(a, b));
    let alternative = rule(left, right);
    let target = [distractor, alternative, preferred]
        .into_iter()
        .rev()
        .fold(result.clone(), |body, premise| {
            Formula::implies(premise, body)
        });
    let goal = ResearchQuestion::from_formula(proof::close(target)).unwrap();
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = crate::Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let (seed, budget) = (71119, 11);
    let mut frontier = Frontier::open(&directory.0, &graph, seed, settings).unwrap();

    let miss = attempt(&goal, None, seed, budget).unwrap();
    assert!(miss.solution.is_none());
    assert!(
        miss.terminal
            .observed_search_failure(miss.cost.search_expansions)
    );
    let completion =
        evidence::observed_completion(&goal, 1, miss.terminal, miss.cost.search_expansions, None);
    frontier
        .attempted(&goal, &graph, &completion, evidence::Outcome::NoCandidate)
        .unwrap();
    let work = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    assert!(helpers.iter().all(|helper| work.planned.contains(helper)));
    assert_eq!(work.pending.as_slice(), &helpers[..1]);
    assert!(work.required.is_empty());
    drop(work);

    let first = publish(
        &mut frontier,
        &mut graph,
        &helpers[0],
        attempt(&helpers[0], None, seed, 64).unwrap(),
        2,
    );
    register_program(&mut graph, &left_base);
    register_program(&mut graph, &crossed);
    assert!(
        frontier
            .solving_inputs(&graph, &goal, &[])
            .unwrap()
            .0
            .is_empty()
    );
    drop(frontier);

    let mut frontier = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    let work = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    assert_eq!(work.pending.as_slice(), &helpers[1..]);
    assert!(work.required.is_empty());
    assert_eq!(frontier.support_updates(), 0);
    drop(work);

    let second = publish(
        &mut frontier,
        &mut graph,
        &helpers[1],
        attempt(&helpers[1], None, seed, 64).unwrap(),
        3,
    );
    let work = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    assert!(work.pending.is_empty());
    assert_eq!(work.required.len(), 2);
    let (required, inputs) = frontier.solving_inputs(&graph, &goal, &[]).unwrap();
    assert_eq!(required, work.required);
    drop(work);
    let generation = solve(&goal, &required, &inputs, seed, budget).unwrap();
    assert!(generation.cost.search_expansions <= budget);
    let root = publish(&mut frontier, &mut graph, &goal, generation, 4);
    let dependencies = graph.learning_proof_dependencies(root).unwrap();
    assert_eq!(dependencies.len(), 2);
    assert!(dependencies.contains(&first) && dependencies.contains(&second));
    assert_eq!(frontier.support_updates(), 2);
    assert!(frontier.loop_focus(&graph, |_| true).unwrap().is_none());
    drop(frontier);
    let reopened = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    assert_eq!(reopened.support_updates(), 2);
}

#[test]
fn an_exhausted_pair_releases_the_next_complete_alternative() {
    const TEST: &str = "learning::tests::native_prerequisite::an_exhausted_pair_releases_the_next_complete_alternative";
    if std::env::var_os("NAOME_NATIVE_PAIR_FALLBACK_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_NATIVE_PAIR_FALLBACK_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    let (_, viable) = super::helper_goal();
    let [a, b] = [0, 1].map(FreeVariable::new);
    let blocked = ResearchQuestion::from_formula(proof::close(Formula::equal(a, b))).unwrap();
    let other = ResearchQuestion::from_formula(donor(21).0).unwrap();
    let target = Formula::member(a, b);
    let rule = |first: &ResearchQuestion, second: &ResearchQuestion| {
        Formula::implies(
            first.proved_target().clone(),
            Formula::implies(second.proved_target().clone(), target.clone()),
        )
    };
    let decoy = Formula::implies(viable[0].proved_target().clone(), Formula::equal(b, a));
    let formula = [rule(&blocked, &other), decoy, rule(&viable[0], &viable[1])]
        .into_iter()
        .rev()
        .fold(target.clone(), |body, premise| {
            Formula::implies(premise, body)
        });
    let goal = ResearchQuestion::from_formula(proof::close(formula)).unwrap();
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = crate::Graph::default();
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let (seed, budget) = (71119, 11);
    let mut frontier = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    let record_miss = |frontier: &mut Frontier, graph: &crate::Graph, question, job| {
        let miss = attempt(question, None, seed, budget).unwrap();
        assert!(miss.solution.is_none());
        assert!(
            miss.terminal
                .observed_search_failure(miss.cost.search_expansions)
        );
        let completion = evidence::observed_completion(
            question,
            job,
            miss.terminal,
            miss.cost.search_expansions,
            None,
        );
        frontier
            .attempted(question, graph, &completion, evidence::Outcome::NoCandidate)
            .unwrap();
    };
    record_miss(&mut frontier, &graph, &goal, 1);
    let work = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    assert_eq!(
        work.planned,
        [&blocked, &other, &viable[0], &viable[1]].map(Clone::clone)
    );
    assert_eq!(work.pending.as_slice(), std::slice::from_ref(&blocked));
    assert!(work.required.is_empty());
    drop(work);
    record_miss(&mut frontier, &graph, &blocked, 2);
    drop(frontier);

    let mut frontier = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
    let mut expected = Vec::new();
    for (index, helper) in viable.iter().enumerate() {
        let work = frontier.loop_work(&goal, &graph, |_| true).unwrap();
        assert_eq!(work.pending.as_slice(), std::slice::from_ref(helper));
        assert!(work.required.is_empty());
        drop(work);
        expected.push(publish(
            &mut frontier,
            &mut graph,
            helper,
            attempt(helper, None, seed, 64).unwrap(),
            3 + index as u64,
        ));
    }
    let work = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    assert!(work.pending.is_empty());
    assert_eq!(work.required.len(), 2);
    let (required, inputs) = frontier
        .solving_inputs(&graph, &goal, &work.required)
        .unwrap();
    drop(work);
    let generation = solve(&goal, &required, &inputs, seed, budget).unwrap();
    let root = publish(&mut frontier, &mut graph, &goal, generation, 5);
    let dependencies = graph.learning_proof_dependencies(root).unwrap();
    assert_eq!(dependencies.len(), 2);
    assert!(expected.iter().all(|id| dependencies.contains(id)));
    assert_eq!(frontier.support_updates(), 2);
}

#[test]
fn a_known_local_cut_is_checked_inline_under_the_original_search_budget() {
    if !crate::learning::tests::isolated(
        "learning::tests::native_prerequisite::a_known_local_cut_is_checked_inline_under_the_original_search_budget",
    ) {
        return;
    }
    use naome_checker::{
        ArtifactState,
        question::{
            AssessmentQuestion, KnowledgeSnapshot, PrefilterPolicy, QuestionRegistry,
            RejectionReason, assess_question,
        },
    };
    use naome_proof::ProofCertificate;

    let [a, b, c, d, z] = [0, 1, 2, 3, 10].map(FreeVariable::new);
    let inclusion = Formula::for_all(
        z,
        Formula::implies(Formula::member(z, a), Formula::member(z, b)),
    );
    let helper = ResearchQuestion::from_formula(proof::close(Formula::implies(
        inclusion,
        Formula::implies(Formula::member(c, a), Formula::member(c, b)),
    )))
    .unwrap();
    let conclusion = Formula::member(a, b);
    let mut rules = [
        Formula::implies(
            helper.proved_target().clone(),
            Formula::for_all(z, Formula::member(z, b)),
        ),
        Formula::implies(Formula::member(b, a), Formula::equal(a, b)),
        Formula::implies(Formula::equal(a, b), Formula::member(c, b)),
        Formula::implies(Formula::member(c, b), Formula::equal(c, a)),
        Formula::implies(Formula::equal(c, a), Formula::member(b, d)),
    ];
    rules.rotate_left(2);
    let goal = rules
        .into_iter()
        .rev()
        .fold(conclusion, |goal, rule| Formula::implies(rule, goal));
    let goal = ResearchQuestion::from_formula(proof::close(goal)).unwrap();
    let context = ArtifactState::new();
    let registry = QuestionRegistry::new();
    let snapshot = KnowledgeSnapshot::new([0; 32], &context, &registry);
    let request = AssessmentQuestion::from_research_question(&helper, None).unwrap();
    let assessed = assess_question(&request, &snapshot, &PrefilterPolicy::default());
    assert_eq!(assessed.reason, Some(RejectionReason::KnownProof));
    let witness = assessed.deduction.unwrap();
    assert!(witness.original_proofs().is_empty());
    let inputs = Prerequisites::internal_cut(witness.canonical_certificate().to_vec()).unwrap();
    let restored: Prerequisites =
        serde_json::from_slice(&serde_json::to_vec(&inputs).unwrap()).unwrap();
    assert!(restored.contains_inputs(&inputs));
    assert!(!Prerequisites::default().contains_inputs(&restored));
    assert!(
        restored
            .require(
                &State::fresh(),
                &[crate::hex(witness.proof_id().as_bytes())]
            )
            .is_err()
    );

    let mut owner = crate::jobs::tests::Manual::new();
    let binding = crate::jobs::Binding::new([0; 32], [0; 32]);
    assert!(
        owner
            .client
            .submit_after(
                crate::jobs::Input::Find {
                    cursor: 0,
                    question: goal.to_hex()
                },
                binding.clone(),
                Vec::new(),
                restored.clone(),
            )
            .is_err()
    );
    let solve_request = crate::jobs::Input::Solve {
        question: goal.to_hex(),
    };
    let _ticket = owner
        .client
        .submit_after(solve_request.clone(), binding, Vec::new(), restored.clone())
        .unwrap();
    let requests = owner.requests();
    assert!(matches!(requests.as_slice(), [(_, input)] if input == &solve_request));
    let mut worker = State::fresh().job();
    worker.prerequisites = restored.clone();
    worker.validate().unwrap();
    worker.training = true;
    assert!(worker.validate().is_err());

    let seed = 1403;
    let budget = 13;
    let control = attempt(&goal, None, seed, budget).unwrap();
    assert!(control.solution.is_none());
    let generated = solve(&goal, &[], &restored, seed, budget).unwrap();
    assert_eq!(generated.cost.search_expansions, budget);
    assert!(generated.cost.dependency_check_steps >= 4);
    let solution = generated
        .solution
        .expect("the checked local cut should close");
    assert!(solution.helpers.is_empty());
    assert!(!solution.refuted);
    let search::Tree::Program(packet) = &solution.tree else {
        panic!("native program expected");
    };
    assert!(
        !packet
            .commands()
            .unwrap()
            .iter()
            .any(|command| { matches!(command, Command::ProofReference { .. }) })
    );
    let copy = goal.clone();
    std::thread::spawn(move || solution.check_target(&copy))
        .join()
        .unwrap()
        .unwrap();

    let unrelated = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity { variable: a },
        ProofStep::Generalization {
            premise: 0,
            variable: a,
        },
    ])
    .unwrap();
    let unrelated = Prerequisites::internal_cut(unrelated.to_canonical_bytes()).unwrap();
    assert!(!restored.contains_inputs(&unrelated));
    let Err(error) = solve(&goal, &[], &unrelated, seed, budget) else {
        panic!("a checked but unrelated certificate was admitted");
    };
    assert_eq!(
        error,
        "internal cut does not match the requested proof path"
    );
}

pub(crate) fn catalog_case(graph: &mut crate::Graph) -> (ResearchQuestion, naome_proof::ProofId) {
    use naome_proof::program::ScopedAction;

    let names = [10, 11, 12].map(FreeVariable::new);
    let donors = [3, 20, 41].map(|mask| donor(mask).2);
    let closed = donors.each_ref().map(|packet| packet.target().unwrap());
    let opened = closed.each_ref().map(|formula| {
        names.into_iter().fold(formula.clone(), |body, name| {
            body.open_outer_universal(name).unwrap()
        })
    });
    let [left, middle, right] = opened;
    let body = Formula::conjunction(left, Formula::conjunction(middle, right));
    let close = |formula| {
        names
            .into_iter()
            .rev()
            .fold(formula, |body, name| Formula::for_all(name, body))
    };
    let mut actions = Vec::new();
    let mut results = Vec::new();
    let result = |actions: &[ScopedAction]| (donors.len() + actions.len() - 1) as u32;
    for donor in 0..donors.len() as u32 {
        let mut premise = donor;
        for name in names {
            actions.push(ScopedAction::Instantiate {
                universal: premise,
                replacement: name.identifier(),
                premises: Vec::new(),
            });
            premise = result(&actions);
        }
        results.push(premise);
    }
    actions.push(ScopedAction::Conjoin {
        left: results[1],
        right: results[2],
    });
    actions.push(ScopedAction::Conjoin {
        left: results[0],
        right: result(&actions),
    });
    let commands = Projection::scoped_with_references(
        &closed.map(Into::into),
        &actions,
        result(&actions),
        &names,
        &donors.each_ref().map(|packet| packet.manifest.proof_id()),
    );
    for packet in &donors {
        register_program(graph, packet);
    }
    let source = peer::Packet::compose(&close(body.clone()), &commands, &donors, []).unwrap();
    register_program(graph, &source);
    let [a, _, c] = names;
    let d = FreeVariable::new(13);
    let guard = Formula::for_all(d, Formula::implies(body, Formula::member(d, a)));
    let target = close(Formula::implies(guard, Formula::member(c, a)));
    (
        ResearchQuestion::from_formula(target).unwrap(),
        source.manifest.proof_id(),
    )
}

pub(crate) fn publish_catalog_solution(
    graph: &mut crate::Graph,
    solution: &Solution,
) -> naome_proof::ArtifactId {
    let search::Tree::Program(program) = &solution.tree else {
        panic!("catalog result must use the native program format");
    };
    register_program(graph, program);
    program.manifest.artifact_id()
}

#[test]
fn catalog_reuses_a_checked_universal_for_an_existential_consequent() {
    use crate::{checkpoint::tests::Directory, jobs::CatalogSource};
    use naome_proof::program::{Axiom, ScopedAction};

    let _reservation = qualification_fixture();
    let directory = Directory::new();
    let mut graph = crate::Graph::open(&directory.0).unwrap();
    let pairing = naome_foundation::ZfcAxiom::Pairing.formula();
    let [a, b, p] = [0, 1, 2].map(FreeVariable::new);
    let consequent = pairing
        .open_outer_universal(b)
        .unwrap()
        .open_outer_universal(a)
        .unwrap();
    let question = ResearchQuestion::from_formula(proof::close(Formula::implies(
        Formula::member(a, p),
        consequent,
    )))
    .unwrap();
    assert!(
        CatalogSource::for_exact_local_scope(&graph, &question)
            .unwrap()
            .is_none()
    );

    let source = peer::Packet::compose(
        &pairing,
        &[
            Command::Axiom {
                axiom: Axiom::Pairing,
            },
            Command::Seal { proof: 0 },
        ],
        &[],
        [],
    )
    .unwrap();
    register_program(&mut graph, &source);
    let selected = CatalogSource::for_exact_local_scope(&graph, &question)
        .unwrap()
        .expect("the checked instance is indexed under the opened consequent");
    assert_eq!(selected.proof_id(), source.manifest.proof_id());
    let selected: CatalogSource =
        serde_json::from_slice(&serde_json::to_vec(&selected).unwrap()).unwrap();
    let solution = selected
        .solve_local_scope(&question.to_hex())
        .unwrap()
        .unwrap();
    assert_eq!(solution.cost.search_expansions, 3);
    assert!(selected.supports(&solution).unwrap());
    let search::Tree::Program(packet) = &solution.tree else {
        panic!("expected a native program");
    };
    let commands = packet.commands().unwrap();
    let actions = commands
        .iter()
        .find_map(|command| match command {
            Command::Deduce { actions, .. } => Some(actions),
            _ => None,
        })
        .unwrap();
    assert!(matches!(actions.as_slice(), [
        ScopedAction::Instantiate { premises: first, .. },
        ScopedAction::Instantiate { premises: second, .. },
    ] if first.is_empty() && second.is_empty()));
    solution.check_target(&question).unwrap();
    let root = publish_catalog_solution(&mut graph, &solution);
    drop(graph);
    let graph = crate::Graph::open(&directory.0).unwrap();
    assert_eq!(
        graph.learning_proof_dependencies(root).unwrap().as_ref(),
        &[source.manifest.artifact_id()]
    );
}

#[test]
fn free_finder_proposes_a_witness_question_whose_checked_answer_cites_the_source() {
    const TEST: &str = "learning::tests::native_prerequisite::free_finder_proposes_a_witness_question_whose_checked_answer_cites_the_source";
    const SMALL_CACHE: usize = 4096;
    if std::env::var_os("NAOME_WITNESS_CACHE_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_WITNESS_CACHE_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut profile = crate::resources::ResourceProfile::default();
    profile.tuning.question_cache_bytes = Some(SMALL_CACHE);
    crate::resources::configure(profile).unwrap();
    let _reservation = qualification_fixture();
    use crate::checkpoint::tests::Directory;

    let directory = Directory::new();
    let mut graph = crate::Graph::open(&directory.0).unwrap();
    let (_, _, lemma) = donor(21);
    register_program(&mut graph, &lemma);
    let x = FreeVariable::new(0);
    let body = lemma.target().unwrap().open_outer_universal(x).unwrap();
    let expected = ResearchQuestion::from_formula(Formula::exists(x, body)).unwrap();
    let proposal_bytes = expected.canonical_bytes().len() * 8 + 256;
    assert!(proposal_bytes > 1024 && proposal_bytes <= SMALL_CACHE);
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut finder = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let mut owner =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    finder
        .refresh(&graph, |q| owner.assess(&graph, q).passed())
        .unwrap();
    let question = finder
        .candidate_page(0, |q| owner.assess(&graph, q).passed())
        .unwrap()
        .into_iter()
        .find(|q| q == &expected)
        .expect("a checked universal yields a novel witness question without a supplied goal");

    drop(finder);
    let finder = Frontier::open(&directory.0, &graph, 41, settings).unwrap();
    let (required, inputs) = finder.solving_inputs(&graph, &question, &[]).unwrap();
    assert!(required.is_empty());
    assert!(inputs.has_offer());
    let result = solve(&question, &required, &inputs, 41, 2).unwrap();
    assert_eq!(result.cost.search_expansions, 2);
    let solution = result.solution.unwrap();
    solution.check_target(&question).unwrap();
    let root = publish_catalog_solution(&mut graph, &solution);
    assert_eq!(
        graph.learning_proof_dependencies(root).unwrap().as_ref(),
        &[lemma.manifest.artifact_id()],
    );
    assert!(!owner.assess(&graph, &question).passed());
}

#[test]
fn recurrent_checked_citations_restore_a_route_from_the_same_catalogue() {
    const TEST: &str = "learning::tests::native_prerequisite::recurrent_checked_citations_restore_a_route_from_the_same_catalogue";
    if std::env::var_os("NAOME_RECALL_MATCHED_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_RECALL_MATCHED_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    use crate::checkpoint::tests::Directory;
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let seed = 6021;
    let (x, y) = (FreeVariable::new(0), FreeVariable::new(1));
    let (_, _, base) = donor(21);
    let source = base.target().unwrap();
    let source_id = base.manifest.proof_id();
    let source_question = ResearchQuestion::from_formula(source.clone()).unwrap();
    assert!(
        State::eligible(&source_question.to_hex()),
        "eligible recall source"
    );
    let instance = source.open_outer_universal(x).unwrap();
    let question = |assumption| {
        ResearchQuestion::from_formula(proof::close(Formula::implies(assumption, instance.clone())))
            .unwrap()
    };
    let seed_goals = [
        question(Formula::member(x, y)),
        question(Formula::member(x, x)),
    ];
    let probes = [
        question(Formula::equal(x, y)),
        question(Formula::member(y, x)),
    ];
    let unrelated = ResearchQuestion::from_formula(proof::close(Formula::implies(
        Formula::equal(x, y),
        donor(38)
            .2
            .target()
            .unwrap()
            .open_outer_universal(y)
            .unwrap(),
    )))
    .unwrap();
    for q in seed_goals.iter().chain(&probes) {
        assert!(State::eligible(&q.to_hex()));
        assert!(knowledge::directly_applies(q.proved_target(), &source).unwrap());

        assert_eq!(
            crate::structure::Features::of(q).family,
            crate::structure::Features::of(&probes[0]).family,
        );
    }

    let mut catalogues = Vec::new();
    let mut results = Vec::new();
    for recall in [false, true] {
        let directory = Directory::new();
        let mut graph = crate::Graph::open(&directory.0).unwrap();
        register_program(&mut graph, &base);
        let mut finder = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
        if !recall {
            finder.disable_structural_recall();
        }
        for (index, q) in seed_goals.iter().enumerate() {
            let (required, selected) = finder.solving_inputs(&graph, q, &[]).unwrap();
            assert!(required.is_empty());
            assert_eq!(selected.has_offer(), recall);
            // Keep the checked starting catalogue for the post-restart probes
            // identical even when the control cannot retrieve the source.
            let inputs = if recall {
                selected
            } else {
                graph
                    .offered_solving_inputs(source_id, &[])
                    .unwrap()
                    .unwrap()
            };
            let found = solve(q, &[], &inputs, seed, 12).unwrap();
            let job = index as u64 + 1;
            let root = stage_publication(&mut finder, &mut graph, q, found, job);
            assert_eq!(
                graph.learning_proof_dependencies(root).unwrap().as_ref(),
                &[base.manifest.artifact_id()],
            );
            if index == 0 {
                finder.verified(q, &graph, job, root).unwrap();
                // Redelivery is not another encounter.
                finder.verified(q, &graph, job, root).unwrap();
                let (_, inputs) = finder.solving_inputs(&graph, &probes[0], &[]).unwrap();
                assert_eq!(
                    inputs.has_offer(),
                    recall,
                    "one checked use can supply an applicable offer",
                );
            } else {
                // The checker committed the proof; the resolution transaction
                // committed, but its acknowledgement did not reach Finder.
                crate::checkpoint::fail_after_commit();
                assert!(finder.verified(q, &graph, job, root).is_err());
            }
        }
        let before = graph.content_root();
        drop(finder);
        assert_eq!(graph.content_root(), before);
        catalogues.push(before);
        let mut finder = Frontier::open(&directory.0, &graph, seed, settings).unwrap();
        if !recall {
            finder.disable_structural_recall();
        }
        let (_, unrelated_inputs) = finder.solving_inputs(&graph, &unrelated, &[]).unwrap();
        assert!(
            !unrelated_inputs.has_offer(),
            "family alone must not offer an inapplicable proof"
        );
        let mut trials = Vec::new();
        let mut admission =
            crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
        for q in &probes {
            let decision = admission.assess(&graph, q);
            assert!(
                decision.passed(),
                "probe must remain open: {:?}",
                decision.reason
            );
            let (required, inputs) = finder.solving_inputs(&graph, q, &[]).unwrap();
            let result = solve(q, &required, &inputs, seed, 8).unwrap();
            let mut cited = false;
            if let Some(solution) = &result.solution {
                solution.check_target(q).unwrap();
                if let search::Tree::Program(program) = &solution.tree {
                    cited = peer::contributing_proofs(&program.commands().unwrap())
                        .unwrap()
                        .contains(&source_id);
                }
            }
            let expansions = result.cost.search_expansions;
            assert!(expansions <= 8);
            trials.push((result.solution.is_some(), cited, expansions));
            eprintln!(
                "{recall:?} offered={} trial={:?}",
                inputs.has_offer(),
                trials.last()
            );
        }
        results.push(trials);
    }
    assert_eq!(catalogues[0], catalogues[1]);
    assert!(results[1].iter().all(|&(solved, cited, _)| solved && cited));
    assert!(
        results[0]
            .iter()
            .any(|&(solved, cited, _)| !solved || !cited)
    );
}
