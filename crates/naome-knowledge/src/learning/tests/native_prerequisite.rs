use super::*;
use naome_foundation::Logic;
use naome_proof::{
    ProofStep,
    program::{Command, Projection},
};

fn donor(pattern: u32) -> (Formula, peer::Packet, peer::Packet) {
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
    let guard = proof::close(Formula::implies(atom(0, a, b), atom(5, c, b)));
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
    let inputs = Prerequisites::from_inputs(Vec::new(), packet.into_iter().collect()).unwrap();
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
        let (lemma, donor, base) = donor(relevant);
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
                "continuation without={} with={} expansions={}",
                control.diagnostic, next.diagnostic, next.cost.search_expansions
            );
            assert!(next.cost.search_expansions <= continuation_budget);
            let next = next
                .solution
                .unwrap_or_else(|| panic!("{}", next.diagnostic));
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
                "{}:{}:{}",
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
            assert!(empty.solution.is_none());
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
            .unwrap_or_else(|| panic!("{}", right.diagnostic));
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

#[test]
fn an_observed_open_cut_schedules_one_helper_and_learns_from_its_checked_use() {
    use crate::frontier::{Frontier, evidence};
    use crate::jobs;

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
    fn publish(
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
                diagnostic: generation.diagnostic,
                frontier: generation.frontier,
            }),
        };
        frontier
            .attempted(question, graph, &completion, evidence::Outcome::Candidate)
            .unwrap();
        frontier.prepared(question, job, root).unwrap();
        frontier.verified(question, graph, job, root).unwrap();
        root
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
fn a_known_local_cut_is_checked_inline_under_the_original_search_budget() {
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
