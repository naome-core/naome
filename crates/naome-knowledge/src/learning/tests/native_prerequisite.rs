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
        let budget = 8;
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
            let control = attempt(&second, None, seed, budget).unwrap();
            assert!(control.solution.is_none());
            let next = solve(&second, &required, &inputs, seed, budget).unwrap();
            eprintln!(
                "continuation without={} with={} expansions={}",
                control.diagnostic, next.diagnostic, next.cost.search_expansions
            );
            assert!(next.cost.search_expansions <= budget);
            let next = next
                .solution
                .unwrap_or_else(|| panic!("{}", next.diagnostic));
            continuation = Some((second, next, first_id));
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
