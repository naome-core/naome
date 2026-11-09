use super::*;
use crate::learning as native;

fn question() -> naome_checker::question::ResearchQuestion {
    naome_checker::question::ResearchQuestion::from_hex(&native::tests::own_question()).unwrap()
}
struct Ordered;
impl Ranker for Ordered {
    fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, crate::Error> {
        Ok(vec![0.; d.candidates.len()])
    }
}

#[test]
fn recording_preserves_actual_neural_choices_exploration_and_optimizer_bytes() {
    let q = question();
    let solution = native::tests::own_solution();
    let target = if solution.refuted {
        q.refuted_target()
    } else {
        q.proved_target()
    };
    let (_, graphs) = compile(target, &solution.tree).unwrap();
    assert!(!graphs.is_empty());
    let mut io = native::tests::MemoryStore::default();
    let checkpoint = native::model::test_update(
        &native::model::Checkpoint::fresh(),
        &graphs,
        &mut 71,
        &mut io,
    )
    .unwrap();
    let mut engine = native::Engine::default();
    let mut results = Vec::new();
    for capture in [false, true] {
        let result = engine
            .with(&checkpoint, &mut io, |runtime| {
                let mut ranker = native::Exploring {
                    model: runtime,
                    seed: 197,
                    explore: true,
                };
                let found = super::super::solve_recording(
                    target,
                    &mut ranker,
                    128,
                    Instant::now(),
                    &[],
                    capture,
                )?;
                Ok((found, ranker.seed))
            })
            .unwrap();
        assert_eq!(engine.snapshot(&checkpoint, &mut io).unwrap(), checkpoint);
        results.push(result);
    }
    let (plain, plain_rng) = &results[0];
    let (recorded, recorded_rng) = &results[1];
    assert_eq!(native::digest(&plain.tree), native::digest(&recorded.tree));
    assert_eq!(plain.expansions, recorded.expansions);
    assert_eq!(plain.terminal, recorded.terminal);
    assert_eq!(plain_rng, recorded_rng);
    assert!(plain.execution.is_none());
    let trace = recorded.execution.as_ref().unwrap();
    trace.validate_context(&q, &[]).unwrap();
    assert_eq!(trace.attempts, recorded.expansions);
    assert!(!trace.events.is_empty());
    let restored: Trace =
        crate::checkpoint::decode(&crate::checkpoint::encode(trace).unwrap()).unwrap();
    assert_eq!(&restored, trace);
}

#[test]
fn altered_state_action_scores_parent_or_work_are_rejected() {
    let q = question();
    let result = solve(q.proved_target(), &mut Ordered, 128).unwrap();
    let original = result.execution.unwrap();
    original.validate_context(&q, &[]).unwrap();
    assert!(!original.events.is_empty());
    for mutation in 0..6 {
        let mut trace = original.clone();
        match mutation {
            0 => trace.events[0].state = "f1".repeat(32),
            1 => trace.events[0].offered = "f1".repeat(32),
            2 => trace.events[0].selected = usize::MAX,
            3 => trace.events[0].parent = Some(Branch { event: 0, child: 0 }),
            4 => trace.events[0].end = trace.attempts + 1,
            _ => trace.events[0].ranks = Some(vec![f32::NAN.to_bits()]),
        }
        let error = trace.validate().unwrap_err();
        if mutation == 0 {
            assert_eq!(
                serde_json::to_value(&error).unwrap()["code"],
                u32::from(crate::ResearchFailure::TraceStateBinding)
            );
        }
    }
    let other =
        naome_checker::question::ResearchQuestion::from_hex("040101000000000100000000").unwrap();
    assert!(original.validate_context(&other, &[]).is_err());
}

#[test]
fn truncated_observations_keep_a_replayable_prefix_and_count_omitted_work() {
    let q = naome_checker::question::ResearchQuestion::from_hex(
        "04040304040401010000000201000000020101000000010100000000",
    )
    .unwrap();
    let result = solve(q.proved_target(), &mut Ordered, 256).unwrap();
    assert!(result.tree.is_none());
    let trace = result.execution.unwrap();
    trace.validate_context(&q, &[]).unwrap();
    assert!(
        trace.omitted > 0,
        "fixture must exceed the bounded observation prefix"
    );
    assert_eq!(trace.events.len() + trace.omitted, result.expansions);
    assert!(crate::checkpoint::encode(&trace).unwrap().len() <= BYTES);
    assert!(trace.events.iter().all(|event| !event.closed));
}

#[test]
fn a_closed_flag_cannot_replace_an_unrecorded_required_transition() {
    let q = naome_checker::question::ResearchQuestion::from_hex(
        "0404040303010100000002010000000201010000000101000000010303010100000001010000000101010000000001000000000301010000000201000000020101000000000100000000",
    ).unwrap();
    let found = solve(q.proved_target(), &mut Ordered, 128).unwrap();
    assert!(found.tree.is_some());
    let mut trace = found.execution.unwrap();
    assert!(trace.events.len() > 1);
    assert!(!trace.closed_subtrees().unwrap().is_empty());
    assert!(trace.events[0].closed);
    trace.events.truncate(1);
    trace.omitted = trace.attempts - trace.events.len();
    trace.validate_context(&q, &[]).unwrap();
    assert!(
        trace.closed_subtrees().unwrap().is_empty(),
        "missing checked transitions cannot be filled in"
    );
}

#[test]
fn theorem_context_binds_the_original_checked_packet_not_just_an_allowed_formula() {
    let axiom = naome_foundation::ZfcAxiom::Pairing;
    let term = native::calculus::axiom(naome_proof::ProofStep::ZfcAxiom(axiom)).unwrap();
    let checked = native::proof::verify(&term, &axiom.formula()).unwrap();
    let entry = native::knowledge::Entry {
        packet: native::evidence::pack(&checked).unwrap(),
    };
    let variable = FreeVariable::new(0);
    let target = Formula::implies(
        Formula::for_all(variable, Formula::equal(variable, variable)),
        axiom.formula(),
    );
    let q = naome_checker::question::ResearchQuestion::from_formula(target.clone()).unwrap();
    let found = solve_with_knowledge(
        &target,
        &mut Ordered,
        128,
        Instant::now(),
        std::slice::from_ref(&entry),
    )
    .unwrap();
    assert!(found.tree.is_some());
    let trace = found.execution.unwrap();
    trace
        .validate_context(&q, std::slice::from_ref(&entry))
        .unwrap();
    assert!(trace.validate_context(&q, &[]).is_err());
    let original_state = trace.states().unwrap().remove(0);
    let mut changed_state = original_state.clone();
    changed_state.knowledge_context[0] = "ff".repeat(32);
    assert_ne!(
        binding(&original_state).unwrap(),
        binding(&changed_state).unwrap(),
        "memory and graph keys bind the exact checked helper packet even when its formula is identical"
    );
    let mut substituted = trace.clone();
    substituted.root.as_mut().unwrap().knowledge[0].packet = "ff".repeat(32);
    assert!(
        substituted
            .validate_context(&q, std::slice::from_ref(&entry))
            .is_err()
    );
}

struct Distracted {
    goal_block: Formula,
}

impl Ranker for Distracted {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, crate::Error> {
        use naome_foundation::graph::Node;
        fn contains(formula: naome_foundation::FormulaView<'_>, goal: &Formula) -> bool {
            formula == goal.view()
                || match formula.graph_node() {
                    Node::Not(inner) => contains(inner, goal),
                    Node::Implies(left, right) => contains(left, goal) || contains(right, goal),
                    _ => false,
                }
        }
        let found_block = decision
            .context
            .iter()
            .any(|entry| entry.formula == self.goal_block);
        Ok(decision
            .candidates
            .iter()
            .map(|choice| {
                let reaches_goal = choice
                    .consequences
                    .iter()
                    .any(|result| contains(result.view(), &decision.goal));
                if found_block == reaches_goal { 1. } else { 0. }
            })
            .collect())
    }
}

#[test]
fn a_budgeted_detour_recovers_a_checked_decision_for_replay() {
    use native::experience::{ExperienceSummary, Observation, TraceBinding};
    let variables = (0..7).map(FreeVariable::new).collect::<Vec<_>>();
    let [a, _, c, d, e, f, g] = variables.as_slice() else {
        unreachable!()
    };
    let mut distractors = Vec::new();
    for (i, &left) in variables.iter().enumerate() {
        distractors.extend(
            variables[i + 1..]
                .iter()
                .map(|&right| Formula::negate(Formula::equal(left, right))),
        );
    }
    fn conjunction(parts: &[Formula]) -> Formula {
        if let [part] = parts {
            return part.clone();
        }
        let (left, right) = parts.split_at(parts.len() / 2);
        Formula::conjunction(conjunction(left), conjunction(right))
    }
    let distractor = conjunction(&distractors);
    let goal = Formula::member(*g, *a);
    let goal_block = Formula::conjunction(
        Formula::conjunction(Formula::member(*c, *d), Formula::member(*d, *e)),
        Formula::conjunction(Formula::member(*f, *g), goal.clone()),
    );
    let target = native::proof::close(Formula::implies(
        Formula::conjunction(distractor, goal_block.clone()),
        goal,
    ));
    let question = naome_checker::question::ResearchQuestion::from_formula(target.clone()).unwrap();
    struct Limited;
    impl Ranker for Limited {
        fn scores(&mut self, _: &Decision) -> Result<Vec<f32>, crate::Error> {
            Err(crate::Error::MemoryOverload {
                requested: 3,
                charged: 4,
                budget: 5,
            })
        }
    }
    assert!(matches!(
        solve(&target, &mut Limited, 48),
        Err(crate::Error::MemoryOverload {
            requested: 3,
            charged: 4,
            budget: 5
        })
    ));
    let found = solve(&target, &mut Distracted { goal_block }, 48).unwrap();
    let tree = found
        .tree
        .expect("the alternative closes within the original budget");
    assert!(found.expansions < 48);
    let trace = found.execution.unwrap();
    let repair = trace
        .repair
        .as_ref()
        .unwrap_or_else(|| panic!("no repair retained after {} expansions", found.expansions));
    let failed = &trace.events[repair.failed];
    assert_eq!(failed.start, 1);
    assert_eq!(failed.end, 16);
    assert!(!failed.closed);
    assert_ne!(failed.selected, repair.selected);
    assert_eq!(trace.attempts, found.expansions);

    let (term, _) = compile(&target, &tree).unwrap();
    let proof = native::construction::program_from_recipe(
        &target,
        native::proof::recipe(&term, &target).unwrap(),
    )
    .unwrap();
    assert_eq!(proof.packet.target().unwrap(), target);
    let proof_id = crate::hex(proof.packet.manifest.proof_id().as_bytes());
    let graph = trace
        .checked_repair(&target, &[])
        .unwrap()
        .expect("verified correction");
    assert_eq!(graph.binding, failed.state);
    assert_eq!(graph.successes, [repair.selected]);

    // Only the prefix through the failed decision is available from the
    // journal. The successful replay remains independently checkable.
    let mut prefix = trace.clone();
    prefix.events.truncate(repair.failed + 1);
    prefix.omitted = prefix.attempts - prefix.events.len();
    assert!(prefix.closed_subtrees().unwrap().is_empty());
    let make_observation = |trace: Trace| {
        let executions = vec![trace];
        let mut summary = ExperienceSummary {
            job: 1,
            question: crate::hex(question.resolution_id()),
            checkpoint: "01".repeat(32),
            policy: "02".repeat(32),
            request_binding: "03".repeat(32),
            native_context: "04".repeat(32),
            origin: native::Origin::Local,
            terminal: TerminalEvidence::CertifiedCandidate {
                proof_id: proof_id.clone(),
                refuted: false,
            },
            trace: TraceBinding {
                checked_trajectory: Some(native::digest(&Tree::Program(Box::new(
                    proof.packet.clone(),
                )))),
                observed_branches: None,
                observed_execution: Some(native::digest(&executions)),
            },
            cost: None,
            search_limit: 48,
            spent_ms: 0,
            reserved_units: 1,
            receipt: String::new(),
        };
        summary.receipt = native::digest(&summary);
        Observation {
            question: question.to_hex(),
            summary,
            executions,
            frontier: None,
            knowledge: Vec::new(),
        }
    };
    let bytes = crate::checkpoint::encode(&make_observation(prefix.clone())).unwrap();
    let restored: Observation = crate::checkpoint::decode(&bytes).unwrap();
    let mut pool = native::pool::Pool::default();
    pool.reconcile(&[restored], true).unwrap();
    assert_eq!(pool.derived_counts().repairs, 1);
    let batch = pool.batch(&mut 0);
    assert_eq!(batch.len(), 16);
    assert!(batch.iter().all(|example| example.key() == graph.key()));

    let mut forged = prefix;
    forged.repair.as_mut().unwrap().proof = serde_json::to_string(&Tree::Close(0, 0)).unwrap();
    let mut pool = native::pool::Pool::default();
    pool.reconcile(&[make_observation(forged)], true).unwrap();
    assert!(pool.is_empty(), "an unchecked replay cannot become a label");
}
