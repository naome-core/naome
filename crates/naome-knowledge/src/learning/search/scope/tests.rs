use super::*;
use crate::learning::{Checkpoint, Engine, Solution, SolveContext, proof, search_question_report};
use naome_checker::question::ResearchQuestion;

struct Ordered;
impl Ranker for Ordered {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, crate::Error> {
        Ok(vec![0.; decision.candidates.len()])
    }
}

fn transport() -> ResearchQuestion {
    let element = FreeVariable::new(60);
    let binder = FreeVariable::new(61);
    let [a, b, c, d, e, f] = [0, 1, 2, 3, 4, 5].map(FreeVariable::new);
    let rule = |from, to| {
        Formula::for_all(
            binder,
            Formula::implies(Formula::member(binder, from), Formula::member(binder, to)),
        )
    };
    let assumptions = [
        rule(a, b),
        rule(b, d),
        rule(a, c),
        rule(c, d),
        Formula::member(element, a),
        rule(a, e),
        rule(e, f),
        rule(f, d),
        Formula::equal(a, FreeVariable::new(13)),
    ];
    let formula = assumptions
        .into_iter()
        .rev()
        .fold(Formula::member(element, d), |body, a| {
            Formula::implies(a, body)
        });
    ResearchQuestion::from_formula(proof::close(formula)).unwrap()
}

fn solve(question: &ResearchQuestion, budget: usize) -> Option<Solution> {
    let context = SolveContext {
        native_programs: true,
        ..Default::default()
    };
    let mut engine = Engine::default();
    let mut io = crate::learning::tests::MemoryStore::default();
    let result = engine
        .with_error(&Checkpoint::fresh(), &mut io, |runtime| {
            search_question_report(&question.to_hex(), runtime, budget, &context)
        })
        .unwrap();
    assert!(result.cost.search_expansions <= budget);
    result.solution
}

fn isolated(name: &str) -> bool {
    crate::learning::tests::isolated(&format!("learning::search::scope::tests::{name}"))
}

#[test]
fn a_wide_transport_scope_pays_for_each_actual_step_and_replays_its_choice() {
    let question = transport();
    assert!(solve(&question, 1).is_none());
    let result = solve(&question, 2).expect("two supported scoped instantiations");
    let expected = question.clone();
    let independent = result.clone();
    std::thread::spawn(move || independent.check_target(&expected))
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(result.cost.search_expansions, 2);
    let Tree::Program(packet) = result.tree else {
        panic!("native deduction must produce a checked program");
    };
    let records = packet.commands().unwrap();
    assert!(records.iter().any(|command| matches!(
        command,
        Command::Deduce { assumptions, actions, .. }
            if assumptions.len() == 9 && actions.len() == 2
    )));
    let graphs = program_graphs(
        question.proved_target(),
        &records,
        &naome_checker::ArtifactState::default(),
    )
    .unwrap();
    assert_eq!(graphs.len(), 1);
    assert_eq!(graphs[0].candidates.len(), 2);
    assert_eq!(graphs[0].context.len(), 3);
}

#[test]
fn a_free_variable_does_not_hide_a_later_scoped_witness() {
    if !isolated("a_free_variable_does_not_hide_a_later_scoped_witness") {
        return;
    }
    let [a, b, c, d, witness] = [0, 1, 2, 3, 4].map(FreeVariable::new);
    let initial = Formula::member(a, b);
    let change_member = Formula::for_all(
        witness,
        Formula::implies(Formula::member(a, witness), Formula::member(c, witness)),
    );
    let change_set = Formula::for_all(
        witness,
        Formula::implies(Formula::member(witness, b), Formula::member(witness, d)),
    );
    let goal = Formula::conjunction(Formula::member(c, b), Formula::member(a, d));
    let formula = [change_member, change_set, initial]
        .into_iter()
        .rev()
        .fold(goal, |body, premise| Formula::implies(premise, body));
    let question = ResearchQuestion::from_formula(proof::close(formula)).unwrap();
    let context = SolveContext {
        native_programs: true,
        ..Default::default()
    };
    let attempt = |limit| search_question_report(&question.to_hex(), &mut Ordered, limit, &context);
    assert!(attempt(2).unwrap().solution.is_none());
    let result = attempt(3).unwrap();
    assert_eq!(result.cost.search_expansions, 3);
    let solution = result.solution.expect("both conjuncts must be proved");
    solution.check_target(&question).unwrap();
    let Tree::Program(packet) = solution.tree else {
        panic!("expected native scoped proof");
    };
    let records = packet.commands().unwrap();
    assert!(records.iter().any(|record| matches!(
        record,
        Command::Deduce { actions, .. }
            if matches!(actions.as_slice(), [
                ScopedAction::Instantiate { replacement: 1, .. },
                ScopedAction::Instantiate { .. },
                ScopedAction::Conjoin { .. }
            ])
    )));
    assert!(
        !program_graphs(
            question.proved_target(),
            &records,
            &naome_checker::ArtifactState::default()
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn a_valid_peer_deduction_can_include_an_action_the_local_policy_omits() {
    let question = transport();
    let target = question.proved_target();
    let scope = Scope::open(target).unwrap().unwrap();
    let (first, _) = scope.offers(&scope.assumptions);
    let ScopedAction::Instantiate {
        universal,
        replacement,
        ..
    } = first[0].0
    else {
        panic!("expected a matched local instance");
    };
    let (tree, _) = search(target, &mut Ordered, 2, Instant::now()).unwrap();
    let Some(Tree::Scoped { mut actions, .. }) = tree else {
        panic!("expected an ordinary bounded scope proof");
    };
    // Insert an independently legal bare instance before the selected proof.
    for action in &mut actions {
        if let ScopedAction::Instantiate { premises, .. } = action {
            for premise in premises {
                if *premise >= scope.assumptions.len() as u32 {
                    *premise += 1;
                }
            }
        }
    }
    let off_policy = ScopedAction::Instantiate {
        universal,
        replacement,
        premises: Vec::new(),
    };
    assert!(first.iter().all(|(action, _)| action != &off_policy));
    actions.insert(0, off_policy);
    let assumptions = scope
        .assumptions
        .iter()
        .cloned()
        .map(ProofFormula::from)
        .collect::<Vec<_>>();
    // Build the incoming peer program before local projection removes the
    // unused instance. The checker can accept a proof the model cannot replay.
    let records = Projection::scoped(
        &assumptions,
        &actions,
        (assumptions.len() + actions.len() - 1) as u32,
        &scope.binders,
    );
    assert_ne!(commands(target, &actions).unwrap(), records);
    let packet = crate::learning::peer::Packet::compose(target, &records, &[], []).unwrap();
    assert_eq!(&packet.target().unwrap(), target);
    assert!(
        program_graphs(target, &records, &naome_checker::ArtifactState::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_checked_prefix_unlocks_transport_beyond_one_scope() {
    use crate::learning::{Prerequisites, solve_with_report};
    let element = FreeVariable::new(30);
    let binder = FreeVariable::new(31);
    let mut target = Formula::member(element, FreeVariable::new(9));
    for index in (0..9).rev() {
        let left = Formula::member(binder, FreeVariable::new(index));
        let right = Formula::member(binder, FreeVariable::new(index + 1));
        target = Formula::implies(
            Formula::for_all(binder, Formula::implies(left, right)),
            target,
        );
    }
    target = Formula::implies(Formula::member(element, FreeVariable::new(0)), target);
    let goal = ResearchQuestion::from_formula(proof::close(target)).unwrap();
    assert!(solve(&goal, 32).is_none());

    let alternatives = cut::questions(goal.proved_target());
    assert!(alternatives.len() >= 2);
    let helper = &alternatives[1][0];
    let witness = solve(helper, 8).expect("an independently solvable cut");
    witness.check_target(helper).unwrap();
    let Tree::Program(packet) = witness.tree else {
        panic!("native witness program");
    };
    let proof_id = packet.manifest.proof_id();
    let prefix = cut::plan(goal.proved_target(), 1, |formula| {
        (formula == helper.proved_target()).then_some(proof_id)
    })
    .expect("the exact alternative transport prefix");
    let required = [crate::hex(proof_id.as_bytes())];
    let inputs = Prerequisites::from_inputs(Vec::new(), vec![*packet], None).unwrap();
    let mut engine = Engine::default();
    let mut io = crate::learning::tests::MemoryStore::default();
    let context = || SolveContext {
        required: &required,
        prerequisites: Some(&inputs),
        native_programs: true,
        ..Default::default()
    };
    let short = engine
        .with(&Checkpoint::fresh(), &mut io, |runtime| {
            solve_with_report(&goal.to_hex(), runtime, prefix.work() - 1, 1, context())
        })
        .unwrap();
    assert!(short.solution.is_none());
    let found = engine
        .with(&Checkpoint::fresh(), &mut io, |runtime| {
            solve_with_report(&goal.to_hex(), runtime, prefix.work(), 1, context())
        })
        .unwrap();
    assert_eq!(found.cost.search_expansions, 16);
    let root = found
        .solution
        .expect("a checked scoped proof using the prefix");
    let independent = root.clone();
    std::thread::spawn(move || independent.check_target(&goal))
        .join()
        .unwrap()
        .unwrap();
    let Tree::Program(root) = root.tree else {
        panic!("native composed program");
    };
    assert!(root.commands().unwrap().iter().any(|command| matches!(
        command, Command::ProofReference { proof_id: used } if used == proof_id.as_bytes()
    )));
}

#[test]
fn a_long_transport_requires_both_checked_segments_under_the_local_allowance() {
    use crate::learning::{Prerequisites, solve_with_report};
    if !isolated("a_long_transport_requires_both_checked_segments_under_the_local_allowance") {
        return;
    }
    let subject = FreeVariable::new(0);
    let binder = FreeVariable::new(40);
    let atom = |index: u32, point| {
        let object = FreeVariable::new(1 + index / 2);
        if index.is_multiple_of(2) {
            Formula::member(point, object)
        } else {
            Formula::equal(point, object)
        }
    };
    let target = (0..15).rev().fold(atom(15, subject), |body, index| {
        let step = Formula::for_all(
            binder,
            Formula::implies(atom(index, binder), atom(index + 1, binder)),
        );
        Formula::implies(step, body)
    });
    let goal =
        ResearchQuestion::from_formula(proof::close(Formula::implies(atom(0, subject), target)))
            .unwrap();
    assert!(solve(&goal, 32).is_none());
    let groups = cut::questions(goal.proved_target());
    let [group] = groups.as_slice() else {
        panic!("one serial transport route");
    };
    let [first, second] = group.as_slice() else {
        panic!("two independent segment questions");
    };
    let witness = |question: &ResearchQuestion| {
        let solution = solve(question, 5).expect("checked segment within one scope");
        solution.check_target(question).unwrap();
        let Tree::Program(packet) = solution.tree else {
            panic!("native checked segment");
        };
        *packet
    };
    let packets = [witness(first), witness(second)];
    let ids = packets.each_ref().map(|packet| packet.manifest.proof_id());
    let mut engine = Engine::default();
    let mut io = crate::learning::tests::MemoryStore::default();
    let mut run = |indices: &[usize], maximum| {
        let required = indices
            .iter()
            .map(|&i| crate::hex(ids[i].as_bytes()))
            .collect::<Vec<_>>();
        let packets = indices.iter().map(|&i| packets[i].clone()).collect();
        let inputs = Prerequisites::from_inputs(Vec::new(), packets, None).unwrap();
        engine
            .with(&Checkpoint::fresh(), &mut io, |runtime| {
                solve_with_report(
                    &goal.to_hex(),
                    runtime,
                    maximum,
                    1,
                    SolveContext {
                        required: &required,
                        prerequisites: Some(&inputs),
                        native_programs: true,
                        ..Default::default()
                    },
                )
            })
            .unwrap()
    };
    for one in [0, 1] {
        assert!(run(&[one], 32).solution.is_none());
    }
    assert!(run(&[0, 1], 21).solution.is_none());
    let result = run(&[1, 0], 22);
    assert_eq!(result.cost.search_expansions, 22);
    let solution = result.solution.expect("checked consumer of both segments");
    solution.check_target(&goal).unwrap();
    let Tree::Program(root) = solution.tree else {
        panic!("native serial transport");
    };
    let records = root.commands().unwrap();
    assert!(records.iter().any(|command| matches!(
        command,
        Command::Deduce { actions, .. } if actions.len() == 7
    )));
    let references = records
        .iter()
        .filter_map(|command| match command {
            Command::ProofReference { proof_id } => Some(*proof_id),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(references, ids.map(|id| *id.as_bytes()));
}

#[test]
fn scoped_program_applies_two_premises_in_one_checked_action() {
    struct NoModel;
    impl Ranker for NoModel {
        fn scores(&mut self, _: &Decision) -> Result<Vec<f32>, crate::Error> {
            Err("the applicable action closes without ranking".into())
        }
    }

    let [x, y, z] = [0, 1, 2].map(FreeVariable::new);
    let rule = Formula::for_all(
        y,
        Formula::implies(
            Formula::member(y, x),
            Formula::implies(Formula::equal(y, z), Formula::member(x, y)),
        ),
    );
    let target = Formula::for_all(
        x,
        Formula::for_all(
            z,
            Formula::implies(
                rule,
                Formula::implies(
                    Formula::member(z, x),
                    Formula::implies(Formula::equal(z, z), Formula::member(x, z)),
                ),
            ),
        ),
    );
    let (tree, work) = search(&target, &mut NoModel, 1, Instant::now()).unwrap();
    assert_eq!(work, 1);
    let Some(Tree::Scoped { actions, .. }) = tree else {
        panic!("the compound action must close the goal");
    };
    assert!(
        matches!(&actions[..], [ScopedAction::Instantiate { premises, .. }] if premises.len() == 2)
    );
    let commands = commands(&target, &actions).unwrap();
    let mut checker =
        naome_checker::program::Engine::open(rusqlite::Connection::open_in_memory().unwrap())
            .unwrap();
    checker.append_group(&commands).unwrap();
    while checker
        .advance(64, 32768, &naome_checker::ArtifactState::new())
        .unwrap()
    {}
    while !checker.prepare_export(64).unwrap() {}
    assert_eq!(checker.checked().unwrap().conclusion(), Some(&target));
}

#[test]
fn a_checked_witness_cut_discharges_a_wide_existential_goal() {
    if !isolated("a_checked_witness_cut_discharges_a_wide_existential_goal") {
        return;
    }
    use crate::learning::{Prerequisites, solve_with_report};

    let question = ResearchQuestion::from_hex(concat!(
        "0404040404040404030403010100000003010000000001010000000201000000000304030101000000070100000000",
        "0101000000000100000004030204020101000000070100000000030403010100000006010000000003010100000000",
        "0100000005010100000003010000000003040301010000000001000000050301010000000001000000040101000000",
        "0001000000010304030101000000080100000000010100000000010000000503020402010100000008010000000003",
        "0403010100000008010000000001010000000601000000000204020101000000020100000000",
    )).unwrap();
    let cross_witness = ResearchQuestion::from_hex(concat!(
        "0404040404040404030403010100000000010000000503010100000000010000000401010000000001000000010304",
        "0301010000000301000000000101000000000100000002030204020101000000070100000000030403010100000008",
        "0100000000010100000000010000000503040301010000000001000000060301010000000001000000040101000000",
        "0301000000000304030101000000080100000000010100000000010000000603040301010000000701000000000101",
        "0000000001000000040302040201010000000801000000000204020101000000030100000000",
    )).unwrap();
    assert!(cut::questions(cross_witness.proved_target()).is_empty());

    let target = question.proved_target();
    let groups = cut::questions(target);
    let [group] = groups.as_slice() else {
        panic!("expected one same-witness route");
    };
    let [helper] = group.as_slice() else {
        panic!("expected one helper in the route");
    };
    assert!(solve(&question, 32).is_none());
    let mut engine = Engine::default();
    let mut store = crate::learning::tests::MemoryStore::default();
    let generated = engine
        .with(&Checkpoint::fresh(), &mut store, |runtime| {
            solve_with_report(
                &helper.to_hex(),
                runtime,
                128,
                1,
                SolveContext {
                    native_programs: true,
                    ..Default::default()
                },
            )
        })
        .unwrap();
    let found = generated.solution.unwrap_or_else(|| {
        panic!(
            "the normal Solver must prove the smaller question: {:?} ({:?}) for {}",
            generated.diagnostic,
            generated.terminal,
            helper.to_hex()
        )
    });
    found.check_target(helper).unwrap();
    let Tree::Program(packet) = found.tree else {
        panic!("expected a native witness proof");
    };
    let id = packet.manifest.proof_id();
    let required = [crate::hex(id.as_bytes())];
    let cut = cut::plan(target, 1, |formula| {
        (formula == helper.proved_target()).then_some(id)
    })
    .expect("the exact checked witness is applicable");
    assert!(cut::plan(target, 1, |_| None).is_none());
    let work = cut.work();
    let inputs = Prerequisites::from_inputs(Vec::new(), vec![*packet], None).unwrap();
    let context = || SolveContext {
        required: &required,
        prerequisites: Some(&inputs),
        native_programs: true,
        ..Default::default()
    };
    let mut run = |limit| {
        engine
            .with(&Checkpoint::fresh(), &mut store, |runtime| {
                solve_with_report(&question.to_hex(), runtime, limit, 1, context())
            })
            .unwrap()
    };
    assert!(run(work - 1).solution.is_none());
    let result = run(work);
    assert_eq!(result.cost.search_expansions, work);
    let solution = result
        .solution
        .expect("the checked witness cut proves the original goal");
    solution.check_target(&question).unwrap();
    let Tree::Program(packet) = solution.tree else {
        panic!("expected a native proof using the cut");
    };
    let references = packet
        .commands()
        .unwrap()
        .into_iter()
        .filter_map(|command| match command {
            Command::ProofReference { proof_id } => Some(proof_id),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(references, [*id.as_bytes()]);
}

#[test]
fn scoped_search_preserves_ranker_resource_failure() {
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
    let [x, y] = [0, 1].map(FreeVariable::new);
    let scope = Scope {
        binders: Vec::new(),
        assumptions: vec![Formula::for_all(x, Formula::member(x, y))],
        goal: Formula::equal(x, y),
    };
    let (offers, _) = scope.offers(&scope.assumptions);
    assert!(offers.len() > 1 && offers[0].1 != scope.goal);
    assert!(matches!(
        search_scope(&scope, &mut Limited, 2, Instant::now()),
        Err(crate::Error::MemoryOverload {
            requested: 3,
            charged: 4,
            budget: 5
        })
    ));
}

#[test]
fn invalid_scoped_result_has_registered_failure() {
    let error = deduce(&[], &[], 0).err().unwrap();
    assert_eq!(
        serde_json::to_value(error).unwrap()["code"],
        u32::from(crate::ResearchFailure::ScopeResultOrder)
    );
}
