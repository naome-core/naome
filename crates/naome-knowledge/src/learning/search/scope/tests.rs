use super::*;
use crate::learning::{Checkpoint, Engine, Solution, SolveContext, proof, search_question_report};
use naome_checker::question::ResearchQuestion;

struct Ordered;
impl Ranker for Ordered {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, String> {
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
        .with(&Checkpoint::fresh(), &mut io, |runtime| {
            search_question_report(&question.to_hex(), runtime, budget, &context)
        })
        .unwrap();
    assert!(result.cost.search_expansions <= budget);
    result.solution
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
    let graphs = program_graphs(question.proved_target(), &records).unwrap();
    assert_eq!(graphs.len(), 1);
    assert_eq!(graphs[0].candidates.len(), 2);
    assert_eq!(graphs[0].context.len(), 3);
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
    actions.insert(
        0,
        ScopedAction::Instantiate {
            universal,
            replacement,
            premises: Vec::new(),
        },
    );
    let records = commands(target, &actions).unwrap();
    let packet = crate::learning::peer::Packet::compose(target, &records, &[], []).unwrap();
    assert_eq!(&packet.target().unwrap(), target);
    assert!(program_graphs(target, &records).unwrap().is_empty());
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
    let helper = &alternatives[1];
    let prefix = cut::plan(goal.proved_target(), helper.proved_target())
        .expect("the exact alternative transport prefix");
    let witness = solve(helper, 8).expect("an independently solvable cut");
    witness.check_target(helper).unwrap();
    let Tree::Program(packet) = witness.tree else {
        panic!("native witness program");
    };
    let proof_id = packet.manifest.proof_id();
    let required = [crate::hex(proof_id.as_bytes())];
    let inputs = Prerequisites::from_inputs(Vec::new(), vec![*packet]).unwrap();
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
