use super::*;
use crate::learning::{
    Checkpoint, Engine, Generation, Prerequisites, Solution, experience, program::Candidate,
    solve_with_generation, solve_with_report_typed, tests::MemoryStore,
};
use naome_checker::question::ResearchQuestion;
use naome_proof::{DefinedFormula, DefinitionCertificate, DefinitionKind};

fn transport_pair() -> ResearchQuestion {
    let [a, b, source, destination, x] = [0, 1, 2, 3, 4].map(FreeVariable::new);
    let before = |element| Formula::member(element, source);
    let after = |element| Formula::member(element, destination);
    let rule = Formula::for_all(x, Formula::implies(before(x), after(x)));
    let goal = Formula::conjunction(
        Formula::conjunction(after(a), before(a)),
        Formula::conjunction(after(b), before(b)),
    );
    let target = [rule, before(a), before(b)]
        .into_iter()
        .rev()
        .fold(goal, |goal, assumption| Formula::implies(assumption, goal));
    ResearchQuestion::from_formula(proof::close(target)).unwrap()
}

fn member_relation() -> definitions::Entry {
    let [element, set] = [0, 1].map(FreeVariable::new);
    let certificate = DefinitionCertificate::new(
        DefinitionKind::Relation { arity: 2 },
        DefinedFormula::from_primitive(&Formula::member(element, set)).unwrap(),
    )
    .unwrap();
    definitions::Entry {
        certificate: certificate.to_canonical_bytes(),
        obligation: None,
    }
}

fn paired(
    question: &ResearchQuestion,
    budget: usize,
    definitions: &[definitions::Entry],
    inputs: Option<&Prerequisites>,
    theorems: &[knowledge::Entry],
) -> (Generation, Generation) {
    let mut engine = Engine::default();
    let mut io = MemoryStore::default();
    let checkpoint = Checkpoint::fresh();
    let source = question.to_hex();
    let context = || SolveContext {
        native_programs: true,
        definitions,
        prerequisites: inputs,
        theorems,
        ..Default::default()
    };
    // Load the same frozen checkpoint before timing either arm.
    engine.with_error(&checkpoint, &mut io, |_| Ok(())).unwrap();
    let baseline = engine
        .with_error(&checkpoint, &mut io, |runtime| {
            solve_with_generation(&source, runtime, budget, 1, context(), false)
        })
        .unwrap();
    let generated = engine
        .with_error(&checkpoint, &mut io, |runtime| {
            solve_with_report_typed(&source, runtime, budget, 1, context())
        })
        .unwrap();
    for (arm, result) in [("existing", &baseline), ("typed", &generated)] {
        assert!(result.cost.search_expansions <= budget);
        if let Some(solution) = &result.solution {
            solution.check_target(question).unwrap();
        }
        eprintln!(
            "{arm} budget={budget} solved={} expansions={} typed_model_decisions={} generation_micros={}",
            result.solution.is_some(),
            result.cost.search_expansions,
            result
                .cost
                .typed_generation
                .map_or(0, |work| work.model_decisions),
            result.cost.generation_micros,
        );
    }
    (baseline, generated)
}

fn independent_replay(
    question: &ResearchQuestion,
    solution: &Solution,
    context: &dyn ContextView,
) -> Vec<Command> {
    let candidate = Candidate::from_solution(solution, question).unwrap();
    let bytes = naome_proof::program::encode_records(&candidate.commands).unwrap();
    let mut checker =
        naome_checker::program::Engine::open(rusqlite::Connection::open_in_memory().unwrap())
            .unwrap();
    let commands = naome_proof::program::decode_records(&bytes).unwrap();
    checker.append_group(&commands).unwrap();
    let mut work = 0;
    while checker.advance(64, 32768, context).unwrap() {
        work += checker.last_quantum_steps();
    }
    work += checker.last_quantum_steps();
    while !checker.prepare_export(64).unwrap() {}
    let proof = checker.checked().unwrap();
    assert_eq!(proof.manifest(), &candidate.manifest);
    assert_eq!(proof.conclusion(), Some(question.proved_target()));
    question.classify_checked_program(&proof).unwrap();
    eprintln!(
        "native commands={} bytes={} checker_steps={work}",
        proof.manifest().commands,
        proof.manifest().input_bytes
    );
    commands
}

#[test]
fn native_solver_composes_nested_conjunctions_outside_the_original_menu() {
    let question = transport_pair();
    let definitions = [member_relation()];
    let (baseline, generated) = paired(&question, 5, &definitions, None, &[]);
    assert!(baseline.solution.is_none());
    let work = generated.cost.typed_generation.unwrap();
    assert_eq!(work.actions, 5);
    assert!(work.model_decisions >= 2);
    let solution = generated.solution.expect("generated proof");
    let context = definitions::context(&definitions).unwrap();
    let commands = independent_replay(&question, &solution, &context);
    let scope = Scope::open(question.proved_target()).unwrap().unwrap();
    let actions = commands
        .iter()
        .find_map(|command| match command {
            Command::Deduce { actions, .. } => Some(actions),
            _ => None,
        })
        .unwrap();
    assert_eq!(actions.len(), 5);
    assert!(actions.iter().any(
        |action| matches!(action, ScopedAction::Instantiate { premises, .. } if premises.len() == 1)
    ));
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, ScopedAction::Conjoin { .. }))
            .count(),
        3
    );
    let mut facts = scope.assumptions.clone();
    let mut novel = 0;
    for action in actions {
        let result = scope.apply(&facts, action).unwrap();
        if result != scope.goal && matches!(action, ScopedAction::Conjoin { .. }) {
            let (offered, _) = scope.offers(&facts);
            assert!(offered.iter().all(|(candidate, _)| candidate != action));
            novel += 1;
        }
        facts.push(result);
    }
    assert_eq!(novel, 2);

    // Isolate the model's influence on the path from the new grammar's
    // influence on reachability. Both runs have the same typed continuations.
    let (ordered, ordered_work) = attempt(
        question.proved_target(),
        &mut Ordered,
        5,
        Instant::now(),
        &SolveContext {
            definitions: &definitions,
            ..Default::default()
        },
    )
    .unwrap();
    let ordered = ordered.unwrap().packet;
    assert_eq!(ordered.target().unwrap(), *question.proved_target());
    assert_eq!(ordered_work.actions, work.actions);
    eprintln!(
        "ordered and neural program hashes differ={}",
        ordered.manifest.program_hash
            != Candidate::from_solution(&solution, &question)
                .unwrap()
                .manifest
                .program_hash
    );
    let definition_id = definitions[0].certificate().unwrap().definition_id();
    assert!(commands.iter().any(|command| matches!(command, Command::DefinedRelation { definition_id: id, arguments } if id == definition_id.as_bytes() && arguments.len() == 2)));

    let mut invalid = commands;
    let arguments = invalid
        .iter_mut()
        .find_map(|command| match command {
            Command::DefinedRelation { arguments, .. } => Some(arguments),
            _ => None,
        })
        .unwrap();
    arguments.pop();
    let artifact = crate::unhex(&definitions[0].artifact().unwrap()).unwrap();
    let error =
        Packet::compose(question.proved_target(), &invalid, &[], [artifact.into()]).unwrap_err();
    use naome_checker::diagnostics::{ExpansionFailure, Failure};
    assert!(
        matches!(
            &error,
            crate::Error::Proof(diagnostic) if matches!(
                diagnostic.failure,
                Failure::Expansion { reason: ExpansionFailure::ArityMismatch { expected: 2, actual: 1, .. } }
            )
        ),
        "{error}"
    );

    let (_, standard) = paired(&question, 128, &definitions, None, &[]);
    assert_eq!(standard.cost.typed_generation.unwrap().actions, 5);
    assert!(standard.solution.is_some());

    let (_, exhausted) = paired(&question, 4, &definitions, None, &[]);
    assert!(exhausted.solution.is_none());
    assert_eq!(exhausted.cost.search_expansions, 4);
    assert_eq!(exhausted.cost.typed_generation.unwrap().actions, 4);
    assert!(matches!(
        exhausted.terminal,
        experience::TerminalEvidence::Budget(experience::Budget::Expansions)
    ));
}

fn reflexivity(alias: bool) -> (Formula, Packet) {
    let x = FreeVariable::new(0);
    let formula = Formula::for_all(x, Formula::equal(x, x));
    let mut commands = vec![
        Command::Reflexivity { variable: 0 },
        Command::Generalization {
            premise: 0,
            variable: 0,
        },
    ];
    if alias {
        commands.push(Command::Alias { input: 1 });
    }
    commands.push(Command::Seal {
        proof: commands.len() as u64 - 1,
    });
    let packet = Packet::compose(&formula, &commands, &[], []).unwrap();
    (formula, packet)
}

#[test]
fn native_solver_resolves_new_checked_proofs_and_fixed_axioms_from_context() {
    let (reflexive, first) = reflexivity(false);
    let (_, second) = reflexivity(true);
    assert_ne!(first.manifest.proof_id(), second.manifest.proof_id());
    let axiom = Axiom::Pairing;
    let axiom_formula = naome_foundation::ZfcAxiom::from(axiom).formula();
    let target = Formula::conjunction(
        Formula::conjunction(reflexive, axiom_formula.clone()),
        axiom_formula,
    );
    let question = ResearchQuestion::from_formula(target).unwrap();

    for proof in [first, second] {
        let id = proof.manifest.proof_id();
        let inputs = Prerequisites::from_inputs(Vec::new(), vec![proof], None).unwrap();
        let (baseline, generated) = paired(&question, 2, &[], Some(&inputs), &[]);
        assert!(baseline.solution.is_none());
        let context = inputs.checked_program_inputs().unwrap();
        let commands =
            independent_replay(&question, &generated.solution.unwrap(), &context.context);
        assert!(commands.contains(&Command::ProofReference {
            proof_id: *id.as_bytes()
        }));
        assert!(commands.contains(&Command::Axiom { axiom }));

        // A changed ID cannot gain authority from the generator's context slots.
        let mut invalid = commands;
        let reference = invalid
            .iter_mut()
            .find(|command| matches!(command, Command::ProofReference { .. }))
            .unwrap();
        *reference = Command::ProofReference {
            proof_id: [255; 32],
        };
        let error =
            Packet::compose(question.proved_target(), &invalid, context.programs, []).unwrap_err();
        assert!(
            matches!(
                &error,
                crate::Error::Proof(diagnostic)
                    if matches!(diagnostic.failure, naome_checker::diagnostics::Failure::MissingProof { .. })
            ),
            "{error}"
        );
    }
}

struct Malformed;
impl Ranker for Malformed {
    fn scores(&mut self, _: &Decision) -> Result<Vec<f32>, crate::Error> {
        Ok(vec![f32::NAN])
    }
}

#[test]
fn invalid_model_output_does_not_select_a_fact_or_argument() {
    let question = transport_pair();
    let error = attempt(
        question.proved_target(),
        &mut Malformed,
        5,
        Instant::now(),
        &SolveContext::default(),
    )
    .err()
    .expect("invalid choice scores");
    assert_eq!(error, crate::ResearchFailure::ScopeInvalidScores.into());
}

struct Ordered;
impl Ranker for Ordered {
    fn scores(&mut self, decision: &Decision) -> Result<Vec<f32>, crate::Error> {
        Ok(vec![0.; decision.candidates.len()])
    }
}

#[test]
fn certified_proof_addresses_resolve_in_both_solver_contexts() {
    let variable = FreeVariable::new(0);
    let certificate = naome_proof::ProofCertificate::new(vec![
        naome_proof::ProofStep::EqualityReflexivity { variable },
        naome_proof::ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
    .unwrap();
    let checked = proof::check(certificate.clone(), &naome_checker::ArtifactState::new()).unwrap();
    let binary = crate::object::BinaryArtifact::from_checked(&checked).unwrap();
    let prerequisite = Prerequisites::new(vec![binary.envelope()]).unwrap();
    let verified = proof::verify_native(
        certificate,
        Vec::new(),
        Vec::new(),
        Some(checked.conclusion()),
    )
    .unwrap();
    let theorem = [knowledge::Entry {
        packet: crate::learning::evidence::pack(&verified).unwrap(),
    }];
    let axiom = naome_foundation::ZfcAxiom::Pairing.formula();
    let goal =
        ResearchQuestion::from_formula(Formula::conjunction(checked.conclusion().clone(), axiom))
            .unwrap();

    let mut context = naome_checker::ArtifactState::new();
    let reference = Command::ProofReference {
        proof_id: *checked.proof_id().as_bytes(),
    };
    context.register_proof(checked).unwrap();
    for (inputs, entries) in [(Some(&prerequisite), &[][..]), (None, &theorem[..])] {
        let (_, generated) = paired(&goal, 1, &[], inputs, entries);
        let commands = independent_replay(&goal, &generated.solution.unwrap(), &context);
        assert!(commands.contains(&reference));
    }
}
