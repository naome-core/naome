use super::{replay::replay_choices, *};
use crate::learning::solve_with_report_typed;

/// A direct, checked route fits in two typed actions. Following the first
/// rule of the alternative chain spends a third action before closure.
fn shortcut_question(edges: u32, equal_goal: bool, reverse: bool) -> ResearchQuestion {
    let x = FreeVariable::new(30);
    let a = FreeVariable::new(31);
    let atom = |element, index| {
        let set = FreeVariable::new(index);
        if equal_goal && index == edges {
            Formula::equal(element, set)
        } else {
            Formula::member(element, set)
        }
    };
    let rule = |from, to| Formula::for_all(x, Formula::implies(atom(x, from), atom(x, to)));
    let facts = (0..edges)
        .map(|index| rule(index, index + 1))
        .chain([rule(0, edges), atom(a, 0)])
        .collect::<Vec<_>>();
    let [mut left, mut right] = [atom(a, edges), atom(a, 0)];
    if reverse {
        std::mem::swap(&mut left, &mut right);
    }
    let target = facts
        .into_iter()
        .rev()
        .fold(Formula::conjunction(left, right), |rest, premise| {
            Formula::implies(premise, rest)
        });
    ResearchQuestion::from_formula(proof::close(target)).unwrap()
}

#[test]
#[ignore = "bounded paired observation of weight transfer from checked native replay"]
fn checked_decoder_replay_weight_transfer() {
    let mut graphs = Vec::new();
    let mut state = crate::learning::State::fresh();
    let mut evidence = Vec::new();
    for edges in [2, 3] {
        let question = shortcut_question(edges, false, false);
        let scope = Scope::decompose(question.proved_target(), None).unwrap();
        let (goal, _) = crate::learning::conjunction_operands(&scope.goal).unwrap();
        let universal = edges as usize;
        let rule = instantiation::Universal::new(&scope.assumptions[universal]).unwrap();
        let variable = rule
            .applications(&scope.assumptions, FreeVariable::new(0))
            .find_map(|(premise, variable)| {
                (premise == universal + 1 && rule.consequence(variable).as_ref() == Some(&goal))
                    .then_some(variable)
            })
            .unwrap();
        let actions = [
            ScopedAction::Instantiate {
                universal: edges,
                replacement: variable.identifier(),
                premises: vec![edges + 1],
            },
            ScopedAction::Conjoin {
                left: scope.assumptions.len() as u32,
                right: edges + 1,
            },
        ];
        let commands = scope.program(&actions, &[]).unwrap();
        let packet = Packet::compose(question.proved_target(), &commands, &[], []).unwrap();
        let checked = replay_choices(&question, &packet, &naome_checker::ArtifactState::new());
        assert!(checked.iter().any(|g| g.candidates.len() > 1));
        graphs.extend(checked);
        let proof_id = crate::hex(packet.manifest.proof_id().as_bytes());
        let tree = Tree::Program(Box::new(packet));
        let job = u64::from(edges);
        evidence.push(crate::learning::Evidence {
            job,
            proof_id: proof_id.clone(),
            trace: tree.clone(),
        });
        assert!(
            state
                .accept(crate::learning::Example {
                    origin: crate::learning::Origin::Local,
                    job,
                    question: question.to_hex(),
                    proof_id,
                    refuted: false,
                    tree,
                })
                .unwrap()
        );
    }
    let pool = state.training_pool(&evidence).unwrap();
    assert!(
        graphs
            .iter()
            .all(|graph| pool.graphs().iter().any(|row| row.key() == graph.key()))
    );

    let mut io = MemoryStore::default();
    let before = Checkpoint::fresh();
    let mut after = before.clone();
    let mut cursor = 91;
    let mut trainer = Engine::default();
    let phase = crate::learning::meta::Plan::targeted().phase(0);
    const UNITS: u64 = 4;
    for _ in 0..UNITS {
        after = trainer
            .train_replay_using(
                &after,
                &state,
                (&evidence, &[]),
                &mut cursor,
                phase,
                &mut io,
            )
            .unwrap()
            .unwrap()
            .0;
    }
    assert_eq!(
        state.model, before,
        "candidate training must preserve the serving checkpoint"
    );
    assert_eq!(
        after.updates,
        before.updates + UNITS * crate::learning::model::UPDATES_PER_UNIT
    );
    assert!(after.model.is_some() && after.optimizer.is_some());

    let mut engine = Engine::default();
    let mut counts = [0; 3];
    for (edges, equality, reverse) in [
        (2, true, false),
        (2, true, true),
        (3, true, false),
        (3, true, true),
        (4, false, true),
        (4, true, true),
    ] {
        let question = shortcut_question(edges, equality, reverse);
        let context = || SolveContext {
            native_programs: true,
            ..Default::default()
        };
        let neutral = attempt(
            question.proved_target(),
            &mut Ordered,
            2,
            Instant::now(),
            &context(),
            None,
        )
        .unwrap()
        .0;
        if let Some(candidate) = &neutral {
            assert_eq!(
                candidate.packet.target().unwrap(),
                *question.proved_target()
            );
        }
        let mut solved = [neutral.is_some(), false, false];
        for (index, checkpoint) in [&before, &after].into_iter().enumerate() {
            let result = engine
                .with_error(checkpoint, &mut io, |runtime| {
                    solve_with_report_typed(&question.to_hex(), runtime, 2, 1, context())
                })
                .unwrap();
            assert!(result.cost.search_expansions <= 2);
            if let Some(solution) = result.solution {
                solution.check_target(&question).unwrap();
                solved[index + 1] = true;
            }
        }
        for (count, success) in counts.iter_mut().zip(solved) {
            *count += usize::from(success);
        }
        eprintln!(
            "transfer edges={edges} equality={equality} reverse={reverse} checked_neutral_before_after={solved:?}"
        );
    }
    let base = state;
    assert_eq!(base.model, before);
    let mut protected = [0; 2];
    let mut losses = Vec::new();
    for (index, case) in crate::learning::curriculum::development()
        .into_iter()
        .take(crate::learning::curriculum::CORPUS_DEVELOPMENT)
        .enumerate()
    {
        let result = crate::learning::transfer::evaluate(
            &case.source,
            &base,
            &after,
            &mut engine,
            &mut io,
            10_000 + index as u64,
        )
        .unwrap();
        protected[0] += usize::from(result.before.solved);
        protected[1] += usize::from(result.after.solved);
        if result.before.solved && !result.after.solved {
            losses.push(case.id.clone());
        }
    }
    eprintln!("protected paired qualification before/after={protected:?} losses={losses:?}");
    eprintln!(
        "typed replay: {} checked graphs, fresh verified outcomes neutral/before/after={counts:?}",
        graphs.len()
    );
}
