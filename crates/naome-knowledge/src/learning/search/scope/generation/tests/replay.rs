use super::*;

#[test]
fn typed_subgoals_unlock_a_two_rule_chain_at_the_same_budget() {
    if !crate::learning::tests::isolated(
        "learning::search::scope::generation::tests::replay::typed_subgoals_unlock_a_two_rule_chain_at_the_same_budget",
    ) {
        return;
    }
    let [s, t, u, a, b, x] = [0, 1, 2, 3, 4, 5].map(FreeVariable::new);
    let rule = |from, to| {
        Formula::for_all(
            x,
            Formula::implies(Formula::member(x, from), Formula::member(x, to)),
        )
    };
    let pair = |v| Formula::conjunction(Formula::member(v, s), Formula::member(v, u));
    let target = [
        rule(s, t),
        rule(t, u),
        Formula::member(a, s),
        Formula::member(b, s),
    ]
    .into_iter()
    .rev()
    .fold(Formula::conjunction(pair(a), pair(b)), |goal, premise| {
        Formula::implies(premise, goal)
    });
    let question = ResearchQuestion::from_formula(proof::close(target)).unwrap();
    let (existing, typed) = paired(&question, 7, &[], None, &[]);
    assert!(existing.solution.is_none());
    assert_eq!(typed.cost.typed_generation.unwrap().actions, 7);
    let solution = typed
        .solution
        .expect("two independently checked two-step chains");
    let commands = independent_replay(&question, &solution, &naome_checker::ArtifactState::new());
    let actions = commands
        .iter()
        .find_map(|command| match command {
            Command::Deduce { actions, .. } => Some(actions),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        actions
            .iter()
            .filter(
                |a| matches!(a, ScopedAction::Instantiate { premises, .. } if premises.len() == 1)
            )
            .count(),
        4
    );
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, ScopedAction::Conjoin { .. }))
            .count(),
        3
    );
    let Tree::Program(packet) = solution.tree else {
        panic!("expected canonical proof");
    };
    assert!(!replay_choices(&question, &packet, &naome_checker::ArtifactState::new()).is_empty());
}

pub(super) fn replay_choices(
    question: &ResearchQuestion,
    packet: &Packet,
    state: &dyn ContextView,
) -> Vec<Graph> {
    use naome_checker::program::Engine as Checker;
    let commands = packet.commands().unwrap();
    let mut checker = Checker::open(rusqlite::Connection::open_in_memory().unwrap()).unwrap();
    checker.append_group(&commands).unwrap();
    while checker.advance(64, 32768, state).unwrap() {}
    while !checker.prepare_export(64).unwrap() {}
    let proof = checker.checked().unwrap();
    proof.check_manifest(&packet.manifest).unwrap();
    assert_eq!(proof.conclusion(), Some(question.proved_target()));
    crate::learning::search::scope::typed_program_graphs(
        &proof,
        question.proved_target(),
        &commands,
        &vec![true; commands.len()],
    )
    .unwrap()
}

#[test]
fn graph_lemmas_feed_checked_decoder_replay_and_the_training_pool_after_reload() {
    if !crate::learning::tests::isolated(
        "learning::search::scope::generation::tests::replay::graph_lemmas_feed_checked_decoder_replay_and_the_training_pool_after_reload",
    ) {
        return;
    }
    fn reflexive(binders: u32) -> naome_checker::CheckedProof {
        let mut steps = vec![naome_proof::ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(0),
        }];
        for variable in (0..binders).rev() {
            steps.push(naome_proof::ProofStep::Generalization {
                premise: steps.len() as u32 - 1,
                variable: FreeVariable::new(variable),
            });
        }
        proof::check(
            naome_proof::ProofCertificate::new(steps).unwrap(),
            &naome_checker::ArtifactState::new(),
        )
        .unwrap()
    }
    let lemmas = [reflexive(2), reflexive(3)];
    let target = Formula::conjunction(
        Formula::conjunction(
            lemmas[0].conclusion().clone(),
            naome_foundation::ZfcAxiom::Pairing.formula(),
        ),
        Formula::conjunction(
            lemmas[1].conclusion().clone(),
            naome_foundation::ZfcAxiom::Union.formula(),
        ),
    );
    let question = ResearchQuestion::from_formula(target).unwrap();
    let mut graph = crate::Graph::default();
    let directory = crate::checkpoint::tests::Directory::new();
    let frontier = crate::frontier::Frontier::open(
        &directory.0,
        &graph,
        7,
        crate::jobs::Settings {
            native_proof_learning: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        frontier
            .solving_inputs(&graph, &question, &[])
            .unwrap()
            .1
            .is_empty()
    );
    for lemma in &lemmas {
        graph
            .ingest(
                crate::object::BinaryArtifact::from_checked(lemma)
                    .unwrap()
                    .envelope(),
                Instant::now(),
            )
            .unwrap();
    }
    let (required, inputs) = frontier.solving_inputs(&graph, &question, &[]).unwrap();
    assert!(required.is_empty());
    let inputs: Prerequisites =
        serde_json::from_slice(&serde_json::to_vec(&inputs).unwrap()).unwrap();
    let (_, generated) = paired(&question, 3, &[], Some(&inputs), &[]);
    assert_eq!(generated.cost.typed_generation.unwrap().actions, 3);
    let solution = generated
        .solution
        .expect("two newly indexed lemmas are available to the solver");
    let commands = independent_replay(&question, &solution, graph.checked_context());
    for lemma in &lemmas {
        assert!(commands.contains(&Command::ProofReference {
            proof_id: *lemma.proof_id().as_bytes()
        }));
    }
    let Tree::Program(packet) = &solution.tree else {
        panic!("expected a native proof");
    };
    let decisions = replay_choices(&question, packet, graph.checked_context());
    assert!(decisions.iter().any(|graph| graph.candidates.len() > 1));
    let observed = crate::learning::digest(&decisions);
    let restored: Packet = serde_json::from_slice(&serde_json::to_vec(packet).unwrap()).unwrap();
    let q = question.clone();
    let replayed = std::thread::spawn(move || {
        let recovered = inputs.checked_program_inputs().unwrap();
        replay_choices(&q, &restored, &recovered.context)
    })
    .join()
    .unwrap();
    assert_eq!(crate::learning::digest(&replayed), observed);
    let evidence = [crate::learning::Evidence {
        job: 1,
        proof_id: solution.proof_id.clone(),
        trace: solution.tree.clone(),
    }];
    let mut state = crate::learning::State::fresh();
    assert!(
        state
            .accept(crate::learning::Example {
                origin: crate::learning::Origin::Local,
                job: 1,
                question: question.to_hex(),
                proof_id: solution.proof_id,
                refuted: false,
                tree: solution.tree,
            })
            .unwrap()
    );
    let (state, evidence): (crate::learning::State, [crate::learning::Evidence; 1]) =
        serde_json::from_slice(&serde_json::to_vec(&(state, evidence)).unwrap()).unwrap();
    let mut tampered = evidence.clone();
    let Tree::Program(packet) = &mut tampered[0].trace else {
        panic!("expected native evidence");
    };
    packet.manifest.program_hash[0] ^= 1;
    assert!(state.training_pool(&tampered).is_err());
    let pool = state.training_pool(&evidence).unwrap();
    assert!(
        decisions
            .iter()
            .all(|g| pool.graphs().iter().any(|row| row.key() == g.key()))
    );
}

#[test]
fn checked_specialization_reuses_a_variable_without_capture() {
    if !crate::learning::tests::isolated(
        "learning::search::scope::generation::tests::replay::checked_specialization_reuses_a_variable_without_capture",
    ) {
        return;
    }
    let [from, to, set] = [0, 1, 2].map(FreeVariable::new);
    let mut steps = vec![naome_proof::ProofStep::EqualitySubstitution {
        from,
        to,
        body: Formula::member(from, set).into(),
    }];
    for variable in [set, to, from] {
        steps.push(naome_proof::ProofStep::Generalization {
            premise: steps.len() as u32 - 1,
            variable,
        });
    }
    let checked = proof::check(
        naome_proof::ProofCertificate::new(steps).unwrap(),
        &naome_checker::ArtifactState::new(),
    )
    .unwrap();
    let id = checked.proof_id();
    let mut graph = crate::Graph::default();
    graph
        .ingest(
            crate::object::BinaryArtifact::from_checked(&checked)
                .unwrap()
                .envelope(),
            Instant::now(),
        )
        .unwrap();
    let [a, source] = [5, 6].map(FreeVariable::new);
    let assumption = Formula::member(a, source);
    let specialized = Formula::implies(
        Formula::equal(a, a),
        Formula::implies(assumption.clone(), assumption.clone()),
    );
    let target = proof::close(Formula::implies(
        assumption.clone(),
        Formula::conjunction(specialized, assumption),
    ));
    let question = ResearchQuestion::from_formula(target).unwrap();
    let inputs = graph
        .scoped_solving_inputs(&question)
        .unwrap()
        .expect("indexed specialization");
    assert!(!inputs.has_offer());
    let (_, generated) = paired(&question, 4, &[], Some(&inputs), &[]);
    let solution = generated
        .solution
        .expect("three capture-safe instantiations and a conjunction");
    assert_eq!(solution.cost.typed_generation.unwrap().actions, 4);
    let commands = independent_replay(&question, &solution, graph.checked_context());
    assert!(commands.contains(&Command::ProofReference {
        proof_id: *id.as_bytes()
    }));
    let actions = commands
        .iter()
        .find_map(|command| match command {
            Command::Deduce { actions, .. } => Some(actions),
            _ => None,
        })
        .unwrap();
    let replacements: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            ScopedAction::Instantiate { replacement, .. } => Some(*replacement),
            _ => None,
        })
        .collect();
    assert_eq!(replacements.len(), 3);
    assert_eq!(replacements[0], replacements[1]);
}
