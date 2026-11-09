use super::*;

#[tokio::test]
async fn accepted_peer_work_alternates_with_owned_work_and_does_not_enter_backlog() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let own = ResearchQuestion::from_hex(&mocks::create_question(0)).unwrap();
    let peer_question = ResearchQuestion::from_hex(&mocks::create_question(1)).unwrap();
    admitted(&mut questions, &graph, &own).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![own.clone()],
    );
    let peer = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    assert!(autonomous.offer_work(
        peer,
        *own.resolution_id(),
        &peer_question.to_hex(),
        &graph,
        &mut questions
    ));
    let selection = questions.completed().await;
    questions.finish(&graph, selection);
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let first = owner.requests();
    assert!(
        matches!(&first[..], [(_, jobs::Input::Solve { question })] if question == &own.to_hex())
    );
    owner.complete(first[0].0, Ok(jobs::Output::NoCandidate));
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let second = owner.requests();
    assert!(
        matches!(&second[..], [(_, jobs::Input::Solve { question })] if question == &peer_question.to_hex())
    );
    assert!(
        !autonomous
            .unanswered
            .iter()
            .any(|q| q.resolution_id() == peer_question.resolution_id())
    );
    owner.complete(second[0].0, Ok(jobs::Output::NoCandidate));
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    assert!(
        !autonomous
            .unanswered
            .iter()
            .any(|q| q.resolution_id() == peer_question.resolution_id())
    );
    assert!(owner.requests().iter().any(
        |(_, input)| matches!(input, jobs::Input::Solve { question } if question == &own.to_hex())
    ));
}

#[tokio::test]
async fn malformed_offers_are_declined_without_starting_selection() {
    let graph = Graph::default();
    let mut questions = questions();
    let owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![],
    );
    let peer = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    assert!(!autonomous.offer_work(
        peer,
        [9; 32],
        "not a canonical question",
        &graph,
        &mut questions
    ));
    assert!(questions.available());
    assert!(!autonomous.cooperation.has_selected());
}

#[tokio::test]
async fn restart_retires_peer_job_and_preserves_own_work() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let own = ResearchQuestion::from_hex(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &own).await;
    let mut owner = jobs::tests::Manual::new();
    let mut recovery = owner.recovery();
    let mut foreign = recovered(
        17,
        jobs::Input::Solve {
            question: mocks::create_question(1),
        },
    );
    foreign.binding.cooperative = true;
    recovery.records.push(foreign);
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        recovery,
        vec![own.clone()],
    );
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    owner.requests();
    assert!(owner.discarded().iter().any(|input| matches!(input, jobs::Input::Solve { question } if question == &mocks::create_question(1))));
    autonomous.advance(&mut graph, &mut questions);
    assert!(owner.requests().iter().any(
        |(_, input)| matches!(input, jobs::Input::Solve { question } if question == &own.to_hex())
    ));
}

#[tokio::test]
async fn a_shared_goal_joins_the_running_own_job_without_a_second_allowance() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let own = ResearchQuestion::from_hex(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &own).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![own.clone()],
    );
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let initial = owner.requests();
    assert!(
        matches!(&initial[..], [(_, jobs::Input::Solve { question })] if question == &own.to_hex())
    );
    let peer = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    let goal = [7; 32];
    assert!(autonomous.offer_work(peer, goal, &own.to_hex(), &graph, &mut questions));
    let selection = questions.completed().await;
    questions.finish(&graph, selection);
    autonomous.advance(&mut graph, &mut questions);
    assert!(
        owner.requests().is_empty(),
        "a group must reuse the active local job"
    );
    assert_eq!(
        autonomous.solving.get(own.resolution_id()).unwrap().member,
        Some((peer, goal))
    );
    assert!(
        matches!(autonomous.cooperation.take_notice(), Some((p, g, q, true, _, _)) if p == peer && g == goal && q == *own.resolution_id())
    );
    owner.complete(initial[0].0, Ok(jobs::Output::NoCandidate));
    autonomous.advance(&mut graph, &mut questions);
    assert!(
        matches!(autonomous.cooperation.take_notice(), Some((p, g, q, false, _, _)) if p == peer && g == goal && q == *own.resolution_id())
    );
    assert!(
        autonomous
            .unanswered
            .iter()
            .any(|q| q.resolution_id() == own.resolution_id())
    );
}

#[tokio::test]
async fn long_peer_work_yields_a_full_solver_slot_to_waiting_owned_work() {
    let mut graph = Graph::default();
    let mut questions = questions();
    let own = ResearchQuestion::from_hex(&mocks::create_question(0)).unwrap();
    admitted(&mut questions, &graph, &own).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![own.clone()],
    );
    let capacity = crate::resources::active_limits().solving_jobs;
    assert!((1..=2).contains(&capacity));
    for i in 0..capacity {
        let source = mocks::create_question(i as u64 + 1);
        let question = ResearchQuestion::from_hex(&source).unwrap();
        let ticket = owner
            .client
            .submit(
                jobs::Input::Solve { question: source },
                jobs::Binding::new([1; 32], [2; 32]).for_cooperation(),
            )
            .unwrap();
        owner.requests();
        autonomous.solving.insert(
            *question.resolution_id(),
            Solving {
                completion: None,
                question,
                ticket,
                seen: questions.revision(&graph),
                cooperative: true,
                member: None,
                memory: None,
                cooperative_started: Some(
                    Instant::now() - crate::resources::limits().pending_retry,
                ),
            },
        );
    }
    autonomous.next_proof = Instant::now();
    autonomous.advance(&mut graph, &mut questions);
    let requests = owner.requests();
    assert_eq!(
        owner.discarded().len(),
        1,
        "only one peer job must yield a full slot"
    );
    assert!(requests.iter().any(
        |(_, input)| matches!(input, jobs::Input::Solve { question } if question == &own.to_hex())
    ));
}

#[test]
fn an_unrelated_offer_does_not_consume_selection_for_an_active_goal() {
    let variable = naome_foundation::FreeVariable::new(0);
    let own = ResearchQuestion::from_formula(naome_foundation::Formula::for_all(
        variable,
        naome_foundation::Formula::equal(variable, variable),
    ))
    .unwrap();
    let foreign = ResearchQuestion::from_formula(naome_foundation::Formula::for_all(
        variable,
        naome_foundation::Formula::member(variable, variable),
    ))
    .unwrap();
    let graph = Graph::default();
    let mut questions = questions();
    let owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![own],
    );
    let peer = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    assert!(!autonomous.offer_work(peer, [4; 32], &foreign.to_hex(), &graph, &mut questions));
    assert!(questions.available());
}
