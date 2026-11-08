use super::*;

#[tokio::test]
async fn full_question_page_preserves_discovery_and_rotates_unresolved_work() {
    const CASE: &str = "autonomous::tests::calibration::full_question_page_preserves_discovery_and_rotates_unresolved_work";
    if std::env::var_os("NAOME_FINDING_PAGE_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_FINDING_PAGE_TEST", "1")
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
    profile.tuning.question_page = Some(1);
    crate::resources::configure(profile).unwrap();
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::default();
    let mut questions = questions();
    questions.attach_persistence(&directory.0, &graph).unwrap();
    let first = ResearchQuestion::from_hex(&mocks::create_question(0)).unwrap();
    let second = ResearchQuestion::from_hex(&mocks::create_question(1)).unwrap();
    admitted(&mut questions, &graph, &first).await;
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        intervals(3_600_000),
        owner.client.clone(),
        owner.recovery(),
        vec![first.clone()],
    );
    autonomous.next_question = Instant::now();
    autonomous.next_proof = Instant::now() + Duration::from_secs(3600);
    autonomous.advance(&mut graph, &mut questions);
    let requests = owner.requests();
    assert!(matches!(
        requests.as_slice(),
        [(_, jobs::Input::Find { .. })]
    ));
    owner.complete(requests[0].0, Ok(jobs::Output::Question(second.to_hex())));
    autonomous.advance(&mut graph, &mut questions);
    let selection = questions.completed().await;
    questions.finish(&graph, selection);
    autonomous.advance(&mut graph, &mut questions);
    assert_eq!(autonomous.unanswered.len(), 1);
    assert!(autonomous.unanswered.contains(&first));

    let mut attempted = BTreeSet::new();
    for _ in 0..3 {
        autonomous.next_proof = Instant::now();
        autonomous.advance(&mut graph, &mut questions);
        let requests = owner.requests();
        let [(job, jobs::Input::Solve { question })] = requests.as_slice() else {
            panic!("expected a bounded solve opportunity: {requests:?}");
        };
        attempted.insert(question.clone());
        owner.complete(*job, Ok(jobs::Output::NoCandidate));
        autonomous.next_proof = Instant::now() + Duration::from_secs(3600);
        autonomous.advance(&mut graph, &mut questions);
        assert!(autonomous.unanswered.len() <= 1);
        assert!(autonomous.solving.is_empty());
    }
    assert_eq!(attempted, BTreeSet::from([first.to_hex(), second.to_hex()]));
    drop(questions);
    let mut restored = super::questions();
    restored.attach_persistence(&directory.0, &graph).unwrap();
    let backlog = (0..2)
        .map(|_| restored.next_backlog(&graph).unwrap().to_hex())
        .collect::<BTreeSet<_>>();
    assert_eq!(backlog, attempted, "unresolved admissions survive restart");
    assert!(graph.ids().is_empty(), "NoCandidate establishes no answer");
}

#[tokio::test]
async fn finding_feedback_tracks_admitted_questions_instead_of_raw_provider_output() {
    const CASE: &str = "autonomous::tests::calibration::finding_feedback_tracks_admitted_questions_instead_of_raw_provider_output";
    if std::env::var_os("NAOME_FINDING_FEEDBACK_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_FINDING_FEEDBACK_TEST", "1")
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
    let mut graph = Graph::default();
    graph
        .produce("00000000020600000000210000000000000000")
        .unwrap();
    let mut questions =
        LocalQuestions::new(Some(|_: ResearchQuestion| std::future::ready(Ok(true))));
    let mut owner = jobs::tests::Manual::new();
    let mut autonomous = Autonomous::new(
        Intervals {
            question_interval_ms: 3_600_000,
            proof_interval_ms: 3_600_000,
            ..Intervals::default()
        },
        owner.client.clone(),
        owner.recovery(),
        vec![],
    );
    let outcomes = ["040001000000000100000000", "040101000000000100000000"];
    for (index, source) in outcomes.into_iter().enumerate() {
        autonomous.next_question = Instant::now();
        autonomous.advance(&mut graph, &mut questions);
        let requests = owner.requests();
        assert_eq!(requests.len(), 1);
        assert!(matches!(requests[0].1, jobs::Input::Find { .. }));
        owner.complete(requests[0].0, Ok(jobs::Output::Question(source.into())));
        autonomous.advance(&mut graph, &mut questions);
        if index == 1 {
            assert_eq!(
                crate::resources::feedback::statistics().empty_finding_streak,
                1,
                "raw provider output cannot reset unproductive-finding backoff"
            );
            let selection = questions.completed().await;
            questions.finish(&graph, selection);
        }
        autonomous.advance(&mut graph, &mut questions);
        assert_eq!(
            crate::resources::feedback::statistics().empty_finding_streak,
            u64::from(index == 0)
        );
    }
    assert_eq!(autonomous.unanswered.len(), 1);
}
