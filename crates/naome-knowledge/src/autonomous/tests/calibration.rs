use super::*;

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
        .produce("goal=all(x,eq(x,x)) proof:p0=refl(x) p1=gen(p0,x) return p1")
        .unwrap();
    let mut questions =
        LocalQuestions::new(Some(|_: CompiledQuestion| std::future::ready(Ok(true))));
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
    let outcomes = ["goal=all(x,eq(x,x))", "goal=all(x,mem(x,x))"];
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
            let interest = questions.completed().await;
            questions.finish(&graph, interest);
        }
        autonomous.advance(&mut graph, &mut questions);
        assert_eq!(
            crate::resources::feedback::statistics().empty_finding_streak,
            u64::from(index == 0)
        );
    }
    assert_eq!(autonomous.unanswered.len(), 1);
}
