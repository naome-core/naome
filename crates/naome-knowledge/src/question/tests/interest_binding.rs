use super::*;

#[tokio::test]
async fn pending_interest_cannot_be_sealed_after_its_policy_or_owner_changes() {
    for owner_failure in [false, true] {
        let directory = Directory::new();
        let graph = Graph::default();
        let mut provider = crate::jobs::tests::Manual::new();
        let mut local = Managed::managed(
            provider.client.clone(),
            &directory.0,
            Duration::from_secs(3600),
        )
        .unwrap();
        let (reply, receiver) = oneshot::channel();
        local.process(Command::Admit(question(QUESTION), reply), &graph);
        let (id, _) = provider.requests().remove(0);
        if owner_failure {
            local.select(None);
            provider.complete(id, Ok(crate::jobs::Output::Interest(true)));
        } else {
            local.policy.revision += 1;
            provider.complete(id, Ok(crate::jobs::Output::Interest(true)));
            let interest = local.completed().await;
            local.finish(&graph, interest);
        }
        let admission = receiver.await.unwrap();
        assert_eq!(admission.outcome, AdmissionOutcome::NotInserted);
        assert_eq!(admission.assessment.interest, InterestAssessment::Stale);
        assert!(admission.assessment.selected.is_none());
        assert_eq!(local.registry.len(), 0);
    }
}

#[tokio::test]
async fn independent_admissions_share_interest_epoch_but_receive_fresh_formal_receipts() {
    let directory = Directory::new();
    let graph = Graph::default();
    let mut owner = crate::jobs::tests::Manual::new();
    let mut local = Managed::managed(
        owner.client.clone(),
        &directory.0,
        Duration::from_secs(3600),
    )
    .unwrap();
    let mut replies = Vec::new();
    for source in [QUESTION, SOLVED] {
        let (reply, receiver) = oneshot::channel();
        local.process(Command::Admit(question(source), reply), &graph);
        replies.push(receiver);
    }
    let requests = owner.requests();
    assert_eq!(requests.len(), 2);
    let before = local.formal_context(&graph).snapshot;
    for (id, _) in requests {
        owner.complete(id, Ok(crate::jobs::Output::Interest(true)));
        let outcome = local.completed().await;
        local.finish(&graph, outcome);
    }
    let first = replies.remove(0).await.unwrap();
    let second = replies.remove(0).await.unwrap();
    let AdmissionOutcome::Admitted(first) = first.outcome else {
        panic!("first independent admission");
    };
    let AdmissionOutcome::Admitted(second) = second.outcome else {
        panic!("second independent admission");
    };
    assert_eq!(first.snapshot_before(), before);
    assert_eq!(second.snapshot_before(), first.snapshot_after());
    assert_eq!(
        second.snapshot_after(),
        local.formal_context(&graph).snapshot
    );
    assert_eq!(local.registry.len(), 2);
    assert!(
        owner.requests().is_empty(),
        "no repeated provider work after unrelated admission"
    );
}

#[tokio::test]
async fn reusable_interest_cannot_be_rebound_to_another_question_policy_or_owner() {
    let graph = Graph::default();
    let mut local = LocalQuestions::new(Some(crate::mocks::assess_interest));
    let original = question(QUESTION);
    let (_, reply) = local.begin_exchange(
        &graph,
        original.clone(),
        Instant::now() + Duration::from_secs(5),
    );
    let outcome = local.completed().await;
    local.finish(&graph, outcome);
    let assessment = reply.await.unwrap();
    assert!(
        local
            .prepare_exchange(&graph, &original, &assessment)
            .is_ok()
    );
    assert!(
        local
            .prepare_exchange(&graph, &question(SOLVED), &assessment)
            .is_err()
    );
    local.policy.revision += 1;
    assert!(
        local
            .prepare_exchange(&graph, &original, &assessment)
            .is_err()
    );
    local.policy.revision -= 1;
    local.select(Some([19; 32]));
    let mut rebound = assessment;
    rebound.selection = local.selection;
    assert!(local.prepare_exchange(&graph, &original, &rebound).is_err());
}

#[tokio::test]
async fn positive_interest_survives_unrelated_registry_growth_but_fresh_duplicates_fail() {
    let graph = Graph::default();
    let mut local = LocalQuestions::new(Some(crate::mocks::assess_interest));
    let original = question(QUESTION);
    let (_, reply) = local.begin_exchange(
        &graph,
        original.clone(),
        Instant::now() + Duration::from_secs(5),
    );
    let outcome = local.completed().await;
    local.finish(&graph, outcome);
    let assessment = reply.await.unwrap();
    let (reply, result) = oneshot::channel();
    local.process(Command::ImportBaseline(question(SOLVED), reply), &graph);
    result.await.unwrap().unwrap();
    let current = local
        .refresh_exchange(&graph, &original, &assessment)
        .unwrap();
    assert_ne!(assessment.prefilter.snapshot, current.prefilter.snapshot);
    assert!(
        local
            .prepare_exchange(&graph, &original, &assessment)
            .is_ok()
    );
    let (reply, result) = oneshot::channel();
    local.process(Command::ImportBaseline(original.clone(), reply), &graph);
    result.await.unwrap().unwrap();
    assert!(
        local
            .prepare_exchange(&graph, &original, &assessment)
            .is_err()
    );
}
