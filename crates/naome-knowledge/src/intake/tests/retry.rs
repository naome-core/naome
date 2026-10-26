use super::*;

static CALLS: AtomicUsize = AtomicUsize::new(0);
fn counted(_: CompiledQuestion) -> Ready<Result<bool, String>> {
    CALLS.fetch_add(1, Ordering::SeqCst);
    ready(Ok(true))
}
async fn decision(
    owner: &mut crate::jobs::tests::Manual,
    questions: &mut Questions,
    graph: &Graph,
    managed: bool,
) {
    if managed {
        let requests = owner.requests();
        assert_eq!(requests.len(), 1);
        owner.complete(requests[0].0, Ok(crate::jobs::Output::Interest(true)));
        let result = questions.completed().await;
        questions.finish(graph, result);
    } else {
        interest(questions, graph).await;
    }
}

#[tokio::test]
async fn temporary_overload_retains_final_selection_without_declining_or_repeating_interest() {
    const CASE: &str = "intake::tests::retry::temporary_overload_retains_final_selection_without_declining_or_repeating_interest";
    // Adaptive budgets belong to a process, so the resource transition is isolated.
    if std::env::var("NAOME_INTAKE_RETRY_CASE").as_deref() != Ok(CASE) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_INTAKE_RETRY_CASE", CASE)
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
    for managed in [false, true] {
        crate::resources::tests::budget(false);
        CALLS.store(0, Ordering::SeqCst);
        let directory = Directory::new();
        let mut graph = Graph::open(&directory.0).unwrap();
        let mut owner = crate::jobs::tests::Manual::new();
        let mut questions: Questions = if managed {
            Questions::managed(owner.client.clone(), &directory.0, Duration::from_secs(60)).unwrap()
        } else {
            LocalQuestions::new(Some(counted as fn(_) -> _))
        };
        let (object, metadata) = fixture(76);
        let id = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
        let peer = PeerId::random();
        let mut intake = Intake::default();
        intake.enqueue(peer, metadata.clone(), &graph).unwrap();
        intake.advance(&mut graph, &mut questions);
        decision(&mut owner, &mut questions, &graph, managed).await;
        intake.advance(&mut graph, &mut questions);
        if managed {
            intake.enqueue(peer, metadata.clone(), &graph).unwrap();
            intake.advance(&mut graph, &mut questions);
        }
        assert_eq!(intake.needed(), [(peer, id, id)]);
        intake
            .payload(peer, id, id, object.clone(), &graph)
            .unwrap();
        intake.advance(&mut graph, &mut questions);
        decision(&mut owner, &mut questions, &graph, managed).await;
        let before = graph.content_root();
        crate::resources::tests::budget(true);
        assert!(
            matches!(
                intake.advance(&mut graph, &mut questions),
                Progress::Waiting
            ),
            "temporary overload must defer a selected closure"
        );
        assert!(intake.contains(id));
        assert!(intake.declined.is_empty());
        assert_eq!(graph.content_root(), before);
        assert_eq!(registered(&mut questions, &graph), 0);
        crate::resources::tests::budget(false);
        let mut accepted = false;
        for _ in 0..8 {
            match intake.advance(&mut graph, &mut questions) {
                Progress::Accepted(ids) => {
                    assert_eq!(ids, [id]);
                    accepted = true;
                    break;
                }
                Progress::Skipped(_, error) => panic!("selection was lost across a retry: {error}"),
                Progress::Waiting => {}
            }
            if !intake.refresh_needed().is_empty() {
                assert_eq!(
                    intake.enqueue(peer, metadata.clone(), &graph).unwrap(),
                    "metadata_refreshed"
                );
            }
            for (_, root, needed) in intake.needed() {
                assert_eq!((root, needed), (id, id));
                intake
                    .payload(peer, root, needed, object.clone(), &graph)
                    .unwrap();
            }
        }
        assert!(
            accepted,
            "recovery must finish without another provider decision"
        );
        assert_eq!(graph.accepted_count(), 1);
        assert_eq!(registered(&mut questions, &graph), 1);
        assert!(owner.requests().is_empty());
        if !managed {
            assert_eq!(CALLS.load(Ordering::SeqCst), 2);
        }
    }
}

#[tokio::test]
async fn reduced_capacity_drains_active_selection_before_admitting_another_root() {
    const CASE: &str = "intake::tests::retry::reduced_capacity_drains_active_selection_before_admitting_another_root";
    if std::env::var("NAOME_INTAKE_DRAIN_CASE").as_deref() != Ok(CASE) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_INTAKE_DRAIN_CASE", CASE)
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
    let mut budget = crate::resources::tests::snapshot(false);
    budget.budget.concurrency = 2;
    crate::resources::adaptive::publish(budget.clone());
    assert_eq!(crate::resources::active_limits().interest_decisions, 2);
    let fixtures: Vec<_> = (79..82).map(fixture).collect();
    let ids: Vec<_> = fixtures
        .iter()
        .map(|(object, _)| ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap()))
        .collect();
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let mut owner = crate::jobs::tests::Manual::new();
    let mut questions =
        Questions::managed(owner.client.clone(), &directory.0, Duration::from_secs(60)).unwrap();
    let mut intake = Intake::default();
    let peer = PeerId::random();
    intake.enqueue(peer, fixtures[0].1.clone(), &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    decision(&mut owner, &mut questions, &graph, true).await;
    intake.advance(&mut graph, &mut questions);
    intake.enqueue(peer, fixtures[0].1.clone(), &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    assert_eq!(intake.needed(), [(peer, ids[0], ids[0])]);
    intake.enqueue(peer, fixtures[1].1.clone(), &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    decision(&mut owner, &mut questions, &graph, true).await;
    intake.advance(&mut graph, &mut questions);
    intake.enqueue(peer, fixtures[1].1.clone(), &graph).unwrap();
    let deadline = intake
        .active
        .as_ref()
        .unwrap()
        .description
        .transfer
        .deadline();
    budget.budget.concurrency = 1;
    crate::resources::adaptive::publish(budget);
    assert_eq!(crate::resources::active_limits().interest_decisions, 1);
    intake.enqueue(peer, fixtures[2].1.clone(), &graph).unwrap();
    intake
        .payload(peer, ids[0], ids[0], fixtures[0].0.clone(), &graph)
        .unwrap();
    intake.advance(&mut graph, &mut questions);
    let mut pending = owner.requests();
    assert_eq!(
        pending.len(),
        1,
        "the active root must reach final selection while another selected root waits"
    );
    assert!(
        matches!(&pending[0].1, crate::jobs::Input::Interest { purpose: crate::jobs::Purpose::Final, root: Some(root), .. } if root == &hex(ids[0].as_bytes()))
    );
    assert_eq!(
        intake.queue.len(),
        1,
        "capacity reduction must still block new initial admission"
    );
    assert_eq!(
        intake
            .waiting
            .iter()
            .find(|waiting| waiting.description.transfer.root() == ids[0])
            .unwrap()
            .description
            .transfer
            .deadline(),
        deadline
    );
    let mut decisions = Vec::new();
    for _ in 0..40 {
        if !pending.is_empty() {
            assert_eq!(
                pending.len(),
                1,
                "provider concurrency must honor the reduced capacity"
            );
            for (job, input) in std::mem::take(&mut pending) {
                decisions.push(input);
                owner.complete(job, Ok(crate::jobs::Output::Interest(true)));
            }
            let completed = questions.completed().await;
            questions.finish(&graph, completed);
        }
        if let Progress::Skipped(_, error) = intake.advance(&mut graph, &mut questions) {
            panic!("admitted selection was lost while draining: {error}");
        }
        for (_, id) in intake.refresh_needed() {
            let index = ids.iter().position(|candidate| *candidate == id).unwrap();
            intake
                .enqueue(peer, fixtures[index].1.clone(), &graph)
                .unwrap();
        }
        for (_, root, id) in intake.needed() {
            let index = ids.iter().position(|candidate| *candidate == id).unwrap();
            intake
                .payload(peer, root, id, fixtures[index].0.clone(), &graph)
                .unwrap();
        }
        pending = owner.requests();
        if graph.accepted_count() == 3 {
            break;
        }
    }
    assert_eq!(
        graph.accepted_count(),
        3,
        "all previously selected and queued roots must drain"
    );
    assert_eq!(registered(&mut questions, &graph), 3);
    assert!(pending.is_empty());
    assert_eq!(
        decisions.len(),
        4,
        "retain both initial decisions across the capacity reduction"
    );
    for id in &ids {
        assert_eq!(decisions.iter().filter(|input| matches!(input, crate::jobs::Input::Interest { purpose: crate::jobs::Purpose::Final, root: Some(root), .. } if root == &hex(id.as_bytes()))).count(), 1);
    }
}

#[tokio::test]
async fn allocation_backpressure_preserves_payload_frontier_and_prepared_inputs() {
    for during_preparation in [false, true] {
        let (object, metadata) = fixture(77);
        let id = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
        let peer = PeerId::random();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut questions = LocalQuestions::new(Some(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            ready(Ok(true))
        }));
        let mut graph = Graph::default();
        let mut intake = Intake::default();
        intake.enqueue(peer, metadata, &graph).unwrap();
        approve(&mut intake, &mut questions, &mut graph).await;
        if !during_preparation {
            crate::resources::fail_next_memory_allocation();
            let error = intake
                .payload(peer, id, id, object.clone(), &graph)
                .unwrap_err();
            assert!(matches!(error, crate::Error::MemoryOverload { .. }));
            assert!(error.retryable());
            assert_eq!(intake.needed(), [(peer, id, id)]);
            assert_eq!(
                intake.active.as_ref().unwrap().closure.certificate_count(),
                0
            );
        }
        intake.payload(peer, id, id, object, &graph).unwrap();
        if during_preparation {
            crate::resources::fail_next_memory_allocation();
            assert!(matches!(
                intake.advance(&mut graph, &mut questions),
                Progress::Waiting
            ));
            assert_eq!(
                intake.active.as_ref().unwrap().closure.certificate_count(),
                1
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(intake.needed().is_empty());
            assert_eq!(graph.accepted_count(), 0);
        }
        assert!(matches!(
            intake.advance(&mut graph, &mut questions),
            Progress::Waiting
        ));
        interest(&mut questions, &graph).await;
        assert!(
            matches!(intake.advance(&mut graph, &mut questions), Progress::Accepted(ids) if ids == [id])
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(graph.checker_calls(), (0, 1));
        assert!(intake.declined.is_empty());
        assert_eq!(graph.accepted_count(), 1);
    }
}

#[tokio::test]
async fn sealed_selection_cannot_publish_through_a_different_root_grant() {
    let (object, metadata) = fixture(78);
    let id = ArtifactId::from_bytes(id_bytes(&object.artifact_id).unwrap());
    let peer = PeerId::random();
    let mut graph = Graph::default();
    let before = graph.content_root();
    let mut questions = new_questions();
    let mut intake = Intake::default();
    intake.enqueue(peer, metadata, &graph).unwrap();
    approve(&mut intake, &mut questions, &mut graph).await;
    intake.payload(peer, id, id, object, &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    interest(&mut questions, &graph).await;
    let mut root = intake.active.take().unwrap();
    root.selection.poll(&graph, &mut questions).unwrap();
    let Phase::Final(batch) = root.phase else {
        panic!("complete checked batch");
    };
    let wrong = TransferGrant::new(peer, ArtifactId::from_bytes([9; 32]), None);
    assert_eq!(
        root.selection
            .publish(&mut graph, &mut questions, &wrong, *batch),
        Err(crate::Error::InvalidInput(
            "publication root differs from selection".into()
        ))
    );
    assert_eq!(graph.content_root(), before);
    assert_eq!(graph.accepted_count(), 0);
    assert_eq!(registered(&mut questions, &graph), 0);
}
