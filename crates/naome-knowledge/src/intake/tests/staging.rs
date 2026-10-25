use super::*;

async fn complete(
    owner: &mut crate::jobs::tests::Manual,
    questions: &mut Questions,
    graph: &Graph,
) {
    let requests = owner.requests();
    assert_eq!(requests.len(), 1);
    owner.complete(requests[0].0, Ok(crate::jobs::Output::Interest(true)));
    let result = questions.completed().await;
    questions.finish(graph, result);
}

#[tokio::test]
async fn managed_short_proof_is_fetched_and_checked_once_across_final_interest() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let mut owner = crate::jobs::tests::Manual::new();
    let mut questions =
        Questions::managed(owner.client.clone(), &directory.0, Duration::from_secs(60)).unwrap();
    let peer = PeerId::random();
    let mut intake = Intake::default();
    let (object, metadata) = fixture(74);
    let id = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    complete(&mut owner, &mut questions, &graph).await;
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    assert_eq!(
        intake.enqueue(peer, metadata, &graph).unwrap(),
        "metadata_refreshed"
    );
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    assert_eq!(intake.needed(), [(peer, id, id)]);
    intake.payload(peer, id, id, object, &graph).unwrap();
    assert!(matches!(
        intake.advance(&mut graph, &mut questions),
        Progress::Waiting
    ));
    assert_eq!(graph.checker_calls(), (0, 1));
    assert!(intake.needed().is_empty());
    assert!(matches!(
        intake.waiting.front().unwrap().phase,
        managed::Phase::Final { batch: Some(_), .. }
    ));
    complete(&mut owner, &mut questions, &graph).await;
    let Progress::Accepted(ids) = intake.advance(&mut graph, &mut questions) else {
        panic!("cached checked closure must publish without a refetch");
    };
    assert_eq!(ids, [id]);
    assert!(intake.refresh_needed().is_empty() && intake.needed().is_empty());
    assert_eq!(graph.checker_calls(), (0, 1));
    assert!(owner.requests().is_empty());
    assert_eq!(graph.accepted_count(), 1);
}

#[tokio::test]
async fn expired_staging_releases_payload_but_keeps_the_final_interest_result() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let mut owner = crate::jobs::tests::Manual::new();
    let mut questions = Questions::managed(
        owner.client.clone(),
        &directory.0,
        Duration::from_secs(3600),
    )
    .unwrap();
    let peer = PeerId::random();
    let mut intake = Intake::default();
    let (object, metadata) = fixture(75);
    let id = ProofId::from_bytes(id_bytes(&object.proof_id).unwrap());
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    complete(&mut owner, &mut questions, &graph).await;
    intake.advance(&mut graph, &mut questions);
    intake.enqueue(peer, metadata.clone(), &graph).unwrap();
    intake.advance(&mut graph, &mut questions);
    intake
        .payload(peer, id, id, object.clone(), &graph)
        .unwrap();
    intake.advance(&mut graph, &mut questions);
    intake
        .waiting
        .front_mut()
        .unwrap()
        .description
        .transfer
        .set_received_for_test(Instant::now() - crate::resources::limits().root_timeout);
    intake.advance(&mut graph, &mut questions);
    assert!(matches!(
        intake.waiting.front().unwrap().phase,
        managed::Phase::Final { batch: None, .. }
    ));
    assert_eq!(graph.accepted_count(), 0);
    complete(&mut owner, &mut questions, &graph).await;
    intake.advance(&mut graph, &mut questions);
    assert_eq!(
        intake.enqueue(peer, metadata, &graph).unwrap(),
        "metadata_refreshed"
    );
    intake.advance(&mut graph, &mut questions);
    intake.payload(peer, id, id, object, &graph).unwrap();
    assert!(
        matches!(intake.advance(&mut graph, &mut questions), Progress::Accepted(ids) if ids == [id])
    );
    assert!(
        owner.requests().is_empty(),
        "eviction requires no repeated final provider decision"
    );
    assert_eq!(graph.checker_calls(), (0, 2));
}
