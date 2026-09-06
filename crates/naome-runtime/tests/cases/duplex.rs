use super::*;
use naome_chain::ArtifactBlock;
use naome_node::FixedValidatorNodeFinalitySelectionV0;

async fn exercise(
    mut owners: [Runtime<'_>; 2],
    fixture: &Fixture,
    block: ArtifactBlock,
    payload: Vec<u8>,
) {
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let value = round.value_for_artifact_block(block);
    for owner in &mut owners {
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
    }
    assert!(matches!(
        owners[0].author_proposal(FixedValidatorProposalSourceV0::Fresh {
            artifact_block: block,
            canonical_artifact_bytes: payload,
        }),
        Event::ProposalAuthored
    ));
    let mut finalized = [false; 2];
    let mut publications = [0; 2];
    let mut peer_receipts = [0; 2];
    let mut peer_precommits = [0; 2];
    let mut local_precommits = [0; 2];
    timeout(Duration::from_secs(15), async {
        loop {
            let (actor, event) = {
                let [first, second] = &mut owners;
                tokio::select! {
                    event = first.next_event() => (0, event),
                    event = second.next_event() => (1, event),
                }
            };
            match event {
                Event::PublicationComplete(publication) => {
                    assert!(publication.is_complete());
                    assert!(publication.local_admission_attempted());
                    let deliveries = publication.deliveries().collect::<Vec<_>>();
                    assert_eq!(deliveries.len(), 1);
                    assert_eq!(deliveries[0].peer_id(), owners[1-actor].local_peer_id());
                    assert!(matches!(deliveries[0].state(), Delivery::Received(_)), "publication failed: {:?}", deliveries[0].state());
                    publications[actor] += 1;
                }
                Event::PeerCompleted { peer_id, received } => {
                    assert_eq!(peer_id, owners[1-actor].local_peer_id());
                    assert!(received);
                    peer_receipts[actor] += 1;
                }
                Event::PeerAttempted { started, .. } => assert!(started),
                Event::Admission(report) => {
                    assert!(report.all_admitted(), "failed admission: {:?}", report.results);
                    let local = report.source == InputSource::LocalPublication;
                    if !local {
                        assert_eq!(report.source, InputSource::Peer(owners[1-actor].local_peer_id()));
                        assert_eq!(report.receipt_queued, Some(true));
                    }
                    if report.results.iter().flatten().any(|result| result.route == naome_runtime::FixedValidatorRuntimeRouteV0::CurrentProposalPrecommit) {
                        if local { local_precommits[actor] += 1; }
                        else { peer_precommits[actor] += 1; }
                    }
                }
                Event::Finality(FixedValidatorNodeFinalitySelectionV0::Finalized { position, ancestry_id, .. }) => {
                    assert!(!finalized[actor]);
                    assert_eq!(position, round.position());
                    assert_eq!(ancestry_id, value.ancestry_id());
                    assert_eq!(local_precommits[actor], 1);
                    assert_eq!(peer_precommits[actor], 1);
                    finalized[actor] = true;
                }
                Event::TimerArmed(_) | Event::Transitioned { .. } | Event::PublicationPrepared(_) | Event::Network(_) => {},
                Event::DriverBlocked(error) => panic!("driver blocked: {error:?}"),
                Event::DriverRejected(error) => panic!("driver rejected: {error:?}"),
                Event::Fatal(error) => panic!("fatal: {error}"),
                _ => panic!("unexpected autonomous event"),
            }
            if finalized == [true; 2] && publications == [3, 2] && peer_receipts == [3, 2] { break; }
        }
    }).await.expect("autonomous reciprocal owners did not finish every intended receipt and finality");
    for owner in &owners {
        let driver = owner.driver().unwrap();
        assert_eq!(
            driver
                .selected_artifact_history()
                .selected_head_block_id()
                .unwrap(),
            block.id()
        );
        assert_eq!(driver.position().height().value(), 2);
        assert_eq!(driver.position().round().value(), 0);
        assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
        assert!(owner.pending_publication().is_none());
    }
}

#[test]
fn autonomous_equal_weight_owners_complete_reciprocal_publications_and_finality() {
    let fixture = Fixture::weighted(1);
    let layouts = [TestLayout::new("duplex-a"), TestLayout::new("duplex-b")];
    let [first, second] = std::array::from_fn::<_, 2, _>(|actor| {
        provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layouts[actor],
        )
        .create(fixture.keys[actor].clone())
        .unwrap()
    });
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (first_network, second_network, second_peer) = executor.block_on(connected_pair());
    let first_peer = first_network.local_peer_id();
    let payload = pairing_payload();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    first
        .run_with_signing_session(|first_scope| {
            second
                .run_with_signing_session(|second_scope| {
                    let owners = [
                        Runtime::new(
                            node_driver(first_scope),
                            first_network,
                            vec![second_peer],
                            timeouts(Duration::from_secs(60)),
                        )
                        .unwrap(),
                        Runtime::new(
                            node_driver(second_scope),
                            second_network,
                            vec![first_peer],
                            timeouts(Duration::from_secs(60)),
                        )
                        .unwrap(),
                    ];
                    executor.block_on(exercise(owners, &fixture, block, payload));
                })
                .unwrap()
        })
        .unwrap();
}
