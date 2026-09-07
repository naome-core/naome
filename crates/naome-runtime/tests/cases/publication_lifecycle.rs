use super::*;
use naome_network::{Keypair, StaticArtifactNetwork};
use naome_storage::FixedValidatorCompletedPublicationV0 as Completed;

fn empty_network() -> StaticArtifactNetwork {
    StaticArtifactNetwork::new(Keypair::generate_ed25519(), []).unwrap()
}

fn signed_images(layout: &TestLayout) -> Vec<(String, Vec<u8>)> {
    layout
        .authority_images()
        .into_iter()
        .flatten()
        .filter(|(name, _)| name.ends_with(".journal") || name.ends_with(".anchor"))
        .collect()
}

#[test]
fn completed_proposal_and_undelivered_votes_recover_without_key_use() {
    let fixture = Fixture::new();
    for stop_after in 0..=2 {
        let layout = TestLayout::new("publication-transfer-gap");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[0].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let expected = ready
            .run_with_signing_session(|scope| {
                executor.block_on(async {
                    let mut owner = Runtime::new(
                        node_driver(scope),
                        empty_network(),
                        vec![],
                        timeouts(Duration::from_secs(60)),
                    )
                    .unwrap()
                    .with_publication_journal(&layout.candidate_store, true)
                    .unwrap();
                    assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                    let payload = pairing_payload();
                    let block = ArtifactChainState::new(fixture.definition)
                        .prepare_block(artifact_id(&payload))
                        .unwrap();
                    assert!(matches!(
                        owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: block,
                            canonical_artifact_bytes: payload
                        }),
                        Event::ProposalAuthored
                    ));
                    if stop_after > 0 {
                        let mut votes = 0;
                        for _ in 0..30 {
                            if let Event::PublicationPrepared(_) = owner.next_event().await
                                && matches!(
                                    owner.pending_publication().unwrap().message(),
                                    Message::Vote { .. }
                                )
                            {
                                votes += 1;
                                if votes == stop_after {
                                    break;
                                }
                            }
                        }
                        assert_eq!(votes, stop_after);
                    }
                    let history = owner.driver().unwrap().publication_history().unwrap();
                    let mut expected: Vec<_> = history
                        .entries()
                        .map(|entry| {
                            let message = match entry {
                                Completed::Proposal(proposal) => ConsensusPushMessage::Proposal {
                                    canonical_proposal: proposal
                                        .canonical_proposal_control_bytes()
                                        .to_vec(),
                                    canonical_artifact: proposal
                                        .canonical_artifact_bytes()
                                        .unwrap()
                                        .to_vec(),
                                },
                                Completed::Vote(vote) => ConsensusPushMessage::Vote {
                                    canonical_vote: vote.canonical_bytes().to_vec(),
                                },
                            };
                            (entry.state_id(), message)
                        })
                        .collect();
                    expected.sort_by_key(|entry| entry.0);
                    assert_eq!(expected.len(), stop_after + 1);
                    expected
                })
            })
            .unwrap();
        let before = signed_images(&layout);
        let FixedValidatorNodeStartupV0::Ready(ready) = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .open(fixture.keys[0].clone())
        .unwrap() else {
            panic!("strict ready")
        };
        ready.run_with_signing_session(|scope| executor.block_on(async {
            let mut owner = Runtime::new(node_driver(scope), empty_network(), vec![], timeouts(Duration::from_secs(60))).unwrap()
                .with_publication_journal(&layout.candidate_store, false).unwrap();
            let mut actual = Vec::new();
            let mut completed = 0;
            for _ in 0..30 {
                match owner.next_event().await {
                    Event::PublicationRecovered { state_id, .. } => actual.push((state_id,
                        owner.pending_publication().unwrap().message().copy_message().unwrap())),
                    Event::PublicationComplete(publication) => {
                        assert!(publication.recovered());
                        assert!(publication.local_admission_attempted());
                        completed += 1;
                        if completed == expected.len() { break; }
                    },
                    Event::TimerArmed(_) | Event::Admission(_) => {},
                    _ => panic!("recovery must not step or sign before retained publications transfer"),
                }
            }
            actual.sort_by_key(|entry| entry.0);
            assert_eq!(actual, expected);
            assert_eq!(completed, expected.len());
            assert_eq!(signed_images(&layout), before, "resend and fresh local admission perform no signing or anchor write");
        })).unwrap();
    }
}

#[test]
fn receipt_write_failure_stops_signer_and_strict_restart_retains_exact_resend_debt() {
    use naome_network::{NetworkEvent, StaticPeer};
    let fixture = Fixture::new();
    let layout = TestLayout::new("publication-receipt-failure");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (network, mut peer, peer_id) = executor.block_on(connected_pair());
    let (state_id, message, snapshot, backup) = ready.run_with_signing_session(|scope| executor.block_on(async {
        let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id], timeouts(Duration::from_secs(60))).unwrap()
            .with_publication_journal(&layout.candidate_store, true).unwrap();
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        let payload = pairing_payload();
        let block = ArtifactChainState::new(fixture.definition).prepare_block(artifact_id(&payload)).unwrap();
        assert!(matches!(owner.author_proposal(FixedValidatorProposalSourceV0::Fresh { artifact_block: block, canonical_artifact_bytes: payload }), Event::ProposalAuthored));
        loop {
            match owner.next_event().await {
                Event::PeerAttempted { started: true, .. } => break,
                event => check_local(event),
            }
        }
        let publication = owner.pending_publication().unwrap();
        let state_id = publication.message().state_id();
        let message = publication.message().copy_message().unwrap();
        let snapshot = std::fs::read_dir(&layout.candidate_store).unwrap().map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|extension| extension == "deliveries")).unwrap();
        let backup = snapshot.with_extension("backup");
        std::fs::rename(&snapshot, &backup).unwrap();
        std::fs::create_dir(&snapshot).unwrap();
        let mut received = false;
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = owner.next_event() => match event {
                        Event::Fatal(error) => {
                            assert!(matches!(*error, naome_runtime::FixedValidatorRuntimeFailureV0::Publication(_)));
                            break;
                        },
                        Event::Network(_) => {},
                        _ => panic!("a failed durable receipt must not report peer completion"),
                    },
                    event = peer.next_event() => if let NetworkEvent::InboundConsensusPush(inbound) = event {
                        assert_eq!(inbound.message(), &message);
                        let _ = peer.acknowledge_consensus_push(inbound).unwrap();
                        received = true;
                    },
                }
            }
        }).await.unwrap();
        assert!(received);
        assert!(owner.driver().is_none());
        assert!(owner.pending_publication().unwrap().deliveries().all(|delivery| matches!(delivery.state(), Delivery::NotAttempted)));
        (state_id, message, snapshot, backup)
    })).unwrap();
    drop(peer);
    // Repair only the injected test filesystem obstruction, preserving the last
    // successfully synchronized receipt snapshot as a strict restart would see.
    std::fs::remove_dir(&snapshot).unwrap();
    std::fs::rename(&backup, &snapshot).unwrap();
    let signed_before = signed_images(&layout);
    let snapshot_bytes = std::fs::read(&snapshot).unwrap();
    for fault in 0..3 {
        if fault == 1 {
            std::fs::remove_file(&snapshot).unwrap();
        }
        if fault == 2 {
            std::fs::write(&snapshot, &snapshot_bytes[..snapshot_bytes.len() - 1]).unwrap();
        }
        let FixedValidatorNodeStartupV0::Ready(ready) = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .open(fixture.keys[0].clone())
        .unwrap() else {
            panic!("strict signer ready")
        };
        ready
            .run_with_signing_session(|scope| {
                executor.block_on(async {
                    let network = StaticArtifactNetwork::new(
                        Keypair::generate_ed25519(),
                        [StaticPeer::new(
                            peer_id,
                            "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                        )],
                    )
                    .unwrap();
                    let peers = if fault == 0 { vec![] } else { vec![peer_id] };
                    assert!(
                        Runtime::new(
                            node_driver(scope),
                            network,
                            peers,
                            timeouts(Duration::from_secs(60))
                        )
                        .unwrap()
                        .with_publication_journal(&layout.candidate_store, false)
                        .is_err()
                    );
                })
            })
            .unwrap();
        assert_eq!(signed_images(&layout), signed_before);
        std::fs::write(&snapshot, &snapshot_bytes).unwrap();
    }
    let FixedValidatorNodeStartupV0::Ready(ready) = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .open(fixture.keys[0].clone())
    .unwrap() else {
        panic!("strict ready")
    };
    ready.run_with_signing_session(|scope| executor.block_on(async {
        let network = StaticArtifactNetwork::new(Keypair::generate_ed25519(), [StaticPeer::new(peer_id, "/ip4/127.0.0.1/tcp/1".parse().unwrap())]).unwrap();
        let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id], timeouts(Duration::from_secs(60))).unwrap()
            .with_publication_journal(&layout.candidate_store, false).unwrap();
        assert!(matches!(owner.next_event().await, Event::PublicationRecovered { state_id: actual, .. } if actual == state_id));
        let recovered = owner.pending_publication().unwrap();
        assert_eq!(recovered.message().copy_message().unwrap(), message);
        assert!(recovered.deliveries().all(|delivery| matches!(delivery.state(), Delivery::NotAttempted)));
        assert_eq!(signed_images(&layout), signed_before);
    })).unwrap();
}
