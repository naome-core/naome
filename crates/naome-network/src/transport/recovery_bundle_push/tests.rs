use super::*;
use crate::transport::inbound_retention::InboundRetentionBudget;
use crate::{AcknowledgedRecoveryBundleStageError, RecoveryBundleStageSelection};
use libp2p::swarm::ConnectionId;
use naome_chain::ArtifactBlockId;
use naome_chain::{ArtifactBlock, ArtifactChainState, ArtifactDag};
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStoreLimits,
    ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits,
    CandidateBranchRecoveryBundleStageFailure,
};
use naome_storage::{
    ArtifactBlockCandidateStore, CandidateBranchRecoveryBundleLimits, CanonicalArtifactPayloadStore,
};
use std::time::Duration;
use tokio::time::timeout;

use crate::Keypair;

struct BundleFixture {
    definition: naome_chain::ArtifactChainDefinition,
    blocks: Vec<ArtifactBlock>,
    payloads: Vec<Vec<u8>>,
    limits: CandidateBranchRecoveryBundleLimits,
    bytes: Vec<u8>,
}

impl BundleFixture {
    fn anchor(&self) -> ArtifactBlockId {
        self.definition.id().virtual_genesis_block_id()
    }

    fn target(&self) -> ArtifactBlockId {
        self.blocks.last().unwrap().id()
    }

    fn payload_bytes(&self) -> u64 {
        u64::try_from(self.payloads.iter().map(Vec::len).sum::<usize>()).unwrap()
    }
}

fn bundle_fixture() -> BundleFixture {
    let definition = crate::tests::test_chain_definition();
    let payloads = vec![crate::tests::pairing_bytes(), crate::tests::union_bytes()];
    let mut dag = ArtifactDag::new();
    let artifact_ids = payloads
        .iter()
        .map(|payload| {
            dag.apply_canonical_artifact_bytes(payload.clone())
                .unwrap()
                .artifact_id()
        })
        .collect::<Vec<_>>();
    let mut branch = ArtifactChainState::new(definition);
    let mut blocks = Vec::new();
    for (&artifact_id, payload) in artifact_ids.iter().zip(&payloads) {
        let block = branch.prepare_block(artifact_id).unwrap();
        branch.apply_block(&block, payload.clone()).unwrap();
        blocks.push(block);
    }
    let payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();
    let limits = CandidateBranchRecoveryBundleLimits::new(
        blocks.len(),
        u64::try_from(payload_bytes).unwrap(),
        RECOVERY_BUNDLE_PUSH_MAX_BYTES as u64,
    )
    .unwrap();
    let source = crate::tests::TestDirectory::new("recovery-bundle-stage-source");
    let journal = crate::tests::create_journal(source.path()).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        source.path(),
        definition,
        ArtifactBlockCandidateStoreLimits::new(blocks.len()).unwrap(),
    )
    .unwrap();
    for block in &blocks {
        assert_eq!(
            candidates.insert(block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        source.path(),
        ArtifactPayloadStoreLimits::new(payloads.len(), u64::try_from(payload_bytes).unwrap())
            .unwrap(),
    )
    .unwrap();
    let mut accepted = ArtifactDag::new();
    for payload in &payloads {
        let record = accepted
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap();
        assert_eq!(
            payload_store.insert(record).unwrap(),
            ArtifactPayloadInsertOutcome::Inserted
        );
    }
    let bytes = journal
        .export_candidate_branch_recovery_bundle_v0(
            blocks.last().unwrap().id(),
            &mut candidates,
            &mut payload_store,
            limits,
        )
        .unwrap()
        .into_canonical_bytes();
    BundleFixture {
        definition,
        blocks,
        payloads,
        limits,
        bytes,
    }
}

fn receipt_event(
    network: &mut StaticArtifactNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
) -> OutboundRecoveryBundlePushEvent {
    let event = network
        .handle_recovery_bundle_push_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(2_000),
            message: request_response::Message::Response {
                request_id,
                response: RecoveryBundlePushReceipt,
            },
        })
        .expect("the retained push produces one terminal event");
    let NetworkEvent::OutboundRecoveryBundlePush(event) = event else {
        panic!("recovery-bundle receipt did not produce its outbound terminal")
    };
    event
}

#[test]
fn request_accepts_the_exact_transport_maximum() {
    assert_eq!(
        RecoveryBundlePushRequest::new(vec![0; RECOVERY_BUNDLE_PUSH_MAX_BYTES])
            .unwrap()
            .into_bundle_bytes()
            .len(),
        RECOVERY_BUNDLE_PUSH_MAX_BYTES
    );
}

#[test]
fn request_rejects_one_byte_over_the_transport_maximum() {
    let actual = RECOVERY_BUNDLE_PUSH_MAX_BYTES + 1;
    assert!(matches!(
        RecoveryBundlePushRequest::new(vec![0; actual]),
        Err(RecoveryBundlePushRequestError::TooLong {
            actual: rejected,
            maximum: RECOVERY_BUNDLE_PUSH_MAX_BYTES,
        }) if rejected == actual
    ));
}

#[test]
fn inbound_capacity_preserves_one_full_size_slot_per_configured_peer() {
    assert_eq!(crate::MAX_CONNECTIONS_PER_PEER, 1);
    assert_eq!(crate::MAX_RECOVERY_BUNDLE_PUSH_STREAMS_PER_CONNECTION, 1);
    assert_eq!(
        RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS,
        MAX_STATIC_PEERS
    );
    assert_eq!(
        RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
        RECOVERY_BUNDLE_PUSH_MAX_BYTES * MAX_STATIC_PEERS
    );

    let budget = Arc::new(InboundRetentionBudget::new(
        RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS,
        RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
    ));
    let first_peer = Keypair::generate_ed25519().public().to_peer_id();
    let first_permit = InboundRetentionBudget::try_acquire(&budget, 0).unwrap();
    let mut first = RecoveryBundlePushRequest::from_inbound(Vec::new(), first_permit);
    assert!(first.bind_inbound_peer(first_peer));

    let duplicate_permit = InboundRetentionBudget::try_acquire(&budget, 0).unwrap();
    let mut duplicate = RecoveryBundlePushRequest::from_inbound(Vec::new(), duplicate_permit);
    assert!(!duplicate.bind_inbound_peer(first_peer));
    drop(duplicate);

    let mut retained = vec![first];
    for _ in 1..MAX_STATIC_PEERS {
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let permit = InboundRetentionBudget::try_acquire(&budget, 0).unwrap();
        let mut request = RecoveryBundlePushRequest::from_inbound(Vec::new(), permit);
        assert!(request.bind_inbound_peer(peer_id));
        retained.push(request);
    }
    assert!(InboundRetentionBudget::try_acquire(&budget, 0).is_none());
    drop(retained);

    let released_permit = InboundRetentionBudget::try_acquire(&budget, 0).unwrap();
    let mut released = RecoveryBundlePushRequest::from_inbound(Vec::new(), released_permit);
    assert!(released.bind_inbound_peer(first_peer));
}

#[tokio::test]
async fn authenticated_peer_receives_opaque_bytes_and_sender_gets_only_a_receipt() {
    let (mut sender, mut receiver, _sender_peer, receiver_peer) =
        crate::tests::connected_pair().await;
    let expected = vec![0xa5, 0x5a, 0x00];
    let ticket = sender
        .push_recovery_bundle(receiver_peer, expected.clone())
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = receiver.next_event() => if let NetworkEvent::InboundRecoveryBundlePush(inbound) = event {
                    assert_eq!(inbound.peer_id(), sender.local_peer_id());
                    assert_eq!(inbound.bundle_bytes(), expected);
                    let inbound_pointer = inbound.bundle_bytes().as_ptr();
                    let accepted = receiver.acknowledge_recovery_bundle_push(inbound).unwrap();
                    assert_eq!(accepted, expected);
                    assert_eq!(accepted.as_ptr(), inbound_pointer);
                },
                event = sender.next_event() => if let NetworkEvent::OutboundRecoveryBundlePush(event) = event {
                    let receipt = ticket.complete(event).unwrap().unwrap();
                    assert_eq!(receipt.peer_id(), receiver_peer);
                    assert_eq!(receipt.encoded_bytes(), expected.len());
                    return;
                },
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn acknowledged_authenticated_bundle_stages_unselected_data_without_mutating_history() {
    let fixture = bundle_fixture();
    let destination = crate::tests::TestDirectory::new("recovery-bundle-stage-destination");
    let selected = crate::tests::create_journal(destination.path()).unwrap();
    let selected_before = crate::tests::snapshot(&destination, &selected);
    let mut candidates = ArtifactBlockCandidateStore::create(
        destination.path(),
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(fixture.blocks.len()).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        destination.path(),
        ArtifactPayloadStoreLimits::new(fixture.payloads.len(), fixture.payload_bytes()).unwrap(),
    )
    .unwrap();
    let (mut sender, mut receiver, sender_peer, receiver_peer) =
        crate::tests::connected_pair().await;
    let expected_bytes = fixture.bytes.clone();
    let anchor = fixture.anchor();
    let target = fixture.target();
    let mut ticket = Some(
        sender
            .push_recovery_bundle(receiver_peer, fixture.bytes)
            .unwrap(),
    );

    timeout(Duration::from_secs(10), async {
        let mut staged = false;
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if !staged && let NetworkEvent::InboundRecoveryBundlePush(inbound) = event {
                        let inbound_pointer = inbound.bundle_bytes().as_ptr();
                        let acknowledged = receiver
                            .acknowledge_recovery_bundle_push_with_source(inbound)
                            .unwrap();
                        assert_eq!(acknowledged.peer_id(), sender_peer);
                        assert_eq!(acknowledged.bundle_bytes().as_ptr(), inbound_pointer);
                        let outcome = acknowledged
                            .stage_candidate_branch(
                                RecoveryBundleStageSelection::new(sender_peer, anchor, target),
                                &selected,
                                &mut candidates,
                                &mut payloads,
                                fixture.limits,
                            )
                            .unwrap();
                        assert_eq!(outcome.peer_id(), sender_peer);
                        assert_eq!(outcome.staging().candidate_block_count(), 2);
                        assert_eq!(outcome.staging().candidate_inserted_count(), 2);
                        assert_eq!(outcome.staging().payload_inserted_count(), 2);
                        assert_eq!(outcome.staging().bundle_bytes(), expected_bytes);
                        assert_eq!(outcome.staging().bundle_bytes().as_ptr(), inbound_pointer);
                        staged = true;
                    }
                },
                event = sender.next_event() => {
                    if staged && let NetworkEvent::OutboundRecoveryBundlePush(event) = event {
                        let receipt = ticket.take().unwrap().complete(event).unwrap().unwrap();
                        assert_eq!(receipt.peer_id(), receiver_peer);
                        break;
                    }
                },
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(candidates.len().unwrap(), 2);
    assert_eq!(payloads.len().unwrap(), 2);
    crate::tests::assert_snapshot(&destination, &selected, &selected_before);
}

#[tokio::test]
async fn stream_receipt_survives_strict_staging_rejection_and_attests_no_storage() {
    let fixture = bundle_fixture();
    let destination = crate::tests::TestDirectory::new("recovery-bundle-rejected-destination");
    let selected = crate::tests::create_journal(destination.path()).unwrap();
    let selected_before = crate::tests::snapshot(&destination, &selected);
    let mut candidates = ArtifactBlockCandidateStore::create(
        destination.path(),
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(fixture.blocks.len()).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        destination.path(),
        ArtifactPayloadStoreLimits::new(fixture.payloads.len(), fixture.payload_bytes()).unwrap(),
    )
    .unwrap();
    let (mut sender, mut receiver, sender_peer, receiver_peer) =
        crate::tests::connected_pair().await;
    let malformed = vec![0xff];
    let ticket = sender
        .push_recovery_bundle(receiver_peer, malformed)
        .unwrap();

    timeout(Duration::from_secs(10), async {
        let mut rejected = false;
        let mut receipt_received = false;
        let mut ticket = Some(ticket);
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if !rejected && let NetworkEvent::InboundRecoveryBundlePush(inbound) = event {
                        let inbound_pointer = inbound.bundle_bytes().as_ptr();
                        let acknowledged = receiver
                            .acknowledge_recovery_bundle_push_with_source(inbound)
                            .unwrap();
                        let error = acknowledged
                            .stage_candidate_branch(
                                RecoveryBundleStageSelection::new(
                                    sender_peer,
                                    fixture.anchor(),
                                    fixture.target(),
                                ),
                                &selected,
                                &mut candidates,
                                &mut payloads,
                                fixture.limits,
                            )
                            .unwrap_err();
                        assert_eq!(error.bundle_bytes().as_ptr(), inbound_pointer);
                        let AcknowledgedRecoveryBundleStageError::Staging { source, .. } = *error else {
                            panic!("matching source must reach strict staging")
                        };
                        assert!(matches!(
                            source.failure(),
                            CandidateBranchRecoveryBundleStageFailure::Decode { .. }
                        ));
                        rejected = true;
                        if receipt_received {
                            break;
                        }
                    }
                },
                event = sender.next_event() => {
                    if let NetworkEvent::OutboundRecoveryBundlePush(event) = event {
                        let receipt = ticket.take().unwrap().complete(event).unwrap().unwrap();
                        assert_eq!(receipt.peer_id(), receiver_peer);
                        assert_eq!(receipt.encoded_bytes(), 1);
                        receipt_received = true;
                        if rejected {
                            break;
                        }
                    }
                },
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    crate::tests::assert_snapshot(&destination, &selected, &selected_before);
}

#[test]
fn operable_finality_history_stages_a_suffix_without_mutating_finality() {
    let fixture = bundle_fixture();
    let finality_directory = crate::tests::TestDirectory::new("recovery-bundle-operable-finality");
    let mut finality_fixture = crate::tests::FinalityFixture::new();
    let mut finality = finality_fixture.create(&finality_directory);
    let selected_block =
        finality_fixture.commit_payload(&mut finality, crate::tests::pairing_bytes());
    assert_eq!(selected_block, fixture.blocks[0].id());
    let finality_before = crate::tests::finality_snapshot(&finality_directory, &finality);
    let stores = crate::tests::TestDirectory::new("recovery-bundle-operable-stores");
    let mut candidates = ArtifactBlockCandidateStore::create(
        stores.path(),
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(1).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        stores.path(),
        ArtifactPayloadStoreLimits::new(1, u64::try_from(fixture.payloads[1].len()).unwrap())
            .unwrap(),
    )
    .unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let anchor = fixture.anchor();
    let target = fixture.target();
    let limits = fixture.limits;
    let acknowledged = AcknowledgedRecoveryBundlePush {
        peer_id,
        bundle_bytes: fixture.bytes,
    };

    let outcome = acknowledged
        .stage_candidate_branch(
            RecoveryBundleStageSelection::new(peer_id, anchor, target),
            &finality,
            &mut candidates,
            &mut payloads,
            limits,
        )
        .unwrap();

    assert_eq!(outcome.staging().selected_prefix_count(), 1);
    assert_eq!(outcome.staging().candidate_block_count(), 1);
    assert_eq!(outcome.staging().candidate_inserted_count(), 1);
    assert_eq!(outcome.staging().payload_inserted_count(), 1);
    assert_eq!(candidates.len().unwrap(), 1);
    assert_eq!(payloads.len().unwrap(), 1);
    crate::tests::assert_finality_snapshot(&finality_directory, &finality, &finality_before);
}

#[test]
fn terminal_finality_history_rejects_staging_before_store_writes() {
    let fixture = bundle_fixture();
    let finality_directory = crate::tests::TestDirectory::new("recovery-bundle-stage-finality");
    let mut finality_fixture = crate::tests::FinalityFixture::new();
    let mut finality = finality_fixture.create(&finality_directory);
    finality_fixture.halt_with_conflict(
        &mut finality,
        crate::tests::pairing_bytes(),
        crate::tests::union_bytes(),
    );
    let finality_bytes = finality_directory.journal_bytes();
    let finality_state_id = finality.state_id().unwrap();
    let finality_halt = finality.halt().unwrap();
    let stores = crate::tests::TestDirectory::new("recovery-bundle-stage-halted-stores");
    let mut candidates = ArtifactBlockCandidateStore::create(
        stores.path(),
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(2).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        stores.path(),
        ArtifactPayloadStoreLimits::new(2, fixture.payload_bytes()).unwrap(),
    )
    .unwrap();
    let candidate_bytes =
        std::fs::read(stores.path().join("artifact-block-candidate-store.log")).unwrap();
    let payload_bytes = std::fs::read(stores.path().join("artifact-payload-store.log")).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let anchor = fixture.anchor();
    let target = fixture.target();
    let acknowledged = AcknowledgedRecoveryBundlePush {
        peer_id,
        bundle_bytes: fixture.bytes,
    };
    let error = acknowledged
        .stage_candidate_branch(
            RecoveryBundleStageSelection::new(peer_id, anchor, target),
            &finality,
            &mut candidates,
            &mut payloads,
            fixture.limits,
        )
        .unwrap_err();
    let AcknowledgedRecoveryBundleStageError::Staging { source, .. } = *error else {
        panic!("matching source must reach selected-history staging")
    };
    assert!(matches!(
        source.failure(),
        CandidateBranchRecoveryBundleStageFailure::SelectedHistory { .. }
    ));
    assert_eq!(source.candidate_acknowledged_count(), 0);
    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    assert_eq!(
        std::fs::read(stores.path().join("artifact-block-candidate-store.log")).unwrap(),
        candidate_bytes
    );
    assert_eq!(
        std::fs::read(stores.path().join("artifact-payload-store.log")).unwrap(),
        payload_bytes
    );
    assert_eq!(finality_directory.journal_bytes(), finality_bytes);
    assert_eq!(finality.state_id().unwrap(), finality_state_id);
    assert_eq!(finality.halt().unwrap(), finality_halt);
}

#[test]
fn caller_selected_source_mismatch_preserves_bytes_and_writes_nothing() {
    let fixture = bundle_fixture();
    let destination = crate::tests::TestDirectory::new("recovery-bundle-wrong-source");
    let selected = crate::tests::create_journal(destination.path()).unwrap();
    let selected_before = crate::tests::snapshot(&destination, &selected);
    let mut candidates = ArtifactBlockCandidateStore::create(
        destination.path(),
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(fixture.blocks.len()).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        destination.path(),
        ArtifactPayloadStoreLimits::new(fixture.payloads.len(), fixture.payload_bytes()).unwrap(),
    )
    .unwrap();
    let actual_peer = Keypair::generate_ed25519().public().to_peer_id();
    let expected_peer = Keypair::generate_ed25519().public().to_peer_id();
    let anchor = fixture.anchor();
    let target = fixture.target();
    let limits = fixture.limits;
    let malformed = vec![0xff];
    let bundle_pointer = malformed.as_ptr();
    let acknowledged = AcknowledgedRecoveryBundlePush {
        peer_id: actual_peer,
        bundle_bytes: malformed,
    };

    let error = acknowledged
        .stage_candidate_branch(
            RecoveryBundleStageSelection::new(expected_peer, anchor, target),
            &selected,
            &mut candidates,
            &mut payloads,
            limits,
        )
        .unwrap_err();

    assert_eq!(error.bundle_bytes().as_ptr(), bundle_pointer);
    assert!(matches!(
        *error,
        AcknowledgedRecoveryBundleStageError::UnexpectedPeer {
            expected,
            actual,
            ..
        } if expected == expected_peer && actual == actual_peer
    ));
    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    crate::tests::assert_snapshot(&destination, &selected, &selected_before);
}

#[tokio::test]
async fn closed_response_channel_returns_the_same_owned_bytes() {
    let (mut sender, mut receiver, sender_peer, receiver_peer) =
        crate::tests::connected_pair().await;
    let expected = vec![0xa5, 0x5a, 0x00];
    let _ticket = sender
        .push_recovery_bundle(receiver_peer, expected.clone())
        .unwrap();
    let inbound = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if let NetworkEvent::InboundRecoveryBundlePush(inbound) = event {
                        return inbound;
                    }
                }
                _ = sender.next_event() => {}
            }
        }
    })
    .await
    .unwrap();
    let inbound_pointer = inbound.bundle_bytes().as_ptr();
    drop(sender);
    timeout(Duration::from_secs(10), async {
        while inbound.channel.is_open() {
            let _ = receiver.next_event().await;
        }
    })
    .await
    .unwrap();

    let error = receiver
        .acknowledge_recovery_bundle_push(inbound)
        .unwrap_err();
    assert_eq!(error.peer_id(), sender_peer);
    assert_eq!(error.bundle_bytes(), expected);
    assert_eq!(error.bundle_bytes().as_ptr(), inbound_pointer);
    let recovered = error.into_bundle_bytes();
    assert_eq!(recovered, expected);
    assert_eq!(recovered.as_ptr(), inbound_pointer);
}

#[test]
fn ticket_rejects_other_network_and_changed_byte_count_without_losing_values() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut first = crate::tests::test_network_for_peers(&[peer_id]);
    let mut second = crate::tests::test_network_for_peers(&[peer_id]);
    let first_ticket = first.push_recovery_bundle(peer_id, vec![0xa5]).unwrap();
    let second_ticket = second.push_recovery_bundle(peer_id, vec![0xa5]).unwrap();
    assert_eq!(first_ticket.request_id, second_ticket.request_id);

    let second_event = receipt_event(&mut second, second_ticket.request_id, peer_id);
    assert!(!first_ticket.accepts_event(&second_event));
    let mismatch = first_ticket.complete(second_event).unwrap_err();
    let (first_ticket, second_event) = (*mismatch).into_parts();
    assert!(second_ticket.accepts_event(&second_event));
    let _ = second_ticket.complete(second_event).unwrap().unwrap();
    drop(
        first
            .pending
            .remove(&ExchangeRequestId::RecoveryBundlePush(
                first_ticket.request_id,
            ))
            .unwrap(),
    );

    let ticket = first
        .push_recovery_bundle(peer_id, vec![0xa5, 0x5a])
        .unwrap();
    let mut event = receipt_event(&mut first, ticket.request_id, peer_id);
    event.bytes += 1;
    assert!(!ticket.accepts_event(&event));
    let mismatch = ticket.complete(event).unwrap_err();
    let (ticket, mut event) = (*mismatch).into_parts();
    event.bytes -= 1;
    assert!(ticket.accepts_event(&event));
    let receipt = ticket.complete(event).unwrap().unwrap();
    assert_eq!(receipt.encoded_bytes(), 2);
}
