use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::artifact_exchange::{ArtifactRequest, ArtifactResponse};
use naome::block_exchange::ArtifactBlockRequest;
use naome_chain::{ArtifactBlock, ArtifactChainState, ArtifactDag};
use naome_foundation::FreeVariable;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofId, ProofStep};
use naome_storage::ArtifactChainJournal;
use tokio::time::timeout;

use super::*;
use crate::codec::ArtifactBlockWireResponse;
use crate::tests::{
    TestDirectory, assert_snapshot, connected_pair, create_journal, pairing_bytes, snapshot,
    test_chain_definition, test_network_for_peers,
};
use crate::{
    ArtifactBlockAncestryPullError, ArtifactBlockImportError, ExchangeRequestId,
    JournalServiceEvent, JournalServiceRequest, Keypair, NetworkEvent, PendingRequest,
    RequestStartError,
};

fn independent_proof_bytes(index: usize) -> Vec<u8> {
    let mut steps = vec![ProofStep::EqualityReflexivity {
        variable: FreeVariable::new(u32::try_from(index).unwrap()),
    }];
    for variable in 0..=index {
        steps.push(ProofStep::Generalization {
            premise: u32::try_from(steps.len() - 1).unwrap(),
            variable: FreeVariable::new(u32::try_from(variable).unwrap()),
        });
    }
    let normal = ProofCertificate::new(steps)
        .unwrap()
        .into_unchecked_normal_form();
    ArtifactPayload::Proof(normal.certificate().clone()).to_canonical_bytes()
}

fn artifact_id(bytes: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(bytes.to_vec())
        .unwrap()
        .artifact_id()
}

fn referenced_generalization_bytes(parent: ProofId) -> Vec<u8> {
    let normal = ProofCertificate::new(vec![
        ProofStep::ProofReference { proof_id: parent },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(7),
        },
    ])
    .unwrap()
    .into_unchecked_normal_form();
    ArtifactPayload::Proof(normal.certificate().clone()).to_canonical_bytes()
}

fn valid_extension(count: usize) -> (Vec<ArtifactBlock>, HashMap<ArtifactId, Vec<u8>>) {
    let mut state = ArtifactChainState::new(test_chain_definition());
    let mut blocks = Vec::with_capacity(count);
    let mut payloads = HashMap::with_capacity(count);
    for index in 0..count {
        let bytes = independent_proof_bytes(index + 1);
        let artifact_id = artifact_id(&bytes);
        let block = state.prepare_block(artifact_id).unwrap();
        state.apply_block(&block, bytes.clone()).unwrap();
        payloads.insert(artifact_id, bytes);
        blocks.push(block);
    }
    (blocks, payloads)
}

fn dependent_extension() -> (Vec<ArtifactBlock>, HashMap<ArtifactId, Vec<u8>>) {
    let mut state = ArtifactChainState::new(test_chain_definition());
    let mut identity = ArtifactDag::new();
    let parent_bytes = pairing_bytes();
    let parent_record = identity
        .apply_canonical_artifact_bytes(parent_bytes.clone())
        .unwrap();
    let parent_artifact_id = parent_record.artifact_id();
    let parent_proof_id = parent_record.as_proof().unwrap().proof_id();
    let parent_block = state.prepare_block(parent_artifact_id).unwrap();
    state
        .apply_block(&parent_block, parent_bytes.clone())
        .unwrap();

    let child_bytes = referenced_generalization_bytes(parent_proof_id);
    let child_artifact_id = identity
        .apply_canonical_artifact_bytes(child_bytes.clone())
        .unwrap()
        .artifact_id();
    let child_block = state.prepare_block(child_artifact_id).unwrap();
    state
        .apply_block(&child_block, child_bytes.clone())
        .unwrap();

    (
        vec![parent_block, child_block],
        HashMap::from([
            (parent_artifact_id, parent_bytes),
            (child_artifact_id, child_bytes),
        ]),
    )
}

fn pending_block_request(
    network: &StaticArtifactNetwork,
    peer_id: PeerId,
) -> (request_response::OutboundRequestId, ArtifactBlockRequest) {
    network
        .pending
        .iter()
        .find_map(|(request_id, pending)| match (request_id, pending) {
            (ExchangeRequestId::Block(request_id), PendingRequest::Block(pending))
                if network.pending_peer_id(pending.peer_index) == peer_id =>
            {
                Some((*request_id, pending.request))
            }
            _ => None,
        })
        .expect("the catch-up has one pending block request")
}

fn pending_artifact_request(
    network: &StaticArtifactNetwork,
    peer_id: PeerId,
) -> (request_response::OutboundRequestId, ArtifactRequest) {
    network
        .pending
        .iter()
        .find_map(|(request_id, pending)| match (request_id, pending) {
            (ExchangeRequestId::Artifact(request_id), PendingRequest::Artifact(pending))
                if network.pending_peer_id(pending.peer_index) == peer_id =>
            {
                Some((*request_id, pending.request))
            }
            _ => None,
        })
        .expect("the catch-up has one pending proof request")
}

fn block_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    bytes: impl Into<Vec<u8>>,
) -> NetworkEvent {
    let bytes = bytes.into();
    let (request_id, _) = pending_block_request(network, peer_id);
    network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_300),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactBlockWireResponse::new(bytes),
            },
        })
        .expect("the retained catch-up block request produces one terminal event")
}

fn artifact_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    let (request_id, _) = pending_artifact_request(network, peer_id);
    network
        .handle_artifact_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_301),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained catch-up proof request produces one terminal event")
}

fn unrelated_event(peer_id: PeerId) -> NetworkEvent {
    NetworkEvent::ArtifactCancellationDrained {
        peer_id,
        request: ArtifactRequest::new(ArtifactId::from_bytes([0xee; 32])),
        outcome: crate::CancellationDrainOutcome::ResponseDiscarded,
    }
}

fn pull_to_import(
    mut catch_up: ArtifactBlockCatchUp,
    network: &mut StaticArtifactNetwork,
    selected: &mut ArtifactChainJournal,
    peer_id: PeerId,
    blocks: &[ArtifactBlock],
) -> ArtifactBlockCatchUp {
    for block in blocks.iter().rev() {
        assert_eq!(catch_up.pending_block_id(), block.id());
        assert_eq!(catch_up.committed_block_count(), 0);
        let event = block_response_event(network, peer_id, block.to_canonical_bytes());
        assert!(catch_up.accepts_event(&event));
        catch_up = catch_up
            .on_event(network, selected, event)
            .unwrap()
            .expect("catch-up cannot finish while only retrieving ancestry");
    }
    assert!(
        !network
            .pending
            .keys()
            .any(|request| matches!(request, ExchangeRequestId::Block(_)))
    );
    assert!(
        network
            .pending
            .keys()
            .any(|request| matches!(request, ExchangeRequestId::Artifact(_)))
    );
    catch_up
}

fn drive_unit_success(count: usize) {
    let directory = TestDirectory::new(&format!("catch-up-{count}-blocks"));
    let mut selected = create_journal(directory.path()).unwrap();
    let anchor = selected.head_block_id().unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(count);
    let target = blocks.last().unwrap().id();
    let mut network = test_network_for_peers(&[peer_id]);
    let catch_up = network
        .start_artifact_block_catch_up(&selected, peer_id, target)
        .unwrap();
    let catch_up = pull_to_import(catch_up, &mut network, &mut selected, peer_id, &blocks);

    assert_eq!(catch_up.anchor_block_id(), anchor);
    assert_eq!(catch_up.target_block_id(), target);
    assert_eq!(catch_up.pending_block_id(), blocks[0].id());
    assert_eq!(catch_up.last_acknowledged_head_block_id(), anchor);
    let mut catch_up = Some(catch_up);
    for (index, block) in blocks.iter().enumerate() {
        let current = catch_up.take().unwrap();
        assert_eq!(current.pending_block_id(), block.id());
        let (_, request) = pending_artifact_request(&network, current.pending_peer_id());
        let event = artifact_response_event(
            &mut network,
            peer_id,
            payloads[&request.artifact_id()].clone(),
        );
        assert!(current.accepts_event(&event));
        match current
            .on_event(&mut network, &mut selected, event)
            .unwrap()
        {
            Some(next) => {
                assert!(index + 1 < blocks.len());
                assert_eq!(next.committed_block_count(), index + 1);
                assert_eq!(next.last_acknowledged_head_block_id(), block.id());
                catch_up = Some(next);
            }
            None => assert_eq!(index + 1, blocks.len()),
        }
    }

    assert!(catch_up.is_none());
    assert_eq!(selected.head_block_id().unwrap(), target);
    assert_eq!(
        selected.artifact_set_root().unwrap(),
        blocks.last().unwrap().resulting_artifact_set_root()
    );
    assert_eq!(selected.len().unwrap(), count);
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn start_preserves_exact_metadata_and_nests_pull_precedence() {
    let directory = TestDirectory::new("catch-up-start");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let anchor = selected.head_block_id().unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, _) = valid_extension(1);
    let target = blocks[0].id();
    let mut network = test_network_for_peers(&[peer_id]);

    let catch_up = network
        .start_artifact_block_catch_up(&selected, peer_id, target)
        .unwrap();
    assert_eq!(catch_up.anchor_block_id(), anchor);
    assert_eq!(catch_up.target_block_id(), target);
    assert_eq!(catch_up.pending_block_id(), target);
    assert_eq!(catch_up.pending_peer_id(), peer_id);
    assert_eq!(catch_up.committed_block_count(), 0);
    assert_eq!(catch_up.last_acknowledged_head_block_id(), anchor);
    let (_, request) = pending_block_request(&network, peer_id);
    assert_eq!(request.block_id(), target);
    catch_up.cancel();
    drop(block_response_event(&mut network, peer_id, Vec::new()));

    assert!(matches!(
        network.start_artifact_block_catch_up(&selected, unknown_peer, anchor),
        Err(ArtifactBlockCatchUpError::AncestryPull { source })
            if matches!(
                source.as_ref(),
                ArtifactBlockAncestryPullError::TargetAlreadySelected { block_id }
                    if *block_id == anchor
            )
    ));
    assert!(matches!(
        network.start_artifact_block_catch_up(&selected, unknown_peer, target),
        Err(ArtifactBlockCatchUpError::AncestryPull { source })
            if matches!(
                source.as_ref(),
                ArtifactBlockAncestryPullError::RequestStart {
                    source: RequestStartError::UnknownPeer(peer_id),
                    ..
                } if *peer_id == unknown_peer
            )
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(network.pending.is_empty());
}

#[test]
fn one_three_and_sixteen_block_catch_ups_commit_only_after_the_phase_bridge() {
    for count in [1, 3, 16] {
        drive_unit_success(count);
    }
}

#[test]
fn referenced_child_catch_up_imports_its_parent_block_first() {
    let directory = TestDirectory::new("catch-up-referenced-child");
    let mut selected = create_journal(directory.path()).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = dependent_extension();
    let [parent, child] = blocks.as_slice() else {
        panic!("the dependent fixture has exactly two blocks")
    };
    assert_eq!(child.parent_block_id(), parent.id());
    let mut network = test_network_for_peers(&[peer_id]);
    let catch_up = network
        .start_artifact_block_catch_up(&selected, peer_id, child.id())
        .unwrap();
    let catch_up = pull_to_import(catch_up, &mut network, &mut selected, peer_id, &blocks);

    assert_eq!(catch_up.pending_block_id(), parent.id());
    let (_, request) = pending_artifact_request(&network, peer_id);
    assert_eq!(request.artifact_id(), parent.artifact_id());
    let event = artifact_response_event(
        &mut network,
        peer_id,
        payloads[&parent.artifact_id()].clone(),
    );
    let catch_up = catch_up
        .on_event(&mut network, &mut selected, event)
        .unwrap()
        .expect("the referenced child remains after its parent commits");
    assert_eq!(selected.head_block_id().unwrap(), parent.id());
    assert_eq!(selected.len().unwrap(), 1);

    assert_eq!(catch_up.pending_block_id(), child.id());
    let (_, request) = pending_artifact_request(&network, peer_id);
    assert_eq!(request.artifact_id(), child.artifact_id());
    let event = artifact_response_event(
        &mut network,
        peer_id,
        payloads[&child.artifact_id()].clone(),
    );
    assert!(
        catch_up
            .on_event(&mut network, &mut selected, event)
            .unwrap()
            .is_none()
    );
    assert_eq!(selected.head_block_id().unwrap(), child.id());
    assert_eq!(selected.len().unwrap(), 2);
    assert!(selected.artifact(parent.artifact_id()).unwrap().is_some());
    assert!(selected.artifact(child.artifact_id()).unwrap().is_some());
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn later_import_failure_reports_and_preserves_the_exact_acknowledged_prefix() {
    let directory = TestDirectory::new("catch-up-prefix-failure");
    let mut selected = create_journal(directory.path()).unwrap();
    let anchor = selected.head_block_id().unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(2);
    let target = blocks[1].id();
    let mut network = test_network_for_peers(&[peer_id]);
    let catch_up = network
        .start_artifact_block_catch_up(&selected, peer_id, target)
        .unwrap();
    let catch_up = pull_to_import(catch_up, &mut network, &mut selected, peer_id, &blocks);

    let (_, request) = pending_artifact_request(&network, peer_id);
    let event = artifact_response_event(
        &mut network,
        peer_id,
        payloads[&request.artifact_id()].clone(),
    );
    let catch_up = catch_up
        .on_event(&mut network, &mut selected, event)
        .unwrap()
        .unwrap();
    assert_eq!(catch_up.committed_block_count(), 1);
    assert_eq!(catch_up.last_acknowledged_head_block_id(), blocks[0].id());
    assert_eq!(catch_up.pending_block_id(), blocks[1].id());

    let event = artifact_response_event(&mut network, peer_id, vec![0xff]);
    let error = catch_up
        .on_event(&mut network, &mut selected, event)
        .unwrap_err();
    let ArtifactBlockCatchUpError::AncestryImport { source } = error else {
        panic!("later proof failure escaped its ancestry-import boundary")
    };
    assert_eq!(source.committed_block_count(), 1);
    assert_eq!(source.last_acknowledged_head_block_id(), blocks[0].id());
    assert_eq!(source.failed_block_id(), blocks[1].id());
    assert_eq!(source.target_block_id(), target);
    assert_eq!(selected.head_block_id().unwrap(), blocks[0].id());
    assert_ne!(selected.head_block_id().unwrap(), anchor);
    assert_eq!(selected.len().unwrap(), 1);
    assert!(
        selected
            .artifact(blocks[0].artifact_id())
            .unwrap()
            .is_some()
    );
    assert!(
        selected
            .artifact(blocks[1].artifact_id())
            .unwrap()
            .is_none()
    );
}

#[test]
fn pull_completion_preserves_the_import_start_failure_boundary() {
    let directory = TestDirectory::new("catch-up-import-start-failure");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, _) = valid_extension(1);
    let target = blocks[0].id();
    let mut network = test_network_for_peers(&[peer_id]);
    let catch_up = network
        .start_artifact_block_catch_up(&selected, peer_id, target)
        .unwrap();
    assert!(!catch_up.accepts_event(&NetworkEvent::Listening {
        address: crate::tests::address(0),
    }));
    let event = block_response_event(&mut network, peer_id, blocks[0].to_canonical_bytes());
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);

    let error = catch_up
        .on_event(&mut network, &mut selected, event)
        .unwrap_err();
    let ArtifactBlockCatchUpError::AncestryImport { source } = error else {
        panic!("import-start failure escaped its ancestry-import boundary")
    };
    assert_eq!(source.committed_block_count(), 0);
    assert_eq!(source.last_acknowledged_head_block_id(), before.head);
    assert_eq!(source.failed_block_id(), target);
    assert!(matches!(
        source.block_import_error(),
        ArtifactBlockImportError::NoEligibleArtifactPeer { .. }
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn cancellation_delegates_block_and_artifact_request_drain_semantics() {
    let directory = TestDirectory::new("catch-up-cancellation");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(1);
    let target = blocks[0].id();
    let mut network = test_network_for_peers(&[peer_id]);

    let catch_up = network
        .start_artifact_block_catch_up(&selected, peer_id, target)
        .unwrap();
    catch_up.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let terminal = block_response_event(&mut network, peer_id, Vec::new());
    assert!(matches!(terminal, NetworkEvent::OutboundBlock(_)));
    drop(terminal);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let catch_up = network
        .start_artifact_block_catch_up(&selected, peer_id, target)
        .unwrap();
    let catch_up = pull_to_import(catch_up, &mut network, &mut selected, peer_id, &blocks);
    let (_, request) = pending_artifact_request(&network, peer_id);
    catch_up.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let drained = artifact_response_event(
        &mut network,
        peer_id,
        payloads[&request.artifact_id()].clone(),
    );
    assert!(matches!(
        drained,
        NetworkEvent::ArtifactCancellationDrained { .. }
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn routing_and_network_instance_correlation_delegate_across_both_phases() {
    let directory = TestDirectory::new("catch-up-routing");
    let mut selected = create_journal(directory.path()).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, _) = valid_extension(1);
    let target = blocks[0].id();
    let mut origin = test_network_for_peers(&[peer_id]);
    let mut wrong_driver = test_network_for_peers(&[peer_id]);

    let catch_up = origin
        .start_artifact_block_catch_up(&selected, peer_id, target)
        .unwrap();
    assert!(!catch_up.accepts_event(&unrelated_event(peer_id)));
    let block = block_response_event(&mut origin, peer_id, blocks[0].to_canonical_bytes());
    assert!(catch_up.accepts_event(&block));
    assert!(matches!(
        catch_up.on_event(&mut wrong_driver, &mut selected, block),
        Err(ArtifactBlockCatchUpError::AncestryPull { source })
            if matches!(source.as_ref(), ArtifactBlockAncestryPullError::UnexpectedEvent)
    ));
    assert_eq!(selected.len().unwrap(), 0);

    let catch_up = origin
        .start_artifact_block_catch_up(&selected, peer_id, target)
        .unwrap();
    let catch_up = pull_to_import(catch_up, &mut origin, &mut selected, peer_id, &blocks);
    assert!(!catch_up.accepts_event(&unrelated_event(peer_id)));
    let (_, request) = pending_artifact_request(&origin, peer_id);
    let proof = artifact_response_event(&mut origin, peer_id, independent_proof_bytes(1));
    assert_eq!(request.artifact_id(), blocks[0].artifact_id());
    assert!(catch_up.accepts_event(&proof));
    assert!(matches!(
        catch_up.on_event(&mut wrong_driver, &mut selected, proof),
        Err(ArtifactBlockCatchUpError::AncestryImport { source })
            if matches!(
                source.block_import_error(),
                crate::ArtifactBlockImportError::UnexpectedEvent
            )
    ));
    assert_eq!(selected.len().unwrap(), 0);
}

#[tokio::test]
async fn real_two_node_catch_up_reaches_and_reopens_exact_three_block_target() {
    let (mut target_network, mut source_network, _, source_peer_id) = connected_pair().await;
    let source_directory = TestDirectory::new("catch-up-real-source");
    let mut source = create_journal(source_directory.path()).unwrap();
    let mut artifact_ids = Vec::new();
    let mut block_ids = Vec::new();
    for index in 1..=3 {
        let bytes = independent_proof_bytes(index);
        let artifact_id = artifact_id(&bytes);
        let block = source.prepare_block(artifact_id).unwrap();
        source.apply_block(&block, bytes).unwrap();
        artifact_ids.push(artifact_id);
        block_ids.push(block.id());
    }
    let source_before = snapshot(&source_directory, &source);
    let target_id = *block_ids.last().unwrap();

    let target_directory = TestDirectory::new("catch-up-real-target");
    let mut target = create_journal(target_directory.path()).unwrap();
    let mut catch_up = Some(
        target_network
            .start_artifact_block_catch_up(&target, source_peer_id, target_id)
            .unwrap(),
    );
    let mut served_blocks = 0;
    let mut served_proofs = 0;

    timeout(Duration::from_secs(20), async {
        while catch_up.is_some() {
            tokio::select! {
                event = target_network.next_event() => {
                    let current = catch_up.take().unwrap();
                    if current.accepts_event(&event) {
                        catch_up = current
                            .on_event(&mut target_network, &mut target, event)
                            .unwrap();
                    } else {
                        catch_up = Some(current);
                    }
                }
                event = source_network.next_journal_service_event(&source) => match event {
                    JournalServiceEvent::Served(JournalServiceRequest::Block { .. }) => {
                        served_blocks += 1;
                    }
                    JournalServiceEvent::Served(JournalServiceRequest::Artifact { .. }) => {
                        served_proofs += 1;
                    }
                    JournalServiceEvent::Served(JournalServiceRequest::ChainHead { .. }) => {
                        panic!("catch-up unexpectedly requested a chain head")
                    }
                    JournalServiceEvent::ServeFailed { request, error } => {
                        panic!("source failed to serve {request:?}: {error}")
                    }
                    JournalServiceEvent::Network(NetworkEvent::ListenerError { error, .. }) => {
                        panic!("source listener failed: {error}")
                    }
                    JournalServiceEvent::Network(_) => {}
                },
            }
        }
    })
    .await
    .expect("real three-block catch-up timed out");

    assert_eq!(served_blocks, 3, "each ancestry block must be fetched once");
    assert_eq!(
        served_proofs, 3,
        "each independent proof must be fetched once"
    );
    assert_eq!(target.head_block_id().unwrap(), target_id);
    assert_eq!(
        target.artifact_set_root().unwrap(),
        source.artifact_set_root().unwrap()
    );
    assert_eq!(target.len().unwrap(), source.len().unwrap());
    for artifact_id in artifact_ids {
        assert_eq!(
            target
                .artifact(artifact_id)
                .unwrap()
                .unwrap()
                .canonical_artifact_bytes(),
            source
                .artifact(artifact_id)
                .unwrap()
                .unwrap()
                .canonical_artifact_bytes()
        );
    }
    for block_id in block_ids {
        assert_eq!(
            target
                .block(block_id)
                .unwrap()
                .unwrap()
                .to_canonical_bytes(),
            source
                .block(block_id)
                .unwrap()
                .unwrap()
                .to_canonical_bytes()
        );
    }
    assert_snapshot(&source_directory, &source, &source_before);

    let expected_root = target.artifact_set_root().unwrap();
    let expected_len = target.len().unwrap();
    drop(target);
    let reopened = ArtifactChainJournal::open_verified(
        target_directory.path(),
        test_chain_definition(),
        target_id,
    )
    .unwrap();
    assert_eq!(reopened.head_block_id().unwrap(), target_id);
    assert_eq!(reopened.artifact_set_root().unwrap(), expected_root);
    assert_eq!(reopened.len().unwrap(), expected_len);
}
