use std::collections::HashMap;
use std::sync::atomic::Ordering;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::block_exchange::ProofBlockRequest;
use naome::proof_exchange::{ProofRequest, ProofResponse};
use naome_chain::{
    ProofBlock, ProofBlockApplyError, ProofChainId, ProofChainState, ProofDag,
    ProofTransitionApplyError,
};
use naome_ledger::{LedgerError, ProofBatchError};
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use naome_storage::{ProofChainJournal, ProofChainJournalError};

use super::*;
use crate::codec::ProofBlockWireResponse;
use crate::tests::{TestDirectory, create_journal, pairing_bytes, test_network_for_peers};
use crate::{
    ExchangeRequestId, Keypair, MAX_PROOF_BLOCK_ANCESTRY_BLOCKS, NetworkEvent, PendingRequest,
    ProofBlockAncestryPullProgress, ProofBlockImportError,
};

fn canonical_bytes(steps: Vec<ProofStep>) -> Vec<u8> {
    ProofCertificate::new(steps)
        .unwrap()
        .into_unchecked_normal_form()
        .into_canonical_bytes()
        .into_vec()
}

fn independent_proof_bytes(index: usize) -> Vec<u8> {
    let mut steps = vec![ProofStep::EqualityReflexivity {
        variable: naome_foundation::FreeVariable::new(u32::try_from(index).unwrap()),
    }];
    for variable in 0..=index {
        steps.push(ProofStep::Generalization {
            premise: u32::try_from(steps.len() - 1).unwrap(),
            variable: naome_foundation::FreeVariable::new(u32::try_from(variable).unwrap()),
        });
    }
    canonical_bytes(steps)
}

fn proof_id(bytes: &[u8]) -> ProofId {
    ProofDag::new()
        .apply_canonical_proof_bytes(bytes.to_vec())
        .unwrap()
        .proof_id()
}

fn valid_extension(
    selected: &ProofChainJournal,
    count: usize,
) -> (Vec<ProofBlock>, HashMap<ProofId, Vec<u8>>) {
    let mut state = ProofChainState::new(selected.chain_id());
    let mut blocks = Vec::with_capacity(count);
    let mut payloads = HashMap::with_capacity(count);
    for index in 0..count {
        let bytes = independent_proof_bytes(index + 1);
        let id = proof_id(&bytes);
        let block = state.prepare_block(vec![id]).unwrap();
        state
            .apply_block(
                &block,
                vec![naome_chain::AddressedProofCandidate::new(id, bytes.clone())],
            )
            .unwrap();
        payloads.insert(id, bytes);
        blocks.push(block);
    }
    (blocks, payloads)
}

fn ancestry(
    selected: &ProofChainJournal,
    peer_id: PeerId,
    blocks: Vec<ProofBlock>,
) -> UnselectedProofBlockAncestry {
    let anchor_block_id = selected.head_block_id().unwrap();
    let target_block_id = blocks.last().unwrap().id();
    UnselectedProofBlockAncestry::from_parts_for_test(
        peer_id,
        anchor_block_id,
        target_block_id,
        blocks,
    )
}

fn pending_proof_request(
    network: &StaticProofNetwork,
    peer_id: PeerId,
) -> (request_response::OutboundRequestId, ProofRequest) {
    network
        .pending
        .iter()
        .find_map(|(request_id, pending)| match (request_id, pending) {
            (ExchangeRequestId::Proof(request_id), PendingRequest::Proof(pending))
                if network.pending_peer_id(pending.peer_index) == peer_id =>
            {
                Some((*request_id, pending.request))
            }
            _ => None,
        })
        .expect("the ancestry import has one pending proof request")
}

fn pending_block_request(
    network: &StaticProofNetwork,
    peer_id: PeerId,
) -> (request_response::OutboundRequestId, ProofBlockRequest) {
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
        .expect("the ancestry pull has one pending block request")
}

fn block_response_event(
    network: &mut StaticProofNetwork,
    peer_id: PeerId,
    block: &ProofBlock,
) -> NetworkEvent {
    let (request_id, request) = pending_block_request(network, peer_id);
    assert_eq!(request.block_id(), block.id());
    network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_101),
            message: request_response::Message::Response {
                request_id,
                response: ProofBlockWireResponse::new(block.to_canonical_bytes()),
            },
        })
        .expect("the retained block request produces one terminal event")
}

fn pull_ancestry(
    network: &mut StaticProofNetwork,
    selected: &ProofChainJournal,
    peer_id: PeerId,
    blocks: &[ProofBlock],
) -> UnselectedProofBlockAncestry {
    let mut pull = network
        .start_proof_block_ancestry_pull(selected, peer_id, blocks.last().unwrap().id())
        .unwrap();
    for (index, block) in blocks.iter().rev().enumerate() {
        let event = block_response_event(network, peer_id, block);
        match pull.on_event(network, selected, event).unwrap() {
            ProofBlockAncestryPullProgress::AwaitingResponse(next) => {
                assert!(index + 1 < blocks.len());
                pull = next;
            }
            ProofBlockAncestryPullProgress::Complete(ancestry) => {
                assert_eq!(index + 1, blocks.len());
                return ancestry;
            }
        }
    }
    unreachable!("the nonempty path completes at its anchor")
}

fn proof_response_event_from(
    network: &mut StaticProofNetwork,
    expected_peer_id: PeerId,
    actual_peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    let (request_id, _) = pending_proof_request(network, expected_peer_id);
    network
        .handle_proof_exchange_event(request_response::Event::Message {
            peer: actual_peer_id,
            connection_id: ConnectionId::new_unchecked(1_100),
            message: request_response::Message::Response {
                request_id,
                response: ProofResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained proof request produces one terminal event")
}

fn proof_response_event(
    network: &mut StaticProofNetwork,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    proof_response_event_from(network, peer_id, peer_id, bytes)
}

fn drive_success(
    network: &mut StaticProofNetwork,
    selected: &mut ProofChainJournal,
    mut import: ProofBlockAncestryImport,
    payloads: &HashMap<ProofId, Vec<u8>>,
) {
    loop {
        assert!(
            !network
                .pending
                .keys()
                .any(|request| matches!(request, ExchangeRequestId::Block(_))),
            "retained ancestry blocks must never be fetched again"
        );
        let peer_id = import.pending_peer_id();
        let (_, request) = pending_proof_request(network, peer_id);
        let bytes = payloads.get(&request.proof_id()).unwrap().clone();
        let event = proof_response_event(network, peer_id, bytes);
        assert!(import.accepts_event(&event));
        match import.on_event(network, selected, event).unwrap() {
            Some(next) => import = next,
            None => return,
        }
    }
}

#[test]
fn one_three_and_sixteen_block_paths_commit_forward_without_block_refetch() {
    for count in [1, 3, MAX_PROOF_BLOCK_ANCESTRY_BLOCKS] {
        let directory = TestDirectory::new("ancestry-import-success");
        let mut selected = create_journal(directory.path()).unwrap();
        let anchor = selected.head_block_id().unwrap();
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let (blocks, payloads) = valid_extension(&selected, count);
        let target = blocks.last().unwrap().id();
        let expected_ids = blocks.iter().map(ProofBlock::id).collect::<Vec<_>>();
        let mut network = test_network_for_peers(&[peer_id]);

        let import = network
            .start_proof_block_ancestry_import(&selected, ancestry(&selected, peer_id, blocks))
            .unwrap();
        assert_eq!(import.anchor_block_id(), anchor);
        assert_eq!(import.target_block_id(), target);
        assert_eq!(import.committed_block_count(), 0);
        assert_eq!(import.last_acknowledged_head_block_id(), anchor);
        assert_eq!(import.pending_block_id(), expected_ids[0]);
        drive_success(&mut network, &mut selected, import, &payloads);

        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert_eq!(selected.head_block_id().unwrap(), target);
        for block_id in expected_ids {
            assert!(selected.block(block_id).unwrap().is_some());
        }
        drop(selected);
        let reopened = ProofChainJournal::open_verified(
            directory.path(),
            ProofChainId::from_bytes([0x41; 32]),
            target,
        )
        .unwrap();
        assert_eq!(reopened.len().unwrap(), count);
    }
}

#[test]
fn invalid_second_payload_reports_prefix_and_fresh_pull_retries_from_that_head() {
    let directory = TestDirectory::new("ancestry-import-prefix");
    let mut selected = create_journal(directory.path()).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(&selected, 3);
    let ids = blocks.iter().map(ProofBlock::id).collect::<Vec<_>>();
    let target = ids[2];
    let mut network = test_network_for_peers(&[peer_id]);
    let import = network
        .start_proof_block_ancestry_import(&selected, ancestry(&selected, peer_id, blocks.clone()))
        .unwrap();

    let (_, first_request) = pending_proof_request(&network, peer_id);
    let first_event = proof_response_event(
        &mut network,
        peer_id,
        payloads[&first_request.proof_id()].clone(),
    );
    let import = import
        .on_event(&mut network, &mut selected, first_event)
        .unwrap()
        .unwrap();
    assert_eq!(import.committed_block_count(), 1);
    assert_eq!(import.last_acknowledged_head_block_id(), ids[0]);
    assert_eq!(import.pending_block_id(), ids[1]);

    let expected_proof_id = pending_proof_request(&network, peer_id).1.proof_id();
    let wrong = pairing_bytes();
    let actual_proof_id = proof_id(&wrong);
    assert_ne!(actual_proof_id, expected_proof_id);
    let event = proof_response_event(&mut network, peer_id, wrong);
    let error = import
        .on_event(&mut network, &mut selected, event)
        .unwrap_err();
    assert_eq!(error.target_block_id(), target);
    assert_eq!(error.failed_block_id(), ids[1]);
    assert_eq!(error.committed_block_count(), 1);
    assert_eq!(error.last_acknowledged_head_block_id(), ids[0]);
    assert!(matches!(
        error.block_import_error(),
        ProofBlockImportError::SelectedState { source }
            if matches!(
                source.as_ref(),
                ProofChainJournalError::BlockAdmission {
                    source: ProofBlockApplyError::Transition {
                        source: ProofTransitionApplyError::Batch {
                            source: ProofBatchError::Candidate {
                                expected: Some(expected),
                                source: LedgerError::ProofIdMismatch { expected: nested, actual },
                                ..
                            }
                        }
                    }
                } if *expected == expected_proof_id
                    && *nested == expected_proof_id
                    && *actual == actual_proof_id
            )
    ));
    assert_eq!(selected.head_block_id().unwrap(), ids[0]);
    assert!(selected.block(ids[0]).unwrap().is_some());
    assert!(selected.block(ids[1]).unwrap().is_none());
    assert!(selected.block(ids[2]).unwrap().is_none());
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let fresh = pull_ancestry(&mut network, &selected, peer_id, &blocks[1..]);
    assert_eq!(fresh.anchor_block_id(), ids[0]);
    assert_eq!(fresh.target_block_id(), target);
    let import = network
        .start_proof_block_ancestry_import(&selected, fresh)
        .unwrap();
    drive_success(&mut network, &mut selected, import, &payloads);
    assert_eq!(selected.head_block_id().unwrap(), target);
    assert!(selected.block(ids[1]).unwrap().is_some());
    assert!(selected.block(ids[2]).unwrap().is_some());
}

#[test]
fn start_rejects_head_drift_before_proof_traffic_with_zero_prefix() {
    let directory = TestDirectory::new("ancestry-import-start-drift");
    let mut selected = create_journal(directory.path()).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, _) = valid_extension(&selected, 1);
    let target = blocks[0].id();
    let ancestry = ancestry(&selected, peer_id, blocks);
    let anchor = ancestry.anchor_block_id();
    crate::tests::apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let actual = selected.head_block_id().unwrap();
    let mut network = test_network_for_peers(&[peer_id]);

    let error = network
        .start_proof_block_ancestry_import(&selected, ancestry)
        .unwrap_err();
    assert_eq!(error.target_block_id(), target);
    assert_eq!(error.failed_block_id(), target);
    assert_eq!(error.committed_block_count(), 0);
    assert_eq!(error.last_acknowledged_head_block_id(), anchor);
    assert!(matches!(
        error.block_import_error(),
        ProofBlockImportError::ParentBlockIdMismatch { expected, actual: parent }
            if *expected == actual && *parent != actual
    ));
    assert!(network.pending.is_empty());
}

#[test]
fn cancellation_before_first_acknowledgement_drains_only_the_active_proof_request() {
    let directory = TestDirectory::new("ancestry-import-cancel");
    let selected = create_journal(directory.path()).unwrap();
    let anchor = selected.head_block_id().unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(&selected, 3);
    let mut network = test_network_for_peers(&[peer_id]);
    let import = network
        .start_proof_block_ancestry_import(&selected, ancestry(&selected, peer_id, blocks))
        .unwrap();
    let (_, request) = pending_proof_request(&network, peer_id);

    import.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let drained =
        proof_response_event(&mut network, peer_id, payloads[&request.proof_id()].clone());
    assert!(matches!(
        drained,
        NetworkEvent::ProofCancellationDrained { .. }
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(selected.head_block_id().unwrap(), anchor);
    assert!(network.pending.is_empty());
}

#[test]
fn foreign_driver_is_rejected_without_selecting_the_current_block() {
    let directory = TestDirectory::new("ancestry-import-foreign-driver");
    let mut selected = create_journal(directory.path()).unwrap();
    let anchor = selected.head_block_id().unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(&selected, 1);
    let mut origin = test_network_for_peers(&[peer_id]);
    let mut wrong_driver = test_network_for_peers(&[peer_id]);
    let import = origin
        .start_proof_block_ancestry_import(&selected, ancestry(&selected, peer_id, blocks))
        .unwrap();
    let (_, request) = pending_proof_request(&origin, peer_id);
    let event = proof_response_event(&mut origin, peer_id, payloads[&request.proof_id()].clone());
    assert!(import.accepts_event(&event));

    let error = import
        .on_event(&mut wrong_driver, &mut selected, event)
        .unwrap_err();
    assert_eq!(error.committed_block_count(), 0);
    assert_eq!(error.last_acknowledged_head_block_id(), anchor);
    assert!(matches!(
        error.block_import_error(),
        ProofBlockImportError::UnexpectedEvent
    ));
    assert_eq!(selected.head_block_id().unwrap(), anchor);
    assert!(origin.pending.is_empty());
    assert!(wrong_driver.pending.is_empty());
    assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(
        wrong_driver.pending_budget.active.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn selected_head_drift_during_proof_acquisition_rejects_the_current_block() {
    let directory = TestDirectory::new("ancestry-import-midflight-drift");
    let mut selected = create_journal(directory.path()).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(&selected, 1);
    let target = blocks[0].id();
    let mut network = test_network_for_peers(&[peer_id]);
    let import = network
        .start_proof_block_ancestry_import(&selected, ancestry(&selected, peer_id, blocks))
        .unwrap();
    let (_, request) = pending_proof_request(&network, peer_id);
    crate::tests::apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let drifted_head = selected.head_block_id().unwrap();

    let event = proof_response_event(&mut network, peer_id, payloads[&request.proof_id()].clone());
    let error = import
        .on_event(&mut network, &mut selected, event)
        .unwrap_err();
    assert_eq!(error.failed_block_id(), target);
    assert_eq!(error.committed_block_count(), 0);
    assert!(matches!(
        error.block_import_error(),
        ProofBlockImportError::ParentBlockIdMismatch { expected, actual }
            if *expected == drifted_head && *actual != drifted_head
    ));
    assert_eq!(selected.head_block_id().unwrap(), drifted_head);
    assert!(selected.block(target).unwrap().is_none());
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn peer_mismatch_precedes_selected_head_drift() {
    let directory = TestDirectory::new("ancestry-import-peer-mismatch");
    let mut selected = create_journal(directory.path()).unwrap();
    let expected_peer = Keypair::generate_ed25519().public().to_peer_id();
    let actual_peer = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, _) = valid_extension(&selected, 1);
    let target = blocks[0].id();
    let mut network = test_network_for_peers(&[expected_peer, actual_peer]);
    let import = network
        .start_proof_block_ancestry_import(&selected, ancestry(&selected, expected_peer, blocks))
        .unwrap();
    crate::tests::apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let drifted_head = selected.head_block_id().unwrap();

    let event = proof_response_event_from(&mut network, expected_peer, actual_peer, Vec::new());
    let error = import
        .on_event(&mut network, &mut selected, event)
        .unwrap_err();
    assert_eq!(error.failed_block_id(), target);
    assert_eq!(error.committed_block_count(), 0);
    assert!(matches!(
        error.block_import_error(),
        ProofBlockImportError::ProofAcquisition { source, .. }
            if matches!(
                source.as_ref(),
                crate::DependencyAcquisitionError::RequestFailed {
                    peer_id,
                    source,
                    ..
                } if *peer_id == expected_peer
                    && matches!(
                        source.as_ref(),
                        crate::OutboundProofFailure::PeerMismatch { expected, actual }
                            if *expected == expected_peer && *actual == actual_peer
                    )
            )
    ));
    assert_eq!(selected.head_block_id().unwrap(), drifted_head);
    assert!(selected.block(target).unwrap().is_none());
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn cancellation_after_one_acknowledgement_retains_only_that_prefix() {
    let directory = TestDirectory::new("ancestry-import-prefix-cancel");
    let mut selected = create_journal(directory.path()).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(&selected, 3);
    let ids = blocks.iter().map(ProofBlock::id).collect::<Vec<_>>();
    let mut network = test_network_for_peers(&[peer_id]);
    let import = network
        .start_proof_block_ancestry_import(&selected, ancestry(&selected, peer_id, blocks))
        .unwrap();
    let (_, first_request) = pending_proof_request(&network, peer_id);
    let first = proof_response_event(
        &mut network,
        peer_id,
        payloads[&first_request.proof_id()].clone(),
    );
    let import = import
        .on_event(&mut network, &mut selected, first)
        .unwrap()
        .unwrap();
    let (_, second_request) = pending_proof_request(&network, peer_id);
    assert_eq!(import.committed_block_count(), 1);
    assert_eq!(import.last_acknowledged_head_block_id(), ids[0]);

    import.cancel();
    assert_eq!(selected.head_block_id().unwrap(), ids[0]);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let drained = proof_response_event(
        &mut network,
        peer_id,
        payloads[&second_request.proof_id()].clone(),
    );
    assert!(matches!(
        drained,
        NetworkEvent::ProofCancellationDrained { .. }
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(selected.block(ids[0]).unwrap().is_some());
    assert!(selected.block(ids[1]).unwrap().is_none());
    assert!(selected.block(ids[2]).unwrap().is_none());
    assert!(network.pending.is_empty());
}

#[test]
fn disconnected_source_prevents_next_block_start_after_acknowledged_prefix() {
    let directory = TestDirectory::new("ancestry-import-next-start-failure");
    let mut selected = create_journal(directory.path()).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let (blocks, payloads) = valid_extension(&selected, 2);
    let ids = blocks.iter().map(ProofBlock::id).collect::<Vec<_>>();
    let next_root = blocks[1].transition().root_proof_id();
    let target = ids[1];
    let mut network = test_network_for_peers(&[peer_id]);
    let import = network
        .start_proof_block_ancestry_import(&selected, ancestry(&selected, peer_id, blocks))
        .unwrap();
    let (_, request) = pending_proof_request(&network, peer_id);
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);

    let event = proof_response_event(&mut network, peer_id, payloads[&request.proof_id()].clone());
    let error = import
        .on_event(&mut network, &mut selected, event)
        .unwrap_err();
    assert_eq!(error.target_block_id(), target);
    assert_eq!(error.failed_block_id(), ids[1]);
    assert_eq!(error.committed_block_count(), 1);
    assert_eq!(error.last_acknowledged_head_block_id(), ids[0]);
    assert!(matches!(
        error.block_import_error(),
        ProofBlockImportError::ProofAcquisition { source, .. }
            if matches!(
                source.as_ref(),
                crate::DependencyAcquisitionError::NoEligiblePeer { proof_id }
                    if *proof_id == next_root
            )
    ));
    assert_eq!(selected.head_block_id().unwrap(), ids[0]);
    assert!(selected.block(ids[0]).unwrap().is_some());
    assert!(selected.block(ids[1]).unwrap().is_none());
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}
