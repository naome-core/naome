use std::sync::atomic::Ordering;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::proof_exchange::{ProofRequest, ProofResponse};
use naome_chain::{
    ProofBlock, ProofBlockId, ProofChainId, ProofDag, ProofSetRoot, ProofTransition,
    ProofTransitionError,
};
use naome_foundation::FreeVariable;
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use naome_storage::{ProofChainJournal, ProofChainJournalError};

use super::*;
use crate::codec::ProofBlockWireResponse;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, create_journal, pairing_bytes, snapshot,
    test_network_for_peers, union_bytes,
};
use crate::{
    DependencyAcquisitionError, ExchangeRequestId, Keypair, NetworkEvent, OutboundProofFailure,
    PendingRequest,
};

fn referenced_generalization_bytes(parent: ProofId) -> Vec<u8> {
    ProofCertificate::new(vec![
        ProofStep::ProofReference { proof_id: parent },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(7),
        },
    ])
    .unwrap()
    .into_unchecked_normal_form()
    .into_canonical_bytes()
    .into_vec()
}

fn proof_id(bytes: &[u8]) -> ProofId {
    ProofDag::new()
        .apply_canonical_proof_bytes(bytes.to_vec())
        .unwrap()
        .proof_id()
}

fn referenced_block(selected: &ProofChainJournal) -> (ProofBlock, Vec<(ProofId, Vec<u8>)>) {
    let parent_bytes = pairing_bytes();
    let mut identity = ProofDag::new();
    let parent_id = identity
        .apply_canonical_proof_bytes(parent_bytes.clone())
        .unwrap()
        .proof_id();
    let root_bytes = referenced_generalization_bytes(parent_id);
    let root_id = identity
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();
    let block = selected.prepare_block(vec![parent_id, root_id]).unwrap();
    (
        block,
        vec![(parent_id, parent_bytes), (root_id, root_bytes)],
    )
}

fn pending_block_request(
    network: &StaticProofNetwork,
    peer_id: PeerId,
) -> request_response::OutboundRequestId {
    network
        .pending
        .iter()
        .find_map(|(request_id, pending)| match (request_id, pending) {
            (ExchangeRequestId::Block(request_id), PendingRequest::Block(pending))
                if network.pending_peer_id(pending.peer_index) == peer_id =>
            {
                Some(*request_id)
            }
            _ => None,
        })
        .expect("the peer has one pending block request")
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
        .expect("the peer has one pending proof request")
}

fn block_response_event(
    network: &mut StaticProofNetwork,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    let request_id = pending_block_request(network, peer_id);
    network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(900),
            message: request_response::Message::Response {
                request_id,
                response: ProofBlockWireResponse::new(bytes),
            },
        })
        .expect("the retained block request produces one terminal event")
}

fn proof_response_event(
    network: &mut StaticProofNetwork,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    proof_response_event_from(network, peer_id, peer_id, bytes)
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
            connection_id: ConnectionId::new_unchecked(901),
            message: request_response::Message::Response {
                request_id,
                response: ProofResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained proof request produces one terminal event")
}

fn start_import(
    network: &mut StaticProofNetwork,
    selected: &ProofChainJournal,
    peer_id: PeerId,
    block: &ProofBlock,
) -> ProofBlockImport {
    network
        .start_proof_block_import(selected, peer_id, block.id())
        .unwrap()
}

fn reject_block(
    directory: &TestDirectory,
    selected: &mut ProofChainJournal,
    peer_id: PeerId,
    block: ProofBlock,
) -> ProofBlockImportError {
    let before = snapshot(directory, selected);
    let mut network = test_network_for_peers(&[peer_id]);
    let block_id = block.id();
    let import = start_import(&mut network, selected, peer_id, &block);
    let event = block_response_event(&mut network, peer_id, block.to_canonical_bytes());
    assert!(import.accepts_event(&event));
    let error = import.on_event(&mut network, selected, event).unwrap_err();

    assert_snapshot(directory, selected, &before);
    assert!(selected.block(block_id).unwrap().is_none());
    assert!(
        !network
            .pending
            .keys()
            .any(|request_id| matches!(request_id, ExchangeRequestId::Proof(_)))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    error
}

#[test]
fn already_selected_target_precedes_peer_validation_and_network_work() {
    let directory = TestDirectory::new("block-import-already-selected");
    let mut selected = create_journal(directory.path()).unwrap();
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);
    let virtual_genesis = selected.head_block_id().unwrap();
    let empty_snapshot = snapshot(&directory, &selected);

    assert!(matches!(
        network.start_proof_block_import(&selected, unknown_peer, virtual_genesis),
        Err(ProofBlockImportError::TargetAlreadySelected { block_id })
            if block_id == virtual_genesis
    ));
    assert_snapshot(&directory, &selected, &empty_snapshot);
    assert!(network.pending.is_empty());

    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let first_block_id = selected.head_block_id().unwrap();
    let first_snapshot = snapshot(&directory, &selected);

    assert!(matches!(
        network.start_proof_block_import(&selected, unknown_peer, virtual_genesis),
        Err(ProofBlockImportError::TargetAlreadySelected { block_id })
            if block_id == virtual_genesis
    ));
    assert_snapshot(&directory, &selected, &first_snapshot);
    assert!(network.pending.is_empty());

    assert!(matches!(
        network.start_proof_block_import(&selected, unknown_peer, first_block_id),
        Err(ProofBlockImportError::TargetAlreadySelected { block_id })
            if block_id == first_block_id
    ));
    assert_snapshot(&directory, &selected, &first_snapshot);
    assert!(network.pending.is_empty());

    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let historical_snapshot = snapshot(&directory, &selected);
    assert_ne!(historical_snapshot.head, first_block_id);
    assert!(matches!(
        network.start_proof_block_import(&selected, unknown_peer, first_block_id),
        Err(ProofBlockImportError::TargetAlreadySelected { block_id })
            if block_id == first_block_id
    ));
    assert_snapshot(&directory, &selected, &historical_snapshot);
    assert!(network.pending.is_empty());
}

#[test]
fn block_context_preflight_has_parent_then_previous_then_resulting_precedence() {
    let directory = TestDirectory::new("block-import-context-precedence");
    let mut selected = create_journal(directory.path()).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let id = proof_id(&pairing_bytes());
    let prepared = selected.prepare_block(vec![id]).unwrap();
    let parent = prepared.parent_block_id();
    let previous = prepared.transition().previous_proof_set_root();
    let resulting = prepared.transition().resulting_proof_set_root();
    let wrong_parent = ProofBlockId::from_bytes([0xa1; 32]);
    let wrong_previous = ProofSetRoot::from_bytes([0xa2; 32]);
    let wrong_resulting = ProofSetRoot::from_bytes([0xa3; 32]);
    assert_ne!(wrong_parent, parent);
    assert_ne!(wrong_previous, previous);
    assert_ne!(wrong_resulting, resulting);

    let all_wrong = ProofBlock::new(
        wrong_parent,
        ProofTransition::new(wrong_previous, wrong_resulting, vec![id]).unwrap(),
    );
    assert!(matches!(
        reject_block(&directory, &mut selected, peer_id, all_wrong),
        ProofBlockImportError::ParentBlockIdMismatch { expected, actual }
            if expected == parent && actual == wrong_parent
    ));

    let wrong_roots = ProofBlock::new(
        parent,
        ProofTransition::new(wrong_previous, wrong_resulting, vec![id]).unwrap(),
    );
    assert!(matches!(
        reject_block(&directory, &mut selected, peer_id, wrong_roots),
        ProofBlockImportError::PreviousProofSetRootMismatch { expected, actual }
            if expected == previous && actual == wrong_previous
    ));

    let wrong_result = ProofBlock::new(
        parent,
        ProofTransition::new(previous, wrong_resulting, vec![id]).unwrap(),
    );
    assert!(matches!(
        reject_block(&directory, &mut selected, peer_id, wrong_result),
        ProofBlockImportError::ResultingProofSetRootMismatch { expected, actual }
            if expected == resulting && actual == wrong_resulting
    ));
}

#[test]
fn already_selected_transition_fails_preparation_before_resulting_root_or_proof_traffic() {
    let directory = TestDirectory::new("block-import-selected-transition");
    let mut selected = create_journal(directory.path()).unwrap();
    let selected_id = apply_fresh_blocks(&mut selected, [pairing_bytes()])[0];
    let parent = selected.head_block_id().unwrap();
    let previous = selected.proof_set_root().unwrap();
    let wrong_resulting = ProofSetRoot::from_bytes([0xa4; 32]);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let block = ProofBlock::new(
        parent,
        ProofTransition::new(previous, wrong_resulting, vec![selected_id]).unwrap(),
    );

    assert!(matches!(
        reject_block(&directory, &mut selected, peer_id, block),
        ProofBlockImportError::SelectedState { source }
            if matches!(
                source.as_ref(),
                ProofChainJournalError::Preparation {
                    source: ProofTransitionError::AlreadySelectedProofId {
                        index: 0,
                        proof_id,
                    },
                } if *proof_id == selected_id
            )
    ));
}

#[test]
fn foreign_network_generation_is_rejected_before_block_interpretation() {
    let directory = TestDirectory::new("block-import-network-generation");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let id = proof_id(&pairing_bytes());
    let block = selected.prepare_block(vec![id]).unwrap();
    let mut first = test_network_for_peers(&[peer_id]);
    let mut second = test_network_for_peers(&[peer_id]);
    let first_import = start_import(&mut first, &selected, peer_id, &block);
    let first_request_id = pending_block_request(&first, peer_id);
    let second_import = start_import(&mut second, &selected, peer_id, &block);
    let second_request_id = pending_block_request(&second, peer_id);
    assert_eq!(first_request_id, second_request_id);

    let second_event = block_response_event(&mut second, peer_id, block.to_canonical_bytes());
    assert!(!first_import.accepts_event(&second_event));
    assert!(matches!(
        first_import.on_event(&mut first, &mut selected, second_event),
        Err(ProofBlockImportError::UnexpectedEvent)
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(
        first
            .pending
            .contains_key(&ExchangeRequestId::Block(first_request_id))
    );
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(
        first
            .pending
            .remove(&ExchangeRequestId::Block(first_request_id))
            .unwrap(),
    );
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 0);
    drop(second_import);
    assert_eq!(second.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn block_phase_rejects_a_driver_network_that_did_not_start_the_ticket() {
    let directory = TestDirectory::new("block-import-driver-network");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let id = proof_id(&pairing_bytes());
    let block = selected.prepare_block(vec![id]).unwrap();
    let mut origin = test_network_for_peers(&[peer_id]);
    let mut wrong_driver = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut origin, &selected, peer_id, &block);
    let event = block_response_event(&mut origin, peer_id, block.to_canonical_bytes());
    assert!(import.accepts_event(&event));

    assert!(matches!(
        import.on_event(&mut wrong_driver, &mut selected, event),
        Err(ProofBlockImportError::UnexpectedEvent)
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(origin.pending.is_empty());
    assert!(wrong_driver.pending.is_empty());
    assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(
        wrong_driver.pending_budget.active.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn proof_phase_rejects_a_driver_network_that_did_not_start_the_acquisition() {
    let directory = TestDirectory::new("block-import-proof-driver-network");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let id = proof_id(&pairing_bytes());
    let block = selected.prepare_block(vec![id]).unwrap();
    let mut origin = test_network_for_peers(&[peer_id]);
    let mut wrong_driver = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut origin, &selected, peer_id, &block);
    let found = block_response_event(&mut origin, peer_id, block.to_canonical_bytes());
    let import = import
        .on_event(&mut origin, &mut selected, found)
        .unwrap()
        .unwrap();
    let event = proof_response_event(&mut origin, peer_id, pairing_bytes());
    assert!(import.accepts_event(&event));

    assert!(matches!(
        import.on_event(&mut wrong_driver, &mut selected, event),
        Err(ProofBlockImportError::UnexpectedEvent)
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(origin.pending.is_empty());
    assert!(wrong_driver.pending.is_empty());
    assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(
        wrong_driver.pending_budget.active.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn authenticated_peer_mismatch_precedes_block_decoding_and_context_checks() {
    let directory = TestDirectory::new("block-import-peer-mismatch");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let expected_peer = Keypair::generate_ed25519().public().to_peer_id();
    let actual_peer = Keypair::generate_ed25519().public().to_peer_id();
    let id = proof_id(&pairing_bytes());
    let block = ProofBlock::new(
        ProofBlockId::from_bytes([0xb1; 32]),
        ProofTransition::new(
            ProofSetRoot::from_bytes([0xb2; 32]),
            ProofSetRoot::from_bytes([0xb3; 32]),
            vec![id],
        )
        .unwrap(),
    );
    let mut network = test_network_for_peers(&[expected_peer, actual_peer]);
    let import = start_import(&mut network, &selected, expected_peer, &block);
    let request_id = pending_block_request(&network, expected_peer);
    let event = network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: actual_peer,
            connection_id: ConnectionId::new_unchecked(902),
            message: request_response::Message::Response {
                request_id,
                response: ProofBlockWireResponse::new(vec![0xff]),
            },
        })
        .unwrap();
    assert!(import.accepts_event(&event));

    assert!(matches!(
        import.on_event(&mut network, &mut selected, event),
        Err(ProofBlockImportError::BlockRequestFailed {
            peer_id,
            block_id,
            source,
        }) if peer_id == expected_peer
            && block_id == block.id()
            && matches!(
                source.as_ref(),
                OutboundProofBlockFailure::PeerMismatch { expected, actual }
                    if *expected == expected_peer && *actual == actual_peer
            )
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn referenced_direct_child_import_is_unselected_until_one_atomic_commit() {
    let directory = TestDirectory::new("block-import-success");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let (block, payloads) = referenced_block(&selected);
    let block_id = block.id();
    let root_id = block.transition().root_proof_id();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut network, &selected, peer_id, &block);
    assert_eq!(import.target_block_id(), block_id);
    assert_eq!(import.pending_peer_id(), peer_id);

    let block_event = block_response_event(&mut network, peer_id, block.to_canonical_bytes());
    assert!(import.accepts_event(&block_event));
    let mut import = import
        .on_event(&mut network, &mut selected, block_event)
        .unwrap()
        .expect("the block starts proof acquisition");
    assert_snapshot(&directory, &selected, &before);
    assert!(selected.block(block_id).unwrap().is_none());

    let (_, root_request) = pending_proof_request(&network, peer_id);
    assert_eq!(root_request.proof_id(), root_id);
    let root_bytes = payloads
        .iter()
        .find(|(proof_id, _)| *proof_id == root_id)
        .unwrap()
        .1
        .clone();
    let root_event = proof_response_event(&mut network, peer_id, root_bytes);
    assert!(import.accepts_event(&root_event));
    import = import
        .on_event(&mut network, &mut selected, root_event)
        .unwrap()
        .expect("the referenced parent remains absent");
    assert_snapshot(&directory, &selected, &before);
    assert!(selected.block(block_id).unwrap().is_none());

    let (_, parent_request) = pending_proof_request(&network, peer_id);
    let parent_bytes = payloads
        .iter()
        .find(|(proof_id, _)| *proof_id == parent_request.proof_id())
        .unwrap()
        .1
        .clone();
    let parent_event = proof_response_event(&mut network, peer_id, parent_bytes);
    assert!(import.accepts_event(&parent_event));
    assert!(
        import
            .on_event(&mut network, &mut selected, parent_event)
            .unwrap()
            .is_none(),
        "the exact block commit is the sole terminal success"
    );

    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(selected.head_block_id().unwrap(), block_id);
    assert_eq!(selected.len().unwrap(), 2);
    assert!(selected.block(block_id).unwrap().is_some());
    assert_ne!(directory.journal_bytes(), before.bytes);

    drop(selected);
    let reopened = ProofChainJournal::open_verified(
        directory.path(),
        ProofChainId::from_bytes([0x41; 32]),
        block_id,
    )
    .unwrap();
    assert_eq!(reopened.len().unwrap(), 2);
    assert!(reopened.proof(root_id).unwrap().is_some());
}

#[test]
fn unavailable_block_or_proof_never_selects_partial_state() {
    let directory = TestDirectory::new("block-import-unavailable");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let (block, _) = referenced_block(&selected);
    let block_id = block.id();
    let root_id = block.transition().root_proof_id();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();

    let mut block_network = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut block_network, &selected, peer_id, &block);
    let unavailable = block_response_event(&mut block_network, peer_id, Vec::new());
    assert!(matches!(
        import.on_event(&mut block_network, &mut selected, unavailable),
        Err(ProofBlockImportError::BlockUnavailable {
            peer_id: source,
            block_id: target,
        }) if source == peer_id && target == block_id
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(block_network.pending.is_empty());

    let mut proof_network = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut proof_network, &selected, peer_id, &block);
    let found = block_response_event(&mut proof_network, peer_id, block.to_canonical_bytes());
    let import = import
        .on_event(&mut proof_network, &mut selected, found)
        .unwrap()
        .unwrap();
    assert_snapshot(&directory, &selected, &before);
    let unavailable = proof_response_event(&mut proof_network, peer_id, Vec::new());
    assert!(matches!(
        import.on_event(&mut proof_network, &mut selected, unavailable),
        Err(ProofBlockImportError::ProofAcquisition {
            block_id: target,
            source,
        }) if target == block_id
            && matches!(
                source.as_ref(),
                DependencyAcquisitionError::Unavailable {
                    peer_id: source_peer,
                    proof_id,
                } if *source_peer == peer_id && *proof_id == root_id
            )
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(selected.block(block_id).unwrap().is_none());
    assert_eq!(
        proof_network.pending_budget.active.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn competing_sibling_loses_to_current_parent_before_proof_interpretation() {
    let directory = TestDirectory::new("block-import-siblings");
    let mut selected = create_journal(directory.path()).unwrap();
    let initial_head = selected.head_block_id().unwrap();
    let pairing = pairing_bytes();
    let union = union_bytes();
    let pairing_id = proof_id(&pairing);
    let union_id = proof_id(&union);
    let first_block = selected.prepare_block(vec![pairing_id]).unwrap();
    let second_block = selected.prepare_block(vec![union_id]).unwrap();
    assert_eq!(first_block.parent_block_id(), initial_head);
    assert_eq!(second_block.parent_block_id(), initial_head);
    assert_ne!(first_block.id(), second_block.id());

    let first_peer = Keypair::generate_ed25519().public().to_peer_id();
    let second_peer = Keypair::generate_ed25519().public().to_peer_id();
    let third_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[first_peer, second_peer, third_peer]);
    let first = start_import(&mut network, &selected, first_peer, &first_block);
    let second = start_import(&mut network, &selected, second_peer, &second_block);
    let third = start_import(&mut network, &selected, third_peer, &second_block);
    let first_event =
        block_response_event(&mut network, first_peer, first_block.to_canonical_bytes());
    let first = first
        .on_event(&mut network, &mut selected, first_event)
        .unwrap()
        .unwrap();
    let second_event =
        block_response_event(&mut network, second_peer, second_block.to_canonical_bytes());
    let second = second
        .on_event(&mut network, &mut selected, second_event)
        .unwrap()
        .unwrap();
    let third_event =
        block_response_event(&mut network, third_peer, second_block.to_canonical_bytes());
    let third = third
        .on_event(&mut network, &mut selected, third_event)
        .unwrap()
        .unwrap();

    let first_proof = proof_response_event(&mut network, first_peer, pairing);
    assert!(
        first
            .on_event(&mut network, &mut selected, first_proof)
            .unwrap()
            .is_none()
    );
    let selected_head = first_block.id();
    assert_eq!(selected.head_block_id().unwrap(), selected_head);

    let second_proof = proof_response_event(&mut network, second_peer, Vec::new());
    assert!(matches!(
        second.on_event(&mut network, &mut selected, second_proof),
        Err(ProofBlockImportError::ParentBlockIdMismatch { expected, actual })
            if expected == selected_head && actual == initial_head
    ));
    assert_eq!(selected.head_block_id().unwrap(), selected_head);
    assert!(selected.block(first_block.id()).unwrap().is_some());
    assert!(selected.block(second_block.id()).unwrap().is_none());
    assert_eq!(selected.len().unwrap(), 1);

    let third_proof = proof_response_event_from(&mut network, third_peer, first_peer, Vec::new());
    assert!(matches!(
        third.on_event(&mut network, &mut selected, third_proof),
        Err(ProofBlockImportError::ProofAcquisition { source, .. })
            if matches!(
                source.as_ref(),
                DependencyAcquisitionError::RequestFailed {
                    peer_id,
                    source,
                    ..
                } if *peer_id == third_peer
                    && matches!(
                        source.as_ref(),
                        OutboundProofFailure::PeerMismatch { expected, actual }
                            if *expected == third_peer && *actual == first_peer
                    )
            )
    ));
    assert_eq!(selected.head_block_id().unwrap(), selected_head);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn cancellation_preserves_each_physical_phase_until_its_exact_drain() {
    let directory = TestDirectory::new("block-import-cancellation");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let id = proof_id(&pairing_bytes());
    let block = selected.prepare_block(vec![id]).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();

    let mut network = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut network, &selected, peer_id, &block);
    import.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let terminal = block_response_event(&mut network, peer_id, Vec::new());
    assert!(matches!(terminal, NetworkEvent::OutboundBlock(_)));
    drop(terminal);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);

    let import = start_import(&mut network, &selected, peer_id, &block);
    let found = block_response_event(&mut network, peer_id, block.to_canonical_bytes());
    let import = import
        .on_event(&mut network, &mut selected, found)
        .unwrap()
        .unwrap();
    let (_, request) = pending_proof_request(&network, peer_id);
    assert_eq!(request.proof_id(), id);
    import.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let drained = proof_response_event(&mut network, peer_id, pairing_bytes());
    assert!(matches!(
        drained,
        NetworkEvent::ProofCancellationDrained { .. }
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}
