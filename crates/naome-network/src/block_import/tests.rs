use std::sync::atomic::Ordering;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::artifact_exchange::{ArtifactRequest, ArtifactResponse};
use naome_chain::{
    ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId, ArtifactDag, ArtifactSetRoot,
};
use naome_foundation::FreeVariable;
use naome_ledger::LedgerError;
use naome_proof::{
    ArtifactId, ArtifactPayload, DefinedFormula, DefinitionCertificate, DefinitionId,
    ProofCertificate, ProofFormula, ProofId, ProofStep,
};
use naome_storage::{ArtifactChainJournal, ArtifactChainJournalError};

use super::*;
use crate::codec::ArtifactBlockWireResponse;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, create_journal, pairing_bytes, snapshot,
    test_network_for_peers, union_bytes,
};
use crate::{ExchangeRequestId, Keypair, NetworkEvent, OutboundArtifactFailure, PendingRequest};

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

fn artifact_id(bytes: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(bytes.to_vec())
        .unwrap()
        .artifact_id()
}

fn referenced_block(
    selected: &ArtifactChainJournal,
) -> (ArtifactBlock, Vec<(ArtifactId, Vec<u8>)>) {
    let parent_bytes = pairing_bytes();
    let mut identity = ArtifactDag::new();
    let parent_record = identity
        .apply_canonical_artifact_bytes(parent_bytes.clone())
        .unwrap();
    let parent_artifact_id = parent_record.artifact_id();
    let parent_proof_id = parent_record.as_proof().unwrap().proof_id();
    let root_bytes = referenced_generalization_bytes(parent_proof_id);
    let root_artifact_id = identity
        .apply_canonical_artifact_bytes(root_bytes.clone())
        .unwrap()
        .artifact_id();
    let block = selected.prepare_block(root_artifact_id).unwrap();
    (
        block,
        vec![
            (parent_artifact_id, parent_bytes),
            (root_artifact_id, root_bytes),
        ],
    )
}

fn definition_dependent_block(
    selected: &ArtifactChainJournal,
) -> (ArtifactBlock, Vec<u8>, DefinitionId) {
    let value = FreeVariable::new(0);
    let definition =
        DefinitionCertificate::relation(1, DefinedFormula::equal(value, value)).unwrap();
    let definition_id = definition.definition_id();
    let definition_bytes = ArtifactPayload::Definition(definition).to_canonical_bytes();
    let application =
        ProofFormula::from_defined(DefinedFormula::defined_relation(definition_id, [value]))
            .unwrap();
    let normal = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity { variable: value },
        ProofStep::Simplification {
            antecedent: application.clone(),
            consequent: application,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
        ProofStep::Generalization {
            premise: 3,
            variable: value,
        },
    ])
    .unwrap()
    .into_unchecked_normal_form();
    let proof_bytes = ArtifactPayload::Proof(normal.certificate().clone()).to_canonical_bytes();

    let mut identity = ArtifactDag::new();
    identity
        .apply_canonical_artifact_bytes(definition_bytes)
        .unwrap();
    let proof_artifact_id = identity
        .apply_canonical_artifact_bytes(proof_bytes.clone())
        .unwrap()
        .artifact_id();
    (
        selected.prepare_block(proof_artifact_id).unwrap(),
        proof_bytes,
        definition_id,
    )
}

fn pending_block_request(
    network: &StaticArtifactNetwork,
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
        .expect("the peer has one pending proof request")
}

fn block_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    bytes: impl Into<Vec<u8>>,
) -> NetworkEvent {
    let bytes = bytes.into();
    let request_id = pending_block_request(network, peer_id);
    network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(900),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactBlockWireResponse::new(bytes),
            },
        })
        .expect("the retained block request produces one terminal event")
}

fn artifact_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    artifact_response_event_from(network, peer_id, peer_id, bytes)
}

fn artifact_response_event_from(
    network: &mut StaticArtifactNetwork,
    expected_peer_id: PeerId,
    actual_peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    let (request_id, _) = pending_artifact_request(network, expected_peer_id);
    network
        .handle_artifact_exchange_event(request_response::Event::Message {
            peer: actual_peer_id,
            connection_id: ConnectionId::new_unchecked(901),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained proof request produces one terminal event")
}

fn proof_failure_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> NetworkEvent {
    let (request_id, _) = pending_artifact_request(network, peer_id);
    network
        .handle_artifact_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(903),
            request_id,
            error,
        })
        .expect("the retained proof request produces one terminal event")
}

fn start_import(
    network: &mut StaticArtifactNetwork,
    selected: &ArtifactChainJournal,
    peer_id: PeerId,
    block: &ArtifactBlock,
) -> ArtifactBlockImport {
    network
        .start_artifact_block_import(selected, peer_id, block.id())
        .unwrap()
}

fn reject_block(
    directory: &TestDirectory,
    selected: &mut ArtifactChainJournal,
    peer_id: PeerId,
    block: ArtifactBlock,
) -> ArtifactBlockImportError {
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
            .any(|request_id| matches!(request_id, ExchangeRequestId::Artifact(_)))
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    error
}

fn reject_exact_payload_without_fallback(
    fixture: &str,
    payload: Vec<u8>,
) -> (ArtifactChainJournalError, ArtifactId) {
    let directory = TestDirectory::new(fixture);
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let bytes = pairing_bytes();
    let expected = artifact_id(&bytes);
    let block = selected.prepare_block(expected).unwrap();
    let preferred = Keypair::generate_ed25519().public().to_peer_id();
    let fallback = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[preferred, fallback]);
    let import = start_import(&mut network, &selected, preferred, &block);
    let block_event = block_response_event(&mut network, preferred, block.to_canonical_bytes());
    let import = import
        .on_event(&mut network, &mut selected, block_event)
        .unwrap()
        .expect("the exact block proof is requested");
    assert_eq!(import.pending_peer_id(), preferred);

    let event = artifact_response_event(&mut network, preferred, payload);
    let error = import
        .on_event(&mut network, &mut selected, event)
        .expect_err("an invalid exact payload is terminal");
    assert_snapshot(&directory, &selected, &before);
    assert!(network.pending.is_empty(), "no fallback request may start");
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let ArtifactBlockImportError::SelectedState { source } = error else {
        panic!("invalid exact payload escaped journal admission: {error:?}")
    };
    (*source, expected)
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
        network.start_artifact_block_import(&selected, unknown_peer, virtual_genesis),
        Err(ArtifactBlockImportError::TargetAlreadySelected { block_id })
            if block_id == virtual_genesis
    ));
    assert_snapshot(&directory, &selected, &empty_snapshot);
    assert!(network.pending.is_empty());

    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let first_block_id = selected.head_block_id().unwrap();
    let first_snapshot = snapshot(&directory, &selected);

    assert!(matches!(
        network.start_artifact_block_import(&selected, unknown_peer, virtual_genesis),
        Err(ArtifactBlockImportError::TargetAlreadySelected { block_id })
            if block_id == virtual_genesis
    ));
    assert_snapshot(&directory, &selected, &first_snapshot);
    assert!(network.pending.is_empty());

    assert!(matches!(
        network.start_artifact_block_import(&selected, unknown_peer, first_block_id),
        Err(ArtifactBlockImportError::TargetAlreadySelected { block_id })
            if block_id == first_block_id
    ));
    assert_snapshot(&directory, &selected, &first_snapshot);
    assert!(network.pending.is_empty());

    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let historical_snapshot = snapshot(&directory, &selected);
    assert_ne!(historical_snapshot.head, first_block_id);
    assert!(matches!(
        network.start_artifact_block_import(&selected, unknown_peer, first_block_id),
        Err(ArtifactBlockImportError::TargetAlreadySelected { block_id })
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
    let id = artifact_id(&pairing_bytes());
    let prepared = selected.prepare_block(id).unwrap();
    let parent = prepared.parent_block_id();
    let previous = prepared.previous_artifact_set_root();
    let resulting = prepared.resulting_artifact_set_root();
    let wrong_parent = ArtifactBlockId::from_bytes([0xa1; 32]);
    let wrong_previous = ArtifactSetRoot::from_bytes([0xa2; 32]);
    let wrong_resulting = ArtifactSetRoot::from_bytes([0xa3; 32]);
    assert_ne!(wrong_parent, parent);
    assert_ne!(wrong_previous, previous);
    assert_ne!(wrong_resulting, resulting);

    let all_wrong = ArtifactBlock::new(wrong_parent, wrong_previous, wrong_resulting, id);
    assert!(matches!(
        reject_block(&directory, &mut selected, peer_id, all_wrong),
        ArtifactBlockImportError::ParentBlockIdMismatch { expected, actual }
            if expected == parent && actual == wrong_parent
    ));

    let wrong_roots = ArtifactBlock::new(parent, wrong_previous, wrong_resulting, id);
    assert!(matches!(
        reject_block(&directory, &mut selected, peer_id, wrong_roots),
        ArtifactBlockImportError::PreviousArtifactSetRootMismatch { expected, actual }
            if expected == previous && actual == wrong_previous
    ));

    let wrong_result = ArtifactBlock::new(parent, previous, wrong_resulting, id);
    assert!(matches!(
        reject_block(&directory, &mut selected, peer_id, wrong_result),
        ArtifactBlockImportError::ResultingArtifactSetRootMismatch { expected, actual }
            if expected == resulting && actual == wrong_resulting
    ));
}

#[test]
fn already_selected_proof_fails_preparation_before_resulting_root_or_proof_traffic() {
    let directory = TestDirectory::new("block-import-selected-proof");
    let mut selected = create_journal(directory.path()).unwrap();
    let selected_id = apply_fresh_blocks(&mut selected, [pairing_bytes()])[0];
    let parent = selected.head_block_id().unwrap();
    let previous = selected.artifact_set_root().unwrap();
    let wrong_resulting = ArtifactSetRoot::from_bytes([0xa4; 32]);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let block = ArtifactBlock::new(parent, previous, wrong_resulting, selected_id);

    assert!(matches!(
        reject_block(&directory, &mut selected, peer_id, block),
        ArtifactBlockImportError::SelectedState { source }
            if matches!(
                source.as_ref(),
                ArtifactChainJournalError::Preparation {
                    source: naome_chain::ArtifactBlockPrepareError::AlreadySelectedArtifactId {
                        artifact_id,
                    },
                } if *artifact_id == selected_id
            )
    ));
}

#[test]
fn foreign_network_generation_is_rejected_before_block_interpretation() {
    let directory = TestDirectory::new("block-import-network-generation");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let id = artifact_id(&pairing_bytes());
    let block = selected.prepare_block(id).unwrap();
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
        Err(ArtifactBlockImportError::UnexpectedEvent)
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
    let id = artifact_id(&pairing_bytes());
    let block = selected.prepare_block(id).unwrap();
    let mut origin = test_network_for_peers(&[peer_id]);
    let mut wrong_driver = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut origin, &selected, peer_id, &block);
    let event = block_response_event(&mut origin, peer_id, block.to_canonical_bytes());
    assert!(import.accepts_event(&event));

    assert!(matches!(
        import.on_event(&mut wrong_driver, &mut selected, event),
        Err(ArtifactBlockImportError::UnexpectedEvent)
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
fn proof_phase_rejects_a_driver_network_that_did_not_start_the_request() {
    let directory = TestDirectory::new("block-import-proof-driver-network");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let id = artifact_id(&pairing_bytes());
    let block = selected.prepare_block(id).unwrap();
    let mut origin = test_network_for_peers(&[peer_id]);
    let mut wrong_driver = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut origin, &selected, peer_id, &block);
    let found = block_response_event(&mut origin, peer_id, block.to_canonical_bytes());
    let import = import
        .on_event(&mut origin, &mut selected, found)
        .unwrap()
        .unwrap();
    let event = artifact_response_event(&mut origin, peer_id, pairing_bytes());
    assert!(import.accepts_event(&event));

    assert!(matches!(
        import.on_event(&mut wrong_driver, &mut selected, event),
        Err(ArtifactBlockImportError::UnexpectedEvent)
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
    let id = artifact_id(&pairing_bytes());
    let block = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0xb1; 32]),
        ArtifactSetRoot::from_bytes([0xb2; 32]),
        ArtifactSetRoot::from_bytes([0xb3; 32]),
        id,
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
                response: ArtifactBlockWireResponse::new(vec![0xff]),
            },
        })
        .unwrap();
    assert!(import.accepts_event(&event));

    assert!(matches!(
        import.on_event(&mut network, &mut selected, event),
        Err(ArtifactBlockImportError::BlockRequestFailed {
            peer_id,
            block_id,
            source,
        }) if peer_id == expected_peer
            && block_id == block.id()
            && matches!(
                source.as_ref(),
                OutboundArtifactBlockFailure::PeerMismatch { expected, actual }
                    if *expected == expected_peer && *actual == actual_peer
            )
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn missing_reference_fails_journal_admission_without_dependency_request() {
    let directory = TestDirectory::new("block-import-missing-reference");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let (block, payloads) = referenced_block(&selected);
    let block_id = block.id();
    let root_id = block.artifact_id();
    let root_bytes = payloads[1].1.clone();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut network, &selected, peer_id, &block);

    let block_event = block_response_event(&mut network, peer_id, block.to_canonical_bytes());
    let import = import
        .on_event(&mut network, &mut selected, block_event)
        .unwrap()
        .expect("the exact block proof is requested");
    let (_, request) = pending_artifact_request(&network, peer_id);
    assert_eq!(request.artifact_id(), root_id);

    let root_event = artifact_response_event(&mut network, peer_id, root_bytes);
    assert!(matches!(
        import.on_event(&mut network, &mut selected, root_event),
        Err(ArtifactBlockImportError::SelectedState { source })
            if matches!(
                source.as_ref(),
                ArtifactChainJournalError::BlockAdmission {
                    source: ArtifactBlockApplyError::Admission {
                        source: LedgerError::ProofCheck { .. },
                    },
                }
            )
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(selected.block(block_id).unwrap().is_none());
    assert!(
        network.pending.is_empty(),
        "no dependency request may start"
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn missing_definition_fails_journal_admission_without_dependency_request() {
    let directory = TestDirectory::new("block-import-missing-definition");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let (block, proof_bytes, definition_id) = definition_dependent_block(&selected);
    let block_id = block.id();
    let proof_artifact_id = block.artifact_id();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut network, &selected, peer_id, &block);

    let block_event = block_response_event(&mut network, peer_id, block.to_canonical_bytes());
    let import = import
        .on_event(&mut network, &mut selected, block_event)
        .unwrap()
        .expect("the exact proof artifact is requested");
    let (_, request) = pending_artifact_request(&network, peer_id);
    assert_eq!(request.artifact_id(), proof_artifact_id);

    let proof_event = artifact_response_event(&mut network, peer_id, proof_bytes);
    assert!(matches!(
        import.on_event(&mut network, &mut selected, proof_event),
        Err(ArtifactBlockImportError::SelectedState { source })
            if matches!(
                source.as_ref(),
                ArtifactChainJournalError::BlockAdmission {
                    source: ArtifactBlockApplyError::Admission {
                        source: LedgerError::ProofCheck { .. },
                    },
                }
            )
    ));
    assert!(
        !selected
            .artifact_state()
            .unwrap()
            .contains_definition(definition_id)
    );
    assert_snapshot(&directory, &selected, &before);
    assert!(selected.block(block_id).unwrap().is_none());
    assert!(
        network.pending.is_empty(),
        "a missing definition must not trigger recursive dependency traffic"
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn unavailable_block_or_proof_never_selects_partial_state() {
    let directory = TestDirectory::new("block-import-unavailable");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let (block, _) = referenced_block(&selected);
    let block_id = block.id();
    let root_id = block.artifact_id();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();

    let mut block_network = test_network_for_peers(&[peer_id]);
    let import = start_import(&mut block_network, &selected, peer_id, &block);
    let unavailable = block_response_event(&mut block_network, peer_id, Vec::new());
    assert!(matches!(
        import.on_event(&mut block_network, &mut selected, unavailable),
        Err(ArtifactBlockImportError::BlockUnavailable {
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
    let unavailable = artifact_response_event(&mut proof_network, peer_id, Vec::new());
    assert!(matches!(
        import.on_event(&mut proof_network, &mut selected, unavailable),
        Err(ArtifactBlockImportError::ArtifactUnavailable {
            peer_id: source_peer,
            artifact_id,
        }) if source_peer == peer_id && artifact_id == root_id
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(selected.block(block_id).unwrap().is_none());
    assert_eq!(
        proof_network.pending_budget.active.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn ordinary_proof_transport_failure_falls_back_to_the_next_peer() {
    let directory = TestDirectory::new("block-import-proof-transport-fallback");
    let mut selected = create_journal(directory.path()).unwrap();
    let bytes = pairing_bytes();
    let proof_id = artifact_id(&bytes);
    let block = selected.prepare_block(proof_id).unwrap();
    let preferred = Keypair::generate_ed25519().public().to_peer_id();
    let fallback = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[preferred, fallback]);
    let import = start_import(&mut network, &selected, preferred, &block);
    let block_event = block_response_event(&mut network, preferred, block.to_canonical_bytes());
    let import = import
        .on_event(&mut network, &mut selected, block_event)
        .unwrap()
        .expect("the preferred peer receives the exact proof request");
    assert_eq!(import.pending_peer_id(), preferred);

    let failure = proof_failure_event(
        &mut network,
        preferred,
        request_response::OutboundFailure::Timeout,
    );
    let import = import
        .on_event(&mut network, &mut selected, failure)
        .unwrap()
        .expect("an ordinary transport failure retries the next peer");
    assert_eq!(import.pending_peer_id(), fallback);
    let (_, request) = pending_artifact_request(&network, fallback);
    assert_eq!(request.artifact_id(), proof_id);

    let response = artifact_response_event(&mut network, fallback, bytes);
    assert!(
        import
            .on_event(&mut network, &mut selected, response)
            .unwrap()
            .is_none()
    );
    assert_eq!(selected.head_block_id().unwrap(), block.id());
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn wrong_id_payload_is_terminal_without_peer_fallback() {
    let bytes = union_bytes();
    let actual = artifact_id(&bytes);
    let (source, expected) =
        reject_exact_payload_without_fallback("block-import-wrong-proof-id", bytes);

    assert!(matches!(
        source,
        ArtifactChainJournalError::BlockAdmission {
            source: ArtifactBlockApplyError::Admission {
                source: LedgerError::ArtifactIdMismatch {
                    expected: error_expected,
                    actual: error_actual,
                },
            },
        } if error_expected == expected && error_actual == actual
    ));
}

#[test]
fn malformed_payload_is_terminal_without_peer_fallback() {
    let (source, _) =
        reject_exact_payload_without_fallback("block-import-malformed-proof", vec![0xff]);

    assert!(matches!(
        source,
        ArtifactChainJournalError::BlockAdmission {
            source: ArtifactBlockApplyError::Admission {
                source: LedgerError::Decode { .. },
            },
        }
    ));
}

#[tokio::test(start_paused = true)]
async fn fallback_keeps_one_absolute_proof_import_deadline() {
    let directory = TestDirectory::new("block-import-shared-proof-deadline");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let bytes = pairing_bytes();
    let proof_id = artifact_id(&bytes);
    let block = selected.prepare_block(proof_id).unwrap();
    let preferred = Keypair::generate_ed25519().public().to_peer_id();
    let fallback = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[preferred, fallback]);
    let import = start_import(&mut network, &selected, preferred, &block);
    let block_event = block_response_event(&mut network, preferred, block.to_canonical_bytes());
    let import = import
        .on_event(&mut network, &mut selected, block_event)
        .unwrap()
        .expect("the preferred peer receives the exact proof request");

    let before_retry = ARTIFACT_BLOCK_IMPORT_TIMEOUT - Duration::from_secs(30);
    tokio::time::advance(before_retry).await;
    let failure = proof_failure_event(
        &mut network,
        preferred,
        request_response::OutboundFailure::Timeout,
    );
    let import = import
        .on_event(&mut network, &mut selected, failure)
        .unwrap()
        .expect("the fallback starts within the original deadline");
    assert_eq!(import.pending_peer_id(), fallback);

    tokio::time::advance(Duration::from_secs(30)).await;
    let deadline = network
        .take_due_artifact_request_deadline(tokio::time::Instant::now())
        .expect("the original proof-import deadline expires during the fallback");
    assert!(import.accepts_event(&deadline));
    assert!(matches!(
        import.on_event(&mut network, &mut selected, deadline),
        Err(ArtifactBlockImportError::ArtifactDeadlineExceeded {
            peer_id: deadline_peer,
            artifact_id: deadline_artifact,
        }) if deadline_peer == fallback && deadline_artifact == proof_id
    ));
    assert_snapshot(&directory, &selected, &before);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let drained = artifact_response_event(&mut network, fallback, bytes);
    assert!(matches!(
        drained,
        NetworkEvent::ArtifactCancellationDrained { .. }
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn exact_payload_retries_each_configured_peer_at_most_once() {
    let directory = TestDirectory::new("block-import-eight-peer-retry");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let bytes = pairing_bytes();
    let id = artifact_id(&bytes);
    let block = selected.prepare_block(id).unwrap();
    let peers = (0..crate::MAX_STATIC_PEERS)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let preferred = peers[3];
    let mut network = test_network_for_peers(&peers);
    let import = start_import(&mut network, &selected, preferred, &block);
    let block_event = block_response_event(&mut network, preferred, block.to_canonical_bytes());
    let mut import = import
        .on_event(&mut network, &mut selected, block_event)
        .unwrap()
        .unwrap();
    let mut attempted = Vec::new();

    loop {
        let peer_id = import.pending_peer_id();
        assert!(!attempted.contains(&peer_id));
        attempted.push(peer_id);
        let unavailable = artifact_response_event(&mut network, peer_id, Vec::new());
        match import.on_event(&mut network, &mut selected, unavailable) {
            Ok(Some(next)) => import = next,
            Err(ArtifactBlockImportError::ArtifactUnavailable {
                peer_id: final_peer,
                artifact_id,
            }) => {
                assert_eq!(final_peer, peer_id);
                assert_eq!(artifact_id, id);
                break;
            }
            result => panic!("unexpected exact-payload retry result: {result:?}"),
        }
    }

    assert_eq!(attempted.len(), crate::MAX_STATIC_PEERS);
    assert_snapshot(&directory, &selected, &before);
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn competing_sibling_loses_to_current_parent_before_proof_interpretation() {
    let directory = TestDirectory::new("block-import-siblings");
    let mut selected = create_journal(directory.path()).unwrap();
    let initial_head = selected.head_block_id().unwrap();
    let pairing = pairing_bytes();
    let union = union_bytes();
    let pairing_id = artifact_id(&pairing);
    let union_id = artifact_id(&union);
    let first_block = selected.prepare_block(pairing_id).unwrap();
    let second_block = selected.prepare_block(union_id).unwrap();
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

    let first_proof = artifact_response_event(&mut network, first_peer, pairing);
    assert!(
        first
            .on_event(&mut network, &mut selected, first_proof)
            .unwrap()
            .is_none()
    );
    let selected_head = first_block.id();
    assert_eq!(selected.head_block_id().unwrap(), selected_head);

    let second_proof = artifact_response_event(&mut network, second_peer, Vec::new());
    assert!(matches!(
        second.on_event(&mut network, &mut selected, second_proof),
        Err(ArtifactBlockImportError::ParentBlockIdMismatch { expected, actual })
            if expected == selected_head && actual == initial_head
    ));
    assert_eq!(selected.head_block_id().unwrap(), selected_head);
    assert!(selected.block(first_block.id()).unwrap().is_some());
    assert!(selected.block(second_block.id()).unwrap().is_none());
    assert_eq!(selected.len().unwrap(), 1);

    let third_proof =
        artifact_response_event_from(&mut network, third_peer, first_peer, Vec::new());
    assert!(matches!(
        third.on_event(&mut network, &mut selected, third_proof),
        Err(ArtifactBlockImportError::ArtifactRequestFailed {
            peer_id,
            source,
            ..
        }) if peer_id == third_peer
            && matches!(
                source.as_ref(),
                OutboundArtifactFailure::PeerMismatch { expected, actual }
                    if *expected == third_peer && *actual == first_peer
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
    let id = artifact_id(&pairing_bytes());
    let block = selected.prepare_block(id).unwrap();
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
    let (_, request) = pending_artifact_request(&network, peer_id);
    assert_eq!(request.artifact_id(), id);
    import.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let drained = artifact_response_event(&mut network, peer_id, pairing_bytes());
    assert!(matches!(
        drained,
        NetworkEvent::ArtifactCancellationDrained { .. }
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}
