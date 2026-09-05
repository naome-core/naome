use std::fs;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome_chain::{ArtifactBlock, ArtifactBlockId, ArtifactDag, ArtifactSetRoot};
use naome_foundation::FreeVariable;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use naome_protocol::artifact_exchange::{ArtifactRequest, ArtifactResponse};
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreLimits, ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits,
    CandidatePayloadArchiveError, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
};

use super::*;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, create_journal, pairing_bytes, snapshot,
    test_chain_definition, test_network_for_peers, union_bytes,
};
use crate::{Keypair, NetworkEvent, OutboundArtifactFailure, RequestStartError};

const CANDIDATE_STORE_FILE_NAME: &str = "artifact-block-candidate-store.log";
const PAYLOAD_STORE_FILE_NAME: &str = "artifact-payload-store.log";

fn artifact_id(bytes: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(bytes.to_vec())
        .unwrap()
        .artifact_id()
}

fn referenced_generalization_bytes(parent: naome_proof::ProofId) -> Vec<u8> {
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

fn candidate_store(directory: &TestDirectory) -> ArtifactBlockCandidateStore {
    ArtifactBlockCandidateStore::create(
        directory.path(),
        test_chain_definition(),
        ArtifactBlockCandidateStoreLimits::new(8).unwrap(),
    )
    .unwrap()
}

fn payload_limits() -> ArtifactPayloadStoreLimits {
    ArtifactPayloadStoreLimits::new(8, 1_000_000).unwrap()
}

fn payload_store(directory: &TestDirectory) -> CanonicalArtifactPayloadStore {
    CanonicalArtifactPayloadStore::create(directory.path(), payload_limits()).unwrap()
}

fn retain_candidate(
    selected: &ArtifactChainJournal,
    candidates: &mut ArtifactBlockCandidateStore,
    bytes: &[u8],
) -> ArtifactBlock {
    let block = selected.prepare_block(artifact_id(bytes)).unwrap();
    assert_eq!(
        candidates.insert(&block).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    block
}

fn seed_payload(payloads: &mut CanonicalArtifactPayloadStore, bytes: &[u8]) {
    let mut identity = ArtifactDag::new();
    let record = identity
        .apply_canonical_artifact_bytes(bytes.to_vec())
        .unwrap();
    assert_eq!(
        payloads.insert(record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
}

fn pending_artifact_request(
    network: &StaticArtifactNetwork,
    peer_id: PeerId,
) -> (request_response::OutboundRequestId, ArtifactRequest) {
    network
        .pending_artifact_for_peer_for_test(peer_id)
        .expect("the candidate payload fill has one pending artifact request")
}

fn artifact_response_event_from(
    network: &mut StaticArtifactNetwork,
    expected_peer_id: PeerId,
    actual_peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    let (request_id, _) = pending_artifact_request(network, expected_peer_id);
    network
        .handle_artifact_exchange_event_for_test(request_response::Event::Message {
            peer: actual_peer_id,
            connection_id: ConnectionId::new_unchecked(1_700),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained artifact request produces one terminal event")
}

fn artifact_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    artifact_response_event_from(network, peer_id, peer_id, bytes)
}

fn artifact_failure_event(network: &mut StaticArtifactNetwork, peer_id: PeerId) -> NetworkEvent {
    let (request_id, _) = pending_artifact_request(network, peer_id);
    network
        .handle_artifact_exchange_event_for_test(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_701),
            request_id,
            error: request_response::OutboundFailure::Timeout,
        })
        .expect("the retained artifact request produces one failure terminal")
}

#[test]
fn archive_hit_revalidates_and_completes_without_peer_lookup_or_selection() {
    let directory = TestDirectory::new("candidate-payload-archive-hit");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let mut payloads = payload_store(&directory);
    seed_payload(&mut payloads, &bytes);
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    assert!(
        network
            .start_artifact_block_candidate_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                unknown_peer,
                block.id(),
            )
            .unwrap()
            .is_none()
    );

    assert_snapshot(&directory, &selected, &before);
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(payloads.len().unwrap(), 1);
    assert_eq!(
        payloads
            .get(block.artifact_id())
            .unwrap()
            .unwrap()
            .into_canonical_artifact_bytes()
            .as_ref(),
        bytes
    );
}

#[test]
fn archive_hit_with_missing_selected_dependency_fails_before_peer_lookup() {
    let directory = TestDirectory::new("candidate-payload-archive-hit-dependency");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let parent_bytes = pairing_bytes();
    let mut identity = ArtifactDag::new();
    let parent_proof_id = identity
        .apply_canonical_artifact_bytes(parent_bytes)
        .unwrap()
        .as_proof()
        .unwrap()
        .proof_id();
    let child_bytes = referenced_generalization_bytes(parent_proof_id);
    let child_record = identity
        .apply_canonical_artifact_bytes(child_bytes.clone())
        .unwrap();
    let child_id = child_record.artifact_id();
    let block = selected.prepare_block(child_id).unwrap();
    let mut candidates = candidate_store(&directory);
    assert_eq!(
        candidates.insert(&block).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    let mut payloads = payload_store(&directory);
    assert_eq!(
        payloads.insert(child_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    assert!(matches!(
        network.start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            unknown_peer,
            block.id(),
        ),
        Err(ArtifactBlockCandidatePayloadFillError::CandidateArchive {
            artifact_id,
            source,
        }) if artifact_id == child_id
            && matches!(source.as_ref(), CandidatePayloadArchiveError::Validation { .. })
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(payloads.len().unwrap(), 1);
}

#[test]
fn archive_miss_requests_exact_peer_and_durably_archives_without_selection() {
    let directory = TestDirectory::new("candidate-payload-network-fill");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let mut payloads = payload_store(&directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fill = network
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            peer_id,
            block.id(),
        )
        .unwrap()
        .expect("the archive miss starts one exact request");
    assert_eq!(fill.target_block_id(), block.id());
    assert_eq!(fill.pending_peer_id(), peer_id);
    assert_eq!(candidates.len().unwrap(), 1);
    assert_eq!(
        pending_artifact_request(&network, peer_id).1.artifact_id(),
        block.artifact_id()
    );

    let event = artifact_response_event(&mut network, peer_id, bytes.clone());
    assert!(fill.accepts_event(&event));
    fill.on_event(&mut network, &selected, event).unwrap();
    assert_snapshot(&directory, &selected, &before);
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);

    drop(payloads);
    let mut reopened = CanonicalArtifactPayloadStore::open(directory.path(), payload_limits())
        .expect("the acknowledged payload archive reopens");
    assert_eq!(
        reopened
            .get(block.artifact_id())
            .unwrap()
            .unwrap()
            .into_canonical_artifact_bytes()
            .as_ref(),
        bytes
    );

    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut offline = test_network_for_peers(&[]);
    assert!(
        offline
            .start_artifact_block_candidate_payload_fill(
                &selected,
                &mut candidates,
                &mut reopened,
                unknown_peer,
                block.id(),
            )
            .unwrap()
            .is_none()
    );
    assert!((offline.pending_count_for_test() == 0));
}

#[test]
fn start_precedence_is_chain_then_selection_then_candidate_then_shape_then_archive_then_peer() {
    let selected_directory = TestDirectory::new("candidate-payload-start-precedence-selected");
    let selected = create_journal(selected_directory.path()).unwrap();
    let before = snapshot(&selected_directory, &selected);
    let foreign_directory = TestDirectory::new("candidate-payload-start-precedence-foreign");
    let foreign_definition = naome_chain::ArtifactChainDefinition::new([0x92; 32]);
    let mut foreign_candidates = ArtifactBlockCandidateStore::create(
        foreign_directory.path(),
        foreign_definition,
        ArtifactBlockCandidateStoreLimits::new(8).unwrap(),
    )
    .unwrap();
    let mut foreign_payloads = payload_store(&foreign_directory);
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);
    let target = ArtifactBlockId::from_bytes([0x93; 32]);

    assert!(matches!(
        network.start_artifact_block_candidate_payload_fill(
            &selected,
            &mut foreign_candidates,
            &mut foreign_payloads,
            unknown_peer,
            target,
        ),
        Err(ArtifactBlockCandidatePayloadFillError::ChainIdMismatch { selected: actual_selected, candidates })
            if actual_selected == selected.chain_id() && candidates == foreign_definition.id()
    ));

    let mut candidates = candidate_store(&selected_directory);
    let mut payloads = payload_store(&selected_directory);
    assert!(matches!(
        network.start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            unknown_peer,
            before.head,
        ),
        Err(ArtifactBlockCandidatePayloadFillError::TargetAlreadySelected { block_id })
            if block_id == before.head
    ));
    assert!(matches!(
        network.start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            unknown_peer,
            target,
        ),
        Err(ArtifactBlockCandidatePayloadFillError::CandidateNotRetained { block_id })
            if block_id == target
    ));

    let valid = selected
        .prepare_block(artifact_id(&pairing_bytes()))
        .unwrap();
    let wrong_parent = ArtifactBlockId::from_bytes([0x94; 32]);
    let malformed = ArtifactBlock::new(
        wrong_parent,
        ArtifactSetRoot::from_bytes([0x95; 32]),
        ArtifactSetRoot::from_bytes([0x96; 32]),
        valid.artifact_id(),
    );
    assert_eq!(
        candidates.insert(&malformed).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    assert!(matches!(
        network.start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            unknown_peer,
            malformed.id(),
        ),
        Err(ArtifactBlockCandidatePayloadFillError::ParentBlockIdMismatch { expected, actual })
            if expected == before.head && actual == wrong_parent
    ));

    let block = retain_candidate(&selected, &mut candidates, &pairing_bytes());
    assert!(matches!(
        network.start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            unknown_peer,
            block.id(),
        ),
        Err(ArtifactBlockCandidatePayloadFillError::RequestStart {
            peer_id,
            artifact_id: requested,
            source,
        }) if peer_id == unknown_peer
            && requested == block.artifact_id()
            && matches!(source.as_ref(), RequestStartError::UnknownPeer(source_peer) if *source_peer == unknown_peer)
    ));
    assert_snapshot(&selected_directory, &selected, &before);
    assert!((network.pending_count_for_test() == 0));
}

#[test]
fn invalid_found_bytes_fail_sealed_validation_without_archive_or_selection() {
    let directory = TestDirectory::new("candidate-payload-invalid-found");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let mut payloads = payload_store(&directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let fill = network
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            peer_id,
            block.id(),
        )
        .unwrap()
        .unwrap();

    let event = artifact_response_event(&mut network, peer_id, vec![0xff]);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidatePayloadFillError::CandidateArchive {
            artifact_id,
            source,
        }) if artifact_id == block.artifact_id()
            && matches!(source.as_ref(), CandidatePayloadArchiveError::Validation { .. })
    ));
    assert_snapshot(&directory, &selected, &before);
    assert!(payloads.is_empty().unwrap());
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
}

#[test]
fn valid_found_bytes_report_archive_capacity_without_mutating_journal_or_candidate() {
    let directory = TestDirectory::new("candidate-payload-archive-capacity");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let candidate_image = fs::read(directory.path().join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_bytes = u64::try_from(bytes.len()).unwrap();
    let maximum = payload_bytes - 1;
    let mut payloads = CanonicalArtifactPayloadStore::create(
        directory.path(),
        ArtifactPayloadStoreLimits::new(1, maximum).unwrap(),
    )
    .unwrap();
    let payload_image = fs::read(directory.path().join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let fill = network
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            peer_id,
            block.id(),
        )
        .unwrap()
        .unwrap();

    let event = artifact_response_event(&mut network, peer_id, bytes);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidatePayloadFillError::CandidateArchive {
            artifact_id,
            source,
        }) if artifact_id == block.artifact_id()
            && matches!(
                source.as_ref(),
                CandidatePayloadArchiveError::Archive { source }
                    if matches!(
                        source.as_ref(),
                        CanonicalArtifactPayloadStoreError::PayloadByteLimitExceeded {
                            actual,
                            maximum: error_maximum,
                        } if *actual == payload_bytes && *error_maximum == maximum
                    )
            )
    ));
    assert_snapshot(&directory, &selected, &before);
    assert_eq!(candidates.len().unwrap(), 1);
    assert_eq!(candidates.get(block.id()).unwrap(), Some(block));
    assert_eq!(
        fs::read(directory.path().join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert!(payloads.is_empty().unwrap());
    assert_eq!(
        fs::read(directory.path().join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
}

#[test]
fn selected_head_change_precedes_unavailable_and_leaves_archive_empty() {
    let directory = TestDirectory::new("candidate-payload-head-change");
    let mut selected = create_journal(directory.path()).unwrap();
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let captured_head = selected.head_block_id().unwrap();
    let mut payloads = payload_store(&directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let fill = network
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            peer_id,
            block.id(),
        )
        .unwrap()
        .unwrap();

    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let actual_head = selected.head_block_id().unwrap();
    let event = artifact_response_event(&mut network, peer_id, Vec::new());
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidatePayloadFillError::SelectedHeadChanged { expected, actual })
            if expected == captured_head && actual == actual_head
    ));
    assert!(payloads.is_empty().unwrap());
    assert_eq!(selected.len().unwrap(), 1);
}

#[test]
fn peer_mismatch_precedes_selected_head_change() {
    let directory = TestDirectory::new("candidate-payload-peer-mismatch");
    let mut selected = create_journal(directory.path()).unwrap();
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let mut payloads = payload_store(&directory);
    let expected_peer = Keypair::generate_ed25519().public().to_peer_id();
    let actual_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[expected_peer]);
    let fill = network
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            expected_peer,
            block.id(),
        )
        .unwrap()
        .unwrap();

    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let event = artifact_response_event_from(&mut network, expected_peer, actual_peer, bytes);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidatePayloadFillError::ArtifactRequestFailed {
            peer_id,
            source,
            ..
        }) if peer_id == expected_peer
            && matches!(
                source.as_ref(),
                OutboundArtifactFailure::PeerMismatch { expected, actual }
                    if *expected == expected_peer && *actual == actual_peer
            )
    ));
    assert!(payloads.is_empty().unwrap());
}

#[test]
fn foreign_driver_and_transport_failure_are_terminal_without_retry() {
    let directory = TestDirectory::new("candidate-payload-driver-and-failure");
    let selected = create_journal(directory.path()).unwrap();
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let mut payloads = payload_store(&directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut first = test_network_for_peers(&[peer_id]);
    let mut second = test_network_for_peers(&[peer_id]);
    let fill = first
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            peer_id,
            block.id(),
        )
        .unwrap()
        .unwrap();
    let event = artifact_failure_event(&mut first, peer_id);
    assert!(fill.accepts_event(&event));
    assert!(matches!(
        fill.on_event(&mut second, &selected, event),
        Err(ArtifactBlockCandidatePayloadFillError::UnexpectedEvent)
    ));
    assert!(payloads.is_empty().unwrap());
    assert_eq!(first.active_permit_count_for_test(), 0);

    let fill = second
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            peer_id,
            block.id(),
        )
        .unwrap()
        .unwrap();
    let event = artifact_failure_event(&mut second, peer_id);
    assert!(matches!(
        fill.on_event(&mut second, &selected, event),
        Err(ArtifactBlockCandidatePayloadFillError::ArtifactRequestFailed {
            peer_id: failed_peer,
            artifact_id,
            source,
        }) if failed_peer == peer_id
            && artifact_id == block.artifact_id()
            && matches!(
                source.as_ref(),
                OutboundArtifactFailure::Transport(request_response::OutboundFailure::Timeout)
            )
    ));
    assert!((second.pending_count_for_test() == 0));
    assert_eq!(second.active_permit_count_for_test(), 0);
}

#[tokio::test(start_paused = true)]
async fn one_absolute_deadline_is_terminal_without_archive() {
    let directory = TestDirectory::new("candidate-payload-deadline");
    let selected = create_journal(directory.path()).unwrap();
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let mut payloads = payload_store(&directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let fill = network
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            peer_id,
            block.id(),
        )
        .unwrap()
        .unwrap();

    tokio::time::advance(ARTIFACT_BLOCK_IMPORT_TIMEOUT).await;
    let deadline = network
        .take_due_artifact_request_deadline_for_test(tokio::time::Instant::now())
        .expect("the exact payload request deadline is due");
    assert!(fill.accepts_event(&deadline));
    assert!(matches!(
        fill.on_event(&mut network, &selected, deadline),
        Err(ArtifactBlockCandidatePayloadFillError::ArtifactDeadlineExceeded {
            peer_id: deadline_peer,
            artifact_id,
        }) if deadline_peer == peer_id && artifact_id == block.artifact_id()
    ));
    assert!(payloads.is_empty().unwrap());
    assert_eq!(network.active_permit_count_for_test(), 1);

    let drained = artifact_response_event(&mut network, peer_id, bytes);
    assert!(matches!(
        drained,
        NetworkEvent::ArtifactCancellationDrained { .. }
    ));
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
}

#[test]
fn unavailable_is_terminal_and_does_not_try_another_configured_peer() {
    let directory = TestDirectory::new("candidate-payload-unavailable");
    let selected = create_journal(directory.path()).unwrap();
    let bytes = pairing_bytes();
    let mut candidates = candidate_store(&directory);
    let block = retain_candidate(&selected, &mut candidates, &bytes);
    let mut payloads = payload_store(&directory);
    let selected_peer = Keypair::generate_ed25519().public().to_peer_id();
    let unused_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[selected_peer, unused_peer]);
    let fill = network
        .start_artifact_block_candidate_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            selected_peer,
            block.id(),
        )
        .unwrap()
        .unwrap();

    let event = artifact_response_event(&mut network, selected_peer, Vec::new());
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidatePayloadFillError::ArtifactUnavailable {
            peer_id,
            artifact_id,
        }) if peer_id == selected_peer && artifact_id == block.artifact_id()
    ));
    assert!(payloads.is_empty().unwrap());
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
}
