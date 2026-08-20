use std::sync::atomic::Ordering;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::artifact_exchange::{ArtifactRequest, ArtifactResponse};
use naome_chain::{ArtifactBlock, ArtifactChainState, ArtifactDag, ArtifactSetRoot};
use naome_foundation::FreeVariable;
use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep};
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreLimits, ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits,
    CandidateBranchReconstructionError, CandidateBranchReconstructionLimits,
    CanonicalArtifactPayloadStore, CanonicalArtifactPayloadStoreError,
};

use super::*;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, create_journal, pairing_bytes, snapshot,
    test_chain_definition, test_network_for_peers, union_bytes,
};
use crate::{
    ExchangeRequestId, Keypair, NetworkEvent, OutboundArtifactFailure, PendingRequest,
    RequestStartError,
};

struct DependencyBranch {
    blocks: Vec<ArtifactBlock>,
    payloads: Vec<Vec<u8>>,
    root: ArtifactSetRoot,
}

fn reconstruction_limits(blocks: usize) -> CandidateBranchReconstructionLimits {
    CandidateBranchReconstructionLimits::new(blocks).unwrap()
}

fn candidate_store(directory: &TestDirectory) -> ArtifactBlockCandidateStore {
    ArtifactBlockCandidateStore::create(
        directory.path(),
        test_chain_definition(),
        ArtifactBlockCandidateStoreLimits::new(8).unwrap(),
    )
    .unwrap()
}

fn payload_limits(entries: usize, bytes: u64) -> ArtifactPayloadStoreLimits {
    ArtifactPayloadStoreLimits::new(entries, bytes).unwrap()
}

fn payload_store(directory: &TestDirectory) -> CanonicalArtifactPayloadStore {
    CanonicalArtifactPayloadStore::create(directory.path(), payload_limits(8, 1_000_000)).unwrap()
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

fn dependency_branch() -> DependencyBranch {
    let first_bytes = pairing_bytes();
    let mut identities = ArtifactDag::new();
    let first_record = identities
        .apply_canonical_artifact_bytes(first_bytes.clone())
        .unwrap();
    let first_id = first_record.artifact_id();
    let first_proof_id = first_record.as_proof().unwrap().proof_id();
    let second_bytes = referenced_generalization_bytes(first_proof_id);
    let second_id = identities
        .apply_canonical_artifact_bytes(second_bytes.clone())
        .unwrap()
        .artifact_id();

    let mut branch = ArtifactChainState::new(test_chain_definition());
    let first = branch.prepare_block(first_id).unwrap();
    branch.apply_block(&first, first_bytes.clone()).unwrap();
    let second = branch.prepare_block(second_id).unwrap();
    branch.apply_block(&second, second_bytes.clone()).unwrap();

    DependencyBranch {
        blocks: vec![first, second],
        payloads: vec![first_bytes, second_bytes],
        root: branch.artifact_dag().artifact_set_root(),
    }
}

fn insert_candidates(store: &mut ArtifactBlockCandidateStore, blocks: &[ArtifactBlock]) {
    for block in blocks {
        assert_eq!(
            store.insert(block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
}

fn seed_payloads(store: &mut CanonicalArtifactPayloadStore, payloads: &[Vec<u8>]) {
    let mut source = ArtifactDag::new();
    for payload in payloads {
        let record = source
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap();
        assert_eq!(
            store.insert(record).unwrap(),
            ArtifactPayloadInsertOutcome::Inserted
        );
    }
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
        .expect("the branch payload fill has one pending artifact request")
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
            connection_id: ConnectionId::new_unchecked(1_800),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained branch payload request produces one terminal event")
}

fn artifact_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    artifact_response_event_from(network, peer_id, peer_id, bytes)
}

fn awaiting(
    progress: ArtifactBlockCandidateBranchPayloadFillProgress<'_>,
) -> ArtifactBlockCandidateBranchPayloadFill<'_> {
    let ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(fill) = progress else {
        panic!("the branch payload fill unexpectedly completed")
    };
    fill
}

fn complete(
    progress: ArtifactBlockCandidateBranchPayloadFillProgress<'_>,
) -> naome_storage::ReconstructedCandidateBranch {
    let ArtifactBlockCandidateBranchPayloadFillProgress::Complete(reconstructed) = progress else {
        panic!("the branch payload fill unexpectedly awaits a response")
    };
    reconstructed
}

#[test]
fn all_archive_hits_complete_branch_only_dependency_without_peer_lookup() {
    let directory = TestDirectory::new("candidate-branch-payload-all-hits");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let target = branch.blocks[1].id();
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, &branch.blocks);
    let mut payloads = payload_store(&directory);
    seed_payloads(&mut payloads, &branch.payloads);
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    assert!(matches!(
        network.start_artifact_block_candidate_branch_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            unknown_peer,
            target,
            reconstruction_limits(1),
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::Reconstruction { source })
            if matches!(
                source.as_ref(),
                CandidateBranchReconstructionError::BlockLimitExceeded { maximum: 1, .. }
            )
    ));
    assert!(network.pending.is_empty());

    let reconstructed = complete(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                unknown_peer,
                target,
                reconstruction_limits(2),
            )
            .unwrap(),
    );
    assert_eq!(reconstructed.target_block_id(), target);
    assert_eq!(reconstructed.block_count(), 2);
    assert_eq!(reconstructed.snapshot().artifact_set_root(), branch.root);
    assert_snapshot(&directory, &selected, &before);
    assert!(network.pending.is_empty());
    assert_eq!(payloads.len().unwrap(), 2);
}

#[test]
fn acknowledged_prefix_survives_failure_and_restart_requests_only_next_payload() {
    let directory = TestDirectory::new("candidate-branch-payload-restart");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let first = branch.blocks[0];
    let target = branch.blocks[1];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, &branch.blocks);
    let mut payloads = payload_store(&directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let unused_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id, unused_peer]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                peer_id,
                target.id(),
                reconstruction_limits(2),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_block_id(), first.id());
    assert_eq!(fill.pending_artifact_id(), first.artifact_id());
    let event = artifact_response_event(&mut network, peer_id, branch.payloads[0].clone());
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_block_id(), target.id());
    assert_eq!(fill.pending_artifact_id(), target.artifact_id());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    assert_eq!(
        pending_artifact_request(&network, peer_id).1.artifact_id(),
        target.artifact_id()
    );

    let unavailable = artifact_response_event(&mut network, peer_id, Vec::new());
    assert!(matches!(
        fill.on_event(&mut network, unavailable),
        Err(ArtifactBlockCandidateBranchPayloadFillError::ArtifactUnavailable {
            peer_id: actual_peer,
            block_id,
            artifact_id,
        }) if *actual_peer == peer_id && block_id == target.id() && artifact_id == target.artifact_id()
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(payloads.contains(first.artifact_id()).unwrap());
    assert!(!payloads.contains(target.artifact_id()).unwrap());
    drop(payloads);

    let mut payloads =
        CanonicalArtifactPayloadStore::open(directory.path(), payload_limits(8, 1_000_000))
            .unwrap();
    assert!(payloads.contains(first.artifact_id()).unwrap());
    let mut restarted = test_network_for_peers(&[peer_id]);
    let fill = awaiting(
        restarted
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                peer_id,
                target.id(),
                reconstruction_limits(2),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_block_id(), target.id());
    let event = artifact_response_event(&mut restarted, peer_id, branch.payloads[1].clone());
    let reconstructed = complete(fill.on_event(&mut restarted, event).unwrap());
    assert_eq!(reconstructed.target_block_id(), target.id());
    assert_eq!(reconstructed.snapshot().artifact_set_root(), branch.root);
    assert!(payloads.contains(target.artifact_id()).unwrap());
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn acknowledged_payload_survives_the_next_request_start_failure() {
    let directory = TestDirectory::new("candidate-branch-payload-next-start-failure");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let first = branch.blocks[0];
    let target = branch.blocks[1];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, &branch.blocks);
    let limits = payload_limits(8, 1_000_000);
    let mut payloads = CanonicalArtifactPayloadStore::create(directory.path(), limits).unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                peer_id,
                target.id(),
                reconstruction_limits(2),
            )
            .unwrap(),
    );
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);
    let event = artifact_response_event(&mut network, peer_id, branch.payloads[0].clone());
    assert!(matches!(
        fill.on_event(&mut network, event),
        Err(ArtifactBlockCandidateBranchPayloadFillError::RequestStart {
            peer_id: actual_peer,
            block_id,
            artifact_id,
            source,
        }) if *actual_peer == peer_id
            && block_id == target.id()
            && artifact_id == target.artifact_id()
            && matches!(
                source.as_ref(),
                RequestStartError::PeerDisconnected(actual) if *actual == peer_id
            )
    ));
    assert!(payloads.contains(first.artifact_id()).unwrap());
    assert!(!payloads.contains(target.artifact_id()).unwrap());
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);

    drop(payloads);
    let reopened = CanonicalArtifactPayloadStore::open(directory.path(), limits).unwrap();
    assert!(reopened.contains(first.artifact_id()).unwrap());
    assert!(!reopened.contains(target.artifact_id()).unwrap());
}

#[test]
fn invalid_and_over_capacity_payloads_fail_without_archive_or_partial_result() {
    let invalid_directory = TestDirectory::new("candidate-branch-payload-invalid");
    let selected = create_journal(invalid_directory.path()).unwrap();
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&invalid_directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let mut payloads = payload_store(&invalid_directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                peer_id,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    let event = artifact_response_event(&mut network, peer_id, vec![0xff]);
    assert!(matches!(
        fill.on_event(&mut network, event),
        Err(ArtifactBlockCandidateBranchPayloadFillError::Reconstruction { source })
            if matches!(
                source.as_ref(),
                CandidateBranchReconstructionError::BlockValidation { block_id, .. }
                    if *block_id == block.id()
            )
    ));
    assert!(payloads.is_empty().unwrap());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let capacity_directory = TestDirectory::new("candidate-branch-payload-capacity");
    let selected = create_journal(capacity_directory.path()).unwrap();
    let mut candidates = candidate_store(&capacity_directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let maximum = u64::try_from(branch.payloads[0].len()).unwrap() - 1;
    let mut payloads = CanonicalArtifactPayloadStore::create(
        capacity_directory.path(),
        payload_limits(1, maximum),
    )
    .unwrap();
    let mut network = test_network_for_peers(&[peer_id]);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                peer_id,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    let event = artifact_response_event(&mut network, peer_id, branch.payloads[0].clone());
    assert!(matches!(
        fill.on_event(&mut network, event),
        Err(ArtifactBlockCandidateBranchPayloadFillError::Reconstruction { source })
            if matches!(
                source.as_ref(),
                CandidateBranchReconstructionError::PayloadArchive {
                    block_id,
                    artifact_id,
                    source,
                } if *block_id == block.id()
                    && *artifact_id == block.artifact_id()
                    && matches!(
                        source.as_ref(),
                        CanonicalArtifactPayloadStoreError::PayloadByteLimitExceeded {
                            maximum: error_maximum,
                            ..
                        } if *error_maximum == maximum
                    )
            )
    ));
    assert!(payloads.is_empty().unwrap());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn branch_only_dependency_continues_from_captured_snapshot_after_selected_head_drift() {
    let directory = TestDirectory::new("candidate-branch-payload-head-drift");
    let mut selected = create_journal(directory.path()).unwrap();
    let branch = dependency_branch();
    let target = branch.blocks[1];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, &branch.blocks);
    let mut payloads = payload_store(&directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                peer_id,
                target.id(),
                reconstruction_limits(2),
            )
            .unwrap(),
    );

    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let selected_head = selected.head_block_id().unwrap();
    let event = artifact_response_event(&mut network, peer_id, branch.payloads[0].clone());
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    let event = artifact_response_event(&mut network, peer_id, branch.payloads[1].clone());
    let reconstructed = complete(fill.on_event(&mut network, event).unwrap());

    assert_eq!(reconstructed.target_block_id(), target.id());
    assert_eq!(reconstructed.block_count(), 2);
    assert_eq!(reconstructed.snapshot().artifact_set_root(), branch.root);
    assert_eq!(selected.head_block_id().unwrap(), selected_head);
    assert_eq!(selected.len().unwrap(), 1);
    assert_ne!(selected_head, target.id());
    assert!(network.pending.is_empty());
}

#[test]
fn peer_mismatch_is_exact_and_cancellation_drains_the_physical_permit() {
    let directory = TestDirectory::new("candidate-branch-payload-mismatch-cancel");
    let selected = create_journal(directory.path()).unwrap();
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let mut payloads = payload_store(&directory);
    let expected_peer = Keypair::generate_ed25519().public().to_peer_id();
    let actual_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[expected_peer]);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                expected_peer,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    let mismatch = artifact_response_event_from(
        &mut network,
        expected_peer,
        actual_peer,
        branch.payloads[0].clone(),
    );
    assert!(fill.accepts_event(&mismatch));
    assert!(matches!(
        fill.on_event(&mut network, mismatch),
        Err(ArtifactBlockCandidateBranchPayloadFillError::ArtifactRequestFailed {
            peer_id,
            block_id,
            artifact_id,
            source,
        }) if *peer_id == expected_peer
            && block_id == block.id()
            && artifact_id == block.artifact_id()
            && matches!(
                source.as_ref(),
                OutboundArtifactFailure::PeerMismatch { expected, actual }
                    if *expected == expected_peer && *actual == actual_peer
            )
    ));
    assert!(payloads.is_empty().unwrap());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                expected_peer,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    fill.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let drained = artifact_response_event(&mut network, expected_peer, branch.payloads[0].clone());
    assert!(matches!(
        drained,
        NetworkEvent::ArtifactCancellationDrained { .. }
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(payloads.is_empty().unwrap());
}

#[test]
fn archive_miss_uses_only_the_exact_caller_selected_peer() {
    let directory = TestDirectory::new("candidate-branch-payload-direct-peer");
    let selected = create_journal(directory.path()).unwrap();
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let mut payloads = payload_store(&directory);
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let configured_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[configured_peer]);

    assert!(matches!(
        network.start_artifact_block_candidate_branch_payload_fill(
            &selected,
            &mut candidates,
            &mut payloads,
            unknown_peer,
            block.id(),
            reconstruction_limits(1),
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::RequestStart {
            peer_id,
            block_id,
            artifact_id,
            source,
        }) if *peer_id == unknown_peer
            && block_id == block.id()
            && artifact_id == block.artifact_id()
            && matches!(source.as_ref(), RequestStartError::UnknownPeer(actual) if *actual == unknown_peer)
    ));
    assert!(network.pending.is_empty());
    assert!(payloads.is_empty().unwrap());
}

#[tokio::test(start_paused = true)]
async fn one_payload_deadline_is_terminal_and_drains_without_archive() {
    let directory = TestDirectory::new("candidate-branch-payload-deadline");
    let selected = create_journal(directory.path()).unwrap();
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let mut payloads = payload_store(&directory);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill(
                &selected,
                &mut candidates,
                &mut payloads,
                peer_id,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );

    tokio::time::advance(ARTIFACT_BLOCK_IMPORT_TIMEOUT).await;
    let deadline = network
        .take_due_artifact_request_deadline(tokio::time::Instant::now())
        .unwrap();
    assert!(fill.accepts_event(&deadline));
    assert!(matches!(
        fill.on_event(&mut network, deadline),
        Err(ArtifactBlockCandidateBranchPayloadFillError::ArtifactDeadlineExceeded {
            peer_id: actual_peer,
            block_id,
            artifact_id,
        }) if *actual_peer == peer_id
            && block_id == block.id()
            && artifact_id == block.artifact_id()
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let drained = artifact_response_event(&mut network, peer_id, branch.payloads[0].clone());
    assert!(matches!(
        drained,
        NetworkEvent::ArtifactCancellationDrained { .. }
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(payloads.is_empty().unwrap());
}
