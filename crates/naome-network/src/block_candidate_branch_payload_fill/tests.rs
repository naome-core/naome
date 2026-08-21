use std::fs;
use std::sync::atomic::Ordering;
use std::time::Duration;

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
use tokio::time::timeout;

use super::*;
use crate::tests::{
    TestDirectory, address, apply_fresh_blocks, assert_snapshot, create_journal, listening_address,
    pairing_bytes, snapshot, test_chain_definition, test_network_for_peers, union_bytes,
};
use crate::{
    ExchangeRequestId, Keypair, MAX_PENDING_REQUESTS, MAX_STATIC_PEERS, NetworkEvent,
    OutboundArtifactFailure, PeerSessionEvent, PendingRequest, RequestStartError, StaticPeer,
};

const CANDIDATE_STORE_FILE_NAME: &str = "artifact-block-candidate-store.log";
const PAYLOAD_STORE_FILE_NAME: &str = "artifact-payload-store.log";

struct DependencyBranch {
    blocks: Vec<ArtifactBlock>,
    payloads: Vec<Vec<u8>>,
    root: ArtifactSetRoot,
}

fn peer_ids(count: usize) -> Vec<PeerId> {
    (0..count)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect()
}

fn candidate_store_bytes(directory: &TestDirectory) -> Vec<u8> {
    fs::read(directory.path().join(CANDIDATE_STORE_FILE_NAME)).unwrap()
}

fn payload_store_bytes(directory: &TestDirectory) -> Vec<u8> {
    fs::read(directory.path().join(PAYLOAD_STORE_FILE_NAME)).unwrap()
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

fn artifact_failure_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> NetworkEvent {
    let (request_id, _) = pending_artifact_request(network, peer_id);
    network
        .handle_artifact_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_801),
            request_id,
            error,
        })
        .expect("the branch payload fill produces one failure terminal event")
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

async fn connected_archive_triplet() -> (
    StaticArtifactNetwork,
    StaticArtifactNetwork,
    StaticArtifactNetwork,
    PeerId,
    PeerId,
) {
    let mut identities = (0..3)
        .map(|_| Keypair::generate_ed25519())
        .collect::<Vec<_>>();
    identities.sort_unstable_by_key(|identity| identity.public().to_peer_id().to_bytes());
    let mut identities = identities.into_iter();
    let client_identity = identities.next().unwrap();
    let first_server_identity = identities.next().unwrap();
    let second_server_identity = identities.next().unwrap();
    let client_peer_id = client_identity.public().to_peer_id();
    let first_server_peer_id = first_server_identity.public().to_peer_id();
    let second_server_peer_id = second_server_identity.public().to_peer_id();

    let mut first_server = StaticArtifactNetwork::new(
        first_server_identity,
        [StaticPeer::new(client_peer_id, address(1))],
    )
    .unwrap();
    let first_server_address = listening_address(&mut first_server).await;
    let mut second_server = StaticArtifactNetwork::new(
        second_server_identity,
        [StaticPeer::new(client_peer_id, address(2))],
    )
    .unwrap();
    let second_server_address = listening_address(&mut second_server).await;
    let mut client = StaticArtifactNetwork::new(
        client_identity,
        [
            StaticPeer::new(first_server_peer_id, first_server_address),
            StaticPeer::new(second_server_peer_id, second_server_address),
        ],
    )
    .unwrap();

    let mut client_established = [false; 2];
    let mut first_server_established = false;
    let mut second_server_established = false;
    timeout(Duration::from_secs(15), async {
        while !client_established.iter().all(|established| *established)
            || !first_server_established
            || !second_server_established
        {
            tokio::select! {
                event = client.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id })
                        if peer_id == first_server_peer_id => client_established[0] = true,
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id })
                        if peer_id == second_server_peer_id => client_established[1] = true,
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("client dial to {peer_id} failed")
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("client listener failed: {error}")
                    }
                    _ => {}
                },
                event = first_server.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, client_peer_id);
                        first_server_established = true;
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("first server listener failed: {error}")
                    }
                    _ => {}
                },
                event = second_server.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        assert_eq!(peer_id, client_peer_id);
                        second_server_established = true;
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("second server listener failed: {error}")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("both archive peer sessions did not establish");

    (
        client,
        first_server,
        second_server,
        first_server_peer_id,
        second_server_peer_id,
    )
}

async fn complete_fallback_branch_fill<'store>(
    client: &mut StaticArtifactNetwork,
    first_server: &mut StaticArtifactNetwork,
    second_server: &mut StaticArtifactNetwork,
    first_server_payloads: &mut CanonicalArtifactPayloadStore,
    second_server_payloads: &mut CanonicalArtifactPayloadStore,
    progress: ArtifactBlockCandidateBranchPayloadFillProgress<'store>,
) -> (
    naome_storage::ReconstructedCandidateBranch,
    Vec<(naome_proof::ArtifactId, PeerId)>,
) {
    let mut fill = Some(awaiting(progress));
    let mut attempts = Vec::new();
    let reconstructed = timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = client.next_event() => {
                    let active = fill.as_ref().expect("a branch fill remains active");
                    if !active.accepts_event(&event) {
                        continue;
                    }
                    attempts.push((active.pending_artifact_id(), active.pending_peer_id()));
                    let active = fill.take().unwrap();
                    match active.on_event(client, event).unwrap() {
                        ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(next) => {
                            fill = Some(next);
                        }
                        ArtifactBlockCandidateBranchPayloadFillProgress::Complete(reconstructed) => {
                            return reconstructed;
                        }
                    }
                }
                event = first_server.next_event() => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        first_server
                            .respond_artifact_from_payload_store(inbound, first_server_payloads)
                            .unwrap();
                    }
                    NetworkEvent::InboundArtifactFailure { error, .. } => {
                        panic!("first archive response failed: {error}")
                    }
                    _ => {}
                },
                event = second_server.next_event() => match event {
                    NetworkEvent::InboundArtifactRequest(inbound) => {
                        second_server
                            .respond_artifact_from_payload_store(inbound, second_server_payloads)
                            .unwrap();
                    }
                    NetworkEvent::InboundArtifactFailure { error, .. } => {
                        panic!("second archive response failed: {error}")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("candidate branch payload fallback timed out");
    (reconstructed, attempts)
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

#[test]
fn fallback_peer_validation_is_lazy_bounded_and_reports_lowest_raw_identity() {
    let all_hit_directory = TestDirectory::new("candidate-branch-fallback-lazy-validation");
    let all_hit_selected = create_journal(all_hit_directory.path()).unwrap();
    let all_hit_before = snapshot(&all_hit_directory, &all_hit_selected);
    let branch = dependency_branch();
    let target = branch.blocks[1].id();
    let mut all_hit_candidates = candidate_store(&all_hit_directory);
    insert_candidates(&mut all_hit_candidates, &branch.blocks);
    let all_hit_candidate_bytes = candidate_store_bytes(&all_hit_directory);
    let mut all_hit_payloads = payload_store(&all_hit_directory);
    seed_payloads(&mut all_hit_payloads, &branch.payloads);
    let invalid_peers = peer_ids(MAX_STATIC_PEERS + 1);
    let duplicate_unknown = [invalid_peers[0], invalid_peers[0]];
    let mut all_hit_network = test_network_for_peers(&[]);

    for peer_ids in [&[][..], &invalid_peers[..], &duplicate_unknown[..]] {
        let reconstructed = complete(
            all_hit_network
                .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                    &all_hit_selected,
                    &mut all_hit_candidates,
                    &mut all_hit_payloads,
                    peer_ids,
                    target,
                    reconstruction_limits(2),
                )
                .unwrap(),
        );
        assert_eq!(reconstructed.target_block_id(), target);
        assert_eq!(reconstructed.snapshot().artifact_set_root(), branch.root);
    }
    assert!(matches!(
        all_hit_network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &all_hit_selected,
                &mut all_hit_candidates,
                &mut all_hit_payloads,
                &[],
                target,
                reconstruction_limits(1),
            ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::Reconstruction { source })
            if matches!(
                source.as_ref(),
                CandidateBranchReconstructionError::BlockLimitExceeded { maximum: 1, .. }
            )
    ));
    assert!(all_hit_network.pending.is_empty());
    assert_eq!(
        candidate_store_bytes(&all_hit_directory),
        all_hit_candidate_bytes
    );
    assert_snapshot(&all_hit_directory, &all_hit_selected, &all_hit_before);

    let miss_directory = TestDirectory::new("candidate-branch-fallback-peer-validation");
    let miss_selected = create_journal(miss_directory.path()).unwrap();
    let miss_before = snapshot(&miss_directory, &miss_selected);
    let block = branch.blocks[0];
    let mut miss_candidates = candidate_store(&miss_directory);
    insert_candidates(&mut miss_candidates, std::slice::from_ref(&block));
    let miss_candidate_bytes = candidate_store_bytes(&miss_directory);
    let mut miss_payloads = payload_store(&miss_directory);
    let mut configured = peer_ids(2);
    configured.sort_unstable();
    let mut network = test_network_for_peers(&configured);

    assert!(matches!(
        network.start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
            &miss_selected,
            &mut miss_candidates,
            &mut miss_payloads,
            &[],
            block.id(),
            reconstruction_limits(1),
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::EmptyPayloadPeerSet)
    ));

    let too_many = peer_ids(MAX_STATIC_PEERS + 1);
    assert!(matches!(
        network.start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
            &miss_selected,
            &mut miss_candidates,
            &mut miss_payloads,
            &too_many,
            block.id(),
            reconstruction_limits(1),
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::TooManyPayloadPeers {
            actual,
            maximum,
        }) if actual == MAX_STATIC_PEERS + 1 && maximum == MAX_STATIC_PEERS
    ));

    let [lowest, highest] = configured.as_slice() else {
        unreachable!("the fixture contains exactly two configured peers")
    };
    let unknown_before_duplicates = Keypair::generate_ed25519().public().to_peer_id();
    let duplicate_order = [
        unknown_before_duplicates,
        *highest,
        *lowest,
        *highest,
        *lowest,
    ];
    assert!(matches!(
        network.start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
            &miss_selected,
            &mut miss_candidates,
            &mut miss_payloads,
            &duplicate_order,
            block.id(),
            reconstruction_limits(1),
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::DuplicatePayloadPeer { peer_id })
            if *peer_id == *lowest
    ));

    let mut unknown = peer_ids(2);
    unknown.sort_unstable();
    let unknown_order = [unknown[1], *highest, unknown[0]];
    assert!(matches!(
        network.start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
            &miss_selected,
            &mut miss_candidates,
            &mut miss_payloads,
            &unknown_order,
            block.id(),
            reconstruction_limits(1),
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::UnknownPayloadPeer { peer_id })
            if *peer_id == unknown[0]
    ));
    assert!(network.pending.is_empty());
    assert!(miss_payloads.is_empty().unwrap());
    assert_eq!(candidate_store_bytes(&miss_directory), miss_candidate_bytes);
    assert_snapshot(&miss_directory, &miss_selected, &miss_before);
}

#[test]
fn fallback_preserves_non_raw_caller_order_across_transport_codec_and_unavailable() {
    let directory = TestDirectory::new("candidate-branch-fallback-order");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let candidate_bytes = candidate_store_bytes(&directory);
    let mut payloads = payload_store(&directory);
    let mut raw_order = peer_ids(4);
    raw_order.sort_unstable();
    let caller_order = [raw_order[2], raw_order[0], raw_order[3], raw_order[1]];
    assert_ne!(caller_order.as_slice(), raw_order.as_slice());
    let mut network = test_network_for_peers(&raw_order);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &caller_order,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_peer_id(), caller_order[0]);

    let event = artifact_failure_event(
        &mut network,
        caller_order[0],
        request_response::OutboundFailure::Timeout,
    );
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_peer_id(), caller_order[1]);

    let codec_error = std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid artifact response framing",
    );
    let event = artifact_failure_event(
        &mut network,
        caller_order[1],
        request_response::OutboundFailure::Io(codec_error),
    );
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_peer_id(), caller_order[2]);

    let event = artifact_response_event(&mut network, caller_order[2], Vec::new());
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_peer_id(), caller_order[3]);

    let event = artifact_response_event(&mut network, caller_order[3], branch.payloads[0].clone());
    let reconstructed = complete(fill.on_event(&mut network, event).unwrap());
    assert_eq!(reconstructed.target_block_id(), block.id());
    assert!(payloads.contains(block.artifact_id()).unwrap());
    assert!(network.pending.is_empty());
    assert_eq!(candidate_store_bytes(&directory), candidate_bytes);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_skips_busy_and_disconnected_peers_but_the_eighth_succeeds() {
    let directory = TestDirectory::new("candidate-branch-fallback-skips");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let candidate_bytes = candidate_store_bytes(&directory);
    let mut payloads = payload_store(&directory);
    let peers = peer_ids(MAX_STATIC_PEERS);
    let mut network = test_network_for_peers(&peers);

    network
        .request_artifact(
            peers[0],
            ArtifactRequest::new(naome_proof::ArtifactId::from_bytes([0xb1; 32])),
        )
        .unwrap();
    for peer_id in &peers[1..MAX_STATIC_PEERS - 1] {
        network
            .swarm
            .behaviour_mut()
            .sessions
            .mark_disconnected_for_test(*peer_id);
    }

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_peer_id(), peers[MAX_STATIC_PEERS - 1]);
    assert_eq!(network.pending.len(), 2);
    let event = artifact_response_event(
        &mut network,
        peers[MAX_STATIC_PEERS - 1],
        branch.payloads[0].clone(),
    );
    let reconstructed = complete(fill.on_event(&mut network, event).unwrap());
    assert_eq!(reconstructed.target_block_id(), block.id());
    assert_eq!(network.pending.len(), 1);

    drop(artifact_response_event(&mut network, peers[0], Vec::new()));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(candidate_store_bytes(&directory), candidate_bytes);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_distinguishes_no_requestable_peer_from_last_terminal_exhaustion() {
    let directory = TestDirectory::new("candidate-branch-fallback-exhaustion");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let candidate_bytes = candidate_store_bytes(&directory);
    let mut payloads = payload_store(&directory);
    let peers = peer_ids(2);
    let mut network = test_network_for_peers(&peers);

    network
        .request_artifact(
            peers[0],
            ArtifactRequest::new(naome_proof::ArtifactId::from_bytes([0xb2; 32])),
        )
        .unwrap();
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peers[1]);
    assert!(matches!(
        network.start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
            &selected,
            &mut candidates,
            &mut payloads,
            &peers,
            block.id(),
            reconstruction_limits(1),
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::NoRequestablePayloadPeer {
            block_id,
            artifact_id,
        }) if block_id == block.id() && artifact_id == block.artifact_id()
    ));
    drop(artifact_response_event(&mut network, peers[0], Vec::new()));
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_connected_for_test(peers[1]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    let event = artifact_response_event(&mut network, peers[0], Vec::new());
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[1]);
    let event = artifact_failure_event(
        &mut network,
        peers[1],
        request_response::OutboundFailure::Timeout,
    );
    assert!(matches!(
        fill.on_event(&mut network, event),
        Err(ArtifactBlockCandidateBranchPayloadFillError::ArtifactRequestFailed {
            peer_id,
            block_id,
            artifact_id,
            source,
        }) if *peer_id == peers[1]
            && block_id == block.id()
            && artifact_id == block.artifact_id()
            && matches!(
                source.as_ref(),
                OutboundArtifactFailure::Transport(request_response::OutboundFailure::Timeout)
            )
    ));
    assert!(network.pending.is_empty());
    assert!(payloads.is_empty().unwrap());
    assert_eq!(candidate_store_bytes(&directory), candidate_bytes);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_global_request_capacity_is_terminal_without_peer_rotation() {
    let directory = TestDirectory::new("candidate-branch-fallback-global-capacity");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let candidate_bytes = candidate_store_bytes(&directory);
    let mut payloads = payload_store(&directory);
    let peers = peer_ids(2);
    let caller_order = [peers[1], peers[0]];
    let mut network = test_network_for_peers(&peers);
    let mut retained_terminals = Vec::new();

    for index in 0..MAX_PENDING_REQUESTS {
        network
            .request_artifact(
                peers[0],
                ArtifactRequest::new(naome_proof::ArtifactId::from_bytes([index as u8; 32])),
            )
            .unwrap();
        retained_terminals.push(artifact_response_event(&mut network, peers[0], Vec::new()));
    }
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        MAX_PENDING_REQUESTS
    );
    assert!(matches!(
        network.start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
            &selected,
            &mut candidates,
            &mut payloads,
            &caller_order,
            block.id(),
            reconstruction_limits(1),
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::RequestStart {
            peer_id,
            block_id,
            artifact_id,
            source,
        }) if *peer_id == caller_order[0]
            && block_id == block.id()
            && artifact_id == block.artifact_id()
            && matches!(
                source.as_ref(),
                RequestStartError::GlobalLimit { maximum } if *maximum == MAX_PENDING_REQUESTS
            )
    ));
    assert!(network.pending.is_empty());
    assert!(payloads.is_empty().unwrap());
    drop(retained_terminals);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(candidate_store_bytes(&directory), candidate_bytes);
    assert_snapshot(&directory, &selected, &before);
}

#[tokio::test(start_paused = true)]
async fn fallback_shares_one_exact_deadline_across_all_attempts_for_one_artifact() {
    assert_eq!(ARTIFACT_BLOCK_IMPORT_TIMEOUT, Duration::from_secs(120));
    let directory = TestDirectory::new("candidate-branch-fallback-shared-deadline");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let candidate_bytes = candidate_store_bytes(&directory);
    let mut payloads = payload_store(&directory);
    let peers = peer_ids(3);
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    tokio::time::advance(Duration::from_secs(40)).await;
    let event = artifact_failure_event(
        &mut network,
        peers[0],
        request_response::OutboundFailure::Timeout,
    );
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[1]);

    tokio::time::advance(Duration::from_secs(79)).await;
    let event = artifact_response_event(&mut network, peers[1], Vec::new());
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[2]);

    tokio::time::advance(Duration::from_secs(1)).await;
    let deadline = artifact_response_event(&mut network, peers[2], branch.payloads[0].clone());
    assert!(fill.accepts_event(&deadline));
    assert!(matches!(
        fill.on_event(&mut network, deadline),
        Err(ArtifactBlockCandidateBranchPayloadFillError::ArtifactDeadlineExceeded {
            peer_id,
            block_id,
            artifact_id,
        }) if *peer_id == peers[2]
            && block_id == block.id()
            && artifact_id == block.artifact_id()
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(payloads.is_empty().unwrap());
    assert_eq!(candidate_store_bytes(&directory), candidate_bytes);
    assert_snapshot(&directory, &selected, &before);
}

#[tokio::test(start_paused = true)]
async fn fallback_durable_acknowledgement_starts_a_fresh_next_artifact_deadline() {
    let directory = TestDirectory::new("candidate-branch-fallback-fresh-deadline");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let first = branch.blocks[0];
    let target = branch.blocks[1];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, &branch.blocks);
    let candidate_bytes = candidate_store_bytes(&directory);
    let mut payloads = payload_store(&directory);
    let peers = peer_ids(2);
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                target.id(),
                reconstruction_limits(2),
            )
            .unwrap(),
    );
    tokio::time::advance(Duration::from_secs(119)).await;
    let event = artifact_response_event(&mut network, peers[0], branch.payloads[0].clone());
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_block_id(), target.id());
    assert_eq!(fill.pending_peer_id(), peers[0]);

    tokio::time::advance(Duration::from_secs(1)).await;
    let event = artifact_response_event(&mut network, peers[0], branch.payloads[1].clone());
    let reconstructed = complete(fill.on_event(&mut network, event).unwrap());
    assert_eq!(reconstructed.target_block_id(), target.id());
    assert_eq!(reconstructed.snapshot().artifact_set_root(), branch.root);
    assert!(payloads.contains(first.artifact_id()).unwrap());
    assert!(payloads.contains(target.artifact_id()).unwrap());
    assert!(network.pending.is_empty());
    assert_eq!(candidate_store_bytes(&directory), candidate_bytes);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_peer_mismatch_unexpected_and_found_failures_do_not_rotate() {
    let directory = TestDirectory::new("candidate-branch-fallback-terminal-found");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let block = branch.blocks[0];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let candidate_bytes = candidate_store_bytes(&directory);
    let mut payloads = payload_store(&directory);
    let peers = peer_ids(2);
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    let event =
        artifact_response_event_from(&mut network, peers[0], peers[1], branch.payloads[0].clone());
    assert!(matches!(
        fill.on_event(&mut network, event),
        Err(ArtifactBlockCandidateBranchPayloadFillError::ArtifactRequestFailed {
            peer_id,
            block_id,
            artifact_id,
            source,
        }) if *peer_id == peers[0]
            && block_id == block.id()
            && artifact_id == block.artifact_id()
            && matches!(
                source.as_ref(),
                OutboundArtifactFailure::PeerMismatch { expected, actual }
                    if *expected == peers[0] && *actual == peers[1]
            )
    ));
    assert!(network.pending.is_empty());

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    assert!(matches!(
        fill.on_event(
            &mut network,
            NetworkEvent::Listening {
                address: address(0)
            }
        ),
        Err(ArtifactBlockCandidateBranchPayloadFillError::UnexpectedEvent)
    ));
    assert_eq!(network.pending.len(), 1);
    assert_eq!(
        pending_artifact_request(&network, peers[0]).1.artifact_id(),
        block.artifact_id()
    );
    assert!(matches!(
        artifact_response_event(&mut network, peers[0], branch.payloads[0].clone()),
        NetworkEvent::ArtifactCancellationDrained { .. }
    ));
    assert!(network.pending.is_empty());

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    let event = artifact_response_event(&mut network, peers[0], branch.payloads[0].clone());
    let mut other_network = test_network_for_peers(&peers);
    assert!(matches!(
        fill.on_event(&mut other_network, event),
        Err(ArtifactBlockCandidateBranchPayloadFillError::UnexpectedEvent)
    ));
    assert!(network.pending.is_empty());
    assert!(other_network.pending.is_empty());

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    let event = artifact_response_event(&mut network, peers[0], union_bytes());
    assert!(matches!(
        fill.on_event(&mut network, event),
        Err(ArtifactBlockCandidateBranchPayloadFillError::Reconstruction { source })
            if matches!(
                source.as_ref(),
                CandidateBranchReconstructionError::BlockValidation { block_id, .. }
                    if *block_id == block.id()
            )
    ));
    assert!(network.pending.is_empty());
    assert!(payloads.is_empty().unwrap());
    assert_eq!(candidate_store_bytes(&directory), candidate_bytes);
    assert_snapshot(&directory, &selected, &before);

    let capacity_directory = TestDirectory::new("candidate-branch-fallback-archive-failure");
    let capacity_selected = create_journal(capacity_directory.path()).unwrap();
    let capacity_before = snapshot(&capacity_directory, &capacity_selected);
    let mut capacity_candidates = candidate_store(&capacity_directory);
    insert_candidates(&mut capacity_candidates, std::slice::from_ref(&block));
    let capacity_candidate_bytes = candidate_store_bytes(&capacity_directory);
    let maximum = u64::try_from(branch.payloads[0].len()).unwrap() - 1;
    let mut capacity_payloads = CanonicalArtifactPayloadStore::create(
        capacity_directory.path(),
        payload_limits(1, maximum),
    )
    .unwrap();
    let mut capacity_network = test_network_for_peers(&peers);
    let fill = awaiting(
        capacity_network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &capacity_selected,
                &mut capacity_candidates,
                &mut capacity_payloads,
                &peers,
                block.id(),
                reconstruction_limits(1),
            )
            .unwrap(),
    );
    let event =
        artifact_response_event(&mut capacity_network, peers[0], branch.payloads[0].clone());
    assert!(matches!(
        fill.on_event(&mut capacity_network, event),
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
    assert!(capacity_network.pending.is_empty());
    assert!(capacity_payloads.is_empty().unwrap());
    assert_eq!(
        candidate_store_bytes(&capacity_directory),
        capacity_candidate_bytes
    );
    assert_snapshot(&capacity_directory, &capacity_selected, &capacity_before);
}

#[test]
fn fallback_resets_order_after_durable_payload_and_restart_skips_that_prefix() {
    let directory = TestDirectory::new("candidate-branch-fallback-reset-restart");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let branch = dependency_branch();
    let first = branch.blocks[0];
    let target = branch.blocks[1];
    let mut candidates = candidate_store(&directory);
    insert_candidates(&mut candidates, &branch.blocks);
    let candidate_bytes = candidate_store_bytes(&directory);
    let limits = payload_limits(8, 1_000_000);
    let mut payloads = CanonicalArtifactPayloadStore::create(directory.path(), limits).unwrap();
    let peers = peer_ids(2);
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                target.id(),
                reconstruction_limits(2),
            )
            .unwrap(),
    );
    let event = artifact_response_event(&mut network, peers[0], Vec::new());
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[1]);
    let event = artifact_response_event(&mut network, peers[1], branch.payloads[0].clone());
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_block_id(), target.id());
    assert_eq!(fill.pending_artifact_id(), target.artifact_id());
    assert_eq!(fill.pending_peer_id(), peers[0]);
    let event = artifact_failure_event(
        &mut network,
        peers[0],
        request_response::OutboundFailure::Timeout,
    );
    let fill = awaiting(fill.on_event(&mut network, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[1]);
    let event = artifact_response_event(&mut network, peers[1], Vec::new());
    assert!(matches!(
        fill.on_event(&mut network, event),
        Err(ArtifactBlockCandidateBranchPayloadFillError::ArtifactUnavailable {
            peer_id,
            block_id,
            artifact_id,
        }) if *peer_id == peers[1]
            && block_id == target.id()
            && artifact_id == target.artifact_id()
    ));
    assert!(payloads.contains(first.artifact_id()).unwrap());
    assert!(!payloads.contains(target.artifact_id()).unwrap());
    let durable_prefix = payload_store_bytes(&directory);
    assert!(network.pending.is_empty());
    drop(network);
    drop(payloads);

    let mut payloads = CanonicalArtifactPayloadStore::open(directory.path(), limits).unwrap();
    assert_eq!(payload_store_bytes(&directory), durable_prefix);
    assert!(payloads.contains(first.artifact_id()).unwrap());
    assert!(!payloads.contains(target.artifact_id()).unwrap());
    let mut restarted = test_network_for_peers(&peers);
    let fill = awaiting(
        restarted
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &mut payloads,
                &peers,
                target.id(),
                reconstruction_limits(2),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_block_id(), target.id());
    assert_eq!(fill.pending_peer_id(), peers[0]);
    let event = artifact_response_event(&mut restarted, peers[0], branch.payloads[1].clone());
    let reconstructed = complete(fill.on_event(&mut restarted, event).unwrap());
    assert_eq!(reconstructed.target_block_id(), target.id());
    assert_eq!(reconstructed.snapshot().artifact_set_root(), branch.root);
    assert!(payloads.contains(first.artifact_id()).unwrap());
    assert!(payloads.contains(target.artifact_id()).unwrap());
    assert!(restarted.pending.is_empty());
    assert_eq!(candidate_store_bytes(&directory), candidate_bytes);
    assert_snapshot(&directory, &selected, &before);
}

#[tokio::test]
async fn reopened_archives_recover_one_branch_from_two_authenticated_servers_without_selection() {
    let branch = dependency_branch();
    let first = branch.blocks[0];
    let target = branch.blocks[1];
    let server_limits = payload_limits(1, 1_000_000);

    let first_server_directory = TestDirectory::new("candidate-branch-fallback-first-server");
    let first_server_journal = create_journal(first_server_directory.path()).unwrap();
    let first_server_selected = snapshot(&first_server_directory, &first_server_journal);
    let mut first_server_payloads =
        CanonicalArtifactPayloadStore::create(first_server_directory.path(), server_limits)
            .unwrap();
    let mut first_source = ArtifactDag::new();
    let first_record = first_source
        .apply_canonical_artifact_bytes(branch.payloads[0].clone())
        .unwrap();
    assert_eq!(
        first_server_payloads.insert(first_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    let first_server_archive = payload_store_bytes(&first_server_directory);
    drop(first_server_payloads);
    let mut first_server_payloads =
        CanonicalArtifactPayloadStore::open(first_server_directory.path(), server_limits).unwrap();

    let second_server_directory = TestDirectory::new("candidate-branch-fallback-second-server");
    let second_server_journal = create_journal(second_server_directory.path()).unwrap();
    let second_server_selected = snapshot(&second_server_directory, &second_server_journal);
    let mut second_server_payloads =
        CanonicalArtifactPayloadStore::create(second_server_directory.path(), server_limits)
            .unwrap();
    let mut second_source = ArtifactDag::new();
    second_source
        .apply_canonical_artifact_bytes(branch.payloads[0].clone())
        .unwrap();
    let second_record = second_source
        .apply_canonical_artifact_bytes(branch.payloads[1].clone())
        .unwrap();
    assert_eq!(
        second_server_payloads.insert(second_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    let second_server_archive = payload_store_bytes(&second_server_directory);
    drop(second_server_payloads);
    let mut second_server_payloads =
        CanonicalArtifactPayloadStore::open(second_server_directory.path(), server_limits).unwrap();

    let client_directory = TestDirectory::new("candidate-branch-fallback-client");
    let client_journal = create_journal(client_directory.path()).unwrap();
    let client_selected = snapshot(&client_directory, &client_journal);
    let mut candidates = candidate_store(&client_directory);
    insert_candidates(&mut candidates, &branch.blocks);
    let client_candidate_bytes = candidate_store_bytes(&client_directory);
    let client_payload_limits = payload_limits(2, 1_000_000);
    let mut client_payloads =
        CanonicalArtifactPayloadStore::create(client_directory.path(), client_payload_limits)
            .unwrap();

    for artifact_id in [first.artifact_id(), target.artifact_id()] {
        assert!(
            first_server_journal
                .artifact(artifact_id)
                .unwrap()
                .is_none()
        );
        assert!(
            second_server_journal
                .artifact(artifact_id)
                .unwrap()
                .is_none()
        );
        assert!(client_journal.artifact(artifact_id).unwrap().is_none());
    }

    let (
        mut client,
        mut first_server,
        mut second_server,
        first_server_peer_id,
        second_server_peer_id,
    ) = connected_archive_triplet().await;
    let peer_order = [first_server_peer_id, second_server_peer_id];
    let progress = client
        .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
            &client_journal,
            &mut candidates,
            &mut client_payloads,
            &peer_order,
            target.id(),
            reconstruction_limits(2),
        )
        .unwrap();
    let (reconstructed, attempts) = complete_fallback_branch_fill(
        &mut client,
        &mut first_server,
        &mut second_server,
        &mut first_server_payloads,
        &mut second_server_payloads,
        progress,
    )
    .await;

    assert_eq!(
        attempts,
        vec![
            (first.artifact_id(), first_server_peer_id),
            (target.artifact_id(), first_server_peer_id),
            (target.artifact_id(), second_server_peer_id),
        ]
    );
    assert_eq!(reconstructed.target_block_id(), target.id());
    assert_eq!(reconstructed.block_count(), 2);
    assert_eq!(reconstructed.snapshot().artifact_set_root(), branch.root);
    assert!(client_payloads.contains(first.artifact_id()).unwrap());
    assert!(client_payloads.contains(target.artifact_id()).unwrap());
    assert_eq!(first_server_payloads.len().unwrap(), 1);
    assert_eq!(second_server_payloads.len().unwrap(), 1);
    assert_eq!(
        payload_store_bytes(&first_server_directory),
        first_server_archive
    );
    assert_eq!(
        payload_store_bytes(&second_server_directory),
        second_server_archive
    );
    assert_eq!(
        candidate_store_bytes(&client_directory),
        client_candidate_bytes
    );
    assert_snapshot(&client_directory, &client_journal, &client_selected);
    assert_snapshot(
        &first_server_directory,
        &first_server_journal,
        &first_server_selected,
    );
    assert_snapshot(
        &second_server_directory,
        &second_server_journal,
        &second_server_selected,
    );

    drop(client_payloads);
    let reopened_client =
        CanonicalArtifactPayloadStore::open(client_directory.path(), client_payload_limits)
            .unwrap();
    assert_eq!(reopened_client.len().unwrap(), 2);
}
