use std::fs::OpenOptions;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome_chain::{
    ArtifactBlock, ArtifactBlockId, ArtifactChainDefinition, ArtifactChainState, ArtifactDag,
    ArtifactSetRoot,
};
use naome_foundation::FreeVariable;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use naome_protocol::artifact_exchange::{ArtifactRequest, ArtifactResponse};
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactBlockCandidateStoreLimits,
    ArtifactPayloadStoreLimits, CandidateBranchReconstructionLimits, CanonicalArtifactPayloadStore,
};
use tokio::time::timeout;

use super::*;
use crate::tests::{
    FinalityFixture, TestDirectory, apply_fresh_blocks, assert_finality_snapshot, assert_snapshot,
    connected_pair, create_journal, finality_snapshot, pairing_bytes, snapshot,
    test_chain_definition, test_network_for_peers, union_bytes,
};
use crate::{
    Keypair, MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS, MAX_PENDING_REQUESTS, MAX_STATIC_PEERS,
    NetworkEvent, OutboundArtifactBlockFailure, RequestStartError,
};

fn artifact_id(index: usize) -> ArtifactId {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    bytes[31] = 0xa5;
    ArtifactId::from_bytes(bytes)
}

fn root(index: usize) -> ArtifactSetRoot {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    bytes[31] = 0x5a;
    ArtifactSetRoot::from_bytes(bytes)
}

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

fn peer_ids(count: usize) -> Vec<PeerId> {
    (0..count)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect()
}

fn extension(
    anchor: ArtifactBlockId,
    anchor_root: ArtifactSetRoot,
    count: usize,
) -> Vec<ArtifactBlock> {
    let mut parent = anchor;
    let mut previous_root = anchor_root;
    let mut blocks = Vec::with_capacity(count);
    for index in 0..count {
        let resulting_root = root(0x1_000 + index);
        let block = ArtifactBlock::new(
            parent,
            previous_root,
            resulting_root,
            artifact_id(0x2_000 + index),
        );
        parent = block.id();
        previous_root = resulting_root;
        blocks.push(block);
    }
    blocks
}

fn candidate_store(
    directory: &TestDirectory,
    definition: ArtifactChainDefinition,
    maximum: usize,
) -> ArtifactBlockCandidateStore {
    ArtifactBlockCandidateStore::create(
        directory.path(),
        definition,
        ArtifactBlockCandidateStoreLimits::new(maximum).unwrap(),
    )
    .unwrap()
}

fn retain(
    store: &mut ArtifactBlockCandidateStore,
    blocks: impl IntoIterator<Item = ArtifactBlock>,
) {
    for block in blocks {
        assert_eq!(
            store.insert(&block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
}

fn pending_block_request(
    network: &StaticArtifactNetwork,
    peer_id: PeerId,
) -> (
    request_response::OutboundRequestId,
    naome_protocol::block_exchange::ArtifactBlockRequest,
) {
    network
        .pending_block_for_peer_for_test(peer_id)
        .expect("the candidate ancestry fill has one pending block request")
}

fn pending_artifact_request(
    network: &StaticArtifactNetwork,
    peer_id: PeerId,
) -> (request_response::OutboundRequestId, ArtifactRequest) {
    network
        .pending_artifact_for_peer_for_test(peer_id)
        .expect("the composed branch recovery has one pending artifact request")
}

fn artifact_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    let (request_id, _) = pending_artifact_request(network, peer_id);
    network
        .handle_artifact_exchange_event_for_test(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_503),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the composed payload fill produces one terminal event")
}

fn block_wire_response_event(
    network: &mut StaticArtifactNetwork,
    pending_peer_id: PeerId,
    response_peer_id: PeerId,
    bytes: impl Into<Vec<u8>>,
) -> NetworkEvent {
    let (request_id, _) = pending_block_request(network, pending_peer_id);
    network
        .handle_block_exchange_event_for_test(request_response::Event::Message {
            peer: response_peer_id,
            connection_id: ConnectionId::new_unchecked(1_500),
            message: request_response::Message::Response {
                request_id,
                response: bytes.into(),
            },
        })
        .expect("the retained fill request produces one terminal event")
}

fn block_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    block: &ArtifactBlock,
) -> NetworkEvent {
    block_wire_response_event(network, peer_id, peer_id, block.to_canonical_bytes())
}

fn unavailable_event(network: &mut StaticArtifactNetwork, peer_id: PeerId) -> NetworkEvent {
    block_wire_response_event(network, peer_id, peer_id, Vec::new())
}

fn block_failure_event(network: &mut StaticArtifactNetwork, peer_id: PeerId) -> NetworkEvent {
    let (request_id, _) = pending_block_request(network, peer_id);
    network
        .handle_block_exchange_event_for_test(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_502),
            request_id,
            error: request_response::OutboundFailure::Timeout,
        })
        .expect("the retained fill request produces one failure terminal")
}

fn invalid_block_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
) -> NetworkEvent {
    block_wire_response_event(network, peer_id, peer_id, vec![0xff])
}

fn peer_mismatch_event(
    network: &mut StaticArtifactNetwork,
    expected_peer_id: PeerId,
    actual_peer_id: PeerId,
    block: &ArtifactBlock,
) -> NetworkEvent {
    block_wire_response_event(
        network,
        expected_peer_id,
        actual_peer_id,
        block.to_canonical_bytes(),
    )
}

fn awaiting(
    progress: ArtifactBlockCandidateAncestryFillProgress<'_>,
) -> ArtifactBlockCandidateAncestryFill<'_> {
    progress.expect("candidate ancestry fill completed before its missing block arrived")
}

fn assert_complete(progress: ArtifactBlockCandidateAncestryFillProgress<'_>) {
    assert!(progress.is_none());
}

#[test]
fn finality_history_supports_current_and_historical_candidate_fills_read_only() {
    let directory = TestDirectory::new("candidate-fill-finality-current-historical");
    let mut fixture = FinalityFixture::new();
    let mut selected = fixture.create(&directory);
    let historical = fixture.commit_payload(&mut selected, pairing_bytes());
    let historical_root = selected.artifact_set_root().unwrap();
    let _ = fixture.commit_payload(&mut selected, union_bytes());
    let current = selected.artifact_head_block_id().unwrap();
    let current_root = selected.artifact_set_root().unwrap();
    let before = finality_snapshot(&directory, &selected);

    let peers = peer_ids(3);
    let mut network = test_network_for_peers(&peers);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 2);

    let current_target = extension(current, current_root, 1).remove(0);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peers[0],
                current_target.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peers[0], &current_target);
    assert_complete(fill.on_event(&mut network, &selected, event).unwrap());

    let historical_target = extension(historical, historical_root, 1).remove(0);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers[1..],
                historical,
                historical_target.id(),
            )
            .unwrap(),
    );
    let unavailable = unavailable_event(&mut network, peers[1]);
    let fill = awaiting(fill.on_event(&mut network, &selected, unavailable).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[2]);
    let event = block_response_event(&mut network, peers[2], &historical_target);
    assert_complete(fill.on_event(&mut network, &selected, event).unwrap());

    assert_eq!(
        candidates.get(current_target.id()).unwrap(),
        Some(current_target)
    );
    assert_eq!(
        candidates.get(historical_target.id()).unwrap(),
        Some(historical_target)
    );
    assert_finality_snapshot(&directory, &selected, &before);
}

#[test]
fn finality_head_drift_and_halt_fail_before_candidate_insertion_or_request() {
    let drift_directory = TestDirectory::new("candidate-fill-finality-drift");
    let mut drift_fixture = FinalityFixture::new();
    let mut drifted = drift_fixture.create(&drift_directory);
    let target = extension(
        drifted.artifact_head_block_id().unwrap(),
        drifted.artifact_set_root().unwrap(),
        1,
    )
    .remove(0);
    let peer_id = peer_ids(1)[0];
    let mut network = test_network_for_peers(&[peer_id]);
    let mut candidates = candidate_store(&drift_directory, test_chain_definition(), 1);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &drifted,
                &mut candidates,
                peer_id,
                target.id(),
            )
            .unwrap(),
    );
    let _ = drift_fixture.commit_payload(&mut drifted, pairing_bytes());
    let after_drift = finality_snapshot(&drift_directory, &drifted);
    let actual = drifted.artifact_head_block_id().unwrap();
    let event = block_response_event(&mut network, peer_id, &target);
    assert!(matches!(
        fill.on_event(&mut network, &drifted, event),
        Err(ArtifactBlockCandidateAncestryFillError::SelectedHeadChanged {
            actual: observed,
            ..
        }) if observed == actual
    ));
    assert!(candidates.get(target.id()).unwrap().is_none());
    assert_finality_snapshot(&drift_directory, &drifted, &after_drift);

    let halted_directory = TestDirectory::new("candidate-fill-finality-halt");
    let mut halted_fixture = FinalityFixture::new();
    let mut halted = halted_fixture.create(&halted_directory);
    halted_fixture.halt_with_conflict(&mut halted, pairing_bytes(), union_bytes());
    let halted_bytes = halted_directory.journal_bytes();
    let halted_state_id = halted.state_id().unwrap();
    let halted_summary = halted.halt().unwrap();
    let halted_target = extension(
        test_chain_definition().id().virtual_genesis_block_id(),
        ArtifactChainState::new(test_chain_definition())
            .artifact_dag()
            .artifact_set_root(),
        1,
    )
    .remove(0);
    let mut halted_candidates = candidate_store(&halted_directory, test_chain_definition(), 1);
    let unknown_peer = peer_ids(1)[0];
    let mut halted_network = test_network_for_peers(&[]);
    let foreign_directory = TestDirectory::new("candidate-fill-finality-halt-foreign");
    let foreign_definition = ArtifactChainDefinition::new([0x98; 32]);
    let foreign_chain_id = foreign_definition.id();
    let mut foreign_candidates = candidate_store(&foreign_directory, foreign_definition, 1);
    assert!(matches!(
        halted_network.start_artifact_block_candidate_ancestry_fill(
            &halted,
            &mut foreign_candidates,
            unknown_peer,
            halted_target.id(),
        ),
        Err(ArtifactBlockCandidateAncestryFillError::ChainIdMismatch {
            selected,
            candidates,
        }) if selected == test_chain_definition().id() && candidates == foreign_chain_id
    ));
    assert!(matches!(
        halted_network.start_artifact_block_candidate_ancestry_fill(
            &halted,
            &mut halted_candidates,
            unknown_peer,
            halted_target.id(),
        ),
        Err(ArtifactBlockCandidateAncestryFillError::SelectedHistoryState { .. })
    ));
    assert_eq!(halted_network.pending_count_for_test(), 0);
    assert!(halted_candidates.get(halted_target.id()).unwrap().is_none());
    assert_eq!(halted_directory.journal_bytes(), halted_bytes);
    assert_eq!(halted.state_id().unwrap(), halted_state_id);
    assert_eq!(halted.halt().unwrap(), halted_summary);
}

#[test]
fn finality_history_preserves_the_fixed_candidate_ancestry_limit() {
    let directory = TestDirectory::new("candidate-fill-finality-limit");
    let fixture = FinalityFixture::new();
    let selected = fixture.create(&directory);
    let before = finality_snapshot(&directory, &selected);
    let blocks = extension(
        selected.artifact_head_block_id().unwrap(),
        selected.artifact_set_root().unwrap(),
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS + 1,
    );
    let target = blocks.last().unwrap().id();
    let mut candidates = candidate_store(
        &directory,
        test_chain_definition(),
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS + 1,
    );
    retain(&mut candidates, blocks);
    let mut network = test_network_for_peers(&[]);
    let unknown_peer = peer_ids(1)[0];
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill(
            &selected,
            &mut candidates,
            unknown_peer,
            target,
        ),
        Err(
            ArtifactBlockCandidateAncestryFillError::AncestryLimitExceeded {
                maximum: MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS,
                ..
            }
        )
    ));
    assert_eq!(network.pending_count_for_test(), 0);
    assert_finality_snapshot(&directory, &selected, &before);
}

#[test]
fn mixed_retained_path_requests_only_the_hole_and_completes_without_selection() {
    let directory = TestDirectory::new("candidate-fill-mixed");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let blocks = extension(before.head, before.root, 3);
    let [anchor_child, missing_middle, target] = blocks.as_slice() else {
        unreachable!("the fixture contains exactly three blocks")
    };
    let limits = ArtifactBlockCandidateStoreLimits::new(3).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(directory.path(), test_chain_definition(), limits)
            .unwrap();
    retain(&mut candidates, [*target, *anchor_child]);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let progress = network
        .start_artifact_block_candidate_ancestry_fill(
            &selected,
            &mut candidates,
            peer_id,
            target.id(),
        )
        .unwrap();
    let fill = awaiting(progress);
    assert_eq!(fill.anchor_block_id(), before.head);
    assert_eq!(fill.target_block_id(), target.id());
    assert_eq!(fill.pending_block_id(), missing_middle.id());
    assert_eq!(fill.pending_peer_id(), peer_id);
    assert_eq!(
        pending_block_request(&network, peer_id).1.block_id(),
        missing_middle.id()
    );
    assert_eq!(network.pending_count_for_test(), 1);

    let event = block_response_event(&mut network, peer_id, missing_middle);
    assert!(fill.accepts_event(&event));
    assert_complete(fill.on_event(&mut network, &selected, event).unwrap());

    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
    assert_snapshot(&directory, &selected, &before);
    for block in &blocks {
        assert_eq!(candidates.get(block.id()).unwrap(), Some(*block));
    }

    drop(candidates);
    let mut reopened =
        ArtifactBlockCandidateStore::open(directory.path(), test_chain_definition(), limits)
            .unwrap();
    for block in blocks {
        assert_eq!(reopened.get(block.id()).unwrap(), Some(block));
    }
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn restart_skips_the_durable_target_and_resumes_at_its_missing_parent() {
    let directory = TestDirectory::new("candidate-fill-restart");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let blocks = extension(before.head, before.root, 3);
    let [anchor_child, middle, target] = blocks.as_slice() else {
        unreachable!("the fixture contains exactly three blocks")
    };
    let limits = ArtifactBlockCandidateStoreLimits::new(3).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(directory.path(), test_chain_definition(), limits)
            .unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut first_network = test_network_for_peers(&[peer_id]);

    let fill = awaiting(
        first_network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                target.id(),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_block_id(), target.id());
    let event = block_response_event(&mut first_network, peer_id, target);
    let fill = awaiting(fill.on_event(&mut first_network, &selected, event).unwrap());
    assert_eq!(fill.pending_block_id(), middle.id());
    assert_eq!(
        pending_block_request(&first_network, peer_id).1.block_id(),
        middle.id()
    );
    fill.cancel();

    assert_eq!(candidates.get(target.id()).unwrap(), Some(*target));
    assert_eq!(candidates.get(middle.id()).unwrap(), None);
    drop(first_network);
    drop(candidates);

    let mut candidates =
        ArtifactBlockCandidateStore::open(directory.path(), test_chain_definition(), limits)
            .unwrap();
    let mut restarted_network = test_network_for_peers(&[peer_id]);
    let fill = awaiting(
        restarted_network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                target.id(),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_block_id(), middle.id());
    assert_eq!(
        pending_block_request(&restarted_network, peer_id)
            .1
            .block_id(),
        middle.id()
    );

    let event = block_response_event(&mut restarted_network, peer_id, middle);
    let fill = awaiting(
        fill.on_event(&mut restarted_network, &selected, event)
            .unwrap(),
    );
    assert_eq!(fill.pending_block_id(), anchor_child.id());
    let event = block_response_event(&mut restarted_network, peer_id, anchor_child);
    assert_complete(
        fill.on_event(&mut restarted_network, &selected, event)
            .unwrap(),
    );

    assert_eq!(candidates.len().unwrap(), 3);
    assert!((restarted_network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn inserted_target_survives_the_next_parent_request_start_failure() {
    let directory = TestDirectory::new("candidate-fill-next-start-failure");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let blocks = extension(before.head, before.root, 2);
    let [parent, target] = blocks.as_slice() else {
        unreachable!("the fixture contains exactly two blocks")
    };
    let limits = ArtifactBlockCandidateStoreLimits::new(2).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(directory.path(), test_chain_definition(), limits)
            .unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                target.id(),
            )
            .unwrap(),
    );
    network.mark_disconnected_for_test(peer_id);
    let event = block_response_event(&mut network, peer_id, target);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::RequestStart {
            block_id,
            source: RequestStartError::PeerDisconnected(actual_peer),
        }) if block_id == parent.id() && actual_peer == peer_id
    ));

    assert_eq!(candidates.get(target.id()).unwrap(), Some(*target));
    assert_eq!(candidates.get(parent.id()).unwrap(), None);
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
    assert_snapshot(&directory, &selected, &before);

    drop(candidates);
    let mut reopened =
        ArtifactBlockCandidateStore::open(directory.path(), test_chain_definition(), limits)
            .unwrap();
    assert_eq!(reopened.get(target.id()).unwrap(), Some(*target));
    assert_eq!(reopened.get(parent.id()).unwrap(), None);
}

#[test]
fn lazy_peer_validation_follows_retained_shape_then_first_missing_address() {
    let directory = TestDirectory::new("candidate-fill-lazy-peer");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let valid = extension(before.head, before.root, 1).remove(0);
    let wrong_root = root(0xf001);
    assert_ne!(wrong_root, before.root);
    let invalid = ArtifactBlock::new(before.head, wrong_root, root(0xf002), artifact_id(0xf003));
    let mut candidates = candidate_store(&directory, test_chain_definition(), 2);
    retain(&mut candidates, [valid, invalid]);
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    assert_complete(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                unknown_peer,
                valid.id(),
            )
            .unwrap(),
    );

    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill(
            &selected,
            &mut candidates,
            unknown_peer,
            invalid.id(),
        ),
        Err(ArtifactBlockCandidateAncestryFillError::ArtifactSetRootMismatch {
            preceding_block_id,
            expected,
            actual,
        }) if preceding_block_id == before.head && expected == before.root && actual == wrong_root
    ));

    let missing = ArtifactBlockId::from_bytes([0xfe; 32]);
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill(
            &selected,
            &mut candidates,
            unknown_peer,
            missing,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::RequestStart {
            block_id,
            source: RequestStartError::UnknownPeer(peer_id),
        }) if block_id == missing && peer_id == unknown_peer
    ));
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn sixteen_retained_blocks_complete_but_seventeen_fail_before_network_work() {
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();

    let maximum_directory = TestDirectory::new("candidate-fill-sixteen");
    let maximum_selected = create_journal(maximum_directory.path()).unwrap();
    let maximum_before = snapshot(&maximum_directory, &maximum_selected);
    let maximum_blocks = extension(
        maximum_before.head,
        maximum_before.root,
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS,
    );
    let maximum_target = maximum_blocks.last().unwrap().id();
    let mut maximum_candidates = candidate_store(
        &maximum_directory,
        test_chain_definition(),
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS,
    );
    retain(&mut maximum_candidates, maximum_blocks);
    let mut maximum_network = test_network_for_peers(&[]);
    assert_complete(
        maximum_network
            .start_artifact_block_candidate_ancestry_fill(
                &maximum_selected,
                &mut maximum_candidates,
                peer_id,
                maximum_target,
            )
            .unwrap(),
    );
    assert!((maximum_network.pending_count_for_test() == 0));
    assert_snapshot(&maximum_directory, &maximum_selected, &maximum_before);

    let excess_directory = TestDirectory::new("candidate-fill-seventeen");
    let excess_selected = create_journal(excess_directory.path()).unwrap();
    let excess_before = snapshot(&excess_directory, &excess_selected);
    let excess_blocks = extension(
        excess_before.head,
        excess_before.root,
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS + 1,
    );
    let excess_target = excess_blocks.last().unwrap().id();
    let expected_next = excess_blocks[0].id();
    let mut excess_candidates = candidate_store(
        &excess_directory,
        test_chain_definition(),
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS + 1,
    );
    retain(&mut excess_candidates, excess_blocks);
    let mut excess_network = test_network_for_peers(&[]);
    assert!(matches!(
        excess_network.start_artifact_block_candidate_ancestry_fill(
            &excess_selected,
            &mut excess_candidates,
            peer_id,
            excess_target,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::AncestryLimitExceeded {
            maximum,
            next_block_id,
        }) if maximum == MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS && next_block_id == expected_next
    ));
    assert!((excess_network.pending_count_for_test() == 0));
    assert_snapshot(&excess_directory, &excess_selected, &excess_before);
}

#[test]
fn chain_and_selected_target_precede_poisoned_candidate_reads() {
    let selected_directory = TestDirectory::new("candidate-fill-precedence-selected");
    let selected = create_journal(selected_directory.path()).unwrap();
    let selected_head = selected.head_block_id().unwrap();
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    let foreign_directory = TestDirectory::new("candidate-fill-precedence-foreign");
    let foreign_definition = ArtifactChainDefinition::new([0x42; 32]);
    let foreign_chain_id = foreign_definition.id();
    let mut foreign = candidate_store(&foreign_directory, foreign_definition, 1);
    let poison = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0x31; 32]),
        root(0x31),
        root(0x32),
        artifact_id(0x33),
    );
    retain(&mut foreign, [poison]);
    OpenOptions::new()
        .write(true)
        .open(
            foreign_directory
                .path()
                .join("artifact-block-candidate-store.log"),
        )
        .unwrap()
        .set_len(0)
        .unwrap();
    assert!(matches!(
        foreign.get(poison.id()),
        Err(ArtifactBlockCandidateStoreError::Read { .. })
    ));

    let missing = ArtifactBlockId::from_bytes([0x34; 32]);
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill(
            &selected,
            &mut foreign,
            unknown_peer,
            missing,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::ChainIdMismatch {
            selected,
            candidates,
        }) if selected == test_chain_definition().id() && candidates == foreign_chain_id
    ));

    let candidates_directory = TestDirectory::new("candidate-fill-precedence-poisoned");
    let mut candidates = candidate_store(&candidates_directory, test_chain_definition(), 1);
    retain(&mut candidates, [poison]);
    OpenOptions::new()
        .write(true)
        .open(
            candidates_directory
                .path()
                .join("artifact-block-candidate-store.log"),
        )
        .unwrap()
        .set_len(0)
        .unwrap();
    assert!(matches!(
        candidates.get(poison.id()),
        Err(ArtifactBlockCandidateStoreError::Read { .. })
    ));

    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill(
            &selected,
            &mut candidates,
            unknown_peer,
            selected_head,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::TargetAlreadySelected { block_id })
            if block_id == selected_head
    ));
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill(
            &selected,
            &mut candidates,
            unknown_peer,
            missing,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::CandidateStoreRead {
            block_id,
            source,
        }) if block_id == missing
            && matches!(source.as_ref(), ArtifactBlockCandidateStoreError::Poisoned)
    ));
    assert!((network.pending_count_for_test() == 0));
}

#[test]
fn transport_outcomes_precede_head_drift_while_shape_precedes_insertion() {
    let directory = TestDirectory::new("candidate-fill-event-precedence");
    let mut selected = create_journal(directory.path()).unwrap();
    let initial = snapshot(&directory, &selected);
    let target = extension(initial.head, initial.root, 1).remove(0);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 3);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                target.id(),
            )
            .unwrap(),
    );
    let unavailable = unavailable_event(&mut network, peer_id);
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    assert!(matches!(
        fill.on_event(&mut network, &selected, unavailable),
        Err(ArtifactBlockCandidateAncestryFillError::BlockUnavailable {
            peer_id: actual_peer,
            block_id,
        }) if actual_peer == peer_id && block_id == target.id()
    ));
    assert_eq!(candidates.get(target.id()).unwrap(), None);

    let advanced = snapshot(&directory, &selected);
    let drift_target = extension(advanced.head, advanced.root, 1).remove(0);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                drift_target.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peer_id, &drift_target);
    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let changed = selected.head_block_id().unwrap();
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::SelectedHeadChanged {
            expected,
            actual,
        }) if expected == advanced.head && actual == changed
    ));
    assert_eq!(candidates.get(drift_target.id()).unwrap(), None);

    let current_head = selected.head_block_id().unwrap();
    let current_root = selected.artifact_set_root().unwrap();
    let wrong_previous = root(0xf100);
    assert_ne!(wrong_previous, current_root);
    let malformed = ArtifactBlock::new(
        current_head,
        wrong_previous,
        root(0xf101),
        artifact_id(0xf102),
    );
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                malformed.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peer_id, &malformed);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::ArtifactSetRootMismatch {
            preceding_block_id,
            expected,
            actual,
        }) if preceding_block_id == current_head
            && expected == current_root
            && actual == wrong_previous
    ));
    assert_eq!(candidates.get(malformed.id()).unwrap(), None);
    assert!((network.pending_count_for_test() == 0));
}

#[test]
fn insertion_failure_is_typed_and_starts_no_parent_request() {
    let directory = TestDirectory::new("candidate-fill-insert-failure");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let target = extension(before.head, before.root, 1).remove(0);
    let unrelated = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0xc1; 32]),
        root(0xc1),
        root(0xc2),
        artifact_id(0xc3),
    );
    let mut candidates = candidate_store(&directory, test_chain_definition(), 1);
    retain(&mut candidates, [unrelated]);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                target.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peer_id, &target);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::CandidateStoreInsert {
            block_id,
            source,
        }) if block_id == target.id()
            && matches!(
                source.as_ref(),
                ArtifactBlockCandidateStoreError::EntryLimitExceeded { .. }
            )
    ));
    assert_eq!(candidates.get(target.id()).unwrap(), None);
    assert_eq!(candidates.get(unrelated.id()).unwrap(), Some(unrelated));
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn terminal_and_routing_failures_preserve_the_candidate_store() {
    let directory = TestDirectory::new("candidate-fill-terminal-errors");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let target = extension(before.head, before.root, 1).remove(0);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 1);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                target.id(),
            )
            .unwrap(),
    );
    let event = block_failure_event(&mut network, peer_id);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::BlockRequestFailed {
            peer_id: actual_peer,
            block_id,
            source,
        }) if actual_peer == peer_id
            && block_id == target.id()
            && matches!(
                source.as_ref(),
                OutboundArtifactBlockFailure::Transport(
                    request_response::OutboundFailure::Timeout
                )
            )
    ));
    assert_eq!(candidates.get(target.id()).unwrap(), None);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill(
                &selected,
                &mut candidates,
                peer_id,
                target.id(),
            )
            .unwrap(),
    );
    let unrelated = NetworkEvent::Listening {
        address: "/memory/1503".parse().unwrap(),
    };
    assert!(!fill.accepts_event(&unrelated));
    assert!(matches!(
        fill.on_event(&mut network, &selected, unrelated),
        Err(ArtifactBlockCandidateAncestryFillError::UnexpectedEvent)
    ));
    assert_eq!(candidates.get(target.id()).unwrap(), None);
    assert_eq!(network.pending_count_for_test(), 1);
    drop(unavailable_event(&mut network, peer_id));
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_peer_validation_is_lazy_and_reports_lowest_raw_identity() {
    let directory = TestDirectory::new("candidate-fill-fallback-validation");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let valid = extension(before.head, before.root, 1).remove(0);
    let wrong_root = root(0xfa01);
    assert_ne!(wrong_root, before.root);
    let invalid = ArtifactBlock::new(before.head, wrong_root, root(0xfa02), artifact_id(0xfa03));
    let mut candidates = candidate_store(&directory, test_chain_definition(), 2);
    retain(&mut candidates, [valid, invalid]);

    let mut configured = peer_ids(2);
    configured.sort_unstable();
    let mut network = test_network_for_peers(&configured);

    assert_complete(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &[],
                valid.id(),
            )
            .unwrap(),
    );
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
            &selected,
            &mut candidates,
            &[],
            invalid.id(),
        ),
        Err(ArtifactBlockCandidateAncestryFillError::ArtifactSetRootMismatch {
            preceding_block_id,
            expected,
            actual,
        }) if preceding_block_id == before.head && expected == before.root && actual == wrong_root
    ));

    let missing = ArtifactBlockId::from_bytes([0xfa; 32]);
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
            &selected,
            &mut candidates,
            &[],
            missing,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::EmptyBlockPeerSet)
    ));

    let too_many = peer_ids(MAX_STATIC_PEERS + 1);
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
            &selected,
            &mut candidates,
            &too_many,
            missing,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::TooManyBlockPeers {
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
        network.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
            &selected,
            &mut candidates,
            &duplicate_order,
            missing,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::DuplicateBlockPeer { peer_id })
            if peer_id == *lowest
    ));

    let mut unknown = peer_ids(2);
    unknown.sort_unstable();
    let unknown_order = [unknown[1], *highest, unknown[0]];
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
            &selected,
            &mut candidates,
            &unknown_order,
            missing,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::UnknownBlockPeer { peer_id })
            if peer_id == unknown[0]
    ));
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_uses_caller_order_across_retryable_terminals_then_retains() {
    let directory = TestDirectory::new("candidate-fill-fallback-order");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let target = extension(before.head, before.root, 1).remove(0);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 1);
    let mut raw_order = peer_ids(4);
    raw_order.sort_unstable();
    let caller_order = [raw_order[2], raw_order[0], raw_order[3], raw_order[1]];
    assert_ne!(caller_order.as_slice(), raw_order.as_slice());
    let mut network = test_network_for_peers(&raw_order);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &caller_order,
                target.id(),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_peer_id(), caller_order[0]);

    let event = unavailable_event(&mut network, caller_order[0]);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_peer_id(), caller_order[1]);

    let event = block_failure_event(&mut network, caller_order[1]);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_peer_id(), caller_order[2]);

    let event = invalid_block_response_event(&mut network, caller_order[2]);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_peer_id(), caller_order[3]);

    let event = block_response_event(&mut network, caller_order[3], &target);
    assert_complete(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(candidates.get(target.id()).unwrap(), Some(target));
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_skips_busy_and_disconnected_peers_but_accepts_the_eighth() {
    let directory = TestDirectory::new("candidate-fill-fallback-skips");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let target = extension(before.head, before.root, 1).remove(0);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 1);
    let peers = peer_ids(MAX_STATIC_PEERS);
    let mut network = test_network_for_peers(&peers);

    let busy_ticket = network
        .request_block(
            peers[0],
            ArtifactBlockRequest::new(ArtifactBlockId::from_bytes([0xfb; 32])),
        )
        .unwrap();
    for peer_id in &peers[1..MAX_STATIC_PEERS - 1] {
        network.mark_disconnected_for_test(*peer_id);
    }

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                target.id(),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_peer_id(), peers[MAX_STATIC_PEERS - 1]);
    assert_eq!(network.pending_count_for_test(), 2);
    fill.cancel();

    drop(unavailable_event(&mut network, peers[MAX_STATIC_PEERS - 1]));
    drop(unavailable_event(&mut network, peers[0]));
    drop(busy_ticket);
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(network.active_permit_count_for_test(), 0);
    assert_eq!(candidates.get(target.id()).unwrap(), None);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_reports_no_requestable_peer_and_global_capacity() {
    let no_peer_directory = TestDirectory::new("candidate-fill-fallback-no-requestable");
    let no_peer_selected = create_journal(no_peer_directory.path()).unwrap();
    let no_peer_before = snapshot(&no_peer_directory, &no_peer_selected);
    let no_peer_target = extension(no_peer_before.head, no_peer_before.root, 1).remove(0);
    let mut no_peer_candidates = candidate_store(&no_peer_directory, test_chain_definition(), 1);
    let no_peer_ids = peer_ids(2);
    let mut no_peer_network = test_network_for_peers(&no_peer_ids);
    let busy_ticket = no_peer_network
        .request_block(
            no_peer_ids[0],
            ArtifactBlockRequest::new(ArtifactBlockId::from_bytes([0xfc; 32])),
        )
        .unwrap();
    no_peer_network.mark_disconnected_for_test(no_peer_ids[1]);
    assert!(matches!(
        no_peer_network.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
            &no_peer_selected,
            &mut no_peer_candidates,
            &no_peer_ids,
            no_peer_target.id(),
        ),
        Err(ArtifactBlockCandidateAncestryFillError::NoRequestableBlockPeer { block_id })
            if block_id == no_peer_target.id()
    ));
    drop(unavailable_event(&mut no_peer_network, no_peer_ids[0]));
    drop(busy_ticket);
    assert_eq!(no_peer_candidates.get(no_peer_target.id()).unwrap(), None);

    let limit_directory = TestDirectory::new("candidate-fill-fallback-global-limit");
    let limit_selected = create_journal(limit_directory.path()).unwrap();
    let limit_before = snapshot(&limit_directory, &limit_selected);
    let limit_target = extension(limit_before.head, limit_before.root, 1).remove(0);
    let mut limit_candidates = candidate_store(&limit_directory, test_chain_definition(), 1);
    let limit_peers = peer_ids(2);
    let mut limit_network = test_network_for_peers(&limit_peers);
    let mut retained_terminals = Vec::new();
    for index in 0..MAX_PENDING_REQUESTS {
        let ticket = limit_network
            .request_block(
                limit_peers[0],
                ArtifactBlockRequest::new(ArtifactBlockId::from_bytes([index as u8; 32])),
            )
            .unwrap();
        retained_terminals.push(unavailable_event(&mut limit_network, limit_peers[0]));
        drop(ticket);
    }
    assert_eq!(
        limit_network.active_permit_count_for_test(),
        MAX_PENDING_REQUESTS
    );
    assert!(matches!(
        limit_network.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
            &limit_selected,
            &mut limit_candidates,
            &[limit_peers[1]],
            limit_target.id(),
        ),
        Err(ArtifactBlockCandidateAncestryFillError::RequestStart {
            block_id,
            source: RequestStartError::GlobalLimit { maximum },
        }) if block_id == limit_target.id() && maximum == MAX_PENDING_REQUESTS
    ));
    assert_eq!(limit_candidates.get(limit_target.id()).unwrap(), None);
    drop(retained_terminals);
    assert_eq!(limit_network.active_permit_count_for_test(), 0);
}

#[test]
fn fallback_exhaustion_returns_the_last_retryable_terminal() {
    let directory = TestDirectory::new("candidate-fill-fallback-exhaustion");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let target = extension(before.head, before.root, 1).remove(0);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 1);
    let peers = peer_ids(2);
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                target.id(),
            )
            .unwrap(),
    );
    let event = unavailable_event(&mut network, peers[0]);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[1]);
    let event = block_failure_event(&mut network, peers[1]);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::BlockRequestFailed {
            peer_id,
            block_id,
            source,
        }) if peer_id == peers[1]
            && block_id == target.id()
            && matches!(
                source.as_ref(),
                OutboundArtifactBlockFailure::Transport(
                    request_response::OutboundFailure::Timeout
                )
            )
    ));
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(candidates.get(target.id()).unwrap(), None);

    network.mark_disconnected_for_test(peers[1]);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                target.id(),
            )
            .unwrap(),
    );
    let event = unavailable_event(&mut network, peers[0]);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::BlockUnavailable {
            peer_id,
            block_id,
        }) if peer_id == peers[0] && block_id == target.id()
    ));
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(candidates.get(target.id()).unwrap(), None);

    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn fallback_peer_mismatch_shape_and_store_failures_do_not_rotate() {
    let directory = TestDirectory::new("candidate-fill-fallback-terminal-found");
    let mut selected = create_journal(directory.path()).unwrap();
    let initial = snapshot(&directory, &selected);
    let target = extension(initial.head, initial.root, 1).remove(0);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 1);
    let peers = peer_ids(2);
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                target.id(),
            )
            .unwrap(),
    );
    let event = peer_mismatch_event(&mut network, peers[0], peers[1], &target);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::BlockRequestFailed {
            peer_id,
            block_id,
            source,
        }) if peer_id == peers[0]
            && block_id == target.id()
            && matches!(
                source.as_ref(),
                OutboundArtifactBlockFailure::PeerMismatch { expected, actual }
                    if *expected == peers[0] && *actual == peers[1]
            )
    ));
    assert!((network.pending_count_for_test() == 0));

    let drift_target = extension(initial.head, initial.root, 1).remove(0);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                drift_target.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peers[0], &drift_target);
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let actual_head = selected.head_block_id().unwrap();
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::SelectedHeadChanged {
            expected,
            actual,
        }) if expected == initial.head && actual == actual_head
    ));
    assert!((network.pending_count_for_test() == 0));

    let current_head = selected.head_block_id().unwrap();
    let current_root = selected.artifact_set_root().unwrap();
    let malformed_root = root(0xfd01);
    assert_ne!(malformed_root, current_root);
    let malformed = ArtifactBlock::new(
        current_head,
        malformed_root,
        root(0xfd02),
        artifact_id(0xfd03),
    );
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                malformed.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peers[0], &malformed);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::ArtifactSetRootMismatch {
            preceding_block_id,
            expected,
            actual,
        }) if preceding_block_id == current_head
            && expected == current_root
            && actual == malformed_root
    ));
    assert!((network.pending_count_for_test() == 0));

    let unrelated = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0xfe; 32]),
        root(0xfe01),
        root(0xfe02),
        artifact_id(0xfe03),
    );
    retain(&mut candidates, [unrelated]);
    let valid = extension(current_head, current_root, 1).remove(0);
    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                valid.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peers[0], &valid);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::CandidateStoreInsert {
            block_id,
            source,
        }) if block_id == valid.id()
            && matches!(
                source.as_ref(),
                ArtifactBlockCandidateStoreError::EntryLimitExceeded { .. }
            )
    ));
    assert!((network.pending_count_for_test() == 0));
    assert_eq!(candidates.get(valid.id()).unwrap(), None);
    assert_eq!(candidates.get(unrelated.id()).unwrap(), Some(unrelated));
}

#[test]
fn fallback_resets_after_durable_insert_and_restart_skips_that_prefix() {
    let directory = TestDirectory::new("candidate-fill-fallback-reset-restart");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let blocks = extension(before.head, before.root, 2);
    let [parent, target] = blocks.as_slice() else {
        unreachable!("the fixture contains exactly two blocks")
    };
    let limits = ArtifactBlockCandidateStoreLimits::new(2).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(directory.path(), test_chain_definition(), limits)
            .unwrap();
    let peers = peer_ids(2);
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                target.id(),
            )
            .unwrap(),
    );
    let event = unavailable_event(&mut network, peers[0]);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[1]);
    let event = block_response_event(&mut network, peers[1], target);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_block_id(), parent.id());
    assert_eq!(fill.pending_peer_id(), peers[0]);

    let event = unavailable_event(&mut network, peers[0]);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[1]);
    let event = unavailable_event(&mut network, peers[1]);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::BlockUnavailable {
            peer_id,
            block_id,
        }) if peer_id == peers[1] && block_id == parent.id()
    ));
    assert_eq!(candidates.get(target.id()).unwrap(), Some(*target));
    assert_eq!(candidates.get(parent.id()).unwrap(), None);
    assert_snapshot(&directory, &selected, &before);

    drop(network);
    drop(candidates);
    let mut candidates =
        ArtifactBlockCandidateStore::open(directory.path(), test_chain_definition(), limits)
            .unwrap();
    assert_eq!(candidates.get(target.id()).unwrap(), Some(*target));
    let mut restarted = test_network_for_peers(&peers);
    let fill = awaiting(
        restarted
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                target.id(),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_block_id(), parent.id());
    assert_eq!(fill.pending_peer_id(), peers[0]);
    let event = block_response_event(&mut restarted, peers[0], parent);
    assert_complete(fill.on_event(&mut restarted, &selected, event).unwrap());
    assert_eq!(candidates.get(parent.id()).unwrap(), Some(*parent));
    assert_eq!(candidates.get(target.id()).unwrap(), Some(*target));
    assert!((restarted.pending_count_for_test() == 0));
}

#[test]
fn explicit_selected_anchor_accepts_genesis_historical_and_current_paths_lazily() {
    let directory = TestDirectory::new("candidate-fill-explicit-anchor-local");
    let mut selected = create_journal(directory.path()).unwrap();
    let genesis = selected.head_block_id().unwrap();
    let genesis_root = selected.artifact_set_root().unwrap();
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let historical = selected.head_block_id().unwrap();
    let historical_root = selected.artifact_set_root().unwrap();
    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let current = selected.head_block_id().unwrap();
    let current_root = selected.artifact_set_root().unwrap();
    let before = snapshot(&directory, &selected);

    let genesis_child = extension(genesis, genesis_root, 1).remove(0);
    let historical_child = extension(historical, historical_root, 1).remove(0);
    let current_child = extension(current, current_root, 1).remove(0);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 3);
    retain(
        &mut candidates,
        [genesis_child, historical_child, current_child],
    );
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    assert_complete(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
                &selected,
                &mut candidates,
                unknown_peer,
                genesis,
                genesis_child.id(),
            )
            .unwrap(),
    );
    assert_complete(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
                &selected,
                &mut candidates,
                &[],
                historical,
                historical_child.id(),
            )
            .unwrap(),
    );
    assert_complete(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
                &selected,
                &mut candidates,
                unknown_peer,
                current,
                current_child.id(),
            )
            .unwrap(),
    );

    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn explicit_selected_anchor_rejects_unknown_and_candidate_only_anchors_before_peers() {
    let directory = TestDirectory::new("candidate-fill-explicit-anchor-rejection");
    let mut selected = create_journal(directory.path()).unwrap();
    let genesis = selected.head_block_id().unwrap();
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let current = selected.head_block_id().unwrap();
    let current_root = selected.artifact_set_root().unwrap();
    let before = snapshot(&directory, &selected);
    let candidate_only_anchor = extension(current, current_root, 1).remove(0);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 1);
    retain(&mut candidates, [candidate_only_anchor]);
    let unknown_anchor = ArtifactBlockId::from_bytes([0xe1; 32]);
    let missing_target = ArtifactBlockId::from_bytes([0xe2; 32]);
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    let foreign_directory = TestDirectory::new("candidate-fill-explicit-anchor-foreign");
    let foreign_definition = ArtifactChainDefinition::new([0x43; 32]);
    let foreign_chain_id = foreign_definition.id();
    let mut foreign = candidate_store(&foreign_directory, foreign_definition, 1);
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
            &selected,
            &mut foreign,
            &[],
            unknown_anchor,
            missing_target,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::ChainIdMismatch {
            selected,
            candidates,
        }) if selected == test_chain_definition().id() && candidates == foreign_chain_id
    ));

    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
            &selected,
            &mut candidates,
            &[],
            unknown_anchor,
            missing_target,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::SelectedAnchorNotRetained { block_id })
            if block_id == unknown_anchor
    ));
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
            &selected,
            &mut candidates,
            unknown_peer,
            candidate_only_anchor.id(),
            missing_target,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::SelectedAnchorNotRetained { block_id })
            if block_id == candidate_only_anchor.id()
    ));
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
            &selected,
            &mut candidates,
            unknown_peer,
            genesis,
            current,
        ),
        Err(ArtifactBlockCandidateAncestryFillError::TargetAlreadySelected { block_id })
            if block_id == current
    ));

    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn explicit_selected_anchor_survives_unrelated_selected_head_advancement() {
    let directory = TestDirectory::new("candidate-fill-explicit-anchor-head-advance");
    let mut selected = create_journal(directory.path()).unwrap();
    let genesis = selected.head_block_id().unwrap();
    let genesis_root = selected.artifact_set_root().unwrap();
    let blocks = extension(genesis, genesis_root, 2);
    let [parent, target] = blocks.as_slice() else {
        unreachable!("the fixture contains exactly two blocks")
    };
    let mut candidates = candidate_store(&directory, test_chain_definition(), 2);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
                &selected,
                &mut candidates,
                peer_id,
                genesis,
                target.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peer_id, target);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.anchor_block_id(), genesis);
    assert_eq!(fill.pending_block_id(), parent.id());

    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let advanced = snapshot(&directory, &selected);
    let event = block_response_event(&mut network, peer_id, parent);
    assert_complete(fill.on_event(&mut network, &selected, event).unwrap());

    assert_eq!(candidates.get(parent.id()).unwrap(), Some(*parent));
    assert_eq!(candidates.get(target.id()).unwrap(), Some(*target));
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &advanced);
}

#[test]
fn explicit_selected_anchor_rejects_a_different_selected_ancestor_without_requesting_it() {
    let directory = TestDirectory::new("candidate-fill-explicit-anchor-divergence");
    let mut selected = create_journal(directory.path()).unwrap();
    let genesis = selected.head_block_id().unwrap();
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let historical = selected.head_block_id().unwrap();
    let historical_root = selected.artifact_set_root().unwrap();
    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let before = snapshot(&directory, &selected);
    let target = ArtifactBlock::new(
        historical,
        historical_root,
        root(0xe301),
        artifact_id(0xe302),
    );
    let mut candidates = candidate_store(&directory, test_chain_definition(), 1);
    retain(&mut candidates, [target]);
    let mut network = test_network_for_peers(&[]);

    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
            &selected,
            &mut candidates,
            &[],
            genesis,
            target.id(),
        ),
        Err(ArtifactBlockCandidateAncestryFillError::DivergentAncestry {
            expected_anchor,
            encountered,
        }) if expected_anchor == genesis && encountered == historical
    ));
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn explicit_selected_anchor_rejects_a_pending_block_that_becomes_selected() {
    let directory = TestDirectory::new("candidate-fill-explicit-anchor-pending-selected");
    let mut selected = create_journal(directory.path()).unwrap();
    let genesis = selected.head_block_id().unwrap();
    let genesis_root = selected.artifact_set_root().unwrap();
    let parent_bytes = pairing_bytes();
    let parent_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(parent_bytes.clone())
        .unwrap()
        .artifact_id();
    let parent = selected.prepare_block(parent_id).unwrap();
    let target = ArtifactBlock::new(
        parent.id(),
        parent.resulting_artifact_set_root(),
        root(0xe401),
        artifact_id(0xe402),
    );
    assert_eq!(parent.parent_block_id(), genesis);
    assert_eq!(parent.previous_artifact_set_root(), genesis_root);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 2);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
                &selected,
                &mut candidates,
                peer_id,
                genesis,
                target.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peer_id, &target);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_block_id(), parent.id());

    selected.apply_block(&parent, parent_bytes).unwrap();
    let selected_after = snapshot(&directory, &selected);
    let event = block_response_event(&mut network, peer_id, &parent);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::DivergentAncestry {
            expected_anchor,
            encountered,
        }) if expected_anchor == genesis && encountered == parent.id()
    ));

    assert_eq!(candidates.get(target.id()).unwrap(), Some(target));
    assert_eq!(candidates.get(parent.id()).unwrap(), None);
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &selected_after);
}

#[test]
fn explicit_selected_anchor_preserves_the_fixed_sixteen_block_bound() {
    let directory = TestDirectory::new("candidate-fill-explicit-anchor-bound");
    let mut selected = create_journal(directory.path()).unwrap();
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let historical = selected.head_block_id().unwrap();
    let historical_root = selected.artifact_set_root().unwrap();
    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let before = snapshot(&directory, &selected);
    let blocks = extension(
        historical,
        historical_root,
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS + 1,
    );
    let mut candidates = candidate_store(
        &directory,
        test_chain_definition(),
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS + 1,
    );
    retain(&mut candidates, blocks.iter().copied());
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    assert_complete(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
                &selected,
                &mut candidates,
                unknown_peer,
                historical,
                blocks[MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS - 1].id(),
            )
            .unwrap(),
    );
    assert!(matches!(
        network.start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
            &selected,
            &mut candidates,
            &[],
            historical,
            blocks[MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS].id(),
        ),
        Err(ArtifactBlockCandidateAncestryFillError::AncestryLimitExceeded {
            maximum,
            next_block_id,
        }) if maximum == MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS
            && next_block_id == blocks[0].id()
    ));
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn explicit_selected_anchor_fallback_reopens_and_resumes_at_the_durable_parent() {
    let directory = TestDirectory::new("candidate-fill-explicit-anchor-reopen");
    let mut selected = create_journal(directory.path()).unwrap();
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let historical = selected.head_block_id().unwrap();
    let historical_root = selected.artifact_set_root().unwrap();
    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let before = snapshot(&directory, &selected);
    let blocks = extension(historical, historical_root, 2);
    let [parent, target] = blocks.as_slice() else {
        unreachable!("the fixture contains exactly two blocks")
    };
    let limits = ArtifactBlockCandidateStoreLimits::new(2).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(directory.path(), test_chain_definition(), limits)
            .unwrap();
    let peers = peer_ids(2);
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                historical,
                target.id(),
            )
            .unwrap(),
    );
    let event = block_response_event(&mut network, peers[0], target);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_block_id(), parent.id());
    assert_eq!(fill.pending_peer_id(), peers[0]);
    let event = unavailable_event(&mut network, peers[0]);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_peer_id(), peers[1]);
    let event = unavailable_event(&mut network, peers[1]);
    assert!(matches!(
        fill.on_event(&mut network, &selected, event),
        Err(ArtifactBlockCandidateAncestryFillError::BlockUnavailable {
            peer_id,
            block_id,
        }) if peer_id == peers[1] && block_id == parent.id()
    ));
    assert_eq!(candidates.get(target.id()).unwrap(), Some(*target));
    assert_eq!(candidates.get(parent.id()).unwrap(), None);
    drop(network);
    drop(candidates);

    let mut candidates =
        ArtifactBlockCandidateStore::open(directory.path(), test_chain_definition(), limits)
            .unwrap();
    let mut restarted = test_network_for_peers(&peers);
    let fill = awaiting(
        restarted
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
                &selected,
                &mut candidates,
                &peers,
                historical,
                target.id(),
            )
            .unwrap(),
    );
    assert_eq!(fill.pending_block_id(), parent.id());
    assert_eq!(fill.pending_peer_id(), peers[0]);
    let event = block_response_event(&mut restarted, peers[0], parent);
    assert_complete(fill.on_event(&mut restarted, &selected, event).unwrap());
    assert_eq!(candidates.get(parent.id()).unwrap(), Some(*parent));
    assert_eq!(candidates.get(target.id()).unwrap(), Some(*target));
    assert_snapshot(&directory, &selected, &before);
}

#[tokio::test]
async fn real_reopened_candidate_server_fills_a_historical_branch_without_selection() {
    let (mut client, mut server, _, server_peer_id) = connected_pair().await;

    let client_directory = TestDirectory::new("candidate-fill-explicit-anchor-real-client");
    let mut client_selected = create_journal(client_directory.path()).unwrap();
    apply_fresh_blocks(&mut client_selected, [pairing_bytes()]);
    let historical = client_selected.head_block_id().unwrap();
    let historical_root = client_selected.artifact_set_root().unwrap();
    apply_fresh_blocks(&mut client_selected, [union_bytes()]);
    let client_selected_before = snapshot(&client_directory, &client_selected);
    let blocks = extension(historical, historical_root, 2);
    let target = blocks[1];
    let limits = ArtifactBlockCandidateStoreLimits::new(2).unwrap();
    let mut client_candidates = ArtifactBlockCandidateStore::create(
        client_directory.path(),
        test_chain_definition(),
        limits,
    )
    .unwrap();

    let server_directory = TestDirectory::new("candidate-fill-explicit-anchor-real-server");
    let server_selected = create_journal(server_directory.path()).unwrap();
    let server_selected_before = snapshot(&server_directory, &server_selected);
    let mut server_candidates = ArtifactBlockCandidateStore::create(
        server_directory.path(),
        test_chain_definition(),
        limits,
    )
    .unwrap();
    retain(&mut server_candidates, blocks.iter().copied());
    drop(server_candidates);
    let mut server_candidates =
        ArtifactBlockCandidateStore::open(server_directory.path(), test_chain_definition(), limits)
            .unwrap();

    let mut fill = client
        .start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
            &client_selected,
            &mut client_candidates,
            server_peer_id,
            historical,
            target.id(),
        )
        .unwrap();
    let mut served = 0_usize;
    timeout(Duration::from_secs(20), async {
        while fill.is_some() {
            tokio::select! {
                event = client.next_event() => {
                    let current = fill.take().unwrap();
                    if current.accepts_event(&event) {
                        fill = current
                            .on_event(&mut client, &client_selected, event)
                            .unwrap();
                    } else {
                        if let NetworkEvent::ListenerError { error, .. } = &event {
                            panic!("candidate-fill client listener failed: {error}");
                        }
                        fill = Some(current);
                    }
                }
                event = server.next_event() => match event {
                    NetworkEvent::InboundBlockRequest(inbound) => {
                        server
                            .respond_block_from_candidate_store(inbound, &mut server_candidates)
                            .unwrap();
                        served += 1;
                    }
                    NetworkEvent::InboundBlockFailure { error, .. } => {
                        panic!("candidate-fill server request failed: {error}");
                    }
                    NetworkEvent::ListenerError { error, .. } => {
                        panic!("candidate-fill server listener failed: {error}");
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("authenticated historical candidate fill timed out");

    assert_eq!(served, 2);
    assert!((client.pending_count_for_test() == 0));
    assert_snapshot(&client_directory, &client_selected, &client_selected_before);
    assert_snapshot(&server_directory, &server_selected, &server_selected_before);
    for block in &blocks {
        assert_eq!(server_candidates.get(block.id()).unwrap(), Some(*block));
    }

    drop(client_candidates);
    let mut reopened_client =
        ArtifactBlockCandidateStore::open(client_directory.path(), test_chain_definition(), limits)
            .unwrap();
    for block in blocks {
        assert_eq!(reopened_client.get(block.id()).unwrap(), Some(block));
    }
    assert_snapshot(&client_directory, &client_selected, &client_selected_before);
    assert_snapshot(&server_directory, &server_selected, &server_selected_before);
}

#[test]
fn explicit_anchor_fill_composes_with_payload_fallback_for_a_branch_only_dependency() {
    let directory = TestDirectory::new("candidate-fill-explicit-anchor-composition");
    let mut selected = create_journal(directory.path()).unwrap();
    let base_bytes = pairing_bytes();
    let mut identities = ArtifactDag::new();
    let base_id = identities
        .apply_canonical_artifact_bytes(base_bytes.clone())
        .unwrap()
        .artifact_id();
    let base = selected.prepare_block(base_id).unwrap();
    selected.apply_block(&base, base_bytes.clone()).unwrap();
    let historical = base.id();

    let first_bytes = independent_proof_bytes(3);
    let first_record = identities
        .apply_canonical_artifact_bytes(first_bytes.clone())
        .unwrap();
    let first_id = first_record.artifact_id();
    let first_proof_id = first_record.as_proof().unwrap().proof_id();
    let target_bytes = referenced_generalization_bytes(first_proof_id);
    let target_id = identities
        .apply_canonical_artifact_bytes(target_bytes.clone())
        .unwrap()
        .artifact_id();

    let mut branch = ArtifactChainState::new(test_chain_definition());
    branch.apply_block(&base, base_bytes).unwrap();
    let first = branch.prepare_block(first_id).unwrap();
    branch.apply_block(&first, first_bytes.clone()).unwrap();
    let target = branch.prepare_block(target_id).unwrap();
    branch.apply_block(&target, target_bytes.clone()).unwrap();
    let expected_root = branch.artifact_dag().artifact_set_root();

    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let before = snapshot(&directory, &selected);
    let mut candidates = candidate_store(&directory, test_chain_definition(), 2);
    let mut payloads = CanonicalArtifactPayloadStore::create(
        directory.path(),
        ArtifactPayloadStoreLimits::new(2, 1_000_000).unwrap(),
    )
    .unwrap();
    let peers = peer_ids(4);
    let block_peers = &peers[..2];
    let payload_peers = &peers[2..];
    let mut network = test_network_for_peers(&peers);

    let fill = awaiting(
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
                &selected,
                &mut candidates,
                block_peers,
                historical,
                target.id(),
            )
            .unwrap(),
    );
    let event = unavailable_event(&mut network, block_peers[0]);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_peer_id(), block_peers[1]);
    let event = block_response_event(&mut network, block_peers[1], &target);
    let fill = awaiting(fill.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(fill.pending_block_id(), first.id());
    assert_eq!(fill.pending_peer_id(), block_peers[0]);
    let event = block_response_event(&mut network, block_peers[0], &first);
    assert_complete(fill.on_event(&mut network, &selected, event).unwrap());

    let progress = network
        .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
            &selected,
            &mut candidates,
            &mut payloads,
            payload_peers,
            target.id(),
            CandidateBranchReconstructionLimits::new(2).unwrap(),
        )
        .unwrap();
    let crate::ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(fill) = progress
    else {
        panic!("the empty archive unexpectedly completed branch reconstruction")
    };
    assert_eq!(fill.pending_block_id(), first.id());
    assert_eq!(fill.pending_peer_id(), payload_peers[0]);
    let event = artifact_response_event(&mut network, payload_peers[0], Vec::new());
    let progress = fill.on_event(&mut network, event).unwrap();
    let crate::ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(fill) = progress
    else {
        panic!("the unavailable first payload unexpectedly completed reconstruction")
    };
    assert_eq!(fill.pending_peer_id(), payload_peers[1]);
    let event = artifact_response_event(&mut network, payload_peers[1], first_bytes);
    let progress = fill.on_event(&mut network, event).unwrap();
    let crate::ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(fill) = progress
    else {
        panic!("the first durable payload unexpectedly completed reconstruction")
    };
    assert_eq!(fill.pending_block_id(), target.id());
    assert_eq!(fill.pending_peer_id(), payload_peers[0]);
    let event = artifact_response_event(&mut network, payload_peers[0], target_bytes);
    let progress = fill.on_event(&mut network, event).unwrap();
    let crate::ArtifactBlockCandidateBranchPayloadFillProgress::Complete(reconstructed) = progress
    else {
        panic!("the complete branch still awaits a payload")
    };

    assert_eq!(reconstructed.anchor_block_id(), historical);
    assert_eq!(reconstructed.target_block_id(), target.id());
    assert_eq!(reconstructed.snapshot().artifact_set_root(), expected_root);
    assert!(payloads.contains(first.artifact_id()).unwrap());
    assert!(payloads.contains(target.artifact_id()).unwrap());
    assert_eq!(candidates.get(first.id()).unwrap(), Some(first));
    assert_eq!(candidates.get(target.id()).unwrap(), Some(target));
    assert!((network.pending_count_for_test() == 0));
    assert_snapshot(&directory, &selected, &before);
}
