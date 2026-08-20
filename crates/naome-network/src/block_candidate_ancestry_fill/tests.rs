use std::fs::OpenOptions;
use std::sync::atomic::Ordering;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome_chain::{ArtifactBlock, ArtifactBlockId, ArtifactChainDefinition, ArtifactSetRoot};
use naome_proof::ArtifactId;
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactBlockCandidateStoreLimits,
};

use super::*;
use crate::codec::ArtifactBlockWireResponse;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, create_journal, pairing_bytes, snapshot,
    test_chain_definition, test_network_for_peers, union_bytes,
};
use crate::{
    ExchangeRequestId, Keypair, MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS, NetworkEvent,
    OutboundArtifactBlockFailure, PendingRequest, RequestStartError,
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
    naome::block_exchange::ArtifactBlockRequest,
) {
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
        .expect("the candidate ancestry fill has one pending block request")
}

fn block_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    block: &ArtifactBlock,
) -> NetworkEvent {
    let (request_id, _) = pending_block_request(network, peer_id);
    network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_500),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactBlockWireResponse::new(block.to_canonical_bytes()),
            },
        })
        .expect("the retained fill request produces one terminal event")
}

fn unavailable_event(network: &mut StaticArtifactNetwork, peer_id: PeerId) -> NetworkEvent {
    let (request_id, _) = pending_block_request(network, peer_id);
    network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_501),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactBlockWireResponse::new(Vec::new()),
            },
        })
        .expect("the retained fill request produces one unavailable terminal")
}

fn block_failure_event(network: &mut StaticArtifactNetwork, peer_id: PeerId) -> NetworkEvent {
    let (request_id, _) = pending_block_request(network, peer_id);
    network
        .handle_block_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_502),
            request_id,
            error: request_response::OutboundFailure::Timeout,
        })
        .expect("the retained fill request produces one failure terminal")
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
    assert_eq!(network.pending.len(), 1);

    let event = block_response_event(&mut network, peer_id, missing_middle);
    assert!(fill.accepts_event(&event));
    assert_complete(fill.on_event(&mut network, &selected, event).unwrap());

    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
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
    assert!(restarted_network.pending.is_empty());
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
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);
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
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
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
    assert!(network.pending.is_empty());
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
    assert!(maximum_network.pending.is_empty());
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
    assert!(excess_network.pending.is_empty());
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
    assert!(network.pending.is_empty());
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
    assert!(network.pending.is_empty());
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
    assert!(network.pending.is_empty());
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
    assert_eq!(network.pending.len(), 1);
    drop(unavailable_event(&mut network, peer_id));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}
