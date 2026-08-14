use std::sync::atomic::Ordering;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::block_exchange::ArtifactBlockExchangeWireError;
use naome_chain::{ArtifactBlock, ArtifactBlockId, ArtifactSetRoot};
use naome_proof::ArtifactId;
use naome_storage::ArtifactChainJournal;

use super::*;
use crate::codec::ArtifactBlockWireResponse;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, create_journal, pairing_bytes, snapshot,
    test_chain_definition, test_network_for_peers, union_bytes,
};
use crate::{ExchangeRequestId, Keypair, NetworkEvent, PendingRequest, RequestStartError};

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
    let mut previous = anchor_root;
    let mut blocks = Vec::with_capacity(count);
    for index in 0..count {
        let resulting = root(0x1000 + index);
        let block = ArtifactBlock::new(parent, previous, resulting, artifact_id(0x2000 + index));
        parent = block.id();
        previous = resulting;
        blocks.push(block);
    }
    blocks
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
        .expect("the peer has one pending block request")
}

fn block_response_event_from(
    network: &mut StaticArtifactNetwork,
    expected_peer_id: PeerId,
    actual_peer_id: PeerId,
    bytes: impl Into<Vec<u8>>,
) -> NetworkEvent {
    let bytes = bytes.into();
    let (request_id, _) = pending_block_request(network, expected_peer_id);
    network
        .handle_block_exchange_event(request_response::Event::Message {
            peer: actual_peer_id,
            connection_id: ConnectionId::new_unchecked(1_000),
            message: request_response::Message::Response {
                request_id,
                response: ArtifactBlockWireResponse::new(bytes),
            },
        })
        .expect("the retained ancestry request produces one terminal event")
}

fn block_response_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    block: &ArtifactBlock,
) -> NetworkEvent {
    block_response_event_from(network, peer_id, peer_id, block.to_canonical_bytes())
}

fn unavailable_event(network: &mut StaticArtifactNetwork, peer_id: PeerId) -> NetworkEvent {
    block_response_event_from(network, peer_id, peer_id, Vec::new())
}

fn block_failure_event(
    network: &mut StaticArtifactNetwork,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> NetworkEvent {
    let (request_id, _) = pending_block_request(network, peer_id);
    network
        .handle_block_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(1_001),
            request_id,
            error,
        })
        .expect("the retained ancestry request produces one failure terminal")
}

fn start_pull(
    network: &mut StaticArtifactNetwork,
    selected: &ArtifactChainJournal,
    peer_id: PeerId,
    target: ArtifactBlockId,
) -> ArtifactBlockAncestryPull {
    network
        .start_artifact_block_ancestry_pull(selected, peer_id, target)
        .unwrap()
}

fn awaiting(progress: ArtifactBlockAncestryPullProgress) -> ArtifactBlockAncestryPull {
    let ArtifactBlockAncestryPullProgress::AwaitingResponse(pull) = progress else {
        panic!("ancestry completed before reaching its anchor")
    };
    pull
}

fn complete_path(
    network: &mut StaticArtifactNetwork,
    selected: &ArtifactChainJournal,
    peer_id: PeerId,
    blocks: &[ArtifactBlock],
) -> UnselectedArtifactBlockAncestry {
    let target = blocks.last().unwrap().id();
    let mut pull = start_pull(network, selected, peer_id, target);
    for (index, block) in blocks.iter().rev().enumerate() {
        assert_eq!(pull.pending_block_id(), block.id());
        assert_eq!(pull.pending_peer_id(), peer_id);
        assert_eq!(network.pending.len(), 1);
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

        let event = block_response_event(network, peer_id, block);
        assert!(pull.accepts_event(&event));
        let progress = pull.on_event(network, selected, event).unwrap();
        if index + 1 == blocks.len() {
            let ArtifactBlockAncestryPullProgress::Complete(ancestry) = progress else {
                panic!("the anchor child started an unnecessary parent request")
            };
            return ancestry;
        }
        pull = awaiting(progress);
    }
    unreachable!("a path is nonempty")
}

#[test]
fn current_head_historical_block_and_virtual_genesis_beat_peer_validation() {
    let directory = TestDirectory::new("ancestry-selected-targets");
    let mut selected = create_journal(directory.path()).unwrap();
    let virtual_genesis = selected.head_block_id().unwrap();
    let unknown_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[]);

    assert!(matches!(
        network.start_artifact_block_ancestry_pull(&selected, unknown_peer, virtual_genesis),
        Err(ArtifactBlockAncestryPullError::TargetAlreadySelected { block_id })
            if block_id == virtual_genesis
    ));
    assert!(network.pending.is_empty());

    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let historical = selected.head_block_id().unwrap();
    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let current = selected.head_block_id().unwrap();
    let before = snapshot(&directory, &selected);

    for target in [current, historical, virtual_genesis] {
        assert!(matches!(
            network.start_artifact_block_ancestry_pull(&selected, unknown_peer, target),
            Err(ArtifactBlockAncestryPullError::TargetAlreadySelected { block_id })
                if block_id == target
        ));
        assert!(network.pending.is_empty());
        assert_snapshot(&directory, &selected, &before);
    }

    let absent = ArtifactBlockId::from_bytes([0x77; 32]);
    assert!(matches!(
        network.start_artifact_block_ancestry_pull(&selected, unknown_peer, absent),
        Err(ArtifactBlockAncestryPullError::RequestStart {
            block_id,
            source: RequestStartError::UnknownPeer(peer_id),
        }) if block_id == absent && peer_id == unknown_peer
    ));
}

#[test]
fn direct_and_multi_block_paths_are_forward_ordered_and_never_select() {
    for count in [1, 3] {
        let directory = TestDirectory::new("ancestry-success");
        let selected = create_journal(directory.path()).unwrap();
        let before = snapshot(&directory, &selected);
        let blocks = extension(before.head, before.root, count);
        let target = blocks.last().unwrap().id();
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let mut network = test_network_for_peers(&[peer_id]);

        let ancestry = complete_path(&mut network, &selected, peer_id, &blocks);
        assert_eq!(ancestry.peer_id(), peer_id);
        assert_eq!(ancestry.anchor_block_id(), before.head);
        assert_eq!(ancestry.target_block_id(), target);
        assert_eq!(ancestry.blocks(), blocks);
        assert_eq!(ancestry.into_blocks(), blocks);
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert_snapshot(&directory, &selected, &before);

        drop(selected);
        let reopened = ArtifactChainJournal::open_recovering_unverified(
            directory.path(),
            test_chain_definition(),
        )
        .unwrap();
        assert_eq!(reopened.head_block_id().unwrap(), before.head);
        assert_eq!(directory.journal_bytes(), before.bytes);
    }
}

#[test]
fn sixteen_blocks_succeed_but_seventeen_stop_before_request_seventeen() {
    let directory = TestDirectory::new("ancestry-bound");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();

    let sixteen = extension(before.head, before.root, MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS);
    let mut network = test_network_for_peers(&[peer_id]);
    let ancestry = complete_path(&mut network, &selected, peer_id, &sixteen);
    assert_eq!(ancestry.blocks(), sixteen);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let seventeen = extension(
        before.head,
        before.root,
        MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS + 1,
    );
    let target = seventeen.last().unwrap().id();
    let mut pull = start_pull(&mut network, &selected, peer_id, target);
    for block in seventeen
        .iter()
        .rev()
        .take(MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS - 1)
    {
        assert_eq!(pull.pending_block_id(), block.id());
        let event = block_response_event(&mut network, peer_id, block);
        pull = awaiting(pull.on_event(&mut network, &selected, event).unwrap());
    }

    let sixteenth_response = &seventeen[1];
    assert_eq!(pull.pending_block_id(), sixteenth_response.id());
    let event = block_response_event(&mut network, peer_id, sixteenth_response);
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::AncestryLimitExceeded {
            maximum: MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS,
            next_block_id,
        }) if next_block_id == seventeen[0].id()
    ));
    assert!(network.pending.is_empty(), "request 17 must not be issued");
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn anchor_and_adjacent_artifact_set_roots_are_both_required() {
    let directory = TestDirectory::new("ancestry-root-continuity");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();

    let wrong_previous = root(0xdead);
    assert_ne!(wrong_previous, before.root);
    let direct = ArtifactBlock::new(before.head, wrong_previous, root(1), artifact_id(1));
    let mut network = test_network_for_peers(&[peer_id]);
    let pull = start_pull(&mut network, &selected, peer_id, direct.id());
    let event = block_response_event(&mut network, peer_id, &direct);
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::ArtifactSetRootMismatch {
            preceding_block_id,
            expected,
            actual,
        }) if preceding_block_id == before.head
            && expected == before.root
            && actual == wrong_previous
    ));

    let parent_result = root(2);
    let child_previous = root(3);
    let parent = ArtifactBlock::new(before.head, before.root, parent_result, artifact_id(2));
    let child = ArtifactBlock::new(parent.id(), child_previous, root(4), artifact_id(3));
    let pull = start_pull(&mut network, &selected, peer_id, child.id());
    let child_event = block_response_event(&mut network, peer_id, &child);
    let pull = awaiting(pull.on_event(&mut network, &selected, child_event).unwrap());
    let parent_event = block_response_event(&mut network, peer_id, &parent);
    assert!(matches!(
        pull.on_event(&mut network, &selected, parent_event),
        Err(ArtifactBlockAncestryPullError::ArtifactSetRootMismatch {
            preceding_block_id,
            expected,
            actual,
        }) if preceding_block_id == parent.id()
            && expected == parent_result
            && actual == child_previous
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn older_selected_parent_and_virtual_genesis_are_divergence_not_fetch_targets() {
    let directory = TestDirectory::new("ancestry-divergence");
    let mut selected = create_journal(directory.path()).unwrap();
    let virtual_genesis = selected.head_block_id().unwrap();
    let empty_root = selected.artifact_set_root().unwrap();
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let historical = selected.head_block_id().unwrap();
    let historical_root = selected.artifact_set_root().unwrap();
    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let before = snapshot(&directory, &selected);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let fork = extension(historical, historical_root, 2);
    let pull = start_pull(&mut network, &selected, peer_id, fork[1].id());
    let event = block_response_event(&mut network, peer_id, &fork[1]);
    let pull = awaiting(pull.on_event(&mut network, &selected, event).unwrap());
    let event = block_response_event(&mut network, peer_id, &fork[0]);
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::DivergentAncestry {
            expected_anchor,
            encountered,
        }) if expected_anchor == before.head && encountered == historical
    ));
    assert!(network.pending.is_empty());

    let genesis_fork = extension(virtual_genesis, empty_root, 1);
    let pull = start_pull(&mut network, &selected, peer_id, genesis_fork[0].id());
    let event = block_response_event(&mut network, peer_id, &genesis_fork[0]);
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::DivergentAncestry {
            expected_anchor,
            encountered,
        }) if expected_anchor == before.head && encountered == virtual_genesis
    ));
    assert!(
        network.pending.is_empty(),
        "genesis must never be requested"
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn repeated_id_guard_covers_target_and_every_requested_parent() {
    let target_parent = ArtifactBlockId::from_bytes([0x31; 32]);
    let target = ArtifactBlock::new(target_parent, root(1), root(2), artifact_id(1));
    assert!(ArtifactBlockAncestryPull::was_already_requested(
        target.id(),
        &[],
        target.id(),
    ));
    assert!(ArtifactBlockAncestryPull::was_already_requested(
        target.id(),
        std::slice::from_ref(&target),
        target_parent,
    ));
    assert!(!ArtifactBlockAncestryPull::was_already_requested(
        target.id(),
        &[target],
        ArtifactBlockId::from_bytes([0x32; 32]),
    ));
}

#[test]
fn unavailable_transport_wrong_identity_and_peer_mismatch_are_terminal() {
    let directory = TestDirectory::new("ancestry-terminal-errors");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let expected_peer = Keypair::generate_ed25519().public().to_peer_id();
    let actual_peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[expected_peer, actual_peer]);
    let target = extension(before.head, before.root, 1).remove(0);

    let pull = start_pull(&mut network, &selected, expected_peer, target.id());
    let event = unavailable_event(&mut network, expected_peer);
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::BlockUnavailable {
            peer_id,
            block_id,
        }) if peer_id == expected_peer && block_id == target.id()
    ));

    let pull = start_pull(&mut network, &selected, expected_peer, target.id());
    let event = block_failure_event(
        &mut network,
        expected_peer,
        request_response::OutboundFailure::Timeout,
    );
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::BlockRequestFailed { source, .. })
            if matches!(
                source.as_ref(),
                OutboundArtifactBlockFailure::Transport(request_response::OutboundFailure::Timeout)
            )
    ));

    let wrong = extension(before.head, before.root, 1).remove(0);
    let requested = ArtifactBlockId::from_bytes([0x44; 32]);
    assert_ne!(wrong.id(), requested);
    let pull = start_pull(&mut network, &selected, expected_peer, requested);
    let event = block_response_event_from(
        &mut network,
        expected_peer,
        expected_peer,
        wrong.to_canonical_bytes(),
    );
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::BlockRequestFailed {
            block_id,
            source,
            ..
        }) if block_id == requested
            && matches!(
                source.as_ref(),
                OutboundArtifactBlockFailure::InvalidResponse {
                    source: ArtifactBlockExchangeWireError::BlockIdMismatch { expected, actual },
                } if *expected == requested && *actual == wrong.id()
            )
    ));

    let pull = start_pull(&mut network, &selected, expected_peer, target.id());
    let event = block_response_event_from(&mut network, expected_peer, actual_peer, vec![0xff]);
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::BlockRequestFailed {
            peer_id,
            block_id,
            source,
        }) if peer_id == expected_peer
            && block_id == target.id()
            && matches!(
                source.as_ref(),
                OutboundArtifactBlockFailure::PeerMismatch { expected, actual }
                    if *expected == expected_peer && *actual == actual_peer
            )
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn network_generation_driver_and_protocol_correlation_fail_closed() {
    let directory = TestDirectory::new("ancestry-correlation");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let target = extension(before.head, before.root, 1).remove(0);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();

    let mut first = test_network_for_peers(&[peer_id]);
    let mut second = test_network_for_peers(&[peer_id]);
    let first_pull = start_pull(&mut first, &selected, peer_id, target.id());
    let second_pull = start_pull(&mut second, &selected, peer_id, target.id());
    assert_eq!(
        pending_block_request(&first, peer_id).0,
        pending_block_request(&second, peer_id).0,
    );
    let second_event = unavailable_event(&mut second, peer_id);
    assert!(!first_pull.accepts_event(&second_event));
    assert!(matches!(
        first_pull.on_event(&mut first, &selected, second_event),
        Err(ArtifactBlockAncestryPullError::UnexpectedEvent)
    ));
    drop(second_pull);
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 1);
    assert_eq!(second.pending_budget.active.load(Ordering::Relaxed), 0);
    drop(block_failure_event(
        &mut first,
        peer_id,
        request_response::OutboundFailure::Timeout,
    ));
    assert_eq!(first.pending_budget.active.load(Ordering::Relaxed), 0);

    let mut origin = test_network_for_peers(&[peer_id]);
    let mut wrong_driver = test_network_for_peers(&[peer_id]);
    let pull = start_pull(&mut origin, &selected, peer_id, target.id());
    let event = block_response_event(&mut origin, peer_id, &target);
    assert!(pull.accepts_event(&event));
    assert!(matches!(
        pull.on_event(&mut wrong_driver, &selected, event),
        Err(ArtifactBlockAncestryPullError::UnexpectedEvent)
    ));
    assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(
        wrong_driver.pending_budget.active.load(Ordering::Relaxed),
        0
    );

    let mut network = test_network_for_peers(&[peer_id]);
    let first_pull = start_pull(&mut network, &selected, peer_id, target.id());
    let first_event = unavailable_event(&mut network, peer_id);
    let later_pull = start_pull(&mut network, &selected, peer_id, target.id());
    assert!(!later_pull.accepts_event(&first_event));
    assert!(matches!(
        later_pull.on_event(&mut network, &selected, first_event),
        Err(ArtifactBlockAncestryPullError::UnexpectedEvent)
    ));
    drop(first_pull);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(block_failure_event(
        &mut network,
        peer_id,
        request_response::OutboundFailure::Timeout,
    ));

    let pull = start_pull(&mut network, &selected, peer_id, target.id());
    let unrelated = NetworkEvent::Listening {
        address: "/memory/1".parse().unwrap(),
    };
    assert!(!pull.accepts_event(&unrelated));
    assert!(matches!(
        pull.on_event(&mut network, &selected, unrelated),
        Err(ArtifactBlockAncestryPullError::UnexpectedEvent)
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(block_failure_event(
        &mut network,
        peer_id,
        request_response::OutboundFailure::Timeout,
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn selected_head_drift_precedes_block_semantics_but_not_transport_outcomes() {
    let directory = TestDirectory::new("ancestry-selected-drift");
    let mut selected = create_journal(directory.path()).unwrap();
    let anchor = selected.head_block_id().unwrap();
    let anchor_root = selected.artifact_set_root().unwrap();
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let target = ArtifactBlock::new(anchor, root(0x81), root(0x82), artifact_id(0x83));
    let mut network = test_network_for_peers(&[peer_id]);

    let pull = start_pull(&mut network, &selected, peer_id, target.id());
    let event = block_response_event(&mut network, peer_id, &target);
    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let advanced = snapshot(&directory, &selected);
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::SelectedHeadChanged { expected, actual })
            if expected == anchor && actual == advanced.head
    ));
    assert_snapshot(&directory, &selected, &advanced);

    let absent = ArtifactBlockId::from_bytes([0x84; 32]);
    let pull = start_pull(&mut network, &selected, peer_id, absent);
    let unavailable = unavailable_event(&mut network, peer_id);
    apply_fresh_blocks(&mut selected, [union_bytes()]);
    let advanced_again = snapshot(&directory, &selected);
    assert!(matches!(
        pull.on_event(&mut network, &selected, unavailable),
        Err(ArtifactBlockAncestryPullError::BlockUnavailable { block_id, .. })
            if block_id == absent
    ));
    assert_snapshot(&directory, &selected, &advanced_again);
    assert_ne!(anchor_root, advanced_again.root);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn selected_head_drift_is_rechecked_after_a_target_block_was_retained() {
    let directory = TestDirectory::new("ancestry-late-selected-drift");
    let mut selected = create_journal(directory.path()).unwrap();
    let anchor = selected.head_block_id().unwrap();
    let anchor_root = selected.artifact_set_root().unwrap();
    let parent = ArtifactBlock::new(anchor, anchor_root, root(0xa1), artifact_id(0xa1));
    let child = ArtifactBlock::new(parent.id(), root(0xa2), root(0xa3), artifact_id(0xa2));
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let pull = start_pull(&mut network, &selected, peer_id, child.id());
    let event = block_response_event(&mut network, peer_id, &child);
    let pull = awaiting(pull.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(pull.pending_block_id(), parent.id());
    let parent_event = block_response_event(&mut network, peer_id, &parent);

    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let advanced = snapshot(&directory, &selected);
    assert!(matches!(
        pull.on_event(&mut network, &selected, parent_event),
        Err(ArtifactBlockAncestryPullError::SelectedHeadChanged { expected, actual })
            if expected == anchor && actual == advanced.head
    ));
    assert_snapshot(&directory, &selected, &advanced);
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn next_parent_request_failure_discards_the_unselected_prefix() {
    let directory = TestDirectory::new("ancestry-next-start-failure");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let blocks = extension(before.head, before.root, 2);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);
    let pull = start_pull(&mut network, &selected, peer_id, blocks[1].id());
    let event = block_response_event(&mut network, peer_id, &blocks[1]);

    let unrelated = network
        .request_block(
            peer_id,
            naome::block_exchange::ArtifactBlockRequest::new(ArtifactBlockId::from_bytes(
                [0x91; 32],
            )),
        )
        .unwrap();
    assert!(matches!(
        pull.on_event(&mut network, &selected, event),
        Err(ArtifactBlockAncestryPullError::RequestStart {
            block_id,
            source: RequestStartError::AlreadyPending(actual_peer),
        }) if block_id == blocks[0].id() && actual_peer == peer_id
    ));
    assert_eq!(network.pending.len(), 1);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(unrelated);
    network.pending.clear();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_snapshot(&directory, &selected, &before);
}

#[test]
fn cancellation_keeps_only_the_physical_request_until_its_late_terminal() {
    let directory = TestDirectory::new("ancestry-cancel");
    let selected = create_journal(directory.path()).unwrap();
    let before = snapshot(&directory, &selected);
    let blocks = extension(before.head, before.root, 2);
    let peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id]);

    let pull = start_pull(&mut network, &selected, peer_id, blocks[1].id());
    pull.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let late = unavailable_event(&mut network, peer_id);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(late);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let pull = start_pull(&mut network, &selected, peer_id, blocks[1].id());
    let event = block_response_event(&mut network, peer_id, &blocks[1]);
    let pull = awaiting(pull.on_event(&mut network, &selected, event).unwrap());
    assert_eq!(pull.pending_block_id(), blocks[0].id());
    pull.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let late = block_failure_event(
        &mut network,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    drop(late);
    assert!(network.pending.is_empty());
    assert_snapshot(&directory, &selected, &before);
}
