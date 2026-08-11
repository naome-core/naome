use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::proof_exchange::ProofResponse;
use naome_chain::{ProofBlockApplyError, ProofDag, ProofTransitionApplyError};
use naome_foundation::{Formula, FreeVariable, ZfcAxiom};
use naome_ledger::ProofBatchError;

use super::*;
use crate::tests::{TestDirectory, apply_fresh_blocks, create_journal};
use crate::{CancellationDrainOutcome, NetworkEvent, PendingBudget, StaticPeer};

fn proof_id(byte: u8) -> ProofId {
    ProofId::from_bytes([byte; 32])
}

fn pairing_bytes() -> Vec<u8> {
    vec![0x00, 0x00, 0x00, 0x01, 0x10, 0x01]
}

fn canonical_bytes(steps: Vec<ProofStep>) -> Vec<u8> {
    ProofCertificate::new(steps)
        .unwrap()
        .into_unchecked_normal_form()
        .into_canonical_bytes()
        .into_vec()
}

fn reference_closure_bytes(dependencies: &[ProofId]) -> Vec<u8> {
    assert!(!dependencies.is_empty());
    let mut steps = dependencies
        .iter()
        .copied()
        .map(|proof_id| ProofStep::ProofReference { proof_id })
        .collect::<Vec<_>>();
    let mut root = 0_u32;
    for next in 1..dependencies.len() {
        steps.push(ProofStep::ModusPonens {
            premise: root,
            implication: u32::try_from(next).unwrap(),
        });
        root = u32::try_from(steps.len() - 1).unwrap();
    }
    canonical_bytes(steps)
}

fn referenced_generalization_bytes(parent: ProofId) -> Vec<u8> {
    canonical_bytes(vec![
        ProofStep::ProofReference { proof_id: parent },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(7),
        },
    ])
}

fn identity_bytes(variable: FreeVariable) -> Vec<u8> {
    canonical_bytes(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Generalization {
            premise: 0,
            variable,
        },
    ])
}

fn identity_detour_bytes(variable: FreeVariable) -> Vec<u8> {
    let equality = Formula::equal(variable, variable);
    canonical_bytes(vec![
        ProofStep::EqualityReflexivity { variable },
        ProofStep::Simplification {
            antecedent: equality.clone(),
            consequent: equality,
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
            variable,
        },
    ])
}

fn proof_citing_both_identities(
    direct: ProofId,
    detour: ProofId,
    variable: FreeVariable,
) -> Vec<u8> {
    let equality = Formula::equal(variable, variable);
    let identity = Formula::for_all(variable, equality);
    canonical_bytes(vec![
        ProofStep::ProofReference { proof_id: direct },
        ProofStep::ProofReference { proof_id: detour },
        ProofStep::Simplification {
            antecedent: identity.clone(),
            consequent: identity,
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 2,
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 3,
        },
    ])
}

fn valid_parent_and_root() -> (Vec<u8>, ProofId, Vec<u8>, ProofId) {
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
    (parent_bytes, parent_id, root_bytes, root_id)
}

fn test_network() -> (StaticProofNetwork, PeerId) {
    let remote = crate::Keypair::generate_ed25519();
    let remote_peer_id = remote.public().to_peer_id();
    (test_network_for_peer(remote_peer_id), remote_peer_id)
}

fn test_network_for_peer(remote_peer_id: PeerId) -> StaticProofNetwork {
    test_network_for_peers(&[remote_peer_id])
}

fn test_network_for_peers(remote_peer_ids: &[PeerId]) -> StaticProofNetwork {
    let local = crate::Keypair::generate_ed25519();
    assert!(!remote_peer_ids.contains(&local.public().to_peer_id()));
    let peers = remote_peer_ids
        .iter()
        .copied()
        .enumerate()
        .map(|(index, peer_id)| {
            let address = format!("/ip4/127.0.0.1/tcp/{}", 9 + index).parse().unwrap();
            StaticPeer::new(peer_id, address)
        })
        .collect::<Vec<_>>();
    let mut network = StaticProofNetwork::new(local, peers).unwrap();
    for &peer_id in remote_peer_ids {
        network
            .swarm
            .behaviour_mut()
            .sessions
            .mark_connected_for_test(peer_id);
    }
    network
}

fn response_for(
    network: &mut StaticProofNetwork,
    acquisition: &ProofDependencyAcquisition,
    bytes: Vec<u8>,
) -> OutboundProofEvent {
    let request_id = acquisition.pending_request_id;
    let pending = network
        .pending
        .remove(&request_id)
        .expect("the acquisition request is pending");
    OutboundProofEvent {
        request_id,
        peer_id: pending.peer_id,
        request: pending.request,
        control: Arc::clone(&pending.control),
        outcome: OutboundProofOutcome::Response {
            response: ProofResponse::from_wire_bytes(bytes).unwrap(),
            _permit: pending._permit,
        },
    }
}

fn transport_response(
    network: &mut StaticProofNetwork,
    request_id: OutboundRequestId,
    peer_id: PeerId,
    bytes: Vec<u8>,
) -> NetworkEvent {
    network
        .handle_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(700),
            message: request_response::Message::Response {
                request_id,
                response: ProofResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained request produces one terminal event")
}

fn transport_failure(
    network: &mut StaticProofNetwork,
    request_id: OutboundRequestId,
    peer_id: PeerId,
    error: request_response::OutboundFailure,
) -> NetworkEvent {
    network
        .handle_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(701),
            request_id,
            error,
        })
        .expect("the retained request produces one terminal event")
}

fn start(
    network: &mut StaticProofNetwork,
    selected: &ProofChainJournal,
    peer_id: PeerId,
    requested_root: ProofId,
) -> ProofDependencyAcquisition {
    network
        .start_dependency_acquisition(selected, peer_id, requested_root)
        .unwrap()
}

fn candidate(id: u8, dependencies: &[u8]) -> QuarantinedCandidate {
    let budget = Arc::new(PendingBudget::default());
    let permit = PendingBudget::try_acquire(&budget).unwrap();
    QuarantinedCandidate {
        expected_proof_id: proof_id(id),
        canonical_proof_bytes: vec![id],
        direct_dependencies: dependencies.iter().map(|byte| proof_id(*byte)).collect(),
        _permit: permit,
    }
}

#[test]
fn shared_dependency_order_is_unique_dependency_first_and_root_last() {
    let candidates = vec![candidate(3, &[1, 2]), candidate(1, &[2]), candidate(2, &[])];

    let order = dependency_order(&candidates, proof_id(3)).unwrap();
    let ordered_ids = order
        .into_iter()
        .map(|index| candidates[index].expected_proof_id)
        .collect::<Vec<_>>();

    assert_eq!(ordered_ids, [proof_id(2), proof_id(1), proof_id(3)]);
}

#[test]
fn address_cycle_reports_the_closing_edge() {
    let candidates = vec![candidate(2, &[1]), candidate(1, &[2])];

    assert!(matches!(
        dependency_order(&candidates, proof_id(2)),
        Err(DependencyAcquisitionError::DependencyCycle { from, dependency })
            if from == proof_id(1) && dependency == proof_id(2)
    ));
}

#[test]
fn closure_debug_does_not_expose_candidate_bytes() {
    let closure = UnselectedProofClosure {
        requested_root: proof_id(9),
        candidates: vec![candidate(9, &[])],
    };

    let debug = format!("{closure:?}");
    assert!(debug.contains("candidate_count: 1"));
    assert!(!debug.contains("canonical_proof_bytes"));
}

#[test]
fn caller_block_order_reorders_an_equivalent_quarantined_topology() {
    let directory = TestDirectory::new("caller-block-order");
    let mut selected = create_journal(directory.path()).unwrap();
    let variable = FreeVariable::new(17);
    let direct_bytes = identity_bytes(variable);
    let detour_bytes = identity_detour_bytes(variable);
    let mut identity = ProofDag::new();
    let direct_id = identity
        .apply_canonical_proof_bytes(direct_bytes.clone())
        .unwrap()
        .proof_id();
    let detour_id = identity
        .apply_canonical_proof_bytes(detour_bytes.clone())
        .unwrap()
        .proof_id();
    let root_bytes = proof_citing_both_identities(direct_id, detour_id, variable);
    let root_id = identity
        .apply_canonical_proof_bytes(root_bytes.clone())
        .unwrap()
        .proof_id();

    let budget = Arc::new(PendingBudget::default());
    let quarantined =
        |expected_proof_id, canonical_proof_bytes, direct_dependencies| QuarantinedCandidate {
            expected_proof_id,
            canonical_proof_bytes,
            direct_dependencies,
            _permit: PendingBudget::try_acquire(&budget).unwrap(),
        };
    let closure = UnselectedProofClosure {
        requested_root: root_id,
        candidates: vec![
            quarantined(direct_id, direct_bytes, Vec::new()),
            quarantined(detour_id, detour_bytes, Vec::new()),
            quarantined(root_id, root_bytes, vec![direct_id, detour_id]),
        ],
    };
    assert_eq!(budget.active.load(Ordering::Relaxed), 3);

    let block = selected
        .prepare_block(vec![detour_id, direct_id, root_id])
        .unwrap();
    assert_eq!(
        closure
            .apply_block(&mut selected, &block)
            .unwrap()
            .proof_id(),
        root_id
    );
    assert_eq!(selected.head_block_id().unwrap(), block.id());
    assert_eq!(selected.len().unwrap(), 3);
    assert_eq!(budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn closure_count_mismatch_releases_permits_and_stale_parent_wins() {
    let directory = TestDirectory::new("closure-shape-mismatch");
    let mut selected = create_journal(directory.path()).unwrap();
    let first = proof_id(0x31);
    let second = proof_id(0x32);
    let extra = proof_id(0x33);
    let block = selected.prepare_block(vec![first, second]).unwrap();
    let initial_head = selected.head_block_id().unwrap();
    let initial_bytes = directory.journal_bytes();

    let closure_with = |ids: &[ProofId], budget: &Arc<PendingBudget>| UnselectedProofClosure {
        requested_root: second,
        candidates: ids
            .iter()
            .copied()
            .map(|expected_proof_id| QuarantinedCandidate {
                expected_proof_id,
                canonical_proof_bytes: vec![0xff],
                direct_dependencies: Vec::new(),
                _permit: PendingBudget::try_acquire(budget).unwrap(),
            })
            .collect(),
    };

    let budget = Arc::new(PendingBudget::default());
    let incomplete = closure_with(&[first], &budget);
    assert!(matches!(
        incomplete.apply_block(&mut selected, &block),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::Transition {
                source: ProofTransitionApplyError::CandidateCountMismatch { .. }
            }
        })
    ));
    assert_eq!(budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(selected.head_block_id().unwrap(), initial_head);
    assert!(selected.is_empty().unwrap());
    assert_eq!(directory.journal_bytes(), initial_bytes);

    apply_fresh_blocks(&mut selected, [pairing_bytes()]);
    let advanced_head = selected.head_block_id().unwrap();
    let advanced_bytes = directory.journal_bytes();
    let budget = Arc::new(PendingBudget::default());
    let malformed = closure_with(&[extra], &budget);
    assert!(matches!(
        malformed.apply_block(&mut selected, &block),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::ParentBlockIdMismatch { .. }
        })
    ));
    assert_eq!(budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(selected.head_block_id().unwrap(), advanced_head);
    assert_eq!(directory.journal_bytes(), advanced_bytes);
}

#[test]
fn selected_dependency_is_a_cut_and_promotion_adds_only_the_root() {
    let (parent_bytes, parent_id, root_bytes, root_id) = valid_parent_and_root();
    let directory = TestDirectory::new("selected-cut");
    let mut selected = create_journal(directory.path()).unwrap();
    assert_eq!(
        apply_fresh_blocks(&mut selected, [parent_bytes]),
        [parent_id]
    );
    let before = directory.journal_bytes();
    let before_root = selected.proof_set_root().unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, root_id);
    let response = response_for(&mut network, &acquisition, root_bytes);

    let DependencyAcquisitionProgress::Complete(closure) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("selected dependency unexpectedly caused another request");
    };
    assert_eq!(closure.candidate_count(), 1);
    assert_eq!(directory.journal_bytes(), before);
    assert_eq!(selected.proof_set_root().unwrap(), before_root);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let block = selected.prepare_block(vec![root_id]).unwrap();
    assert_eq!(
        closure
            .apply_block(&mut selected, &block)
            .unwrap()
            .proof_id(),
        root_id
    );
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(selected.len().unwrap(), 2);
    assert!(selected.proof(parent_id).unwrap().is_some());
}

#[test]
fn selected_root_and_unknown_peer_fail_before_a_request_is_retained() {
    let directory = TestDirectory::new("start-preflight");
    let mut selected = create_journal(directory.path()).unwrap();
    let selected_root = apply_fresh_blocks(&mut selected, [pairing_bytes()])[0];
    let (mut network, peer_id) = test_network();

    assert!(matches!(
        network.start_dependency_acquisition(&selected, peer_id, selected_root),
        Err(DependencyAcquisitionError::RootAlreadySelected { proof_id })
            if proof_id == selected_root
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let unknown = crate::Keypair::generate_ed25519().public().to_peer_id();
    let requested = proof_id(0x40);
    assert!(matches!(
        network.start_dependency_acquisition(&selected, unknown, requested),
        Err(DependencyAcquisitionError::RequestStart { proof_id, source: RequestStartError::UnknownPeer(actual) })
            if proof_id == requested && actual == unknown
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);

    let disconnected_peer = crate::Keypair::generate_ed25519().public().to_peer_id();
    let disconnected_address = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
    let mut disconnected = StaticProofNetwork::new(
        crate::Keypair::generate_ed25519(),
        [StaticPeer::new(disconnected_peer, disconnected_address)],
    )
    .unwrap();
    assert!(matches!(
        disconnected.start_dependency_acquisition(
            &selected,
            disconnected_peer,
            requested,
        ),
        Err(DependencyAcquisitionError::NoEligiblePeer { proof_id })
            if proof_id == requested
    ));
    assert!(disconnected.pending.is_empty());
    assert_eq!(
        disconnected.pending_budget.active.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn unavailable_and_malformed_responses_drop_the_complete_quarantine() {
    let directory = TestDirectory::new("terminal-response-errors");
    let selected = create_journal(directory.path()).unwrap();
    let before = directory.journal_bytes();

    for (bytes, decode) in [(Vec::new(), false), (vec![0xff], true)] {
        let (mut network, peer_id) = test_network();
        let requested = proof_id(0x41);
        let acquisition = start(&mut network, &selected, peer_id, requested);
        let response = response_for(&mut network, &acquisition, bytes);
        let error = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap_err();
        assert!(
            matches!(error, DependencyAcquisitionError::Decode { proof_id, .. } if decode && proof_id == requested)
                || matches!(error, DependencyAcquisitionError::Unavailable { peer_id: actual_peer, proof_id } if !decode && actual_peer == peer_id && proof_id == requested)
        );
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
        assert_eq!(directory.journal_bytes(), before);
    }
}

#[test]
fn unavailable_retries_the_same_request_after_releasing_its_permit() {
    let directory = TestDirectory::new("unavailable-fallback");
    let selected = create_journal(directory.path()).unwrap();
    let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
    let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[fallback, preferred]);
    let requested = proof_id(0xa0);
    let acquisition = start(&mut network, &selected, preferred, requested);
    let control = Arc::clone(acquisition.cancellation.control());
    let other_permits = (0..crate::MAX_PENDING_REQUESTS - 1)
        .map(|_| PendingBudget::try_acquire(&network.pending_budget).unwrap())
        .collect::<Vec<_>>();
    let response = response_for(&mut network, &acquisition, Vec::new());
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        crate::MAX_PENDING_REQUESTS
    );

    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("unavailable preferred peer did not start fallback");
    };
    assert_eq!(acquisition.pending_peer_id(), fallback);
    assert_eq!(acquisition.pending_request(), ProofRequest::new(requested));
    assert_eq!(acquisition.attempts_issued, 2);
    assert!(Arc::ptr_eq(acquisition.cancellation.control(), &control));
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        crate::MAX_PENDING_REQUESTS
    );
    assert_eq!(network.pending.len(), 1);
    drop(other_permits);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let response = response_for(&mut network, &acquisition, Vec::new());
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, response),
        Err(DependencyAcquisitionError::Unavailable { peer_id, proof_id })
            if peer_id == fallback && proof_id == requested
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn fallback_visits_preferred_then_raw_order_without_repeating_a_peer() {
    let directory = TestDirectory::new("fallback-order");
    let selected = create_journal(directory.path()).unwrap();
    let mut peers = [
        crate::Keypair::generate_ed25519().public().to_peer_id(),
        crate::Keypair::generate_ed25519().public().to_peer_id(),
        crate::Keypair::generate_ed25519().public().to_peer_id(),
    ];
    peers.sort_unstable_by_key(|peer_id| peer_id.to_bytes());
    let [first, second, preferred] = peers;
    let mut network = test_network_for_peers(&[second, preferred, first]);
    let requested = proof_id(0xa6);
    let acquisition = start(&mut network, &selected, preferred, requested);
    assert_eq!(acquisition.pending_peer_id(), preferred);

    let unavailable = response_for(&mut network, &acquisition, Vec::new());
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, unavailable)
        .unwrap()
    else {
        panic!("first fallback did not start");
    };
    assert_eq!(acquisition.pending_peer_id(), first);

    let unavailable = response_for(&mut network, &acquisition, Vec::new());
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, unavailable)
        .unwrap()
    else {
        panic!("second fallback did not start");
    };
    assert_eq!(acquisition.pending_peer_id(), second);
    assert_eq!(acquisition.attempts_issued, 3);

    let unavailable = response_for(&mut network, &acquisition, Vec::new());
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, unavailable),
        Err(DependencyAcquisitionError::Unavailable { peer_id, proof_id })
            if peer_id == second && proof_id == requested
    ));
    assert!(network.pending.is_empty());
}

#[test]
fn disconnected_and_busy_peers_are_skipped_without_consuming_attempts() {
    let directory = TestDirectory::new("fallback-skips");
    let selected = create_journal(directory.path()).unwrap();
    let mut peers = [
        crate::Keypair::generate_ed25519().public().to_peer_id(),
        crate::Keypair::generate_ed25519().public().to_peer_id(),
        crate::Keypair::generate_ed25519().public().to_peer_id(),
    ];
    peers.sort_unstable_by_key(|peer_id| peer_id.to_bytes());
    let [disconnected, busy, available] = peers;
    let mut network = test_network_for_peers(&[available, disconnected, busy]);
    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(disconnected);
    network
        .request_proof(busy, ProofRequest::new(proof_id(0xb0)))
        .unwrap();

    let acquisition = start(&mut network, &selected, disconnected, proof_id(0xb1));
    assert_eq!(acquisition.pending_peer_id(), available);
    assert_eq!(acquisition.attempts_issued, 1);
    assert_eq!(network.pending.len(), 2);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);
}

#[test]
fn transport_failure_falls_back_without_reusing_the_failed_peer() {
    let directory = TestDirectory::new("transport-fallback");
    let selected = create_journal(directory.path()).unwrap();
    let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
    let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[preferred, fallback]);
    let requested = proof_id(0xa1);
    let acquisition = start(&mut network, &selected, preferred, requested);
    let event = transport_failure(
        &mut network,
        acquisition.pending_request_id,
        preferred,
        request_response::OutboundFailure::Timeout,
    );
    let NetworkEvent::OutboundProof(event) = event else {
        panic!("transport failure was not surfaced");
    };

    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, event)
        .unwrap()
    else {
        panic!("transport failure did not start fallback");
    };
    assert_eq!(acquisition.pending_peer_id(), fallback);
    assert_eq!(acquisition.pending_request(), ProofRequest::new(requested));
    assert_eq!(acquisition.attempts_issued, 2);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
}

#[test]
fn fallback_provider_is_preferred_for_the_next_dependency() {
    let (parent_bytes, parent_id, root_bytes, root_id) = valid_parent_and_root();
    let directory = TestDirectory::new("fallback-stickiness");
    let selected = create_journal(directory.path()).unwrap();
    let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
    let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[preferred, fallback]);
    let acquisition = start(&mut network, &selected, preferred, root_id);
    let unavailable = response_for(&mut network, &acquisition, Vec::new());
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, unavailable)
        .unwrap()
    else {
        panic!("root fallback did not start");
    };
    assert_eq!(acquisition.pending_peer_id(), fallback);

    let root = response_for(&mut network, &acquisition, root_bytes);
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) =
        acquisition.on_event(&mut network, &selected, root).unwrap()
    else {
        panic!("root did not discover its parent");
    };
    assert_eq!(acquisition.pending_peer_id(), fallback);
    assert_eq!(acquisition.pending_request(), ProofRequest::new(parent_id));
    assert_eq!(acquisition.attempts_issued, 3);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

    let parent = response_for(&mut network, &acquisition, parent_bytes);
    let DependencyAcquisitionProgress::Complete(closure) = acquisition
        .on_event(&mut network, &selected, parent)
        .unwrap()
    else {
        panic!("two-candidate closure did not complete");
    };
    assert_eq!(closure.candidate_count(), 2);
}

#[test]
fn malformed_and_noncanonical_candidates_do_not_fall_back() {
    let directory = TestDirectory::new("structural-errors-do-not-fallback");
    let selected = create_journal(directory.path()).unwrap();
    let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
    let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
    let noncanonical = ProofCertificate::new(vec![
        ProofStep::ProofReference {
            proof_id: proof_id(0x77),
        },
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
    ])
    .unwrap()
    .to_canonical_bytes();

    for bytes in [vec![0xff], noncanonical] {
        let mut network = test_network_for_peers(&[fallback, preferred]);
        let requested = proof_id(0xa2);
        let acquisition = start(&mut network, &selected, preferred, requested);
        let response = response_for(&mut network, &acquisition, bytes);
        let error = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap_err();
        assert!(matches!(
            error,
            DependencyAcquisitionError::Decode { .. }
                | DependencyAcquisitionError::NonCanonical { .. }
        ));
        assert!(network.pending.is_empty());
        assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn request_attempt_limit_never_resets_for_a_new_dependency() {
    let directory = TestDirectory::new("request-attempt-limit");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0xa3);
    let first_dependency = proof_id(0xa4);
    let second_dependency = proof_id(0xa5);
    let mut acquisition = start(&mut network, &selected, peer_id, requested);
    acquisition.attempts_issued = u8::try_from(MAX_DEPENDENCY_ACQUISITION_REQUESTS - 1).unwrap();
    let root = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&[first_dependency]),
    );
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) =
        acquisition.on_event(&mut network, &selected, root).unwrap()
    else {
        panic!("the final permitted request was not issued");
    };
    assert_eq!(
        usize::from(acquisition.attempts_issued),
        MAX_DEPENDENCY_ACQUISITION_REQUESTS
    );

    let dependency = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&[second_dependency]),
    );
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, dependency),
        Err(DependencyAcquisitionError::RequestAttemptLimit {
            pending_proof_id,
            maximum,
        }) if pending_proof_id == second_dependency
            && maximum == MAX_DEPENDENCY_ACQUISITION_REQUESTS
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn seven_fallbacks_and_eight_candidates_complete_at_exact_request_limit() {
    let directory = TestDirectory::new("exact-request-limit-completion");
    let selected = create_journal(directory.path()).unwrap();
    let peer_ids = (0..crate::MAX_STATIC_PEERS)
        .map(|_| crate::Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peer_ids);
    let requested = proof_id(0xc0);
    let dependencies = (1..PROOF_BATCH_MAX_CANDIDATES)
        .map(|index| proof_id(u8::try_from(0xc0 + index).unwrap()))
        .collect::<Vec<_>>();
    let mut acquisition = start(&mut network, &selected, peer_ids[0], requested);

    for _ in 0..crate::MAX_STATIC_PEERS - 1 {
        let unavailable = response_for(&mut network, &acquisition, Vec::new());
        let DependencyAcquisitionProgress::AwaitingResponse(next) = acquisition
            .on_event(&mut network, &selected, unavailable)
            .unwrap()
        else {
            panic!("bounded root fallback terminated before the eighth peer");
        };
        acquisition = next;
    }

    let root = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&[dependencies[0]]),
    );
    let DependencyAcquisitionProgress::AwaitingResponse(next) =
        acquisition.on_event(&mut network, &selected, root).unwrap()
    else {
        panic!("root did not request its first dependency");
    };
    acquisition = next;

    for window in dependencies.windows(2) {
        let response = response_for(
            &mut network,
            &acquisition,
            reference_closure_bytes(&[window[1]]),
        );
        let DependencyAcquisitionProgress::AwaitingResponse(next) = acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        else {
            panic!("dependency chain completed before its leaf");
        };
        acquisition = next;
    }

    assert_eq!(
        usize::from(acquisition.attempts_issued),
        MAX_DEPENDENCY_ACQUISITION_REQUESTS
    );
    let leaf = response_for(&mut network, &acquisition, pairing_bytes());
    let DependencyAcquisitionProgress::Complete(closure) =
        acquisition.on_event(&mut network, &selected, leaf).unwrap()
    else {
        panic!("exact-limit closure did not complete");
    };
    assert_eq!(closure.candidate_count(), PROOF_BATCH_MAX_CANDIDATES);
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        PROOF_BATCH_MAX_CANDIDATES
    );
    drop(closure);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn fifteenth_terminal_request_cannot_start_a_sixteenth_attempt() {
    let directory = TestDirectory::new("terminal-request-attempt-limit");
    let selected = create_journal(directory.path()).unwrap();
    let preferred = crate::Keypair::generate_ed25519().public().to_peer_id();
    let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[preferred, fallback]);
    let requested = proof_id(0xa7);
    let mut acquisition = start(&mut network, &selected, preferred, requested);
    acquisition.attempts_issued = u8::try_from(MAX_DEPENDENCY_ACQUISITION_REQUESTS).unwrap();
    let unavailable = response_for(&mut network, &acquisition, Vec::new());

    assert!(matches!(
        acquisition.on_event(&mut network, &selected, unavailable),
        Err(DependencyAcquisitionError::RequestAttemptLimit {
            pending_proof_id,
            maximum,
        }) if pending_proof_id == requested
            && maximum == MAX_DEPENDENCY_ACQUISITION_REQUESTS
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn noncanonical_candidate_cannot_trigger_an_unreachable_reference_request() {
    let directory = TestDirectory::new("noncanonical");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x42);
    let unreachable = proof_id(0x99);
    let bytes = ProofCertificate::new(vec![
        ProofStep::ProofReference {
            proof_id: unreachable,
        },
        ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
    ])
    .unwrap()
    .to_canonical_bytes();
    let acquisition = start(&mut network, &selected, peer_id, requested);
    let response = response_for(&mut network, &acquisition, bytes);

    assert!(matches!(
        acquisition.on_event(&mut network, &selected, response),
        Err(DependencyAcquisitionError::NonCanonical { proof_id }) if proof_id == requested
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(selected.proof(unreachable).unwrap().is_none());
}

#[test]
fn ninth_absent_candidate_is_rejected_before_another_request() {
    let directory = TestDirectory::new("candidate-bound");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x50);
    let dependencies = (0..PROOF_BATCH_MAX_CANDIDATES)
        .map(|index| proof_id(u8::try_from(index + 1).unwrap()))
        .collect::<Vec<_>>();
    let acquisition = start(&mut network, &selected, peer_id, requested);
    let response = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&dependencies),
    );

    assert!(matches!(
        acquisition.on_event(&mut network, &selected, response),
        Err(DependencyAcquisitionError::TooManyCandidates { actual, maximum })
            if actual == PROOF_BATCH_MAX_CANDIDATES + 1
                && maximum == PROOF_BATCH_MAX_CANDIDATES
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn exact_maximum_closure_holds_all_permits_until_drop() {
    let directory = TestDirectory::new("maximum-closure");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x51);
    let dependencies = (0..PROOF_BATCH_MAX_CANDIDATES - 1)
        .map(|index| proof_id(u8::try_from(index + 1).unwrap()))
        .collect::<Vec<_>>();
    let acquisition = start(&mut network, &selected, peer_id, requested);
    let response = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&dependencies),
    );
    let DependencyAcquisitionProgress::AwaitingResponse(mut acquisition) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("maximum closure did not request its dependencies");
    };

    let closure = loop {
        let response = response_for(&mut network, &acquisition, pairing_bytes());
        match acquisition
            .on_event(&mut network, &selected, response)
            .unwrap()
        {
            DependencyAcquisitionProgress::AwaitingResponse(next) => acquisition = next,
            DependencyAcquisitionProgress::Complete(closure) => break closure,
        }
    };
    assert_eq!(closure.candidate_count(), PROOF_BATCH_MAX_CANDIDATES);
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        PROOF_BATCH_MAX_CANDIDATES
    );
    drop(closure);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(selected.is_empty().unwrap());
}

#[test]
fn repeated_and_shared_references_are_requested_once() {
    let directory = TestDirectory::new("reference-dedup");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x52);
    let first = proof_id(0x01);
    let shared = proof_id(0x02);
    let acquisition = start(&mut network, &selected, peer_id, requested);
    let response = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&[first, first, shared]),
    );
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("root did not request its first unique dependency");
    };
    assert_eq!(acquisition.pending_request().proof_id(), first);

    let response = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&[shared]),
    );
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("shared dependency was not requested");
    };
    assert_eq!(acquisition.pending_request().proof_id(), shared);
    let response = response_for(&mut network, &acquisition, pairing_bytes());
    let DependencyAcquisitionProgress::Complete(closure) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("deduplicated closure did not complete");
    };
    assert_eq!(closure.candidate_count(), 3);
    assert!(network.pending.is_empty());
    drop(closure);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn later_unavailable_response_discards_the_earlier_quarantine() {
    let directory = TestDirectory::new("later-unavailable");
    let selected = create_journal(directory.path()).unwrap();
    let before = directory.journal_bytes();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x53);
    let dependency = proof_id(0x54);
    let acquisition = start(&mut network, &selected, peer_id, requested);
    let response = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&[dependency]),
    );
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("dependency was not requested");
    };
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);
    let response = response_for(&mut network, &acquisition, Vec::new());
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, response),
        Err(DependencyAcquisitionError::Unavailable { proof_id, .. })
            if proof_id == dependency
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(network.pending.is_empty());
    assert!(selected.is_empty().unwrap());
    assert_eq!(directory.journal_bytes(), before);
}

#[test]
fn acquired_self_and_two_node_cycles_terminate_without_selection() {
    let directory = TestDirectory::new("cycles");
    let selected = create_journal(directory.path()).unwrap();

    let (mut self_network, self_peer) = test_network();
    let self_id = proof_id(0x61);
    let self_acquisition = start(&mut self_network, &selected, self_peer, self_id);
    let self_response = response_for(
        &mut self_network,
        &self_acquisition,
        reference_closure_bytes(&[self_id]),
    );
    assert!(matches!(
        self_acquisition.on_event(&mut self_network, &selected, self_response),
        Err(DependencyAcquisitionError::DependencyCycle { from, dependency })
            if from == self_id && dependency == self_id
    ));
    assert_eq!(
        self_network.pending_budget.active.load(Ordering::Relaxed),
        0
    );

    let (mut network, peer_id) = test_network();
    let root = proof_id(0x62);
    let child = proof_id(0x63);
    let acquisition = start(&mut network, &selected, peer_id, root);
    let response = response_for(
        &mut network,
        &acquisition,
        reference_closure_bytes(&[child]),
    );
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("two-node cycle did not request its second node");
    };
    assert_eq!(acquisition.pending_request().proof_id(), child);
    let response = response_for(&mut network, &acquisition, reference_closure_bytes(&[root]));
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, response),
        Err(DependencyAcquisitionError::DependencyCycle { from, dependency })
            if from == child && dependency == root
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(selected.is_empty().unwrap());
}

#[test]
fn stale_same_address_response_does_not_consume_a_new_generation() {
    let directory = TestDirectory::new("late-response");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x71);
    let first = start(&mut network, &selected, peer_id, requested);
    let stale = response_for(&mut network, &first, pairing_bytes());
    drop(first);

    let current = start(&mut network, &selected, peer_id, requested);
    assert!(!current.accepts_event(&stale));
    assert_eq!(current.pending_request().proof_id(), requested);
    drop(stale);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);

    let response = response_for(&mut network, &current, pairing_bytes());
    let DependencyAcquisitionProgress::Complete(closure) =
        current.on_event(&mut network, &selected, response).unwrap()
    else {
        panic!("leaf candidate unexpectedly requested a dependency");
    };
    drop(closure);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn unexpected_generation_precedes_payload_interpretation() {
    let directory = TestDirectory::new("unexpected-generation");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x74);
    let previous = start(&mut network, &selected, peer_id, requested);
    let stale_unavailable = response_for(&mut network, &previous, Vec::new());
    drop(previous);

    let current = start(&mut network, &selected, peer_id, requested);
    let current_request_id = current.pending_request_id;
    assert!(!current.accepts_event(&stale_unavailable));
    assert!(matches!(
        current.on_event(&mut network, &selected, stale_unavailable),
        Err(DependencyAcquisitionError::UnexpectedEvent)
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(network.pending.remove(&current_request_id));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(selected.is_empty().unwrap());
}

#[test]
fn follow_up_request_must_use_the_originating_network_instance() {
    let directory = TestDirectory::new("follow-up-network-instance");
    let selected = create_journal(directory.path()).unwrap();
    let remote = crate::Keypair::generate_ed25519();
    let peer_id = remote.public().to_peer_id();
    let mut origin = test_network_for_peer(peer_id);
    let mut wrong_driver = test_network_for_peer(peer_id);
    let requested = proof_id(0x73);
    let acquisition = start(&mut origin, &selected, peer_id, requested);
    let response = response_for(&mut origin, &acquisition, pairing_bytes());
    assert!(acquisition.accepts_event(&response));

    assert!(matches!(
        acquisition.on_event(&mut wrong_driver, &selected, response),
        Err(DependencyAcquisitionError::NetworkInstanceMismatch)
    ));
    assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(
        wrong_driver.pending_budget.active.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn response_must_come_from_the_originating_network_instance() {
    let directory = TestDirectory::new("response-network-instance");
    let selected = create_journal(directory.path()).unwrap();
    let remote = crate::Keypair::generate_ed25519();
    let peer_id = remote.public().to_peer_id();
    let mut origin = test_network_for_peer(peer_id);
    let mut other = test_network_for_peer(peer_id);
    let requested = proof_id(0x75);
    let acquisition = start(&mut origin, &selected, peer_id, requested);
    let origin_request_id = acquisition.pending_request_id;
    let other_acquisition = start(&mut other, &selected, peer_id, requested);
    let mut other_response = response_for(&mut other, &other_acquisition, pairing_bytes());
    other_response.request_id = origin_request_id;

    assert!(!acquisition.accepts_event(&other_response));
    assert!(matches!(
        acquisition.on_event(&mut origin, &selected, other_response),
        Err(DependencyAcquisitionError::NetworkInstanceMismatch)
    ));
    assert_eq!(other.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(origin.pending.remove(&origin_request_id));
    assert_eq!(origin.pending_budget.active.load(Ordering::Relaxed), 0);
    drop(other_acquisition);
}

#[test]
fn wrong_address_promotion_is_atomic_and_releases_its_permit() {
    let directory = TestDirectory::new("wrong-address");
    let mut selected = create_journal(directory.path()).unwrap();
    let before = directory.journal_bytes();
    let before_root = selected.proof_set_root().unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x72);
    let acquisition = start(&mut network, &selected, peer_id, requested);
    let response = response_for(&mut network, &acquisition, pairing_bytes());
    let DependencyAcquisitionProgress::Complete(closure) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("leaf candidate unexpectedly requested a dependency");
    };
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let block = selected.prepare_block(vec![requested]).unwrap();

    assert!(matches!(
        closure.apply_block(&mut selected, &block),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::Transition {
                source: ProofTransitionApplyError::Batch {
                    source: ProofBatchError::Candidate { index: 0, .. }
                }
            }
        })
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(selected.proof_set_root().unwrap(), before_root);
    assert!(selected.is_empty().unwrap());
    assert_eq!(directory.journal_bytes(), before);
}

#[test]
fn selected_state_drift_is_revalidated_without_filtering_the_closure() {
    let (parent_bytes, parent_id, root_bytes, root_id) = valid_parent_and_root();
    let directory = TestDirectory::new("state-drift");
    let mut selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, root_id);
    let response = response_for(&mut network, &acquisition, root_bytes);
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("root dependency was not requested");
    };
    let response = response_for(&mut network, &acquisition, parent_bytes.clone());
    let DependencyAcquisitionProgress::Complete(closure) = acquisition
        .on_event(&mut network, &selected, response)
        .unwrap()
    else {
        panic!("complete two-node closure did not finish");
    };
    assert_eq!(closure.candidate_count(), 2);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

    let stale_block = selected.prepare_block(vec![parent_id, root_id]).unwrap();
    assert_eq!(
        apply_fresh_blocks(&mut selected, [parent_bytes]),
        [parent_id]
    );
    let before = directory.journal_bytes();
    let before_root = selected.proof_set_root().unwrap();
    let before_len = selected.len().unwrap();
    assert!(matches!(
        closure.apply_block(&mut selected, &stale_block),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::ParentBlockIdMismatch { .. }
        })
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert_eq!(selected.len().unwrap(), before_len);
    assert_eq!(selected.proof_set_root().unwrap(), before_root);
    assert!(selected.proof(parent_id).unwrap().is_some());
    assert!(selected.proof(root_id).unwrap().is_none());
    assert_eq!(directory.journal_bytes(), before);
}

#[test]
fn cancellation_releases_quarantine_but_retains_the_wire_permit_until_drain() {
    let (parent_bytes, _parent_id, root_bytes, root_id) = valid_parent_and_root();
    let directory = TestDirectory::new("cancel-retains-wire-permit");
    let selected = create_journal(directory.path()).unwrap();
    let before = directory.journal_bytes();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, root_id);
    let event = response_for(&mut network, &acquisition, root_bytes);
    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, event)
        .unwrap()
    else {
        panic!("root dependency was not requested");
    };
    let request_id = acquisition.pending_request_id;
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 2);

    acquisition.cancel();
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    assert!(network.pending.contains_key(&request_id));
    assert!(network.pending[&request_id].control.is_cancelled());
    assert!(matches!(
        network.request_proof(peer_id, ProofRequest::new(proof_id(0x91))),
        Err(RequestStartError::AlreadyPending(actual)) if actual == peer_id
    ));

    let event = transport_response(&mut network, request_id, peer_id, parent_bytes);
    assert!(matches!(
        event,
        NetworkEvent::CancellationDrained {
            peer_id: actual,
            outcome: CancellationDrainOutcome::ResponseDiscarded,
            ..
        } if actual == peer_id
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(network.pending.is_empty());
    assert!(selected.is_empty().unwrap());
    assert_eq!(directory.journal_bytes(), before);
}

#[test]
fn cancelled_transport_failure_settles_once_with_its_typed_cause() {
    let directory = TestDirectory::new("cancel-failure-drain");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, proof_id(0x92));
    let request_id = acquisition.pending_request_id;
    acquisition.cancel();

    let event = transport_failure(
        &mut network,
        request_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    assert!(matches!(
        event,
        NetworkEvent::CancellationDrained {
            outcome: CancellationDrainOutcome::Failure(source),
            ..
        } if matches!(
            source.as_ref(),
            OutboundProofFailure::Transport(request_response::OutboundFailure::Timeout)
        )
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(
        network
            .handle_exchange_event(request_response::Event::OutboundFailure {
                peer: peer_id,
                connection_id: ConnectionId::new_unchecked(702),
                request_id,
                error: request_response::OutboundFailure::Timeout,
            })
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn session_disconnect_does_not_settle_a_cancelled_request() {
    let directory = TestDirectory::new("cancel-disconnect-order");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, proof_id(0x9b));
    let request_id = acquisition.pending_request_id;
    acquisition.cancel();

    network
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(peer_id);
    assert!(matches!(
        network.next_event().await,
        NetworkEvent::PeerSession(crate::PeerSessionEvent::Disconnected {
            peer_id: disconnected,
        }) if disconnected == peer_id
    ));
    assert!(network.pending.contains_key(&request_id));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    assert!(matches!(
        network.request_proof(peer_id, ProofRequest::new(proof_id(0x9c))),
        Err(RequestStartError::AlreadyPending(actual)) if actual == peer_id
    ));

    assert!(matches!(
        transport_failure(
            &mut network,
            request_id,
            peer_id,
            request_response::OutboundFailure::ConnectionClosed,
        ),
        NetworkEvent::CancellationDrained {
            outcome: CancellationDrainOutcome::Failure(source),
            ..
        } if matches!(
            source.as_ref(),
            OutboundProofFailure::Transport(
                request_response::OutboundFailure::ConnectionClosed
            )
        )
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
    assert!(matches!(
        network.request_proof(peer_id, ProofRequest::new(proof_id(0x9d))),
        Err(RequestStartError::PeerDisconnected(actual)) if actual == peer_id
    ));
}

#[test]
fn cancelled_requests_retain_the_complete_global_budget_until_exact_drain() {
    let directory = TestDirectory::new("cancel-global-budget");
    let selected = create_journal(directory.path()).unwrap();
    let peer_ids = (0..crate::MAX_PENDING_REQUESTS)
        .map(|_| crate::Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peer_ids);
    let request_ids = peer_ids
        .iter()
        .copied()
        .enumerate()
        .map(|(index, peer_id)| {
            let acquisition = start(
                &mut network,
                &selected,
                peer_id,
                proof_id(u8::try_from(0xa0 + index).unwrap()),
            );
            let request_id = acquisition.pending_request_id;
            acquisition.cancel();
            request_id
        })
        .collect::<Vec<_>>();

    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        crate::MAX_PENDING_REQUESTS
    );
    assert!(PendingBudget::try_acquire(&network.pending_budget).is_none());

    for (index, (&peer_id, &request_id)) in peer_ids.iter().zip(&request_ids).enumerate() {
        assert!(matches!(
            transport_response(&mut network, request_id, peer_id, pairing_bytes()),
            NetworkEvent::CancellationDrained {
                outcome: CancellationDrainOutcome::ResponseDiscarded,
                ..
            }
        ));
        assert_eq!(
            network.pending_budget.active.load(Ordering::Relaxed),
            crate::MAX_PENDING_REQUESTS - index - 1
        );
    }
    assert!(network.pending.is_empty());
}

#[tokio::test(start_paused = true)]
async fn next_event_expires_once_at_the_absolute_deadline_and_drains_later() {
    let directory = TestDirectory::new("absolute-deadline-event");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, proof_id(0x93));
    let request_id = acquisition.pending_request_id;

    tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
    let event = network.next_event().await;
    let NetworkEvent::OutboundProof(event) = event else {
        panic!("absolute deadline did not produce an outbound proof event");
    };
    assert!(event.is_deadline_exceeded());
    assert!(acquisition.accepts_event(&event));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    assert!(network.pending[&request_id].control.is_cancelled());
    assert!(
        network
            .take_due_acquisition_deadline(tokio::time::Instant::now())
            .is_none()
    );
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, event),
        Err(DependencyAcquisitionError::DeadlineExceeded {
            pending_proof_id,
            ..
        }) if pending_proof_id == proof_id(0x93)
    ));

    let event = transport_response(&mut network, request_id, peer_id, pairing_bytes());
    assert!(matches!(
        event,
        NetworkEvent::CancellationDrained {
            outcome: CancellationDrainOutcome::ResponseDiscarded,
            ..
        }
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn deadline_equality_expires_but_completed_closures_do_not() {
    let (parent_bytes, parent_id, _root_bytes, _root_id) = valid_parent_and_root();
    let directory = TestDirectory::new("deadline-boundary");
    let mut selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();

    let acquisition = start(&mut network, &selected, peer_id, parent_id);
    tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT - Duration::from_nanos(1)).await;
    let event = response_for(&mut network, &acquisition, parent_bytes.clone());
    let DependencyAcquisitionProgress::Complete(closure) = acquisition
        .on_event(&mut network, &selected, event)
        .unwrap()
    else {
        panic!("leaf closure did not complete before its deadline");
    };
    tokio::time::advance(Duration::from_nanos(2)).await;
    let block = selected.prepare_block(vec![parent_id]).unwrap();
    assert_eq!(
        closure
            .apply_block(&mut selected, &block)
            .unwrap()
            .proof_id(),
        parent_id
    );

    let requested = proof_id(0x94);
    let acquisition = start(&mut network, &selected, peer_id, requested);
    tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
    let event = response_for(&mut network, &acquisition, pairing_bytes());
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, event),
        Err(DependencyAcquisitionError::DeadlineExceeded {
            pending_proof_id,
            ..
        }) if pending_proof_id == requested
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn deadline_precedes_unavailable_malformed_and_ordinary_transport_failure() {
    let directory = TestDirectory::new("deadline-error-precedence");
    let selected = create_journal(directory.path()).unwrap();
    let peer_id = crate::Keypair::generate_ed25519().public().to_peer_id();
    let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id, fallback]);

    for (requested, bytes) in [(proof_id(0xb0), Vec::new()), (proof_id(0xb1), vec![0xff])] {
        let acquisition = start(&mut network, &selected, peer_id, requested);
        tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
        let event = response_for(&mut network, &acquisition, bytes);
        assert!(matches!(
            acquisition.on_event(&mut network, &selected, event),
            Err(DependencyAcquisitionError::DeadlineExceeded {
                pending_proof_id,
                ..
            }) if pending_proof_id == requested
        ));
    }

    let requested = proof_id(0xb2);
    let acquisition = start(&mut network, &selected, peer_id, requested);
    tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
    let event = transport_failure(
        &mut network,
        acquisition.pending_request_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, match event {
            NetworkEvent::OutboundProof(event) => event,
            _ => panic!("deadline did not replace the ordinary transport failure"),
        }),
        Err(DependencyAcquisitionError::DeadlineExceeded {
            pending_proof_id,
            ..
        }) if pending_proof_id == requested
    ));
}

#[tokio::test(start_paused = true)]
async fn equal_deadlines_are_emitted_once_in_request_generation_order() {
    let directory = TestDirectory::new("equal-deadline-order");
    let selected = create_journal(directory.path()).unwrap();
    let peer_ids = (0..2)
        .map(|_| crate::Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peer_ids);
    let first = start(&mut network, &selected, peer_ids[0], proof_id(0xb3));
    let second = start(&mut network, &selected, peer_ids[1], proof_id(0xb4));

    tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
    let NetworkEvent::OutboundProof(first_event) = network
        .take_due_acquisition_deadline(tokio::time::Instant::now())
        .expect("the first equal deadline is due")
    else {
        panic!("deadline did not produce an outbound proof event");
    };
    assert!(first.accepts_event(&first_event));
    assert!(!second.accepts_event(&first_event));

    let NetworkEvent::OutboundProof(second_event) = network
        .take_due_acquisition_deadline(tokio::time::Instant::now())
        .expect("the second equal deadline is due")
    else {
        panic!("deadline did not produce an outbound proof event");
    };
    assert!(second.accepts_event(&second_event));
    assert!(
        network
            .take_due_acquisition_deadline(tokio::time::Instant::now())
            .is_none()
    );
}

#[test]
fn every_dependency_request_inherits_one_control_and_deadline() {
    let (_parent_bytes, _parent_id, root_bytes, root_id) = valid_parent_and_root();
    let directory = TestDirectory::new("one-absolute-deadline");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, root_id);
    let first_control = Arc::clone(acquisition.cancellation.control());
    let deadline = first_control.deadline;
    let event = response_for(&mut network, &acquisition, root_bytes);

    let DependencyAcquisitionProgress::AwaitingResponse(acquisition) = acquisition
        .on_event(&mut network, &selected, event)
        .unwrap()
    else {
        panic!("root dependency was not requested");
    };
    assert!(Arc::ptr_eq(
        &first_control,
        acquisition.cancellation.control()
    ));
    assert_eq!(acquisition.cancellation.control().deadline, deadline);
    assert!(Arc::ptr_eq(
        &network.pending[&acquisition.pending_request_id].control,
        &first_control
    ));
}

#[test]
fn pre_deadline_failure_and_cancelled_peer_mismatch_are_typed() {
    let directory = TestDirectory::new("failure-precedence");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, proof_id(0x95));
    let request_id = acquisition.pending_request_id;
    let event = transport_failure(
        &mut network,
        request_id,
        peer_id,
        request_response::OutboundFailure::ConnectionClosed,
    );
    let NetworkEvent::OutboundProof(event) = event else {
        panic!("active failure was not surfaced");
    };
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, event),
        Err(DependencyAcquisitionError::RequestFailed {
            source,
            ..
        }) if matches!(
            source.as_ref(),
            OutboundProofFailure::Transport(
                request_response::OutboundFailure::ConnectionClosed
            )
        )
    ));

    let requested = proof_id(0x96);
    let acquisition = start(&mut network, &selected, peer_id, requested);
    let request_id = acquisition.pending_request_id;
    acquisition
        .cancellation
        .control()
        .cancelled
        .store(true, Ordering::Relaxed);
    let actual = crate::Keypair::generate_ed25519().public().to_peer_id();
    let event = transport_response(&mut network, request_id, actual, pairing_bytes());
    assert!(matches!(
        event,
        NetworkEvent::CancellationDrained {
            outcome: CancellationDrainOutcome::Failure(source),
            ..
        } if matches!(
            source.as_ref(),
            OutboundProofFailure::PeerMismatch {
                    expected,
                    actual: received,
            } if *expected == peer_id && *received == actual
        )
    ));
    drop(acquisition);
}

#[tokio::test(start_paused = true)]
async fn a_processed_peer_mismatch_outranks_the_acquisition_deadline() {
    let directory = TestDirectory::new("peer-mismatch-deadline");
    let selected = create_journal(directory.path()).unwrap();
    let peer_id = crate::Keypair::generate_ed25519().public().to_peer_id();
    let fallback = crate::Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer_id, fallback]);
    let requested = proof_id(0x98);
    let acquisition = start(&mut network, &selected, peer_id, requested);
    let request_id = acquisition.pending_request_id;
    tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
    let actual = fallback;
    let event = transport_response(&mut network, request_id, actual, pairing_bytes());
    let NetworkEvent::OutboundProof(event) = event else {
        panic!("active peer mismatch was not surfaced");
    };
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, event),
        Err(DependencyAcquisitionError::RequestFailed {
            source,
            ..
        }) if matches!(
            source.as_ref(),
            OutboundProofFailure::PeerMismatch {
                expected,
                actual: received,
            } if *expected == peer_id && *received == actual
        )
    ));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn a_deadline_emitted_first_preserves_later_peer_mismatch_on_drain() {
    let directory = TestDirectory::new("deadline-before-peer-mismatch");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, proof_id(0xb5));
    let request_id = acquisition.pending_request_id;
    tokio::time::advance(DEPENDENCY_ACQUISITION_TIMEOUT).await;
    let deadline = network
        .take_due_acquisition_deadline(tokio::time::Instant::now())
        .expect("the logical deadline is due");

    let actual = crate::Keypair::generate_ed25519().public().to_peer_id();
    assert!(matches!(
        transport_response(&mut network, request_id, actual, pairing_bytes()),
        NetworkEvent::CancellationDrained {
            outcome: CancellationDrainOutcome::Failure(source),
            ..
        } if matches!(
            source.as_ref(),
            OutboundProofFailure::PeerMismatch {
                expected,
                actual: received,
            } if *expected == peer_id && *received == actual
        )
    ));
    let NetworkEvent::OutboundProof(deadline) = deadline else {
        panic!("logical deadline did not produce an outbound proof event");
    };
    assert!(matches!(
        acquisition.on_event(&mut network, &selected, deadline),
        Err(DependencyAcquisitionError::DeadlineExceeded { .. })
    ));
}

#[test]
fn dropping_an_acquisition_tombstones_its_current_generation() {
    let directory = TestDirectory::new("drop-acquisition");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let acquisition = start(&mut network, &selected, peer_id, proof_id(0x99));
    let request_id = acquisition.pending_request_id;
    drop(acquisition);

    assert!(network.pending[&request_id].control.is_cancelled());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    let event = transport_response(&mut network, request_id, peer_id, pairing_bytes());
    assert!(matches!(
        event,
        NetworkEvent::CancellationDrained {
            outcome: CancellationDrainOutcome::ResponseDiscarded,
            ..
        }
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn stale_failure_cannot_consume_a_new_same_address_generation() {
    let directory = TestDirectory::new("stale-failure-generation");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let requested = proof_id(0x9a);
    let old = start(&mut network, &selected, peer_id, requested);
    let event = transport_failure(
        &mut network,
        old.pending_request_id,
        peer_id,
        request_response::OutboundFailure::Timeout,
    );
    let NetworkEvent::OutboundProof(stale) = event else {
        panic!("active failure was not surfaced");
    };
    drop(old);

    let current = start(&mut network, &selected, peer_id, requested);
    let current_request_id = current.pending_request_id;
    assert!(!current.accepts_event(&stale));
    assert!(matches!(
        current.on_event(&mut network, &selected, stale),
        Err(DependencyAcquisitionError::UnexpectedEvent)
    ));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(network.pending.remove(&current_request_id));
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn dropping_the_network_releases_every_tombstoned_permit() {
    let directory = TestDirectory::new("drop-network-tombstones");
    let selected = create_journal(directory.path()).unwrap();
    let (mut network, peer_id) = test_network();
    let budget = Arc::clone(&network.pending_budget);
    start(&mut network, &selected, peer_id, proof_id(0x97)).cancel();
    assert_eq!(budget.active.load(Ordering::Relaxed), 1);
    drop(network);
    assert_eq!(budget.active.load(Ordering::Relaxed), 0);
}
