use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libp2p::request_response;
use libp2p::swarm::ConnectionId;
use naome::chain_head_exchange::{ProofChainHeadRequest, ProofChainHeadResponse};
use naome_chain::{ProofBlockId, ProofChainDefinition, ProofChainId};
use naome_storage::ProofChainJournal;
use tokio::time::timeout;

use super::*;
use crate::tests::{
    TestDirectory, apply_fresh_blocks, assert_snapshot, create_journal, listening_address,
    pairing_bytes, snapshot, test_network_for_peers,
};
use crate::{
    ExchangeRequestId, InboundProofChainHeadRequest, Keypair, PeerSessionEvent, PendingRequest,
    StaticPeer,
};

fn chain_id(byte: u8) -> ProofChainId {
    ProofChainId::from_bytes([byte; 32])
}

fn block_id(byte: u8) -> ProofBlockId {
    ProofBlockId::from_bytes([byte; 32])
}

fn request_id(
    network: &StaticProofNetwork,
    peer_id: PeerId,
) -> request_response::OutboundRequestId {
    let peer_index = network
        .swarm
        .behaviour()
        .sessions
        .peer_index(&peer_id)
        .expect("the survey peer is configured");
    network
        .pending
        .iter()
        .find_map(|(request_id, pending)| match (request_id, pending) {
            (ExchangeRequestId::Head(request_id), PendingRequest::Head(pending))
                if pending.peer_index == peer_index =>
            {
                Some(*request_id)
            }
            _ => None,
        })
        .expect("the peer has one pending head request")
}

fn response_event(
    network: &mut StaticProofNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    head: Option<ProofBlockId>,
) -> NetworkEvent {
    let bytes = head.as_ref().map_or(&[][..], |head| head.as_bytes());
    network
        .handle_head_exchange_event(request_response::Event::Message {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(3_000),
            message: request_response::Message::Response {
                request_id,
                response: ProofChainHeadResponse::from_wire_bytes(bytes).unwrap(),
            },
        })
        .expect("the retained survey request produces one terminal")
}

fn failure_event(
    network: &mut StaticProofNetwork,
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
) -> NetworkEvent {
    network
        .handle_head_exchange_event(request_response::Event::OutboundFailure {
            peer: peer_id,
            connection_id: ConnectionId::new_unchecked(3_001),
            request_id,
            error: request_response::OutboundFailure::Timeout,
        })
        .expect("the retained survey request produces one failure terminal")
}

fn awaiting(progress: ProofChainHeadSurveyProgress) -> ProofChainHeadSurvey {
    let ProofChainHeadSurveyProgress::AwaitingResponses(survey) = progress else {
        panic!("survey completed while selected peers remained pending")
    };
    survey
}

fn complete(progress: ProofChainHeadSurveyProgress) -> CompletedProofChainHeadSurvey {
    let ProofChainHeadSurveyProgress::Complete(survey) = progress else {
        panic!("survey remained pending after all selected peers settled")
    };
    survey
}

async fn serve_and_receive_terminal(
    surveyor: &mut StaticProofNetwork,
    server: &mut StaticProofNetwork,
    inbound: InboundProofChainHeadRequest,
    journal: &ProofChainJournal,
    expected_peer: PeerId,
) -> NetworkEvent {
    server
        .respond_chain_head_from_journal(inbound, journal)
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = surveyor.next_event() => {
                    if let NetworkEvent::OutboundChainHead(terminal) = &event {
                        assert_eq!(terminal.peer_id(), expected_peer);
                        return event;
                    }
                }
                event = server.next_event() => {
                    if let NetworkEvent::InboundChainHeadFailure { error, .. } = event {
                        panic!("served head-survey request failed inbound: {error}")
                    }
                }
            }
        }
    })
    .await
    .expect("served head-survey request did not become terminal")
}

#[test]
fn shape_failures_start_nothing_and_do_not_advance_request_generation() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let request = ProofChainHeadRequest::new(chain_id(0x11));
    let mut control = test_network_for_peers(&[peer]);
    let mut after_failures = test_network_for_peers(&[peer]);

    assert!(matches!(
        after_failures.start_chain_head_survey(&[], request),
        Err(ProofChainHeadSurveyStartError::EmptyPeerSet)
    ));
    let oversized = vec![peer; MAX_STATIC_PEERS + 1];
    assert!(matches!(
        after_failures.start_chain_head_survey(&oversized, request),
        Err(ProofChainHeadSurveyStartError::TooManyPeers { actual, maximum })
            if actual == MAX_STATIC_PEERS + 1 && maximum == MAX_STATIC_PEERS
    ));
    assert!(matches!(
        after_failures.start_chain_head_survey(&[peer, peer], request),
        Err(ProofChainHeadSurveyStartError::DuplicatePeer(actual)) if actual == peer
    ));
    assert!(matches!(
        after_failures.start_chain_head_survey(&[peer, unknown], request),
        Err(ProofChainHeadSurveyStartError::RequestStart(
            RequestStartError::UnknownPeer(actual)
        )) if actual == unknown
    ));
    assert!(after_failures.pending.is_empty());
    assert_eq!(
        after_failures.pending_budget.active.load(Ordering::Relaxed),
        0
    );

    let control_survey = control.start_chain_head_survey(&[peer], request).unwrap();
    let after_survey = after_failures
        .start_chain_head_survey(&[peer], request)
        .unwrap();
    let control_id = request_id(&control, peer);
    let after_id = request_id(&after_failures, peer);
    assert_eq!(control_id, after_id);
    let _ = complete(
        control_survey
            .on_event(failure_event(&mut control, control_id, peer))
            .unwrap(),
    );
    let _ = complete(
        after_survey
            .on_event(failure_event(&mut after_failures, after_id, peer))
            .unwrap(),
    );
}

#[test]
fn ordered_peer_preflight_is_all_or_none() {
    let first = Keypair::generate_ed25519().public().to_peer_id();
    let second = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let request = ProofChainHeadRequest::new(chain_id(0x21));

    let mut unknown_network = test_network_for_peers(&[first]);
    assert!(matches!(
        unknown_network.start_chain_head_survey(&[first, unknown, second], request),
        Err(ProofChainHeadSurveyStartError::RequestStart(
            RequestStartError::UnknownPeer(actual)
        )) if actual == unknown
    ));
    assert!(unknown_network.pending.is_empty());

    let mut disconnected = test_network_for_peers(&[first, second]);
    disconnected
        .swarm
        .behaviour_mut()
        .sessions
        .mark_disconnected_for_test(second);
    assert!(matches!(
        disconnected.start_chain_head_survey(&[first, second], request),
        Err(ProofChainHeadSurveyStartError::RequestStart(
            RequestStartError::PeerDisconnected(actual)
        )) if actual == second
    ));
    assert!(disconnected.pending.is_empty());

    let mut occupied = test_network_for_peers(&[first, second]);
    let ticket = occupied.request_chain_head(second, request).unwrap();
    let occupied_id = request_id(&occupied, second);
    assert!(matches!(
        occupied.start_chain_head_survey(&[first, second], request),
        Err(ProofChainHeadSurveyStartError::RequestStart(
            RequestStartError::AlreadyPending(actual)
        )) if actual == second
    ));
    assert_eq!(occupied.pending.len(), 1);
    let NetworkEvent::OutboundChainHead(event) = failure_event(&mut occupied, occupied_id, second)
    else {
        unreachable!()
    };
    let _ = ticket.complete(event).unwrap();
    assert!(occupied.pending.is_empty());
}

#[test]
fn capacity_is_reserved_atomically_after_peer_preflight() {
    let first = Keypair::generate_ed25519().public().to_peer_id();
    let second = Keypair::generate_ed25519().public().to_peer_id();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[first, second]);
    let request = ProofChainHeadRequest::new(chain_id(0x31));
    let budget = Arc::clone(&network.pending_budget);
    let retained = (0..MAX_PENDING_REQUESTS - 1)
        .map(|_| PendingBudget::try_acquire(&budget).unwrap())
        .collect::<Vec<_>>();

    assert!(matches!(
        network.start_chain_head_survey(&[first, unknown], request),
        Err(ProofChainHeadSurveyStartError::RequestStart(
            RequestStartError::UnknownPeer(actual)
        )) if actual == unknown
    ));
    assert!(matches!(
        network.start_chain_head_survey(&[first, second], request),
        Err(ProofChainHeadSurveyStartError::InsufficientCapacity {
            requested: 2,
            available: 1,
            maximum: MAX_PENDING_REQUESTS,
        })
    ));
    assert!(network.pending.is_empty());
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        MAX_PENDING_REQUESTS - 1
    );
    drop(retained);

    let mut control = test_network_for_peers(&[first, second]);
    let network_survey = network.start_chain_head_survey(&[first], request).unwrap();
    let control_survey = control.start_chain_head_survey(&[first], request).unwrap();
    let network_id = request_id(&network, first);
    let control_id = request_id(&control, first);
    assert_eq!(network_id, control_id);
    let _ = complete(
        network_survey
            .on_event(failure_event(&mut network, network_id, first))
            .unwrap(),
    );
    let _ = complete(
        control_survey
            .on_event(failure_event(&mut control, control_id, first))
            .unwrap(),
    );
}

#[test]
fn reverse_mixed_terminals_preserve_request_and_caller_order() {
    let peers = (0..3)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peers);
    let request = ProofChainHeadRequest::new(chain_id(0x41));
    let mut survey = network.start_chain_head_survey(&peers, request).unwrap();
    let ids = peers
        .iter()
        .map(|&peer| request_id(&network, peer))
        .collect::<Vec<_>>();

    assert_eq!(survey.request(), request);
    assert_eq!(survey.peer_count(), 3);
    assert_eq!(survey.pending_peer_count(), 3);
    let found = response_event(&mut network, ids[2], peers[2], Some(block_id(0x43)));
    assert!(survey.accepts_event(&found));
    survey = awaiting(survey.on_event(found).unwrap());
    assert_eq!(survey.pending_peer_count(), 2);
    let failed = failure_event(&mut network, ids[0], peers[0]);
    assert!(survey.accepts_event(&failed));
    survey = awaiting(survey.on_event(failed).unwrap());
    assert_eq!(survey.pending_peer_count(), 1);
    let unavailable = response_event(&mut network, ids[1], peers[1], None);
    assert!(survey.accepts_event(&unavailable));
    let completed = complete(survey.on_event(unavailable).unwrap());
    assert_eq!(completed.request(), request);
    let rows = completed.peer_results();
    assert_eq!(
        rows.iter().map(|row| row.peer_id()).collect::<Vec<_>>(),
        peers
    );
    assert!(matches!(
        rows[0].result(),
        Err(OutboundProofChainHeadFailure::Transport(
            request_response::OutboundFailure::Timeout
        ))
    ));
    assert_eq!(rows[1].result().unwrap(), None);
    assert_eq!(rows[2].result().unwrap(), Some(block_id(0x43)));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn unrelated_cross_network_and_late_generation_events_remain_routable() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let request = ProofChainHeadRequest::new(chain_id(0x51));
    let mut first_network = test_network_for_peers(&[peer]);
    let mut second_network = test_network_for_peers(&[peer]);
    let first = first_network
        .start_chain_head_survey(&[peer], request)
        .unwrap();
    let second = second_network
        .start_chain_head_survey(&[peer], request)
        .unwrap();
    let first_id = request_id(&first_network, peer);
    let second_id = request_id(&second_network, peer);
    assert_eq!(first_id, second_id);

    let unrelated = NetworkEvent::PeerSession(PeerSessionEvent::Disconnected { peer_id: peer });
    let mismatch = first.on_event(unrelated).unwrap_err();
    let (first, unrelated) = (*mismatch).into_parts();
    assert!(matches!(unrelated, NetworkEvent::PeerSession(_)));

    let second_event = response_event(&mut second_network, second_id, peer, None);
    assert!(!first.accepts_event(&second_event));
    let mismatch = first.on_event(second_event).unwrap_err();
    let (first, second_event) = (*mismatch).into_parts();
    let _ = complete(second.on_event(second_event).unwrap());
    let _ = complete(
        first
            .on_event(response_event(&mut first_network, first_id, peer, None))
            .unwrap(),
    );

    let old = first_network
        .start_chain_head_survey(&[peer], request)
        .unwrap();
    let old_id = request_id(&first_network, peer);
    let old_event = response_event(&mut first_network, old_id, peer, None);
    let current = first_network
        .start_chain_head_survey(&[peer], request)
        .unwrap();
    let current_id = request_id(&first_network, peer);
    assert_ne!(old_id, current_id);
    let mismatch = current.on_event(old_event).unwrap_err();
    let (current, old_event) = (*mismatch).into_parts();
    let _ = complete(old.on_event(old_event).unwrap());
    let _ = complete(
        current
            .on_event(response_event(&mut first_network, current_id, peer, None))
            .unwrap(),
    );
}

#[test]
fn wrong_authenticated_peer_is_one_source_bound_row_failure() {
    let expected = Keypair::generate_ed25519().public().to_peer_id();
    let actual = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[expected, actual]);
    let request = ProofChainHeadRequest::new(chain_id(0x61));
    let survey = network
        .start_chain_head_survey(&[expected], request)
        .unwrap();
    let id = request_id(&network, expected);
    let completed = complete(
        survey
            .on_event(response_event(&mut network, id, actual, None))
            .unwrap(),
    );
    let [row] = completed.peer_results() else {
        panic!("one selected peer produces one row")
    };
    assert_eq!(row.peer_id(), expected);
    assert!(matches!(
        row.result(),
        Err(OutboundProofChainHeadFailure::PeerMismatch {
            expected: retained,
            actual: received,
        }) if *retained == expected && *received == actual
    ));
}

#[test]
fn cancellation_retains_physical_requests_until_each_terminal_drains() {
    let peers = (0..MAX_STATIC_PEERS)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peers);
    let request = ProofChainHeadRequest::new(chain_id(0x71));
    let survey = network.start_chain_head_survey(&peers, request).unwrap();
    let ids = peers
        .iter()
        .map(|&peer| request_id(&network, peer))
        .collect::<Vec<_>>();
    survey.cancel();
    assert_eq!(network.pending.len(), MAX_STATIC_PEERS);
    assert_eq!(
        network.pending_budget.active.load(Ordering::Relaxed),
        MAX_STATIC_PEERS
    );

    for (settled, (&id, &peer)) in ids.iter().zip(&peers).enumerate() {
        let event = failure_event(&mut network, id, peer);
        let remaining = peers.len() - settled - 1;
        assert_eq!(network.pending.len(), remaining);
        assert_eq!(
            network.pending_budget.active.load(Ordering::Relaxed),
            remaining
        );
        drop(event);
    }

    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let mut network = test_network_for_peers(&[peer]);
    let survey = network.start_chain_head_survey(&[peer], request).unwrap();
    let id = request_id(&network, peer);
    drop(survey);
    assert_eq!(network.pending.len(), 1);
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 1);
    drop(failure_event(&mut network, id, peer));
    assert!(network.pending.is_empty());
    assert_eq!(network.pending_budget.active.load(Ordering::Relaxed), 0);
}

#[test]
fn identical_heads_remain_distinct_authenticated_rows() {
    let peers = (0..3)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect::<Vec<_>>();
    let mut network = test_network_for_peers(&peers);
    let request = ProofChainHeadRequest::new(chain_id(0x81));
    let shared_head = block_id(0x82);
    let mut survey = network.start_chain_head_survey(&peers, request).unwrap();
    let ids = peers
        .iter()
        .map(|&peer| request_id(&network, peer))
        .collect::<Vec<_>>();
    for index in 0..2 {
        survey = awaiting(
            survey
                .on_event(response_event(
                    &mut network,
                    ids[index],
                    peers[index],
                    Some(shared_head),
                ))
                .unwrap(),
        );
    }
    let completed = complete(
        survey
            .on_event(response_event(
                &mut network,
                ids[2],
                peers[2],
                Some(shared_head),
            ))
            .unwrap(),
    );
    assert_eq!(completed.peer_results().len(), peers.len());
    for (row, peer) in completed.peer_results().iter().zip(peers) {
        assert_eq!(row.peer_id(), peer);
        assert_eq!(row.result().unwrap(), Some(shared_head));
    }
}

#[tokio::test]
async fn three_real_peers_report_source_bound_heads_without_mutating_any_journal() {
    let mut identities = (0..4)
        .map(|_| Keypair::generate_ed25519())
        .collect::<Vec<_>>();
    identities.sort_by_key(|identity| identity.public().to_peer_id().to_bytes());
    let surveyor_identity = identities.remove(0);
    let empty_identity = identities.remove(0);
    let advanced_identity = identities.remove(0);
    let foreign_identity = identities.remove(0);
    let surveyor_peer = surveyor_identity.public().to_peer_id();
    let empty_peer = empty_identity.public().to_peer_id();
    let advanced_peer = advanced_identity.public().to_peer_id();
    let foreign_peer = foreign_identity.public().to_peer_id();
    let passive_surveyor = StaticPeer::new(surveyor_peer, "/ip4/127.0.0.1/tcp/1".parse().unwrap());

    let mut empty_server =
        StaticProofNetwork::new(empty_identity, [passive_surveyor.clone()]).unwrap();
    let mut advanced_server =
        StaticProofNetwork::new(advanced_identity, [passive_surveyor.clone()]).unwrap();
    let mut foreign_server = StaticProofNetwork::new(foreign_identity, [passive_surveyor]).unwrap();
    let empty_address = listening_address(&mut empty_server).await;
    let advanced_address = listening_address(&mut advanced_server).await;
    let foreign_address = listening_address(&mut foreign_server).await;

    let mut surveyor = StaticProofNetwork::new(
        surveyor_identity,
        [
            StaticPeer::new(empty_peer, empty_address),
            StaticPeer::new(advanced_peer, advanced_address),
            StaticPeer::new(foreign_peer, foreign_address),
        ],
    )
    .unwrap();

    let mut surveyor_established = [false; 3];
    let mut server_established = [false; 3];
    timeout(Duration::from_secs(10), async {
        while !surveyor_established.iter().all(|established| *established)
            || !server_established.iter().all(|established| *established)
        {
            tokio::select! {
                event = surveyor.next_event() => match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) => {
                        let index = [empty_peer, advanced_peer, foreign_peer]
                            .iter()
                            .position(|configured| *configured == peer_id)
                            .expect("surveyor established only a configured server");
                        surveyor_established[index] = true;
                    }
                    NetworkEvent::PeerSession(PeerSessionEvent::DialFailed { peer_id }) => {
                        panic!("managed head-survey dial to {peer_id} failed")
                    }
                    _ => {}
                },
                event = empty_server.next_event(), if !server_established[0] => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        assert_eq!(peer_id, surveyor_peer);
                        server_established[0] = true;
                    }
                },
                event = advanced_server.next_event(), if !server_established[1] => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        assert_eq!(peer_id, surveyor_peer);
                        server_established[1] = true;
                    }
                },
                event = foreign_server.next_event(), if !server_established[2] => {
                    if let NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id }) = event {
                        assert_eq!(peer_id, surveyor_peer);
                        server_established[2] = true;
                    }
                },
            }
        }
    })
    .await
    .expect("four managed head-survey sessions did not establish");

    let surveyor_directory = TestDirectory::new("head-survey-real-surveyor");
    let surveyor_journal = create_journal(surveyor_directory.path()).unwrap();
    let surveyor_before = snapshot(&surveyor_directory, &surveyor_journal);
    let empty_directory = TestDirectory::new("head-survey-real-empty");
    let empty_journal = create_journal(empty_directory.path()).unwrap();
    let empty_before = snapshot(&empty_directory, &empty_journal);
    let advanced_directory = TestDirectory::new("head-survey-real-advanced");
    let mut advanced_journal = create_journal(advanced_directory.path()).unwrap();
    apply_fresh_blocks(&mut advanced_journal, [pairing_bytes()]);
    let advanced_before = snapshot(&advanced_directory, &advanced_journal);
    let foreign_directory = TestDirectory::new("head-survey-real-foreign");
    let foreign_journal = ProofChainJournal::create(
        foreign_directory.path(),
        ProofChainDefinition::new([0x99; 32]),
    )
    .unwrap();
    let foreign_before = snapshot(&foreign_directory, &foreign_journal);

    let request = ProofChainHeadRequest::new(surveyor_journal.chain_id());
    let caller_order = [foreign_peer, advanced_peer, empty_peer];
    let mut survey = surveyor
        .start_chain_head_survey(&caller_order, request)
        .unwrap();

    let mut empty_inbound = None;
    let mut advanced_inbound = None;
    let mut foreign_inbound = None;
    timeout(Duration::from_secs(10), async {
        while empty_inbound.is_none() || advanced_inbound.is_none() || foreign_inbound.is_none() {
            tokio::select! {
                event = surveyor.next_event() => {
                    if let NetworkEvent::OutboundChainHead(event) = event {
                        panic!("unserved head-survey request became terminal: {event:?}")
                    }
                }
                event = empty_server.next_event(), if empty_inbound.is_none() => {
                    if let NetworkEvent::InboundChainHeadRequest(inbound) = event {
                        assert_eq!(inbound.peer_id(), surveyor_peer);
                        assert_eq!(inbound.request(), request);
                        empty_inbound = Some(inbound);
                    }
                }
                event = advanced_server.next_event(), if advanced_inbound.is_none() => {
                    if let NetworkEvent::InboundChainHeadRequest(inbound) = event {
                        assert_eq!(inbound.peer_id(), surveyor_peer);
                        assert_eq!(inbound.request(), request);
                        advanced_inbound = Some(inbound);
                    }
                }
                event = foreign_server.next_event(), if foreign_inbound.is_none() => {
                    if let NetworkEvent::InboundChainHeadRequest(inbound) = event {
                        assert_eq!(inbound.peer_id(), surveyor_peer);
                        assert_eq!(inbound.request(), request);
                        foreign_inbound = Some(inbound);
                    }
                }
            }
        }
    })
    .await
    .expect("three real servers did not receive the shared head request");

    let empty_terminal = serve_and_receive_terminal(
        &mut surveyor,
        &mut empty_server,
        empty_inbound.unwrap(),
        &empty_journal,
        empty_peer,
    )
    .await;
    survey = awaiting(survey.on_event(empty_terminal).unwrap());
    let foreign_terminal = serve_and_receive_terminal(
        &mut surveyor,
        &mut foreign_server,
        foreign_inbound.unwrap(),
        &foreign_journal,
        foreign_peer,
    )
    .await;
    survey = awaiting(survey.on_event(foreign_terminal).unwrap());
    let advanced_terminal = serve_and_receive_terminal(
        &mut surveyor,
        &mut advanced_server,
        advanced_inbound.unwrap(),
        &advanced_journal,
        advanced_peer,
    )
    .await;
    let completed = complete(survey.on_event(advanced_terminal).unwrap());

    let (completed_request, rows) = completed.into_parts();
    assert_eq!(completed_request, request);
    assert_eq!(
        rows.iter().map(|row| row.peer_id()).collect::<Vec<_>>(),
        caller_order
    );
    let mut rows = rows.into_iter();
    let foreign_row = rows.next().unwrap();
    assert_eq!(foreign_row.peer_id(), foreign_peer);
    assert_eq!(foreign_row.into_result().unwrap(), None);
    let advanced_row = rows.next().unwrap();
    assert_eq!(advanced_row.peer_id(), advanced_peer);
    assert_eq!(
        advanced_row.into_result().unwrap(),
        Some(advanced_journal.head_block_id().unwrap())
    );
    let empty_row = rows.next().unwrap();
    assert_eq!(empty_row.peer_id(), empty_peer);
    assert_eq!(
        empty_row.into_result().unwrap(),
        Some(empty_journal.head_block_id().unwrap())
    );
    assert!(rows.next().is_none());
    assert_snapshot(&surveyor_directory, &surveyor_journal, &surveyor_before);
    assert_snapshot(&empty_directory, &empty_journal, &empty_before);
    assert_snapshot(&advanced_directory, &advanced_journal, &advanced_before);
    assert_snapshot(&foreign_directory, &foreign_journal, &foreign_before);
}
