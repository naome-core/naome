use super::codec::{STATE_PROTOCOL, StateCodec};
use super::*;
use libp2p::{
    futures::{executor::block_on, io::Cursor},
    request_response::Codec,
};
use std::time::Duration;
const MAX: usize = STATE_MAX_FRAME_BYTES;
fn context() -> StateContext {
    StateContext::new([1; 32], [2; 32])
}
fn codec() -> StateCodec {
    StateCodec {
        context: Some(context()),
        maximum: MAX,
        global: Some(Arc::new(InboundRetentionBudget::new(4, 8 * MAX))),
        requests: Arc::new(InboundRetentionBudget::new(2, 4 * MAX)),
        responses: Arc::new(InboundRetentionBudget::new(2, 4 * MAX)),
    }
}
#[test]
fn state_codec_rejects_malformed_frames_and_releases_all_custody() {
    let mut codec = codec();
    let bytes = StateRequest::new(
        context(),
        StateRequestBody::Proposal(vec![9; 200].into()),
        MAX,
    )
    .unwrap()
    .to_wire_bytes();
    for cut in 0..bytes.len() {
        assert!(
            block_on(codec.read_request(&STATE_PROTOCOL, &mut Cursor::new(&bytes[..cut]))).is_err()
        );
        assert!(
            InboundRetentionBudget::try_acquire(codec.global.as_ref().unwrap(), 8 * MAX).is_some()
        );
    }
    for offset in [0, 2, 3, 35, 67, 68] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(block_on(codec.read_request(&STATE_PROTOCOL, &mut Cursor::new(bad))).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(block_on(codec.read_request(&STATE_PROTOCOL, &mut Cursor::new(extra))).is_err());
    let a = block_on(codec.read_request(&STATE_PROTOCOL, &mut Cursor::new(&bytes))).unwrap();
    let b = block_on(codec.read_request(&STATE_PROTOCOL, &mut Cursor::new(&bytes))).unwrap();
    assert_eq!(
        block_on(codec.read_request(&STATE_PROTOCOL, &mut Cursor::new(&bytes)))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop((a, b));
    assert!(InboundRetentionBudget::try_acquire(codec.global.as_ref().unwrap(), 8 * MAX).is_some());
    let response = StateResponse::new(
        context(),
        [3; 32],
        StateResponseBody::Proof {
            proof_id: naome_proof::ProofId::from_bytes([4; 32]),
            certificate: vec![1; 200].into(),
        },
        MAX,
    )
    .unwrap()
    .to_wire_bytes();
    for cut in 0..response.len() {
        assert!(
            block_on(codec.read_response(&STATE_PROTOCOL, &mut Cursor::new(&response[..cut])))
                .is_err()
        );
    }
    let retained =
        block_on(codec.read_response(&STATE_PROTOCOL, &mut Cursor::new(response))).unwrap();
    assert!(InboundRetentionBudget::try_acquire(codec.global.as_ref().unwrap(), 8 * MAX).is_none());
    drop(retained);
    assert!(InboundRetentionBudget::try_acquire(codec.global.as_ref().unwrap(), 8 * MAX).is_some());
}
fn fixture() -> (Genesis, Vec<identity::Keypair>) {
    use ed25519_dalek::SigningKey;
    use naome_ledger::{
        AccountId,
        profile::{Profile, STATE_CHECKER_PROFILE, ValidatorRegistration},
    };
    let keys: Vec<_> = (0..4)
        .map(|i| identity::Keypair::ed25519_from_bytes([201 + i; 32]).unwrap())
        .collect();
    let listeners: Vec<_> = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let accounts: Vec<_> = (0..6)
        .map(|i| {
            SigningKey::from_bytes(&[i + 1; 32])
                .verifying_key()
                .to_bytes()
        })
        .collect();
    let validators: Vec<ValidatorRegistration> = (0..4)
        .map(|i| ValidatorRegistration {
            owner: AccountId::for_key(&accounts[i]),
            consensus_key: SigningKey::from_bytes(&[i as u8 + 101; 32])
                .verifying_key()
                .to_bytes(),
            transport_key: SigningKey::from_bytes(&[i as u8 + 201; 32])
                .verifying_key()
                .to_bytes(),
            endpoint: listeners[i].local_addr().unwrap().to_string(),
        })
        .collect();
    let retirement_order = [2, 0, 3, 1].map(|i| validators[i].id()).to_vec();
    (
        Genesis::new(
            Profile::short_test(),
            "naome:zfc".into(),
            STATE_CHECKER_PROFILE.into(),
            naome_ledger::profile::STATE_PROTOCOL_VERSION,
            100,
            [9; 32],
            accounts,
            validators,
            retirement_order,
        )
        .unwrap(),
        keys,
    )
}

fn rotation_fixture() -> (
    LedgerState,
    LedgerState,
    Vec<identity::Keypair>,
    HandoffPlan,
    TimeCertificate,
) {
    use ed25519_dalek::SigningKey;
    use naome_ledger::{AccountId, RecordId, authority::NextPeriodKeys, time::SignedTimeReport};
    let (genesis, _) = fixture();
    let parent = LedgerState::new(genesis);
    let time = TimeCertificate::new(
        (0..3)
            .map(|index| {
                SignedTimeReport::sign(
                    parent.genesis(),
                    parent.authority(),
                    parent.head(),
                    1,
                    parent.time(),
                    &SigningKey::from_bytes(&[index + 101; 32]),
                )
                .unwrap()
            })
            .collect(),
        parent.genesis(),
        parent.authority(),
        parent.head(),
        1,
        parent.time(),
    )
    .unwrap();
    let listeners: Vec<_> = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let keys: Vec<_> = (0..4)
        .map(|index| identity::Keypair::ed25519_from_bytes([index + 171; 32]).unwrap())
        .collect();
    let mut offers = (0..4)
        .map(|index| {
            let owner = SigningKey::from_bytes(&[index + 1; 32]);
            let unit = parent
                .authority()
                .owner(AccountId::for_key(owner.verifying_key().as_bytes()))
                .unwrap();
            NextPeriodKeys::sign(
                parent.authority(),
                parent.head(),
                parent.commitment(),
                unit.id(),
                &owner,
                &SigningKey::from_bytes(&[index + 151; 32]),
                &SigningKey::from_bytes(&[index + 171; 32]),
                listeners[index as usize].local_addr().unwrap().to_string(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    offers.sort_by_key(NextPeriodKeys::unit);
    let plan = HandoffPlan::new(offers, None).unwrap();
    let selected = parent
        .execute(time.clone(), Vec::new(), plan.clone())
        .unwrap()
        .bind_record(RecordId::from_bytes([31; 32]));
    drop(listeners);
    (parent, selected, keys, plan, time)
}

#[tokio::test]
async fn staged_promotion_requires_exact_selected_roster_and_keeps_noise_sessions() {
    use crate::StateTransportPair;
    let (parent, selected, keys, plan, time) = rotation_fixture();
    let mut a = StateNetwork::new_staged(keys[0].clone(), &parent, &plan, &time).unwrap();
    let mut b = StateNetwork::new_staged(keys[1].clone(), &parent, &plan, &time).unwrap();
    for network in [&mut a, &mut b] {
        network
            .listen_on(network.state_listen_address().unwrap().clone())
            .unwrap();
    }
    let (a_id, b_id) = (a.local_peer_id(), b.local_peer_id());
    let mut connected = (false, false);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !connected.0 || !connected.1 {
            tokio::select! {
                event = a.next_event() => if let NetworkEvent::PeerSession(super::super::PeerSessionEvent::Established {peer_id}) = event {
                    connected.0 |= peer_id == b_id;
                },
                event = b.next_event() => if let NetworkEvent::PeerSession(super::super::PeerSessionEvent::Established {peer_id}) = event {
                    connected.1 |= peer_id == a_id;
                },
            }
        }
    })
    .await
    .expect("staged Noise sessions");
    let old = StateNetwork::new_for_parent(
        identity::Keypair::ed25519_from_bytes([201; 32]).unwrap(),
        &parent,
    )
    .unwrap();
    let mut pair = StateTransportPair::new(old).unwrap();
    pair.stage(a).unwrap();
    assert!(!pair.try_promote_selected(&selected));
    pair.retire_old();
    assert!(!pair.try_promote_selected(&parent));
    assert_eq!(
        pair.staged().unwrap().state_lane(),
        Some(StateLane::Handoff)
    );
    assert!(pair.try_promote_selected(&selected));
    assert!(pair.staged().is_none());
    let promoted = pair.active_mut().unwrap();
    assert_eq!(promoted.state_lane(), Some(StateLane::Active));
    assert_eq!(
        promoted.state_authority_id(),
        Some(selected.authority().id())
    );
    assert!(
        promoted
            .swarm
            .behaviour()
            .sessions
            .connection_status_at(
                promoted
                    .swarm
                    .behaviour()
                    .sessions
                    .peer_index(&b_id)
                    .unwrap()
            )
            .unwrap()
    );
    assert_eq!(
        promoted
            .state_exchange
            .as_ref()
            .unwrap()
            .recovery_registry
            .as_ref()
            .unwrap()
            .commitment(),
        selected.commitment()
    );
    assert!(!pair.try_promote_selected(&selected));
    assert!(!b.promote_staged_selected(&parent));
    b.state_exchange
        .as_mut()
        .unwrap()
        .courier_peers
        .insert(a_id);
    assert!(!b.promote_staged_selected(&selected));
    assert_eq!(b.state_lane(), Some(StateLane::Handoff));
}
async fn pair() -> (StateNetwork, StateNetwork) {
    pair_context(false).await
}
async fn pair_context(mismatch: bool) -> (StateNetwork, StateNetwork) {
    let (genesis, keys) = fixture();
    let mut a = StateNetwork::new_state(keys[0].clone(), &genesis).unwrap();
    let other = Genesis::new(
        genesis.profile().clone(),
        genesis.foundation().into(),
        genesis.checker_profile().into(),
        genesis.protocol_version(),
        genesis.start_utc(),
        if mismatch {
            [8; 32]
        } else {
            *genesis.run_nonce()
        },
        genesis.accounts().iter().map(|a| *a.key()).collect(),
        genesis.validators().to_vec(),
        genesis.retirement_order().to_vec(),
    )
    .unwrap();
    let mut b = StateNetwork::new_state(keys[1].clone(), &other).unwrap();
    a.listen_on(a.state_listen_address().unwrap().clone())
        .unwrap();
    b.listen_on(b.state_listen_address().unwrap().clone())
        .unwrap();
    let (pa, pb) = (a.local_peer_id(), b.local_peer_id());
    let (mut ready_a, mut ready_b) = (false, false);
    tokio::time::timeout(Duration::from_secs(10),async {
        while !ready_a || !ready_b {tokio::select! {
            event=a.next_event()=>if let NetworkEvent::PeerSession(super::super::PeerSessionEvent::Established {peer_id})=event {ready_a|=peer_id==pb;},
            event=b.next_event()=>if let NetworkEvent::PeerSession(super::super::PeerSessionEvent::Established {peer_id})=event {ready_b|=peer_id==pa;},
        }}
    }).await.expect("state_exchange Noise pair");
    (a, b)
}
async fn exchange(
    a: &mut StateNetwork,
    b: &mut StateNetwork,
    body: StateResponseBody,
) -> StateEvent {
    let mut body = Some(body);
    tokio::time::timeout(Duration::from_secs(10),async {loop {tokio::select! {
        event=a.next_event()=>if let NetworkEvent::OutboundState(event)=event {return event;},
        event=b.next_event()=>if let NetworkEvent::InboundState(inbound)=event { assert_eq!(inbound.peer_id(),a.local_peer_id()); b.respond_state(inbound,body.take().unwrap()).unwrap(); },
    }}}).await.expect("state_exchange roundtrip")
}
#[tokio::test]
async fn state_real_noise_roundtrip_retained_response_blocks_next_and_resumes() {
    let (mut a, mut b) = pair().await;
    let peer = b.local_peer_id();
    let ticket = a.request_state(peer, StateRequestBody::Handshake).unwrap();
    let event = exchange(&mut a, &mut b, StateResponseBody::Ready).await;
    assert!(ticket.accepts_event(&event));
    let received = ticket.complete(event).unwrap().unwrap();
    assert_eq!(received.response().body(), &StateResponseBody::Ready);
    assert!(matches!(
        a.request_state(peer, StateRequestBody::Handshake),
        Err(StateStartError::Transport(
            RequestStartError::AlreadyPending { .. }
        ))
    ));
    drop(received);
    let ticket = a
        .request_state(peer, StateRequestBody::Proposal(vec![7; 65536].into()))
        .unwrap();
    let event = exchange(&mut a, &mut b, StateResponseBody::Accepted).await;
    assert_eq!(
        ticket.complete(event).unwrap().unwrap().response().body(),
        &StateResponseBody::Accepted
    );
    assert!(
        a.set_state_peer_enabled(
            identity::Keypair::generate_ed25519().public().to_peer_id(),
            true
        )
        .is_err()
    );
    a.set_state_peer_enabled(peer, false).unwrap();
    a.set_state_peer_enabled(peer, true).unwrap();
}
#[tokio::test]
async fn state_unknown_local_identity_fails_closed() {
    use ed25519_dalek::SigningKey;
    use naome_ledger::{AccountId, ResolutionId, operations::JoinIntent};

    let (genesis, _) = fixture();
    let candidate_consensus = SigningKey::from_bytes(&[71; 32]);
    let candidate_transport = SigningKey::from_bytes(&[72; 32]);
    let candidate_endpoint = (43000..43005)
        .map(|port| format!("127.0.0.1:{port}"))
        .find(|endpoint| !genesis.validators().iter().any(|v| v.endpoint == *endpoint))
        .unwrap();
    let intent = JoinIntent::new(
        &genesis,
        AccountId::for_key(genesis.accounts()[4].key()),
        1,
        ResolutionId::from_bytes([88; 32]),
        1,
        &candidate_consensus,
        &candidate_transport,
        candidate_endpoint,
    )
    .unwrap();
    let candidate_identity =
        identity::Keypair::ed25519_from_bytes(candidate_transport.to_bytes()).unwrap();
    assert_eq!(
        state_peer_id(*intent.transport_key()).unwrap(),
        candidate_identity.public().to_peer_id()
    );
    assert!(matches!(
        StateNetwork::new_state(candidate_identity, &genesis),
        Err(StateNetworkBuildError::Identity)
    ));
}

#[tokio::test]
async fn state_wrong_digest_is_terminal_failure_and_stale_ticket_preserves_event() {
    let (mut a, mut b) = pair().await;
    let peer = b.local_peer_id();
    let stale = a.request_state(peer, StateRequestBody::Handshake).unwrap();
    drop(exchange(&mut a, &mut b, StateResponseBody::Ready).await);
    let ticket = a.request_state(peer, StateRequestBody::Handshake).unwrap();
    let event = exchange(&mut a, &mut b, StateResponseBody::Ready).await;
    assert!(!stale.accepts_event(&event));
    let mismatch = stale.complete(event).unwrap_err();
    let (_, event) = mismatch.into_parts();
    assert!(ticket.complete(event).unwrap().is_ok());
    let ticket = a.request_state(peer, StateRequestBody::Handshake).unwrap();
    let event=tokio::time::timeout(Duration::from_secs(10),async {loop {tokio::select! {
        event=a.next_event()=>if let NetworkEvent::OutboundState(event)=event {break event;},
        event=b.next_event()=>if let NetworkEvent::InboundState(inbound)=event {
            let config=b.state_exchange.as_ref().unwrap();
            let response=StateResponse::new(config.context,[255;32],StateResponseBody::Ready,MAX).unwrap();
            let custody=Arc::new(Custody {_global:InboundRetentionBudget::try_acquire(&config.budget,2*response.wire_len()).unwrap(),peer:None});
            b.swarm.behaviour_mut().state_exchange.send_response(inbound.peer,inbound.channel,WireResponse {response,_custody:custody}).unwrap();
        },
    }}}).await.unwrap();
    assert!(matches!(
        ticket.complete(event).unwrap(),
        Err(StateFailure::Correlation)
    ));
}

#[test]
fn state_cancelled_body_read_releases_reserved_bytes_and_context_fails_before_body_read() {
    use libp2p::futures::AsyncRead;
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };
    struct HeaderOnly {
        header: Vec<u8>,
        position: usize,
        body_polls: usize,
    }
    impl AsyncRead for HeaderOnly {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            out: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.position == self.header.len() {
                self.body_polls += 1;
                return Poll::Pending;
            }
            let count = out.len().min(self.header.len() - self.position);
            out[..count].copy_from_slice(&self.header[self.position..self.position + count]);
            self.position += count;
            Poll::Ready(Ok(count))
        }
    }
    let mut codec = codec();
    let bytes = StateRequest::new(
        context(),
        StateRequestBody::Proposal(vec![1; 200].into()),
        MAX,
    )
    .unwrap()
    .to_wire_bytes();
    let mut input = HeaderOnly {
        header: bytes[..STATE_FRAME_HEADER_BYTES].to_vec(),
        position: 0,
        body_polls: 0,
    };
    let budget = Arc::clone(codec.global.as_ref().unwrap());
    let protocol = STATE_PROTOCOL;
    let mut future = Box::pin(codec.read_request(&protocol, &mut input));
    let waker = libp2p::futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert!(InboundRetentionBudget::try_acquire(&budget, 8 * MAX).is_none());
    drop(future);
    assert_eq!(input.body_polls, 1);
    assert!(InboundRetentionBudget::try_acquire(&budget, 8 * MAX).is_some());
    input.header[3] ^= 1;
    input.position = 0;
    input.body_polls = 0;
    assert!(block_on(codec.read_request(&STATE_PROTOCOL, &mut input)).is_err());
    assert_eq!(input.body_polls, 0);
}

#[tokio::test]
async fn state_noise_peer_with_wrong_genesis_never_delivers_application_payload() {
    let (mut a, mut b) = pair_context(true).await;
    let ticket = a
        .request_state(
            b.local_peer_id(),
            StateRequestBody::Proposal(vec![1; 65536].into()),
        )
        .unwrap();
    let terminal=tokio::time::timeout(Duration::from_secs(10),async {loop {tokio::select! {
        event=a.next_event()=>if let NetworkEvent::OutboundState(event)=event {return event;},
        event=b.next_event()=>assert!(!matches!(event,NetworkEvent::InboundState(_))),
    }}}).await.unwrap();
    assert!(matches!(
        ticket.complete(terminal).unwrap(),
        Err(StateFailure::Transport(_))
    ));
}

mod boundary;

mod lifecycle;

#[tokio::test]
async fn stale_peer_ids_can_recover_history_only_after_owner_and_fresh_transport_proof() {
    use ed25519_dalek::SigningKey;
    use naome_ledger::state::LedgerState;
    let transport = SigningKey::from_bytes(&[230; 32]);
    let (genesis, keys) = fixture();
    let selected = LedgerState::new(genesis);
    let client_key = identity::Keypair::ed25519_from_bytes(transport.to_bytes()).unwrap();
    let mut client = StateNetwork::new_recovery_only(client_key, &selected).unwrap();
    assert!(client.state_listen_address().is_none());
    let mut server = StateNetwork::new_for_parent(keys[0].clone(), &selected).unwrap();
    let server_id = server.local_peer_id();
    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkEvent::Listening { address } = server.next_event().await {
                break address;
            }
        }
    })
    .await
    .unwrap();
    let port = address
        .to_string()
        .rsplit('/')
        .next()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let connection = client.dial_recovery(&format!("127.0.0.1:{port}")).unwrap();
    let (mut connected_client, mut connected_server) = (false, false);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !connected_client || !connected_server {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::RecoveryConnected { connection_id, peer_id, initiated_by_us } = event {
                    assert_eq!(connection_id, connection); assert_eq!(peer_id, server_id); assert!(initiated_by_us); connected_client = true;
                },
                event = server.next_event() => if let NetworkEvent::RecoveryConnected { peer_id, initiated_by_us, .. } = event {
                    assert_eq!(peer_id, client.local_peer_id()); assert!(!initiated_by_us); connected_server = true;
                },
            }
        }
    }).await.unwrap();
    assert!(matches!(
        client.request_recovery_state(
            server_id,
            StateRequestBody::History {
                from: 1,
                max_records: 1
            }
        ),
        Err(StateStartError::Lane)
    ));
    assert!(matches!(
        server.request_recovery_evidence_to_owner(
            client.local_peer_id(),
            StateRequestBody::Agreement(vec![1].into()),
        ),
        Err(StateStartError::Lane)
    ));

    let ticket = client
        .request_recovery_state(server_id, StateRequestBody::RecoveryChallenge)
        .unwrap();
    let challenge = tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = client.next_event() => if let NetworkEvent::OutboundState(event) = event {
            let response = ticket.complete(event).unwrap().unwrap();
            if let StateResponseBody::RecoveryNonce(nonce) = response.response().body() { break *nonce; }
            panic!("expected recipient challenge");
        },
        event = server.next_event() => assert!(!matches!(event, NetworkEvent::InboundState(_))),
    }}}).await.unwrap();
    let hello = RecoveryHello::sign(
        client.state_context().unwrap(),
        server_id,
        challenge,
        &SigningKey::from_bytes(&[1; 32]),
        &transport,
    );
    let mut ticket = Some(
        client
            .request_recovery_state(
                server_id,
                StateRequestBody::RecoveryHello(hello.encode().to_vec().into()),
            )
            .unwrap(),
    );
    let (mut accepted, mut authenticated) = (false, false);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !accepted || !authenticated { tokio::select! {
            event = client.next_event() => if let NetworkEvent::OutboundState(event) = event {
                assert_eq!(ticket.take().unwrap().complete(event).unwrap().unwrap().response().body(), &StateResponseBody::Accepted);
                accepted = true;
            },
            event = server.next_event() => if let NetworkEvent::RecoveryAuthenticated { peer_id, owner } = event {
                assert_eq!(peer_id, client.local_peer_id()); assert_eq!(owner, hello.owner()); authenticated = true;
            },
        }}
    }).await.unwrap();
    // Accepting our hello grants only our outbound recovery requests. It does
    // not authenticate the remote recipient as an owner on the local node.
    assert!(client.recovery_grants.is_empty());
    assert!(client.recovery_remote_grants.contains(&server_id));
    assert_eq!(
        server.recovery_grants.get(&client.local_peer_id()),
        Some(&hello.owner())
    );
    assert!(matches!(
        server.request_recovery_state(
            client.local_peer_id(),
            StateRequestBody::Agreement(vec![1].into()),
        ),
        Err(StateStartError::Lane)
    ));
    assert!(matches!(
        server.request_recovery_evidence_to_owner(
            client.local_peer_id(),
            StateRequestBody::History {
                from: 1,
                max_records: 1,
            },
        ),
        Err(StateStartError::Lane)
    ));
    assert!(matches!(
        client.request_recovery_evidence_to_owner(
            server_id,
            StateRequestBody::Agreement(vec![1].into()),
        ),
        Err(StateStartError::Lane)
    ));
    for body in [
        StateRequestBody::Agreement(vec![1].into()),
        StateRequestBody::ReadySignature(vec![2].into()),
        StateRequestBody::TerminalSignature(vec![3].into()),
        StateRequestBody::Finalized(vec![4].into()),
    ] {
        let expected = std::mem::discriminant(&body);
        let reverse = server
            .request_recovery_evidence_to_owner(client.local_peer_id(), body)
            .unwrap();
        let reverse_result = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = client.next_event() => if let NetworkEvent::InboundState(inbound) = event {
                        assert_eq!(inbound.peer_id(), server_id);
                        assert_eq!(inbound.recovery_owner(), None);
                        assert_eq!(std::mem::discriminant(inbound.request().body()), expected);
                        client.respond_state(inbound, StateResponseBody::Accepted).unwrap();
                    },
                    event = server.next_event() => if let NetworkEvent::OutboundState(event) = event {
                        break reverse.complete(event).unwrap().unwrap().response().body().clone();
                    },
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(reverse_result, StateResponseBody::Accepted);
    }
    let first_lease = *server.recovery_leases.get(&client.local_peer_id()).unwrap();
    let repeated = client
        .request_recovery_state(server_id, StateRequestBody::RecoveryChallenge)
        .unwrap();
    let repeated = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::OutboundState(event) = event {
                    break repeated.complete(event).unwrap().unwrap().response().body().clone();
                },
                event = server.next_event() => assert!(!matches!(event, NetworkEvent::RecoveryAuthenticated { .. })),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        repeated,
        StateResponseBody::Rejected(StateRejection::Unauthorized)
    );
    let current_lease = server.recovery_leases.get(&client.local_peer_id()).unwrap();
    assert_eq!(current_lease.idle_deadline, first_lease.idle_deadline);
    assert_eq!(
        current_lease.absolute_deadline,
        first_lease.absolute_deadline
    );
    assert!(matches!(
        client.request_recovery_state(server_id, StateRequestBody::UserAction(vec![1].into())),
        Err(StateStartError::Lane)
    ));
    let idle_before_empty = server
        .recovery_leases
        .get(&client.local_peer_id())
        .unwrap()
        .idle_deadline;
    let ticket = client
        .request_recovery_state(
            server_id,
            StateRequestBody::History {
                from: 1,
                max_records: 1,
            },
        )
        .unwrap();
    let mut response = None;
    tokio::time::timeout(Duration::from_secs(10), async { loop { tokio::select! {
        event = client.next_event() => if let NetworkEvent::OutboundState(event) = event { response = Some(event); break; },
        event = server.next_event() => if let NetworkEvent::InboundState(inbound) = event {
            assert_eq!(inbound.recovery_owner(), Some(hello.owner()));
            assert_eq!(inbound.peer_id(), client.local_peer_id());
            server.respond_state(inbound, StateResponseBody::History(vec![])).unwrap();
        },
    }}}).await.unwrap();
    assert!(
        matches!(ticket.complete(response.unwrap()).unwrap().unwrap().response().body(), StateResponseBody::History(items) if items.is_empty())
    );
    // An empty history response does not prolong a recovery connection. The
    // owner may reconnect later, but it cannot hold both limited slots idle.
    let client_id = client.local_peer_id();
    let lease = server.recovery_leases.get_mut(&client_id).unwrap();
    assert_eq!(lease.idle_deadline, idle_before_empty);
    lease.idle_deadline = Instant::now() - Duration::from_millis(1);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let NetworkEvent::RecoveryDisconnected { peer_id } = server.next_event().await {
                assert_eq!(peer_id, client_id);
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(!server.recovery_grants.contains_key(&client_id));
    assert!(!server.recovery_leases.contains_key(&client_id));
}

#[tokio::test]
async fn recovery_only_server_sends_finality_to_authenticated_owner_without_vote_lane() {
    use ed25519_dalek::SigningKey;
    use naome_ledger::state::LedgerState;

    let (genesis, _) = fixture();
    let selected = LedgerState::new(genesis);
    let client_transport = SigningKey::from_bytes(&[230; 32]);
    let server_transport = SigningKey::from_bytes(&[231; 32]);
    let mut client = StateNetwork::new_recovery_only(
        identity::Keypair::ed25519_from_bytes(client_transport.to_bytes()).unwrap(),
        &selected,
    )
    .unwrap();
    let mut server = StateNetwork::new_recovery_only(
        identity::Keypair::ed25519_from_bytes(server_transport.to_bytes()).unwrap(),
        &selected,
    )
    .unwrap();
    assert!(server.state_listen_address().is_none());
    let server_id = server.local_peer_id();
    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkEvent::Listening { address } = server.next_event().await {
                break address;
            }
        }
    })
    .await
    .unwrap();
    let port = address
        .to_string()
        .rsplit('/')
        .next()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    client.dial_recovery(&format!("127.0.0.1:{port}")).unwrap();
    let (mut client_connected, mut server_connected) = (false, false);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !client_connected || !server_connected {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::RecoveryConnected { peer_id, .. } = event {
                    assert_eq!(peer_id, server_id); client_connected = true;
                },
                event = server.next_event() => if let NetworkEvent::RecoveryConnected { peer_id, .. } = event {
                    assert_eq!(peer_id, client.local_peer_id()); server_connected = true;
                },
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        server.request_recovery_evidence_to_owner(
            client.local_peer_id(),
            StateRequestBody::Finalized(vec![1].into()),
        ),
        Err(StateStartError::Lane)
    ));
    let challenge = client
        .request_recovery_state(server_id, StateRequestBody::RecoveryChallenge)
        .unwrap();
    let nonce = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::OutboundState(event) = event {
                    if let StateResponseBody::RecoveryNonce(nonce) = challenge.complete(event).unwrap().unwrap().response().body() { break *nonce; }
                    panic!("expected challenge nonce");
                },
                event = server.next_event() => assert!(!matches!(event, NetworkEvent::InboundState(_))),
            }
        }
    })
    .await
    .unwrap();
    let hello = RecoveryHello::sign(
        client.state_context().unwrap(),
        server_id,
        nonce,
        &SigningKey::from_bytes(&[1; 32]),
        &client_transport,
    );
    let mut hello_ticket = Some(
        client
            .request_recovery_state(
                server_id,
                StateRequestBody::RecoveryHello(hello.encode().to_vec().into()),
            )
            .unwrap(),
    );
    let (mut accepted, mut authenticated) = (false, false);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !accepted || !authenticated {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::OutboundState(event) = event {
                    assert_eq!(hello_ticket.take().unwrap().complete(event).unwrap().unwrap().response().body(), &StateResponseBody::Accepted);
                    accepted = true;
                },
                event = server.next_event() => if let NetworkEvent::RecoveryAuthenticated { owner, .. } = event {
                    assert_eq!(owner, hello.owner()); authenticated = true;
                },
            }
        }
    })
    .await
    .unwrap();
    for denied in [
        StateRequestBody::Agreement(vec![1].into()),
        StateRequestBody::Proposal(vec![1].into()),
        StateRequestBody::Vote(vec![1].into()),
        StateRequestBody::TimeReport(vec![1].into()),
        StateRequestBody::UserAction(vec![1].into()),
    ] {
        assert!(matches!(
            server.request_recovery_evidence_to_owner(client.local_peer_id(), denied),
            Err(StateStartError::Lane)
        ));
    }
    let finality = server
        .request_recovery_evidence_to_owner(
            client.local_peer_id(),
            StateRequestBody::Finalized(vec![2].into()),
        )
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => if let NetworkEvent::InboundState(inbound) = event {
                    assert_eq!(inbound.peer_id(), server_id);
                    assert_eq!(inbound.recovery_owner(), None);
                    assert!(matches!(inbound.request().body(), StateRequestBody::Finalized(_)));
                    client.respond_state(inbound, StateResponseBody::Accepted).unwrap();
                },
                event = server.next_event() => if let NetworkEvent::OutboundState(event) = event {
                    break finality.complete(event).unwrap().unwrap().response().body().clone();
                },
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(response, StateResponseBody::Accepted);
}

#[test]
fn recovery_hello_rejects_replay_wrong_recipient_and_used_key() {
    use ed25519_dalek::SigningKey;
    use naome_ledger::state::LedgerState;
    let (genesis, keys) = fixture();
    let selected = LedgerState::new(genesis);
    let context = StateContext::new(
        *selected.genesis().id().as_bytes(),
        *selected.genesis().profile().id().as_bytes(),
    );
    let owner = SigningKey::from_bytes(&[1; 32]);
    let fresh = SigningKey::from_bytes(&[230; 32]);
    let remote = state_peer_id(fresh.verifying_key().to_bytes()).unwrap();
    let recipient = keys[0].public().to_peer_id();
    let hello = RecoveryHello::sign(context, recipient, [7; 32], &owner, &fresh);
    assert_eq!(RecoveryHello::decode(&hello.encode()).unwrap(), hello);
    assert_eq!(
        hello.verify(&selected, context, recipient, remote, [7; 32]),
        Ok(hello.owner())
    );
    assert_eq!(
        hello.verify(&selected, context, recipient, remote, [8; 32]),
        Err(RecoveryError::Challenge)
    );
    assert_eq!(
        hello.verify(
            &selected,
            context,
            keys[1].public().to_peer_id(),
            remote,
            [7; 32]
        ),
        Err(RecoveryError::Signature)
    );
    assert_eq!(
        hello.verify(
            &selected,
            context,
            recipient,
            keys[1].public().to_peer_id(),
            [7; 32]
        ),
        Err(RecoveryError::Identity)
    );
    assert!(matches!(
        StateNetwork::new_recovery_only(keys[0].clone(), &selected),
        Err(StateNetworkBuildError::Identity)
    ));
    let used = SigningKey::from_bytes(&[201; 32]);
    let old = RecoveryHello::sign(context, recipient, [7; 32], &owner, &used);
    assert_eq!(
        old.verify(
            &selected,
            context,
            recipient,
            keys[0].public().to_peer_id(),
            [7; 32]
        ),
        Err(RecoveryError::Identity)
    );
}
