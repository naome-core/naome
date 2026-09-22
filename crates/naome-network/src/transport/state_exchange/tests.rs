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
    let validators = (0..4)
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
        )
        .unwrap(),
        keys,
    )
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
    let (genesis, _) = fixture();
    assert!(matches!(
        StateNetwork::new_state(identity::Keypair::generate_ed25519(), &genesis),
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
