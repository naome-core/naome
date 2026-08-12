use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use libp2p::core::{Endpoint, UpgradeInfo, peer_record::PeerRecord};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::swarm::{ConnectionHandler, ConnectionId, NetworkBehaviour};
use libp2p::{StreamProtocol, Swarm, SwarmBuilder, request_response, tcp};
use tokio::time::{Instant, timeout};

use super::*;
use crate::address_store::{BootstrapPeer, PeerAddressStore, SignedPeerRecord};
use crate::bootstrap::{
    AuthenticatedPeerRecordBatch, PeerRecordBootstrapClient, PeerRecordBootstrapEvent,
};
use crate::tests::TestDirectory;
use crate::{INBOUND_AUTH_BURST, INBOUND_AUTH_REFILL_INTERVAL};

#[derive(Clone)]
struct NonemptyRequestCodec;

#[async_trait]
impl request_response::Codec for NonemptyRequestCodec {
    type Protocol = StreamProtocol;
    type Request = ();
    type Response = ();

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        _: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut unexpected = [0_u8; 1];
        io.read_exact(&mut unexpected).await.map(|_| ())
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        _: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[0xff]).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        _: &mut T,
        _: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

#[derive(NetworkBehaviour)]
struct NonemptyClientBehaviour {
    exchange: request_response::Behaviour<NonemptyRequestCodec>,
}

fn nonempty_client(identity: Keypair) -> Swarm<NonemptyClientBehaviour> {
    let exchange = request_response::Behaviour::with_codec(
        NonemptyRequestCodec,
        [(
            PEER_RECORD_PROTOCOL,
            request_response::ProtocolSupport::Outbound,
        )],
        request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT),
    );
    SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(tcp::Config::new(), noise::Config::new, || {
            yamux_config(MAX_PEER_RECORD_STREAMS_PER_CONNECTION)
        })
        .unwrap()
        .with_behaviour(|_| NonemptyClientBehaviour { exchange })
        .unwrap()
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(PEER_RECORD_IDLE_TIMEOUT)
                .with_max_negotiating_inbound_streams(0)
        })
        .with_connection_timeout(CONNECTION_TIMEOUT)
        .build()
}

fn signed_record(identity: &Keypair, address: Multiaddr) -> SignedPeerRecord {
    let record = PeerRecord::new_interop(identity, vec![address]).unwrap();
    SignedPeerRecord::from_envelope_bytes(record.into_signed_envelope().into_protobuf_encoding())
        .unwrap()
}

async fn listening_address(responder: &mut PeerRecordBootstrapResponder) -> Multiaddr {
    responder
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            match responder.next_event().await {
                PeerRecordBootstrapResponderEvent::Listening { address } => return address,
                PeerRecordBootstrapResponderEvent::ListenerError { error, .. } => {
                    panic!("peer-record responder listener failed: {error}")
                }
                PeerRecordBootstrapResponderEvent::ListenerClosed { reason, .. } => {
                    panic!("peer-record responder listener closed: {reason:?}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("peer-record responder did not start listening")
}

async fn receive_and_flush(
    client: &mut PeerRecordBootstrapClient,
    responder: &mut PeerRecordBootstrapResponder,
) -> AuthenticatedPeerRecordBatch {
    timeout(Duration::from_secs(10), async {
        let mut received = None;
        let mut flushed = false;
        loop {
            if let (Some(batch), true) = (received.take(), flushed) {
                return batch;
            }
            tokio::select! {
                event = client.next_event(), if received.is_none() => match event {
                    PeerRecordBootstrapEvent::Received(batch) => received = Some(batch),
                    PeerRecordBootstrapEvent::Failed { error, .. } => {
                        panic!("peer-record pull failed: {error}")
                    }
                },
                event = responder.next_event(), if !flushed => match event {
                    PeerRecordBootstrapResponderEvent::ResponseSent { .. } => flushed = true,
                    PeerRecordBootstrapResponderEvent::Failed { error, .. } => {
                        panic!("peer-record response failed: {error}")
                    }
                    PeerRecordBootstrapResponderEvent::ListenerError { error, .. } => {
                        panic!("peer-record responder listener failed: {error}")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("peer-record exchange timed out")
}

#[tokio::test]
async fn unknown_client_receives_the_fixed_batch_and_persists_responder_provenance() {
    let responder_identity = Keypair::generate_ed25519();
    let responder_peer_id = responder_identity.public().to_peer_id();
    let signer = Keypair::generate_ed25519();
    let signer_peer_id = signer.public().to_peer_id();
    assert_ne!(signer_peer_id, responder_peer_id);
    let record = signed_record(&signer, "/ip4/11.12.13.14/tcp/4001".parse().unwrap());
    let mut responder = PeerRecordBootstrapResponder::new(
        responder_identity,
        PeerRecordBatch::new([record]).unwrap(),
    )
    .unwrap();
    assert_eq!(responder.published_record_count(), 1);
    let address = listening_address(&mut responder).await;

    let client_identity = Keypair::generate_ed25519();
    let client_peer_id = client_identity.public().to_peer_id();
    let bootstrap = BootstrapPeer::new(responder_peer_id, address).unwrap();
    let mut client = PeerRecordBootstrapClient::new(client_identity, [bootstrap.clone()]).unwrap();
    client.start_pull(responder_peer_id).unwrap();
    let batch = receive_and_flush(&mut client, &mut responder).await;
    assert_eq!(batch.source_peer_id(), responder_peer_id);
    assert_eq!(batch.record_count(), 1);

    let directory = TestDirectory::new("responder-provenance");
    let mut store =
        PeerAddressStore::create(directory.path(), client_peer_id, [bootstrap.clone()]).unwrap();
    let received_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let admission = batch.admit_into(&mut store, received_at).unwrap();
    assert_eq!(admission.inserted(), 1);

    client.start_pull(responder_peer_id).unwrap();
    let replay = receive_and_flush(&mut client, &mut responder).await;
    let replayed_at = received_at + Duration::from_secs(86_400);
    let replay_admission = replay.admit_into(&mut store, replayed_at).unwrap();
    assert_eq!(replay_admission.inserted(), 0);
    assert_eq!(replay_admission.replaced(), 0);
    assert_eq!(replay_admission.ignored_stale(), 1);
    assert_eq!(
        store
            .dial_candidates(received_at + crate::PEER_RECORD_TTL - Duration::from_secs(1))
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .dial_candidates(received_at + crate::PEER_RECORD_TTL)
            .unwrap()
            .is_empty(),
        "replay refreshed the local receipt-time TTL"
    );
    drop(store);
    let reopened = PeerAddressStore::open(directory.path(), client_peer_id, [bootstrap]).unwrap();
    let candidates = reopened
        .dial_candidates(received_at + Duration::from_secs(1))
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].peer_id(), signer_peer_id);
    assert_eq!(candidates[0].source_peer_id(), responder_peer_id);
}

#[tokio::test]
async fn immediate_second_pull_reuses_the_authenticated_connection() {
    let responder_identity = Keypair::generate_ed25519();
    let responder_peer_id = responder_identity.public().to_peer_id();
    let mut responder =
        PeerRecordBootstrapResponder::new(responder_identity, PeerRecordBatch::new([]).unwrap())
            .unwrap();
    let address = listening_address(&mut responder).await;
    let bootstrap = BootstrapPeer::new(responder_peer_id, address).unwrap();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), [bootstrap]).unwrap();

    client.start_pull(responder_peer_id).unwrap();
    let first = receive_and_flush(&mut client, &mut responder).await;
    assert!(first.is_empty());
    let first_connection = responder.last_request_connection_id().unwrap();
    drop(first);

    client.start_pull(responder_peer_id).unwrap();
    let second = receive_and_flush(&mut client, &mut responder).await;
    assert!(second.is_empty());
    assert_eq!(
        responder.last_request_connection_id(),
        Some(first_connection)
    );
}

#[tokio::test]
async fn maximum_record_count_roundtrips_through_the_production_client() {
    let records = (0..crate::MAX_PEER_RECORDS_PER_BATCH)
        .map(|index| {
            let identity = Keypair::generate_ed25519();
            signed_record(
                &identity,
                format!(
                    "/ip4/{}.{}.{}.1/tcp/4001",
                    20 + index / 16,
                    index % 16,
                    index
                )
                .parse()
                .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let responder_identity = Keypair::generate_ed25519();
    let responder_peer_id = responder_identity.public().to_peer_id();
    let mut responder = PeerRecordBootstrapResponder::new(
        responder_identity,
        PeerRecordBatch::new(records).unwrap(),
    )
    .unwrap();
    assert_eq!(
        responder.published_record_count(),
        crate::MAX_PEER_RECORDS_PER_BATCH
    );
    let address = listening_address(&mut responder).await;
    let bootstrap = BootstrapPeer::new(responder_peer_id, address).unwrap();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), [bootstrap]).unwrap();
    client.start_pull(responder_peer_id).unwrap();
    let batch = receive_and_flush(&mut client, &mut responder).await;
    assert_eq!(batch.record_count(), crate::MAX_PEER_RECORDS_PER_BATCH);
}

#[tokio::test]
async fn second_connection_from_the_same_authenticated_peer_is_denied() {
    let responder_identity = Keypair::generate_ed25519();
    let responder_peer_id = responder_identity.public().to_peer_id();
    let mut responder =
        PeerRecordBootstrapResponder::new(responder_identity, PeerRecordBatch::new([]).unwrap())
            .unwrap();
    let address = listening_address(&mut responder).await;
    let bootstrap = BootstrapPeer::new(responder_peer_id, address).unwrap();
    let client_identity = Keypair::generate_ed25519();
    let mut first =
        PeerRecordBootstrapClient::new(client_identity.clone(), [bootstrap.clone()]).unwrap();
    let mut second = PeerRecordBootstrapClient::new(client_identity, [bootstrap]).unwrap();

    first.start_pull(responder_peer_id).unwrap();
    let retained_connection = receive_and_flush(&mut first, &mut responder).await;
    drop(retained_connection);
    assert_eq!(responder.swarm.connected_peers().count(), 1);

    second.start_pull(responder_peer_id).unwrap();
    let event = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = second.next_event() => return event,
                _ = responder.next_event() => {}
            }
        }
    })
    .await
    .expect("second same-peer connection did not terminate");
    assert!(matches!(event, PeerRecordBootstrapEvent::Failed { .. }));
    assert_eq!(responder.swarm.connected_peers().count(), 1);
}

#[tokio::test]
async fn exhausted_response_budget_fails_instead_of_returning_empty() {
    let responder_identity = Keypair::generate_ed25519();
    let responder_peer_id = responder_identity.public().to_peer_id();
    let mut responder =
        PeerRecordBootstrapResponder::new(responder_identity, PeerRecordBatch::new([]).unwrap())
            .unwrap();
    let address = listening_address(&mut responder).await;
    let bootstrap = BootstrapPeer::new(responder_peer_id, address).unwrap();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), [bootstrap]).unwrap();

    client.start_pull(responder_peer_id).unwrap();
    let first = receive_and_flush(&mut client, &mut responder).await;
    drop(first);
    responder.response_budget.exhaust(Instant::now());
    client.start_pull(responder_peer_id).unwrap();

    timeout(Duration::from_secs(10), async {
        let mut client_failed = false;
        let mut responder_failed = false;
        while !client_failed || !responder_failed {
            tokio::select! {
                event = client.next_event(), if !client_failed => match event {
                    PeerRecordBootstrapEvent::Failed { .. } => client_failed = true,
                    PeerRecordBootstrapEvent::Received(_) => {
                        panic!("rate rejection became a successful empty response")
                    }
                },
                event = responder.next_event() => match event {
                    PeerRecordBootstrapResponderEvent::Failed { error, .. }
                        if !responder_failed
                            && matches!(
                                error,
                                PeerRecordBootstrapResponderFailure::RateLimited
                            ) => responder_failed = true,
                    PeerRecordBootstrapResponderEvent::Failed { error, .. } => {
                        panic!("unexpected or duplicate responder failure: {error}")
                    }
                    PeerRecordBootstrapResponderEvent::ResponseSent { .. } => {
                        panic!("rate-rejected response was flushed")
                    }
                    _ => {}
                },
            }
        }
    })
    .await
    .expect("rate-rejected pull did not terminate on both peers");
    timeout(Duration::from_secs(10), async {
        while !responder.suppressed_terminals.is_empty() {
            if let libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Exchange(event)) =
                responder.swarm.select_next_some().await
            {
                assert!(
                    responder.handle_exchange_event(event).is_none(),
                    "rate rejection emitted a second public responder terminal"
                );
            }
        }
    })
    .await
    .expect("rate-rejected terminal suppression did not drain");
    assert!(responder.suppressed_terminals.is_empty());
}

#[tokio::test]
async fn nonempty_request_closes_without_consuming_a_response_token() {
    let responder_identity = Keypair::generate_ed25519();
    let responder_peer_id = responder_identity.public().to_peer_id();
    let mut responder =
        PeerRecordBootstrapResponder::new(responder_identity, PeerRecordBatch::new([]).unwrap())
            .unwrap();
    let address = listening_address(&mut responder).await;
    let mut client = nonempty_client(Keypair::generate_ed25519());
    client.behaviour_mut().exchange.send_request_with_addresses(
        &responder_peer_id,
        (),
        vec![address],
    );
    let initial_tokens = responder.response_budget.tokens();

    timeout(Duration::from_secs(10), async {
        let mut client_failed = false;
        let mut responder_failed = false;
        while !client_failed || !responder_failed {
            tokio::select! {
                event = client.select_next_some(), if !client_failed => {
                    if matches!(
                        event,
                        libp2p::swarm::SwarmEvent::Behaviour(
                            NonemptyClientBehaviourEvent::Exchange(
                                request_response::Event::OutboundFailure { .. }
                            )
                        )
                    ) {
                        client_failed = true;
                    }
                }
                event = responder.next_event() => match event {
                    PeerRecordBootstrapResponderEvent::Failed { error, .. }
                        if !responder_failed
                            && matches!(
                                error,
                                PeerRecordBootstrapResponderFailure::InvalidRequest
                            ) => responder_failed = true,
                    PeerRecordBootstrapResponderEvent::Failed { error, .. } => {
                        panic!("unexpected or duplicate responder failure: {error}")
                    }
                    PeerRecordBootstrapResponderEvent::ResponseSent { .. } => {
                        panic!("nonempty request received the publication")
                    }
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("nonempty pull did not terminate on both peers");
    assert_eq!(responder.response_budget.tokens(), initial_tokens);
    assert!(responder.suppressed_terminals.is_empty());
}

#[tokio::test]
async fn one_listener_and_inbound_only_protocol_are_explicit() {
    let identity = Keypair::generate_ed25519();
    let mut responder =
        PeerRecordBootstrapResponder::new(identity, PeerRecordBatch::new([]).unwrap()).unwrap();
    responder
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    assert!(matches!(
        responder.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        Err(PeerRecordBootstrapResponderListenError::AlreadyListening)
    ));

    let remote_identity = Keypair::generate_ed25519();
    let remote_peer_id = remote_identity.public().to_peer_id();
    let local_address: Multiaddr = "/ip4/127.0.0.1/tcp/39002".parse().unwrap();
    let remote_address: Multiaddr = "/ip4/127.0.0.1/tcp/39003".parse().unwrap();
    let handler = NetworkBehaviour::handle_established_inbound_connection(
        responder.swarm.behaviour_mut(),
        ConnectionId::new_unchecked(900),
        remote_peer_id,
        &local_address,
        &remote_address,
    )
    .unwrap();
    let protocols = handler
        .listen_protocol()
        .upgrade()
        .protocol_info()
        .map(|protocol| protocol.to_string())
        .collect::<Vec<_>>();
    assert_eq!(protocols, [PEER_RECORD_PROTOCOL.to_string()]);
    assert!(
        NetworkBehaviour::handle_pending_outbound_connection(
            responder.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(901),
            Some(remote_peer_id),
            &[],
            Endpoint::Dialer,
        )
        .is_err()
    );

    assert!(responder.remove_listener_for_test());
    let closed_listener = timeout(Duration::from_secs(10), async {
        loop {
            if let PeerRecordBootstrapResponderEvent::ListenerClosed { listener_id, .. } =
                responder.next_event().await
            {
                return listener_id;
            }
        }
    })
    .await
    .expect("removed responder listener did not close");
    assert!(
        responder
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .is_ok(),
        "exact listener closure did not release the one-listener slot"
    );
    assert_ne!(responder.listener_id, Some(closed_listener));
}

#[test]
fn response_budget_has_exact_burst_and_lazy_refill() {
    let start = Instant::now();
    let mut budget = TokenBucket::new(RESPONSE_BURST, RESPONSE_REFILL_INTERVAL, start);
    for _ in 0..RESPONSE_BURST {
        assert!(budget.try_take(start));
    }
    assert!(!budget.try_take(start));
    assert!(!budget.try_take(start + RESPONSE_REFILL_INTERVAL - Duration::from_nanos(1)));
    assert!(budget.try_take(start + RESPONSE_REFILL_INTERVAL));
    assert!(!budget.try_take(start + RESPONSE_REFILL_INTERVAL));
    assert!(budget.try_take(start + RESPONSE_REFILL_INTERVAL * 9));
    assert_eq!(budget.tokens(), RESPONSE_BURST - 1);
}

#[test]
fn responder_limits_match_the_v0_contract() {
    assert_eq!(MAX_RESPONDER_CONNECTIONS, 8);
    assert_eq!(INBOUND_AUTH_BURST, 8);
    assert_eq!(INBOUND_AUTH_REFILL_INTERVAL, Duration::from_secs(1));
    assert_eq!(RESPONSE_BURST, 8);
    assert_eq!(RESPONSE_REFILL_INTERVAL, Duration::from_secs(1));
    assert_eq!(MAX_PEER_RECORD_STREAMS_PER_CONNECTION, 1);
    assert_eq!(PEER_RECORD_IDLE_TIMEOUT, Duration::from_secs(10));
}

#[tokio::test(start_paused = true)]
async fn pre_authentication_gate_has_exact_burst_and_refill() {
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/39004".parse().unwrap();
    let mut gate = PreAuthenticationGate::new(Instant::now());
    for index in 0..INBOUND_AUTH_BURST {
        assert!(
            NetworkBehaviour::handle_pending_inbound_connection(
                &mut gate,
                ConnectionId::new_unchecked(1_000 + usize::try_from(index).unwrap()),
                &address,
                &address,
            )
            .is_ok()
        );
    }
    assert!(
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut gate,
            ConnectionId::new_unchecked(1_100),
            &address,
            &address,
        )
        .is_err()
    );
    tokio::time::advance(INBOUND_AUTH_REFILL_INTERVAL).await;
    assert!(
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut gate,
            ConnectionId::new_unchecked(1_101),
            &address,
            &address,
        )
        .is_ok()
    );
    assert!(
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut gate,
            ConnectionId::new_unchecked(1_102),
            &address,
            &address,
        )
        .is_err()
    );
}

#[tokio::test]
async fn connection_limit_rejection_does_not_consume_pre_authentication_budget() {
    let mut responder = PeerRecordBootstrapResponder::new(
        Keypair::generate_ed25519(),
        PeerRecordBatch::new([]).unwrap(),
    )
    .unwrap();
    let address: Multiaddr = "/ip4/127.0.0.1/tcp/39005".parse().unwrap();

    for index in 0..MAX_RESPONDER_CONNECTIONS {
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut responder.swarm.behaviour_mut().limits,
            ConnectionId::new_unchecked(1_200 + index),
            &address,
            &address,
        )
        .unwrap();
    }
    let tokens_before = responder
        .swarm
        .behaviour()
        .pre_authentication
        .budget
        .tokens();
    assert_eq!(tokens_before, INBOUND_AUTH_BURST);

    assert!(
        NetworkBehaviour::handle_pending_inbound_connection(
            responder.swarm.behaviour_mut(),
            ConnectionId::new_unchecked(1_200 + MAX_RESPONDER_CONNECTIONS),
            &address,
            &address,
        )
        .is_err()
    );
    assert_eq!(
        responder
            .swarm
            .behaviour()
            .pre_authentication
            .budget
            .tokens(),
        tokens_before
    );
}
