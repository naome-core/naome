use std::time::{Duration, SystemTime};

use libp2p::core::{Endpoint, UpgradeInfo, peer_record::PeerRecord, transport::PortUse};
use libp2p::futures::StreamExt;
use libp2p::swarm::{ConnectionHandler, ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{Swarm, SwarmBuilder, connection_limits, request_response, tcp};
use tokio::time::timeout;

use super::*;
use crate::Multiaddr;
use crate::address_store::SignedPeerRecord;
use crate::tests::TestDirectory;

#[derive(NetworkBehaviour)]
struct ServerBehaviour {
    limits: connection_limits::Behaviour,
    exchange: request_response::Behaviour<PeerRecordCodec>,
}

struct TestServer {
    swarm: Swarm<ServerBehaviour>,
}

impl TestServer {
    fn new(identity: Keypair) -> Self {
        let maximum = u32::try_from(MAX_BOOTSTRAP_PEERS).unwrap();
        let limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(maximum))
                .with_max_pending_outgoing(Some(0))
                .with_max_established_incoming(Some(maximum))
                .with_max_established_outgoing(Some(0))
                .with_max_established(Some(maximum))
                .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER)),
        );
        let exchange = request_response::Behaviour::with_codec(
            PeerRecordCodec,
            [(
                PEER_RECORD_PROTOCOL,
                request_response::ProtocolSupport::Inbound,
            )],
            request_response::Config::default()
                .with_request_timeout(REQUEST_TIMEOUT)
                .with_max_concurrent_streams(1),
        );
        let behaviour = ServerBehaviour { limits, exchange };
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(tcp::Config::new(), noise::Config::new, || {
                yamux_config(MAX_BOOTSTRAP_STREAMS_PER_CONNECTION)
            })
            .unwrap()
            .with_behaviour(|_| behaviour)
            .unwrap()
            .with_swarm_config(|config| {
                config
                    .with_idle_connection_timeout(BOOTSTRAP_IDLE_TIMEOUT)
                    .with_max_negotiating_inbound_streams(MAX_BOOTSTRAP_STREAMS_PER_CONNECTION)
            })
            .with_connection_timeout(CONNECTION_TIMEOUT)
            .build();
        Self { swarm }
    }

    async fn listen(&mut self) -> Multiaddr {
        self.swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        timeout(Duration::from_secs(10), async {
            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => return address,
                    SwarmEvent::ListenerError { error, .. } => {
                        panic!("bootstrap test listener failed: {error}")
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("bootstrap test listener did not start")
    }
}

fn signed_record(identity: &Keypair, address: Multiaddr) -> SignedPeerRecord {
    let record = PeerRecord::new_interop(identity, vec![address]).unwrap();
    SignedPeerRecord::from_envelope_bytes(record.into_signed_envelope().into_protobuf_encoding())
        .unwrap()
}

async fn receive(
    client: &mut PeerRecordBootstrapClient,
    server: &mut TestServer,
    response: PeerRecordBatch,
) -> PeerRecordBootstrapEvent {
    timeout(Duration::from_secs(10), async {
        let mut response = Some(response);
        loop {
            tokio::select! {
                event = client.next_event() => return event,
                event = server.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(ServerBehaviourEvent::Exchange(
                        request_response::Event::Message {
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        },
                    )) = event {
                        assert_eq!(request, PeerRecordPullRequest);
                        server
                            .swarm
                            .behaviour_mut()
                            .exchange
                            .send_response(channel, response.take().expect("one request expected"))
                            .unwrap();
                    }
                }
            }
        }
    })
    .await
    .expect("bootstrap pull timed out")
}

#[tokio::test]
async fn authenticated_batch_keeps_its_source_through_atomic_admission_and_reopen() {
    let server_identity = Keypair::generate_ed25519();
    let server_peer_id = server_identity.public().to_peer_id();
    let mut server = TestServer::new(server_identity);
    let server_address = server.listen().await;

    let client_identity = Keypair::generate_ed25519();
    let client_peer_id = client_identity.public().to_peer_id();
    let configured = BootstrapPeer::new(server_peer_id, server_address.clone()).unwrap();
    let mut client = PeerRecordBootstrapClient::new(client_identity, [configured.clone()]).unwrap();
    assert_eq!(client.bootstrap_peers(), std::slice::from_ref(&configured));
    client.start_pull(server_peer_id).unwrap();

    let record_identity = Keypair::generate_ed25519();
    let record = signed_record(&record_identity, "/ip4/11.2.3.4/tcp/4001".parse().unwrap());
    let event = receive(
        &mut client,
        &mut server,
        PeerRecordBatch::new([record]).unwrap(),
    )
    .await;
    let PeerRecordBootstrapEvent::Received(batch) = event else {
        panic!("expected one authenticated batch")
    };
    assert_eq!(batch.source_peer_id(), server_peer_id);
    assert_eq!(batch.record_count(), 1);
    assert_eq!(client.active_source_count(), 1);
    assert_eq!(
        client.start_pull(server_peer_id),
        Err(PeerRecordPullStartError::AlreadyActiveOrRetained(
            server_peer_id
        ))
    );

    let directory = TestDirectory::new("admission");
    let decoy_identity = Keypair::generate_ed25519();
    let decoy = BootstrapPeer::new(
        decoy_identity.public().to_peer_id(),
        "/ip4/127.0.0.1/tcp/4002".parse().unwrap(),
    )
    .unwrap();
    let mut store = PeerAddressStore::create(
        directory.path(),
        client_peer_id,
        [decoy.clone(), configured.clone()],
    )
    .unwrap();
    let admitted = batch.admit_into(&mut store, SystemTime::now()).unwrap();
    assert_eq!(admitted.inserted(), 1);
    assert_eq!(client.active_source_count(), 0);
    assert_eq!(store.len().unwrap(), 1);
    drop(store);
    let reopened =
        PeerAddressStore::open(directory.path(), client_peer_id, [decoy, configured]).unwrap();
    assert_eq!(reopened.len().unwrap(), 1);
    let candidates = reopened.dial_candidates(SystemTime::now()).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].source_peer_id(), server_peer_id);
}

#[tokio::test]
async fn pull_uses_the_requested_nonfirst_bootstrap_address_and_identity() {
    let left = Keypair::generate_ed25519();
    let right = Keypair::generate_ed25519();
    let (first_identity, second_identity) =
        if left.public().to_peer_id().to_bytes() < right.public().to_peer_id().to_bytes() {
            (left, right)
        } else {
            (right, left)
        };
    let first_peer_id = first_identity.public().to_peer_id();
    let second_peer_id = second_identity.public().to_peer_id();
    let mut first_server = TestServer::new(first_identity);
    let mut second_server = TestServer::new(second_identity);
    let first_address = first_server.listen().await;
    let second_address = second_server.listen().await;
    assert_ne!(first_address, second_address);

    let first = BootstrapPeer::new(first_peer_id, first_address).unwrap();
    let second = BootstrapPeer::new(second_peer_id, second_address).unwrap();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), [second, first]).unwrap();
    assert_eq!(client.bootstrap_peers()[0].peer_id(), first_peer_id);
    assert_eq!(client.bootstrap_peers()[1].peer_id(), second_peer_id);
    client.start_pull(second_peer_id).unwrap();

    let event = timeout(Duration::from_secs(10), async {
        let mut response = Some(PeerRecordBatch::new([]).unwrap());
        loop {
            tokio::select! {
                event = client.next_event() => return event,
                event = first_server.swarm.select_next_some() => {
                    if matches!(
                        event,
                        SwarmEvent::Behaviour(ServerBehaviourEvent::Exchange(
                            request_response::Event::Message {
                                message: request_response::Message::Request { .. },
                                ..
                            },
                        ))
                    ) {
                        panic!("the requested second source used the first source address")
                    }
                }
                event = second_server.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(ServerBehaviourEvent::Exchange(
                        request_response::Event::Message {
                            message: request_response::Message::Request { request, channel, .. },
                            ..
                        },
                    )) = event {
                        assert_eq!(request, PeerRecordPullRequest);
                        second_server
                            .swarm
                            .behaviour_mut()
                            .exchange
                            .send_response(
                                channel,
                                response.take().expect("one request expected"),
                            )
                            .unwrap();
                    }
                }
            }
        }
    })
    .await
    .expect("non-first bootstrap pull timed out");
    let PeerRecordBootstrapEvent::Received(batch) = event else {
        panic!("expected a response from the requested second source")
    };
    assert_eq!(batch.source_peer_id(), second_peer_id);
}

#[tokio::test]
async fn retained_and_dropped_empty_batches_hold_then_release_the_source_slot() {
    let server_identity = Keypair::generate_ed25519();
    let server_peer_id = server_identity.public().to_peer_id();
    let mut server = TestServer::new(server_identity);
    let server_address = server.listen().await;
    let configured = BootstrapPeer::new(server_peer_id, server_address).unwrap();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), [configured]).unwrap();

    client.start_pull(server_peer_id).unwrap();
    let event = receive(&mut client, &mut server, PeerRecordBatch::new([]).unwrap()).await;
    let PeerRecordBootstrapEvent::Received(batch) = event else {
        panic!("expected an empty authenticated batch")
    };
    assert!(batch.is_empty());
    assert_eq!(client.active_source_count(), 1);
    drop(batch);
    assert_eq!(client.active_source_count(), 0);
    client.start_pull(server_peer_id).unwrap();
    let event = receive(&mut client, &mut server, PeerRecordBatch::new([]).unwrap()).await;
    let PeerRecordBootstrapEvent::Received(batch) = event else {
        panic!("expected another empty authenticated batch")
    };
    let directory = TestDirectory::new("admission-error");
    let mut store = PeerAddressStore::create(directory.path(), client.local_peer_id(), []).unwrap();
    assert!(matches!(
        batch.admit_into(&mut store, SystemTime::now()),
        Err(PeerAddressStoreError::UnknownSource(_))
    ));
    assert!(store.is_empty().unwrap());
    assert_eq!(client.active_source_count(), 0);
}

#[tokio::test]
async fn wrong_noise_identity_fails_and_releases_the_source_slot() {
    let actual_identity = Keypair::generate_ed25519();
    let mut server = TestServer::new(actual_identity);
    let server_address = server.listen().await;
    let expected_identity = Keypair::generate_ed25519();
    let expected_peer_id = expected_identity.public().to_peer_id();
    let configured = BootstrapPeer::new(expected_peer_id, server_address).unwrap();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), [configured]).unwrap();

    client.start_pull(expected_peer_id).unwrap();
    let event = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = client.next_event() => return event,
                _ = server.swarm.select_next_some() => {}
            }
        }
    })
    .await
    .expect("wrong-identity pull did not terminate");
    assert!(matches!(
        event,
        PeerRecordBootstrapEvent::Failed {
            bootstrap_peer_id,
            error,
        } if bootstrap_peer_id == expected_peer_id
            && matches!(*error, PeerRecordPullFailure::Transport(_))
    ));
    assert_eq!(client.active_source_count(), 0);
    client.start_pull(expected_peer_id).unwrap();
}

#[test]
fn client_connection_handler_advertises_no_inbound_protocol() {
    let remote = Keypair::generate_ed25519();
    let remote_peer_id = remote.public().to_peer_id();
    let remote_address: Multiaddr = "/ip4/127.0.0.1/tcp/39000".parse().unwrap();
    let configured = BootstrapPeer::new(remote_peer_id, remote_address.clone()).unwrap();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), [configured]).unwrap();
    let handler = NetworkBehaviour::handle_established_outbound_connection(
        &mut client.swarm.behaviour_mut().exchange,
        ConnectionId::new_unchecked(600),
        remote_peer_id,
        &remote_address,
        Endpoint::Dialer,
        PortUse::New,
    )
    .unwrap();
    assert_eq!(
        handler.listen_protocol().upgrade().protocol_info().count(),
        0
    );
}

#[tokio::test]
async fn start_checks_unknown_then_retained_source_without_a_second_counter() {
    let local = Keypair::generate_ed25519();
    let bootstraps = (0..MAX_BOOTSTRAP_PEERS)
        .map(|index| {
            let identity = Keypair::generate_ed25519();
            let peer_id = identity.public().to_peer_id();
            BootstrapPeer::new(
                peer_id,
                format!("/ip4/127.0.0.1/tcp/{}", 30_000 + index)
                    .parse()
                    .unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let peer_ids = bootstraps
        .iter()
        .map(BootstrapPeer::peer_id)
        .collect::<Vec<_>>();
    let mut client = PeerRecordBootstrapClient::new(local, bootstraps).unwrap();
    let unknown = Keypair::generate_ed25519().public().to_peer_id();
    assert_eq!(
        client.start_pull(unknown),
        Err(PeerRecordPullStartError::UnknownBootstrap(unknown))
    );
    assert_eq!(client.active_source_count(), 0);

    for peer_id in &peer_ids {
        client.start_pull(*peer_id).unwrap();
    }
    assert_eq!(client.active_source_count(), MAX_BOOTSTRAP_PEERS as u32);
    assert_eq!(
        client.start_pull(peer_ids[0]),
        Err(PeerRecordPullStartError::AlreadyActiveOrRetained(
            peer_ids[0]
        ))
    );
}

#[tokio::test]
async fn exact_request_and_peer_correlation_cannot_consume_another_generation() {
    let expected_identity = Keypair::generate_ed25519();
    let expected_peer_id = expected_identity.public().to_peer_id();
    let configured = BootstrapPeer::new(
        expected_peer_id,
        "/ip4/127.0.0.1/tcp/39001".parse().unwrap(),
    )
    .unwrap();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), [configured]).unwrap();
    client.start_pull(expected_peer_id).unwrap();
    let old_request_id = client.pending[0].request_id;
    let old = client.take_pending(old_request_id).unwrap();
    drop(old);
    client.start_pull(expected_peer_id).unwrap();
    let current_request_id = client.pending[0].request_id;
    assert_ne!(old_request_id, current_request_id);

    assert!(
        client
            .handle_exchange_event(request_response::Event::Message {
                peer: expected_peer_id,
                connection_id: ConnectionId::new_unchecked(700),
                message: request_response::Message::Response {
                    request_id: old_request_id,
                    response: PeerRecordBatch::new([]).unwrap(),
                },
            })
            .is_none()
    );
    assert_eq!(client.pending.len(), 1);
    assert_eq!(client.pending[0].request_id, current_request_id);
    assert_eq!(client.active_source_count(), 1);

    let wrong_peer = Keypair::generate_ed25519().public().to_peer_id();
    assert!(matches!(
        client.handle_exchange_event(request_response::Event::Message {
            peer: wrong_peer,
            connection_id: ConnectionId::new_unchecked(701),
            message: request_response::Message::Response {
                request_id: current_request_id,
                response: PeerRecordBatch::new([]).unwrap(),
            },
        }),
        Some(PeerRecordBootstrapEvent::Failed {
            bootstrap_peer_id,
            error,
        }) if bootstrap_peer_id == expected_peer_id
            && matches!(
                *error,
                PeerRecordPullFailure::PeerMismatch { expected, actual }
                    if expected == expected_peer_id && actual == wrong_peer
            )
    ));
    assert!(client.pending.is_empty());
    assert_eq!(client.active_source_count(), 0);
}

#[tokio::test]
async fn eight_delivered_batches_retain_exactly_eight_source_slots() {
    let bootstraps = (0..MAX_BOOTSTRAP_PEERS)
        .map(|index| {
            let identity = Keypair::generate_ed25519();
            BootstrapPeer::new(
                identity.public().to_peer_id(),
                format!("/ip4/127.0.0.1/tcp/{}", 39_100 + index)
                    .parse()
                    .unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let peer_ids = bootstraps
        .iter()
        .map(BootstrapPeer::peer_id)
        .collect::<Vec<_>>();
    let mut client =
        PeerRecordBootstrapClient::new(Keypair::generate_ed25519(), bootstraps).unwrap();
    for peer_id in &peer_ids {
        client.start_pull(*peer_id).unwrap();
    }

    let terminals = client
        .pending
        .iter()
        .map(|pending| {
            let peer_id = client.bootstraps[pending.permit.source_index()].peer_id();
            (pending.request_id, peer_id)
        })
        .collect::<Vec<_>>();
    let mut received = Vec::new();
    for (index, (request_id, peer_id)) in terminals.into_iter().enumerate() {
        let event = client
            .handle_exchange_event(request_response::Event::Message {
                peer: peer_id,
                connection_id: ConnectionId::new_unchecked(800 + index),
                message: request_response::Message::Response {
                    request_id,
                    response: PeerRecordBatch::new([]).unwrap(),
                },
            })
            .unwrap();
        let PeerRecordBootstrapEvent::Received(batch) = event else {
            panic!("expected an authenticated batch")
        };
        received.push(batch);
    }
    assert!(client.pending.is_empty());
    assert_eq!(client.active_source_count(), MAX_BOOTSTRAP_PEERS as u32);
    for peer_id in &peer_ids {
        assert_eq!(
            client.start_pull(*peer_id),
            Err(PeerRecordPullStartError::AlreadyActiveOrRetained(*peer_id))
        );
    }
    received.pop();
    assert_eq!(
        client.active_source_count(),
        u32::try_from(MAX_BOOTSTRAP_PEERS - 1).unwrap()
    );
    client
        .start_pull(peer_ids[MAX_BOOTSTRAP_PEERS - 1])
        .unwrap();
}
