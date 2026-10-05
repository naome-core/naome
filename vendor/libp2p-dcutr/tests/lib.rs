// Copyright 2021 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{collections::HashSet, time::Duration};

use libp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    transport::{upgrade::Version, MemoryTransport, Transport},
    ConnectedPoint,
};
use libp2p_dcutr as dcutr;
use libp2p_identify as identify;
use libp2p_identity as identity;
use libp2p_identity::PeerId;
use libp2p_plaintext as plaintext;
use libp2p_relay as relay;
use libp2p_swarm::{Config, ConnectionId, NetworkBehaviour, Swarm, SwarmEvent};
use libp2p_swarm_test::SwarmExt as _;
use tracing_subscriber::EnvFilter;

#[tokio::test]
async fn connect() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut relay = build_relay();
    let mut dst = build_client();
    let mut src = build_client();

    // Have all swarms listen on a local TCP address.
    let (_, relay_tcp_addr) = relay.listen().with_tcp_addr_external().await;
    let (_, dst_tcp_addr) = dst.listen().await;
    let (_, src_tcp_addr) = src.listen().await;

    assert!(src.external_addresses().next().is_none());
    assert!(dst.external_addresses().next().is_none());

    let relay_peer_id = *relay.local_peer_id();
    let dst_peer_id = *dst.local_peer_id();

    tokio::spawn(relay.loop_on_next());

    let dst_relayed_addr = relay_tcp_addr
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(dst_peer_id));
    dst.listen_on(dst_relayed_addr.clone()).unwrap();

    wait_for_reservation(
        &mut dst,
        dst_relayed_addr.clone(),
        relay_peer_id,
        false, // No renewal.
    )
    .await;
    tokio::spawn(dst.loop_on_next());

    let dst_addr = dst_tcp_addr.with(Protocol::P2p(dst_peer_id));
    src.dial(dst_relayed_addr.clone()).unwrap();
    let mut observed = UpgradeEvents::default();
    let mut recent = std::collections::VecDeque::new();
    let completed = {
        let result = futures::future::select(
            futures_timer::Delay::new(Duration::from_secs(10)),
            Box::pin(async {
                loop {
                    let event = src.next_swarm_event().await;
                    eprintln!("dcutr_connect_event={event:?}");
                    if recent.len() == 32 {
                        recent.pop_front();
                    }
                    recent.push_back(format!("{event:?}"));
                    if let SwarmEvent::Behaviour(ClientEvent::Dcutr(dcutr::Event {
                        remote_peer_id,
                        result: Err(error),
                    })) = &event
                    {
                        if *remote_peer_id == dst_peer_id {
                            panic!("native DCUtR upgrade failed: {error}; recent={recent:?}");
                        }
                    }
                    observed.record(
                        &event,
                        dst_peer_id,
                        &dst_relayed_addr,
                        &dst_addr,
                        &src_tcp_addr,
                    );
                    if let Some(connection) = observed.complete() {
                        return connection;
                    }
                }
            }),
        )
        .await;
        match result {
            futures::future::Either::Right(_) => true,
            futures::future::Either::Left(((), pending)) => {
                drop(pending);
                false
            }
        }
    };
    assert!(
        completed,
        "DCUtR circuit/direct/success contract incomplete after 10s: {observed:?}; recent={recent:?}"
    );
}

#[derive(Debug, Default)]
struct UpgradeEvents {
    circuit: bool,
    direct: HashSet<ConnectionId>,
    reported: Option<ConnectionId>,
}

impl UpgradeEvents {
    fn record(
        &mut self,
        event: &SwarmEvent<ClientEvent>,
        expected_peer: PeerId,
        circuit_addr: &Multiaddr,
        dst_addr: &Multiaddr,
        src_addr: &Multiaddr,
    ) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } if *peer_id == expected_peer => {
                if endpoint.is_relayed() {
                    self.circuit |= endpoint.get_remote_address() == circuit_addr;
                } else {
                    let valid_endpoint = match endpoint {
                        ConnectedPoint::Dialer { address, .. } => address == dst_addr,
                        // Simultaneous-open can complete in the inbound direction.
                        // Bind it to this source listener and the expected peer;
                        // the native success must identify this same connection.
                        ConnectedPoint::Listener {
                            local_addr,
                            send_back_addr,
                        } => {
                            local_addr == src_addr
                                && send_back_addr
                                    .iter()
                                    .any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_loopback()))
                                && send_back_addr
                                    .iter()
                                    .any(|p| matches!(p, Protocol::Tcp(port) if port != 0))
                        }
                    };
                    if valid_endpoint {
                        self.direct.insert(*connection_id);
                    }
                }
            }
            SwarmEvent::Behaviour(ClientEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result: Ok(connection_id),
            })) if *remote_peer_id == expected_peer => self.reported = Some(*connection_id),
            _ => {}
        }
    }

    fn complete(&self) -> Option<ConnectionId> {
        self.reported
            .filter(|connection| self.circuit && self.direct.contains(connection))
    }
}

#[test]
fn collector_preserves_peer_endpoint_and_native_success_id_in_both_directions() {
    use libp2p_core::{transport::PortUse, Endpoint};
    let peer = PeerId::random();
    let other = PeerId::random();
    let circuit: Multiaddr = format!("/ip4/127.0.0.1/tcp/41000/p2p/{other}/p2p-circuit/p2p/{peer}")
        .parse()
        .unwrap();
    let destination: Multiaddr = format!("/ip4/127.0.0.1/tcp/41001/p2p/{peer}")
        .parse()
        .unwrap();
    let source: Multiaddr = "/ip4/127.0.0.1/tcp/41002".parse().unwrap();
    let direct_id = ConnectionId::new_unchecked(2);
    let outbound = ConnectedPoint::Dialer {
        address: destination.clone(),
        role_override: Endpoint::Dialer,
        port_use: PortUse::Reuse,
    };
    let inbound = ConnectedPoint::Listener {
        local_addr: source.clone(),
        send_back_addr: "/ip4/127.0.0.1/tcp/41003".parse().unwrap(),
    };
    // The upstream outbound-only predicate drops this valid inbound direction.
    assert_ne!(inbound.get_remote_address(), &destination);
    let established = |peer_id, connection_id, endpoint| SwarmEvent::ConnectionEstablished {
        peer_id,
        connection_id,
        endpoint,
        num_established: std::num::NonZeroU32::new(1).unwrap(),
        concurrent_dial_errors: None,
        established_in: Duration::ZERO,
    };
    let success = |remote_peer_id, connection_id| {
        SwarmEvent::Behaviour(ClientEvent::Dcutr(dcutr::Event {
            remote_peer_id,
            result: Ok(connection_id),
        }))
    };
    let circuit_event = established(
        peer,
        ConnectionId::new_unchecked(1),
        ConnectedPoint::Dialer {
            address: circuit.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        },
    );
    let record = |events: &mut UpgradeEvents, event: &SwarmEvent<ClientEvent>| {
        events.record(event, peer, &circuit, &destination, &source);
    };
    for endpoint in [outbound.clone(), inbound.clone()] {
        for success_first in [false, true] {
            let mut events = UpgradeEvents::default();
            record(&mut events, &circuit_event);
            let direct = established(peer, direct_id, endpoint.clone());
            let reported = success(peer, direct_id);
            for event in if success_first {
                [reported, direct]
            } else {
                [direct, reported]
            } {
                record(&mut events, &event);
            }
            assert_eq!(events.complete(), Some(direct_id));
        }
    }
    for (direct_peer, endpoint, reported_peer, reported_id, include_circuit) in [
        (other, outbound.clone(), peer, direct_id, true),
        (peer, outbound.clone(), other, direct_id, true),
        (
            peer,
            outbound.clone(),
            peer,
            ConnectionId::new_unchecked(3),
            true,
        ),
        (peer, outbound, peer, direct_id, false),
        (
            peer,
            ConnectedPoint::Dialer {
                address: circuit.clone(),
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
            peer,
            direct_id,
            true,
        ),
        (
            peer,
            ConnectedPoint::Dialer {
                address: source.clone(),
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
            peer,
            direct_id,
            true,
        ),
        (
            peer,
            ConnectedPoint::Listener {
                local_addr: "/ip4/127.0.0.1/tcp/41004".parse().unwrap(),
                send_back_addr: "/ip4/127.0.0.1/tcp/41003".parse().unwrap(),
            },
            peer,
            direct_id,
            true,
        ),
    ] {
        let mut events = UpgradeEvents::default();
        if include_circuit {
            record(&mut events, &circuit_event);
        }
        record(&mut events, &established(direct_peer, direct_id, endpoint));
        record(&mut events, &success(reported_peer, reported_id));
        assert!(events.complete().is_none());
    }
}

fn build_relay() -> Swarm<Relay> {
    Swarm::new_ephemeral_tokio(|identity| {
        let local_peer_id = identity.public().to_peer_id();

        Relay {
            relay: relay::Behaviour::new(
                local_peer_id,
                relay::Config {
                    reservation_duration: Duration::from_secs(2),
                    ..Default::default()
                },
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/relay".to_owned(),
                identity.public(),
            )),
        }
    })
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct Relay {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

fn build_client() -> Swarm<Client> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = local_key.public().to_peer_id();

    let (relay_transport, behaviour) = relay::client::new(local_peer_id);

    let transport = relay_transport
        .or_transport(MemoryTransport::default())
        .or_transport(libp2p_tcp::tokio::Transport::default())
        .upgrade(Version::V1)
        .authenticate(plaintext::Config::new(&local_key))
        .multiplex(libp2p_yamux::Config::default())
        .boxed();

    Swarm::new(
        transport,
        Client {
            relay: behaviour,
            dcutr: dcutr::Behaviour::new(local_peer_id),
            identify: identify::Behaviour::new(identify::Config::new(
                "/client".to_owned(),
                local_key.public(),
            )),
        },
        local_peer_id,
        Config::with_tokio_executor(),
    )
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct Client {
    relay: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    identify: identify::Behaviour,
}

async fn wait_for_reservation(
    client: &mut Swarm<Client>,
    client_addr: Multiaddr,
    relay_peer_id: PeerId,
    is_renewal: bool,
) {
    let mut new_listen_addr_for_relayed_addr = false;
    let mut reservation_req_accepted = false;
    let mut addr_observed = false;

    loop {
        if new_listen_addr_for_relayed_addr && reservation_req_accepted && addr_observed {
            break;
        }

        match client.next_swarm_event().await {
            SwarmEvent::NewListenAddr { address, .. } if address == client_addr => {
                new_listen_addr_for_relayed_addr = true;
            }
            SwarmEvent::Behaviour(ClientEvent::Relay(
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id: peer_id,
                    renewal,
                    ..
                },
            )) if relay_peer_id == peer_id && renewal == is_renewal => {
                reservation_req_accepted = true;
            }
            SwarmEvent::Dialing {
                peer_id: Some(peer_id),
                ..
            } if peer_id == relay_peer_id => {}
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay_peer_id => {}
            SwarmEvent::Behaviour(ClientEvent::Identify(identify::Event::Received { .. })) => {
                addr_observed = true;
            }
            SwarmEvent::Behaviour(ClientEvent::Identify(_)) => {}
            SwarmEvent::NewExternalAddrCandidate { .. } => {}
            SwarmEvent::ExternalAddrConfirmed { address } if !is_renewal => {
                assert_eq!(address, client_addr);
            }
            SwarmEvent::NewExternalAddrOfPeer { .. } => {}
            e => panic!("{e:?}"),
        }
    }
}
