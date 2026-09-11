//! Bounded authenticated transport for verified membership and observer bootstrap.
//!
//! Transport admission is deliberately separate from voting admission. Unknown
//! organizations can connect and apply; only consensus verifies their authority.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    error::Error,
    fmt,
    sync::Arc,
    time::Duration,
};

use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Swarm, SwarmBuilder, connection_limits, noise, request_response, tcp, yamux};
use naome_consensus::verified_membership::{MAX_MEMBERS, MembershipSnapshot};
use tokio::time::Instant;

use super::{
    inbound_retention::{InboundRetentionBudget, InboundRetentionPermit},
    rate_limit::TokenBucket,
};
use crate::{Keypair, Multiaddr, PeerId, StaticPeer};

mod codec;
mod peer_exchange;
use codec::{MembershipCodec, PROTOCOL, RequestFrame, ResponseFrame};
use peer_exchange::{DecodeLanes, PeerExchange};

pub const MAX_OBSERVER_CONNECTIONS: usize = 16;
pub const MAX_PENDING_EXCHANGES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipRequestMessage {
    Publication(Vec<u8>),
    Application(Vec<u8>),
    Approval(Vec<u8>),
    Candidate(Vec<u8>),
    Status { context: [u8; 32] },
    Finality { context: [u8; 32], height: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipResponseMessage {
    Receipt,
    Status {
        context: [u8; 32],
        height: u64,
        ancestry: [u8; 32],
    },
    Finality(Vec<u8>),
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MembershipExchangeId(u64);

pub struct MembershipInbound {
    pub peer: PeerId,
    pub message: MembershipRequestMessage,
    channel: request_response::ResponseChannel<ResponseFrame>,
    _permit: InboundRetentionPermit,
}

pub enum MembershipNetworkEvent {
    Listening(Multiaddr),
    Connected(PeerId),
    Disconnected(PeerId),
    Inbound(MembershipInbound),
    Response(MembershipNetworkResponse),
    Failed {
        id: MembershipExchangeId,
        peer: PeerId,
    },
}

pub struct MembershipNetworkResponse {
    pub id: MembershipExchangeId,
    pub peer: PeerId,
    pub message: MembershipResponseMessage,
    _permit: Option<InboundRetentionPermit>,
}

#[derive(Debug)]
pub enum MembershipNetworkError {
    Build,
    Peer,
    Address,
    Busy,
    Limit,
    Response,
}
impl fmt::Display for MembershipNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "membership network: {self:?}")
    }
}
impl Error for MembershipNetworkError {}

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    exchange: PeerExchange,
}

/// Separate protocol framing avoids interpreting old fixed-profile traffic.
pub struct MembershipNetwork {
    swarm: Swarm<Behaviour>,
    bootstraps: Vec<StaticPeer>,
    admitted: HashSet<PeerId>,
    connected: BTreeSet<PeerId>,
    pacing: HashMap<PeerId, TokenBucket>,
    pending: HashMap<request_response::OutboundRequestId, (MembershipExchangeId, PeerId)>,
    next_id: u64,
    lanes: Arc<DecodeLanes>,
}

impl MembershipNetwork {
    pub fn new(
        identity: Keypair,
        bootstraps: Vec<StaticPeer>,
        snapshot: &MembershipSnapshot,
    ) -> Result<Self, MembershipNetworkError> {
        let local = identity.public().to_peer_id();
        if bootstraps.len() > MAX_MEMBERS {
            return Err(MembershipNetworkError::Limit);
        }
        let mut peers = HashSet::new();
        for peer in &bootstraps {
            if peer.peer_id() == local || !peers.insert(peer.peer_id()) {
                return Err(MembershipNetworkError::Peer);
            }
        }
        let limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(16))
                .with_max_pending_outgoing(Some(16))
                .with_max_established(Some(((MAX_MEMBERS + MAX_OBSERVER_CONNECTIONS) * 2) as u32))
                .with_max_established_per_peer(Some(2)),
        );
        let lanes = Arc::new(DecodeLanes {
            admitted: std::sync::RwLock::new(HashSet::new()),
            factory_peer: std::sync::RwLock::new(None),
            validators: Arc::new(InboundRetentionBudget::new(8, 8 * codec::MAX_FRAME_BYTES)),
            observers: Arc::new(InboundRetentionBudget::new(2, 2 * codec::MAX_FRAME_BYTES)),
        });
        let exchange = request_response::Behaviour::with_codec(
            MembershipCodec::new(Arc::clone(&lanes)),
            [(PROTOCOL, request_response::ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(2),
        );
        let behaviour = Behaviour {
            limits,
            exchange: PeerExchange::new(exchange, Arc::clone(&lanes)),
        };
        let mut swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::new().nodelay(true).listen_backlog(16),
                noise::Config::new,
                || {
                    let mut config = yamux::Config::default();
                    config.set_max_num_streams(8);
                    config
                },
            )
            .map_err(|_| MembershipNetworkError::Build)?
            .with_behaviour(|_| behaviour)
            .map_err(|_| MembershipNetworkError::Build)?
            .with_swarm_config(|config| {
                config
                    .with_idle_connection_timeout(Duration::from_secs(120))
                    .with_max_negotiating_inbound_streams(2)
            })
            .with_connection_timeout(Duration::from_secs(10))
            .build();
        for peer in &bootstraps {
            swarm.add_peer_address(peer.peer_id(), peer.address().clone());
        }
        let mut network = Self {
            swarm,
            bootstraps,
            admitted: HashSet::new(),
            connected: BTreeSet::new(),
            pacing: HashMap::new(),
            pending: HashMap::new(),
            next_id: 0,
            lanes,
        };
        network.update_membership(snapshot)?;
        Ok(network)
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }
    pub fn is_local_key(&self, key: &[u8; 32]) -> bool {
        libp2p::identity::ed25519::PublicKey::try_from_bytes(key).is_ok_and(|key| {
            libp2p::identity::PublicKey::from(key).to_peer_id() == self.local_peer_id()
        })
    }
    pub fn peers(&self) -> Vec<PeerId> {
        let mut peers = self.connected.clone();
        peers.extend(self.bootstraps.iter().map(StaticPeer::peer_id));
        peers.into_iter().collect()
    }
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected.iter().copied().collect()
    }
    pub fn listen_on(&mut self, address: Multiaddr) -> Result<(), MembershipNetworkError> {
        self.swarm
            .listen_on(address)
            .map(|_| ())
            .map_err(|_| MembershipNetworkError::Address)
    }
    pub fn update_membership(
        &mut self,
        snapshot: &MembershipSnapshot,
    ) -> Result<(), MembershipNetworkError> {
        let mut admitted = HashSet::new();
        for member in snapshot.members() {
            let public = libp2p::identity::ed25519::PublicKey::try_from_bytes(&member.network_key)
                .map_err(|_| MembershipNetworkError::Peer)?;
            admitted.insert(libp2p::identity::PublicKey::from(public).to_peer_id());
        }
        *self
            .lanes
            .admitted
            .write()
            .map_err(|_| MembershipNetworkError::Build)? = admitted.clone();
        self.admitted = admitted;
        let excess: Vec<_> = self
            .connected
            .iter()
            .filter(|peer| !self.admitted.contains(peer))
            .skip(MAX_OBSERVER_CONNECTIONS)
            .copied()
            .collect();
        for peer in excess {
            let _ = self.swarm.disconnect_peer_id(peer);
        }
        Ok(())
    }
    pub fn send(
        &mut self,
        peer: PeerId,
        message: MembershipRequestMessage,
    ) -> Result<MembershipExchangeId, MembershipNetworkError> {
        codec::validate_request(&message).map_err(|_| MembershipNetworkError::Limit)?;
        if self.pending.len() >= MAX_PENDING_EXCHANGES
            || self
                .pending
                .values()
                .any(|(_, pending_peer)| *pending_peer == peer)
        {
            return Err(MembershipNetworkError::Busy);
        }
        if !self.connected.contains(&peer)
            && !self
                .bootstraps
                .iter()
                .any(|bootstrap| bootstrap.peer_id() == peer)
        {
            return Err(MembershipNetworkError::Peer);
        }
        let id = MembershipExchangeId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(MembershipNetworkError::Limit)?;
        let request_id = self.swarm.behaviour_mut().exchange.send_request(
            &peer,
            RequestFrame {
                message,
                permit: None,
            },
        );
        self.pending.insert(request_id, (id, peer));
        Ok(id)
    }
    pub fn respond(
        &mut self,
        inbound: MembershipInbound,
        message: MembershipResponseMessage,
    ) -> Result<(), MembershipNetworkError> {
        codec::validate_response(&message).map_err(|_| MembershipNetworkError::Limit)?;
        drop(inbound._permit);
        let budget = self
            .lanes
            .budget(inbound.peer)
            .map_err(|_| MembershipNetworkError::Build)?;
        let permit = InboundRetentionBudget::try_acquire(&budget, codec::response_length(&message))
            .ok_or(MembershipNetworkError::Busy)?;
        self.swarm
            .behaviour_mut()
            .exchange
            .send_response(
                inbound.channel,
                ResponseFrame {
                    message,
                    _permit: Some(permit),
                },
            )
            .map_err(|_| MembershipNetworkError::Response)
    }

    pub async fn next_event(&mut self) -> MembershipNetworkEvent {
        let mut suppressed = 0;
        loop {
            suppressed += 1;
            if suppressed == 32 {
                tokio::task::yield_now().await;
                suppressed = 0;
            }
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    return MembershipNetworkEvent::Listening(address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    if !self.connected.contains(&peer_id)
                        && !self.admitted.contains(&peer_id)
                        && self
                            .connected
                            .iter()
                            .filter(|peer| !self.admitted.contains(peer))
                            .count()
                            >= MAX_OBSERVER_CONNECTIONS
                    {
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        continue;
                    }
                    self.connected.insert(peer_id);
                    self.pacing.entry(peer_id).or_insert_with(|| {
                        TokenBucket::new(32, Duration::from_millis(20), Instant::now())
                    });
                    return MembershipNetworkEvent::Connected(peer_id);
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    num_established: 0,
                    ..
                } => {
                    self.connected.remove(&peer_id);
                    self.pacing.remove(&peer_id);
                    return MembershipNetworkEvent::Disconnected(peer_id);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Exchange(event)) => match event {
                    request_response::Event::Message { peer, message, .. } => match message {
                        request_response::Message::Request {
                            request, channel, ..
                        } => {
                            if !self
                                .pacing
                                .get_mut(&peer)
                                .is_some_and(|bucket| bucket.try_take(Instant::now()))
                            {
                                continue;
                            }
                            let Some(mut permit) = request.permit else {
                                continue;
                            };
                            if !permit.bind_peer(peer) {
                                continue;
                            }
                            return MembershipNetworkEvent::Inbound(MembershipInbound {
                                peer,
                                message: request.message,
                                channel,
                                _permit: permit,
                            });
                        }
                        request_response::Message::Response {
                            request_id,
                            response,
                        } => {
                            if let Some((id, expected_peer)) = self.pending.remove(&request_id) {
                                if expected_peer != peer {
                                    return MembershipNetworkEvent::Failed {
                                        id,
                                        peer: expected_peer,
                                    };
                                }
                                return MembershipNetworkEvent::Response(
                                    MembershipNetworkResponse {
                                        id,
                                        peer,
                                        message: response.message,
                                        _permit: response._permit,
                                    },
                                );
                            }
                        }
                    },
                    request_response::Event::OutboundFailure { request_id, .. } => {
                        if let Some((id, peer)) = self.pending.remove(&request_id) {
                            return MembershipNetworkEvent::Failed { id, peer };
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
}
