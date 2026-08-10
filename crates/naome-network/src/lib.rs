//! Authenticated and resource-bounded proof transport for static NAOME peers.
//!
//! TCP carries mutually authenticated Noise sessions, Yamux provides one
//! substream per exchange, and the retained libp2p request handle plus
//! authenticated peer bind each received response to the immutable
//! [`ProofRequest`] that caused it. Static authorization is not Sybil
//! resistance, discovery, consensus, or proof selection.
//!
//! The caller owns the Tokio runtime, drives [`StaticProofNetwork::next_event`],
//! and decides when an opaque response is admitted to its journal. This crate
//! starts no background task and owns no [`ProofDagJournal`].

mod codec;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use codec::{PROTOCOL, ProofCodec};
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    Swarm, SwarmBuilder, allow_block_list, connection_limits, noise, request_response, tcp, yamux,
};
use naome::proof_exchange::{
    PROOF_RESPONSE_MAX_BYTES, ProofRequest, ProofResponse, ProofResponseOutcome,
    admit_proof_response, proof_response,
};
use naome_storage::{JournalError, ProofDagJournal};

pub use libp2p::core::transport::ListenerId;
pub use libp2p::{Multiaddr, PeerId, identity::Keypair};

/// Maximum number of peers configured in one static transport.
pub const MAX_STATIC_PEERS: usize = 8;
/// Maximum established connections with one authenticated peer.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 1;
/// Maximum number of pending outbound proof requests.
pub const MAX_PENDING_REQUESTS: usize = 8;
/// Maximum concurrent request-response streams on one connection.
pub const MAX_STREAMS_PER_CONNECTION: usize = 2;
/// Maximum total Yamux substreams on one connection.
pub const MAX_YAMUX_STREAMS_PER_CONNECTION: usize = 8;
/// Configured TCP listen backlog.
pub const TCP_LISTEN_BACKLOG: u32 = 16;
/// Maximum duration for TCP, Noise, and Yamux connection establishment.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum duration of the negotiated request-response phase.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Duration after which an unused authenticated connection closes.
pub const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// One statically authorized peer and its dial address.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct StaticPeer {
    peer_id: PeerId,
    address: Multiaddr,
}

impl StaticPeer {
    /// Constructs one authorized peer.
    pub const fn new(peer_id: PeerId, address: Multiaddr) -> Self {
        Self { peer_id, address }
    }

    /// Returns the authenticated peer identity.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the static dial address.
    pub const fn address(&self) -> &Multiaddr {
        &self.address
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    allowed: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    exchange: request_response::Behaviour<ProofCodec>,
}

struct PendingRequest {
    peer_id: PeerId,
    request: ProofRequest,
    _permit: PendingPermit,
}

/// Authenticated proof transport over a fixed set of authorized peers.
pub struct StaticProofNetwork {
    swarm: Swarm<Behaviour>,
    peers: HashMap<PeerId, Multiaddr>,
    pending: HashMap<request_response::OutboundRequestId, PendingRequest>,
    pending_budget: Arc<PendingBudget>,
}

impl StaticProofNetwork {
    /// Builds a bounded TCP + Noise + Yamux proof transport.
    ///
    /// This must run inside a Tokio runtime with I/O and time drivers enabled.
    pub fn new(
        identity: Keypair,
        peers: impl IntoIterator<Item = StaticPeer>,
    ) -> Result<Self, BuildError> {
        let local_peer_id = identity.public().to_peer_id();
        let mut peer_map = HashMap::new();
        for peer in peers {
            if peer.peer_id == local_peer_id {
                return Err(BuildError::LocalPeer(local_peer_id));
            }
            if peer_map.insert(peer.peer_id, peer.address).is_some() {
                return Err(BuildError::DuplicatePeer(peer.peer_id));
            }
            if peer_map.len() > MAX_STATIC_PEERS {
                return Err(BuildError::TooManyPeers {
                    actual: peer_map.len(),
                    maximum: MAX_STATIC_PEERS,
                });
            }
        }

        let peers_u32 = u32::try_from(MAX_STATIC_PEERS).expect("MAX_STATIC_PEERS fits u32");
        let connection_limits = connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(peers_u32))
            .with_max_pending_outgoing(Some(peers_u32))
            .with_max_established(Some(peers_u32))
            .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER));
        let limits = connection_limits::Behaviour::new(connection_limits);

        let mut allowed = allow_block_list::Behaviour::default();
        for peer_id in peer_map.keys() {
            allowed.allow_peer(*peer_id);
        }

        let exchange_config = request_response::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(MAX_STREAMS_PER_CONNECTION);
        let exchange = request_response::Behaviour::with_codec(
            ProofCodec,
            [(PROTOCOL, request_response::ProtocolSupport::Full)],
            exchange_config,
        );

        let behaviour = Behaviour {
            limits,
            allowed,
            exchange,
        };
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::new().listen_backlog(TCP_LISTEN_BACKLOG),
                noise::Config::new,
                yamux_config,
            )
            .map_err(BuildError::Noise)?
            .with_behaviour(|_| behaviour)
            .expect("constructing the fixed proof-network behavior is infallible")
            .with_swarm_config(|config| {
                config
                    .with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
                    .with_max_negotiating_inbound_streams(MAX_STREAMS_PER_CONNECTION)
            })
            .with_connection_timeout(CONNECTION_TIMEOUT)
            .build();

        Ok(Self {
            swarm,
            peers: peer_map,
            pending: HashMap::new(),
            pending_budget: Arc::new(PendingBudget::default()),
        })
    }

    /// Returns this transport's authenticated peer identity.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Starts listening on one TCP multi-address.
    pub fn listen_on(&mut self, address: Multiaddr) -> Result<ListenerId, ListenError> {
        self.swarm.listen_on(address).map_err(ListenError)
    }

    /// Starts one proof request to an authorized static peer.
    pub fn request_proof(
        &mut self,
        peer_id: PeerId,
        request: ProofRequest,
    ) -> Result<(), RequestStartError> {
        let address = self
            .peers
            .get(&peer_id)
            .ok_or(RequestStartError::UnknownPeer(peer_id))?;
        if self
            .pending
            .values()
            .any(|pending| pending.peer_id == peer_id)
        {
            return Err(RequestStartError::AlreadyPending(peer_id));
        }
        let permit = PendingBudget::try_acquire(&self.pending_budget).ok_or(
            RequestStartError::GlobalLimit {
                maximum: MAX_PENDING_REQUESTS,
            },
        )?;
        let request_id = self
            .swarm
            .behaviour_mut()
            .exchange
            .send_request_with_addresses(&peer_id, request, vec![address.clone()]);
        let replaced = self.pending.insert(
            request_id,
            PendingRequest {
                peer_id,
                request,
                _permit: permit,
            },
        );
        debug_assert!(replaced.is_none());
        Ok(())
    }

    /// Waits for the next proof-network event.
    pub async fn next_event(&mut self) -> NetworkEvent {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(BehaviourEvent::Exchange(event)) => {
                    if let Some(event) = self.handle_exchange_event(event) {
                        return event;
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    return NetworkEvent::Listening { address };
                }
                SwarmEvent::ListenerError { listener_id, error } => {
                    return NetworkEvent::ListenerError { listener_id, error };
                }
                SwarmEvent::ListenerClosed {
                    listener_id,
                    addresses,
                    reason,
                } => {
                    return NetworkEvent::ListenerClosed {
                        listener_id,
                        addresses,
                        reason,
                    };
                }
                _ => {}
            }
        }
    }

    fn handle_exchange_event(
        &mut self,
        event: request_response::Event<ProofRequest, ProofResponse>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundRequest(InboundProofRequest {
                    peer_id: peer,
                    request_id,
                    request,
                    channel,
                })),
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let pending = self.pending.remove(&request_id)?;
                    if pending.peer_id != peer {
                        return Some(NetworkEvent::ResponsePeerMismatch {
                            expected: pending.peer_id,
                            actual: peer,
                            request: pending.request,
                        });
                    }
                    Some(NetworkEvent::Response(ReceivedProofResponse {
                        peer_id: peer,
                        request: pending.request,
                        response,
                        _permit: pending._permit,
                    }))
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => self
                .pending
                .remove(&request_id)
                .map(|pending| NetworkEvent::OutboundFailure {
                    peer_id: peer,
                    request: pending.request,
                    error,
                }),
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => Some(NetworkEvent::InboundFailure {
                peer_id: peer,
                request_id,
                error,
            }),
            request_response::Event::ResponseSent { .. } => None,
        }
    }

    /// Serves one authenticated request from the healthy local journal.
    ///
    /// One bounded proof-sized copy is required because rust-libp2p owns the
    /// response until its asynchronous stream write completes. The journal is
    /// not borrowed across that write.
    pub fn respond_from_journal(
        &mut self,
        inbound: InboundProofRequest,
        journal: &ProofDagJournal,
    ) -> Result<(), RespondError> {
        let response_bytes =
            proof_response(journal, inbound.request).map_err(RespondError::Journal)?;
        if !inbound.channel.is_open() {
            return Err(RespondError::ChannelClosed);
        }
        let bytes = response_bytes.map_or_else(Vec::new, <[u8]>::to_vec);
        debug_assert!(bytes.len() <= PROOF_RESPONSE_MAX_BYTES);
        let response = ProofResponse::from_wire_bytes(bytes)
            .expect("retained canonical proof obeys the certificate limit");
        self.swarm
            .behaviour_mut()
            .exchange
            .send_response(inbound.channel, response)
            .map_err(|_| RespondError::ChannelClosed)
    }
}

fn yamux_config() -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(MAX_YAMUX_STREAMS_PER_CONNECTION);
    config
}

/// One request received from an authenticated, authorized peer.
#[must_use]
pub struct InboundProofRequest {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    request: ProofRequest,
    channel: request_response::ResponseChannel<ProofResponse>,
}

impl InboundProofRequest {
    /// Returns the authenticated sender.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the requested proof address.
    pub const fn request(&self) -> ProofRequest {
        self.request
    }
}

impl fmt::Debug for InboundProofRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundProofRequest")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// One response cryptographically correlated with its original request.
#[must_use]
pub struct ReceivedProofResponse {
    peer_id: PeerId,
    request: ProofRequest,
    response: ProofResponse,
    _permit: PendingPermit,
}

impl ReceivedProofResponse {
    /// Returns the authenticated responder.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable request that caused this response.
    pub const fn request(&self) -> ProofRequest {
        self.request
    }

    /// Returns whether the peer supplied no proof payload.
    pub const fn is_unavailable(&self) -> bool {
        self.response.is_unavailable()
    }

    /// Strictly admits this response against its immutable requested address.
    pub fn admit(
        self,
        journal: &mut ProofDagJournal,
    ) -> Result<ProofResponseOutcome, JournalError> {
        admit_proof_response(journal, self.request, self.response)
    }
}

impl fmt::Debug for ReceivedProofResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedProofResponse")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("response", &self.response)
            .finish()
    }
}

/// An externally relevant transport event.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum NetworkEvent {
    Listening {
        address: Multiaddr,
    },
    InboundRequest(InboundProofRequest),
    Response(ReceivedProofResponse),
    OutboundFailure {
        peer_id: PeerId,
        request: ProofRequest,
        error: request_response::OutboundFailure,
    },
    InboundFailure {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        error: request_response::InboundFailure,
    },
    ResponsePeerMismatch {
        expected: PeerId,
        actual: PeerId,
        request: ProofRequest,
    },
    ListenerError {
        listener_id: ListenerId,
        error: std::io::Error,
    },
    ListenerClosed {
        listener_id: ListenerId,
        addresses: Vec<Multiaddr>,
        reason: Result<(), std::io::Error>,
    },
}

#[derive(Default)]
struct PendingBudget {
    active: AtomicUsize,
}

impl PendingBudget {
    fn try_acquire(budget: &Arc<Self>) -> Option<PendingPermit> {
        budget
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                (active < MAX_PENDING_REQUESTS).then_some(active + 1)
            })
            .ok()?;
        Some(PendingPermit {
            budget: Arc::clone(budget),
        })
    }
}

struct PendingPermit {
    budget: Arc<PendingBudget>,
}

impl Drop for PendingPermit {
    fn drop(&mut self) {
        let previous = self.budget.active.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0);
    }
}

/// Construction failure for a static proof network.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    TooManyPeers { actual: usize, maximum: usize },
    LocalPeer(PeerId),
    DuplicatePeer(PeerId),
    Noise(noise::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyPeers { actual, maximum } => {
                write!(
                    formatter,
                    "static peer count {actual} exceeds maximum {maximum}"
                )
            }
            Self::LocalPeer(peer_id) => {
                write!(formatter, "local peer {peer_id} cannot authorize itself")
            }
            Self::DuplicatePeer(peer_id) => {
                write!(
                    formatter,
                    "static peer {peer_id} is configured more than once"
                )
            }
            Self::Noise(source) => write!(formatter, "cannot configure Noise: {source}"),
        }
    }
}

impl Error for BuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Noise(source) => Some(source),
            _ => None,
        }
    }
}

/// Failure to bind a TCP listener.
#[derive(Debug)]
pub struct ListenError(libp2p::TransportError<std::io::Error>);

impl fmt::Display for ListenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cannot listen for proof peers: {}", self.0)
    }
}

impl Error for ListenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// Failure to start one outbound proof request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestStartError {
    UnknownPeer(PeerId),
    AlreadyPending(PeerId),
    GlobalLimit { maximum: usize },
}

impl fmt::Display for RequestStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPeer(peer_id) => {
                write!(formatter, "peer {peer_id} is not statically authorized")
            }
            Self::AlreadyPending(peer_id) => {
                write!(
                    formatter,
                    "peer {peer_id} already has a pending proof request"
                )
            }
            Self::GlobalLimit { maximum } => {
                write!(
                    formatter,
                    "pending proof requests reached maximum {maximum}"
                )
            }
        }
    }
}

impl Error for RequestStartError {}

/// Failure to serve an authenticated inbound request.
#[derive(Debug)]
#[non_exhaustive]
pub enum RespondError {
    Journal(JournalError),
    ChannelClosed,
}

impl fmt::Display for RespondError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(source) => write!(formatter, "cannot read proof journal: {source}"),
            Self::ChannelClosed => write!(formatter, "proof response channel is closed"),
        }
    }
}

impl Error for RespondError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(source) => Some(source),
            Self::ChannelClosed => None,
        }
    }
}

#[cfg(test)]
mod tests;
