//! Managed authenticated transport, request custody, and exchange lifecycles.

mod inbound_retention;
pub(crate) mod rate_limit;
pub(crate) mod session;
pub(crate) mod state_exchange;
use crate::*;
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    Swarm, SwarmBuilder, allow_block_list, connection_limits, noise, request_response, tcp, yamux,
};
use session::Behaviour as SessionBehaviour;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
const MANAGED_SESSION_IDLE_TIMEOUT: Duration = Duration::MAX;
pub(crate) const MAX_NEGOTIATING_INBOUND_STREAMS_PER_CONNECTION: usize = 2;
const DIAL_RETRY_DELAYS: [Duration; 7] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
    Duration::from_secs(60),
];

/// Maximum number of peers configured in one static transport.
pub const MAX_STATIC_PEERS: usize = 8;
/// Maximum established connections with one authenticated peer.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 1;
/// Maximum pending or caller-retained outbound requests across all application exchanges.
pub const MAX_PENDING_REQUESTS: usize = 8;
/// Maximum total Yamux substreams on one connection.
pub const MAX_YAMUX_STREAMS_PER_CONNECTION: usize = 8;
/// Configured TCP listen backlog.
pub const TCP_LISTEN_BACKLOG: u32 = 16;
/// Maximum duration for TCP, Noise, and Yamux connection establishment.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum duration of the negotiated request-response phase.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Initial delay after one failed managed-session dial.
pub const DIAL_RETRY_BASE: Duration = DIAL_RETRY_DELAYS[0];
/// Maximum delay between managed-session dial attempts.
pub const DIAL_RETRY_MAX: Duration = DIAL_RETRY_DELAYS[DIAL_RETRY_DELAYS.len() - 1];
/// Connected duration required before the next failure resets dial backoff.
pub const STABLE_SESSION_DURATION: Duration = Duration::from_secs(60);
/// Maximum pre-authentication inbound connection burst.
pub const INBOUND_AUTH_BURST: u32 = 8;
/// Sustained pre-authentication inbound connection refill interval.
pub const INBOUND_AUTH_REFILL_INTERVAL: Duration = Duration::from_secs(1);

/// One manually authorized peer and its complete dial address.
///
/// This is a fixed endpoint, not a bootstrap seed or discovered address.
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
    sessions: SessionBehaviour,
    state_exchange: state_exchange::Behaviour,
}

/// Authenticated canonical state transport over the immutable genesis peers.
pub struct StateNetwork {
    swarm: Swarm<Behaviour>,
    // Each peer behaviour has its own request counter; the peer is part of the key.
    pending: HashMap<(PeerId, request_response::OutboundRequestId), state_exchange::PendingState>,
    pending_budget: Arc<PendingBudget>,
    state_exchange: Option<state_exchange::StateConfig>,
}

impl StateNetwork {
    /// Reports static transport configuration, not connectivity or consensus trust.
    pub fn is_configured_peer(&self, peer_id: &PeerId) -> bool {
        self.swarm
            .behaviour()
            .sessions
            .peer_index(peer_id)
            .is_some()
    }

    fn build(
        identity: Keypair,
        peers: impl IntoIterator<Item = StaticPeer>,
    ) -> Result<Self, BuildError> {
        let local_peer_id = identity.public().to_peer_id();
        let mut static_peers = Vec::with_capacity(MAX_STATIC_PEERS);
        for peer in peers {
            if peer.peer_id == local_peer_id {
                return Err(BuildError::LocalPeer(local_peer_id));
            }
            if static_peers
                .iter()
                .any(|configured: &StaticPeer| configured.peer_id == peer.peer_id)
            {
                return Err(BuildError::DuplicatePeer(peer.peer_id));
            }
            if static_peers.len() == MAX_STATIC_PEERS {
                return Err(BuildError::TooManyPeers {
                    actual: static_peers.len() + 1,
                    maximum: MAX_STATIC_PEERS,
                });
            }
            static_peers.push(peer);
        }

        let peers_u32 = u32::try_from(MAX_STATIC_PEERS).expect("MAX_STATIC_PEERS fits u32");
        let connection_limits = connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(peers_u32))
            .with_max_pending_outgoing(Some(peers_u32))
            .with_max_established(Some(peers_u32))
            .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER));
        let limits = connection_limits::Behaviour::new(connection_limits);

        let mut allowed = allow_block_list::Behaviour::default();
        for peer in &static_peers {
            allowed.allow_peer(peer.peer_id);
        }
        let state_exchange =
            state_exchange::Behaviour::new(static_peers.iter().map(StaticPeer::peer_id), None);
        let sessions = SessionBehaviour::new(local_peer_id, static_peers);
        let behaviour = Behaviour {
            limits,
            allowed,
            sessions,
            state_exchange,
        };
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::new().listen_backlog(TCP_LISTEN_BACKLOG),
                noise::Config::new,
                || yamux_config(MAX_YAMUX_STREAMS_PER_CONNECTION),
            )
            .map_err(BuildError::Noise)?
            .with_behaviour(|_| behaviour)
            .expect("constructing the fixed state-network behavior is infallible")
            .with_swarm_config(|config| {
                config
                    .with_idle_connection_timeout(MANAGED_SESSION_IDLE_TIMEOUT)
                    .with_max_negotiating_inbound_streams(
                        MAX_NEGOTIATING_INBOUND_STREAMS_PER_CONNECTION,
                    )
            })
            .with_connection_timeout(CONNECTION_TIMEOUT)
            .build();

        Ok(Self {
            swarm,
            pending: HashMap::new(),
            state_exchange: None,
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

    fn acquire_request_permit(
        &self,
        peer_id: PeerId,
        transport_connected: bool,
    ) -> Result<(usize, PendingPermit), RequestStartError> {
        let peer_index = self.preflight_request(peer_id, transport_connected)?;
        PendingBudget::try_acquire(&self.pending_budget)
            .map(|permit| (peer_index, permit))
            .ok_or(RequestStartError::GlobalLimit {
                maximum: MAX_PENDING_REQUESTS,
            })
    }

    fn preflight_request(
        &self,
        peer_id: PeerId,
        transport_connected: bool,
    ) -> Result<usize, RequestStartError> {
        let sessions = &self.swarm.behaviour().sessions;
        let Some(peer_index) = sessions.peer_index(&peer_id) else {
            return Err(RequestStartError::UnknownPeer(peer_id));
        };
        if self
            .pending
            .values()
            .any(|pending| pending.peer_index == peer_index)
        {
            return Err(RequestStartError::AlreadyPending(peer_id));
        }
        let session_connected = sessions
            .connection_status_at(peer_index)
            .expect("a configured peer index remains valid");
        if !session_connected || !transport_connected {
            return Err(RequestStartError::PeerDisconnected(peer_id));
        }
        Ok(peer_index)
    }
    fn pending_peer_id(&self, peer_index: usize) -> PeerId {
        self.swarm
            .behaviour()
            .sessions
            .peer_id_at(peer_index)
            .expect("a pending peer index remains configured")
    }

    /// Waits for the next canonical state network event.
    pub async fn next_event(&mut self) -> NetworkEvent {
        let mut suppressed = 0usize;
        loop {
            if suppressed == 32 {
                tokio::task::yield_now().await;
                suppressed = 0;
            }
            suppressed += 1;
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(BehaviourEvent::StateExchange(event)) => {
                    if let Some(event) = self.handle_state_event(event) {
                        return event;
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sessions(event)) => {
                    return NetworkEvent::PeerSession(event);
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
}
pub(crate) fn yamux_config(max_streams: usize) -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(max_streams);
    config
}

/// An externally relevant transport event.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum NetworkEvent {
    Listening {
        address: Multiaddr,
    },
    InboundState(state_exchange::InboundState),
    OutboundState(state_exchange::StateEvent),
    PeerSession(PeerSessionEvent),
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
                active.checked_add(1).filter(|n| *n <= MAX_PENDING_REQUESTS)
            })
            .ok()?;
        Some(PendingPermit {
            budget: Arc::clone(budget),
        })
    }
}
pub(crate) struct PendingPermit {
    budget: Arc<PendingBudget>,
}
impl Drop for PendingPermit {
    fn drop(&mut self) {
        let previous = self.budget.active.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0);
    }
}
/// Construction failure for a static state network.
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
        write!(formatter, "cannot listen for state peers: {}", self.0)
    }
}

impl Error for ListenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// Failure to start one outbound state-network exchange request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestStartError {
    UnknownPeer(PeerId),
    AlreadyPending(PeerId),
    PeerDisconnected(PeerId),
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
                    "peer {peer_id} already has a pending outbound exchange request"
                )
            }
            Self::PeerDisconnected(peer_id) => {
                write!(formatter, "peer {peer_id} has no established session")
            }
            Self::GlobalLimit { maximum } => {
                write!(
                    formatter,
                    "shared pending or retained outbound request limit reached maximum {maximum}"
                )
            }
        }
    }
}

impl Error for RequestStartError {}

/// One externally visible managed static-peer session transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum PeerSessionEvent {
    Established { peer_id: PeerId },
    DialFailed { peer_id: PeerId },
    Disconnected { peer_id: PeerId },
}

impl PeerSessionEvent {
    /// Returns the configured peer whose session changed.
    pub const fn peer_id(self) -> PeerId {
        match self {
            Self::Established { peer_id }
            | Self::DialFailed { peer_id }
            | Self::Disconnected { peer_id } => peer_id,
        }
    }
}

#[cfg(test)]
mod tests;
