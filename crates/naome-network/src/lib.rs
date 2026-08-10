//! Authenticated proof transport plus bounded untrusted peer-address routing.
//!
//! TCP carries mutually authenticated Noise sessions, Yamux provides one
//! substream per exchange, and the retained libp2p request handle plus
//! authenticated peer bind each received response to the immutable
//! [`ProofRequest`] that caused it. Static authorization is not Sybil
//! resistance, discovery, consensus, or proof selection.
//!
//! The endpoint with the lexicographically lower raw binary `PeerId` in each
//! configured pair owns dialing; proof requests reuse that managed full-duplex
//! session and never open connections.
//!
//! A separate outbound-only [`PeerRecordBootstrapClient`] authenticates exact
//! operator-configured bootstrap endpoints and returns source-bound record
//! batches for explicit atomic admission. It exposes no listener, installs no
//! proof protocol, and never converts a learned candidate into proof authority.
//!
//! The caller owns the Tokio runtime, drives network event loops, routes
//! correlated proof events through a bounded dependency acquisition, and
//! explicitly promotes the resulting opaque closure or admits a peer-record
//! batch. This crate starts no NAOME-owned background task and owns no
//! [`ProofDagJournal`].

mod acquisition;
mod address_store;
mod bootstrap;
mod codec;
mod record_exchange;
mod session;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use codec::{PROTOCOL, ProofCodec};
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    Swarm, SwarmBuilder, allow_block_list, connection_limits, noise, request_response, tcp, yamux,
};
use naome::proof_exchange::{
    PROOF_RESPONSE_MAX_BYTES, ProofRequest, ProofResponse, proof_response,
};
use naome_ledger::PROOF_BATCH_MAX_CANDIDATES;
use naome_storage::{JournalError, ProofDagJournal};
use session::Behaviour as SessionBehaviour;
use tokio::time::Instant;

const MANAGED_SESSION_IDLE_TIMEOUT: Duration = Duration::MAX;
const DIAL_RETRY_DELAYS: [Duration; 7] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
    Duration::from_secs(60),
];

pub use acquisition::{
    DependencyAcquisitionError, DependencyAcquisitionProgress, ProofDependencyAcquisition,
    UnselectedProofClosure,
};
pub use address_store::{
    BootstrapConfigError, BootstrapPeer, BootstrapPeerError, DialCandidate,
    MAX_ADDRESSES_PER_PEER_RECORD, MAX_BOOTSTRAP_PEERS, MAX_DIAL_CANDIDATES,
    MAX_DIAL_CANDIDATES_PER_BOOTSTRAP, MAX_PEER_ADDRESS_BYTES, MAX_PEER_ADDRESS_RECORDS,
    MAX_RECORDS_PER_BOOTSTRAP, MAX_RECORDS_PER_NETWORK_GROUP, MAX_SIGNED_PEER_RECORD_BYTES,
    PEER_RECORD_TTL, PeerAddressStore, PeerAddressStoreError, PeerRecordAdmission,
    PeerRecordBatchAdmission, SignedPeerRecord, SignedPeerRecordError,
};
pub use bootstrap::{
    AuthenticatedPeerRecordBatch, PeerRecordBootstrapBuildError, PeerRecordBootstrapClient,
    PeerRecordBootstrapEvent, PeerRecordPullFailure, PeerRecordPullStartError,
};
pub use libp2p::core::transport::ListenerId;
pub use libp2p::{Multiaddr, PeerId, identity::Keypair};
pub use record_exchange::{
    MAX_PEER_RECORDS_PER_BATCH, PEER_RECORD_BATCH_MAX_BYTES, PEER_RECORD_PULL_REQUEST_BYTES,
    PeerRecordBatch, PeerRecordExchangeWireError, PeerRecordPullRequest,
};

/// Maximum number of peers configured in one static transport.
pub const MAX_STATIC_PEERS: usize = 8;
/// Maximum established connections with one authenticated peer.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 1;
/// Maximum number of pending outbound proof requests.
pub const MAX_PENDING_REQUESTS: usize = 8;
/// Maximum requests issued by one dependency acquisition across all peers.
pub const MAX_DEPENDENCY_ACQUISITION_REQUESTS: usize =
    PROOF_BATCH_MAX_CANDIDATES + MAX_STATIC_PEERS - 1;
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
/// Absolute monotonic budget for one dependency acquisition.
pub const DEPENDENCY_ACQUISITION_TIMEOUT: Duration = Duration::from_secs(120);
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
    exchange: request_response::Behaviour<ProofCodec>,
}

struct PendingRequest {
    peer_id: PeerId,
    request: ProofRequest,
    control: Arc<AcquisitionControl>,
    _permit: PendingPermit,
}

struct AcquisitionControl {
    network_budget: Arc<PendingBudget>,
    deadline: Instant,
    cancelled: AtomicBool,
}

impl AcquisitionControl {
    fn new(network_budget: Arc<PendingBudget>, deadline: Instant) -> Self {
        Self {
            network_budget,
            deadline,
            cancelled: AtomicBool::new(false),
        }
    }

    fn cancel(&self) -> bool {
        !self.cancelled.swap(true, Ordering::Relaxed)
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

/// Authenticated proof transport over a fixed set of authorized peers.
pub struct StaticProofNetwork {
    swarm: Swarm<Behaviour>,
    pending: HashMap<request_response::OutboundRequestId, PendingRequest>,
    pending_budget: Arc<PendingBudget>,
}

impl StaticProofNetwork {
    /// Builds a bounded TCP + Noise + Yamux proof transport.
    ///
    /// This must run inside a Tokio runtime with I/O and time drivers enabled.
    /// Useful connectivity requires both endpoints to configure each other,
    /// the higher raw binary `PeerId` to expose the configured listener, and
    /// both event loops to remain driven. The lower `PeerId` owns dialing.
    pub fn new(
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
        let sessions = SessionBehaviour::new(local_peer_id, static_peers);

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
            sessions,
            exchange,
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
            .expect("constructing the fixed proof-network behavior is infallible")
            .with_swarm_config(|config| {
                config
                    .with_idle_connection_timeout(MANAGED_SESSION_IDLE_TIMEOUT)
                    .with_max_negotiating_inbound_streams(MAX_STREAMS_PER_CONNECTION)
            })
            .with_connection_timeout(CONNECTION_TIMEOUT)
            .build();

        Ok(Self {
            swarm,
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

    fn request_acquisition_proof(
        &mut self,
        peer_id: PeerId,
        request: ProofRequest,
        control: &Arc<AcquisitionControl>,
    ) -> Result<request_response::OutboundRequestId, RequestStartError> {
        let Some(session_connected) = self.swarm.behaviour().sessions.connection_status(&peer_id)
        else {
            return Err(RequestStartError::UnknownPeer(peer_id));
        };
        if self
            .pending
            .values()
            .any(|pending| pending.peer_id == peer_id)
        {
            return Err(RequestStartError::AlreadyPending(peer_id));
        }
        let transport_connected = self.swarm.behaviour().exchange.is_connected(&peer_id);
        #[cfg(test)]
        let transport_connected =
            transport_connected || self.swarm.behaviour().sessions.is_test_connected(&peer_id);
        if !session_connected || !transport_connected {
            return Err(RequestStartError::PeerDisconnected(peer_id));
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
            .send_request(&peer_id, request);
        let replaced = self.pending.insert(
            request_id,
            PendingRequest {
                peer_id,
                request,
                control: Arc::clone(control),
                _permit: permit,
            },
        );
        debug_assert!(replaced.is_none());
        Ok(request_id)
    }

    #[cfg(test)]
    fn request_proof(
        &mut self,
        peer_id: PeerId,
        request: ProofRequest,
    ) -> Result<request_response::OutboundRequestId, RequestStartError> {
        let deadline = Instant::now()
            .checked_add(DEPENDENCY_ACQUISITION_TIMEOUT)
            .expect("the fixed acquisition timeout fits Tokio Instant");
        let control = Arc::new(AcquisitionControl::new(
            Arc::clone(&self.pending_budget),
            deadline,
        ));
        self.request_acquisition_proof(peer_id, request, &control)
    }

    /// Waits for the next proof-network event.
    pub async fn next_event(&mut self) -> NetworkEvent {
        loop {
            if let Some(event) = self.take_due_acquisition_deadline(Instant::now()) {
                return event;
            }

            let swarm_event = if let Some(deadline) = self.next_acquisition_deadline() {
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline) => continue,
                    event = self.swarm.select_next_some() => event,
                }
            } else {
                self.swarm.select_next_some().await
            };

            match swarm_event {
                SwarmEvent::Behaviour(BehaviourEvent::Exchange(event)) => {
                    if let Some(event) = self.handle_exchange_event(event) {
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

    fn next_acquisition_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .filter(|pending| !pending.control.is_cancelled())
            .map(|pending| pending.control.deadline)
            .min()
    }

    fn take_due_acquisition_deadline(&mut self, now: Instant) -> Option<NetworkEvent> {
        let request_id = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                !pending.control.is_cancelled() && now >= pending.control.deadline
            })
            .min_by_key(|(request_id, pending)| (pending.control.deadline, **request_id))
            .map(|(request_id, _)| *request_id)?;
        let pending = self
            .pending
            .get(&request_id)
            .expect("the due request remains pending");
        if !pending.control.cancel() {
            return None;
        }
        Some(NetworkEvent::OutboundProof(OutboundProofEvent {
            request_id,
            peer_id: pending.peer_id,
            request: pending.request,
            control: Arc::clone(&pending.control),
            outcome: OutboundProofOutcome::DeadlineExceeded,
        }))
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
                        let expected = pending.peer_id;
                        return Some(Self::finish_peer_mismatch(
                            request_id, pending, expected, peer,
                        ));
                    }
                    if pending.control.is_cancelled() {
                        return Some(NetworkEvent::CancellationDrained {
                            peer_id: pending.peer_id,
                            request: pending.request,
                            outcome: CancellationDrainOutcome::ResponseDiscarded,
                        });
                    }
                    if Instant::now() >= pending.control.deadline {
                        return Some(if pending.control.cancel() {
                            NetworkEvent::OutboundProof(OutboundProofEvent {
                                request_id,
                                peer_id: pending.peer_id,
                                request: pending.request,
                                control: pending.control,
                                outcome: OutboundProofOutcome::DeadlineExceeded,
                            })
                        } else {
                            NetworkEvent::CancellationDrained {
                                peer_id: pending.peer_id,
                                request: pending.request,
                                outcome: CancellationDrainOutcome::ResponseDiscarded,
                            }
                        });
                    }
                    Some(NetworkEvent::OutboundProof(OutboundProofEvent {
                        request_id,
                        peer_id: peer,
                        request: pending.request,
                        control: pending.control,
                        outcome: OutboundProofOutcome::Response {
                            response,
                            _permit: pending._permit,
                        },
                    }))
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let pending = self.pending.remove(&request_id)?;
                if pending.peer_id != peer {
                    let expected = pending.peer_id;
                    return Some(Self::finish_peer_mismatch(
                        request_id, pending, expected, peer,
                    ));
                }
                Some(Self::finish_failed_request(
                    request_id,
                    pending,
                    Box::new(OutboundProofFailure::Transport(error)),
                ))
            }
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

    fn finish_peer_mismatch(
        request_id: request_response::OutboundRequestId,
        pending: PendingRequest,
        expected: PeerId,
        actual: PeerId,
    ) -> NetworkEvent {
        let error = Box::new(OutboundProofFailure::PeerMismatch { expected, actual });
        if pending.control.is_cancelled() {
            return NetworkEvent::CancellationDrained {
                peer_id: pending.peer_id,
                request: pending.request,
                outcome: CancellationDrainOutcome::Failure(error),
            };
        }
        NetworkEvent::OutboundProof(OutboundProofEvent {
            request_id,
            peer_id: pending.peer_id,
            request: pending.request,
            control: pending.control,
            outcome: OutboundProofOutcome::Failure(error),
        })
    }

    fn finish_failed_request(
        request_id: request_response::OutboundRequestId,
        pending: PendingRequest,
        error: Box<OutboundProofFailure>,
    ) -> NetworkEvent {
        if pending.control.is_cancelled() {
            return NetworkEvent::CancellationDrained {
                peer_id: pending.peer_id,
                request: pending.request,
                outcome: CancellationDrainOutcome::Failure(error),
            };
        }
        if Instant::now() >= pending.control.deadline {
            return if pending.control.cancel() {
                NetworkEvent::OutboundProof(OutboundProofEvent {
                    request_id,
                    peer_id: pending.peer_id,
                    request: pending.request,
                    control: pending.control,
                    outcome: OutboundProofOutcome::DeadlineExceeded,
                })
            } else {
                NetworkEvent::CancellationDrained {
                    peer_id: pending.peer_id,
                    request: pending.request,
                    outcome: CancellationDrainOutcome::Failure(error),
                }
            };
        }
        NetworkEvent::OutboundProof(OutboundProofEvent {
            request_id,
            peer_id: pending.peer_id,
            request: pending.request,
            control: pending.control,
            outcome: OutboundProofOutcome::Failure(error),
        })
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

fn yamux_config(max_streams: usize) -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(max_streams);
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

/// One terminal outcome correlated with its exact outbound proof request.
#[must_use]
pub struct OutboundProofEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: ProofRequest,
    control: Arc<AcquisitionControl>,
    outcome: OutboundProofOutcome,
}

impl OutboundProofEvent {
    /// Returns the expected authenticated peer.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable request that caused this terminal outcome.
    pub const fn request(&self) -> ProofRequest {
        self.request
    }

    /// Returns the terminal request failure, when this was not a response or
    /// acquisition deadline.
    pub fn failure(&self) -> Option<&OutboundProofFailure> {
        match &self.outcome {
            OutboundProofOutcome::Failure(error) => Some(error.as_ref()),
            _ => None,
        }
    }

    /// Returns whether the absolute acquisition deadline caused this event.
    pub const fn is_deadline_exceeded(&self) -> bool {
        matches!(self.outcome, OutboundProofOutcome::DeadlineExceeded)
    }
}

impl fmt::Debug for OutboundProofEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match &self.outcome {
            OutboundProofOutcome::Response { .. } => "Response",
            OutboundProofOutcome::Failure(_) => "Failure",
            OutboundProofOutcome::DeadlineExceeded => "DeadlineExceeded",
        };
        formatter
            .debug_struct("OutboundProofEvent")
            .field("request_id", &self.request_id)
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("outcome", &outcome)
            .finish_non_exhaustive()
    }
}

enum OutboundProofOutcome {
    Response {
        response: ProofResponse,
        _permit: PendingPermit,
    },
    Failure(Box<OutboundProofFailure>),
    DeadlineExceeded,
}

/// A typed terminal failure for one exact outbound proof request.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundProofFailure {
    Transport(request_response::OutboundFailure),
    PeerMismatch { expected: PeerId, actual: PeerId },
}

impl fmt::Display for OutboundProofFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => write!(formatter, "proof request failed: {source}"),
            Self::PeerMismatch { expected, actual } => {
                write!(
                    formatter,
                    "proof terminal event came from {actual}, expected {expected}"
                )
            }
        }
    }
}

impl Error for OutboundProofFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::PeerMismatch { .. } => None,
        }
    }
}

/// The physical terminal result that released one cancelled request slot.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum CancellationDrainOutcome {
    ResponseDiscarded,
    Failure(Box<OutboundProofFailure>),
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
    OutboundProof(OutboundProofEvent),
    CancellationDrained {
        peer_id: PeerId,
        request: ProofRequest,
        outcome: CancellationDrainOutcome,
    },
    InboundFailure {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        error: request_response::InboundFailure,
    },
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
                    "peer {peer_id} already has a pending proof request"
                )
            }
            Self::PeerDisconnected(peer_id) => {
                write!(formatter, "peer {peer_id} has no established session")
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
