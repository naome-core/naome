//! Managed authenticated transport, request custody, and exchange lifecycles.

use crate::*;

pub(crate) mod batch;
pub(crate) mod block_transport;
pub(crate) mod codec;
pub(crate) mod consensus_push;
pub(crate) mod head_announcement;
pub(crate) mod head_transport;
mod inbound_retention;
pub(crate) mod payload_request;
pub(crate) mod rate_limit;
pub(crate) mod recovery_bundle_push;
pub(crate) mod request_correlation;
pub(crate) mod session;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use block_transport::PendingArtifactBlockRequest;
use codec::{
    ARTIFACT_BLOCK_PROTOCOL, ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
    ARTIFACT_CHAIN_HEAD_PROTOCOL, ARTIFACT_PROTOCOL, ArtifactBlockCodec,
    ArtifactChainHeadAnnouncementCodec, ArtifactChainHeadCodec, ArtifactCodec,
    RECOVERY_BUNDLE_PUSH_PROTOCOL, RecoveryBundlePushCodec,
};
use consensus_push::codec::{CONSENSUS_PUSH_PROTOCOL, ConsensusPushCodec};
use head_announcement::PendingArtifactChainHeadAnnouncement;
use head_transport::PendingArtifactChainHeadRequest;
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    Swarm, SwarmBuilder, allow_block_list, connection_limits, noise, request_response, tcp, yamux,
};
use naome_protocol::artifact_exchange::{ArtifactRequest, ArtifactResponse};
use naome_storage::ArtifactChainJournalError;
use session::Behaviour as SessionBehaviour;
use tokio::time::Instant;

const MANAGED_SESSION_IDLE_TIMEOUT: Duration = Duration::MAX;
pub(crate) const PEER_RECORD_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_PEER_RECORD_STREAMS_PER_CONNECTION: usize = 1;
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
/// Maximum concurrent streams for each artifact, block, or head-pull exchange.
pub const MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION: usize = 2;
/// Maximum concurrent head-announcement streams on one connection.
pub const MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION: usize = 1;
/// Maximum concurrent recovery-bundle push streams on one connection.
pub const MAX_RECOVERY_BUNDLE_PUSH_STREAMS_PER_CONNECTION: usize = 1;
/// Maximum concurrent consensus push streams on one connection, shared by both directions.
pub const MAX_CONSENSUS_PUSH_STREAMS_PER_CONNECTION: usize = 1;
/// Aggregate application-stream ceiling imposed by Yamux.
/// Per-exchange limits sum to nine; they contend for eight total substreams,
/// with negotiation and transient streams also consuming capacity. Exhaustion
/// may fail exchanges or the connection.
pub const MAX_EXCHANGE_STREAMS_PER_CONNECTION: usize = MAX_YAMUX_STREAMS_PER_CONNECTION;
/// Maximum total Yamux substreams on one connection.
pub const MAX_YAMUX_STREAMS_PER_CONNECTION: usize = 8;
/// Configured TCP listen backlog.
pub const TCP_LISTEN_BACKLOG: u32 = 16;
/// Maximum duration for TCP, Noise, and Yamux connection establishment.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum duration of the negotiated request-response phase.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Absolute monotonic budget for importing one block's exact artifact payload.
pub const ARTIFACT_BLOCK_IMPORT_TIMEOUT: Duration = Duration::from_secs(120);
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
/// Maximum burst of admitted store- or journal-backed response attempts.
pub const INBOUND_APPLICATION_REQUEST_BURST: u32 = 8;
/// Sustained refill interval for store- or journal-backed responses.
pub const INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL: Duration = Duration::from_secs(1);

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
    artifact_exchange: request_response::Behaviour<ArtifactCodec>,
    block_exchange: request_response::Behaviour<ArtifactBlockCodec>,
    head_exchange: request_response::Behaviour<ArtifactChainHeadCodec>,
    head_announcement: request_response::Behaviour<ArtifactChainHeadAnnouncementCodec>,
    recovery_bundle_push: request_response::Behaviour<RecoveryBundlePushCodec>,
    consensus_push: request_response::Behaviour<ConsensusPushCodec>,
}

struct PendingArtifactRequest {
    peer_index: usize,
    request: ArtifactRequest,
    control: Arc<ArtifactRequestControl>,
    _permit: PendingPermit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ExchangeRequestId {
    Artifact(request_response::OutboundRequestId),
    Block(request_response::OutboundRequestId),
    Head(request_response::OutboundRequestId),
    Announcement(request_response::OutboundRequestId),
    RecoveryBundlePush(request_response::OutboundRequestId),
    ConsensusPush(request_response::OutboundRequestId),
}

enum PendingRequest {
    Artifact(PendingArtifactRequest),
    Block(PendingArtifactBlockRequest),
    Head(PendingArtifactChainHeadRequest),
    Announcement(PendingArtifactChainHeadAnnouncement),
    RecoveryBundlePush(recovery_bundle_push::PendingRecoveryBundlePush),
    ConsensusPush(consensus_push::PendingConsensusPush),
}

impl PendingRequest {
    fn peer_index(&self) -> usize {
        match self {
            Self::Artifact(pending) => pending.peer_index,
            Self::Block(pending) => pending.peer_index,
            Self::Head(pending) => pending.peer_index,
            Self::Announcement(pending) => pending.peer_index,
            Self::RecoveryBundlePush(pending) => pending.peer_index,
            Self::ConsensusPush(pending) => pending.peer_index,
        }
    }
}

struct ArtifactRequestControl {
    network_budget: Arc<PendingBudget>,
    deadline: Instant,
    cancelled: AtomicBool,
}

impl ArtifactRequestControl {
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

/// Authenticated artifact transport over a fixed set of authorized peers.
pub struct StaticArtifactNetwork {
    swarm: Swarm<Behaviour>,
    pending: HashMap<ExchangeRequestId, PendingRequest>,
    pending_budget: Arc<PendingBudget>,
    inbound_application_request_budget: rate_limit::TokenBucket,
}

impl StaticArtifactNetwork {
    /// Reports static transport configuration, not connectivity or consensus trust.
    pub fn is_configured_peer(&self, peer_id: &PeerId) -> bool {
        self.swarm
            .behaviour()
            .sessions
            .peer_index(peer_id)
            .is_some()
    }

    /// Builds a bounded TCP + Noise + Yamux artifact transport.
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
            .with_max_concurrent_streams(MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION);
        let artifact_exchange = request_response::Behaviour::with_codec(
            ArtifactCodec,
            [(ARTIFACT_PROTOCOL, request_response::ProtocolSupport::Full)],
            exchange_config.clone(),
        );
        let block_exchange = request_response::Behaviour::with_codec(
            ArtifactBlockCodec,
            [(
                ARTIFACT_BLOCK_PROTOCOL,
                request_response::ProtocolSupport::Full,
            )],
            exchange_config.clone(),
        );
        let head_exchange = request_response::Behaviour::with_codec(
            ArtifactChainHeadCodec,
            [(
                ARTIFACT_CHAIN_HEAD_PROTOCOL,
                request_response::ProtocolSupport::Full,
            )],
            exchange_config,
        );
        let announcement_config = request_response::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION);
        let head_announcement = request_response::Behaviour::with_codec(
            ArtifactChainHeadAnnouncementCodec,
            [(
                ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
                request_response::ProtocolSupport::Full,
            )],
            announcement_config,
        );
        let recovery_bundle_push = request_response::Behaviour::with_codec(
            RecoveryBundlePushCodec::new(Arc::new(inbound_retention::InboundRetentionBudget::new(
                RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS,
                RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
            ))),
            [(
                RECOVERY_BUNDLE_PUSH_PROTOCOL,
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(REQUEST_TIMEOUT)
                .with_max_concurrent_streams(MAX_RECOVERY_BUNDLE_PUSH_STREAMS_PER_CONNECTION),
        );

        let consensus_push = request_response::Behaviour::with_codec(
            ConsensusPushCodec::new(Arc::new(inbound_retention::InboundRetentionBudget::new(
                CONSENSUS_PUSH_MAX_RETAINED_INBOUND_EVENTS,
                CONSENSUS_PUSH_MAX_RETAINED_INBOUND_BYTES,
            ))),
            [(
                CONSENSUS_PUSH_PROTOCOL,
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(REQUEST_TIMEOUT)
                .with_max_concurrent_streams(MAX_CONSENSUS_PUSH_STREAMS_PER_CONNECTION),
        );
        let behaviour = Behaviour {
            limits,
            allowed,
            sessions,
            artifact_exchange,
            block_exchange,
            head_exchange,
            head_announcement,
            recovery_bundle_push,
            consensus_push,
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
            .expect("constructing the fixed artifact-network behavior is infallible")
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
            pending_budget: Arc::new(PendingBudget::default()),
            inbound_application_request_budget: rate_limit::TokenBucket::new(
                INBOUND_APPLICATION_REQUEST_BURST,
                INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL,
                Instant::now(),
            ),
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

    fn request_controlled_artifact(
        &mut self,
        peer_id: PeerId,
        request: ArtifactRequest,
        control: &Arc<ArtifactRequestControl>,
    ) -> Result<request_response::OutboundRequestId, RequestStartError> {
        let transport_connected = self
            .swarm
            .behaviour()
            .artifact_exchange
            .is_connected(&peer_id);
        let (peer_index, permit) = self.acquire_request_permit(peer_id, transport_connected)?;
        let request_id = self
            .swarm
            .behaviour_mut()
            .artifact_exchange
            .send_request(&peer_id, request);
        self.insert_pending(
            ExchangeRequestId::Artifact(request_id),
            PendingRequest::Artifact(PendingArtifactRequest {
                peer_index,
                request,
                control: Arc::clone(control),
                _permit: permit,
            }),
        );
        Ok(request_id)
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
            .any(|pending| pending.peer_index() == peer_index)
        {
            return Err(RequestStartError::AlreadyPending(peer_id));
        }
        let session_connected = sessions
            .connection_status_at(peer_index)
            .expect("a configured peer index remains valid");
        #[cfg(test)]
        let transport_connected = transport_connected || sessions.is_test_connected(&peer_id);
        if !session_connected || !transport_connected {
            return Err(RequestStartError::PeerDisconnected(peer_id));
        }
        Ok(peer_index)
    }

    fn insert_pending(&mut self, key: ExchangeRequestId, pending: PendingRequest) {
        debug_assert!(matches!(
            (&key, &pending),
            (ExchangeRequestId::Artifact(_), PendingRequest::Artifact(_))
                | (ExchangeRequestId::Block(_), PendingRequest::Block(_))
                | (ExchangeRequestId::Head(_), PendingRequest::Head(_))
                | (
                    ExchangeRequestId::Announcement(_),
                    PendingRequest::Announcement(_)
                )
                | (
                    ExchangeRequestId::RecoveryBundlePush(_),
                    PendingRequest::RecoveryBundlePush(_)
                )
                | (
                    ExchangeRequestId::ConsensusPush(_),
                    PendingRequest::ConsensusPush(_)
                )
        ));
        let replaced = self.pending.insert(key, pending);
        debug_assert!(replaced.is_none());
    }

    fn pending_peer_id(&self, peer_index: usize) -> PeerId {
        self.swarm
            .behaviour()
            .sessions
            .peer_id_at(peer_index)
            .expect("a pending peer index remains configured")
    }

    #[cfg(test)]
    pub(crate) fn request_artifact(
        &mut self,
        peer_id: PeerId,
        request: ArtifactRequest,
    ) -> Result<request_response::OutboundRequestId, RequestStartError> {
        let deadline = Instant::now()
            .checked_add(ARTIFACT_BLOCK_IMPORT_TIMEOUT)
            .expect("the fixed artifact-request timeout fits Tokio Instant");
        let control = Arc::new(ArtifactRequestControl::new(
            Arc::clone(&self.pending_budget),
            deadline,
        ));
        self.request_controlled_artifact(peer_id, request, &control)
    }

    /// Waits for the next artifact-network event.
    pub async fn next_event(&mut self) -> NetworkEvent {
        loop {
            if let Some(event) = self.take_due_artifact_request_deadline(Instant::now()) {
                return event;
            }

            let swarm_event = if let Some(deadline) = self.next_artifact_request_deadline() {
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline) => continue,
                    event = self.swarm.select_next_some() => event,
                }
            } else {
                self.swarm.select_next_some().await
            };

            match swarm_event {
                SwarmEvent::Behaviour(BehaviourEvent::ArtifactExchange(event)) => {
                    if let Some(event) = self.handle_artifact_exchange_event(event) {
                        return event;
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::BlockExchange(event)) => {
                    if let Some(event) = self.handle_block_exchange_event(event) {
                        return event;
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::HeadExchange(event)) => {
                    if let Some(event) = self.handle_head_exchange_event(event) {
                        return event;
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::HeadAnnouncement(event)) => {
                    if let Some(event) = self.handle_head_announcement_event(event) {
                        return event;
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::RecoveryBundlePush(event)) => {
                    if let Some(event) = self.handle_recovery_bundle_push_event(event) {
                        return event;
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::ConsensusPush(event)) => {
                    if let Some(event) = self.handle_consensus_push_event(event) {
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

    fn next_artifact_request_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .filter_map(|pending| match pending {
                PendingRequest::Artifact(pending) if !pending.control.is_cancelled() => {
                    Some(pending.control.deadline)
                }
                PendingRequest::Artifact(_)
                | PendingRequest::Block(_)
                | PendingRequest::Head(_)
                | PendingRequest::Announcement(_)
                | PendingRequest::RecoveryBundlePush(_)
                | PendingRequest::ConsensusPush(_) => None,
            })
            .min()
    }

    fn take_due_artifact_request_deadline(&mut self, now: Instant) -> Option<NetworkEvent> {
        let request_id = self
            .pending
            .iter()
            .filter_map(|(key, pending)| match (key, pending) {
                (ExchangeRequestId::Artifact(request_id), PendingRequest::Artifact(pending))
                    if !pending.control.is_cancelled() && now >= pending.control.deadline =>
                {
                    Some((*request_id, pending.control.deadline))
                }
                _ => None,
            })
            .min_by_key(|(request_id, deadline)| (*deadline, *request_id))?
            .0;
        let PendingRequest::Artifact(pending) = self
            .pending
            .get(&ExchangeRequestId::Artifact(request_id))
            .expect("the due artifact request remains pending")
        else {
            unreachable!("an artifact request key always stores an artifact request")
        };
        if !pending.control.cancel() {
            return None;
        }
        let peer_id = self.pending_peer_id(pending.peer_index);
        Some(NetworkEvent::OutboundArtifact(OutboundArtifactEvent {
            request_id,
            peer_id,
            request: pending.request,
            control: Arc::clone(&pending.control),
            outcome: OutboundArtifactOutcome::DeadlineExceeded,
        }))
    }

    fn handle_artifact_exchange_event(
        &mut self,
        event: request_response::Event<ArtifactRequest, ArtifactResponse>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundArtifactRequest(
                    InboundArtifactRequest {
                        peer_id: peer,
                        request_id,
                        request,
                        channel,
                    },
                )),
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let pending = self.remove_pending_artifact(request_id)?;
                    let expected = self.pending_peer_id(pending.peer_index);
                    if expected != peer {
                        return Some(Self::finish_peer_mismatch(
                            request_id, pending, expected, peer,
                        ));
                    }
                    if pending.control.is_cancelled() {
                        return Some(NetworkEvent::ArtifactCancellationDrained {
                            peer_id: expected,
                            request: pending.request,
                            outcome: CancellationDrainOutcome::ResponseDiscarded,
                        });
                    }
                    if Instant::now() >= pending.control.deadline {
                        return Some(if pending.control.cancel() {
                            NetworkEvent::OutboundArtifact(OutboundArtifactEvent {
                                request_id,
                                peer_id: expected,
                                request: pending.request,
                                control: pending.control,
                                outcome: OutboundArtifactOutcome::DeadlineExceeded,
                            })
                        } else {
                            NetworkEvent::ArtifactCancellationDrained {
                                peer_id: expected,
                                request: pending.request,
                                outcome: CancellationDrainOutcome::ResponseDiscarded,
                            }
                        });
                    }
                    Some(NetworkEvent::OutboundArtifact(OutboundArtifactEvent {
                        request_id,
                        peer_id: expected,
                        request: pending.request,
                        control: pending.control,
                        outcome: OutboundArtifactOutcome::Response {
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
                let pending = self.remove_pending_artifact(request_id)?;
                let expected = self.pending_peer_id(pending.peer_index);
                if expected != peer {
                    return Some(Self::finish_peer_mismatch(
                        request_id, pending, expected, peer,
                    ));
                }
                Some(Self::finish_failed_request(
                    request_id,
                    pending,
                    expected,
                    Box::new(OutboundArtifactFailure::Transport(error)),
                ))
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => Some(NetworkEvent::InboundArtifactFailure {
                peer_id: peer,
                request_id,
                error,
            }),
            request_response::Event::ResponseSent { .. } => None,
        }
    }

    fn finish_peer_mismatch(
        request_id: request_response::OutboundRequestId,
        pending: PendingArtifactRequest,
        expected: PeerId,
        actual: PeerId,
    ) -> NetworkEvent {
        let error = Box::new(OutboundArtifactFailure::PeerMismatch { expected, actual });
        if pending.control.is_cancelled() {
            return NetworkEvent::ArtifactCancellationDrained {
                peer_id: expected,
                request: pending.request,
                outcome: CancellationDrainOutcome::Failure(error),
            };
        }
        NetworkEvent::OutboundArtifact(OutboundArtifactEvent {
            request_id,
            peer_id: expected,
            request: pending.request,
            control: pending.control,
            outcome: OutboundArtifactOutcome::Failure(error),
        })
    }

    fn finish_failed_request(
        request_id: request_response::OutboundRequestId,
        pending: PendingArtifactRequest,
        peer_id: PeerId,
        error: Box<OutboundArtifactFailure>,
    ) -> NetworkEvent {
        if pending.control.is_cancelled() {
            return NetworkEvent::ArtifactCancellationDrained {
                peer_id,
                request: pending.request,
                outcome: CancellationDrainOutcome::Failure(error),
            };
        }
        if Instant::now() >= pending.control.deadline {
            return if pending.control.cancel() {
                NetworkEvent::OutboundArtifact(OutboundArtifactEvent {
                    request_id,
                    peer_id,
                    request: pending.request,
                    control: pending.control,
                    outcome: OutboundArtifactOutcome::DeadlineExceeded,
                })
            } else {
                NetworkEvent::ArtifactCancellationDrained {
                    peer_id,
                    request: pending.request,
                    outcome: CancellationDrainOutcome::Failure(error),
                }
            };
        }
        NetworkEvent::OutboundArtifact(OutboundArtifactEvent {
            request_id,
            peer_id,
            request: pending.request,
            control: pending.control,
            outcome: OutboundArtifactOutcome::Failure(error),
        })
    }

    fn remove_pending_artifact(
        &mut self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<PendingArtifactRequest> {
        let pending = self
            .pending
            .remove(&ExchangeRequestId::Artifact(request_id))?;
        let PendingRequest::Artifact(pending) = pending else {
            unreachable!("an artifact request key always stores an artifact request")
        };
        Some(pending)
    }

    pub(crate) fn respond_artifact_with(
        &mut self,
        inbound: InboundArtifactRequest,
        build: impl FnOnce() -> Result<ArtifactResponse, RespondError>,
    ) -> Result<(), RespondError> {
        if !inbound.channel.is_open() {
            return Err(RespondError::ChannelClosed);
        }
        self.take_inbound_application_request()?;
        let response = build()?;
        self.swarm
            .behaviour_mut()
            .artifact_exchange
            .send_response(inbound.channel, response)
            .map_err(|_| RespondError::ChannelClosed)
    }

    fn take_inbound_application_request(&mut self) -> Result<(), RespondError> {
        self.inbound_application_request_budget
            .try_take(Instant::now())
            .then_some(())
            .ok_or(RespondError::RateLimited)
    }
}

pub(crate) fn yamux_config(max_streams: usize) -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(max_streams);
    config
}

/// One request received from an authenticated, authorized peer.
#[must_use]
pub struct InboundArtifactRequest {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    request: ArtifactRequest,
    channel: request_response::ResponseChannel<ArtifactResponse>,
}

impl InboundArtifactRequest {
    /// Returns the authenticated sender.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the requested artifact address.
    pub const fn request(&self) -> ArtifactRequest {
        self.request
    }
}

impl fmt::Debug for InboundArtifactRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundArtifactRequest")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// One terminal outcome correlated with its exact outbound artifact request.
#[must_use]
pub struct OutboundArtifactEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: ArtifactRequest,
    control: Arc<ArtifactRequestControl>,
    outcome: OutboundArtifactOutcome,
}

impl OutboundArtifactEvent {
    pub(crate) fn into_parts(self) -> (PeerId, OutboundArtifactOutcome) {
        (self.peer_id, self.outcome)
    }

    /// Returns the expected authenticated peer.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable request that caused this terminal outcome.
    pub const fn request(&self) -> ArtifactRequest {
        self.request
    }

    /// Returns the terminal request failure, when this was not a response or
    /// artifact-request deadline.
    pub fn failure(&self) -> Option<&OutboundArtifactFailure> {
        match &self.outcome {
            OutboundArtifactOutcome::Failure(error) => Some(error.as_ref()),
            _ => None,
        }
    }

    /// Returns whether the absolute artifact-request deadline caused this event.
    pub const fn is_deadline_exceeded(&self) -> bool {
        matches!(self.outcome, OutboundArtifactOutcome::DeadlineExceeded)
    }
}

impl fmt::Debug for OutboundArtifactEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match &self.outcome {
            OutboundArtifactOutcome::Response { .. } => "Response",
            OutboundArtifactOutcome::Failure(_) => "Failure",
            OutboundArtifactOutcome::DeadlineExceeded => "DeadlineExceeded",
        };
        formatter
            .debug_struct("OutboundArtifactEvent")
            .field("request_id", &self.request_id)
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("outcome", &outcome)
            .finish_non_exhaustive()
    }
}

pub(crate) enum OutboundArtifactOutcome {
    Response {
        response: ArtifactResponse,
        _permit: PendingPermit,
    },
    Failure(Box<OutboundArtifactFailure>),
    DeadlineExceeded,
}

/// A typed terminal failure for one exact outbound artifact request.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundArtifactFailure {
    Transport(request_response::OutboundFailure),
    PeerMismatch { expected: PeerId, actual: PeerId },
}

impl fmt::Display for OutboundArtifactFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => write!(formatter, "artifact request failed: {source}"),
            Self::PeerMismatch { expected, actual } => {
                write!(
                    formatter,
                    "artifact terminal event came from {actual}, expected {expected}"
                )
            }
        }
    }
}

impl Error for OutboundArtifactFailure {
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
    Failure(Box<OutboundArtifactFailure>),
}

/// An externally relevant transport event.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum NetworkEvent {
    Listening {
        address: Multiaddr,
    },
    InboundArtifactRequest(InboundArtifactRequest),
    OutboundArtifact(OutboundArtifactEvent),
    InboundBlockRequest(InboundArtifactBlockRequest),
    OutboundBlock(OutboundArtifactBlockEvent),
    InboundChainHeadRequest(InboundArtifactChainHeadRequest),
    OutboundChainHead(OutboundArtifactChainHeadEvent),
    InboundChainHeadAnnouncement(InboundArtifactChainHeadAnnouncement),
    OutboundChainHeadAnnouncement(OutboundArtifactChainHeadAnnouncementEvent),
    InboundRecoveryBundlePush(InboundRecoveryBundlePush),
    OutboundRecoveryBundlePush(OutboundRecoveryBundlePushEvent),
    InboundConsensusPush(InboundConsensusPush),
    OutboundConsensusPush(OutboundConsensusPushEvent),
    ArtifactCancellationDrained {
        peer_id: PeerId,
        request: ArtifactRequest,
        outcome: CancellationDrainOutcome,
    },
    InboundArtifactFailure {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        error: request_response::InboundFailure,
    },
    InboundBlockFailure {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        error: request_response::InboundFailure,
    },
    InboundChainHeadFailure {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        error: request_response::InboundFailure,
    },
    InboundChainHeadAnnouncementFailure {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        error: request_response::InboundFailure,
    },
    InboundConsensusPushFailure {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        error: request_response::InboundFailure,
    },
    InboundRecoveryBundlePushFailure {
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

    fn try_acquire_many(
        budget: &Arc<Self>,
        count: usize,
    ) -> Result<[Option<PendingPermit>; MAX_PENDING_REQUESTS], usize> {
        debug_assert!((1..=MAX_PENDING_REQUESTS).contains(&count));
        budget
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                active
                    .checked_add(count)
                    .filter(|projected| *projected <= MAX_PENDING_REQUESTS)
            })
            .map_err(|active| MAX_PENDING_REQUESTS.saturating_sub(active))?;
        Ok(std::array::from_fn(|index| {
            (index < count).then(|| PendingPermit {
                budget: Arc::clone(budget),
            })
        }))
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

/// Construction failure for a static artifact network.
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
        write!(formatter, "cannot listen for artifact peers: {}", self.0)
    }
}

impl Error for ListenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// Failure to start one outbound artifact-network exchange request.
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

/// Failure to serve an authenticated inbound request.
#[derive(Debug)]
#[non_exhaustive]
pub enum RespondError {
    Journal(ArtifactChainJournalError),
    CandidateStore(naome_storage::ArtifactBlockCandidateStoreError),
    PayloadStore(naome_storage::CanonicalArtifactPayloadStoreError),
    ChannelClosed,
    RateLimited,
}

impl fmt::Display for RespondError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(source) => {
                write!(formatter, "cannot read artifact-chain journal: {source}")
            }
            Self::CandidateStore(source) => {
                write!(
                    formatter,
                    "cannot read artifact-block candidate store: {source}"
                )
            }
            Self::PayloadStore(source) => {
                write!(
                    formatter,
                    "cannot read canonical artifact-payload store: {source}"
                )
            }
            Self::ChannelClosed => write!(formatter, "response channel is closed"),
            Self::RateLimited => {
                formatter.write_str("inbound application request budget is exhausted")
            }
        }
    }
}

impl Error for RespondError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(source) => Some(source),
            Self::CandidateStore(source) => Some(source),
            Self::PayloadStore(source) => Some(source),
            Self::ChannelClosed | Self::RateLimited => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod test_support;
