//! Authenticated proof transport plus bounded untrusted peer-address routing.
//!
//! TCP carries mutually authenticated Noise sessions, Yamux provides one
//! substream per exchange, and the retained libp2p request handle plus
//! authenticated peer bind each terminal to the immutable proof, proof-block,
//! proof-chain-head, or head-announcement operation that caused it. Static
//! authorization is not Sybil resistance, discovery, consensus, or proof
//! selection.
//!
//! The endpoint with the lexicographically lower raw binary `PeerId` in each
//! configured pair owns dialing; proof, exact-block, head-pull, and
//! head-announcement exchanges reuse that managed full-duplex session and
//! never open connections.
//!
//! A separate outbound-only [`PeerRecordBootstrapClient`] authenticates exact
//! operator-configured bootstrap endpoints and returns source-bound record
//! batches for explicit atomic admission. A separate inbound-only
//! [`PeerRecordBootstrapResponder`] serves one operator-supplied immutable
//! canonical batch to bounded authenticated requesters. Neither swarm installs
//! the proof protocol or converts a learned candidate into proof authority.
//! A separate [`LocalPeerRecordIssuer`] persists one identity-bound sequence
//! watermark before returning each newly signed standard peer record. It never
//! retains the private key, discovers addresses, or publishes by itself.
//!
//! The caller owns the Tokio runtime, drives every network event loop, routes
//! correlated proof events through a bounded dependency acquisition, consumes
//! exact-block terminals through their generation tickets, may pull, explicitly
//! announce, broadcast, or survey source-bound untrusted chain heads across a
//! bounded caller-selected peer set, may retrieve one bounded caller-selected
//! and unselected block ancestry, imports either one exact child or one
//! consumed ancestry, or composes retrieval and import into one exact-target
//! catch-up. Every import target remains a separate caller decision. The caller
//! also explicitly promotes a resulting opaque closure or admits a peer-record
//! batch. The
//! responder publication is not derived from the address store.
//! [`StaticProofNetwork::next_journal_service_event`] serves authenticated
//! proof, block, and head pulls from one borrowed journal while returning
//! announcements and every other event unchanged; it starts no background
//! task.
//! This crate starts no NAOME-owned background task and owns no
//! [`ProofChainJournal`].

mod acquisition;
mod address_store;
mod block_ancestry;
mod block_ancestry_import;
mod block_catch_up;
mod block_import;
mod block_transport;
mod bootstrap;
mod codec;
mod head_announcement;
mod head_broadcast;
mod head_survey;
mod head_transport;
mod journal_service;
mod local_issuer;
mod rate_limit;
mod record_exchange;
mod responder;
mod session;
mod snapshot_io;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use block_transport::PendingProofBlockRequest;
use codec::{
    PROOF_BLOCK_PROTOCOL, PROOF_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL, PROOF_CHAIN_HEAD_PROTOCOL,
    PROTOCOL, ProofBlockCodec, ProofChainHeadAnnouncementCodec, ProofChainHeadCodec, ProofCodec,
};
use head_announcement::PendingProofChainHeadAnnouncement;
use head_transport::PendingProofChainHeadRequest;
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    Swarm, SwarmBuilder, allow_block_list, connection_limits, noise, request_response, tcp, yamux,
};
use naome::proof_exchange::{PROOF_RESPONSE_MAX_BYTES, ProofRequest, ProofResponse};
use naome_chain::ProofBlockId;
use naome_ledger::PROOF_BATCH_MAX_CANDIDATES;
use naome_storage::{ProofChainJournal, ProofChainJournalError};
use session::Behaviour as SessionBehaviour;
use tokio::time::Instant;

const MANAGED_SESSION_IDLE_TIMEOUT: Duration = Duration::MAX;
const PEER_RECORD_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PEER_RECORD_STREAMS_PER_CONNECTION: usize = 1;
const MAX_NEGOTIATING_INBOUND_STREAMS_PER_CONNECTION: usize = 2;
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
pub use block_ancestry::{
    MAX_PROOF_BLOCK_ANCESTRY_BLOCKS, ProofBlockAncestryPull, ProofBlockAncestryPullError,
    ProofBlockAncestryPullProgress, UnselectedProofBlockAncestry,
};
pub use block_ancestry_import::{
    ProofBlockAncestryImport, ProofBlockAncestryImportError, ProofBlockAncestryImportProgress,
};
pub use block_catch_up::{ProofBlockCatchUp, ProofBlockCatchUpError, ProofBlockCatchUpProgress};
pub use block_import::{ProofBlockImport, ProofBlockImportError, ProofBlockImportProgress};
pub use block_transport::{
    BlockRequestTicket, InboundProofBlockRequest, OutboundProofBlockEvent,
    OutboundProofBlockFailure, ProofBlockRequestEventMismatch,
};
pub use bootstrap::{
    AuthenticatedPeerRecordBatch, PeerRecordBootstrapBuildError, PeerRecordBootstrapClient,
    PeerRecordBootstrapEvent, PeerRecordPullFailure, PeerRecordPullStartError,
};
pub use head_announcement::{
    AuthenticatedProofChainHeadAnnouncementReceipt, HeadAnnouncementAcknowledgeError,
    HeadAnnouncementStartError, HeadAnnouncementTicket, InboundProofChainHeadAnnouncement,
    OutboundProofChainHeadAnnouncementEvent, OutboundProofChainHeadAnnouncementFailure,
    ProofChainHeadAnnouncementEventMismatch,
};
pub use head_broadcast::{
    CompletedProofChainHeadBroadcast, MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS,
    ProofChainHeadBroadcast, ProofChainHeadBroadcastEventMismatch,
    ProofChainHeadBroadcastPeerResult, ProofChainHeadBroadcastProgress,
    ProofChainHeadBroadcastStartError,
};
pub use head_survey::{
    CompletedProofChainHeadSurvey, ProofChainHeadSurvey, ProofChainHeadSurveyEventMismatch,
    ProofChainHeadSurveyPeerResult, ProofChainHeadSurveyProgress, ProofChainHeadSurveyStartError,
};
pub use head_transport::{
    AuthenticatedProofChainHeadResponse, ChainHeadRequestTicket, InboundProofChainHeadRequest,
    OutboundProofChainHeadEvent, OutboundProofChainHeadFailure, ProofChainHeadRequestEventMismatch,
};
pub use journal_service::{JournalServiceEvent, JournalServiceRequest};
pub use libp2p::core::transport::ListenerId;
pub use libp2p::{Multiaddr, PeerId, identity::Keypair};
pub use local_issuer::{LocalPeerRecordIssuer, LocalPeerRecordIssuerError};
pub use record_exchange::{
    MAX_PEER_RECORDS_PER_BATCH, PEER_RECORD_BATCH_MAX_BYTES, PEER_RECORD_PULL_REQUEST_BYTES,
    PeerRecordBatch, PeerRecordExchangeWireError, PeerRecordPullRequest,
};
pub use responder::{
    PeerRecordBootstrapResponder, PeerRecordBootstrapResponderBuildError,
    PeerRecordBootstrapResponderEvent, PeerRecordBootstrapResponderFailure,
    PeerRecordBootstrapResponderListenError,
};

fn selected_context_contains_block(
    selected: &ProofChainJournal,
    current_head: ProofBlockId,
    virtual_genesis: ProofBlockId,
    block_id: ProofBlockId,
) -> Result<bool, ProofChainJournalError> {
    Ok(block_id == current_head
        || block_id == virtual_genesis
        || selected.block(block_id)?.is_some())
}

/// Maximum number of peers configured in one static transport.
pub const MAX_STATIC_PEERS: usize = 8;
/// Maximum established connections with one authenticated peer.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 1;
/// Maximum pending or caller-retained outbound proof, block, head, and announcement requests.
pub const MAX_PENDING_REQUESTS: usize = 8;
/// Maximum requests issued by one dependency acquisition across all peers.
pub const MAX_DEPENDENCY_ACQUISITION_REQUESTS: usize =
    PROOF_BATCH_MAX_CANDIDATES + MAX_STATIC_PEERS - 1;
/// Maximum concurrent streams for each proof, block, or head-pull exchange.
pub const MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION: usize = 2;
/// Maximum concurrent head-announcement streams on one connection.
pub const MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION: usize = 1;
/// Maximum concurrent application-exchange streams on one connection.
pub const MAX_EXCHANGE_STREAMS_PER_CONNECTION: usize =
    MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION * 3 + MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION;
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
/// Maximum burst of admitted journal-response attempts per network instance.
pub const INBOUND_APPLICATION_REQUEST_BURST: u32 = 8;
/// Sustained refill interval for journal-backed authenticated-peer responses.
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
    proof_exchange: request_response::Behaviour<ProofCodec>,
    block_exchange: request_response::Behaviour<ProofBlockCodec>,
    head_exchange: request_response::Behaviour<ProofChainHeadCodec>,
    head_announcement: request_response::Behaviour<ProofChainHeadAnnouncementCodec>,
}

struct PendingProofRequest {
    peer_index: usize,
    request: ProofRequest,
    control: Arc<AcquisitionControl>,
    _permit: PendingPermit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ExchangeRequestId {
    Proof(request_response::OutboundRequestId),
    Block(request_response::OutboundRequestId),
    Head(request_response::OutboundRequestId),
    Announcement(request_response::OutboundRequestId),
}

enum PendingRequest {
    Proof(PendingProofRequest),
    Block(PendingProofBlockRequest),
    Head(PendingProofChainHeadRequest),
    Announcement(PendingProofChainHeadAnnouncement),
}

impl PendingRequest {
    fn peer_index(&self) -> usize {
        match self {
            Self::Proof(pending) => pending.peer_index,
            Self::Block(pending) => pending.peer_index,
            Self::Head(pending) => pending.peer_index,
            Self::Announcement(pending) => pending.peer_index,
        }
    }
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
    pending: HashMap<ExchangeRequestId, PendingRequest>,
    pending_budget: Arc<PendingBudget>,
    inbound_application_request_budget: rate_limit::TokenBucket,
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
            .with_max_concurrent_streams(MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION);
        let proof_exchange = request_response::Behaviour::with_codec(
            ProofCodec,
            [(PROTOCOL, request_response::ProtocolSupport::Full)],
            exchange_config.clone(),
        );
        let block_exchange = request_response::Behaviour::with_codec(
            ProofBlockCodec,
            [(
                PROOF_BLOCK_PROTOCOL,
                request_response::ProtocolSupport::Full,
            )],
            exchange_config.clone(),
        );
        let head_exchange = request_response::Behaviour::with_codec(
            ProofChainHeadCodec,
            [(
                PROOF_CHAIN_HEAD_PROTOCOL,
                request_response::ProtocolSupport::Full,
            )],
            exchange_config,
        );
        let announcement_config = request_response::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION);
        let head_announcement = request_response::Behaviour::with_codec(
            ProofChainHeadAnnouncementCodec,
            [(
                PROOF_CHAIN_HEAD_ANNOUNCEMENT_PROTOCOL,
                request_response::ProtocolSupport::Full,
            )],
            announcement_config,
        );

        let behaviour = Behaviour {
            limits,
            allowed,
            sessions,
            proof_exchange,
            block_exchange,
            head_exchange,
            head_announcement,
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

    fn request_acquisition_proof(
        &mut self,
        peer_id: PeerId,
        request: ProofRequest,
        control: &Arc<AcquisitionControl>,
    ) -> Result<request_response::OutboundRequestId, RequestStartError> {
        let transport_connected = self.swarm.behaviour().proof_exchange.is_connected(&peer_id);
        let (peer_index, permit) = self.acquire_request_permit(peer_id, transport_connected)?;
        let request_id = self
            .swarm
            .behaviour_mut()
            .proof_exchange
            .send_request(&peer_id, request);
        self.insert_pending(
            ExchangeRequestId::Proof(request_id),
            PendingRequest::Proof(PendingProofRequest {
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
            (ExchangeRequestId::Proof(_), PendingRequest::Proof(_))
                | (ExchangeRequestId::Block(_), PendingRequest::Block(_))
                | (ExchangeRequestId::Head(_), PendingRequest::Head(_))
                | (
                    ExchangeRequestId::Announcement(_),
                    PendingRequest::Announcement(_)
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
                SwarmEvent::Behaviour(BehaviourEvent::ProofExchange(event)) => {
                    if let Some(event) = self.handle_proof_exchange_event(event) {
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
            .filter_map(|pending| match pending {
                PendingRequest::Proof(pending) if !pending.control.is_cancelled() => {
                    Some(pending.control.deadline)
                }
                PendingRequest::Proof(_)
                | PendingRequest::Block(_)
                | PendingRequest::Head(_)
                | PendingRequest::Announcement(_) => None,
            })
            .min()
    }

    fn take_due_acquisition_deadline(&mut self, now: Instant) -> Option<NetworkEvent> {
        let request_id = self
            .pending
            .iter()
            .filter_map(|(key, pending)| match (key, pending) {
                (ExchangeRequestId::Proof(request_id), PendingRequest::Proof(pending))
                    if !pending.control.is_cancelled() && now >= pending.control.deadline =>
                {
                    Some((*request_id, pending.control.deadline))
                }
                _ => None,
            })
            .min_by_key(|(request_id, deadline)| (*deadline, *request_id))?
            .0;
        let PendingRequest::Proof(pending) = self
            .pending
            .get(&ExchangeRequestId::Proof(request_id))
            .expect("the due proof request remains pending")
        else {
            unreachable!("a proof request key always stores a proof request")
        };
        if !pending.control.cancel() {
            return None;
        }
        let peer_id = self.pending_peer_id(pending.peer_index);
        Some(NetworkEvent::OutboundProof(OutboundProofEvent {
            request_id,
            peer_id,
            request: pending.request,
            control: Arc::clone(&pending.control),
            outcome: OutboundProofOutcome::DeadlineExceeded,
        }))
    }

    fn handle_proof_exchange_event(
        &mut self,
        event: request_response::Event<ProofRequest, ProofResponse>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundProofRequest(InboundProofRequest {
                    peer_id: peer,
                    request_id,
                    request,
                    channel,
                })),
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let pending = self.remove_pending_proof(request_id)?;
                    let expected = self.pending_peer_id(pending.peer_index);
                    if expected != peer {
                        return Some(Self::finish_peer_mismatch(
                            request_id, pending, expected, peer,
                        ));
                    }
                    if pending.control.is_cancelled() {
                        return Some(NetworkEvent::ProofCancellationDrained {
                            peer_id: expected,
                            request: pending.request,
                            outcome: CancellationDrainOutcome::ResponseDiscarded,
                        });
                    }
                    if Instant::now() >= pending.control.deadline {
                        return Some(if pending.control.cancel() {
                            NetworkEvent::OutboundProof(OutboundProofEvent {
                                request_id,
                                peer_id: expected,
                                request: pending.request,
                                control: pending.control,
                                outcome: OutboundProofOutcome::DeadlineExceeded,
                            })
                        } else {
                            NetworkEvent::ProofCancellationDrained {
                                peer_id: expected,
                                request: pending.request,
                                outcome: CancellationDrainOutcome::ResponseDiscarded,
                            }
                        });
                    }
                    Some(NetworkEvent::OutboundProof(OutboundProofEvent {
                        request_id,
                        peer_id: expected,
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
                let pending = self.remove_pending_proof(request_id)?;
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
                    Box::new(OutboundProofFailure::Transport(error)),
                ))
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => Some(NetworkEvent::InboundProofFailure {
                peer_id: peer,
                request_id,
                error,
            }),
            request_response::Event::ResponseSent { .. } => None,
        }
    }

    fn finish_peer_mismatch(
        request_id: request_response::OutboundRequestId,
        pending: PendingProofRequest,
        expected: PeerId,
        actual: PeerId,
    ) -> NetworkEvent {
        let error = Box::new(OutboundProofFailure::PeerMismatch { expected, actual });
        if pending.control.is_cancelled() {
            return NetworkEvent::ProofCancellationDrained {
                peer_id: expected,
                request: pending.request,
                outcome: CancellationDrainOutcome::Failure(error),
            };
        }
        NetworkEvent::OutboundProof(OutboundProofEvent {
            request_id,
            peer_id: expected,
            request: pending.request,
            control: pending.control,
            outcome: OutboundProofOutcome::Failure(error),
        })
    }

    fn finish_failed_request(
        request_id: request_response::OutboundRequestId,
        pending: PendingProofRequest,
        peer_id: PeerId,
        error: Box<OutboundProofFailure>,
    ) -> NetworkEvent {
        if pending.control.is_cancelled() {
            return NetworkEvent::ProofCancellationDrained {
                peer_id,
                request: pending.request,
                outcome: CancellationDrainOutcome::Failure(error),
            };
        }
        if Instant::now() >= pending.control.deadline {
            return if pending.control.cancel() {
                NetworkEvent::OutboundProof(OutboundProofEvent {
                    request_id,
                    peer_id,
                    request: pending.request,
                    control: pending.control,
                    outcome: OutboundProofOutcome::DeadlineExceeded,
                })
            } else {
                NetworkEvent::ProofCancellationDrained {
                    peer_id,
                    request: pending.request,
                    outcome: CancellationDrainOutcome::Failure(error),
                }
            };
        }
        NetworkEvent::OutboundProof(OutboundProofEvent {
            request_id,
            peer_id,
            request: pending.request,
            control: pending.control,
            outcome: OutboundProofOutcome::Failure(error),
        })
    }

    fn remove_pending_proof(
        &mut self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<PendingProofRequest> {
        let pending = self.pending.remove(&ExchangeRequestId::Proof(request_id))?;
        let PendingRequest::Proof(pending) = pending else {
            unreachable!("a proof request key always stores a proof request")
        };
        Some(pending)
    }

    #[cfg(test)]
    fn pending_proof(
        &self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<&PendingProofRequest> {
        match self.pending.get(&ExchangeRequestId::Proof(request_id))? {
            PendingRequest::Proof(pending) => Some(pending),
            PendingRequest::Block(_) => {
                unreachable!("a proof request key always stores a proof request")
            }
            PendingRequest::Head(_) => {
                unreachable!("a proof request key always stores a proof request")
            }
            PendingRequest::Announcement(_) => {
                unreachable!("a proof request key always stores a proof request")
            }
        }
    }

    /// Serves one authenticated request from the healthy local journal.
    ///
    /// One bounded proof-sized copy is required because rust-libp2p owns the
    /// response until its asynchronous stream write completes. The journal is
    /// not borrowed across that write.
    pub fn respond_proof_from_journal(
        &mut self,
        inbound: InboundProofRequest,
        journal: &ProofChainJournal,
    ) -> Result<(), RespondError> {
        let response_bytes = journal
            .proof(inbound.request.proof_id())
            .map_err(RespondError::Journal)?
            .map(|record| record.canonical_proof_bytes());
        if !inbound.channel.is_open() {
            return Err(RespondError::ChannelClosed);
        }
        self.take_inbound_application_request()?;
        let bytes = response_bytes.map_or_else(Vec::new, <[u8]>::to_vec);
        debug_assert!(bytes.len() <= PROOF_RESPONSE_MAX_BYTES);
        let response = ProofResponse::from_wire_bytes(bytes)
            .expect("retained canonical proof obeys the certificate limit");
        self.swarm
            .behaviour_mut()
            .proof_exchange
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
    InboundProofRequest(InboundProofRequest),
    OutboundProof(OutboundProofEvent),
    InboundBlockRequest(InboundProofBlockRequest),
    OutboundBlock(OutboundProofBlockEvent),
    InboundChainHeadRequest(InboundProofChainHeadRequest),
    OutboundChainHead(OutboundProofChainHeadEvent),
    InboundChainHeadAnnouncement(InboundProofChainHeadAnnouncement),
    OutboundChainHeadAnnouncement(OutboundProofChainHeadAnnouncementEvent),
    ProofCancellationDrained {
        peer_id: PeerId,
        request: ProofRequest,
        outcome: CancellationDrainOutcome,
    },
    InboundProofFailure {
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

/// Failure to start one outbound proof-network exchange request.
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
    Journal(ProofChainJournalError),
    ChannelClosed,
    RateLimited,
}

impl fmt::Display for RespondError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(source) => {
                write!(formatter, "cannot read proof-chain journal: {source}")
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
            Self::ChannelClosed | Self::RateLimited => None,
        }
    }
}

#[cfg(test)]
mod tests;
