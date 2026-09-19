//! Bounded canonical state exchange over immutable genesis peers.
//!
//! TCP carries mutually authenticated Noise sessions, with Yamux stream limits,
//! fixed dial ownership, bounded request custody, and exact response correlation.
//! The caller drives every event loop. Transport owns no journal or signer and
//! a delivery receipt grants no mathematical, finality, or economic authority.

mod transport;
pub use libp2p::core::transport::ListenerId;
pub use libp2p::{Multiaddr, PeerId, identity::Keypair};
use transport::rate_limit;
pub use transport::{
    BuildError, CONNECTION_TIMEOUT, DIAL_RETRY_BASE, DIAL_RETRY_MAX, INBOUND_AUTH_BURST,
    INBOUND_AUTH_REFILL_INTERVAL, ListenError, MAX_CONNECTIONS_PER_PEER, MAX_PENDING_REQUESTS,
    MAX_STATIC_PEERS, MAX_YAMUX_STREAMS_PER_CONNECTION, NetworkEvent, PeerSessionEvent,
    REQUEST_TIMEOUT, RequestStartError, STABLE_SESSION_DURATION, StaticArtifactNetwork, StaticPeer,
    TCP_LISTEN_BACKLOG,
};

pub use transport::state_exchange::{
    InboundResearch, ResearchContext, ResearchEvent, ResearchFailure, ResearchHistoryItem,
    ResearchMismatch, ResearchNetworkBuildError, ResearchReceivedResponse, ResearchRejection,
    ResearchRequest, ResearchRequestBody, ResearchRespondError, ResearchResponse,
    ResearchResponseBody, ResearchStartError, ResearchTicket, ResearchWireError, research_peer_id,
};
