//! Bounded canonical state exchange across sealed validator periods.
//!
//! TCP carries mutually authenticated Noise sessions, with Yamux stream limits,
//! bounded request custody, and exact response correlation. Selected period
//! peers use managed static sessions; owner-authenticated recovery sessions can
//! fetch history and handoff data after fresh-key possession is checked.
//! The caller drives every event loop. Transport owns no journal or signer and
//! a delivery receipt grants no mathematical, finality, or economic authority.

mod transport;
pub use libp2p::core::transport::ListenerId;
pub use libp2p::swarm::ConnectionId;
pub use libp2p::{Multiaddr, PeerId, identity::Keypair};
use transport::rate_limit;
pub use transport::{
    BuildError, CONNECTION_TIMEOUT, DIAL_RETRY_BASE, DIAL_RETRY_MAX, INBOUND_AUTH_BURST,
    INBOUND_AUTH_REFILL_INTERVAL, ListenError, MAX_CONNECTIONS_PER_PEER, MAX_PENDING_REQUESTS,
    MAX_STATIC_PEERS, MAX_YAMUX_STREAMS_PER_CONNECTION, NetworkEvent, PeerSessionEvent,
    RECOVERY_AUTH_TIMEOUT, REQUEST_TIMEOUT, RequestStartError, STABLE_SESSION_DURATION,
    StateNetwork, StateTransportEvent, StateTransportPair, StateTransportPairError, StaticPeer,
    TCP_LISTEN_BACKLOG,
};

pub use transport::state_exchange::{
    InboundState, RECOVERY_HELLO_BYTES, RecoveryDialError, RecoveryError, RecoveryHello,
    StateContext, StateEvent, StateFailure, StateHistoryItem, StateLane, StateMismatch,
    StateNetworkBuildError, StateReceivedResponse, StateRejection, StateRequest, StateRequestBody,
    StateRespondError, StateResponse, StateResponseBody, StateStartError, StateTicket,
    StateWireError, state_peer_id,
};
