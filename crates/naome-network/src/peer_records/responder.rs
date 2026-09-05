use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use libp2p::core::{Endpoint, Multiaddr, transport::PortUse};
use libp2p::futures::StreamExt;
use libp2p::swarm::behaviour::{FromSwarm, ToSwarm};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent,
    dummy,
};
use libp2p::{
    PeerId, Swarm, SwarmBuilder, connection_limits, identity::Keypair, noise, request_response, tcp,
};
use tokio::time::Instant;

use crate::ListenerId;
use crate::codec::{PEER_RECORD_PROTOCOL, PeerRecordResponderCodec, PeerRecordResponderRequest};
use crate::rate_limit::TokenBucket;
use crate::record_exchange::{PeerRecordBatch, PeerRecordExchangeWireError};
use crate::{
    CONNECTION_TIMEOUT, INBOUND_AUTH_BURST, INBOUND_AUTH_REFILL_INTERVAL, MAX_CONNECTIONS_PER_PEER,
    MAX_PEER_RECORD_STREAMS_PER_CONNECTION, PEER_RECORD_IDLE_TIMEOUT, REQUEST_TIMEOUT,
    TCP_LISTEN_BACKLOG, yamux_config,
};

const MAX_RESPONDER_CONNECTIONS: usize = 8;
const RESPONSE_BURST: u32 = 8;
const RESPONSE_REFILL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    pre_authentication: PreAuthenticationGate,
    exchange: request_response::Behaviour<PeerRecordResponderCodec>,
}

struct PreAuthenticationGate {
    budget: TokenBucket,
}

impl PreAuthenticationGate {
    fn new(now: Instant) -> Self {
        Self {
            budget: TokenBucket::new(INBOUND_AUTH_BURST, INBOUND_AUTH_REFILL_INTERVAL, now),
        }
    }
}

impl NetworkBehaviour for PreAuthenticationGate {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if self.budget.try_take(Instant::now()) {
            Ok(())
        } else {
            Err(ConnectionDenied::new(ResponderDenied))
        }
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        Err(ConnectionDenied::new(ResponderDenied))
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Err(ConnectionDenied::new(ResponderDenied))
    }

    fn on_swarm_event(&mut self, _: FromSwarm<'_>) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[derive(Debug)]
struct ResponderDenied;

impl fmt::Display for ResponderDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("peer-record responder connection denied")
    }
}

impl Error for ResponderDenied {}

/// Inbound-only server for one explicit immutable peer-record publication.
///
/// The responder accepts Noise-authenticated requesters but grants them no
/// artifact authority. It never reads from a peer-address store, dials another
/// node, retries, or starts a background task. The caller must continuously
/// poll [`Self::next_event`] for network progress and timeout delivery. The
/// same responder serves configured-bootstrap and caller-selected learned-peer
/// pulls; it assigns neither role to its own identity.
pub struct PeerRecordBootstrapResponder {
    swarm: Swarm<Behaviour>,
    publication: Arc<Vec<u8>>,
    response_budget: TokenBucket,
    suppressed_terminals: Vec<request_response::InboundRequestId>,
    listener_id: Option<ListenerId>,
    #[cfg(test)]
    last_request_connection_id: Option<ConnectionId>,
}

impl PeerRecordBootstrapResponder {
    /// Builds one bounded responder around a verified canonical batch.
    ///
    /// The publication is encoded once and remains immutable for the complete
    /// lifetime of this responder. This must run inside a Tokio runtime with
    /// I/O and time drivers enabled.
    pub fn new(
        identity: Keypair,
        publication: PeerRecordBatch,
    ) -> Result<Self, PeerRecordBootstrapResponderBuildError> {
        let encoded_publication = publication
            .to_wire_bytes()
            .map_err(PeerRecordBootstrapResponderBuildError::Publication)?;
        drop(publication);
        let maximum = u32::try_from(MAX_RESPONDER_CONNECTIONS)
            .expect("the responder connection cap fits u32");
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
            PeerRecordResponderCodec,
            [(
                PEER_RECORD_PROTOCOL,
                request_response::ProtocolSupport::Inbound,
            )],
            request_response::Config::default()
                .with_request_timeout(REQUEST_TIMEOUT)
                .with_max_concurrent_streams(MAX_PEER_RECORD_STREAMS_PER_CONNECTION),
        );
        let behaviour = Behaviour {
            limits,
            pre_authentication: PreAuthenticationGate::new(Instant::now()),
            exchange,
        };
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::new().listen_backlog(TCP_LISTEN_BACKLOG),
                noise::Config::new,
                || yamux_config(MAX_PEER_RECORD_STREAMS_PER_CONNECTION),
            )
            .map_err(PeerRecordBootstrapResponderBuildError::Noise)?
            .with_behaviour(|_| behaviour)
            .expect("constructing the fixed peer-record responder behavior is infallible")
            .with_swarm_config(|config| {
                config
                    .with_idle_connection_timeout(PEER_RECORD_IDLE_TIMEOUT)
                    .with_max_negotiating_inbound_streams(MAX_PEER_RECORD_STREAMS_PER_CONNECTION)
            })
            .with_connection_timeout(CONNECTION_TIMEOUT)
            .build();
        Ok(Self {
            swarm,
            publication: Arc::new(encoded_publication),
            response_budget: TokenBucket::new(
                RESPONSE_BURST,
                RESPONSE_REFILL_INTERVAL,
                Instant::now(),
            ),
            suppressed_terminals: Vec::with_capacity(MAX_RESPONDER_CONNECTIONS),
            listener_id: None,
            #[cfg(test)]
            last_request_connection_id: None,
        })
    }

    /// Returns the responder's Noise-authenticated identity.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Returns the number of records in the immutable publication.
    pub fn published_record_count(&self) -> usize {
        usize::from(self.publication[0])
    }

    /// Starts the responder's single TCP listener.
    pub fn listen_on(
        &mut self,
        address: Multiaddr,
    ) -> Result<ListenerId, PeerRecordBootstrapResponderListenError> {
        if self.listener_id.is_some() {
            return Err(PeerRecordBootstrapResponderListenError::AlreadyListening);
        }
        let listener_id = self
            .swarm
            .listen_on(address)
            .map_err(PeerRecordBootstrapResponderListenError::Transport)?;
        self.listener_id = Some(listener_id);
        Ok(listener_id)
    }

    /// Waits for the next externally relevant responder event.
    pub async fn next_event(&mut self) -> PeerRecordBootstrapResponderEvent {
        loop {
            match self.swarm.select_next_some().await {
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Exchange(event)) => {
                    if let Some(event) = self.handle_exchange_event(event) {
                        return event;
                    }
                }
                libp2p::swarm::SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                } if self.listener_id == Some(listener_id) => {
                    return PeerRecordBootstrapResponderEvent::Listening { address };
                }
                libp2p::swarm::SwarmEvent::ListenerError { listener_id, error }
                    if self.listener_id == Some(listener_id) =>
                {
                    return PeerRecordBootstrapResponderEvent::ListenerError { listener_id, error };
                }
                libp2p::swarm::SwarmEvent::ListenerClosed {
                    listener_id,
                    addresses,
                    reason,
                } if self.listener_id == Some(listener_id) => {
                    self.listener_id = None;
                    return PeerRecordBootstrapResponderEvent::ListenerClosed {
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
        event: request_response::Event<PeerRecordResponderRequest, Arc<Vec<u8>>>,
    ) -> Option<PeerRecordBootstrapResponderEvent> {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Request {
                        request,
                        request_id,
                        channel,
                    },
            } => {
                #[cfg(test)]
                {
                    self.last_request_connection_id = Some(connection_id);
                }
                let rejection = match request {
                    PeerRecordResponderRequest::Valid => {
                        (!self.response_budget.try_take(Instant::now()))
                            .then_some(PeerRecordBootstrapResponderFailure::RateLimited)
                    }
                    PeerRecordResponderRequest::Invalid => {
                        Some(PeerRecordBootstrapResponderFailure::InvalidRequest)
                    }
                    PeerRecordResponderRequest::ReadTimedOut => {
                        Some(PeerRecordBootstrapResponderFailure::RequestReadTimedOut)
                    }
                    PeerRecordResponderRequest::ReadFailed(source) => Some(
                        PeerRecordBootstrapResponderFailure::RequestReadFailed(source),
                    ),
                };
                if let Some(error) = rejection {
                    self.suppress_terminal(request_id);
                    drop(channel);
                    self.swarm.close_connection(connection_id);
                    return Some(PeerRecordBootstrapResponderEvent::Failed {
                        requester_peer_id: peer,
                        error,
                    });
                }
                if self
                    .swarm
                    .behaviour_mut()
                    .exchange
                    .send_response(channel, Arc::clone(&self.publication))
                    .is_err()
                {
                    self.swarm.close_connection(connection_id);
                    return None;
                }
                None
            }
            request_response::Event::ResponseSent { peer, .. } => {
                Some(PeerRecordBootstrapResponderEvent::ResponseSent {
                    requester_peer_id: peer,
                })
            }
            request_response::Event::InboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            } => {
                self.swarm.close_connection(connection_id);
                if let Some(index) = self
                    .suppressed_terminals
                    .iter()
                    .position(|suppressed| *suppressed == request_id)
                {
                    self.suppressed_terminals.swap_remove(index);
                    return None;
                }
                Some(PeerRecordBootstrapResponderEvent::Failed {
                    requester_peer_id: peer,
                    error: PeerRecordBootstrapResponderFailure::Transport(error),
                })
            }
            request_response::Event::Message {
                message: request_response::Message::Response { .. },
                ..
            }
            | request_response::Event::OutboundFailure { .. } => None,
        }
    }

    fn suppress_terminal(&mut self, request_id: request_response::InboundRequestId) {
        debug_assert!(self.suppressed_terminals.len() < MAX_RESPONDER_CONNECTIONS);
        self.suppressed_terminals.push(request_id);
    }

    #[cfg(test)]
    fn last_request_connection_id(&self) -> Option<ConnectionId> {
        self.last_request_connection_id
    }

    #[cfg(test)]
    fn remove_listener_for_test(&mut self) -> bool {
        self.listener_id
            .is_some_and(|listener_id| self.swarm.remove_listener(listener_id))
    }
}

/// Failure to build an inbound peer-record responder.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerRecordBootstrapResponderBuildError {
    /// The immutable publication could not be encoded.
    Publication(PeerRecordExchangeWireError),
    /// The Noise authentication configuration could not be built.
    Noise(noise::Error),
}

impl fmt::Display for PeerRecordBootstrapResponderBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Publication(source) => {
                write!(formatter, "cannot encode peer-record publication: {source}")
            }
            Self::Noise(source) => {
                write!(
                    formatter,
                    "cannot configure peer-record responder Noise: {source}"
                )
            }
        }
    }
}

impl Error for PeerRecordBootstrapResponderBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Publication(source) => Some(source),
            Self::Noise(source) => Some(source),
        }
    }
}

/// Failure to start the responder's single listener.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerRecordBootstrapResponderListenError {
    /// This responder already owns one active listener.
    AlreadyListening,
    /// The TCP transport rejected the requested address.
    Transport(libp2p::TransportError<std::io::Error>),
}

impl fmt::Display for PeerRecordBootstrapResponderListenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyListening => formatter.write_str("peer-record responder already listens"),
            Self::Transport(source) => {
                write!(formatter, "cannot listen for peer-record pulls: {source}")
            }
        }
    }
}

impl Error for PeerRecordBootstrapResponderListenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::AlreadyListening => None,
        }
    }
}

/// Terminal failure while serving one authenticated requester.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerRecordBootstrapResponderFailure {
    /// The exact inbound request ended in a libp2p transport failure.
    Transport(request_response::InboundFailure),
    /// The global valid-request budget was exhausted.
    RateLimited,
    /// The request was nonempty even though the wire contract is exactly empty.
    InvalidRequest,
    /// The request did not close its write half within the fixed read budget.
    RequestReadTimedOut,
    /// The request stream failed while reading the exact empty body.
    RequestReadFailed(std::io::Error),
}

impl fmt::Display for PeerRecordBootstrapResponderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => write!(formatter, "peer-record response failed: {source}"),
            Self::RateLimited => formatter.write_str("peer-record response rate exceeded"),
            Self::InvalidRequest => formatter.write_str("invalid peer-record pull request"),
            Self::RequestReadTimedOut => {
                formatter.write_str("peer-record pull request read timed out")
            }
            Self::RequestReadFailed(source) => {
                write!(formatter, "peer-record pull request read failed: {source}")
            }
        }
    }
}

impl Error for PeerRecordBootstrapResponderFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::RequestReadFailed(source) => Some(source),
            Self::RateLimited | Self::InvalidRequest | Self::RequestReadTimedOut => None,
        }
    }
}

/// One externally relevant event from the inbound-only responder.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum PeerRecordBootstrapResponderEvent {
    /// The single configured listener exposed one concrete address.
    Listening { address: Multiaddr },
    /// The fixed publication was flushed locally for one authenticated requester.
    ResponseSent { requester_peer_id: PeerId },
    /// One inbound request produced a responder-visible failure.
    Failed {
        requester_peer_id: PeerId,
        error: PeerRecordBootstrapResponderFailure,
    },
    /// The active listener reported a transport error.
    ListenerError {
        listener_id: ListenerId,
        error: std::io::Error,
    },
    /// The active listener closed and released the one-listener slot.
    ListenerClosed {
        listener_id: ListenerId,
        addresses: Vec<Multiaddr>,
        reason: Result<(), std::io::Error>,
    },
}

#[cfg(test)]
mod tests;
