//! Authenticated transport binding for one peer-local artifact-chain head.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response;
use naome_chain::ArtifactBlockId;
use naome_protocol::chain_head_exchange::{ArtifactChainHeadRequest, ArtifactChainHeadResponse};
use naome_storage::ArtifactChainJournal;

use super::{
    ExchangeRequestId, NetworkEvent, PeerId, PendingBudget, PendingPermit, PendingRequest,
    RequestStartError, RespondError, StaticArtifactNetwork,
};

pub(super) struct PendingArtifactChainHeadRequest {
    pub(super) peer_index: usize,
    pub(super) request: ArtifactChainHeadRequest,
    pub(super) _permit: PendingPermit,
}

/// One opaque generation of an outbound artifact-chain-head request.
///
/// Dropping the ticket does not cancel its physical libp2p request. The
/// transport retains the peer slot and global permit until the corresponding
/// response or failure becomes terminal.
#[must_use]
pub struct ChainHeadRequestTicket {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: ArtifactChainHeadRequest,
    network_budget: Arc<PendingBudget>,
}

impl ChainHeadRequestTicket {
    /// Returns the authenticated peer expected for this request generation.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable chain-head request carried by this generation.
    pub const fn request(&self) -> ArtifactChainHeadRequest {
        self.request
    }

    /// Returns whether `event` is the exact terminal for this ticket.
    pub fn accepts_event(&self, event: &OutboundArtifactChainHeadEvent) -> bool {
        self.request_id == event.request_id
            && self.peer_id == event.peer_id
            && self.request == event.request
            && Arc::ptr_eq(&self.network_budget, event.network_budget())
    }

    /// Consumes this ticket and its exact terminal event.
    ///
    /// A mismatched event is returned together with this still-routable ticket;
    /// no response or failure can be extracted without generation correlation.
    pub fn complete(
        self,
        event: OutboundArtifactChainHeadEvent,
    ) -> Result<
        Result<AuthenticatedArtifactChainHeadResponse, Box<OutboundArtifactChainHeadFailure>>,
        Box<ArtifactChainHeadRequestEventMismatch>,
    > {
        if !self.accepts_event(&event) {
            return Err(Box::new(ArtifactChainHeadRequestEventMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.into_result())
    }
}

impl fmt::Debug for ChainHeadRequestTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChainHeadRequestTicket")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// One ticket/event mismatch that preserves both values for routing.
#[must_use]
pub struct ArtifactChainHeadRequestEventMismatch {
    ticket: ChainHeadRequestTicket,
    event: OutboundArtifactChainHeadEvent,
}

impl ArtifactChainHeadRequestEventMismatch {
    /// Returns the unmatched ticket and terminal event.
    pub fn into_parts(self) -> (ChainHeadRequestTicket, OutboundArtifactChainHeadEvent) {
        (self.ticket, self.event)
    }
}

impl fmt::Debug for ArtifactChainHeadRequestEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactChainHeadRequestEventMismatch")
            .field("ticket", &self.ticket)
            .field("event", &self.event)
            .finish()
    }
}

impl fmt::Display for ArtifactChainHeadRequestEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("artifact-chain-head terminal event does not match its request ticket")
    }
}

impl Error for ArtifactChainHeadRequestEventMismatch {}

/// One request received from an authenticated, statically authorized peer.
#[must_use]
pub struct InboundArtifactChainHeadRequest {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    request: ArtifactChainHeadRequest,
    channel: request_response::ResponseChannel<ArtifactChainHeadResponse>,
}

impl InboundArtifactChainHeadRequest {
    /// Returns the authenticated sender.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the requested artifact-chain context.
    pub const fn request(&self) -> ArtifactChainHeadRequest {
        self.request
    }
}

impl fmt::Debug for InboundArtifactChainHeadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundArtifactChainHeadRequest")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// One terminal chain-head event awaiting its exact generation ticket.
#[must_use]
pub struct OutboundArtifactChainHeadEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: ArtifactChainHeadRequest,
    outcome: OutboundArtifactChainHeadOutcome,
}

impl OutboundArtifactChainHeadEvent {
    /// Returns the expected authenticated peer.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable request that caused this terminal event.
    pub const fn request(&self) -> ArtifactChainHeadRequest {
        self.request
    }

    fn network_budget(&self) -> &Arc<PendingBudget> {
        match &self.outcome {
            OutboundArtifactChainHeadOutcome::Response { _permit, .. } => &_permit.budget,
            OutboundArtifactChainHeadOutcome::Failure { network_budget, .. } => network_budget,
        }
    }

    fn into_result(
        self,
    ) -> Result<AuthenticatedArtifactChainHeadResponse, Box<OutboundArtifactChainHeadFailure>> {
        match self.outcome {
            OutboundArtifactChainHeadOutcome::Response { response, .. } => {
                Ok(AuthenticatedArtifactChainHeadResponse {
                    peer_id: self.peer_id,
                    request: self.request,
                    response,
                })
            }
            OutboundArtifactChainHeadOutcome::Failure { error, .. } => Err(error),
        }
    }
}

impl fmt::Debug for OutboundArtifactChainHeadEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match &self.outcome {
            OutboundArtifactChainHeadOutcome::Response { .. } => "Response",
            OutboundArtifactChainHeadOutcome::Failure { .. } => "Failure",
        };
        formatter
            .debug_struct("OutboundArtifactChainHeadEvent")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("outcome", &outcome)
            .finish_non_exhaustive()
    }
}

enum OutboundArtifactChainHeadOutcome {
    Response {
        response: ArtifactChainHeadResponse,
        _permit: PendingPermit,
    },
    Failure {
        error: Box<OutboundArtifactChainHeadFailure>,
        network_budget: Arc<PendingBudget>,
    },
}

/// One authenticated peer-local response to an exact chain-head request.
///
/// Authentication binds the response to `peer_id`; it does not make the
/// reported head fresh, selected, available, finalized, or authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct AuthenticatedArtifactChainHeadResponse {
    peer_id: PeerId,
    request: ArtifactChainHeadRequest,
    response: ArtifactChainHeadResponse,
}

impl AuthenticatedArtifactChainHeadResponse {
    /// Returns the authenticated peer that supplied this response.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact chain context requested from that peer.
    pub const fn request(&self) -> ArtifactChainHeadRequest {
        self.request
    }

    /// Returns whether this peer reported the requested chain unavailable.
    pub const fn is_unavailable(&self) -> bool {
        self.response.is_unavailable()
    }

    /// Returns this peer's untrusted reported head, when available.
    pub const fn head_block_id(&self) -> Option<ArtifactBlockId> {
        self.response.head_block_id()
    }
}

/// A typed terminal failure for one exact outbound chain-head request.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundArtifactChainHeadFailure {
    /// The request-response stream failed before a complete response arrived.
    Transport(request_response::OutboundFailure),
    /// A terminal event came from a peer other than the retained expectation.
    PeerMismatch { expected: PeerId, actual: PeerId },
}

impl fmt::Display for OutboundArtifactChainHeadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => {
                write!(formatter, "artifact-chain-head request failed: {source}")
            }
            Self::PeerMismatch { expected, actual } => write!(
                formatter,
                "artifact-chain-head terminal event came from {actual}, expected {expected}"
            ),
        }
    }
}

impl Error for OutboundArtifactChainHeadFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::PeerMismatch { .. } => None,
        }
    }
}

impl StaticArtifactNetwork {
    /// Starts one chain-scoped head request over an established managed session.
    ///
    /// The returned ticket is the only public path to the terminal outcome.
    /// This method never opens a request-driven connection or imports a block.
    pub fn request_chain_head(
        &mut self,
        peer_id: PeerId,
        request: ArtifactChainHeadRequest,
    ) -> Result<ChainHeadRequestTicket, RequestStartError> {
        let transport_connected = self.swarm.behaviour().head_exchange.is_connected(&peer_id);
        let (peer_index, permit) = self.acquire_request_permit(peer_id, transport_connected)?;
        Ok(self.enqueue_chain_head_request(peer_index, peer_id, request, permit))
    }

    pub(super) fn enqueue_chain_head_request(
        &mut self,
        peer_index: usize,
        peer_id: PeerId,
        request: ArtifactChainHeadRequest,
        permit: PendingPermit,
    ) -> ChainHeadRequestTicket {
        debug_assert_eq!(self.pending_peer_id(peer_index), peer_id);
        let request_id = self
            .swarm
            .behaviour_mut()
            .head_exchange
            .send_request(&peer_id, request);
        let ticket = ChainHeadRequestTicket {
            request_id,
            peer_id,
            request,
            network_budget: Arc::clone(&self.pending_budget),
        };
        self.insert_pending(
            ExchangeRequestId::Head(request_id),
            PendingRequest::Head(PendingArtifactChainHeadRequest {
                peer_index,
                request,
                _permit: permit,
            }),
        );
        ticket
    }

    pub(super) fn handle_head_exchange_event(
        &mut self,
        event: request_response::Event<ArtifactChainHeadRequest, ArtifactChainHeadResponse>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundChainHeadRequest(
                    InboundArtifactChainHeadRequest {
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
                    let pending = self.remove_pending_head(request_id)?;
                    let expected = self.pending_peer_id(pending.peer_index);
                    if expected != peer {
                        return Some(Self::finish_head_failure(
                            request_id,
                            expected,
                            pending,
                            OutboundArtifactChainHeadFailure::PeerMismatch {
                                expected,
                                actual: peer,
                            },
                        ));
                    }
                    Some(Self::finish_head_response(
                        request_id, expected, pending, response,
                    ))
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let pending = self.remove_pending_head(request_id)?;
                let expected = self.pending_peer_id(pending.peer_index);
                let failure = if expected == peer {
                    OutboundArtifactChainHeadFailure::Transport(error)
                } else {
                    OutboundArtifactChainHeadFailure::PeerMismatch {
                        expected,
                        actual: peer,
                    }
                };
                Some(Self::finish_head_failure(
                    request_id, expected, pending, failure,
                ))
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => Some(NetworkEvent::InboundChainHeadFailure {
                peer_id: peer,
                request_id,
                error,
            }),
            request_response::Event::ResponseSent { .. } => None,
        }
    }

    fn finish_head_response(
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
        pending: PendingArtifactChainHeadRequest,
        response: ArtifactChainHeadResponse,
    ) -> NetworkEvent {
        let PendingArtifactChainHeadRequest {
            peer_index: _,
            request,
            _permit,
        } = pending;
        NetworkEvent::OutboundChainHead(OutboundArtifactChainHeadEvent {
            request_id,
            peer_id,
            request,
            outcome: OutboundArtifactChainHeadOutcome::Response { response, _permit },
        })
    }

    fn finish_head_failure(
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
        pending: PendingArtifactChainHeadRequest,
        failure: OutboundArtifactChainHeadFailure,
    ) -> NetworkEvent {
        let network_budget = Arc::clone(&pending._permit.budget);
        NetworkEvent::OutboundChainHead(OutboundArtifactChainHeadEvent {
            request_id,
            peer_id,
            request: pending.request,
            outcome: OutboundArtifactChainHeadOutcome::Failure {
                error: Box::new(failure),
                network_budget,
            },
        })
    }

    fn remove_pending_head(
        &mut self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<PendingArtifactChainHeadRequest> {
        let pending = self.pending.remove(&ExchangeRequestId::Head(request_id))?;
        let PendingRequest::Head(pending) = pending else {
            unreachable!("a chain-head request key always stores a chain-head request")
        };
        Some(pending)
    }

    /// Serves one authenticated chain-head request from the healthy local journal.
    pub fn respond_chain_head_from_journal(
        &mut self,
        inbound: InboundArtifactChainHeadRequest,
        journal: &ArtifactChainJournal,
    ) -> Result<(), RespondError> {
        let head_block_id = journal.head_block_id().map_err(RespondError::Journal)?;
        let head_bytes = (journal.chain_id() == inbound.request.chain_id())
            .then_some(head_block_id)
            .map(|block_id| *block_id.as_bytes());
        if !inbound.channel.is_open() {
            return Err(RespondError::ChannelClosed);
        }
        self.take_inbound_application_request()?;
        let response = ArtifactChainHeadResponse::from_wire_bytes(
            head_bytes
                .as_ref()
                .map_or(&[][..], <[u8; ArtifactBlockId::BYTE_LENGTH]>::as_slice),
        )
        .expect("a journal head is an exact artifact-block identity");
        self.swarm
            .behaviour_mut()
            .head_exchange
            .send_response(inbound.channel, response)
            .map_err(|_| RespondError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests;
