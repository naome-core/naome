//! Authenticated transport binding for exact proof-block retrieval.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response;
use naome::block_exchange::{
    ProofBlockExchangeWireError, ProofBlockRequest, ProofBlockResponse, proof_block_response,
};
use naome_chain::ProofBlock;
use naome_storage::{ProofChainJournal, ProofChainJournalError};

use super::codec::ProofBlockWireResponse;
use super::{
    ExchangeRequestId, NetworkEvent, PeerId, PendingBudget, PendingPermit, PendingRequest,
    RequestStartError, RespondError, StaticProofNetwork,
};

pub(super) struct PendingProofBlockRequest {
    pub(super) peer_index: usize,
    pub(super) request: ProofBlockRequest,
    pub(super) _permit: PendingPermit,
}

/// One opaque generation of an outbound proof-block request.
///
/// Dropping the ticket does not cancel its physical libp2p request. The
/// transport retains the peer slot and global permit until the corresponding
/// response or failure becomes terminal.
#[must_use]
pub struct BlockRequestTicket {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: ProofBlockRequest,
    network_budget: Arc<PendingBudget>,
}

impl BlockRequestTicket {
    pub(super) fn belongs_to_network(&self, network: &StaticProofNetwork) -> bool {
        Arc::ptr_eq(&self.network_budget, &network.pending_budget)
    }

    /// Returns the authenticated peer expected for this request generation.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable block request carried by this generation.
    pub const fn request(&self) -> ProofBlockRequest {
        self.request
    }

    /// Returns whether `event` is the exact terminal for this ticket.
    pub fn accepts_event(&self, event: &OutboundProofBlockEvent) -> bool {
        self.request_id == event.request_id
            && self.peer_id == event.peer_id
            && self.request == event.request
            && Arc::ptr_eq(&self.network_budget, &event.network_budget)
    }

    /// Consumes this ticket and its exact terminal event.
    ///
    /// A mismatched event is returned together with this still-routable ticket;
    /// no response or failure can be extracted without generation correlation.
    pub fn complete(
        self,
        event: OutboundProofBlockEvent,
    ) -> Result<
        Result<ProofBlockResponse, Box<OutboundProofBlockFailure>>,
        Box<ProofBlockRequestEventMismatch>,
    > {
        if !self.accepts_event(&event) {
            return Err(Box::new(ProofBlockRequestEventMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.into_result())
    }
}

impl fmt::Debug for BlockRequestTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockRequestTicket")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// One ticket/event mismatch that preserves both values for routing.
#[must_use]
pub struct ProofBlockRequestEventMismatch {
    ticket: BlockRequestTicket,
    event: OutboundProofBlockEvent,
}

impl ProofBlockRequestEventMismatch {
    /// Returns the unmatched ticket and terminal event.
    pub fn into_parts(self) -> (BlockRequestTicket, OutboundProofBlockEvent) {
        (self.ticket, self.event)
    }
}

impl fmt::Debug for ProofBlockRequestEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofBlockRequestEventMismatch")
            .field("ticket", &self.ticket)
            .field("event", &self.event)
            .finish()
    }
}

impl fmt::Display for ProofBlockRequestEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("proof-block terminal event does not match its request ticket")
    }
}

impl Error for ProofBlockRequestEventMismatch {}

/// One request received from an authenticated, statically authorized peer.
#[must_use]
pub struct InboundProofBlockRequest {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    request: ProofBlockRequest,
    channel: request_response::ResponseChannel<ProofBlockWireResponse>,
}

impl InboundProofBlockRequest {
    /// Returns the authenticated sender.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact requested block address.
    pub const fn request(&self) -> ProofBlockRequest {
        self.request
    }
}

impl fmt::Debug for InboundProofBlockRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundProofBlockRequest")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// One terminal block-request event awaiting its exact generation ticket.
#[must_use]
pub struct OutboundProofBlockEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: ProofBlockRequest,
    network_budget: Arc<PendingBudget>,
    outcome: OutboundProofBlockOutcome,
}

impl OutboundProofBlockEvent {
    /// Returns the expected authenticated peer.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable request that caused this terminal event.
    pub const fn request(&self) -> ProofBlockRequest {
        self.request
    }

    fn into_result(self) -> Result<ProofBlockResponse, Box<OutboundProofBlockFailure>> {
        match self.outcome {
            OutboundProofBlockOutcome::Response { response, .. } => Ok(response),
            OutboundProofBlockOutcome::Failure(error) => Err(error),
        }
    }
}

impl fmt::Debug for OutboundProofBlockEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match &self.outcome {
            OutboundProofBlockOutcome::Response { .. } => "Response",
            OutboundProofBlockOutcome::Failure(_) => "Failure",
        };
        formatter
            .debug_struct("OutboundProofBlockEvent")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("outcome", &outcome)
            .finish_non_exhaustive()
    }
}

enum OutboundProofBlockOutcome {
    Response {
        response: ProofBlockResponse,
        _permit: PendingPermit,
    },
    Failure(Box<OutboundProofBlockFailure>),
}

fn checked_block_lookup(
    lookup: Result<Option<&ProofBlock>, ProofChainJournalError>,
) -> Result<Option<&ProofBlock>, RespondError> {
    lookup.map_err(RespondError::Journal)
}

/// A typed terminal failure for one exact outbound proof-block request.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundProofBlockFailure {
    /// The request-response stream failed before a complete response arrived.
    Transport(request_response::OutboundFailure),
    /// A complete bounded response violated block framing or request identity.
    InvalidResponse { source: ProofBlockExchangeWireError },
    /// A terminal event came from a peer other than the retained expectation.
    PeerMismatch { expected: PeerId, actual: PeerId },
}

impl fmt::Display for OutboundProofBlockFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => write!(formatter, "proof-block request failed: {source}"),
            Self::InvalidResponse { source } => {
                write!(formatter, "proof-block response is invalid: {source}")
            }
            Self::PeerMismatch { expected, actual } => write!(
                formatter,
                "proof-block terminal event came from {actual}, expected {expected}"
            ),
        }
    }
}

impl Error for OutboundProofBlockFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::InvalidResponse { source } => Some(source),
            Self::PeerMismatch { .. } => None,
        }
    }
}

impl StaticProofNetwork {
    /// Starts one exact block request over an established managed session.
    ///
    /// The returned ticket is the only public path to the terminal outcome.
    /// This method never opens a request-driven connection.
    pub fn request_block(
        &mut self,
        peer_id: PeerId,
        request: ProofBlockRequest,
    ) -> Result<BlockRequestTicket, RequestStartError> {
        let transport_connected = self.swarm.behaviour().block_exchange.is_connected(&peer_id);
        let (peer_index, permit) = self.acquire_request_permit(peer_id, transport_connected)?;
        let request_id = self
            .swarm
            .behaviour_mut()
            .block_exchange
            .send_request(&peer_id, request);
        let ticket = BlockRequestTicket {
            request_id,
            peer_id,
            request,
            network_budget: Arc::clone(&self.pending_budget),
        };
        self.insert_pending(
            ExchangeRequestId::Block(request_id),
            PendingRequest::Block(PendingProofBlockRequest {
                peer_index,
                request,
                _permit: permit,
            }),
        );
        Ok(ticket)
    }

    pub(super) fn handle_block_exchange_event(
        &mut self,
        event: request_response::Event<ProofBlockRequest, ProofBlockWireResponse>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundBlockRequest(
                    InboundProofBlockRequest {
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
                    let pending = self.remove_pending_block(request_id)?;
                    let expected = self.pending_peer_id(pending.peer_index);
                    if expected != peer {
                        return Some(Self::finish_block_failure(
                            request_id,
                            expected,
                            pending,
                            OutboundProofBlockFailure::PeerMismatch {
                                expected,
                                actual: peer,
                            },
                        ));
                    }
                    match ProofBlockResponse::from_wire_bytes(pending.request, response.as_bytes())
                    {
                        Ok(response) => Some(Self::finish_block_response(
                            request_id, expected, pending, response,
                        )),
                        Err(source) => Some(Self::finish_block_failure(
                            request_id,
                            expected,
                            pending,
                            OutboundProofBlockFailure::InvalidResponse { source },
                        )),
                    }
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let pending = self.remove_pending_block(request_id)?;
                let expected = self.pending_peer_id(pending.peer_index);
                let failure = if expected == peer {
                    OutboundProofBlockFailure::Transport(error)
                } else {
                    OutboundProofBlockFailure::PeerMismatch {
                        expected,
                        actual: peer,
                    }
                };
                Some(Self::finish_block_failure(
                    request_id, expected, pending, failure,
                ))
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => Some(NetworkEvent::InboundBlockFailure {
                peer_id: peer,
                request_id,
                error,
            }),
            request_response::Event::ResponseSent { .. } => None,
        }
    }

    fn finish_block_response(
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
        pending: PendingProofBlockRequest,
        response: ProofBlockResponse,
    ) -> NetworkEvent {
        let PendingProofBlockRequest {
            peer_index: _,
            request,
            _permit,
        } = pending;
        let network_budget = Arc::clone(&_permit.budget);
        NetworkEvent::OutboundBlock(OutboundProofBlockEvent {
            request_id,
            peer_id,
            request,
            network_budget,
            outcome: OutboundProofBlockOutcome::Response { response, _permit },
        })
    }

    fn finish_block_failure(
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
        pending: PendingProofBlockRequest,
        failure: OutboundProofBlockFailure,
    ) -> NetworkEvent {
        let network_budget = Arc::clone(&pending._permit.budget);
        NetworkEvent::OutboundBlock(OutboundProofBlockEvent {
            request_id,
            peer_id,
            request: pending.request,
            network_budget,
            outcome: OutboundProofBlockOutcome::Failure(Box::new(failure)),
        })
    }

    fn remove_pending_block(
        &mut self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<PendingProofBlockRequest> {
        let pending = self.pending.remove(&ExchangeRequestId::Block(request_id))?;
        let PendingRequest::Block(pending) = pending else {
            unreachable!("a block request key always stores a block request")
        };
        Some(pending)
    }

    /// Serves one authenticated block request from the healthy local journal.
    ///
    /// A found response performs one bounded canonical encoding because
    /// rust-libp2p must own the response until its asynchronous write ends.
    pub fn respond_block_from_journal(
        &mut self,
        inbound: InboundProofBlockRequest,
        journal: &ProofChainJournal,
    ) -> Result<(), RespondError> {
        let block = checked_block_lookup(proof_block_response(journal, inbound.request))?;
        if !inbound.channel.is_open() {
            return Err(RespondError::ChannelClosed);
        }
        let bytes = block.map_or_else(Vec::new, ProofBlock::to_canonical_bytes);
        let response = ProofBlockWireResponse::new(bytes);
        self.swarm
            .behaviour_mut()
            .block_exchange
            .send_response(inbound.channel, response)
            .map_err(|_| RespondError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests;
