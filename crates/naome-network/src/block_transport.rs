//! Authenticated transport binding for exact artifact-block retrieval.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response;
use naome::block_exchange::{
    ArtifactBlockExchangeWireError, ArtifactBlockRequest, ArtifactBlockResponse,
};
use naome_chain::{ArtifactBlock, ArtifactBlockId};
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactChainJournal,
};

use super::codec::ArtifactBlockWireResponse;
use super::{
    ExchangeRequestId, NetworkEvent, PeerId, PendingBudget, PendingPermit, PendingRequest,
    RequestStartError, RespondError, StaticArtifactNetwork,
};

pub(super) struct PendingArtifactBlockRequest {
    pub(super) peer_index: usize,
    pub(super) request: ArtifactBlockRequest,
    pub(super) _permit: PendingPermit,
}

/// One opaque generation of an outbound artifact-block request.
///
/// Dropping the ticket does not cancel its physical libp2p request. The
/// transport retains the peer slot and global permit until the corresponding
/// response or failure becomes terminal.
#[must_use]
pub struct BlockRequestTicket {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: ArtifactBlockRequest,
    network_budget: Arc<PendingBudget>,
}

impl BlockRequestTicket {
    pub(super) fn belongs_to_network(&self, network: &StaticArtifactNetwork) -> bool {
        Arc::ptr_eq(&self.network_budget, &network.pending_budget)
    }

    /// Returns the authenticated peer expected for this request generation.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable block request carried by this generation.
    pub const fn request(&self) -> ArtifactBlockRequest {
        self.request
    }

    /// Returns whether `event` is the exact terminal for this ticket.
    pub fn accepts_event(&self, event: &OutboundArtifactBlockEvent) -> bool {
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
        event: OutboundArtifactBlockEvent,
    ) -> Result<
        Result<ArtifactBlockResponse, Box<OutboundArtifactBlockFailure>>,
        Box<ArtifactBlockRequestEventMismatch>,
    > {
        if !self.accepts_event(&event) {
            return Err(Box::new(ArtifactBlockRequestEventMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.into_result())
    }

    /// Consumes this ticket and durably retains its exact found block as an
    /// unselected structural candidate.
    ///
    /// A mismatched terminal preserves both routable values and never accesses
    /// `store`. A matched transport failure or `Unavailable` response also
    /// performs no insertion. Success is returned only after the candidate
    /// store acknowledges an insert or exact idempotent replay.
    pub fn complete_into_candidate_store(
        self,
        event: OutboundArtifactBlockEvent,
        store: &mut ArtifactBlockCandidateStore,
    ) -> Result<
        Result<ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateRetentionError>,
        Box<ArtifactBlockRequestEventMismatch>,
    > {
        let peer_id = self.peer_id;
        let block_id = self.request.block_id();
        let response = match self.complete(event)? {
            Ok(response) => response,
            Err(source) => {
                return Ok(Err(ArtifactBlockCandidateRetentionError::RequestFailed {
                    peer_id,
                    block_id,
                    source,
                }));
            }
        };
        let Some(block) = response.into_block() else {
            return Ok(Err(
                ArtifactBlockCandidateRetentionError::BlockUnavailable { peer_id, block_id },
            ));
        };
        Ok(store.insert(&block).map_err(|source| {
            ArtifactBlockCandidateRetentionError::CandidateStore {
                block_id,
                source: Box::new(source),
            }
        }))
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
pub struct ArtifactBlockRequestEventMismatch {
    ticket: BlockRequestTicket,
    event: OutboundArtifactBlockEvent,
}

impl ArtifactBlockRequestEventMismatch {
    /// Returns the unmatched ticket and terminal event.
    pub fn into_parts(self) -> (BlockRequestTicket, OutboundArtifactBlockEvent) {
        (self.ticket, self.event)
    }
}

impl fmt::Debug for ArtifactBlockRequestEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactBlockRequestEventMismatch")
            .field("ticket", &self.ticket)
            .field("event", &self.event)
            .finish()
    }
}

impl fmt::Display for ArtifactBlockRequestEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("artifact-block terminal event does not match its request ticket")
    }
}

impl Error for ArtifactBlockRequestEventMismatch {}

/// Failure to retain one exact authenticated artifact-block response.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockCandidateRetentionError {
    /// The matched request failed before yielding a usable response.
    RequestFailed {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
        source: Box<OutboundArtifactBlockFailure>,
    },
    /// The authenticated peer reported no block for the exact address.
    BlockUnavailable {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
    },
    /// The exact found block could not be durably retained.
    CandidateStore {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
}

impl fmt::Display for ArtifactBlockCandidateRetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestFailed {
                peer_id,
                block_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed artifact-block candidate request {block_id:?}: {source}"
            ),
            Self::BlockUnavailable { peer_id, block_id } => write!(
                formatter,
                "peer {peer_id} has no artifact-block candidate at {block_id:?}"
            ),
            Self::CandidateStore { block_id, source } => write!(
                formatter,
                "cannot retain artifact-block candidate {block_id:?}: {source}"
            ),
        }
    }
}

impl Error for ArtifactBlockCandidateRetentionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RequestFailed { source, .. } => Some(source.as_ref()),
            Self::CandidateStore { source, .. } => Some(source.as_ref()),
            Self::BlockUnavailable { .. } => None,
        }
    }
}

/// One request received from an authenticated, statically authorized peer.
#[must_use]
pub struct InboundArtifactBlockRequest {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    request: ArtifactBlockRequest,
    channel: request_response::ResponseChannel<ArtifactBlockWireResponse>,
}

impl InboundArtifactBlockRequest {
    /// Returns the authenticated sender.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact requested block address.
    pub const fn request(&self) -> ArtifactBlockRequest {
        self.request
    }
}

impl fmt::Debug for InboundArtifactBlockRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundArtifactBlockRequest")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// One terminal block-request event awaiting its exact generation ticket.
#[must_use]
pub struct OutboundArtifactBlockEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: ArtifactBlockRequest,
    network_budget: Arc<PendingBudget>,
    outcome: OutboundArtifactBlockOutcome,
}

impl OutboundArtifactBlockEvent {
    /// Returns the expected authenticated peer.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable request that caused this terminal event.
    pub const fn request(&self) -> ArtifactBlockRequest {
        self.request
    }

    fn into_result(self) -> Result<ArtifactBlockResponse, Box<OutboundArtifactBlockFailure>> {
        match self.outcome {
            OutboundArtifactBlockOutcome::Response { response, .. } => Ok(response),
            OutboundArtifactBlockOutcome::Failure(error) => Err(error),
        }
    }
}

impl fmt::Debug for OutboundArtifactBlockEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match &self.outcome {
            OutboundArtifactBlockOutcome::Response { .. } => "Response",
            OutboundArtifactBlockOutcome::Failure(_) => "Failure",
        };
        formatter
            .debug_struct("OutboundArtifactBlockEvent")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("outcome", &outcome)
            .finish_non_exhaustive()
    }
}

enum OutboundArtifactBlockOutcome {
    Response {
        response: ArtifactBlockResponse,
        _permit: PendingPermit,
    },
    Failure(Box<OutboundArtifactBlockFailure>),
}

/// A typed terminal failure for one exact outbound artifact-block request.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundArtifactBlockFailure {
    /// The request-response stream failed before a complete response arrived.
    Transport(request_response::OutboundFailure),
    /// A complete bounded response violated block framing or request identity.
    InvalidResponse {
        source: ArtifactBlockExchangeWireError,
    },
    /// A terminal event came from a peer other than the retained expectation.
    PeerMismatch { expected: PeerId, actual: PeerId },
}

impl fmt::Display for OutboundArtifactBlockFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => write!(formatter, "artifact-block request failed: {source}"),
            Self::InvalidResponse { source } => {
                write!(formatter, "artifact-block response is invalid: {source}")
            }
            Self::PeerMismatch { expected, actual } => write!(
                formatter,
                "artifact-block terminal event came from {actual}, expected {expected}"
            ),
        }
    }
}

impl Error for OutboundArtifactBlockFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::InvalidResponse { source } => Some(source),
            Self::PeerMismatch { .. } => None,
        }
    }
}

impl StaticArtifactNetwork {
    /// Starts one exact block request over an established managed session.
    ///
    /// The returned ticket is the only public path to the terminal outcome.
    /// This method never opens a request-driven connection.
    pub fn request_block(
        &mut self,
        peer_id: PeerId,
        request: ArtifactBlockRequest,
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
            PendingRequest::Block(PendingArtifactBlockRequest {
                peer_index,
                request,
                _permit: permit,
            }),
        );
        Ok(ticket)
    }

    pub(super) fn handle_block_exchange_event(
        &mut self,
        event: request_response::Event<ArtifactBlockRequest, ArtifactBlockWireResponse>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundBlockRequest(
                    InboundArtifactBlockRequest {
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
                            OutboundArtifactBlockFailure::PeerMismatch {
                                expected,
                                actual: peer,
                            },
                        ));
                    }
                    match ArtifactBlockResponse::from_wire_bytes(
                        pending.request,
                        response.as_bytes(),
                    ) {
                        Ok(response) => Some(Self::finish_block_response(
                            request_id, expected, pending, response,
                        )),
                        Err(source) => Some(Self::finish_block_failure(
                            request_id,
                            expected,
                            pending,
                            OutboundArtifactBlockFailure::InvalidResponse { source },
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
                    OutboundArtifactBlockFailure::Transport(error)
                } else {
                    OutboundArtifactBlockFailure::PeerMismatch {
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
        pending: PendingArtifactBlockRequest,
        response: ArtifactBlockResponse,
    ) -> NetworkEvent {
        let PendingArtifactBlockRequest {
            peer_index: _,
            request,
            _permit,
        } = pending;
        let network_budget = Arc::clone(&_permit.budget);
        NetworkEvent::OutboundBlock(OutboundArtifactBlockEvent {
            request_id,
            peer_id,
            request,
            network_budget,
            outcome: OutboundArtifactBlockOutcome::Response { response, _permit },
        })
    }

    fn finish_block_failure(
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
        pending: PendingArtifactBlockRequest,
        failure: OutboundArtifactBlockFailure,
    ) -> NetworkEvent {
        let network_budget = Arc::clone(&pending._permit.budget);
        NetworkEvent::OutboundBlock(OutboundArtifactBlockEvent {
            request_id,
            peer_id,
            request: pending.request,
            network_budget,
            outcome: OutboundArtifactBlockOutcome::Failure(Box::new(failure)),
        })
    }

    fn remove_pending_block(
        &mut self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<PendingArtifactBlockRequest> {
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
        inbound: InboundArtifactBlockRequest,
        journal: &ArtifactChainJournal,
    ) -> Result<(), RespondError> {
        let block = journal
            .block(inbound.request.block_id())
            .map_err(RespondError::Journal)?;
        self.respond_block_value(inbound, block)
    }

    /// Serves one authenticated block request from a caller-routed candidate store.
    ///
    /// The request carries no chain identity: the caller must supply the
    /// intended chain-scoped store. A failed integrity read is reported rather
    /// than translated to `Unavailable`; serving never inserts, replaces,
    /// promotes, or deletes a candidate.
    pub fn respond_block_from_candidate_store(
        &mut self,
        inbound: InboundArtifactBlockRequest,
        store: &mut ArtifactBlockCandidateStore,
    ) -> Result<(), RespondError> {
        let block = store
            .get(inbound.request.block_id())
            .map_err(RespondError::CandidateStore)?;
        self.respond_block_value(inbound, block.as_ref())
    }

    fn respond_block_value(
        &mut self,
        inbound: InboundArtifactBlockRequest,
        block: Option<&ArtifactBlock>,
    ) -> Result<(), RespondError> {
        if !inbound.channel.is_open() {
            return Err(RespondError::ChannelClosed);
        }
        self.take_inbound_application_request()?;
        let response = block.map_or_else(ArtifactBlockWireResponse::unavailable, |block| {
            ArtifactBlockWireResponse::from_block_bytes(block.to_canonical_bytes())
        });
        self.swarm
            .behaviour_mut()
            .block_exchange
            .send_response(inbound.channel, response)
            .map_err(|_| RespondError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests;
