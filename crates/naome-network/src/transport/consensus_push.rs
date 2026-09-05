//! Caller-selected authenticated delivery of one opaque proposal or vote.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response;

use super::inbound_retention::InboundRetentionPermit;

pub(super) mod codec;

use super::{
    ExchangeRequestId, MAX_STATIC_PEERS, NetworkEvent, PeerId, PendingBudget, PendingPermit,
    PendingRequest, RequestStartError, StaticArtifactNetwork,
};

/// Minimum proposal control width accepted by the envelope.
pub const CONSENSUS_PUSH_MIN_PROPOSAL_BYTES: usize =
    naome_consensus::VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH;
/// Maximum proposal control width accepted by the envelope.
pub const CONSENSUS_PUSH_MAX_PROPOSAL_BYTES: usize =
    naome_consensus::VerifiedFixedConsensusProposalV0::MAX_BYTE_LENGTH;
/// Maximum canonical artifact payload width accepted by the envelope.
pub const CONSENSUS_PUSH_MAX_PAYLOAD_BYTES: usize = naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;
/// Exact signed vote width accepted by the envelope.
pub const CONSENSUS_PUSH_VOTE_BYTES: usize = naome_consensus::VerifiedConsensusVoteV0::BYTE_LENGTH;
/// Maximum aggregate body bytes retained by inbound consensus transport events.
pub const CONSENSUS_PUSH_MAX_RETAINED_INBOUND_BYTES: usize =
    (CONSENSUS_PUSH_MAX_PROPOSAL_BYTES + CONSENSUS_PUSH_MAX_PAYLOAD_BYTES) * MAX_STATIC_PEERS;
/// Maximum inbound consensus transport events retained at once.
pub const CONSENSUS_PUSH_MAX_RETAINED_INBOUND_EVENTS: usize = MAX_STATIC_PEERS;

/// Caller-owned candidate bytes for one explicit one-hop delivery.
///
/// Inner bytes remain opaque to transport. A vote does not carry a released
/// proposal token: callers must retain that token separately when destructuring
/// a driver publication command. This component does not grant consensus admission,
/// signer identity, forwarding, selection, persistence, or finality authority.
#[derive(PartialEq, Eq)]
#[must_use]
pub enum ConsensusPushMessage {
    Proposal {
        canonical_proposal: Vec<u8>,
        canonical_artifact: Vec<u8>,
    },
    Vote {
        canonical_vote: Vec<u8>,
    },
}
impl ConsensusPushMessage {
    pub fn size(&self) -> ConsensusPushSize {
        match self {
            Self::Proposal {
                canonical_proposal,
                canonical_artifact,
            } => ConsensusPushSize::Proposal {
                control_bytes: canonical_proposal.len(),
                payload_bytes: canonical_artifact.len(),
            },
            Self::Vote { canonical_vote } => ConsensusPushSize::Vote {
                bytes: canonical_vote.len(),
            },
        }
    }
}
impl fmt::Debug for ConsensusPushMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.size().fmt(f)
    }
}

/// Kind and body widths of one request, without its contents or authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusPushSize {
    Proposal {
        control_bytes: usize,
        payload_bytes: usize,
    },
    Vote {
        bytes: usize,
    },
}
impl ConsensusPushSize {
    pub(super) fn validate(self) -> Result<(), ConsensusPushLengthError> {
        let check = |field, actual, minimum, maximum| {
            if (minimum..=maximum).contains(&actual) {
                Ok(())
            } else {
                Err(ConsensusPushLengthError {
                    field,
                    actual,
                    minimum,
                    maximum,
                })
            }
        };
        match self {
            Self::Proposal {
                control_bytes,
                payload_bytes,
            } => {
                check(
                    ConsensusPushField::ProposalControl,
                    control_bytes,
                    CONSENSUS_PUSH_MIN_PROPOSAL_BYTES,
                    CONSENSUS_PUSH_MAX_PROPOSAL_BYTES,
                )?;
                check(
                    ConsensusPushField::ArtifactPayload,
                    payload_bytes,
                    1,
                    CONSENSUS_PUSH_MAX_PAYLOAD_BYTES,
                )
            }
            Self::Vote { bytes } => check(
                ConsensusPushField::Vote,
                bytes,
                CONSENSUS_PUSH_VOTE_BYTES,
                CONSENSUS_PUSH_VOTE_BYTES,
            ),
        }
    }
    pub(super) fn body_bytes(self) -> usize {
        match self {
            Self::Proposal {
                control_bytes,
                payload_bytes,
            } => control_bytes + payload_bytes,
            Self::Vote { bytes } => bytes,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusPushField {
    ProposalControl,
    ArtifactPayload,
    Vote,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusPushLengthError {
    pub field: ConsensusPushField,
    pub actual: usize,
    pub minimum: usize,
    pub maximum: usize,
}
impl fmt::Display for ConsensusPushLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "consensus {:?} has {} bytes, expected {}..={}",
            self.field, self.actual, self.minimum, self.maximum
        )
    }
}
impl Error for ConsensusPushLengthError {}

#[must_use]
pub(super) struct ConsensusPushRequest {
    message: ConsensusPushMessage,
    _inbound_permit: Option<InboundRetentionPermit>,
}
impl ConsensusPushRequest {
    pub(super) fn from_inbound(
        message: ConsensusPushMessage,
        permit: InboundRetentionPermit,
    ) -> Self {
        Self {
            message,
            _inbound_permit: Some(permit),
        }
    }
    pub(super) fn message(&self) -> &ConsensusPushMessage {
        &self.message
    }
    fn bind_inbound_peer(&mut self, peer_id: PeerId) -> bool {
        self._inbound_permit
            .as_mut()
            .is_some_and(|permit| permit.bind_peer(peer_id))
    }
}
impl fmt::Debug for ConsensusPushRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

pub(super) struct PendingConsensusPush {
    pub(super) peer_index: usize,
    pub(super) size: ConsensusPushSize,
    pub(super) _permit: PendingPermit,
}

/// Opaque generation for one exact consensus push.
#[must_use]
pub struct ConsensusPushTicket {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    size: ConsensusPushSize,
    network_budget: Arc<PendingBudget>,
}
impl ConsensusPushTicket {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn size(&self) -> ConsensusPushSize {
        self.size
    }
    pub fn accepts_event(&self, event: &OutboundConsensusPushEvent) -> bool {
        crate::request_correlation::RequestCorrelation::new(
            self.request_id,
            self.peer_id,
            &self.size,
        )
        .matches(
            crate::request_correlation::RequestCorrelation::new(
                event.request_id,
                event.peer_id,
                &event.size,
            ),
            &self.network_budget,
            event.network_budget(),
        )
    }
    pub fn complete(
        self,
        event: OutboundConsensusPushEvent,
    ) -> Result<
        Result<AuthenticatedConsensusPushReceipt, Box<OutboundConsensusPushFailure>>,
        Box<ConsensusPushEventMismatch>,
    > {
        if !self.accepts_event(&event) {
            return Err(Box::new(ConsensusPushEventMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.into_result())
    }
}
impl fmt::Debug for ConsensusPushTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsensusPushTicket")
            .field("peer_id", &self.peer_id)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}
#[must_use]
pub struct ConsensusPushEventMismatch {
    ticket: ConsensusPushTicket,
    event: OutboundConsensusPushEvent,
}
impl ConsensusPushEventMismatch {
    pub fn into_parts(self) -> (ConsensusPushTicket, OutboundConsensusPushEvent) {
        (self.ticket, self.event)
    }
}
impl fmt::Debug for ConsensusPushEventMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsensusPushEventMismatch")
            .finish_non_exhaustive()
    }
}
impl fmt::Display for ConsensusPushEventMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("consensus push terminal does not match its ticket")
    }
}
impl Error for ConsensusPushEventMismatch {}

/// An opaque message received from an authenticated configured peer.
#[must_use]
pub struct InboundConsensusPush {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    request: ConsensusPushRequest,
    channel: request_response::ResponseChannel<ConsensusPushReceipt>,
}
impl InboundConsensusPush {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn message(&self) -> &ConsensusPushMessage {
        self.request.message()
    }
}
impl fmt::Debug for InboundConsensusPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundConsensusPush")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("message", &self.request.message)
            .finish()
    }
}

/// Immediate authenticated source and exact owned candidate bytes.
///
/// These caller-owned bytes no longer count against transport retention. Neither
/// this value nor a stream receipt proves inner validity or consensus admission.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct ReceivedConsensusPush {
    peer_id: PeerId,
    message: ConsensusPushMessage,
}
impl ReceivedConsensusPush {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn message(&self) -> &ConsensusPushMessage {
        &self.message
    }
    pub fn into_parts(self) -> (PeerId, ConsensusPushMessage) {
        (self.peer_id, self.message)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ConsensusPushReceipt;
/// Receipt only confirms that the authenticated receiver accepted this stream; it says nothing about inner validity or consensus state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct AuthenticatedConsensusPushReceipt {
    peer_id: PeerId,
    size: ConsensusPushSize,
}
impl AuthenticatedConsensusPushReceipt {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn size(&self) -> ConsensusPushSize {
        self.size
    }
}
#[must_use]
pub struct OutboundConsensusPushEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    size: ConsensusPushSize,
    outcome: OutboundConsensusPushOutcome,
}
impl OutboundConsensusPushEvent {
    fn network_budget(&self) -> &Arc<PendingBudget> {
        match &self.outcome {
            OutboundConsensusPushOutcome::Receipt { _permit } => &_permit.budget,
            OutboundConsensusPushOutcome::Failure { network_budget, .. } => network_budget,
        }
    }
    fn into_result(
        self,
    ) -> Result<AuthenticatedConsensusPushReceipt, Box<OutboundConsensusPushFailure>> {
        match self.outcome {
            OutboundConsensusPushOutcome::Receipt { _permit } => {
                Ok(AuthenticatedConsensusPushReceipt {
                    peer_id: self.peer_id,
                    size: self.size,
                })
            }
            OutboundConsensusPushOutcome::Failure { error, .. } => Err(error),
        }
    }
}
impl fmt::Debug for OutboundConsensusPushEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundConsensusPushEvent")
            .field("peer_id", &self.peer_id)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}
enum OutboundConsensusPushOutcome {
    Receipt {
        _permit: PendingPermit,
    },
    Failure {
        error: Box<OutboundConsensusPushFailure>,
        network_budget: Arc<PendingBudget>,
    },
}
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundConsensusPushFailure {
    Transport(request_response::OutboundFailure),
    PeerMismatch { expected: PeerId, actual: PeerId },
}
impl fmt::Display for OutboundConsensusPushFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "consensus push failed: {e}"),
            Self::PeerMismatch { expected, actual } => write!(
                f,
                "consensus push terminal came from {actual}, expected {expected}"
            ),
        }
    }
}
impl Error for OutboundConsensusPushFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::PeerMismatch { .. } => None,
        }
    }
}

impl StaticArtifactNetwork {
    /// Queues one opaque message to an explicitly selected, connected static peer.
    ///
    /// Synchronous failure returns the exact owned message. After queueing, an
    /// asynchronous failure carries no retry copy. Dropping the ticket does not
    /// cancel delivery. No retry, dial, forwarding, or self-admission is implied.
    pub fn push_consensus(
        &mut self,
        peer_id: PeerId,
        message: ConsensusPushMessage,
    ) -> Result<ConsensusPushTicket, Box<ConsensusPushStartError>> {
        let size = message.size();
        if let Err(error) = size.validate() {
            return Err(Box::new(ConsensusPushStartError {
                message,
                reason: ConsensusPushStartFailure::Length(error),
            }));
        }
        let connected = self.swarm.behaviour().consensus_push.is_connected(&peer_id);
        let (peer_index, permit) = match self.acquire_request_permit(peer_id, connected) {
            Ok(value) => value,
            Err(error) => {
                return Err(Box::new(ConsensusPushStartError {
                    message,
                    reason: ConsensusPushStartFailure::RequestStart(error),
                }));
            }
        };
        let request_id = self.swarm.behaviour_mut().consensus_push.send_request(
            &peer_id,
            ConsensusPushRequest {
                message,
                _inbound_permit: None,
            },
        );
        self.insert_pending(
            ExchangeRequestId::ConsensusPush(request_id),
            PendingRequest::ConsensusPush(PendingConsensusPush {
                peer_index,
                size,
                _permit: permit,
            }),
        );
        Ok(ConsensusPushTicket {
            request_id,
            peer_id,
            size,
            network_budget: Arc::clone(&self.pending_budget),
        })
    }

    /// Queues a stream-only receipt and returns the source and exact owned bytes.
    /// A closed response channel also returns both. The caller must separately
    /// decode and explicitly admit a message through its driver.
    pub fn acknowledge_consensus_push(
        &mut self,
        inbound: InboundConsensusPush,
    ) -> Result<ReceivedConsensusPush, Box<ConsensusPushAcknowledgeError>> {
        let InboundConsensusPush {
            peer_id,
            request,
            channel,
            ..
        } = inbound;
        let received = ReceivedConsensusPush {
            peer_id,
            message: request.message,
        };
        match self
            .swarm
            .behaviour_mut()
            .consensus_push
            .send_response(channel, ConsensusPushReceipt)
        {
            Ok(()) => Ok(received),
            Err(_) => Err(Box::new(ConsensusPushAcknowledgeError { received })),
        }
    }
    pub(super) fn handle_consensus_push_event(
        &mut self,
        event: request_response::Event<ConsensusPushRequest, ConsensusPushReceipt>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    mut request,
                    channel,
                } => {
                    if !request.bind_inbound_peer(peer) {
                        return None;
                    }
                    Some(NetworkEvent::InboundConsensusPush(InboundConsensusPush {
                        peer_id: peer,
                        request_id,
                        request,
                        channel,
                    }))
                }
                request_response::Message::Response {
                    request_id,
                    response: _,
                } => {
                    let pending = self
                        .pending
                        .remove(&ExchangeRequestId::ConsensusPush(request_id))?;
                    let PendingRequest::ConsensusPush(pending) = pending else {
                        unreachable!()
                    };
                    let expected = self.pending_peer_id(pending.peer_index);
                    let size = pending.size;
                    let outcome = if expected == peer {
                        OutboundConsensusPushOutcome::Receipt {
                            _permit: pending._permit,
                        }
                    } else {
                        OutboundConsensusPushOutcome::Failure {
                            error: Box::new(OutboundConsensusPushFailure::PeerMismatch {
                                expected,
                                actual: peer,
                            }),
                            network_budget: Arc::clone(&pending._permit.budget),
                        }
                    };
                    Some(NetworkEvent::OutboundConsensusPush(
                        OutboundConsensusPushEvent {
                            request_id,
                            peer_id: expected,
                            size,
                            outcome,
                        },
                    ))
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let pending = self
                    .pending
                    .remove(&ExchangeRequestId::ConsensusPush(request_id))?;
                let PendingRequest::ConsensusPush(pending) = pending else {
                    unreachable!()
                };
                let expected = self.pending_peer_id(pending.peer_index);
                let size = pending.size;
                let failure = if expected == peer {
                    OutboundConsensusPushFailure::Transport(error)
                } else {
                    OutboundConsensusPushFailure::PeerMismatch {
                        expected,
                        actual: peer,
                    }
                };
                Some(NetworkEvent::OutboundConsensusPush(
                    OutboundConsensusPushEvent {
                        request_id,
                        peer_id: expected,
                        size,
                        outcome: OutboundConsensusPushOutcome::Failure {
                            error: Box::new(failure),
                            network_budget: Arc::clone(&pending._permit.budget),
                        },
                    },
                ))
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => Some(NetworkEvent::InboundConsensusPushFailure {
                peer_id: peer,
                request_id,
                error,
            }),
            request_response::Event::ResponseSent { .. } => None,
        }
    }
}
/// A synchronous rejection preserving the exact input allocations.
#[derive(Debug)]
pub struct ConsensusPushStartError {
    message: ConsensusPushMessage,
    reason: ConsensusPushStartFailure,
}
impl ConsensusPushStartError {
    pub fn message(&self) -> &ConsensusPushMessage {
        &self.message
    }
    pub const fn reason(&self) -> &ConsensusPushStartFailure {
        &self.reason
    }
    pub fn into_parts(self) -> (ConsensusPushMessage, ConsensusPushStartFailure) {
        (self.message, self.reason)
    }
}
#[derive(Debug)]
pub enum ConsensusPushStartFailure {
    Length(ConsensusPushLengthError),
    RequestStart(RequestStartError),
}
impl fmt::Display for ConsensusPushStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            ConsensusPushStartFailure::Length(e) => write!(f, "cannot push consensus message: {e}"),
            ConsensusPushStartFailure::RequestStart(e) => {
                write!(f, "cannot start consensus push: {e}")
            }
        }
    }
}
impl Error for ConsensusPushStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.reason {
            ConsensusPushStartFailure::Length(e) => Some(e),
            ConsensusPushStartFailure::RequestStart(e) => Some(e),
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct ConsensusPushAcknowledgeError {
    received: ReceivedConsensusPush,
}
impl ConsensusPushAcknowledgeError {
    pub fn received(&self) -> &ReceivedConsensusPush {
        &self.received
    }
    pub fn into_received(self) -> ReceivedConsensusPush {
        self.received
    }
}
impl fmt::Display for ConsensusPushAcknowledgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("consensus push response channel is closed")
    }
}
impl Error for ConsensusPushAcknowledgeError {}

#[cfg(test)]
mod tests;
