//! Caller-selected authenticated delivery of one opaque recovery bundle.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response;

use super::{
    ExchangeRequestId, NetworkEvent, PeerId, PendingBudget, PendingPermit, PendingRequest,
    RequestStartError, StaticArtifactNetwork,
};

/// Maximum encoded recovery-bundle bytes accepted by the transport envelope.
pub const RECOVERY_BUNDLE_PUSH_MAX_BYTES: usize = 16 * 1024 * 1024;

/// One opaque canonical recovery-bundle push request.
#[must_use]
pub struct RecoveryBundlePushRequest(Vec<u8>);

impl RecoveryBundlePushRequest {
    /// Owns exactly one already-encoded canonical bundle within the transport bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, RecoveryBundlePushRequestError> {
        if bytes.len() > RECOVERY_BUNDLE_PUSH_MAX_BYTES {
            return Err(RecoveryBundlePushRequestError::TooLong {
                actual: bytes.len(),
                maximum: RECOVERY_BUNDLE_PUSH_MAX_BYTES,
            });
        }
        Ok(Self(bytes))
    }
    pub fn into_canonical_bundle_bytes(self) -> Vec<u8> {
        self.0
    }
}
impl fmt::Debug for RecoveryBundlePushRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryBundlePushRequest")
            .field("encoded_bytes", &self.0.len())
            .finish()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryBundlePushRequestError {
    TooLong { actual: usize, maximum: usize },
}
impl fmt::Display for RecoveryBundlePushRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { actual, maximum } => {
                write!(f, "recovery bundle has {actual} bytes, exceeding {maximum}")
            }
        }
    }
}
impl Error for RecoveryBundlePushRequestError {}

pub(super) struct PendingRecoveryBundlePush {
    pub(super) peer_index: usize,
    pub(super) bytes: usize,
    pub(super) _permit: PendingPermit,
}

/// Opaque generation for one exact recovery-bundle push.
#[must_use]
pub struct RecoveryBundlePushTicket {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    bytes: usize,
    network_budget: Arc<PendingBudget>,
}
impl RecoveryBundlePushTicket {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn encoded_bytes(&self) -> usize {
        self.bytes
    }
    pub fn accepts_event(&self, event: &OutboundRecoveryBundlePushEvent) -> bool {
        self.request_id == event.request_id
            && self.peer_id == event.peer_id
            && self.bytes == event.bytes
            && Arc::ptr_eq(&self.network_budget, event.network_budget())
    }
    pub fn complete(
        self,
        event: OutboundRecoveryBundlePushEvent,
    ) -> Result<
        Result<AuthenticatedRecoveryBundlePushReceipt, Box<OutboundRecoveryBundlePushFailure>>,
        Box<RecoveryBundlePushEventMismatch>,
    > {
        if !self.accepts_event(&event) {
            return Err(Box::new(RecoveryBundlePushEventMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.into_result())
    }
}
impl fmt::Debug for RecoveryBundlePushTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryBundlePushTicket")
            .field("peer_id", &self.peer_id)
            .field("encoded_bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}
#[must_use]
pub struct RecoveryBundlePushEventMismatch {
    ticket: RecoveryBundlePushTicket,
    event: OutboundRecoveryBundlePushEvent,
}
impl RecoveryBundlePushEventMismatch {
    pub fn into_parts(self) -> (RecoveryBundlePushTicket, OutboundRecoveryBundlePushEvent) {
        (self.ticket, self.event)
    }
}
impl fmt::Debug for RecoveryBundlePushEventMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryBundlePushEventMismatch")
            .finish_non_exhaustive()
    }
}
impl fmt::Display for RecoveryBundlePushEventMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("recovery-bundle push terminal does not match its ticket")
    }
}
impl Error for RecoveryBundlePushEventMismatch {}

/// An opaque bundle received from an authenticated configured peer.
#[must_use]
pub struct InboundRecoveryBundlePush {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    request: RecoveryBundlePushRequest,
    channel: request_response::ResponseChannel<RecoveryBundlePushReceipt>,
}
impl InboundRecoveryBundlePush {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn encoded_bytes(&self) -> usize {
        self.request.0.len()
    }
    /// Borrows the unvalidated canonical-bundle candidate bytes.
    pub fn canonical_bundle_bytes(&self) -> &[u8] {
        &self.request.0
    }
    pub fn into_canonical_bundle_bytes(self) -> Vec<u8> {
        self.request.into_canonical_bundle_bytes()
    }
}
impl fmt::Debug for InboundRecoveryBundlePush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundRecoveryBundlePush")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("encoded_bytes", &self.request.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RecoveryBundlePushReceipt;
/// Receipt only confirms that the authenticated receiver accepted this stream; it says nothing about the bundle's bytes or any state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct AuthenticatedRecoveryBundlePushReceipt {
    peer_id: PeerId,
    bytes: usize,
}
impl AuthenticatedRecoveryBundlePushReceipt {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn encoded_bytes(&self) -> usize {
        self.bytes
    }
}
#[must_use]
pub struct OutboundRecoveryBundlePushEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    bytes: usize,
    outcome: OutboundRecoveryBundlePushOutcome,
}
impl OutboundRecoveryBundlePushEvent {
    fn network_budget(&self) -> &Arc<PendingBudget> {
        match &self.outcome {
            OutboundRecoveryBundlePushOutcome::Receipt { _permit } => &_permit.budget,
            OutboundRecoveryBundlePushOutcome::Failure { network_budget, .. } => network_budget,
        }
    }
    fn into_result(
        self,
    ) -> Result<AuthenticatedRecoveryBundlePushReceipt, Box<OutboundRecoveryBundlePushFailure>>
    {
        match self.outcome {
            OutboundRecoveryBundlePushOutcome::Receipt { _permit } => {
                Ok(AuthenticatedRecoveryBundlePushReceipt {
                    peer_id: self.peer_id,
                    bytes: self.bytes,
                })
            }
            OutboundRecoveryBundlePushOutcome::Failure { error, .. } => Err(error),
        }
    }
}
impl fmt::Debug for OutboundRecoveryBundlePushEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundRecoveryBundlePushEvent")
            .field("peer_id", &self.peer_id)
            .field("encoded_bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}
enum OutboundRecoveryBundlePushOutcome {
    Receipt {
        _permit: PendingPermit,
    },
    Failure {
        error: Box<OutboundRecoveryBundlePushFailure>,
        network_budget: Arc<PendingBudget>,
    },
}
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundRecoveryBundlePushFailure {
    Transport(request_response::OutboundFailure),
    PeerMismatch { expected: PeerId, actual: PeerId },
}
impl fmt::Display for OutboundRecoveryBundlePushFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "recovery-bundle push failed: {e}"),
            Self::PeerMismatch { expected, actual } => write!(
                f,
                "recovery-bundle push terminal came from {actual}, expected {expected}"
            ),
        }
    }
}
impl Error for OutboundRecoveryBundlePushFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::PeerMismatch { .. } => None,
        }
    }
}

impl StaticArtifactNetwork {
    pub fn push_recovery_bundle(
        &mut self,
        peer_id: PeerId,
        bytes: Vec<u8>,
    ) -> Result<RecoveryBundlePushTicket, RecoveryBundlePushStartError> {
        let request =
            RecoveryBundlePushRequest::new(bytes).map_err(RecoveryBundlePushStartError::Bundle)?;
        let connected = self
            .swarm
            .behaviour()
            .recovery_bundle_push
            .is_connected(&peer_id);
        let (peer_index, permit) = self
            .acquire_request_permit(peer_id, connected)
            .map_err(RecoveryBundlePushStartError::RequestStart)?;
        let encoded_bytes = request.0.len();
        let request_id = self
            .swarm
            .behaviour_mut()
            .recovery_bundle_push
            .send_request(&peer_id, request);
        self.insert_pending(
            ExchangeRequestId::RecoveryBundlePush(request_id),
            PendingRequest::RecoveryBundlePush(PendingRecoveryBundlePush {
                peer_index,
                bytes: encoded_bytes,
                _permit: permit,
            }),
        );
        Ok(RecoveryBundlePushTicket {
            request_id,
            peer_id,
            bytes: encoded_bytes,
            network_budget: Arc::clone(&self.pending_budget),
        })
    }
    pub fn acknowledge_recovery_bundle_push(
        &mut self,
        inbound: InboundRecoveryBundlePush,
    ) -> Result<(), RecoveryBundlePushAcknowledgeError> {
        self.swarm
            .behaviour_mut()
            .recovery_bundle_push
            .send_response(inbound.channel, RecoveryBundlePushReceipt)
            .map_err(|_| RecoveryBundlePushAcknowledgeError::ChannelClosed)
    }
    pub(super) fn handle_recovery_bundle_push_event(
        &mut self,
        event: request_response::Event<RecoveryBundlePushRequest, RecoveryBundlePushReceipt>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundRecoveryBundlePush(
                    InboundRecoveryBundlePush {
                        peer_id: peer,
                        request_id,
                        request,
                        channel,
                    },
                )),
                request_response::Message::Response {
                    request_id,
                    response: _,
                } => {
                    let pending = self
                        .pending
                        .remove(&ExchangeRequestId::RecoveryBundlePush(request_id))?;
                    let PendingRequest::RecoveryBundlePush(pending) = pending else {
                        unreachable!()
                    };
                    let expected = self.pending_peer_id(pending.peer_index);
                    let bytes = pending.bytes;
                    let outcome = if expected == peer {
                        OutboundRecoveryBundlePushOutcome::Receipt {
                            _permit: pending._permit,
                        }
                    } else {
                        OutboundRecoveryBundlePushOutcome::Failure {
                            error: Box::new(OutboundRecoveryBundlePushFailure::PeerMismatch {
                                expected,
                                actual: peer,
                            }),
                            network_budget: Arc::clone(&pending._permit.budget),
                        }
                    };
                    Some(NetworkEvent::OutboundRecoveryBundlePush(
                        OutboundRecoveryBundlePushEvent {
                            request_id,
                            peer_id: expected,
                            bytes,
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
                    .remove(&ExchangeRequestId::RecoveryBundlePush(request_id))?;
                let PendingRequest::RecoveryBundlePush(pending) = pending else {
                    unreachable!()
                };
                let expected = self.pending_peer_id(pending.peer_index);
                let bytes = pending.bytes;
                let failure = if expected == peer {
                    OutboundRecoveryBundlePushFailure::Transport(error)
                } else {
                    OutboundRecoveryBundlePushFailure::PeerMismatch {
                        expected,
                        actual: peer,
                    }
                };
                Some(NetworkEvent::OutboundRecoveryBundlePush(
                    OutboundRecoveryBundlePushEvent {
                        request_id,
                        peer_id: expected,
                        bytes,
                        outcome: OutboundRecoveryBundlePushOutcome::Failure {
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
            } => Some(NetworkEvent::InboundRecoveryBundlePushFailure {
                peer_id: peer,
                request_id,
                error,
            }),
            request_response::Event::ResponseSent { .. } => None,
        }
    }
}
#[derive(Debug)]
pub enum RecoveryBundlePushStartError {
    Bundle(RecoveryBundlePushRequestError),
    RequestStart(RequestStartError),
}
impl fmt::Display for RecoveryBundlePushStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bundle(e) => write!(f, "cannot push recovery bundle: {e}"),
            Self::RequestStart(e) => write!(f, "cannot start recovery-bundle push: {e}"),
        }
    }
}
impl Error for RecoveryBundlePushStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bundle(e) => Some(e),
            Self::RequestStart(e) => Some(e),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryBundlePushAcknowledgeError {
    ChannelClosed,
}
impl fmt::Display for RecoveryBundlePushAcknowledgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("recovery-bundle push response channel is closed")
    }
}
impl Error for RecoveryBundlePushAcknowledgeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn request_accepts_the_exact_transport_maximum() {
        assert_eq!(
            RecoveryBundlePushRequest::new(vec![0; RECOVERY_BUNDLE_PUSH_MAX_BYTES])
                .unwrap()
                .into_canonical_bundle_bytes()
                .len(),
            RECOVERY_BUNDLE_PUSH_MAX_BYTES
        );
    }

    #[test]
    fn request_rejects_one_byte_over_the_transport_maximum() {
        let actual = RECOVERY_BUNDLE_PUSH_MAX_BYTES + 1;
        assert!(matches!(
            RecoveryBundlePushRequest::new(vec![0; actual]),
            Err(RecoveryBundlePushRequestError::TooLong {
                actual: rejected,
                maximum: RECOVERY_BUNDLE_PUSH_MAX_BYTES,
            }) if rejected == actual
        ));
    }

    #[tokio::test]
    async fn authenticated_peer_receives_opaque_bytes_and_sender_gets_only_a_receipt() {
        let (mut sender, mut receiver, _sender_peer, receiver_peer) =
            crate::tests::connected_pair().await;
        let expected = vec![0xa5, 0x5a, 0x00];
        let ticket = sender
            .push_recovery_bundle(receiver_peer, expected.clone())
            .unwrap();
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_event() => if let NetworkEvent::InboundRecoveryBundlePush(inbound) = event {
                        assert_eq!(inbound.peer_id(), sender.local_peer_id());
                        assert_eq!(inbound.canonical_bundle_bytes(), expected);
                        receiver.acknowledge_recovery_bundle_push(inbound).unwrap();
                    },
                    event = sender.next_event() => if let NetworkEvent::OutboundRecoveryBundlePush(event) = event {
                        let receipt = ticket.complete(event).unwrap().unwrap();
                        assert_eq!(receipt.peer_id(), receiver_peer);
                        assert_eq!(receipt.encoded_bytes(), expected.len());
                        return;
                    },
                }
            }
        }).await.unwrap();
    }
}
