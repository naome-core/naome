//! Caller-selected authenticated delivery of one opaque recovery bundle.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use libp2p::request_response;

use super::{
    ExchangeRequestId, MAX_STATIC_PEERS, NetworkEvent, PeerId, PendingBudget, PendingPermit,
    PendingRequest, RequestStartError, StaticArtifactNetwork,
};

/// Maximum encoded recovery-bundle bytes accepted by the transport envelope.
pub const RECOVERY_BUNDLE_PUSH_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Maximum aggregate bytes retained by inbound recovery-bundle transport events.
pub const RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES: usize =
    RECOVERY_BUNDLE_PUSH_MAX_BYTES * MAX_STATIC_PEERS;
/// Maximum inbound recovery-bundle transport events retained at once.
pub const RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS: usize = MAX_STATIC_PEERS;

/// One opaque canonical recovery-bundle push request.
#[must_use]
pub struct RecoveryBundlePushRequest {
    bytes: Vec<u8>,
    _inbound_permit: Option<RecoveryBundlePushInboundPermit>,
}

impl RecoveryBundlePushRequest {
    /// Owns exactly one already-encoded canonical bundle within the transport bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, RecoveryBundlePushRequestError> {
        if bytes.len() > RECOVERY_BUNDLE_PUSH_MAX_BYTES {
            return Err(RecoveryBundlePushRequestError::TooLong {
                actual: bytes.len(),
                maximum: RECOVERY_BUNDLE_PUSH_MAX_BYTES,
            });
        }
        Ok(Self {
            bytes,
            _inbound_permit: None,
        })
    }

    pub(super) fn from_inbound(bytes: Vec<u8>, permit: RecoveryBundlePushInboundPermit) -> Self {
        debug_assert!(bytes.len() <= RECOVERY_BUNDLE_PUSH_MAX_BYTES);
        Self {
            bytes,
            _inbound_permit: Some(permit),
        }
    }

    pub(super) fn bundle_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn bind_inbound_peer(&mut self, peer_id: PeerId) -> bool {
        self._inbound_permit
            .as_mut()
            .is_some_and(|permit| permit.bind_peer(peer_id))
    }

    pub(super) fn into_bundle_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl fmt::Debug for RecoveryBundlePushRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryBundlePushRequest")
            .field("encoded_bytes", &self.bytes.len())
            .finish()
    }
}

#[derive(Default)]
pub(super) struct RecoveryBundlePushInboundBudget {
    retained: Mutex<RecoveryBundlePushInboundBudgetState>,
}

#[derive(Default)]
struct RecoveryBundlePushInboundBudgetState {
    events: usize,
    bytes: usize,
    peers: HashSet<PeerId>,
}

impl RecoveryBundlePushInboundBudget {
    pub(super) fn try_acquire(
        budget: &Arc<Self>,
        bytes: usize,
    ) -> Option<RecoveryBundlePushInboundPermit> {
        let mut retained = budget.retained.lock().ok()?;
        let events = retained.events.checked_add(1)?;
        let aggregate_bytes = retained.bytes.checked_add(bytes)?;
        if events > RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS
            || aggregate_bytes > RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES
        {
            return None;
        }
        retained.events = events;
        retained.bytes = aggregate_bytes;
        Some(RecoveryBundlePushInboundPermit {
            budget: Arc::clone(budget),
            bytes,
            peer_id: None,
        })
    }
}

pub(super) struct RecoveryBundlePushInboundPermit {
    budget: Arc<RecoveryBundlePushInboundBudget>,
    bytes: usize,
    peer_id: Option<PeerId>,
}

impl RecoveryBundlePushInboundPermit {
    fn bind_peer(&mut self, peer_id: PeerId) -> bool {
        if self.peer_id.is_some() {
            return false;
        }
        let Ok(mut retained) = self.budget.retained.lock() else {
            return false;
        };
        if !retained.peers.insert(peer_id) {
            return false;
        }
        self.peer_id = Some(peer_id);
        true
    }
}

impl Drop for RecoveryBundlePushInboundPermit {
    fn drop(&mut self) {
        let mut retained = self
            .budget
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retained.events = retained.events.saturating_sub(1);
        retained.bytes = retained.bytes.saturating_sub(self.bytes);
        if let Some(peer_id) = self.peer_id {
            retained.peers.remove(&peer_id);
        }
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
        self.request.bytes.len()
    }
    /// Borrows the unvalidated recovery-bundle candidate bytes.
    pub fn bundle_bytes(&self) -> &[u8] {
        self.request.bundle_bytes()
    }
}
impl fmt::Debug for InboundRecoveryBundlePush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundRecoveryBundlePush")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("encoded_bytes", &self.request.bytes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        let encoded_bytes = request.bytes.len();
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
    ) -> Result<Vec<u8>, RecoveryBundlePushAcknowledgeError> {
        let InboundRecoveryBundlePush {
            peer_id,
            request,
            channel,
            ..
        } = inbound;
        let bundle_bytes = request.into_bundle_bytes();
        match self
            .swarm
            .behaviour_mut()
            .recovery_bundle_push
            .send_response(channel, RecoveryBundlePushReceipt)
        {
            Ok(()) => Ok(bundle_bytes),
            Err(_) => Err(RecoveryBundlePushAcknowledgeError {
                peer_id,
                bundle_bytes,
            }),
        }
    }
    pub(super) fn handle_recovery_bundle_push_event(
        &mut self,
        event: request_response::Event<RecoveryBundlePushRequest, RecoveryBundlePushReceipt>,
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
                    Some(NetworkEvent::InboundRecoveryBundlePush(
                        InboundRecoveryBundlePush {
                            peer_id: peer,
                            request_id,
                            request,
                            channel,
                        },
                    ))
                }
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
#[derive(Debug, PartialEq, Eq)]
pub struct RecoveryBundlePushAcknowledgeError {
    peer_id: PeerId,
    bundle_bytes: Vec<u8>,
}
impl RecoveryBundlePushAcknowledgeError {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn bundle_bytes(&self) -> &[u8] {
        &self.bundle_bytes
    }
    pub fn into_bundle_bytes(self) -> Vec<u8> {
        self.bundle_bytes
    }
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
    use libp2p::swarm::ConnectionId;
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::Keypair;

    fn receipt_event(
        network: &mut StaticArtifactNetwork,
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
    ) -> OutboundRecoveryBundlePushEvent {
        let event = network
            .handle_recovery_bundle_push_event(request_response::Event::Message {
                peer: peer_id,
                connection_id: ConnectionId::new_unchecked(2_000),
                message: request_response::Message::Response {
                    request_id,
                    response: RecoveryBundlePushReceipt,
                },
            })
            .expect("the retained push produces one terminal event");
        let NetworkEvent::OutboundRecoveryBundlePush(event) = event else {
            panic!("recovery-bundle receipt did not produce its outbound terminal")
        };
        event
    }

    #[test]
    fn request_accepts_the_exact_transport_maximum() {
        assert_eq!(
            RecoveryBundlePushRequest::new(vec![0; RECOVERY_BUNDLE_PUSH_MAX_BYTES])
                .unwrap()
                .into_bundle_bytes()
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

    #[test]
    fn inbound_capacity_preserves_one_full_size_slot_per_configured_peer() {
        assert_eq!(crate::MAX_CONNECTIONS_PER_PEER, 1);
        assert_eq!(crate::MAX_RECOVERY_BUNDLE_PUSH_STREAMS_PER_CONNECTION, 1);
        assert_eq!(
            RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS,
            MAX_STATIC_PEERS
        );
        assert_eq!(
            RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
            RECOVERY_BUNDLE_PUSH_MAX_BYTES * MAX_STATIC_PEERS
        );

        let budget = Arc::new(RecoveryBundlePushInboundBudget::default());
        let first_peer = Keypair::generate_ed25519().public().to_peer_id();
        let first_permit = RecoveryBundlePushInboundBudget::try_acquire(&budget, 0).unwrap();
        let mut first = RecoveryBundlePushRequest::from_inbound(Vec::new(), first_permit);
        assert!(first.bind_inbound_peer(first_peer));

        let duplicate_permit = RecoveryBundlePushInboundBudget::try_acquire(&budget, 0).unwrap();
        let mut duplicate = RecoveryBundlePushRequest::from_inbound(Vec::new(), duplicate_permit);
        assert!(!duplicate.bind_inbound_peer(first_peer));
        drop(duplicate);

        let mut retained = vec![first];
        for _ in 1..MAX_STATIC_PEERS {
            let peer_id = Keypair::generate_ed25519().public().to_peer_id();
            let permit = RecoveryBundlePushInboundBudget::try_acquire(&budget, 0).unwrap();
            let mut request = RecoveryBundlePushRequest::from_inbound(Vec::new(), permit);
            assert!(request.bind_inbound_peer(peer_id));
            retained.push(request);
        }
        assert!(RecoveryBundlePushInboundBudget::try_acquire(&budget, 0).is_none());
        drop(retained);

        let released_permit = RecoveryBundlePushInboundBudget::try_acquire(&budget, 0).unwrap();
        let mut released = RecoveryBundlePushRequest::from_inbound(Vec::new(), released_permit);
        assert!(released.bind_inbound_peer(first_peer));
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
                        assert_eq!(inbound.bundle_bytes(), expected);
                        let inbound_pointer = inbound.bundle_bytes().as_ptr();
                        let accepted = receiver.acknowledge_recovery_bundle_push(inbound).unwrap();
                        assert_eq!(accepted, expected);
                        assert_eq!(accepted.as_ptr(), inbound_pointer);
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

    #[tokio::test]
    async fn closed_response_channel_returns_the_same_owned_bytes() {
        let (mut sender, mut receiver, sender_peer, receiver_peer) =
            crate::tests::connected_pair().await;
        let expected = vec![0xa5, 0x5a, 0x00];
        let _ticket = sender
            .push_recovery_bundle(receiver_peer, expected.clone())
            .unwrap();
        let inbound = timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = receiver.next_event() => {
                        if let NetworkEvent::InboundRecoveryBundlePush(inbound) = event {
                            return inbound;
                        }
                    }
                    _ = sender.next_event() => {}
                }
            }
        })
        .await
        .unwrap();
        let inbound_pointer = inbound.bundle_bytes().as_ptr();
        drop(sender);
        timeout(Duration::from_secs(10), async {
            while inbound.channel.is_open() {
                let _ = receiver.next_event().await;
            }
        })
        .await
        .unwrap();

        let error = receiver
            .acknowledge_recovery_bundle_push(inbound)
            .unwrap_err();
        assert_eq!(error.peer_id(), sender_peer);
        assert_eq!(error.bundle_bytes(), expected);
        assert_eq!(error.bundle_bytes().as_ptr(), inbound_pointer);
        let recovered = error.into_bundle_bytes();
        assert_eq!(recovered, expected);
        assert_eq!(recovered.as_ptr(), inbound_pointer);
    }

    #[test]
    fn ticket_rejects_other_network_and_changed_byte_count_without_losing_values() {
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let mut first = crate::tests::test_network_for_peers(&[peer_id]);
        let mut second = crate::tests::test_network_for_peers(&[peer_id]);
        let first_ticket = first.push_recovery_bundle(peer_id, vec![0xa5]).unwrap();
        let second_ticket = second.push_recovery_bundle(peer_id, vec![0xa5]).unwrap();
        assert_eq!(first_ticket.request_id, second_ticket.request_id);

        let second_event = receipt_event(&mut second, second_ticket.request_id, peer_id);
        assert!(!first_ticket.accepts_event(&second_event));
        let mismatch = first_ticket.complete(second_event).unwrap_err();
        let (first_ticket, second_event) = (*mismatch).into_parts();
        assert!(second_ticket.accepts_event(&second_event));
        let _ = second_ticket.complete(second_event).unwrap().unwrap();
        drop(
            first
                .pending
                .remove(&ExchangeRequestId::RecoveryBundlePush(
                    first_ticket.request_id,
                ))
                .unwrap(),
        );

        let ticket = first
            .push_recovery_bundle(peer_id, vec![0xa5, 0x5a])
            .unwrap();
        let mut event = receipt_event(&mut first, ticket.request_id, peer_id);
        event.bytes += 1;
        assert!(!ticket.accepts_event(&event));
        let mismatch = ticket.complete(event).unwrap_err();
        let (ticket, mut event) = (*mismatch).into_parts();
        event.bytes -= 1;
        assert!(ticket.accepts_event(&event));
        let receipt = ticket.complete(event).unwrap().unwrap();
        assert_eq!(receipt.encoded_bytes(), 2);
    }
}
