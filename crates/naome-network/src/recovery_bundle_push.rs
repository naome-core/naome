//! Caller-selected authenticated delivery of one opaque recovery bundle.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use libp2p::request_response;
use naome_chain::ArtifactBlockId;
use naome_storage::{
    ArtifactBlockCandidateStore, CandidateBranchRecoveryBundleLimits,
    CandidateBranchRecoveryBundleStageError, CandidateBranchRecoveryBundleStageOutcome,
    CanonicalArtifactPayloadStore, SelectedArtifactHistory,
    stage_candidate_branch_recovery_bundle_v0,
};

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

/// One source-bound stream acceptance with its exact caller-owned bundle bytes.
///
/// The authenticated immediate peer remains only a transport observation. The
/// receipt already sent for this value means stream acceptance, not decoding,
/// validation, persistence, provenance, selection, consensus, or finality.
#[must_use]
pub struct AcknowledgedRecoveryBundlePush {
    peer_id: PeerId,
    bundle_bytes: Vec<u8>,
}

/// The exact transport source and branch endpoints selected by the caller for staging.
///
/// The expected peer is only a source constraint. It grants no provenance,
/// selection, consensus, or finality authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryBundleStageSelection {
    expected_peer_id: PeerId,
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
}

impl RecoveryBundleStageSelection {
    pub const fn new(
        expected_peer_id: PeerId,
        anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
    ) -> Self {
        Self {
            expected_peer_id,
            anchor_block_id,
            target_block_id,
        }
    }

    pub const fn expected_peer_id(&self) -> PeerId {
        self.expected_peer_id
    }

    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }
}

impl AcknowledgedRecoveryBundlePush {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn encoded_bytes(&self) -> usize {
        self.bundle_bytes.len()
    }
    pub fn bundle_bytes(&self) -> &[u8] {
        &self.bundle_bytes
    }
    pub fn into_bundle_bytes(self) -> Vec<u8> {
        self.bundle_bytes
    }

    /// Stages this accepted stream only for the exact caller-selected source,
    /// selected anchor, and unselected target.
    ///
    /// Complete staging preserves the source observation only in the returned
    /// memory value; neither durable store records peer provenance. A mismatch
    /// or staging failure returns the exact owned bytes.
    pub fn stage_candidate_branch(
        self,
        selection: RecoveryBundleStageSelection,
        selected: &dyn SelectedArtifactHistory,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<AcknowledgedRecoveryBundleStageOutcome, Box<AcknowledgedRecoveryBundleStageError>>
    {
        if self.peer_id != selection.expected_peer_id {
            return Err(Box::new(
                AcknowledgedRecoveryBundleStageError::UnexpectedPeer {
                    expected: selection.expected_peer_id,
                    actual: self.peer_id,
                    acknowledged: self,
                },
            ));
        }
        let peer_id = self.peer_id;
        match stage_candidate_branch_recovery_bundle_v0(
            self.bundle_bytes,
            selection.anchor_block_id,
            selection.target_block_id,
            selected,
            candidates,
            payloads,
            limits,
        ) {
            Ok(staging) => Ok(AcknowledgedRecoveryBundleStageOutcome { peer_id, staging }),
            Err(source) => Err(Box::new(AcknowledgedRecoveryBundleStageError::Staging {
                peer_id,
                source,
            })),
        }
    }
}

impl fmt::Debug for AcknowledgedRecoveryBundlePush {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcknowledgedRecoveryBundlePush")
            .field("peer_id", &self.peer_id)
            .field("encoded_bytes", &self.bundle_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Complete unselected staging bound to the observed authenticated source.
#[must_use]
pub struct AcknowledgedRecoveryBundleStageOutcome {
    peer_id: PeerId,
    staging: CandidateBranchRecoveryBundleStageOutcome,
}

impl AcknowledgedRecoveryBundleStageOutcome {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn staging(&self) -> &CandidateBranchRecoveryBundleStageOutcome {
        &self.staging
    }
    pub fn into_staging(self) -> CandidateBranchRecoveryBundleStageOutcome {
        self.staging
    }
}

impl fmt::Debug for AcknowledgedRecoveryBundleStageOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcknowledgedRecoveryBundleStageOutcome")
            .field("peer_id", &self.peer_id)
            .field("staging", &self.staging)
            .finish()
    }
}

/// A source-authorization or strict unselected-staging failure.
#[must_use]
pub enum AcknowledgedRecoveryBundleStageError {
    UnexpectedPeer {
        expected: PeerId,
        actual: PeerId,
        acknowledged: AcknowledgedRecoveryBundlePush,
    },
    Staging {
        peer_id: PeerId,
        source: CandidateBranchRecoveryBundleStageError,
    },
}

impl AcknowledgedRecoveryBundleStageError {
    pub fn bundle_bytes(&self) -> &[u8] {
        match self {
            Self::UnexpectedPeer { acknowledged, .. } => acknowledged.bundle_bytes(),
            Self::Staging { source, .. } => source.bundle_bytes(),
        }
    }
    pub fn into_bundle_bytes(self) -> Vec<u8> {
        match self {
            Self::UnexpectedPeer { acknowledged, .. } => acknowledged.into_bundle_bytes(),
            Self::Staging { source, .. } => source.into_bundle_bytes(),
        }
    }
}

impl fmt::Debug for AcknowledgedRecoveryBundleStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedPeer {
                expected,
                actual,
                acknowledged,
            } => formatter
                .debug_struct("AcknowledgedRecoveryBundleStageError::UnexpectedPeer")
                .field("expected", expected)
                .field("actual", actual)
                .field("acknowledged", acknowledged)
                .finish(),
            Self::Staging { peer_id, source } => formatter
                .debug_struct("AcknowledgedRecoveryBundleStageError::Staging")
                .field("peer_id", peer_id)
                .field("source", source)
                .finish(),
        }
    }
}

impl fmt::Display for AcknowledgedRecoveryBundleStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedPeer {
                expected, actual, ..
            } => write!(
                formatter,
                "acknowledged recovery bundle came from {actual}, expected caller-selected {expected}"
            ),
            Self::Staging { peer_id, source } => {
                write!(
                    formatter,
                    "recovery bundle from {peer_id} was not staged: {source}"
                )
            }
        }
    }
}

impl Error for AcknowledgedRecoveryBundleStageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnexpectedPeer { .. } => None,
            Self::Staging { source, .. } => Some(source),
        }
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
        self.acknowledge_recovery_bundle_push_with_source(inbound)
            .map(AcknowledgedRecoveryBundlePush::into_bundle_bytes)
    }

    /// Sends the stream-only receipt and preserves the authenticated immediate
    /// source alongside the exact owned bytes for explicit caller policy.
    pub fn acknowledge_recovery_bundle_push_with_source(
        &mut self,
        inbound: InboundRecoveryBundlePush,
    ) -> Result<AcknowledgedRecoveryBundlePush, RecoveryBundlePushAcknowledgeError> {
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
            Ok(()) => Ok(AcknowledgedRecoveryBundlePush {
                peer_id,
                bundle_bytes,
            }),
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
    use naome_chain::{ArtifactBlock, ArtifactChainState, ArtifactDag};
    use naome_storage::{
        ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStoreLimits,
        ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits,
        CandidateBranchRecoveryBundleStageFailure,
    };
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::Keypair;

    struct BundleFixture {
        definition: naome_chain::ArtifactChainDefinition,
        blocks: Vec<ArtifactBlock>,
        payloads: Vec<Vec<u8>>,
        limits: CandidateBranchRecoveryBundleLimits,
        bytes: Vec<u8>,
    }

    impl BundleFixture {
        fn anchor(&self) -> ArtifactBlockId {
            self.definition.id().virtual_genesis_block_id()
        }

        fn target(&self) -> ArtifactBlockId {
            self.blocks.last().unwrap().id()
        }

        fn payload_bytes(&self) -> u64 {
            u64::try_from(self.payloads.iter().map(Vec::len).sum::<usize>()).unwrap()
        }
    }

    fn bundle_fixture() -> BundleFixture {
        let definition = crate::tests::test_chain_definition();
        let payloads = vec![crate::tests::pairing_bytes(), crate::tests::union_bytes()];
        let mut dag = ArtifactDag::new();
        let artifact_ids = payloads
            .iter()
            .map(|payload| {
                dag.apply_canonical_artifact_bytes(payload.clone())
                    .unwrap()
                    .artifact_id()
            })
            .collect::<Vec<_>>();
        let mut branch = ArtifactChainState::new(definition);
        let mut blocks = Vec::new();
        for (&artifact_id, payload) in artifact_ids.iter().zip(&payloads) {
            let block = branch.prepare_block(artifact_id).unwrap();
            branch.apply_block(&block, payload.clone()).unwrap();
            blocks.push(block);
        }
        let payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();
        let limits = CandidateBranchRecoveryBundleLimits::new(
            blocks.len(),
            u64::try_from(payload_bytes).unwrap(),
            RECOVERY_BUNDLE_PUSH_MAX_BYTES as u64,
        )
        .unwrap();
        let source = crate::tests::TestDirectory::new("recovery-bundle-stage-source");
        let journal = crate::tests::create_journal(source.path()).unwrap();
        let mut candidates = ArtifactBlockCandidateStore::create(
            source.path(),
            definition,
            ArtifactBlockCandidateStoreLimits::new(blocks.len()).unwrap(),
        )
        .unwrap();
        for block in &blocks {
            assert_eq!(
                candidates.insert(block).unwrap(),
                ArtifactBlockCandidateInsertOutcome::Inserted
            );
        }
        let mut payload_store = CanonicalArtifactPayloadStore::create(
            source.path(),
            ArtifactPayloadStoreLimits::new(payloads.len(), u64::try_from(payload_bytes).unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut accepted = ArtifactDag::new();
        for payload in &payloads {
            let record = accepted
                .apply_canonical_artifact_bytes(payload.clone())
                .unwrap();
            assert_eq!(
                payload_store.insert(record).unwrap(),
                ArtifactPayloadInsertOutcome::Inserted
            );
        }
        let bytes = journal
            .export_candidate_branch_recovery_bundle_v0(
                blocks.last().unwrap().id(),
                &mut candidates,
                &mut payload_store,
                limits,
            )
            .unwrap()
            .into_canonical_bytes();
        BundleFixture {
            definition,
            blocks,
            payloads,
            limits,
            bytes,
        }
    }

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
    async fn acknowledged_authenticated_bundle_stages_unselected_data_without_mutating_history() {
        let fixture = bundle_fixture();
        let destination = crate::tests::TestDirectory::new("recovery-bundle-stage-destination");
        let selected = crate::tests::create_journal(destination.path()).unwrap();
        let selected_before = crate::tests::snapshot(&destination, &selected);
        let mut candidates = ArtifactBlockCandidateStore::create(
            destination.path(),
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(fixture.blocks.len()).unwrap(),
        )
        .unwrap();
        let mut payloads = CanonicalArtifactPayloadStore::create(
            destination.path(),
            ArtifactPayloadStoreLimits::new(fixture.payloads.len(), fixture.payload_bytes())
                .unwrap(),
        )
        .unwrap();
        let (mut sender, mut receiver, sender_peer, receiver_peer) =
            crate::tests::connected_pair().await;
        let expected_bytes = fixture.bytes.clone();
        let anchor = fixture.anchor();
        let target = fixture.target();
        let mut ticket = Some(
            sender
                .push_recovery_bundle(receiver_peer, fixture.bytes)
                .unwrap(),
        );

        timeout(Duration::from_secs(10), async {
            let mut staged = false;
            loop {
                tokio::select! {
                    event = receiver.next_event() => {
                        if !staged && let NetworkEvent::InboundRecoveryBundlePush(inbound) = event {
                            let inbound_pointer = inbound.bundle_bytes().as_ptr();
                            let acknowledged = receiver
                                .acknowledge_recovery_bundle_push_with_source(inbound)
                                .unwrap();
                            assert_eq!(acknowledged.peer_id(), sender_peer);
                            assert_eq!(acknowledged.bundle_bytes().as_ptr(), inbound_pointer);
                            let outcome = acknowledged
                                .stage_candidate_branch(
                                    RecoveryBundleStageSelection::new(sender_peer, anchor, target),
                                    &selected,
                                    &mut candidates,
                                    &mut payloads,
                                    fixture.limits,
                                )
                                .unwrap();
                            assert_eq!(outcome.peer_id(), sender_peer);
                            assert_eq!(outcome.staging().candidate_block_count(), 2);
                            assert_eq!(outcome.staging().candidate_inserted_count(), 2);
                            assert_eq!(outcome.staging().payload_inserted_count(), 2);
                            assert_eq!(outcome.staging().bundle_bytes(), expected_bytes);
                            assert_eq!(outcome.staging().bundle_bytes().as_ptr(), inbound_pointer);
                            staged = true;
                        }
                    },
                    event = sender.next_event() => {
                        if staged && let NetworkEvent::OutboundRecoveryBundlePush(event) = event {
                            let receipt = ticket.take().unwrap().complete(event).unwrap().unwrap();
                            assert_eq!(receipt.peer_id(), receiver_peer);
                            break;
                        }
                    },
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(candidates.len().unwrap(), 2);
        assert_eq!(payloads.len().unwrap(), 2);
        crate::tests::assert_snapshot(&destination, &selected, &selected_before);
    }

    #[tokio::test]
    async fn stream_receipt_survives_strict_staging_rejection_and_attests_no_storage() {
        let fixture = bundle_fixture();
        let destination = crate::tests::TestDirectory::new("recovery-bundle-rejected-destination");
        let selected = crate::tests::create_journal(destination.path()).unwrap();
        let selected_before = crate::tests::snapshot(&destination, &selected);
        let mut candidates = ArtifactBlockCandidateStore::create(
            destination.path(),
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(fixture.blocks.len()).unwrap(),
        )
        .unwrap();
        let mut payloads = CanonicalArtifactPayloadStore::create(
            destination.path(),
            ArtifactPayloadStoreLimits::new(fixture.payloads.len(), fixture.payload_bytes())
                .unwrap(),
        )
        .unwrap();
        let (mut sender, mut receiver, sender_peer, receiver_peer) =
            crate::tests::connected_pair().await;
        let malformed = vec![0xff];
        let ticket = sender
            .push_recovery_bundle(receiver_peer, malformed)
            .unwrap();

        timeout(Duration::from_secs(10), async {
            let mut rejected = false;
            let mut receipt_received = false;
            let mut ticket = Some(ticket);
            loop {
                tokio::select! {
                    event = receiver.next_event() => {
                        if !rejected && let NetworkEvent::InboundRecoveryBundlePush(inbound) = event {
                            let inbound_pointer = inbound.bundle_bytes().as_ptr();
                            let acknowledged = receiver
                                .acknowledge_recovery_bundle_push_with_source(inbound)
                                .unwrap();
                            let error = acknowledged
                                .stage_candidate_branch(
                                    RecoveryBundleStageSelection::new(
                                        sender_peer,
                                        fixture.anchor(),
                                        fixture.target(),
                                    ),
                                    &selected,
                                    &mut candidates,
                                    &mut payloads,
                                    fixture.limits,
                                )
                                .unwrap_err();
                            assert_eq!(error.bundle_bytes().as_ptr(), inbound_pointer);
                            let AcknowledgedRecoveryBundleStageError::Staging { source, .. } = *error else {
                                panic!("matching source must reach strict staging")
                            };
                            assert!(matches!(
                                source.failure(),
                                CandidateBranchRecoveryBundleStageFailure::Decode { .. }
                            ));
                            rejected = true;
                            if receipt_received {
                                break;
                            }
                        }
                    },
                    event = sender.next_event() => {
                        if let NetworkEvent::OutboundRecoveryBundlePush(event) = event {
                            let receipt = ticket.take().unwrap().complete(event).unwrap().unwrap();
                            assert_eq!(receipt.peer_id(), receiver_peer);
                            assert_eq!(receipt.encoded_bytes(), 1);
                            receipt_received = true;
                            if rejected {
                                break;
                            }
                        }
                    },
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(candidates.len().unwrap(), 0);
        assert_eq!(payloads.len().unwrap(), 0);
        crate::tests::assert_snapshot(&destination, &selected, &selected_before);
    }

    #[test]
    fn operable_finality_history_stages_a_suffix_without_mutating_finality() {
        let fixture = bundle_fixture();
        let finality_directory =
            crate::tests::TestDirectory::new("recovery-bundle-operable-finality");
        let mut finality_fixture = crate::tests::FinalityFixture::new();
        let mut finality = finality_fixture.create(&finality_directory);
        let selected_block =
            finality_fixture.commit_payload(&mut finality, crate::tests::pairing_bytes());
        assert_eq!(selected_block, fixture.blocks[0].id());
        let finality_before = crate::tests::finality_snapshot(&finality_directory, &finality);
        let stores = crate::tests::TestDirectory::new("recovery-bundle-operable-stores");
        let mut candidates = ArtifactBlockCandidateStore::create(
            stores.path(),
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(1).unwrap(),
        )
        .unwrap();
        let mut payloads = CanonicalArtifactPayloadStore::create(
            stores.path(),
            ArtifactPayloadStoreLimits::new(1, u64::try_from(fixture.payloads[1].len()).unwrap())
                .unwrap(),
        )
        .unwrap();
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let anchor = fixture.anchor();
        let target = fixture.target();
        let limits = fixture.limits;
        let acknowledged = AcknowledgedRecoveryBundlePush {
            peer_id,
            bundle_bytes: fixture.bytes,
        };

        let outcome = acknowledged
            .stage_candidate_branch(
                RecoveryBundleStageSelection::new(peer_id, anchor, target),
                &finality,
                &mut candidates,
                &mut payloads,
                limits,
            )
            .unwrap();

        assert_eq!(outcome.staging().selected_prefix_count(), 1);
        assert_eq!(outcome.staging().candidate_block_count(), 1);
        assert_eq!(outcome.staging().candidate_inserted_count(), 1);
        assert_eq!(outcome.staging().payload_inserted_count(), 1);
        assert_eq!(candidates.len().unwrap(), 1);
        assert_eq!(payloads.len().unwrap(), 1);
        crate::tests::assert_finality_snapshot(&finality_directory, &finality, &finality_before);
    }

    #[test]
    fn terminal_finality_history_rejects_staging_before_store_writes() {
        let fixture = bundle_fixture();
        let finality_directory = crate::tests::TestDirectory::new("recovery-bundle-stage-finality");
        let mut finality_fixture = crate::tests::FinalityFixture::new();
        let mut finality = finality_fixture.create(&finality_directory);
        finality_fixture.halt_with_conflict(
            &mut finality,
            crate::tests::pairing_bytes(),
            crate::tests::union_bytes(),
        );
        let finality_bytes = finality_directory.journal_bytes();
        let finality_state_id = finality.state_id().unwrap();
        let finality_halt = finality.halt().unwrap();
        let stores = crate::tests::TestDirectory::new("recovery-bundle-stage-halted-stores");
        let mut candidates = ArtifactBlockCandidateStore::create(
            stores.path(),
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(2).unwrap(),
        )
        .unwrap();
        let mut payloads = CanonicalArtifactPayloadStore::create(
            stores.path(),
            ArtifactPayloadStoreLimits::new(2, fixture.payload_bytes()).unwrap(),
        )
        .unwrap();
        let candidate_bytes =
            std::fs::read(stores.path().join("artifact-block-candidate-store.log")).unwrap();
        let payload_bytes =
            std::fs::read(stores.path().join("artifact-payload-store.log")).unwrap();
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let anchor = fixture.anchor();
        let target = fixture.target();
        let acknowledged = AcknowledgedRecoveryBundlePush {
            peer_id,
            bundle_bytes: fixture.bytes,
        };
        let error = acknowledged
            .stage_candidate_branch(
                RecoveryBundleStageSelection::new(peer_id, anchor, target),
                &finality,
                &mut candidates,
                &mut payloads,
                fixture.limits,
            )
            .unwrap_err();
        let AcknowledgedRecoveryBundleStageError::Staging { source, .. } = *error else {
            panic!("matching source must reach selected-history staging")
        };
        assert!(matches!(
            source.failure(),
            CandidateBranchRecoveryBundleStageFailure::SelectedHistory { .. }
        ));
        assert_eq!(source.candidate_acknowledged_count(), 0);
        assert_eq!(candidates.len().unwrap(), 0);
        assert_eq!(payloads.len().unwrap(), 0);
        assert_eq!(
            std::fs::read(stores.path().join("artifact-block-candidate-store.log")).unwrap(),
            candidate_bytes
        );
        assert_eq!(
            std::fs::read(stores.path().join("artifact-payload-store.log")).unwrap(),
            payload_bytes
        );
        assert_eq!(finality_directory.journal_bytes(), finality_bytes);
        assert_eq!(finality.state_id().unwrap(), finality_state_id);
        assert_eq!(finality.halt().unwrap(), finality_halt);
    }

    #[test]
    fn caller_selected_source_mismatch_preserves_bytes_and_writes_nothing() {
        let fixture = bundle_fixture();
        let destination = crate::tests::TestDirectory::new("recovery-bundle-wrong-source");
        let selected = crate::tests::create_journal(destination.path()).unwrap();
        let selected_before = crate::tests::snapshot(&destination, &selected);
        let mut candidates = ArtifactBlockCandidateStore::create(
            destination.path(),
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(fixture.blocks.len()).unwrap(),
        )
        .unwrap();
        let mut payloads = CanonicalArtifactPayloadStore::create(
            destination.path(),
            ArtifactPayloadStoreLimits::new(fixture.payloads.len(), fixture.payload_bytes())
                .unwrap(),
        )
        .unwrap();
        let actual_peer = Keypair::generate_ed25519().public().to_peer_id();
        let expected_peer = Keypair::generate_ed25519().public().to_peer_id();
        let anchor = fixture.anchor();
        let target = fixture.target();
        let limits = fixture.limits;
        let malformed = vec![0xff];
        let bundle_pointer = malformed.as_ptr();
        let acknowledged = AcknowledgedRecoveryBundlePush {
            peer_id: actual_peer,
            bundle_bytes: malformed,
        };

        let error = acknowledged
            .stage_candidate_branch(
                RecoveryBundleStageSelection::new(expected_peer, anchor, target),
                &selected,
                &mut candidates,
                &mut payloads,
                limits,
            )
            .unwrap_err();

        assert_eq!(error.bundle_bytes().as_ptr(), bundle_pointer);
        assert!(matches!(
            *error,
            AcknowledgedRecoveryBundleStageError::UnexpectedPeer {
                expected,
                actual,
                ..
            } if expected == expected_peer && actual == actual_peer
        ));
        assert_eq!(candidates.len().unwrap(), 0);
        assert_eq!(payloads.len().unwrap(), 0);
        crate::tests::assert_snapshot(&destination, &selected, &selected_before);
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
