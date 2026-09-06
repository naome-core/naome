//! Exact-height, authenticated transport of untrusted complete finality proofs.

use std::{error::Error, fmt, sync::Arc};

use libp2p::request_response;
use naome_consensus::{ConsensusContextV0, ConsensusHeight};
use naome_storage::{
    FixedValidatorAnchoredFinalityJournalV0, FixedValidatorFinalityJournalErrorV0,
    SelectedFinalityProofHistoryV0,
};

use super::inbound_retention::{InboundRetentionBudget, InboundRetentionPermit};
use super::{
    ExchangeRequestId, MAX_STATIC_PEERS, NetworkEvent, PeerId, PendingBudget, PendingPermit,
    PendingRequest, RequestStartError, RespondError, StaticArtifactNetwork,
};

pub(super) mod codec;

/// Complete context and positive-height request width.
pub const FINALITY_PROOF_REQUEST_BYTES: usize = 76;
/// Minimum complete fixed-validator V0 finality envelope width.
pub const FINALITY_PROOF_MIN_ENVELOPE_BYTES: usize =
    naome_consensus::VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH;
/// Maximum complete fixed-validator V0 finality envelope width.
pub const FINALITY_PROOF_MAX_ENVELOPE_BYTES: usize =
    naome_consensus::VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH;
/// Maximum canonical artifact payload width.
pub const FINALITY_PROOF_MAX_PAYLOAD_BYTES: usize = naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;
/// Maximum combined body bytes in retained or in-flight proof responses, in both directions.
pub const FINALITY_PROOF_MAX_RETAINED_BYTES: usize =
    MAX_STATIC_PEERS * (FINALITY_PROOF_MAX_ENVELOPE_BYTES + FINALITY_PROOF_MAX_PAYLOAD_BYTES);

/// A caller-selected address. Construction establishes no finality or peer trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct FinalityProofRequest {
    context: ConsensusContextV0,
    height: ConsensusHeight,
}

impl FinalityProofRequest {
    /// Returns no request for virtual genesis, which has no finality envelope.
    pub const fn new(context: ConsensusContextV0, height: ConsensusHeight) -> Option<Self> {
        if height.value() == 0 {
            None
        } else {
            Some(Self { context, height })
        }
    }

    pub const fn context(self) -> ConsensusContextV0 {
        self.context
    }
    pub const fn height(self) -> ConsensusHeight {
        self.height
    }
}

/// A complete bounded response, still requiring exact-request and full proof verification.
#[must_use]
pub enum FinalityProofResponse {
    Unavailable,
    Found {
        canonical_envelope: Vec<u8>,
        canonical_artifact: Vec<u8>,
    },
}

impl fmt::Debug for FinalityProofResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("Unavailable"),
            Self::Found {
                canonical_envelope,
                canonical_artifact,
            } => f
                .debug_struct("Found")
                .field("envelope_bytes", &canonical_envelope.len())
                .field("artifact_bytes", &canonical_artifact.len())
                .finish(),
        }
    }
}

pub(super) struct WireRequest {
    request: FinalityProofRequest,
    permit: Option<InboundRetentionPermit>,
}
impl fmt::Debug for WireRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.request.fmt(f)
    }
}

pub(super) struct WireResponse {
    response: FinalityProofResponse,
    _permit: InboundRetentionPermit,
}
impl fmt::Debug for WireResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.response.fmt(f)
    }
}

pub(super) struct PendingFinalityProof {
    pub(super) peer_index: usize,
    request: FinalityProofRequest,
    permit: PendingPermit,
}

/// An exact request generation. Dropping it does not cancel the physical request.
#[must_use]
pub struct FinalityProofTicket {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: FinalityProofRequest,
    network_budget: Arc<PendingBudget>,
}

impl FinalityProofTicket {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn request(&self) -> FinalityProofRequest {
        self.request
    }

    pub fn accepts_event(&self, event: &OutboundFinalityProofEvent) -> bool {
        super::request_correlation::RequestCorrelation::new(
            self.request_id,
            self.peer_id,
            &self.request,
        )
        .matches(
            super::request_correlation::RequestCorrelation::new(
                event.request_id,
                event.peer_id,
                &event.request,
            ),
            &self.network_budget,
            &event.network_budget,
        )
    }

    /// Only exact correlation releases the response. Mismatch preserves both owners.
    pub fn complete(
        self,
        event: OutboundFinalityProofEvent,
    ) -> Result<
        Result<AuthenticatedFinalityProofResponse, Box<OutboundFinalityProofFailure>>,
        Box<FinalityProofEventMismatch>,
    > {
        if !self.accepts_event(&event) {
            return Err(Box::new(FinalityProofEventMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event
            .outcome
            .map(|response| AuthenticatedFinalityProofResponse {
                peer_id: event.peer_id,
                request: event.request,
                response,
            }))
    }
}

impl fmt::Debug for FinalityProofTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalityProofTicket")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
#[must_use]
pub struct FinalityProofEventMismatch {
    ticket: FinalityProofTicket,
    event: OutboundFinalityProofEvent,
}
impl FinalityProofEventMismatch {
    pub fn into_parts(self) -> (FinalityProofTicket, OutboundFinalityProofEvent) {
        (self.ticket, self.event)
    }
}
impl fmt::Display for FinalityProofEventMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("finality proof terminal does not match its ticket")
    }
}
impl Error for FinalityProofEventMismatch {}

/// An authenticated inbound request retaining its bounded per-peer custody.
#[must_use]
pub struct InboundFinalityProofRequest {
    peer_id: PeerId,
    request: WireRequest,
    channel: request_response::ResponseChannel<WireResponse>,
}
impl InboundFinalityProofRequest {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn request(&self) -> FinalityProofRequest {
        self.request.request
    }
}
impl fmt::Debug for InboundFinalityProofRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundFinalityProofRequest")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request.request)
            .finish_non_exhaustive()
    }
}

/// A response or failure awaiting its exact ticket; successful bodies retain both budgets.
#[must_use]
pub struct OutboundFinalityProofEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    request: FinalityProofRequest,
    network_budget: Arc<PendingBudget>,
    outcome: Result<WireResponse, Box<OutboundFinalityProofFailure>>,
    _permit: Option<PendingPermit>,
}
impl OutboundFinalityProofEvent {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn request(&self) -> FinalityProofRequest {
        self.request
    }
}
impl fmt::Debug for OutboundFinalityProofEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundFinalityProofEvent")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("successful_transport", &self.outcome.is_ok())
            .finish_non_exhaustive()
    }
}

/// Authentication establishes the immediate source, not content validity or finality.
#[must_use]
pub struct AuthenticatedFinalityProofResponse {
    peer_id: PeerId,
    request: FinalityProofRequest,
    response: WireResponse,
}
impl AuthenticatedFinalityProofResponse {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn request(&self) -> FinalityProofRequest {
        self.request
    }

    /// Transfers the original body allocations to caller custody and releases transport retention.
    pub fn into_response(self) -> FinalityProofResponse {
        self.response.response
    }
}
impl fmt::Debug for AuthenticatedFinalityProofResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedFinalityProofResponse")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("response", &self.response.response)
            .finish()
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundFinalityProofFailure {
    Transport(request_response::OutboundFailure),
    PeerMismatch { expected: PeerId, actual: PeerId },
}
impl fmt::Display for OutboundFinalityProofFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "finality proof request failed: {self:?}")
    }
}
impl Error for OutboundFinalityProofFailure {}

#[derive(Debug)]
#[non_exhaustive]
pub enum FinalityProofRespondError {
    Transport(RespondError),
    Journal(FixedValidatorFinalityJournalErrorV0),
    InvalidLengths,
    RetentionLimit,
    Allocation,
}
impl fmt::Display for FinalityProofRespondError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot serve finality proof: {self:?}")
    }
}
impl Error for FinalityProofRespondError {}

pub(super) fn valid_lengths(envelope: usize, payload: usize) -> bool {
    (FINALITY_PROOF_MIN_ENVELOPE_BYTES..=FINALITY_PROOF_MAX_ENVELOPE_BYTES).contains(&envelope)
        && (1..=FINALITY_PROOF_MAX_PAYLOAD_BYTES).contains(&payload)
}

impl StaticArtifactNetwork {
    /// Starts one exact-height request over an existing managed session, using shared permits.
    pub fn request_finality_proof(
        &mut self,
        peer_id: PeerId,
        request: FinalityProofRequest,
    ) -> Result<FinalityProofTicket, RequestStartError> {
        let connected = self
            .swarm
            .behaviour()
            .finality_exchange
            .is_connected(&peer_id);
        let (peer_index, permit) = self.acquire_request_permit(peer_id, connected)?;
        let request_id = self.swarm.behaviour_mut().finality_exchange.send_request(
            &peer_id,
            WireRequest {
                request,
                permit: None,
            },
        );
        self.insert_pending(
            ExchangeRequestId::Finality(request_id),
            PendingRequest::Finality(PendingFinalityProof {
                peer_index,
                request,
                permit,
            }),
        );
        Ok(FinalityProofTicket {
            request_id,
            peer_id,
            request,
            network_budget: Arc::clone(&self.pending_budget),
        })
    }

    /// Copies one caller-selected opaque proof pair under bounded response custody.
    /// Neither the caller's bytes nor this operation grant verification or finality authority.
    pub fn respond_finality_proof(
        &mut self,
        inbound: InboundFinalityProofRequest,
        proof: Option<(&[u8], &[u8])>,
    ) -> Result<(), FinalityProofRespondError> {
        self.preflight_finality_response(&inbound)?;
        self.send_finality_response(inbound, proof)
    }

    /// Serves only the healthy journal's first retained proof at the exact requested height.
    /// Rate admission precedes journal access and body allocation. This borrows no signer.
    pub fn respond_finality_proof_from_journal(
        &mut self,
        inbound: InboundFinalityProofRequest,
        journal: &FixedValidatorAnchoredFinalityJournalV0,
    ) -> Result<(), FinalityProofRespondError> {
        self.respond_finality_proof_from_selected_history(inbound, journal)
    }

    /// Serves the same exact proof through the sealed projection available to a
    /// live driver. Channel/rate admission precedes all selected-history reads;
    /// shared response reservation precedes copying either body.
    pub fn respond_finality_proof_from_selected_history(
        &mut self,
        inbound: InboundFinalityProofRequest,
        history: &dyn SelectedFinalityProofHistoryV0,
    ) -> Result<(), FinalityProofRespondError> {
        self.preflight_finality_response(&inbound)?;
        let proof = history
            .selected_finality_proof(inbound.request().context(), inbound.request().height())
            .map_err(FinalityProofRespondError::Journal)?
            .map(|record| {
                (
                    record.canonical_envelope_bytes(),
                    record.canonical_artifact_bytes(),
                )
            });
        self.send_finality_response(inbound, proof)
    }

    fn preflight_finality_response(
        &mut self,
        inbound: &InboundFinalityProofRequest,
    ) -> Result<(), FinalityProofRespondError> {
        if !inbound.channel.is_open() {
            return Err(FinalityProofRespondError::Transport(
                RespondError::ChannelClosed,
            ));
        }
        self.take_inbound_application_request()
            .map_err(FinalityProofRespondError::Transport)
    }

    fn send_finality_response(
        &mut self,
        inbound: InboundFinalityProofRequest,
        proof: Option<(&[u8], &[u8])>,
    ) -> Result<(), FinalityProofRespondError> {
        let length = match proof {
            Some((envelope, payload)) if valid_lengths(envelope.len(), payload.len()) => {
                envelope.len() + payload.len()
            }
            Some(_) => return Err(FinalityProofRespondError::InvalidLengths),
            None => 0,
        };
        let permit = InboundRetentionBudget::try_acquire(&self.finality_response_budget, length)
            .ok_or(FinalityProofRespondError::RetentionLimit)?;
        let copy = |bytes: &[u8]| {
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(bytes.len())
                .map_err(|_| FinalityProofRespondError::Allocation)?;
            owned.extend_from_slice(bytes);
            Ok(owned)
        };
        let response = match proof {
            Some((envelope, payload)) => FinalityProofResponse::Found {
                canonical_envelope: copy(envelope)?,
                canonical_artifact: copy(payload)?,
            },
            None => FinalityProofResponse::Unavailable,
        };
        self.swarm
            .behaviour_mut()
            .finality_exchange
            .send_response(
                inbound.channel,
                WireResponse {
                    response,
                    _permit: permit,
                },
            )
            .map_err(|_| FinalityProofRespondError::Transport(RespondError::ChannelClosed))
    }

    pub(super) fn handle_finality_exchange_event(
        &mut self,
        event: request_response::Event<WireRequest, WireResponse>,
    ) -> Option<NetworkEvent> {
        let (peer, request_id, outcome) = match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    mut request,
                    channel,
                    ..
                } => {
                    if !request
                        .permit
                        .as_mut()
                        .is_some_and(|permit| permit.bind_peer(peer))
                    {
                        return None;
                    }
                    return Some(NetworkEvent::InboundFinalityProof(
                        InboundFinalityProofRequest {
                            peer_id: peer,
                            request,
                            channel,
                        },
                    ));
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => (peer, request_id, Ok(response)),
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => (
                peer,
                request_id,
                Err(OutboundFinalityProofFailure::Transport(error)),
            ),
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                return Some(NetworkEvent::InboundFinalityProofFailure {
                    peer_id: peer,
                    request_id,
                    error,
                });
            }
            request_response::Event::ResponseSent { .. } => return None,
        };
        let PendingRequest::Finality(pending) = self
            .pending
            .remove(&ExchangeRequestId::Finality(request_id))?
        else {
            unreachable!("finality request namespace retains only finality requests")
        };
        let expected = self.pending_peer_id(pending.peer_index);
        let outcome = if peer == expected {
            outcome
        } else {
            Err(OutboundFinalityProofFailure::PeerMismatch {
                expected,
                actual: peer,
            })
        };
        let network_budget = Arc::clone(&pending.permit.budget);
        let permit = outcome.is_ok().then_some(pending.permit);
        Some(NetworkEvent::OutboundFinalityProof(
            OutboundFinalityProofEvent {
                request_id,
                peer_id: expected,
                request: pending.request,
                network_budget,
                outcome: outcome.map_err(Box::new),
                _permit: permit,
            },
        ))
    }
}

#[cfg(test)]
mod tests;
