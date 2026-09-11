//! Direct authenticated offers with separately bounded inbound custody.
use super::inbound_retention::InboundRetentionPermit;
use super::{
    ExchangeRequestId, NetworkEvent, PeerId, PendingBudget, PendingPermit, PendingRequest,
    RequestStartError, RespondError, StaticArtifactNetwork,
};
use libp2p::request_response;
pub use naome_protocol::candidate_offer::{
    CANDIDATE_OFFER_MAX_BYTES, CANDIDATE_OFFER_MAX_IDS, CandidateOffer, CandidateOfferError,
};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc, time::Duration};
use tokio::time::Instant;
mod behaviour;
mod codec;
pub(super) use behaviour::Behaviour;
pub(super) use codec::{CANDIDATE_OFFER_PROTOCOL, CandidateOfferCodec};

/// Minimum interval between decoded offers delivered by one configured peer.
/// Rejected offers receive no success receipt; this is not a byte-rate guarantee.
pub const CANDIDATE_OFFER_INTERVAL: Duration = Duration::from_secs(1);

pub(super) fn fingerprint(offer: &CandidateOffer) -> [u8; 32] {
    Sha256::digest(offer.to_wire_bytes()).into()
}

pub(super) struct OfferRequest {
    offer: CandidateOffer,
    permit: Option<InboundRetentionPermit>,
}
impl fmt::Debug for OfferRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferRequest")
            .field("offer", &self.offer)
            .finish_non_exhaustive()
    }
}

pub(super) struct PendingOffer {
    pub(super) peer_index: usize,
    offer: CandidateOffer,
    permit: PendingPermit,
}

/// An authenticated raw offer. Retaining it retains its independent inbound budget.
#[must_use]
pub struct InboundCandidateOffer {
    peer: PeerId,
    request: OfferRequest,
    channel: request_response::ResponseChannel<[u8; 32]>,
}
impl InboundCandidateOffer {
    /// Returns the authenticated immediate publisher, not a validity authority.
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }
    /// Borrows the complete untrusted offer while retaining its bounded custody.
    pub fn offer(&self) -> &CandidateOffer {
        &self.request.offer
    }
}
impl fmt::Debug for InboundCandidateOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundCandidateOffer")
            .field("peer", &self.peer)
            .field("offer", &self.request.offer)
            .finish_non_exhaustive()
    }
}

/// One immutable outbound offer generation. Dropping it does not cancel transport.
#[must_use]
pub struct CandidateOfferTicket {
    id: request_response::OutboundRequestId,
    peer: PeerId,
    offer: CandidateOffer,
    budget: Arc<PendingBudget>,
}
impl CandidateOfferTicket {
    /// Returns the exact immediate receiver.
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }
    /// Returns the exact offer retained by this generation.
    pub fn offer(&self) -> &CandidateOffer {
        &self.offer
    }
    /// Tests network-instance, generation, peer and exact-offer correlation.
    pub fn accepts_event(&self, event: &CandidateOfferEvent) -> bool {
        self.id == event.id
            && self.peer == event.peer
            && self.offer == event.offer
            && Arc::ptr_eq(&self.budget, &event.permit.budget)
    }
    /// Consumes an exact terminal; a mismatch preserves both values for routing.
    pub fn complete(
        self,
        event: CandidateOfferEvent,
    ) -> Result<Result<(), CandidateOfferFailure>, Box<CandidateOfferMismatch>> {
        if !self.accepts_event(&event) {
            return Err(Box::new(CandidateOfferMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.failure.map_or(Ok(()), Err))
    }
}
impl fmt::Debug for CandidateOfferTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateOfferTicket")
            .field("peer", &self.peer)
            .field("offer", &self.offer)
            .finish_non_exhaustive()
    }
}

/// One exact terminal, retaining the shared outbound permit until consumed/dropped.
#[must_use]
pub struct CandidateOfferEvent {
    id: request_response::OutboundRequestId,
    peer: PeerId,
    offer: CandidateOffer,
    failure: Option<CandidateOfferFailure>,
    permit: PendingPermit,
}
impl fmt::Debug for CandidateOfferEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateOfferEvent")
            .field("peer", &self.peer)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}
/// A mismatch never consumes either routable value.
#[derive(Debug)]
#[must_use]
pub struct CandidateOfferMismatch {
    ticket: CandidateOfferTicket,
    event: CandidateOfferEvent,
}
impl CandidateOfferMismatch {
    /// Recovers both unchanged values.
    pub fn into_parts(self) -> (CandidateOfferTicket, CandidateOfferEvent) {
        (self.ticket, self.event)
    }
}
/// Authenticated delivery failure; no durability, validity or selection is inferred.
#[derive(Debug)]
pub enum CandidateOfferFailure {
    /// The physical exchange failed.
    Transport(request_response::OutboundFailure),
    /// The response came from a different peer or did not acknowledge these bytes.
    ReceiptMismatch,
}

impl StaticArtifactNetwork {
    /// Announces one bounded offer to a connected configured peer. No dial or relay.
    pub fn announce_candidate_offer(
        &mut self,
        peer: PeerId,
        offer: CandidateOffer,
    ) -> Result<CandidateOfferTicket, RequestStartError> {
        let connected = self.swarm.behaviour().candidate_offer.is_connected(&peer);
        let (peer_index, permit) = self.acquire_request_permit(peer, connected)?;
        let id = self.swarm.behaviour_mut().candidate_offer.send_request(
            &peer,
            OfferRequest {
                offer: offer.clone(),
                permit: None,
            },
        );
        let ticket = CandidateOfferTicket {
            id,
            peer,
            offer: offer.clone(),
            budget: Arc::clone(&self.pending_budget),
        };
        self.insert_pending(
            ExchangeRequestId::CandidateOffer(peer, id),
            PendingRequest::CandidateOffer(PendingOffer {
                peer_index,
                offer,
                permit,
            }),
        );
        Ok(ticket)
    }
    /// Receipts these exact bytes. The caller MUST persist its accepted offer first.
    /// The receipt attests neither candidate validity nor permanent retention.
    pub fn acknowledge_candidate_offer(
        &mut self,
        inbound: InboundCandidateOffer,
    ) -> Result<(), RespondError> {
        let digest = fingerprint(inbound.offer());
        self.swarm
            .behaviour_mut()
            .candidate_offer
            .send_response(inbound.peer, inbound.channel, digest)
            .map_err(|_| RespondError::ChannelClosed)
    }
    pub(super) fn handle_candidate_offer_event(
        &mut self,
        event: request_response::Event<OfferRequest, [u8; 32]>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    mut request,
                    channel,
                    ..
                } => {
                    if !self.is_configured_peer(&peer) || !request.permit.as_mut()?.bind_peer(peer)
                    {
                        return None;
                    }
                    let now = Instant::now();
                    // The map cannot exceed the bounded configured peer set. Offers
                    // have independent per-peer pacing; no global token can be stolen.
                    let next = self.candidate_offer_due.entry(peer).or_insert(now);
                    if now < *next {
                        return None;
                    }
                    *next = now + CANDIDATE_OFFER_INTERVAL;
                    Some(NetworkEvent::InboundCandidateOffer(InboundCandidateOffer {
                        peer,
                        request,
                        channel,
                    }))
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => self.finish_candidate_offer(request_id, peer, Some(response), None),
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => self.finish_candidate_offer(
                request_id,
                peer,
                None,
                Some(CandidateOfferFailure::Transport(error)),
            ),
            // Malformed/flooding requests do not create an unbounded application
            // diagnostic stream. Their stream fails and no success receipt is sent.
            request_response::Event::InboundFailure { .. }
            | request_response::Event::ResponseSent { .. } => None,
        }
    }
    fn finish_candidate_offer(
        &mut self,
        id: request_response::OutboundRequestId,
        actual: PeerId,
        receipt: Option<[u8; 32]>,
        mut failure: Option<CandidateOfferFailure>,
    ) -> Option<NetworkEvent> {
        let PendingRequest::CandidateOffer(pending) = self
            .pending
            .remove(&ExchangeRequestId::CandidateOffer(actual, id))?
        else {
            unreachable!("candidate offer request key")
        };
        let peer = self.pending_peer_id(pending.peer_index);
        if peer != actual || receipt.is_some_and(|digest| digest != fingerprint(&pending.offer)) {
            failure = Some(CandidateOfferFailure::ReceiptMismatch);
        }
        Some(NetworkEvent::OutboundCandidateOffer(CandidateOfferEvent {
            id,
            peer,
            offer: pending.offer,
            failure,
            permit: pending.permit,
        }))
    }
}

#[cfg(test)]
mod tests;
