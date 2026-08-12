//! Authenticated transport binding for one proof-chain-head announcement.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response;
use naome::chain_head_announcement::ProofChainHeadAnnouncement;
use naome_storage::{ProofChainJournal, ProofChainJournalError};

use super::codec::ProofChainHeadAnnouncementReceipt;
use super::{
    ExchangeRequestId, NetworkEvent, PeerId, PendingBudget, PendingPermit, PendingRequest,
    RequestStartError, StaticProofNetwork,
};

pub(super) struct PendingProofChainHeadAnnouncement {
    pub(super) peer_index: usize,
    pub(super) announcement: ProofChainHeadAnnouncement,
    pub(super) _permit: PendingPermit,
}

/// One opaque generation of an outbound proof-chain-head announcement.
///
/// Dropping the ticket does not cancel its physical libp2p request. The
/// transport retains the peer slot and global permit until the corresponding
/// receipt or failure becomes terminal.
#[must_use]
pub struct HeadAnnouncementTicket {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    announcement: ProofChainHeadAnnouncement,
    network_budget: Arc<PendingBudget>,
}

impl HeadAnnouncementTicket {
    /// Returns the authenticated peer expected for this announcement.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable announcement carried by this generation.
    pub const fn announcement(&self) -> ProofChainHeadAnnouncement {
        self.announcement
    }

    /// Returns whether `event` is the exact terminal for this ticket.
    pub fn accepts_event(&self, event: &OutboundProofChainHeadAnnouncementEvent) -> bool {
        self.request_id == event.request_id
            && self.peer_id == event.peer_id
            && self.announcement == event.announcement
            && Arc::ptr_eq(&self.network_budget, event.network_budget())
    }

    /// Consumes this ticket and its exact terminal event.
    pub fn complete(
        self,
        event: OutboundProofChainHeadAnnouncementEvent,
    ) -> Result<
        Result<
            AuthenticatedProofChainHeadAnnouncementReceipt,
            Box<OutboundProofChainHeadAnnouncementFailure>,
        >,
        Box<ProofChainHeadAnnouncementEventMismatch>,
    > {
        if !self.accepts_event(&event) {
            return Err(Box::new(ProofChainHeadAnnouncementEventMismatch {
                ticket: self,
                event,
            }));
        }
        Ok(event.into_result())
    }
}

impl fmt::Debug for HeadAnnouncementTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeadAnnouncementTicket")
            .field("peer_id", &self.peer_id)
            .field("announcement", &self.announcement)
            .finish_non_exhaustive()
    }
}

/// One ticket/event mismatch that preserves both values for routing.
#[must_use]
pub struct ProofChainHeadAnnouncementEventMismatch {
    ticket: HeadAnnouncementTicket,
    event: OutboundProofChainHeadAnnouncementEvent,
}

impl ProofChainHeadAnnouncementEventMismatch {
    /// Returns the unmatched ticket and terminal event.
    pub fn into_parts(
        self,
    ) -> (
        HeadAnnouncementTicket,
        OutboundProofChainHeadAnnouncementEvent,
    ) {
        (self.ticket, self.event)
    }
}

impl fmt::Debug for ProofChainHeadAnnouncementEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofChainHeadAnnouncementEventMismatch")
            .field("ticket", &self.ticket)
            .field("event", &self.event)
            .finish()
    }
}

impl fmt::Display for ProofChainHeadAnnouncementEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("proof-chain-head announcement terminal does not match its request ticket")
    }
}

impl Error for ProofChainHeadAnnouncementEventMismatch {}

/// One announcement received from an authenticated, statically authorized peer.
#[must_use]
pub struct InboundProofChainHeadAnnouncement {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    announcement: ProofChainHeadAnnouncement,
    channel: request_response::ResponseChannel<ProofChainHeadAnnouncementReceipt>,
}

impl InboundProofChainHeadAnnouncement {
    /// Returns the authenticated sender.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact untrusted chain-head observation.
    pub const fn announcement(&self) -> ProofChainHeadAnnouncement {
        self.announcement
    }
}

impl fmt::Debug for InboundProofChainHeadAnnouncement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundProofChainHeadAnnouncement")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("announcement", &self.announcement)
            .finish_non_exhaustive()
    }
}

/// One terminal announcement event awaiting its exact generation ticket.
#[must_use]
pub struct OutboundProofChainHeadAnnouncementEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    announcement: ProofChainHeadAnnouncement,
    outcome: OutboundProofChainHeadAnnouncementOutcome,
}

impl OutboundProofChainHeadAnnouncementEvent {
    /// Returns the expected authenticated peer.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable announcement that caused this terminal.
    pub const fn announcement(&self) -> ProofChainHeadAnnouncement {
        self.announcement
    }

    fn network_budget(&self) -> &Arc<PendingBudget> {
        match &self.outcome {
            OutboundProofChainHeadAnnouncementOutcome::Receipt { _permit } => &_permit.budget,
            OutboundProofChainHeadAnnouncementOutcome::Failure { network_budget, .. } => {
                network_budget
            }
        }
    }

    fn into_result(
        self,
    ) -> Result<
        AuthenticatedProofChainHeadAnnouncementReceipt,
        Box<OutboundProofChainHeadAnnouncementFailure>,
    > {
        match self.outcome {
            OutboundProofChainHeadAnnouncementOutcome::Receipt { .. } => {
                Ok(AuthenticatedProofChainHeadAnnouncementReceipt {
                    peer_id: self.peer_id,
                    announcement: self.announcement,
                })
            }
            OutboundProofChainHeadAnnouncementOutcome::Failure { error, .. } => Err(error),
        }
    }
}

impl fmt::Debug for OutboundProofChainHeadAnnouncementEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match &self.outcome {
            OutboundProofChainHeadAnnouncementOutcome::Receipt { .. } => "Receipt",
            OutboundProofChainHeadAnnouncementOutcome::Failure { .. } => "Failure",
        };
        formatter
            .debug_struct("OutboundProofChainHeadAnnouncementEvent")
            .field("peer_id", &self.peer_id)
            .field("announcement", &self.announcement)
            .field("outcome", &outcome)
            .finish_non_exhaustive()
    }
}

enum OutboundProofChainHeadAnnouncementOutcome {
    Receipt {
        _permit: PendingPermit,
    },
    Failure {
        error: Box<OutboundProofChainHeadAnnouncementFailure>,
        network_budget: Arc<PendingBudget>,
    },
}

/// One authenticated receipt for an exact proof-chain-head announcement.
///
/// This confirms only that the remote peer explicitly acknowledged the exact
/// message. It establishes no validation, selection, availability, or
/// consensus claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct AuthenticatedProofChainHeadAnnouncementReceipt {
    peer_id: PeerId,
    announcement: ProofChainHeadAnnouncement,
}

impl AuthenticatedProofChainHeadAnnouncementReceipt {
    /// Returns the authenticated peer that receipted the announcement.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact receipted announcement.
    pub const fn announcement(&self) -> ProofChainHeadAnnouncement {
        self.announcement
    }
}

/// A typed terminal failure for one outbound head announcement.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundProofChainHeadAnnouncementFailure {
    /// The request-response stream failed before an exact receipt arrived.
    Transport(request_response::OutboundFailure),
    /// A terminal event came from a peer other than the retained expectation.
    PeerMismatch { expected: PeerId, actual: PeerId },
}

impl fmt::Display for OutboundProofChainHeadAnnouncementFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => {
                write!(formatter, "proof-chain-head announcement failed: {source}")
            }
            Self::PeerMismatch { expected, actual } => write!(
                formatter,
                "proof-chain-head announcement terminal came from {actual}, expected {expected}"
            ),
        }
    }
}

impl Error for OutboundProofChainHeadAnnouncementFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::PeerMismatch { .. } => None,
        }
    }
}

/// Failure to snapshot and start one outbound head announcement.
#[derive(Debug)]
#[non_exhaustive]
pub enum HeadAnnouncementStartError {
    /// The local journal could not supply a healthy selected head.
    Journal(ProofChainJournalError),
    /// The authenticated outbound request could not start.
    RequestStart(RequestStartError),
}

impl fmt::Display for HeadAnnouncementStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(source) => write!(formatter, "cannot read announced head: {source}"),
            Self::RequestStart(source) => write!(formatter, "cannot start announcement: {source}"),
        }
    }
}

impl Error for HeadAnnouncementStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(source) => Some(source),
            Self::RequestStart(source) => Some(source),
        }
    }
}

impl StaticProofNetwork {
    /// Snapshots and announces the healthy local journal head to one static peer.
    ///
    /// The returned ticket is the only public path to the terminal receipt.
    /// This method never opens a request-driven connection or mutates the journal.
    pub fn announce_chain_head_from_journal(
        &mut self,
        peer_id: PeerId,
        journal: &ProofChainJournal,
    ) -> Result<HeadAnnouncementTicket, HeadAnnouncementStartError> {
        let head_block_id = journal
            .head_block_id()
            .map_err(HeadAnnouncementStartError::Journal)?;
        let announcement = ProofChainHeadAnnouncement::new(journal.chain_id(), head_block_id);
        let transport_connected = self
            .swarm
            .behaviour()
            .head_announcement
            .is_connected(&peer_id);
        let (peer_index, permit) = self
            .acquire_request_permit(peer_id, transport_connected)
            .map_err(HeadAnnouncementStartError::RequestStart)?;
        let request_id = self
            .swarm
            .behaviour_mut()
            .head_announcement
            .send_request(&peer_id, announcement);
        let ticket = HeadAnnouncementTicket {
            request_id,
            peer_id,
            announcement,
            network_budget: Arc::clone(&self.pending_budget),
        };
        self.insert_pending(
            ExchangeRequestId::Announcement(request_id),
            PendingRequest::Announcement(PendingProofChainHeadAnnouncement {
                peer_index,
                announcement,
                _permit: permit,
            }),
        );
        Ok(ticket)
    }

    pub(super) fn handle_head_announcement_event(
        &mut self,
        event: request_response::Event<
            ProofChainHeadAnnouncement,
            ProofChainHeadAnnouncementReceipt,
        >,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundChainHeadAnnouncement(
                    InboundProofChainHeadAnnouncement {
                        peer_id: peer,
                        request_id,
                        announcement: request,
                        channel,
                    },
                )),
                request_response::Message::Response {
                    request_id,
                    response: _,
                } => {
                    let pending = self.remove_pending_announcement(request_id)?;
                    let expected = self.pending_peer_id(pending.peer_index);
                    if expected != peer {
                        return Some(Self::finish_announcement_failure(
                            request_id,
                            expected,
                            pending,
                            OutboundProofChainHeadAnnouncementFailure::PeerMismatch {
                                expected,
                                actual: peer,
                            },
                        ));
                    }
                    Some(Self::finish_announcement_receipt(
                        request_id, expected, pending,
                    ))
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let pending = self.remove_pending_announcement(request_id)?;
                let expected = self.pending_peer_id(pending.peer_index);
                let failure = if expected == peer {
                    OutboundProofChainHeadAnnouncementFailure::Transport(error)
                } else {
                    OutboundProofChainHeadAnnouncementFailure::PeerMismatch {
                        expected,
                        actual: peer,
                    }
                };
                Some(Self::finish_announcement_failure(
                    request_id, expected, pending, failure,
                ))
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => Some(NetworkEvent::InboundChainHeadAnnouncementFailure {
                peer_id: peer,
                request_id,
                error,
            }),
            request_response::Event::ResponseSent { .. } => None,
        }
    }

    fn finish_announcement_receipt(
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
        pending: PendingProofChainHeadAnnouncement,
    ) -> NetworkEvent {
        let PendingProofChainHeadAnnouncement {
            peer_index: _,
            announcement,
            _permit,
        } = pending;
        NetworkEvent::OutboundChainHeadAnnouncement(OutboundProofChainHeadAnnouncementEvent {
            request_id,
            peer_id,
            announcement,
            outcome: OutboundProofChainHeadAnnouncementOutcome::Receipt { _permit },
        })
    }

    fn finish_announcement_failure(
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
        pending: PendingProofChainHeadAnnouncement,
        failure: OutboundProofChainHeadAnnouncementFailure,
    ) -> NetworkEvent {
        let network_budget = Arc::clone(&pending._permit.budget);
        NetworkEvent::OutboundChainHeadAnnouncement(OutboundProofChainHeadAnnouncementEvent {
            request_id,
            peer_id,
            announcement: pending.announcement,
            outcome: OutboundProofChainHeadAnnouncementOutcome::Failure {
                error: Box::new(failure),
                network_budget,
            },
        })
    }

    fn remove_pending_announcement(
        &mut self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<PendingProofChainHeadAnnouncement> {
        let pending = self
            .pending
            .remove(&ExchangeRequestId::Announcement(request_id))?;
        let PendingRequest::Announcement(pending) = pending else {
            unreachable!("an announcement request key always stores an announcement")
        };
        Some(pending)
    }

    /// Explicitly receipts one authenticated inbound head announcement.
    pub fn acknowledge_chain_head_announcement(
        &mut self,
        inbound: InboundProofChainHeadAnnouncement,
    ) -> Result<(), HeadAnnouncementAcknowledgeError> {
        self.swarm
            .behaviour_mut()
            .head_announcement
            .send_response(inbound.channel, ProofChainHeadAnnouncementReceipt)
            .map_err(|_| HeadAnnouncementAcknowledgeError::ChannelClosed)
    }
}

/// Failure to send an explicit head-announcement receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadAnnouncementAcknowledgeError {
    /// The response channel closed before the receipt was accepted.
    ChannelClosed,
}

impl fmt::Display for HeadAnnouncementAcknowledgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("proof-chain-head announcement response channel is closed")
    }
}

impl Error for HeadAnnouncementAcknowledgeError {}

#[cfg(test)]
mod tests;
