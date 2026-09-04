//! Authenticated transport binding for one artifact-chain-head announcement.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response;
use naome_protocol::chain_head_announcement::ArtifactChainHeadAnnouncement;
use naome_storage::{ArtifactChainJournal, ArtifactChainJournalError};

use super::codec::ArtifactChainHeadAnnouncementReceipt;
use super::{
    ExchangeRequestId, NetworkEvent, PeerId, PendingBudget, PendingPermit, PendingRequest,
    RequestStartError, StaticArtifactNetwork,
};

pub(super) struct PendingArtifactChainHeadAnnouncement {
    pub(super) peer_index: usize,
    pub(super) announcement: ArtifactChainHeadAnnouncement,
    pub(super) _permit: PendingPermit,
}

/// One opaque generation of an outbound artifact-chain-head announcement.
///
/// Dropping the ticket does not cancel its physical libp2p request. The
/// transport retains the peer slot and global permit until the corresponding
/// receipt or failure becomes terminal.
#[must_use]
pub struct HeadAnnouncementTicket {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    announcement: ArtifactChainHeadAnnouncement,
    network_budget: Arc<PendingBudget>,
}

impl HeadAnnouncementTicket {
    /// Returns the authenticated peer expected for this announcement.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable announcement carried by this generation.
    pub const fn announcement(&self) -> ArtifactChainHeadAnnouncement {
        self.announcement
    }

    /// Returns whether `event` is the exact terminal for this ticket.
    pub fn accepts_event(&self, event: &OutboundArtifactChainHeadAnnouncementEvent) -> bool {
        self.request_id == event.request_id
            && self.peer_id == event.peer_id
            && self.announcement == event.announcement
            && Arc::ptr_eq(&self.network_budget, event.network_budget())
    }

    /// Consumes this ticket and its exact terminal event.
    pub fn complete(
        self,
        event: OutboundArtifactChainHeadAnnouncementEvent,
    ) -> Result<
        Result<
            AuthenticatedArtifactChainHeadAnnouncementReceipt,
            Box<OutboundArtifactChainHeadAnnouncementFailure>,
        >,
        Box<ArtifactChainHeadAnnouncementEventMismatch>,
    > {
        if !self.accepts_event(&event) {
            return Err(Box::new(ArtifactChainHeadAnnouncementEventMismatch {
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
pub struct ArtifactChainHeadAnnouncementEventMismatch {
    ticket: HeadAnnouncementTicket,
    event: OutboundArtifactChainHeadAnnouncementEvent,
}

impl ArtifactChainHeadAnnouncementEventMismatch {
    /// Returns the unmatched ticket and terminal event.
    pub fn into_parts(
        self,
    ) -> (
        HeadAnnouncementTicket,
        OutboundArtifactChainHeadAnnouncementEvent,
    ) {
        (self.ticket, self.event)
    }
}

impl fmt::Debug for ArtifactChainHeadAnnouncementEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactChainHeadAnnouncementEventMismatch")
            .field("ticket", &self.ticket)
            .field("event", &self.event)
            .finish()
    }
}

impl fmt::Display for ArtifactChainHeadAnnouncementEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "artifact-chain-head announcement terminal does not match its request ticket",
        )
    }
}

impl Error for ArtifactChainHeadAnnouncementEventMismatch {}

/// One announcement received from an authenticated, statically authorized peer.
#[must_use]
pub struct InboundArtifactChainHeadAnnouncement {
    peer_id: PeerId,
    request_id: request_response::InboundRequestId,
    announcement: ArtifactChainHeadAnnouncement,
    channel: request_response::ResponseChannel<ArtifactChainHeadAnnouncementReceipt>,
}

impl InboundArtifactChainHeadAnnouncement {
    /// Returns the authenticated sender.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact untrusted chain-head observation.
    pub const fn announcement(&self) -> ArtifactChainHeadAnnouncement {
        self.announcement
    }
}

impl fmt::Debug for InboundArtifactChainHeadAnnouncement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundArtifactChainHeadAnnouncement")
            .field("peer_id", &self.peer_id)
            .field("request_id", &self.request_id)
            .field("announcement", &self.announcement)
            .finish_non_exhaustive()
    }
}

/// One terminal announcement event awaiting its exact generation ticket.
#[must_use]
pub struct OutboundArtifactChainHeadAnnouncementEvent {
    request_id: request_response::OutboundRequestId,
    peer_id: PeerId,
    announcement: ArtifactChainHeadAnnouncement,
    outcome: OutboundArtifactChainHeadAnnouncementOutcome,
}

impl OutboundArtifactChainHeadAnnouncementEvent {
    /// Returns the expected authenticated peer.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the immutable announcement that caused this terminal.
    pub const fn announcement(&self) -> ArtifactChainHeadAnnouncement {
        self.announcement
    }

    fn network_budget(&self) -> &Arc<PendingBudget> {
        match &self.outcome {
            OutboundArtifactChainHeadAnnouncementOutcome::Receipt { _permit } => &_permit.budget,
            OutboundArtifactChainHeadAnnouncementOutcome::Failure { network_budget, .. } => {
                network_budget
            }
        }
    }

    fn into_result(
        self,
    ) -> Result<
        AuthenticatedArtifactChainHeadAnnouncementReceipt,
        Box<OutboundArtifactChainHeadAnnouncementFailure>,
    > {
        match self.outcome {
            OutboundArtifactChainHeadAnnouncementOutcome::Receipt { .. } => {
                Ok(AuthenticatedArtifactChainHeadAnnouncementReceipt {
                    peer_id: self.peer_id,
                    announcement: self.announcement,
                })
            }
            OutboundArtifactChainHeadAnnouncementOutcome::Failure { error, .. } => Err(error),
        }
    }
}

impl fmt::Debug for OutboundArtifactChainHeadAnnouncementEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match &self.outcome {
            OutboundArtifactChainHeadAnnouncementOutcome::Receipt { .. } => "Receipt",
            OutboundArtifactChainHeadAnnouncementOutcome::Failure { .. } => "Failure",
        };
        formatter
            .debug_struct("OutboundArtifactChainHeadAnnouncementEvent")
            .field("peer_id", &self.peer_id)
            .field("announcement", &self.announcement)
            .field("outcome", &outcome)
            .finish_non_exhaustive()
    }
}

enum OutboundArtifactChainHeadAnnouncementOutcome {
    Receipt {
        _permit: PendingPermit,
    },
    Failure {
        error: Box<OutboundArtifactChainHeadAnnouncementFailure>,
        network_budget: Arc<PendingBudget>,
    },
}

/// One authenticated receipt for an exact artifact-chain-head announcement.
///
/// This confirms only that the remote peer explicitly acknowledged the exact
/// message. It establishes no validation, selection, availability, or
/// consensus claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct AuthenticatedArtifactChainHeadAnnouncementReceipt {
    peer_id: PeerId,
    announcement: ArtifactChainHeadAnnouncement,
}

impl AuthenticatedArtifactChainHeadAnnouncementReceipt {
    /// Returns the authenticated peer that receipted the announcement.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the exact receipted announcement.
    pub const fn announcement(&self) -> ArtifactChainHeadAnnouncement {
        self.announcement
    }
}

/// A typed terminal failure for one outbound head announcement.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutboundArtifactChainHeadAnnouncementFailure {
    /// The request-response stream failed before an exact receipt arrived.
    Transport(request_response::OutboundFailure),
    /// A terminal event came from a peer other than the retained expectation.
    PeerMismatch { expected: PeerId, actual: PeerId },
}

impl fmt::Display for OutboundArtifactChainHeadAnnouncementFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => {
                write!(
                    formatter,
                    "artifact-chain-head announcement failed: {source}"
                )
            }
            Self::PeerMismatch { expected, actual } => write!(
                formatter,
                "artifact-chain-head announcement terminal came from {actual}, expected {expected}"
            ),
        }
    }
}

impl Error for OutboundArtifactChainHeadAnnouncementFailure {
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
    Journal(ArtifactChainJournalError),
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

impl StaticArtifactNetwork {
    /// Snapshots and announces the healthy local journal head to one static peer.
    ///
    /// The returned ticket is the only public path to the terminal receipt.
    /// This method never opens a request-driven connection or mutates the journal.
    pub fn announce_chain_head_from_journal(
        &mut self,
        peer_id: PeerId,
        journal: &ArtifactChainJournal,
    ) -> Result<HeadAnnouncementTicket, HeadAnnouncementStartError> {
        let head_block_id = journal
            .head_block_id()
            .map_err(HeadAnnouncementStartError::Journal)?;
        let announcement = ArtifactChainHeadAnnouncement::new(journal.chain_id(), head_block_id);
        let transport_connected = self
            .swarm
            .behaviour()
            .head_announcement
            .is_connected(&peer_id);
        let (peer_index, permit) = self
            .acquire_request_permit(peer_id, transport_connected)
            .map_err(HeadAnnouncementStartError::RequestStart)?;
        Ok(self.enqueue_head_announcement(peer_index, peer_id, announcement, permit))
    }

    pub(super) fn enqueue_head_announcement(
        &mut self,
        peer_index: usize,
        peer_id: PeerId,
        announcement: ArtifactChainHeadAnnouncement,
        permit: PendingPermit,
    ) -> HeadAnnouncementTicket {
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
            PendingRequest::Announcement(PendingArtifactChainHeadAnnouncement {
                peer_index,
                announcement,
                _permit: permit,
            }),
        );
        ticket
    }

    pub(super) fn handle_head_announcement_event(
        &mut self,
        event: request_response::Event<
            ArtifactChainHeadAnnouncement,
            ArtifactChainHeadAnnouncementReceipt,
        >,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => Some(NetworkEvent::InboundChainHeadAnnouncement(
                    InboundArtifactChainHeadAnnouncement {
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
                            OutboundArtifactChainHeadAnnouncementFailure::PeerMismatch {
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
                    OutboundArtifactChainHeadAnnouncementFailure::Transport(error)
                } else {
                    OutboundArtifactChainHeadAnnouncementFailure::PeerMismatch {
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
        pending: PendingArtifactChainHeadAnnouncement,
    ) -> NetworkEvent {
        let PendingArtifactChainHeadAnnouncement {
            peer_index: _,
            announcement,
            _permit,
        } = pending;
        NetworkEvent::OutboundChainHeadAnnouncement(OutboundArtifactChainHeadAnnouncementEvent {
            request_id,
            peer_id,
            announcement,
            outcome: OutboundArtifactChainHeadAnnouncementOutcome::Receipt { _permit },
        })
    }

    fn finish_announcement_failure(
        request_id: request_response::OutboundRequestId,
        peer_id: PeerId,
        pending: PendingArtifactChainHeadAnnouncement,
        failure: OutboundArtifactChainHeadAnnouncementFailure,
    ) -> NetworkEvent {
        let network_budget = Arc::clone(&pending._permit.budget);
        NetworkEvent::OutboundChainHeadAnnouncement(OutboundArtifactChainHeadAnnouncementEvent {
            request_id,
            peer_id,
            announcement: pending.announcement,
            outcome: OutboundArtifactChainHeadAnnouncementOutcome::Failure {
                error: Box::new(failure),
                network_budget,
            },
        })
    }

    fn remove_pending_announcement(
        &mut self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<PendingArtifactChainHeadAnnouncement> {
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
        inbound: InboundArtifactChainHeadAnnouncement,
    ) -> Result<(), HeadAnnouncementAcknowledgeError> {
        self.swarm
            .behaviour_mut()
            .head_announcement
            .send_response(inbound.channel, ArtifactChainHeadAnnouncementReceipt)
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
        formatter.write_str("artifact-chain-head announcement response channel is closed")
    }
}

impl Error for HeadAnnouncementAcknowledgeError {}

#[cfg(test)]
mod tests;
