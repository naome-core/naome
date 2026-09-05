//! Bounded caller-selected broadcast of one immutable artifact-chain head.

use std::error::Error;
use std::fmt;

use naome_protocol::chain_head_announcement::ArtifactChainHeadAnnouncement;
use naome_storage::{ArtifactChainJournal, ArtifactChainJournalError};

use super::{
    HeadAnnouncementTicket, MAX_PENDING_REQUESTS, MAX_STATIC_PEERS, NetworkEvent,
    OutboundArtifactChainHeadAnnouncementFailure, PeerId, RequestStartError, StaticArtifactNetwork,
};

/// Maximum number of explicitly selected peers in one head broadcast.
pub const MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS: usize = MAX_STATIC_PEERS;

/// One bounded artifact-chain-head broadcast awaiting peer terminals.
///
/// Every peer receives the same journal snapshot. Receipts and failures remain
/// source-bound observations; this workflow computes no aggregate acceptance,
/// freshness, quorum, selection, or consensus result.
#[derive(Debug)]
#[must_use]
pub struct ArtifactChainHeadBroadcast {
    announcement: ArtifactChainHeadAnnouncement,
    peers: Vec<BroadcastPeerState>,
}

#[derive(Debug)]
enum BroadcastPeerState {
    Pending(HeadAnnouncementTicket),
    Complete(ArtifactChainHeadBroadcastPeerResult),
}

impl StaticArtifactNetwork {
    /// Starts one all-or-none broadcast of a healthy local journal-head snapshot.
    ///
    /// `peer_ids` must contain one to eight unique, statically authorized and
    /// connected peers. Every structural, journal, peer, and capacity check
    /// completes before the first physical request is queued.
    pub fn start_chain_head_broadcast_from_journal(
        &mut self,
        peer_ids: &[PeerId],
        journal: &ArtifactChainJournal,
    ) -> Result<ArtifactChainHeadBroadcast, ArtifactChainHeadBroadcastStartError> {
        validate_peer_set(peer_ids)?;
        let head_block_id = journal
            .head_block_id()
            .map_err(ArtifactChainHeadBroadcastStartError::Journal)?;
        let announcement = ArtifactChainHeadAnnouncement::new(journal.chain_id(), head_block_id);

        let peers = self
            .start_head_announcement_batch(peer_ids, announcement)
            .map_err(|error| match error {
                crate::transport::batch::BatchStartError::RequestStart(source) => {
                    ArtifactChainHeadBroadcastStartError::RequestStart(source)
                }
                crate::transport::batch::BatchStartError::InsufficientCapacity { available } => {
                    ArtifactChainHeadBroadcastStartError::InsufficientCapacity {
                        requested: peer_ids.len(),
                        available,
                        maximum: MAX_PENDING_REQUESTS,
                    }
                }
            })?
            .into_iter()
            .map(BroadcastPeerState::Pending)
            .collect();

        Ok(ArtifactChainHeadBroadcast {
            announcement,
            peers,
        })
    }
}

impl ArtifactChainHeadBroadcast {
    /// Returns the single immutable announcement sent to every selected peer.
    pub const fn announcement(&self) -> ArtifactChainHeadAnnouncement {
        self.announcement
    }

    /// Returns the number of caller-selected peers in this broadcast.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns the number of peers whose physical terminal is still awaited.
    pub fn pending_peer_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|peer| matches!(peer, BroadcastPeerState::Pending(_)))
            .count()
    }

    /// Returns whether `event` is one exact terminal awaited by this broadcast.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        let NetworkEvent::OutboundChainHeadAnnouncement(event) = event else {
            return false;
        };
        self.peers.iter().any(|peer| {
            matches!(peer, BroadcastPeerState::Pending(ticket) if ticket.accepts_event(event))
        })
    }

    /// Cancels the logical broadcast and releases its completed outcomes.
    ///
    /// Pending tickets retain their existing non-cancelling transport
    /// semantics: physical terminals continue to drain their peer slots and
    /// shared permits through [`StaticArtifactNetwork::next_event`].
    pub fn cancel(self) {}

    /// Advances this broadcast with one exact source-bound peer terminal.
    ///
    /// Mismatched events preserve both the complete broadcast and event for
    /// caller routing. Matching failures are retained as per-peer outcomes and
    /// never cancel, retry, or reinterpret another peer.
    pub fn on_event(
        mut self,
        event: NetworkEvent,
    ) -> Result<ArtifactChainHeadBroadcastProgress, Box<ArtifactChainHeadBroadcastEventMismatch>>
    {
        let NetworkEvent::OutboundChainHeadAnnouncement(terminal) = event else {
            return Err(Box::new(ArtifactChainHeadBroadcastEventMismatch {
                broadcast: self,
                event,
            }));
        };
        let Some(index) = self.peers.iter().position(|peer| {
            matches!(peer, BroadcastPeerState::Pending(ticket) if ticket.accepts_event(&terminal))
        }) else {
            return Err(Box::new(ArtifactChainHeadBroadcastEventMismatch {
                broadcast: self,
                event: NetworkEvent::OutboundChainHeadAnnouncement(terminal),
            }));
        };

        let peer_id = terminal.peer_id();
        let state = std::mem::replace(
            &mut self.peers[index],
            BroadcastPeerState::Complete(ArtifactChainHeadBroadcastPeerResult {
                peer_id,
                failure: None,
            }),
        );
        let BroadcastPeerState::Pending(ticket) = state else {
            unreachable!("an accepted broadcast terminal belongs to a pending peer")
        };
        match ticket
            .complete(terminal)
            .expect("an accepted broadcast terminal matches its ticket")
        {
            Ok(receipt) => {
                debug_assert_eq!(receipt.peer_id(), peer_id);
                debug_assert_eq!(receipt.announcement(), self.announcement);
            }
            Err(failure) => {
                self.peers[index] =
                    BroadcastPeerState::Complete(ArtifactChainHeadBroadcastPeerResult {
                        peer_id,
                        failure: Some(failure),
                    });
            }
        }

        if self.pending_peer_count() != 0 {
            return Ok(ArtifactChainHeadBroadcastProgress::AwaitingReceipts(self));
        }

        let peer_results = self
            .peers
            .into_iter()
            .map(|peer| match peer {
                BroadcastPeerState::Complete(result) => result,
                BroadcastPeerState::Pending(_) => {
                    unreachable!("a completed broadcast has no pending peer")
                }
            })
            .collect();
        Ok(ArtifactChainHeadBroadcastProgress::Complete(
            CompletedArtifactChainHeadBroadcast {
                announcement: self.announcement,
                peer_results,
            },
        ))
    }
}

/// Progress after one exact broadcast terminal.
#[derive(Debug)]
#[must_use]
pub enum ArtifactChainHeadBroadcastProgress {
    /// At least one selected peer terminal remains pending.
    AwaitingReceipts(ArtifactChainHeadBroadcast),
    /// Every selected peer produced exactly one source-bound outcome.
    Complete(CompletedArtifactChainHeadBroadcast),
}

/// One completed broadcast with deterministic caller-ordered peer outcomes.
#[derive(Debug)]
#[must_use]
pub struct CompletedArtifactChainHeadBroadcast {
    announcement: ArtifactChainHeadAnnouncement,
    peer_results: Vec<ArtifactChainHeadBroadcastPeerResult>,
}

impl CompletedArtifactChainHeadBroadcast {
    /// Returns the single immutable announcement sent to every peer.
    pub const fn announcement(&self) -> ArtifactChainHeadAnnouncement {
        self.announcement
    }

    /// Returns source-bound outcomes in original caller order.
    pub fn peer_results(&self) -> &[ArtifactChainHeadBroadcastPeerResult] {
        &self.peer_results
    }

    /// Consumes this report into its one shared announcement and ordered rows.
    pub fn into_parts(
        self,
    ) -> (
        ArtifactChainHeadAnnouncement,
        Vec<ArtifactChainHeadBroadcastPeerResult>,
    ) {
        (self.announcement, self.peer_results)
    }
}

/// One caller-ordered source-bound peer outcome.
#[derive(Debug)]
#[must_use]
pub struct ArtifactChainHeadBroadcastPeerResult {
    peer_id: PeerId,
    failure: Option<Box<OutboundArtifactChainHeadAnnouncementFailure>>,
}

impl ArtifactChainHeadBroadcastPeerResult {
    /// Returns the authenticated peer for this outcome.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Borrows the exact receipt-or-failure outcome.
    pub fn result(&self) -> Result<(), &OutboundArtifactChainHeadAnnouncementFailure> {
        match &self.failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    /// Consumes the exact receipt-or-failure outcome.
    pub fn into_result(self) -> Result<(), Box<OutboundArtifactChainHeadAnnouncementFailure>> {
        match self.failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

/// One mismatch preserving the complete broadcast and unrouted event.
#[derive(Debug)]
#[must_use]
pub struct ArtifactChainHeadBroadcastEventMismatch {
    broadcast: ArtifactChainHeadBroadcast,
    event: NetworkEvent,
}

impl ArtifactChainHeadBroadcastEventMismatch {
    /// Returns both values unchanged for caller routing or recovery.
    pub fn into_parts(self) -> (ArtifactChainHeadBroadcast, NetworkEvent) {
        (self.broadcast, self.event)
    }
}

impl fmt::Display for ArtifactChainHeadBroadcastEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("network event does not belong to this artifact-chain-head broadcast")
    }
}

impl Error for ArtifactChainHeadBroadcastEventMismatch {}

/// Failure to atomically start one bounded artifact-chain-head broadcast.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactChainHeadBroadcastStartError {
    /// No destination peer was selected.
    EmptyPeerSet,
    /// The selected peer count exceeds the fixed static-peer bound.
    TooManyPeers { actual: usize, maximum: usize },
    /// The same destination peer appears more than once.
    DuplicatePeer(PeerId),
    /// The local journal could not supply a healthy selected-head snapshot.
    Journal(ArtifactChainJournalError),
    /// One destination failed caller-ordered authorization/session preflight.
    RequestStart(RequestStartError),
    /// The shared request budget cannot reserve the whole batch atomically.
    InsufficientCapacity {
        requested: usize,
        available: usize,
        maximum: usize,
    },
}

impl fmt::Display for ArtifactChainHeadBroadcastStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPeerSet => formatter.write_str("artifact-chain-head broadcast has no peers"),
            Self::TooManyPeers { actual, maximum } => write!(
                formatter,
                "artifact-chain-head broadcast peer count {actual} exceeds maximum {maximum}"
            ),
            Self::DuplicatePeer(peer_id) => write!(
                formatter,
                "artifact-chain-head broadcast selects peer {peer_id} more than once"
            ),
            Self::Journal(source) => write!(formatter, "cannot read broadcast head: {source}"),
            Self::RequestStart(source) => {
                write!(
                    formatter,
                    "cannot start artifact-chain-head broadcast: {source}"
                )
            }
            Self::InsufficientCapacity {
                requested,
                available,
                maximum,
            } => write!(
                formatter,
                "artifact-chain-head broadcast needs {requested} request slots, only {available} of {maximum} are available"
            ),
        }
    }
}

impl Error for ArtifactChainHeadBroadcastStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(source) => Some(source),
            Self::RequestStart(source) => Some(source),
            _ => None,
        }
    }
}

fn validate_peer_set(peer_ids: &[PeerId]) -> Result<(), ArtifactChainHeadBroadcastStartError> {
    crate::peer_selection::validate_peer_set(peer_ids, MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS)
        .map_err(|error| match error {
            crate::peer_selection::PeerSetError::Empty => {
                ArtifactChainHeadBroadcastStartError::EmptyPeerSet
            }
            crate::peer_selection::PeerSetError::TooMany { actual, maximum } => {
                ArtifactChainHeadBroadcastStartError::TooManyPeers { actual, maximum }
            }
            crate::peer_selection::PeerSetError::Duplicate(peer_id) => {
                ArtifactChainHeadBroadcastStartError::DuplicatePeer(peer_id)
            }
        })
}

#[cfg(test)]
mod tests;
