//! Bounded caller-selected broadcast of one immutable proof-chain head.

use std::error::Error;
use std::fmt;

use naome::chain_head_announcement::ProofChainHeadAnnouncement;
use naome_storage::{ProofChainJournal, ProofChainJournalError};

use super::{
    HeadAnnouncementTicket, MAX_PENDING_REQUESTS, MAX_STATIC_PEERS, NetworkEvent,
    OutboundProofChainHeadAnnouncementFailure, PeerId, PendingBudget, RequestStartError,
    StaticProofNetwork,
};

/// Maximum number of explicitly selected peers in one head broadcast.
pub const MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS: usize = MAX_STATIC_PEERS;

/// One bounded proof-chain-head broadcast awaiting peer terminals.
///
/// Every peer receives the same journal snapshot. Receipts and failures remain
/// source-bound observations; this workflow computes no aggregate acceptance,
/// freshness, quorum, selection, or consensus result.
#[derive(Debug)]
#[must_use]
pub struct ProofChainHeadBroadcast {
    announcement: ProofChainHeadAnnouncement,
    peers: Vec<BroadcastPeerState>,
}

#[derive(Debug)]
enum BroadcastPeerState {
    Pending(HeadAnnouncementTicket),
    Complete(ProofChainHeadBroadcastPeerResult),
}

impl StaticProofNetwork {
    /// Starts one all-or-none broadcast of a healthy local journal-head snapshot.
    ///
    /// `peer_ids` must contain one to eight unique, statically authorized and
    /// connected peers. Every structural, journal, peer, and capacity check
    /// completes before the first physical request is queued.
    pub fn start_chain_head_broadcast_from_journal(
        &mut self,
        peer_ids: &[PeerId],
        journal: &ProofChainJournal,
    ) -> Result<ProofChainHeadBroadcast, ProofChainHeadBroadcastStartError> {
        validate_peer_set(peer_ids)?;
        let head_block_id = journal
            .head_block_id()
            .map_err(ProofChainHeadBroadcastStartError::Journal)?;
        let announcement = ProofChainHeadAnnouncement::new(journal.chain_id(), head_block_id);

        let mut peer_indices = [0; MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS];
        for (&peer_id, peer_index) in peer_ids.iter().zip(&mut peer_indices) {
            let transport_connected = self
                .swarm
                .behaviour()
                .head_announcement
                .is_connected(&peer_id);
            *peer_index = self
                .preflight_request(peer_id, transport_connected)
                .map_err(ProofChainHeadBroadcastStartError::RequestStart)?;
        }

        let permits = PendingBudget::try_acquire_many(&self.pending_budget, peer_ids.len())
            .map_err(
                |available| ProofChainHeadBroadcastStartError::InsufficientCapacity {
                    requested: peer_ids.len(),
                    available,
                    maximum: MAX_PENDING_REQUESTS,
                },
            )?;
        let mut peers = Vec::with_capacity(peer_ids.len());
        for ((&peer_index, &peer_id), permit) in peer_indices[..peer_ids.len()]
            .iter()
            .zip(peer_ids)
            .zip(permits.into_iter().flatten())
        {
            peers.push(BroadcastPeerState::Pending(self.enqueue_head_announcement(
                peer_index,
                peer_id,
                announcement,
                permit,
            )));
        }

        Ok(ProofChainHeadBroadcast {
            announcement,
            peers,
        })
    }
}

impl ProofChainHeadBroadcast {
    /// Returns the single immutable announcement sent to every selected peer.
    pub const fn announcement(&self) -> ProofChainHeadAnnouncement {
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
    /// shared permits through [`StaticProofNetwork::next_event`].
    pub fn cancel(self) {}

    /// Advances this broadcast with one exact source-bound peer terminal.
    ///
    /// Mismatched events preserve both the complete broadcast and event for
    /// caller routing. Matching failures are retained as per-peer outcomes and
    /// never cancel, retry, or reinterpret another peer.
    pub fn on_event(
        mut self,
        event: NetworkEvent,
    ) -> Result<ProofChainHeadBroadcastProgress, Box<ProofChainHeadBroadcastEventMismatch>> {
        let NetworkEvent::OutboundChainHeadAnnouncement(terminal) = event else {
            return Err(Box::new(ProofChainHeadBroadcastEventMismatch {
                broadcast: self,
                event,
            }));
        };
        let Some(index) = self.peers.iter().position(|peer| {
            matches!(peer, BroadcastPeerState::Pending(ticket) if ticket.accepts_event(&terminal))
        }) else {
            return Err(Box::new(ProofChainHeadBroadcastEventMismatch {
                broadcast: self,
                event: NetworkEvent::OutboundChainHeadAnnouncement(terminal),
            }));
        };

        let peer_id = terminal.peer_id();
        let state = std::mem::replace(
            &mut self.peers[index],
            BroadcastPeerState::Complete(ProofChainHeadBroadcastPeerResult {
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
                    BroadcastPeerState::Complete(ProofChainHeadBroadcastPeerResult {
                        peer_id,
                        failure: Some(failure),
                    });
            }
        }

        if self.pending_peer_count() != 0 {
            return Ok(ProofChainHeadBroadcastProgress::AwaitingReceipts(self));
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
        Ok(ProofChainHeadBroadcastProgress::Complete(
            CompletedProofChainHeadBroadcast {
                announcement: self.announcement,
                peer_results,
            },
        ))
    }
}

/// Progress after one exact broadcast terminal.
#[derive(Debug)]
#[must_use]
pub enum ProofChainHeadBroadcastProgress {
    /// At least one selected peer terminal remains pending.
    AwaitingReceipts(ProofChainHeadBroadcast),
    /// Every selected peer produced exactly one source-bound outcome.
    Complete(CompletedProofChainHeadBroadcast),
}

/// One completed broadcast with deterministic caller-ordered peer outcomes.
#[derive(Debug)]
#[must_use]
pub struct CompletedProofChainHeadBroadcast {
    announcement: ProofChainHeadAnnouncement,
    peer_results: Vec<ProofChainHeadBroadcastPeerResult>,
}

impl CompletedProofChainHeadBroadcast {
    /// Returns the single immutable announcement sent to every peer.
    pub const fn announcement(&self) -> ProofChainHeadAnnouncement {
        self.announcement
    }

    /// Returns source-bound outcomes in original caller order.
    pub fn peer_results(&self) -> &[ProofChainHeadBroadcastPeerResult] {
        &self.peer_results
    }

    /// Consumes this report into its one shared announcement and ordered rows.
    pub fn into_parts(
        self,
    ) -> (
        ProofChainHeadAnnouncement,
        Vec<ProofChainHeadBroadcastPeerResult>,
    ) {
        (self.announcement, self.peer_results)
    }
}

/// One caller-ordered source-bound peer outcome.
#[derive(Debug)]
#[must_use]
pub struct ProofChainHeadBroadcastPeerResult {
    peer_id: PeerId,
    failure: Option<Box<OutboundProofChainHeadAnnouncementFailure>>,
}

impl ProofChainHeadBroadcastPeerResult {
    /// Returns the authenticated peer for this outcome.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Borrows the exact receipt-or-failure outcome.
    pub fn result(&self) -> Result<(), &OutboundProofChainHeadAnnouncementFailure> {
        match &self.failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    /// Consumes the exact receipt-or-failure outcome.
    pub fn into_result(self) -> Result<(), Box<OutboundProofChainHeadAnnouncementFailure>> {
        match self.failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

/// One mismatch preserving the complete broadcast and unrouted event.
#[derive(Debug)]
#[must_use]
pub struct ProofChainHeadBroadcastEventMismatch {
    broadcast: ProofChainHeadBroadcast,
    event: NetworkEvent,
}

impl ProofChainHeadBroadcastEventMismatch {
    /// Returns both values unchanged for caller routing or recovery.
    pub fn into_parts(self) -> (ProofChainHeadBroadcast, NetworkEvent) {
        (self.broadcast, self.event)
    }
}

impl fmt::Display for ProofChainHeadBroadcastEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("network event does not belong to this proof-chain-head broadcast")
    }
}

impl Error for ProofChainHeadBroadcastEventMismatch {}

/// Failure to atomically start one bounded proof-chain-head broadcast.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProofChainHeadBroadcastStartError {
    /// No destination peer was selected.
    EmptyPeerSet,
    /// The selected peer count exceeds the fixed static-peer bound.
    TooManyPeers { actual: usize, maximum: usize },
    /// The same destination peer appears more than once.
    DuplicatePeer(PeerId),
    /// The local journal could not supply a healthy selected-head snapshot.
    Journal(ProofChainJournalError),
    /// One destination failed caller-ordered authorization/session preflight.
    RequestStart(RequestStartError),
    /// The shared request budget cannot reserve the whole batch atomically.
    InsufficientCapacity {
        requested: usize,
        available: usize,
        maximum: usize,
    },
}

impl fmt::Display for ProofChainHeadBroadcastStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPeerSet => formatter.write_str("proof-chain-head broadcast has no peers"),
            Self::TooManyPeers { actual, maximum } => write!(
                formatter,
                "proof-chain-head broadcast peer count {actual} exceeds maximum {maximum}"
            ),
            Self::DuplicatePeer(peer_id) => write!(
                formatter,
                "proof-chain-head broadcast selects peer {peer_id} more than once"
            ),
            Self::Journal(source) => write!(formatter, "cannot read broadcast head: {source}"),
            Self::RequestStart(source) => {
                write!(
                    formatter,
                    "cannot start proof-chain-head broadcast: {source}"
                )
            }
            Self::InsufficientCapacity {
                requested,
                available,
                maximum,
            } => write!(
                formatter,
                "proof-chain-head broadcast needs {requested} request slots, only {available} of {maximum} are available"
            ),
        }
    }
}

impl Error for ProofChainHeadBroadcastStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(source) => Some(source),
            Self::RequestStart(source) => Some(source),
            _ => None,
        }
    }
}

fn validate_peer_set(peer_ids: &[PeerId]) -> Result<(), ProofChainHeadBroadcastStartError> {
    if peer_ids.is_empty() {
        return Err(ProofChainHeadBroadcastStartError::EmptyPeerSet);
    }
    if peer_ids.len() > MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS {
        return Err(ProofChainHeadBroadcastStartError::TooManyPeers {
            actual: peer_ids.len(),
            maximum: MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS,
        });
    }
    for (index, &peer_id) in peer_ids.iter().enumerate() {
        if peer_ids[..index].contains(&peer_id) {
            return Err(ProofChainHeadBroadcastStartError::DuplicatePeer(peer_id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
