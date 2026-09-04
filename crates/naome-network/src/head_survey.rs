//! Bounded caller-selected observation of authenticated peer-local chain heads.

use std::error::Error;
use std::fmt;

use naome_chain::ArtifactBlockId;
use naome_protocol::chain_head_exchange::ArtifactChainHeadRequest;

use super::{
    ChainHeadRequestTicket, MAX_PENDING_REQUESTS, MAX_STATIC_PEERS, NetworkEvent,
    OutboundArtifactChainHeadFailure, PeerId, PendingBudget, RequestStartError,
    StaticArtifactNetwork,
};

/// One bounded artifact-chain-head survey awaiting peer terminals.
///
/// Each result remains bound to its authenticated source. This workflow does
/// not group equal heads, rank observations, select a target, or read or mutate
/// local selected state.
#[derive(Debug)]
#[must_use]
pub struct ArtifactChainHeadSurvey {
    request: ArtifactChainHeadRequest,
    peers: Vec<SurveyPeerState>,
}

#[derive(Debug)]
enum SurveyPeerState {
    Pending(ChainHeadRequestTicket),
    Complete(ArtifactChainHeadSurveyPeerResult),
}

impl StaticArtifactNetwork {
    /// Starts one all-or-none survey for an exact caller-selected chain context.
    ///
    /// `peer_ids` must contain one to [`MAX_STATIC_PEERS`] unique, statically
    /// authorized and connected peers. Every structural, peer, and capacity
    /// check completes before the first physical request is queued.
    pub fn start_chain_head_survey(
        &mut self,
        peer_ids: &[PeerId],
        request: ArtifactChainHeadRequest,
    ) -> Result<ArtifactChainHeadSurvey, ArtifactChainHeadSurveyStartError> {
        validate_peer_set(peer_ids)?;

        let mut peer_indices = [0; MAX_STATIC_PEERS];
        for (&peer_id, peer_index) in peer_ids.iter().zip(&mut peer_indices) {
            let transport_connected = self.swarm.behaviour().head_exchange.is_connected(&peer_id);
            *peer_index = self
                .preflight_request(peer_id, transport_connected)
                .map_err(ArtifactChainHeadSurveyStartError::RequestStart)?;
        }

        let permits = PendingBudget::try_acquire_many(&self.pending_budget, peer_ids.len())
            .map_err(
                |available| ArtifactChainHeadSurveyStartError::InsufficientCapacity {
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
            peers.push(SurveyPeerState::Pending(
                self.enqueue_chain_head_request(peer_index, peer_id, request, permit),
            ));
        }

        Ok(ArtifactChainHeadSurvey { request, peers })
    }
}

impl ArtifactChainHeadSurvey {
    /// Returns the single immutable chain-head request sent to every peer.
    pub const fn request(&self) -> ArtifactChainHeadRequest {
        self.request
    }

    /// Returns the number of caller-selected peers in this survey.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns the number of peers whose physical terminal is still awaited.
    pub fn pending_peer_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|peer| matches!(peer, SurveyPeerState::Pending(_)))
            .count()
    }

    /// Returns whether `event` is one exact terminal awaited by this survey.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        let NetworkEvent::OutboundChainHead(event) = event else {
            return false;
        };
        self.peers.iter().any(
            |peer| matches!(peer, SurveyPeerState::Pending(ticket) if ticket.accepts_event(event)),
        )
    }

    /// Cancels the logical survey and releases its completed outcomes.
    ///
    /// Pending tickets retain their existing non-cancelling transport
    /// semantics: physical terminals continue to drain their peer slots and
    /// shared permits through [`StaticArtifactNetwork::next_event`].
    pub fn cancel(self) {}

    /// Advances this survey with one exact source-bound peer terminal.
    ///
    /// Mismatched events preserve both the complete survey and event for
    /// caller routing. Matching failures are retained as per-peer outcomes and
    /// never cancel, retry, or reinterpret another peer.
    pub fn on_event(
        mut self,
        event: NetworkEvent,
    ) -> Result<ArtifactChainHeadSurveyProgress, Box<ArtifactChainHeadSurveyEventMismatch>> {
        let NetworkEvent::OutboundChainHead(terminal) = event else {
            return Err(Box::new(ArtifactChainHeadSurveyEventMismatch {
                survey: self,
                event,
            }));
        };
        let Some(index) = self.peers.iter().position(|peer| {
            matches!(peer, SurveyPeerState::Pending(ticket) if ticket.accepts_event(&terminal))
        }) else {
            return Err(Box::new(ArtifactChainHeadSurveyEventMismatch {
                survey: self,
                event: NetworkEvent::OutboundChainHead(terminal),
            }));
        };

        let peer_id = terminal.peer_id();
        let state = std::mem::replace(
            &mut self.peers[index],
            SurveyPeerState::Complete(ArtifactChainHeadSurveyPeerResult {
                peer_id,
                outcome: Ok(None),
            }),
        );
        let SurveyPeerState::Pending(ticket) = state else {
            unreachable!("an accepted survey terminal belongs to a pending peer")
        };
        let outcome = match ticket
            .complete(terminal)
            .expect("an accepted survey terminal matches its ticket")
        {
            Ok(response) => {
                debug_assert_eq!(response.peer_id(), peer_id);
                debug_assert_eq!(response.request(), self.request);
                Ok(response.head_block_id())
            }
            Err(failure) => Err(failure),
        };
        self.peers[index] =
            SurveyPeerState::Complete(ArtifactChainHeadSurveyPeerResult { peer_id, outcome });

        if self.pending_peer_count() != 0 {
            return Ok(ArtifactChainHeadSurveyProgress::AwaitingResponses(self));
        }

        let peer_results = self
            .peers
            .into_iter()
            .map(|peer| match peer {
                SurveyPeerState::Complete(result) => result,
                SurveyPeerState::Pending(_) => {
                    unreachable!("a completed survey has no pending peer")
                }
            })
            .collect();
        Ok(ArtifactChainHeadSurveyProgress::Complete(
            CompletedArtifactChainHeadSurvey {
                request: self.request,
                peer_results,
            },
        ))
    }
}

/// Progress after one exact survey terminal.
#[derive(Debug)]
#[must_use]
pub enum ArtifactChainHeadSurveyProgress {
    /// At least one selected peer terminal remains pending.
    AwaitingResponses(ArtifactChainHeadSurvey),
    /// Every selected peer produced exactly one source-bound outcome.
    Complete(CompletedArtifactChainHeadSurvey),
}

/// One completed survey with deterministic caller-ordered peer outcomes.
#[derive(Debug)]
#[must_use]
pub struct CompletedArtifactChainHeadSurvey {
    request: ArtifactChainHeadRequest,
    peer_results: Vec<ArtifactChainHeadSurveyPeerResult>,
}

impl CompletedArtifactChainHeadSurvey {
    /// Returns the single immutable request sent to every peer.
    pub const fn request(&self) -> ArtifactChainHeadRequest {
        self.request
    }

    /// Returns source-bound outcomes in original caller order.
    pub fn peer_results(&self) -> &[ArtifactChainHeadSurveyPeerResult] {
        &self.peer_results
    }

    /// Consumes this report into its one shared request and ordered rows.
    pub fn into_parts(
        self,
    ) -> (
        ArtifactChainHeadRequest,
        Vec<ArtifactChainHeadSurveyPeerResult>,
    ) {
        (self.request, self.peer_results)
    }
}

/// One caller-ordered source-bound peer outcome.
#[derive(Debug)]
#[must_use]
pub struct ArtifactChainHeadSurveyPeerResult {
    peer_id: PeerId,
    outcome: Result<Option<ArtifactBlockId>, Box<OutboundArtifactChainHeadFailure>>,
}

impl ArtifactChainHeadSurveyPeerResult {
    /// Returns the authenticated peer for this outcome.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Borrows the exact found, unavailable, or failure outcome.
    pub fn result(&self) -> Result<Option<ArtifactBlockId>, &OutboundArtifactChainHeadFailure> {
        match &self.outcome {
            Ok(head_block_id) => Ok(*head_block_id),
            Err(failure) => Err(failure),
        }
    }

    /// Consumes the exact found, unavailable, or failure outcome.
    pub fn into_result(
        self,
    ) -> Result<Option<ArtifactBlockId>, Box<OutboundArtifactChainHeadFailure>> {
        self.outcome
    }
}

/// One mismatch preserving the complete survey and unrouted event.
#[derive(Debug)]
#[must_use]
pub struct ArtifactChainHeadSurveyEventMismatch {
    survey: ArtifactChainHeadSurvey,
    event: NetworkEvent,
}

impl ArtifactChainHeadSurveyEventMismatch {
    /// Returns both values unchanged for caller routing or recovery.
    pub fn into_parts(self) -> (ArtifactChainHeadSurvey, NetworkEvent) {
        (self.survey, self.event)
    }
}

impl fmt::Display for ArtifactChainHeadSurveyEventMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("network event does not belong to this artifact-chain-head survey")
    }
}

impl Error for ArtifactChainHeadSurveyEventMismatch {}

/// Failure to atomically start one bounded artifact-chain-head survey.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactChainHeadSurveyStartError {
    /// No source peer was selected.
    EmptyPeerSet,
    /// The selected peer count exceeds the fixed static-peer bound.
    TooManyPeers { actual: usize, maximum: usize },
    /// The same source peer appears more than once.
    DuplicatePeer(PeerId),
    /// One source failed caller-ordered authorization/session preflight.
    RequestStart(RequestStartError),
    /// The shared request budget cannot reserve the whole batch atomically.
    InsufficientCapacity {
        requested: usize,
        available: usize,
        maximum: usize,
    },
}

impl fmt::Display for ArtifactChainHeadSurveyStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPeerSet => formatter.write_str("artifact-chain-head survey has no peers"),
            Self::TooManyPeers { actual, maximum } => write!(
                formatter,
                "artifact-chain-head survey peer count {actual} exceeds maximum {maximum}"
            ),
            Self::DuplicatePeer(peer_id) => write!(
                formatter,
                "artifact-chain-head survey selects peer {peer_id} more than once"
            ),
            Self::RequestStart(source) => {
                write!(
                    formatter,
                    "cannot start artifact-chain-head survey: {source}"
                )
            }
            Self::InsufficientCapacity {
                requested,
                available,
                maximum,
            } => write!(
                formatter,
                "artifact-chain-head survey needs {requested} request slots, only {available} of {maximum} are available"
            ),
        }
    }
}

impl Error for ArtifactChainHeadSurveyStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RequestStart(source) => Some(source),
            _ => None,
        }
    }
}

fn validate_peer_set(peer_ids: &[PeerId]) -> Result<(), ArtifactChainHeadSurveyStartError> {
    if peer_ids.is_empty() {
        return Err(ArtifactChainHeadSurveyStartError::EmptyPeerSet);
    }
    if peer_ids.len() > MAX_STATIC_PEERS {
        return Err(ArtifactChainHeadSurveyStartError::TooManyPeers {
            actual: peer_ids.len(),
            maximum: MAX_STATIC_PEERS,
        });
    }
    for (index, &peer_id) in peer_ids.iter().enumerate() {
        if peer_ids[..index].contains(&peer_id) {
            return Err(ArtifactChainHeadSurveyStartError::DuplicatePeer(peer_id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
