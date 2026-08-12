//! Caller-driven journal serving for one static proof-network event loop.

use naome::block_exchange::ProofBlockRequest;
use naome::chain_head_exchange::ProofChainHeadRequest;
use naome::proof_exchange::ProofRequest;
use naome_storage::ProofChainJournal;

use super::{NetworkEvent, PeerId, RespondError, StaticProofNetwork};

/// One authenticated journal-read request handled by the service boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum JournalServiceRequest {
    /// One exact proof request.
    Proof {
        peer_id: PeerId,
        request: ProofRequest,
    },
    /// One exact proof-block request.
    Block {
        peer_id: PeerId,
        request: ProofBlockRequest,
    },
    /// One exact proof-chain-head request.
    ChainHead {
        peer_id: PeerId,
        request: ProofChainHeadRequest,
    },
}

/// One observable result from the caller-driven journal service.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum JournalServiceEvent {
    /// The response was accepted by libp2p for asynchronous writing.
    Served(JournalServiceRequest),
    /// The journal read, response budget, or response-channel transfer failed.
    ServeFailed {
        request: JournalServiceRequest,
        error: RespondError,
    },
    /// An event outside automatic journal serving remains caller-owned.
    Network(NetworkEvent),
}

impl StaticProofNetwork {
    /// Waits for and observably handles one journal-backed network event.
    ///
    /// Authenticated proof, block, and chain-head requests are served through
    /// their existing bounded response paths. Every other event, including a
    /// chain-head announcement, is returned unchanged for explicit caller
    /// policy. This method owns no task, queue, retry, or selected-state
    /// mutation.
    pub async fn next_journal_service_event(
        &mut self,
        journal: &ProofChainJournal,
    ) -> JournalServiceEvent {
        let event = self.next_event().await;
        self.handle_journal_service_event(event, journal)
    }

    fn handle_journal_service_event(
        &mut self,
        event: NetworkEvent,
        journal: &ProofChainJournal,
    ) -> JournalServiceEvent {
        let (request, result) = match event {
            NetworkEvent::InboundProofRequest(inbound) => {
                let request = JournalServiceRequest::Proof {
                    peer_id: inbound.peer_id(),
                    request: inbound.request(),
                };
                (request, self.respond_proof_from_journal(inbound, journal))
            }
            NetworkEvent::InboundBlockRequest(inbound) => {
                let request = JournalServiceRequest::Block {
                    peer_id: inbound.peer_id(),
                    request: inbound.request(),
                };
                (request, self.respond_block_from_journal(inbound, journal))
            }
            NetworkEvent::InboundChainHeadRequest(inbound) => {
                let request = JournalServiceRequest::ChainHead {
                    peer_id: inbound.peer_id(),
                    request: inbound.request(),
                };
                (
                    request,
                    self.respond_chain_head_from_journal(inbound, journal),
                )
            }
            event => return JournalServiceEvent::Network(event),
        };

        match result {
            Ok(()) => JournalServiceEvent::Served(request),
            Err(error) => JournalServiceEvent::ServeFailed { request, error },
        }
    }
}

#[cfg(test)]
mod tests;
