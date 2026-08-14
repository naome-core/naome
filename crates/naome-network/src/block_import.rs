//! Caller-selected import of one exact direct-child proof block.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use libp2p::request_response::OutboundRequestId;
use naome::block_exchange::ProofBlockRequest;
use naome::proof_exchange::ProofRequest;
use naome_chain::{ProofBlock, ProofBlockId, ProofSetRoot};
use naome_proof::ProofId;
use naome_storage::{ProofChainJournal, ProofChainJournalError};

use super::{
    BlockRequestTicket, NetworkEvent, OutboundProofBlockFailure, OutboundProofEvent,
    OutboundProofFailure, OutboundProofOutcome, PROOF_BLOCK_IMPORT_TIMEOUT, PeerId,
    ProofRequestControl, RequestStartError, StaticProofNetwork, selected_context_contains_block,
};

/// One caller-selected direct-child block import in progress.
///
/// The caller supplies the exact target block identity. The import retrieves
/// only that block, preflights its fixed commitments, requests exactly its one
/// committed [`ProofId`], and delegates the sole mutation to the journal's
/// canonical single-proof block application.
#[derive(Debug)]
#[must_use]
pub struct ProofBlockImport {
    target_block_id: ProofBlockId,
    phase: ProofBlockImportPhase,
}

#[derive(Debug)]
enum ProofBlockImportPhase {
    Block {
        ticket: BlockRequestTicket,
    },
    Proof {
        block: ProofBlock,
        request: ProofPayloadRequest,
    },
}

struct ProofPayloadRequest {
    control: Option<Arc<ProofRequestControl>>,
    peer_id: PeerId,
    request: ProofRequest,
    request_id: OutboundRequestId,
    attempted_peers: u8,
}

impl ProofPayloadRequest {
    fn start(
        network: &mut StaticProofNetwork,
        preferred_peer_id: PeerId,
        proof_id: ProofId,
    ) -> Result<Self, ProofBlockImportError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(PROOF_BLOCK_IMPORT_TIMEOUT)
            .expect("the fixed proof-block import timeout fits Tokio Instant");
        let control = Arc::new(ProofRequestControl::new(
            Arc::clone(&network.pending_budget),
            deadline,
        ));
        let request = ProofRequest::new(proof_id);
        let mut attempted_peers = 0;
        let (peer_id, request_id) = start_next_proof_attempt(
            network,
            preferred_peer_id,
            request,
            &control,
            &mut attempted_peers,
        )
        .map_err(|source| match source {
            ProofAttemptSelectionError::NoEligiblePeer => {
                ProofBlockImportError::NoEligibleProofPeer { proof_id }
            }
            ProofAttemptSelectionError::RequestStart(source) => {
                ProofBlockImportError::ProofRequestStart { proof_id, source }
            }
        })?;
        Ok(Self {
            control: Some(control),
            peer_id,
            request,
            request_id,
            attempted_peers,
        })
    }

    fn control(&self) -> &Arc<ProofRequestControl> {
        self.control
            .as_ref()
            .expect("an active block import retains proof-request control")
    }

    fn belongs_to_network(&self, network: &StaticProofNetwork) -> bool {
        Arc::ptr_eq(&self.control().network_budget, &network.pending_budget)
    }

    fn accepts_event(&self, event: &OutboundProofEvent) -> bool {
        Arc::ptr_eq(self.control(), &event.control)
            && self.request_id == event.request_id
            && self.peer_id == event.peer_id
            && self.request == event.request
    }

    fn deadline_expired(&self) -> bool {
        tokio::time::Instant::now() >= self.control().deadline
    }

    fn retry(
        mut self,
        network: &mut StaticProofNetwork,
        terminal_error: ProofBlockImportError,
    ) -> Result<Self, ProofBlockImportError> {
        if self.deadline_expired() {
            return Err(ProofBlockImportError::ProofDeadlineExceeded {
                peer_id: self.peer_id,
                proof_id: self.request.proof_id(),
            });
        }
        let control = self
            .control
            .as_ref()
            .expect("an active block import retains proof-request control");
        let (peer_id, request_id) = match start_next_proof_attempt(
            network,
            self.peer_id,
            self.request,
            control,
            &mut self.attempted_peers,
        ) {
            Ok(started) => started,
            Err(ProofAttemptSelectionError::NoEligiblePeer) => return Err(terminal_error),
            Err(ProofAttemptSelectionError::RequestStart(source)) => {
                return Err(ProofBlockImportError::ProofRequestStart {
                    proof_id: self.request.proof_id(),
                    source,
                });
            }
        };
        self.peer_id = peer_id;
        self.request_id = request_id;
        Ok(self)
    }

    fn disarm(&mut self) {
        self.control = None;
    }
}

impl Drop for ProofPayloadRequest {
    fn drop(&mut self) {
        if let Some(control) = &self.control {
            control.cancel();
        }
    }
}

impl fmt::Debug for ProofPayloadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofPayloadRequest")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

enum ProofAttemptSelectionError {
    NoEligiblePeer,
    RequestStart(RequestStartError),
}

fn start_next_proof_attempt(
    network: &mut StaticProofNetwork,
    preferred_peer_id: PeerId,
    request: ProofRequest,
    control: &Arc<ProofRequestControl>,
    attempted_peers: &mut u8,
) -> Result<(PeerId, OutboundRequestId), ProofAttemptSelectionError> {
    let (preferred_index, peer_count) = {
        let sessions = &network.swarm.behaviour().sessions;
        let preferred_index = sessions.peer_index(&preferred_peer_id).ok_or(
            ProofAttemptSelectionError::RequestStart(RequestStartError::UnknownPeer(
                preferred_peer_id,
            )),
        )?;
        (preferred_index, sessions.peer_count())
    };

    for position in 0..peer_count {
        let index = if position == 0 {
            preferred_index
        } else {
            let ordered = position - 1;
            if ordered < preferred_index {
                ordered
            } else {
                ordered + 1
            }
        };
        let bit = 1_u8
            .checked_shl(u32::try_from(index).expect("the peer index fits u32"))
            .expect("the static peer count fits one attempted-peer mask");
        if *attempted_peers & bit != 0 {
            continue;
        }
        *attempted_peers |= bit;

        let peer_id = network
            .swarm
            .behaviour()
            .sessions
            .peer_id_at(index)
            .expect("the configured peer index remains stable");
        match network.request_controlled_proof(peer_id, request, control) {
            Ok(request_id) => return Ok((peer_id, request_id)),
            Err(RequestStartError::AlreadyPending(_) | RequestStartError::PeerDisconnected(_)) => {}
            Err(source) => return Err(ProofAttemptSelectionError::RequestStart(source)),
        }
    }

    Err(ProofAttemptSelectionError::NoEligiblePeer)
}

impl StaticProofNetwork {
    /// Starts importing one caller-selected block that must directly extend
    /// `selected`.
    pub fn start_proof_block_import(
        &mut self,
        selected: &ProofChainJournal,
        peer_id: PeerId,
        target_block_id: ProofBlockId,
    ) -> Result<ProofBlockImport, ProofBlockImportError> {
        let current_head = selected
            .head_block_id()
            .map_err(ProofBlockImportError::selected_state)?;
        let virtual_genesis = selected.chain_id().virtual_genesis_block_id();
        if selected_context_contains_block(selected, current_head, virtual_genesis, target_block_id)
            .map_err(ProofBlockImportError::selected_state)?
        {
            return Err(ProofBlockImportError::TargetAlreadySelected {
                block_id: target_block_id,
            });
        }

        let ticket = self
            .request_block(peer_id, ProofBlockRequest::new(target_block_id))
            .map_err(|source| ProofBlockImportError::RequestStart {
                block_id: target_block_id,
                source,
            })?;
        Ok(ProofBlockImport {
            target_block_id,
            phase: ProofBlockImportPhase::Block { ticket },
        })
    }
}

impl ProofBlockImport {
    /// Returns the exact block identity selected by the caller.
    pub const fn target_block_id(&self) -> ProofBlockId {
        self.target_block_id
    }

    /// Returns the authenticated peer serving the currently pending request.
    pub const fn pending_peer_id(&self) -> PeerId {
        match &self.phase {
            ProofBlockImportPhase::Block { ticket } => ticket.peer_id(),
            ProofBlockImportPhase::Proof { request, .. } => request.peer_id,
        }
    }

    /// Returns whether `event` is the exact terminal awaited by this phase.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        match (&self.phase, event) {
            (ProofBlockImportPhase::Block { ticket }, NetworkEvent::OutboundBlock(event)) => {
                ticket.accepts_event(event)
            }
            (ProofBlockImportPhase::Proof { request, .. }, NetworkEvent::OutboundProof(event)) => {
                request.accepts_event(event)
            }
            _ => false,
        }
    }

    /// Cancels this import according to its current physical request phase.
    pub fn cancel(self) {}

    /// Advances this import with its exact correlated network event.
    pub fn on_event(
        self,
        network: &mut StaticProofNetwork,
        selected: &mut ProofChainJournal,
        event: NetworkEvent,
    ) -> Result<ProofBlockImportProgress, ProofBlockImportError> {
        if !self.accepts_event(&event) {
            return Err(ProofBlockImportError::UnexpectedEvent);
        }

        let Self {
            target_block_id,
            phase,
        } = self;
        match phase {
            ProofBlockImportPhase::Block { ticket } => {
                let NetworkEvent::OutboundBlock(event) = event else {
                    unreachable!("the accepted block phase event is an outbound block terminal")
                };
                if !ticket.belongs_to_network(network) {
                    return Err(ProofBlockImportError::UnexpectedEvent);
                }
                let peer_id = ticket.peer_id();
                let response = ticket
                    .complete(event)
                    .expect("the accepted block event matches its ticket")
                    .map_err(|source| ProofBlockImportError::BlockRequestFailed {
                        peer_id,
                        block_id: target_block_id,
                        source,
                    })?;
                let block =
                    response
                        .into_block()
                        .ok_or(ProofBlockImportError::BlockUnavailable {
                            peer_id,
                            block_id: target_block_id,
                        })?;

                Self::start_from_retained_block(network, selected, peer_id, target_block_id, block)
                    .map(Some)
            }
            ProofBlockImportPhase::Proof { block, mut request } => {
                let NetworkEvent::OutboundProof(event) = event else {
                    unreachable!("the accepted proof phase event is an outbound proof terminal")
                };
                if !request.belongs_to_network(network) {
                    return Err(ProofBlockImportError::UnexpectedEvent);
                }

                let OutboundProofEvent {
                    peer_id, outcome, ..
                } = event;
                let proof_id = block.proof_id();
                if matches!(
                    &outcome,
                    OutboundProofOutcome::Failure(source)
                        if matches!(source.as_ref(), OutboundProofFailure::PeerMismatch { .. })
                ) {
                    let OutboundProofOutcome::Failure(source) = outcome else {
                        unreachable!("the peer-mismatch guard matched a failure")
                    };
                    return Err(ProofBlockImportError::ProofRequestFailed {
                        peer_id,
                        proof_id,
                        source,
                    });
                }

                Self::require_current_parent(selected, &block)?;
                if matches!(outcome, OutboundProofOutcome::DeadlineExceeded)
                    || request.deadline_expired()
                {
                    return Err(ProofBlockImportError::ProofDeadlineExceeded { peer_id, proof_id });
                }

                match outcome {
                    OutboundProofOutcome::Response { response, _permit } => {
                        if response.is_unavailable() {
                            drop(response);
                            drop(_permit);
                            let error =
                                ProofBlockImportError::ProofUnavailable { peer_id, proof_id };
                            let request = request.retry(network, error)?;
                            return Ok(Some(Self {
                                target_block_id,
                                phase: ProofBlockImportPhase::Proof { block, request },
                            }));
                        }

                        request.disarm();
                        let result = selected.apply_block(&block, response.into_wire_bytes());
                        drop(_permit);
                        let _ = result.map_err(ProofBlockImportError::selected_state)?;
                        Ok(None)
                    }
                    OutboundProofOutcome::Failure(source) => {
                        let error = ProofBlockImportError::ProofRequestFailed {
                            peer_id,
                            proof_id,
                            source,
                        };
                        let request = request.retry(network, error)?;
                        Ok(Some(Self {
                            target_block_id,
                            phase: ProofBlockImportPhase::Proof { block, request },
                        }))
                    }
                    OutboundProofOutcome::DeadlineExceeded => {
                        unreachable!("the deadline terminal was handled above")
                    }
                }
            }
        }
    }

    pub(super) fn start_from_retained_block(
        network: &mut StaticProofNetwork,
        selected: &ProofChainJournal,
        peer_id: PeerId,
        target_block_id: ProofBlockId,
        block: ProofBlock,
    ) -> Result<Self, ProofBlockImportError> {
        debug_assert_eq!(block.id(), target_block_id);
        Self::preflight_block(selected, &block)?;
        let request = ProofPayloadRequest::start(network, peer_id, block.proof_id())?;
        Ok(Self {
            target_block_id,
            phase: ProofBlockImportPhase::Proof { block, request },
        })
    }

    fn preflight_block(
        selected: &ProofChainJournal,
        block: &ProofBlock,
    ) -> Result<(), ProofBlockImportError> {
        Self::require_current_parent(selected, block)?;

        let expected_previous = selected
            .proof_set_root()
            .map_err(ProofBlockImportError::selected_state)?;
        let actual_previous = block.previous_proof_set_root();
        if actual_previous != expected_previous {
            return Err(ProofBlockImportError::PreviousProofSetRootMismatch {
                expected: expected_previous,
                actual: actual_previous,
            });
        }

        let prepared = selected
            .prepare_block(block.proof_id())
            .map_err(ProofBlockImportError::selected_state)?;
        let expected_resulting = prepared.resulting_proof_set_root();
        let actual_resulting = block.resulting_proof_set_root();
        if actual_resulting != expected_resulting {
            return Err(ProofBlockImportError::ResultingProofSetRootMismatch {
                expected: expected_resulting,
                actual: actual_resulting,
            });
        }

        Ok(())
    }

    fn require_current_parent(
        selected: &ProofChainJournal,
        block: &ProofBlock,
    ) -> Result<(), ProofBlockImportError> {
        let expected = selected
            .head_block_id()
            .map_err(ProofBlockImportError::selected_state)?;
        let actual = block.parent_block_id();
        if actual != expected {
            return Err(ProofBlockImportError::ParentBlockIdMismatch { expected, actual });
        }
        Ok(())
    }
}

/// Progress for one caller-selected block import event.
pub type ProofBlockImportProgress = Option<ProofBlockImport>;

/// A fail-closed caller-selected proof-block import error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProofBlockImportError {
    /// The selected journal failed a read, preparation, application, or commit.
    SelectedState { source: Box<ProofChainJournalError> },
    /// The target is the current head, virtual genesis, or a selected block.
    TargetAlreadySelected { block_id: ProofBlockId },
    /// The exact target block request could not be started.
    RequestStart {
        block_id: ProofBlockId,
        source: RequestStartError,
    },
    /// The supplied event or driver did not belong to this import generation.
    UnexpectedEvent,
    /// The exact target block request failed before yielding a usable response.
    BlockRequestFailed {
        peer_id: PeerId,
        block_id: ProofBlockId,
        source: Box<OutboundProofBlockFailure>,
    },
    /// The authenticated peer reported no block for the exact target address.
    BlockUnavailable {
        peer_id: PeerId,
        block_id: ProofBlockId,
    },
    /// The fetched block did not directly extend the current selected head.
    ParentBlockIdMismatch {
        expected: ProofBlockId,
        actual: ProofBlockId,
    },
    /// The fetched block committed a different selected root before execution.
    PreviousProofSetRootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
    /// The fetched block committed a different projected selected root.
    ResultingProofSetRootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
    /// No configured, connected, free peer could serve the exact proof payload.
    NoEligibleProofPeer { proof_id: ProofId },
    /// The exact proof request could not be started.
    ProofRequestStart {
        proof_id: ProofId,
        source: RequestStartError,
    },
    /// One authenticated peer's exact proof request failed.
    ProofRequestFailed {
        peer_id: PeerId,
        proof_id: ProofId,
        source: Box<OutboundProofFailure>,
    },
    /// Every eligible peer tried so far reported the exact proof unavailable.
    ProofUnavailable { peer_id: PeerId, proof_id: ProofId },
    /// The absolute single-payload import deadline expired.
    ProofDeadlineExceeded { peer_id: PeerId, proof_id: ProofId },
}

impl ProofBlockImportError {
    fn selected_state(source: ProofChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for ProofBlockImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectedState { source } => {
                write!(
                    formatter,
                    "proof-block import cannot use selected state: {source}"
                )
            }
            Self::TargetAlreadySelected { block_id } => {
                write!(formatter, "proof block {block_id:?} is already selected")
            }
            Self::RequestStart { block_id, source } => {
                write!(
                    formatter,
                    "cannot request proof block {block_id:?}: {source}"
                )
            }
            Self::UnexpectedEvent => formatter
                .write_str("network event or driver does not belong to this proof-block import"),
            Self::BlockRequestFailed {
                peer_id,
                block_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed proof-block import request {block_id:?}: {source}"
            ),
            Self::BlockUnavailable { peer_id, block_id } => write!(
                formatter,
                "peer {peer_id} has no proof block at {block_id:?}"
            ),
            Self::ParentBlockIdMismatch { expected, actual } => write!(
                formatter,
                "proof block extends parent {actual:?}, expected current head {expected:?}"
            ),
            Self::PreviousProofSetRootMismatch { expected, actual } => write!(
                formatter,
                "proof block starts at proof-set root {actual:?}, expected {expected:?}"
            ),
            Self::ResultingProofSetRootMismatch { expected, actual } => write!(
                formatter,
                "proof block projects proof-set root {actual:?}, expected {expected:?}"
            ),
            Self::NoEligibleProofPeer { proof_id } => write!(
                formatter,
                "no configured peer can currently serve block proof {proof_id:?}"
            ),
            Self::ProofRequestStart { proof_id, source } => {
                write!(
                    formatter,
                    "cannot request block proof {proof_id:?}: {source}"
                )
            }
            Self::ProofRequestFailed {
                peer_id,
                proof_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed block proof request {proof_id:?}: {source}"
            ),
            Self::ProofUnavailable { peer_id, proof_id } => write!(
                formatter,
                "peer {peer_id} reported block proof {proof_id:?} unavailable"
            ),
            Self::ProofDeadlineExceeded { peer_id, proof_id } => write!(
                formatter,
                "block proof import from {peer_id} exceeded {PROOF_BLOCK_IMPORT_TIMEOUT:?} while awaiting {proof_id:?}"
            ),
        }
    }
}

impl Error for ProofBlockImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::RequestStart { source, .. } | Self::ProofRequestStart { source, .. } => {
                Some(source)
            }
            Self::BlockRequestFailed { source, .. } => Some(source.as_ref()),
            Self::ProofRequestFailed { source, .. } => Some(source.as_ref()),
            Self::TargetAlreadySelected { .. }
            | Self::UnexpectedEvent
            | Self::BlockUnavailable { .. }
            | Self::ParentBlockIdMismatch { .. }
            | Self::PreviousProofSetRootMismatch { .. }
            | Self::ResultingProofSetRootMismatch { .. }
            | Self::NoEligibleProofPeer { .. }
            | Self::ProofUnavailable { .. }
            | Self::ProofDeadlineExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
