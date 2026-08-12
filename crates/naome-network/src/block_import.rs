//! Caller-selected import of one exact direct-child proof block.

use std::error::Error;
use std::fmt;

use naome::block_exchange::ProofBlockRequest;
use naome_chain::{ProofBlock, ProofBlockId, ProofSetRoot};
use naome_storage::{ProofChainJournal, ProofChainJournalError};

use super::{
    BlockRequestTicket, DependencyAcquisitionError, DependencyAcquisitionProgress, NetworkEvent,
    OutboundProofBlockFailure, OutboundProofFailure, PeerId, ProofDependencyAcquisition,
    RequestStartError, StaticProofNetwork, selected_context_contains_block,
};

/// One caller-selected direct-child block import in progress.
///
/// The caller supplies the exact target block identity. The import retrieves
/// only that block, checks it against the journal's current context before
/// proof traffic, acquires its existing bounded proof closure, and delegates
/// the sole mutation to the journal's normal atomic block application path.
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
    Proofs {
        block: ProofBlock,
        acquisition: ProofDependencyAcquisition,
    },
}

impl StaticProofNetwork {
    /// Starts importing one caller-selected block that must directly extend
    /// `selected`.
    ///
    /// The target is rejected before network work when it is the current head,
    /// virtual genesis anchor, or a committed selected block. The returned
    /// import remains caller-driven;
    /// route only events accepted by [`ProofBlockImport::accepts_event`] into
    /// [`ProofBlockImport::on_event`].
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
            ProofBlockImportPhase::Proofs { acquisition, .. } => acquisition.pending_peer_id(),
        }
    }

    /// Returns whether `event` is the exact terminal awaited by this phase.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        match (&self.phase, event) {
            (ProofBlockImportPhase::Block { ticket }, NetworkEvent::OutboundBlock(event)) => {
                ticket.accepts_event(event)
            }
            (
                ProofBlockImportPhase::Proofs { acquisition, .. },
                NetworkEvent::OutboundProof(event),
            ) => acquisition.accepts_event(event),
            _ => false,
        }
    }

    /// Cancels this import according to its current physical request phase.
    ///
    /// During block retrieval, the existing non-cancelling ticket semantics
    /// retain the request slot until libp2p emits a terminal. During proof
    /// acquisition, dropping the acquisition installs its existing
    /// cancellation tombstone and releases quarantined payloads immediately.
    pub fn cancel(self) {}

    /// Advances this import with its exact correlated network event.
    ///
    /// `network` must be the same instance that started the current request.
    ///
    /// Ordinary errors leave the journal unchanged. Only the existing
    /// ambiguous journal commit failure can poison `selected` after in-memory
    /// admission; reopening resolves that existing old-or-new durable state.
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
            ProofBlockImportPhase::Proofs { block, acquisition } => {
                let NetworkEvent::OutboundProof(event) = event else {
                    unreachable!("the accepted proof phase event is an outbound proof terminal")
                };
                if !acquisition.belongs_to_network(network) {
                    return Err(ProofBlockImportError::UnexpectedEvent);
                }
                if !matches!(
                    event.failure(),
                    Some(OutboundProofFailure::PeerMismatch { .. })
                ) {
                    Self::require_current_parent(selected, &block)?;
                }
                let progress =
                    acquisition
                        .on_event(network, selected, event)
                        .map_err(|source| ProofBlockImportError::ProofAcquisition {
                            block_id: target_block_id,
                            source: Box::new(source),
                        })?;
                match progress {
                    DependencyAcquisitionProgress::AwaitingResponse(acquisition) => {
                        Ok(Some(ProofBlockImport {
                            target_block_id,
                            phase: ProofBlockImportPhase::Proofs { block, acquisition },
                        }))
                    }
                    DependencyAcquisitionProgress::Complete(closure) => {
                        closure
                            .apply_block(selected, &block)
                            .map_err(ProofBlockImportError::selected_state)?;
                        Ok(None)
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
        let root_proof_id = block.transition().root_proof_id();
        let acquisition = network
            .start_dependency_acquisition(selected, peer_id, root_proof_id)
            .map_err(|source| ProofBlockImportError::ProofAcquisition {
                block_id: target_block_id,
                source: Box::new(source),
            })?;
        Ok(Self {
            target_block_id,
            phase: ProofBlockImportPhase::Proofs { block, acquisition },
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
        let actual_previous = block.transition().previous_proof_set_root();
        if actual_previous != expected_previous {
            return Err(ProofBlockImportError::PreviousProofSetRootMismatch {
                expected: expected_previous,
                actual: actual_previous,
            });
        }

        let prepared = selected
            .prepare_block(block.transition().proof_ids().to_vec())
            .map_err(ProofBlockImportError::selected_state)?;
        let expected_resulting = prepared.transition().resulting_proof_set_root();
        let actual_resulting = block.transition().resulting_proof_set_root();
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

/// Allocation-free progress for one caller-selected block import event.
///
/// `Some(import)` means one block or proof request remains active. `None`
/// means the exact target returned by [`ProofBlockImport::target_block_id`]
/// was atomically committed.
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
    /// The existing bounded proof-closure acquisition failed.
    ProofAcquisition {
        block_id: ProofBlockId,
        source: Box<DependencyAcquisitionError>,
    },
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
            Self::ProofAcquisition { block_id, source } => write!(
                formatter,
                "cannot acquire proofs for block {block_id:?}: {source}"
            ),
        }
    }
}

impl Error for ProofBlockImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::RequestStart { source, .. } => Some(source),
            Self::BlockRequestFailed { source, .. } => Some(source.as_ref()),
            Self::ProofAcquisition { source, .. } => Some(source.as_ref()),
            Self::TargetAlreadySelected { .. }
            | Self::UnexpectedEvent
            | Self::BlockUnavailable { .. }
            | Self::ParentBlockIdMismatch { .. }
            | Self::PreviousProofSetRootMismatch { .. }
            | Self::ResultingProofSetRootMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
