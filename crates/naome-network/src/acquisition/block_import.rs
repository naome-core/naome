//! Caller-selected import of one exact direct-child artifact block.

use std::error::Error;
use std::fmt;

use naome_chain::{ArtifactBlock, ArtifactBlockId, ArtifactSetRoot};
use naome_proof::ArtifactId;
use naome_protocol::block_exchange::ArtifactBlockRequest;
use naome_storage::{ArtifactChainJournal, ArtifactChainJournalError};

use crate::transport::payload_request::{ArtifactAttemptSelectionError, ArtifactPayloadRequest};

use super::{
    ARTIFACT_BLOCK_IMPORT_TIMEOUT, BlockRequestTicket, NetworkEvent, OutboundArtifactBlockFailure,
    OutboundArtifactFailure, OutboundArtifactOutcome, PeerId, RequestStartError,
    StaticArtifactNetwork, selected_context_contains_block,
};

/// One caller-selected direct-child block import in progress.
///
/// The caller supplies the exact target block identity. The import retrieves
/// only that block, preflights its fixed commitments, requests exactly its one
/// committed [`ArtifactId`], and delegates the sole mutation to the journal's
/// canonical single-artifact block application.
#[derive(Debug)]
#[must_use]
pub struct ArtifactBlockImport {
    target_block_id: ArtifactBlockId,
    phase: ArtifactBlockImportPhase,
}

#[derive(Debug)]
enum ArtifactBlockImportPhase {
    Block {
        ticket: BlockRequestTicket,
    },
    Artifact {
        block: ArtifactBlock,
        request: ArtifactPayloadRequest,
    },
}

fn retry_artifact_request(
    request: ArtifactPayloadRequest,
    network: &mut StaticArtifactNetwork,
    terminal_error: ArtifactBlockImportError,
) -> Result<ArtifactPayloadRequest, ArtifactBlockImportError> {
    let artifact_id = request.artifact_id();
    if request.deadline_expired() {
        return Err(ArtifactBlockImportError::ArtifactDeadlineExceeded {
            peer_id: request.peer_id(),
            artifact_id,
        });
    }
    request.try_next(network).map_err(|source| match source {
        ArtifactAttemptSelectionError::NoEligiblePeer => terminal_error,
        ArtifactAttemptSelectionError::RequestStart(source) => {
            ArtifactBlockImportError::ArtifactRequestStart {
                artifact_id,
                source,
            }
        }
    })
}

impl StaticArtifactNetwork {
    /// Starts importing one caller-selected block that must directly extend
    /// `selected`.
    pub fn start_artifact_block_import(
        &mut self,
        selected: &ArtifactChainJournal,
        peer_id: PeerId,
        target_block_id: ArtifactBlockId,
    ) -> Result<ArtifactBlockImport, ArtifactBlockImportError> {
        let current_head = selected
            .head_block_id()
            .map_err(ArtifactBlockImportError::selected_state)?;
        let virtual_genesis = selected.chain_id().virtual_genesis_block_id();
        if selected_context_contains_block(selected, current_head, virtual_genesis, target_block_id)
            .map_err(ArtifactBlockImportError::selected_state)?
        {
            return Err(ArtifactBlockImportError::TargetAlreadySelected {
                block_id: target_block_id,
            });
        }

        let ticket = self
            .request_block(peer_id, ArtifactBlockRequest::new(target_block_id))
            .map_err(|source| ArtifactBlockImportError::RequestStart {
                block_id: target_block_id,
                source,
            })?;
        Ok(ArtifactBlockImport {
            target_block_id,
            phase: ArtifactBlockImportPhase::Block { ticket },
        })
    }
}

impl ArtifactBlockImport {
    /// Returns the exact block identity selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the authenticated peer serving the currently pending request.
    pub const fn pending_peer_id(&self) -> PeerId {
        match &self.phase {
            ArtifactBlockImportPhase::Block { ticket } => ticket.peer_id(),
            ArtifactBlockImportPhase::Artifact { request, .. } => request.peer_id(),
        }
    }

    /// Returns whether `event` is the exact terminal awaited by this phase.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        match (&self.phase, event) {
            (ArtifactBlockImportPhase::Block { ticket }, NetworkEvent::OutboundBlock(event)) => {
                ticket.accepts_event(event)
            }
            (
                ArtifactBlockImportPhase::Artifact { request, .. },
                NetworkEvent::OutboundArtifact(event),
            ) => request.accepts_event(event),
            _ => false,
        }
    }

    /// Cancels this import according to its current physical request phase.
    pub fn cancel(self) {}

    /// Advances this import with its exact correlated network event.
    pub fn on_event(
        self,
        network: &mut StaticArtifactNetwork,
        selected: &mut ArtifactChainJournal,
        event: NetworkEvent,
    ) -> Result<ArtifactBlockImportProgress, ArtifactBlockImportError> {
        if !self.accepts_event(&event) {
            return Err(ArtifactBlockImportError::UnexpectedEvent);
        }

        let Self {
            target_block_id,
            phase,
        } = self;
        match phase {
            ArtifactBlockImportPhase::Block { ticket } => {
                let NetworkEvent::OutboundBlock(event) = event else {
                    unreachable!("the accepted block phase event is an outbound block terminal")
                };
                if !ticket.belongs_to_network(network) {
                    return Err(ArtifactBlockImportError::UnexpectedEvent);
                }
                let peer_id = ticket.peer_id();
                let response = ticket
                    .complete(event)
                    .expect("the accepted block event matches its ticket")
                    .map_err(|source| ArtifactBlockImportError::BlockRequestFailed {
                        peer_id,
                        block_id: target_block_id,
                        source,
                    })?;
                let block =
                    response
                        .into_block()
                        .ok_or(ArtifactBlockImportError::BlockUnavailable {
                            peer_id,
                            block_id: target_block_id,
                        })?;

                Self::start_from_retained_block(network, selected, peer_id, target_block_id, block)
                    .map(Some)
            }
            ArtifactBlockImportPhase::Artifact { block, mut request } => {
                let NetworkEvent::OutboundArtifact(event) = event else {
                    unreachable!(
                        "the accepted artifact phase event is an outbound artifact terminal"
                    )
                };
                if !request.belongs_to_network(network) {
                    return Err(ArtifactBlockImportError::UnexpectedEvent);
                }

                let (peer_id, outcome) = event.into_parts();
                let artifact_id = block.artifact_id();
                if matches!(
                    &outcome,
                    OutboundArtifactOutcome::Failure(source)
                        if matches!(source.as_ref(), OutboundArtifactFailure::PeerMismatch { .. })
                ) {
                    let OutboundArtifactOutcome::Failure(source) = outcome else {
                        unreachable!("the peer-mismatch guard matched a failure")
                    };
                    return Err(ArtifactBlockImportError::ArtifactRequestFailed {
                        peer_id,
                        artifact_id,
                        source,
                    });
                }

                Self::require_current_parent(selected, &block)?;
                if matches!(outcome, OutboundArtifactOutcome::DeadlineExceeded)
                    || request.deadline_expired()
                {
                    return Err(ArtifactBlockImportError::ArtifactDeadlineExceeded {
                        peer_id,
                        artifact_id,
                    });
                }

                match outcome {
                    OutboundArtifactOutcome::Response { response, _permit } => {
                        if response.is_unavailable() {
                            drop(response);
                            drop(_permit);
                            let error = ArtifactBlockImportError::ArtifactUnavailable {
                                peer_id,
                                artifact_id,
                            };
                            let request = retry_artifact_request(request, network, error)?;
                            return Ok(Some(Self {
                                target_block_id,
                                phase: ArtifactBlockImportPhase::Artifact { block, request },
                            }));
                        }

                        request.disarm();
                        let result = selected.apply_block(&block, response.into_wire_bytes());
                        drop(_permit);
                        let _ = result.map_err(ArtifactBlockImportError::selected_state)?;
                        Ok(None)
                    }
                    OutboundArtifactOutcome::Failure(source) => {
                        let error = ArtifactBlockImportError::ArtifactRequestFailed {
                            peer_id,
                            artifact_id,
                            source,
                        };
                        let request = retry_artifact_request(request, network, error)?;
                        Ok(Some(Self {
                            target_block_id,
                            phase: ArtifactBlockImportPhase::Artifact { block, request },
                        }))
                    }
                    OutboundArtifactOutcome::DeadlineExceeded => {
                        unreachable!("the deadline terminal was handled above")
                    }
                }
            }
        }
    }

    pub(super) fn start_from_retained_block(
        network: &mut StaticArtifactNetwork,
        selected: &ArtifactChainJournal,
        peer_id: PeerId,
        target_block_id: ArtifactBlockId,
        block: ArtifactBlock,
    ) -> Result<Self, ArtifactBlockImportError> {
        debug_assert_eq!(block.id(), target_block_id);
        Self::preflight_block(selected, &block)?;
        let request = ArtifactPayloadRequest::start(network, peer_id, block.artifact_id())
            .map_err(|source| match source {
                ArtifactAttemptSelectionError::NoEligiblePeer => {
                    ArtifactBlockImportError::NoEligibleArtifactPeer {
                        artifact_id: block.artifact_id(),
                    }
                }
                ArtifactAttemptSelectionError::RequestStart(source) => {
                    ArtifactBlockImportError::ArtifactRequestStart {
                        artifact_id: block.artifact_id(),
                        source,
                    }
                }
            })?;
        Ok(Self {
            target_block_id,
            phase: ArtifactBlockImportPhase::Artifact { block, request },
        })
    }

    pub(super) fn preflight_block(
        selected: &ArtifactChainJournal,
        block: &ArtifactBlock,
    ) -> Result<(), ArtifactBlockImportError> {
        Self::require_current_parent(selected, block)?;

        let expected_previous = selected
            .artifact_set_root()
            .map_err(ArtifactBlockImportError::selected_state)?;
        let actual_previous = block.previous_artifact_set_root();
        if actual_previous != expected_previous {
            return Err(ArtifactBlockImportError::PreviousArtifactSetRootMismatch {
                expected: expected_previous,
                actual: actual_previous,
            });
        }

        let prepared = selected
            .prepare_block(block.artifact_id())
            .map_err(ArtifactBlockImportError::selected_state)?;
        let expected_resulting = prepared.resulting_artifact_set_root();
        let actual_resulting = block.resulting_artifact_set_root();
        if actual_resulting != expected_resulting {
            return Err(ArtifactBlockImportError::ResultingArtifactSetRootMismatch {
                expected: expected_resulting,
                actual: actual_resulting,
            });
        }

        Ok(())
    }

    fn require_current_parent(
        selected: &ArtifactChainJournal,
        block: &ArtifactBlock,
    ) -> Result<(), ArtifactBlockImportError> {
        let expected = selected
            .head_block_id()
            .map_err(ArtifactBlockImportError::selected_state)?;
        let actual = block.parent_block_id();
        if actual != expected {
            return Err(ArtifactBlockImportError::ParentBlockIdMismatch { expected, actual });
        }
        Ok(())
    }
}

/// Progress for one caller-selected block import event.
pub type ArtifactBlockImportProgress = Option<ArtifactBlockImport>;

/// A fail-closed caller-selected artifact-block import error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockImportError {
    /// The selected journal failed a read, preparation, application, or commit.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The target is the current head, virtual genesis, or a selected block.
    TargetAlreadySelected { block_id: ArtifactBlockId },
    /// The exact target block request could not be started.
    RequestStart {
        block_id: ArtifactBlockId,
        source: RequestStartError,
    },
    /// The supplied event or driver did not belong to this import generation.
    UnexpectedEvent,
    /// The exact target block request failed before yielding a usable response.
    BlockRequestFailed {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
        source: Box<OutboundArtifactBlockFailure>,
    },
    /// The authenticated peer reported no block for the exact target address.
    BlockUnavailable {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
    },
    /// The fetched block did not directly extend the current selected head.
    ParentBlockIdMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The fetched block committed a different selected root before execution.
    PreviousArtifactSetRootMismatch {
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// The fetched block committed a different projected selected root.
    ResultingArtifactSetRootMismatch {
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// No configured, connected, free peer could serve the exact artifact payload.
    NoEligibleArtifactPeer { artifact_id: ArtifactId },
    /// The exact artifact request could not be started.
    ArtifactRequestStart {
        artifact_id: ArtifactId,
        source: RequestStartError,
    },
    /// One authenticated peer's exact artifact request failed.
    ArtifactRequestFailed {
        peer_id: PeerId,
        artifact_id: ArtifactId,
        source: Box<OutboundArtifactFailure>,
    },
    /// Every eligible peer tried so far reported the exact artifact unavailable.
    ArtifactUnavailable {
        peer_id: PeerId,
        artifact_id: ArtifactId,
    },
    /// The absolute single-payload import deadline expired.
    ArtifactDeadlineExceeded {
        peer_id: PeerId,
        artifact_id: ArtifactId,
    },
}

impl ArtifactBlockImportError {
    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for ArtifactBlockImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectedState { source } => {
                write!(
                    formatter,
                    "artifact-block import cannot use selected state: {source}"
                )
            }
            Self::TargetAlreadySelected { block_id } => {
                write!(formatter, "artifact block {block_id:?} is already selected")
            }
            Self::RequestStart { block_id, source } => {
                write!(
                    formatter,
                    "cannot request artifact block {block_id:?}: {source}"
                )
            }
            Self::UnexpectedEvent => formatter
                .write_str("network event or driver does not belong to this artifact-block import"),
            Self::BlockRequestFailed {
                peer_id,
                block_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed artifact-block import request {block_id:?}: {source}"
            ),
            Self::BlockUnavailable { peer_id, block_id } => write!(
                formatter,
                "peer {peer_id} has no artifact block at {block_id:?}"
            ),
            Self::ParentBlockIdMismatch { expected, actual } => write!(
                formatter,
                "artifact block extends parent {actual:?}, expected current head {expected:?}"
            ),
            Self::PreviousArtifactSetRootMismatch { expected, actual } => write!(
                formatter,
                "artifact block starts at artifact-set root {actual:?}, expected {expected:?}"
            ),
            Self::ResultingArtifactSetRootMismatch { expected, actual } => write!(
                formatter,
                "artifact block projects artifact-set root {actual:?}, expected {expected:?}"
            ),
            Self::NoEligibleArtifactPeer { artifact_id } => write!(
                formatter,
                "no configured peer can currently serve block artifact {artifact_id:?}"
            ),
            Self::ArtifactRequestStart {
                artifact_id,
                source,
            } => {
                write!(
                    formatter,
                    "cannot request block artifact {artifact_id:?}: {source}"
                )
            }
            Self::ArtifactRequestFailed {
                peer_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed block artifact request {artifact_id:?}: {source}"
            ),
            Self::ArtifactUnavailable {
                peer_id,
                artifact_id,
            } => write!(
                formatter,
                "peer {peer_id} reported block artifact {artifact_id:?} unavailable"
            ),
            Self::ArtifactDeadlineExceeded {
                peer_id,
                artifact_id,
            } => write!(
                formatter,
                "block artifact import from {peer_id} exceeded {ARTIFACT_BLOCK_IMPORT_TIMEOUT:?} while awaiting {artifact_id:?}"
            ),
        }
    }
}

impl Error for ArtifactBlockImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::RequestStart { source, .. } | Self::ArtifactRequestStart { source, .. } => {
                Some(source)
            }
            Self::BlockRequestFailed { source, .. } => Some(source.as_ref()),
            Self::ArtifactRequestFailed { source, .. } => Some(source.as_ref()),
            Self::TargetAlreadySelected { .. }
            | Self::UnexpectedEvent
            | Self::BlockUnavailable { .. }
            | Self::ParentBlockIdMismatch { .. }
            | Self::PreviousArtifactSetRootMismatch { .. }
            | Self::ResultingArtifactSetRootMismatch { .. }
            | Self::NoEligibleArtifactPeer { .. }
            | Self::ArtifactUnavailable { .. }
            | Self::ArtifactDeadlineExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
