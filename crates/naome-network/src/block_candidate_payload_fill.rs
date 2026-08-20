//! Caller-selected validation and archival of one retained candidate payload.

use std::error::Error;
use std::fmt;

use naome_chain::{ArtifactBlock, ArtifactBlockId, ArtifactChainId, ArtifactSetRoot};
use naome_proof::ArtifactId;
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, ArtifactChainJournal,
    ArtifactChainJournalError, CandidatePayloadArchiveError, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
};

use super::block_import::{ArtifactBlockImport, ArtifactBlockImportError, ArtifactPayloadRequest};
use super::{
    ARTIFACT_BLOCK_IMPORT_TIMEOUT, NetworkEvent, OutboundArtifactEvent, OutboundArtifactFailure,
    OutboundArtifactOutcome, PeerId, RequestStartError, StaticArtifactNetwork,
    selected_context_contains_block,
};

/// One exact retained candidate payload request in progress.
///
/// The caller supplies the candidate identity and authenticated peer. This
/// workflow exclusively binds one payload store until its exact request ends,
/// then validates and archives the returned bytes without selecting the block
/// or mutating the selected journal.
#[must_use]
pub struct ArtifactBlockCandidatePayloadFill<'store> {
    payloads: &'store mut CanonicalArtifactPayloadStore,
    target_block_id: ArtifactBlockId,
    block: ArtifactBlock,
    request: ArtifactPayloadRequest,
}

impl fmt::Debug for ArtifactBlockCandidatePayloadFill<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactBlockCandidatePayloadFill")
            .field("anchor_block_id", &self.block.parent_block_id())
            .field("target_block_id", &self.target_block_id)
            .field("pending_peer_id", &self.pending_peer_id())
            .finish_non_exhaustive()
    }
}

impl StaticArtifactNetwork {
    /// Starts filling the exact payload of one retained direct-child candidate.
    ///
    /// An already archived payload is integrity-read and fully revalidated
    /// before this returns `None`. Only an archive miss consults `peer_id` and
    /// returns a request workflow in `Some`.
    pub fn start_artifact_block_candidate_payload_fill<'store>(
        &mut self,
        selected: &ArtifactChainJournal,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &'store mut CanonicalArtifactPayloadStore,
        peer_id: PeerId,
        target_block_id: ArtifactBlockId,
    ) -> Result<
        Option<ArtifactBlockCandidatePayloadFill<'store>>,
        ArtifactBlockCandidatePayloadFillError,
    > {
        let selected_chain_id = selected.chain_id();
        let candidate_chain_id = candidates.chain_id();
        if selected_chain_id != candidate_chain_id {
            return Err(ArtifactBlockCandidatePayloadFillError::ChainIdMismatch {
                selected: selected_chain_id,
                candidates: candidate_chain_id,
            });
        }

        let anchor_block_id = selected
            .head_block_id()
            .map_err(ArtifactBlockCandidatePayloadFillError::selected_state)?;
        let virtual_genesis = selected.chain_id().virtual_genesis_block_id();
        if selected_context_contains_block(
            selected,
            anchor_block_id,
            virtual_genesis,
            target_block_id,
        )
        .map_err(ArtifactBlockCandidatePayloadFillError::selected_state)?
        {
            return Err(
                ArtifactBlockCandidatePayloadFillError::TargetAlreadySelected {
                    block_id: target_block_id,
                },
            );
        }

        let block = candidates
            .get(target_block_id)
            .map_err(
                |source| ArtifactBlockCandidatePayloadFillError::CandidateStoreRead {
                    block_id: target_block_id,
                    source: Box::new(source),
                },
            )?
            .ok_or(
                ArtifactBlockCandidatePayloadFillError::CandidateNotRetained {
                    block_id: target_block_id,
                },
            )?;
        debug_assert_eq!(block.id(), target_block_id);
        ArtifactBlockImport::preflight_block(selected, &block)
            .map_err(ArtifactBlockCandidatePayloadFillError::from_preflight)?;

        let artifact_id = block.artifact_id();
        if let Some(payload) = payloads.get(artifact_id).map_err(|source| {
            ArtifactBlockCandidatePayloadFillError::PayloadStoreRead {
                artifact_id,
                source: Box::new(source),
            }
        })? {
            let _ = payloads
                .validate_and_insert_candidate_payload(
                    selected,
                    &block,
                    payload.into_canonical_artifact_bytes().into_vec(),
                )
                .map_err(
                    |source| ArtifactBlockCandidatePayloadFillError::CandidateArchive {
                        artifact_id,
                        source: Box::new(source),
                    },
                )?;
            return Ok(None);
        }

        let request =
            ArtifactPayloadRequest::start_direct(self, peer_id, artifact_id).map_err(|source| {
                ArtifactBlockCandidatePayloadFillError::RequestStart {
                    peer_id,
                    artifact_id,
                    source: Box::new(source),
                }
            })?;
        Ok(Some(ArtifactBlockCandidatePayloadFill {
            payloads,
            target_block_id,
            block,
            request,
        }))
    }
}

impl ArtifactBlockCandidatePayloadFill<'_> {
    /// Returns the exact retained candidate selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the authenticated peer serving the pending exact payload.
    pub const fn pending_peer_id(&self) -> PeerId {
        self.request.peer_id()
    }

    /// Returns whether `event` is the exact terminal awaited by this fill.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        matches!(event, NetworkEvent::OutboundArtifact(event) if self.request.accepts_event(event))
    }

    /// Cancels the pending exact payload request.
    pub fn cancel(self) {}

    /// Consumes the exact terminal, then validates and archives found bytes.
    pub fn on_event(
        self,
        network: &mut StaticArtifactNetwork,
        selected: &ArtifactChainJournal,
        event: NetworkEvent,
    ) -> Result<(), ArtifactBlockCandidatePayloadFillError> {
        if !self.accepts_event(&event) {
            return Err(ArtifactBlockCandidatePayloadFillError::UnexpectedEvent);
        }

        let Self {
            payloads,
            target_block_id: _,
            block,
            mut request,
        } = self;
        if !request.belongs_to_network(network) {
            return Err(ArtifactBlockCandidatePayloadFillError::UnexpectedEvent);
        }
        let NetworkEvent::OutboundArtifact(OutboundArtifactEvent {
            peer_id, outcome, ..
        }) = event
        else {
            unreachable!("the accepted payload-fill event is an outbound artifact terminal")
        };
        let artifact_id = block.artifact_id();

        if matches!(
            &outcome,
            OutboundArtifactOutcome::Failure(source)
                if matches!(source.as_ref(), OutboundArtifactFailure::PeerMismatch { .. })
        ) {
            let OutboundArtifactOutcome::Failure(source) = outcome else {
                unreachable!("the peer-mismatch guard matched a failure")
            };
            return Err(
                ArtifactBlockCandidatePayloadFillError::ArtifactRequestFailed {
                    peer_id,
                    artifact_id,
                    source,
                },
            );
        }

        let expected_head = block.parent_block_id();
        let actual_head = selected
            .head_block_id()
            .map_err(ArtifactBlockCandidatePayloadFillError::selected_state)?;
        if actual_head != expected_head {
            return Err(
                ArtifactBlockCandidatePayloadFillError::SelectedHeadChanged {
                    expected: expected_head,
                    actual: actual_head,
                },
            );
        }
        if matches!(outcome, OutboundArtifactOutcome::DeadlineExceeded)
            || request.deadline_expired()
        {
            return Err(
                ArtifactBlockCandidatePayloadFillError::ArtifactDeadlineExceeded {
                    peer_id,
                    artifact_id,
                },
            );
        }

        match outcome {
            OutboundArtifactOutcome::Response { response, _permit } => {
                if response.is_unavailable() {
                    return Err(
                        ArtifactBlockCandidatePayloadFillError::ArtifactUnavailable {
                            peer_id,
                            artifact_id,
                        },
                    );
                }

                request.disarm();
                let result = payloads.validate_and_insert_candidate_payload(
                    selected,
                    &block,
                    response.into_wire_bytes(),
                );
                drop(_permit);
                let _ = result.map_err(|source| {
                    ArtifactBlockCandidatePayloadFillError::CandidateArchive {
                        artifact_id,
                        source: Box::new(source),
                    }
                })?;
                Ok(())
            }
            OutboundArtifactOutcome::Failure(source) => Err(
                ArtifactBlockCandidatePayloadFillError::ArtifactRequestFailed {
                    peer_id,
                    artifact_id,
                    source,
                },
            ),
            OutboundArtifactOutcome::DeadlineExceeded => {
                unreachable!("the deadline terminal was handled above")
            }
        }
    }
}

/// A fail-closed retained-candidate payload fill error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockCandidatePayloadFillError {
    /// The selected journal and candidate store use different chain contexts.
    ChainIdMismatch {
        selected: ArtifactChainId,
        candidates: ArtifactChainId,
    },
    /// The selected journal failed a required read or candidate validation.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The target is the current head, virtual genesis, or a selected block.
    TargetAlreadySelected { block_id: ArtifactBlockId },
    /// The exact candidate store read failed.
    CandidateStoreRead {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
    /// The exact target block is not retained as a candidate.
    CandidateNotRetained { block_id: ArtifactBlockId },
    /// The candidate did not directly extend the captured selected head.
    ParentBlockIdMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The candidate committed a different selected root before execution.
    PreviousArtifactSetRootMismatch {
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// The candidate committed a different projected selected root.
    ResultingArtifactSetRootMismatch {
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// The exact payload archive integrity read failed.
    PayloadStoreRead {
        artifact_id: ArtifactId,
        source: Box<CanonicalArtifactPayloadStoreError>,
    },
    /// The exact caller-selected peer request could not be started.
    RequestStart {
        peer_id: PeerId,
        artifact_id: ArtifactId,
        source: Box<RequestStartError>,
    },
    /// The supplied event or driver did not belong to this fill generation.
    UnexpectedEvent,
    /// The selected head changed after the request started.
    SelectedHeadChanged {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The exact artifact request failed before yielding a usable response.
    ArtifactRequestFailed {
        peer_id: PeerId,
        artifact_id: ArtifactId,
        source: Box<OutboundArtifactFailure>,
    },
    /// The authenticated peer reported no payload for the exact address.
    ArtifactUnavailable {
        peer_id: PeerId,
        artifact_id: ArtifactId,
    },
    /// The absolute single-payload deadline expired.
    ArtifactDeadlineExceeded {
        peer_id: PeerId,
        artifact_id: ArtifactId,
    },
    /// Exact bytes failed validation or durable archive.
    CandidateArchive {
        artifact_id: ArtifactId,
        source: Box<CandidatePayloadArchiveError>,
    },
}

impl ArtifactBlockCandidatePayloadFillError {
    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }

    fn from_preflight(source: ArtifactBlockImportError) -> Self {
        match source {
            ArtifactBlockImportError::SelectedState { source } => Self::SelectedState { source },
            ArtifactBlockImportError::ParentBlockIdMismatch { expected, actual } => {
                Self::ParentBlockIdMismatch { expected, actual }
            }
            ArtifactBlockImportError::PreviousArtifactSetRootMismatch { expected, actual } => {
                Self::PreviousArtifactSetRootMismatch { expected, actual }
            }
            ArtifactBlockImportError::ResultingArtifactSetRootMismatch { expected, actual } => {
                Self::ResultingArtifactSetRootMismatch { expected, actual }
            }
            _ => unreachable!("candidate preflight emits only selected-state and shape errors"),
        }
    }
}

impl fmt::Display for ArtifactBlockCandidatePayloadFillError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainIdMismatch {
                selected,
                candidates,
            } => write!(
                formatter,
                "selected chain {selected:?} does not match candidate store {candidates:?}"
            ),
            Self::SelectedState { source } => {
                write!(
                    formatter,
                    "candidate payload fill cannot use selected state: {source}"
                )
            }
            Self::TargetAlreadySelected { block_id } => {
                write!(formatter, "artifact block {block_id:?} is already selected")
            }
            Self::CandidateStoreRead { block_id, source } => write!(
                formatter,
                "cannot read candidate artifact block {block_id:?}: {source}"
            ),
            Self::CandidateNotRetained { block_id } => {
                write!(
                    formatter,
                    "artifact block candidate {block_id:?} is not retained"
                )
            }
            Self::ParentBlockIdMismatch { expected, actual } => write!(
                formatter,
                "artifact block candidate extends parent {actual:?}, expected current head {expected:?}"
            ),
            Self::PreviousArtifactSetRootMismatch { expected, actual } => write!(
                formatter,
                "artifact block candidate starts at artifact-set root {actual:?}, expected {expected:?}"
            ),
            Self::ResultingArtifactSetRootMismatch { expected, actual } => write!(
                formatter,
                "artifact block candidate projects artifact-set root {actual:?}, expected {expected:?}"
            ),
            Self::PayloadStoreRead {
                artifact_id,
                source,
            } => write!(
                formatter,
                "cannot read candidate artifact payload {artifact_id:?}: {source}"
            ),
            Self::RequestStart {
                peer_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "cannot request candidate artifact {artifact_id:?} from {peer_id}: {source}"
            ),
            Self::UnexpectedEvent => formatter.write_str(
                "network event or driver does not belong to this candidate payload fill",
            ),
            Self::SelectedHeadChanged { expected, actual } => write!(
                formatter,
                "selected head changed from {expected:?} to {actual:?} during candidate payload fill"
            ),
            Self::ArtifactRequestFailed {
                peer_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed candidate artifact request {artifact_id:?}: {source}"
            ),
            Self::ArtifactUnavailable {
                peer_id,
                artifact_id,
            } => write!(
                formatter,
                "peer {peer_id} reported candidate artifact {artifact_id:?} unavailable"
            ),
            Self::ArtifactDeadlineExceeded {
                peer_id,
                artifact_id,
            } => write!(
                formatter,
                "candidate artifact request from {peer_id} exceeded {ARTIFACT_BLOCK_IMPORT_TIMEOUT:?} while awaiting {artifact_id:?}"
            ),
            Self::CandidateArchive {
                artifact_id,
                source,
            } => write!(
                formatter,
                "candidate artifact {artifact_id:?} failed validation or archive: {source}"
            ),
        }
    }
}

impl Error for ArtifactBlockCandidatePayloadFillError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::CandidateStoreRead { source, .. } => Some(source.as_ref()),
            Self::PayloadStoreRead { source, .. } => Some(source.as_ref()),
            Self::RequestStart { source, .. } => Some(source.as_ref()),
            Self::ArtifactRequestFailed { source, .. } => Some(source.as_ref()),
            Self::CandidateArchive { source, .. } => Some(source.as_ref()),
            Self::ChainIdMismatch { .. }
            | Self::TargetAlreadySelected { .. }
            | Self::CandidateNotRetained { .. }
            | Self::ParentBlockIdMismatch { .. }
            | Self::PreviousArtifactSetRootMismatch { .. }
            | Self::ResultingArtifactSetRootMismatch { .. }
            | Self::UnexpectedEvent
            | Self::SelectedHeadChanged { .. }
            | Self::ArtifactUnavailable { .. }
            | Self::ArtifactDeadlineExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
