//! Network-assisted reconstruction of one retained candidate branch.

use std::error::Error;
use std::fmt;

use naome_chain::ArtifactBlockId;
use naome_proof::ArtifactId;
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactChainJournal, CandidateBranchReconstructionCursor,
    CandidateBranchReconstructionError, CandidateBranchReconstructionLimits,
    CandidateBranchReconstructionProgress, CanonicalArtifactPayloadStore,
    ReconstructedCandidateBranch,
};

use super::block_import::ArtifactPayloadRequest;
use super::{
    ARTIFACT_BLOCK_IMPORT_TIMEOUT, NetworkEvent, OutboundArtifactEvent, OutboundArtifactFailure,
    OutboundArtifactOutcome, PeerId, RequestStartError, StaticArtifactNetwork,
};

/// Current result of one network-assisted candidate-branch reconstruction.
///
/// Only a complete result exposes a branch snapshot. The awaiting variant owns
/// opaque reconstruction progress and one exact authenticated payload request.
#[must_use]
#[derive(Debug)]
pub enum ArtifactBlockCandidateBranchPayloadFillProgress<'store> {
    /// One exact committed payload is awaiting its correlated terminal.
    AwaitingResponse(ArtifactBlockCandidateBranchPayloadFill<'store>),
    /// Every retained candidate block and payload passed strict validation.
    Complete(ReconstructedCandidateBranch),
}

/// One exact candidate-branch payload request in progress.
///
/// The workflow exclusively borrows one payload archive until its active
/// request ends. Each found payload is strictly validated and durably archived
/// before the workflow advances. Dropping the workflow exposes no partial
/// snapshot; a fresh start can rediscover any acknowledged durable prefix.
#[must_use]
pub struct ArtifactBlockCandidateBranchPayloadFill<'store> {
    reconstruction: Box<CandidateBranchReconstructionCursor<'store>>,
    request: ArtifactPayloadRequest,
}

impl fmt::Debug for ArtifactBlockCandidateBranchPayloadFill<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactBlockCandidateBranchPayloadFill")
            .field("target_block_id", &self.target_block_id())
            .field("pending_block_id", &self.pending_block_id())
            .field("pending_artifact_id", &self.pending_artifact_id())
            .field("pending_peer_id", &self.pending_peer_id())
            .finish_non_exhaustive()
    }
}

impl StaticArtifactNetwork {
    /// Starts or resumes network-assisted reconstruction of one retained branch.
    ///
    /// The caller chooses the exact candidate tip, positive local work bound,
    /// payload archive, and one authenticated peer. The complete candidate path
    /// is shape-checked to the nearest selected ancestor before any request or
    /// write. Healthy archive hits are integrity-read and fully revalidated; a
    /// fully retained branch completes synchronously without inspecting
    /// `payload_peer_id`.
    ///
    /// An archive miss requests only its exact committed [`ArtifactId`] from the
    /// supplied peer, with no peer fallback or retry. Reconstruction continues
    /// from the immutable selected snapshot captured here even if the live
    /// journal later advances. This method never mutates candidates or selected
    /// state and grants no selection, consensus, finality, availability, or
    /// peer-trust authority.
    pub fn start_artifact_block_candidate_branch_payload_fill<'store>(
        &mut self,
        selected: &ArtifactChainJournal,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &'store mut CanonicalArtifactPayloadStore,
        payload_peer_id: PeerId,
        target_block_id: ArtifactBlockId,
        limits: CandidateBranchReconstructionLimits,
    ) -> Result<
        ArtifactBlockCandidateBranchPayloadFillProgress<'store>,
        ArtifactBlockCandidateBranchPayloadFillError,
    > {
        let reconstruction = selected
            .start_candidate_branch_reconstruction(target_block_id, candidates, payloads, limits)
            .map_err(ArtifactBlockCandidateBranchPayloadFillError::reconstruction)?;
        ArtifactBlockCandidateBranchPayloadFill::advance(self, payload_peer_id, reconstruction)
    }
}

impl<'store> ArtifactBlockCandidateBranchPayloadFill<'store> {
    fn advance(
        network: &mut StaticArtifactNetwork,
        payload_peer_id: PeerId,
        reconstruction: CandidateBranchReconstructionProgress<'store>,
    ) -> Result<
        ArtifactBlockCandidateBranchPayloadFillProgress<'store>,
        ArtifactBlockCandidateBranchPayloadFillError,
    > {
        match reconstruction {
            CandidateBranchReconstructionProgress::Complete(reconstructed) => Ok(
                ArtifactBlockCandidateBranchPayloadFillProgress::Complete(reconstructed),
            ),
            CandidateBranchReconstructionProgress::AwaitingPayload(reconstruction) => {
                let block_id = reconstruction.pending_block_id();
                let artifact_id = reconstruction.pending_artifact_id();
                let request =
                    ArtifactPayloadRequest::start_direct(network, payload_peer_id, artifact_id)
                        .map_err(|source| {
                            ArtifactBlockCandidateBranchPayloadFillError::RequestStart {
                                peer_id: Box::new(payload_peer_id),
                                block_id,
                                artifact_id,
                                source: Box::new(source),
                            }
                        })?;
                Ok(
                    ArtifactBlockCandidateBranchPayloadFillProgress::AwaitingResponse(Self {
                        reconstruction: Box::new(reconstruction),
                        request,
                    }),
                )
            }
        }
    }

    /// Returns the exact candidate tip selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.reconstruction.target_block_id()
    }

    /// Returns the exact candidate block awaiting its committed payload.
    pub fn pending_block_id(&self) -> ArtifactBlockId {
        self.reconstruction.pending_block_id()
    }

    /// Returns the exact committed payload address awaited by this request.
    pub fn pending_artifact_id(&self) -> ArtifactId {
        self.reconstruction.pending_artifact_id()
    }

    /// Returns the authenticated peer expected to serve the active request.
    pub const fn pending_peer_id(&self) -> PeerId {
        self.request.peer_id()
    }

    /// Returns whether `event` is the exact terminal awaited by this workflow.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        matches!(event, NetworkEvent::OutboundArtifact(event) if self.request.accepts_event(event))
    }

    /// Cancels the active request and releases the exclusive payload-store borrow.
    ///
    /// Already acknowledged archives remain durable. The physical libp2p
    /// request slot drains through the network event loop.
    pub fn cancel(self) {}

    /// Advances reconstruction with its exact correlated payload terminal.
    ///
    /// Found bytes are strictly validated and durably archived before any next
    /// request is started. Failure returns no partial branch snapshot.
    pub fn on_event(
        self,
        network: &mut StaticArtifactNetwork,
        event: NetworkEvent,
    ) -> Result<
        ArtifactBlockCandidateBranchPayloadFillProgress<'store>,
        ArtifactBlockCandidateBranchPayloadFillError,
    > {
        if !self.accepts_event(&event) {
            return Err(ArtifactBlockCandidateBranchPayloadFillError::UnexpectedEvent);
        }

        let Self {
            reconstruction,
            mut request,
        } = self;
        if !request.belongs_to_network(network) {
            return Err(ArtifactBlockCandidateBranchPayloadFillError::UnexpectedEvent);
        }
        let NetworkEvent::OutboundArtifact(OutboundArtifactEvent {
            peer_id, outcome, ..
        }) = event
        else {
            unreachable!("an accepted branch payload event is an outbound artifact terminal")
        };
        let block_id = reconstruction.pending_block_id();
        let artifact_id = reconstruction.pending_artifact_id();

        if matches!(
            &outcome,
            OutboundArtifactOutcome::Failure(source)
                if matches!(source.as_ref(), OutboundArtifactFailure::PeerMismatch { .. })
        ) {
            let OutboundArtifactOutcome::Failure(source) = outcome else {
                unreachable!("the peer-mismatch guard matched a failure")
            };
            return Err(
                ArtifactBlockCandidateBranchPayloadFillError::ArtifactRequestFailed {
                    peer_id: Box::new(peer_id),
                    block_id,
                    artifact_id,
                    source,
                },
            );
        }

        if matches!(outcome, OutboundArtifactOutcome::DeadlineExceeded)
            || request.deadline_expired()
        {
            return Err(
                ArtifactBlockCandidateBranchPayloadFillError::ArtifactDeadlineExceeded {
                    peer_id: Box::new(peer_id),
                    block_id,
                    artifact_id,
                },
            );
        }

        match outcome {
            OutboundArtifactOutcome::Response { response, _permit } => {
                if response.is_unavailable() {
                    return Err(
                        ArtifactBlockCandidateBranchPayloadFillError::ArtifactUnavailable {
                            peer_id: Box::new(peer_id),
                            block_id,
                            artifact_id,
                        },
                    );
                }

                request.disarm();
                let reconstruction = (*reconstruction)
                    .validate_and_archive_pending_payload(response.into_wire_bytes());
                drop(_permit);
                let reconstruction = reconstruction
                    .map_err(ArtifactBlockCandidateBranchPayloadFillError::reconstruction)?;
                Self::advance(network, peer_id, reconstruction)
            }
            OutboundArtifactOutcome::Failure(source) => Err(
                ArtifactBlockCandidateBranchPayloadFillError::ArtifactRequestFailed {
                    peer_id: Box::new(peer_id),
                    block_id,
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

/// A fail-closed network-assisted candidate-branch reconstruction error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockCandidateBranchPayloadFillError {
    /// Local path discovery, strict validation, or durable archive failed.
    Reconstruction {
        source: Box<CandidateBranchReconstructionError>,
    },
    /// The exact caller-selected peer request could not be started.
    RequestStart {
        peer_id: Box<PeerId>,
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        source: Box<RequestStartError>,
    },
    /// The supplied event or network driver did not belong to this generation.
    UnexpectedEvent,
    /// The exact artifact request failed before yielding a usable response.
    ArtifactRequestFailed {
        peer_id: Box<PeerId>,
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        source: Box<OutboundArtifactFailure>,
    },
    /// The authenticated peer reported no payload for the exact address.
    ArtifactUnavailable {
        peer_id: Box<PeerId>,
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
    },
    /// The absolute single-payload deadline expired.
    ArtifactDeadlineExceeded {
        peer_id: Box<PeerId>,
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
    },
}

impl ArtifactBlockCandidateBranchPayloadFillError {
    fn reconstruction(source: CandidateBranchReconstructionError) -> Self {
        Self::Reconstruction {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for ArtifactBlockCandidateBranchPayloadFillError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reconstruction { source } => {
                write!(
                    formatter,
                    "candidate branch reconstruction failed: {source}"
                )
            }
            Self::RequestStart {
                peer_id,
                block_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "cannot request candidate branch block {block_id:?} payload {artifact_id:?} from {peer_id}: {source}"
            ),
            Self::UnexpectedEvent => formatter.write_str(
                "network event or driver does not belong to this candidate branch payload fill",
            ),
            Self::ArtifactRequestFailed {
                peer_id,
                block_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed candidate branch block {block_id:?} payload request {artifact_id:?}: {source}"
            ),
            Self::ArtifactUnavailable {
                peer_id,
                block_id,
                artifact_id,
            } => write!(
                formatter,
                "peer {peer_id} reported candidate branch block {block_id:?} payload {artifact_id:?} unavailable"
            ),
            Self::ArtifactDeadlineExceeded {
                peer_id,
                block_id,
                artifact_id,
            } => write!(
                formatter,
                "candidate branch payload request from {peer_id} exceeded {ARTIFACT_BLOCK_IMPORT_TIMEOUT:?} while awaiting block {block_id:?} payload {artifact_id:?}"
            ),
        }
    }
}

impl Error for ArtifactBlockCandidateBranchPayloadFillError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Reconstruction { source } => Some(source.as_ref()),
            Self::RequestStart { source, .. } => Some(source.as_ref()),
            Self::ArtifactRequestFailed { source, .. } => Some(source.as_ref()),
            Self::UnexpectedEvent
            | Self::ArtifactUnavailable { .. }
            | Self::ArtifactDeadlineExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
