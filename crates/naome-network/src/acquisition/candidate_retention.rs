//! Exact correlated block response retention into an unselected candidate store.

use crate::{
    ArtifactBlockRequestEventMismatch, BlockRequestTicket, OutboundArtifactBlockEvent,
    OutboundArtifactBlockFailure, PeerId,
};
use naome_chain::ArtifactBlockId;
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError,
};
use std::{error::Error, fmt};

impl BlockRequestTicket {
    /// Consumes this ticket and durably retains its exact found block as an
    /// unselected structural candidate.
    ///
    /// A mismatched terminal preserves both routable values and never accesses
    /// `store`. A matched transport failure or `Unavailable` response also
    /// performs no insertion. Success is returned only after the candidate
    /// store acknowledges an insert or exact idempotent replay.
    pub fn complete_into_candidate_store(
        self,
        event: OutboundArtifactBlockEvent,
        store: &mut ArtifactBlockCandidateStore,
    ) -> Result<
        Result<ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateRetentionError>,
        Box<ArtifactBlockRequestEventMismatch>,
    > {
        let peer_id = self.peer_id();
        let block_id = self.request().block_id();
        let response = match self.complete(event)? {
            Ok(response) => response,
            Err(source) => {
                return Ok(Err(ArtifactBlockCandidateRetentionError::RequestFailed {
                    peer_id,
                    block_id,
                    source,
                }));
            }
        };
        let Some(block) = response.into_block() else {
            return Ok(Err(
                ArtifactBlockCandidateRetentionError::BlockUnavailable { peer_id, block_id },
            ));
        };
        Ok(store.insert(&block).map_err(|source| {
            ArtifactBlockCandidateRetentionError::CandidateStore {
                block_id,
                source: Box::new(source),
            }
        }))
    }
}

/// Failure to retain one exact authenticated artifact-block response.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockCandidateRetentionError {
    /// The matched request failed before yielding a usable response.
    RequestFailed {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
        source: Box<OutboundArtifactBlockFailure>,
    },
    /// The authenticated peer reported no block for the exact address.
    BlockUnavailable {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
    },
    /// The exact found block could not be durably retained.
    CandidateStore {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
}

impl fmt::Display for ArtifactBlockCandidateRetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestFailed {
                peer_id,
                block_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed artifact-block candidate request {block_id:?}: {source}"
            ),
            Self::BlockUnavailable { peer_id, block_id } => write!(
                formatter,
                "peer {peer_id} has no artifact-block candidate at {block_id:?}"
            ),
            Self::CandidateStore { block_id, source } => write!(
                formatter,
                "cannot retain artifact-block candidate {block_id:?}: {source}"
            ),
        }
    }
}

impl Error for ArtifactBlockCandidateRetentionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RequestFailed { source, .. } => Some(source.as_ref()),
            Self::CandidateStore { source, .. } => Some(source.as_ref()),
            Self::BlockUnavailable { .. } => None,
        }
    }
}
