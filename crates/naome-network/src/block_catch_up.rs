//! Caller-selected catch-up to one exact artifact-block target.

use std::error::Error;
use std::fmt;

use naome_chain::ArtifactBlockId;
use naome_storage::ArtifactChainJournal;

use super::{
    ArtifactBlockAncestryImport, ArtifactBlockAncestryImportError, ArtifactBlockAncestryPull,
    ArtifactBlockAncestryPullError, ArtifactBlockAncestryPullProgress, NetworkEvent, PeerId,
    StaticArtifactNetwork,
};

/// One caller-selected exact-target artifact-block catch-up in progress.
///
/// The workflow first retrieves one bounded ancestry from the selected target
/// back to the captured journal head, then consumes that ancestry into the
/// existing forward import. It never selects a target, retries a failed phase,
/// or makes the complete operation atomic across blocks.
#[derive(Debug)]
#[must_use]
pub struct ArtifactBlockCatchUp {
    state: ArtifactBlockCatchUpState,
}

#[derive(Debug)]
// Keeping both lower workflows inline avoids one heap allocation at start and
// another allocation after every consuming phase transition.
#[allow(clippy::large_enum_variant)]
enum ArtifactBlockCatchUpState {
    Pull(ArtifactBlockAncestryPull),
    Import(ArtifactBlockAncestryImport),
}

impl StaticArtifactNetwork {
    /// Starts catching up to one exact caller-selected target from one peer.
    ///
    /// Start delegates the complete selected-state and request precedence to
    /// [`StaticArtifactNetwork::start_artifact_block_ancestry_pull`]. No journal
    /// mutation occurs until the retrieved ancestry enters its import phase.
    pub fn start_artifact_block_catch_up(
        &mut self,
        selected: &ArtifactChainJournal,
        peer_id: PeerId,
        target_block_id: ArtifactBlockId,
    ) -> Result<ArtifactBlockCatchUp, ArtifactBlockCatchUpError> {
        let pull = self
            .start_artifact_block_ancestry_pull(selected, peer_id, target_block_id)
            .map_err(ArtifactBlockCatchUpError::ancestry_pull)?;
        Ok(ArtifactBlockCatchUp {
            state: ArtifactBlockCatchUpState::Pull(pull),
        })
    }
}

impl ArtifactBlockCatchUp {
    /// Returns the selected head captured when ancestry retrieval started.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        match &self.state {
            ArtifactBlockCatchUpState::Pull(pull) => pull.anchor_block_id(),
            ArtifactBlockCatchUpState::Import(import) => import.anchor_block_id(),
        }
    }

    /// Returns the exact target identity selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        match &self.state {
            ArtifactBlockCatchUpState::Pull(pull) => pull.target_block_id(),
            ArtifactBlockCatchUpState::Import(import) => import.target_block_id(),
        }
    }

    /// Returns the exact block currently being retrieved or imported.
    pub const fn pending_block_id(&self) -> ArtifactBlockId {
        match &self.state {
            ArtifactBlockCatchUpState::Pull(pull) => pull.pending_block_id(),
            ArtifactBlockCatchUpState::Import(import) => import.pending_block_id(),
        }
    }

    /// Returns the peer serving the active block or artifact request.
    ///
    /// During exact artifact-payload retrieval this may differ from the ancestry
    /// source after a bounded retry.
    pub const fn pending_peer_id(&self) -> PeerId {
        match &self.state {
            ArtifactBlockCatchUpState::Pull(pull) => pull.pending_peer_id(),
            ArtifactBlockCatchUpState::Import(import) => import.pending_peer_id(),
        }
    }

    /// Returns the number of blocks durably acknowledged by this catch-up.
    pub const fn committed_block_count(&self) -> usize {
        match &self.state {
            ArtifactBlockCatchUpState::Pull(_) => 0,
            ArtifactBlockCatchUpState::Import(import) => import.committed_block_count(),
        }
    }

    /// Returns the last head whose commit this catch-up observed succeeding.
    pub const fn last_acknowledged_head_block_id(&self) -> ArtifactBlockId {
        match &self.state {
            ArtifactBlockCatchUpState::Pull(pull) => pull.anchor_block_id(),
            ArtifactBlockCatchUpState::Import(import) => import.last_acknowledged_head_block_id(),
        }
    }

    /// Returns whether `event` is the exact terminal awaited by this catch-up.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        match &self.state {
            ArtifactBlockCatchUpState::Pull(pull) => pull.accepts_event(event),
            ArtifactBlockCatchUpState::Import(import) => import.accepts_event(event),
        }
    }

    /// Cancels the active phase without rolling back an acknowledged prefix.
    ///
    /// The physical request retains the lower workflow's existing drain
    /// semantics. No later block or retry is started.
    pub fn cancel(self) {}

    /// Advances the active phase with its exact correlated network terminal.
    ///
    /// Completing the pull consumes its opaque ancestry directly into the
    /// import phase in this same call. `None` is returned only after the exact
    /// target has been durably acknowledged. Earlier acknowledged blocks
    /// remain selected if a later import step fails.
    pub fn on_event(
        self,
        network: &mut StaticArtifactNetwork,
        selected: &mut ArtifactChainJournal,
        event: NetworkEvent,
    ) -> Result<ArtifactBlockCatchUpProgress, ArtifactBlockCatchUpError> {
        match self.state {
            ArtifactBlockCatchUpState::Pull(pull) => {
                match pull
                    .on_event(network, selected, event)
                    .map_err(ArtifactBlockCatchUpError::ancestry_pull)?
                {
                    ArtifactBlockAncestryPullProgress::AwaitingResponse(pull) => {
                        Ok(Some(ArtifactBlockCatchUp {
                            state: ArtifactBlockCatchUpState::Pull(pull),
                        }))
                    }
                    ArtifactBlockAncestryPullProgress::Complete(ancestry) => {
                        let import = network
                            .start_artifact_block_ancestry_import(selected, ancestry)
                            .map_err(ArtifactBlockCatchUpError::ancestry_import)?;
                        Ok(Some(ArtifactBlockCatchUp {
                            state: ArtifactBlockCatchUpState::Import(import),
                        }))
                    }
                }
            }
            ArtifactBlockCatchUpState::Import(import) => import
                .on_event(network, selected, event)
                .map(|progress| {
                    progress.map(|import| ArtifactBlockCatchUp {
                        state: ArtifactBlockCatchUpState::Import(import),
                    })
                })
                .map_err(ArtifactBlockCatchUpError::ancestry_import),
        }
    }
}

/// Allocation-free progress after one exact catch-up terminal.
///
/// `Some(catch_up)` means one block or artifact request remains active. `None`
/// means the exact caller-selected target was durably acknowledged.
pub type ArtifactBlockCatchUpProgress = Option<ArtifactBlockCatchUp>;

/// One fail-closed catch-up failure from its exact lower workflow.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockCatchUpError {
    /// Ancestry retrieval failed before any catch-up block was committed.
    AncestryPull {
        source: Box<ArtifactBlockAncestryPullError>,
    },
    /// Ancestry import failed with its exact acknowledged-prefix metadata.
    AncestryImport {
        source: Box<ArtifactBlockAncestryImportError>,
    },
}

impl ArtifactBlockCatchUpError {
    fn ancestry_pull(source: ArtifactBlockAncestryPullError) -> Self {
        Self::AncestryPull {
            source: Box::new(source),
        }
    }

    fn ancestry_import(source: ArtifactBlockAncestryImportError) -> Self {
        Self::AncestryImport {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for ArtifactBlockCatchUpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AncestryPull { source } => {
                write!(
                    formatter,
                    "artifact-block catch-up ancestry retrieval failed: {source}"
                )
            }
            Self::AncestryImport { source } => {
                write!(
                    formatter,
                    "artifact-block catch-up ancestry import failed: {source}"
                )
            }
        }
    }
}

impl Error for ArtifactBlockCatchUpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AncestryPull { source } => Some(source.as_ref()),
            Self::AncestryImport { source } => Some(source.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests;
