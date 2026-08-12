//! Caller-selected catch-up to one exact proof-block target.

use std::error::Error;
use std::fmt;

use naome_chain::ProofBlockId;
use naome_storage::ProofChainJournal;

use super::{
    NetworkEvent, PeerId, ProofBlockAncestryImport, ProofBlockAncestryImportError,
    ProofBlockAncestryPull, ProofBlockAncestryPullError, ProofBlockAncestryPullProgress,
    StaticProofNetwork,
};

/// One caller-selected exact-target proof-block catch-up in progress.
///
/// The workflow first retrieves one bounded ancestry from the selected target
/// back to the captured journal head, then consumes that ancestry into the
/// existing forward import. It never selects a target, retries a failed phase,
/// or makes the complete operation atomic across blocks.
#[derive(Debug)]
#[must_use]
pub struct ProofBlockCatchUp {
    state: ProofBlockCatchUpState,
}

#[derive(Debug)]
// Keeping both lower workflows inline avoids one heap allocation at start and
// another allocation after every consuming phase transition.
#[allow(clippy::large_enum_variant)]
enum ProofBlockCatchUpState {
    Pull(ProofBlockAncestryPull),
    Import(ProofBlockAncestryImport),
}

impl StaticProofNetwork {
    /// Starts catching up to one exact caller-selected target from one peer.
    ///
    /// Start delegates the complete selected-state and request precedence to
    /// [`StaticProofNetwork::start_proof_block_ancestry_pull`]. No journal
    /// mutation occurs until the retrieved ancestry enters its import phase.
    pub fn start_proof_block_catch_up(
        &mut self,
        selected: &ProofChainJournal,
        peer_id: PeerId,
        target_block_id: ProofBlockId,
    ) -> Result<ProofBlockCatchUp, ProofBlockCatchUpError> {
        let pull = self
            .start_proof_block_ancestry_pull(selected, peer_id, target_block_id)
            .map_err(ProofBlockCatchUpError::ancestry_pull)?;
        Ok(ProofBlockCatchUp {
            state: ProofBlockCatchUpState::Pull(pull),
        })
    }
}

impl ProofBlockCatchUp {
    /// Returns the selected head captured when ancestry retrieval started.
    pub const fn anchor_block_id(&self) -> ProofBlockId {
        match &self.state {
            ProofBlockCatchUpState::Pull(pull) => pull.anchor_block_id(),
            ProofBlockCatchUpState::Import(import) => import.anchor_block_id(),
        }
    }

    /// Returns the exact target identity selected by the caller.
    pub const fn target_block_id(&self) -> ProofBlockId {
        match &self.state {
            ProofBlockCatchUpState::Pull(pull) => pull.target_block_id(),
            ProofBlockCatchUpState::Import(import) => import.target_block_id(),
        }
    }

    /// Returns the exact block currently being retrieved or imported.
    pub const fn pending_block_id(&self) -> ProofBlockId {
        match &self.state {
            ProofBlockCatchUpState::Pull(pull) => pull.pending_block_id(),
            ProofBlockCatchUpState::Import(import) => import.pending_block_id(),
        }
    }

    /// Returns the peer serving the active block or proof request.
    ///
    /// During proof acquisition this may differ from the ancestry source under
    /// the existing bounded dependency-fallback contract.
    pub const fn pending_peer_id(&self) -> PeerId {
        match &self.state {
            ProofBlockCatchUpState::Pull(pull) => pull.pending_peer_id(),
            ProofBlockCatchUpState::Import(import) => import.pending_peer_id(),
        }
    }

    /// Returns the number of blocks durably acknowledged by this catch-up.
    pub const fn committed_block_count(&self) -> usize {
        match &self.state {
            ProofBlockCatchUpState::Pull(_) => 0,
            ProofBlockCatchUpState::Import(import) => import.committed_block_count(),
        }
    }

    /// Returns the last head whose commit this catch-up observed succeeding.
    pub const fn last_acknowledged_head_block_id(&self) -> ProofBlockId {
        match &self.state {
            ProofBlockCatchUpState::Pull(pull) => pull.anchor_block_id(),
            ProofBlockCatchUpState::Import(import) => import.last_acknowledged_head_block_id(),
        }
    }

    /// Returns whether `event` is the exact terminal awaited by this catch-up.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        match &self.state {
            ProofBlockCatchUpState::Pull(pull) => pull.accepts_event(event),
            ProofBlockCatchUpState::Import(import) => import.accepts_event(event),
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
        network: &mut StaticProofNetwork,
        selected: &mut ProofChainJournal,
        event: NetworkEvent,
    ) -> Result<ProofBlockCatchUpProgress, ProofBlockCatchUpError> {
        match self.state {
            ProofBlockCatchUpState::Pull(pull) => {
                match pull
                    .on_event(network, selected, event)
                    .map_err(ProofBlockCatchUpError::ancestry_pull)?
                {
                    ProofBlockAncestryPullProgress::AwaitingResponse(pull) => {
                        Ok(Some(ProofBlockCatchUp {
                            state: ProofBlockCatchUpState::Pull(pull),
                        }))
                    }
                    ProofBlockAncestryPullProgress::Complete(ancestry) => {
                        let import = network
                            .start_proof_block_ancestry_import(selected, ancestry)
                            .map_err(ProofBlockCatchUpError::ancestry_import)?;
                        Ok(Some(ProofBlockCatchUp {
                            state: ProofBlockCatchUpState::Import(import),
                        }))
                    }
                }
            }
            ProofBlockCatchUpState::Import(import) => import
                .on_event(network, selected, event)
                .map(|progress| {
                    progress.map(|import| ProofBlockCatchUp {
                        state: ProofBlockCatchUpState::Import(import),
                    })
                })
                .map_err(ProofBlockCatchUpError::ancestry_import),
        }
    }
}

/// Allocation-free progress after one exact catch-up terminal.
///
/// `Some(catch_up)` means one block or proof request remains active. `None`
/// means the exact caller-selected target was durably acknowledged.
pub type ProofBlockCatchUpProgress = Option<ProofBlockCatchUp>;

/// One fail-closed catch-up failure from its exact lower workflow.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProofBlockCatchUpError {
    /// Ancestry retrieval failed before any catch-up block was committed.
    AncestryPull {
        source: Box<ProofBlockAncestryPullError>,
    },
    /// Ancestry import failed with its exact acknowledged-prefix metadata.
    AncestryImport {
        source: Box<ProofBlockAncestryImportError>,
    },
}

impl ProofBlockCatchUpError {
    fn ancestry_pull(source: ProofBlockAncestryPullError) -> Self {
        Self::AncestryPull {
            source: Box::new(source),
        }
    }

    fn ancestry_import(source: ProofBlockAncestryImportError) -> Self {
        Self::AncestryImport {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for ProofBlockCatchUpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AncestryPull { source } => {
                write!(
                    formatter,
                    "proof-block catch-up ancestry retrieval failed: {source}"
                )
            }
            Self::AncestryImport { source } => {
                write!(
                    formatter,
                    "proof-block catch-up ancestry import failed: {source}"
                )
            }
        }
    }
}

impl Error for ProofBlockCatchUpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AncestryPull { source } => Some(source.as_ref()),
            Self::AncestryImport { source } => Some(source.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests;
