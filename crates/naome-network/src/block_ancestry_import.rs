//! Caller-selected import of one bounded retained artifact-block ancestry.

use std::error::Error;
use std::fmt;
use std::vec::IntoIter;

use naome_chain::{ArtifactBlock, ArtifactBlockId, ArtifactChainId, ArtifactSetRoot};
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, ArtifactChainJournal,
    ArtifactChainJournalError,
};

use super::{
    ArtifactBlockImport, ArtifactBlockImportError, NetworkEvent, PeerId, StaticArtifactNetwork,
    UnselectedArtifactBlockAncestry,
    block_ancestry::{
        ArtifactBlockAncestryShapeContext, ArtifactBlockAncestryShapeError, retain_ancestry_block,
    },
    selected_context_contains_block,
};

/// One bounded caller-selected ancestry import in progress.
///
/// Blocks are consumed in their retained forward order. Each block acquires
/// and commits exactly its one artifact payload before the next block starts. A later
/// failure preserves the prefix already acknowledged by the journal.
#[derive(Debug)]
#[must_use]
pub struct ArtifactBlockAncestryImport {
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    preferred_artifact_peer_id: PeerId,
    committed_block_count: usize,
    last_acknowledged_head_block_id: ArtifactBlockId,
    remaining_blocks: IntoIter<ArtifactBlock>,
    current: ArtifactBlockImport,
}

impl StaticArtifactNetwork {
    /// Starts importing one caller-selected, already retrieved ancestry.
    ///
    /// The ancestry is consumed, so its retained blocks cannot be reused by a
    /// competing workflow. No block request is issued. The first block is
    /// preflighted against `selected` before artifact traffic starts.
    pub fn start_artifact_block_ancestry_import(
        &mut self,
        selected: &ArtifactChainJournal,
        ancestry: UnselectedArtifactBlockAncestry,
    ) -> Result<ArtifactBlockAncestryImport, ArtifactBlockAncestryImportError> {
        let (peer_id, anchor_block_id, target_block_id, blocks) = ancestry.into_parts();
        ArtifactBlockAncestryImport::start_from_parts(
            self,
            selected,
            peer_id,
            anchor_block_id,
            target_block_id,
            blocks,
        )
    }

    /// Starts strict sequential import from one caller-selected retained target.
    ///
    /// Candidate blocks are integrity-read backward from `target_block_id` to
    /// the current selected head without any block request. Their bounded path
    /// remains unselected until the returned import obtains and strictly
    /// applies each committed artifact payload in forward order. The preferred
    /// payload peer is not candidate provenance, and deterministic fallback may
    /// use another configured peer. A candidate integrity-read failure retains
    /// the store's existing poison-and-reopen behavior.
    pub fn start_artifact_block_candidate_ancestry_import(
        &mut self,
        selected: &ArtifactChainJournal,
        candidates: &mut ArtifactBlockCandidateStore,
        preferred_artifact_peer_id: PeerId,
        target_block_id: ArtifactBlockId,
    ) -> Result<ArtifactBlockAncestryImport, ArtifactBlockCandidateAncestryImportStartError> {
        let selected_chain_id = selected.chain_id();
        let candidate_chain_id = candidates.chain_id();
        if selected_chain_id != candidate_chain_id {
            return Err(
                ArtifactBlockCandidateAncestryImportStartError::ChainIdMismatch {
                    selected: selected_chain_id,
                    candidates: candidate_chain_id,
                },
            );
        }

        let anchor_block_id = selected
            .head_block_id()
            .map_err(ArtifactBlockCandidateAncestryImportStartError::selected_state)?;
        let virtual_genesis_block_id = selected_chain_id.virtual_genesis_block_id();
        if selected_context_contains_block(
            selected,
            anchor_block_id,
            virtual_genesis_block_id,
            target_block_id,
        )
        .map_err(ArtifactBlockCandidateAncestryImportStartError::selected_state)?
        {
            return Err(
                ArtifactBlockCandidateAncestryImportStartError::TargetAlreadySelected {
                    block_id: target_block_id,
                },
            );
        }
        let anchor_artifact_set_root = selected
            .artifact_set_root()
            .map_err(ArtifactBlockCandidateAncestryImportStartError::selected_state)?;
        let shape = ArtifactBlockAncestryShapeContext::new(
            anchor_block_id,
            anchor_artifact_set_root,
            virtual_genesis_block_id,
            target_block_id,
        );

        let mut blocks = Vec::new();
        let mut block_id = target_block_id;
        loop {
            let block = candidates
                .get(block_id)
                .map_err(
                    |source| ArtifactBlockCandidateAncestryImportStartError::CandidateStore {
                        block_id,
                        source: Box::new(source),
                    },
                )?
                .ok_or(
                    ArtifactBlockCandidateAncestryImportStartError::CandidateNotRetained {
                        block_id,
                    },
                )?;
            let next_block_id = retain_ancestry_block(shape, &mut blocks, block, |block_id| {
                selected.block(block_id).map(|block| block.is_some())
            })
            .map_err(ArtifactBlockCandidateAncestryImportStartError::from_shape)?;
            let Some(next_block_id) = next_block_id else {
                break;
            };
            block_id = next_block_id;
        }

        ArtifactBlockAncestryImport::start_from_parts(
            self,
            selected,
            preferred_artifact_peer_id,
            anchor_block_id,
            target_block_id,
            blocks,
        )
        .map_err(
            |source| ArtifactBlockCandidateAncestryImportStartError::ImportStart {
                source: Box::new(source),
            },
        )
    }
}

impl ArtifactBlockAncestryImport {
    fn start_from_parts(
        network: &mut StaticArtifactNetwork,
        selected: &ArtifactChainJournal,
        preferred_artifact_peer_id: PeerId,
        anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
        blocks: Vec<ArtifactBlock>,
    ) -> Result<Self, ArtifactBlockAncestryImportError> {
        let mut remaining_blocks = blocks.into_iter();
        let first = remaining_blocks
            .next()
            .expect("a retained ancestry always contains its target block");
        let first_block_id = first.id();
        let current = ArtifactBlockImport::start_from_retained_block(
            network,
            selected,
            preferred_artifact_peer_id,
            first_block_id,
            first,
        )
        .map_err(|source| {
            ArtifactBlockAncestryImportError::new(
                target_block_id,
                first_block_id,
                0,
                anchor_block_id,
                source,
            )
        })?;

        Ok(Self {
            anchor_block_id,
            target_block_id,
            preferred_artifact_peer_id,
            committed_block_count: 0,
            last_acknowledged_head_block_id: anchor_block_id,
            remaining_blocks,
            current,
        })
    }

    /// Returns the selected head captured by the consumed ancestry pull.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    /// Returns the exact ancestry target originally selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the number of blocks durably acknowledged by this workflow.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the last head whose commit this workflow observed succeeding.
    pub const fn last_acknowledged_head_block_id(&self) -> ArtifactBlockId {
        self.last_acknowledged_head_block_id
    }

    /// Returns the retained block currently acquiring its artifact payload.
    pub const fn pending_block_id(&self) -> ArtifactBlockId {
        self.current.target_block_id()
    }

    /// Returns the authenticated peer serving the current artifact request.
    pub const fn pending_peer_id(&self) -> PeerId {
        self.current.pending_peer_id()
    }

    /// Returns whether `event` is the exact terminal awaited by this import.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        self.current.accepts_event(event)
    }

    /// Cancels this workflow without rolling back its acknowledged prefix.
    ///
    /// The active artifact request retains its existing physical drain
    /// semantics. Every unprocessed retained block is released immediately.
    pub fn cancel(self) {}

    /// Advances this import with its exact correlated artifact terminal.
    ///
    /// Ordinary failure of the current block performs no mutation for that
    /// block. Blocks previously acknowledged by the journal remain committed.
    /// An ambiguous journal commit remains unacknowledged in the returned
    /// prefix metadata and leaves recovery to journal reopen.
    pub fn on_event(
        self,
        network: &mut StaticArtifactNetwork,
        selected: &mut ArtifactChainJournal,
        event: NetworkEvent,
    ) -> Result<ArtifactBlockAncestryImportProgress, ArtifactBlockAncestryImportError> {
        let Self {
            anchor_block_id,
            target_block_id,
            preferred_artifact_peer_id,
            committed_block_count,
            last_acknowledged_head_block_id,
            mut remaining_blocks,
            current,
        } = self;
        let current_block_id = current.target_block_id();
        let progress = current
            .on_event(network, selected, event)
            .map_err(|source| {
                ArtifactBlockAncestryImportError::new(
                    target_block_id,
                    current_block_id,
                    committed_block_count,
                    last_acknowledged_head_block_id,
                    source,
                )
            })?;

        if let Some(current) = progress {
            return Ok(Some(Self {
                anchor_block_id,
                target_block_id,
                preferred_artifact_peer_id,
                committed_block_count,
                last_acknowledged_head_block_id,
                remaining_blocks,
                current,
            }));
        }

        let committed_block_count = committed_block_count + 1;
        let last_acknowledged_head_block_id = current_block_id;
        let Some(next) = remaining_blocks.next() else {
            debug_assert_eq!(current_block_id, target_block_id);
            return Ok(None);
        };
        let next_block_id = next.id();
        let current = ArtifactBlockImport::start_from_retained_block(
            network,
            selected,
            preferred_artifact_peer_id,
            next_block_id,
            next,
        )
        .map_err(|source| {
            ArtifactBlockAncestryImportError::new(
                target_block_id,
                next_block_id,
                committed_block_count,
                last_acknowledged_head_block_id,
                source,
            )
        })?;

        Ok(Some(Self {
            anchor_block_id,
            target_block_id,
            preferred_artifact_peer_id,
            committed_block_count,
            last_acknowledged_head_block_id,
            remaining_blocks,
            current,
        }))
    }
}

/// Allocation-free progress after one exact artifact terminal.
///
/// `Some(import)` means one artifact request remains active. `None` means every
/// retained block through the exact target was durably acknowledged.
pub type ArtifactBlockAncestryImportProgress = Option<ArtifactBlockAncestryImport>;

/// A rejected candidate-store-backed ancestry import start.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockCandidateAncestryImportStartError {
    /// The candidate store and selected journal belong to different chains.
    ChainIdMismatch {
        selected: ArtifactChainId,
        candidates: ArtifactChainId,
    },
    /// The selected journal failed a required read.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The target is the current head, virtual genesis, or another selected block.
    TargetAlreadySelected { block_id: ArtifactBlockId },
    /// The candidate store could not read one required block address.
    CandidateStore {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
    /// One required candidate address was not retained locally.
    CandidateNotRetained { block_id: ArtifactBlockId },
    /// One child block did not start at its parent's resulting artifact-set root.
    ArtifactSetRootMismatch {
        preceding_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// A parent address repeated within the retained path.
    RepeatedBlockId { block_id: ArtifactBlockId },
    /// The retained path met selected history other than the current head.
    DivergentAncestry {
        expected_anchor: ArtifactBlockId,
        encountered: ArtifactBlockId,
    },
    /// The retained path did not reach the current head within the fixed bound.
    AncestryLimitExceeded {
        maximum: usize,
        next_block_id: ArtifactBlockId,
    },
    /// The complete retained path failed strict first-block preflight or payload start.
    ImportStart {
        source: Box<ArtifactBlockAncestryImportError>,
    },
}

impl ArtifactBlockCandidateAncestryImportStartError {
    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }

    fn from_shape(error: ArtifactBlockAncestryShapeError<ArtifactChainJournalError>) -> Self {
        match error {
            ArtifactBlockAncestryShapeError::SelectedState(source) => Self::selected_state(source),
            ArtifactBlockAncestryShapeError::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            },
            ArtifactBlockAncestryShapeError::RepeatedBlockId { block_id } => {
                Self::RepeatedBlockId { block_id }
            }
            ArtifactBlockAncestryShapeError::DivergentAncestry {
                expected_anchor,
                encountered,
            } => Self::DivergentAncestry {
                expected_anchor,
                encountered,
            },
            ArtifactBlockAncestryShapeError::AncestryLimitExceeded {
                maximum,
                next_block_id,
            } => Self::AncestryLimitExceeded {
                maximum,
                next_block_id,
            },
        }
    }
}

impl fmt::Display for ArtifactBlockCandidateAncestryImportStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainIdMismatch {
                selected,
                candidates,
            } => write!(
                formatter,
                "candidate store chain {candidates:?} does not match selected journal chain {selected:?}"
            ),
            Self::SelectedState { source } => write!(
                formatter,
                "candidate ancestry import cannot use selected state: {source}"
            ),
            Self::TargetAlreadySelected { block_id } => write!(
                formatter,
                "candidate ancestry import target {block_id:?} is already selected"
            ),
            Self::CandidateStore { block_id, source } => write!(
                formatter,
                "cannot read candidate block address {block_id:?}: {source}"
            ),
            Self::CandidateNotRetained { block_id } => write!(
                formatter,
                "candidate ancestry block {block_id:?} is not retained"
            ),
            Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate ancestry predecessor {preceding_block_id:?} ends at artifact-set root {expected:?}, but its child starts at {actual:?}"
            ),
            Self::RepeatedBlockId { block_id } => {
                write!(formatter, "candidate ancestry repeats block {block_id:?}")
            }
            Self::DivergentAncestry {
                expected_anchor,
                encountered,
            } => write!(
                formatter,
                "candidate ancestry expected anchor {expected_anchor:?} but encountered selected-chain context {encountered:?}"
            ),
            Self::AncestryLimitExceeded {
                maximum,
                next_block_id,
            } => write!(
                formatter,
                "candidate ancestry exceeds {maximum} retained blocks before parent {next_block_id:?}"
            ),
            Self::ImportStart { source } => {
                write!(
                    formatter,
                    "cannot start retained candidate ancestry import: {source}"
                )
            }
        }
    }
}

impl Error for ArtifactBlockCandidateAncestryImportStartError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::CandidateStore { source, .. } => Some(source.as_ref()),
            Self::ImportStart { source } => Some(source.as_ref()),
            Self::ChainIdMismatch { .. }
            | Self::TargetAlreadySelected { .. }
            | Self::CandidateNotRetained { .. }
            | Self::ArtifactSetRootMismatch { .. }
            | Self::RepeatedBlockId { .. }
            | Self::DivergentAncestry { .. }
            | Self::AncestryLimitExceeded { .. } => None,
        }
    }
}

/// One ancestry-import failure plus its last acknowledged durable prefix.
#[derive(Debug)]
pub struct ArtifactBlockAncestryImportError {
    target_block_id: ArtifactBlockId,
    failed_block_id: ArtifactBlockId,
    committed_block_count: usize,
    last_acknowledged_head_block_id: ArtifactBlockId,
    source: Box<ArtifactBlockImportError>,
}

impl ArtifactBlockAncestryImportError {
    fn new(
        target_block_id: ArtifactBlockId,
        failed_block_id: ArtifactBlockId,
        committed_block_count: usize,
        last_acknowledged_head_block_id: ArtifactBlockId,
        source: ArtifactBlockImportError,
    ) -> Self {
        Self {
            target_block_id,
            failed_block_id,
            committed_block_count,
            last_acknowledged_head_block_id,
            source: Box::new(source),
        }
    }

    /// Returns the exact caller-selected ancestry target.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the block that could not be acknowledged by this workflow.
    pub const fn failed_block_id(&self) -> ArtifactBlockId {
        self.failed_block_id
    }

    /// Returns the number of prior blocks acknowledged before this failure.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the last head whose commit this workflow observed succeeding.
    pub const fn last_acknowledged_head_block_id(&self) -> ArtifactBlockId {
        self.last_acknowledged_head_block_id
    }

    /// Returns the underlying single-block import failure.
    pub fn block_import_error(&self) -> &ArtifactBlockImportError {
        &self.source
    }
}

impl fmt::Display for ArtifactBlockAncestryImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ancestry import failed at block {:?} after {} acknowledged commits ending at {:?}: {}",
            self.failed_block_id,
            self.committed_block_count,
            self.last_acknowledged_head_block_id,
            self.source
        )
    }
}

impl Error for ArtifactBlockAncestryImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests;
