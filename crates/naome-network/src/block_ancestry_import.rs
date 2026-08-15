//! Caller-selected import of one bounded retained artifact-block ancestry.

use std::error::Error;
use std::fmt;
use std::vec::IntoIter;

use naome_chain::{ArtifactBlock, ArtifactBlockId};
use naome_storage::ArtifactChainJournal;

use super::{
    ArtifactBlockImport, ArtifactBlockImportError, NetworkEvent, PeerId, StaticArtifactNetwork,
    UnselectedArtifactBlockAncestry,
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
    source_peer_id: PeerId,
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
        let mut remaining_blocks = blocks.into_iter();
        let first = remaining_blocks
            .next()
            .expect("a completed ancestry always contains its target block");
        let first_block_id = first.id();
        let current = ArtifactBlockImport::start_from_retained_block(
            self,
            selected,
            peer_id,
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

        Ok(ArtifactBlockAncestryImport {
            anchor_block_id,
            target_block_id,
            source_peer_id: peer_id,
            committed_block_count: 0,
            last_acknowledged_head_block_id: anchor_block_id,
            remaining_blocks,
            current,
        })
    }
}

impl ArtifactBlockAncestryImport {
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
            source_peer_id,
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
                source_peer_id,
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
            source_peer_id,
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
            source_peer_id,
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
