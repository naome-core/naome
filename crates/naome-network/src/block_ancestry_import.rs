//! Caller-selected import of one bounded retained proof-block ancestry.

use std::error::Error;
use std::fmt;
use std::vec::IntoIter;

use naome_chain::{ProofBlock, ProofBlockId};
use naome_storage::ProofChainJournal;

use super::{
    NetworkEvent, PeerId, ProofBlockImport, ProofBlockImportError, StaticProofNetwork,
    UnselectedProofBlockAncestry,
};

/// One bounded caller-selected ancestry import in progress.
///
/// Blocks are consumed in their retained forward order. Each block acquires
/// and commits exactly its one proof payload before the next block starts. A later
/// failure preserves the prefix already acknowledged by the journal.
#[derive(Debug)]
#[must_use]
pub struct ProofBlockAncestryImport {
    anchor_block_id: ProofBlockId,
    target_block_id: ProofBlockId,
    source_peer_id: PeerId,
    committed_block_count: usize,
    last_acknowledged_head_block_id: ProofBlockId,
    remaining_blocks: IntoIter<ProofBlock>,
    current: ProofBlockImport,
}

impl StaticProofNetwork {
    /// Starts importing one caller-selected, already retrieved ancestry.
    ///
    /// The ancestry is consumed, so its retained blocks cannot be reused by a
    /// competing workflow. No block request is issued. The first block is
    /// preflighted against `selected` before proof traffic starts.
    pub fn start_proof_block_ancestry_import(
        &mut self,
        selected: &ProofChainJournal,
        ancestry: UnselectedProofBlockAncestry,
    ) -> Result<ProofBlockAncestryImport, ProofBlockAncestryImportError> {
        let (peer_id, anchor_block_id, target_block_id, blocks) = ancestry.into_parts();
        let mut remaining_blocks = blocks.into_iter();
        let first = remaining_blocks
            .next()
            .expect("a completed ancestry always contains its target block");
        let first_block_id = first.id();
        let current = ProofBlockImport::start_from_retained_block(
            self,
            selected,
            peer_id,
            first_block_id,
            first,
        )
        .map_err(|source| {
            ProofBlockAncestryImportError::new(
                target_block_id,
                first_block_id,
                0,
                anchor_block_id,
                source,
            )
        })?;

        Ok(ProofBlockAncestryImport {
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

impl ProofBlockAncestryImport {
    /// Returns the selected head captured by the consumed ancestry pull.
    pub const fn anchor_block_id(&self) -> ProofBlockId {
        self.anchor_block_id
    }

    /// Returns the exact ancestry target originally selected by the caller.
    pub const fn target_block_id(&self) -> ProofBlockId {
        self.target_block_id
    }

    /// Returns the number of blocks durably acknowledged by this workflow.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the last head whose commit this workflow observed succeeding.
    pub const fn last_acknowledged_head_block_id(&self) -> ProofBlockId {
        self.last_acknowledged_head_block_id
    }

    /// Returns the retained block currently acquiring its proof payload.
    pub const fn pending_block_id(&self) -> ProofBlockId {
        self.current.target_block_id()
    }

    /// Returns the authenticated peer serving the current proof request.
    pub const fn pending_peer_id(&self) -> PeerId {
        self.current.pending_peer_id()
    }

    /// Returns whether `event` is the exact terminal awaited by this import.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        self.current.accepts_event(event)
    }

    /// Cancels this workflow without rolling back its acknowledged prefix.
    ///
    /// The active proof request retains its existing physical drain
    /// semantics. Every unprocessed retained block is released immediately.
    pub fn cancel(self) {}

    /// Advances this import with its exact correlated proof terminal.
    ///
    /// Ordinary failure of the current block performs no mutation for that
    /// block. Blocks previously acknowledged by the journal remain committed.
    /// An ambiguous journal commit remains unacknowledged in the returned
    /// prefix metadata and leaves recovery to journal reopen.
    pub fn on_event(
        self,
        network: &mut StaticProofNetwork,
        selected: &mut ProofChainJournal,
        event: NetworkEvent,
    ) -> Result<ProofBlockAncestryImportProgress, ProofBlockAncestryImportError> {
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
                ProofBlockAncestryImportError::new(
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
        let current = ProofBlockImport::start_from_retained_block(
            network,
            selected,
            source_peer_id,
            next_block_id,
            next,
        )
        .map_err(|source| {
            ProofBlockAncestryImportError::new(
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

/// Allocation-free progress after one exact proof terminal.
///
/// `Some(import)` means one proof request remains active. `None` means every
/// retained block through the exact target was durably acknowledged.
pub type ProofBlockAncestryImportProgress = Option<ProofBlockAncestryImport>;

/// One ancestry-import failure plus its last acknowledged durable prefix.
#[derive(Debug)]
pub struct ProofBlockAncestryImportError {
    target_block_id: ProofBlockId,
    failed_block_id: ProofBlockId,
    committed_block_count: usize,
    last_acknowledged_head_block_id: ProofBlockId,
    source: Box<ProofBlockImportError>,
}

impl ProofBlockAncestryImportError {
    fn new(
        target_block_id: ProofBlockId,
        failed_block_id: ProofBlockId,
        committed_block_count: usize,
        last_acknowledged_head_block_id: ProofBlockId,
        source: ProofBlockImportError,
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
    pub const fn target_block_id(&self) -> ProofBlockId {
        self.target_block_id
    }

    /// Returns the block that could not be acknowledged by this workflow.
    pub const fn failed_block_id(&self) -> ProofBlockId {
        self.failed_block_id
    }

    /// Returns the number of prior blocks acknowledged before this failure.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the last head whose commit this workflow observed succeeding.
    pub const fn last_acknowledged_head_block_id(&self) -> ProofBlockId {
        self.last_acknowledged_head_block_id
    }

    /// Returns the underlying single-block import failure.
    pub fn block_import_error(&self) -> &ProofBlockImportError {
        &self.source
    }
}

impl fmt::Display for ProofBlockAncestryImportError {
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

impl Error for ProofBlockAncestryImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests;
