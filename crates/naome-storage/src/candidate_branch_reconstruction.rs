use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use naome_chain::{
    ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId, ArtifactChainBranchSnapshot,
    ArtifactChainId, ArtifactSetRoot,
};
use naome_proof::ArtifactId;

use crate::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, ArtifactChainJournal,
    ArtifactChainJournalError, CandidateBranchPayloadArchiveError, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
};

/// Caller-local work bound for one candidate-branch reconstruction.
///
/// The bound is not persisted, committed by a block, or interpreted as a
/// consensus retention rule. A reconstruction may inspect at most this many
/// unselected candidate blocks before reaching selected history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateBranchReconstructionLimits {
    max_blocks: usize,
}

impl CandidateBranchReconstructionLimits {
    /// Constructs a positive candidate-block work bound.
    pub const fn new(max_blocks: usize) -> Result<Self, CandidateBranchReconstructionLimitsError> {
        if max_blocks == 0 {
            return Err(CandidateBranchReconstructionLimitsError::ZeroMaxBlocks);
        }
        Ok(Self { max_blocks })
    }

    /// Returns the maximum number of candidate blocks inspected.
    pub const fn max_blocks(&self) -> usize {
        self.max_blocks
    }
}

/// A rejected candidate-branch reconstruction limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidateBranchReconstructionLimitsError {
    /// A reconstruction must permit at least one candidate block.
    ZeroMaxBlocks,
}

impl fmt::Display for CandidateBranchReconstructionLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxBlocks => {
                formatter.write_str("candidate branch reconstruction block limit must be positive")
            }
        }
    }
}

impl Error for CandidateBranchReconstructionLimitsError {}

/// One completely reconstructed and strictly validated local candidate branch.
///
/// The result owns only a memory-resident branch snapshot plus descriptive
/// addresses. It is not selected state, a reusable validation certificate, a
/// data-availability claim, or consensus or finality authority.
#[must_use]
pub struct ReconstructedCandidateBranch {
    anchor_block_id: ArtifactBlockId,
    block_count: usize,
    snapshot: ArtifactChainBranchSnapshot,
}

impl ReconstructedCandidateBranch {
    /// Returns the nearest selected ancestor from which reconstruction started.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    /// Returns the exact candidate tip selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.snapshot.head_block_id()
    }

    /// Returns the number of strictly validated candidate blocks.
    pub const fn block_count(&self) -> usize {
        self.block_count
    }

    /// Borrows the final memory-only branch snapshot.
    pub const fn snapshot(&self) -> &ArtifactChainBranchSnapshot {
        &self.snapshot
    }

    /// Consumes this description and returns the final memory-only snapshot.
    pub fn into_snapshot(self) -> ArtifactChainBranchSnapshot {
        self.snapshot
    }
}

impl fmt::Debug for ReconstructedCandidateBranch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconstructedCandidateBranch")
            .field("anchor_block_id", &self.anchor_block_id)
            .field("target_block_id", &self.snapshot.head_block_id())
            .field("block_count", &self.block_count)
            .field("artifact_set_root", &self.snapshot.artifact_set_root())
            .finish_non_exhaustive()
    }
}

/// Current result of one exact candidate-branch reconstruction.
///
/// A complete result is returned only after every candidate block and payload
/// has passed strict forward validation. An awaiting result owns the private
/// in-memory progress needed to validate one exact missing payload; it exposes
/// no partial branch snapshot or candidate-block sequence.
#[must_use]
#[derive(Debug)]
pub enum CandidateBranchReconstructionProgress<'store> {
    /// Reconstruction is paused at one exact payload not retained locally.
    AwaitingPayload(CandidateBranchReconstructionCursor<'store>),
    /// The complete candidate branch was strictly reconstructed.
    Complete(ReconstructedCandidateBranch),
}

/// Opaque, consuming progress for one candidate branch awaiting a payload.
///
/// The cursor owns an immutable reconstruction context captured from the
/// selected journal and candidate store plus an exclusive borrow of the exact
/// payload archive supplied at start. Continuation therefore cannot be
/// redirected to another archive. It is neither selected state nor a consensus,
/// finality, availability, or peer-trust claim. Dropping it is safe; a later
/// reconstruction can rediscover any payloads already archived.
#[must_use]
pub struct CandidateBranchReconstructionCursor<'store> {
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    block_count: usize,
    snapshot: ArtifactChainBranchSnapshot,
    remaining_blocks: std::vec::IntoIter<ArtifactBlock>,
    payloads: &'store mut CanonicalArtifactPayloadStore,
}

impl<'store> CandidateBranchReconstructionCursor<'store> {
    /// Returns the exact candidate tip originally selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the exact candidate block waiting for its committed payload.
    pub fn pending_block_id(&self) -> ArtifactBlockId {
        self.pending_block().id()
    }

    /// Returns the exact committed artifact address waiting for payload bytes.
    pub fn pending_artifact_id(&self) -> ArtifactId {
        self.pending_block().artifact_id()
    }

    /// Strictly validates and durably archives the pending exact payload.
    ///
    /// The cursor is consumed. Success advances through any later payloads
    /// already retained by the start-bound archive, returning either the next
    /// exact missing payload or the complete reconstructed branch. A validation
    /// or archive failure returns no successor cursor; a durable archive success
    /// remains discoverable by a fresh reconstruction even if later progress
    /// fails.
    pub fn validate_and_archive_pending_payload(
        self,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<CandidateBranchReconstructionProgress<'store>, CandidateBranchReconstructionError>
    {
        let Self {
            anchor_block_id,
            target_block_id,
            block_count,
            snapshot,
            mut remaining_blocks,
            payloads,
        } = self;
        let pending_block = remaining_blocks
            .next()
            .expect("an awaiting reconstruction cursor always retains its pending block");
        let block_id = pending_block.id();
        let artifact_id = pending_block.artifact_id();
        let snapshot = payloads
            .validate_and_insert_branch_payload(&snapshot, &pending_block, canonical_artifact_bytes)
            .map_err(|source| match source {
                CandidateBranchPayloadArchiveError::Validation { source } => {
                    CandidateBranchReconstructionError::BlockValidation { block_id, source }
                }
                CandidateBranchPayloadArchiveError::Archive { source } => {
                    CandidateBranchReconstructionError::PayloadArchive {
                        block_id,
                        artifact_id,
                        source,
                    }
                }
            })?
            .into_successor();

        advance_candidate_branch_reconstruction(
            anchor_block_id,
            target_block_id,
            block_count,
            snapshot,
            remaining_blocks,
            payloads,
        )
    }

    fn pending_block(&self) -> &ArtifactBlock {
        self.remaining_blocks
            .as_slice()
            .first()
            .expect("an awaiting reconstruction cursor always retains its pending block")
    }
}

impl fmt::Debug for CandidateBranchReconstructionCursor<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateBranchReconstructionCursor")
            .field("target_block_id", &self.target_block_id)
            .field("pending_block_id", &self.pending_block_id())
            .field("pending_artifact_id", &self.pending_artifact_id())
            .finish_non_exhaustive()
    }
}

impl ArtifactChainJournal {
    /// Starts one exact retained candidate-branch reconstruction.
    ///
    /// The caller chooses `target_block_id`. This method first follows and
    /// shape-checks the complete exact parent path backward through `candidates`
    /// to the nearest selected journal position. Only then does it integrity-load
    /// payloads and strictly validate blocks forward from that replay-built
    /// snapshot. The first missing payload returns an opaque cursor addressed to
    /// the exact block and artifact and exclusively bound to this same payload
    /// archive; no partial snapshot is exposed.
    ///
    /// Starting never writes any store, selects or promotes any block, or grants
    /// consensus or finality authority. Candidate and payload integrity-read
    /// failures retain their existing poison-and-reopen semantics.
    pub fn start_candidate_branch_reconstruction<'store>(
        &self,
        target_block_id: ArtifactBlockId,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &'store mut CanonicalArtifactPayloadStore,
        limits: CandidateBranchReconstructionLimits,
    ) -> Result<CandidateBranchReconstructionProgress<'store>, CandidateBranchReconstructionError>
    {
        let selected_chain_id = self.chain_id();
        let candidate_chain_id = candidates.chain_id();
        if selected_chain_id != candidate_chain_id {
            return Err(CandidateBranchReconstructionError::ChainIdMismatch {
                selected: selected_chain_id,
                candidates: candidate_chain_id,
            });
        }

        if self
            .branch_snapshot_at(target_block_id)
            .map_err(CandidateBranchReconstructionError::selected_state)?
            .is_some()
        {
            return Err(CandidateBranchReconstructionError::TargetAlreadySelected {
                block_id: target_block_id,
            });
        }

        let mut reverse_blocks = Vec::<ArtifactBlock>::new();
        let mut seen_block_ids = HashSet::<ArtifactBlockId>::new();
        let mut next_block_id = target_block_id;
        let (anchor_block_id, snapshot) = loop {
            reverse_blocks.try_reserve(1).map_err(|_| {
                CandidateBranchReconstructionError::CandidateBufferAllocation {
                    next_block_id,
                    retained_blocks: reverse_blocks.len(),
                }
            })?;
            seen_block_ids.try_reserve(1).map_err(|_| {
                CandidateBranchReconstructionError::CandidateBufferAllocation {
                    next_block_id,
                    retained_blocks: reverse_blocks.len(),
                }
            })?;
            let block = candidates
                .get(next_block_id)
                .map_err(
                    |source| CandidateBranchReconstructionError::CandidateStoreRead {
                        block_id: next_block_id,
                        source: Box::new(source),
                    },
                )?
                .ok_or(CandidateBranchReconstructionError::CandidateNotRetained {
                    block_id: next_block_id,
                })?;
            let block_id = block.id();
            debug_assert_eq!(block_id, next_block_id);
            if !seen_block_ids.insert(block_id) {
                return Err(CandidateBranchReconstructionError::RepeatedBlockId { block_id });
            }

            if let Some(child) = reverse_blocks.last() {
                require_root_continuity(
                    block_id,
                    block.resulting_artifact_set_root(),
                    child.previous_artifact_set_root(),
                )?;
            }

            let parent_block_id = block.parent_block_id();
            if let Some(selected_snapshot) = self
                .branch_snapshot_at(parent_block_id)
                .map_err(CandidateBranchReconstructionError::selected_state)?
            {
                require_root_continuity(
                    parent_block_id,
                    selected_snapshot.artifact_set_root(),
                    block.previous_artifact_set_root(),
                )?;
                reverse_blocks.push(block);
                break (parent_block_id, selected_snapshot);
            }

            if seen_block_ids.contains(&parent_block_id) {
                return Err(CandidateBranchReconstructionError::RepeatedBlockId {
                    block_id: parent_block_id,
                });
            }

            if reverse_blocks.len() + 1 == limits.max_blocks {
                return Err(CandidateBranchReconstructionError::BlockLimitExceeded {
                    maximum: limits.max_blocks,
                    next_block_id: parent_block_id,
                });
            }

            reverse_blocks.push(block);
            next_block_id = parent_block_id;
        };

        reverse_blocks.reverse();
        let block_count = reverse_blocks.len();
        advance_candidate_branch_reconstruction(
            anchor_block_id,
            target_block_id,
            block_count,
            snapshot,
            reverse_blocks.into_iter(),
            payloads,
        )
    }

    /// Reconstructs one exact retained candidate branch without writing storage.
    ///
    /// The caller chooses `target_block_id`. The reconstruction follows exact
    /// parent addresses backward through `candidates` until the nearest selected
    /// journal position, then integrity-loads every committed payload and applies
    /// the complete strict block checks forward from that replay-built snapshot.
    /// Success is all-or-nothing and returns only a memory-resident snapshot.
    ///
    /// The method never inserts, selects, promotes, or persists a block or
    /// snapshot. Candidate and payload integrity-read failures retain their
    /// existing poison-and-reopen semantics.
    pub fn reconstruct_candidate_branch(
        &self,
        target_block_id: ArtifactBlockId,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        limits: CandidateBranchReconstructionLimits,
    ) -> Result<ReconstructedCandidateBranch, CandidateBranchReconstructionError> {
        match self.start_candidate_branch_reconstruction(
            target_block_id,
            candidates,
            payloads,
            limits,
        )? {
            CandidateBranchReconstructionProgress::Complete(reconstructed) => Ok(reconstructed),
            CandidateBranchReconstructionProgress::AwaitingPayload(cursor) => {
                Err(CandidateBranchReconstructionError::PayloadNotRetained {
                    block_id: cursor.pending_block_id(),
                    artifact_id: cursor.pending_artifact_id(),
                })
            }
        }
    }
}

fn advance_candidate_branch_reconstruction<'store>(
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    block_count: usize,
    mut snapshot: ArtifactChainBranchSnapshot,
    mut remaining_blocks: std::vec::IntoIter<ArtifactBlock>,
    payloads: &'store mut CanonicalArtifactPayloadStore,
) -> Result<CandidateBranchReconstructionProgress<'store>, CandidateBranchReconstructionError> {
    while let Some(block) = remaining_blocks.as_slice().first() {
        let block_id = block.id();
        let artifact_id = block.artifact_id();
        let Some(payload) = payloads.get(artifact_id).map_err(|source| {
            CandidateBranchReconstructionError::PayloadStoreRead {
                block_id,
                artifact_id,
                source: Box::new(source),
            }
        })?
        else {
            return Ok(CandidateBranchReconstructionProgress::AwaitingPayload(
                CandidateBranchReconstructionCursor {
                    anchor_block_id,
                    target_block_id,
                    block_count,
                    snapshot,
                    remaining_blocks,
                    payloads,
                },
            ));
        };
        let block = remaining_blocks
            .next()
            .expect("the payload belongs to the pending candidate block");
        snapshot = snapshot
            .validate_child(&block, payload.into_canonical_artifact_bytes().into_vec())
            .map_err(
                |source| CandidateBranchReconstructionError::BlockValidation {
                    block_id,
                    source: Box::new(source),
                },
            )?;
    }
    debug_assert_eq!(snapshot.head_block_id(), target_block_id);

    Ok(CandidateBranchReconstructionProgress::Complete(
        ReconstructedCandidateBranch {
            anchor_block_id,
            block_count,
            snapshot,
        },
    ))
}

fn require_root_continuity(
    preceding_block_id: ArtifactBlockId,
    expected: ArtifactSetRoot,
    actual: ArtifactSetRoot,
) -> Result<(), CandidateBranchReconstructionError> {
    if expected != actual {
        return Err(
            CandidateBranchReconstructionError::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            },
        );
    }
    Ok(())
}

/// A fail-closed local candidate-branch reconstruction error.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBranchReconstructionError {
    /// The candidate store belongs to a different artifact chain.
    ChainIdMismatch {
        selected: ArtifactChainId,
        candidates: ArtifactChainId,
    },
    /// The selected journal failed a required health or position lookup.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The caller-supplied target is already selected, including virtual genesis.
    TargetAlreadySelected { block_id: ArtifactBlockId },
    /// Reserving one bounded backward-path slot failed.
    CandidateBufferAllocation {
        next_block_id: ArtifactBlockId,
        retained_blocks: usize,
    },
    /// One exact candidate-store integrity read failed.
    CandidateStoreRead {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
    /// One exact block required by the parent path is not retained.
    CandidateNotRetained { block_id: ArtifactBlockId },
    /// Adjacent candidate or selected-anchor artifact-set roots do not join.
    ArtifactSetRootMismatch {
        preceding_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// A parent address repeats within the candidate path.
    RepeatedBlockId { block_id: ArtifactBlockId },
    /// The path did not reach selected history within the caller's local bound.
    BlockLimitExceeded {
        maximum: usize,
        next_block_id: ArtifactBlockId,
    },
    /// One exact payload-store integrity read failed.
    PayloadStoreRead {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        source: Box<CanonicalArtifactPayloadStoreError>,
    },
    /// A strictly validated pending payload could not be durably archived.
    PayloadArchive {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        source: Box<CanonicalArtifactPayloadStoreError>,
    },
    /// One candidate's exact committed payload is not retained.
    PayloadNotRetained {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
    },
    /// Strict forward block validation rejected one retained candidate.
    BlockValidation {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockApplyError>,
    },
}

impl CandidateBranchReconstructionError {
    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for CandidateBranchReconstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainIdMismatch {
                selected,
                candidates,
            } => write!(
                formatter,
                "candidate branch chain mismatch: selected {selected:?}, candidates {candidates:?}"
            ),
            Self::SelectedState { source } => {
                write!(
                    formatter,
                    "candidate branch selected-state read failed: {source}"
                )
            }
            Self::TargetAlreadySelected { block_id } => write!(
                formatter,
                "candidate branch target {block_id:?} is already selected"
            ),
            Self::CandidateBufferAllocation {
                next_block_id,
                retained_blocks,
            } => write!(
                formatter,
                "candidate branch path after {retained_blocks} blocks could not reserve storage for {next_block_id:?}"
            ),
            Self::CandidateStoreRead { block_id, source } => write!(
                formatter,
                "candidate branch block {block_id:?} could not be read: {source}"
            ),
            Self::CandidateNotRetained { block_id } => write!(
                formatter,
                "candidate branch block {block_id:?} is not retained"
            ),
            Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate branch after {preceding_block_id:?} expected artifact-set root {expected:?}, actual {actual:?}"
            ),
            Self::RepeatedBlockId { block_id } => write!(
                formatter,
                "candidate branch repeats block address {block_id:?}"
            ),
            Self::BlockLimitExceeded {
                maximum,
                next_block_id,
            } => write!(
                formatter,
                "candidate branch did not reach selected history within {maximum} blocks; next parent is {next_block_id:?}"
            ),
            Self::PayloadStoreRead {
                block_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "candidate branch block {block_id:?} payload {artifact_id:?} could not be read: {source}"
            ),
            Self::PayloadArchive {
                block_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "candidate branch block {block_id:?} payload {artifact_id:?} could not be archived: {source}"
            ),
            Self::PayloadNotRetained {
                block_id,
                artifact_id,
            } => write!(
                formatter,
                "candidate branch block {block_id:?} payload {artifact_id:?} is not retained"
            ),
            Self::BlockValidation { block_id, source } => write!(
                formatter,
                "candidate branch block {block_id:?} failed strict validation: {source}"
            ),
        }
    }
}

impl Error for CandidateBranchReconstructionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::CandidateStoreRead { source, .. } => Some(source.as_ref()),
            Self::PayloadStoreRead { source, .. } => Some(source.as_ref()),
            Self::PayloadArchive { source, .. } => Some(source.as_ref()),
            Self::BlockValidation { source, .. } => Some(source.as_ref()),
            Self::ChainIdMismatch { .. }
            | Self::TargetAlreadySelected { .. }
            | Self::CandidateBufferAllocation { .. }
            | Self::CandidateNotRetained { .. }
            | Self::ArtifactSetRootMismatch { .. }
            | Self::RepeatedBlockId { .. }
            | Self::BlockLimitExceeded { .. }
            | Self::PayloadNotRetained { .. } => None,
        }
    }
}
