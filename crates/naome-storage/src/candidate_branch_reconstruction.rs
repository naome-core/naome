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
    ArtifactChainJournalError, CanonicalArtifactPayloadStore, CanonicalArtifactPayloadStoreError,
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

impl ArtifactChainJournal {
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
        let (anchor_block_id, mut snapshot) = loop {
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
        for block in reverse_blocks {
            let block_id = block.id();
            let artifact_id = block.artifact_id();
            let payload = payloads
                .get(artifact_id)
                .map_err(
                    |source| CandidateBranchReconstructionError::PayloadStoreRead {
                        block_id,
                        artifact_id,
                        source: Box::new(source),
                    },
                )?
                .ok_or(CandidateBranchReconstructionError::PayloadNotRetained {
                    block_id,
                    artifact_id,
                })?;
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

        Ok(ReconstructedCandidateBranch {
            anchor_block_id,
            block_count,
            snapshot,
        })
    }
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
