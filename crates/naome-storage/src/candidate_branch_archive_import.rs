use std::error::Error;
use std::fmt;

use naome_chain::{
    ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId, ArtifactChainId, ArtifactSetRoot,
};
use naome_proof::ArtifactId;

use crate::candidate_branch_reconstruction::{
    CandidateBranchPathAnchor, CandidateBranchPathError, collect_candidate_branch_path,
};
use crate::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, ArtifactChainJournal,
    ArtifactChainJournalError, CanonicalArtifactPayloadStore, CanonicalArtifactPayloadStoreError,
};

/// Caller-local work and memory bounds for one offline candidate-branch import.
///
/// These values are neither persisted nor consensus resource limits. The block
/// bound limits the exact retained ancestry inspected, while the byte bound
/// limits the logical canonical payload bytes retained between full preflight
/// and sequential journal application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateBranchArchiveImportLimits {
    max_blocks: usize,
    max_buffered_payload_bytes: u64,
}

impl CandidateBranchArchiveImportLimits {
    /// Constructs positive caller-local block and buffered-payload bounds.
    pub const fn new(
        max_blocks: usize,
        max_buffered_payload_bytes: u64,
    ) -> Result<Self, CandidateBranchArchiveImportLimitsError> {
        if max_blocks == 0 {
            return Err(CandidateBranchArchiveImportLimitsError::ZeroMaxBlocks);
        }
        if max_buffered_payload_bytes == 0 {
            return Err(CandidateBranchArchiveImportLimitsError::ZeroMaxBufferedPayloadBytes);
        }
        Ok(Self {
            max_blocks,
            max_buffered_payload_bytes,
        })
    }

    /// Returns the maximum number of retained candidate blocks inspected.
    pub const fn max_blocks(&self) -> usize {
        self.max_blocks
    }

    /// Returns the maximum logical payload bytes retained for one import.
    pub const fn max_buffered_payload_bytes(&self) -> u64 {
        self.max_buffered_payload_bytes
    }
}

/// A rejected offline candidate-branch import limit configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidateBranchArchiveImportLimitsError {
    /// The operation must permit at least one candidate block.
    ZeroMaxBlocks,
    /// The operation must permit at least one retained payload byte.
    ZeroMaxBufferedPayloadBytes,
}

impl fmt::Display for CandidateBranchArchiveImportLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxBlocks => {
                formatter.write_str("candidate branch archive import block limit must be positive")
            }
            Self::ZeroMaxBufferedPayloadBytes => formatter.write_str(
                "candidate branch archive import buffered-payload byte limit must be positive",
            ),
        }
    }
}

impl Error for CandidateBranchArchiveImportLimitsError {}

/// A fully acknowledged offline candidate-branch import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CandidateBranchArchiveImportOutcome {
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    committed_block_count: usize,
    buffered_payload_bytes: u64,
}

impl CandidateBranchArchiveImportOutcome {
    /// Returns the exact selected head captured before preflight.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    /// Returns the exact caller-selected target now acknowledged by the journal.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the number of journal commits acknowledged by this operation.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the logical canonical payload bytes retained during preflight.
    pub const fn buffered_payload_bytes(&self) -> u64 {
        self.buffered_payload_bytes
    }
}

struct PreparedCandidateBranchEntry {
    block: ArtifactBlock,
    canonical_artifact_bytes: Vec<u8>,
}

impl ArtifactChainJournal {
    /// Fully preflights and sequentially imports one exact locally archived branch.
    ///
    /// The caller chooses `target_block_id`. The candidate path must extend this
    /// journal's exact current selected head; meeting any other retained selected
    /// position is divergent rather than a reorganization request. Every block,
    /// exact archived payload, dependency, mathematical check, and resulting
    /// state transition passes against an immutable branch snapshot before the
    /// first selected journal write. The same owned payload bytes are retained
    /// and then passed through ordinary journal application, which deliberately
    /// repeats strict validation before each sequential durable commit.
    ///
    /// Success acknowledges the complete target. A preflight error commits
    /// nothing. A later journal error reports only the prefix whose commits this
    /// call observed succeeding; an ambiguous current commit remains excluded
    /// and retains the journal's poison-and-reopen boundary. The operation is
    /// not a whole-branch atomic transaction, branch-selection algorithm,
    /// rollback, reorganization, consensus, or finality decision.
    pub fn import_candidate_branch_from_archive(
        &mut self,
        target_block_id: ArtifactBlockId,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        limits: CandidateBranchArchiveImportLimits,
    ) -> Result<CandidateBranchArchiveImportOutcome, CandidateBranchArchiveImportError> {
        let selected_chain_id = self.chain_id();
        let candidate_chain_id = candidates.chain_id();
        if selected_chain_id != candidate_chain_id {
            return Err(CandidateBranchArchiveImportError::preflight(
                CandidateBranchArchiveImportPreflightError::ChainIdMismatch {
                    selected: selected_chain_id,
                    candidates: candidate_chain_id,
                },
            ));
        }

        let anchor_block_id = self.head_block_id().map_err(|source| {
            CandidateBranchArchiveImportError::preflight(
                CandidateBranchArchiveImportPreflightError::selected_state(source),
            )
        })?;
        let anchor_snapshot = self
            .branch_snapshot_at(anchor_block_id)
            .map_err(|source| {
                CandidateBranchArchiveImportError::preflight(
                    CandidateBranchArchiveImportPreflightError::selected_state(source),
                )
            })?
            .expect("the healthy current selected head always retains its snapshot");
        let path = collect_candidate_branch_path(
            self,
            target_block_id,
            candidates,
            limits.max_blocks,
            CandidateBranchPathAnchor::ExactSelected {
                block_id: anchor_block_id,
                snapshot: anchor_snapshot,
            },
        )
        .map_err(|source| {
            CandidateBranchArchiveImportError::preflight(
                CandidateBranchArchiveImportPreflightError::from_path(source),
            )
        })?;
        debug_assert_eq!(path.anchor_block_id, anchor_block_id);

        let block_count = path.blocks.len();
        let mut prepared = Vec::<PreparedCandidateBranchEntry>::new();
        prepared.try_reserve_exact(block_count).map_err(|_| {
            CandidateBranchArchiveImportError::preflight(
                CandidateBranchArchiveImportPreflightError::ImportBufferAllocation { block_count },
            )
        })?;

        let mut snapshot = path.snapshot;
        let mut buffered_payload_bytes = 0_u64;
        for block in path.blocks {
            let block_id = block.id();
            let artifact_id = block.artifact_id();
            let payload = payloads
                .get(artifact_id)
                .map_err(|source| {
                    CandidateBranchArchiveImportError::preflight(
                        CandidateBranchArchiveImportPreflightError::PayloadStoreRead {
                            block_id,
                            artifact_id,
                            source: Box::new(source),
                        },
                    )
                })?
                .ok_or_else(|| {
                    CandidateBranchArchiveImportError::preflight(
                        CandidateBranchArchiveImportPreflightError::PayloadNotRetained {
                            block_id,
                            artifact_id,
                        },
                    )
                })?;
            let canonical_artifact_bytes = payload.into_canonical_artifact_bytes().into_vec();
            let additional = u64::try_from(canonical_artifact_bytes.len())
                .expect("one in-memory payload length fits u64");
            let attempted = buffered_payload_bytes
                .checked_add(additional)
                .ok_or_else(|| {
                    CandidateBranchArchiveImportError::preflight(
                        CandidateBranchArchiveImportPreflightError::PayloadByteCountOverflow {
                            block_id,
                            artifact_id,
                            accumulated: buffered_payload_bytes,
                            additional,
                        },
                    )
                })?;
            if attempted > limits.max_buffered_payload_bytes {
                return Err(CandidateBranchArchiveImportError::preflight(
                    CandidateBranchArchiveImportPreflightError::PayloadByteLimitExceeded {
                        block_id,
                        artifact_id,
                        maximum: limits.max_buffered_payload_bytes,
                        attempted,
                    },
                ));
            }

            let mut validation_bytes = Vec::new();
            validation_bytes
                .try_reserve_exact(canonical_artifact_bytes.len())
                .map_err(|_| {
                    CandidateBranchArchiveImportError::preflight(
                        CandidateBranchArchiveImportPreflightError::PayloadBufferAllocation {
                            block_id,
                            artifact_id,
                            bytes: canonical_artifact_bytes.len(),
                        },
                    )
                })?;
            validation_bytes.extend_from_slice(&canonical_artifact_bytes);
            snapshot = snapshot
                .validate_child(&block, validation_bytes)
                .map_err(|source| {
                    CandidateBranchArchiveImportError::preflight(
                        CandidateBranchArchiveImportPreflightError::BlockValidation {
                            block_id,
                            source: Box::new(source),
                        },
                    )
                })?;
            buffered_payload_bytes = attempted;
            prepared.push(PreparedCandidateBranchEntry {
                block,
                canonical_artifact_bytes,
            });
        }
        debug_assert_eq!(snapshot.head_block_id(), target_block_id);

        self.reserve_selected_block_entries(block_count)
            .map_err(|source| {
                CandidateBranchArchiveImportError::preflight(
                    CandidateBranchArchiveImportPreflightError::JournalPreparation {
                        source: Box::new(source),
                    },
                )
            })?;
        drop(snapshot);

        let mut committed_block_count = 0_usize;
        let mut last_acknowledged_head_block_id = anchor_block_id;
        for PreparedCandidateBranchEntry {
            block,
            canonical_artifact_bytes,
        } in prepared
        {
            let block_id = block.id();
            if let Err(source) = self.apply_block(&block, canonical_artifact_bytes) {
                return Err(CandidateBranchArchiveImportError::Commit {
                    source: CandidateBranchArchiveImportCommitError {
                        target_block_id,
                        failed_block_id: block_id,
                        committed_block_count,
                        last_acknowledged_head_block_id,
                        source: Box::new(source),
                    },
                });
            }
            committed_block_count += 1;
            last_acknowledged_head_block_id = block_id;
        }

        debug_assert_eq!(last_acknowledged_head_block_id, target_block_id);
        Ok(CandidateBranchArchiveImportOutcome {
            anchor_block_id,
            target_block_id,
            committed_block_count,
            buffered_payload_bytes,
        })
    }
}

/// A fail-closed offline candidate-branch import failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBranchArchiveImportError {
    /// Complete content preflight failed before any selected journal write.
    Preflight {
        source: CandidateBranchArchiveImportPreflightError,
    },
    /// Sequential journal application failed after the reported acknowledged prefix.
    Commit {
        source: CandidateBranchArchiveImportCommitError,
    },
}

impl CandidateBranchArchiveImportError {
    fn preflight(source: CandidateBranchArchiveImportPreflightError) -> Self {
        Self::Preflight { source }
    }
}

impl fmt::Display for CandidateBranchArchiveImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preflight { source } => {
                write!(
                    formatter,
                    "candidate branch archive import preflight failed: {source}"
                )
            }
            Self::Commit { source } => write!(formatter, "{source}"),
        }
    }
}

impl Error for CandidateBranchArchiveImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Preflight { source } => Some(source),
            Self::Commit { source } => Some(source),
        }
    }
}

/// A complete-content preflight failure that selected no candidate block.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBranchArchiveImportPreflightError {
    /// The candidate store belongs to another artifact chain.
    ChainIdMismatch {
        selected: ArtifactChainId,
        candidates: ArtifactChainId,
    },
    /// The selected journal failed a required health or position lookup.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The exact caller target is already selected, including virtual genesis.
    TargetAlreadySelected { block_id: ArtifactBlockId },
    /// Reserving one bounded candidate-path slot failed.
    CandidateBufferAllocation {
        next_block_id: ArtifactBlockId,
        retained_blocks: usize,
    },
    /// One exact candidate-store integrity read failed.
    CandidateStoreRead {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
    /// One required exact candidate address is absent locally.
    CandidateNotRetained { block_id: ArtifactBlockId },
    /// Adjacent candidate or selected-anchor roots do not join.
    ArtifactSetRootMismatch {
        preceding_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// A block address repeats within the retained path.
    RepeatedBlockId { block_id: ArtifactBlockId },
    /// The path reached selected history other than the captured current head.
    DivergentAncestry {
        expected_anchor: ArtifactBlockId,
        encountered: ArtifactBlockId,
    },
    /// The exact path did not reach the current head within the local block bound.
    BlockLimitExceeded {
        maximum: usize,
        next_block_id: ArtifactBlockId,
    },
    /// Reserving the complete private import plan failed.
    ImportBufferAllocation { block_count: usize },
    /// One exact payload-store integrity read failed.
    PayloadStoreRead {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        source: Box<CanonicalArtifactPayloadStoreError>,
    },
    /// One candidate's exact committed payload is absent locally.
    PayloadNotRetained {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
    },
    /// The logical aggregate payload byte count overflowed.
    PayloadByteCountOverflow {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        accumulated: u64,
        additional: u64,
    },
    /// Retaining another exact payload would exceed the caller-local byte bound.
    PayloadByteLimitExceeded {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        maximum: u64,
        attempted: u64,
    },
    /// Copying exact payload bytes for immutable preflight failed.
    PayloadBufferAllocation {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        bytes: usize,
    },
    /// Strict immutable branch validation rejected one candidate.
    BlockValidation {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockApplyError>,
    },
    /// The selected journal could not reserve its complete block-index growth.
    JournalPreparation {
        source: Box<ArtifactChainJournalError>,
    },
}

impl CandidateBranchArchiveImportPreflightError {
    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }

    fn from_path(error: CandidateBranchPathError) -> Self {
        match error {
            CandidateBranchPathError::SelectedState { source } => Self::SelectedState { source },
            CandidateBranchPathError::TargetAlreadySelected { block_id } => {
                Self::TargetAlreadySelected { block_id }
            }
            CandidateBranchPathError::CandidateBufferAllocation {
                next_block_id,
                retained_blocks,
            } => Self::CandidateBufferAllocation {
                next_block_id,
                retained_blocks,
            },
            CandidateBranchPathError::CandidateStoreRead { block_id, source } => {
                Self::CandidateStoreRead { block_id, source }
            }
            CandidateBranchPathError::CandidateNotRetained { block_id } => {
                Self::CandidateNotRetained { block_id }
            }
            CandidateBranchPathError::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            },
            CandidateBranchPathError::RepeatedBlockId { block_id } => {
                Self::RepeatedBlockId { block_id }
            }
            CandidateBranchPathError::DivergentAncestry {
                expected_anchor,
                encountered,
            } => Self::DivergentAncestry {
                expected_anchor,
                encountered,
            },
            CandidateBranchPathError::BlockLimitExceeded {
                maximum,
                next_block_id,
            } => Self::BlockLimitExceeded {
                maximum,
                next_block_id,
            },
        }
    }
}

impl fmt::Display for CandidateBranchArchiveImportPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainIdMismatch {
                selected,
                candidates,
            } => write!(
                formatter,
                "candidate branch archive import chain mismatch: selected {selected:?}, candidates {candidates:?}"
            ),
            Self::SelectedState { source } => write!(
                formatter,
                "candidate branch archive import cannot use selected state: {source}"
            ),
            Self::TargetAlreadySelected { block_id } => write!(
                formatter,
                "candidate branch archive import target {block_id:?} is already selected"
            ),
            Self::CandidateBufferAllocation {
                next_block_id,
                retained_blocks,
            } => write!(
                formatter,
                "candidate branch archive import path after {retained_blocks} blocks could not reserve storage for {next_block_id:?}"
            ),
            Self::CandidateStoreRead { block_id, source } => write!(
                formatter,
                "candidate branch archive import block {block_id:?} could not be read: {source}"
            ),
            Self::CandidateNotRetained { block_id } => write!(
                formatter,
                "candidate branch archive import block {block_id:?} is not retained"
            ),
            Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate branch archive import after {preceding_block_id:?} expected artifact-set root {expected:?}, actual {actual:?}"
            ),
            Self::RepeatedBlockId { block_id } => write!(
                formatter,
                "candidate branch archive import repeats block address {block_id:?}"
            ),
            Self::DivergentAncestry {
                expected_anchor,
                encountered,
            } => write!(
                formatter,
                "candidate branch archive import expected current-head anchor {expected_anchor:?} but encountered selected position {encountered:?}"
            ),
            Self::BlockLimitExceeded {
                maximum,
                next_block_id,
            } => write!(
                formatter,
                "candidate branch archive import did not reach the current head within {maximum} blocks; next parent is {next_block_id:?}"
            ),
            Self::ImportBufferAllocation { block_count } => write!(
                formatter,
                "candidate branch archive import could not reserve {block_count} prepared entries"
            ),
            Self::PayloadStoreRead {
                block_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "candidate branch archive import block {block_id:?} payload {artifact_id:?} could not be read: {source}"
            ),
            Self::PayloadNotRetained {
                block_id,
                artifact_id,
            } => write!(
                formatter,
                "candidate branch archive import block {block_id:?} payload {artifact_id:?} is not retained"
            ),
            Self::PayloadByteCountOverflow {
                block_id,
                artifact_id,
                accumulated,
                additional,
            } => write!(
                formatter,
                "candidate branch archive import payload count overflowed after {accumulated} bytes while adding {additional} bytes for block {block_id:?} payload {artifact_id:?}"
            ),
            Self::PayloadByteLimitExceeded {
                block_id,
                artifact_id,
                maximum,
                attempted,
            } => write!(
                formatter,
                "candidate branch archive import block {block_id:?} payload {artifact_id:?} would buffer {attempted} bytes, maximum {maximum}"
            ),
            Self::PayloadBufferAllocation {
                block_id,
                artifact_id,
                bytes,
            } => write!(
                formatter,
                "candidate branch archive import could not copy {bytes} bytes for block {block_id:?} payload {artifact_id:?} preflight"
            ),
            Self::BlockValidation { block_id, source } => write!(
                formatter,
                "candidate branch archive import block {block_id:?} failed strict preflight: {source}"
            ),
            Self::JournalPreparation { source } => write!(
                formatter,
                "candidate branch archive import could not reserve selected journal capacity: {source}"
            ),
        }
    }
}

impl Error for CandidateBranchArchiveImportPreflightError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::CandidateStoreRead { source, .. } => Some(source.as_ref()),
            Self::PayloadStoreRead { source, .. } => Some(source.as_ref()),
            Self::BlockValidation { source, .. } => Some(source.as_ref()),
            Self::JournalPreparation { source } => Some(source.as_ref()),
            Self::ChainIdMismatch { .. }
            | Self::TargetAlreadySelected { .. }
            | Self::CandidateBufferAllocation { .. }
            | Self::CandidateNotRetained { .. }
            | Self::ArtifactSetRootMismatch { .. }
            | Self::RepeatedBlockId { .. }
            | Self::DivergentAncestry { .. }
            | Self::BlockLimitExceeded { .. }
            | Self::ImportBufferAllocation { .. }
            | Self::PayloadNotRetained { .. }
            | Self::PayloadByteCountOverflow { .. }
            | Self::PayloadByteLimitExceeded { .. }
            | Self::PayloadBufferAllocation { .. } => None,
        }
    }
}

/// A sequential journal failure with the exact acknowledged import prefix.
#[derive(Debug)]
pub struct CandidateBranchArchiveImportCommitError {
    target_block_id: ArtifactBlockId,
    failed_block_id: ArtifactBlockId,
    committed_block_count: usize,
    last_acknowledged_head_block_id: ArtifactBlockId,
    source: Box<ArtifactChainJournalError>,
}

impl CandidateBranchArchiveImportCommitError {
    /// Returns the exact caller-selected import target.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the block whose commit this call did not observe succeeding.
    pub const fn failed_block_id(&self) -> ArtifactBlockId {
        self.failed_block_id
    }

    /// Returns the number of prior commits this call observed succeeding.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the last head whose commit this call observed succeeding.
    pub const fn last_acknowledged_head_block_id(&self) -> ArtifactBlockId {
        self.last_acknowledged_head_block_id
    }

    /// Returns the underlying selected-journal failure.
    pub fn journal_error(&self) -> &ArtifactChainJournalError {
        &self.source
    }
}

impl fmt::Display for CandidateBranchArchiveImportCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate branch archive import failed at block {:?} after {} acknowledged commits ending at {:?}: {}",
            self.failed_block_id,
            self.committed_block_count,
            self.last_acknowledged_head_block_id,
            self.source
        )
    }
}

impl Error for CandidateBranchArchiveImportCommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
