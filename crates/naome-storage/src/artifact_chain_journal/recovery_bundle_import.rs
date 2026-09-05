//! Fully validated selected import and acknowledged-prefix failure evidence.

use super::*;
use crate::candidate_branch_recovery_bundle::{copy_payload, decode_bundle};

impl ArtifactChainJournal {
    /// Imports or resumes one exact portable V0 bundle at its captured head.
    ///
    /// The bundle is decoded again under `limits`. The journal must still be at
    /// the original anchor or at an exact already-selected bundle prefix. The
    /// complete branch is strictly validated before the unselected suffix is
    /// applied through ordinary sequential journal commits.
    pub fn import_candidate_branch_recovery_bundle_v0(
        &mut self,
        bundle: &CandidateBranchRecoveryBundleV0,
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<CandidateBranchRecoveryBundleImportOutcome, CandidateBranchRecoveryBundleImportError>
    {
        self.core
            .import_candidate_branch_recovery_bundle_v0(bundle, limits)
    }
}

struct PreparedBundleEntry {
    block: ArtifactBlock,
    payload: Vec<u8>,
}

impl<F: StoreIo> JournalCore<F> {
    pub(crate) fn import_candidate_branch_recovery_bundle_v0(
        &mut self,
        bundle: &CandidateBranchRecoveryBundleV0,
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<CandidateBranchRecoveryBundleImportOutcome, CandidateBranchRecoveryBundleImportError>
    {
        let decoded = decode_bundle(bundle.canonical_bytes(), limits)
            .map_err(CandidateBranchRecoveryBundleImportError::decode)?;
        let selected_chain_id = self.chain.chain_id();
        if selected_chain_id != decoded.chain_id {
            return Err(CandidateBranchRecoveryBundleImportError::ChainIdMismatch {
                selected: selected_chain_id,
                bundle: decoded.chain_id,
            });
        }
        self.ensure_healthy()
            .map_err(CandidateBranchRecoveryBundleImportError::selected_state)?;

        let current_head = self.chain.head_block_id();
        let current_root = self.chain.artifact_dag().artifact_set_root();
        let anchor_snapshot = self.blocks.snapshot(decoded.anchor_block_id).ok_or(
            CandidateBranchRecoveryBundleImportError::AnchorNotSelected {
                anchor_block_id: decoded.anchor_block_id,
            },
        )?;
        let actual_anchor_root = anchor_snapshot.artifact_set_root();
        if actual_anchor_root != decoded.anchor_artifact_set_root {
            return Err(
                CandidateBranchRecoveryBundleImportError::AnchorArtifactSetRootMismatch {
                    anchor_block_id: decoded.anchor_block_id,
                    expected: decoded.anchor_artifact_set_root,
                    actual: actual_anchor_root,
                },
            );
        }

        let already_selected_block_count = if current_head == decoded.anchor_block_id {
            if current_root != decoded.anchor_artifact_set_root {
                return Err(
                    CandidateBranchRecoveryBundleImportError::SelectedPrefixArtifactSetRootMismatch {
                        block_id: current_head,
                        expected: decoded.anchor_artifact_set_root,
                        actual: current_root,
                    },
                );
            }
            0
        } else {
            let Some(position) = decoded
                .entries
                .iter()
                .position(|entry| entry.block.id() == current_head)
            else {
                return Err(
                    CandidateBranchRecoveryBundleImportError::CurrentHeadNotBundlePrefix {
                        anchor_block_id: decoded.anchor_block_id,
                        target_block_id: decoded.target_block_id,
                        actual: current_head,
                    },
                );
            };
            position + 1
        };

        for entry in &decoded.entries[..already_selected_block_count] {
            let block_id = entry.block.id();
            let selected_block = self.blocks.get(&block_id).ok_or(
                CandidateBranchRecoveryBundleImportError::SelectedPrefixBlockMissing { block_id },
            )?;
            if selected_block != &entry.block {
                return Err(
                    CandidateBranchRecoveryBundleImportError::SelectedPrefixBlockMismatch {
                        block_id,
                    },
                );
            }
            let actual_root = self.blocks.artifact_set_root(block_id).ok_or(
                CandidateBranchRecoveryBundleImportError::SelectedPrefixBlockMissing { block_id },
            )?;
            let expected_root = entry.block.resulting_artifact_set_root();
            if actual_root != expected_root {
                return Err(
                    CandidateBranchRecoveryBundleImportError::SelectedPrefixArtifactSetRootMismatch {
                        block_id,
                        expected: expected_root,
                        actual: actual_root,
                    },
                );
            }
        }
        let expected_current_root = if already_selected_block_count == 0 {
            decoded.anchor_artifact_set_root
        } else {
            decoded.entries[already_selected_block_count - 1]
                .block
                .resulting_artifact_set_root()
        };
        if current_root != expected_current_root {
            return Err(
                CandidateBranchRecoveryBundleImportError::SelectedPrefixArtifactSetRootMismatch {
                    block_id: current_head,
                    expected: expected_current_root,
                    actual: current_root,
                },
            );
        }

        let suffix_count = decoded.entries.len() - already_selected_block_count;
        let mut prepared = Vec::new();
        prepared.try_reserve_exact(suffix_count).map_err(|_| {
            CandidateBranchRecoveryBundleImportError::ImportPlanAllocation {
                entries: suffix_count,
            }
        })?;
        let mut snapshot = anchor_snapshot;
        for (entry_index, entry) in decoded.entries.iter().enumerate() {
            let block_id = entry.block.id();
            let artifact_id = entry.block.artifact_id();
            let payload_bytes = &bundle.canonical_bytes()[entry.payload_range.clone()];
            let validation_payload = copy_payload(payload_bytes).map_err(|bytes| {
                CandidateBranchRecoveryBundleImportError::PayloadAllocation {
                    block_id,
                    artifact_id,
                    bytes,
                }
            })?;
            if entry_index >= already_selected_block_count {
                let commit_payload = copy_payload(payload_bytes).map_err(|bytes| {
                    CandidateBranchRecoveryBundleImportError::PayloadAllocation {
                        block_id,
                        artifact_id,
                        bytes,
                    }
                })?;
                prepared.push(PreparedBundleEntry {
                    block: entry.block,
                    payload: commit_payload,
                });
            }
            snapshot = snapshot
                .validate_child(&entry.block, validation_payload)
                .map_err(
                    |source| CandidateBranchRecoveryBundleImportError::BlockValidation {
                        block_id,
                        source: Box::new(source),
                    },
                )?;
        }
        debug_assert_eq!(snapshot.head_block_id(), decoded.target_block_id);

        self.blocks
            .reserve_entries(suffix_count)
            .map_err(
                |source| CandidateBranchRecoveryBundleImportError::JournalPreparation {
                    source: Box::new(source),
                },
            )?;
        drop(snapshot);

        let resumed_from_block_id = current_head;
        let mut committed_block_count = 0_usize;
        let mut last_acknowledged_head_block_id = current_head;
        for PreparedBundleEntry { block, payload } in prepared {
            let block_id = block.id();
            if let Err(source) = self.apply_block(&block, payload) {
                return Err(CandidateBranchRecoveryBundleImportError::Commit {
                    source: CandidateBranchRecoveryBundleCommitError {
                        target_block_id: decoded.target_block_id,
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
        debug_assert_eq!(last_acknowledged_head_block_id, decoded.target_block_id);

        Ok(CandidateBranchRecoveryBundleImportOutcome {
            anchor_block_id: decoded.anchor_block_id,
            resumed_from_block_id,
            target_block_id: decoded.target_block_id,
            already_selected_block_count,
            committed_block_count,
            total_payload_bytes: decoded.total_payload_bytes,
        })
    }
}

/// A fully validated and acknowledged recovery-bundle import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct CandidateBranchRecoveryBundleImportOutcome {
    anchor_block_id: ArtifactBlockId,
    resumed_from_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    already_selected_block_count: usize,
    committed_block_count: usize,
    total_payload_bytes: u64,
}

impl CandidateBranchRecoveryBundleImportOutcome {
    /// Returns the original exact selected anchor committed by the bundle.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    /// Returns the selected head from which this invocation resumed.
    pub const fn resumed_from_block_id(&self) -> ArtifactBlockId {
        self.resumed_from_block_id
    }

    /// Returns the exact caller-selected target now acknowledged.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the number of exact bundle-prefix blocks already selected at start.
    pub const fn already_selected_block_count(&self) -> usize {
        self.already_selected_block_count
    }

    /// Returns the number of new commits acknowledged by this invocation.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the complete bundle's logical tagged-payload byte count.
    pub const fn total_payload_bytes(&self) -> u64 {
        self.total_payload_bytes
    }
}

/// A fail-closed recovery-bundle import failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBranchRecoveryBundleImportError {
    /// Destination-limit or strict bundle decoding failed.
    Decode {
        source: CandidateBranchRecoveryBundleDecodeError,
    },
    /// The bundle belongs to another artifact-chain context.
    ChainIdMismatch {
        selected: ArtifactChainId,
        bundle: ArtifactChainId,
    },
    /// The selected journal failed its required health check.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The bundle's original anchor is not retained selected history.
    AnchorNotSelected { anchor_block_id: ArtifactBlockId },
    /// The retained anchor snapshot does not have the bundle's exact root.
    AnchorArtifactSetRootMismatch {
        anchor_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// The current head is neither the original anchor nor a bundle prefix.
    CurrentHeadNotBundlePrefix {
        anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// A claimed selected prefix block is absent from the journal index.
    SelectedPrefixBlockMissing { block_id: ArtifactBlockId },
    /// A claimed selected prefix block differs from the bundle block.
    SelectedPrefixBlockMismatch { block_id: ArtifactBlockId },
    /// A selected prefix snapshot has a different authenticated artifact root.
    SelectedPrefixArtifactSetRootMismatch {
        block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// Reserving the complete unselected suffix plan failed.
    ImportPlanAllocation { entries: usize },
    /// Copying one bounded payload for preflight or later commit failed.
    PayloadAllocation {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        bytes: usize,
    },
    /// One block or payload failed complete validation from the original anchor.
    BlockValidation {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockApplyError>,
    },
    /// The selected journal could not reserve its complete suffix index growth.
    JournalPreparation {
        source: Box<ArtifactChainJournalError>,
    },
    /// Sequential application failed after the reported acknowledged suffix.
    Commit {
        source: CandidateBranchRecoveryBundleCommitError,
    },
}

impl CandidateBranchRecoveryBundleImportError {
    fn decode(source: CandidateBranchRecoveryBundleDecodeError) -> Self {
        Self::Decode { source }
    }

    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for CandidateBranchRecoveryBundleImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { source } => {
                write!(
                    formatter,
                    "candidate recovery bundle decode failed: {source}"
                )
            }
            Self::ChainIdMismatch { selected, bundle } => write!(
                formatter,
                "candidate recovery bundle chain {bundle:?} does not match selected chain {selected:?}"
            ),
            Self::SelectedState { source } => write!(
                formatter,
                "candidate recovery bundle cannot use selected state: {source}"
            ),
            Self::AnchorNotSelected { anchor_block_id } => write!(
                formatter,
                "candidate recovery bundle anchor {anchor_block_id:?} is not retained selected history"
            ),
            Self::AnchorArtifactSetRootMismatch {
                anchor_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate recovery bundle anchor {anchor_block_id:?} commits artifact-set root {expected:?}, selected snapshot has {actual:?}"
            ),
            Self::CurrentHeadNotBundlePrefix {
                anchor_block_id,
                target_block_id,
                actual,
            } => write!(
                formatter,
                "selected head {actual:?} is neither candidate recovery bundle anchor {anchor_block_id:?} nor an exact prefix through target {target_block_id:?}"
            ),
            Self::SelectedPrefixBlockMissing { block_id } => write!(
                formatter,
                "candidate recovery bundle prefix block {block_id:?} is absent from selected history"
            ),
            Self::SelectedPrefixBlockMismatch { block_id } => write!(
                formatter,
                "candidate recovery bundle prefix block {block_id:?} differs from selected history"
            ),
            Self::SelectedPrefixArtifactSetRootMismatch {
                block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate recovery bundle selected prefix at {block_id:?} expected artifact-set root {expected:?}, actual {actual:?}"
            ),
            Self::ImportPlanAllocation { entries } => write!(
                formatter,
                "candidate recovery bundle could not reserve an import plan for {entries} entries"
            ),
            Self::PayloadAllocation {
                block_id,
                artifact_id,
                bytes,
            } => write!(
                formatter,
                "candidate recovery bundle could not allocate {bytes} bytes for block {block_id:?} payload {artifact_id:?} preflight"
            ),
            Self::BlockValidation { block_id, source } => write!(
                formatter,
                "candidate recovery bundle block {block_id:?} failed strict import preflight: {source}"
            ),
            Self::JournalPreparation { source } => write!(
                formatter,
                "candidate recovery bundle could not reserve selected journal capacity: {source}"
            ),
            Self::Commit { source } => write!(formatter, "{source}"),
        }
    }
}

impl Error for CandidateBranchRecoveryBundleImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { source } => Some(source),
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::BlockValidation { source, .. } => Some(source.as_ref()),
            Self::JournalPreparation { source } => Some(source.as_ref()),
            Self::Commit { source } => Some(source),
            _ => None,
        }
    }
}

/// A sequential journal failure with the exact newly acknowledged suffix.
#[derive(Debug)]
pub struct CandidateBranchRecoveryBundleCommitError {
    target_block_id: ArtifactBlockId,
    failed_block_id: ArtifactBlockId,
    committed_block_count: usize,
    last_acknowledged_head_block_id: ArtifactBlockId,
    source: Box<ArtifactChainJournalError>,
}

impl CandidateBranchRecoveryBundleCommitError {
    /// Returns the exact bundle target.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the block whose commit this invocation did not observe succeeding.
    pub const fn failed_block_id(&self) -> ArtifactBlockId {
        self.failed_block_id
    }

    /// Returns the number of new commits this invocation observed succeeding.
    pub const fn committed_block_count(&self) -> usize {
        self.committed_block_count
    }

    /// Returns the last selected head this invocation observed being acknowledged.
    pub const fn last_acknowledged_head_block_id(&self) -> ArtifactBlockId {
        self.last_acknowledged_head_block_id
    }

    /// Returns the underlying selected-journal failure.
    pub fn journal_error(&self) -> &ArtifactChainJournalError {
        &self.source
    }
}

impl fmt::Display for CandidateBranchRecoveryBundleCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate branch recovery bundle commit failed at {:?} after {} acknowledged commits ending at {:?}: {}",
            self.failed_block_id,
            self.committed_block_count,
            self.last_acknowledged_head_block_id,
            self.source
        )
    }
}

impl Error for CandidateBranchRecoveryBundleCommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
