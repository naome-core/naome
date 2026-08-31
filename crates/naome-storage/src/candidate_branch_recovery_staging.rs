//! Strict unselected staging of one caller-owned recovery bundle.

use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;

use naome_chain::{
    ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId, ArtifactChainBranchSnapshot,
    ArtifactChainId, ArtifactSetRoot,
};
use naome_proof::ArtifactId;

use crate::candidate_branch_recovery_bundle::decode_bundle;
use crate::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactPayloadInsertOutcome,
    CandidateBranchPayloadArchiveError, CandidateBranchRecoveryBundleDecodeError,
    CandidateBranchRecoveryBundleLimits, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError, SelectedArtifactHistory, SelectedArtifactHistoryError,
};

struct StagingEntry {
    predecessor: ArtifactChainBranchSnapshot,
    block: ArtifactBlock,
    payload: Vec<u8>,
}

struct StagingPlan {
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    selected_prefix_count: usize,
    entries: Vec<StagingEntry>,
}

struct StagingDestination<'a> {
    selected: &'a dyn SelectedArtifactHistory,
    candidates: &'a mut ArtifactBlockCandidateStore,
    payloads: &'a mut CanonicalArtifactPayloadStore,
    limits: CandidateBranchRecoveryBundleLimits,
}

trait StagingCommitObserver {
    fn candidate_committed(
        &mut self,
        _index: usize,
        _block_id: ArtifactBlockId,
        _block_bytes: usize,
        _outcome: ArtifactBlockCandidateInsertOutcome,
        _candidates: &mut ArtifactBlockCandidateStore,
    ) -> Result<(), ArtifactBlockCandidateStoreError> {
        Ok(())
    }

    fn payload_committed(
        &mut self,
        _index: usize,
        _artifact_id: ArtifactId,
        _payload_bytes: usize,
        _outcome: ArtifactPayloadInsertOutcome,
        _payloads: &mut CanonicalArtifactPayloadStore,
    ) -> Result<(), CanonicalArtifactPayloadStoreError> {
        Ok(())
    }
}

struct ObserveSuccessfulCommits;

impl StagingCommitObserver for ObserveSuccessfulCommits {}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CandidateBranchRecoveryBundleStageTestFault {
    CandidateAfterDurableCommit { index: usize },
    PayloadAfterDurableCommit { index: usize },
}

#[cfg(test)]
pub(crate) struct CandidateBranchRecoveryBundleStageTestOptions {
    limits: CandidateBranchRecoveryBundleLimits,
    fault: CandidateBranchRecoveryBundleStageTestFault,
}

#[cfg(test)]
impl CandidateBranchRecoveryBundleStageTestOptions {
    pub(crate) const fn new(
        limits: CandidateBranchRecoveryBundleLimits,
        fault: CandidateBranchRecoveryBundleStageTestFault,
    ) -> Self {
        Self { limits, fault }
    }
}

#[cfg(test)]
struct InjectAmbiguousCommit {
    fault: CandidateBranchRecoveryBundleStageTestFault,
}

#[cfg(test)]
impl StagingCommitObserver for InjectAmbiguousCommit {
    fn candidate_committed(
        &mut self,
        index: usize,
        block_id: ArtifactBlockId,
        block_bytes: usize,
        outcome: ArtifactBlockCandidateInsertOutcome,
        candidates: &mut ArtifactBlockCandidateStore,
    ) -> Result<(), ArtifactBlockCandidateStoreError> {
        if self.fault
            == (CandidateBranchRecoveryBundleStageTestFault::CandidateAfterDurableCommit { index })
            && outcome == ArtifactBlockCandidateInsertOutcome::Inserted
        {
            candidates.poison_after_injected_ambiguous_commit();
            return Err(ArtifactBlockCandidateStoreError::Commit {
                block_id,
                block_bytes,
                source: std::io::Error::other("injected post-durable candidate commit failure"),
            });
        }
        Ok(())
    }

    fn payload_committed(
        &mut self,
        index: usize,
        artifact_id: ArtifactId,
        payload_bytes: usize,
        outcome: ArtifactPayloadInsertOutcome,
        payloads: &mut CanonicalArtifactPayloadStore,
    ) -> Result<(), CanonicalArtifactPayloadStoreError> {
        if self.fault
            == (CandidateBranchRecoveryBundleStageTestFault::PayloadAfterDurableCommit { index })
            && outcome == ArtifactPayloadInsertOutcome::Inserted
        {
            payloads.poison_after_injected_ambiguous_commit();
            return Err(CanonicalArtifactPayloadStoreError::Commit {
                artifact_id,
                payload_bytes,
                source: std::io::Error::other("injected post-durable payload commit failure"),
            });
        }
        Ok(())
    }
}

/// Strictly validates and stages one caller-owned recovery bundle as unselected data.
///
/// The caller independently selects the exact retained selected `anchor_block_id`
/// and unselected `target_block_id`. Complete destination-limited decoding,
/// selected-history validation, and candidate/payload conflict and capacity
/// preflight finish before the first write. The non-selected suffix is then
/// idempotently committed to the candidate-block store first and the validated
/// payload archive second. The two stores have separate acknowledged prefixes;
/// there is deliberately no cross-store atomicity.
///
/// The owned bytes are returned on success and every failure. Staging never
/// mutates selected history, records peer provenance, sends a network receipt,
/// or grants selection, consensus, or finality authority.
pub fn stage_candidate_branch_recovery_bundle_v0(
    bundle_bytes: Vec<u8>,
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    selected: &dyn SelectedArtifactHistory,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    limits: CandidateBranchRecoveryBundleLimits,
) -> Result<CandidateBranchRecoveryBundleStageOutcome, CandidateBranchRecoveryBundleStageError> {
    stage_candidate_branch_recovery_bundle_with_observer(
        bundle_bytes,
        anchor_block_id,
        target_block_id,
        StagingDestination {
            selected,
            candidates,
            payloads,
            limits,
        },
        &mut ObserveSuccessfulCommits,
    )
}

#[cfg(test)]
pub(crate) fn stage_candidate_branch_recovery_bundle_v0_with_test_fault(
    bundle_bytes: Vec<u8>,
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    selected: &dyn SelectedArtifactHistory,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    options: CandidateBranchRecoveryBundleStageTestOptions,
) -> Result<CandidateBranchRecoveryBundleStageOutcome, CandidateBranchRecoveryBundleStageError> {
    stage_candidate_branch_recovery_bundle_with_observer(
        bundle_bytes,
        anchor_block_id,
        target_block_id,
        StagingDestination {
            selected,
            candidates,
            payloads,
            limits: options.limits,
        },
        &mut InjectAmbiguousCommit {
            fault: options.fault,
        },
    )
}

fn stage_candidate_branch_recovery_bundle_with_observer(
    bundle_bytes: Vec<u8>,
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    destination: StagingDestination<'_>,
    observer: &mut impl StagingCommitObserver,
) -> Result<CandidateBranchRecoveryBundleStageOutcome, CandidateBranchRecoveryBundleStageError> {
    let plan = match prepare_staging_plan(
        &bundle_bytes,
        anchor_block_id,
        target_block_id,
        destination.selected,
        destination.candidates,
        destination.payloads,
        destination.limits,
    ) {
        Ok(plan) => plan,
        Err(failure) => {
            return Err(CandidateBranchRecoveryBundleStageError::new(
                bundle_bytes,
                0,
                0,
                0,
                0,
                failure,
            ));
        }
    };

    let candidate_block_count = plan.entries.len();
    let mut candidate_acknowledged_count = 0;
    let mut candidate_inserted_count = 0;
    for (index, entry) in plan.entries.iter().enumerate() {
        let block_id = entry.block.id();
        let insertion = match destination.candidates.insert(&entry.block) {
            Ok(insertion) => insertion,
            Err(source) => {
                return Err(CandidateBranchRecoveryBundleStageError::new(
                    bundle_bytes,
                    candidate_acknowledged_count,
                    candidate_inserted_count,
                    0,
                    0,
                    CandidateBranchRecoveryBundleStageFailure::CandidateCommit {
                        block_id,
                        source: Box::new(source),
                    },
                ));
            }
        };
        if let Err(source) = observer.candidate_committed(
            index,
            block_id,
            entry.block.to_canonical_bytes().len(),
            insertion,
            destination.candidates,
        ) {
            return Err(CandidateBranchRecoveryBundleStageError::new(
                bundle_bytes,
                candidate_acknowledged_count,
                candidate_inserted_count,
                0,
                0,
                CandidateBranchRecoveryBundleStageFailure::CandidateCommit {
                    block_id,
                    source: Box::new(source),
                },
            ));
        }
        candidate_acknowledged_count += 1;
        if insertion == ArtifactBlockCandidateInsertOutcome::Inserted {
            candidate_inserted_count += 1;
        }
    }

    let mut payload_inserted_count = 0;
    for (payload_acknowledged_count, entry) in plan.entries.into_iter().enumerate() {
        let block_id = entry.block.id();
        let artifact_id = entry.block.artifact_id();
        let payload_bytes = entry.payload.len();
        let outcome = match destination.payloads.validate_and_insert_branch_payload(
            &entry.predecessor,
            &entry.block,
            entry.payload,
        ) {
            Ok(outcome) => outcome,
            Err(CandidateBranchPayloadArchiveError::Validation { source }) => {
                return Err(CandidateBranchRecoveryBundleStageError::new(
                    bundle_bytes,
                    candidate_acknowledged_count,
                    candidate_inserted_count,
                    payload_acknowledged_count,
                    payload_inserted_count,
                    CandidateBranchRecoveryBundleStageFailure::PayloadCommitValidation {
                        block_id,
                        source,
                    },
                ));
            }
            Err(CandidateBranchPayloadArchiveError::Archive { source }) => {
                return Err(CandidateBranchRecoveryBundleStageError::new(
                    bundle_bytes,
                    candidate_acknowledged_count,
                    candidate_inserted_count,
                    payload_acknowledged_count,
                    payload_inserted_count,
                    CandidateBranchRecoveryBundleStageFailure::PayloadCommit {
                        block_id,
                        artifact_id,
                        source,
                    },
                ));
            }
        };
        if let Err(source) = observer.payload_committed(
            payload_acknowledged_count,
            artifact_id,
            payload_bytes,
            outcome.insertion_outcome(),
            destination.payloads,
        ) {
            return Err(CandidateBranchRecoveryBundleStageError::new(
                bundle_bytes,
                candidate_acknowledged_count,
                candidate_inserted_count,
                payload_acknowledged_count,
                payload_inserted_count,
                CandidateBranchRecoveryBundleStageFailure::PayloadCommit {
                    block_id,
                    artifact_id,
                    source: Box::new(source),
                },
            ));
        }
        if outcome.insertion_outcome() == ArtifactPayloadInsertOutcome::Inserted {
            payload_inserted_count += 1;
        }
    }

    Ok(CandidateBranchRecoveryBundleStageOutcome {
        bundle_bytes,
        anchor_block_id: plan.anchor_block_id,
        target_block_id: plan.target_block_id,
        selected_prefix_count: plan.selected_prefix_count,
        candidate_block_count,
        candidate_inserted_count,
        payload_inserted_count,
    })
}

fn prepare_staging_plan(
    bundle_bytes: &[u8],
    expected_anchor_block_id: ArtifactBlockId,
    expected_target_block_id: ArtifactBlockId,
    selected: &dyn SelectedArtifactHistory,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    limits: CandidateBranchRecoveryBundleLimits,
) -> Result<StagingPlan, CandidateBranchRecoveryBundleStageFailure> {
    let decoded = decode_bundle(bundle_bytes, limits).map_err(|source| {
        CandidateBranchRecoveryBundleStageFailure::Decode {
            source: Box::new(source),
        }
    })?;

    let selected_chain_id = selected.selected_chain_id();
    let candidate_chain_id = candidates.chain_id();
    if selected_chain_id != candidate_chain_id {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::CandidateChainIdMismatch {
                selected: selected_chain_id,
                candidates: candidate_chain_id,
            },
        );
    }
    if decoded.chain_id != selected_chain_id {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::BundleChainIdMismatch {
                selected: selected_chain_id,
                bundle: decoded.chain_id,
            },
        );
    }
    if decoded.anchor_block_id != expected_anchor_block_id {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::UnexpectedAnchor {
                expected: expected_anchor_block_id,
                actual: decoded.anchor_block_id,
            },
        );
    }
    if decoded.target_block_id != expected_target_block_id {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::UnexpectedTarget {
                expected: expected_target_block_id,
                actual: decoded.target_block_id,
            },
        );
    }

    let anchor_snapshot = selected
        .selected_branch_snapshot_at(expected_anchor_block_id)
        .map_err(
            |source| CandidateBranchRecoveryBundleStageFailure::SelectedHistory {
                block_id: expected_anchor_block_id,
                source: Box::new(source),
            },
        )?
        .ok_or(
            CandidateBranchRecoveryBundleStageFailure::AnchorNotSelected {
                block_id: expected_anchor_block_id,
            },
        )?;
    if anchor_snapshot.artifact_set_root() != decoded.anchor_artifact_set_root {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::AnchorArtifactSetRootMismatch {
                anchor_block_id: expected_anchor_block_id,
                expected: anchor_snapshot.artifact_set_root(),
                actual: decoded.anchor_artifact_set_root,
            },
        );
    }
    if selected
        .selected_branch_snapshot_at(expected_target_block_id)
        .map_err(
            |source| CandidateBranchRecoveryBundleStageFailure::SelectedHistory {
                block_id: expected_target_block_id,
                source: Box::new(source),
            },
        )?
        .is_some()
    {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::TargetAlreadySelected {
                block_id: expected_target_block_id,
            },
        );
    }

    let mut entries = Vec::new();
    entries
        .try_reserve_exact(decoded.entries.len())
        .map_err(
            |source| CandidateBranchRecoveryBundleStageFailure::PlanAllocation {
                entries: decoded.entries.len(),
                source,
            },
        )?;
    let mut snapshot = anchor_snapshot;
    let mut selected_prefix_count = 0;
    let mut reached_candidate_suffix = false;
    for decoded_entry in decoded.entries {
        let block = decoded_entry.block;
        let block_id = block.id();
        let payload_bytes = bundle_bytes
            .get(decoded_entry.payload_range)
            .expect("strict bundle decoding retains in-range payload offsets");
        let payload = copy_payload(payload_bytes).map_err(|source| {
            CandidateBranchRecoveryBundleStageFailure::PayloadAllocation {
                block_id,
                bytes: payload_bytes.len(),
                source,
            }
        })?;
        let validation_payload = copy_payload(payload_bytes).map_err(|source| {
            CandidateBranchRecoveryBundleStageFailure::PayloadAllocation {
                block_id,
                bytes: payload_bytes.len(),
                source,
            }
        })?;
        let predecessor = snapshot.clone();
        snapshot = predecessor
            .validate_child(&block, validation_payload)
            .map_err(
                |source| CandidateBranchRecoveryBundleStageFailure::BlockValidation {
                    block_id,
                    source: Box::new(source),
                },
            )?;

        match selected
            .selected_branch_snapshot_at(block_id)
            .map_err(
                |source| CandidateBranchRecoveryBundleStageFailure::SelectedHistory {
                    block_id,
                    source: Box::new(source),
                },
            )? {
            Some(selected_snapshot) => {
                if reached_candidate_suffix {
                    return Err(
                        CandidateBranchRecoveryBundleStageFailure::SelectedHistoryReentry {
                            block_id,
                        },
                    );
                }
                if selected_snapshot.artifact_set_root() != snapshot.artifact_set_root() {
                    return Err(
                        CandidateBranchRecoveryBundleStageFailure::SelectedPrefixRootMismatch {
                            block_id,
                            expected: selected_snapshot.artifact_set_root(),
                            actual: snapshot.artifact_set_root(),
                        },
                    );
                }
                selected_prefix_count += 1;
            }
            None => {
                reached_candidate_suffix = true;
                entries.push(StagingEntry {
                    predecessor,
                    block,
                    payload,
                });
            }
        }
    }
    debug_assert_eq!(snapshot.head_block_id(), expected_target_block_id);
    debug_assert!(!entries.is_empty());

    preflight_candidate_store(candidates, &entries)?;
    preflight_payload_store(payloads, &entries)?;

    Ok(StagingPlan {
        anchor_block_id: expected_anchor_block_id,
        target_block_id: expected_target_block_id,
        selected_prefix_count,
        entries,
    })
}

fn preflight_candidate_store(
    candidates: &mut ArtifactBlockCandidateStore,
    entries: &[StagingEntry],
) -> Result<(), CandidateBranchRecoveryBundleStageFailure> {
    let current_entries = candidates.len().map_err(|source| {
        CandidateBranchRecoveryBundleStageFailure::CandidateStorePreflight {
            block_id: None,
            source: Box::new(source),
        }
    })?;
    let mut new_entries = 0_usize;
    for entry in entries {
        let block_id = entry.block.id();
        match candidates.get(block_id).map_err(|source| {
            CandidateBranchRecoveryBundleStageFailure::CandidateStorePreflight {
                block_id: Some(block_id),
                source: Box::new(source),
            }
        })? {
            Some(retained) if retained != entry.block => {
                return Err(
                    CandidateBranchRecoveryBundleStageFailure::CandidateConflict { block_id },
                );
            }
            Some(_) => {}
            None => {
                new_entries = new_entries.checked_add(1).ok_or(
                    CandidateBranchRecoveryBundleStageFailure::CandidateEntryCountOverflow,
                )?;
            }
        }
    }
    let actual = current_entries
        .checked_add(new_entries)
        .ok_or(CandidateBranchRecoveryBundleStageFailure::CandidateEntryCountOverflow)?;
    let maximum = candidates.limits().max_entries();
    if actual > maximum {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::CandidateEntryLimitExceeded {
                actual,
                maximum,
            },
        );
    }
    Ok(())
}

fn preflight_payload_store(
    payloads: &mut CanonicalArtifactPayloadStore,
    entries: &[StagingEntry],
) -> Result<(), CandidateBranchRecoveryBundleStageFailure> {
    let current_entries = payloads.len().map_err(|source| {
        CandidateBranchRecoveryBundleStageFailure::PayloadStorePreflight {
            artifact_id: None,
            source: Box::new(source),
        }
    })?;
    let current_bytes = payloads.total_payload_bytes().map_err(|source| {
        CandidateBranchRecoveryBundleStageFailure::PayloadStorePreflight {
            artifact_id: None,
            source: Box::new(source),
        }
    })?;
    let mut new_entries = 0_usize;
    let mut new_bytes = 0_u64;
    for entry in entries {
        let artifact_id = entry.block.artifact_id();
        match payloads.get(artifact_id).map_err(|source| {
            CandidateBranchRecoveryBundleStageFailure::PayloadStorePreflight {
                artifact_id: Some(artifact_id),
                source: Box::new(source),
            }
        })? {
            Some(retained) if retained.canonical_artifact_bytes() != entry.payload => {
                return Err(CandidateBranchRecoveryBundleStageFailure::PayloadConflict {
                    artifact_id,
                });
            }
            Some(_) => {}
            None => {
                new_entries = new_entries
                    .checked_add(1)
                    .ok_or(CandidateBranchRecoveryBundleStageFailure::PayloadEntryCountOverflow)?;
                let bytes = u64::try_from(entry.payload.len()).map_err(|_| {
                    CandidateBranchRecoveryBundleStageFailure::PayloadByteCountOverflow
                })?;
                new_bytes = new_bytes
                    .checked_add(bytes)
                    .ok_or(CandidateBranchRecoveryBundleStageFailure::PayloadByteCountOverflow)?;
            }
        }
    }

    let actual_entries = current_entries
        .checked_add(new_entries)
        .ok_or(CandidateBranchRecoveryBundleStageFailure::PayloadEntryCountOverflow)?;
    let payload_limits = payloads.limits();
    if actual_entries > payload_limits.max_entries() {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::PayloadEntryLimitExceeded {
                actual: actual_entries,
                maximum: payload_limits.max_entries(),
            },
        );
    }
    let actual_bytes = current_bytes
        .checked_add(new_bytes)
        .ok_or(CandidateBranchRecoveryBundleStageFailure::PayloadByteCountOverflow)?;
    if actual_bytes > payload_limits.max_total_payload_bytes() {
        return Err(
            CandidateBranchRecoveryBundleStageFailure::PayloadByteLimitExceeded {
                actual: actual_bytes,
                maximum: payload_limits.max_total_payload_bytes(),
            },
        );
    }
    Ok(())
}

fn copy_payload(bytes: &[u8]) -> Result<Vec<u8>, TryReserveError> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len())?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

/// Complete unselected staging result with the original caller-owned bytes.
#[must_use]
pub struct CandidateBranchRecoveryBundleStageOutcome {
    bundle_bytes: Vec<u8>,
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    selected_prefix_count: usize,
    candidate_block_count: usize,
    candidate_inserted_count: usize,
    payload_inserted_count: usize,
}

impl CandidateBranchRecoveryBundleStageOutcome {
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }
    pub const fn selected_prefix_count(&self) -> usize {
        self.selected_prefix_count
    }
    pub const fn candidate_block_count(&self) -> usize {
        self.candidate_block_count
    }
    pub const fn candidate_inserted_count(&self) -> usize {
        self.candidate_inserted_count
    }
    pub const fn payload_inserted_count(&self) -> usize {
        self.payload_inserted_count
    }
    pub fn encoded_bytes(&self) -> usize {
        self.bundle_bytes.len()
    }
    pub fn bundle_bytes(&self) -> &[u8] {
        &self.bundle_bytes
    }
    pub fn into_bundle_bytes(self) -> Vec<u8> {
        self.bundle_bytes
    }
}

impl fmt::Debug for CandidateBranchRecoveryBundleStageOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateBranchRecoveryBundleStageOutcome")
            .field("anchor_block_id", &self.anchor_block_id)
            .field("target_block_id", &self.target_block_id)
            .field("selected_prefix_count", &self.selected_prefix_count)
            .field("candidate_block_count", &self.candidate_block_count)
            .field("candidate_inserted_count", &self.candidate_inserted_count)
            .field("payload_inserted_count", &self.payload_inserted_count)
            .field("encoded_bytes", &self.bundle_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Staging failure with the exact acknowledged durable prefixes and original bytes.
#[must_use]
pub struct CandidateBranchRecoveryBundleStageError {
    bundle_bytes: Vec<u8>,
    candidate_acknowledged_count: usize,
    candidate_inserted_count: usize,
    payload_acknowledged_count: usize,
    payload_inserted_count: usize,
    failure: Box<CandidateBranchRecoveryBundleStageFailure>,
}

impl CandidateBranchRecoveryBundleStageError {
    fn new(
        bundle_bytes: Vec<u8>,
        candidate_acknowledged_count: usize,
        candidate_inserted_count: usize,
        payload_acknowledged_count: usize,
        payload_inserted_count: usize,
        failure: CandidateBranchRecoveryBundleStageFailure,
    ) -> Self {
        Self {
            bundle_bytes,
            candidate_acknowledged_count,
            candidate_inserted_count,
            payload_acknowledged_count,
            payload_inserted_count,
            failure: Box::new(failure),
        }
    }

    pub const fn candidate_acknowledged_count(&self) -> usize {
        self.candidate_acknowledged_count
    }
    pub const fn candidate_inserted_count(&self) -> usize {
        self.candidate_inserted_count
    }
    pub const fn payload_acknowledged_count(&self) -> usize {
        self.payload_acknowledged_count
    }
    pub const fn payload_inserted_count(&self) -> usize {
        self.payload_inserted_count
    }
    pub fn failure(&self) -> &CandidateBranchRecoveryBundleStageFailure {
        self.failure.as_ref()
    }
    pub fn encoded_bytes(&self) -> usize {
        self.bundle_bytes.len()
    }
    pub fn bundle_bytes(&self) -> &[u8] {
        &self.bundle_bytes
    }
    pub fn into_bundle_bytes(self) -> Vec<u8> {
        self.bundle_bytes
    }
}

impl fmt::Debug for CandidateBranchRecoveryBundleStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateBranchRecoveryBundleStageError")
            .field("encoded_bytes", &self.bundle_bytes.len())
            .field(
                "candidate_acknowledged_count",
                &self.candidate_acknowledged_count,
            )
            .field("candidate_inserted_count", &self.candidate_inserted_count)
            .field(
                "payload_acknowledged_count",
                &self.payload_acknowledged_count,
            )
            .field("payload_inserted_count", &self.payload_inserted_count)
            .field("failure", &self.failure)
            .finish()
    }
}

impl fmt::Display for CandidateBranchRecoveryBundleStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "candidate branch recovery bundle staging failed after {} candidate and {} payload acknowledgements: {}",
            self.candidate_acknowledged_count, self.payload_acknowledged_count, self.failure
        )
    }
}

impl Error for CandidateBranchRecoveryBundleStageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.failure.as_ref())
    }
}

/// Exact reason one recovery bundle could not be staged.
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateBranchRecoveryBundleStageFailure {
    Decode {
        source: Box<CandidateBranchRecoveryBundleDecodeError>,
    },
    CandidateChainIdMismatch {
        selected: ArtifactChainId,
        candidates: ArtifactChainId,
    },
    BundleChainIdMismatch {
        selected: ArtifactChainId,
        bundle: ArtifactChainId,
    },
    UnexpectedAnchor {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    UnexpectedTarget {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    SelectedHistory {
        block_id: ArtifactBlockId,
        source: Box<SelectedArtifactHistoryError>,
    },
    AnchorNotSelected {
        block_id: ArtifactBlockId,
    },
    AnchorArtifactSetRootMismatch {
        anchor_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    TargetAlreadySelected {
        block_id: ArtifactBlockId,
    },
    PlanAllocation {
        entries: usize,
        source: TryReserveError,
    },
    PayloadAllocation {
        block_id: ArtifactBlockId,
        bytes: usize,
        source: TryReserveError,
    },
    BlockValidation {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockApplyError>,
    },
    SelectedHistoryReentry {
        block_id: ArtifactBlockId,
    },
    SelectedPrefixRootMismatch {
        block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    CandidateStorePreflight {
        block_id: Option<ArtifactBlockId>,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
    CandidateConflict {
        block_id: ArtifactBlockId,
    },
    CandidateEntryCountOverflow,
    CandidateEntryLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    PayloadStorePreflight {
        artifact_id: Option<ArtifactId>,
        source: Box<CanonicalArtifactPayloadStoreError>,
    },
    PayloadConflict {
        artifact_id: ArtifactId,
    },
    PayloadEntryCountOverflow,
    PayloadByteCountOverflow,
    PayloadEntryLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    PayloadByteLimitExceeded {
        actual: u64,
        maximum: u64,
    },
    CandidateCommit {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
    PayloadCommitValidation {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockApplyError>,
    },
    PayloadCommit {
        block_id: ArtifactBlockId,
        artifact_id: ArtifactId,
        source: Box<CanonicalArtifactPayloadStoreError>,
    },
}

impl fmt::Display for CandidateBranchRecoveryBundleStageFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { source } => write!(formatter, "strict bundle decoding failed: {source}"),
            Self::CandidateChainIdMismatch {
                selected,
                candidates,
            } => write!(
                formatter,
                "selected history chain {selected:?} does not match candidate store chain {candidates:?}"
            ),
            Self::BundleChainIdMismatch { selected, bundle } => write!(
                formatter,
                "selected history chain {selected:?} does not match bundle chain {bundle:?}"
            ),
            Self::UnexpectedAnchor { expected, actual } => write!(
                formatter,
                "bundle anchor {actual:?} does not match caller-selected {expected:?}"
            ),
            Self::UnexpectedTarget { expected, actual } => write!(
                formatter,
                "bundle target {actual:?} does not match caller-selected {expected:?}"
            ),
            Self::SelectedHistory { block_id, source } => write!(
                formatter,
                "selected history lookup at {block_id:?} failed: {source}"
            ),
            Self::AnchorNotSelected { block_id } => {
                write!(
                    formatter,
                    "bundle anchor {block_id:?} is not retained selected history"
                )
            }
            Self::AnchorArtifactSetRootMismatch {
                anchor_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "bundle anchor {anchor_block_id:?} has artifact-set root {actual:?}, expected selected {expected:?}"
            ),
            Self::TargetAlreadySelected { block_id } => {
                write!(formatter, "bundle target {block_id:?} is already selected")
            }
            Self::PlanAllocation { entries, .. } => write!(
                formatter,
                "could not reserve a bounded staging plan for {entries} entries"
            ),
            Self::PayloadAllocation {
                block_id, bytes, ..
            } => write!(
                formatter,
                "could not reserve {bytes} staged payload bytes for block {block_id:?}"
            ),
            Self::BlockValidation { block_id, source } => write!(
                formatter,
                "bundle block {block_id:?} failed complete branch validation: {source}"
            ),
            Self::SelectedHistoryReentry { block_id } => write!(
                formatter,
                "bundle candidate suffix re-enters selected history at {block_id:?}"
            ),
            Self::SelectedPrefixRootMismatch {
                block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "bundle selected prefix {block_id:?} has root {actual:?}, expected {expected:?}"
            ),
            Self::CandidateStorePreflight {
                block_id: Some(block_id),
                source,
            } => write!(
                formatter,
                "candidate store preflight at {block_id:?} failed: {source}"
            ),
            Self::CandidateStorePreflight {
                block_id: None,
                source,
            } => write!(formatter, "candidate store preflight failed: {source}"),
            Self::CandidateConflict { block_id } => write!(
                formatter,
                "candidate store retains different bytes for block {block_id:?}"
            ),
            Self::CandidateEntryCountOverflow => {
                formatter.write_str("candidate staging entry count overflowed")
            }
            Self::CandidateEntryLimitExceeded { actual, maximum } => write!(
                formatter,
                "candidate staging would retain {actual} entries, exceeding {maximum}"
            ),
            Self::PayloadStorePreflight {
                artifact_id: Some(artifact_id),
                source,
            } => write!(
                formatter,
                "payload store preflight at {artifact_id:?} failed: {source}"
            ),
            Self::PayloadStorePreflight {
                artifact_id: None,
                source,
            } => write!(formatter, "payload store preflight failed: {source}"),
            Self::PayloadConflict { artifact_id } => write!(
                formatter,
                "payload store retains different bytes for artifact {artifact_id:?}"
            ),
            Self::PayloadEntryCountOverflow => {
                formatter.write_str("payload staging entry count overflowed")
            }
            Self::PayloadByteCountOverflow => {
                formatter.write_str("payload staging byte count overflowed")
            }
            Self::PayloadEntryLimitExceeded { actual, maximum } => write!(
                formatter,
                "payload staging would retain {actual} entries, exceeding {maximum}"
            ),
            Self::PayloadByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "payload staging would retain {actual} bytes, exceeding {maximum}"
            ),
            Self::CandidateCommit { block_id, source } => write!(
                formatter,
                "candidate commit at block {block_id:?} failed: {source}"
            ),
            Self::PayloadCommitValidation { block_id, source } => write!(
                formatter,
                "payload commit revalidation at block {block_id:?} failed: {source}"
            ),
            Self::PayloadCommit {
                block_id,
                artifact_id,
                source,
            } => write!(
                formatter,
                "payload commit for block {block_id:?} and artifact {artifact_id:?} failed: {source}"
            ),
        }
    }
}

impl Error for CandidateBranchRecoveryBundleStageFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { source } => Some(source.as_ref()),
            Self::SelectedHistory { source, .. } => Some(source.as_ref()),
            Self::PlanAllocation { source, .. } | Self::PayloadAllocation { source, .. } => {
                Some(source)
            }
            Self::BlockValidation { source, .. } | Self::PayloadCommitValidation { source, .. } => {
                Some(source.as_ref())
            }
            Self::CandidateStorePreflight { source, .. } | Self::CandidateCommit { source, .. } => {
                Some(source.as_ref())
            }
            Self::PayloadStorePreflight { source, .. } | Self::PayloadCommit { source, .. } => {
                Some(source.as_ref())
            }
            _ => None,
        }
    }
}
