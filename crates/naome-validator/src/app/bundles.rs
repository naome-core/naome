use std::{fs::File, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

use naome_chain::ArtifactBlockId;
use naome_storage::{
    CandidateBranchRecoveryBundleExportError as ExportError,
    CandidateBranchRecoveryBundleLimits as Limits,
    CandidateBranchRecoveryBundleStageFailure as StageFailure, SelectedArtifactHistory,
    export_candidate_branch_recovery_bundle_v0, stage_candidate_branch_recovery_bundle_v0,
};
use serde_json::{Value, json};

use super::{Result, sources::Sources};

pub(super) fn limits(blocks: u64, payload_bytes: u64, bundle_bytes: u64) -> Result<Limits> {
    Limits::new(
        usize::try_from(blocks).map_err(|_| "bundle_block_limit")?,
        payload_bytes,
        bundle_bytes,
    )
    .map_err(|_| "bundle_limits")
}

pub(super) fn export(
    path: &Path,
    selected: &dyn SelectedArtifactHistory,
    sources: &mut Sources,
    target: ArtifactBlockId,
    limits: Limits,
) -> Value {
    // Complete export validation precedes creation of any destination entry.
    let bundle = match export_candidate_branch_recovery_bundle_v0(
        selected,
        target,
        &mut sources.candidates,
        &mut sources.payloads,
        limits,
    ) {
        Ok(bundle) => bundle,
        Err(error) => {
            return json!({"event": "bundle_export_failed", "code": export_code(&error),
                "output_created": false});
        }
    };
    if let Err((code, created)) = write_new(path, bundle.canonical_bytes()) {
        return json!({"event": "bundle_export_failed", "code": code,
            "output_created": created});
    }
    json!({"event": "bundle_exported",
        "anchor": hex(bundle.anchor_block_id()), "target": hex(bundle.target_block_id()),
        "block_count": bundle.block_count(),
        "payload_bytes": bundle.total_payload_bytes().to_string(),
        "encoded_bytes": bundle.encoded_bytes().to_string()})
}

fn write_new(path: &Path, bytes: &[u8]) -> std::result::Result<(), (&'static str, bool)> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ("bundle_file_create", false))?;
    // Preserve a partial or ambiguously durable file after any later failure.
    file.write_all(bytes)
        .map_err(|_| ("bundle_file_write", true))?;
    file.sync_all().map_err(|_| ("bundle_file_sync", true))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ("bundle_directory_sync", true))
}

pub(super) fn stage(
    bytes: Vec<u8>,
    selected: &dyn SelectedArtifactHistory,
    sources: &mut Sources,
    anchor: ArtifactBlockId,
    target: ArtifactBlockId,
    limits: Limits,
) -> Value {
    match stage_candidate_branch_recovery_bundle_v0(
        bytes,
        anchor,
        target,
        selected,
        &mut sources.candidates,
        &mut sources.payloads,
        limits,
    ) {
        Ok(outcome) => {
            let report = json!({"event": "bundle_staged",
                "anchor": hex(outcome.anchor_block_id()), "target": hex(outcome.target_block_id()),
                "selected_prefix_count": outcome.selected_prefix_count(),
                "candidate_block_count": outcome.candidate_block_count(),
                "candidate_inserted_count": outcome.candidate_inserted_count(),
                "payload_inserted_count": outcome.payload_inserted_count(),
                "encoded_bytes": outcome.encoded_bytes().to_string(), "bundle_bytes_discarded": true});
            drop(outcome.into_bundle_bytes());
            report
        }
        Err(error) => {
            let report = json!({"event": "bundle_stage_failed", "code": stage_code(error.failure()),
                "candidate_acknowledged_count": error.candidate_acknowledged_count(),
                "candidate_inserted_count": error.candidate_inserted_count(),
                "payload_acknowledged_count": error.payload_acknowledged_count(),
                "payload_inserted_count": error.payload_inserted_count(),
                "encoded_bytes": error.encoded_bytes().to_string(), "bundle_bytes_discarded": true});
            drop(error.into_bundle_bytes());
            report
        }
    }
}

fn hex(id: ArtifactBlockId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn export_code(error: &ExportError) -> &'static str {
    match error {
        ExportError::ChainIdMismatch { .. } => "chain_id",
        ExportError::SelectedState { .. } | ExportError::SelectedHistoryState { .. } => {
            "selected_history"
        }
        ExportError::TargetAlreadySelected { .. } => "target_selected",
        ExportError::CandidateStoreRead { .. } => "candidate_read",
        ExportError::CandidateNotRetained { .. } => "candidate_missing",
        ExportError::PayloadStoreRead { .. } => "payload_read",
        ExportError::PayloadNotRetained { .. } => "payload_missing",
        ExportError::DivergentAncestry { .. } => "divergent_ancestry",
        ExportError::BlockLimitExceeded { .. } => "block_limit",
        ExportError::PayloadByteLimitExceeded { .. } => "payload_limit",
        ExportError::BundleByteLimitExceeded { .. } => "bundle_limit",
        ExportError::BlockValidation { .. } | ExportError::ArtifactSetRootMismatch { .. } => {
            "branch_validation"
        }
        _ => "export_failed",
    }
}

fn stage_code(error: &StageFailure) -> &'static str {
    match error {
        StageFailure::Decode { .. } => "bundle_decode",
        StageFailure::CandidateChainIdMismatch { .. }
        | StageFailure::BundleChainIdMismatch { .. } => "chain_id",
        StageFailure::UnexpectedAnchor { .. } => "unexpected_anchor",
        StageFailure::UnexpectedTarget { .. } => "unexpected_target",
        StageFailure::SelectedHistory { .. } => "selected_history",
        StageFailure::AnchorNotSelected { .. } => "anchor_not_selected",
        StageFailure::AnchorArtifactSetRootMismatch { .. } => "anchor_root",
        StageFailure::TargetAlreadySelected { .. } => "target_selected",
        StageFailure::BlockValidation { .. }
        | StageFailure::SelectedHistoryReentry { .. }
        | StageFailure::SelectedPrefixRootMismatch { .. } => "branch_validation",
        StageFailure::CandidateStorePreflight { .. } => "candidate_preflight",
        StageFailure::CandidateConflict { .. } => "candidate_conflict",
        StageFailure::CandidateEntryLimitExceeded { .. } => "candidate_capacity",
        StageFailure::PayloadStorePreflight { .. } => "payload_preflight",
        StageFailure::PayloadConflict { .. } => "payload_conflict",
        StageFailure::PayloadEntryLimitExceeded { .. }
        | StageFailure::PayloadByteLimitExceeded { .. } => "payload_capacity",
        StageFailure::CandidateCommit { .. } => "candidate_commit",
        StageFailure::PayloadCommitValidation { .. } => "payload_commit_validation",
        StageFailure::PayloadCommit { .. } => "payload_commit",
        // Allocation, arithmetic and future failures remain unclassified: never
        // infer preflight or absence of effects from an unknown category.
        _ => "stage_failed",
    }
}
