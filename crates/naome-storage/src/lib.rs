//! Crash-consistent local persistence for NAOME artifact-chain state and payloads.
//!
//! [`ArtifactChainJournal`] stores canonical [`ArtifactBlock`] values together
//! with the exact tagged canonical artifact payload committed by each block.
//! Opening a journal reconstructs the block head and complete selected artifact
//! DAG through
//! strict [`ArtifactChainState`] replay; persisted bytes never bypass block or
//! artifact validation. One exact-parent block may also be validated read-only;
//! durable application always revalidates before selection and commit.
//!
//! [`CanonicalArtifactPayloadStore`] separately archives exact tagged payload
//! bytes from accepted artifact records or from candidates strictly validated
//! against an exact selected or memory-only branch predecessor. Archiving does
//! not make bytes selected or reusable as checked records; consumers must
//! validate them again in their target artifact context.
//!
//! [`FixedValidatorFinalityJournalV0`] is the separate fixed-validator V0
//! durable authority for coupling one strictly verified consensus transition
//! to its exact artifact successor. It cleanly replaces the artifact-only
//! journal within one prerelease directory, retains the first exact finality
//! proof per selected height, and requires an externally retained exact
//! [`FixedValidatorFinalityJournalStateIdV0`] for operational reopen. A distinct
//! verified sibling produces a durable terminal halt rather than fork choice.
//! Its retained selected transition is also the only source of a signer-height
//! handoff: the caller must explicitly acknowledge the journal's exact current
//! state identity as externally durable before the key-owning vote session can
//! consume that child.
//! [`FixedValidatorAnchoredFinalityJournalV0`] is the stricter file-backed
//! product path: it owns a separately locked canonical anchor, advances its
//! exact frame sequence and state identity after every synchronized finality or
//! halt footer, and publishes no outcome until that replacement and its parent
//! directory are synchronized.
//!
//! [`FixedValidatorVoteSafetyJournalV0`] separately owns one local consensus
//! signing key and enforces prepare-before-key-use and complete-before-release
//! for exact kernel-sealed vote and proposal intents. A one-time activation
//! record commits an independent positive prepared-proposal replay ceiling
//! before any signing or recovery session can issue; the V0 header-bound vote
//! ceiling remains unchanged. The key is reachable only through the journal's
//! sole lock-state session, and signing requires an explicit caller assertion
//! that the exact prepared state ID is durable in a separate monotonic anchor.
//! Before session issuance, that anchor must also cover one exact persisted
//! initial signing-lineage binding. Each later finality-authorized child lineage
//! is appended and externally acknowledged before signer memory advances, so an
//! exact anchored reopen can authorize that child even if a crash preceded its
//! first vote. When no branch object survives the process restart, the vote
//! journal issues an opaque capability that lets finality history recover only
//! the exact matching branch, including after a later finality halt when no
//! explicit conflict stop has been applied; the vote journal then rechecks
//! handle provenance and derives the latest durable current-lineage state under
//! a caller-local round-work ceiling before issuing its sole session. The
//! finality journal can also issue opaque authority for an externally anchored
//! durable conflict; explicit consumption appends a separate terminal stop to
//! each matching local signer journal without selecting or rolling back either
//! sibling. Until that authority is routed, prior point-in-time signer handoffs
//! remain unchanged.
//! The per-key chained log prevents replacement and same-slot vote or proposal
//! state divergence, while an anchored reopen with either kind of unresolved
//! preparation remains deliberately non-signable. A conflicting same-slot
//! proposal intent terminally stops only this local signer; its summary is not
//! objective equivocation proof, peer evidence, branch choice, or finality
//! authority.
//! [`FixedValidatorAnchoredVoteSafetyJournalV0`] pairs that journal with one
//! independently locked per-key anchor. Its session APIs remove raw external
//! state-ID acknowledgements: lineage, preparation, completion, checkpoint,
//! height, and stop records advance the paired anchor internally before any
//! live effect, key-use authority, stop, or signed bytes are released.
//! These file anchors fail closed on journal/anchor crash gaps; they do not
//! detect coordinated rollback of both files, provide hardware monotonicity,
//! or repair a mismatched pair.
//!
//! [`ArtifactBlockCandidateStore`] retains chain-scoped structural blocks,
//! including siblings and blocks with unavailable parents, without validating
//! or selecting a candidate history. These stores define no reorganization,
//! fork choice, consensus, finality, networking, or economic state.
//!
//! The journal exporters publish [`CandidateBranchRecoveryBundleV0`] bytes for
//! one caller-selected, fully validated branch anchored either at the current
//! selected head or at virtual genesis. Decoded bundles remain untrusted until
//! import preflight validates their payloads and destination prefix. The
//! genesis-anchored exporter sources its selected prefix only from
//! replay-accepted journal records; the wire bytes carry no anchor-mode or
//! provenance authority and remain a caller-owned offline artifact.
//! A separate strict staging operation re-decodes one caller-owned bundle
//! against an exact caller-selected anchor, target, and sealed selected history,
//! preflights both durable stores, and retains only its unselected suffix in the
//! candidate store followed by the validated payload archive. Those stores
//! expose independent acknowledged prefixes rather than cross-store atomicity;
//! staging never mutates or selects history and retains no peer provenance.
//! One separate candidate-backed finality boundary accepts an exact
//! caller-selected retained block, its archived payload, a complete canonical
//! finality envelope, and a caller-local round-work ceiling. It revalidates the
//! complete envelope against the current operable fixed-validator journal head
//! and delegates only the resulting sealed transition to durable finality.
//! Source-store presence grants no selection authority and neither source is
//! mutated; each staged height requires its own independently certified call.

mod block_candidate_store;
mod candidate_branch_archive_import;
mod candidate_branch_reconstruction;
mod candidate_branch_recovery_bundle;
mod candidate_branch_recovery_staging;
#[cfg(test)]
mod fault_io;
mod fixed_validator_anchor;
mod fixed_validator_finality_journal;
mod fixed_validator_vote_safety_journal;
mod payload_store;
mod store_io;
use store_io::{AppendPhase, ExclusiveLockError, StoreIo, open_exclusive_lock};

pub use block_candidate_store::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateInventory,
    ArtifactBlockCandidateInventoryError, ArtifactBlockCandidateInventoryLimits,
    ArtifactBlockCandidateInventoryLimitsError, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactBlockCandidateStoreLimits,
    ArtifactBlockCandidateStoreLimitsError,
};

pub use candidate_branch_archive_import::{
    CandidateBranchArchiveImportCommitError, CandidateBranchArchiveImportError,
    CandidateBranchArchiveImportLimits, CandidateBranchArchiveImportLimitsError,
    CandidateBranchArchiveImportOutcome, CandidateBranchArchiveImportPreflightError,
};

pub use candidate_branch_recovery_bundle::{
    CandidateBranchRecoveryBundleDecodeError, CandidateBranchRecoveryBundleExportError,
    CandidateBranchRecoveryBundleLimits, CandidateBranchRecoveryBundleLimitsError,
    CandidateBranchRecoveryBundleV0, export_candidate_branch_recovery_bundle_v0,
};

pub use candidate_branch_recovery_staging::{
    CandidateBranchRecoveryBundleStageError, CandidateBranchRecoveryBundleStageFailure,
    CandidateBranchRecoveryBundleStageOutcome, stage_candidate_branch_recovery_bundle_v0,
};

pub use candidate_branch_reconstruction::{
    CandidateBranchReconstructionCursor, CandidateBranchReconstructionError,
    CandidateBranchReconstructionLimits, CandidateBranchReconstructionLimitsError,
    CandidateBranchReconstructionProgress, ReconstructedCandidateBranch,
    reconstruct_candidate_branch, start_candidate_branch_reconstruction,
};
pub use fixed_validator_finality_journal::{
    CandidateBackedFinalityCommitV0, CandidateBackedFinalityConflictV0,
    CandidateBackedFinalityErrorV0, FixedValidatorAnchoredFinalityJournalErrorV0,
    FixedValidatorAnchoredFinalityJournalV0, FixedValidatorDurableFinalityConflictV0,
    FixedValidatorDurableFinalityTransitionV0, FixedValidatorFinalityCommitOutcomeV0,
    FixedValidatorFinalityHaltKindV0, FixedValidatorFinalityHaltV0,
    FixedValidatorFinalityJournalErrorV0, FixedValidatorFinalityJournalStateIdV0,
    FixedValidatorFinalityJournalV0, FixedValidatorFinalityRecordV0,
    FixedValidatorFinalityReplayLimitErrorV0, FixedValidatorFinalityReplayLimitV0,
    FixedValidatorHistoricalFinalityConflictErrorV0,
    commit_candidate_backed_anchored_finality_conflict_v0,
    commit_candidate_backed_anchored_finality_conflict_vote_batch_v0,
    commit_candidate_backed_anchored_finality_v0, commit_candidate_backed_finality_conflict_v0,
    commit_candidate_backed_finality_conflict_vote_batch_v0, commit_candidate_backed_finality_v0,
};
pub use fixed_validator_vote_safety_journal::{
    FixedValidatorAnchoredRecoveredSigningSessionV0, FixedValidatorAnchoredSignerRecoveryV0,
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorAnchoredVoteSafetyJournalV0,
    FixedValidatorAnchoredVoteSafetySigningSessionV0,
    FixedValidatorDurablePrepareAcknowledgementV0,
    FixedValidatorDurableProposalPrepareAcknowledgementV0,
    FixedValidatorFinalityConflictSignerStopOutcomeV0, FixedValidatorFinalityConflictSignerStopV0,
    FixedValidatorPendingProposalV0, FixedValidatorPendingVoteV0,
    FixedValidatorPreparedHeightAdvanceV0, FixedValidatorPreparedHigherRoundAdvanceV0,
    FixedValidatorPreparedProposalV0, FixedValidatorPreparedVoteV0,
    FixedValidatorProposalPrepareOutcomeV0, FixedValidatorProposalReplayLimitErrorV0,
    FixedValidatorProposalReplayLimitV0, FixedValidatorProposalSafetyHaltV0,
    FixedValidatorRecoveredSignerBranchV0, FixedValidatorRecoveredSigningSessionV0,
    FixedValidatorSignedProposalV0, FixedValidatorSignedVoteV0,
    FixedValidatorSignerRecoveryRoundLimitV0, FixedValidatorVoteCompletionMismatchV0,
    FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyHaltV0,
    FixedValidatorVoteSafetyJournalErrorV0, FixedValidatorVoteSafetyJournalStateIdV0,
    FixedValidatorVoteSafetyJournalV0, FixedValidatorVoteSafetyReplayLimitErrorV0,
    FixedValidatorVoteSafetyReplayLimitV0, FixedValidatorVoteSafetySigningSessionV0,
};

pub use fixed_validator_anchor::FixedValidatorAnchorErrorV0;

pub use payload_store::{
    ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits, ArtifactPayloadStoreLimitsError,
    CandidateBranchPayloadArchiveError, CandidateBranchPayloadArchiveOutcome,
    CandidatePayloadArchiveError, CanonicalArtifactPayload, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
};

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, SeekFrom, Write};
use std::path::Path;

use naome_chain::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockId,
    ArtifactBlockPrepareError, ArtifactChainBranchSnapshot, ArtifactChainDefinition,
    ArtifactChainId, ArtifactChainState, ArtifactSetProof, ArtifactSetRoot,
};
use naome_ledger::{AcceptedArtifactRecord, ArtifactState};
use naome_proof::{ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId};

mod selected_history;
use selected_history::selected_artifact_history_sealed;
pub use selected_history::{SelectedArtifactHistory, SelectedArtifactHistoryError};
mod artifact_chain_journal;
pub use artifact_chain_journal::{
    ArtifactChainJournal, ArtifactChainJournalError, CandidateBranchRecoveryBundleCommitError,
    CandidateBranchRecoveryBundleImportError, CandidateBranchRecoveryBundleImportOutcome,
};

const LOCK_FILE_NAME: &str = "artifact-chain.lock";
const JOURNAL_FILE_NAME: &str = "artifact-chain.journal";
