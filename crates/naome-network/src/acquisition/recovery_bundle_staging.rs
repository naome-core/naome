//! Caller-selected source checks and unselected staging of accepted bundle bytes.

use crate::{AcknowledgedRecoveryBundlePush, PeerId};
use naome_chain::ArtifactBlockId;
use naome_storage::{
    ArtifactBlockCandidateStore, CandidateBranchRecoveryBundleLimits,
    CandidateBranchRecoveryBundleStageError, CandidateBranchRecoveryBundleStageOutcome,
    CanonicalArtifactPayloadStore, SelectedArtifactHistory,
    stage_candidate_branch_recovery_bundle_v0,
};
use std::{error::Error, fmt};

/// The exact transport source and branch endpoints selected by the caller for staging.
///
/// The expected peer is only a source constraint. It grants no provenance,
/// selection, consensus, or finality authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryBundleStageSelection {
    expected_peer_id: PeerId,
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
}

impl RecoveryBundleStageSelection {
    pub const fn new(
        expected_peer_id: PeerId,
        anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
    ) -> Self {
        Self {
            expected_peer_id,
            anchor_block_id,
            target_block_id,
        }
    }

    pub const fn expected_peer_id(&self) -> PeerId {
        self.expected_peer_id
    }

    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }
}

impl AcknowledgedRecoveryBundlePush {
    /// Stages this accepted stream only for the exact caller-selected source,
    /// selected anchor, and unselected target.
    ///
    /// Complete staging preserves the source observation only in the returned
    /// memory value; neither durable store records peer provenance. A mismatch
    /// or staging failure returns the exact owned bytes.
    pub fn stage_candidate_branch(
        self,
        selection: RecoveryBundleStageSelection,
        selected: &dyn SelectedArtifactHistory,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        limits: CandidateBranchRecoveryBundleLimits,
    ) -> Result<AcknowledgedRecoveryBundleStageOutcome, Box<AcknowledgedRecoveryBundleStageError>>
    {
        if self.peer_id() != selection.expected_peer_id {
            return Err(Box::new(
                AcknowledgedRecoveryBundleStageError::UnexpectedPeer {
                    expected: selection.expected_peer_id,
                    actual: self.peer_id(),
                    acknowledged: self,
                },
            ));
        }
        let peer_id = self.peer_id();
        match stage_candidate_branch_recovery_bundle_v0(
            self.into_bundle_bytes(),
            selection.anchor_block_id,
            selection.target_block_id,
            selected,
            candidates,
            payloads,
            limits,
        ) {
            Ok(staging) => Ok(AcknowledgedRecoveryBundleStageOutcome { peer_id, staging }),
            Err(source) => Err(Box::new(AcknowledgedRecoveryBundleStageError::Staging {
                peer_id,
                source,
            })),
        }
    }
}

/// Complete unselected staging bound to the observed authenticated source.
#[must_use]
pub struct AcknowledgedRecoveryBundleStageOutcome {
    peer_id: PeerId,
    staging: CandidateBranchRecoveryBundleStageOutcome,
}

impl AcknowledgedRecoveryBundleStageOutcome {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub const fn staging(&self) -> &CandidateBranchRecoveryBundleStageOutcome {
        &self.staging
    }
    pub fn into_staging(self) -> CandidateBranchRecoveryBundleStageOutcome {
        self.staging
    }
}

impl fmt::Debug for AcknowledgedRecoveryBundleStageOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcknowledgedRecoveryBundleStageOutcome")
            .field("peer_id", &self.peer_id)
            .field("staging", &self.staging)
            .finish()
    }
}

/// A source-authorization or strict unselected-staging failure.
#[must_use]
pub enum AcknowledgedRecoveryBundleStageError {
    UnexpectedPeer {
        expected: PeerId,
        actual: PeerId,
        acknowledged: AcknowledgedRecoveryBundlePush,
    },
    Staging {
        peer_id: PeerId,
        source: CandidateBranchRecoveryBundleStageError,
    },
}

impl AcknowledgedRecoveryBundleStageError {
    pub fn bundle_bytes(&self) -> &[u8] {
        match self {
            Self::UnexpectedPeer { acknowledged, .. } => acknowledged.bundle_bytes(),
            Self::Staging { source, .. } => source.bundle_bytes(),
        }
    }
    pub fn into_bundle_bytes(self) -> Vec<u8> {
        match self {
            Self::UnexpectedPeer { acknowledged, .. } => acknowledged.into_bundle_bytes(),
            Self::Staging { source, .. } => source.into_bundle_bytes(),
        }
    }
}

impl fmt::Debug for AcknowledgedRecoveryBundleStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedPeer {
                expected,
                actual,
                acknowledged,
            } => formatter
                .debug_struct("AcknowledgedRecoveryBundleStageError::UnexpectedPeer")
                .field("expected", expected)
                .field("actual", actual)
                .field("acknowledged", acknowledged)
                .finish(),
            Self::Staging { peer_id, source } => formatter
                .debug_struct("AcknowledgedRecoveryBundleStageError::Staging")
                .field("peer_id", peer_id)
                .field("source", source)
                .finish(),
        }
    }
}

impl fmt::Display for AcknowledgedRecoveryBundleStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedPeer {
                expected, actual, ..
            } => write!(
                formatter,
                "acknowledged recovery bundle came from {actual}, expected caller-selected {expected}"
            ),
            Self::Staging { peer_id, source } => {
                write!(
                    formatter,
                    "recovery bundle from {peer_id} was not staged: {source}"
                )
            }
        }
    }
}

impl Error for AcknowledgedRecoveryBundleStageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnexpectedPeer { .. } => None,
            Self::Staging { source, .. } => Some(source),
        }
    }
}
