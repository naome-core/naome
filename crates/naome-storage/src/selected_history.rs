//! Sealed read-only access to replay-verified selected history.

use super::*;

pub(super) mod selected_artifact_history_sealed {
    pub trait Sealed {}
}

/// Read-only access to one replay-verified selected artifact history.
///
/// Implementations are sealed to the storage-owned journals that can establish
/// selected history by strict replay. Callers can inspect an exact selected
/// position through this capability, but cannot implement it for candidate or
/// peer-supplied state and cannot use it to mutate selection.
pub trait SelectedArtifactHistory: selected_artifact_history_sealed::Sealed {
    /// Returns the immutable artifact-chain identity.
    ///
    /// This context remains readable after a handle becomes terminal so callers
    /// can reject cross-chain inputs before any selected-state health read. It
    /// conveys no selected position or finality authority.
    fn selected_chain_id(&self) -> ArtifactChainId;

    /// Returns the exact selected artifact head while the owner is operable.
    fn selected_head_block_id(&self) -> Result<ArtifactBlockId, SelectedArtifactHistoryError>;

    /// Returns the authenticated selected artifact-set root while operable.
    fn selected_artifact_set_root(&self) -> Result<ArtifactSetRoot, SelectedArtifactHistoryError>;

    /// Returns one owned replay-verified selected snapshot while operable.
    fn selected_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, SelectedArtifactHistoryError>;
}

/// Failure to inspect storage-owned selected artifact history.
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectedArtifactHistoryError {
    /// The artifact-only selected journal denied the read.
    ArtifactChainJournal {
        source: Box<ArtifactChainJournalError>,
    },
    /// The joint fixed-validator finality journal denied the read.
    FixedValidatorFinalityJournal {
        source: Box<FixedValidatorFinalityJournalErrorV0>,
    },
}

impl SelectedArtifactHistoryError {
    pub(super) fn artifact_chain(source: ArtifactChainJournalError) -> Self {
        Self::ArtifactChainJournal {
            source: Box::new(source),
        }
    }

    pub(super) fn fixed_validator_finality(source: FixedValidatorFinalityJournalErrorV0) -> Self {
        Self::FixedValidatorFinalityJournal {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for SelectedArtifactHistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactChainJournal { source } => {
                write!(
                    formatter,
                    "selected artifact-chain journal read failed: {source}"
                )
            }
            Self::FixedValidatorFinalityJournal { source } => write!(
                formatter,
                "selected fixed-validator finality journal read failed: {source}"
            ),
        }
    }
}

impl Error for SelectedArtifactHistoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ArtifactChainJournal { source } => Some(source.as_ref()),
            Self::FixedValidatorFinalityJournal { source } => Some(source.as_ref()),
        }
    }
}
