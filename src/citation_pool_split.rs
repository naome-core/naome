//! Checked-proof and selected-proof direct-target citation-pool arithmetic.
//!
//! This module combines a caller-supplied checked proof, a numerically floor-
//! qualified artifact base fee, and a caller-designated target slice. It
//! validates only that the slice is bounded, distinct, and contained in the
//! checked proof's distinct direct dependency set. A selected-proof projection
//! additionally requires that the source identity names a locally admitted
//! proof in the supplied artifact-chain state. The caller remains solely
//! responsible for eligibility and completeness. Neither projection
//! establishes consensus selection or finality, function-definition obligation
//! supporting-proof targets, attribution, beneficiary, fee calculation or
//! payment, inclusion, reward entitlement, actual burn or credit, settlement,
//! persistence, or economic or consensus state.

use std::error::Error;
use std::fmt;

use naome_chain::ArtifactChainState;
use naome_checker::CheckedProof;
use naome_economy::{FloorQualifiedArtifactBaseFee, NaoAtoms};
use naome_proof::ArtifactId;

/// A caller-designated target slice that cannot be coupled to one checked proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckedProofTargetSplitError {
    /// The slice exceeds this proof's distinct direct-dependency count.
    TooManyTargets { actual: usize, maximum: usize },
    /// One target occurs more than once.
    DuplicateTarget { artifact_id: ArtifactId },
    /// One target is absent from the checked proof's direct dependencies.
    NonDirectTarget { artifact_id: ArtifactId },
}

impl fmt::Display for CheckedProofTargetSplitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyTargets { actual, maximum } => write!(
                formatter,
                "checked-proof citation target slice has {actual} entries; the limit is {maximum}"
            ),
            Self::DuplicateTarget { artifact_id } => write!(
                formatter,
                "checked-proof citation target slice repeats artifact {artifact_id:?}"
            ),
            Self::NonDirectTarget { artifact_id } => write!(
                formatter,
                "artifact {artifact_id:?} is not a direct dependency of the checked proof"
            ),
        }
    }
}

impl Error for CheckedProofTargetSplitError {}

/// A selected artifact that cannot supply one proof-specific target split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelectedProofTargetSplitError {
    /// The source identity is absent from the supplied selected chain state.
    UnknownArtifact { artifact_id: ArtifactId },
    /// The selected source artifact is a definition rather than a proof.
    NotProof { artifact_id: ArtifactId },
    /// The caller-designated target slice is invalid for the selected proof.
    TargetSplit(CheckedProofTargetSplitError),
}

impl fmt::Display for SelectedProofTargetSplitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArtifact { artifact_id } => write!(
                formatter,
                "artifact {artifact_id:?} is not selected in the supplied artifact chain"
            ),
            Self::NotProof { artifact_id } => {
                write!(
                    formatter,
                    "selected artifact {artifact_id:?} is not a proof"
                )
            }
            Self::TargetSplit(source) => source.fmt(formatter),
        }
    }
}

impl Error for SelectedProofTargetSplitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TargetSplit(source) => Some(source),
            Self::UnknownArtifact { .. } | Self::NotProof { .. } => None,
        }
    }
}

/// Neutral arithmetic coupled to one checked or locally accepted source proof.
///
/// The target slice is stored in ascending identity order and determines the
/// division count. These values do not establish that any target is eligible,
/// entitled to a reward, credited, or associated with an actual burn.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct ProjectedCheckedProofTargetSplit {
    checked_proof_artifact_id: ArtifactId,
    targets: Box<[ArtifactId]>,
    citation_pool: NaoAtoms,
    per_target_share: NaoAtoms,
    unassigned_remainder: NaoAtoms,
}

impl ProjectedCheckedProofTargetSplit {
    /// Returns the content address of the checked or locally accepted proof.
    ///
    /// The identity alone proves no admission or finality. Success through the
    /// selected-proof path establishes only strict admission and membership in
    /// the supplied local artifact-chain state.
    pub const fn checked_proof_artifact_id(&self) -> ArtifactId {
        self.checked_proof_artifact_id
    }

    /// Returns the caller-designated direct targets in ascending identity order.
    pub fn targets(&self) -> &[ArtifactId] {
        &self.targets
    }

    /// Returns the complete numeric citation pool derived from the supplied fee.
    pub const fn citation_pool(&self) -> NaoAtoms {
        self.citation_pool
    }

    /// Returns the equal numeric share for every returned target.
    pub const fn per_target_share(&self) -> NaoAtoms {
        self.per_target_share
    }

    /// Returns the numeric citation-pool remainder not assigned by division.
    ///
    /// This value is not evidence that the remainder was burned or credited.
    pub const fn unassigned_remainder(&self) -> NaoAtoms {
        self.unassigned_remainder
    }
}

/// Couples caller-designated direct targets to exact citation-pool arithmetic.
///
/// Validation rejects a slice longer than this proof's distinct direct-
/// dependency set first, then the lowest duplicate target, and finally the
/// lowest target absent from that set. A proper subset, the complete set, and
/// an empty set are all valid because eligibility and completeness remain
/// external caller assertions. On success, the division count comes only from
/// the same sorted target slice returned in
/// [`ProjectedCheckedProofTargetSplit`].
///
/// This function validates direct membership only. It does not validate the
/// caller's eligibility assertion or grant any authority excluded by this
/// module.
pub fn project_checked_proof_target_split(
    proof: &CheckedProof,
    base_fee: FloorQualifiedArtifactBaseFee,
    caller_asserted_eligible_targets: &[ArtifactId],
) -> Result<ProjectedCheckedProofTargetSplit, CheckedProofTargetSplitError> {
    let direct_dependencies = proof.direct_artifact_dependencies();
    project_target_split(
        ArtifactId::from_proof_id(proof.proof_id()),
        &direct_dependencies,
        base_fee,
        caller_asserted_eligible_targets,
    )
}

/// Projects caller-designated targets for one locally selected proof artifact.
///
/// The source lookup precedes every target check: an absent artifact returns
/// [`SelectedProofTargetSplitError::UnknownArtifact`], and a selected definition
/// returns [`SelectedProofTargetSplitError::NotProof`]. For a selected proof,
/// target validation and arithmetic are identical to
/// [`project_checked_proof_target_split`]. The selected record proves local
/// strict admission into the supplied exact-head chain state only; it does not
/// prove that the supplied chain is consensus-canonical or that the artifact is
/// included or finalized by consensus, and the caller's eligibility and
/// completeness assertions remain external.
pub fn project_selected_proof_target_split(
    chain: &ArtifactChainState,
    proof_artifact_id: ArtifactId,
    base_fee: FloorQualifiedArtifactBaseFee,
    caller_asserted_eligible_targets: &[ArtifactId],
) -> Result<ProjectedCheckedProofTargetSplit, SelectedProofTargetSplitError> {
    let selected = chain.artifact_dag().artifact(proof_artifact_id).ok_or(
        SelectedProofTargetSplitError::UnknownArtifact {
            artifact_id: proof_artifact_id,
        },
    )?;
    let proof = selected
        .as_proof()
        .ok_or(SelectedProofTargetSplitError::NotProof {
            artifact_id: proof_artifact_id,
        })?;
    let direct_dependencies = proof.direct_artifact_dependencies();
    project_target_split(
        proof.artifact_id(),
        &direct_dependencies,
        base_fee,
        caller_asserted_eligible_targets,
    )
    .map_err(SelectedProofTargetSplitError::TargetSplit)
}

fn project_target_split(
    proof_artifact_id: ArtifactId,
    direct_dependencies: &[ArtifactId],
    base_fee: FloorQualifiedArtifactBaseFee,
    caller_asserted_eligible_targets: &[ArtifactId],
) -> Result<ProjectedCheckedProofTargetSplit, CheckedProofTargetSplitError> {
    if caller_asserted_eligible_targets.len() > direct_dependencies.len() {
        return Err(CheckedProofTargetSplitError::TooManyTargets {
            actual: caller_asserted_eligible_targets.len(),
            maximum: direct_dependencies.len(),
        });
    }

    let mut targets = caller_asserted_eligible_targets.to_vec();
    targets.sort_unstable();

    for pair in targets.windows(2) {
        if pair[0] == pair[1] {
            return Err(CheckedProofTargetSplitError::DuplicateTarget {
                artifact_id: pair[0],
            });
        }
    }

    for artifact_id in &targets {
        if direct_dependencies.binary_search(artifact_id).is_err() {
            return Err(CheckedProofTargetSplitError::NonDirectTarget {
                artifact_id: *artifact_id,
            });
        }
    }

    let target_count = u128::try_from(targets.len())
        .expect("the checked-proof target bound is representable in u128");
    let allocation = base_fee.partition().allocate_citation_pool(target_count);

    Ok(ProjectedCheckedProofTargetSplit {
        checked_proof_artifact_id: proof_artifact_id,
        targets: targets.into_boxed_slice(),
        citation_pool: allocation.citation_pool(),
        per_target_share: allocation.per_target_reward(),
        unassigned_remainder: allocation.burned_remainder(),
    })
}

#[cfg(test)]
mod tests;
