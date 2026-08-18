//! Pairwise caller-supplied artifact-inclusion priority ordering.
//!
//! This module couples one caller-supplied [`ArtifactId`] with one
//! caller-supplied numeric [`NaoAtoms`] inclusion bid. Its total order ranks a
//! higher bid ahead and, for equal bids, a lower artifact identity ahead. It
//! does not establish candidate validity, availability, or admissibility; fee
//! calculation, authorization, or payment; proposer selection or entitlement;
//! lock, round, proposal, inclusion, finality, or block-order authority; or
//! economic or consensus state.

use std::cmp::Ordering;

use naome_economy::NaoAtoms;
use naome_proof::ArtifactId;

/// One caller-supplied artifact identity and numeric inclusion bid.
///
/// [`Ord::cmp`] returns [`Ordering::Greater`] when `self` ranks ahead: first by
/// higher bid, then by lower [`ArtifactId`]. Equal ordering therefore requires
/// the same bid and artifact identity. The ordering is arithmetic only and
/// grants none of the protocol authority excluded by this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ArtifactInclusionPriority {
    artifact_id: ArtifactId,
    inclusion_bid: NaoAtoms,
}

impl ArtifactInclusionPriority {
    /// Couples one caller-supplied artifact identity and inclusion bid.
    pub const fn new(artifact_id: ArtifactId, inclusion_bid: NaoAtoms) -> Self {
        Self {
            artifact_id,
            inclusion_bid,
        }
    }

    /// Returns the caller-supplied artifact identity.
    pub const fn artifact_id(self) -> ArtifactId {
        self.artifact_id
    }

    /// Returns the caller-supplied numeric inclusion bid.
    pub const fn inclusion_bid(self) -> NaoAtoms {
        self.inclusion_bid
    }
}

impl Ord for ArtifactInclusionPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inclusion_bid
            .cmp(&other.inclusion_bid)
            .then_with(|| other.artifact_id.cmp(&self.artifact_id))
    }
}

impl PartialOrd for ArtifactInclusionPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests;
