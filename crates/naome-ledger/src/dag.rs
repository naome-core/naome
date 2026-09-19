//! Checked artifact DAG used inside the complete ledger's proof library.
//! Standalone DAGs support mathematical authoring and grant no selected history,
//! publication provenance, rewards, or finality.

use crate::artifact_set::AuthenticatedArtifactSet;
use crate::{AcceptedArtifactRecord, ArtifactState, LedgerError, LedgerState};
use crate::{ArtifactSetProof, ArtifactSetRoot};
use naome_proof::ArtifactId;

/// A selected, monotonically growing set of accepted artifact-DAG nodes.
///
/// Both the checked resolver state and retained records are private so callers
/// cannot insert unverified bytes, identities, or dependency edges.
#[derive(Clone, Default)]
#[must_use]
pub struct ArtifactDag {
    ledger: LedgerState,
    records: AuthenticatedArtifactSet<AcceptedArtifactRecord>,
}

impl ArtifactDag {
    /// Constructs an empty artifact DAG.
    pub const fn new() -> Self {
        Self {
            ledger: LedgerState::new(),
            records: AuthenticatedArtifactSet::new(),
        }
    }

    /// Returns the number of retained artifacts.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no artifacts have been retained.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns one locally accepted artifact record by its content address.
    pub fn artifact(&self, artifact_id: ArtifactId) -> Option<&AcceptedArtifactRecord> {
        self.records.get(artifact_id)
    }

    /// Returns immutable access to the selected checked-artifact resolver state.
    pub const fn artifact_state(&self) -> &ArtifactState {
        self.ledger.artifact_state()
    }

    /// Returns the authenticated root of the selected exact [`ArtifactId`] set.
    pub fn artifact_set_root(&self) -> ArtifactSetRoot {
        self.records.root()
    }

    /// Returns a compact membership or non-membership proof for `artifact_id`.
    pub fn artifact_set_proof(&self, artifact_id: ArtifactId) -> ArtifactSetProof {
        self.records.proof(artifact_id)
    }

    /// Strictly admits and retains one canonical artifact.
    ///
    /// Every direct dependency must already belong to this selected state. A
    /// failure leaves both the checked ledger and authenticated artifact set
    /// unchanged. This entry point is not bound to an externally expected
    /// address; content-addressed retrieval must use
    /// [`Self::apply_canonical_artifact_bytes_with_expected_id`].
    pub fn apply_canonical_artifact_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<&AcceptedArtifactRecord, LedgerError> {
        let record = self.ledger.apply_canonical_artifact_bytes(bytes)?;
        Ok(self.retain_record(record))
    }

    /// Strictly admits one canonical artifact at an expected content address.
    ///
    /// A checked identity mismatch is rejected by the ledger before either the
    /// ledger state or authenticated artifact set changes.
    pub fn apply_canonical_artifact_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected_artifact_id: ArtifactId,
    ) -> Result<&AcceptedArtifactRecord, LedgerError> {
        let record = self
            .ledger
            .apply_canonical_artifact_bytes_with_expected_id(bytes, expected_artifact_id)?;
        Ok(self.retain_record(record))
    }

    /// Projects an exact set insertion without granting publication or finality.
    pub fn projected_artifact_set_root(&self, artifact_id: ArtifactId) -> (ArtifactSetRoot, bool) {
        self.records.projected_root(artifact_id)
    }

    /// Performs strict addressed admission checks without changing the DAG.
    pub fn validate_canonical_artifact_bytes_with_expected_id(
        &self,
        bytes: Vec<u8>,
        artifact_id: ArtifactId,
    ) -> Result<(), LedgerError> {
        self.ledger
            .validate_canonical_artifact_bytes_with_expected_id(bytes, artifact_id)
    }

    /// Consumes an already checked, metered normal proof and binds its expected
    /// identity before registration. Only ledger verification can use this path;
    /// callers supplying bytes must use strict decode/check admission above.
    pub(crate) fn admit_checked_proof(
        &mut self,
        checked: naome_checker::CheckedProof,
        expected: naome_proof::ProofId,
    ) -> Result<&AcceptedArtifactRecord, LedgerError> {
        let record = self.ledger.admit_checked_proof(checked, expected)?;
        Ok(self.retain_record(AcceptedArtifactRecord::Proof(record)))
    }

    fn retain_record(&mut self, record: AcceptedArtifactRecord) -> &AcceptedArtifactRecord {
        let Some(record) = self.records.insert(record) else {
            unreachable!("private ledger and authenticated artifact set stay aligned")
        };
        record
    }
}

#[cfg(test)]
mod tests;
