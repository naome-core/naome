//! Content-addressed in-memory state for the NAOME artifact DAG.
//!
//! Each admitted node is exactly one canonical proof or conservative definition.
//! Its [`ArtifactId`] is the node address and its checked external references are
//! the outgoing dependency edges. Admission delegates all decoding,
//! canonicality, semantic checking, and identity validation to [`LedgerState`]
//! before retaining the resulting record.
//! Each [`ArtifactBlock`] binds exactly one artifact identity to exact before-and-
//! after [`ArtifactSetRoot`] values and one parent. [`ArtifactChainState`] places
//! those single-artifact blocks in one canonical exact-parent execution history
//! without claiming consensus inclusion or finality. Read-only validation runs
//! the same checks without selection; later application revalidates one direct
//! child against the then-current state.
//!
//! This crate defines no consensus selection, fork choice, reorganization,
//! finality, persistence, economy, or peer-to-peer synchronization.

mod artifact_set;
mod block;

use naome_ledger::{AcceptedArtifactRecord, ArtifactState, LedgerError, LedgerState};
use naome_proof::ArtifactId;

use artifact_set::AuthenticatedArtifactSet;
pub use artifact_set::{
    ARTIFACT_SET_PROOF_MAX_BYTES, ArtifactSetMembership, ArtifactSetProof, ArtifactSetProofError,
    ArtifactSetRoot,
};
pub use block::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactBlockDecodeError,
    ArtifactBlockId, ArtifactBlockPrepareError, ArtifactChainBranchSnapshot,
    ArtifactChainDefinition, ArtifactChainDefinitionDecodeError, ArtifactChainId,
    ArtifactChainState,
};

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
    pub(crate) const fn artifact_state(&self) -> &ArtifactState {
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

    pub(crate) fn projected_artifact_set_root(
        &self,
        artifact_id: ArtifactId,
    ) -> (ArtifactSetRoot, bool) {
        self.records.projected_root(artifact_id)
    }

    pub(crate) fn validate_canonical_artifact_bytes_with_expected_id(
        &self,
        bytes: Vec<u8>,
        artifact_id: ArtifactId,
    ) -> Result<(), LedgerError> {
        self.ledger
            .validate_canonical_artifact_bytes_with_expected_id(bytes, artifact_id)
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
