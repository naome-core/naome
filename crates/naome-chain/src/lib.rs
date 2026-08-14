//! Content-addressed in-memory state for the NAOME proof DAG.
//!
//! Each admitted node is exactly one canonical Foundation proof. Its
//! [`ProofId`] is the node address and its checked external proof references
//! are the outgoing dependency edges. Admission delegates all decoding,
//! canonicality, mathematical checking, and identity validation to
//! [`LedgerState`] before retaining the resulting record.
//! Each [`ProofBlock`] binds exactly one proof identity to exact before-and-
//! after [`ProofSetRoot`] values and one parent. [`ProofChainState`] places
//! those single-proof blocks in one canonical exact-parent execution history
//! without claiming consensus inclusion or finality. Read-only validation runs
//! the same checks without selection; later application revalidates one direct
//! child against the then-current state.
//!
//! This crate defines no consensus selection, fork choice, reorganization,
//! finality, persistence, economy, or peer-to-peer synchronization.

mod block;
mod proof_set;

use naome_ledger::{AcceptedProofRecord, LedgerError, LedgerState, ProofState};
use naome_proof::ProofId;

pub use block::{
    PROOF_BLOCK_BYTES, ProofBlock, ProofBlockApplyError, ProofBlockDecodeError, ProofBlockId,
    ProofBlockPrepareError, ProofChainDefinition, ProofChainDefinitionDecodeError, ProofChainId,
    ProofChainState,
};
use proof_set::AuthenticatedProofSet;
pub use proof_set::{
    PROOF_SET_PROOF_MAX_BYTES, ProofSetMembership, ProofSetProof, ProofSetProofError, ProofSetRoot,
};

/// A selected, monotonically growing set of accepted proof-DAG nodes.
///
/// Both the checked resolver state and retained records are private so callers
/// cannot insert unverified bytes, identities, or dependency edges.
#[derive(Default)]
#[must_use]
pub struct ProofDag {
    ledger: LedgerState,
    records: AuthenticatedProofSet<AcceptedProofRecord>,
}

impl ProofDag {
    /// Constructs an empty proof DAG.
    pub const fn new() -> Self {
        Self {
            ledger: LedgerState::new(),
            records: AuthenticatedProofSet::new(),
        }
    }

    /// Returns the number of retained proof nodes.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no proof nodes have been retained.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns one locally accepted proof record by its content address.
    pub fn proof(&self, proof_id: ProofId) -> Option<&AcceptedProofRecord> {
        self.records.get(proof_id)
    }

    /// Returns immutable access to the selected checked-proof resolver state.
    pub(crate) const fn proof_state(&self) -> &ProofState {
        self.ledger.proof_state()
    }

    /// Returns the authenticated root of the selected exact [`ProofId`] set.
    pub fn proof_set_root(&self) -> ProofSetRoot {
        self.records.root()
    }

    /// Returns a compact membership or non-membership proof for `proof_id`.
    pub fn proof_set_proof(&self, proof_id: ProofId) -> ProofSetProof {
        self.records.proof(proof_id)
    }

    /// Strictly admits and retains one canonical proof node.
    ///
    /// Every direct dependency must already belong to this selected state. A
    /// failure leaves both the checked ledger and authenticated proof set
    /// unchanged. This entry point is not bound to an externally expected
    /// address; content-addressed retrieval must use
    /// [`Self::apply_canonical_proof_bytes_with_expected_id`].
    pub fn apply_canonical_proof_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<&AcceptedProofRecord, LedgerError> {
        let record = self.ledger.apply_canonical_proof_bytes(bytes)?;
        Ok(self.retain_record(record))
    }

    /// Strictly admits one canonical proof node at an expected content address.
    ///
    /// A checked identity mismatch is rejected by the ledger before either the
    /// ledger state or authenticated proof set changes.
    pub fn apply_canonical_proof_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected_proof_id: ProofId,
    ) -> Result<&AcceptedProofRecord, LedgerError> {
        let record = self
            .ledger
            .apply_canonical_proof_bytes_with_expected_id(bytes, expected_proof_id)?;
        Ok(self.retain_record(record))
    }

    pub(crate) fn projected_proof_set_root(&self, proof_id: ProofId) -> (ProofSetRoot, bool) {
        self.records.projected_root(proof_id)
    }

    pub(crate) fn validate_canonical_proof_bytes_with_expected_id(
        &self,
        bytes: Vec<u8>,
        proof_id: ProofId,
    ) -> Result<(), LedgerError> {
        self.ledger
            .validate_canonical_proof_bytes_with_expected_id(bytes, proof_id)
    }

    fn retain_record(&mut self, record: AcceptedProofRecord) -> &AcceptedProofRecord {
        let Some(record) = self.records.insert(record) else {
            unreachable!("private ledger and authenticated proof set stay aligned")
        };
        record
    }
}

#[cfg(test)]
mod tests;
