//! Content-addressed in-memory state for the NAOME proof DAG.
//!
//! Each admitted node is exactly one canonical Foundation proof. Its
//! [`ProofId`] is the node address and its checked external proof references
//! are the outgoing dependency edges. Admission delegates all decoding,
//! canonicality, mathematical checking, and identity validation to
//! [`LedgerState`] before retaining the resulting record.
//!
//! This crate defines neither a linear proof parent nor consensus, finality,
//! persistence, economy, or peer-to-peer synchronization.

mod proof_set;

use naome_ledger::{AcceptedProofRecord, LedgerError, LedgerState};
use naome_proof::ProofId;

pub use naome_ledger::{AddressedProofCandidate, PROOF_BATCH_MAX_CANDIDATES, ProofBatchError};

pub use proof_set::{
    PROOF_SET_PROOF_MAX_BYTES, ProofSetMembership, ProofSetProof, ProofSetProofError, ProofSetRoot,
};

use proof_set::AuthenticatedProofSet;

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

    /// Atomically admits one dependency-first canonical proof transaction.
    ///
    /// The final proof is the transaction root and every earlier proof must be
    /// transitively reachable from it. This unaddressed path is for trusted
    /// local construction and deterministic replay; requested network content
    /// must use [`Self::apply_rooted_canonical_proof_batch`].
    pub fn apply_canonical_proof_batch(
        &mut self,
        candidates: Vec<Vec<u8>>,
    ) -> Result<&AcceptedProofRecord, ProofBatchError> {
        let records = self.ledger.apply_canonical_proof_batch(candidates)?;
        let root = records
            .last()
            .expect("successful proof batches are nonempty")
            .proof_id();
        self.retain_records(records);
        Ok(self
            .records
            .get(root)
            .expect("the rooted batch inserted its final record"))
    }

    /// Atomically admits one dependency closure at expected content addresses.
    ///
    /// A batch error leaves both the checked ledger and authenticated proof set
    /// unchanged. The final candidate must be `requested_root`, and unrelated
    /// valid candidates are rejected before the transaction becomes visible.
    pub fn apply_rooted_canonical_proof_batch(
        &mut self,
        requested_root: ProofId,
        candidates: Vec<AddressedProofCandidate>,
    ) -> Result<&AcceptedProofRecord, ProofBatchError> {
        let records = self
            .ledger
            .apply_rooted_canonical_proof_batch(requested_root, candidates)?;
        self.retain_records(records);
        Ok(self
            .records
            .get(requested_root)
            .expect("the rooted batch inserted its requested root"))
    }

    fn retain_record(&mut self, record: AcceptedProofRecord) -> &AcceptedProofRecord {
        let Some(record) = self.records.insert(record) else {
            unreachable!("private ledger and authenticated proof set stay aligned")
        };
        record
    }

    fn retain_records(&mut self, records: Box<[AcceptedProofRecord]>) {
        for record in records.into_vec() {
            let _ = self.retain_record(record);
        }
    }
}

#[cfg(test)]
mod tests;
