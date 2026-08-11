//! Content-addressed in-memory state for the NAOME proof DAG.
//!
//! Each admitted node is exactly one canonical Foundation proof. Its
//! [`ProofId`] is the node address and its checked external proof references
//! are the outgoing dependency edges. Admission delegates all decoding,
//! canonicality, mathematical checking, and identity validation to
//! [`LedgerState`] before retaining the resulting record.
//! [`ProofTransition`] additionally binds one bounded dependency-first rooted
//! batch to exact before-and-after [`ProofSetRoot`] values. [`ProofBlock`] and
//! [`ProofChainState`] place those transitions in one canonical exact-parent
//! execution history without claiming consensus inclusion or finality.
//!
//! This crate defines no consensus selection, fork choice, reorganization,
//! finality, persistence, economy, or peer-to-peer synchronization.

mod block;
mod proof_set;
mod transition;

use std::error::Error;
use std::fmt;

use naome_ledger::{AcceptedProofRecord, LedgerError, LedgerState};
use naome_proof::ProofId;

pub use naome_ledger::{AddressedProofCandidate, PROOF_BATCH_MAX_CANDIDATES, ProofBatchError};

pub use block::{
    PROOF_BLOCK_MAX_BYTES, ProofBlock, ProofBlockApplyError, ProofBlockDecodeError, ProofBlockId,
    ProofChainId, ProofChainState,
};
pub use proof_set::{
    PROOF_SET_PROOF_MAX_BYTES, ProofSetMembership, ProofSetProof, ProofSetProofError, ProofSetRoot,
};
pub use transition::{
    PROOF_TRANSITION_MAX_BYTES, ProofTransition, ProofTransitionError, ProofTransitionId,
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

    /// Prepares a structurally valid transition from this selected state.
    ///
    /// The supplied identities remain in exact dependency-first, root-last
    /// order. Preparation projects the resulting authenticated root without
    /// checking proof bytes or mutating selected state. Only
    /// [`Self::apply_proof_transition`] establishes that the identities name a
    /// valid root-closed proof transaction.
    pub fn prepare_proof_transition(
        &self,
        proof_ids: Vec<ProofId>,
    ) -> Result<ProofTransition, ProofTransitionError> {
        let previous_root = self.proof_set_root();
        let transition = ProofTransition::new(previous_root, previous_root, proof_ids)?;
        let (resulting_root, already_selected) =
            self.records.projected_root(transition.proof_ids());
        if let Some((index, proof_id)) = already_selected {
            return Err(ProofTransitionError::AlreadySelectedProofId { index, proof_id });
        }
        Ok(transition.with_resulting_root(resulting_root))
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

    /// Atomically applies one canonical proof-state transition.
    ///
    /// State binding, exact candidate correlation, and read-only resulting-root
    /// projection all precede the existing rooted proof-batch admission. A
    /// failure leaves the ledger, retained records, authenticated root, and
    /// proof-set witnesses unchanged.
    pub fn apply_proof_transition(
        &mut self,
        transition: &ProofTransition,
        candidates: Vec<AddressedProofCandidate>,
    ) -> Result<&AcceptedProofRecord, ProofTransitionApplyError> {
        let actual_previous_root = self.proof_set_root();
        if actual_previous_root != transition.previous_proof_set_root() {
            return Err(ProofTransitionApplyError::PreviousProofSetRootMismatch {
                expected: transition.previous_proof_set_root(),
                actual: actual_previous_root,
            });
        }

        if candidates.len() != transition.proof_ids().len() {
            return Err(ProofTransitionApplyError::CandidateCountMismatch {
                expected: transition.proof_ids().len(),
                actual: candidates.len(),
            });
        }
        for (index, (expected, candidate)) in transition
            .proof_ids()
            .iter()
            .copied()
            .zip(&candidates)
            .enumerate()
        {
            let actual = candidate.expected_proof_id();
            if actual != expected {
                return Err(ProofTransitionApplyError::CandidateProofIdMismatch {
                    index,
                    expected,
                    actual,
                });
            }
        }

        let (projected_root, _) = self.records.projected_root(transition.proof_ids());
        if projected_root != transition.resulting_proof_set_root() {
            return Err(ProofTransitionApplyError::ResultingProofSetRootMismatch {
                expected: transition.resulting_proof_set_root(),
                actual: projected_root,
            });
        }

        self.apply_rooted_canonical_proof_batch(transition.root_proof_id(), candidates)
            .map_err(|source| ProofTransitionApplyError::Batch { source })
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

/// A fail-closed proof-state transition application error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofTransitionApplyError {
    /// The transition is bound to a different selected proof set.
    PreviousProofSetRootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
    /// The supplied proof payload count differs from the commitment.
    CandidateCountMismatch { expected: usize, actual: usize },
    /// One candidate is bound to a different proof identity than its position.
    CandidateProofIdMismatch {
        index: usize,
        expected: ProofId,
        actual: ProofId,
    },
    /// Read-only projection did not reproduce the committed resulting root.
    ResultingProofSetRootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
    /// Strict rooted proof admission rejected the complete transition.
    Batch { source: ProofBatchError },
}

impl fmt::Display for ProofTransitionApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreviousProofSetRootMismatch { expected, actual } => write!(
                formatter,
                "proof transition previous root mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateCountMismatch { expected, actual } => write!(
                formatter,
                "proof transition commits {expected} candidates but received {actual}"
            ),
            Self::CandidateProofIdMismatch {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "proof transition candidate {index} expected {expected:?}, received {actual:?}"
            ),
            Self::ResultingProofSetRootMismatch { expected, actual } => write!(
                formatter,
                "proof transition resulting root mismatch: expected {expected:?}, projected {actual:?}"
            ),
            Self::Batch { source } => {
                write!(formatter, "proof transition admission failed: {source}")
            }
        }
    }
}

impl Error for ProofTransitionApplyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Batch { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
