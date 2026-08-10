//! Deterministic proof ledger state transitions for NAOME.
//!
//! Single-proof paths admit one certificate. Rooted batch paths atomically
//! admit a bounded dependency-first closure. The authoring path normalizes an
//! owned certificate; strict byte paths reject any submission that is not
//! already its canonical root-proof normal form. Addressed paths additionally
//! bind checked bytes to expected [`ProofId`] values. Every path registers only
//! after all applicable admission checks succeed. Blocks, persistence, undo,
//! rewards, networking, and source parsing remain outside this crate.

use std::error::Error;
use std::fmt;

use naome_checker::{
    CheckError, CheckedProof, ProofState, ProofStateError, check_normal_form_with_state,
    normalize_and_check_with_state,
};
use naome_proof::{
    DerivationId, ProofCertificate, ProofCertificateError, ProofId, ProofStep, StatementId,
};

/// Maximum number of proofs in one atomic rooted admission.
pub const PROOF_BATCH_MAX_CANDIDATES: usize = 8;

/// One untrusted canonical-proof candidate bound to its requested address.
#[must_use]
pub struct AddressedProofCandidate {
    expected_proof_id: ProofId,
    canonical_proof_bytes: Vec<u8>,
}

impl fmt::Debug for AddressedProofCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddressedProofCandidate")
            .field("expected_proof_id", &self.expected_proof_id)
            .field(
                "canonical_proof_bytes_len",
                &self.canonical_proof_bytes.len(),
            )
            .finish()
    }
}

impl AddressedProofCandidate {
    /// Couples candidate bytes with the immutable address requested by a caller.
    pub const fn new(expected_proof_id: ProofId, canonical_proof_bytes: Vec<u8>) -> Self {
        Self {
            expected_proof_id,
            canonical_proof_bytes,
        }
    }

    /// Returns the address at which these bytes are expected to check.
    pub const fn expected_proof_id(&self) -> ProofId {
        self.expected_proof_id
    }
}

/// The immutable proof payload and metadata produced by one accepted transition.
#[derive(PartialEq, Eq)]
#[must_use]
pub struct AcceptedProofRecord {
    canonical_proof_bytes: Box<[u8]>,
    direct_dependencies: Box<[ProofId]>,
    proof_id: ProofId,
    derivation_id: DerivationId,
    statement_id: StatementId,
}

impl AcceptedProofRecord {
    /// Returns the exact canonical proof-certificate payload that was accepted.
    pub const fn canonical_proof_bytes(&self) -> &[u8] {
        &self.canonical_proof_bytes
    }

    /// Returns the directly cited proof identities in canonical step order.
    pub const fn direct_dependencies(&self) -> &[ProofId] {
        &self.direct_dependencies
    }

    /// Returns the concrete checked proof identity.
    pub const fn proof_id(&self) -> ProofId {
        self.proof_id
    }

    /// Returns the reference-transparent checked derivation identity.
    pub const fn derivation_id(&self) -> DerivationId {
        self.derivation_id
    }

    /// Returns the checked closed statement identity.
    pub const fn statement_id(&self) -> StatementId {
        self.statement_id
    }
}

impl fmt::Debug for AcceptedProofRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedProofRecord")
            .field(
                "canonical_proof_bytes_len",
                &self.canonical_proof_bytes.len(),
            )
            .field("direct_dependencies_len", &self.direct_dependencies.len())
            .field("proof_id", &self.proof_id)
            .field("derivation_id", &self.derivation_id)
            .field("statement_id", &self.statement_id)
            .finish()
    }
}

/// The accepted proof state after zero or more strict proof transitions.
///
/// The inner proof state is private so callers cannot interleave checking and
/// mutation. A transition contributes either one checked proof or one complete
/// atomic rooted transaction; every failure leaves the state unchanged.
#[derive(Default)]
#[must_use]
pub struct LedgerState {
    proof_state: ProofState,
}

impl LedgerState {
    /// Constructs an empty ledger state.
    pub const fn new() -> Self {
        Self {
            proof_state: ProofState::new(),
        }
    }

    /// Returns whether the selected concrete proof has been accepted.
    pub fn contains_proof(&self, proof_id: ProofId) -> bool {
        self.proof_state.contains_proof(proof_id)
    }

    /// Returns whether the selected derivation has been accepted.
    pub fn contains_derivation(&self, derivation_id: DerivationId) -> bool {
        self.proof_state.contains_derivation(derivation_id)
    }

    /// Returns whether the selected statement has been accepted.
    pub fn contains_statement(&self, statement_id: StatementId) -> bool {
        self.proof_state.contains_statement(statement_id)
    }

    /// Normalizes, checks, and atomically registers exactly one owned proof.
    ///
    /// This is the authoring path for an already constructed certificate. Use
    /// [`Self::apply_canonical_proof_bytes`] when the submitted representation
    /// itself must be canonical.
    ///
    /// External references resolve only from the state that existed before
    /// this call. The candidate is not visible while it is being checked. A
    /// checking or registration error leaves the state unchanged.
    pub fn apply(
        &mut self,
        certificate: ProofCertificate,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        let checked = normalize_and_check_with_state(certificate, &self.proof_state)
            .map_err(|source| LedgerError::Check { source })?;
        self.register_checked(checked)
    }

    /// Strictly decodes, checks, and atomically registers one canonical proof.
    ///
    /// The complete input must already equal its canonical root-proof normal
    /// form. A structurally valid but non-canonical submission is rejected
    /// rather than silently rewritten. Once exact equality is established, the
    /// submitted bytes become the accepted record payload. External references
    /// resolve only from the state that existed before this call.
    ///
    /// This entry point derives and accepts any resulting [`ProofId`]. Bytes
    /// received for one externally requested address must use
    /// [`Self::apply_canonical_proof_bytes_with_expected_id`] instead.
    pub fn apply_canonical_proof_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        self.apply_canonical_proof_bytes_inner(bytes, None)
    }

    /// Strictly admits canonical proof bytes only at the expected content address.
    ///
    /// Decoding, canonicality, mathematical checking, and external-reference
    /// resolution precede the address comparison. A different checked
    /// [`ProofId`] returns [`LedgerError::ProofIdMismatch`] before registration,
    /// leaving the state unchanged.
    pub fn apply_canonical_proof_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected_proof_id: ProofId,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        self.apply_canonical_proof_bytes_inner(bytes, Some(expected_proof_id))
    }

    /// Atomically admits a dependency-first canonical proof transaction.
    ///
    /// The final proof is the transaction root. Every earlier candidate must
    /// be transitively reachable from that root, and every cited batch proof
    /// must appear earlier. This unaddressed path derives all proof identities;
    /// externally requested closures must use
    /// [`Self::apply_rooted_canonical_proof_batch`] instead.
    pub fn apply_canonical_proof_batch(
        &mut self,
        candidates: Vec<Vec<u8>>,
    ) -> Result<Box<[AcceptedProofRecord]>, ProofBatchError> {
        preflight_batch_size(candidates.len())?;
        let candidates = candidates
            .into_iter()
            .map(|canonical_proof_bytes| BatchCandidate {
                expected_proof_id: None,
                canonical_proof_bytes,
            })
            .collect();
        self.apply_canonical_proof_batch_inner(None, candidates)
    }

    /// Atomically admits a rooted closure at immutable expected addresses.
    ///
    /// Candidates must be unique, dependency-first, and end with
    /// `requested_root`. Every candidate is strictly checked against the
    /// unchanged selected state plus earlier candidates before any registration
    /// becomes visible. Any failure discards the complete transaction.
    pub fn apply_rooted_canonical_proof_batch(
        &mut self,
        requested_root: ProofId,
        candidates: Vec<AddressedProofCandidate>,
    ) -> Result<Box<[AcceptedProofRecord]>, ProofBatchError> {
        preflight_batch_size(candidates.len())?;
        let candidates = candidates
            .into_iter()
            .map(|candidate| BatchCandidate {
                expected_proof_id: Some(candidate.expected_proof_id),
                canonical_proof_bytes: candidate.canonical_proof_bytes,
            })
            .collect();
        self.apply_canonical_proof_batch_inner(Some(requested_root), candidates)
    }

    fn apply_canonical_proof_batch_inner(
        &mut self,
        requested_root: Option<ProofId>,
        candidates: Vec<BatchCandidate>,
    ) -> Result<Box<[AcceptedProofRecord]>, ProofBatchError> {
        preflight_batch_addresses(requested_root, &candidates)?;

        self.proof_state.apply_batch(|batch| {
            let mut records = Vec::with_capacity(candidates.len());
            for (index, candidate) in candidates.into_iter().enumerate() {
                let expected = candidate.expected_proof_id;
                let normal_form = decode_canonical_normal_form(candidate.canonical_proof_bytes)
                    .map_err(|source| ProofBatchError::Candidate {
                        index,
                        expected,
                        source,
                    })?;
                let checked = batch.check_normal_form(normal_form).map_err(|source| {
                    ProofBatchError::Candidate {
                        index,
                        expected,
                        source: LedgerError::Check { source },
                    }
                })?;
                if let Some(expected) = expected
                    && checked.proof_id() != expected
                {
                    return Err(ProofBatchError::Candidate {
                        index,
                        expected: Some(expected),
                        source: LedgerError::ProofIdMismatch {
                            expected,
                            actual: checked.proof_id(),
                        },
                    });
                }
                let metadata = RecordMetadata::from_checked(&checked);
                let canonical_proof_bytes =
                    batch
                        .register(checked)
                        .map_err(|source| ProofBatchError::Candidate {
                            index,
                            expected,
                            source: LedgerError::State { source },
                        })?;
                records.push(metadata.into_record(canonical_proof_bytes));
            }

            if let Some((index, proof_id)) = first_unreachable_candidate(&records) {
                return Err(ProofBatchError::UnreachableCandidate { index, proof_id });
            }
            Ok(records.into_boxed_slice())
        })
    }

    fn apply_canonical_proof_bytes_inner(
        &mut self,
        bytes: Vec<u8>,
        expected_proof_id: Option<ProofId>,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        let normal_form = decode_canonical_normal_form(bytes)?;
        let checked = check_normal_form_with_state(normal_form, &self.proof_state)
            .map_err(|source| LedgerError::Check { source })?;
        if let Some(expected) = expected_proof_id
            && checked.proof_id() != expected
        {
            return Err(LedgerError::ProofIdMismatch {
                expected,
                actual: checked.proof_id(),
            });
        }
        self.register_checked(checked)
    }

    fn register_checked(
        &mut self,
        checked: CheckedProof,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        let metadata = RecordMetadata::from_checked(&checked);
        let canonical_proof_bytes = self
            .proof_state
            .register(checked)
            .map_err(|source| LedgerError::State { source })?;
        Ok(metadata.into_record(canonical_proof_bytes))
    }
}

struct BatchCandidate {
    expected_proof_id: Option<ProofId>,
    canonical_proof_bytes: Vec<u8>,
}

fn preflight_batch_size(actual: usize) -> Result<(), ProofBatchError> {
    if actual == 0 {
        return Err(ProofBatchError::Empty);
    }
    if actual > PROOF_BATCH_MAX_CANDIDATES {
        return Err(ProofBatchError::TooManyCandidates {
            actual,
            maximum: PROOF_BATCH_MAX_CANDIDATES,
        });
    }
    Ok(())
}

fn preflight_batch_addresses(
    requested_root: Option<ProofId>,
    candidates: &[BatchCandidate],
) -> Result<(), ProofBatchError> {
    for (index, candidate) in candidates.iter().enumerate() {
        if let Some(proof_id) = candidate.expected_proof_id
            && let Some(first_index) = candidates[..index]
                .iter()
                .position(|earlier| earlier.expected_proof_id == Some(proof_id))
        {
            return Err(ProofBatchError::DuplicateExpectedProofId {
                first_index,
                duplicate_index: index,
                proof_id,
            });
        }
    }

    if let Some(requested_root) = requested_root {
        let actual = candidates
            .last()
            .and_then(|candidate| candidate.expected_proof_id)
            .expect("addressed batches contain addressed candidates");
        if actual != requested_root {
            return Err(ProofBatchError::RootNotLast {
                requested: requested_root,
                actual,
            });
        }
    }
    Ok(())
}

fn decode_canonical_normal_form(
    bytes: Vec<u8>,
) -> Result<naome_proof::ProofNormalForm, LedgerError> {
    let certificate = ProofCertificate::from_canonical_bytes(&bytes)
        .map_err(|source| LedgerError::Decode { source })?;
    certificate
        .into_unchecked_normal_form()
        .with_matching_canonical_bytes(bytes.into_boxed_slice())
        .ok_or(LedgerError::NonCanonicalProof)
}

struct RecordMetadata {
    direct_dependencies: Box<[ProofId]>,
    proof_id: ProofId,
    derivation_id: DerivationId,
    statement_id: StatementId,
}

impl RecordMetadata {
    fn from_checked(checked: &CheckedProof) -> Self {
        let steps = checked.normal_form().certificate().steps();
        let dependency_count = steps
            .iter()
            .filter(|step| matches!(step, ProofStep::ProofReference { .. }))
            .count();
        let mut direct_dependencies = Vec::with_capacity(dependency_count);
        for step in steps {
            if let ProofStep::ProofReference { proof_id } = step {
                direct_dependencies.push(*proof_id);
            }
        }
        Self {
            direct_dependencies: direct_dependencies.into_boxed_slice(),
            proof_id: checked.proof_id(),
            derivation_id: checked.derivation_id(),
            statement_id: checked.statement_id(),
        }
    }

    fn into_record(self, canonical_proof_bytes: Box<[u8]>) -> AcceptedProofRecord {
        AcceptedProofRecord {
            canonical_proof_bytes,
            direct_dependencies: self.direct_dependencies,
            proof_id: self.proof_id,
            derivation_id: self.derivation_id,
            statement_id: self.statement_id,
        }
    }
}

fn first_unreachable_candidate(records: &[AcceptedProofRecord]) -> Option<(usize, ProofId)> {
    let mut reachable = [false; PROOF_BATCH_MAX_CANDIDATES];
    reachable[records.len() - 1] = true;
    for index in (0..records.len()).rev() {
        if !reachable[index] {
            continue;
        }
        for dependency in records[index].direct_dependencies() {
            if let Some(dependency_index) = records[..index]
                .iter()
                .position(|record| record.proof_id() == *dependency)
            {
                reachable[dependency_index] = true;
            }
        }
    }
    records
        .iter()
        .enumerate()
        .find(|(index, _)| !reachable[*index])
        .map(|(index, record)| (index, record.proof_id()))
}

/// A fail-closed single-proof ledger transition error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    /// The submitted bytes are not one structurally valid complete certificate.
    Decode { source: ProofCertificateError },
    /// The submitted certificate is not already its root-proof normal form.
    NonCanonicalProof,
    /// Mathematical proof checking failed.
    Check { source: CheckError },
    /// The checked proof does not have the externally expected content address.
    ProofIdMismatch { expected: ProofId, actual: ProofId },
    /// The checked proof could not be registered in the pre-transition state.
    State { source: ProofStateError },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { source } => write!(formatter, "proof decoding failed: {source}"),
            Self::NonCanonicalProof => {
                formatter.write_str("submitted proof is not in canonical root-proof normal form")
            }
            Self::Check { source } => write!(formatter, "proof checking failed: {source}"),
            Self::ProofIdMismatch { expected, actual } => write!(
                formatter,
                "proof identity mismatch: expected {expected:?}, checked {actual:?}"
            ),
            Self::State { source } => write!(formatter, "proof registration failed: {source}"),
        }
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { source } => Some(source),
            Self::NonCanonicalProof => None,
            Self::Check { source } => Some(source),
            Self::ProofIdMismatch { .. } => None,
            Self::State { source } => Some(source),
        }
    }
}

/// A fail-closed atomic rooted proof-batch admission error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofBatchError {
    /// A transaction must contain at least one proof candidate.
    Empty,
    /// The transaction exceeds the fixed candidate-count bound.
    TooManyCandidates { actual: usize, maximum: usize },
    /// Two addressed candidates claim the same expected proof identity.
    DuplicateExpectedProofId {
        first_index: usize,
        duplicate_index: usize,
        proof_id: ProofId,
    },
    /// The final addressed candidate is not the immutable requested root.
    RootNotLast { requested: ProofId, actual: ProofId },
    /// One candidate failed its ordinary strict single-proof checks.
    Candidate {
        index: usize,
        expected: Option<ProofId>,
        source: LedgerError,
    },
    /// One valid candidate is not transitively required by the final root.
    UnreachableCandidate { index: usize, proof_id: ProofId },
}

impl fmt::Display for ProofBatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("proof batch is empty"),
            Self::TooManyCandidates { actual, maximum } => write!(
                formatter,
                "proof batch has {actual} candidates; the limit is {maximum}"
            ),
            Self::DuplicateExpectedProofId {
                first_index,
                duplicate_index,
                proof_id,
            } => write!(
                formatter,
                "proof batch candidate {duplicate_index} repeats address {proof_id:?} from candidate {first_index}"
            ),
            Self::RootNotLast { requested, actual } => write!(
                formatter,
                "proof batch requested root {requested:?}, but the final candidate expects {actual:?}"
            ),
            Self::Candidate {
                index,
                expected,
                source,
            } => match expected {
                Some(expected) => write!(
                    formatter,
                    "proof batch candidate {index} at {expected:?} failed: {source}"
                ),
                None => write!(formatter, "proof batch candidate {index} failed: {source}"),
            },
            Self::UnreachableCandidate { index, proof_id } => write!(
                formatter,
                "proof batch candidate {index} ({proof_id:?}) is not reachable from the final root"
            ),
        }
    }
}

impl Error for ProofBatchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Candidate { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
