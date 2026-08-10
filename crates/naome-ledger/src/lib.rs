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
mod tests {
    use std::error::Error;

    use naome_checker::{
        CheckError, ProofStateError, normalize_and_check, normalize_and_check_with_state,
    };
    use naome_foundation::{Formula, FreeVariable, LogicError, Separation, ZfcAxiom};
    use naome_proof::{
        CERTIFICATE_MAX_BYTES, ProofCertificate, ProofCertificateError, ProofId, ProofStep,
    };

    use super::{
        AddressedProofCandidate, LedgerError, LedgerState, PROOF_BATCH_MAX_CANDIDATES,
        ProofBatchError,
    };

    fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
        ProofCertificate::new(steps).unwrap()
    }

    fn identity(variable: FreeVariable) -> ProofCertificate {
        certificate(vec![
            ProofStep::EqualityReflexivity { variable },
            ProofStep::Generalization {
                premise: 0,
                variable,
            },
        ])
    }

    fn identity_detour(variable: FreeVariable) -> ProofCertificate {
        let equality = Formula::equal(variable, variable);
        certificate(vec![
            ProofStep::EqualityReflexivity { variable },
            ProofStep::Simplification {
                antecedent: equality.clone(),
                consequent: equality,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable,
            },
        ])
    }

    fn referenced_generalization(proof_id: ProofId, variable: FreeVariable) -> ProofCertificate {
        let equality = Formula::equal(variable, variable);
        let identity = Formula::for_all(variable, equality);
        certificate(vec![
            ProofStep::ProofReference { proof_id },
            ProofStep::VacuousUniversal { formula: identity },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ])
    }

    fn proof_using_every_reference(
        references: &[(ProofId, Formula)],
        conclusion_axiom: ZfcAxiom,
    ) -> ProofCertificate {
        let mut steps = references
            .iter()
            .map(|(proof_id, _)| ProofStep::ProofReference {
                proof_id: *proof_id,
            })
            .collect::<Vec<_>>();
        let conclusion = conclusion_axiom.formula();
        steps.push(ProofStep::ZfcAxiom(conclusion_axiom));
        let mut conclusion_step = u32::try_from(steps.len() - 1).unwrap();

        for (reference_step, (_, premise)) in references.iter().enumerate().rev() {
            let implication_step = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStep::Simplification {
                antecedent: conclusion.clone(),
                consequent: premise.clone(),
            });
            let conditional_step = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStep::ModusPonens {
                premise: conclusion_step,
                implication: implication_step,
            });
            conclusion_step = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStep::ModusPonens {
                premise: u32::try_from(reference_step).unwrap(),
                implication: conditional_step,
            });
        }

        certificate(steps)
    }

    fn canonical_bytes(certificate: ProofCertificate) -> Vec<u8> {
        certificate
            .into_unchecked_normal_form()
            .into_canonical_bytes()
            .into_vec()
    }

    fn axiom_candidate(axiom: ZfcAxiom) -> (Vec<u8>, ProofId) {
        let proof = certificate(vec![ProofStep::ZfcAxiom(axiom)]);
        let proof_id = normalize_and_check(proof.clone()).unwrap().proof_id();
        (canonical_bytes(proof), proof_id)
    }

    fn referenced_generalization_bytes(proof_id: ProofId, variable: FreeVariable) -> Vec<u8> {
        canonical_bytes(certificate(vec![
            ProofStep::ProofReference { proof_id },
            ProofStep::Generalization {
                premise: 0,
                variable,
            },
        ]))
    }

    fn reordered_identity_detour(variable: FreeVariable) -> ProofCertificate {
        let equality = Formula::equal(variable, variable);
        certificate(vec![
            ProofStep::Simplification {
                antecedent: equality.clone(),
                consequent: equality,
            },
            ProofStep::EqualityReflexivity { variable },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 0,
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable,
            },
        ])
    }

    fn duplicate_identity(variable: FreeVariable) -> ProofCertificate {
        let equality = Formula::equal(variable, variable);
        let identity = Formula::implies(equality.clone(), equality.clone());
        certificate(vec![
            ProofStep::EqualityReflexivity { variable },
            ProofStep::EqualityReflexivity { variable },
            ProofStep::Simplification {
                antecedent: equality.clone(),
                consequent: equality,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStep::Simplification {
                antecedent: identity.clone(),
                consequent: identity,
            },
            ProofStep::ModusPonens {
                premise: 3,
                implication: 5,
            },
            ProofStep::ModusPonens {
                premise: 4,
                implication: 6,
            },
            ProofStep::Generalization {
                premise: 7,
                variable,
            },
        ])
    }

    #[test]
    fn canonical_bytes_match_authoring_admission_and_duplicate_semantics() {
        let variable = FreeVariable::new(42);
        let bytes = canonical_bytes(identity(variable));
        let mut strict = LedgerState::new();
        let strict_applied = strict.apply_canonical_proof_bytes(bytes.clone()).unwrap();

        let mut authoring = LedgerState::new();
        let authoring_applied = authoring.apply(identity(variable)).unwrap();
        assert_eq!(strict_applied, authoring_applied);
        assert_eq!(strict_applied.canonical_proof_bytes(), bytes);
        assert!(strict_applied.direct_dependencies().is_empty());
        assert_eq!(
            strict.apply_canonical_proof_bytes(bytes),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateProof {
                    proof_id: strict_applied.proof_id(),
                },
            })
        );
    }

    #[test]
    fn expected_proof_id_is_checked_before_registration_and_duplicate_state() {
        let variable = FreeVariable::new(41);
        let bytes = canonical_bytes(identity(variable));
        let checked = normalize_and_check(identity(variable)).unwrap();
        let actual = checked.proof_id();
        let expected = ProofId::from_bytes([0x91; 32]);
        assert_ne!(expected, actual);
        let mut ledger = LedgerState::new();

        let mismatch = ledger
            .apply_canonical_proof_bytes_with_expected_id(bytes.clone(), expected)
            .unwrap_err();
        assert_eq!(mismatch, LedgerError::ProofIdMismatch { expected, actual });
        assert!(mismatch.source().is_none());
        assert!(!ledger.contains_proof(actual));
        assert!(!ledger.contains_derivation(checked.derivation_id()));
        assert!(!ledger.contains_statement(checked.statement_id()));

        let applied = ledger
            .apply_canonical_proof_bytes_with_expected_id(bytes.clone(), actual)
            .unwrap();
        assert_eq!(applied.proof_id(), actual);
        assert_eq!(applied.canonical_proof_bytes(), bytes);

        assert_eq!(
            ledger.apply_canonical_proof_bytes_with_expected_id(bytes.clone(), expected),
            Err(LedgerError::ProofIdMismatch { expected, actual })
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes_with_expected_id(bytes, actual),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateProof { proof_id: actual },
            })
        );
    }

    #[test]
    fn validation_errors_precede_expected_proof_id_binding() {
        let expected = ProofId::from_bytes([0x92; 32]);
        let variable = FreeVariable::new(0);
        let noncanonical = identity(FreeVariable::new(42)).to_canonical_bytes();
        let invalid_inference = canonical_bytes(certificate(vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStep::ZfcAxiom(ZfcAxiom::Union),
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]));
        let missing = ProofId::from_bytes([0x93; 32]);
        let missing_reference = canonical_bytes(certificate(vec![ProofStep::ProofReference {
            proof_id: missing,
        }]));
        let mut ledger = LedgerState::new();

        assert_eq!(
            ledger.apply_canonical_proof_bytes_with_expected_id(vec![0], expected),
            Err(LedgerError::Decode {
                source: ProofCertificateError::UnexpectedEnd,
            })
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes_with_expected_id(noncanonical, expected),
            Err(LedgerError::NonCanonicalProof)
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes_with_expected_id(invalid_inference, expected),
            Err(LedgerError::Check {
                source: CheckError::Logic {
                    step: 2,
                    source: LogicError::ModusPonensMismatch,
                },
            })
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes_with_expected_id(missing_reference, expected),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: missing,
                },
            })
        );

        let valid = canonical_bytes(identity(variable));
        let actual = normalize_and_check(identity(variable)).unwrap().proof_id();
        assert!(
            ledger
                .apply_canonical_proof_bytes_with_expected_id(valid, actual)
                .is_ok()
        );
    }

    #[test]
    fn representation_mutations_are_noncanonical_and_atomic() {
        let zero = FreeVariable::new(0);
        let result = FreeVariable::new(3);
        let cases = [
            ("renamed free variable", identity(FreeVariable::new(42))),
            (
                "alternate topological order",
                reordered_identity_detour(zero),
            ),
            (
                "unreachable valid step",
                certificate(vec![
                    ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
                    ProofStep::EqualityReflexivity { variable: zero },
                    ProofStep::Generalization {
                        premise: 1,
                        variable: zero,
                    },
                ]),
            ),
            (
                "unreachable invalid step",
                certificate(vec![
                    ProofStep::Separation(Separation {
                        predicate: Formula::equal(result, result),
                        element: FreeVariable::new(1),
                        source: FreeVariable::new(2),
                        result,
                        parameters: Vec::new(),
                    }),
                    ProofStep::EqualityReflexivity { variable: zero },
                    ProofStep::Generalization {
                        premise: 1,
                        variable: zero,
                    },
                ]),
            ),
            ("reachable duplicate nodes", duplicate_identity(zero)),
        ];

        for (name, certificate) in cases {
            let submitted = certificate.to_canonical_bytes();
            let canonical = canonical_bytes(certificate);
            assert_ne!(submitted, canonical, "{name}");

            let mut ledger = LedgerState::new();
            assert_eq!(
                ledger.apply_canonical_proof_bytes(submitted),
                Err(LedgerError::NonCanonicalProof),
                "{name}"
            );
            let applied = ledger
                .apply_canonical_proof_bytes(canonical)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(ledger.contains_proof(applied.proof_id()));
        }
    }

    #[test]
    fn decode_errors_precede_canonicality_without_mutation() {
        let valid = canonical_bytes(identity(FreeVariable::new(0)));
        let mut trailing = valid.clone();
        trailing.push(0);
        let over_limit = vec![0; CERTIFICATE_MAX_BYTES + 1];
        let cases = [
            (&[0][..], ProofCertificateError::UnexpectedEnd),
            (
                trailing.as_slice(),
                ProofCertificateError::TrailingBytes { remaining: 1 },
            ),
            (
                over_limit.as_slice(),
                ProofCertificateError::InputTooLong {
                    actual: CERTIFICATE_MAX_BYTES + 1,
                    maximum: CERTIFICATE_MAX_BYTES,
                },
            ),
        ];

        let mut ledger = LedgerState::new();
        for (bytes, source) in cases {
            let error = ledger
                .apply_canonical_proof_bytes(bytes.to_vec())
                .unwrap_err();
            assert_eq!(error, LedgerError::Decode { source });
            assert!(error.source().is_some());
        }
        let applied = ledger.apply_canonical_proof_bytes(valid).unwrap();
        assert!(ledger.contains_proof(applied.proof_id()));
    }

    #[test]
    fn canonicality_precedes_reachable_reference_checking() {
        let missing = ProofId::from_bytes([0x44; 32]);
        let invalid_inference = canonical_bytes(certificate(vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStep::ZfcAxiom(ZfcAxiom::Union),
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]));
        let submitted = certificate(vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStep::ProofReference { proof_id: missing },
        ]);
        let canonical = canonical_bytes(submitted.clone());
        let mut ledger = LedgerState::new();

        assert_eq!(
            ledger.apply_canonical_proof_bytes(submitted.to_canonical_bytes()),
            Err(LedgerError::NonCanonicalProof)
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes(canonical),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: missing,
                },
            })
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes(invalid_inference),
            Err(LedgerError::Check {
                source: CheckError::Logic {
                    step: 2,
                    source: LogicError::ModusPonensMismatch,
                },
            })
        );
    }

    #[test]
    fn canonical_five_reference_proof_requires_complete_pre_transition_state() {
        let axioms = [
            ZfcAxiom::Extensionality,
            ZfcAxiom::Pairing,
            ZfcAxiom::Union,
            ZfcAxiom::PowerSet,
            ZfcAxiom::Infinity,
        ];
        let parents = axioms
            .iter()
            .copied()
            .map(|axiom| {
                let proof = certificate(vec![ProofStep::ZfcAxiom(axiom)]);
                let proof_id = normalize_and_check(proof.clone()).unwrap().proof_id();
                (canonical_bytes(proof), proof_id, axiom.formula())
            })
            .collect::<Vec<_>>();
        let references = parents
            .iter()
            .map(|(_, proof_id, conclusion)| (*proof_id, conclusion.clone()))
            .collect::<Vec<_>>();
        let target = proof_using_every_reference(&references, ZfcAxiom::Choice);
        let target_bytes = canonical_bytes(target);
        let mut ledger = LedgerState::new();

        for (bytes, _, _) in &parents[..parents.len() - 1] {
            let _ = ledger.apply_canonical_proof_bytes(bytes.clone()).unwrap();
        }
        assert_eq!(
            ledger.apply_canonical_proof_bytes(target_bytes.clone()),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 4,
                    proof_id: parents[4].1,
                },
            })
        );

        let _ = ledger
            .apply_canonical_proof_bytes(parents[4].0.clone())
            .unwrap();
        let applied = ledger
            .apply_canonical_proof_bytes(target_bytes.clone())
            .unwrap();
        assert_eq!(applied.canonical_proof_bytes(), target_bytes);
        assert_eq!(
            applied.direct_dependencies(),
            parents
                .iter()
                .map(|(_, proof_id, _)| *proof_id)
                .collect::<Vec<_>>()
        );
        assert!(ledger.contains_proof(applied.proof_id()));
    }

    #[test]
    fn records_keep_only_unique_direct_dependencies_and_replay_in_dependency_order() {
        let source_proof = certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)]);
        let source_bytes = canonical_bytes(source_proof);
        let mut original = LedgerState::new();
        let source = original.apply_canonical_proof_bytes(source_bytes).unwrap();
        let repeated = vec![
            (source.proof_id(), ZfcAxiom::Pairing.formula()),
            (source.proof_id(), ZfcAxiom::Pairing.formula()),
        ];
        let child_bytes = canonical_bytes(proof_using_every_reference(&repeated, ZfcAxiom::Choice));
        let child = original.apply_canonical_proof_bytes(child_bytes).unwrap();
        assert_eq!(child.direct_dependencies(), [source.proof_id()]);

        let grandchild_bytes = canonical_bytes(proof_using_every_reference(
            &[(child.proof_id(), ZfcAxiom::Choice.formula())],
            ZfcAxiom::Infinity,
        ));
        let grandchild = original
            .apply_canonical_proof_bytes(grandchild_bytes)
            .unwrap();
        assert_eq!(grandchild.direct_dependencies(), [child.proof_id()]);
        assert!(
            !grandchild
                .direct_dependencies()
                .contains(&source.proof_id())
        );

        let mut replay = LedgerState::new();
        assert_eq!(
            replay.apply_canonical_proof_bytes(child.canonical_proof_bytes().to_vec()),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: source.proof_id(),
                },
            })
        );
        let replayed_source = replay
            .apply_canonical_proof_bytes(source.canonical_proof_bytes().to_vec())
            .unwrap();
        let replayed_child = replay
            .apply_canonical_proof_bytes(child.canonical_proof_bytes().to_vec())
            .unwrap();
        let replayed_grandchild = replay
            .apply_canonical_proof_bytes(grandchild.canonical_proof_bytes().to_vec())
            .unwrap();
        assert_eq!(replayed_source, source);
        assert_eq!(replayed_child, child);
        assert_eq!(replayed_grandchild, grandchild);
    }

    #[test]
    fn authoring_record_excludes_unreachable_unknown_dependencies() {
        let missing = ProofId::from_bytes([0x77; 32]);
        let expected_bytes =
            canonical_bytes(certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)]));
        let candidate = certificate(vec![
            ProofStep::ProofReference { proof_id: missing },
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
        ]);
        let mut ledger = LedgerState::new();

        let record = ledger.apply(candidate).unwrap();

        assert_eq!(record.canonical_proof_bytes(), expected_bytes);
        assert!(record.direct_dependencies().is_empty());
        assert!(!ledger.contains_proof(missing));
        assert!(ledger.contains_proof(record.proof_id()));
    }

    #[test]
    fn alternative_derivations_share_a_statement_and_register_distinct_identities() {
        let variable = FreeVariable::new(7);
        let mut ledger = LedgerState::new();

        let direct = ledger.apply(identity(variable)).unwrap();
        assert!(ledger.contains_proof(direct.proof_id()));
        assert!(ledger.contains_derivation(direct.derivation_id()));
        assert!(ledger.contains_statement(direct.statement_id()));

        let detour = ledger.apply(identity_detour(variable)).unwrap();
        assert_eq!(detour.statement_id(), direct.statement_id());
        assert_ne!(detour.derivation_id(), direct.derivation_id());
        assert_ne!(detour.proof_id(), direct.proof_id());
        assert!(ledger.contains_proof(detour.proof_id()));
        assert!(ledger.contains_derivation(detour.derivation_id()));
    }

    #[test]
    fn accepted_record_content_is_independent_of_the_selected_state() {
        let variable = FreeVariable::new(7);
        let direct_bytes = canonical_bytes(identity(variable));

        let mut absent = LedgerState::new();
        let new = absent
            .apply_canonical_proof_bytes(direct_bytes.clone())
            .unwrap();

        let mut present = LedgerState::new();
        let detour = present.apply(identity_detour(variable)).unwrap();
        let existing = present.apply_canonical_proof_bytes(direct_bytes).unwrap();

        assert_eq!(existing.statement_id(), detour.statement_id());
        assert_eq!(new, existing);
    }

    #[test]
    fn references_resolve_only_from_the_selected_pre_transition_state() {
        let variable = FreeVariable::new(9);
        let mut selected = LedgerState::new();
        let source = selected.apply(identity(variable)).unwrap();
        let dependent = referenced_generalization(source.proof_id(), variable);

        let mut independent = LedgerState::new();
        assert_eq!(
            independent.apply(dependent.clone()),
            Err(LedgerError::Check {
                source: CheckError::UnknownProofReference {
                    step: 0,
                    proof_id: source.proof_id(),
                },
            })
        );
        assert!(!independent.contains_proof(source.proof_id()));

        let applied = selected.apply(dependent).unwrap();
        assert!(selected.contains_proof(applied.proof_id()));
        assert!(!independent.contains_proof(applied.proof_id()));
    }

    #[test]
    fn one_proof_can_use_five_members_of_the_pre_transition_state() {
        let axioms = [
            ZfcAxiom::Extensionality,
            ZfcAxiom::Pairing,
            ZfcAxiom::Union,
            ZfcAxiom::PowerSet,
            ZfcAxiom::Infinity,
        ];
        let mut ledger = LedgerState::new();
        let references = axioms
            .iter()
            .copied()
            .map(|axiom| {
                let applied = ledger
                    .apply(certificate(vec![ProofStep::ZfcAxiom(axiom)]))
                    .unwrap();
                (applied.proof_id(), axiom.formula())
            })
            .collect::<Vec<_>>();
        let proof = proof_using_every_reference(&references, ZfcAxiom::Choice);
        assert_eq!(proof.steps().len(), 21);

        let applied = ledger.apply(proof.clone()).unwrap();
        assert!(ledger.contains_proof(applied.proof_id()));

        for missing in 0..references.len() {
            let mut incomplete = LedgerState::new();
            for (index, axiom) in axioms.iter().copied().enumerate() {
                if index == missing {
                    continue;
                }

                let accepted = incomplete
                    .apply(certificate(vec![ProofStep::ZfcAxiom(axiom)]))
                    .unwrap();
                assert_eq!(accepted.proof_id(), references[index].0);
            }

            assert!(matches!(
                incomplete.apply(proof.clone()),
                Err(LedgerError::Check {
                    source: CheckError::UnknownProofReference { proof_id, .. }
                }) if proof_id == references[missing].0
            ));
            for (index, (proof_id, _)) in references.iter().enumerate() {
                assert_eq!(incomplete.contains_proof(*proof_id), index != missing);
            }
            assert!(!incomplete.contains_proof(applied.proof_id()));
        }
    }

    #[test]
    fn duplicate_artifacts_and_reference_aliases_leave_state_unchanged() {
        let variable = FreeVariable::new(11);
        let mut ledger = LedgerState::new();
        let source = ledger.apply(identity(variable)).unwrap();

        assert_eq!(
            ledger.apply(identity(FreeVariable::new(42))),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateProof {
                    proof_id: source.proof_id(),
                },
            })
        );
        let alias = certificate(vec![ProofStep::ProofReference {
            proof_id: source.proof_id(),
        }]);
        let alias_id = normalize_and_check_with_state(alias.clone(), &ledger.proof_state)
            .unwrap()
            .proof_id();
        let alias_bytes = canonical_bytes(alias.clone());
        assert_eq!(
            ledger.apply(alias),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateDerivation {
                    derivation_id: source.derivation_id(),
                },
            })
        );
        let wrong_expected = ProofId::from_bytes([0x94; 32]);
        assert_ne!(wrong_expected, alias_id);
        let mismatch = ledger
            .apply_canonical_proof_bytes_with_expected_id(alias_bytes.clone(), wrong_expected);
        assert_eq!(
            mismatch,
            Err(LedgerError::ProofIdMismatch {
                expected: wrong_expected,
                actual: alias_id,
            })
        );
        assert_eq!(
            ledger.apply_canonical_proof_bytes_with_expected_id(alias_bytes, alias_id),
            Err(LedgerError::State {
                source: ProofStateError::DuplicateDerivation {
                    derivation_id: source.derivation_id(),
                },
            })
        );

        assert!(!ledger.contains_proof(alias_id));
        assert!(ledger.contains_proof(source.proof_id()));
        assert!(ledger.contains_derivation(source.derivation_id()));
        assert!(ledger.contains_statement(source.statement_id()));
    }

    #[test]
    fn checker_and_registration_errors_expose_sources_without_partial_updates() {
        let variable = FreeVariable::new(13);
        let mut ledger = LedgerState::new();
        let open = certificate(vec![ProofStep::EqualityReflexivity { variable }]);
        let open_error = ledger.apply(open).unwrap_err();
        assert!(matches!(
            open_error,
            LedgerError::Check {
                source: CheckError::OpenConclusion { step: 0 }
            }
        ));
        assert!(open_error.source().is_some());
        assert!(open_error.to_string().contains("proof checking failed"));

        let applied = ledger.apply(identity(variable)).unwrap();
        let duplicate_error = ledger.apply(identity(variable)).unwrap_err();
        assert!(matches!(
            duplicate_error,
            LedgerError::State {
                source: ProofStateError::DuplicateProof { .. }
            }
        ));
        assert!(duplicate_error.source().is_some());
        assert!(
            duplicate_error
                .to_string()
                .contains("proof registration failed")
        );
        assert!(ledger.contains_proof(applied.proof_id()));
        assert!(ledger.contains_derivation(applied.derivation_id()));
        assert!(ledger.contains_statement(applied.statement_id()));
    }

    #[test]
    fn batch_shape_and_candidate_order_fail_before_mutation() {
        let root = ProofId::from_bytes([0x81; 32]);
        let other = ProofId::from_bytes([0x82; 32]);
        let mut ledger = LedgerState::new();

        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(root, Vec::new()),
            Err(ProofBatchError::Empty)
        );

        let oversized_count = (0..=PROOF_BATCH_MAX_CANDIDATES)
            .map(|index| {
                AddressedProofCandidate::new(
                    ProofId::from_bytes([u8::try_from(index).unwrap(); 32]),
                    vec![0],
                )
            })
            .collect();
        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(root, oversized_count),
            Err(ProofBatchError::TooManyCandidates {
                actual: PROOF_BATCH_MAX_CANDIDATES + 1,
                maximum: PROOF_BATCH_MAX_CANDIDATES,
            })
        );

        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(
                root,
                vec![
                    AddressedProofCandidate::new(root, vec![0]),
                    AddressedProofCandidate::new(root, vec![0]),
                ],
            ),
            Err(ProofBatchError::DuplicateExpectedProofId {
                first_index: 0,
                duplicate_index: 1,
                proof_id: root,
            })
        );
        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(
                root,
                vec![AddressedProofCandidate::new(other, vec![0])],
            ),
            Err(ProofBatchError::RootNotLast {
                requested: root,
                actual: other,
            })
        );
        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(
                root,
                vec![
                    AddressedProofCandidate::new(other, vec![0]),
                    AddressedProofCandidate::new(root, Vec::new()),
                ],
            ),
            Err(ProofBatchError::Candidate {
                index: 0,
                expected: Some(other),
                source: LedgerError::Decode {
                    source: ProofCertificateError::UnexpectedEnd,
                },
            })
        );
        assert!(!ledger.contains_proof(root));
        assert!(!ledger.contains_proof(other));
    }

    #[test]
    fn addressed_candidate_debug_omits_proof_payload() {
        let candidate =
            AddressedProofCandidate::new(ProofId::from_bytes([0x11; 32]), vec![222, 173, 190, 239]);
        let debug = format!("{candidate:?}");

        assert!(debug.contains("canonical_proof_bytes_len: 4"));
        assert!(debug.contains("expected_proof_id"));
        assert!(!debug.contains("222"));
    }

    #[test]
    fn later_candidate_failures_discard_every_earlier_candidate() {
        let (parent_bytes, parent_id) = axiom_candidate(ZfcAxiom::Pairing);
        let parent_checked =
            normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)])).unwrap();
        let (valid_root_bytes, valid_root_id) = axiom_candidate(ZfcAxiom::Union);
        let malformed_expected = ProofId::from_bytes([0x83; 32]);
        let noncanonical_expected = ProofId::from_bytes([0x84; 32]);
        let invalid_expected = ProofId::from_bytes([0x85; 32]);
        let mismatch_expected = ProofId::from_bytes([0x86; 32]);
        let noncanonical = certificate(vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStep::ZfcAxiom(ZfcAxiom::Union),
        ])
        .to_canonical_bytes();
        let invalid = canonical_bytes(certificate(vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStep::ZfcAxiom(ZfcAxiom::Union),
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]));

        let cases = [
            (
                malformed_expected,
                vec![0],
                LedgerError::Decode {
                    source: ProofCertificateError::UnexpectedEnd,
                },
            ),
            (
                noncanonical_expected,
                noncanonical,
                LedgerError::NonCanonicalProof,
            ),
            (
                invalid_expected,
                invalid,
                LedgerError::Check {
                    source: CheckError::Logic {
                        step: 2,
                        source: LogicError::ModusPonensMismatch,
                    },
                },
            ),
            (
                mismatch_expected,
                valid_root_bytes,
                LedgerError::ProofIdMismatch {
                    expected: mismatch_expected,
                    actual: valid_root_id,
                },
            ),
        ];

        for (expected, bytes, source) in cases {
            let mut ledger = LedgerState::new();
            assert_eq!(
                ledger.apply_rooted_canonical_proof_batch(
                    expected,
                    vec![
                        AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                        AddressedProofCandidate::new(expected, bytes),
                    ],
                ),
                Err(ProofBatchError::Candidate {
                    index: 1,
                    expected: Some(expected),
                    source,
                })
            );
            assert!(!ledger.contains_proof(parent_id));
            assert!(!ledger.contains_derivation(parent_checked.derivation_id()));
            assert!(!ledger.contains_statement(parent_checked.statement_id()));
            assert!(!ledger.contains_proof(valid_root_id));
        }
    }

    #[test]
    fn rooted_batch_rejects_smuggling_and_wrong_root_then_retries_cleanly() {
        let (parent_bytes, parent_id) = axiom_candidate(ZfcAxiom::Pairing);
        let (unrelated_bytes, unrelated_id) = axiom_candidate(ZfcAxiom::Union);
        let root_bytes = referenced_generalization_bytes(parent_id, FreeVariable::new(0));
        let mut control = LedgerState::new();
        let _ = control
            .apply_canonical_proof_bytes(parent_bytes.clone())
            .unwrap();
        let root_id = control
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();

        let mut ledger = LedgerState::new();
        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(
                root_id,
                vec![
                    AddressedProofCandidate::new(unrelated_id, unrelated_bytes),
                    AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                    AddressedProofCandidate::new(root_id, root_bytes.clone()),
                ],
            ),
            Err(ProofBatchError::UnreachableCandidate {
                index: 0,
                proof_id: unrelated_id,
            })
        );
        assert!(!ledger.contains_proof(unrelated_id));
        assert!(!ledger.contains_proof(parent_id));
        assert!(!ledger.contains_proof(root_id));

        let wrong_root = ProofId::from_bytes([0x87; 32]);
        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(
                wrong_root,
                vec![
                    AddressedProofCandidate::new(parent_id, parent_bytes.clone()),
                    AddressedProofCandidate::new(wrong_root, root_bytes.clone()),
                ],
            ),
            Err(ProofBatchError::Candidate {
                index: 1,
                expected: Some(wrong_root),
                source: LedgerError::ProofIdMismatch {
                    expected: wrong_root,
                    actual: root_id,
                },
            })
        );
        assert!(!ledger.contains_proof(parent_id));
        assert!(!ledger.contains_proof(root_id));

        let records = ledger
            .apply_rooted_canonical_proof_batch(
                root_id,
                vec![
                    AddressedProofCandidate::new(parent_id, parent_bytes),
                    AddressedProofCandidate::new(root_id, root_bytes),
                ],
            )
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].proof_id(), parent_id);
        assert_eq!(records[1].proof_id(), root_id);
        assert_eq!(records[1].direct_dependencies(), [parent_id]);
        assert!(ledger.contains_proof(parent_id));
        assert!(ledger.contains_proof(root_id));
    }

    #[test]
    fn rooted_batch_allows_selected_external_dependencies() {
        let (external_bytes, external_id) = axiom_candidate(ZfcAxiom::Union);
        let root_bytes = referenced_generalization_bytes(external_id, FreeVariable::new(2));
        let mut control = LedgerState::new();
        let _ = control
            .apply_canonical_proof_bytes(external_bytes.clone())
            .unwrap();
        let root_id = control
            .apply_canonical_proof_bytes(root_bytes.clone())
            .unwrap()
            .proof_id();
        let mut ledger = LedgerState::new();
        let _ = ledger.apply_canonical_proof_bytes(external_bytes).unwrap();

        let records = ledger
            .apply_rooted_canonical_proof_batch(
                root_id,
                vec![AddressedProofCandidate::new(root_id, root_bytes)],
            )
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].proof_id(), root_id);
        assert_eq!(records[0].direct_dependencies(), [external_id]);
        assert!(ledger.contains_proof(external_id));
        assert!(ledger.contains_proof(root_id));
    }

    #[test]
    fn duplicate_derivation_rejects_the_complete_rooted_batch() {
        let direct = identity(FreeVariable::new(0));
        let direct_checked = normalize_and_check(direct.clone()).unwrap();
        let direct_id = direct_checked.proof_id();
        let direct_bytes = canonical_bytes(direct);
        let alias = certificate(vec![ProofStep::ProofReference {
            proof_id: direct_id,
        }]);
        let mut control = LedgerState::new();
        let _ = control
            .apply_canonical_proof_bytes(direct_bytes.clone())
            .unwrap();
        let alias_checked =
            normalize_and_check_with_state(alias.clone(), &control.proof_state).unwrap();
        let alias_id = alias_checked.proof_id();
        let alias_bytes = canonical_bytes(alias);
        assert_ne!(alias_id, direct_id);
        assert_eq!(
            alias_checked.derivation_id(),
            direct_checked.derivation_id()
        );

        let mut ledger = LedgerState::new();
        assert_eq!(
            ledger.apply_rooted_canonical_proof_batch(
                alias_id,
                vec![
                    AddressedProofCandidate::new(direct_id, direct_bytes),
                    AddressedProofCandidate::new(alias_id, alias_bytes),
                ],
            ),
            Err(ProofBatchError::Candidate {
                index: 1,
                expected: Some(alias_id),
                source: LedgerError::State {
                    source: ProofStateError::DuplicateDerivation {
                        derivation_id: direct_checked.derivation_id(),
                    },
                },
            })
        );
        assert!(!ledger.contains_proof(direct_id));
        assert!(!ledger.contains_proof(alias_id));
        assert!(!ledger.contains_derivation(direct_checked.derivation_id()));
        assert!(!ledger.contains_statement(direct_checked.statement_id()));
    }
}
