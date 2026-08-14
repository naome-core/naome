//! Deterministic proof ledger state transitions for NAOME.
//!
//! Each admission path admits one certificate. The authoring path normalizes
//! an owned certificate; strict byte paths reject any submission that is not
//! already its canonical root-proof normal form. Addressed paths additionally
//! bind checked bytes to expected [`ProofId`] values. Applying registers only
//! after all applicable admission checks succeed; read-only validation runs the
//! same checks without registration. Blocks, persistence, undo, rewards,
//! networking, and source parsing remain outside this crate.

use std::error::Error;
use std::fmt;

pub use naome_checker::ProofState;

use naome_checker::{
    CheckError, CheckedProof, ProofStateError, check_normal_form_with_state,
    normalize_and_check_with_state,
};
use naome_proof::{
    DerivationId, ProofCertificate, ProofCertificateError, ProofId, ProofStep, StatementId,
};

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

/// The accepted proof state after zero or more strict proof admissions.
///
/// The inner proof state is private so callers cannot interleave checking and
/// mutation. Each successful admission contributes exactly one checked proof;
/// every failure leaves the state unchanged.
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

    /// Returns immutable access to the accepted checked-proof resolver state.
    ///
    /// The borrow cannot register proofs or outlive this ledger state. Callers
    /// therefore observe exactly the proofs admitted by completed transitions.
    pub const fn proof_state(&self) -> &ProofState {
        &self.proof_state
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

    /// Strictly validates canonical proof bytes at one expected address.
    ///
    /// This performs the same decode, canonicality, mathematical, address,
    /// dependency, duplicate, and collision checks as addressed admission but
    /// does not mutate the selected proof state.
    pub fn validate_canonical_proof_bytes_with_expected_id(
        &self,
        bytes: Vec<u8>,
        expected_proof_id: ProofId,
    ) -> Result<(), LedgerError> {
        let checked = self.check_canonical_proof_bytes(bytes, Some(expected_proof_id))?;
        self.proof_state
            .validate_registration(&checked)
            .map_err(|source| LedgerError::State { source })
    }

    fn apply_canonical_proof_bytes_inner(
        &mut self,
        bytes: Vec<u8>,
        expected_proof_id: Option<ProofId>,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        let checked = self.check_canonical_proof_bytes(bytes, expected_proof_id)?;
        self.register_checked(checked)
    }

    fn check_canonical_proof_bytes(
        &self,
        bytes: Vec<u8>,
        expected_proof_id: Option<ProofId>,
    ) -> Result<CheckedProof, LedgerError> {
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
        Ok(checked)
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

#[cfg(test)]
mod tests;
