//! Deterministic selected-artifact ledger admission for NAOME.
//!
//! Each strict admission accepts exactly one canonically tagged proof or
//! conservative definition. Proofs must already be canonical root normal
//! forms; definitions must be self-contained canonical certificates whose
//! computed function-obligation statements resolve from immutable pre-admission
//! state.
//! Applying mutates selected state only after decoding, canonicality, semantic
//! checking, content-address verification, and registration preflight succeed.
//! Blocks, persistence, consensus, networking, and source parsing remain
//! outside this crate.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

pub use naome_checker::ArtifactState;

use naome_checker::{
    ArtifactStateError, CheckError, CheckedDefinition, CheckedProof, DefinitionCheckError,
    check_definition_with_state, check_normal_form_with_state, normalize_and_check_with_state,
};
use naome_proof::{
    ArtifactId, ArtifactPayload, ArtifactPayloadError, DefinitionId, DerivationId,
    ProofCertificate, ProofId, ProofNormalForm, ProofStep, StatementId,
};

/// The immutable proof payload and identities produced by one accepted artifact.
#[derive(PartialEq, Eq)]
#[must_use]
pub struct AcceptedProofRecord {
    canonical_artifact_bytes: Box<[u8]>,
    direct_proof_dependencies: Box<[ProofId]>,
    direct_definition_dependencies: Box<[DefinitionId]>,
    artifact_id: ArtifactId,
    proof_id: ProofId,
    derivation_id: DerivationId,
    statement_id: StatementId,
}

impl AcceptedProofRecord {
    /// Returns the exact tagged canonical artifact payload that was accepted.
    pub const fn canonical_artifact_bytes(&self) -> &[u8] {
        &self.canonical_artifact_bytes
    }

    /// Returns the inner canonical proof-certificate payload without its tag.
    pub fn canonical_proof_bytes(&self) -> &[u8] {
        &self.canonical_artifact_bytes[1..]
    }

    /// Returns directly cited proof identities in canonical step order.
    pub const fn direct_proof_dependencies(&self) -> &[ProofId] {
        &self.direct_proof_dependencies
    }

    /// Returns directly cited definition identities in canonical occurrence order.
    pub const fn direct_definition_dependencies(&self) -> &[DefinitionId] {
        &self.direct_definition_dependencies
    }

    /// Returns the distinct direct dependencies as typed artifact addresses.
    ///
    /// Proof and definition identities recorded during this proof's ledger
    /// acceptance are mapped into their domain-separated [`ArtifactId`] values,
    /// sorted in ascending identity order, and deduplicated. The projection does
    /// not expand transitive ancestors and establishes no current selection,
    /// block or consensus inclusion, citation eligibility, beneficiary, reward,
    /// settlement, or state authority.
    #[must_use]
    pub fn direct_artifact_dependencies(&self) -> Box<[ArtifactId]> {
        let mut dependencies = Vec::with_capacity(
            self.direct_proof_dependencies.len() + self.direct_definition_dependencies.len(),
        );
        dependencies.extend(
            self.direct_proof_dependencies
                .iter()
                .copied()
                .map(ArtifactId::from_proof_id),
        );
        dependencies.extend(
            self.direct_definition_dependencies
                .iter()
                .copied()
                .map(ArtifactId::from_definition_id),
        );
        dependencies.sort_unstable();
        dependencies.dedup();
        dependencies.into_boxed_slice()
    }

    /// Returns the typed artifact address committed by a block.
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
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
                "canonical_artifact_bytes_len",
                &self.canonical_artifact_bytes.len(),
            )
            .field(
                "direct_proof_dependencies_len",
                &self.direct_proof_dependencies.len(),
            )
            .field(
                "direct_definition_dependencies_len",
                &self.direct_definition_dependencies.len(),
            )
            .field("artifact_id", &self.artifact_id)
            .field("proof_id", &self.proof_id)
            .field("derivation_id", &self.derivation_id)
            .field("statement_id", &self.statement_id)
            .finish()
    }
}

/// The immutable definition payload and dependencies produced by one admission.
#[derive(PartialEq, Eq)]
#[must_use]
pub struct AcceptedDefinitionRecord {
    canonical_artifact_bytes: Box<[u8]>,
    obligation_statement_id: Option<StatementId>,
    artifact_id: ArtifactId,
    definition_id: DefinitionId,
}

impl AcceptedDefinitionRecord {
    /// Returns the exact tagged canonical artifact payload that was accepted.
    pub const fn canonical_artifact_bytes(&self) -> &[u8] {
        &self.canonical_artifact_bytes
    }

    /// Returns the inner canonical definition payload without its tag.
    pub fn canonical_definition_bytes(&self) -> &[u8] {
        &self.canonical_artifact_bytes[1..]
    }

    /// Returns the computed selected statement required by a function definition.
    pub const fn obligation_statement_id(&self) -> Option<StatementId> {
        self.obligation_statement_id
    }

    /// Returns the typed artifact address committed by a block.
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }

    /// Returns the checked definition identity.
    pub const fn definition_id(&self) -> DefinitionId {
        self.definition_id
    }
}

impl fmt::Debug for AcceptedDefinitionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedDefinitionRecord")
            .field(
                "canonical_artifact_bytes_len",
                &self.canonical_artifact_bytes.len(),
            )
            .field("obligation_statement_id", &self.obligation_statement_id)
            .field("artifact_id", &self.artifact_id)
            .field("definition_id", &self.definition_id)
            .finish()
    }
}

/// One strictly checked proof or conservative definition retained by the ledger.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum AcceptedArtifactRecord {
    /// A checked proof artifact.
    Proof(AcceptedProofRecord),
    /// A checked definition artifact.
    Definition(AcceptedDefinitionRecord),
}

impl AcceptedArtifactRecord {
    /// Returns the opaque typed identity committed by an artifact block.
    pub const fn artifact_id(&self) -> ArtifactId {
        match self {
            Self::Proof(record) => record.artifact_id(),
            Self::Definition(record) => record.artifact_id(),
        }
    }

    /// Returns the exact tagged canonical payload accepted by the ledger.
    pub const fn canonical_artifact_bytes(&self) -> &[u8] {
        match self {
            Self::Proof(record) => record.canonical_artifact_bytes(),
            Self::Definition(record) => record.canonical_artifact_bytes(),
        }
    }

    /// Returns the proof record when this artifact is a proof.
    pub const fn as_proof(&self) -> Option<&AcceptedProofRecord> {
        match self {
            Self::Proof(record) => Some(record),
            Self::Definition(_) => None,
        }
    }

    /// Returns the definition record when this artifact is a definition.
    pub const fn as_definition(&self) -> Option<&AcceptedDefinitionRecord> {
        match self {
            Self::Definition(record) => Some(record),
            Self::Proof(_) => None,
        }
    }
}

/// Selected checked-artifact state after zero or more strict admissions.
///
/// The resolver is private so callers cannot interleave checking and mutation.
/// Every failure leaves the complete selected state unchanged.
/// Cloning is constant-time and shares immutable resolver nodes; later strict
/// admissions path-copy only the changed resolver paths.
#[derive(Clone, Default)]
#[must_use]
pub struct LedgerState {
    artifact_state: ArtifactState,
}

impl LedgerState {
    /// Constructs an empty ledger state.
    pub const fn new() -> Self {
        Self {
            artifact_state: ArtifactState::new(),
        }
    }

    /// Returns immutable access to the selected checked-artifact resolver.
    pub const fn artifact_state(&self) -> &ArtifactState {
        &self.artifact_state
    }

    /// Returns whether one exact proof is selected.
    pub fn contains_proof(&self, proof_id: ProofId) -> bool {
        self.artifact_state.contains_proof(proof_id)
    }

    /// Returns whether one derivation is selected.
    pub fn contains_derivation(&self, derivation_id: DerivationId) -> bool {
        self.artifact_state.contains_derivation(derivation_id)
    }

    /// Returns whether one statement is selected.
    pub fn contains_statement(&self, statement_id: StatementId) -> bool {
        self.artifact_state.contains_statement(statement_id)
    }

    /// Returns whether one exact definition is selected.
    pub fn contains_definition(&self, definition_id: DefinitionId) -> bool {
        self.artifact_state.contains_definition(definition_id)
    }

    /// Normalizes, checks, and atomically registers one constructed proof.
    ///
    /// This authoring-oriented path does not accept externally supplied bytes.
    /// Strict block and transport admission must use
    /// [`Self::apply_canonical_artifact_bytes_with_expected_id`].
    pub fn apply_proof(
        &mut self,
        certificate: ProofCertificate,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        let checked = normalize_and_check_with_state(certificate, &self.artifact_state)
            .map_err(|source| LedgerError::ProofCheck { source })?;
        let canonical_artifact_bytes =
            ArtifactPayload::Proof(checked.normal_form().certificate().clone())
                .to_canonical_bytes()
                .into_boxed_slice();
        self.register_checked_proof(checked, canonical_artifact_bytes)
    }

    /// Strictly admits one complete tagged canonical artifact payload.
    pub fn apply_canonical_artifact_bytes(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<AcceptedArtifactRecord, LedgerError> {
        self.apply_canonical_artifact_bytes_inner(bytes, None)
    }

    /// Strictly admits one tagged artifact only at its expected address.
    ///
    /// Decode, canonicality, checking, dependency resolution, and content-ID
    /// derivation precede the address comparison. Registration happens last.
    pub fn apply_canonical_artifact_bytes_with_expected_id(
        &mut self,
        bytes: Vec<u8>,
        expected_artifact_id: ArtifactId,
    ) -> Result<AcceptedArtifactRecord, LedgerError> {
        self.apply_canonical_artifact_bytes_inner(bytes, Some(expected_artifact_id))
    }

    /// Performs the exact strict addressed checks without mutating selected state.
    pub fn validate_canonical_artifact_bytes_with_expected_id(
        &self,
        bytes: Vec<u8>,
        expected_artifact_id: ArtifactId,
    ) -> Result<(), LedgerError> {
        let checked = self.check_canonical_artifact_bytes(bytes)?;
        let actual = checked.artifact_id();
        if actual != expected_artifact_id {
            return Err(LedgerError::ArtifactIdMismatch {
                expected: expected_artifact_id,
                actual,
            });
        }
        match &checked {
            PendingArtifact::Proof { checked, .. } => self
                .artifact_state
                .validate_proof_registration(checked)
                .map_err(|source| LedgerError::State { source }),
            PendingArtifact::Definition { checked, .. } => self
                .artifact_state
                .validate_definition_registration(checked)
                .map_err(|source| LedgerError::State { source }),
        }
    }

    fn apply_canonical_artifact_bytes_inner(
        &mut self,
        bytes: Vec<u8>,
        expected_artifact_id: Option<ArtifactId>,
    ) -> Result<AcceptedArtifactRecord, LedgerError> {
        let checked = self.check_canonical_artifact_bytes(bytes)?;
        let actual = checked.artifact_id();
        if let Some(expected) = expected_artifact_id
            && actual != expected
        {
            return Err(LedgerError::ArtifactIdMismatch { expected, actual });
        }
        match checked {
            PendingArtifact::Proof {
                checked,
                canonical_artifact_bytes,
            } => self
                .register_checked_proof(checked, canonical_artifact_bytes)
                .map(AcceptedArtifactRecord::Proof),
            PendingArtifact::Definition {
                checked,
                canonical_artifact_bytes,
            } => self
                .register_checked_definition(checked, canonical_artifact_bytes)
                .map(AcceptedArtifactRecord::Definition),
        }
    }

    fn check_canonical_artifact_bytes(
        &self,
        bytes: Vec<u8>,
    ) -> Result<PendingArtifact, LedgerError> {
        let payload = ArtifactPayload::from_canonical_bytes(&bytes)
            .map_err(|source| LedgerError::Decode { source })?;
        let canonical_artifact_bytes = bytes.into_boxed_slice();
        match payload {
            ArtifactPayload::Proof(certificate) => {
                let normal_form =
                    canonical_proof_normal_form(certificate, &canonical_artifact_bytes[1..])?;
                let checked = check_normal_form_with_state(normal_form, &self.artifact_state)
                    .map_err(|source| LedgerError::ProofCheck { source })?;
                Ok(PendingArtifact::Proof {
                    checked,
                    canonical_artifact_bytes,
                })
            }
            ArtifactPayload::Definition(certificate) => {
                let checked = check_definition_with_state(certificate, &self.artifact_state)
                    .map_err(|source| LedgerError::DefinitionCheck { source })?;
                Ok(PendingArtifact::Definition {
                    checked,
                    canonical_artifact_bytes,
                })
            }
        }
    }

    fn register_checked_proof(
        &mut self,
        checked: CheckedProof,
        canonical_artifact_bytes: Box<[u8]>,
    ) -> Result<AcceptedProofRecord, LedgerError> {
        let metadata = ProofRecordMetadata::from_checked(&checked);
        drop(
            self.artifact_state
                .register_proof(checked)
                .map_err(|source| LedgerError::State { source })?,
        );
        Ok(metadata.into_record(canonical_artifact_bytes))
    }

    fn register_checked_definition(
        &mut self,
        checked: CheckedDefinition,
        canonical_artifact_bytes: Box<[u8]>,
    ) -> Result<AcceptedDefinitionRecord, LedgerError> {
        let metadata = DefinitionRecordMetadata::from_checked(&checked);
        self.artifact_state
            .register_definition(checked)
            .map_err(|source| LedgerError::State { source })?;
        Ok(metadata.into_record(canonical_artifact_bytes))
    }
}

fn canonical_proof_normal_form(
    certificate: ProofCertificate,
    submitted_inner_bytes: &[u8],
) -> Result<ProofNormalForm, LedgerError> {
    certificate
        .into_unchecked_normal_form()
        .with_matching_canonical_bytes(submitted_inner_bytes.into())
        .ok_or(LedgerError::NonCanonicalProof)
}

enum PendingArtifact {
    Proof {
        checked: CheckedProof,
        canonical_artifact_bytes: Box<[u8]>,
    },
    Definition {
        checked: CheckedDefinition,
        canonical_artifact_bytes: Box<[u8]>,
    },
}

impl PendingArtifact {
    fn artifact_id(&self) -> ArtifactId {
        match self {
            Self::Proof { checked, .. } => ArtifactId::from_proof_id(checked.proof_id()),
            Self::Definition { checked, .. } => {
                ArtifactId::from_definition_id(checked.definition_id())
            }
        }
    }
}

struct ProofRecordMetadata {
    direct_proof_dependencies: Box<[ProofId]>,
    direct_definition_dependencies: Box<[DefinitionId]>,
    artifact_id: ArtifactId,
    proof_id: ProofId,
    derivation_id: DerivationId,
    statement_id: StatementId,
}

impl ProofRecordMetadata {
    fn from_checked(checked: &CheckedProof) -> Self {
        let steps = checked.normal_form().certificate().steps();
        let mut proof_dependencies = Vec::new();
        let mut definition_dependencies = Vec::new();
        let mut seen_definitions = BTreeSet::new();
        for step in steps {
            if let ProofStep::ProofReference { proof_id } = step {
                proof_dependencies.push(*proof_id);
            }
            for definition_id in step.definition_references() {
                if seen_definitions.insert(definition_id) {
                    definition_dependencies.push(definition_id);
                }
            }
        }
        let proof_id = checked.proof_id();
        Self {
            direct_proof_dependencies: proof_dependencies.into_boxed_slice(),
            direct_definition_dependencies: definition_dependencies.into_boxed_slice(),
            artifact_id: ArtifactId::from_proof_id(proof_id),
            proof_id,
            derivation_id: checked.derivation_id(),
            statement_id: checked.statement_id(),
        }
    }

    fn into_record(self, canonical_artifact_bytes: Box<[u8]>) -> AcceptedProofRecord {
        AcceptedProofRecord {
            canonical_artifact_bytes,
            direct_proof_dependencies: self.direct_proof_dependencies,
            direct_definition_dependencies: self.direct_definition_dependencies,
            artifact_id: self.artifact_id,
            proof_id: self.proof_id,
            derivation_id: self.derivation_id,
            statement_id: self.statement_id,
        }
    }
}

struct DefinitionRecordMetadata {
    obligation_statement_id: Option<StatementId>,
    artifact_id: ArtifactId,
    definition_id: DefinitionId,
}

impl DefinitionRecordMetadata {
    fn from_checked(checked: &CheckedDefinition) -> Self {
        let definition_id = checked.definition_id();
        Self {
            obligation_statement_id: checked.obligation_statement_id(),
            artifact_id: ArtifactId::from_definition_id(definition_id),
            definition_id,
        }
    }

    fn into_record(self, canonical_artifact_bytes: Box<[u8]>) -> AcceptedDefinitionRecord {
        AcceptedDefinitionRecord {
            canonical_artifact_bytes,
            obligation_statement_id: self.obligation_statement_id,
            artifact_id: self.artifact_id,
            definition_id: self.definition_id,
        }
    }
}

/// A fail-closed single-artifact ledger admission failure.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    /// The tagged payload is not one structurally valid complete artifact.
    Decode { source: ArtifactPayloadError },
    /// A proof is structurally valid but not its canonical root normal form.
    NonCanonicalProof,
    /// Mathematical proof checking failed.
    ProofCheck { source: CheckError },
    /// Conservative definition checking failed.
    DefinitionCheck { source: DefinitionCheckError },
    /// The checked artifact does not have the externally expected address.
    ArtifactIdMismatch {
        expected: ArtifactId,
        actual: ArtifactId,
    },
    /// The checked artifact could not be registered in selected state.
    State { source: ArtifactStateError },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { source } => write!(formatter, "artifact decoding failed: {source}"),
            Self::NonCanonicalProof => {
                formatter.write_str("submitted proof is not in canonical root-proof normal form")
            }
            Self::ProofCheck { source } => write!(formatter, "proof checking failed: {source}"),
            Self::DefinitionCheck { source } => {
                write!(formatter, "definition checking failed: {source}")
            }
            Self::ArtifactIdMismatch { expected, actual } => write!(
                formatter,
                "artifact identity mismatch: expected {expected:?}, checked {actual:?}"
            ),
            Self::State { source } => write!(formatter, "artifact registration failed: {source}"),
        }
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { source } => Some(source),
            Self::ProofCheck { source } => Some(source),
            Self::DefinitionCheck { source } => Some(source),
            Self::State { source } => Some(source),
            Self::NonCanonicalProof | Self::ArtifactIdMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
