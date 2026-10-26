use naome_authoring::CompiledProof;
use naome_foundation::FOUNDATION_ID;
use naome_proof::program::MANIFEST_MAGIC;
use naome_proof::{
    ArtifactId, ArtifactPayload, DefinitionCertificate, ProofCertificate, ProofId, ProofNormalForm,
    ProofStep, StatementId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

pub const CODEC_ID: &str = "naome:artifact-codec";
pub use naome_checker::CHECKER_ID;
pub const GRAPH_POLICY_ID: &str = "naome:knowledge:artifacts";

pub(crate) fn program_manifest(
    bytes: &[u8],
) -> Result<Option<naome_proof::program::Manifest>, crate::Error> {
    if bytes.first() != Some(&0xff) {
        return Ok(None);
    }
    let body = bytes
        .strip_prefix(MANIFEST_MAGIC)
        .ok_or("unknown program payload format")?;
    let manifest = naome_proof::program::Manifest::from_canonical_bytes(body)?;
    if manifest.commands > i64::MAX as u64 || manifest.input_bytes > i64::MAX as u64 {
        return Err("invalid canonical program manifest".into());
    }
    Ok(Some(manifest))
}

pub(crate) fn record_content_id(
    statement: Option<StatementId>,
    bytes: &[u8],
) -> Result<ArtifactId, crate::Error> {
    if let Some(manifest) = program_manifest(bytes)? {
        if Some(manifest.statement_id()) != statement {
            return Err("program statement binding differs".into());
        }
        return Ok(manifest.artifact_id());
    }
    match bytes.split_first() {
        Some((&ArtifactPayload::PROOF_TAG, payload)) => Ok(content_id(
            statement.ok_or("proof statement missing")?,
            payload,
        )),
        Some((&ArtifactPayload::DEFINITION_TAG, payload)) => {
            if statement.is_some() {
                return Err("definition has a statement claim".into());
            }
            Ok(DefinitionCertificate::from_canonical_bytes(payload)
                .map_err(|error| error.to_string())?
                .definition_id()
                .into())
        }
        _ => Err("unknown artifact payload".into()),
    }
}

/// Untrusted typed artifact envelope. Construction grants no validity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub compatibility: String,
    pub artifact_id: String,
    pub statement_id: Option<String>,
    /// A concrete proof of a function's computed total-unique obligation.
    /// This is dependency routing metadata; Checker verifies its conclusion.
    pub obligation_proof: Option<String>,
    pub payload: String,
}

/// Bounded, untrusted description of a newly derived resolution obligation.
/// It contains no certificate bytes and makes no proof-validity claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Metadata {
    pub artifact_id: String,
    pub proof_id: String,
    pub statement_id: String,
    pub question: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgramMetadata {
    pub manifest: naome_proof::program::Manifest,
    pub question: Option<String>,
}
/// Typed graph projections; these carry no independent mathematical authority.
pub(crate) enum ProofDescription {
    Certificate(Metadata),
    Program(ProgramMetadata),
}
pub(crate) enum ArtifactTransfer {
    Certificate(Envelope),
    Program(ProgramMetadata),
}

impl ProgramMetadata {
    pub(crate) fn question(
        &self,
    ) -> Result<Option<naome_authoring::CompiledQuestion>, crate::Error> {
        self.question
            .as_ref()
            .map(|question| {
                Metadata {
                    artifact_id: hex(self.manifest.artifact_id().as_bytes()),
                    proof_id: hex(self.manifest.proof_id().as_bytes()),
                    statement_id: hex(self.manifest.statement_id().as_bytes()),
                    question: question.clone(),
                }
                .compile()
                .map(|(_, _, question)| question)
            })
            .transpose()
    }
}

impl Metadata {
    pub(crate) fn compile(
        &self,
    ) -> Result<(ArtifactId, StatementId, naome_authoring::CompiledQuestion), crate::Error> {
        let id = ArtifactId::from_bytes(id_bytes(&self.artifact_id)?);
        if ArtifactId::from_proof_id(ProofId::from_bytes(id_bytes(&self.proof_id)?)) != id {
            return Err("description proof address differs".into());
        }
        let statement = StatementId::from_bytes(id_bytes(&self.statement_id)?);
        let question = naome_authoring::CompiledQuestion::compile(&self.question)
            .map_err(|error| error.to_string())?;
        let positive = target_id(question.positive_target())?;
        let negative = target_id(question.negative_target())?;
        if statement != positive && statement != negative {
            return Err("description statement does not match a question target".into());
        }
        Ok((id, statement, question))
    }
}

// Early address binding uses the unchanged checker framing. Only a checked
// conclusion and classify_checked_proof establish the eventual resolution.
fn target_id(formula: &naome_foundation::Formula) -> Result<StatementId, crate::Error> {
    let bytes = formula
        .encode_canonical()
        .map_err(|error| error.to_string())?;
    StatementId::of_canonical_formula(&bytes).ok_or("statement identity width".into())
}

pub fn compatibility() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:knowledge:compatibility\0");
    for value in [FOUNDATION_ID, CODEC_ID, CHECKER_ID, GRAPH_POLICY_ID] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}

/// Canonical payload and typed identities. Neither grants mathematical validity.
#[derive(Clone, Debug)]
pub(crate) struct BinaryArtifact {
    pub id: ArtifactId,
    pub statement: Option<StatementId>,
    pub obligation: Option<ProofId>,
    pub bytes: std::sync::Arc<[u8]>,
    // Program citations belong to their authenticated canonical command stream.
    pub dependencies: BTreeSet<ArtifactId>,
    pub _memory: Option<std::sync::Arc<crate::resources::MemoryLease>>,
}

impl PartialEq for BinaryArtifact {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.statement == other.statement
            && self.obligation == other.obligation
            && self.bytes == other.bytes
            && self.dependencies == other.dependencies
    }
}
impl Eq for BinaryArtifact {}
impl BinaryArtifact {
    pub(crate) fn same_content(&self, other: &Self) -> bool {
        self.id == other.id && self.statement == other.statement && self.bytes == other.bytes
    }
}

pub(crate) enum CandidatePayload {
    Proof(ProofNormalForm),
    Definition(DefinitionCertificate),
}
pub(crate) struct Candidate {
    pub id: ArtifactId,
    pub statement: Option<StatementId>,
    pub obligation: Option<ProofId>,
    pub payload: CandidatePayload,
    pub dependencies: BTreeSet<ArtifactId>,
    pub bytes: std::sync::Arc<[u8]>,
    memory: std::sync::Arc<crate::resources::MemoryLease>,
}
impl Candidate {
    #[cfg(test)]
    pub(crate) fn into_normal(self) -> ProofNormalForm {
        match self.payload {
            CandidatePayload::Proof(normal) => normal,
            CandidatePayload::Definition(_) => panic!("proof fixture required"),
        }
    }
    pub(crate) fn record(&self) -> BinaryArtifact {
        BinaryArtifact {
            id: self.id,
            statement: self.statement,
            obligation: self.obligation,
            bytes: self.bytes.clone(),
            dependencies: self.dependencies.clone(),
            _memory: Some(self.memory.clone()),
        }
    }
}

/// Sealed mathematical results share the node's single publication lifecycle.
pub(crate) enum CheckedArtifact {
    Proof(naome_checker::CheckedProof),
    Definition(naome_checker::CheckedDefinition),
}
impl CheckedArtifact {
    pub(crate) fn from_compiled(compiled: naome_authoring::CompiledArtifact) -> Self {
        match compiled {
            naome_authoring::CompiledArtifact::Proof(proof) => {
                Self::Proof(proof.into_checked_proof())
            }
            naome_authoring::CompiledArtifact::Definition(definition) => {
                Self::Definition(definition.into_checked_definition())
            }
        }
    }
    pub(crate) fn id(&self) -> ArtifactId {
        match self {
            Self::Proof(proof) => proof.artifact_id(),
            Self::Definition(definition) => definition.definition_id().into(),
        }
    }
    pub(crate) fn statement(&self) -> Option<StatementId> {
        match self {
            Self::Proof(proof) => Some(proof.statement_id()),
            Self::Definition(_) => None,
        }
    }
    pub(crate) fn proof(&self) -> Result<&naome_checker::CheckedProof, crate::Error> {
        match self {
            Self::Proof(proof) => Ok(proof),
            Self::Definition(_) => Err("selected question root must be a proof".into()),
        }
    }
    pub(crate) fn register(
        self,
        context: &mut naome_checker::DiskArtifactState,
    ) -> Result<(), crate::Error> {
        match self {
            Self::Proof(proof) => {
                context
                    .register_proof_for_replication(proof)
                    .map_err(crate::Error::from)?;
            }
            Self::Definition(definition) => {
                context
                    .register_definition(definition)
                    .map_err(crate::Error::from)?;
            }
        }
        Ok(())
    }
    pub(crate) fn record(
        &self,
        context: &dyn naome_checker::ContextView,
    ) -> Result<BinaryArtifact, crate::Error> {
        match self {
            Self::Proof(proof) => BinaryArtifact::from_checked(proof),
            Self::Definition(definition) => {
                let obligation = definition
                    .obligation_statement_id()
                    .map(|statement| {
                        context
                            .statement_header(statement)
                            .map_err(crate::Error::from)?
                            .map(|header| header.proof_id())
                            .ok_or_else(|| {
                                crate::Error::from("definition obligation witness missing")
                            })
                    })
                    .transpose()?;
                let certificate = definition.certificate().to_canonical_bytes();
                let length = certificate
                    .len()
                    .checked_add(1)
                    .ok_or("artifact byte overflow")?;
                let memory = crate::resources::MemoryLease::acquire(
                    length.checked_mul(4).ok_or("artifact memory overflow")?,
                )?;
                let mut bytes = Vec::with_capacity(length);
                bytes.push(ArtifactPayload::DEFINITION_TAG);
                bytes.extend(certificate);
                let dependencies = obligation
                    .into_iter()
                    .map(ArtifactId::from_proof_id)
                    .collect();
                Ok(BinaryArtifact {
                    id: self.id(),
                    statement: None,
                    obligation,
                    bytes: bytes.into(),
                    dependencies,
                    _memory: Some(memory),
                })
            }
        }
    }
}

impl BinaryArtifact {
    pub(crate) fn from_program(
        proof: &naome_checker::program::CheckedProgram,
    ) -> Result<Self, crate::Error> {
        let manifest = proof.manifest();
        let mut bytes = MANIFEST_MAGIC.to_vec();
        bytes.extend(manifest.canonical_bytes()?);
        Ok(Self {
            id: manifest.artifact_id(),
            statement: Some(manifest.statement_id()),
            obligation: None,
            bytes: bytes.into(),
            dependencies: BTreeSet::new(),
            _memory: None,
        })
    }
    pub(crate) fn program(&self) -> Result<Option<naome_proof::program::Manifest>, crate::Error> {
        let manifest = program_manifest(&self.bytes)?;
        if let Some(manifest) = &manifest
            && (manifest.artifact_id() != self.id
                || Some(manifest.statement_id()) != self.statement
                || self.obligation.is_some()
                || !self.dependencies.is_empty())
        {
            return Err("canonical program identity differs".into());
        }
        Ok(manifest)
    }
    pub(crate) fn proof_id(&self) -> Result<Option<ProofId>, crate::Error> {
        if let Some(manifest) = self.program()? {
            return Ok(Some(manifest.proof_id()));
        }
        match self.bytes.split_first() {
            Some((&ArtifactPayload::PROOF_TAG, payload)) => Ok(Some(
                ProofId::of_canonical_certificate(
                    self.statement.ok_or("proof statement missing")?,
                    payload,
                )
                .ok_or("proof identity width")?,
            )),
            Some((&ArtifactPayload::DEFINITION_TAG, _)) => Ok(None),
            _ => Err("unknown artifact payload".into()),
        }
    }
    pub(crate) fn from_checked(proof: &naome_checker::CheckedProof) -> Result<Self, crate::Error> {
        let dependencies = dependencies_with_limit(
            proof.artifact_id(),
            proof.normal_form(),
            crate::resources::limits().proof_dependencies,
        )?;
        let mut bytes = Vec::with_capacity(1 + proof.normal_form().canonical_bytes().len());
        bytes.push(ArtifactPayload::PROOF_TAG);
        bytes.extend_from_slice(proof.normal_form().canonical_bytes());
        let memory = crate::resources::MemoryLease::acquire(
            bytes
                .len()
                .checked_mul(4)
                .ok_or("artifact memory overflow")?,
        )?;
        Ok(Self {
            id: proof.artifact_id(),
            statement: Some(proof.statement_id()),
            obligation: None,
            bytes: bytes.into(),
            dependencies,
            _memory: Some(memory),
        })
    }
    pub(crate) fn envelope(&self) -> Envelope {
        Envelope {
            compatibility: hex(&compatibility()),
            artifact_id: hex(self.id.as_bytes()),
            statement_id: self.statement.map(|id| hex(id.as_bytes())),
            obligation_proof: self.obligation.map(|id| hex(id.as_bytes())),
            payload: hex(&self.bytes),
        }
    }
    pub(crate) fn prepare(self) -> Result<Candidate, crate::Error> {
        self.prepare_with_limits(
            crate::resources::limits().proof_bytes,
            crate::resources::limits().proof_dependencies,
        )
    }
    pub(crate) fn prepare_retained(self) -> Result<Candidate, crate::Error> {
        self.prepare_with_limits(
            naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES,
            naome_proof::CERTIFICATE_MAX_STEPS,
        )
    }
    fn prepare_with_limits(
        self,
        maximum: usize,
        maximum_dependencies: usize,
    ) -> Result<Candidate, crate::Error> {
        if self.bytes.len() > maximum {
            return Err(crate::Error::InputLimit("artifact byte limit"));
        }
        let memory = crate::resources::MemoryLease::acquire(
            self.bytes
                .len()
                .checked_mul(64)
                .ok_or("artifact memory overflow")?,
        )?;
        let candidate = prepare_candidate(
            self.id,
            self.statement,
            self.obligation,
            self.bytes,
            maximum_dependencies,
            memory,
        )?;
        if candidate.dependencies != self.dependencies {
            return Err("artifact dependency metadata differs".into());
        }
        Ok(candidate)
    }
}

fn prepare_candidate(
    id: ArtifactId,
    statement: Option<StatementId>,
    obligation: Option<ProofId>,
    bytes: std::sync::Arc<[u8]>,
    maximum_dependencies: usize,
    memory: std::sync::Arc<crate::resources::MemoryLease>,
) -> Result<Candidate, crate::Error> {
    let payload = match bytes.split_first() {
        Some((&ArtifactPayload::PROOF_TAG, payload)) => {
            if obligation.is_some() {
                return Err("proof has definition obligation metadata".into());
            }
            let certificate = ProofCertificate::from_canonical_bytes(payload).map_err(|error| {
                crate::Error::CertificateFormat(Box::new(crate::CertificateFormatError {
                    message: format!("malformed certificate: {error}"),
                    input_digest: naome_checker::diagnostics::Digest::of(payload),
                    reason: naome_authoring::FormatFailure::from(&error),
                }))
            })?;
            let normal = certificate.into_unchecked_normal_form();
            if normal.canonical_bytes() != payload {
                return Err("non-normal proof bytes".into());
            }
            CandidatePayload::Proof(normal)
        }
        Some((&ArtifactPayload::DEFINITION_TAG, payload)) => {
            let definition = DefinitionCertificate::from_canonical_bytes(payload)
                .map_err(|error| error.to_string())?;
            if matches!(
                definition.kind(),
                naome_proof::DefinitionKind::Function { .. }
            ) != obligation.is_some()
            {
                return Err("definition obligation witness binding differs".into());
            }
            CandidatePayload::Definition(definition)
        }
        _ => return Err("unknown artifact payload".into()),
    };
    if record_content_id(statement, &bytes)? != id {
        return Err("claimed artifact ID mismatch".into());
    }
    let dependencies = match &payload {
        CandidatePayload::Proof(normal) => {
            dependencies_with_limit(id, normal, maximum_dependencies)?
        }
        CandidatePayload::Definition(_) => obligation
            .into_iter()
            .map(ArtifactId::from_proof_id)
            .collect(),
    };
    if dependencies.len() > maximum_dependencies {
        return Err(crate::Error::InputLimit("dependency count limit"));
    }
    Ok(Candidate {
        id,
        statement,
        obligation,
        payload,
        dependencies,
        bytes,
        memory,
    })
}
fn dependencies_with_limit(
    id: ArtifactId,
    normal: &ProofNormalForm,
    maximum: usize,
) -> Result<BTreeSet<ArtifactId>, crate::Error> {
    let mut dependencies = BTreeSet::new();
    for step in normal.certificate().steps() {
        dependencies.extend(
            step.definition_references()
                .into_iter()
                .map(ArtifactId::from_definition_id),
        );
        if let ProofStep::ProofReference { proof_id } = step {
            dependencies.insert((*proof_id).into());
        }
    }
    if dependencies.len() > maximum {
        return Err(crate::Error::InputLimit("dependency count limit"));
    }
    if dependencies.contains(&id) {
        return Err("dependency cycle".into());
    }
    Ok(dependencies)
}
impl Envelope {
    /// Read the concrete citation identity from an untrusted canonical payload.
    /// This establishes syntax and address binding only, never validity.
    pub fn proof_id(&self) -> Result<Option<ProofId>, crate::Error> {
        if let Some(manifest) = self.program_claim()? {
            return Ok(Some(manifest.proof_id()));
        }
        let candidate = self.clone().prepare()?;
        candidate.record().proof_id()
    }

    /// Read the definition identity without granting selection or validity.
    pub fn definition_id(&self) -> Result<Option<naome_proof::DefinitionId>, crate::Error> {
        if self.program_claim()?.is_some() {
            return Ok(None);
        }
        let candidate = self.clone().prepare()?;
        Ok(match candidate.payload {
            CandidatePayload::Definition(certificate) => Some(certificate.definition_id()),
            CandidatePayload::Proof(_) => None,
        })
    }
    fn program_claim(&self) -> Result<Option<naome_proof::program::Manifest>, crate::Error> {
        if !self.payload.starts_with("ff") {
            return Ok(None);
        }
        if self.compatibility != hex(&compatibility()) {
            return Err("compatibility mismatch".into());
        }
        if self.payload.len() > 2 * crate::resources::limits().proof_bytes {
            return Err(crate::Error::InputLimit("artifact byte limit"));
        }
        let _memory = crate::resources::MemoryLease::acquire(self.payload.len())?;
        let manifest =
            program_manifest(&unhex(&self.payload)?)?.ok_or("program manifest missing")?;
        if self.artifact_id != hex(manifest.artifact_id().as_bytes())
            || self.statement_id.as_deref()
                != Some(hex(manifest.statement_id().as_bytes()).as_str())
            || self.obligation_proof.is_some()
        {
            return Err("program identity binding differs".into());
        }
        Ok(Some(manifest))
    }
    pub fn from_compiled(proof: CompiledProof) -> Self {
        Self {
            compatibility: hex(&compatibility()),
            artifact_id: hex(proof.artifact_id().as_bytes()),
            statement_id: Some(hex(proof.statement_id().as_bytes())),
            obligation_proof: None,
            payload: format!(
                "{:02x}{}",
                ArtifactPayload::PROOF_TAG,
                hex(proof.canonical_proof_bytes())
            ),
        }
    }
    pub(crate) fn prepare(self) -> Result<Candidate, crate::Error> {
        self.prepare_with_limits(
            crate::resources::limits().proof_bytes,
            crate::resources::limits().proof_dependencies,
        )
    }
    pub(crate) fn prepare_retained(self) -> Result<Candidate, crate::Error> {
        self.prepare_with_limits(
            naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES,
            naome_proof::CERTIFICATE_MAX_STEPS,
        )
    }
    fn prepare_with_limits(
        self,
        maximum: usize,
        maximum_dependencies: usize,
    ) -> Result<Candidate, crate::Error> {
        if self.compatibility != hex(&compatibility()) {
            return Err("compatibility mismatch".into());
        }
        let id = ArtifactId::from_bytes(id_bytes(&self.artifact_id)?);
        let statement = self
            .statement_id
            .as_deref()
            .map(id_bytes)
            .transpose()?
            .map(StatementId::from_bytes);
        let obligation = self
            .obligation_proof
            .as_deref()
            .map(id_bytes)
            .transpose()?
            .map(ProofId::from_bytes);
        if self.payload.len() > 2 * maximum {
            return Err(crate::Error::InputLimit("artifact byte limit"));
        }
        let memory = crate::resources::MemoryLease::acquire(
            self.payload
                .len()
                .checked_mul(32)
                .ok_or("artifact memory overflow")?,
        )?;
        let bytes = unhex(&self.payload)?;
        prepare_candidate(
            id,
            statement,
            obligation,
            bytes.into(),
            maximum_dependencies,
            memory,
        )
    }
}
/// Early integrity binding only; acceptance compares Checker-reconstructed identities.
pub(crate) fn content_id(statement: StatementId, bytes: &[u8]) -> ArtifactId {
    ProofId::of_canonical_certificate(statement, bytes)
        .expect("bounded proof length fits u32")
        .into()
}

pub(crate) fn id_bytes(value: &str) -> Result<[u8; 32], crate::Error> {
    if value.len() != 64 {
        return Err("identity width".into());
    }
    unhex(value)?
        .try_into()
        .map_err(|_| "identity width".into())
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

pub fn unhex(value: &str) -> Result<Vec<u8>, crate::Error> {
    if !value.len().is_multiple_of(2) {
        return Err("hex width".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            fn digit(value: u8) -> Result<u8, crate::Error> {
                match value {
                    b'0'..=b'9' => Ok(value - b'0'),
                    b'a'..=b'f' => Ok(value - b'a' + 10),
                    _ => Err("noncanonical hex".into()),
                }
            }
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}
