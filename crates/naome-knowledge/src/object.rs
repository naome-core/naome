use naome_authoring::CompiledProof;
use naome_foundation::FOUNDATION_ID;
use naome_proof::{ProofCertificate, ProofId, ProofNormalForm, ProofStep, StatementId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

pub const CODEC_ID: &str = "naome:proof-codec:v0";
pub const CHECKER_ID: &str = "naome:zfc-checker:v0";
pub const GRAPH_POLICY_ID: &str = "naome:knowledge:proof-program:v2";
const PROGRAM_MAGIC: &[u8] = b"\xffNAOP1\0";

pub(crate) fn program_manifest(
    bytes: &[u8],
) -> Result<Option<naome_proof::program::Manifest>, crate::Error> {
    if bytes.first() != Some(&0xff) {
        return Ok(None);
    }
    let body = bytes
        .strip_prefix(PROGRAM_MAGIC)
        .ok_or("unknown program payload format")?;
    if body.len() > 2048 {
        return Err("program manifest width".into());
    }
    let manifest: naome_proof::program::Manifest =
        serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if manifest.commands == 0
        || manifest.input_bytes == 0
        || manifest.commands > i64::MAX as u64
        || manifest.input_bytes > i64::MAX as u64
        || serde_json::to_vec(&manifest).map_err(|e| e.to_string())? != body
    {
        return Err("invalid canonical program manifest".into());
    }
    Ok(Some(manifest))
}

pub(crate) fn record_content_id(
    statement: StatementId,
    bytes: &[u8],
) -> Result<ProofId, crate::Error> {
    match program_manifest(bytes)? {
        Some(manifest) => {
            if manifest.statement_id() != statement {
                return Err("program statement binding differs".into());
            }
            Ok(manifest.proof_id())
        }
        None => Ok(content_id(statement, bytes)),
    }
}

/// Untrusted envelope. Neither construction nor deserialization establishes validity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub compatibility: String,
    pub proof_id: String,
    pub statement_id: String,
    pub proof: String,
}

/// Bounded, untrusted description of a newly derived resolution obligation.
/// It contains no certificate bytes and makes no proof-validity claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Metadata {
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
impl ProgramMetadata {
    pub(crate) fn question(
        &self,
    ) -> Result<Option<naome_authoring::CompiledQuestion>, crate::Error> {
        self.question
            .as_ref()
            .map(|question| {
                Metadata {
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
    ) -> Result<(ProofId, StatementId, naome_authoring::CompiledQuestion), crate::Error> {
        let id = ProofId::from_bytes(id_bytes(&self.proof_id)?);
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
    hash.update(b"naome:knowledge:compatibility:v1\0");
    for value in [FOUNDATION_ID, CODEC_ID, CHECKER_ID, GRAPH_POLICY_ID] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}

/// Canonical binary syntax and typed identities. It grants no mathematical
/// validity. Hex and JSON belong only to transport and CLI boundaries.
#[derive(Clone, Debug)]
pub(crate) struct BinaryProof {
    pub id: ProofId,
    pub statement: StatementId,
    pub bytes: std::sync::Arc<[u8]>,
    pub dependencies: BTreeSet<ProofId>,
    pub _memory: Option<std::sync::Arc<crate::resources::MemoryLease>>,
}
impl PartialEq for BinaryProof {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.statement == other.statement
            && self.bytes == other.bytes
            && self.dependencies == other.dependencies
    }
}
impl Eq for BinaryProof {}

pub(crate) struct Candidate {
    pub id: ProofId,
    pub statement: StatementId,
    pub normal: ProofNormalForm,
    pub dependencies: BTreeSet<ProofId>,
    pub bytes: std::sync::Arc<[u8]>,
    memory: std::sync::Arc<crate::resources::MemoryLease>,
}

impl Candidate {
    pub(crate) fn record(&self) -> BinaryProof {
        BinaryProof {
            id: self.id,
            statement: self.statement,
            bytes: self.bytes.clone(),
            dependencies: self.dependencies.clone(),
            _memory: Some(self.memory.clone()),
        }
    }
}

impl BinaryProof {
    pub(crate) fn from_program(
        proof: &naome_checker::program::CheckedProgram,
    ) -> Result<Self, crate::Error> {
        let manifest = proof.manifest();
        let mut bytes = PROGRAM_MAGIC.to_vec();
        bytes.extend(serde_json::to_vec(manifest).map_err(|e| e.to_string())?);
        Ok(Self {
            id: manifest.proof_id(),
            statement: manifest.statement_id(),
            bytes: bytes.into(),
            dependencies: BTreeSet::new(),
            _memory: None,
        })
    }
    pub(crate) fn program(&self) -> Result<Option<naome_proof::program::Manifest>, crate::Error> {
        let manifest = program_manifest(&self.bytes)?;
        if let Some(manifest) = &manifest
            && (manifest.proof_id() != self.id
                || manifest.statement_id() != self.statement
                || !self.dependencies.is_empty())
        {
            return Err("canonical program identity differs".into());
        }
        Ok(manifest)
    }
    pub(crate) fn from_checked(proof: &naome_checker::CheckedProof) -> Result<Self, crate::Error> {
        let dependencies = dependencies(proof.proof_id(), proof.normal_form())?;
        Ok(Self {
            id: proof.proof_id(),
            statement: proof.statement_id(),
            bytes: proof.normal_form().canonical_bytes().into(),
            dependencies,
            _memory: Some(crate::resources::MemoryLease::acquire(
                proof
                    .normal_form()
                    .canonical_bytes()
                    .len()
                    .checked_mul(4)
                    .ok_or("proof memory overflow")?,
            )?),
        })
    }

    pub(crate) fn envelope(&self) -> Envelope {
        Envelope {
            compatibility: hex(&compatibility()),
            proof_id: hex(self.id.as_bytes()),
            statement_id: hex(self.statement.as_bytes()),
            proof: hex(&self.bytes),
        }
    }

    pub(crate) fn prepare(self) -> Result<Candidate, crate::Error> {
        self.prepare_with_limits(
            crate::resources::limits().proof_bytes,
            crate::resources::limits().proof_dependencies,
        )
    }
    /// Replay uses protocol limits. Local intake settings cannot invalidate history.
    pub(crate) fn prepare_retained(self) -> Result<Candidate, crate::Error> {
        self.prepare_with_limits(
            naome_proof::CERTIFICATE_MAX_BYTES,
            naome_proof::CERTIFICATE_MAX_STEPS,
        )
    }
    fn prepare_with_limits(
        self,
        maximum: usize,
        maximum_dependencies: usize,
    ) -> Result<Candidate, crate::Error> {
        if self.bytes.len() > maximum {
            return Err(crate::Error::InputLimit("proof byte limit"));
        }
        let memory = crate::resources::MemoryLease::acquire(
            self.bytes
                .len()
                .checked_mul(64)
                .ok_or("proof memory overflow")?,
        )?;
        let candidate = prepare_candidate(
            self.id,
            self.statement,
            self.bytes,
            maximum_dependencies,
            memory,
        )?;
        if candidate.dependencies != self.dependencies {
            return Err("proof dependency metadata differs".into());
        }
        Ok(candidate)
    }
}

fn prepare_candidate(
    id: ProofId,
    statement: StatementId,
    bytes: std::sync::Arc<[u8]>,
    maximum_dependencies: usize,
    memory: std::sync::Arc<crate::resources::MemoryLease>,
) -> Result<Candidate, crate::Error> {
    let certificate = ProofCertificate::from_canonical_bytes(&bytes)
        .map_err(|error| format!("malformed certificate: {error}"))?;
    let normal = certificate.into_unchecked_normal_form();
    if normal.canonical_bytes() != bytes.as_ref() {
        return Err("non-normal proof bytes".into());
    }
    if content_id(statement, &bytes) != id {
        return Err("claimed proof ID mismatch".into());
    }
    let dependencies = dependencies_with_limit(id, &normal, maximum_dependencies)?;
    Ok(Candidate {
        id,
        statement,
        normal,
        dependencies,
        bytes,
        memory,
    })
}

fn dependencies(id: ProofId, normal: &ProofNormalForm) -> Result<BTreeSet<ProofId>, crate::Error> {
    dependencies_with_limit(id, normal, crate::resources::limits().proof_dependencies)
}
fn dependencies_with_limit(
    id: ProofId,
    normal: &ProofNormalForm,
    maximum: usize,
) -> Result<BTreeSet<ProofId>, crate::Error> {
    let mut dependencies = BTreeSet::new();
    for step in normal.certificate().steps() {
        if !step.definition_references().is_empty() {
            return Err("definitions unsupported by proof-only graph policy".into());
        }
        if let ProofStep::ProofReference { proof_id } = step {
            dependencies.insert(*proof_id);
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
    pub fn from_compiled(proof: CompiledProof) -> Self {
        Self {
            compatibility: hex(&compatibility()),
            proof_id: hex(proof.proof_id().as_bytes()),
            statement_id: hex(proof.statement_id().as_bytes()),
            proof: hex(proof.canonical_proof_bytes()),
        }
    }

    pub(crate) fn prepare(self) -> Result<Candidate, crate::Error> {
        if self.compatibility != hex(&compatibility()) {
            return Err("compatibility mismatch".into());
        }
        let id = ProofId::from_bytes(id_bytes(&self.proof_id)?);
        let statement = StatementId::from_bytes(id_bytes(&self.statement_id)?);
        if self.proof.len() > 2 * crate::resources::limits().proof_bytes {
            return Err(crate::Error::InputLimit("proof byte limit"));
        }
        let memory = crate::resources::MemoryLease::acquire(
            self.proof
                .len()
                .checked_mul(32)
                .ok_or("proof memory overflow")?,
        )?;
        let bytes = unhex(&self.proof)?;
        prepare_candidate(
            id,
            statement,
            bytes.into(),
            crate::resources::limits().proof_dependencies,
            memory,
        )
    }
}

// Mirror the existing proof address framing only for early integrity filtering.
// Admission still compares the IDs reconstructed by the actual checker.
pub(crate) fn content_id(statement: StatementId, bytes: &[u8]) -> ProofId {
    ProofId::of_canonical_certificate(statement, bytes).expect("bounded proof length fits u32")
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
