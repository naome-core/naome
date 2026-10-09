use naome_authoring::CompiledProof;
use naome_foundation::FOUNDATION_ID;
use naome_proof::{ProofCertificate, ProofId, ProofNormalForm, ProofStep, StatementId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CODEC_ID: &str = "naome:proof-codec:v0";
pub const CHECKER_ID: &str = "naome:zfc-checker:v0";
pub const GRAPH_POLICY_ID: &str = "naome:knowledge:proof-only:v1";
pub const MAX_PROOF_BYTES: usize = 65_536;
pub const MAX_DEPENDENCIES: usize = 32;
pub const MAX_DEPTH: usize = 64;

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

impl Metadata {
    pub(crate) fn compile(
        &self,
    ) -> Result<(ProofId, StatementId, naome_authoring::CompiledQuestion), String> {
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
pub(crate) fn target_id(formula: &naome_foundation::Formula) -> Result<StatementId, String> {
    let bytes = formula
        .encode_canonical()
        .map_err(|error| error.to_string())?;
    let mut hash = Sha256::new();
    hash.update(b"naome:statement\0");
    hash.update((FOUNDATION_ID.len() as u32).to_be_bytes());
    hash.update(FOUNDATION_ID.as_bytes());
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
    Ok(StatementId::from_bytes(hash.finalize().into()))
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

pub(crate) struct Candidate {
    pub envelope: Envelope,
    pub id: ProofId,
    pub statement: StatementId,
    pub normal: ProofNormalForm,
    pub dependencies: BTreeSet<ProofId>,
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

    pub(crate) fn prepare(self) -> Result<Candidate, String> {
        if self.compatibility != hex(&compatibility()) {
            return Err("compatibility mismatch".into());
        }
        let id = ProofId::from_bytes(id_bytes(&self.proof_id)?);
        let statement = StatementId::from_bytes(id_bytes(&self.statement_id)?);
        if self.proof.len() > 2 * MAX_PROOF_BYTES {
            return Err("proof byte limit".into());
        }
        let bytes = unhex(&self.proof)?;
        let certificate = ProofCertificate::from_canonical_bytes(&bytes)
            .map_err(|error| format!("malformed certificate: {error}"))?;
        let normal = certificate.into_unchecked_normal_form();
        if normal.canonical_bytes() != bytes {
            return Err("non-normal proof bytes".into());
        }
        if content_id(statement, &bytes) != id {
            return Err("claimed proof ID mismatch".into());
        }
        let mut dependencies = BTreeSet::new();
        for step in normal.certificate().steps() {
            if !step.definition_references().is_empty() {
                return Err("definitions unsupported by proof-only graph policy".into());
            }
            if let ProofStep::ProofReference { proof_id } = step {
                dependencies.insert(*proof_id);
            }
        }
        if dependencies.len() > MAX_DEPENDENCIES {
            return Err("dependency count limit".into());
        }
        if dependencies.contains(&id) {
            return Err("dependency cycle".into());
        }
        Ok(Candidate {
            envelope: self,
            id,
            statement,
            normal,
            dependencies,
        })
    }
}

// Mirror the existing proof address framing only for early integrity filtering.
// Admission still compares the IDs reconstructed by the actual checker.
pub(crate) fn content_id(statement: StatementId, bytes: &[u8]) -> ProofId {
    let mut hash = Sha256::new();
    hash.update(b"naome:proof\0");
    hash.update((FOUNDATION_ID.len() as u32).to_be_bytes());
    hash.update(FOUNDATION_ID.as_bytes());
    hash.update(statement.as_bytes());
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
    ProofId::from_bytes(hash.finalize().into())
}

pub(crate) fn id_bytes(value: &str) -> Result<[u8; 32], String> {
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

pub fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex width".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            fn digit(value: u8) -> Result<u8, String> {
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
