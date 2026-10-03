//! Ephemeral admission of externally produced research artifacts.
//!
//! This prototype has no selected ledger, validator signer or inference runtime.
//! A checked candidate remains distinct from a selected or finalized result.

use ed25519_dalek::{Signature, VerifyingKey};
use naome_checker::{ArtifactState, check_normal_form_with_state};
use naome_ledger::{
    AccountId,
    profile::{Profile, STATE_CHECKER_PROFILE},
    question::{CompiledQuestion, checker_profile_id},
};
use naome_proof::ProofCertificate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum transport frame, configuration and signed payload bytes.
pub const MAX_BYTES: usize = 64 * 1024;
/// The separate prototype accepts smaller certificates than the full protocol.
pub const MAX_PROOF_BYTES: usize = 16 * 1024;
/// Lifetime admission and retained-request ceiling.
pub const MAX_ADMISSIONS: usize = 128;
const SIGNING_DOMAIN: &[u8] = b"naome:submission:signature:v1\0";

/// Public offline context. Dependencies are checked in this supplied order.
/// They are trusted test inputs, not proof of selected-network membership.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub session: String,
    pub participants: Vec<String>,
    pub dependencies: Vec<String>,
}

/// Exactly three research write APIs. Evaluations express interest only.
#[derive(Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Submission {
    Question {
        source: String,
    },
    Evaluation {
        question: String,
        interested: bool,
        rationale: String,
    },
    ProofCandidate {
        question: String,
        refutation: bool,
        certificate: String,
        dependencies: Vec<String>,
    },
}

/// Signature covers the exact UTF-8 payload string, context, key and nonce.
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub context: String,
    pub key: String,
    pub nonce: u64,
    pub payload: String,
    pub signature: String,
}

impl SignedRequest {
    /// Cross-language signing contract: domain || context32 || key32 || nonceBE8
    /// || payloadLengthBE4 || exactPayloadUTF8. This method does not hold keys.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, &'static str> {
        if self.nonce == 0 || self.nonce > MAX_ADMISSIONS as u64 || self.payload.len() > MAX_BYTES {
            return Err("request_limit");
        }
        let mut bytes = SIGNING_DOMAIN.to_vec();
        bytes.extend(fixed::<32>(&self.context)?);
        bytes.extend(fixed::<32>(&self.key)?);
        bytes.extend(self.nonce.to_be_bytes());
        bytes.extend((self.payload.len() as u32).to_be_bytes());
        bytes.extend(self.payload.as_bytes());
        Ok(bytes)
    }
}

/// An unsigned local receipt. It establishes admission and, for candidates,
/// checker validity only. Object identifiers use prototype-specific domains.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub request: String,
    pub context: String,
    pub author: String,
    pub object: String,
    pub kind: String,
    pub proof: Option<String>,
    pub statement: Option<String>,
    pub duplicate: bool,
    pub selected: bool,
    pub finalized: bool,
}

/// Bounded in-memory admission state, rebuilt fresh for each offline session.
/// Candidate proofs never enter the frozen dependency resolver.
pub struct Admission {
    context: String,
    participants: BTreeSet<[u8; 32]>,
    artifacts: ArtifactState,
    profile: Profile,
    questions: BTreeMap<String, CompiledQuestion>,
    evaluations: BTreeSet<(String, String)>,
    nonces: BTreeMap<String, u64>,
    accepted: BTreeMap<String, (SignedRequest, Receipt)>,
}

impl Admission {
    /// Validates a public context and binds its exact bytes, profile and checker.
    /// Use a new session string on restart; this prototype has no durable replay.
    pub fn from_configuration(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_BYTES {
            return Err("configuration_limit");
        }
        let configuration: Configuration =
            serde_json::from_slice(bytes).map_err(|_| "configuration_schema")?;
        if configuration.session.is_empty()
            || configuration.session.len() > 128
            || configuration.participants.is_empty()
            || configuration.participants.len() > 16
            || configuration.dependencies.len() > 8
        {
            return Err("configuration_limit");
        }
        let mut participants = BTreeSet::new();
        for key in configuration.participants {
            let key = fixed::<32>(&key)?;
            let verifying = VerifyingKey::from_bytes(&key).map_err(|_| "key")?;
            if verifying.is_weak() || !participants.insert(key) {
                return Err("key");
            }
        }
        let mut artifacts = ArtifactState::new();
        for certificate in configuration.dependencies {
            let proof = checked(&certificate, &artifacts)?;
            artifacts
                .register_proof(proof)
                .map_err(|_| "dependency_registration")?;
        }
        let profile = Profile::research();
        let context = digest(
            b"naome:submission:context:v1\0",
            &[
                bytes,
                profile.id().as_bytes(),
                &checker_profile_id(STATE_CHECKER_PROFILE),
            ],
        );
        Ok(Self {
            context,
            participants,
            artifacts,
            profile,
            questions: BTreeMap::new(),
            evaluations: BTreeSet::new(),
            nonces: BTreeMap::new(),
            accepted: BTreeMap::new(),
        })
    }

    /// Public context identifier, also printed by the serving process.
    pub fn context(&self) -> &str {
        &self.context
    }

    /// Parse, authenticate and admit one bounded request atomically.
    /// Failures consume no nonce or admission; exact authenticated retries return
    /// the original receipt with duplicate=true and do not re-run the checker.
    pub fn submit(&mut self, bytes: &[u8]) -> Result<Receipt, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err("frame_limit");
        }
        let request: SignedRequest = serde_json::from_slice(bytes).map_err(|_| "request_schema")?;
        let message = request.signing_bytes()?;
        if request.context != self.context {
            return Err("context");
        }
        let key = fixed::<32>(&request.key)?;
        if !self.participants.contains(&key) {
            return Err("account");
        }
        let verifying = VerifyingKey::from_bytes(&key).map_err(|_| "key")?;
        verifying
            .verify_strict(
                &message,
                &Signature::from_bytes(&fixed::<64>(&request.signature)?),
            )
            .map_err(|_| "signature")?;
        let id = digest(b"naome:submission:request:v1\0", &[&message]);
        if let Some((_, receipt)) = self.accepted.get(&id) {
            let mut receipt = receipt.clone();
            receipt.duplicate = true;
            return Ok(receipt);
        }
        let previous = self.nonces.get(&request.key).copied().unwrap_or(0);
        if request.nonce != previous + 1 {
            return Err("nonce");
        }
        if previous >= 32 || self.accepted.len() >= MAX_ADMISSIONS {
            return Err("admission_limit");
        }
        let submission: Submission =
            serde_json::from_str(&request.payload).map_err(|_| "submission_schema")?;
        let mut receipt = Receipt {
            request: id.clone(),
            context: self.context.clone(),
            author: hex(AccountId::for_key(&key).as_bytes()),
            object: String::new(),
            kind: String::new(),
            proof: None,
            statement: None,
            duplicate: false,
            selected: false,
            finalized: false,
        };
        match submission {
            Submission::Question { source } => {
                if self.questions.len() >= 32 {
                    return Err("question_limit");
                }
                let question =
                    CompiledQuestion::compile(&source, &self.profile).map_err(|_| "question")?;
                let formula = question
                    .formula()
                    .encode_canonical()
                    .map_err(|_| "question")?;
                let object = digest(
                    b"naome:submission:question:v1\0",
                    &[self.context.as_bytes(), &formula],
                );
                if self.questions.contains_key(&object) {
                    return Err("question_exists");
                }
                receipt.object = object.clone();
                receipt.kind = "question_admitted".into();
                self.questions.insert(object, question);
            }
            Submission::Evaluation {
                question,
                interested: _,
                rationale,
            } => {
                fixed::<32>(&question)?;
                if rationale.len() > 1024 {
                    return Err("rationale_limit");
                }
                if !self.questions.contains_key(&question) {
                    return Err("unknown_question");
                }
                let position = (request.key.clone(), question);
                if self.evaluations.contains(&position) {
                    return Err("evaluation_exists");
                }
                receipt.object = id.clone();
                receipt.kind = "advisory_evaluation_admitted".into();
                self.evaluations.insert(position);
            }
            Submission::ProofCandidate {
                question,
                refutation,
                certificate,
                dependencies,
            } => {
                fixed::<32>(&question)?;
                let target = self.questions.get(&question).ok_or("unknown_question")?;
                if dependencies.len() > 8 {
                    return Err("dependency_limit");
                }
                for dependency in &dependencies {
                    fixed::<32>(dependency)?;
                }
                if dependencies.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err("dependencies_not_sorted_unique");
                }
                let proof = checked(&certificate, &self.artifacts)?;
                let actual: Vec<_> = proof
                    .direct_artifact_dependencies()
                    .iter()
                    .map(|id| hex(id.as_bytes()))
                    .collect();
                if actual != dependencies {
                    return Err("dependencies");
                }
                // Exact question formula or one syntactic negation, without
                // adopting the ledger's separate resolution-family settlement.
                let expected = if refutation {
                    naome_foundation::Formula::negate(target.formula().clone())
                } else {
                    target.formula().clone()
                };
                if proof
                    .conclusion()
                    .encode_canonical()
                    .map_err(|_| "target")?
                    != expected.encode_canonical().map_err(|_| "target")?
                {
                    return Err("target");
                }
                receipt.object = id.clone();
                receipt.kind = "checker_valid_candidate".into();
                receipt.proof = Some(hex(proof.proof_id().as_bytes()));
                receipt.statement = Some(hex(proof.statement_id().as_bytes()));
            }
        }
        self.nonces.insert(request.key.clone(), request.nonce);
        self.accepted.insert(id, (request, receipt.clone()));
        Ok(receipt)
    }
}

fn checked(
    certificate: &str,
    state: &ArtifactState,
) -> Result<naome_checker::CheckedProof, &'static str> {
    let bytes = unhex(certificate, MAX_PROOF_BYTES)?;
    let certificate = ProofCertificate::from_canonical_bytes(&bytes).map_err(|_| "certificate")?;
    let normal = certificate.into_unchecked_normal_form();
    if normal.canonical_bytes() != bytes {
        return Err("non_normal_certificate");
    }
    check_normal_form_with_state(normal, state).map_err(|_| "mathematical")
}

fn digest(domain: &[u8], values: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    for value in values {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hex(&hash.finalize())
}

/// Lowercase hex encoding used by the versioned wire format.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}

fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, &'static str> {
    if value.len() > maximum * 2 || !value.len().is_multiple_of(2) {
        return Err("hex_limit");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err("hex"),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}
fn fixed<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    unhex(value, N)?.try_into().map_err(|_| "hex_length")
}
