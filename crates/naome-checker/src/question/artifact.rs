//! Canonical closed research questions and checked resolution.
use std::{error::Error, fmt};

use crate::CheckedProof;
use naome_foundation::Formula;
use naome_proof::{QuestionError, QuestionTarget};
use sha2::{Digest, Sha256};

pub const QUESTION_BYTES: usize = 16 * 1024;

/// A checked proof failed the original question's two exact resolution targets.
/// Formula/codec failures of question compilation remain `QuestionError`.
#[derive(Debug)]
pub enum ResolutionError {
    Target(Box<crate::diagnostics::ProofDiagnostic>),
    Program(crate::program::Error),
}
impl ResolutionError {
    pub fn diagnostic(&self) -> Option<&crate::diagnostics::ProofDiagnostic> {
        match self {
            Self::Target(diagnostic) => Some(diagnostic),
            Self::Program(error) => error.diagnostic(),
        }
    }
}
impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(_) => f.write_str("proof conclusion does not match a question target"),
            Self::Program(error) => error.fmt(f),
        }
    }
}
impl Error for ResolutionError {}
impl serde::Serialize for ResolutionError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Target(diagnostic) => diagnostic.serialize(serializer),
            Self::Program(error) => error.serialize(serializer),
        }
    }
}

/// Mathematical orientation established by a checked proof of an exact target.
/// This grants no publication, scientific relevance, or reward eligibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuestionOutcome {
    Proved,
    Refuted,
}

/// A bounded canonical formula and its rederived resolution targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchQuestion {
    bytes: Vec<u8>,
    record_id: [u8; 32],
    target: QuestionTarget,
}

impl ResearchQuestion {
    pub fn from_checked_program(
        proof: &crate::program::CheckedProgram,
    ) -> Result<Self, QuestionError> {
        let formula = proof.conclusion().ok_or(QuestionError::Invalid(
            "program conclusion exceeds the formula codec",
        ))?;
        Self::from_formula(formula.clone())
    }

    /// Constructs a closed research obligation from the Foundation formula.
    pub fn from_formula(formula: Formula) -> Result<Self, QuestionError> {
        let target = QuestionTarget::from_formula(formula)?;
        let bytes = target
            .formula()
            .encode_canonical()
            .map_err(|error| QuestionError::Mathematical(error.to_string()))?;
        if bytes.len() > QUESTION_BYTES {
            return Err(QuestionError::Limit("question bytes"));
        }
        let record_id = hash(b"naome:state:question-record\0", &[&bytes]);
        Ok(Self {
            bytes,
            record_id,
            target,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    pub fn from_hex(value: &str) -> Result<Self, QuestionError> {
        if value.len() > 2 * QUESTION_BYTES {
            return Err(QuestionError::Limit("encoded question bytes"));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(QuestionError::Invalid("question hex"));
        }
        let bytes = hex::decode(value).map_err(|_| QuestionError::Invalid("question hex"))?;
        Self::from_canonical_bytes(&bytes)
    }

    pub const fn record_id(&self) -> &[u8; 32] {
        &self.record_id
    }

    pub const fn target(&self) -> &QuestionTarget {
        &self.target
    }
    pub const fn formula(&self) -> &Formula {
        self.target.formula()
    }
    pub const fn core(&self) -> &Formula {
        self.target.core()
    }
    pub fn canonical_core(&self) -> &[u8] {
        self.target.canonical_core()
    }
    pub const fn negation_parity(&self) -> bool {
        self.target.negation_parity()
    }
    pub const fn positive_target(&self) -> &Formula {
        self.target.positive_target()
    }
    pub const fn negative_target(&self) -> &Formula {
        self.target.negative_target()
    }
    pub fn proved_target(&self) -> &Formula {
        self.target.proved_target()
    }
    pub fn refuted_target(&self) -> &Formula {
        self.target.refuted_target()
    }
    pub const fn resolution_id(&self) -> &[u8; 32] {
        self.target.resolution_id()
    }

    /// Matches only a checker-validated conclusion against the two exact targets.
    /// Decoding establishes well-formedness; this match establishes
    /// mathematical resolution without publication authority.
    pub fn classify_checked_proof(
        &self,
        proof: &CheckedProof,
    ) -> Result<QuestionOutcome, ResolutionError> {
        self.classify_conclusion(proof.conclusion()).map_err(|_| {
            let mut diagnostic = crate::diagnostics::target_mismatch_at_snapshot(
                proof.normal_form().certificate(),
                proof.context_snapshot(),
                self.proved_target(),
                proof.conclusion(),
            )
            .expect("question targets and checked conclusions obey formula limits");
            let mut alternative = diagnostic.clone();
            diagnostic.question_record = Some(crate::diagnostics::Digest(*self.record_id()));
            alternative
                .bind_target(self.refuted_target())
                .expect("question targets obey formula limits");
            diagnostic.alternative_targets.extend(alternative.target);
            ResolutionError::Target(Box::new(diagnostic))
        })
    }

    pub fn classify_checked_program(
        &self,
        proof: &crate::program::CheckedProgram,
    ) -> Result<QuestionOutcome, ResolutionError> {
        if proof.manifest().conclusion == naome_proof::program::formula_hash(self.proved_target()) {
            return Ok(QuestionOutcome::Proved);
        }
        if proof.manifest().conclusion == naome_proof::program::formula_hash(self.refuted_target())
        {
            return Ok(QuestionOutcome::Refuted);
        }
        match proof.check_target(self.proved_target()) {
            Err(crate::program::Error::Check(mut diagnostic)) => {
                diagnostic.question_record = Some(crate::diagnostics::Digest(*self.record_id()));
                let mut alternative = diagnostic.clone();
                alternative
                    .bind_target(self.refuted_target())
                    .expect("question targets obey formula limits");
                diagnostic.alternative_targets.extend(alternative.target);
                Err(ResolutionError::Target(diagnostic))
            }
            Err(error) => Err(ResolutionError::Program(error)),
            Ok(()) => Ok(QuestionOutcome::Proved),
        }
    }

    fn classify_conclusion(&self, conclusion: &Formula) -> Result<QuestionOutcome, QuestionError> {
        if conclusion == self.proved_target() {
            Ok(QuestionOutcome::Proved)
        } else if conclusion == self.refuted_target() {
            Ok(QuestionOutcome::Refuted)
        } else {
            Err(QuestionError::Invalid(
                "proof conclusion does not match a question target",
            ))
        }
    }

    /// Decodes exactly one canonical Foundation formula and rederives its targets.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, QuestionError> {
        if bytes.len() > QUESTION_BYTES {
            return Err(QuestionError::Limit("encoded question bytes"));
        }
        let formula = Formula::decode_canonical(bytes)
            .map_err(|error| QuestionError::Mathematical(error.to_string()))?;
        let question = Self::from_formula(formula)?;
        if question.canonical_bytes() != bytes {
            return Err(QuestionError::Invalid("noncanonical question formula"));
        }
        Ok(question)
    }
}

#[cfg(test)]
mod tests;

// Question record identities bind the exact canonical formula bytes.
fn hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}
