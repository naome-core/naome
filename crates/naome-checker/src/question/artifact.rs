//! Canonical closed research questions and checked resolution.
use std::{error::Error, fmt};

use crate::CheckedProof;
use naome_foundation::Formula;
use naome_proof::{
    ArtifactId, DefinedFormula, QUESTION_EXPANSION_MAX_NODES, QUESTION_TARGET_MAX_DEPTH,
    QUESTION_TARGET_MAX_NODES, QuestionError, QuestionTarget,
};
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

/// A bounded canonical submission and its rederived primitive resolution targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchQuestion {
    bytes: Vec<u8>,
    record_id: [u8; 32],
    target: QuestionTarget,
    dependencies: Vec<ArtifactId>,
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
        Self::new(bytes, target, Vec::new())
    }

    fn new(
        bytes: Vec<u8>,
        target: QuestionTarget,
        dependencies: Vec<ArtifactId>,
    ) -> Result<Self, QuestionError> {
        if bytes.len() > QUESTION_BYTES {
            return Err(QuestionError::Limit("question bytes"));
        }
        let record_id = hash(b"naome:state:question-record\0", &[&bytes]);
        Ok(Self {
            bytes,
            record_id,
            target,
            dependencies,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    pub fn from_hex(value: &str) -> Result<Self, QuestionError> {
        Self::from_canonical_bytes(&decode_hex(value)?)
    }

    /// Decodes a canonical question against the receiving node's checked context.
    pub fn from_hex_with_context(
        value: &str,
        context: &dyn crate::ContextView,
    ) -> Result<Self, QuestionError> {
        Self::from_canonical_bytes_with_context(&decode_hex(value)?, context)
    }

    /// The exact checked definition artifacts required by this submission.
    pub fn dependencies(&self) -> &[ArtifactId] {
        &self.dependencies
    }

    /// Compiles a compact definition-aware formula to its exact resolution targets.
    pub fn from_defined_formula(
        formula: DefinedFormula,
        context: &dyn crate::ContextView,
    ) -> Result<Self, QuestionError> {
        Self::compile_defined(formula, Some(context))
    }

    fn compile_defined(
        formula: DefinedFormula,
        context: Option<&dyn crate::ContextView>,
    ) -> Result<Self, QuestionError> {
        let (bytes, dependencies) = Self::definition_source(&formula)?;
        if dependencies.is_empty() {
            return Self::from_formula(
                Formula::decode_canonical(&bytes)
                    .map_err(|e| QuestionError::Mathematical(e.to_string()))?,
            );
        }
        let context = context.ok_or(QuestionError::Invalid(
            "question needs a checked definition context",
        ))?;
        let context = crate::context::cache::ReadContext::new(context);
        // A primitive node uses at most eleven bytes. Each referenced
        // certificate's header fits in the expansion unit for the application.
        let context = crate::context::cache::FormulaWorkBudget::new(
            &context,
            11 * QUESTION_EXPANSION_MAX_NODES,
        );
        let (expanded, _) = formula
            .expand_with_node_limit(&context, QUESTION_EXPANSION_MAX_NODES - 1)
            .map_err(|error| match error {
                naome_proof::DefinitionExpansionError::UnknownDefinition { definition_id } => {
                    QuestionError::MissingDefinition(definition_id)
                }
                naome_proof::DefinitionExpansionError::Access(
                    naome_proof::DefinitionAccessError::Limit,
                ) => QuestionError::Limit("question definition decode bytes"),
                _ => QuestionError::Mathematical(error.to_string()),
            })?;
        let target = QuestionTarget::from_expanded_formula(expanded)?;
        Self::new(bytes, target, dependencies)
    }

    fn definition_source(
        formula: &DefinedFormula,
    ) -> Result<(Vec<u8>, Vec<ArtifactId>), QuestionError> {
        let bytes = formula
            .encode_canonical_with_limits(
                QUESTION_TARGET_MAX_NODES - 1,
                QUESTION_TARGET_MAX_DEPTH as u32 - 1,
            )
            .map_err(|error| QuestionError::Mathematical(error.to_string()))?
            .0;
        if bytes.len() > QUESTION_BYTES {
            return Err(QuestionError::Limit("question bytes"));
        }
        if !formula.is_closed() {
            return Err(QuestionError::Invalid("question has free variables"));
        }
        let dependencies = formula
            .definition_references()
            .into_iter()
            .map(ArtifactId::from_definition_id)
            .collect::<std::collections::BTreeSet<_>>();
        if dependencies.len() > super::AssessmentLimits::MAXIMUM.dependencies {
            return Err(QuestionError::Limit("question dependencies"));
        }
        Ok((bytes, dependencies.into_iter().collect()))
    }

    /// Checks question syntax without a checked context, returning whether
    /// semantic validation still requires checked definitions.
    pub fn source_requires_definitions(value: &str) -> Result<bool, QuestionError> {
        let bytes = decode_hex(value)?;
        if let Ok(formula) = Formula::decode_canonical(&bytes) {
            QuestionTarget::from_formula(formula)?;
            return Ok(false);
        }
        let formula = decode_formula(&bytes)?;
        let (canonical, dependencies) = Self::definition_source(&formula)?;
        if canonical != bytes {
            return Err(QuestionError::Invalid("noncanonical question formula"));
        }
        Ok(!dependencies.is_empty())
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

    /// Decodes a canonical question that requires no checked definitions.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, QuestionError> {
        Self::decode(bytes, None)
    }

    /// Decodes a canonical question and checks its exact definition references.
    pub fn from_canonical_bytes_with_context(
        bytes: &[u8],
        context: &dyn crate::ContextView,
    ) -> Result<Self, QuestionError> {
        Self::decode(bytes, Some(context))
    }

    fn decode(
        bytes: &[u8],
        context: Option<&dyn crate::ContextView>,
    ) -> Result<Self, QuestionError> {
        if bytes.len() > QUESTION_BYTES {
            return Err(QuestionError::Limit("encoded question bytes"));
        }
        let question = match Formula::decode_canonical(bytes) {
            Ok(formula) => Self::from_formula(formula)?,
            Err(error) if context.is_none() => {
                return Err(QuestionError::Mathematical(error.to_string()));
            }
            Err(_) => Self::compile_defined(decode_formula(bytes)?, context)?,
        };
        if question.canonical_bytes() != bytes {
            return Err(QuestionError::Invalid("noncanonical question formula"));
        }
        Ok(question)
    }
}

fn decode_formula(bytes: &[u8]) -> Result<DefinedFormula, QuestionError> {
    DefinedFormula::decode_canonical(bytes)
        .map_err(|error| QuestionError::Mathematical(error.to_string()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, QuestionError> {
    if value.len() > 2 * QUESTION_BYTES {
        return Err(QuestionError::Limit("encoded question bytes"));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(QuestionError::Invalid("question hex"));
    }
    hex::decode(value).map_err(|_| QuestionError::Invalid("question hex"))
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
