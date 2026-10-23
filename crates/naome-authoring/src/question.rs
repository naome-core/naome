//! Bounded compilation of closed research obligations using Foundation notation.
//!
//! One bounded headerless question language with optional formula bindings.
//! Targets use the fixed mathematical Foundation and retain exact logical shape.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use naome_checker::CheckedProof;
use naome_foundation::{FORMULA_MAX_DEPTH, Formula, FreeVariable};
use sha2::{Digest, Sha256};

use crate::{CompileDiagnostic, DiagnosticCode, SourceSpan, syntax};

/// Maximum UTF-8 bytes in one formal obligation.
pub const QUESTION_SOURCE_MAX_BYTES: usize = 16 * 1024;
use naome_proof::QuestionTarget;
pub use naome_proof::{QUESTION_TARGET_MAX_DEPTH, QUESTION_TARGET_MAX_NODES, QuestionError};

/// A question source failure with an original-source machine-readable diagnostic.
/// Codec failures continue to use [`QuestionError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuestionCompileError {
    error: QuestionError,
    diagnostic: CompileDiagnostic,
}

impl QuestionCompileError {
    /// Returns the existing question failure class.
    pub const fn error(&self) -> &QuestionError {
        &self.error
    }
    /// Returns a stable code, original UTF-8 span and one-based source position.
    pub const fn diagnostic(&self) -> &CompileDiagnostic {
        &self.diagnostic
    }
    /// Returns the underlying error used by [`CompiledQuestion::compile`].
    pub fn into_error(self) -> QuestionError {
        self.error
    }

    fn code(error: &QuestionError) -> DiagnosticCode {
        match error {
            QuestionError::Limit(_) | QuestionError::Overflow => DiagnosticCode::QuestionLimit,
            QuestionError::Invalid("question has free variables") => {
                DiagnosticCode::QuestionOpenFormula
            }
            QuestionError::Mathematical(_) => DiagnosticCode::QuestionFormula,
            _ => DiagnosticCode::QuestionSyntax,
        }
    }

    fn at(error: QuestionError, source: &str, span: Option<SourceSpan>) -> Self {
        let diagnostic = CompileDiagnostic::at(Self::code(&error), error.to_string(), source, span);
        Self { error, diagnostic }
    }
}

impl fmt::Display for QuestionCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl Error for QuestionCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// Mathematical orientation established by a checked proof of an exact target.
/// This grants no publication, scientific relevance, or reward eligibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuestionOutcome {
    Proved,
    Refuted,
}

/// A compiled closed question; fields cannot bypass source compilation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledQuestion {
    source: String,
    source_hash: [u8; 32],
    target: QuestionTarget,
}

impl CompiledQuestion {
    /// Compiles a bounded obligation without accepting proof or definition input.
    pub fn compile(source: &str) -> Result<Self, QuestionError> {
        Self::compile_with_diagnostic(source).map_err(QuestionCompileError::into_error)
    }

    /// Compiles the same bounded question with original-source repair metadata.
    /// Source spelling may change its source hash, never its target semantics.
    pub fn compile_with_diagnostic(source: &str) -> Result<Self, QuestionCompileError> {
        if source.len() > QUESTION_SOURCE_MAX_BYTES {
            let error = QuestionError::Limit("question source bytes");
            return Err(QuestionCompileError {
                diagnostic: CompileDiagnostic::at(
                    DiagnosticCode::SourceTooLong,
                    error.to_string(),
                    source,
                    None,
                ),
                error,
            });
        }
        // At most source.len() leading negations can later be removed.
        // Preflight every expansion against this finite aggregate allowance.
        let parse_nodes = QUESTION_TARGET_MAX_NODES + source.len();
        let mut parser = Parser {
            source,
            offset: 0,
            token_offset: 0,
            variables: syntax::Variables::default(),
            bindings: BTreeMap::new(),
            binding_nodes: 0,
            maximum_nodes: parse_nodes,
        };
        let mut statement_span = SourceSpan::point(0);
        let parsed = (|| -> Result<Parsed, QuestionError> {
            if parser.peek_word("let") {
                parser.formula_bindings()?;
            }
            parser.word("goal")?;
            parser.punctuation(b'=')?;
            parser.trivia();
            let start = parser.offset;
            let parsed = parser.formula(1)?;
            statement_span = SourceSpan::new(start, parser.offset);
            parser.trivia();
            if parser.offset < source.len() {
                parser.word("success")?;
                parser.punctuation(b'=')?;
                parser.literal("\"resolve\"")?;
            }
            parser.trivia();
            if parser.offset != source.len() {
                parser.token_offset = parser.offset;
                return Err(QuestionError::Invalid("question trailing source"));
            }
            Ok(parsed)
        })()
        .map_err(|error| QuestionCompileError {
            diagnostic: CompileDiagnostic::token(
                QuestionCompileError::code(&error),
                error.to_string(),
                source,
                parser.token_offset,
            ),
            error,
        })?;
        let failure = |error| QuestionCompileError::at(error, source, Some(statement_span));
        if !parsed.formula.is_closed() {
            return Err(failure(QuestionError::Invalid(
                "question has free variables",
            )));
        }
        Self::from_parts(source, parsed.formula).map_err(failure)
    }

    /// Constructs a derived question from an already available formal formula.
    /// It enforces the same target limits and identities as source compilation;
    /// the generated source records presentation provenance, never proof validity.
    pub fn from_formula(formula: Formula) -> Result<Self, QuestionError> {
        let source = format!("goal = {}", formula.to_source());
        if source.len() > QUESTION_SOURCE_MAX_BYTES {
            return Err(QuestionError::Limit("question source bytes"));
        }
        Self::from_parts(&source, formula)
    }

    fn from_parts(source: &str, formula: Formula) -> Result<Self, QuestionError> {
        Ok(Self {
            source: source.to_owned(),
            source_hash: hash(b"naome:state:question-source:v1\0", &[source.as_bytes()]),
            target: QuestionTarget::from_formula(formula)?,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }
    pub const fn source_hash(&self) -> &[u8; 32] {
        &self.source_hash
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
    /// Compilation alone establishes well-formedness; this match establishes
    /// mathematical resolution without any ledger or publication authority.
    pub fn classify_checked_proof(
        &self,
        proof: &CheckedProof,
    ) -> Result<QuestionOutcome, QuestionError> {
        if proof.conclusion() == self.proved_target() {
            Ok(QuestionOutcome::Proved)
        } else if proof.conclusion() == self.refuted_target() {
            Ok(QuestionOutcome::Refuted)
        } else {
            Err(QuestionError::Invalid(
                "proof conclusion does not match a question target",
            ))
        }
    }

    /// Encodes the source as the sole authority; derived fields are recomputed.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, QuestionError> {
        let length = u32::try_from(self.source.len())
            .map_err(|_| QuestionError::Limit("question source bytes"))?;
        let mut bytes = Vec::with_capacity(self.source.len() + 5);
        bytes.push(1);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(self.source.as_bytes());
        Ok(bytes)
    }

    /// Strictly decodes and recompiles; no supplied identifier is trusted.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, QuestionError> {
        if bytes.len() > QUESTION_SOURCE_MAX_BYTES + 5 {
            return Err(QuestionError::Limit("encoded question bytes"));
        }
        let version = *bytes.first().ok_or(QuestionError::Truncated)?;
        if version != 1 {
            return Err(QuestionError::Invalid("question codec version"));
        }
        let length = u32::from_be_bytes(
            bytes
                .get(1..5)
                .ok_or(QuestionError::Truncated)?
                .try_into()
                .map_err(|_| QuestionError::Truncated)?,
        ) as usize;
        if length > QUESTION_SOURCE_MAX_BYTES {
            return Err(QuestionError::Limit("question source bytes"));
        }
        let source = std::str::from_utf8(bytes.get(5..5 + length).ok_or(QuestionError::Truncated)?)
            .map_err(|_| QuestionError::Invalid("UTF-8"))?;
        if bytes.len() != 5 + length {
            return Err(QuestionError::TrailingBytes);
        }
        Self::compile(source)
    }
}

// Domain-separated source/core identities use u64-length framing and grant
// no state or opening authority.
fn hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

struct Parsed {
    formula: Formula,
    nodes: usize,
    depth: usize,
}

struct Parser<'a> {
    source: &'a str,
    offset: usize,
    token_offset: usize,
    variables: syntax::Variables<'a>,
    bindings: BTreeMap<&'a str, Parsed>,
    binding_nodes: usize,
    maximum_nodes: usize,
}

impl<'a> Parser<'a> {
    fn bounded(&self, nodes: usize, depth: usize) -> Result<(), QuestionError> {
        if nodes > self.maximum_nodes {
            return Err(QuestionError::Limit("question expansion nodes"));
        }
        if depth > FORMULA_MAX_DEPTH as usize {
            return Err(QuestionError::Limit("question expansion depth"));
        }
        Ok(())
    }
    fn trivia(&mut self) {
        syntax::trivia(self.source, &mut self.offset);
    }
    fn byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }
    fn name(&mut self) -> Result<&'a str, QuestionError> {
        self.trivia();
        let start = self.offset;
        self.token_offset = start;
        syntax::name(self.source, &mut self.offset)
            .ok_or(QuestionError::Invalid("question expected name"))
    }

    fn word(&mut self, expected: &str) -> Result<(), QuestionError> {
        let name = self.name()?;
        if name != expected {
            return Err(QuestionError::Invalid("question unexpected field"));
        }
        Ok(())
    }
    fn literal(&mut self, expected: &str) -> Result<(), QuestionError> {
        self.trivia();
        self.token_offset = self.offset;
        if !self.source[self.offset..].starts_with(expected) {
            return Err(QuestionError::Invalid(
                "question unsupported success policy",
            ));
        }
        self.offset += expected.len();
        Ok(())
    }
    fn punctuation(&mut self, expected: u8) -> Result<(), QuestionError> {
        self.trivia();
        self.token_offset = self.offset;
        if self.byte() != Some(expected) {
            return Err(QuestionError::Invalid("question punctuation"));
        }
        self.offset += 1;
        Ok(())
    }
    fn variable(&mut self) -> Result<FreeVariable, QuestionError> {
        let name = self.name()?;
        self.variables.named(name).ok_or(QuestionError::Overflow)
    }

    fn peek_word(&mut self, expected: &str) -> bool {
        self.trivia();
        syntax::word_at(self.source, self.offset, expected)
    }

    fn formula_bindings(&mut self) -> Result<(), QuestionError> {
        self.word("let")?;
        self.punctuation(b':')?;
        loop {
            self.trivia();
            self.token_offset = self.offset;
            let name = syntax::binding_name(self.source, &mut self.offset, |name| {
                self.bindings.contains_key(name)
            })
            .map_err(|error| match error {
                syntax::BindingError::Name => QuestionError::Invalid("question expected name"),
                syntax::BindingError::Reserved => {
                    QuestionError::Invalid("question reserved formula binding")
                }
                syntax::BindingError::Duplicate => {
                    QuestionError::Invalid("question duplicate formula binding")
                }
            })?;
            self.punctuation(b'=')?;
            let parse_allowance = self.maximum_nodes;
            self.maximum_nodes = QUESTION_TARGET_MAX_NODES - self.binding_nodes;
            let parsed = self.formula(1)?;
            self.binding_nodes += parsed.nodes;
            self.maximum_nodes = parse_allowance;
            self.bindings.insert(name, parsed);
            if self.peek_word("goal") {
                return Ok(());
            }
        }
    }

    fn quantified(
        &mut self,
        existential: bool,
        source_depth: usize,
    ) -> Result<Parsed, QuestionError> {
        let variables = syntax::binders(self.source, &mut self.offset, &mut self.variables)
            .map_err(|error| match error {
                syntax::BinderError::Name(offset) => {
                    self.token_offset = offset;
                    QuestionError::Invalid("question expected name")
                }
                syntax::BinderError::Comma(offset) => {
                    self.token_offset = offset;
                    QuestionError::Invalid("question punctuation")
                }
                syntax::BinderError::Depth => QuestionError::Limit("question expansion depth"),
                syntax::BinderError::Overflow => QuestionError::Overflow,
            })?;
        self.punctuation(b',')?;
        let extra = variables.len() * if existential { 3 } else { 1 };
        self.bounded(extra + 1, source_depth + extra)?;
        let body = self.formula(source_depth + extra)?;
        let nodes = body.nodes + extra;
        let depth = body.depth + extra;
        self.bounded(nodes, source_depth - 1 + depth)?;
        let mut formula = body.formula;
        for variable in variables.into_iter().rev() {
            formula = if existential {
                Formula::exists(variable, formula)
            } else {
                Formula::for_all(variable, formula)
            };
        }
        Ok(Parsed {
            formula,
            nodes,
            depth,
        })
    }

    fn formula(&mut self, source_depth: usize) -> Result<Parsed, QuestionError> {
        self.bounded(0, source_depth)?;
        let operator = self.name()?;
        let operator_offset = self.token_offset;
        let name_end = self.offset;
        self.trivia();
        if self.byte() != Some(b'(') {
            self.offset = name_end;
            let binding = self
                .bindings
                .get(operator)
                .ok_or(QuestionError::Invalid("question unknown formula binding"))?;
            self.bounded(binding.nodes, source_depth - 1 + binding.depth)?;
            return Ok(Parsed {
                formula: binding.formula.clone(),
                nodes: binding.nodes,
                depth: binding.depth,
            });
        }
        self.punctuation(b'(')?;
        let parsed = match operator {
            "eq" | "mem" | "ne" => {
                let left = self.variable()?;
                self.punctuation(b',')?;
                let right = self.variable()?;
                let formula = if operator == "mem" {
                    Formula::member(left, right)
                } else {
                    Formula::equal(left, right)
                };
                if operator == "ne" {
                    Parsed {
                        formula: Formula::negate(formula),
                        nodes: 2,
                        depth: 2,
                    }
                } else {
                    Parsed {
                        formula,
                        nodes: 1,
                        depth: 1,
                    }
                }
            }
            "all" | "ex" => self.quantified(operator == "ex", source_depth)?,
            "not" => {
                let body = self.formula(source_depth + 1)?;
                let nodes = body.nodes + 1;
                let depth = body.depth + 1;
                self.bounded(nodes, source_depth - 1 + depth)?;
                Parsed {
                    formula: Formula::negate(body.formula),
                    nodes,
                    depth,
                }
            }
            "imp" | "and" | "or" | "iff" => {
                let left = self.formula(source_depth + 1)?;
                self.punctuation(b',')?;
                let right = self.formula(source_depth + 1)?;
                let (nodes, depth) = syntax::binary_shape(
                    operator,
                    (left.nodes, left.depth),
                    (right.nodes, right.depth),
                )
                .ok_or(QuestionError::Overflow)?;
                // Preflight expanded size BEFORE constructors such as iff clone
                // their children. Exponential source expansion stays bounded.
                self.bounded(nodes, source_depth - 1 + depth)?;
                let formula = match operator {
                    "imp" => Formula::implies(left.formula, right.formula),
                    "and" => Formula::conjunction(left.formula, right.formula),
                    "or" => Formula::disjunction(left.formula, right.formula),
                    _ => Formula::biconditional(left.formula, right.formula),
                };
                Parsed {
                    formula,
                    nodes,
                    depth,
                }
            }
            _ => {
                self.token_offset = operator_offset;
                return Err(QuestionError::Invalid(
                    "question unknown formula or unapproved reference",
                ));
            }
        };
        self.bounded(parsed.nodes, source_depth - 1 + parsed.depth)?;
        self.trivia();
        if self.byte() == Some(b',') {
            self.offset += 1;
        }
        self.punctuation(b')')?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests;
