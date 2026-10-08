//! Bounded compilation of closed research obligations using Foundation notation.
//!
//! The source subset is `foundation = "naome:zfc"`, followed by `statement =`
//! and one formula. An optional `success = "resolve"` follows the formula.
//! Primitive and derived calls have exactly the authoring compiler's meaning.
//! The opt-in `nao 1` frontend also accepts bounded formula bindings and ordered
//! binder lists. Definitions, assumptions, and proof imports remain unavailable.
//! Compilation proves well-formedness, not truth.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use naome_checker::CheckedProof;
use naome_foundation::{FORMULA_MAX_DEPTH, FOUNDATION_ID, Formula, FreeVariable};
use sha2::{Digest, Sha256};

use crate::{
    CompileDiagnostic, DiagnosticCode, SourceSpan,
    syntax::{self, SourceSyntax},
};

/// Maximum UTF-8 bytes in one formal obligation.
pub const QUESTION_SOURCE_MAX_BYTES: usize = 16 * 1024;
/// Maximum primitive formula nodes in each expanded target.
pub const QUESTION_TARGET_MAX_NODES: usize = 1024;
/// Maximum nested primitive nodes in each expanded target, counting the root.
pub const QUESTION_TARGET_MAX_DEPTH: usize = 32;

/// A rejected formal question source or canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuestionError {
    Truncated,
    TrailingBytes,
    Limit(&'static str),
    Invalid(&'static str),
    Overflow,
    Mathematical(String),
}

impl fmt::Display for QuestionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated question value"),
            Self::TrailingBytes => f.write_str("trailing question bytes"),
            Self::Limit(name) => write!(f, "question limit exceeded: {name}"),
            Self::Invalid(reason) => write!(f, "invalid question: {reason}"),
            Self::Overflow => f.write_str("question arithmetic overflow"),
            Self::Mathematical(reason) => write!(f, "invalid question formula: {reason}"),
        }
    }
}

impl Error for QuestionError {}

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
    /// Recovers the compatibility error used by [`CompiledQuestion::compile`].
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
    formula: Formula,
    core: Formula,
    canonical_core: Vec<u8>,
    negative_target: Formula,
    negation_parity: bool,
    resolution_id: [u8; 32],
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
        let (syntax, offset) = SourceSyntax::header(source).map_err(|offset| {
            let error = QuestionError::Invalid("question unsupported syntax version");
            QuestionCompileError {
                diagnostic: CompileDiagnostic::token(
                    DiagnosticCode::UnsupportedSyntaxVersion,
                    "expected the supported syntax header `nao 1`".to_owned(),
                    source,
                    offset,
                ),
                error,
            }
        })?;
        let mut parser = Parser {
            source,
            offset,
            token_offset: offset,
            syntax,
            variables: BTreeMap::new(),
            bindings: BTreeMap::new(),
            binding_nodes: 0,
            next_variable: 0,
            maximum_nodes: parse_nodes,
        };
        let mut statement_span = SourceSpan::point(offset);
        let parsed = (|| -> Result<Parsed, QuestionError> {
            if syntax == SourceSyntax::Legacy {
                parser.word("foundation")?;
                parser.punctuation(b'=')?;
                parser.literal("\"naome:zfc\"")?;
            }
            if syntax == SourceSyntax::V1 && parser.peek_word("formulas") {
                parser.formula_bindings()?;
            }
            parser.word("statement")?;
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
        let encoded = parsed
            .formula
            .encode_canonical_with_node_limit(parse_nodes)
            .map_err(|error| failure(QuestionError::Mathematical(error.to_string())))?
            .0;
        // 0x02 is the existing Foundation canonical NOT tag. Removing only
        // leading NOT tags preserves all internal structure and De Bruijn binders.
        let leading = encoded.iter().take_while(|&&tag| tag == 0x02).count();
        let core_nodes = parsed.nodes - leading;
        let core_depth = parsed.depth - leading;
        if core_nodes + 1 > QUESTION_TARGET_MAX_NODES {
            return Err(failure(QuestionError::Limit("question target nodes")));
        }
        if core_depth + 1 > QUESTION_TARGET_MAX_DEPTH {
            return Err(failure(QuestionError::Limit("question target depth")));
        }
        let canonical_core = encoded[leading..].to_vec();
        let core =
            Formula::decode_canonical_with_node_limit(&canonical_core, QUESTION_TARGET_MAX_NODES)
                .map_err(|error| failure(QuestionError::Mathematical(error.to_string())))?
                .0;
        let resolution_id = hash(
            b"naome:state:resolution:v1\0",
            &[FOUNDATION_ID.as_bytes(), &canonical_core],
        );
        Ok(Self {
            source: source.to_owned(),
            source_hash: hash(b"naome:state:question-source:v1\0", &[source.as_bytes()]),
            formula: parsed.formula,
            negative_target: Formula::negate(core.clone()),
            core,
            canonical_core,
            negation_parity: leading % 2 != 0,
            resolution_id,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }
    pub const fn source_hash(&self) -> &[u8; 32] {
        &self.source_hash
    }
    pub const fn formula(&self) -> &Formula {
        &self.formula
    }
    pub const fn core(&self) -> &Formula {
        &self.core
    }
    pub fn canonical_core(&self) -> &[u8] {
        &self.canonical_core
    }
    pub const fn negation_parity(&self) -> bool {
        self.negation_parity
    }
    /// The exact R target, independently of its presentation as PROVED/REFUTED.
    pub const fn positive_target(&self) -> &Formula {
        &self.core
    }
    /// The exact not(R) target, independently of presentation.
    pub const fn negative_target(&self) -> &Formula {
        &self.negative_target
    }
    /// The target whose checked certificate establishes the question as PROVED.
    pub fn proved_target(&self) -> &Formula {
        if self.negation_parity {
            &self.negative_target
        } else {
            &self.core
        }
    }
    /// The opposite target, whose checked certificate establishes REFUTED.
    pub fn refuted_target(&self) -> &Formula {
        if self.negation_parity {
            &self.core
        } else {
            &self.negative_target
        }
    }
    pub const fn resolution_id(&self) -> &[u8; 32] {
        &self.resolution_id
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

// Preserve the original domain and u64-length framing of pure source/core
// identities. The historical namespace grants no state or opening authority.
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
    syntax: SourceSyntax,
    variables: BTreeMap<&'a str, FreeVariable>,
    bindings: BTreeMap<&'a str, Parsed>,
    binding_nodes: usize,
    next_variable: u32,
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
        if !self
            .byte()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        {
            return Err(QuestionError::Invalid("question expected name"));
        }
        self.offset += 1;
        while self
            .byte()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            self.offset += 1;
        }
        Ok(&self.source[start..self.offset])
    }
    fn word(&mut self, expected: &str) -> Result<(), QuestionError> {
        let name = self.name()?;
        if name != expected && name != self.syntax.keyword(expected) {
            return Err(QuestionError::Invalid("question unexpected field"));
        }
        Ok(())
    }
    fn literal(&mut self, expected: &str) -> Result<(), QuestionError> {
        self.trivia();
        self.token_offset = self.offset;
        if !self.source[self.offset..].starts_with(expected) {
            return Err(QuestionError::Invalid(
                "question unsupported Foundation or success policy",
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
        if let Some(variable) = self.variables.get(name) {
            return Ok(*variable);
        }
        let variable = FreeVariable::new(self.next_variable);
        self.next_variable = self
            .next_variable
            .checked_add(1)
            .ok_or(QuestionError::Overflow)?;
        self.variables.insert(name, variable);
        Ok(variable)
    }

    fn peek_word(&mut self, expected: &str) -> bool {
        self.trivia();
        syntax::word_at(self.source, self.offset, expected)
            || syntax::word_at(self.source, self.offset, self.syntax.keyword(expected))
    }

    fn formula_bindings(&mut self) -> Result<(), QuestionError> {
        self.word("formulas")?;
        self.punctuation(b':')?;
        loop {
            let name = self.name()?;
            if self.syntax.reserves(name)
                || syntax::is_formula_operator(name)
                || matches!(
                    name,
                    "foundation"
                        | "definitions"
                        | "definition"
                        | "relation"
                        | "function"
                        | "formulas"
                        | "statement"
                        | "proof"
                        | "return"
                        | "success"
                )
            {
                return Err(QuestionError::Invalid("question reserved formula binding"));
            }
            if self.bindings.contains_key(name) {
                return Err(QuestionError::Invalid("question duplicate formula binding"));
            }
            self.punctuation(b'=')?;
            let parse_allowance = self.maximum_nodes;
            self.maximum_nodes = QUESTION_TARGET_MAX_NODES - self.binding_nodes;
            let parsed = self.formula(1)?;
            self.binding_nodes += parsed.nodes;
            self.maximum_nodes = parse_allowance;
            self.bindings.insert(name, parsed);
            if self.peek_word("statement") {
                return Ok(());
            }
        }
    }

    fn quantified(
        &mut self,
        existential: bool,
        source_depth: usize,
    ) -> Result<Parsed, QuestionError> {
        self.trivia();
        let variables = if self.byte() == Some(b'[') {
            self.offset += 1;
            let mut variables = Vec::new();
            loop {
                if variables.len() == FORMULA_MAX_DEPTH as usize {
                    return Err(QuestionError::Limit("question expansion depth"));
                }
                variables.push(self.variable()?);
                self.trivia();
                if self.byte() == Some(b']') {
                    self.offset += 1;
                    break;
                }
                self.punctuation(b',')?;
                self.trivia();
                if self.byte() == Some(b']') {
                    self.offset += 1;
                    break;
                }
            }
            variables
        } else {
            vec![self.variable()?]
        };
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
        let name_end = self.offset;
        self.trivia();
        if self.syntax == SourceSyntax::V1 && self.byte() != Some(b'(') {
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
        let operator = self.syntax.formula(operator);
        self.punctuation(b'(')?;
        let parsed = match operator {
            "equal" | "member" | "not_equal" => {
                let left = self.variable()?;
                self.punctuation(b',')?;
                let right = self.variable()?;
                let formula = if operator == "member" {
                    Formula::member(left, right)
                } else {
                    Formula::equal(left, right)
                };
                if operator == "not_equal" {
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
            "forall" | "exists" if self.syntax == SourceSyntax::V1 => {
                self.quantified(operator == "exists", source_depth)?
            }
            "not_" | "forall" | "exists" => {
                let variable = if operator == "not_" {
                    None
                } else {
                    let variable = self.variable()?;
                    self.punctuation(b',')?;
                    Some(variable)
                };
                let body = self.formula(source_depth + 1)?;
                let extra = if operator == "exists" { 3 } else { 1 };
                let nodes = body.nodes + extra;
                let depth = body.depth + extra;
                self.bounded(nodes, source_depth - 1 + depth)?;
                let formula = match variable {
                    None => Formula::negate(body.formula),
                    Some(variable) if operator == "forall" => {
                        Formula::for_all(variable, body.formula)
                    }
                    Some(variable) => Formula::exists(variable, body.formula),
                };
                Parsed {
                    formula,
                    nodes,
                    depth,
                }
            }
            "implies" | "and_" | "or_" | "iff" => {
                let left = self.formula(source_depth + 1)?;
                self.punctuation(b',')?;
                let right = self.formula(source_depth + 1)?;
                let (nodes, depth) = match operator {
                    "implies" => (
                        1 + left.nodes + right.nodes,
                        1 + left.depth.max(right.depth),
                    ),
                    "and_" => (
                        3 + left.nodes + right.nodes,
                        (2 + left.depth).max(3 + right.depth),
                    ),
                    "or_" => (
                        2 + left.nodes + right.nodes,
                        (2 + left.depth).max(1 + right.depth),
                    ),
                    _ => (
                        5 + 2 * left.nodes + 2 * right.nodes,
                        4 + left.depth.max(right.depth),
                    ),
                };
                // Preflight expanded size BEFORE constructors such as iff clone
                // their children. Exponential source expansion stays bounded.
                self.bounded(nodes, source_depth - 1 + depth)?;
                let formula = match operator {
                    "implies" => Formula::implies(left.formula, right.formula),
                    "and_" => Formula::conjunction(left.formula, right.formula),
                    "or_" => Formula::disjunction(left.formula, right.formula),
                    _ => Formula::biconditional(left.formula, right.formula),
                };
                Parsed {
                    formula,
                    nodes,
                    depth,
                }
            }
            _ => {
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
