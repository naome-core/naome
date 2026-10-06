//! Bounded compilation of closed research obligations using Foundation notation.
//!
//! The source subset is `foundation = "naome:zfc"`, followed by `statement =`
//! and one formula. An optional `success = "resolve"` follows the formula.
//! Primitive and derived calls have exactly the authoring compiler's meaning.
//! Definitions, assumptions, proof imports, and formula aliases are unavailable
//! in this bounded subset. Compilation proves well-formedness, not truth.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use naome_checker::CheckedProof;
use naome_foundation::{FORMULA_MAX_DEPTH, FOUNDATION_ID, Formula, FreeVariable};
use sha2::{Digest, Sha256};

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
        if source.len() > QUESTION_SOURCE_MAX_BYTES {
            return Err(QuestionError::Limit("question source bytes"));
        }
        // At most source.len() leading negations can later be removed.
        // Preflight every expansion against this finite aggregate allowance.
        let parse_nodes = QUESTION_TARGET_MAX_NODES + source.len();
        let mut parser = Parser {
            source,
            offset: 0,
            variables: BTreeMap::new(),
            next_variable: 0,
            maximum_nodes: parse_nodes,
        };
        parser.word("foundation")?;
        parser.punctuation(b'=')?;
        parser.literal("\"naome:zfc\"")?;
        parser.word("statement")?;
        parser.punctuation(b'=')?;
        let parsed = parser.formula(1)?;
        parser.trivia();
        if parser.offset < source.len() {
            parser.word("success")?;
            parser.punctuation(b'=')?;
            parser.literal("\"resolve\"")?;
        }
        parser.trivia();
        if parser.offset != source.len() {
            return Err(QuestionError::Invalid("question trailing source"));
        }
        if !parsed.formula.is_closed() {
            return Err(QuestionError::Invalid("question has free variables"));
        }
        let encoded = parsed
            .formula
            .encode_canonical_with_node_limit(parse_nodes)
            .map_err(|error| QuestionError::Mathematical(error.to_string()))?
            .0;
        // 0x02 is the existing Foundation canonical NOT tag. Removing only
        // leading NOT tags preserves all internal structure and De Bruijn binders.
        let leading = encoded.iter().take_while(|&&tag| tag == 0x02).count();
        let core_nodes = parsed.nodes - leading;
        let core_depth = parsed.depth - leading;
        if core_nodes + 1 > QUESTION_TARGET_MAX_NODES {
            return Err(QuestionError::Limit("question target nodes"));
        }
        if core_depth + 1 > QUESTION_TARGET_MAX_DEPTH {
            return Err(QuestionError::Limit("question target depth"));
        }
        let canonical_core = encoded[leading..].to_vec();
        let core =
            Formula::decode_canonical_with_node_limit(&canonical_core, QUESTION_TARGET_MAX_NODES)
                .map_err(|error| QuestionError::Mathematical(error.to_string()))?
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
    variables: BTreeMap<&'a str, FreeVariable>,
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
        loop {
            while matches!(self.byte(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                self.offset += 1;
            }
            if self.byte() != Some(b'#') {
                break;
            }
            while !matches!(self.byte(), None | Some(b'\n')) {
                self.offset += 1;
            }
        }
    }
    fn byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }
    fn name(&mut self) -> Result<&'a str, QuestionError> {
        self.trivia();
        let start = self.offset;
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
        if self.name()? != expected {
            return Err(QuestionError::Invalid("question unexpected field"));
        }
        Ok(())
    }
    fn literal(&mut self, expected: &str) -> Result<(), QuestionError> {
        self.trivia();
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
    fn formula(&mut self, source_depth: usize) -> Result<Parsed, QuestionError> {
        self.bounded(0, source_depth)?;
        let operator = self.name()?;
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
