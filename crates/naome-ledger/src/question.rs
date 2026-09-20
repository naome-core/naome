//! Bounded compilation of closed research obligations using Foundation notation.
//!
//! The source subset is `foundation = "naome:zfc"`, followed by `statement =`
//! and one formula. An optional `success = "resolve"` follows the formula.
//! Primitive and derived calls have exactly the authoring compiler's meaning.
//! Definitions, assumptions, proof imports, and formula aliases are unavailable
//! in this initial profile. Compilation proves well-formedness, not truth.

use std::collections::BTreeMap;

use crate::profile::Profile;
use naome_foundation::{FORMULA_MAX_DEPTH, FOUNDATION_ID, Formula, FreeVariable};

use crate::codec::{Reader, Writer};
use crate::identity::hash;
use crate::{
    AccountId, GenesisId, LedgerError, ProfileId, QuestionId, RecordId, ResolutionId,
    SolutionRoundId,
};

/// Maximum UTF-8 bytes in one formal obligation.
pub const QUESTION_SOURCE_MAX_BYTES: usize = 16 * 1024;
/// Maximum primitive formula nodes in each expanded target.
pub const QUESTION_TARGET_MAX_NODES: usize = 1024;
/// Maximum nested primitive nodes in each expanded target, counting the root.
pub const QUESTION_TARGET_MAX_DEPTH: usize = 32;

/// Context fixed at actual question opening, not a claim of finalized opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuestionContext {
    pub genesis: GenesisId,
    pub profile: ProfileId,
    pub checker: [u8; 32],
    pub library_root: [u8; 32],
    pub author: AccountId,
}

/// A compiled closed question; fields cannot bypass source compilation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledQuestion {
    profile_id: ProfileId,
    source: String,
    source_hash: [u8; 32],
    formula: Formula,
    core: Formula,
    canonical_core: Vec<u8>,
    negative_target: Formula,
    negation_parity: bool,
    resolution_id: ResolutionId,
}

impl CompiledQuestion {
    /// Compiles a bounded obligation without accepting proof or definition input.
    pub fn compile(source: &str, profile: &Profile) -> Result<Self, LedgerError> {
        if source.len() > profile.limits().question_source_bytes as usize {
            return Err(LedgerError::Limit("question source bytes"));
        }
        // At most source.len() leading negations can later be removed.
        // Preflight every expansion against this finite aggregate allowance.
        let parse_nodes = profile.limits().target_nodes as usize + source.len();
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
            return Err(LedgerError::Invalid("question trailing source"));
        }
        if !parsed.formula.is_closed() {
            return Err(LedgerError::Invalid("question has free variables"));
        }
        let encoded = parsed
            .formula
            .encode_canonical_with_node_limit(parse_nodes)
            .map_err(|error| LedgerError::Mathematical(error.to_string()))?
            .0;
        // 0x02 is the existing Foundation canonical NOT tag. Removing only
        // leading NOT tags preserves all internal structure and De Bruijn binders.
        let leading = encoded.iter().take_while(|&&tag| tag == 0x02).count();
        let core_nodes = parsed.nodes - leading;
        let core_depth = parsed.depth - leading;
        if core_nodes + 1 > profile.limits().target_nodes as usize {
            return Err(LedgerError::Limit("question target nodes"));
        }
        if core_depth + 1 > profile.limits().target_depth as usize {
            return Err(LedgerError::Limit("question target depth"));
        }
        let canonical_core = encoded[leading..].to_vec();
        let core =
            Formula::decode_canonical_with_node_limit(&canonical_core, QUESTION_TARGET_MAX_NODES)
                .map_err(|error| LedgerError::Mathematical(error.to_string()))?
                .0;
        let resolution_id = ResolutionId::from_bytes(hash(
            b"naome:state:resolution:v1\0",
            &[FOUNDATION_ID.as_bytes(), &canonical_core],
        ));
        Ok(Self {
            profile_id: profile.id(),
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

    pub const fn profile_id(&self) -> ProfileId {
        self.profile_id
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
    pub const fn resolution_id(&self) -> ResolutionId {
        self.resolution_id
    }

    /// Binds source, purpose, author, targets and the immutable opening context.
    /// The profile identity binds all applicable limits and policy parameters.
    pub fn question_id(
        &self,
        context: QuestionContext,
        purpose: &str,
    ) -> Result<QuestionId, LedgerError> {
        if context.profile != self.profile_id {
            return Err(LedgerError::Invalid(
                "question compilation profile mismatch",
            ));
        }
        if purpose.is_empty() || purpose.len() > QUESTION_SOURCE_MAX_BYTES {
            return Err(LedgerError::Limit("question purpose bytes"));
        }
        let negative = self
            .negative_target
            .encode_canonical()
            .map_err(|error| LedgerError::Mathematical(error.to_string()))?;
        Ok(QuestionId::from_bytes(hash(
            b"naome:state:question:v1\0",
            &[
                context.genesis.as_bytes(),
                context.profile.as_bytes(),
                &context.checker,
                &context.library_root,
                context.author.as_bytes(),
                FOUNDATION_ID.as_bytes(),
                purpose.as_bytes(),
                self.source.as_bytes(),
                &self.source_hash,
                &self.canonical_core,
                &negative,
                &[u8::from(self.negation_parity)],
            ],
        )))
    }

    /// Encodes the source as the sole authority; derived fields are recomputed.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let mut writer = Writer::new();
        writer.u8(1);
        writer.string(&self.source)?;
        Ok(writer.finish())
    }

    /// Strictly decodes and recompiles; no supplied identifier is trusted.
    pub fn from_canonical_bytes(bytes: &[u8], profile: &Profile) -> Result<Self, LedgerError> {
        let mut reader = Reader::new(bytes, QUESTION_SOURCE_MAX_BYTES + 5)?;
        if reader.u8()? != 1 {
            return Err(LedgerError::Invalid("question codec version"));
        }
        let source = reader.string(QUESTION_SOURCE_MAX_BYTES)?;
        reader.finish()?;
        Self::compile(source, profile)
    }
}

/// Derives a checker namespace fingerprint for question context binding.
pub fn checker_profile_id(namespace: &str) -> [u8; 32] {
    hash(b"naome:state:checker-profile:v1\0", &[namespace.as_bytes()])
}

/// Derives the solution attempt at COMMIT start from an already finalized
/// approval record. It never asks that approval record to hash its own identity.
pub fn solution_round_id(
    genesis: GenesisId,
    question: QuestionId,
    attempt: u64,
    approval: RecordId,
) -> Result<SolutionRoundId, LedgerError> {
    if attempt == 0 {
        return Err(LedgerError::Invalid("zero question attempt"));
    }
    Ok(SolutionRoundId::from_bytes(hash(
        b"naome:state:solution-round:v1\0",
        &[
            genesis.as_bytes(),
            question.as_bytes(),
            &attempt.to_be_bytes(),
            approval.as_bytes(),
        ],
    )))
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
    fn bounded(&self, nodes: usize, depth: usize) -> Result<(), LedgerError> {
        if nodes > self.maximum_nodes {
            return Err(LedgerError::Limit("question expansion nodes"));
        }
        if depth > FORMULA_MAX_DEPTH as usize {
            return Err(LedgerError::Limit("question expansion depth"));
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
    fn name(&mut self) -> Result<&'a str, LedgerError> {
        self.trivia();
        let start = self.offset;
        if !self
            .byte()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        {
            return Err(LedgerError::Invalid("question expected name"));
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
    fn word(&mut self, expected: &str) -> Result<(), LedgerError> {
        if self.name()? != expected {
            return Err(LedgerError::Invalid("question unexpected field"));
        }
        Ok(())
    }
    fn literal(&mut self, expected: &str) -> Result<(), LedgerError> {
        self.trivia();
        if !self.source[self.offset..].starts_with(expected) {
            return Err(LedgerError::Invalid(
                "question unsupported Foundation or success policy",
            ));
        }
        self.offset += expected.len();
        Ok(())
    }
    fn punctuation(&mut self, expected: u8) -> Result<(), LedgerError> {
        self.trivia();
        if self.byte() != Some(expected) {
            return Err(LedgerError::Invalid("question punctuation"));
        }
        self.offset += 1;
        Ok(())
    }
    fn variable(&mut self) -> Result<FreeVariable, LedgerError> {
        let name = self.name()?;
        if let Some(variable) = self.variables.get(name) {
            return Ok(*variable);
        }
        let variable = FreeVariable::new(self.next_variable);
        self.next_variable = self
            .next_variable
            .checked_add(1)
            .ok_or(LedgerError::Overflow)?;
        self.variables.insert(name, variable);
        Ok(variable)
    }
    fn formula(&mut self, source_depth: usize) -> Result<Parsed, LedgerError> {
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
                return Err(LedgerError::Invalid(
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
