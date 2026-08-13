//! Prerelease `.nao` source lowering for one checked Foundation theorem.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use naome_checker::{CheckError, normalize_and_check};
use naome_foundation::{
    FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, FOUNDATION_ID, Formula, FormulaCodecError, FreeVariable,
    ZfcAxiom,
};
use naome_proof::{
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, CERTIFICATE_MAX_STEPS, DerivationId,
    ProofCertificate, ProofCertificateError, ProofId, ProofStep, StatementId,
};

/// Maximum UTF-8 bytes accepted in one `.nao` source value.
pub const AUTHORING_SOURCE_MAX_BYTES: usize = CERTIFICATE_MAX_BYTES;

/// Compiles one complete, self-contained `.nao` theorem.
pub fn compile(source: &str) -> Result<CompiledProof, CompileError> {
    if source.len() > AUTHORING_SOURCE_MAX_BYTES {
        return Err(CompileError::SourceTooLong {
            actual: source.len(),
            maximum: AUTHORING_SOURCE_MAX_BYTES,
        });
    }

    Parser::new(source).compile()
}

/// Canonical checked output of one successful source compilation.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CompiledProof {
    canonical_proof_bytes: Box<[u8]>,
    statement_id: StatementId,
    derivation_id: DerivationId,
    proof_id: ProofId,
}

impl CompiledProof {
    /// Returns the exact canonical proof normal-form bytes.
    pub fn canonical_proof_bytes(&self) -> &[u8] {
        &self.canonical_proof_bytes
    }

    /// Consumes this result and returns its exact canonical proof bytes.
    pub fn into_canonical_proof_bytes(self) -> Box<[u8]> {
        self.canonical_proof_bytes
    }

    /// Returns the checked conclusion identity.
    pub const fn statement_id(&self) -> StatementId {
        self.statement_id
    }

    /// Returns the checked reference-transparent derivation identity.
    pub const fn derivation_id(&self) -> DerivationId {
        self.derivation_id
    }

    /// Returns the checked concrete canonical proof identity.
    pub const fn proof_id(&self) -> ProofId {
        self.proof_id
    }
}

/// A deterministic `.nao` source compilation failure.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompileError {
    /// The complete source exceeds its byte budget.
    SourceTooLong { actual: usize, maximum: usize },
    /// A lexical or grammar boundary failed at this byte offset.
    Syntax {
        offset: usize,
        expected: &'static str,
    },
    /// The source names an unsupported Foundation identifier.
    FoundationMismatch { offset: usize },
    /// A presentation identifier was declared more than once.
    DuplicateStep { offset: usize, name: String },
    /// A proof step refers to a step that has not already been declared.
    UnknownStep { offset: usize, name: String },
    /// The result does not name the final declared proof step.
    ResultNotFinal { offset: usize },
    /// Formula parsing exceeded the executable Foundation depth limit.
    FormulaDepthLimitExceeded { offset: usize, maximum: u32 },
    /// The declared statement exceeds the canonical Foundation formula limits.
    Statement { source: FormulaCodecError },
    /// The lowered proof certificate is structurally invalid.
    Certificate { source: ProofCertificateError },
    /// The lowered certificate fails deterministic mathematical checking.
    Check { source: CheckError },
    /// The checked conclusion differs from the source statement.
    StatementMismatch,
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "source has {actual} bytes; the limit is {maximum}"
                )
            }
            Self::Syntax { offset, expected } => {
                write!(formatter, "expected {expected} at byte {offset}")
            }
            Self::FoundationMismatch { offset } => write!(
                formatter,
                "unsupported Foundation identifier at byte {offset}; expected {FOUNDATION_ID:?}"
            ),
            Self::DuplicateStep { offset, name } => {
                write!(formatter, "duplicate step {name:?} at byte {offset}")
            }
            Self::UnknownStep { offset, name } => {
                write!(
                    formatter,
                    "unknown or forward step {name:?} at byte {offset}"
                )
            }
            Self::ResultNotFinal { offset } => {
                write!(
                    formatter,
                    "result does not name the final step at byte {offset}"
                )
            }
            Self::FormulaDepthLimitExceeded { offset, maximum } => write!(
                formatter,
                "formula at byte {offset} exceeds the depth limit {maximum}"
            ),
            Self::Statement { source } => write!(formatter, "invalid statement: {source}"),
            Self::Certificate { source } => write!(formatter, "invalid proof structure: {source}"),
            Self::Check { source } => write!(formatter, "proof checking failed: {source}"),
            Self::StatementMismatch => {
                formatter.write_str("declared statement differs from the checked conclusion")
            }
        }
    }
}

impl Error for CompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Statement { source } => Some(source),
            Self::Certificate { source } => Some(source),
            Self::Check { source } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum FormulaContext {
    Statement,
    Certificate,
}

struct Parser<'source> {
    source: &'source str,
    offset: usize,
    variables: HashMap<&'source str, FreeVariable>,
    steps: HashMap<&'source str, u32>,
    statement_nodes: usize,
    certificate_formula_nodes: usize,
}

impl<'source> Parser<'source> {
    fn new(source: &'source str) -> Self {
        Self {
            source,
            offset: 0,
            variables: HashMap::new(),
            steps: HashMap::new(),
            statement_nodes: 0,
            certificate_formula_nodes: 0,
        }
    }

    fn compile(mut self) -> Result<CompiledProof, CompileError> {
        self.keyword("foundation")?;
        let foundation_offset = self.next_offset();
        let foundation = self.string()?;
        if foundation != FOUNDATION_ID {
            return Err(CompileError::FoundationMismatch {
                offset: foundation_offset,
            });
        }
        self.punctuation(';')?;
        self.keyword("theorem")?;
        self.name()?;
        self.punctuation('{')?;
        self.keyword("statement")?;
        let statement = self.formula(1, FormulaContext::Statement)?;
        self.punctuation(';')?;
        self.keyword("proof")?;
        self.punctuation('{')?;

        let mut proof_steps = Vec::new();
        let mut last_step_name = None;
        while self.peek_word("step") {
            if proof_steps.len() == CERTIFICATE_MAX_STEPS {
                return Err(CompileError::Certificate {
                    source: ProofCertificateError::TooManySteps {
                        actual: CERTIFICATE_MAX_STEPS + 1,
                        maximum: CERTIFICATE_MAX_STEPS,
                    },
                });
            }
            self.keyword("step")?;
            let name_offset = self.next_offset();
            let name = self.name()?;
            if self.steps.contains_key(name) {
                return Err(CompileError::DuplicateStep {
                    offset: name_offset,
                    name: name.to_owned(),
                });
            }
            self.punctuation('=')?;
            let step = self.proof_step()?;
            self.punctuation(';')?;
            let position = u32::try_from(proof_steps.len())
                .expect("the certificate step limit fits one local step index");
            self.steps.insert(name, position);
            proof_steps.push(step);
            last_step_name = Some(name);
        }
        self.keyword("result")?;
        let result_offset = self.next_offset();
        let result = self.name()?;
        self.punctuation(';')?;
        self.punctuation('}')?;
        self.punctuation('}')?;
        self.end()?;

        if last_step_name != Some(result) {
            return Err(CompileError::ResultNotFinal {
                offset: result_offset,
            });
        }

        let certificate = ProofCertificate::new(proof_steps)
            .map_err(|source| CompileError::Certificate { source })?;
        let checked =
            normalize_and_check(certificate).map_err(|source| CompileError::Check { source })?;
        if checked.conclusion() != &statement {
            return Err(CompileError::StatementMismatch);
        }
        let statement_id = checked.statement_id();
        let derivation_id = checked.derivation_id();
        let proof_id = checked.proof_id();
        let canonical_proof_bytes = checked.into_normal_form().into_canonical_bytes();
        Ok(CompiledProof {
            canonical_proof_bytes,
            statement_id,
            derivation_id,
            proof_id,
        })
    }

    fn proof_step(&mut self) -> Result<ProofStep, CompileError> {
        self.punctuation('(')?;
        let rule_offset = self.next_offset();
        let rule = self.name()?;
        let step = match rule {
            "simplification" => {
                let antecedent = self.formula(1, FormulaContext::Certificate)?;
                let consequent = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::Simplification {
                    antecedent,
                    consequent,
                }
            }
            "frege" => {
                let first = self.formula(1, FormulaContext::Certificate)?;
                let second = self.formula(1, FormulaContext::Certificate)?;
                let third = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::Frege {
                    first,
                    second,
                    third,
                }
            }
            "classical-contraposition" => {
                let antecedent = self.formula(1, FormulaContext::Certificate)?;
                let consequent = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::ClassicalContraposition {
                    antecedent,
                    consequent,
                }
            }
            "universal-distribution" => {
                let variable = self.variable()?;
                let antecedent = self.formula(1, FormulaContext::Certificate)?;
                let consequent = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::UniversalDistribution {
                    variable,
                    antecedent,
                    consequent,
                }
            }
            "vacuous-universal" => {
                let formula = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::VacuousUniversal { formula }
            }
            "universal-instantiation" => {
                let variable = self.variable()?;
                let replacement = self.variable()?;
                let body = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::UniversalInstantiation {
                    variable,
                    replacement,
                    body,
                }
            }
            "modus-ponens" => {
                let premise = self.earlier_step()?;
                let implication = self.earlier_step()?;
                ProofStep::ModusPonens {
                    premise,
                    implication,
                }
            }
            "equality-reflexivity" => {
                let variable = self.variable()?;
                ProofStep::EqualityReflexivity { variable }
            }
            "equality-substitution" => {
                let from = self.variable()?;
                let to = self.variable()?;
                let body = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::EqualitySubstitution { from, to, body }
            }
            "zfc-axiom" => ProofStep::ZfcAxiom(self.zfc_axiom()?),
            "generalization" => {
                let premise = self.earlier_step()?;
                let variable = self.variable()?;
                ProofStep::Generalization { premise, variable }
            }
            _ => {
                return Err(CompileError::Syntax {
                    offset: rule_offset,
                    expected: "a supported proof expression",
                });
            }
        };
        self.punctuation(')')?;
        Ok(step)
    }

    fn zfc_axiom(&mut self) -> Result<ZfcAxiom, CompileError> {
        let offset = self.next_offset();
        let name = self.name().map_err(|_| CompileError::Syntax {
            offset,
            expected: "a fixed ZFC axiom",
        })?;
        match name {
            "extensionality" => Ok(ZfcAxiom::Extensionality),
            "pairing" => Ok(ZfcAxiom::Pairing),
            "union" => Ok(ZfcAxiom::Union),
            "power-set" => Ok(ZfcAxiom::PowerSet),
            "infinity" => Ok(ZfcAxiom::Infinity),
            "foundation" => Ok(ZfcAxiom::Foundation),
            "choice" => Ok(ZfcAxiom::Choice),
            _ => Err(CompileError::Syntax {
                offset,
                expected: "a fixed ZFC axiom",
            }),
        }
    }

    fn earlier_step(&mut self) -> Result<u32, CompileError> {
        let offset = self.next_offset();
        let name = self.name()?;
        self.steps
            .get(name)
            .copied()
            .ok_or_else(|| CompileError::UnknownStep {
                offset,
                name: name.to_owned(),
            })
    }

    fn formula(&mut self, depth: u32, context: FormulaContext) -> Result<Formula, CompileError> {
        let formula_offset = self.next_offset();
        self.charge_formula_node(context)?;
        if depth > FORMULA_MAX_DEPTH {
            return Err(CompileError::FormulaDepthLimitExceeded {
                offset: formula_offset,
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        self.punctuation('(')?;
        let operator_offset = self.next_offset();
        let operator = self.name()?;
        let formula = match operator {
            "equal" => Formula::equal(self.variable()?, self.variable()?),
            "member" => Formula::member(self.variable()?, self.variable()?),
            "not" => Formula::negate(self.formula(depth + 1, context)?),
            "implies" => {
                let antecedent = self.formula(depth + 1, context)?;
                let consequent = self.formula(depth + 1, context)?;
                Formula::implies(antecedent, consequent)
            }
            "forall" => {
                let variable = self.variable()?;
                let body = self.formula(depth + 1, context)?;
                Formula::for_all(variable, body)
            }
            _ => {
                return Err(CompileError::Syntax {
                    offset: operator_offset,
                    expected: "a supported formula",
                });
            }
        };
        self.punctuation(')')?;
        Ok(formula)
    }

    fn charge_formula_node(&mut self, context: FormulaContext) -> Result<(), CompileError> {
        match context {
            FormulaContext::Statement => {
                if self.statement_nodes == FORMULA_MAX_NODES {
                    return Err(CompileError::Statement {
                        source: FormulaCodecError::NodeLimitExceeded {
                            maximum: FORMULA_MAX_NODES,
                        },
                    });
                }
                self.statement_nodes += 1;
            }
            FormulaContext::Certificate => {
                if self.certificate_formula_nodes == CERTIFICATE_MAX_FORMULA_NODES {
                    return Err(CompileError::Certificate {
                        source: ProofCertificateError::FormulaNodeLimitExceeded {
                            maximum: CERTIFICATE_MAX_FORMULA_NODES,
                        },
                    });
                }
                self.certificate_formula_nodes += 1;
            }
        }
        Ok(())
    }

    fn variable(&mut self) -> Result<FreeVariable, CompileError> {
        let name = self.name()?;
        if let Some(variable) = self.variables.get(name) {
            return Ok(*variable);
        }
        let identifier = u32::try_from(self.variables.len()).map_err(|_| CompileError::Syntax {
            offset: self.offset,
            expected: "a representable variable",
        })?;
        let variable = FreeVariable::new(identifier);
        self.variables.insert(name, variable);
        Ok(variable)
    }

    fn keyword(&mut self, expected: &'static str) -> Result<(), CompileError> {
        let offset = self.next_offset();
        let actual = self.name()?;
        if actual == expected {
            Ok(())
        } else {
            Err(CompileError::Syntax { offset, expected })
        }
    }

    fn name(&mut self) -> Result<&'source str, CompileError> {
        self.skip_trivia();
        let start = self.offset;
        let mut characters = self.source[start..].char_indices();
        let Some((_, first)) = characters.next() else {
            return Err(CompileError::Syntax {
                offset: start,
                expected: "a name",
            });
        };
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(CompileError::Syntax {
                offset: start,
                expected: "a name",
            });
        }
        let mut end = start + first.len_utf8();
        for (relative, character) in characters {
            if !character.is_ascii_alphanumeric() && character != '_' && character != '-' {
                break;
            }
            end = start + relative + character.len_utf8();
        }
        self.offset = end;
        Ok(&self.source[start..end])
    }

    fn string(&mut self) -> Result<&'source str, CompileError> {
        self.skip_trivia();
        let start = self.offset;
        if self.byte() != Some(b'"') {
            return Err(CompileError::Syntax {
                offset: start,
                expected: "a quoted Foundation identifier",
            });
        }
        self.offset += 1;
        let content_start = self.offset;
        let Some(relative_end) = self.source[content_start..].find('"') else {
            return Err(CompileError::Syntax {
                offset: start,
                expected: "a closing quote",
            });
        };
        let content_end = content_start + relative_end;
        self.offset = content_end + 1;
        Ok(&self.source[content_start..content_end])
    }

    fn punctuation(&mut self, expected: char) -> Result<(), CompileError> {
        self.skip_trivia();
        let offset = self.offset;
        if self.source[offset..].starts_with(expected) {
            self.offset += expected.len_utf8();
            Ok(())
        } else {
            Err(CompileError::Syntax {
                offset,
                expected: match expected {
                    ';' => "`;`",
                    '{' => "`{`",
                    '}' => "`}`",
                    '(' => "`(`",
                    ')' => "`)`",
                    '=' => "`=`",
                    _ => "punctuation",
                },
            })
        }
    }

    fn end(&mut self) -> Result<(), CompileError> {
        self.skip_trivia();
        if self.offset == self.source.len() {
            Ok(())
        } else {
            Err(CompileError::Syntax {
                offset: self.offset,
                expected: "end of source",
            })
        }
    }

    fn peek_word(&mut self, expected: &str) -> bool {
        self.skip_trivia();
        let remainder = &self.source[self.offset..];
        remainder.starts_with(expected)
            && remainder[expected.len()..]
                .chars()
                .next()
                .is_none_or(|character| {
                    !character.is_ascii_alphanumeric() && character != '_' && character != '-'
                })
    }

    fn next_offset(&mut self) -> usize {
        self.skip_trivia();
        self.offset
    }

    fn skip_trivia(&mut self) {
        loop {
            while matches!(self.byte(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                self.offset += 1;
            }
            if self.byte() != Some(b'#') {
                break;
            }
            self.offset += 1;
            while !matches!(self.byte(), None | Some(b'\n')) {
                self.offset += 1;
            }
        }
    }

    fn byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }
}

#[cfg(test)]
mod tests;
