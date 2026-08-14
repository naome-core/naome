//! Prerelease `.nao` source lowering for one checked Foundation theorem.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use naome_checker::{CheckError, ProofState, normalize_and_check_with_state};
use naome_foundation::{
    FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, FOUNDATION_ID, Formula, FormulaCodecError, FreeVariable,
    Replacement, Separation, ZfcAxiom,
};
use naome_proof::{
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, CERTIFICATE_MAX_STEPS, DerivationId,
    ProofCertificate, ProofCertificateError, ProofId, ProofStep, StatementId,
};
use naome_storage::{ProofChainJournal, ProofChainJournalError};

/// Maximum UTF-8 bytes accepted in one `.nao` source value.
pub const AUTHORING_SOURCE_MAX_BYTES: usize = CERTIFICATE_MAX_BYTES;

/// Compiles one complete, dependency-free `.nao` theorem.
///
/// Reachable proof references fail because this entry point uses an empty
/// checked-proof state. Use [`compile_against_selected_chain`] when references
/// to already selected proofs are expected.
pub fn compile(source: &str) -> Result<CompiledProof, CompileError> {
    compile_with_proof_state(source, &ProofState::new())
}

/// Compiles one `.nao` theorem against a selected proof-chain journal.
///
/// Journal health is checked before source compilation. Root-reachable
/// references resolve only from proofs strictly applied or replayed into
/// `selected`; block candidates, archived payloads, and arbitrary caller-built
/// proof states are not inputs. Compilation performs no journal I/O or mutation.
/// Its output is still an unselected authoring artifact, and later admission
/// fully rechecks it against the then-current target state. The selected journal
/// does not by itself establish network provenance, consensus, or finality.
pub fn compile_against_selected_chain(
    source: &str,
    selected: &ProofChainJournal,
) -> Result<CompiledProof, SelectedChainCompileError> {
    let proof_state =
        selected
            .proof_state()
            .map_err(|source| SelectedChainCompileError::SelectedState {
                source: Box::new(source),
            })?;
    compile_with_proof_state(source, proof_state)
        .map_err(|source| SelectedChainCompileError::Compilation { source })
}

fn compile_with_proof_state(
    source: &str,
    proof_state: &ProofState,
) -> Result<CompiledProof, CompileError> {
    if source.len() > AUTHORING_SOURCE_MAX_BYTES {
        return Err(CompileError::SourceTooLong {
            actual: source.len(),
            maximum: AUTHORING_SOURCE_MAX_BYTES,
        });
    }

    Parser::new(source).compile(proof_state)
}

/// Failure to obtain selected state or compile against it.
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectedChainCompileError {
    /// The selected journal cannot expose healthy applied-or-replayed state.
    SelectedState { source: Box<ProofChainJournalError> },
    /// Source parsing, proof checking, or exact reference resolution failed.
    Compilation { source: CompileError },
}

impl fmt::Display for SelectedChainCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectedState { source } => {
                write!(
                    formatter,
                    "selected proof-chain state is unavailable: {source}"
                )
            }
            Self::Compilation { source } => write!(formatter, "proof compilation failed: {source}"),
        }
    }
}

impl Error for SelectedChainCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::Compilation { source } => Some(source),
        }
    }
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

struct ParsedFormula {
    formula: Formula,
    expanded_nodes: usize,
    expanded_depth: u32,
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

    fn compile(mut self, proof_state: &ProofState) -> Result<CompiledProof, CompileError> {
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
        let checked = normalize_and_check_with_state(certificate, proof_state)
            .map_err(|source| CompileError::Check { source })?;
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
            "separation" => ProofStep::Separation(Separation {
                predicate: self.formula(1, FormulaContext::Certificate)?,
                element: self.variable()?,
                source: self.variable()?,
                result: self.variable()?,
                parameters: self.schema_parameters()?,
            }),
            "replacement" => ProofStep::Replacement(Replacement {
                predicate: self.formula(1, FormulaContext::Certificate)?,
                input: self.variable()?,
                output: self.variable()?,
                uniqueness_witness: self.variable()?,
                source: self.variable()?,
                result: self.variable()?,
                parameters: self.schema_parameters()?,
            }),
            "proof-reference" => ProofStep::ProofReference {
                proof_id: self.proof_id()?,
            },
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

    fn schema_parameters(&mut self) -> Result<Vec<FreeVariable>, CompileError> {
        self.punctuation('(')?;
        self.keyword("parameters")?;
        let mut parameters = Vec::new();
        loop {
            self.skip_trivia();
            if self.byte() == Some(b')') {
                self.offset += 1;
                return Ok(parameters);
            }
            parameters.push(self.variable()?);
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

    fn proof_id(&mut self) -> Result<ProofId, CompileError> {
        const HEX_LENGTH: usize = ProofId::BYTE_LENGTH * 2;
        const EXPECTED: &str = "a 64-digit lowercase hexadecimal ProofId";

        self.skip_trivia();
        let offset = self.offset;
        let Some(encoded) = self.source.as_bytes().get(offset..offset + HEX_LENGTH) else {
            return Err(CompileError::Syntax {
                offset,
                expected: EXPECTED,
            });
        };
        let mut bytes = [0_u8; ProofId::BYTE_LENGTH];
        for (index, (pair, byte)) in encoded.chunks_exact(2).zip(bytes.iter_mut()).enumerate() {
            let high_offset = offset + index * 2;
            let high_byte = pair[0];
            let Some(high) = lowercase_hex_nibble(high_byte) else {
                return Err(CompileError::Syntax {
                    offset: proof_id_error_offset(offset, high_offset, high_byte),
                    expected: EXPECTED,
                });
            };
            let low_offset = high_offset + 1;
            let low_byte = pair[1];
            let Some(low) = lowercase_hex_nibble(low_byte) else {
                return Err(CompileError::Syntax {
                    offset: proof_id_error_offset(offset, low_offset, low_byte),
                    expected: EXPECTED,
                });
            };
            *byte = (high << 4) | low;
        }
        self.offset += HEX_LENGTH;
        Ok(ProofId::from_bytes(bytes))
    }

    fn formula(&mut self, depth: u32, context: FormulaContext) -> Result<Formula, CompileError> {
        self.parsed_formula(depth, context)
            .map(|parsed| parsed.formula)
    }

    fn parsed_formula(
        &mut self,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let formula_offset = self.next_offset();
        self.charge_formula_nodes(context, 1)?;
        if depth > FORMULA_MAX_DEPTH {
            return Err(CompileError::FormulaDepthLimitExceeded {
                offset: formula_offset,
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        self.punctuation('(')?;
        let operator_offset = self.next_offset();
        let operator = self.name()?;
        let parsed = match operator {
            "equal" => {
                let left = self.variable()?;
                let right = self.variable()?;
                ParsedFormula {
                    formula: Formula::equal(left, right),
                    expanded_nodes: 1,
                    expanded_depth: 1,
                }
            }
            "member" => {
                let element = self.variable()?;
                let set = self.variable()?;
                ParsedFormula {
                    formula: Formula::member(element, set),
                    expanded_nodes: 1,
                    expanded_depth: 1,
                }
            }
            "not-equal" => {
                let left = self.variable()?;
                let right = self.variable()?;
                self.check_derived_expansion(operator_offset, depth, context, 2, 1)?;
                ParsedFormula {
                    formula: Formula::negate(Formula::equal(left, right)),
                    expanded_nodes: 2,
                    expanded_depth: 2,
                }
            }
            "not" => self.parse_not(operator_offset, depth, context)?,
            "implies" => self.parse_implies(operator_offset, depth, context)?,
            "forall" => self.parse_for_all(operator_offset, depth, context)?,
            "and" => self.parse_conjunction(operator_offset, depth, context)?,
            "or" => self.parse_disjunction(operator_offset, depth, context)?,
            "iff" => self.parse_biconditional(operator_offset, depth, context)?,
            "exists" => self.parse_exists(operator_offset, depth, context)?,
            _ => {
                return Err(CompileError::Syntax {
                    offset: operator_offset,
                    expected: "a supported formula",
                });
            }
        };
        self.punctuation(')')?;
        Ok(parsed)
    }

    fn parse_not(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[1, body.expanded_nodes])?;
        let expanded_depth = self.checked_depth_add(offset, body.expanded_depth, 1)?;
        self.check_expanded_depth(offset, depth, expanded_depth)?;
        Ok(ParsedFormula {
            formula: Formula::negate(body.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_implies(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let antecedent = self.parsed_formula(depth + 1, context)?;
        let consequent = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[1, antecedent.expanded_nodes, consequent.expanded_nodes],
        )?;
        let expanded_depth = self.checked_depth_add(
            offset,
            antecedent.expanded_depth.max(consequent.expanded_depth),
            1,
        )?;
        self.check_expanded_depth(offset, depth, expanded_depth)?;
        Ok(ParsedFormula {
            formula: Formula::implies(antecedent.formula, consequent.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_for_all(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let variable = self.variable()?;
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[1, body.expanded_nodes])?;
        let expanded_depth = self.checked_depth_add(offset, body.expanded_depth, 1)?;
        self.check_expanded_depth(offset, depth, expanded_depth)?;
        Ok(ParsedFormula {
            formula: Formula::for_all(variable, body.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_conjunction(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let left = self.parsed_formula(depth + 1, context)?;
        let right = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes =
            self.checked_node_sum(context, &[3, left.expanded_nodes, right.expanded_nodes])?;
        let left_depth = self.checked_depth_add(offset, left.expanded_depth, 2)?;
        let right_depth = self.checked_depth_add(offset, right.expanded_depth, 3)?;
        let expanded_depth = left_depth.max(right_depth);
        self.check_derived_expansion(offset, depth, context, expanded_depth, 2)?;
        Ok(ParsedFormula {
            formula: Formula::conjunction(left.formula, right.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_disjunction(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let left = self.parsed_formula(depth + 1, context)?;
        let right = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes =
            self.checked_node_sum(context, &[2, left.expanded_nodes, right.expanded_nodes])?;
        let left_depth = self.checked_depth_add(offset, left.expanded_depth, 2)?;
        let right_depth = self.checked_depth_add(offset, right.expanded_depth, 1)?;
        let expanded_depth = left_depth.max(right_depth);
        self.check_derived_expansion(offset, depth, context, expanded_depth, 1)?;
        Ok(ParsedFormula {
            formula: Formula::disjunction(left.formula, right.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_biconditional(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let left = self.parsed_formula(depth + 1, context)?;
        let right = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[
                5,
                left.expanded_nodes,
                left.expanded_nodes,
                right.expanded_nodes,
                right.expanded_nodes,
            ],
        )?;
        let additional_nodes =
            self.checked_node_sum(context, &[4, left.expanded_nodes, right.expanded_nodes])?;
        let expanded_depth =
            self.checked_depth_add(offset, left.expanded_depth.max(right.expanded_depth), 4)?;
        self.check_derived_expansion(offset, depth, context, expanded_depth, additional_nodes)?;
        Ok(ParsedFormula {
            formula: Formula::biconditional(left.formula, right.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn parse_exists(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let variable = self.variable()?;
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[3, body.expanded_nodes])?;
        let expanded_depth = self.checked_depth_add(offset, body.expanded_depth, 3)?;
        self.check_derived_expansion(offset, depth, context, expanded_depth, 2)?;
        Ok(ParsedFormula {
            formula: Formula::exists(variable, body.formula),
            expanded_nodes,
            expanded_depth,
        })
    }

    fn check_derived_expansion(
        &mut self,
        operator_offset: usize,
        source_depth: u32,
        context: FormulaContext,
        expanded_depth: u32,
        additional_nodes: usize,
    ) -> Result<(), CompileError> {
        self.charge_formula_nodes(context, additional_nodes)?;
        self.check_expanded_depth(operator_offset, source_depth, expanded_depth)
    }

    fn check_expanded_depth(
        &self,
        operator_offset: usize,
        source_depth: u32,
        expanded_depth: u32,
    ) -> Result<(), CompileError> {
        let absolute_depth = source_depth
            .checked_sub(1)
            .and_then(|prefix| prefix.checked_add(expanded_depth));
        if absolute_depth.is_none_or(|depth| depth > FORMULA_MAX_DEPTH) {
            return Err(CompileError::FormulaDepthLimitExceeded {
                offset: operator_offset,
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        Ok(())
    }

    fn checked_node_sum(
        &self,
        context: FormulaContext,
        terms: &[usize],
    ) -> Result<usize, CompileError> {
        terms
            .iter()
            .try_fold(0_usize, |sum, term| sum.checked_add(*term))
            .ok_or_else(|| Self::formula_node_limit(context))
    }

    fn checked_depth_add(
        &self,
        offset: usize,
        depth: u32,
        additional: u32,
    ) -> Result<u32, CompileError> {
        depth
            .checked_add(additional)
            .ok_or(CompileError::FormulaDepthLimitExceeded {
                offset,
                maximum: FORMULA_MAX_DEPTH,
            })
    }

    fn charge_formula_nodes(
        &mut self,
        context: FormulaContext,
        additional: usize,
    ) -> Result<(), CompileError> {
        let (used, maximum) = match context {
            FormulaContext::Statement => (&mut self.statement_nodes, FORMULA_MAX_NODES),
            FormulaContext::Certificate => (
                &mut self.certificate_formula_nodes,
                CERTIFICATE_MAX_FORMULA_NODES,
            ),
        };
        let Some(total) = used.checked_add(additional) else {
            return Err(Self::formula_node_limit(context));
        };
        if total > maximum {
            return Err(Self::formula_node_limit(context));
        }
        *used = total;
        Ok(())
    }

    fn formula_node_limit(context: FormulaContext) -> CompileError {
        match context {
            FormulaContext::Statement => CompileError::Statement {
                source: FormulaCodecError::NodeLimitExceeded {
                    maximum: FORMULA_MAX_NODES,
                },
            },
            FormulaContext::Certificate => CompileError::Certificate {
                source: ProofCertificateError::FormulaNodeLimitExceeded {
                    maximum: CERTIFICATE_MAX_FORMULA_NODES,
                },
            },
        }
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

const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

const fn proof_id_error_offset(start: usize, offset: usize, byte: u8) -> usize {
    if matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'#' | b')') {
        start
    } else {
        offset
    }
}

#[cfg(test)]
mod tests;
