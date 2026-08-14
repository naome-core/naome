//! Prerelease `.nao` proof-source lowering for one checked Foundation proof.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Write as _};

use naome_checker::{CheckError, ProofState, check_normal_form_with_state};
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

const DIAGNOSTIC_NAME_MAX_SCALARS: usize = 64;

/// Compiles one complete, dependency-free `.nao` proof source.
///
/// Reachable proof references fail because this entry point uses an empty
/// checked-proof state. Use [`compile_against_selected_chain`] when references
/// to already selected proofs are expected.
pub fn compile(source: &str) -> Result<CompiledProof, CompileError> {
    compile_with_proof_state(source, &ProofState::new())
}

/// Compiles one `.nao` proof source against a selected proof-chain journal.
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

/// A stable machine-readable class for one source compilation diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiagnosticCode {
    SourceTooLong,
    Syntax,
    FoundationMismatch,
    DuplicateStep,
    UnknownStep,
    ReturnNotFinal,
    FormulaDepthLimitExceeded,
    Statement,
    Certificate,
    Check,
    StatementMismatch,
}

impl DiagnosticCode {
    /// Returns the stable printable diagnostic code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceTooLong => "NAO0001",
            Self::Syntax => "NAO0002",
            Self::FoundationMismatch => "NAO0003",
            Self::DuplicateStep => "NAO0004",
            Self::UnknownStep => "NAO0005",
            Self::ReturnNotFinal => "NAO0006",
            Self::FormulaDepthLimitExceeded => "NAO0007",
            Self::Statement => "NAO0008",
            Self::Certificate => "NAO0009",
            Self::Check => "NAO0010",
            Self::StatementMismatch => "NAO0011",
        }
    }
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A half-open UTF-8 byte range in one complete `.nao` source value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSpan {
    start: u32,
    end: u32,
}

impl SourceSpan {
    fn new(start: usize, end: usize) -> Self {
        Self::try_new(start, end).expect("accepted source offsets fit in u32")
    }

    fn try_new(start: usize, end: usize) -> Option<Self> {
        Some(Self {
            start: u32::try_from(start).ok()?,
            end: u32::try_from(end).ok()?,
        })
    }

    fn point(offset: usize) -> Self {
        Self::new(offset, offset)
    }

    /// Returns the inclusive start byte offset.
    pub const fn start(self) -> usize {
        self.start as usize
    }

    /// Returns the exclusive end byte offset.
    pub const fn end(self) -> usize {
        self.end as usize
    }

    /// Returns whether the span contains no source bytes.
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// A one-based source position derived from a UTF-8 byte offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourcePosition {
    line: u32,
    column: u32,
}

impl SourcePosition {
    /// Returns the one-based source line.
    pub const fn line(self) -> usize {
        self.line as usize
    }

    /// Returns the one-based Unicode-scalar column.
    pub const fn column(self) -> usize {
        self.column as usize
    }
}

/// Structured, deterministic source information derived from one compile error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct CompileDiagnostic {
    code: DiagnosticCode,
    message: Box<str>,
    primary_span: Option<SourceSpan>,
    primary_position: Option<SourcePosition>,
}

impl CompileDiagnostic {
    /// Returns the stable error-class code.
    pub const fn code(&self) -> DiagnosticCode {
        self.code
    }

    /// Returns the source-oriented diagnostic message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the primary UTF-8 byte span, when the error is source-local.
    pub const fn primary_span(&self) -> Option<SourceSpan> {
        self.primary_span
    }

    /// Returns the one-based start position of the primary span.
    pub const fn primary_position(&self) -> Option<SourcePosition> {
        self.primary_position
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
    /// The return does not name the final declared proof step.
    ReturnNotFinal { offset: usize },
    /// Formula parsing exceeded the executable Foundation depth limit.
    FormulaDepthLimitExceeded { offset: usize, maximum: u32 },
    /// The declared statement exceeds the canonical Foundation formula limits.
    Statement {
        offset: usize,
        source: FormulaCodecError,
    },
    /// The lowered proof certificate is structurally invalid.
    Certificate {
        offset: usize,
        source: ProofCertificateError,
    },
    /// The lowered certificate fails deterministic mathematical checking.
    Check {
        span: SourceSpan,
        source: Box<CheckError>,
    },
    /// The checked conclusion differs from the source statement.
    StatementMismatch { span: SourceSpan },
}

impl CompileError {
    /// Returns the stable diagnostic class for this failure.
    pub const fn diagnostic_code(&self) -> DiagnosticCode {
        match self {
            Self::SourceTooLong { .. } => DiagnosticCode::SourceTooLong,
            Self::Syntax { .. } => DiagnosticCode::Syntax,
            Self::FoundationMismatch { .. } => DiagnosticCode::FoundationMismatch,
            Self::DuplicateStep { .. } => DiagnosticCode::DuplicateStep,
            Self::UnknownStep { .. } => DiagnosticCode::UnknownStep,
            Self::ReturnNotFinal { .. } => DiagnosticCode::ReturnNotFinal,
            Self::FormulaDepthLimitExceeded { .. } => DiagnosticCode::FormulaDepthLimitExceeded,
            Self::Statement { .. } => DiagnosticCode::Statement,
            Self::Certificate { .. } => DiagnosticCode::Certificate,
            Self::Check { .. } => DiagnosticCode::Check,
            Self::StatementMismatch { .. } => DiagnosticCode::StatementMismatch,
        }
    }

    /// Returns the zero-based UTF-8 byte offset of a source-local failure.
    pub const fn source_offset(&self) -> Option<usize> {
        match self {
            Self::SourceTooLong { .. } => None,
            Self::Syntax { offset, .. }
            | Self::FoundationMismatch { offset }
            | Self::DuplicateStep { offset, .. }
            | Self::UnknownStep { offset, .. }
            | Self::ReturnNotFinal { offset }
            | Self::FormulaDepthLimitExceeded { offset, .. }
            | Self::Statement { offset, .. }
            | Self::Certificate { offset, .. } => Some(*offset),
            Self::Check { span, .. } | Self::StatementMismatch { span } => Some(span.start()),
        }
    }

    /// Derives one structured diagnostic against the exact source that failed.
    ///
    /// Positions are one-based. Columns count Unicode scalar values; LF, CRLF,
    /// and bare CR each form one line boundary. The original byte span remains
    /// available for deterministic machine repair.
    pub fn diagnostic(&self, source: &str) -> CompileDiagnostic {
        let primary_span = self.primary_span(source);
        let primary_position = primary_span.and_then(|span| source_position(source, span.start()));
        CompileDiagnostic {
            code: self.diagnostic_code(),
            message: self.diagnostic_message(source).into_boxed_str(),
            primary_span,
            primary_position,
        }
    }

    fn primary_span(&self, source: &str) -> Option<SourceSpan> {
        let span = match self {
            Self::SourceTooLong { .. } => return None,
            Self::Syntax { offset, .. }
            | Self::FoundationMismatch { offset }
            | Self::DuplicateStep { offset, .. }
            | Self::UnknownStep { offset, .. }
            | Self::ReturnNotFinal { offset }
            | Self::FormulaDepthLimitExceeded { offset, .. }
            | Self::Statement { offset, .. }
            | Self::Certificate { offset, .. } => source_token_span(source, *offset)?,
            Self::Check { span, .. } | Self::StatementMismatch { span } => *span,
        };
        valid_source_span(source, span).then_some(span)
    }

    fn diagnostic_message(&self, source_text: &str) -> String {
        match self {
            Self::SourceTooLong { actual, maximum } => {
                format!("source has {actual} bytes; the limit is {maximum}")
            }
            Self::Syntax { expected, .. } => format!("expected {expected}"),
            Self::FoundationMismatch { .. } => {
                format!("unsupported Foundation identifier; expected {FOUNDATION_ID:?}")
            }
            Self::DuplicateStep { name, .. } => {
                format!("duplicate step {}", diagnostic_name(name))
            }
            Self::UnknownStep { name, .. } => {
                format!("unknown or forward step {}", diagnostic_name(name))
            }
            Self::ReturnNotFinal { .. } => "return does not name the final step".to_owned(),
            Self::FormulaDepthLimitExceeded { maximum, .. } => {
                format!("formula exceeds the depth limit {maximum}")
            }
            Self::Statement { source, .. } => format!("invalid statement: {source}"),
            Self::Certificate { source, .. } => format!("invalid proof structure: {source}"),
            Self::Check { span, source } => {
                let step_name = source_token_span(source_text, span.start())
                    .and_then(|name_span| source_text.get(name_span.start()..name_span.end()))
                    .unwrap_or("<proof>");
                check_diagnostic_message(step_name, source)
            }
            Self::StatementMismatch { .. } => {
                "declared statement differs from the checked conclusion".to_owned()
            }
        }
    }
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
            Self::ReturnNotFinal { offset } => {
                write!(
                    formatter,
                    "return does not name the final step at byte {offset}"
                )
            }
            Self::FormulaDepthLimitExceeded { offset, maximum } => write!(
                formatter,
                "formula at byte {offset} exceeds the depth limit {maximum}"
            ),
            Self::Statement { source, .. } => write!(formatter, "invalid statement: {source}"),
            Self::Certificate { source, .. } => {
                write!(formatter, "invalid proof structure: {source}")
            }
            Self::Check { source, .. } => write!(formatter, "proof checking failed: {source}"),
            Self::StatementMismatch { .. } => {
                formatter.write_str("declared statement differs from the checked conclusion")
            }
        }
    }
}

impl Error for CompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Statement { source, .. } => Some(source),
            Self::Certificate { source, .. } => Some(source),
            Self::Check { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

fn check_diagnostic_message(step_name: &str, error: &CheckError) -> String {
    let step_name = diagnostic_name(step_name);
    match error {
        CheckError::UnknownProofReference { .. } => {
            format!("step {step_name} references an unknown proof")
        }
        CheckError::Logic { source, .. } => {
            format!("step {step_name} violates Foundation logic: {source}")
        }
        CheckError::Schema { source, .. } => {
            format!("step {step_name} violates a ZFC schema: {source}")
        }
        CheckError::DerivedFormula { source, .. } => {
            format!("step {step_name} derives a formula outside Formula limits: {source}")
        }
        CheckError::FormulaWorkLimitExceeded {
            actual, maximum, ..
        } => format!(
            "step {step_name} raises formula work to {actual} bytes; the Checker limit is {maximum}"
        ),
        CheckError::OpenConclusion { .. } => {
            format!("proof conclusion at step {step_name} is not closed")
        }
        _ => format!("step {step_name} failed proof checking: {error}"),
    }
}

fn diagnostic_name(name: &str) -> DiagnosticName<'_> {
    DiagnosticName(name)
}

struct DiagnosticName<'name>(&'name str);

impl fmt::Display for DiagnosticName<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_char('"')?;
        let mut characters = self.0.chars();
        for character in characters.by_ref().take(DIAGNOSTIC_NAME_MAX_SCALARS) {
            for escaped in character.escape_debug() {
                formatter.write_char(escaped)?;
            }
        }
        if characters.next().is_some() {
            formatter.write_str("...")?;
        }
        formatter.write_char('"')
    }
}

fn source_token_span(source: &str, offset: usize) -> Option<SourceSpan> {
    if offset > source.len() || !source.is_char_boundary(offset) {
        return None;
    }
    if offset == source.len() {
        return SourceSpan::try_new(offset, offset);
    }

    let remainder = &source[offset..];
    let first = remainder.chars().next()?;
    if first == '"' {
        let end = remainder[1..]
            .find('"')
            .map_or(source.len(), |relative| offset + relative + 2);
        return SourceSpan::try_new(offset, end);
    }
    if first.is_ascii_alphabetic() || first == '_' {
        let end = remainder
            .char_indices()
            .take_while(|(_, character)| character.is_ascii_alphanumeric() || *character == '_')
            .last()
            .map_or(offset, |(relative, character)| {
                offset + relative + character.len_utf8()
            });
        return SourceSpan::try_new(offset, end);
    }
    SourceSpan::try_new(offset, offset + first.len_utf8())
}

fn valid_source_span(source: &str, span: SourceSpan) -> bool {
    span.start() <= span.end()
        && span.end() <= source.len()
        && source.is_char_boundary(span.start())
        && source.is_char_boundary(span.end())
}

fn source_position(source: &str, offset: usize) -> Option<SourcePosition> {
    if offset > source.len() || !source.is_char_boundary(offset) {
        return None;
    }

    let bytes = source.as_bytes();
    let mut cursor = 0;
    let mut line = 1_u32;
    let mut column = 1_u32;
    while cursor < offset {
        match bytes[cursor] {
            b'\r' => {
                cursor += 1;
                if cursor < offset && bytes.get(cursor) == Some(&b'\n') {
                    cursor += 1;
                }
                line = line.checked_add(1)?;
                column = 1;
            }
            b'\n' => {
                cursor += 1;
                line = line.checked_add(1)?;
                column = 1;
            }
            _ => {
                let character = source[cursor..]
                    .chars()
                    .next()
                    .expect("a UTF-8 boundary before source end contains a character");
                cursor += character.len_utf8();
                column = column.checked_add(1)?;
            }
        }
    }
    Some(SourcePosition { line, column })
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

#[derive(Clone, Copy)]
struct StepBinding {
    position: u32,
    span: SourceSpan,
}

struct Parser<'source> {
    source: &'source str,
    offset: usize,
    variables: HashMap<&'source str, FreeVariable>,
    steps: HashMap<&'source str, StepBinding>,
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
        self.punctuation('=')?;
        let foundation_offset = self.next_offset();
        let foundation = self.string("a quoted Foundation identifier")?;
        if foundation != FOUNDATION_ID {
            return Err(CompileError::FoundationMismatch {
                offset: foundation_offset,
            });
        }
        self.keyword("statement")?;
        self.punctuation('=')?;
        let statement_offset = self.next_offset();
        let statement = self.formula(1, FormulaContext::Statement)?;
        let statement_span = SourceSpan::new(statement_offset, self.offset);
        let proof_offset = self.next_offset();
        self.keyword("proof")?;
        self.punctuation(':')?;

        let mut proof_steps = Vec::new();
        let mut last_step_name = None;
        while !self.peek_word("return") {
            if proof_steps.len() == CERTIFICATE_MAX_STEPS {
                let offset = self.next_offset();
                return Err(CompileError::Certificate {
                    offset,
                    source: ProofCertificateError::TooManySteps {
                        actual: CERTIFICATE_MAX_STEPS + 1,
                        maximum: CERTIFICATE_MAX_STEPS,
                    },
                });
            }
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
            let position = u32::try_from(proof_steps.len())
                .expect("the certificate step limit fits one local step index");
            self.steps.insert(
                name,
                StepBinding {
                    position,
                    span: SourceSpan::new(name_offset, self.offset),
                },
            );
            proof_steps.push(step);
            last_step_name = Some(name);
        }
        self.keyword("return")?;
        let result_offset = self.next_offset();
        let result = self.name()?;
        self.end()?;

        if last_step_name != Some(result) {
            return Err(CompileError::ReturnNotFinal {
                offset: result_offset,
            });
        }

        let certificate =
            ProofCertificate::new(proof_steps).map_err(|source| CompileError::Certificate {
                offset: proof_offset,
                source,
            })?;
        let (normal_form, step_origins) =
            certificate.into_unchecked_normal_form_with_step_origins();
        let checked = check_normal_form_with_state(normal_form, proof_state).map_err(|source| {
            let source_step = step_origins.source_step(source.step());
            let origin = source_step.and_then(|position| {
                self.steps
                    .iter()
                    .find(|(_, binding)| binding.position == position)
            });
            let span = origin.map_or(SourceSpan::point(proof_offset), |(_, binding)| binding.span);
            CompileError::Check {
                span,
                source: Box::new(source),
            }
        })?;
        drop(step_origins);
        if checked.conclusion() != &statement {
            return Err(CompileError::StatementMismatch {
                span: statement_span,
            });
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
        let rule_offset = self.next_offset();
        let rule = self.name()?;
        self.punctuation('(')?;
        let step = match rule {
            "simplification" => {
                let antecedent = self.formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let consequent = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::Simplification {
                    antecedent,
                    consequent,
                }
            }
            "frege" => {
                let first = self.formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let second = self.formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let third = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::Frege {
                    first,
                    second,
                    third,
                }
            }
            "classical_contraposition" => {
                let antecedent = self.formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let consequent = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::ClassicalContraposition {
                    antecedent,
                    consequent,
                }
            }
            "universal_distribution" => {
                let variable = self.variable()?;
                self.punctuation(',')?;
                let antecedent = self.formula(1, FormulaContext::Certificate)?;
                self.punctuation(',')?;
                let consequent = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::UniversalDistribution {
                    variable,
                    antecedent,
                    consequent,
                }
            }
            "vacuous_universal" => {
                let formula = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::VacuousUniversal { formula }
            }
            "universal_instantiation" => {
                let variable = self.variable()?;
                self.punctuation(',')?;
                let replacement = self.variable()?;
                self.punctuation(',')?;
                let body = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::UniversalInstantiation {
                    variable,
                    replacement,
                    body,
                }
            }
            "modus_ponens" => {
                let premise = self.earlier_step()?;
                self.punctuation(',')?;
                let implication = self.earlier_step()?;
                ProofStep::ModusPonens {
                    premise,
                    implication,
                }
            }
            "equality_reflexivity" => {
                let variable = self.variable()?;
                ProofStep::EqualityReflexivity { variable }
            }
            "equality_substitution" => {
                let from = self.variable()?;
                self.punctuation(',')?;
                let to = self.variable()?;
                self.punctuation(',')?;
                let body = self.formula(1, FormulaContext::Certificate)?;
                ProofStep::EqualitySubstitution { from, to, body }
            }
            "zfc_axiom" => ProofStep::ZfcAxiom(self.zfc_axiom()?),
            "separation" => ProofStep::Separation(Separation {
                predicate: self.formula(1, FormulaContext::Certificate)?,
                element: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                source: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                result: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                parameters: {
                    self.punctuation(',')?;
                    self.schema_parameters()?
                },
            }),
            "replacement" => ProofStep::Replacement(Replacement {
                predicate: self.formula(1, FormulaContext::Certificate)?,
                input: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                output: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                uniqueness_witness: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                source: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                result: {
                    self.punctuation(',')?;
                    self.variable()?
                },
                parameters: {
                    self.punctuation(',')?;
                    self.schema_parameters()?
                },
            }),
            "cite" => ProofStep::ProofReference {
                proof_id: self.proof_id()?,
            },
            "generalization" => {
                let premise = self.earlier_step()?;
                self.punctuation(',')?;
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
        self.call_end()?;
        Ok(step)
    }

    fn zfc_axiom(&mut self) -> Result<ZfcAxiom, CompileError> {
        let offset = self.next_offset();
        let name = self.string("a quoted ZFC axiom selector")?;
        match name {
            "extensionality" => Ok(ZfcAxiom::Extensionality),
            "pairing" => Ok(ZfcAxiom::Pairing),
            "union" => Ok(ZfcAxiom::Union),
            "power_set" => Ok(ZfcAxiom::PowerSet),
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
        self.keyword("parameters")?;
        self.punctuation('=')?;
        self.punctuation('[')?;
        let mut parameters = Vec::new();
        self.skip_trivia();
        if self.byte() == Some(b']') {
            self.offset += 1;
            return Ok(parameters);
        }
        loop {
            parameters.push(self.variable()?);
            self.skip_trivia();
            if self.byte() == Some(b']') {
                self.offset += 1;
                return Ok(parameters);
            }
            self.punctuation(',')?;
            self.skip_trivia();
            if self.byte() == Some(b']') {
                self.offset += 1;
                return Ok(parameters);
            }
        }
    }

    fn earlier_step(&mut self) -> Result<u32, CompileError> {
        let offset = self.next_offset();
        let name = self.name()?;
        self.steps
            .get(name)
            .map(|binding| binding.position)
            .ok_or_else(|| CompileError::UnknownStep {
                offset,
                name: name.to_owned(),
            })
    }

    fn proof_id(&mut self) -> Result<ProofId, CompileError> {
        const HEX_LENGTH: usize = ProofId::BYTE_LENGTH * 2;
        const EXPECTED: &str = "a 64-digit lowercase hexadecimal ProofId";

        self.skip_trivia();
        let quote_offset = self.offset;
        if self.byte() != Some(b'"') {
            return Err(CompileError::Syntax {
                offset: quote_offset,
                expected: EXPECTED,
            });
        }
        self.offset += 1;
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
        if self.byte() != Some(b'"') {
            return Err(CompileError::Syntax {
                offset: self.offset,
                expected: "a closing quote after the ProofId",
            });
        }
        self.offset += 1;
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
        self.charge_formula_nodes(context, 1, formula_offset)?;
        if depth > FORMULA_MAX_DEPTH {
            return Err(CompileError::FormulaDepthLimitExceeded {
                offset: formula_offset,
                maximum: FORMULA_MAX_DEPTH,
            });
        }
        let operator_offset = formula_offset;
        let operator = self.name()?;
        self.punctuation('(')?;
        let parsed = match operator {
            "equal" => {
                let left = self.variable()?;
                self.punctuation(',')?;
                let right = self.variable()?;
                ParsedFormula {
                    formula: Formula::equal(left, right),
                    expanded_nodes: 1,
                    expanded_depth: 1,
                }
            }
            "member" => {
                let element = self.variable()?;
                self.punctuation(',')?;
                let set = self.variable()?;
                ParsedFormula {
                    formula: Formula::member(element, set),
                    expanded_nodes: 1,
                    expanded_depth: 1,
                }
            }
            "not_equal" => {
                let left = self.variable()?;
                self.punctuation(',')?;
                let right = self.variable()?;
                self.check_derived_expansion(operator_offset, depth, context, 2, 1)?;
                ParsedFormula {
                    formula: Formula::negate(Formula::equal(left, right)),
                    expanded_nodes: 2,
                    expanded_depth: 2,
                }
            }
            "not_" => self.parse_not(operator_offset, depth, context)?,
            "implies" => self.parse_implies(operator_offset, depth, context)?,
            "forall" => self.parse_for_all(operator_offset, depth, context)?,
            "and_" => self.parse_conjunction(operator_offset, depth, context)?,
            "or_" => self.parse_disjunction(operator_offset, depth, context)?,
            "iff" => self.parse_biconditional(operator_offset, depth, context)?,
            "exists" => self.parse_exists(operator_offset, depth, context)?,
            _ => {
                return Err(CompileError::Syntax {
                    offset: operator_offset,
                    expected: "a supported formula",
                });
            }
        };
        self.call_end()?;
        Ok(parsed)
    }

    fn parse_not(
        &mut self,
        offset: usize,
        depth: u32,
        context: FormulaContext,
    ) -> Result<ParsedFormula, CompileError> {
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[1, body.expanded_nodes], offset)?;
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
        self.punctuation(',')?;
        let consequent = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[1, antecedent.expanded_nodes, consequent.expanded_nodes],
            offset,
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
        self.punctuation(',')?;
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[1, body.expanded_nodes], offset)?;
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
        self.punctuation(',')?;
        let right = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[3, left.expanded_nodes, right.expanded_nodes],
            offset,
        )?;
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
        self.punctuation(',')?;
        let right = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(
            context,
            &[2, left.expanded_nodes, right.expanded_nodes],
            offset,
        )?;
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
        self.punctuation(',')?;
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
            offset,
        )?;
        let additional_nodes = self.checked_node_sum(
            context,
            &[4, left.expanded_nodes, right.expanded_nodes],
            offset,
        )?;
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
        self.punctuation(',')?;
        let body = self.parsed_formula(depth + 1, context)?;
        let expanded_nodes = self.checked_node_sum(context, &[3, body.expanded_nodes], offset)?;
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
        self.charge_formula_nodes(context, additional_nodes, operator_offset)?;
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
        offset: usize,
    ) -> Result<usize, CompileError> {
        terms
            .iter()
            .try_fold(0_usize, |sum, term| sum.checked_add(*term))
            .ok_or_else(|| Self::formula_node_limit(context, offset))
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
        offset: usize,
    ) -> Result<(), CompileError> {
        let (used, maximum) = match context {
            FormulaContext::Statement => (&mut self.statement_nodes, FORMULA_MAX_NODES),
            FormulaContext::Certificate => (
                &mut self.certificate_formula_nodes,
                CERTIFICATE_MAX_FORMULA_NODES,
            ),
        };
        let Some(total) = used.checked_add(additional) else {
            return Err(Self::formula_node_limit(context, offset));
        };
        if total > maximum {
            return Err(Self::formula_node_limit(context, offset));
        }
        *used = total;
        Ok(())
    }

    fn formula_node_limit(context: FormulaContext, offset: usize) -> CompileError {
        match context {
            FormulaContext::Statement => CompileError::Statement {
                offset,
                source: FormulaCodecError::NodeLimitExceeded {
                    maximum: FORMULA_MAX_NODES,
                },
            },
            FormulaContext::Certificate => CompileError::Certificate {
                offset,
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
            if !character.is_ascii_alphanumeric() && character != '_' {
                break;
            }
            end = start + relative + character.len_utf8();
        }
        self.offset = end;
        Ok(&self.source[start..end])
    }

    fn string(&mut self, expected: &'static str) -> Result<&'source str, CompileError> {
        self.skip_trivia();
        let start = self.offset;
        if self.byte() != Some(b'"') {
            return Err(CompileError::Syntax {
                offset: start,
                expected,
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
                    ':' => "`:`",
                    '(' => "`(`",
                    ')' => "`)`",
                    '=' => "`=`",
                    ',' => "`,`",
                    '[' => "`[`",
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
                .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    }

    fn call_end(&mut self) -> Result<(), CompileError> {
        self.skip_trivia();
        if self.byte() == Some(b',') {
            self.offset += 1;
        }
        self.punctuation(')')
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
    if matches!(
        byte,
        b' ' | b'\t' | b'\r' | b'\n' | b'#' | b'"' | b',' | b')'
    ) {
        start
    } else {
        offset
    }
}

#[cfg(test)]
mod tests;
