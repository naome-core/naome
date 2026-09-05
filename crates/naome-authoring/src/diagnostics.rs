//! Stable diagnostics and source positions.

use super::*;

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
    DuplicateFormulaBinding,
    UnknownFormulaBinding,
    FormulaBindingNodeLimitExceeded,
    ExpectedProof,
    DuplicateDefinitionAlias,
    UnknownDefinitionAlias,
    DefinitionNotSelected,
    DefinitionArityMismatch,
    Definition,
    DefinitionCheck,
    DefinitionFormula,
    DefinitionExpansion,
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
            Self::DuplicateFormulaBinding => "NAO0012",
            Self::UnknownFormulaBinding => "NAO0013",
            Self::FormulaBindingNodeLimitExceeded => "NAO0014",
            Self::ExpectedProof => "NAO0015",
            Self::DuplicateDefinitionAlias => "NAO0016",
            Self::UnknownDefinitionAlias => "NAO0017",
            Self::DefinitionNotSelected => "NAO0018",
            Self::DefinitionArityMismatch => "NAO0019",
            Self::Definition => "NAO0020",
            Self::DefinitionCheck => "NAO0021",
            Self::DefinitionFormula => "NAO0022",
            Self::DefinitionExpansion => "NAO0023",
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
    pub(super) fn new(start: usize, end: usize) -> Self {
        Self::try_new(start, end).expect("accepted source offsets fit in u32")
    }

    fn try_new(start: usize, end: usize) -> Option<Self> {
        Some(Self {
            start: u32::try_from(start).ok()?,
            end: u32::try_from(end).ok()?,
        })
    }

    pub(super) fn point(offset: usize) -> Self {
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
    /// A source-only formula binding was declared more than once.
    DuplicateFormulaBinding { offset: usize, name: String },
    /// A formula position names a binding that has not already been declared.
    UnknownFormulaBinding { offset: usize, name: String },
    /// Expanded formula bindings exceed their cumulative retention budget.
    FormulaBindingNodeLimitExceeded { offset: usize, maximum: usize },
    /// A proof-only compatibility entry point received a definition source.
    ExpectedProof { offset: usize },
    /// A source-only selected-definition alias was declared twice.
    DuplicateDefinitionAlias { offset: usize, name: String },
    /// A formula or term call names no declared selected-definition alias.
    UnknownDefinitionAlias { offset: usize, name: String },
    /// An alias names a DefinitionId absent from immutable selected state.
    DefinitionNotSelected {
        offset: usize,
        definition_id: DefinitionId,
    },
    /// A relation or term call supplies the wrong number of arguments.
    DefinitionArityMismatch {
        offset: usize,
        name: String,
        expected: u32,
        actual: usize,
    },
    /// A lowered definition certificate is structurally invalid.
    Definition {
        offset: usize,
        source: DefinitionCertificateError,
    },
    /// A definition fails selected-dependency or obligation checking.
    DefinitionCheck {
        span: SourceSpan,
        source: Box<DefinitionCheckError>,
    },
    /// A compact or expanded definition-aware formula is invalid.
    DefinitionFormula {
        offset: usize,
        source: DefinedFormulaCodecError,
    },
    /// A selected definition cannot be expanded under deterministic bounds.
    DefinitionExpansion {
        offset: usize,
        source: DefinitionExpansionError,
    },
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
            Self::DuplicateFormulaBinding { .. } => DiagnosticCode::DuplicateFormulaBinding,
            Self::UnknownFormulaBinding { .. } => DiagnosticCode::UnknownFormulaBinding,
            Self::FormulaBindingNodeLimitExceeded { .. } => {
                DiagnosticCode::FormulaBindingNodeLimitExceeded
            }
            Self::ExpectedProof { .. } => DiagnosticCode::ExpectedProof,
            Self::DuplicateDefinitionAlias { .. } => DiagnosticCode::DuplicateDefinitionAlias,
            Self::UnknownDefinitionAlias { .. } => DiagnosticCode::UnknownDefinitionAlias,
            Self::DefinitionNotSelected { .. } => DiagnosticCode::DefinitionNotSelected,
            Self::DefinitionArityMismatch { .. } => DiagnosticCode::DefinitionArityMismatch,
            Self::Definition { .. } => DiagnosticCode::Definition,
            Self::DefinitionCheck { .. } => DiagnosticCode::DefinitionCheck,
            Self::DefinitionFormula { .. } => DiagnosticCode::DefinitionFormula,
            Self::DefinitionExpansion { .. } => DiagnosticCode::DefinitionExpansion,
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
            | Self::Certificate { offset, .. }
            | Self::DuplicateFormulaBinding { offset, .. }
            | Self::UnknownFormulaBinding { offset, .. }
            | Self::FormulaBindingNodeLimitExceeded { offset, .. } => Some(*offset),
            Self::ExpectedProof { offset }
            | Self::DuplicateDefinitionAlias { offset, .. }
            | Self::UnknownDefinitionAlias { offset, .. }
            | Self::DefinitionNotSelected { offset, .. }
            | Self::DefinitionArityMismatch { offset, .. }
            | Self::Definition { offset, .. }
            | Self::DefinitionFormula { offset, .. } => Some(*offset),
            Self::DefinitionExpansion { offset, .. } => Some(*offset),
            Self::Check { span, .. }
            | Self::StatementMismatch { span }
            | Self::DefinitionCheck { span, .. } => Some(span.start()),
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
            | Self::Certificate { offset, .. }
            | Self::DuplicateFormulaBinding { offset, .. }
            | Self::UnknownFormulaBinding { offset, .. }
            | Self::FormulaBindingNodeLimitExceeded { offset, .. }
            | Self::ExpectedProof { offset }
            | Self::DuplicateDefinitionAlias { offset, .. }
            | Self::UnknownDefinitionAlias { offset, .. }
            | Self::DefinitionNotSelected { offset, .. }
            | Self::DefinitionArityMismatch { offset, .. }
            | Self::Definition { offset, .. }
            | Self::DefinitionFormula { offset, .. } => source_token_span(source, *offset)?,
            Self::DefinitionExpansion { offset, .. } => source_token_span(source, *offset)?,
            Self::Check { span, .. }
            | Self::StatementMismatch { span }
            | Self::DefinitionCheck { span, .. } => *span,
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
            Self::DuplicateFormulaBinding { name, .. } => {
                format!("duplicate formula binding {}", diagnostic_name(name))
            }
            Self::UnknownFormulaBinding { name, .. } => format!(
                "unknown or forward formula binding {}",
                diagnostic_name(name)
            ),
            Self::FormulaBindingNodeLimitExceeded { maximum, .. } => {
                format!("formula bindings exceed the {maximum}-node retention limit")
            }
            Self::ExpectedProof { .. } => "expected a proof source".to_owned(),
            Self::DuplicateDefinitionAlias { name, .. } => {
                format!("duplicate definition alias {}", diagnostic_name(name))
            }
            Self::UnknownDefinitionAlias { name, .. } => {
                format!("unknown definition alias {}", diagnostic_name(name))
            }
            Self::DefinitionNotSelected { .. } => {
                "definition alias is absent from selected chain state".to_owned()
            }
            Self::DefinitionArityMismatch {
                name,
                expected,
                actual,
                ..
            } => format!(
                "definition {} expects {expected} arguments but received {actual}",
                diagnostic_name(name)
            ),
            Self::Definition { source, .. } => {
                format!("invalid definition structure: {source}")
            }
            Self::DefinitionCheck { source, .. } => definition_check_diagnostic_message(source),
            Self::DefinitionFormula { source, .. } => {
                format!("invalid definition-aware formula: {source}")
            }
            Self::DefinitionExpansion { source, .. } => {
                format!("definition expansion failed: {source}")
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
            Self::DuplicateFormulaBinding { offset, name } => {
                write!(
                    formatter,
                    "duplicate formula binding {name:?} at byte {offset}"
                )
            }
            Self::UnknownFormulaBinding { offset, name } => write!(
                formatter,
                "unknown or forward formula binding {name:?} at byte {offset}"
            ),
            Self::FormulaBindingNodeLimitExceeded { offset, maximum } => write!(
                formatter,
                "formula bindings at byte {offset} exceed the {maximum}-node retention limit"
            ),
            Self::ExpectedProof { offset } => {
                write!(formatter, "expected a proof source at byte {offset}")
            }
            Self::DuplicateDefinitionAlias { offset, name } => {
                write!(
                    formatter,
                    "duplicate definition alias {name:?} at byte {offset}"
                )
            }
            Self::UnknownDefinitionAlias { offset, name } => {
                write!(
                    formatter,
                    "unknown definition alias {name:?} at byte {offset}"
                )
            }
            Self::DefinitionNotSelected {
                offset,
                definition_id,
            } => write!(
                formatter,
                "definition {:?} is absent from selected state at byte {offset}",
                definition_id.as_bytes()
            ),
            Self::DefinitionArityMismatch {
                offset,
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "definition {name:?} expects {expected} arguments but received {actual} at byte {offset}"
            ),
            Self::Definition { source, .. } => {
                write!(formatter, "invalid definition structure: {source}")
            }
            Self::DefinitionCheck { source, .. } => {
                formatter.write_str(&definition_check_diagnostic_message(source))
            }
            Self::DefinitionFormula { source, .. } => {
                write!(formatter, "invalid definition-aware formula: {source}")
            }
            Self::DefinitionExpansion { source, .. } => {
                write!(formatter, "definition expansion failed: {source}")
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
            Self::Definition { source, .. } => Some(source),
            Self::DefinitionCheck { source, .. } => Some(source.as_ref()),
            Self::DefinitionFormula { source, .. } => Some(source),
            Self::DefinitionExpansion { source, .. } => Some(source),
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

fn definition_check_diagnostic_message(error: &DefinitionCheckError) -> String {
    match error {
        DefinitionCheckError::UnknownObligationStatement { statement_id } => format!(
            "definition obligation statement {} is absent from selected state",
            lowercase_hex(statement_id.as_bytes())
        ),
        DefinitionCheckError::ObligationConclusionMismatch { statement_id } => format!(
            "definition obligation statement {} has a conflicting conclusion",
            lowercase_hex(statement_id.as_bytes())
        ),
        _ => format!("definition checking failed: {error}"),
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
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

#[cfg(test)]
mod tests;
