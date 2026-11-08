//! Operation outcomes retain their meaning until the presentation boundary.
use crate::{
    EvidenceFailure, InputFault, InputLimit,
    outcome::{DurabilityCode, OperationCode},
};
use std::{error::Error as StdError, fmt, num::NonZeroI32};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FormatFailure {
    EmptyCertificate,
    Limit {
        resource: &'static str,
        actual: Option<u64>,
        maximum: u64,
    },
    ReferenceNotEarlier {
        step: u32,
        reference: u32,
    },
    UnexpectedEnd,
    UnknownTag {
        domain: &'static str,
        tag: u8,
    },
    Formula {
        reason: naome_checker::diagnostics::FormulaFailure,
    },
    TrailingBytes {
        remaining: usize,
    },
    Unsupported,
}
impl From<&naome_proof::ProofCertificateError> for FormatFailure {
    fn from(error: &naome_proof::ProofCertificateError) -> Self {
        use naome_proof::ProofCertificateError;
        match *error {
            ProofCertificateError::EmptyCertificate => Self::EmptyCertificate,
            ProofCertificateError::TooManySteps { actual, maximum } => Self::Limit {
                resource: "steps",
                actual: Some(actual as u64),
                maximum: maximum as u64,
            },
            ProofCertificateError::InputTooLong { actual, maximum } => Self::Limit {
                resource: "bytes",
                actual: Some(actual as u64),
                maximum: maximum as u64,
            },
            ProofCertificateError::FormulaNodeLimitExceeded { maximum } => Self::Limit {
                resource: "nodes",
                actual: None,
                maximum: maximum as u64,
            },
            ProofCertificateError::ReferenceNotEarlier { step, reference } => {
                Self::ReferenceNotEarlier { step, reference }
            }
            ProofCertificateError::UnexpectedEnd => Self::UnexpectedEnd,
            ProofCertificateError::UnknownStepTag(tag) => Self::UnknownTag {
                domain: "proof_step",
                tag,
            },
            ProofCertificateError::UnknownZfcAxiomTag(tag) => Self::UnknownTag {
                domain: "zfc_axiom",
                tag,
            },
            ProofCertificateError::Formula(ref reason) => Self::Formula {
                reason: reason.into(),
            },
            ProofCertificateError::DefinedFormula(ref reason) => Self::Formula {
                reason: reason.into(),
            },
            ProofCertificateError::TrailingBytes { remaining } => Self::TrailingBytes { remaining },
            _ => Self::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateFormatError {
    pub message: String,
    pub input_digest: naome_checker::diagnostics::Digest,
    pub reason: FormatFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DurabilityFailure {
    pub code: DurabilityCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlite_code: Option<NonZeroI32>,
}

impl DurabilityFailure {
    pub(crate) fn new(code: DurabilityCode) -> Self {
        Self {
            code,
            sqlite_code: None,
        }
    }

    pub(crate) fn sqlite(code: DurabilityCode, error: &rusqlite::Error) -> Self {
        Self {
            code,
            sqlite_code: naome_storage::sqlite_code(error),
        }
    }
}

impl From<naome_storage::UncertainCommit> for DurabilityFailure {
    fn from(error: naome_storage::UncertainCommit) -> Self {
        use naome_storage::UncertainCommit;
        let (code, sqlite_code) = match error {
            UncertainCommit::Commit { sqlite_code } => {
                (DurabilityCode::CommitUnconfirmed, sqlite_code)
            }
            UncertainCommit::Rollback { sqlite_code } => {
                (DurabilityCode::RollbackUnconfirmed, sqlite_code)
            }
        };
        Self { code, sqlite_code }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    MemoryOverload {
        requested: usize,
        charged: usize,
        budget: usize,
    },
    DiskOverload {
        available: u128,
        required: u128,
    },
    ExecutionLimit,
    InputLimit(InputLimit),
    InputFault(InputFault),
    QuestionLimit(naome_proof::QuestionLimit),
    StaleAuthority,
    Deadline,
    InvalidInput(String),
    MissingQuestionDefinition(naome_proof::DefinitionId),
    Proof {
        message: String,
        diagnostic: std::sync::Arc<naome_checker::diagnostics::ProofDiagnostic>,
    },
    DiagnosticInspection(naome_checker::diagnostics::InspectionError),
    CertificateFormat(Box<CertificateFormatError>),
    /// Invalid data read from owned storage remains fatal while retaining the
    /// original structured diagnostic. It is never a candidate repair request.
    Stored(Box<Error>),
    CorruptStorage(String),
    UncertainDurability(DurabilityFailure),
    LearningEvidence(EvidenceFailure),
    LearningGraph(crate::LearningGraphFailure),
    ProgramCodec(naome_proof::program::CodecFailure),
    QuestionInput(Box<naome_proof::QuestionError>),
    Runtime(crate::RuntimeFailure),
    Startup {
        code: crate::StartupFailure,
        reaped: bool,
    },
}
impl Error {
    /// The same mathematical contract survives both native proof paths.
    pub fn diagnostic(&self) -> Option<&naome_checker::diagnostics::ProofDiagnostic> {
        match self {
            Self::Proof { diagnostic, .. } => Some(diagnostic),
            Self::Stored(error) => error.diagnostic(),
            _ => None,
        }
    }
    pub fn code(&self) -> u32 {
        let code = match self {
            Self::MemoryOverload { .. } => OperationCode::MemoryOverload,
            Self::DiskOverload { .. } => OperationCode::DiskOverload,
            Self::ExecutionLimit => OperationCode::ExecutionLimit,
            Self::InputLimit(limit) => return (*limit).into(),
            Self::InputFault(fault) => return (*fault).into(),
            Self::QuestionLimit(_) => OperationCode::QuestionLimit,
            Self::StaleAuthority => OperationCode::StaleAuthority,
            Self::Deadline => OperationCode::Deadline,
            Self::InvalidInput(_) => OperationCode::InvalidInput,
            Self::MissingQuestionDefinition(_) => OperationCode::MissingQuestionDefinition,
            Self::Proof { .. } => OperationCode::ProofCheck,
            Self::DiagnosticInspection(_) => OperationCode::DiagnosticInspection,
            Self::CertificateFormat(_) => OperationCode::CertificateFormat,
            Self::Stored(_) => OperationCode::InvalidStoredRecord,
            Self::CorruptStorage(_) => OperationCode::CorruptStorage,
            Self::UncertainDurability(failure) => return failure.code.into(),
            Self::LearningEvidence(failure) => return failure.code().into(),
            Self::LearningGraph(failure) => return (*failure).into(),
            Self::ProgramCodec(_) => OperationCode::ProgramCodec,
            Self::QuestionInput(_) => OperationCode::QuestionInput,
            Self::Runtime(failure) => return (*failure).into(),
            Self::Startup { code, .. } => return (*code).into(),
        };
        code.into()
    }
    pub fn retryable(&self) -> bool {
        if matches!(self, Self::Stored(_)) {
            return false;
        }
        self.diagnostic()
            .is_some_and(|d| matches!(d.failure, naome_checker::diagnostics::Failure::ContextLimit))
            || matches!(
                self,
                Self::MemoryOverload { .. }
                    | Self::DiskOverload { .. }
                    | Self::ExecutionLimit
                    | Self::StaleAuthority
                    | Self::Deadline
            )
    }
    pub(crate) fn storage(self) -> Self {
        match self {
            Self::InvalidInput(message) => Self::CorruptStorage(message),
            error @ (Self::InputFault(_) | Self::QuestionLimit(_) | Self::QuestionInput(_)) => {
                Self::Stored(Box::new(error))
            }
            error @ (Self::Proof { .. } | Self::CertificateFormat(_) | Self::ProgramCodec(_))
                if !error.retryable() =>
            {
                Self::Stored(Box::new(error))
            }
            other => other,
        }
    }
    pub(crate) fn fatal(&self) -> bool {
        self.diagnostic()
            .is_some_and(|d| d.outcome == naome_checker::diagnostics::Outcome::ContextFailure)
            || matches!(
                self,
                Self::Stored(_)
                    | Self::CorruptStorage(_)
                    | Self::UncertainDurability(_)
                    | Self::Runtime(_)
                    | Self::Startup { .. }
            )
    }
    fn format_error(&self) -> Option<(naome_checker::diagnostics::Digest, &FormatFailure)> {
        match self {
            Self::CertificateFormat(error) => Some((error.input_digest, &error.reason)),
            Self::Stored(error) => error.format_error(),
            _ => None,
        }
    }
    #[cfg(test)]
    pub(crate) fn contains(&self, pattern: &str) -> bool {
        self.to_string().contains(pattern)
    }
    #[cfg(test)]
    pub(crate) fn starts_with(&self, pattern: &str) -> bool {
        self.to_string().starts_with(pattern)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryOverload {
                requested,
                charged,
                budget,
            } => write!(
                f,
                "memory overload: requested {requested}, charged {charged}, budget {budget}"
            ),
            Self::DiskOverload {
                available,
                required,
            } => write!(
                f,
                "disk overload: available {available}, required reserve and work {required}"
            ),
            Self::ExecutionLimit => f.write_str("operation execution resources exhausted"),
            Self::InputLimit(limit) => f.write_str(limit.label()),
            Self::InputFault(fault) => f.write_str(match fault {
                InputFault::DescriptionAddressMismatch => "description proof address differs",
                InputFault::ArtifactCompatibilityMismatch => "compatibility mismatch",
                InputFault::CheckedIdentityMismatch => "checked identity mismatch",
            }),
            Self::QuestionLimit(limit) => naome_proof::QuestionError::Limit(*limit).fmt(f),
            Self::InvalidInput(message) => f.write_str(message),
            Self::MissingQuestionDefinition(id) => {
                write!(f, "question definition unavailable: {id:?}")
            }
            Self::Proof { message, .. } => f.write_str(message),
            Self::DiagnosticInspection(error) => error.fmt(f),
            Self::CertificateFormat(error) => f.write_str(&error.message),
            Self::Stored(error) => write!(f, "storage halted: {error}"),
            Self::CorruptStorage(message) => write!(f, "storage halted: {message}"),
            Self::LearningEvidence(error) => error.fmt(f),
            Self::LearningGraph(error) => error.fmt(f),
            Self::ProgramCodec(error) => error.fmt(f),
            Self::QuestionInput(error) => error.fmt(f),
            Self::Runtime(failure) => write!(f, "runtime failure {}", u32::from(*failure)),
            Self::Startup { code, .. } => write!(f, "startup failure {}", u32::from(*code)),
            Self::UncertainDurability(failure) => {
                write!(f, "storage halted: {}", u32::from(failure.code))
            }
            Self::StaleAuthority => {
                f.write_str("publication authority changed before durable commit")
            }
            Self::Deadline => f.write_str("catalog commit deadline expired before durable commit"),
        }
    }
}
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Stored(error) => Some(error),
            Self::DiagnosticInspection(error) => Some(error),
            _ => None,
        }
    }
}
impl From<naome_proof::program::CodecFailure> for Error {
    fn from(error: naome_proof::program::CodecFailure) -> Self {
        Self::ProgramCodec(error)
    }
}

impl From<crate::StartupFailure> for Error {
    fn from(code: crate::StartupFailure) -> Self {
        Self::Startup {
            code,
            reaped: false,
        }
    }
}

impl From<crate::RuntimeFailure> for Error {
    fn from(error: crate::RuntimeFailure) -> Self {
        Self::Runtime(error)
    }
}

impl From<crate::LearningGraphFailure> for Error {
    fn from(error: crate::LearningGraphFailure) -> Self {
        Self::LearningGraph(error)
    }
}

impl From<EvidenceFailure> for Error {
    fn from(error: EvidenceFailure) -> Self {
        Self::LearningEvidence(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        use std::io::ErrorKind;
        if matches!(
            error.kind(),
            ErrorKind::WouldBlock
                | ErrorKind::Interrupted
                | ErrorKind::OutOfMemory
                | ErrorKind::StorageFull
                | ErrorKind::QuotaExceeded
        ) {
            Self::ExecutionLimit
        } else {
            Self::InvalidInput(error.to_string())
        }
    }
}
impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::InvalidInput(message)
    }
}
impl From<naome_checker::program::Error> for Error {
    fn from(error: naome_checker::program::Error) -> Self {
        if error.resource_shortage() {
            return Self::ExecutionLimit;
        }
        match error {
            naome_checker::program::Error::Check(diagnostic) => Self::Proof {
                message: format!(
                    "proof command {} violates {}",
                    diagnostic.location.step,
                    diagnostic.code()
                ),
                diagnostic: diagnostic.into(),
            },
            naome_checker::program::Error::Inspection(error) => Self::DiagnosticInspection(error),
            naome_checker::program::Error::Invalid(message) => Self::InvalidInput(message),
            naome_checker::program::Error::Codec(error) => error.into(),
            naome_checker::program::Error::Storage(error) => {
                Self::CorruptStorage(error.to_string())
            }
            naome_checker::program::Error::Context(error) => error.into(),
        }
    }
}
impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self::InvalidInput(message.to_owned())
    }
}
impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.to_string()
    }
}
impl From<naome_checker::ContextError> for Error {
    fn from(error: naome_checker::ContextError) -> Self {
        match error {
            naome_checker::ContextError::Limit => Self::ExecutionLimit,
            other => Self::CorruptStorage(other.to_string()),
        }
    }
}
impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        if let Self::LearningEvidence(failure) = self {
            return failure.serialize(serializer);
        }
        if let Self::UncertainDurability(failure) = self {
            let mut value = serializer.serialize_struct(
                "DurabilityError",
                3 + usize::from(failure.sqlite_code.is_some()),
            )?;
            value.serialize_field("code", &failure.code)?;
            if let Some(sqlite_code) = failure.sqlite_code {
                value.serialize_field("sqlite_code", &sqlite_code)?;
            }
            value.serialize_field("retryable", &false)?;
            value.serialize_field("fatal", &true)?;
            return value.end();
        }
        use serde::ser::SerializeMap;
        let mut value = serializer.serialize_map(None)?;
        value.serialize_entry("code", &self.code())?;
        value.serialize_entry("retryable", &self.retryable())?;
        value.serialize_entry("fatal", &self.fatal())?;
        if let Some(diagnostic) = self.diagnostic() {
            value.serialize_entry("diagnostic", diagnostic)?;
        }
        if let Self::DiagnosticInspection(error) = self {
            value.serialize_entry("inspection_error", error)?;
        }
        if let Some((input_digest, reason)) = self.format_error() {
            #[derive(serde::Serialize)]
            struct Format<'a> {
                input_digest: naome_checker::diagnostics::Digest,
                reason: &'a FormatFailure,
            }
            value.serialize_entry(
                "format_error",
                &Format {
                    input_digest,
                    reason,
                },
            )?;
        }
        let cause = match self {
            Self::Stored(cause) => {
                value.serialize_entry("cause_code", &cause.code())?;
                cause
            }
            _ => self,
        };
        if let Self::ProgramCodec(reason) = cause {
            value.serialize_entry("reason", &(*reason as u8))?;
        }
        if let Self::QuestionInput(reason) = cause {
            use naome_checker::diagnostics::{ExpansionFailure, FormulaFailure};
            use naome_proof::QuestionError;
            match reason.as_ref() {
                QuestionError::Invalid(fault) => {
                    value.serialize_entry("reason", &(*fault as u8))?
                }
                QuestionError::Formula(error) => {
                    value.serialize_entry("formula", &FormulaFailure::from(error))?
                }
                QuestionError::DefinedFormula(error) => {
                    value.serialize_entry("formula", &FormulaFailure::from(error))?
                }
                QuestionError::Expansion(error) => {
                    value.serialize_entry("expansion", &ExpansionFailure::from(error))?
                }
                _ => {}
            }
        }
        if let Self::MemoryOverload {
            requested,
            charged,
            budget,
        } = self
        {
            value.serialize_entry("requested", requested)?;
            value.serialize_entry("charged", charged)?;
            value.serialize_entry("budget", budget)?;
        }
        if let Self::DiskOverload {
            available,
            required,
        } = self
        {
            // JSON consumers can preserve the full integer using two u64 limbs.
            let limbs = |value: u128| [(value >> 64) as u64, value as u64];
            value.serialize_entry("available", &limbs(*available))?;
            value.serialize_entry("required", &limbs(*required))?;
        }
        if let Self::Startup { reaped, .. } = self {
            value.serialize_entry("reaped", reaped)?;
        }
        if let Self::QuestionLimit(limit) = self {
            value.serialize_entry("limit", &(*limit as u8))?;
        }
        if let Self::MissingQuestionDefinition(id) = self {
            value.serialize_entry("definition", id.as_bytes())?;
        }
        value.end()
    }
}

impl From<naome_checker::CheckError> for Error {
    fn from(error: naome_checker::CheckError) -> Self {
        Self::Proof {
            message: error.to_string(),
            diagnostic: error.into_diagnostic(),
        }
    }
}

impl From<naome_checker::DefinitionCheckError> for Error {
    fn from(error: naome_checker::DefinitionCheckError) -> Self {
        match error {
            naome_checker::DefinitionCheckError::ContextAccess(source) => source.into(),
            naome_checker::DefinitionCheckError::Expansion(
                naome_proof::DefinitionExpansionError::Access(source),
            ) => naome_checker::ContextError::from(source).into(),
            other => Self::InvalidInput(other.to_string()),
        }
    }
}

impl From<naome_checker::question::ResolutionError> for Error {
    fn from(error: naome_checker::question::ResolutionError) -> Self {
        let message = error.to_string();
        match error {
            naome_checker::question::ResolutionError::Target(diagnostic) => Self::Proof {
                message,
                diagnostic: diagnostic.into(),
            },
            naome_checker::question::ResolutionError::Program(error) => error.into(),
        }
    }
}

impl From<naome_foundation::FormulaCodecError> for Error {
    fn from(error: naome_foundation::FormulaCodecError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}
impl From<naome_proof::QuestionError> for Error {
    fn from(error: naome_proof::QuestionError) -> Self {
        match error {
            naome_proof::QuestionError::MissingDefinition(id) => {
                Self::MissingQuestionDefinition(id)
            }
            error => Self::InvalidInput(error.to_string()),
        }
    }
}
impl From<naome_checker::ArtifactStateError> for Error {
    fn from(error: naome_checker::ArtifactStateError) -> Self {
        match error {
            naome_checker::ArtifactStateError::Context(error) => error.into(),
            other => Self::InvalidInput(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests;
