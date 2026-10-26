//! Operation outcomes retain their meaning until the presentation boundary.
use std::{error::Error as StdError, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateFormatError {
    pub message: String,
    pub input_digest: naome_checker::diagnostics::Digest,
    pub reason: naome_authoring::FormatFailure,
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
    InputLimit(&'static str),
    StaleAuthority,
    Deadline,
    InvalidInput(String),
    Proof {
        message: String,
        diagnostic: std::sync::Arc<naome_checker::diagnostics::ProofDiagnostic>,
    },
    Compile(Box<naome_authoring::CompileDiagnostic>),
    DiagnosticInspection(naome_checker::diagnostics::InspectionError),
    CertificateFormat(Box<CertificateFormatError>),
    /// Invalid data read from owned storage remains fatal while retaining the
    /// original structured diagnostic. It is never a candidate repair request.
    Stored(Box<Error>),
    CorruptStorage(String),
    UncertainDurability(String),
}
impl Error {
    /// The same mathematical contract survives both native proof paths.
    pub fn diagnostic(&self) -> Option<&naome_checker::diagnostics::ProofDiagnostic> {
        match self {
            Self::Proof { diagnostic, .. } => Some(diagnostic),
            Self::Compile(diagnostic) => diagnostic.proof(),
            Self::Stored(error) => error.diagnostic(),
            _ => None,
        }
    }
    pub fn compile_diagnostic(&self) -> Option<&naome_authoring::CompileDiagnostic> {
        match self {
            Self::Compile(diagnostic) => Some(diagnostic),
            Self::Stored(error) => error.compile_diagnostic(),
            _ => None,
        }
    }
    pub fn code(&self) -> &'static str {
        match self {
            Self::MemoryOverload { .. } => "resource.memory_overload",
            Self::DiskOverload { .. } => "resource.disk_overload",
            Self::ExecutionLimit => "resource.execution_limit",
            Self::InputLimit(_) => "input.limit",
            Self::StaleAuthority => "publication.stale_authority",
            Self::Deadline => "publication.deadline",
            Self::InvalidInput(_) => "input.invalid",
            Self::Proof { .. } => "proof.check",
            Self::Compile(_) => "source.compile",
            Self::DiagnosticInspection(_) => "diagnostic.inspection",
            Self::CertificateFormat(_) => "certificate.format",
            Self::Stored(_) => "storage.invalid_record",
            Self::CorruptStorage(_) => "storage.corrupt",
            Self::UncertainDurability(_) => "storage.uncertain_durability",
        }
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
            error @ (Self::Proof { .. } | Self::Compile(_) | Self::CertificateFormat(_))
                if !error.retryable() =>
            {
                Self::Stored(Box::new(error))
            }
            other => other,
        }
    }
    pub(crate) fn storage_detail(&self) -> Option<&str> {
        match self {
            Self::Stored(error) => error.detail(),
            Self::Proof { message, .. } if self.fatal() => Some(message),
            Self::Compile(diagnostic) if self.fatal() => Some(diagnostic.message()),
            Self::CorruptStorage(message) | Self::UncertainDurability(message) => Some(message),
            _ => None,
        }
    }
    pub(crate) fn fatal(&self) -> bool {
        self.diagnostic()
            .is_some_and(|d| d.outcome == naome_checker::diagnostics::Outcome::ContextFailure)
            || matches!(
                self,
                Self::Stored(_) | Self::CorruptStorage(_) | Self::UncertainDurability(_)
            )
    }
    fn detail(&self) -> Option<&str> {
        match self {
            Self::Proof { message, .. }
            | Self::InvalidInput(message)
            | Self::CorruptStorage(message)
            | Self::UncertainDurability(message) => Some(message),
            Self::CertificateFormat(error) => Some(&error.message),
            Self::Compile(diagnostic) => Some(diagnostic.message()),
            Self::Stored(error) => error.detail(),
            _ => None,
        }
    }
    fn format_error(
        &self,
    ) -> Option<(
        naome_checker::diagnostics::Digest,
        &naome_authoring::FormatFailure,
    )> {
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
            Self::InputLimit(message) => f.write_str(message),
            Self::InvalidInput(message) => f.write_str(message),
            Self::Proof { message, .. } => f.write_str(message),
            Self::Compile(diagnostic) => f.write_str(diagnostic.message()),
            Self::DiagnosticInspection(error) => error.fmt(f),
            Self::CertificateFormat(error) => f.write_str(&error.message),
            Self::Stored(error) => write!(f, "storage halted: {error}"),
            Self::CorruptStorage(message) | Self::UncertainDurability(message) => {
                write!(f, "storage halted: {message}")
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
        let mut value = serializer.serialize_struct("OperationError", 9)?;
        value.serialize_field("schema_version", &1)?;
        value.serialize_field("code", self.code())?;
        value.serialize_field("message", &self.to_string())?;
        value.serialize_field("retryable", &self.retryable())?;
        value.serialize_field("diagnostic", &self.diagnostic())?;
        value.serialize_field("source_diagnostic", &self.compile_diagnostic())?;
        value.serialize_field(
            "inspection_error",
            &match self {
                Self::DiagnosticInspection(error) => Some(error),
                _ => None,
            },
        )?;
        #[derive(serde::Serialize)]
        struct Format<'a> {
            input_digest: naome_checker::diagnostics::Digest,
            reason: &'a naome_authoring::FormatFailure,
        }
        let format_error = self.format_error().map(|(input_digest, reason)| Format {
            input_digest,
            reason,
        });
        value.serialize_field("format_error", &format_error)?;
        value.serialize_field("fatal", &self.fatal())?;
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

impl From<naome_authoring::CompileError> for Error {
    fn from(error: naome_authoring::CompileError) -> Self {
        match error.kind() {
            naome_authoring::CompileErrorKind::DefinitionExpansion {
                source: naome_proof::DefinitionExpansionError::Access(source),
                ..
            } => return naome_checker::ContextError::from(source.clone()).into(),
            naome_authoring::CompileErrorKind::DefinitionCheck { source, .. } => {
                if let naome_checker::DefinitionCheckError::ContextAccess(source) = source.as_ref()
                {
                    return source.clone().into();
                }
            }
            _ => {}
        }
        Self::Compile(Box::new(error.into_diagnostic()))
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

impl From<naome_authoring::ResolutionError> for Error {
    fn from(error: naome_authoring::ResolutionError) -> Self {
        let message = error.to_string();
        match error {
            naome_authoring::ResolutionError::Target(diagnostic) => Self::Proof {
                message,
                diagnostic: diagnostic.into(),
            },
            naome_authoring::ResolutionError::Program(error) => error.into(),
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
        Self::InvalidInput(error.to_string())
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
