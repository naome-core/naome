use std::fmt;

#[derive(Debug)]
pub enum Error {
    Check(Box<crate::diagnostics::ProofDiagnostic>),
    Inspection(crate::diagnostics::InspectionError),
    Invalid(String),
    Storage(rusqlite::Error),
    Context(crate::ContextError),
}
impl Error {
    pub fn diagnostic(&self) -> Option<&crate::diagnostics::ProofDiagnostic> {
        match self {
            Self::Check(diagnostic) => Some(diagnostic),
            _ => None,
        }
    }
    pub fn resource_shortage(&self) -> bool {
        matches!(self, Self::Context(crate::ContextError::Limit))
            || matches!(self,Self::Storage(rusqlite::Error::SqliteFailure(error,_)) if matches!(error.code,
            rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked|rusqlite::ErrorCode::DiskFull|rusqlite::ErrorCode::OutOfMemory))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Check(diagnostic) => write!(
                f,
                "proof command {} violates {}",
                diagnostic.location.step,
                diagnostic.code()
            ),
            Self::Inspection(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
            Self::Storage(error) => write!(f, "{error}"),
            Self::Context(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Context(e) => Some(e),
            Self::Inspection(e) => Some(e),
            _ => None,
        }
    }
}
impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("ProgramError", 4)?;
        let code = match self {
            Self::Check(_) => "proof_check",
            Self::Inspection(_) => "diagnostic_inspection",
            Self::Invalid(_) => "program_input",
            Self::Storage(_) => "program_storage",
            Self::Context(_) => "checked_context",
        };
        value.serialize_field("code", code)?;
        value.serialize_field("message", &self.to_string())?;
        value.serialize_field("diagnostic", &self.diagnostic())?;
        value.serialize_field(
            "inspection_error",
            &match self {
                Self::Inspection(error) => Some(error),
                _ => None,
            },
        )?;
        value.end()
    }
}
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Invalid(value)
    }
}
impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::Invalid(value.into())
    }
}
impl From<crate::ContextError> for Error {
    fn from(error: crate::ContextError) -> Self {
        Self::Context(error)
    }
}
impl From<Error> for String {
    fn from(value: Error) -> Self {
        value.to_string()
    }
}
