//! Operation outcomes retain their meaning until the presentation boundary.
use std::{error::Error as StdError, fmt};

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
    CorruptStorage(String),
    UncertainDurability(String),
}
impl Error {
    pub fn retryable(&self) -> bool {
        matches!(
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
            other => other,
        }
    }
    pub(crate) fn storage_detail(&self) -> Option<&str> {
        match self {
            Self::CorruptStorage(message) | Self::UncertainDurability(message) => Some(message),
            _ => None,
        }
    }
    pub(crate) fn fatal(&self) -> bool {
        matches!(self, Self::CorruptStorage(_) | Self::UncertainDurability(_))
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
impl StdError for Error {}
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
            naome_checker::program::Error::Invalid(message) => Self::InvalidInput(message),
            naome_checker::program::Error::Storage(error) => {
                Self::CorruptStorage(error.to_string())
            }
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
        serializer.serialize_str(&self.to_string())
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
