use std::fmt;

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Storage(rusqlite::Error),
    Context(crate::ContextError),
}
impl Error {
    pub fn resource_shortage(&self) -> bool {
        matches!(self, Self::Context(crate::ContextError::Limit))
            || matches!(self,Self::Storage(rusqlite::Error::SqliteFailure(error,_)) if matches!(error.code,
            rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked|rusqlite::ErrorCode::DiskFull|rusqlite::ErrorCode::OutOfMemory))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::Storage(error) => write!(f, "{error}"),
            Self::Context(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for Error {}
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
