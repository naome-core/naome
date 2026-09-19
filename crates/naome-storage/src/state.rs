//! Anchored state history and restart-safe state signing.
//!
//! Canonical bytes are replayed through the same consensus and mathematical
//! validation paths used for live admission. Incomplete final writes may be
//! discarded only when the remaining complete prefix exactly matches its
//! independent anchor. A complete but corrupt frame or an anchor gap halts.
//! Separate file anchors do not detect coordinated rollback of both files and
//! make no claim of hardware monotonicity or cross-file atomicity.

mod codec;
#[cfg(test)]
mod faults;
mod history;
mod log;
mod signer;
#[cfg(test)]
mod tests;
pub use history::{SelectedStateHistory, StateAppendOutcome, StateHistory, StateObserver};
pub use signer::{StatePreparation, StateSigner};

use std::fmt;
use std::io;

/// A fail-closed state persistence error.
#[derive(Debug)]
pub enum StateStorageError {
    Io(io::Error),
    Platform(crate::StoragePlatformError),
    Locked,
    Invalid(&'static str),
    Limit(&'static str),
    Poisoned,
    Validation(String),
}
impl fmt::Display for StateStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "state storage I/O: {e}"),
            Self::Platform(e) => write!(f, "research durability unavailable: {e}"),
            Self::Locked => f.write_str("state storage already owned"),
            Self::Invalid(e) => write!(f, "invalid state history: {e}"),
            Self::Limit(e) => write!(f, "state storage limit exceeded: {e}"),
            Self::Poisoned => f.write_str("state storage halted after uncertain durability"),
            Self::Validation(e) => write!(f, "research replay rejected: {e}"),
        }
    }
}
impl std::error::Error for StateStorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Platform(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for StateStorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<crate::StoragePlatformError> for StateStorageError {
    fn from(e: crate::StoragePlatformError) -> Self {
        Self::Platform(e)
    }
}
impl From<naome_ledger::LedgerError> for StateStorageError {
    fn from(e: naome_ledger::LedgerError) -> Self {
        Self::Validation(e.to_string())
    }
}

impl From<naome_consensus::state::StateConsensusError> for StateStorageError {
    fn from(e: naome_consensus::state::StateConsensusError) -> Self {
        Self::Validation(e.to_string())
    }
}
