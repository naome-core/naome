//! Anchored research history and restart-safe research signing.
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
pub use history::{
    ResearchAppendOutcome, ResearchHistory, ResearchObserver, SelectedResearchHistory,
};
pub use signer::{ResearchPreparation, ResearchSigner};

use std::fmt;
use std::io;

/// A fail-closed research persistence error.
#[derive(Debug)]
pub enum ResearchStorageError {
    Io(io::Error),
    Platform(crate::FixedValidatorAnchorErrorV0),
    Locked,
    Invalid(&'static str),
    Limit(&'static str),
    Poisoned,
    Validation(String),
}
impl fmt::Display for ResearchStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "research storage I/O: {e}"),
            Self::Platform(e) => write!(f, "research durability unavailable: {e}"),
            Self::Locked => f.write_str("research storage already owned"),
            Self::Invalid(e) => write!(f, "invalid research history: {e}"),
            Self::Limit(e) => write!(f, "research storage limit exceeded: {e}"),
            Self::Poisoned => f.write_str("research storage halted after uncertain durability"),
            Self::Validation(e) => write!(f, "research replay rejected: {e}"),
        }
    }
}
impl std::error::Error for ResearchStorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Platform(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for ResearchStorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<crate::FixedValidatorAnchorErrorV0> for ResearchStorageError {
    fn from(e: crate::FixedValidatorAnchorErrorV0) -> Self {
        Self::Platform(e)
    }
}
impl From<naome_ledger::ResearchError> for ResearchStorageError {
    fn from(e: naome_ledger::ResearchError) -> Self {
        Self::Validation(e.to_string())
    }
}

impl From<naome_consensus::state::ResearchConsensusError> for ResearchStorageError {
    fn from(e: naome_consensus::state::ResearchConsensusError) -> Self {
        Self::Validation(e.to_string())
    }
}
