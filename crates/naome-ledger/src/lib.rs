//! Deterministic canonical ledger rules for the fixed, trusted NAOME network.
//!
//! Decoding and identifiers establish no mathematical validity or finality.
//! Consensus, transport, persistent signing safety, and durable publication
//! belong to their respective integration layers.

mod artifact_set;
mod dag;
pub use artifact_set::{
    ARTIFACT_SET_PROOF_MAX_BYTES, ArtifactSetMembership, ArtifactSetProof, ArtifactSetProofError,
    ArtifactSetRoot,
};
pub use dag::ArtifactDag;

pub mod artifacts;
pub use artifacts::*;

pub mod accounting;
pub mod authentication;
pub mod authority;
mod capacity;
mod codec;
pub mod identity;
pub mod operations;
pub mod profile;
pub mod question;
pub mod receipt;
pub mod state;
pub mod time;

pub use identity::*;
pub use state::{LedgerExecution, LedgerState};

/// A rejected ledger value. Rejection must leave selected state unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// A bounded input ended before the required field.
    Truncated,
    /// A decoder did not consume exactly one canonical value.
    TrailingBytes,
    /// A deterministic byte, count, depth, or work bound was exceeded.
    Limit(&'static str),
    /// A semantic or canonical contract was violated.
    Invalid(&'static str),
    /// Checked integer arithmetic failed.
    Overflow,
    /// Mathematical verification rejected a certificate.
    Mathematical(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated ledger value"),
            Self::TrailingBytes => f.write_str("trailing ledger bytes"),
            Self::Limit(name) => write!(f, "ledger limit exceeded: {name}"),
            Self::Invalid(reason) => write!(f, "invalid ledger value: {reason}"),
            Self::Overflow => f.write_str("ledger arithmetic overflow"),
            Self::Mathematical(reason) => write!(f, "mathematical verification failed: {reason}"),
        }
    }
}

impl std::error::Error for LedgerError {}

#[cfg(test)]
mod test_support;

pub mod library;

#[cfg(test)]
#[path = "../../../tests/support/codec_corpus.rs"]
mod codec_corpus;
