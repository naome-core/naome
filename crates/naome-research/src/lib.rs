//! Deterministic domain rules for the fixed, trusted research MVP.
//!
//! Decoding and identifiers establish no mathematical validity or finality.
//! Consensus, transport, persistent signing safety, and durable publication
//! belong to their respective integration layers.

pub mod accounting;
pub mod authentication;
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
pub use state::{ResearchRecord, ResearchState, ResearchTransition};

/// A rejected research value. Rejection must leave selected state unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResearchError {
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

impl std::fmt::Display for ResearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated research value"),
            Self::TrailingBytes => f.write_str("trailing research bytes"),
            Self::Limit(name) => write!(f, "research limit exceeded: {name}"),
            Self::Invalid(reason) => write!(f, "invalid research value: {reason}"),
            Self::Overflow => f.write_str("research arithmetic overflow"),
            Self::Mathematical(reason) => write!(f, "mathematical verification failed: {reason}"),
        }
    }
}

impl std::error::Error for ResearchError {}

#[cfg(test)]
mod test_support;

pub mod library;
