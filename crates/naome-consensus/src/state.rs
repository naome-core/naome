//! Fixed-validator consensus for complete state records.
//!
//! State values and signatures have separate versioned domains from the V0
//! artifact protocol. The fixed-set proposer arithmetic and weighted quorum
//! predicates are shared. This module supplies verification and unsigned
//! intents; storage must durably anchor every intent before invoking a key.

mod branch;
mod codec;
mod evidence;
mod lock;
mod seal;

pub use branch::{
    StateAgreement, StateBranch, StateFinality, StateProposal, StateProposalIntent, StateValue,
};
pub use evidence::{
    STATE_QUORUM_MAX_BYTES, STATE_VOTE_BYTES, StateQuorum, StateVote, StateVoteSet,
};
pub use lock::{
    StateIntent, StateLockEvent, StateLockState, StatePhase, StatePublication, StateVoteIntent,
};
pub use seal::{
    SEAL_SIGNATURE_BYTES, STATE_SEAL_MAX_BYTES, SealContext, SealRole, SealSignature, StateSeal,
};

use naome_ledger::LedgerError;
use sha2::{Digest, Sha256};

/// A rejected state consensus transition. Rejection leaves live state intact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateConsensusError {
    /// Strict framing, authority, context, or transition validation failed.
    Invalid(&'static str),
    /// A bound was exceeded before unbounded work or allocation.
    Limit(&'static str),
    /// The deterministic state transition was rejected.
    Ledger(LedgerError),
    /// A checked coordinate or length overflowed.
    Overflow,
}
impl From<LedgerError> for StateConsensusError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}
impl std::fmt::Display for StateConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid state consensus: {reason}"),
            Self::Limit(reason) => write!(f, "state consensus limit: {reason}"),
            Self::Ledger(error) => error.fmt(f),
            Self::Overflow => f.write_str("state consensus overflow"),
        }
    }
}
impl std::error::Error for StateConsensusError {}

type Result<T> = std::result::Result<T, StateConsensusError>;
fn digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for field in fields {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests;
