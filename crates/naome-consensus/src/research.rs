//! Fixed-validator consensus for complete research records.
//!
//! Research values and signatures have separate versioned domains from the V0
//! artifact protocol. The fixed-set proposer arithmetic and weighted quorum
//! predicates are shared. This module supplies verification and unsigned
//! intents; storage must durably anchor every intent before invoking a key.

mod branch;
mod codec;
mod evidence;
mod lock;

pub use branch::{
    ResearchBranch, ResearchFinality, ResearchProposal, ResearchProposalIntent, ResearchValue,
};
pub use evidence::{
    RESEARCH_QUORUM_MAX_BYTES, RESEARCH_VOTE_BYTES, ResearchQuorum, ResearchVote, ResearchVoteSet,
};
pub use lock::{
    ResearchIntent, ResearchLockEvent, ResearchLockState, ResearchPhase, ResearchPublication,
    ResearchVoteIntent,
};

use naome_research::ResearchError;
use sha2::{Digest, Sha256};

/// A rejected research consensus transition. Rejection leaves live state intact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResearchConsensusError {
    /// Strict framing, authority, context, or transition validation failed.
    Invalid(&'static str),
    /// A bound was exceeded before unbounded work or allocation.
    Limit(&'static str),
    /// The deterministic research transition was rejected.
    Research(ResearchError),
    /// A checked coordinate or length overflowed.
    Overflow,
}
impl From<ResearchError> for ResearchConsensusError {
    fn from(error: ResearchError) -> Self {
        Self::Research(error)
    }
}
impl std::fmt::Display for ResearchConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid research consensus: {reason}"),
            Self::Limit(reason) => write!(f, "research consensus limit: {reason}"),
            Self::Research(error) => error.fmt(f),
            Self::Overflow => f.write_str("research consensus overflow"),
        }
    }
}
impl std::error::Error for ResearchConsensusError {}

type Result<T> = std::result::Result<T, ResearchConsensusError>;
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
