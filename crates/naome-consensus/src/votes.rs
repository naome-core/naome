//! In-memory vote role, target, and opaque proposal identity.

/// An opaque evidence-free proposal signing root observed in a vote.
///
/// Constructing this value does not derive the root or establish that any
/// proposal, block, payload, or state transition exists or is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProposalSigningRoot([u8; Self::BYTE_LENGTH]);

impl ProposalSigningRoot {
    /// Exact width of one proposal signing root.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an observed proposal signing root from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw proposal signing-root bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

/// The separately signed Tendermint agreement-message role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub enum ConsensusVoteRole {
    /// A prevote for nil or one proposal signing root.
    Prevote,
    /// A precommit for nil or one proposal signing root.
    Precommit,
}

/// The exact nil-or-proposal target carried by one agreement message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub enum ConsensusVoteTarget {
    /// The validator votes for no proposal at this position.
    Nil,
    /// The validator votes for this opaque proposal signing root.
    Proposal(ProposalSigningRoot),
}
