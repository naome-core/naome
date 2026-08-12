//! One bounded proof-chain-head availability announcement.
//!
//! An announcement carries one exact [`ProofChainId`] and one exact
//! [`ProofBlockId`]. It is an untrusted observation, not a checkpoint,
//! selection decision, freshness proof, or consensus statement.

use std::error::Error;
use std::fmt;

use naome_chain::{ProofBlockId, ProofChainId};

/// Exact byte length of one proof-chain-head announcement.
pub const PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES: usize = 64;

/// One exact proof-chain context and peer-local selected-head observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ProofChainHeadAnnouncement {
    chain_id: ProofChainId,
    head_block_id: ProofBlockId,
}

impl ProofChainHeadAnnouncement {
    /// Constructs one exact chain-head announcement.
    pub const fn new(chain_id: ProofChainId, head_block_id: ProofBlockId) -> Self {
        Self {
            chain_id,
            head_block_id,
        }
    }

    /// Returns the announced proof-chain context.
    pub const fn chain_id(self) -> ProofChainId {
        self.chain_id
    }

    /// Returns the announced peer-local selected head.
    pub const fn head_block_id(self) -> ProofBlockId {
        self.head_block_id
    }

    /// Encodes this announcement as `chain_id || head_block_id`.
    pub fn to_wire_bytes(self) -> [u8; PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES] {
        let mut bytes = [0_u8; PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES];
        bytes[..32].copy_from_slice(self.chain_id.as_bytes());
        bytes[32..].copy_from_slice(self.head_block_id.as_bytes());
        bytes
    }

    /// Decodes one complete proof-chain-head announcement.
    ///
    /// Every exact 64-byte pair is syntactically valid. Decoding establishes
    /// no freshness, availability, ancestry, selection, or consensus claim.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProofChainHeadAnnouncementWireError> {
        let bytes =
            <&[u8; PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES]>::try_from(bytes).map_err(|_| {
                ProofChainHeadAnnouncementWireError::InvalidLength {
                    actual: bytes.len(),
                    expected: PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES,
                }
            })?;
        let chain_id = ProofChainId::from_bytes(
            bytes[..32]
                .try_into()
                .expect("the fixed announcement prefix is 32 bytes"),
        );
        let head_block_id = ProofBlockId::from_bytes(
            bytes[32..]
                .try_into()
                .expect("the fixed announcement suffix is 32 bytes"),
        );
        Ok(Self::new(chain_id, head_block_id))
    }
}

/// A fail-closed proof-chain-head announcement message error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofChainHeadAnnouncementWireError {
    /// The message is not one exact chain-ID and head-ID pair.
    InvalidLength { actual: usize, expected: usize },
}

impl fmt::Display for ProofChainHeadAnnouncementWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "proof-chain-head announcement length {actual} does not equal {expected} bytes"
            ),
        }
    }
}

impl Error for ProofChainHeadAnnouncementWireError {}

#[cfg(test)]
mod tests;
