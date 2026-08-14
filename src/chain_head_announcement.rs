//! One bounded artifact-chain-head availability announcement.
//!
//! An announcement carries one exact [`ArtifactChainId`] and one exact
//! [`ArtifactBlockId`]. It is an untrusted observation, not a checkpoint,
//! selection decision, freshness proof, or consensus statement.

use std::error::Error;
use std::fmt;

use naome_chain::{ArtifactBlockId, ArtifactChainId};

/// Exact byte length of one artifact-chain-head announcement.
pub const ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES: usize = 64;

/// One exact artifact-chain context and peer-local selected-head observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ArtifactChainHeadAnnouncement {
    chain_id: ArtifactChainId,
    head_block_id: ArtifactBlockId,
}

impl ArtifactChainHeadAnnouncement {
    /// Constructs one exact chain-head announcement.
    pub const fn new(chain_id: ArtifactChainId, head_block_id: ArtifactBlockId) -> Self {
        Self {
            chain_id,
            head_block_id,
        }
    }

    /// Returns the announced artifact-chain context.
    pub const fn chain_id(self) -> ArtifactChainId {
        self.chain_id
    }

    /// Returns the announced peer-local selected head.
    pub const fn head_block_id(self) -> ArtifactBlockId {
        self.head_block_id
    }

    /// Encodes this announcement as `chain_id || head_block_id`.
    pub fn to_wire_bytes(self) -> [u8; ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES] {
        let mut bytes = [0_u8; ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES];
        bytes[..32].copy_from_slice(self.chain_id.as_bytes());
        bytes[32..].copy_from_slice(self.head_block_id.as_bytes());
        bytes
    }

    /// Decodes one complete artifact-chain-head announcement.
    ///
    /// Every exact 64-byte pair is syntactically valid. Decoding establishes
    /// no freshness, availability, ancestry, selection, or consensus claim.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ArtifactChainHeadAnnouncementWireError> {
        let bytes =
            <&[u8; ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES]>::try_from(bytes).map_err(|_| {
                ArtifactChainHeadAnnouncementWireError::InvalidLength {
                    actual: bytes.len(),
                    expected: ARTIFACT_CHAIN_HEAD_ANNOUNCEMENT_BYTES,
                }
            })?;
        let chain_id = ArtifactChainId::from_bytes(
            bytes[..32]
                .try_into()
                .expect("the fixed announcement prefix is 32 bytes"),
        );
        let head_block_id = ArtifactBlockId::from_bytes(
            bytes[32..]
                .try_into()
                .expect("the fixed announcement suffix is 32 bytes"),
        );
        Ok(Self::new(chain_id, head_block_id))
    }
}

/// A fail-closed artifact-chain-head announcement message error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactChainHeadAnnouncementWireError {
    /// The message is not one exact chain-ID and head-ID pair.
    InvalidLength { actual: usize, expected: usize },
}

impl fmt::Display for ArtifactChainHeadAnnouncementWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "artifact-chain-head announcement length {actual} does not equal {expected} bytes"
            ),
        }
    }
}

impl Error for ArtifactChainHeadAnnouncementWireError {}

#[cfg(test)]
mod tests;
