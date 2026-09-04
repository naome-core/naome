//! Bounded, transport-neutral exchange of one peer-local artifact-chain head.
//!
//! A request carries exactly one caller-selected [`ArtifactChainId`]. A response
//! is one already delimited outer message: an empty message means
//! `Unavailable`, while a found response is exactly one [`ArtifactBlockId`].
//!
//! A reported head is an untrusted availability observation. This module
//! defines no peer authentication, freshness, ancestry synchronization,
//! checkpoint trust, consensus, finality, or selection policy.

use std::error::Error;
use std::fmt;

use naome_chain::{ArtifactBlockId, ArtifactChainId};

/// Exact byte length of one artifact-chain-head request.
pub const ARTIFACT_CHAIN_HEAD_REQUEST_BYTES: usize = ArtifactChainId::BYTE_LENGTH;

/// Exact byte length of one found artifact-chain-head response.
pub const ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES: usize = ArtifactBlockId::BYTE_LENGTH;

/// A request for one peer-local head in an exact artifact-chain context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ArtifactChainHeadRequest {
    chain_id: ArtifactChainId,
}

impl ArtifactChainHeadRequest {
    /// Constructs a request for `chain_id`.
    pub const fn new(chain_id: ArtifactChainId) -> Self {
        Self { chain_id }
    }

    /// Returns the requested artifact-chain context.
    pub const fn chain_id(self) -> ArtifactChainId {
        self.chain_id
    }

    /// Encodes this request as its exact wire bytes.
    pub const fn to_wire_bytes(self) -> [u8; ARTIFACT_CHAIN_HEAD_REQUEST_BYTES] {
        *self.chain_id.as_bytes()
    }

    /// Decodes one complete artifact-chain-head request message.
    ///
    /// Any 32-byte value is a syntactically valid chain context. Decoding does
    /// not establish that a peer serves it or that any reported head is fresh,
    /// selected, or finalized.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ArtifactChainHeadExchangeWireError> {
        let chain_id =
            <[u8; ARTIFACT_CHAIN_HEAD_REQUEST_BYTES]>::try_from(bytes).map_err(|_| {
                ArtifactChainHeadExchangeWireError::InvalidRequestLength {
                    actual: bytes.len(),
                    expected: ARTIFACT_CHAIN_HEAD_REQUEST_BYTES,
                }
            })?;
        Ok(Self::new(ArtifactChainId::from_bytes(chain_id)))
    }
}

/// One bounded response to an [`ArtifactChainHeadRequest`].
///
/// A found value is only the responding boundary's peer-local report. It is
/// not a trusted rollback anchor, checkpoint, ancestry proof, or consensus
/// statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ArtifactChainHeadResponse {
    head_block_id: Option<ArtifactBlockId>,
}

impl ArtifactChainHeadResponse {
    /// Decodes one complete, already delimited response message.
    ///
    /// Empty is the sole `Unavailable` representation. A found response must
    /// be exactly one raw `ArtifactBlockId`; every other length fails closed.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ArtifactChainHeadExchangeWireError> {
        if bytes.is_empty() {
            return Ok(Self {
                head_block_id: None,
            });
        }
        let head_block_id =
            <[u8; ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES]>::try_from(bytes).map_err(|_| {
                ArtifactChainHeadExchangeWireError::InvalidResponseLength {
                    actual: bytes.len(),
                }
            })?;
        Ok(Self {
            head_block_id: Some(ArtifactBlockId::from_bytes(head_block_id)),
        })
    }

    /// Returns whether the serving boundary reported no head for this chain.
    pub const fn is_unavailable(&self) -> bool {
        self.head_block_id.is_none()
    }

    /// Returns the peer-local reported head, when available.
    pub const fn head_block_id(&self) -> Option<ArtifactBlockId> {
        self.head_block_id
    }

    /// Encodes this response without allocating.
    ///
    /// `None` is the empty unavailable message. `Some(bytes)` is the exact
    /// 32-byte found response.
    pub const fn to_wire_bytes(self) -> Option<[u8; ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES]> {
        match self.head_block_id {
            Some(block_id) => Some(*block_id.as_bytes()),
            None => None,
        }
    }
}

/// A fail-closed artifact-chain-head exchange message error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactChainHeadExchangeWireError {
    /// A request is not exactly one raw `ArtifactChainId`.
    InvalidRequestLength { actual: usize, expected: usize },
    /// A response is neither empty nor exactly one raw `ArtifactBlockId`.
    InvalidResponseLength { actual: usize },
}

impl fmt::Display for ArtifactChainHeadExchangeWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestLength { actual, expected } => write!(
                formatter,
                "artifact-chain-head request length {actual} does not equal {expected} bytes"
            ),
            Self::InvalidResponseLength { actual } => write!(
                formatter,
                "artifact-chain-head response length {actual} is neither 0 nor {ARTIFACT_CHAIN_HEAD_RESPONSE_BYTES} bytes"
            ),
        }
    }
}

impl Error for ArtifactChainHeadExchangeWireError {}

#[cfg(test)]
mod tests;
