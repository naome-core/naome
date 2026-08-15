//! Bounded, transport-neutral exchange of one content-addressed artifact block.
//!
//! A request carries exactly one [`ArtifactBlockId`]. A response is one already
//! delimited outer message: an empty message means `Unavailable`, while a
//! nonempty message must be one complete canonical [`ArtifactBlock`] whose
//! computed identity equals the immutable request address.
//!
//! This module defines no sockets, peers, retries, announcements, ancestry
//! synchronization, artifact-payload transport, chain selection, consensus, or
//! economy.

use std::error::Error;
use std::fmt;

use naome_chain::{ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockDecodeError, ArtifactBlockId};

/// Exact byte length of one artifact-block request.
pub const ARTIFACT_BLOCK_REQUEST_BYTES: usize = ArtifactBlockId::BYTE_LENGTH;

/// Maximum byte length of one artifact-block response message.
pub const ARTIFACT_BLOCK_RESPONSE_MAX_BYTES: usize = ARTIFACT_BLOCK_BYTES;

/// A request for one exact content-addressed artifact block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ArtifactBlockRequest {
    block_id: ArtifactBlockId,
}

impl ArtifactBlockRequest {
    /// Constructs a request for `block_id`.
    pub const fn new(block_id: ArtifactBlockId) -> Self {
        Self { block_id }
    }

    /// Returns the requested block address.
    pub const fn block_id(self) -> ArtifactBlockId {
        self.block_id
    }

    /// Encodes this request as its exact wire bytes.
    pub const fn to_wire_bytes(self) -> [u8; ARTIFACT_BLOCK_REQUEST_BYTES] {
        *self.block_id.as_bytes()
    }

    /// Decodes one complete artifact-block request message.
    ///
    /// Any 32-byte value is a syntactically valid address. Decoding does not
    /// establish that the block exists, belongs to a configured chain, or was
    /// selected.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ArtifactBlockExchangeWireError> {
        let block_id = <[u8; ARTIFACT_BLOCK_REQUEST_BYTES]>::try_from(bytes).map_err(|_| {
            ArtifactBlockExchangeWireError::InvalidRequestLength {
                actual: bytes.len(),
                expected: ARTIFACT_BLOCK_REQUEST_BYTES,
            }
        })?;
        Ok(Self::new(ArtifactBlockId::from_bytes(block_id)))
    }
}

/// One bounded response to a [`ArtifactBlockRequest`].
///
/// A found response owns only a strictly decoded block whose computed identity
/// already matched the immutable request. Raw mismatched bytes cannot be
/// exposed through this type.
#[derive(Debug)]
#[must_use]
pub struct ArtifactBlockResponse {
    block: Option<ArtifactBlock>,
}

impl ArtifactBlockResponse {
    /// Decodes one complete, already delimited response message for `request`.
    ///
    /// An empty message is `Unavailable`. A nonempty message is decoded as one
    /// complete canonical block, then its computed identity must equal the
    /// requested address before the block is retained.
    pub fn from_wire_bytes(
        request: ArtifactBlockRequest,
        bytes: &[u8],
    ) -> Result<Self, ArtifactBlockExchangeWireError> {
        if bytes.is_empty() {
            return Ok(Self { block: None });
        }
        if bytes.len() > ARTIFACT_BLOCK_RESPONSE_MAX_BYTES {
            return Err(ArtifactBlockExchangeWireError::ResponseTooLong {
                actual: bytes.len(),
                maximum: ARTIFACT_BLOCK_RESPONSE_MAX_BYTES,
            });
        }

        let block = ArtifactBlock::from_canonical_bytes(bytes)
            .map_err(|source| ArtifactBlockExchangeWireError::BlockDecode { source })?;
        let actual = block.id();
        let expected = request.block_id();
        if actual != expected {
            return Err(ArtifactBlockExchangeWireError::BlockIdMismatch { expected, actual });
        }

        Ok(Self { block: Some(block) })
    }

    /// Returns whether the sender reported that it has no response block.
    ///
    /// This is only one untrusted sender's answer. It is not evidence of global
    /// absence or non-membership in any selected or finalized chain.
    pub const fn is_unavailable(&self) -> bool {
        self.block.is_none()
    }

    /// Consumes this response and returns the matched decoded block, when found.
    pub fn into_block(self) -> Option<ArtifactBlock> {
        self.block
    }

    /// Encodes this response as its exact transport-neutral message.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.block
            .as_ref()
            .map_or_else(Vec::new, |block| block.to_canonical_bytes().to_vec())
    }
}

/// A fail-closed artifact-block exchange message error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactBlockExchangeWireError {
    /// A request is not exactly one raw `ArtifactBlockId`.
    InvalidRequestLength { actual: usize, expected: usize },
    /// A response exceeds the canonical artifact-block byte limit.
    ResponseTooLong { actual: usize, maximum: usize },
    /// A nonempty response is not one complete canonical artifact block.
    BlockDecode { source: ArtifactBlockDecodeError },
    /// A canonical response block does not match the immutable request address.
    BlockIdMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
}

impl fmt::Display for ArtifactBlockExchangeWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestLength { actual, expected } => write!(
                formatter,
                "artifact-block request length {actual} does not equal {expected} bytes"
            ),
            Self::ResponseTooLong { actual, maximum } => write!(
                formatter,
                "artifact-block response length {actual} exceeds maximum {maximum}"
            ),
            Self::BlockDecode { source } => {
                write!(formatter, "artifact-block response is malformed: {source}")
            }
            Self::BlockIdMismatch { expected, actual } => write!(
                formatter,
                "artifact-block response identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
        }
    }
}

impl Error for ArtifactBlockExchangeWireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BlockDecode { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
