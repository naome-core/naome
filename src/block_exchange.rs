//! Bounded, transport-neutral exchange of one content-addressed proof block.
//!
//! A request carries exactly one [`ProofBlockId`]. A response is one already
//! delimited outer message: an empty message means `Unavailable`, while a
//! nonempty message must be one complete canonical [`ProofBlock`] whose
//! computed identity equals the immutable request address.
//!
//! This module defines no sockets, peers, retries, announcements, ancestry
//! synchronization, proof-payload transport, chain selection, consensus, or
//! economy.

use std::error::Error;
use std::fmt;

use naome_chain::{PROOF_BLOCK_MAX_BYTES, ProofBlock, ProofBlockDecodeError, ProofBlockId};
use naome_storage::{ProofChainJournal, ProofChainJournalError};

/// Exact byte length of one proof-block request.
pub const PROOF_BLOCK_REQUEST_BYTES: usize = 32;

/// Maximum byte length of one proof-block response message.
pub const PROOF_BLOCK_RESPONSE_MAX_BYTES: usize = PROOF_BLOCK_MAX_BYTES;

/// A request for one exact content-addressed proof block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ProofBlockRequest {
    block_id: ProofBlockId,
}

impl ProofBlockRequest {
    /// Constructs a request for `block_id`.
    pub const fn new(block_id: ProofBlockId) -> Self {
        Self { block_id }
    }

    /// Returns the requested block address.
    pub const fn block_id(self) -> ProofBlockId {
        self.block_id
    }

    /// Encodes this request as its exact wire bytes.
    pub const fn to_wire_bytes(self) -> [u8; PROOF_BLOCK_REQUEST_BYTES] {
        *self.block_id.as_bytes()
    }

    /// Decodes one complete proof-block request message.
    ///
    /// Any 32-byte value is a syntactically valid address. Decoding does not
    /// establish that the block exists, belongs to a configured chain, or was
    /// selected.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProofBlockExchangeWireError> {
        let block_id = <[u8; PROOF_BLOCK_REQUEST_BYTES]>::try_from(bytes).map_err(|_| {
            ProofBlockExchangeWireError::InvalidRequestLength {
                actual: bytes.len(),
                expected: PROOF_BLOCK_REQUEST_BYTES,
            }
        })?;
        Ok(Self::new(ProofBlockId::from_bytes(block_id)))
    }
}

/// One bounded response to a [`ProofBlockRequest`].
///
/// A found response owns only a strictly decoded block whose computed identity
/// already matched the immutable request. Raw mismatched bytes cannot be
/// exposed through this type.
#[derive(Debug)]
#[must_use]
pub struct ProofBlockResponse {
    block: Option<ProofBlock>,
}

impl ProofBlockResponse {
    /// Decodes one complete, already delimited response message for `request`.
    ///
    /// An empty message is `Unavailable`. A nonempty message is decoded as one
    /// complete canonical block, then its computed identity must equal the
    /// requested address before the block is retained.
    pub fn from_wire_bytes(
        request: ProofBlockRequest,
        bytes: &[u8],
    ) -> Result<Self, ProofBlockExchangeWireError> {
        if bytes.is_empty() {
            return Ok(Self { block: None });
        }
        if bytes.len() > PROOF_BLOCK_RESPONSE_MAX_BYTES {
            return Err(ProofBlockExchangeWireError::ResponseTooLong {
                actual: bytes.len(),
                maximum: PROOF_BLOCK_RESPONSE_MAX_BYTES,
            });
        }

        let block = ProofBlock::from_canonical_bytes(bytes)
            .map_err(|source| ProofBlockExchangeWireError::BlockDecode { source })?;
        let actual = block.id();
        let expected = request.block_id();
        if actual != expected {
            return Err(ProofBlockExchangeWireError::BlockIdMismatch { expected, actual });
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
    pub fn into_block(self) -> Option<ProofBlock> {
        self.block
    }

    /// Encodes this response as its exact transport-neutral message.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.block
            .as_ref()
            .map_or_else(Vec::new, ProofBlock::to_canonical_bytes)
    }
}

/// Returns one locally committed selected block for `request`, when present.
///
/// The returned value is borrowed directly from the healthy journal. `None`
/// describes only this local selected history. Journal poisoning and every
/// other storage error are preserved rather than converted to `Unavailable`.
pub fn proof_block_response(
    journal: &ProofChainJournal,
    request: ProofBlockRequest,
) -> Result<Option<&ProofBlock>, ProofChainJournalError> {
    journal.block(request.block_id())
}

/// A fail-closed proof-block exchange message error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofBlockExchangeWireError {
    /// A request is not exactly one raw `ProofBlockId`.
    InvalidRequestLength { actual: usize, expected: usize },
    /// A response exceeds the canonical proof-block byte limit.
    ResponseTooLong { actual: usize, maximum: usize },
    /// A nonempty response is not one complete canonical proof block.
    BlockDecode { source: ProofBlockDecodeError },
    /// A canonical response block does not match the immutable request address.
    BlockIdMismatch {
        expected: ProofBlockId,
        actual: ProofBlockId,
    },
}

impl fmt::Display for ProofBlockExchangeWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestLength { actual, expected } => write!(
                formatter,
                "proof-block request length {actual} does not equal {expected} bytes"
            ),
            Self::ResponseTooLong { actual, maximum } => write!(
                formatter,
                "proof-block response length {actual} exceeds maximum {maximum}"
            ),
            Self::BlockDecode { source } => {
                write!(formatter, "proof-block response is malformed: {source}")
            }
            Self::BlockIdMismatch { expected, actual } => write!(
                formatter,
                "proof-block response identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
        }
    }
}

impl Error for ProofBlockExchangeWireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BlockDecode { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
