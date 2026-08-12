//! Bounded, transport-neutral exchange of one peer-local proof-chain head.
//!
//! A request carries exactly one caller-selected [`ProofChainId`]. A response
//! is one already delimited outer message: an empty message means
//! `Unavailable`, while a found response is exactly one [`ProofBlockId`].
//!
//! A reported head is an untrusted availability observation. This module
//! defines no peer authentication, freshness, ancestry synchronization,
//! checkpoint trust, consensus, finality, or selection policy.

use std::error::Error;
use std::fmt;

use naome_chain::{ProofBlockId, ProofChainId};
use naome_storage::{ProofChainJournal, ProofChainJournalError};

/// Exact byte length of one proof-chain-head request.
pub const PROOF_CHAIN_HEAD_REQUEST_BYTES: usize = ProofChainId::BYTE_LENGTH;

/// Exact byte length of one found proof-chain-head response.
pub const PROOF_CHAIN_HEAD_RESPONSE_BYTES: usize = ProofBlockId::BYTE_LENGTH;

/// A request for one peer-local head in an exact proof-chain context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ProofChainHeadRequest {
    chain_id: ProofChainId,
}

impl ProofChainHeadRequest {
    /// Constructs a request for `chain_id`.
    pub const fn new(chain_id: ProofChainId) -> Self {
        Self { chain_id }
    }

    /// Returns the requested proof-chain context.
    pub const fn chain_id(self) -> ProofChainId {
        self.chain_id
    }

    /// Encodes this request as its exact wire bytes.
    pub const fn to_wire_bytes(self) -> [u8; PROOF_CHAIN_HEAD_REQUEST_BYTES] {
        *self.chain_id.as_bytes()
    }

    /// Decodes one complete proof-chain-head request message.
    ///
    /// Any 32-byte value is a syntactically valid chain context. Decoding does
    /// not establish that a peer serves it or that any reported head is fresh,
    /// selected, or finalized.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProofChainHeadExchangeWireError> {
        let chain_id = <[u8; PROOF_CHAIN_HEAD_REQUEST_BYTES]>::try_from(bytes).map_err(|_| {
            ProofChainHeadExchangeWireError::InvalidRequestLength {
                actual: bytes.len(),
                expected: PROOF_CHAIN_HEAD_REQUEST_BYTES,
            }
        })?;
        Ok(Self::new(ProofChainId::from_bytes(chain_id)))
    }
}

/// One bounded response to a [`ProofChainHeadRequest`].
///
/// A found value is only the responding boundary's peer-local report. It is
/// not a trusted rollback anchor, checkpoint, ancestry proof, or consensus
/// statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ProofChainHeadResponse {
    head_block_id: Option<ProofBlockId>,
}

impl ProofChainHeadResponse {
    /// Decodes one complete, already delimited response message.
    ///
    /// Empty is the sole `Unavailable` representation. A found response must
    /// be exactly one raw `ProofBlockId`; every other length fails closed.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProofChainHeadExchangeWireError> {
        if bytes.is_empty() {
            return Ok(Self {
                head_block_id: None,
            });
        }
        let head_block_id =
            <[u8; PROOF_CHAIN_HEAD_RESPONSE_BYTES]>::try_from(bytes).map_err(|_| {
                ProofChainHeadExchangeWireError::InvalidResponseLength {
                    actual: bytes.len(),
                }
            })?;
        Ok(Self {
            head_block_id: Some(ProofBlockId::from_bytes(head_block_id)),
        })
    }

    /// Returns whether the serving boundary reported no head for this chain.
    pub const fn is_unavailable(&self) -> bool {
        self.head_block_id.is_none()
    }

    /// Returns the peer-local reported head, when available.
    pub const fn head_block_id(&self) -> Option<ProofBlockId> {
        self.head_block_id
    }

    /// Encodes this response without allocating.
    ///
    /// `None` is the empty unavailable message. `Some(bytes)` is the exact
    /// 32-byte found response.
    pub const fn to_wire_bytes(self) -> Option<[u8; PROOF_CHAIN_HEAD_RESPONSE_BYTES]> {
        match self.head_block_id {
            Some(block_id) => Some(*block_id.as_bytes()),
            None => None,
        }
    }
}

/// Returns the healthy journal's peer-local head for `request`, when served.
///
/// Journal health is checked before chain-context equality, so a poisoned or
/// otherwise failing journal is never converted into `Unavailable`. A matching
/// empty journal returns its virtual-genesis head as an ordinary found value.
pub fn proof_chain_head_response(
    journal: &ProofChainJournal,
    request: ProofChainHeadRequest,
) -> Result<ProofChainHeadResponse, ProofChainJournalError> {
    let head_block_id = journal.head_block_id()?;
    Ok(ProofChainHeadResponse {
        head_block_id: (journal.chain_id() == request.chain_id()).then_some(head_block_id),
    })
}

/// A fail-closed proof-chain-head exchange message error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofChainHeadExchangeWireError {
    /// A request is not exactly one raw `ProofChainId`.
    InvalidRequestLength { actual: usize, expected: usize },
    /// A response is neither empty nor exactly one raw `ProofBlockId`.
    InvalidResponseLength { actual: usize },
}

impl fmt::Display for ProofChainHeadExchangeWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestLength { actual, expected } => write!(
                formatter,
                "proof-chain-head request length {actual} does not equal {expected} bytes"
            ),
            Self::InvalidResponseLength { actual } => write!(
                formatter,
                "proof-chain-head response length {actual} is neither 0 nor {PROOF_CHAIN_HEAD_RESPONSE_BYTES} bytes"
            ),
        }
    }
}

impl Error for ProofChainHeadExchangeWireError {}

#[cfg(test)]
mod tests;
