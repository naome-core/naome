//! Bounded, transport-neutral exchange of one content-addressed proof.
//!
//! A request carries exactly one [`ProofId`]. A response is one already
//! delimited outer message: an empty message means `Unavailable`, while a
//! nonempty message carries candidate canonical proof bytes. The transport must
//! distinguish a successfully completed empty response from transport failure
//! and reject an announced response length above
//! [`PROOF_RESPONSE_MAX_BYTES`] before allocating its body.
//!
//! This module defines no sockets, peers, retries, dependency fetching,
//! authentication, consensus, or proof selection. Received proof bytes remain
//! unselected until a higher layer explicitly promotes a complete addressed
//! closure.

use std::error::Error;
use std::fmt;

use naome_proof::{CERTIFICATE_MAX_BYTES, ProofId};

/// Exact byte length of one proof request.
pub const PROOF_REQUEST_BYTES: usize = ProofId::BYTE_LENGTH;

/// Maximum byte length of one proof response message.
pub const PROOF_RESPONSE_MAX_BYTES: usize = CERTIFICATE_MAX_BYTES;

/// A request for one exact content-addressed proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ProofRequest {
    proof_id: ProofId,
}

impl ProofRequest {
    /// Constructs a request for `proof_id`.
    pub const fn new(proof_id: ProofId) -> Self {
        Self { proof_id }
    }

    /// Returns the requested proof address.
    pub const fn proof_id(self) -> ProofId {
        self.proof_id
    }

    /// Encodes this request as its exact wire bytes.
    pub const fn to_wire_bytes(self) -> [u8; PROOF_REQUEST_BYTES] {
        *self.proof_id.as_bytes()
    }

    /// Decodes one complete proof-request message.
    ///
    /// Any 32-byte value is a syntactically valid address. Decoding does not
    /// establish that the proof exists or has been checked.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProofExchangeWireError> {
        let proof_id = <[u8; PROOF_REQUEST_BYTES]>::try_from(bytes).map_err(|_| {
            ProofExchangeWireError::InvalidRequestLength {
                actual: bytes.len(),
                expected: PROOF_REQUEST_BYTES,
            }
        })?;
        Ok(Self::new(ProofId::from_bytes(proof_id)))
    }
}

/// One bounded response to a [`ProofRequest`].
///
/// Fields are private so an oversized candidate cannot bypass
/// [`Self::from_wire_bytes`]. The type is intentionally not cloneable because
/// one response may own the maximum-size proof payload.
#[must_use]
pub struct ProofResponse {
    candidate_proof_bytes: Option<Vec<u8>>,
}

impl ProofResponse {
    /// Decodes one complete, already delimited response message.
    ///
    /// An empty message is `Unavailable`. Every nonempty message is a proof
    /// candidate whose structure, canonicality, mathematics, dependencies,
    /// and identity remain untrusted.
    pub fn from_wire_bytes(bytes: Vec<u8>) -> Result<Self, ProofExchangeWireError> {
        if bytes.len() > PROOF_RESPONSE_MAX_BYTES {
            return Err(ProofExchangeWireError::ResponseTooLong {
                actual: bytes.len(),
                maximum: PROOF_RESPONSE_MAX_BYTES,
            });
        }
        Ok(Self {
            candidate_proof_bytes: (!bytes.is_empty()).then_some(bytes),
        })
    }

    /// Returns whether the sender reported that it has no response payload.
    ///
    /// This is only one untrusted peer's answer. It is not evidence that the
    /// proof is globally absent or absent from any authenticated proof set.
    pub const fn is_unavailable(&self) -> bool {
        self.candidate_proof_bytes.is_none()
    }

    /// Consumes this response and returns its exact wire message.
    pub fn into_wire_bytes(self) -> Vec<u8> {
        self.candidate_proof_bytes.unwrap_or_default()
    }
}

impl fmt::Debug for ProofResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofResponse")
            .field("unavailable", &self.is_unavailable())
            .field(
                "candidate_proof_bytes_len",
                &self.candidate_proof_bytes.as_ref().map_or(0, Vec::len),
            )
            .finish()
    }
}

/// A fail-closed proof-exchange message-shape error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofExchangeWireError {
    /// A request is not exactly one raw `ProofId`.
    InvalidRequestLength { actual: usize, expected: usize },
    /// A response exceeds the proof certificate byte limit.
    ResponseTooLong { actual: usize, maximum: usize },
}

impl fmt::Display for ProofExchangeWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestLength { actual, expected } => write!(
                formatter,
                "proof request length {actual} does not equal {expected} bytes"
            ),
            Self::ResponseTooLong { actual, maximum } => write!(
                formatter,
                "proof response length {actual} exceeds maximum {maximum}"
            ),
        }
    }
}

impl Error for ProofExchangeWireError {}

#[cfg(test)]
mod tests;
