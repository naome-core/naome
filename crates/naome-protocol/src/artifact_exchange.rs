//! Bounded transport-neutral exchange of one content-addressed artifact.
//!
//! A request carries exactly one [`ArtifactId`]. An empty response means
//! `Unavailable`; a nonempty response carries candidate bytes for one tagged
//! [`naome_proof::ArtifactPayload`]. The bytes stay untrusted until a strict
//! consumer decodes them, checks the proof or definition against its selected
//! prior state, and requires the resulting identity to equal the immutable
//! request address.
//!
//! This module defines no sockets, peers, retries, recursive dependency
//! fetching, authentication, consensus, or chain selection.

use std::error::Error;
use std::fmt;

use naome_proof::{ARTIFACT_PAYLOAD_MAX_BYTES, ArtifactId};

/// Exact byte length of one artifact request.
pub const ARTIFACT_REQUEST_BYTES: usize = ArtifactId::BYTE_LENGTH;

/// Maximum byte length of one artifact response message.
pub const ARTIFACT_RESPONSE_MAX_BYTES: usize = ARTIFACT_PAYLOAD_MAX_BYTES;

/// A request for one exact content-addressed proof or definition artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ArtifactRequest {
    artifact_id: ArtifactId,
}

impl ArtifactRequest {
    /// Constructs a request for `artifact_id`.
    pub const fn new(artifact_id: ArtifactId) -> Self {
        Self { artifact_id }
    }

    /// Returns the requested artifact address.
    pub const fn artifact_id(self) -> ArtifactId {
        self.artifact_id
    }

    /// Encodes this request as its exact wire bytes.
    pub const fn to_wire_bytes(self) -> [u8; ARTIFACT_REQUEST_BYTES] {
        *self.artifact_id.as_bytes()
    }

    /// Decodes one complete artifact-request message.
    ///
    /// Any 32-byte value is a syntactically valid address. Decoding establishes
    /// neither existence nor mathematical validity.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ArtifactExchangeWireError> {
        let artifact_id = <[u8; ARTIFACT_REQUEST_BYTES]>::try_from(bytes).map_err(|_| {
            ArtifactExchangeWireError::InvalidRequestLength {
                actual: bytes.len(),
                expected: ARTIFACT_REQUEST_BYTES,
            }
        })?;
        Ok(Self::new(ArtifactId::from_bytes(artifact_id)))
    }
}

/// One bounded response to an [`ArtifactRequest`].
///
/// A found response owns the exact candidate wire allocation. Its claimed
/// [`naome_proof::ArtifactPayload`] structure and identity remain deliberately
/// unchecked at
/// this transport-neutral boundary.
#[must_use]
pub struct ArtifactResponse {
    candidate_artifact_bytes: Option<Vec<u8>>,
}

impl ArtifactResponse {
    /// Decodes one complete, already delimited response message.
    ///
    /// Length is rejected before any payload parsing or further allocation.
    pub fn from_wire_bytes(bytes: Vec<u8>) -> Result<Self, ArtifactExchangeWireError> {
        if bytes.len() > ARTIFACT_RESPONSE_MAX_BYTES {
            return Err(ArtifactExchangeWireError::ResponseTooLong {
                actual: bytes.len(),
                maximum: ARTIFACT_RESPONSE_MAX_BYTES,
            });
        }
        Ok(Self {
            candidate_artifact_bytes: (!bytes.is_empty()).then_some(bytes),
        })
    }

    /// Returns whether this peer reported the artifact unavailable.
    pub const fn is_unavailable(&self) -> bool {
        self.candidate_artifact_bytes.is_none()
    }

    /// Consumes this response and returns its exact wire allocation.
    pub fn into_wire_bytes(self) -> Vec<u8> {
        self.candidate_artifact_bytes.unwrap_or_default()
    }
}

impl fmt::Debug for ArtifactResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactResponse")
            .field("unavailable", &self.is_unavailable())
            .field(
                "candidate_artifact_bytes_len",
                &self.candidate_artifact_bytes.as_ref().map_or(0, Vec::len),
            )
            .finish()
    }
}

/// A fail-closed artifact-exchange message-shape error.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactExchangeWireError {
    /// A request is not exactly one raw [`ArtifactId`].
    InvalidRequestLength { actual: usize, expected: usize },
    /// A response exceeds the tagged artifact-payload byte limit.
    ResponseTooLong { actual: usize, maximum: usize },
}

impl fmt::Display for ArtifactExchangeWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestLength { actual, expected } => write!(
                formatter,
                "artifact request length {actual} does not equal {expected} bytes"
            ),
            Self::ResponseTooLong { actual, maximum } => write!(
                formatter,
                "artifact response length {actual} exceeds maximum {maximum}"
            ),
        }
    }
}

impl Error for ArtifactExchangeWireError {}

#[cfg(test)]
mod tests;
