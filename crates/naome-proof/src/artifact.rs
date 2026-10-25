use std::error::Error;
use std::fmt;

use crate::{
    CERTIFICATE_MAX_BYTES, DEFINITION_MAX_BYTES, DefinitionCertificate, DefinitionCertificateError,
    ProofCertificate, ProofCertificateError,
};

const PROOF: u8 = 0x00;
const DEFINITION: u8 = 0x01;

/// Maximum canonical byte length of one typed artifact payload.
pub const ARTIFACT_PAYLOAD_MAX_BYTES: usize = 1 + if CERTIFICATE_MAX_BYTES > DEFINITION_MAX_BYTES {
    CERTIFICATE_MAX_BYTES
} else {
    DEFINITION_MAX_BYTES
};

/// One canonically tagged mathematical artifact payload.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum ArtifactPayload {
    /// One structurally valid proof certificate.
    Proof(ProofCertificate),
    /// One structurally valid conservative definition certificate.
    Definition(DefinitionCertificate),
}

impl ArtifactPayload {
    /// Canonical envelope tag for a proof certificate.
    pub const PROOF_TAG: u8 = PROOF;

    /// Canonical envelope tag for a definition certificate.
    pub const DEFINITION_TAG: u8 = DEFINITION;

    /// Encodes the typed payload with its canonical one-byte tag.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let (tag, mut bytes) = match self {
            Self::Proof(proof) => (PROOF, proof.to_canonical_bytes()),
            Self::Definition(definition) => (DEFINITION, definition.to_canonical_bytes()),
        };
        bytes.reserve(1);
        bytes.insert(0, tag);
        bytes
    }

    /// Decodes one complete canonical typed artifact payload.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ArtifactPayloadError> {
        if bytes.len() > ARTIFACT_PAYLOAD_MAX_BYTES {
            return Err(ArtifactPayloadError::InputTooLong {
                actual: bytes.len(),
                maximum: ARTIFACT_PAYLOAD_MAX_BYTES,
            });
        }
        let (&tag, payload) = bytes
            .split_first()
            .ok_or(ArtifactPayloadError::UnexpectedEnd)?;
        match tag {
            PROOF => ProofCertificate::from_canonical_bytes(payload)
                .map(Self::Proof)
                .map_err(ArtifactPayloadError::Proof),
            DEFINITION => DefinitionCertificate::from_canonical_bytes(payload)
                .map(Self::Definition)
                .map_err(ArtifactPayloadError::Definition),
            tag => Err(ArtifactPayloadError::UnknownTag(tag)),
        }
    }
}

/// A malformed or unsupported canonical artifact envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactPayloadError {
    /// The envelope exceeds the deterministic byte limit.
    InputTooLong { actual: usize, maximum: usize },
    /// The byte sequence contains no artifact tag.
    UnexpectedEnd,
    /// The envelope uses an unknown artifact tag.
    UnknownTag(u8),
    /// The proof payload is structurally invalid.
    Proof(ProofCertificateError),
    /// The definition payload is structurally invalid.
    Definition(DefinitionCertificateError),
}

impl fmt::Display for ArtifactPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "artifact payload has {actual} bytes; the limit is {maximum}"
            ),
            Self::UnexpectedEnd => formatter.write_str("artifact payload has no type tag"),
            Self::UnknownTag(tag) => write!(formatter, "unknown artifact payload tag {tag:#04x}"),
            Self::Proof(source) => write!(formatter, "invalid proof artifact: {source}"),
            Self::Definition(source) => write!(formatter, "invalid definition artifact: {source}"),
        }
    }
}

impl Error for ArtifactPayloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Proof(source) => Some(source),
            Self::Definition(source) => Some(source),
            Self::InputTooLong { .. } | Self::UnexpectedEnd | Self::UnknownTag(_) => None,
        }
    }
}

#[cfg(test)]
mod tests;
