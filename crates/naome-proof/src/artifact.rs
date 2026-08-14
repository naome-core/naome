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
        let (tag, payload) = match self {
            Self::Proof(proof) => (PROOF, proof.to_canonical_bytes()),
            Self::Definition(definition) => (DEFINITION, definition.to_canonical_bytes()),
        };
        let mut bytes = Vec::with_capacity(1 + payload.len());
        bytes.push(tag);
        bytes.extend_from_slice(&payload);
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
mod tests {
    use super::*;
    use crate::{DefinedFormula, ProofStep};
    use naome_foundation::FreeVariable;

    #[test]
    fn proof_and_definition_envelopes_have_exact_distinct_tags() {
        let proof = ProofCertificate::new(vec![ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(7),
        }])
        .unwrap();
        let proof_inner = proof.to_canonical_bytes();
        let proof_payload = ArtifactPayload::Proof(proof);
        let proof_bytes = proof_payload.to_canonical_bytes();
        assert_eq!(proof_bytes[0], PROOF);
        assert_eq!(&proof_bytes[1..], proof_inner);
        assert_eq!(
            ArtifactPayload::from_canonical_bytes(&proof_bytes).unwrap(),
            proof_payload
        );

        let definition = DefinitionCertificate::relation(
            1,
            DefinedFormula::equal(FreeVariable::new(0), FreeVariable::new(0)),
        )
        .unwrap();
        let definition_inner = definition.to_canonical_bytes();
        let definition_payload = ArtifactPayload::Definition(definition);
        let definition_bytes = definition_payload.to_canonical_bytes();
        assert_eq!(definition_bytes[0], DEFINITION);
        assert_eq!(&definition_bytes[1..], definition_inner);
        assert_eq!(
            ArtifactPayload::from_canonical_bytes(&definition_bytes).unwrap(),
            definition_payload
        );
    }

    #[test]
    fn envelope_rejects_empty_unknown_and_typed_mismatch() {
        assert_eq!(
            ArtifactPayload::from_canonical_bytes(&[]),
            Err(ArtifactPayloadError::UnexpectedEnd)
        );
        assert_eq!(
            ArtifactPayload::from_canonical_bytes(&[0xff]),
            Err(ArtifactPayloadError::UnknownTag(0xff))
        );
        assert!(matches!(
            ArtifactPayload::from_canonical_bytes(&[DEFINITION, 0, 0, 0, 1, 0x06, 0, 0, 0, 7]),
            Err(ArtifactPayloadError::Definition(_))
        ));
    }
}
