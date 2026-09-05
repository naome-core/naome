//! Canonical, caller-authority-bound producer-authorization verification.

use std::error::Error;
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use naome_chain::ArtifactChainId;

use super::agreement_evidence::{ContextMismatch, verify_context};
use super::{
    ActiveAgreementSnapshot, ConsensusContextV0, ConsensusGenesisId, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusProtocolVersion, ConsensusRound, ConsensusSignature,
    ProposalSigningRoot,
};

const PRODUCER_AUTHORIZATION_SIGNING_DOMAIN: &[u8] = b"naome:consensus-producer-authorization:v0\0";

const CHAIN_ID_OFFSET: usize = 0;
const GENESIS_ID_OFFSET: usize = CHAIN_ID_OFFSET + ArtifactChainId::BYTE_LENGTH;
const PROTOCOL_VERSION_OFFSET: usize = GENESIS_ID_OFFSET + ConsensusGenesisId::BYTE_LENGTH;
const HEIGHT_OFFSET: usize = PROTOCOL_VERSION_OFFSET + ConsensusProtocolVersion::BYTE_LENGTH;
const ROUND_OFFSET: usize = HEIGHT_OFFSET + 8;
const PROPOSAL_ROOT_OFFSET: usize = ROUND_OFFSET + 8;
const AUTHORIZATION_BODY_BYTES: usize = PROPOSAL_ROOT_OFFSET + ProposalSigningRoot::BYTE_LENGTH;
const PROPOSER_KEY_OFFSET: usize = AUTHORIZATION_BODY_BYTES;
const SIGNATURE_OFFSET: usize = PROPOSER_KEY_OFFSET + super::CONSENSUS_KEY_BYTES;
const PRODUCER_AUTHORIZATION_BYTES: usize = SIGNATURE_OFFSET + super::CONSENSUS_SIGNATURE_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuthorizationBody {
    context: ConsensusContextV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
}

impl AuthorizationBody {
    fn to_canonical_bytes(self) -> [u8; AUTHORIZATION_BODY_BYTES] {
        let mut bytes = [0_u8; AUTHORIZATION_BODY_BYTES];
        bytes[CHAIN_ID_OFFSET..GENESIS_ID_OFFSET]
            .copy_from_slice(self.context.chain_id().as_bytes());
        bytes[GENESIS_ID_OFFSET..PROTOCOL_VERSION_OFFSET]
            .copy_from_slice(self.context.genesis_id().as_bytes());
        bytes[PROTOCOL_VERSION_OFFSET..HEIGHT_OFFSET]
            .copy_from_slice(&self.context.protocol_version().value().to_be_bytes());
        bytes[HEIGHT_OFFSET..ROUND_OFFSET]
            .copy_from_slice(&self.position.height().value().to_be_bytes());
        bytes[ROUND_OFFSET..PROPOSAL_ROOT_OFFSET]
            .copy_from_slice(&self.position.round().value().to_be_bytes());
        bytes[PROPOSAL_ROOT_OFFSET..].copy_from_slice(self.proposal_signing_root.as_bytes());
        bytes
    }
}

/// One canonical producer authorization whose proposer signature, expected
/// identity, active membership, context, and position have been verified.
///
/// The borrowed snapshot is caller-supplied verification context rather than
/// proposer-selection or canonical-state authority. Success authenticates one
/// opaque proposal signing root but does not derive or validate that root,
/// establish proposal validity or availability, select a proposer or block,
/// execute consensus, create a signature, mutate or persist state, trust a
/// network peer, or establish finality.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct VerifiedProducerAuthorizationV0<'snapshot> {
    body: AuthorizationBody,
    proposer: ConsensusKey,
    signature: ConsensusSignature,
    _snapshot: &'snapshot ActiveAgreementSnapshot,
}

impl<'snapshot> VerifiedProducerAuthorizationV0<'snapshot> {
    /// Exact canonical width of one complete producer authorization.
    pub const BYTE_LENGTH: usize = PRODUCER_AUTHORIZATION_BYTES;

    /// Strictly decodes and verifies one complete producer authorization.
    ///
    /// Verification rejects framing and the reserved genesis height before
    /// comparing the embedded context, snapshot position, and exact
    /// caller-designated proposer. It then requires that proposer to be active
    /// in the borrowed snapshot before parsing its raw Ed25519 key and strictly
    /// verifying the direct role-domain-prefixed signing transcript.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        expected_proposer: ConsensusKey,
        snapshot: &'snapshot ActiveAgreementSnapshot,
    ) -> Result<Self, ProducerAuthorizationVerifyError> {
        if bytes.len() != PRODUCER_AUTHORIZATION_BYTES {
            return Err(ProducerAuthorizationVerifyError::InvalidLength {
                actual: bytes.len(),
                expected: PRODUCER_AUTHORIZATION_BYTES,
            });
        }

        let body = decode_authorization_body(&bytes[..AUTHORIZATION_BODY_BYTES])?;
        verify_context(body.context, expected_context)
            .map_err(ProducerAuthorizationVerifyError::from)?;
        if body.position != snapshot.position() {
            return Err(ProducerAuthorizationVerifyError::SnapshotPositionMismatch {
                authorization: body.position,
                snapshot: snapshot.position(),
            });
        }

        let proposer = ConsensusKey::from_bytes(
            bytes[PROPOSER_KEY_OFFSET..SIGNATURE_OFFSET]
                .try_into()
                .expect("the fixed producer key field is 32 bytes"),
        );
        if proposer != expected_proposer {
            return Err(ProducerAuthorizationVerifyError::UnexpectedProposer {
                expected: expected_proposer,
                actual: proposer,
            });
        }
        let _ = snapshot
            .agreement_weight_for(proposer)
            .map_err(|_| ProducerAuthorizationVerifyError::InactiveProposer { proposer })?;

        let signature = ConsensusSignature::from_bytes(
            bytes[SIGNATURE_OFFSET..]
                .try_into()
                .expect("the fixed producer signature field is 64 bytes"),
        );
        verify_signature(body, proposer, signature)?;

        Ok(Self {
            body,
            proposer,
            signature,
            _snapshot: snapshot,
        })
    }

    /// Returns the exact embedded verification context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.body.context
    }

    /// Returns the exact embedded height and round.
    pub const fn position(&self) -> ConsensusPosition {
        self.body.position
    }

    /// Returns the authenticated opaque proposal signing root.
    pub const fn proposal_signing_root(&self) -> ProposalSigningRoot {
        self.body.proposal_signing_root
    }

    /// Returns the authenticated caller-designated proposer key.
    pub const fn proposer(&self) -> ConsensusKey {
        self.proposer
    }

    /// Returns the verified raw Ed25519 signature.
    pub const fn signature(&self) -> ConsensusSignature {
        self.signature
    }

    /// Encodes the complete authorization in its sole canonical representation.
    pub fn to_canonical_bytes(&self) -> [u8; PRODUCER_AUTHORIZATION_BYTES] {
        let mut bytes = [0_u8; PRODUCER_AUTHORIZATION_BYTES];
        bytes[..AUTHORIZATION_BODY_BYTES].copy_from_slice(&self.body.to_canonical_bytes());
        bytes[PROPOSER_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(self.proposer.as_bytes());
        bytes[SIGNATURE_OFFSET..].copy_from_slice(self.signature.as_bytes());
        bytes
    }
}

pub(crate) fn inspect_authorization_route(
    bytes: &[u8],
) -> Result<(ConsensusContextV0, ConsensusPosition), ProducerAuthorizationVerifyError> {
    if bytes.len() != PRODUCER_AUTHORIZATION_BYTES {
        return Err(ProducerAuthorizationVerifyError::InvalidLength {
            actual: bytes.len(),
            expected: PRODUCER_AUTHORIZATION_BYTES,
        });
    }
    let body = decode_authorization_body(&bytes[..AUTHORIZATION_BODY_BYTES])?;
    Ok((body.context, body.position))
}

fn decode_authorization_body(
    bytes: &[u8],
) -> Result<AuthorizationBody, ProducerAuthorizationVerifyError> {
    debug_assert_eq!(bytes.len(), AUTHORIZATION_BODY_BYTES);

    let chain_id = ArtifactChainId::from_bytes(
        bytes[CHAIN_ID_OFFSET..GENESIS_ID_OFFSET]
            .try_into()
            .expect("the fixed chain identity field is 32 bytes"),
    );
    let genesis_id = ConsensusGenesisId::from_bytes(
        bytes[GENESIS_ID_OFFSET..PROTOCOL_VERSION_OFFSET]
            .try_into()
            .expect("the fixed genesis identity field is 32 bytes"),
    );
    let protocol_version = ConsensusProtocolVersion::new(u32::from_be_bytes(
        bytes[PROTOCOL_VERSION_OFFSET..HEIGHT_OFFSET]
            .try_into()
            .expect("the fixed protocol-version field is four bytes"),
    ));
    let height_value = u64::from_be_bytes(
        bytes[HEIGHT_OFFSET..ROUND_OFFSET]
            .try_into()
            .expect("the fixed consensus-height field is eight bytes"),
    );
    if height_value == 0 {
        return Err(ProducerAuthorizationVerifyError::ReservedGenesisHeight);
    }
    let round_value = u64::from_be_bytes(
        bytes[ROUND_OFFSET..PROPOSAL_ROOT_OFFSET]
            .try_into()
            .expect("the fixed consensus-round field is eight bytes"),
    );
    let proposal_signing_root = ProposalSigningRoot::from_bytes(
        bytes[PROPOSAL_ROOT_OFFSET..]
            .try_into()
            .expect("the fixed proposal signing root field is 32 bytes"),
    );

    Ok(AuthorizationBody {
        context: ConsensusContextV0::new(chain_id, genesis_id, protocol_version),
        position: ConsensusPosition::new(
            ConsensusHeight::new(height_value),
            ConsensusRound::new(round_value),
        ),
        proposal_signing_root,
    })
}

fn signing_transcript(body: AuthorizationBody, proposer: ConsensusKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        PRODUCER_AUTHORIZATION_SIGNING_DOMAIN.len()
            + AUTHORIZATION_BODY_BYTES
            + super::CONSENSUS_KEY_BYTES,
    );
    bytes.extend_from_slice(PRODUCER_AUTHORIZATION_SIGNING_DOMAIN);
    bytes.extend_from_slice(&body.to_canonical_bytes());
    bytes.extend_from_slice(proposer.as_bytes());
    bytes
}

pub(crate) fn producer_authorization_signing_transcript(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
    proposer: ConsensusKey,
) -> Vec<u8> {
    signing_transcript(
        AuthorizationBody {
            context,
            position,
            proposal_signing_root,
        },
        proposer,
    )
}

pub(crate) fn complete_producer_authorization(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    proposal_signing_root: ProposalSigningRoot,
    proposer: ConsensusKey,
    signature: ConsensusSignature,
) -> Result<[u8; PRODUCER_AUTHORIZATION_BYTES], ProducerAuthorizationVerifyError> {
    let body = AuthorizationBody {
        context,
        position,
        proposal_signing_root,
    };
    verify_signature(body, proposer, signature)?;

    let mut bytes = [0_u8; PRODUCER_AUTHORIZATION_BYTES];
    bytes[..AUTHORIZATION_BODY_BYTES].copy_from_slice(&body.to_canonical_bytes());
    bytes[PROPOSER_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(proposer.as_bytes());
    bytes[SIGNATURE_OFFSET..].copy_from_slice(signature.as_bytes());
    Ok(bytes)
}

fn verify_signature(
    body: AuthorizationBody,
    proposer: ConsensusKey,
    signature: ConsensusSignature,
) -> Result<(), ProducerAuthorizationVerifyError> {
    let verifying_key = VerifyingKey::from_bytes(proposer.as_bytes())
        .map_err(|_| ProducerAuthorizationVerifyError::MalformedConsensusKey { proposer })?;
    let signature = Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify_strict(&signing_transcript(body, proposer), &signature)
        .map_err(|_| ProducerAuthorizationVerifyError::InvalidSignature { proposer })
}

/// A failure to decode or verify one canonical producer authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProducerAuthorizationVerifyError {
    /// The input is not exactly one fixed-width producer authorization.
    InvalidLength { actual: usize, expected: usize },
    /// Height zero is reserved for genesis and cannot carry this authorization.
    ReservedGenesisHeight,
    /// The embedded chain differs from the caller-selected chain.
    ChainIdMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// The embedded final genesis differs from the caller-selected genesis.
    GenesisIdMismatch {
        expected: ConsensusGenesisId,
        actual: ConsensusGenesisId,
    },
    /// The embedded protocol version differs from the caller-selected version.
    ProtocolVersionMismatch {
        expected: ConsensusProtocolVersion,
        actual: ConsensusProtocolVersion,
    },
    /// The embedded position differs from the borrowed snapshot position.
    SnapshotPositionMismatch {
        authorization: ConsensusPosition,
        snapshot: ConsensusPosition,
    },
    /// The embedded key differs from the caller-designated proposer.
    UnexpectedProposer {
        expected: ConsensusKey,
        actual: ConsensusKey,
    },
    /// The exact expected proposer is absent from the borrowed snapshot.
    InactiveProposer { proposer: ConsensusKey },
    /// The raw proposer key is not an RFC 8032 Ed25519 verifying key.
    MalformedConsensusKey { proposer: ConsensusKey },
    /// Strict Ed25519 verification failed for the exact signing transcript.
    InvalidSignature { proposer: ConsensusKey },
}

impl From<ContextMismatch> for ProducerAuthorizationVerifyError {
    fn from(error: ContextMismatch) -> Self {
        match error {
            ContextMismatch::Chain { expected, actual } => {
                Self::ChainIdMismatch { expected, actual }
            }
            ContextMismatch::Genesis { expected, actual } => {
                Self::GenesisIdMismatch { expected, actual }
            }
            ContextMismatch::ProtocolVersion { expected, actual } => {
                Self::ProtocolVersionMismatch { expected, actual }
            }
        }
    }
}

impl fmt::Display for ProducerAuthorizationVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "canonical producer authorization length {actual} does not equal {expected} bytes"
            ),
            Self::ReservedGenesisHeight => formatter.write_str(
                "canonical producer authorization cannot use reserved genesis height zero",
            ),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "producer authorization chain identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::GenesisIdMismatch { expected, actual } => write!(
                formatter,
                "producer authorization genesis identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                formatter,
                "producer authorization protocol version mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::SnapshotPositionMismatch {
                authorization,
                snapshot,
            } => write!(
                formatter,
                "producer authorization position {authorization:?} differs from snapshot position {snapshot:?}"
            ),
            Self::UnexpectedProposer { expected, actual } => write!(
                formatter,
                "producer authorization proposer mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::InactiveProposer { proposer } => write!(
                formatter,
                "producer authorization proposer is not active in the supplied snapshot: {proposer:?}"
            ),
            Self::MalformedConsensusKey { proposer } => write!(
                formatter,
                "producer authorization consensus key is malformed: {proposer:?}"
            ),
            Self::InvalidSignature { proposer } => write!(
                formatter,
                "producer authorization signature is invalid for key {proposer:?}"
            ),
        }
    }
}

impl Error for ProducerAuthorizationVerifyError {}

#[cfg(test)]
mod tests;
