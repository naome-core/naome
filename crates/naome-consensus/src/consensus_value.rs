//! Canonical evidence-free values and branch-bound envelope composition.

use std::error::Error;
use std::fmt;

use naome_chain::{
    ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockApplyError, ArtifactChainBranchSnapshot,
    ArtifactChainId,
};
use sha2::{Digest, Sha256};

use super::agreement_evidence::{ContextMismatch, verify_context};
use super::{
    ActiveAgreementSnapshot, ConsensusContextV0, ConsensusGenesisId, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusProtocolVersion, FixedAgreementSetId,
    PrecommitCertificateVerifyError, ProducerAuthorizationVerifyError, ProposalSigningRoot,
    ProposerPriorityStateId, VerifiedPrecommitCertificateV0, VerifiedProducerAuthorizationV0,
};

const PROPOSAL_SIGNING_ROOT_DOMAIN: &[u8] = b"naome:consensus-proposal-signing-root:v0\0";
const CONSENSUS_ANCESTRY_DOMAIN: &[u8] = b"naome:consensus-ancestry:v0\0";
const CONSENSUS_GENESIS_ANCESTRY_DOMAIN: &[u8] = b"naome:consensus-ancestry-genesis:v0\0";
const CONSENSUS_ENVELOPE_DOMAIN: &[u8] = b"naome:consensus-envelope:v0\0";
const FIXED_VALIDATOR_ARTIFACT_STATE_DOMAIN: &[u8] =
    b"naome:consensus-state-commitment:fixed-validator-artifact:v0\0";

const CHAIN_ID_OFFSET: usize = 0;
const GENESIS_ID_OFFSET: usize = CHAIN_ID_OFFSET + ArtifactChainId::BYTE_LENGTH;
const PROTOCOL_VERSION_OFFSET: usize = GENESIS_ID_OFFSET + ConsensusGenesisId::BYTE_LENGTH;
const HEIGHT_OFFSET: usize = PROTOCOL_VERSION_OFFSET + ConsensusProtocolVersion::BYTE_LENGTH;
const PARENT_ANCESTRY_OFFSET: usize = HEIGHT_OFFSET + 8;
const ARTIFACT_BLOCK_OFFSET: usize = PARENT_ANCESTRY_OFFSET + ConsensusAncestryId::BYTE_LENGTH;
const POST_CONSENSUS_STATE_OFFSET: usize = ARTIFACT_BLOCK_OFFSET + ARTIFACT_BLOCK_BYTES;
const CONSENSUS_VALUE_BYTES: usize =
    POST_CONSENSUS_STATE_OFFSET + ConsensusStateCommitment::BYTE_LENGTH;

const PRODUCER_AUTHORIZATION_OFFSET: usize = CONSENSUS_VALUE_BYTES;
const PRECOMMIT_CERTIFICATE_OFFSET: usize =
    PRODUCER_AUTHORIZATION_OFFSET + VerifiedProducerAuthorizationV0::BYTE_LENGTH;
const MIN_ENVELOPE_BYTES: usize =
    PRECOMMIT_CERTIFICATE_OFFSET + VerifiedPrecommitCertificateV0::MIN_BYTE_LENGTH;
const MAX_ENVELOPE_BYTES: usize =
    PRECOMMIT_CERTIFICATE_OFFSET + VerifiedPrecommitCertificateV0::MAX_BYTE_LENGTH;

/// Evidence-invariant V0 consensus-parent address.
///
/// A non-genesis address is derived from exact canonical value bytes, while the
/// height-one sentinel is derived from exact chain, genesis, and version
/// context. Constructing either observed address does not establish ancestry,
/// availability, selection, or finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusAncestryId([u8; Self::BYTE_LENGTH]);

impl ConsensusAncestryId {
    /// Exact width of one consensus-ancestry identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an observed consensus-ancestry address from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw consensus-ancestry bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Derives the V0 virtual-genesis consensus parent for one exact context.
    ///
    /// The preimage is the trailing-NUL genesis-ancestry domain followed by the
    /// exact chain identity, final genesis identity, and big-endian protocol
    /// version. This computation does not install or validate that context.
    pub fn virtual_genesis(context: ConsensusContextV0) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(CONSENSUS_GENESIS_ANCESTRY_DOMAIN);
        hasher.update(context.chain_id().as_bytes());
        hasher.update(context.genesis_id().as_bytes());
        hasher.update(context.protocol_version().value().to_be_bytes());
        Self(hasher.finalize().into())
    }
}

/// Commitment to one exact post-transition consensus-state projection.
///
/// Every 32-byte value remains representable for strict value decoding. The
/// fixed-validator branch verifier accepts only the domain-separated digest it
/// derives from the exact context, direct child height, parent ancestry,
/// artifact block, fixed agreement set, and once-advanced proposer base. The
/// commitment does not install that state or address the complete future
/// consensus state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusStateCommitment([u8; Self::BYTE_LENGTH]);

impl ConsensusStateCommitment {
    /// Exact width of one consensus-state commitment.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an observed commitment from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw commitment bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

pub(crate) fn derive_fixed_validator_artifact_state_commitment(
    context: ConsensusContextV0,
    child_height: ConsensusHeight,
    parent_ancestry_id: ConsensusAncestryId,
    artifact_block: ArtifactBlock,
    fixed_agreement_set_id: FixedAgreementSetId,
    proposer_priority_state_id: ProposerPriorityStateId,
) -> ConsensusStateCommitment {
    let mut hasher = Sha256::new();
    hasher.update(FIXED_VALIDATOR_ARTIFACT_STATE_DOMAIN);
    hasher.update(context.chain_id().as_bytes());
    hasher.update(context.genesis_id().as_bytes());
    hasher.update(context.protocol_version().value().to_be_bytes());
    hasher.update(child_height.value().to_be_bytes());
    hasher.update(parent_ancestry_id.as_bytes());
    hasher.update(artifact_block.to_canonical_bytes());
    hasher.update(fixed_agreement_set_id.as_bytes());
    hasher.update(proposer_priority_state_id.as_bytes());
    ConsensusStateCommitment::from_bytes(hasher.finalize().into())
}

/// Evidence-variant identity of one complete canonical V0 consensus envelope.
///
/// This digest commits the value, producer authorization, and exact precommit
/// certificate bytes. Different valid evidence variants therefore have
/// different envelope identities while retaining one value ancestry identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusEnvelopeId([u8; Self::BYTE_LENGTH]);

impl ConsensusEnvelopeId {
    /// Exact width of one complete-envelope identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an observed envelope address from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw complete-envelope identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

/// One canonical evidence-free V0 consensus value.
///
/// The value binds context, positive height, consensus parent, the exact
/// unchanged 128-byte artifact block, and a post-consensus-state commitment.
/// Strict decoding treats that commitment as observed bytes; typed branch
/// verification requires the exact fixed-validator artifact-only V0 branch-state
/// projection. Tendermint round and all producer/precommit evidence remain
/// outside these bytes so the same value can be re-proposed in a later round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct ConsensusValueV0 {
    context: ConsensusContextV0,
    height: ConsensusHeight,
    parent_ancestry_id: ConsensusAncestryId,
    artifact_block: ArtifactBlock,
    post_consensus_state_commitment: ConsensusStateCommitment,
}

impl ConsensusValueV0 {
    /// Exact canonical width of one evidence-free V0 value.
    pub const BYTE_LENGTH: usize = CONSENSUS_VALUE_BYTES;

    /// Constructs one canonical positive-height V0 value.
    pub fn try_new(
        context: ConsensusContextV0,
        height: ConsensusHeight,
        parent_ancestry_id: ConsensusAncestryId,
        artifact_block: ArtifactBlock,
        post_consensus_state_commitment: ConsensusStateCommitment,
    ) -> Result<Self, ConsensusValueError> {
        if height.value() == 0 {
            return Err(ConsensusValueError::ReservedGenesisHeight);
        }
        Ok(Self {
            context,
            height,
            parent_ancestry_id,
            artifact_block,
            post_consensus_state_commitment,
        })
    }

    /// Strictly decodes one complete canonical V0 value.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ConsensusValueError> {
        let bytes = <&[u8; CONSENSUS_VALUE_BYTES]>::try_from(bytes).map_err(|_| {
            ConsensusValueError::InvalidLength {
                actual: bytes.len(),
                expected: CONSENSUS_VALUE_BYTES,
            }
        })?;

        let context = ConsensusContextV0::new(
            ArtifactChainId::from_bytes(
                bytes[CHAIN_ID_OFFSET..GENESIS_ID_OFFSET]
                    .try_into()
                    .expect("the fixed chain identity field is 32 bytes"),
            ),
            ConsensusGenesisId::from_bytes(
                bytes[GENESIS_ID_OFFSET..PROTOCOL_VERSION_OFFSET]
                    .try_into()
                    .expect("the fixed genesis identity field is 32 bytes"),
            ),
            ConsensusProtocolVersion::new(u32::from_be_bytes(
                bytes[PROTOCOL_VERSION_OFFSET..HEIGHT_OFFSET]
                    .try_into()
                    .expect("the fixed protocol-version field is four bytes"),
            )),
        );
        let height = ConsensusHeight::new(u64::from_be_bytes(
            bytes[HEIGHT_OFFSET..PARENT_ANCESTRY_OFFSET]
                .try_into()
                .expect("the fixed consensus-height field is eight bytes"),
        ));
        let parent_ancestry_id = ConsensusAncestryId::from_bytes(
            bytes[PARENT_ANCESTRY_OFFSET..ARTIFACT_BLOCK_OFFSET]
                .try_into()
                .expect("the fixed consensus-parent field is 32 bytes"),
        );
        let artifact_block = ArtifactBlock::from_canonical_bytes(
            &bytes[ARTIFACT_BLOCK_OFFSET..POST_CONSENSUS_STATE_OFFSET],
        )
        .expect("the fixed artifact-block field is exactly one canonical width");
        let post_consensus_state_commitment = ConsensusStateCommitment::from_bytes(
            bytes[POST_CONSENSUS_STATE_OFFSET..]
                .try_into()
                .expect("the fixed state-commitment field is 32 bytes"),
        );

        Self::try_new(
            context,
            height,
            parent_ancestry_id,
            artifact_block,
            post_consensus_state_commitment,
        )
    }

    /// Returns the exact embedded consensus context.
    pub const fn context(self) -> ConsensusContextV0 {
        self.context
    }

    /// Returns the positive consensus height.
    pub const fn height(self) -> ConsensusHeight {
        self.height
    }

    /// Returns the exact evidence-invariant consensus parent.
    pub const fn parent_ancestry_id(self) -> ConsensusAncestryId {
        self.parent_ancestry_id
    }

    /// Returns the exact embedded canonical artifact block.
    pub const fn artifact_block(self) -> ArtifactBlock {
        self.artifact_block
    }

    /// Returns the embedded post-consensus-state commitment.
    pub const fn post_consensus_state_commitment(self) -> ConsensusStateCommitment {
        self.post_consensus_state_commitment
    }

    /// Encodes this value in its sole canonical representation.
    pub fn to_canonical_bytes(self) -> [u8; CONSENSUS_VALUE_BYTES] {
        let mut bytes = [0_u8; CONSENSUS_VALUE_BYTES];
        bytes[CHAIN_ID_OFFSET..GENESIS_ID_OFFSET]
            .copy_from_slice(self.context.chain_id().as_bytes());
        bytes[GENESIS_ID_OFFSET..PROTOCOL_VERSION_OFFSET]
            .copy_from_slice(self.context.genesis_id().as_bytes());
        bytes[PROTOCOL_VERSION_OFFSET..HEIGHT_OFFSET]
            .copy_from_slice(&self.context.protocol_version().value().to_be_bytes());
        bytes[HEIGHT_OFFSET..PARENT_ANCESTRY_OFFSET]
            .copy_from_slice(&self.height.value().to_be_bytes());
        bytes[PARENT_ANCESTRY_OFFSET..ARTIFACT_BLOCK_OFFSET]
            .copy_from_slice(self.parent_ancestry_id.as_bytes());
        bytes[ARTIFACT_BLOCK_OFFSET..POST_CONSENSUS_STATE_OFFSET]
            .copy_from_slice(&self.artifact_block.to_canonical_bytes());
        bytes[POST_CONSENSUS_STATE_OFFSET..]
            .copy_from_slice(self.post_consensus_state_commitment.as_bytes());
        bytes
    }

    /// Derives the evidence-free proposal signing root for this exact value.
    pub fn proposal_signing_root(self) -> ProposalSigningRoot {
        ProposalSigningRoot::from_bytes(domain_hash(
            PROPOSAL_SIGNING_ROOT_DOMAIN,
            &self.to_canonical_bytes(),
        ))
    }

    /// Derives the evidence-invariant consensus-ancestry identity.
    pub fn ancestry_id(self) -> ConsensusAncestryId {
        ConsensusAncestryId::from_bytes(domain_hash(
            CONSENSUS_ANCESTRY_DOMAIN,
            &self.to_canonical_bytes(),
        ))
    }
}

/// One canonical V0 envelope whose value, producer authorization, precommit
/// certificate, and artifact transition were verified together.
///
/// Both evidence objects borrow the same typed round cursor's derived active
/// snapshot. The artifact successor is an immutable memory-only candidate
/// derived from the same typed branch parent that supplied ancestry, height,
/// proposer, and state-commitment authority. Success proves this bounded
/// composition only; it does not select a canonical branch, install finality,
/// mutate a selected journal, persist evidence, or resolve conflicting
/// certificates.
#[must_use]
pub(crate) struct VerifiedConsensusEnvelopeV0<'snapshot> {
    value: ConsensusValueV0,
    producer_authorization: VerifiedProducerAuthorizationV0<'snapshot>,
    precommit_certificate: VerifiedPrecommitCertificateV0<'snapshot>,
    artifact_successor: ArtifactChainBranchSnapshot,
    canonical_envelope_bytes: Vec<u8>,
    canonical_artifact_bytes: Vec<u8>,
    id: ConsensusEnvelopeId,
}

impl<'snapshot> VerifiedConsensusEnvelopeV0<'snapshot> {
    /// Smallest canonical envelope width, containing one precommit signer.
    pub(crate) const MIN_BYTE_LENGTH: usize = MIN_ENVELOPE_BYTES;

    /// Largest canonical envelope width, containing 256 precommit signers.
    pub(crate) const MAX_BYTE_LENGTH: usize = MAX_ENVELOPE_BYTES;

    /// Composes one complete V0 envelope against explicit internal expectations.
    ///
    /// The public typed round boundary derives every expectation before calling
    /// this crate-private helper. Keeping this function non-public prevents
    /// independent proposer, ancestry, state-commitment, and artifact-parent
    /// inputs from bypassing the coupled branch contract.
    #[allow(
        clippy::too_many_arguments,
        reason = "the private composition helper keeps every derived authority check explicit"
    )]
    pub(crate) fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        expected_proposer: ConsensusKey,
        snapshot: &'snapshot ActiveAgreementSnapshot,
        expected_prior_ancestry: Option<ConsensusAncestryId>,
        expected_post_consensus_state_commitment: ConsensusStateCommitment,
        artifact_parent: &ArtifactChainBranchSnapshot,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<Self, ConsensusEnvelopeVerifyError> {
        let value = Self::decode_value(bytes)?;
        verify_context(value.context(), expected_context)
            .map_err(ConsensusEnvelopeVerifyError::from)?;
        if value.height() != snapshot.position().height() {
            return Err(ConsensusEnvelopeVerifyError::SnapshotHeightMismatch {
                value: value.height(),
                snapshot: snapshot.position(),
            });
        }

        let expected_parent = if value.height().value() == 1 {
            if let Some(actual) = expected_prior_ancestry {
                return Err(
                    ConsensusEnvelopeVerifyError::UnexpectedPriorAncestryAtFirstHeight { actual },
                );
            }
            ConsensusAncestryId::virtual_genesis(expected_context)
        } else {
            expected_prior_ancestry.ok_or(ConsensusEnvelopeVerifyError::MissingPriorAncestry {
                height: value.height(),
            })?
        };
        if value.parent_ancestry_id() != expected_parent {
            return Err(ConsensusEnvelopeVerifyError::ParentAncestryMismatch {
                expected: expected_parent,
                actual: value.parent_ancestry_id(),
            });
        }
        if value.post_consensus_state_commitment() != expected_post_consensus_state_commitment {
            return Err(
                ConsensusEnvelopeVerifyError::PostConsensusStateCommitmentMismatch {
                    expected: expected_post_consensus_state_commitment,
                    actual: value.post_consensus_state_commitment(),
                },
            );
        }
        if artifact_parent.chain_id() != expected_context.chain_id() {
            return Err(ConsensusEnvelopeVerifyError::ArtifactChainMismatch {
                expected: expected_context.chain_id(),
                actual: artifact_parent.chain_id(),
            });
        }

        let proposal_signing_root = value.proposal_signing_root();
        let producer_authorization = VerifiedProducerAuthorizationV0::decode_and_verify(
            &bytes[PRODUCER_AUTHORIZATION_OFFSET..PRECOMMIT_CERTIFICATE_OFFSET],
            expected_context,
            expected_proposer,
            snapshot,
        )?;
        if producer_authorization.proposal_signing_root() != proposal_signing_root {
            return Err(
                ConsensusEnvelopeVerifyError::ProducerAuthorizationRootMismatch {
                    expected: proposal_signing_root,
                    actual: producer_authorization.proposal_signing_root(),
                },
            );
        }

        let precommit_certificate = VerifiedPrecommitCertificateV0::decode_and_verify(
            &bytes[PRECOMMIT_CERTIFICATE_OFFSET..],
            expected_context,
            snapshot,
        )?;
        if precommit_certificate.proposal_signing_root() != proposal_signing_root {
            return Err(
                ConsensusEnvelopeVerifyError::PrecommitCertificateRootMismatch {
                    expected: proposal_signing_root,
                    actual: precommit_certificate.proposal_signing_root(),
                },
            );
        }

        let artifact_successor = artifact_parent
            .validate_child(&value.artifact_block(), canonical_artifact_bytes.clone())
            .map_err(ConsensusEnvelopeVerifyError::ArtifactValidation)?;
        let id = ConsensusEnvelopeId::from_bytes(domain_hash(CONSENSUS_ENVELOPE_DOMAIN, bytes));

        Ok(Self {
            value,
            producer_authorization,
            precommit_certificate,
            artifact_successor,
            canonical_envelope_bytes: bytes.to_vec(),
            canonical_artifact_bytes,
            id,
        })
    }

    pub(crate) fn decode_value(
        bytes: &[u8],
    ) -> Result<ConsensusValueV0, ConsensusEnvelopeVerifyError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ConsensusEnvelopeVerifyError::InputTooLong {
                actual: bytes.len(),
                maximum: MAX_ENVELOPE_BYTES,
            });
        }
        if bytes.len() < MIN_ENVELOPE_BYTES {
            return Err(ConsensusEnvelopeVerifyError::InvalidLength {
                actual: bytes.len(),
                minimum: MIN_ENVELOPE_BYTES,
            });
        }
        ConsensusValueV0::from_canonical_bytes(&bytes[..CONSENSUS_VALUE_BYTES])
            .map_err(ConsensusEnvelopeVerifyError::from)
    }

    /// Returns the exact verified evidence-free value.
    pub(crate) const fn value(&self) -> ConsensusValueV0 {
        self.value
    }

    /// Returns the verified producer authorization.
    pub(crate) const fn producer_authorization(
        &self,
    ) -> &VerifiedProducerAuthorizationV0<'snapshot> {
        &self.producer_authorization
    }

    /// Returns the verified non-nil precommit certificate.
    pub(crate) const fn precommit_certificate(&self) -> &VerifiedPrecommitCertificateV0<'snapshot> {
        &self.precommit_certificate
    }

    /// Returns the immutable artifact state after the verified transition.
    pub(crate) const fn artifact_successor(&self) -> &ArtifactChainBranchSnapshot {
        &self.artifact_successor
    }

    /// Consumes the proof into the exact owned components needed by a sealed
    /// branch transition without cloning its retained byte inputs.
    pub(crate) fn into_owned_components(
        self,
    ) -> (
        ConsensusValueV0,
        ConsensusEnvelopeId,
        Vec<u8>,
        Vec<u8>,
        ArtifactChainBranchSnapshot,
    ) {
        (
            self.value,
            self.id,
            self.canonical_envelope_bytes,
            self.canonical_artifact_bytes,
            self.artifact_successor,
        )
    }

    /// Returns the evidence-variant identity of the complete envelope bytes.
    pub(crate) const fn id(&self) -> ConsensusEnvelopeId {
        self.id
    }

    /// Re-encodes the complete verified envelope byte-identically.
    pub(crate) fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            PRECOMMIT_CERTIFICATE_OFFSET + self.precommit_certificate.canonical_byte_length(),
        );
        bytes.extend_from_slice(&self.value.to_canonical_bytes());
        bytes.extend_from_slice(&self.producer_authorization.to_canonical_bytes());
        self.precommit_certificate
            .append_canonical_bytes_to(&mut bytes);
        debug_assert_eq!(bytes, self.canonical_envelope_bytes);
        bytes
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// A malformed or unsupported evidence-free V0 consensus value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsensusValueError {
    /// The input is not exactly one complete fixed-width value.
    InvalidLength { actual: usize, expected: usize },
    /// Height zero is reserved for the installed genesis context.
    ReservedGenesisHeight,
}

impl fmt::Display for ConsensusValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "canonical consensus value length {actual} does not equal {expected} bytes"
            ),
            Self::ReservedGenesisHeight => formatter
                .write_str("canonical consensus value cannot use reserved genesis height zero"),
        }
    }
}

impl Error for ConsensusValueError {}

/// A failure to verify one canonical consensus envelope and artifact transition.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsensusEnvelopeVerifyError {
    /// The complete input exceeds the 256-signer envelope bound.
    InputTooLong { actual: usize, maximum: usize },
    /// The input cannot contain a value, authorization, and one-signer certificate.
    InvalidLength { actual: usize, minimum: usize },
    /// The evidence-free value is malformed.
    Value(ConsensusValueError),
    /// The value's chain differs from the caller-selected chain.
    ChainIdMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// The value's final genesis differs from the caller-selected genesis.
    GenesisIdMismatch {
        expected: ConsensusGenesisId,
        actual: ConsensusGenesisId,
    },
    /// The value's protocol version differs from the caller-selected version.
    ProtocolVersionMismatch {
        expected: ConsensusProtocolVersion,
        actual: ConsensusProtocolVersion,
    },
    /// The value height differs from the borrowed snapshot height.
    SnapshotHeightMismatch {
        value: ConsensusHeight,
        snapshot: ConsensusPosition,
    },
    /// Height one was supplied with a prior-value expectation instead of genesis.
    UnexpectedPriorAncestryAtFirstHeight { actual: ConsensusAncestryId },
    /// A later height has no caller-expected prior ancestry identity.
    MissingPriorAncestry { height: ConsensusHeight },
    /// The embedded consensus parent differs from the required parent.
    ParentAncestryMismatch {
        expected: ConsensusAncestryId,
        actual: ConsensusAncestryId,
    },
    /// The embedded state commitment differs from the branch-derived digest.
    PostConsensusStateCommitmentMismatch {
        expected: ConsensusStateCommitment,
        actual: ConsensusStateCommitment,
    },
    /// The artifact snapshot belongs to another artifact chain.
    ArtifactChainMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// Producer-authorization decoding or authentication failed.
    ProducerAuthorization(ProducerAuthorizationVerifyError),
    /// Producer evidence authenticates another proposal root.
    ProducerAuthorizationRootMismatch {
        expected: ProposalSigningRoot,
        actual: ProposalSigningRoot,
    },
    /// Precommit-certificate decoding or authentication failed.
    PrecommitCertificate(PrecommitCertificateVerifyError),
    /// Precommit evidence authenticates another proposal root.
    PrecommitCertificateRootMismatch {
        expected: ProposalSigningRoot,
        actual: ProposalSigningRoot,
    },
    /// Strict immutable artifact-child validation failed.
    ArtifactValidation(ArtifactBlockApplyError),
}

impl From<ConsensusValueError> for ConsensusEnvelopeVerifyError {
    fn from(error: ConsensusValueError) -> Self {
        Self::Value(error)
    }
}

impl From<ContextMismatch> for ConsensusEnvelopeVerifyError {
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

impl From<ProducerAuthorizationVerifyError> for ConsensusEnvelopeVerifyError {
    fn from(error: ProducerAuthorizationVerifyError) -> Self {
        Self::ProducerAuthorization(error)
    }
}

impl From<PrecommitCertificateVerifyError> for ConsensusEnvelopeVerifyError {
    fn from(error: PrecommitCertificateVerifyError) -> Self {
        Self::PrecommitCertificate(error)
    }
}

impl fmt::Display for ConsensusEnvelopeVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "consensus envelope length {actual} exceeds {maximum} bytes"
            ),
            Self::InvalidLength { actual, minimum } => write!(
                formatter,
                "consensus envelope length {actual} is shorter than {minimum} bytes"
            ),
            Self::Value(error) => error.fmt(formatter),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "consensus value chain identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::GenesisIdMismatch { expected, actual } => write!(
                formatter,
                "consensus value genesis identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                formatter,
                "consensus value protocol version mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::SnapshotHeightMismatch { value, snapshot } => write!(
                formatter,
                "consensus value height {value:?} differs from snapshot position {snapshot:?}"
            ),
            Self::UnexpectedPriorAncestryAtFirstHeight { actual } => write!(
                formatter,
                "first consensus height cannot use caller-supplied prior ancestry {actual:?}"
            ),
            Self::MissingPriorAncestry { height } => write!(
                formatter,
                "consensus height {height:?} requires one caller-expected prior ancestry identity"
            ),
            Self::ParentAncestryMismatch { expected, actual } => write!(
                formatter,
                "consensus parent ancestry mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::PostConsensusStateCommitmentMismatch { expected, actual } => write!(
                formatter,
                "post-consensus-state commitment mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ArtifactChainMismatch { expected, actual } => write!(
                formatter,
                "artifact snapshot chain identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ProducerAuthorization(error) => error.fmt(formatter),
            Self::ProducerAuthorizationRootMismatch { expected, actual } => write!(
                formatter,
                "producer authorization proposal root mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::PrecommitCertificate(error) => error.fmt(formatter),
            Self::PrecommitCertificateRootMismatch { expected, actual } => write!(
                formatter,
                "precommit certificate proposal root mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ArtifactValidation(error) => write!(
                formatter,
                "consensus envelope artifact validation failed: {error}"
            ),
        }
    }
}

impl Error for ConsensusEnvelopeVerifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Value(error) => Some(error),
            Self::ProducerAuthorization(error) => Some(error),
            Self::PrecommitCertificate(error) => Some(error),
            Self::ArtifactValidation(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
