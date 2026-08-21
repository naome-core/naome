//! Canonical, caller-context-bound verification of consensus agreement evidence.

use std::error::Error;
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use naome_chain::ArtifactChainId;
use sha2::{Digest, Sha256};

use super::{
    ActiveAgreementSnapshot, AgreementSignerError, AgreementWeight, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusRound, MAX_ACTIVE_VALIDATORS, has_strict_supermajority,
};

const PREVOTE_SIGNING_DOMAIN: &[u8] = b"naome:consensus-prevote-signing:v0\0";
const PRECOMMIT_SIGNING_DOMAIN: &[u8] = b"naome:consensus-precommit-signing:v0\0";

const VOTE_BODY_BYTES: usize = 118;
const VOTE_KEY_OFFSET: usize = VOTE_BODY_BYTES;
const VOTE_SIGNATURE_OFFSET: usize = VOTE_KEY_OFFSET + super::CONSENSUS_KEY_BYTES;
const SIGNED_VOTE_BYTES: usize = VOTE_SIGNATURE_OFFSET + CONSENSUS_SIGNATURE_BYTES;

const ROLE_OFFSET: usize = 0;
const CHAIN_ID_OFFSET: usize = ROLE_OFFSET + 1;
const GENESIS_ID_OFFSET: usize = CHAIN_ID_OFFSET + ArtifactChainId::BYTE_LENGTH;
const PROTOCOL_VERSION_OFFSET: usize = GENESIS_ID_OFFSET + ConsensusGenesisId::BYTE_LENGTH;
const HEIGHT_OFFSET: usize = PROTOCOL_VERSION_OFFSET + ConsensusProtocolVersion::BYTE_LENGTH;
const ROUND_OFFSET: usize = HEIGHT_OFFSET + 8;
const TARGET_TAG_OFFSET: usize = ROUND_OFFSET + 8;
const TARGET_PAYLOAD_OFFSET: usize = TARGET_TAG_OFFSET + 1;

const CERTIFICATE_COUNT_OFFSET: usize = VOTE_BODY_BYTES;
const CERTIFICATE_ENTRIES_OFFSET: usize = CERTIFICATE_COUNT_OFFSET + 2;
const CERTIFICATE_ENTRY_BYTES: usize = super::CONSENSUS_KEY_BYTES + CONSENSUS_SIGNATURE_BYTES;
const MIN_CERTIFICATE_BYTES: usize = CERTIFICATE_ENTRIES_OFFSET + CERTIFICATE_ENTRY_BYTES;
const MAX_CERTIFICATE_BYTES: usize =
    CERTIFICATE_ENTRIES_OFFSET + MAX_ACTIVE_VALIDATORS * CERTIFICATE_ENTRY_BYTES;

const PREVOTE_TAG: u8 = 1;
const PRECOMMIT_TAG: u8 = 2;
const NIL_TARGET_TAG: u8 = 0;
const PROPOSAL_TARGET_TAG: u8 = 1;

/// Exact width of one raw Ed25519 consensus signature.
pub const CONSENSUS_SIGNATURE_BYTES: usize = 64;

/// Opaque identity of the exact final genesis context installed by a caller.
///
/// Constructing this value does not derive, validate, or install genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusGenesisId([u8; Self::BYTE_LENGTH]);

impl ConsensusGenesisId {
    /// Exact width of one final genesis identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an observed final genesis identity from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw final genesis identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

/// Unsigned protocol-version value carried by V0 consensus agreement evidence.
///
/// This type defines only its exact `u32` big-endian representation. It does
/// not decide which versions a node supports or authorize an upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusProtocolVersion(u32);

impl ConsensusProtocolVersion {
    /// Exact canonical width of one protocol-version value.
    pub const BYTE_LENGTH: usize = 4;

    /// Constructs an observed protocol-version value.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric protocol-version value.
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// The exact caller-selected chain, final genesis, and protocol-version domain.
///
/// This context is verification input only. Construction does not establish a
/// supported chain definition, installed genesis, or supported version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ConsensusContextV0 {
    chain_id: ArtifactChainId,
    genesis_id: ConsensusGenesisId,
    protocol_version: ConsensusProtocolVersion,
}

impl ConsensusContextV0 {
    /// Constructs one exact caller-selected verification context.
    pub const fn new(
        chain_id: ArtifactChainId,
        genesis_id: ConsensusGenesisId,
        protocol_version: ConsensusProtocolVersion,
    ) -> Self {
        Self {
            chain_id,
            genesis_id,
            protocol_version,
        }
    }

    /// Returns the artifact-chain context identity.
    pub const fn chain_id(self) -> ArtifactChainId {
        self.chain_id
    }

    /// Returns the opaque final genesis identity.
    pub const fn genesis_id(self) -> ConsensusGenesisId {
        self.genesis_id
    }

    /// Returns the carried protocol version.
    pub const fn protocol_version(self) -> ConsensusProtocolVersion {
        self.protocol_version
    }
}

/// An opaque evidence-free proposal signing root observed in a vote.
///
/// Constructing this value does not derive the root or establish that any
/// proposal, block, payload, or state transition exists or is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProposalSigningRoot([u8; Self::BYTE_LENGTH]);

impl ProposalSigningRoot {
    /// Exact width of one proposal signing root.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs an observed proposal signing root from raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw proposal signing-root bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

/// The separately signed Tendermint agreement-message role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub enum ConsensusVoteRole {
    /// A prevote for nil or one proposal signing root.
    Prevote,
    /// A precommit for nil or one proposal signing root.
    Precommit,
}

impl ConsensusVoteRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Prevote => PREVOTE_TAG,
            Self::Precommit => PRECOMMIT_TAG,
        }
    }

    const fn signing_domain(self) -> &'static [u8] {
        match self {
            Self::Prevote => PREVOTE_SIGNING_DOMAIN,
            Self::Precommit => PRECOMMIT_SIGNING_DOMAIN,
        }
    }
}

/// The exact nil-or-proposal target carried by one agreement message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub enum ConsensusVoteTarget {
    /// The validator votes for no proposal at this position.
    Nil,
    /// The validator votes for this opaque proposal signing root.
    Proposal(ProposalSigningRoot),
}

/// An observed raw Ed25519 signature.
///
/// Construction does not establish signature or signer validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub struct ConsensusSignature([u8; CONSENSUS_SIGNATURE_BYTES]);

impl ConsensusSignature {
    /// Constructs an observed signature from raw bytes.
    pub const fn from_bytes(bytes: [u8; CONSENSUS_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw signature bytes.
    pub const fn as_bytes(&self) -> &[u8; CONSENSUS_SIGNATURE_BYTES] {
        &self.0
    }
}

/// Evidence-invariant identity of one semantic signed vote.
///
/// This is SHA-256 of the exact role-domain-prefixed unsigned signing
/// transcript. It includes the signer key but excludes the signature, so valid
/// signature variants for one semantic vote share this identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ConsensusVoteId([u8; Self::BYTE_LENGTH]);

impl ConsensusVoteId {
    /// Exact width of one vote identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Returns the raw identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

/// Evidence-variant identity of one complete canonical quorum certificate.
///
/// This is SHA-256 of the complete canonical certificate bytes. Changing the
/// authenticated role, target, signer subset, or any signature changes this
/// identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct QuorumCertificateId([u8; Self::BYTE_LENGTH]);

impl QuorumCertificateId {
    /// Exact width of one certificate evidence identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Returns the raw identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

/// Evidence-variant identity of one complete canonical precommit certificate.
///
/// This is SHA-256 of the complete canonical certificate bytes. Changing the
/// signer subset or any signature changes this identity without changing the
/// opaque proposal signing root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct PrecommitCertificateId([u8; Self::BYTE_LENGTH]);

impl PrecommitCertificateId {
    /// Exact width of one certificate evidence identity.
    pub const BYTE_LENGTH: usize = 32;

    /// Returns the raw identity bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VoteBody {
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
}

impl VoteBody {
    fn to_canonical_bytes(self) -> [u8; VOTE_BODY_BYTES] {
        let mut bytes = [0_u8; VOTE_BODY_BYTES];
        bytes[ROLE_OFFSET] = self.role.tag();
        bytes[CHAIN_ID_OFFSET..GENESIS_ID_OFFSET]
            .copy_from_slice(self.context.chain_id().as_bytes());
        bytes[GENESIS_ID_OFFSET..PROTOCOL_VERSION_OFFSET]
            .copy_from_slice(self.context.genesis_id().as_bytes());
        bytes[PROTOCOL_VERSION_OFFSET..HEIGHT_OFFSET]
            .copy_from_slice(&self.context.protocol_version().value().to_be_bytes());
        bytes[HEIGHT_OFFSET..ROUND_OFFSET]
            .copy_from_slice(&self.position.height().value().to_be_bytes());
        bytes[ROUND_OFFSET..TARGET_TAG_OFFSET]
            .copy_from_slice(&self.position.round().value().to_be_bytes());
        match self.target {
            ConsensusVoteTarget::Nil => {
                bytes[TARGET_TAG_OFFSET] = NIL_TARGET_TAG;
            }
            ConsensusVoteTarget::Proposal(root) => {
                bytes[TARGET_TAG_OFFSET] = PROPOSAL_TARGET_TAG;
                bytes[TARGET_PAYLOAD_OFFSET..].copy_from_slice(root.as_bytes());
            }
        }
        bytes
    }
}

/// One canonical signed vote whose Ed25519 signature has been verified.
///
/// Verification binds the exact embedded role, context, position, signer, and
/// target. It does not establish that the caller-supplied expected context is
/// installed, that the signer is active, or that the target is valid or final.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct VerifiedConsensusVoteV0 {
    body: VoteBody,
    signer: ConsensusKey,
    signature: ConsensusSignature,
    id: ConsensusVoteId,
}

impl VerifiedConsensusVoteV0 {
    /// Exact canonical width of one complete signed vote.
    pub const BYTE_LENGTH: usize = SIGNED_VOTE_BYTES;

    /// Strictly decodes and verifies one complete signed prevote or precommit.
    ///
    /// The expected context is compared before public-key or signature work.
    /// Accepted input has one byte-identical canonical re-encoding.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
    ) -> Result<Self, ConsensusVoteVerifyError> {
        if bytes.len() != SIGNED_VOTE_BYTES {
            return Err(ConsensusVoteDecodeError::InvalidLength {
                actual: bytes.len(),
                expected: SIGNED_VOTE_BYTES,
            }
            .into());
        }

        let body = decode_vote_body(&bytes[..VOTE_BODY_BYTES])?;
        verify_context(body.context, expected_context).map_err(ConsensusVoteVerifyError::from)?;

        let signer = ConsensusKey::from_bytes(
            bytes[VOTE_KEY_OFFSET..VOTE_SIGNATURE_OFFSET]
                .try_into()
                .expect("the fixed signed-vote key field is 32 bytes"),
        );
        let signature = ConsensusSignature::from_bytes(
            bytes[VOTE_SIGNATURE_OFFSET..]
                .try_into()
                .expect("the fixed signed-vote signature field is 64 bytes"),
        );
        verify_vote_signature(body, signer, signature)?;

        Ok(Self {
            body,
            signer,
            signature,
            id: semantic_vote_id(body, signer),
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

    /// Returns the signed agreement-message role.
    pub const fn role(&self) -> ConsensusVoteRole {
        self.body.role
    }

    /// Returns the exact nil-or-proposal target.
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.body.target
    }

    /// Returns the verified raw consensus key.
    pub const fn signer(&self) -> ConsensusKey {
        self.signer
    }

    /// Returns the verified raw signature.
    pub const fn signature(&self) -> ConsensusSignature {
        self.signature
    }

    /// Returns the signature-invariant semantic vote identity.
    pub const fn id(&self) -> ConsensusVoteId {
        self.id
    }

    /// Encodes the complete signed vote in its sole canonical representation.
    pub fn to_canonical_bytes(&self) -> [u8; SIGNED_VOTE_BYTES] {
        let mut bytes = [0_u8; SIGNED_VOTE_BYTES];
        bytes[..VOTE_BODY_BYTES].copy_from_slice(&self.body.to_canonical_bytes());
        bytes[VOTE_KEY_OFFSET..VOTE_SIGNATURE_OFFSET].copy_from_slice(self.signer.as_bytes());
        bytes[VOTE_SIGNATURE_OFFSET..].copy_from_slice(self.signature.as_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CertificateEntry {
    signer: ConsensusKey,
    signature: ConsensusSignature,
}

#[derive(Debug, PartialEq, Eq)]
struct VerifiedCertificateCore<'snapshot> {
    body: VoteBody,
    entries: Box<[CertificateEntry]>,
    id: [u8; QuorumCertificateId::BYTE_LENGTH],
    signed_weight: AgreementWeight,
    snapshot: &'snapshot ActiveAgreementSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CertificateBodyPolicy {
    AnySupported,
    NonNilPrecommit,
}

/// One canonical role-complete quorum certificate verified against an exact
/// borrowed active-agreement snapshot.
///
/// Success proves only that every listed active key validly signed the exact
/// same embedded prevote or precommit for canonical nil or one opaque proposal
/// target, and that their weight is strictly greater than two thirds of the
/// snapshot's unchanged total. The exact authenticated role and target remain
/// data. The borrowed snapshot is verification context, not validator-selection
/// or canonical-state authority. This value does not execute locking, round
/// advancement, finality, selection, persistence, networking, peer trust,
/// signing, or economics.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct VerifiedQuorumCertificateV0<'snapshot> {
    core: VerifiedCertificateCore<'snapshot>,
}

impl<'snapshot> VerifiedQuorumCertificateV0<'snapshot> {
    /// Smallest canonical certificate width, containing one signer.
    pub const MIN_BYTE_LENGTH: usize = MIN_CERTIFICATE_BYTES;

    /// Largest canonical certificate width, containing 256 signers.
    pub const MAX_BYTE_LENGTH: usize = MAX_CERTIFICATE_BYTES;

    /// Strictly decodes and verifies one bounded role-complete certificate.
    ///
    /// The certificate must carry one shared prevote or precommit body, a
    /// canonical nil or proposal target, a nonzero
    /// big-endian `u16` count no greater than 256, and exactly that many
    /// ascending `(ConsensusKey[32], Ed25519Signature[64])` entries. Context,
    /// position, membership, every signature, and strict greater-than-two-thirds
    /// weight are verified all-or-nothing before success is published.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        snapshot: &'snapshot ActiveAgreementSnapshot,
    ) -> Result<Self, QuorumCertificateVerifyError> {
        decode_and_verify_certificate(
            bytes,
            expected_context,
            snapshot,
            CertificateBodyPolicy::AnySupported,
        )
        .map(|core| Self { core })
        .map_err(QuorumCertificateVerifyError::from_shared)
    }

    /// Returns the exact embedded verification context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.core.body.context
    }

    /// Returns the exact height and round shared by every vote.
    pub const fn position(&self) -> ConsensusPosition {
        self.core.body.position
    }

    /// Returns the authenticated agreement-message role.
    pub const fn role(&self) -> ConsensusVoteRole {
        self.core.body.role
    }

    /// Returns the authenticated nil-or-proposal target.
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.core.body.target
    }

    /// Returns the number of distinct verified signers.
    pub fn signer_count(&self) -> usize {
        self.core.entries.len()
    }

    /// Iterates over verified signer keys in canonical ascending order.
    pub fn signer_keys(&self) -> impl ExactSizeIterator<Item = ConsensusKey> + '_ {
        self.core.entries.iter().map(|entry| entry.signer)
    }

    /// Returns the exact verified signer weight in the borrowed snapshot.
    pub const fn signed_weight(&self) -> AgreementWeight {
        self.core.signed_weight
    }

    /// Returns the borrowed snapshot's unchanged total active weight.
    pub const fn total_weight(&self) -> AgreementWeight {
        self.core.snapshot.total_weight()
    }

    /// Returns the evidence-variant identity of the complete certificate bytes.
    pub const fn id(&self) -> QuorumCertificateId {
        QuorumCertificateId(self.core.id)
    }

    /// Encodes the complete certificate in its sole canonical representation.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.core.to_canonical_bytes()
    }

    /// Narrows this evidence to the finality-facing non-nil precommit subtype.
    ///
    /// Failure returns the original generic certificate unchanged and without
    /// allocation. This method does not itself execute finality or any
    /// consensus-state transition.
    #[allow(
        clippy::result_large_err,
        reason = "the lossless failure path deliberately returns the allocation-free original"
    )]
    pub fn try_into_precommit_certificate(
        self,
    ) -> Result<VerifiedPrecommitCertificateV0<'snapshot>, Self> {
        if self.core.body.role == ConsensusVoteRole::Precommit
            && matches!(self.core.body.target, ConsensusVoteTarget::Proposal(_))
        {
            Ok(VerifiedPrecommitCertificateV0 { core: self.core })
        } else {
            Err(self)
        }
    }
}

/// One canonical non-nil precommit certificate verified against an exact
/// borrowed active-agreement snapshot.
///
/// This is the narrow finality-facing evidence subtype. Success proves only
/// authenticated strict-supermajority agreement on one opaque proposal target;
/// the borrowed snapshot is verification context, not validator-selection or
/// canonical-state authority. This value does not itself establish proposal
/// validity or availability, execute finality, select a chain, mutate state,
/// persist data, or trust a peer.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct VerifiedPrecommitCertificateV0<'snapshot> {
    core: VerifiedCertificateCore<'snapshot>,
}

impl<'snapshot> VerifiedPrecommitCertificateV0<'snapshot> {
    /// Smallest canonical certificate width, containing one signer.
    pub const MIN_BYTE_LENGTH: usize = MIN_CERTIFICATE_BYTES;

    /// Largest canonical certificate width, containing 256 signers.
    pub const MAX_BYTE_LENGTH: usize = MAX_CERTIFICATE_BYTES;

    /// Strictly decodes and verifies one bounded non-nil precommit certificate.
    ///
    /// Role and target are rejected immediately after body decoding, preserving
    /// this API's established failure precedence before count, framing, context,
    /// membership, signature, and threshold verification.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        snapshot: &'snapshot ActiveAgreementSnapshot,
    ) -> Result<Self, PrecommitCertificateVerifyError> {
        decode_and_verify_certificate(
            bytes,
            expected_context,
            snapshot,
            CertificateBodyPolicy::NonNilPrecommit,
        )
        .map(|core| Self { core })
    }

    /// Returns the exact embedded verification context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.core.body.context
    }

    /// Returns the exact height and round shared by every precommit.
    pub const fn position(&self) -> ConsensusPosition {
        self.core.body.position
    }

    /// Returns the non-nil opaque proposal signing root.
    pub fn proposal_signing_root(&self) -> ProposalSigningRoot {
        match self.core.body.target {
            ConsensusVoteTarget::Proposal(root) => root,
            ConsensusVoteTarget::Nil => {
                unreachable!("verified precommit certificates reject nil targets")
            }
        }
    }

    /// Returns the number of distinct verified precommit signers.
    pub fn signer_count(&self) -> usize {
        self.core.entries.len()
    }

    /// Iterates over verified signer keys in canonical ascending order.
    pub fn signer_keys(&self) -> impl ExactSizeIterator<Item = ConsensusKey> + '_ {
        self.core.entries.iter().map(|entry| entry.signer)
    }

    /// Returns the exact verified signer weight in the borrowed snapshot.
    pub const fn signed_weight(&self) -> AgreementWeight {
        self.core.signed_weight
    }

    /// Returns the borrowed snapshot's unchanged total active weight.
    pub const fn total_weight(&self) -> AgreementWeight {
        self.core.snapshot.total_weight()
    }

    /// Returns the evidence-variant identity of the complete certificate bytes.
    pub const fn id(&self) -> PrecommitCertificateId {
        PrecommitCertificateId(self.core.id)
    }

    /// Encodes the complete certificate in its sole canonical representation.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.core.to_canonical_bytes()
    }
}

impl<'snapshot> From<VerifiedPrecommitCertificateV0<'snapshot>>
    for VerifiedQuorumCertificateV0<'snapshot>
{
    fn from(certificate: VerifiedPrecommitCertificateV0<'snapshot>) -> Self {
        Self {
            core: certificate.core,
        }
    }
}

impl VerifiedCertificateCore<'_> {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            CERTIFICATE_ENTRIES_OFFSET + self.entries.len() * CERTIFICATE_ENTRY_BYTES,
        );
        bytes.extend_from_slice(&self.body.to_canonical_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.entries.len())
                .expect("a verified certificate contains at most 256 entries")
                .to_be_bytes(),
        );
        for entry in &self.entries {
            bytes.extend_from_slice(entry.signer.as_bytes());
            bytes.extend_from_slice(entry.signature.as_bytes());
        }
        bytes
    }
}

fn decode_and_verify_certificate<'snapshot>(
    bytes: &[u8],
    expected_context: ConsensusContextV0,
    snapshot: &'snapshot ActiveAgreementSnapshot,
    body_policy: CertificateBodyPolicy,
) -> Result<VerifiedCertificateCore<'snapshot>, PrecommitCertificateVerifyError> {
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(PrecommitCertificateVerifyError::InputTooLong {
            actual: bytes.len(),
            maximum: MAX_CERTIFICATE_BYTES,
        });
    }
    if bytes.len() < CERTIFICATE_ENTRIES_OFFSET {
        return Err(PrecommitCertificateVerifyError::InvalidLength {
            actual: bytes.len(),
            minimum: CERTIFICATE_ENTRIES_OFFSET,
        });
    }

    let body = decode_vote_body(&bytes[..VOTE_BODY_BYTES])?;
    if body_policy == CertificateBodyPolicy::NonNilPrecommit {
        if body.role != ConsensusVoteRole::Precommit {
            return Err(PrecommitCertificateVerifyError::WrongVoteRole { actual: body.role });
        }
        if body.target == ConsensusVoteTarget::Nil {
            return Err(PrecommitCertificateVerifyError::NilCertificateTarget);
        }
    }

    let signer_count = usize::from(u16::from_be_bytes(
        bytes[CERTIFICATE_COUNT_OFFSET..CERTIFICATE_ENTRIES_OFFSET]
            .try_into()
            .expect("the fixed certificate count field is two bytes"),
    ));
    if signer_count == 0 {
        return Err(PrecommitCertificateVerifyError::EmptySignerSet);
    }
    if signer_count > MAX_ACTIVE_VALIDATORS {
        return Err(PrecommitCertificateVerifyError::TooManySigners {
            actual: signer_count,
            maximum: MAX_ACTIVE_VALIDATORS,
        });
    }

    let expected_length = CERTIFICATE_ENTRIES_OFFSET + signer_count * CERTIFICATE_ENTRY_BYTES;
    if bytes.len() != expected_length {
        return Err(PrecommitCertificateVerifyError::LengthMismatch {
            actual: bytes.len(),
            expected: expected_length,
        });
    }

    let mut entries: Vec<CertificateEntry> = Vec::with_capacity(signer_count);
    for index in 0..signer_count {
        let start = CERTIFICATE_ENTRIES_OFFSET + index * CERTIFICATE_ENTRY_BYTES;
        let signature_start = start + super::CONSENSUS_KEY_BYTES;
        let signer = ConsensusKey::from_bytes(
            bytes[start..signature_start]
                .try_into()
                .expect("one certificate key field is 32 bytes"),
        );
        let signature = ConsensusSignature::from_bytes(
            bytes[signature_start..signature_start + CONSENSUS_SIGNATURE_BYTES]
                .try_into()
                .expect("one certificate signature field is 64 bytes"),
        );

        if let Some(previous) = entries.last() {
            if previous.signer == signer {
                return Err(PrecommitCertificateVerifyError::DuplicateSigner { signer });
            }
            if previous.signer > signer {
                return Err(PrecommitCertificateVerifyError::NonAscendingSignerOrder {
                    previous: previous.signer,
                    actual: signer,
                });
            }
        }
        entries.push(CertificateEntry { signer, signature });
    }

    verify_context(body.context, expected_context)
        .map_err(PrecommitCertificateVerifyError::from)?;
    if body.position != snapshot.position() {
        return Err(PrecommitCertificateVerifyError::SnapshotPositionMismatch {
            certificate: body.position,
            snapshot: snapshot.position(),
        });
    }

    let mut signed_weight = AgreementWeight::ZERO;
    for entry in &entries {
        let signer_weight = snapshot
            .agreement_weight_for(entry.signer)
            .map_err(PrecommitCertificateVerifyError::from)?;
        signed_weight = AgreementWeight::new(
            signed_weight
                .units()
                .checked_add(signer_weight.units())
                .expect("distinct active signer weights cannot exceed the validated total"),
        );
    }

    for entry in &entries {
        verify_vote_signature(body, entry.signer, entry.signature)
            .map_err(PrecommitCertificateVerifyError::from)?;
    }

    let total_weight = snapshot.total_weight();
    if !has_strict_supermajority(signed_weight.units(), total_weight.units()) {
        return Err(
            PrecommitCertificateVerifyError::InsufficientAgreementWeight {
                signed: signed_weight,
                total: total_weight,
            },
        );
    }

    let mut hasher = Sha256::new();
    hasher.update(bytes);

    Ok(VerifiedCertificateCore {
        body,
        entries: entries.into_boxed_slice(),
        id: hasher.finalize().into(),
        signed_weight,
        snapshot,
    })
}

fn decode_vote_body(bytes: &[u8]) -> Result<VoteBody, ConsensusVoteDecodeError> {
    debug_assert_eq!(bytes.len(), VOTE_BODY_BYTES);

    let role = match bytes[ROLE_OFFSET] {
        PREVOTE_TAG => ConsensusVoteRole::Prevote,
        PRECOMMIT_TAG => ConsensusVoteRole::Precommit,
        actual => return Err(ConsensusVoteDecodeError::UnknownRoleTag { actual }),
    };
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
        return Err(ConsensusVoteDecodeError::ReservedGenesisHeight);
    }
    let round_value = u64::from_be_bytes(
        bytes[ROUND_OFFSET..TARGET_TAG_OFFSET]
            .try_into()
            .expect("the fixed consensus-round field is eight bytes"),
    );
    let target_payload: [u8; ProposalSigningRoot::BYTE_LENGTH] = bytes[TARGET_PAYLOAD_OFFSET..]
        .try_into()
        .expect("the fixed vote-target payload is 32 bytes");
    let target = match bytes[TARGET_TAG_OFFSET] {
        NIL_TARGET_TAG => {
            if target_payload != [0_u8; ProposalSigningRoot::BYTE_LENGTH] {
                return Err(ConsensusVoteDecodeError::NonCanonicalNilTarget);
            }
            ConsensusVoteTarget::Nil
        }
        PROPOSAL_TARGET_TAG => {
            ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes(target_payload))
        }
        actual => return Err(ConsensusVoteDecodeError::UnknownTargetTag { actual }),
    };

    Ok(VoteBody {
        context: ConsensusContextV0::new(chain_id, genesis_id, protocol_version),
        position: ConsensusPosition::new(
            ConsensusHeight::new(height_value),
            ConsensusRound::new(round_value),
        ),
        role,
        target,
    })
}

fn signing_transcript(body: VoteBody, signer: ConsensusKey) -> Vec<u8> {
    let domain = body.role.signing_domain();
    let mut bytes = Vec::with_capacity(domain.len() + VOTE_BODY_BYTES + super::CONSENSUS_KEY_BYTES);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&body.to_canonical_bytes());
    bytes.extend_from_slice(signer.as_bytes());
    bytes
}

fn semantic_vote_id(body: VoteBody, signer: ConsensusKey) -> ConsensusVoteId {
    let mut hasher = Sha256::new();
    hasher.update(body.role.signing_domain());
    hasher.update(body.to_canonical_bytes());
    hasher.update(signer.as_bytes());
    ConsensusVoteId(hasher.finalize().into())
}

fn verify_vote_signature(
    body: VoteBody,
    signer: ConsensusKey,
    signature: ConsensusSignature,
) -> Result<(), ConsensusVoteVerifyError> {
    let verifying_key = VerifyingKey::from_bytes(signer.as_bytes())
        .map_err(|_| ConsensusVoteVerifyError::MalformedConsensusKey { signer })?;
    let signature = Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify_strict(&signing_transcript(body, signer), &signature)
        .map_err(|_| ConsensusVoteVerifyError::InvalidSignature { signer })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ContextMismatch {
    Chain {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    Genesis {
        expected: ConsensusGenesisId,
        actual: ConsensusGenesisId,
    },
    ProtocolVersion {
        expected: ConsensusProtocolVersion,
        actual: ConsensusProtocolVersion,
    },
}

pub(super) fn verify_context(
    actual: ConsensusContextV0,
    expected: ConsensusContextV0,
) -> Result<(), ContextMismatch> {
    if actual.chain_id() != expected.chain_id() {
        return Err(ContextMismatch::Chain {
            expected: expected.chain_id(),
            actual: actual.chain_id(),
        });
    }
    if actual.genesis_id() != expected.genesis_id() {
        return Err(ContextMismatch::Genesis {
            expected: expected.genesis_id(),
            actual: actual.genesis_id(),
        });
    }
    if actual.protocol_version() != expected.protocol_version() {
        return Err(ContextMismatch::ProtocolVersion {
            expected: expected.protocol_version(),
            actual: actual.protocol_version(),
        });
    }
    Ok(())
}

/// A failure to strictly decode one canonical signed consensus vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsensusVoteDecodeError {
    /// The input is not exactly one fixed-width signed vote.
    InvalidLength { actual: usize, expected: usize },
    /// The role tag is neither prevote nor precommit.
    UnknownRoleTag { actual: u8 },
    /// Height zero is reserved for genesis and cannot carry a V0 vote.
    ReservedGenesisHeight,
    /// The target tag is neither nil nor proposal.
    UnknownTargetTag { actual: u8 },
    /// A nil target carries nonzero payload bytes and has another representation.
    NonCanonicalNilTarget,
}

impl fmt::Display for ConsensusVoteDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => write!(
                formatter,
                "canonical signed vote length {actual} does not equal {expected} bytes"
            ),
            Self::UnknownRoleTag { actual } => {
                write!(
                    formatter,
                    "canonical signed vote role tag {actual} is unsupported"
                )
            }
            Self::ReservedGenesisHeight => {
                formatter.write_str("canonical signed vote cannot use reserved genesis height zero")
            }
            Self::UnknownTargetTag { actual } => {
                write!(
                    formatter,
                    "canonical signed vote target tag {actual} is unsupported"
                )
            }
            Self::NonCanonicalNilTarget => formatter
                .write_str("canonical nil vote target must carry an all-zero target payload"),
        }
    }
}

impl Error for ConsensusVoteDecodeError {}

/// A failure to decode or authenticate one signed consensus vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsensusVoteVerifyError {
    /// Canonical decoding failed before authentication.
    Decode(ConsensusVoteDecodeError),
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
    /// The raw consensus key is not an RFC 8032 Ed25519 verifying key.
    MalformedConsensusKey { signer: ConsensusKey },
    /// Strict Ed25519 verification failed for the exact signing transcript.
    InvalidSignature { signer: ConsensusKey },
}

impl From<ConsensusVoteDecodeError> for ConsensusVoteVerifyError {
    fn from(error: ConsensusVoteDecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<ContextMismatch> for ConsensusVoteVerifyError {
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

impl fmt::Display for ConsensusVoteVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "signed vote chain identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::GenesisIdMismatch { expected, actual } => write!(
                formatter,
                "signed vote genesis identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                formatter,
                "signed vote protocol version mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::MalformedConsensusKey { signer } => {
                write!(
                    formatter,
                    "signed vote consensus key is malformed: {signer:?}"
                )
            }
            Self::InvalidSignature { signer } => {
                write!(
                    formatter,
                    "signed vote signature is invalid for key {signer:?}"
                )
            }
        }
    }
}

impl Error for ConsensusVoteVerifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

/// A failure to decode or verify one canonical role-complete quorum certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuorumCertificateVerifyError {
    /// The input exceeds the complete 256-signer certificate bound.
    InputTooLong { actual: usize, maximum: usize },
    /// The input cannot contain the fixed body and signer count.
    InvalidLength { actual: usize, minimum: usize },
    /// The shared vote body is malformed or noncanonical.
    VoteBody(ConsensusVoteDecodeError),
    /// A certificate contains no signatures.
    EmptySignerSet,
    /// A certificate declares more than 256 signer entries.
    TooManySigners { actual: usize, maximum: usize },
    /// The declared count does not consume the complete input exactly.
    LengthMismatch { actual: usize, expected: usize },
    /// One consensus key occurs more than once.
    DuplicateSigner { signer: ConsensusKey },
    /// Signer keys are not in strictly ascending raw-byte order.
    NonAscendingSignerOrder {
        previous: ConsensusKey,
        actual: ConsensusKey,
    },
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
    /// The certificate position differs from the borrowed snapshot position.
    SnapshotPositionMismatch {
        certificate: ConsensusPosition,
        snapshot: ConsensusPosition,
    },
    /// One signer does not belong to the borrowed immutable snapshot.
    UnknownSigner { signer: ConsensusKey },
    /// One raw consensus key is not an RFC 8032 Ed25519 verifying key.
    MalformedConsensusKey { signer: ConsensusKey },
    /// One embedded vote fails strict Ed25519 verification.
    InvalidSignature { signer: ConsensusKey },
    /// Verified signers do not exceed two thirds of the unchanged total weight.
    InsufficientAgreementWeight {
        signed: AgreementWeight,
        total: AgreementWeight,
    },
}

impl QuorumCertificateVerifyError {
    fn from_shared(error: PrecommitCertificateVerifyError) -> Self {
        match error {
            PrecommitCertificateVerifyError::InputTooLong { actual, maximum } => {
                Self::InputTooLong { actual, maximum }
            }
            PrecommitCertificateVerifyError::InvalidLength { actual, minimum } => {
                Self::InvalidLength { actual, minimum }
            }
            PrecommitCertificateVerifyError::VoteBody(error) => Self::VoteBody(error),
            PrecommitCertificateVerifyError::WrongVoteRole { .. }
            | PrecommitCertificateVerifyError::NilCertificateTarget => {
                unreachable!("the role-complete certificate policy accepts every V0 vote body")
            }
            PrecommitCertificateVerifyError::EmptySignerSet => Self::EmptySignerSet,
            PrecommitCertificateVerifyError::TooManySigners { actual, maximum } => {
                Self::TooManySigners { actual, maximum }
            }
            PrecommitCertificateVerifyError::LengthMismatch { actual, expected } => {
                Self::LengthMismatch { actual, expected }
            }
            PrecommitCertificateVerifyError::DuplicateSigner { signer } => {
                Self::DuplicateSigner { signer }
            }
            PrecommitCertificateVerifyError::NonAscendingSignerOrder { previous, actual } => {
                Self::NonAscendingSignerOrder { previous, actual }
            }
            PrecommitCertificateVerifyError::ChainIdMismatch { expected, actual } => {
                Self::ChainIdMismatch { expected, actual }
            }
            PrecommitCertificateVerifyError::GenesisIdMismatch { expected, actual } => {
                Self::GenesisIdMismatch { expected, actual }
            }
            PrecommitCertificateVerifyError::ProtocolVersionMismatch { expected, actual } => {
                Self::ProtocolVersionMismatch { expected, actual }
            }
            PrecommitCertificateVerifyError::SnapshotPositionMismatch {
                certificate,
                snapshot,
            } => Self::SnapshotPositionMismatch {
                certificate,
                snapshot,
            },
            PrecommitCertificateVerifyError::UnknownSigner { signer } => {
                Self::UnknownSigner { signer }
            }
            PrecommitCertificateVerifyError::MalformedConsensusKey { signer } => {
                Self::MalformedConsensusKey { signer }
            }
            PrecommitCertificateVerifyError::InvalidSignature { signer } => {
                Self::InvalidSignature { signer }
            }
            PrecommitCertificateVerifyError::InsufficientAgreementWeight { signed, total } => {
                Self::InsufficientAgreementWeight { signed, total }
            }
        }
    }
}

impl fmt::Display for QuorumCertificateVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "quorum certificate length {actual} exceeds {maximum} bytes"
            ),
            Self::InvalidLength { actual, minimum } => write!(
                formatter,
                "quorum certificate length {actual} is shorter than {minimum} bytes"
            ),
            Self::VoteBody(error) => error.fmt(formatter),
            Self::EmptySignerSet => formatter.write_str("quorum certificate has no signer entries"),
            Self::TooManySigners { actual, maximum } => write!(
                formatter,
                "quorum certificate has {actual} signers; the limit is {maximum}"
            ),
            Self::LengthMismatch { actual, expected } => write!(
                formatter,
                "quorum certificate length {actual} does not equal declared length {expected}"
            ),
            Self::DuplicateSigner { signer } => {
                write!(
                    formatter,
                    "quorum certificate repeats consensus key {signer:?}"
                )
            }
            Self::NonAscendingSignerOrder { previous, actual } => write!(
                formatter,
                "quorum certificate key {actual:?} does not follow {previous:?} in ascending order"
            ),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "quorum certificate chain identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::GenesisIdMismatch { expected, actual } => write!(
                formatter,
                "quorum certificate genesis identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                formatter,
                "quorum certificate protocol version mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::SnapshotPositionMismatch {
                certificate,
                snapshot,
            } => write!(
                formatter,
                "quorum certificate position {certificate:?} differs from snapshot position {snapshot:?}"
            ),
            Self::UnknownSigner { signer } => write!(
                formatter,
                "quorum certificate signer is not active in the supplied snapshot: {signer:?}"
            ),
            Self::MalformedConsensusKey { signer } => write!(
                formatter,
                "quorum certificate consensus key is malformed: {signer:?}"
            ),
            Self::InvalidSignature { signer } => write!(
                formatter,
                "quorum certificate signature is invalid for key {signer:?}"
            ),
            Self::InsufficientAgreementWeight { signed, total } => write!(
                formatter,
                "verified quorum weight {} is not greater than two thirds of total {}",
                signed.units(),
                total.units()
            ),
        }
    }
}

impl Error for QuorumCertificateVerifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::VoteBody(error) => Some(error),
            _ => None,
        }
    }
}

/// A failure to decode or verify one canonical precommit certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrecommitCertificateVerifyError {
    /// The input exceeds the complete 256-signer certificate bound.
    InputTooLong { actual: usize, maximum: usize },
    /// The input cannot contain the fixed body and signer count.
    InvalidLength { actual: usize, minimum: usize },
    /// The shared vote body is malformed or noncanonical.
    VoteBody(ConsensusVoteDecodeError),
    /// A certificate contains a prevote body rather than a precommit body.
    WrongVoteRole { actual: ConsensusVoteRole },
    /// This non-nil certificate form cannot carry a nil precommit quorum.
    NilCertificateTarget,
    /// A certificate contains no signatures.
    EmptySignerSet,
    /// A certificate declares more than 256 signer entries.
    TooManySigners { actual: usize, maximum: usize },
    /// The declared count does not consume the complete input exactly.
    LengthMismatch { actual: usize, expected: usize },
    /// One consensus key occurs more than once.
    DuplicateSigner { signer: ConsensusKey },
    /// Signer keys are not in strictly ascending raw-byte order.
    NonAscendingSignerOrder {
        previous: ConsensusKey,
        actual: ConsensusKey,
    },
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
    /// The certificate position differs from the borrowed snapshot position.
    SnapshotPositionMismatch {
        certificate: ConsensusPosition,
        snapshot: ConsensusPosition,
    },
    /// One signer does not belong to the borrowed immutable snapshot.
    UnknownSigner { signer: ConsensusKey },
    /// One raw consensus key is not an RFC 8032 Ed25519 verifying key.
    MalformedConsensusKey { signer: ConsensusKey },
    /// One precommit fails strict Ed25519 verification.
    InvalidSignature { signer: ConsensusKey },
    /// Verified signers do not exceed two thirds of the unchanged total weight.
    InsufficientAgreementWeight {
        signed: AgreementWeight,
        total: AgreementWeight,
    },
}

impl From<ConsensusVoteDecodeError> for PrecommitCertificateVerifyError {
    fn from(error: ConsensusVoteDecodeError) -> Self {
        Self::VoteBody(error)
    }
}

impl From<ContextMismatch> for PrecommitCertificateVerifyError {
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

impl From<AgreementSignerError> for PrecommitCertificateVerifyError {
    fn from(error: AgreementSignerError) -> Self {
        match error {
            AgreementSignerError::UnknownSigner { consensus_key } => Self::UnknownSigner {
                signer: consensus_key,
            },
            AgreementSignerError::DuplicateSigner { consensus_key } => Self::DuplicateSigner {
                signer: consensus_key,
            },
            AgreementSignerError::TooManySigners { actual, maximum } => {
                Self::TooManySigners { actual, maximum }
            }
        }
    }
}

impl From<ConsensusVoteVerifyError> for PrecommitCertificateVerifyError {
    fn from(error: ConsensusVoteVerifyError) -> Self {
        match error {
            ConsensusVoteVerifyError::Decode(error) => Self::VoteBody(error),
            ConsensusVoteVerifyError::ChainIdMismatch { expected, actual } => {
                Self::ChainIdMismatch { expected, actual }
            }
            ConsensusVoteVerifyError::GenesisIdMismatch { expected, actual } => {
                Self::GenesisIdMismatch { expected, actual }
            }
            ConsensusVoteVerifyError::ProtocolVersionMismatch { expected, actual } => {
                Self::ProtocolVersionMismatch { expected, actual }
            }
            ConsensusVoteVerifyError::MalformedConsensusKey { signer } => {
                Self::MalformedConsensusKey { signer }
            }
            ConsensusVoteVerifyError::InvalidSignature { signer } => {
                Self::InvalidSignature { signer }
            }
        }
    }
}

impl fmt::Display for PrecommitCertificateVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "precommit certificate length {actual} exceeds {maximum} bytes"
            ),
            Self::InvalidLength { actual, minimum } => write!(
                formatter,
                "precommit certificate length {actual} is shorter than {minimum} bytes"
            ),
            Self::VoteBody(error) => error.fmt(formatter),
            Self::WrongVoteRole { actual } => write!(
                formatter,
                "precommit certificate carries the wrong vote role: {actual:?}"
            ),
            Self::NilCertificateTarget => {
                formatter.write_str("nil precommits cannot form this non-nil certificate")
            }
            Self::EmptySignerSet => {
                formatter.write_str("precommit certificate has no signer entries")
            }
            Self::TooManySigners { actual, maximum } => write!(
                formatter,
                "precommit certificate has {actual} signers; the limit is {maximum}"
            ),
            Self::LengthMismatch { actual, expected } => write!(
                formatter,
                "precommit certificate length {actual} does not equal declared length {expected}"
            ),
            Self::DuplicateSigner { signer } => write!(
                formatter,
                "precommit certificate repeats consensus key {signer:?}"
            ),
            Self::NonAscendingSignerOrder { previous, actual } => write!(
                formatter,
                "precommit certificate key {actual:?} does not follow {previous:?} in ascending order"
            ),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "precommit certificate chain identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::GenesisIdMismatch { expected, actual } => write!(
                formatter,
                "precommit certificate genesis identity mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                formatter,
                "precommit certificate protocol version mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::SnapshotPositionMismatch {
                certificate,
                snapshot,
            } => write!(
                formatter,
                "precommit certificate position {certificate:?} differs from snapshot position {snapshot:?}"
            ),
            Self::UnknownSigner { signer } => write!(
                formatter,
                "precommit certificate signer is not active in the supplied snapshot: {signer:?}"
            ),
            Self::MalformedConsensusKey { signer } => write!(
                formatter,
                "precommit certificate consensus key is malformed: {signer:?}"
            ),
            Self::InvalidSignature { signer } => write!(
                formatter,
                "precommit certificate signature is invalid for key {signer:?}"
            ),
            Self::InsufficientAgreementWeight { signed, total } => write!(
                formatter,
                "verified precommit weight {} is not greater than two thirds of total {}",
                signed.units(),
                total.units()
            ),
        }
    }
}

impl Error for PrecommitCertificateVerifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::VoteBody(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
