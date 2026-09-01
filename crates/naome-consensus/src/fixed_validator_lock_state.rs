//! In-memory fixed-validator locking and valid-value effects for one height.
//!
//! This kernel starts only from a branch-derived round-zero cursor and moves
//! through proposal, prevote, and precommit effects at one exact position. It
//! retains exact locked and valid values, but creates no signatures and grants
//! no persistence, timeout, networking, peer-trust, branch-selection, or
//! finality authority. Strictly verified precommit/nil evidence may advance one
//! sequential round, while a bounded strictly verified higher-round prevote or
//! precommit quorum may prepare a phase-only jump to its internally derived
//! cursor without emitting a vote or changing lock or valid-value state.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use naome_chain::{ArtifactBlockId, ArtifactChainId, ArtifactSetRoot};
use sha2::{Digest, Sha256};

use super::agreement_evidence::{
    canonical_unsigned_vote_bytes, decode_canonical_quorum_certificate_header,
    exact_vote_signing_transcript,
};
use super::fixed_consensus_branch::{
    FixedConsensusBranchCoordinateV0, FixedConsensusBranchV0, FixedConsensusRoundV0,
    OwnedVerifiedFixedConsensusTransitionV0, VerifiedFixedConsensusProposalV0,
};
use super::{
    CONSENSUS_KEY_BYTES, ConsensusAncestryId, ConsensusContextV0, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusRound, ConsensusSignature, ConsensusValueError, ConsensusValueV0,
    ConsensusVoteRole, ConsensusVoteTarget, ConsensusVoteVerifyError, FixedAgreementSetId,
    ProposalSigningRoot, ProposerSelectionError, QuorumCertificateId, QuorumCertificateVerifyError,
    VerifiedConsensusVoteV0, VerifiedQuorumCertificateV0,
};

const VOTE_INTENT_HEADER: &[u8] = b"naome:fixed-validator-vote-intent:v0\0";
const HIGHER_ROUND_CHECKPOINT_HEADER: &[u8] = b"naome:fixed-validator-higher-round-checkpoint:v0\0";
const VOTE_EFFECT_STATE_BINDING_DOMAIN: &[u8] =
    b"naome:fixed-validator-vote-effect-state-binding:v0\0";
const HIGHER_ROUND_SOURCE_STATE_BINDING_DOMAIN: &[u8] =
    b"naome:fixed-validator-higher-round-source-state-binding:v0\0";
const OPAQUE_ID_BYTES: usize = 32;
const CONTEXT_BYTES: usize = ArtifactChainId::BYTE_LENGTH + 32 + 4;
const VOTE_TARGET_BYTES: usize = 1 + ProposalSigningRoot::BYTE_LENGTH;
const VOTE_INTENT_FIXED_BYTES: usize = CONTEXT_BYTES
    + 1
    + 8
    + 6 * OPAQUE_ID_BYTES
    + 8
    + 8
    + 1
    + 1
    + 1
    + 1
    + VOTE_TARGET_BYTES
    + CONSENSUS_KEY_BYTES;
const STATE_SNAPSHOT_FIXED_BYTES: usize =
    VOTE_INTENT_FIXED_BYTES - 1 - VOTE_TARGET_BYTES - CONSENSUS_KEY_BYTES;
const HIGHER_ROUND_SOURCE_BYTES: usize = 8 + 8 + 1 + OPAQUE_ID_BYTES;
const CERTIFICATE_LENGTH_BYTES: usize = 4;
const LOCK_SNAPSHOT_BYTES: usize = ConsensusValueV0::BYTE_LENGTH + 8;
const VALID_SNAPSHOT_FIXED_BYTES: usize =
    ConsensusValueV0::BYTE_LENGTH + 8 + QuorumCertificateId::BYTE_LENGTH + 4;

const ABSENT_TAG: u8 = 0;
const PRESENT_TAG: u8 = 1;
const PROPOSAL_PHASE_TAG: u8 = 0;
const PREVOTE_PHASE_TAG: u8 = 1;
const PRECOMMIT_PHASE_TAG: u8 = 2;
const PREVOTE_ROLE_TAG: u8 = 1;
const PRECOMMIT_ROLE_TAG: u8 = 2;
const NIL_TARGET_TAG: u8 = 0;
const PROPOSAL_TARGET_TAG: u8 = 1;

/// The exact local decision phase for one fixed-validator consensus round.
///
/// The phase records only which local decision point the kernel may evaluate
/// next. It can follow a locally returned unsigned effect or authenticated
/// phase-only higher-round catch-up; it is not proof that this validator emitted,
/// signed, or broadcast any vote and is not a timer or network-delivery claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorLockPhaseV0 {
    /// The kernel may evaluate one admitted proposal or the absent/invalid path.
    Proposal,
    /// The kernel may evaluate prevote quorum at this position.
    Prevote,
    /// The kernel may evaluate precommit evidence or advance sequentially.
    Precommit,
}

/// One exact value and round retained by the in-memory lock.
///
/// This is local volatile state only. Observing it does not prove a durable
/// lock, canonical branch, finalized value, or permission to sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorLockedValueV0 {
    value: ConsensusValueV0,
    round: ConsensusRound,
}

impl FixedValidatorLockedValueV0 {
    /// Returns the exact locked value.
    pub const fn value(self) -> ConsensusValueV0 {
        self.value
    }

    /// Returns the round whose proposal prevote quorum created this lock.
    pub const fn round(self) -> ConsensusRound {
        self.round
    }

    /// Returns the evidence-free signing root of the exact locked value.
    pub fn proposal_signing_root(self) -> ProposalSigningRoot {
        self.value.proposal_signing_root()
    }
}

/// One exact latest valid value and its retained canonical prevote certificate.
///
/// This is local volatile evidence retained so a later proposer can re-propose
/// the exact value with its proof. The bytes are already-signed canonical quorum
/// evidence; this type exposes no vote-signing transcript or signature creation
/// capability and grants no persistence or finality authority.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorValidValueV0 {
    value: ConsensusValueV0,
    round: ConsensusRound,
    prevote_certificate_id: QuorumCertificateId,
    canonical_prevote_certificate: Vec<u8>,
}

impl FixedValidatorValidValueV0 {
    /// Returns the exact valid value.
    pub const fn value(&self) -> ConsensusValueV0 {
        self.value
    }

    /// Returns the round authenticated by the retained prevote certificate.
    pub const fn round(&self) -> ConsensusRound {
        self.round
    }

    /// Returns the evidence-variant identity of the retained certificate.
    pub const fn prevote_certificate_id(&self) -> QuorumCertificateId {
        self.prevote_certificate_id
    }

    /// Returns the complete already-verified canonical prevote certificate.
    pub fn canonical_prevote_certificate(&self) -> &[u8] {
        &self.canonical_prevote_certificate
    }
}

/// One unsigned local vote effect decided by the locking kernel.
///
/// The effect deliberately exposes only role, position, and target. It is not a
/// signature, signing transcript, authorization, delivery claim, or durable
/// record.
#[derive(Clone, Debug)]
#[must_use]
pub struct FixedValidatorUnsignedVoteEffectV0 {
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    state_binding: [u8; 32],
    live_lineage_seal: Option<Arc<()>>,
}

impl FixedValidatorUnsignedVoteEffectV0 {
    fn new(
        state: &FixedValidatorLockStateV0,
        role: ConsensusVoteRole,
        target: ConsensusVoteTarget,
    ) -> Self {
        let snapshot = vote_snapshot_from_lock_state(state);
        Self {
            position: snapshot.position,
            role,
            target,
            state_binding: vote_effect_state_binding(&snapshot),
            live_lineage_seal: Some(Arc::clone(&state.live_lineage_seal)),
        }
    }

    fn from_snapshot(
        snapshot: &FixedValidatorVoteStateSnapshotV0,
        role: ConsensusVoteRole,
        target: ConsensusVoteTarget,
    ) -> Self {
        Self {
            position: snapshot.position,
            role,
            target,
            state_binding: vote_effect_state_binding(snapshot),
            live_lineage_seal: None,
        }
    }

    fn belongs_to(&self, state: &FixedValidatorLockStateV0) -> bool {
        self.live_lineage_seal
            .as_ref()
            .is_some_and(|seal| Arc::ptr_eq(seal, &state.live_lineage_seal))
    }

    /// Returns the exact height and round for the unsigned effect.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns whether this effect is a prevote or precommit.
    pub const fn role(&self) -> ConsensusVoteRole {
        self.role
    }

    /// Returns the exact nil-or-proposal target.
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.target
    }
}

impl PartialEq for FixedValidatorUnsignedVoteEffectV0 {
    fn eq(&self, other: &Self) -> bool {
        let same_lineage = match (&self.live_lineage_seal, &other.live_lineage_seal) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        };
        self.position == other.position
            && self.role == other.role
            && self.target == other.target
            && self.state_binding == other.state_binding
            && same_lineage
    }
}

impl Eq for FixedValidatorUnsignedVoteEffectV0 {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FixedValidatorVoteStateSnapshotV0 {
    context: ConsensusContextV0,
    parent_verified_height: Option<ConsensusHeight>,
    parent_ancestry_id: ConsensusAncestryId,
    artifact_head_block_id: ArtifactBlockId,
    artifact_set_root: ArtifactSetRoot,
    fixed_agreement_set_id: FixedAgreementSetId,
    parent_proposer_priority_state_id: [u8; OPAQUE_ID_BYTES],
    post_height_proposer_priority_state_id: [u8; OPAQUE_ID_BYTES],
    position: ConsensusPosition,
    phase: FixedValidatorLockPhaseV0,
    locked: Option<FixedValidatorLockedValueV0>,
    valid: Option<FixedValidatorValidValueV0>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixedValidatorProposalStateSnapshotV0 {
    snapshot: FixedValidatorVoteStateSnapshotV0,
    canonical_bytes: Vec<u8>,
}

impl FixedValidatorProposalStateSnapshotV0 {
    pub(crate) const MIN_BYTE_LENGTH: usize = STATE_SNAPSHOT_FIXED_BYTES;
    pub(crate) const MAX_BYTE_LENGTH: usize = STATE_SNAPSHOT_FIXED_BYTES
        + LOCK_SNAPSHOT_BYTES
        + VALID_SNAPSHOT_FIXED_BYTES
        + VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH;

    pub(crate) fn from_lock_state(
        state: &FixedValidatorLockStateV0,
    ) -> Result<Self, FixedValidatorVoteIntentError> {
        let snapshot = vote_snapshot_from_lock_state(state);
        let length = state_snapshot_length(&snapshot)?;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(length)
            .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
        append_state_snapshot(&mut canonical_bytes, &snapshot);
        debug_assert_eq!(canonical_bytes.len(), length);
        Ok(Self {
            snapshot,
            canonical_bytes,
        })
    }

    pub(crate) fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        expected_fixed_agreement_set_id: FixedAgreementSetId,
    ) -> Result<Self, FixedValidatorVoteIntentError> {
        let mut decoder = VoteIntentDecoder::new(bytes);
        let snapshot = decode_state_snapshot(
            &mut decoder,
            expected_context,
            expected_fixed_agreement_set_id,
        )?;
        decoder.finish()?;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
        canonical_bytes.extend_from_slice(bytes);
        let mut expected = Vec::new();
        expected
            .try_reserve_exact(state_snapshot_length(&snapshot)?)
            .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
        append_state_snapshot(&mut expected, &snapshot);
        if expected != canonical_bytes {
            return Err(FixedValidatorVoteIntentError::NonCanonicalEncoding);
        }
        Ok(Self {
            snapshot,
            canonical_bytes,
        })
    }

    pub(crate) const fn position(&self) -> ConsensusPosition {
        self.snapshot.position
    }

    pub(crate) const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.snapshot.phase
    }

    pub(crate) const fn context(&self) -> ConsensusContextV0 {
        self.snapshot.context
    }

    pub(crate) const fn valid_value(&self) -> Option<&FixedValidatorValidValueV0> {
        self.snapshot.valid.as_ref()
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn restore_for_round(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteIntentError> {
        restore_snapshot_for_round(&self.snapshot, round)
    }
}

/// One strictly decoded but non-authoritative vote-state record.
///
/// Header-bound decoding proves canonical framing, bounded evidence, internal
/// state/effect consistency, and equality to caller-expected context, fixed-set
/// identity, and local signer. It deliberately exposes no signing transcript or
/// signature-completion API. Verification against the exact typed round can
/// reconstruct only a non-signable [`VerifiedReplayFixedValidatorVoteIntentV0`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ObservedFixedValidatorVoteIntentV0 {
    snapshot: FixedValidatorVoteStateSnapshotV0,
    effect: FixedValidatorUnsignedVoteEffectV0,
    signer: ConsensusKey,
    canonical_state_and_vote_intent_bytes: Vec<u8>,
}

/// One exact post-effect lock state and vote intent authorized by a typed round.
///
/// This sealed value is created only by the live locking kernel. Canonical
/// replay deliberately cannot recreate it. It contains no key material and
/// cannot create a signature. A caller must first
/// durably record [`Self::canonical_state_and_vote_intent_bytes`], then sign the
/// exposed pre-existing agreement transcript, and finally pass the raw signature
/// back through [`Self::complete_with_signature`] for strict verification.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorVoteIntentV0 {
    observed: ObservedFixedValidatorVoteIntentV0,
    signing_transcript: Vec<u8>,
}

/// One canonical record reconstructed against its exact typed round.
///
/// Restart verification reconstructs the lock state but deliberately does not
/// recreate live signing authority. If a crash occurred after preparing an
/// intent but before durably storing a completed signed vote, V0 fails closed.
#[derive(Debug)]
#[must_use]
pub struct VerifiedReplayFixedValidatorVoteIntentV0 {
    lock_state: FixedValidatorLockStateV0,
}

/// One verified phase-only higher-round transition prepared by a live lock state.
///
/// The target cursor is derived internally from the exact current cursor and the
/// embedded quorum-certificate position. Private fields bind the transition to
/// the originating live state, retain the exact canonical certificate and
/// complete post-jump checkpoint bytes, and expose no unsigned vote, signing,
/// proposal, selection, or finality authority.
#[must_use]
pub struct VerifiedFixedValidatorHigherRoundAdvanceV0<'branch> {
    target_round: FixedConsensusRoundV0<'branch>,
    source_state_binding: [u8; OPAQUE_ID_BYTES],
    live_lineage_seal: Arc<()>,
    target_phase: FixedValidatorLockPhaseV0,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    certificate_id: QuorumCertificateId,
    canonical_certificate: Vec<u8>,
    canonical_checkpoint: Vec<u8>,
}

impl VerifiedFixedValidatorHigherRoundAdvanceV0<'_> {
    /// Returns the exact internally derived higher-round position.
    pub const fn position(&self) -> ConsensusPosition {
        self.target_round.position()
    }

    /// Returns the role-corresponding destination phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.target_phase
    }

    /// Returns the authenticated quorum role.
    pub const fn role(&self) -> ConsensusVoteRole {
        self.role
    }

    /// Returns the authenticated nil-or-proposal target.
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.target
    }

    /// Returns the evidence-variant identity of the complete certificate.
    pub const fn certificate_id(&self) -> QuorumCertificateId {
        self.certificate_id
    }

    /// Returns the exact canonical triggering quorum certificate.
    pub fn canonical_certificate(&self) -> &[u8] {
        &self.canonical_certificate
    }

    /// Returns the exact canonical durable checkpoint representation.
    pub fn canonical_checkpoint_bytes(&self) -> &[u8] {
        &self.canonical_checkpoint
    }
}

/// One inert structurally verified higher-round checkpoint record.
///
/// Header-bound decoding validates canonical framing, state invariants,
/// source-to-target preservation, and the exact embedded certificate header.
/// It cannot authenticate certificate signatures or membership without the
/// private positioned fixed-set snapshot supplied later by an exact typed
/// round.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ObservedFixedValidatorHigherRoundCheckpointV0 {
    source_position: ConsensusPosition,
    source_phase: FixedValidatorLockPhaseV0,
    source_state_binding: [u8; OPAQUE_ID_BYTES],
    target_snapshot: FixedValidatorVoteStateSnapshotV0,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    certificate_id: QuorumCertificateId,
    canonical_certificate: Vec<u8>,
    canonical_checkpoint: Vec<u8>,
}

/// One exact higher-round checkpoint reconstructed against its typed target.
///
/// This value carries only a non-signing lock state. A key-owning journal may
/// publish it as live state only after its own exact external-anchor and session
/// issuance checks succeed.
#[derive(Debug)]
#[must_use]
pub struct VerifiedReplayFixedValidatorHigherRoundCheckpointV0 {
    lock_state: FixedValidatorLockStateV0,
}

impl ObservedFixedValidatorVoteIntentV0 {
    /// Smallest complete record: no lock and no retained valid value.
    pub const MIN_BYTE_LENGTH: usize = VOTE_INTENT_HEADER.len() + VOTE_INTENT_FIXED_BYTES;

    /// Largest complete record: both lock and a 256-signer retained prevote QC.
    pub const MAX_BYTE_LENGTH: usize = Self::MIN_BYTE_LENGTH
        + LOCK_SNAPSHOT_BYTES
        + VALID_SNAPSHOT_FIXED_BYTES
        + VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH;

    /// Strictly decodes one canonical, bounded record against journal header inputs.
    ///
    /// This operation does not verify active membership, the parent branch,
    /// proposer state, retained QC signatures/weight, or current round authority.
    /// Success is intentionally non-signable until [`Self::verify_for_round`].
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        expected_fixed_agreement_set_id: FixedAgreementSetId,
        expected_signer: ConsensusKey,
    ) -> Result<Self, FixedValidatorVoteIntentError> {
        decode_observed_vote_intent(
            bytes,
            expected_context,
            expected_fixed_agreement_set_id,
            expected_signer,
        )
    }

    /// Returns the exact embedded consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.snapshot.context
    }

    /// Returns the exact embedded immutable fixed-set identity.
    pub const fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.snapshot.fixed_agreement_set_id
    }

    /// Returns the exact embedded height and round.
    pub const fn position(&self) -> ConsensusPosition {
        self.snapshot.position
    }

    /// Returns the inert decoded post-effect local phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.snapshot.phase
    }

    /// Returns the inert decoded vote role.
    pub const fn role(&self) -> ConsensusVoteRole {
        self.effect.role
    }

    /// Returns the inert decoded nil-or-proposal target.
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.effect.target
    }

    /// Returns the caller-expected local signer bound into the record.
    pub const fn signer(&self) -> ConsensusKey {
        self.signer
    }

    /// Returns the complete canonical post-effect state and vote-intent bytes.
    pub fn canonical_state_and_vote_intent_bytes(&self) -> &[u8] {
        &self.canonical_state_and_vote_intent_bytes
    }

    /// Upgrades this observed record only against its exact branch-derived round.
    pub fn verify_for_round(
        self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<VerifiedReplayFixedValidatorVoteIntentV0, FixedValidatorVoteIntentError> {
        let lock_state = restore_lock_state_for_round(&self, round)?;
        Ok(VerifiedReplayFixedValidatorVoteIntentV0 { lock_state })
    }
}

impl FixedValidatorVoteIntentV0 {
    /// Smallest complete canonical state-and-intent record.
    pub const MIN_BYTE_LENGTH: usize = ObservedFixedValidatorVoteIntentV0::MIN_BYTE_LENGTH;

    /// Largest complete canonical state-and-intent record.
    pub const MAX_BYTE_LENGTH: usize = ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH;

    fn from_observed(observed: ObservedFixedValidatorVoteIntentV0) -> Self {
        let signing_transcript = exact_vote_signing_transcript(
            observed.context(),
            observed.position(),
            observed.effect.role,
            observed.effect.target,
            observed.signer,
        );
        Self {
            observed,
            signing_transcript,
        }
    }

    /// Returns the exact consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.observed.context()
    }

    /// Returns the exact immutable fixed-set identity.
    pub const fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.observed.fixed_agreement_set_id()
    }

    /// Returns the exact height and round.
    pub const fn position(&self) -> ConsensusPosition {
        self.observed.position()
    }

    /// Returns the exact vote role.
    pub const fn role(&self) -> ConsensusVoteRole {
        self.observed.role()
    }

    /// Returns the exact nil-or-proposal target.
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.observed.target()
    }

    /// Returns the exact local consensus signer.
    pub const fn signer(&self) -> ConsensusKey {
        self.observed.signer()
    }

    /// Returns the complete canonical post-effect state and vote-intent record.
    pub fn canonical_state_and_vote_intent_bytes(&self) -> &[u8] {
        self.observed.canonical_state_and_vote_intent_bytes()
    }

    /// Returns the existing role-domain-prefixed agreement signing transcript.
    ///
    /// These bytes contain exactly the canonical 118-byte vote body followed by
    /// the 32-byte signer, under the existing role-specific domain. They do not
    /// contain the state snapshot; durable storage must bind the complete record
    /// before any signature is requested.
    pub fn signing_transcript(&self) -> &[u8] {
        &self.signing_transcript
    }

    /// Strictly verifies one raw signature over this exact existing transcript.
    pub fn complete_with_signature(
        &self,
        signature: ConsensusSignature,
    ) -> Result<VerifiedConsensusVoteV0, ConsensusVoteVerifyError> {
        let unsigned = canonical_unsigned_vote_bytes(
            self.context(),
            self.position(),
            self.role(),
            self.target(),
            self.signer(),
        );
        let mut bytes = [0_u8; VerifiedConsensusVoteV0::BYTE_LENGTH];
        bytes[..unsigned.len()].copy_from_slice(&unsigned);
        bytes[unsigned.len()..].copy_from_slice(signature.as_bytes());
        VerifiedConsensusVoteV0::decode_and_verify(&bytes, self.context())
    }
}

impl VerifiedReplayFixedValidatorVoteIntentV0 {
    /// Strictly decodes and reconstructs a record against one exact typed round.
    pub fn decode_and_verify_for_round(
        bytes: &[u8],
        round: &FixedConsensusRoundV0<'_>,
        expected_signer: ConsensusKey,
    ) -> Result<Self, FixedValidatorVoteIntentError> {
        ObservedFixedValidatorVoteIntentV0::decode_and_verify(
            bytes,
            round.context(),
            round.parent_coordinate().fixed_agreement_set_id(),
            expected_signer,
        )?
        .verify_for_round(round)
    }

    /// Returns the reconstructed exact post-effect lock state.
    pub const fn lock_state(&self) -> &FixedValidatorLockStateV0 {
        &self.lock_state
    }

    /// Consumes the non-signable replay and resumes its exact post-effect state.
    pub fn into_lock_state(self) -> FixedValidatorLockStateV0 {
        self.lock_state
    }
}

impl ObservedFixedValidatorHigherRoundCheckpointV0 {
    /// Smallest checkpoint: empty state plus a one-signer quorum certificate.
    pub const MIN_BYTE_LENGTH: usize = HIGHER_ROUND_CHECKPOINT_HEADER.len()
        + HIGHER_ROUND_SOURCE_BYTES
        + STATE_SNAPSHOT_FIXED_BYTES
        + CERTIFICATE_LENGTH_BYTES
        + VerifiedQuorumCertificateV0::MIN_BYTE_LENGTH;

    /// Largest checkpoint: lock, retained valid proof, and two 256-signer QCs.
    pub const MAX_BYTE_LENGTH: usize = Self::MIN_BYTE_LENGTH
        + LOCK_SNAPSHOT_BYTES
        + VALID_SNAPSHOT_FIXED_BYTES
        + 2 * VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH
        - VerifiedQuorumCertificateV0::MIN_BYTE_LENGTH;

    /// Strictly decodes one inert canonical checkpoint against journal headers.
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_context: ConsensusContextV0,
        expected_fixed_agreement_set_id: FixedAgreementSetId,
    ) -> Result<Self, FixedValidatorHigherRoundCheckpointErrorV0> {
        decode_observed_higher_round_checkpoint(
            bytes,
            expected_context,
            expected_fixed_agreement_set_id,
        )
    }

    /// Returns the exact pre-jump position committed by the checkpoint.
    pub const fn source_position(&self) -> ConsensusPosition {
        self.source_position
    }

    /// Returns the exact pre-jump local phase.
    pub const fn source_phase(&self) -> FixedValidatorLockPhaseV0 {
        self.source_phase
    }

    /// Returns the exact post-jump position.
    pub const fn position(&self) -> ConsensusPosition {
        self.target_snapshot.position
    }

    /// Returns the role-corresponding post-jump phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.target_snapshot.phase
    }

    /// Returns the authenticated role recorded by the certificate header.
    pub const fn role(&self) -> ConsensusVoteRole {
        self.role
    }

    /// Returns the authenticated nil-or-proposal target.
    pub const fn target(&self) -> ConsensusVoteTarget {
        self.target
    }

    /// Returns the evidence identity of the retained exact certificate bytes.
    pub const fn certificate_id(&self) -> QuorumCertificateId {
        self.certificate_id
    }

    /// Returns the byte-identical retained canonical quorum certificate.
    pub fn canonical_certificate(&self) -> &[u8] {
        &self.canonical_certificate
    }

    /// Returns the complete canonical checkpoint bytes.
    pub fn canonical_checkpoint_bytes(&self) -> &[u8] {
        &self.canonical_checkpoint
    }

    /// Fully verifies and restores this checkpoint at its exact typed target.
    pub fn verify_for_round(
        self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<
        VerifiedReplayFixedValidatorHigherRoundCheckpointV0,
        FixedValidatorHigherRoundCheckpointErrorV0,
    > {
        let lock_state = restore_higher_round_checkpoint_for_round(&self, round)?;
        Ok(VerifiedReplayFixedValidatorHigherRoundCheckpointV0 { lock_state })
    }
}

impl VerifiedReplayFixedValidatorHigherRoundCheckpointV0 {
    /// Strictly decodes and reconstructs a checkpoint at one exact typed round.
    pub fn decode_and_verify_for_round(
        bytes: &[u8],
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<Self, FixedValidatorHigherRoundCheckpointErrorV0> {
        ObservedFixedValidatorHigherRoundCheckpointV0::decode_and_verify(
            bytes,
            round.context(),
            round.parent_coordinate().fixed_agreement_set_id(),
        )?
        .verify_for_round(round)
    }

    /// Returns the reconstructed non-signing lock state.
    pub const fn lock_state(&self) -> &FixedValidatorLockStateV0 {
        &self.lock_state
    }

    /// Consumes the replay proof and returns its exact post-jump state.
    pub fn into_lock_state(self) -> FixedValidatorLockStateV0 {
        self.lock_state
    }
}

/// One sealed, volatile fixed-validator lock state for a single height.
///
/// Construction requires the exact branch-derived round-zero cursor. All state
/// fields are private, and every fallible mutation validates its complete inputs
/// before changing the state. The state does not own a round cursor. Ordinary
/// paths accept only exact current or sequential-successor cursors; the bounded
/// higher-round path instead derives `R + 1` through its authenticated target
/// internally from one exact current cursor.
#[derive(Debug)]
#[must_use]
pub struct FixedValidatorLockStateV0 {
    live_lineage_seal: Arc<()>,
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    post_height_proposer_priority_state_id: super::ProposerPriorityStateId,
    position: ConsensusPosition,
    phase: FixedValidatorLockPhaseV0,
    locked: Option<FixedValidatorLockedValueV0>,
    valid: Option<FixedValidatorValidValueV0>,
}

impl FixedValidatorLockStateV0 {
    /// Starts an empty volatile lock state from one branch-derived round zero.
    ///
    /// A later-round cursor is rejected even though such cursors are themselves
    /// valid branch-derived objects. This keeps the initial absence of lock and
    /// valid state tied to the sole beginning of one height.
    pub fn try_from_round_zero(
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<Self, FixedValidatorLockStateError> {
        if round.position().round() != ConsensusRound::new(0) {
            return Err(FixedValidatorLockStateError::InitialRoundNotZero {
                actual: round.position().round(),
            });
        }

        Ok(Self {
            live_lineage_seal: Arc::new(()),
            parent_coordinate: round.parent_coordinate(),
            post_height_proposer_priority_state_id: round.post_height_proposer_priority_state_id(),
            position: round.position(),
            phase: FixedValidatorLockPhaseV0::Proposal,
            locked: None,
            valid: None,
        })
    }

    /// Returns the exact current height and round.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns the exact current local decision phase.
    pub const fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.phase
    }

    /// Returns the current volatile lock, if any.
    pub const fn locked_value(&self) -> Option<FixedValidatorLockedValueV0> {
        self.locked
    }

    /// Returns the latest retained valid value and proof, if any.
    pub const fn valid_value(&self) -> Option<&FixedValidatorValidValueV0> {
        self.valid.as_ref()
    }

    /// Seals the exact post-effect state and vote intent for durable admission.
    ///
    /// The supplied effect must be the current state transition's unforgeable
    /// unsigned result, the round must be the state's exact branch-derived
    /// cursor, and the expected signer must belong to that fixed snapshot. This
    /// method grants no key custody, persistence, signature, or release authority.
    pub fn prepare_vote_intent(
        &self,
        round: &FixedConsensusRoundV0<'_>,
        effect: FixedValidatorUnsignedVoteEffectV0,
        signer: ConsensusKey,
    ) -> Result<FixedValidatorVoteIntentV0, FixedValidatorVoteIntentError> {
        self.validate_current_round(round)
            .map_err(FixedValidatorVoteIntentError::LockState)?;
        if !round.verifies_consensus_signer(signer) {
            return Err(FixedValidatorVoteIntentError::SignerNotInFixedSet { signer });
        }
        let snapshot = vote_snapshot_from_lock_state(self);
        validate_effect_for_snapshot(&snapshot, &effect)?;
        if !effect.belongs_to(self) {
            return Err(FixedValidatorVoteIntentError::EffectLineageMismatch);
        }
        let canonical_state_and_vote_intent_bytes =
            encode_state_and_vote_intent(&snapshot, &effect, signer)?;
        let observed = ObservedFixedValidatorVoteIntentV0 {
            snapshot,
            effect,
            signer,
            canonical_state_and_vote_intent_bytes,
        };
        Ok(FixedValidatorVoteIntentV0::from_observed(observed))
    }

    /// Decides the prevote effect for one admitted current-position proposal.
    ///
    /// An unlocked state prevotes the proposal. A matching lock also prevotes
    /// the proposal. A conflicting lock is cleared, and the proposal is
    /// prevoted, only when the proposal carries verified proof for a round `P`
    /// satisfying `locked_round < P < current_round`. Otherwise the lock is
    /// retained and its exact root is prevoted. A newer attached valid-round
    /// certificate is retained even when it does not unlock the current lock.
    pub fn decide_prevote_for_proposal(
        &mut self,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorLockStateError> {
        self.decide_prevote_for_observation(AdmittedProposalObservation::from_verified(proposal))
    }

    /// Decides the absent-or-rejected-proposal prevote effect.
    ///
    /// An existing lock is prevoted; otherwise the effect is nil. The operation
    /// does not alter lock or valid state.
    pub fn decide_prevote_without_proposal(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorLockStateError> {
        self.require_phase(FixedValidatorLockPhaseV0::Proposal)?;
        let target = self.locked.map_or(ConsensusVoteTarget::Nil, |locked| {
            ConsensusVoteTarget::Proposal(locked.proposal_signing_root())
        });

        self.phase = FixedValidatorLockPhaseV0::Prevote;
        Ok(FixedValidatorUnsignedVoteEffectV0::new(
            self,
            ConsensusVoteRole::Prevote,
            target,
        ))
    }

    /// Applies a current-round proposal prevote quorum and decides precommit.
    ///
    /// The raw certificate is first verified against the supplied current
    /// branch-derived cursor's private fixed-set snapshot. The exact admitted
    /// proposal then becomes both the current lock and latest valid value at the
    /// current round. Canonical certificate bytes are copied before any state
    /// change. No signature is created.
    pub fn decide_precommit_for_proposal_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorLockStateError> {
        self.require_phase(FixedValidatorLockPhaseV0::Prevote)?;
        self.validate_current_round(round)?;
        let certificate = round
            .decode_and_verify_quorum_certificate(canonical_certificate)
            .map_err(FixedValidatorLockStateError::QuorumVerification)?;
        let canonical_certificate = try_copy_certificate(canonical_certificate)?;
        self.decide_precommit_for_proposal_observation(
            AdmittedProposalObservation::from_verified(proposal),
            PrevoteQuorumObservation::from_verified(&certificate, canonical_certificate),
        )
    }

    /// Applies a current-round nil prevote quorum and decides nil precommit.
    ///
    /// The raw certificate is first verified against the supplied current
    /// branch-derived cursor's private fixed-set snapshot. A verified nil quorum
    /// clears the current lock but preserves the latest valid value and proof.
    pub fn decide_precommit_for_nil_quorum(
        &mut self,
        round: &FixedConsensusRoundV0<'_>,
        canonical_certificate: &[u8],
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorLockStateError> {
        self.require_phase(FixedValidatorLockPhaseV0::Prevote)?;
        self.validate_current_round(round)?;
        let certificate = round
            .decode_and_verify_quorum_certificate(canonical_certificate)
            .map_err(FixedValidatorLockStateError::QuorumVerification)?;
        let certificate = PrevoteQuorumObservation::from_verified(&certificate, Vec::new());
        self.validate_current_prevote_quorum(&certificate, ConsensusVoteTarget::Nil)?;

        self.locked = None;
        self.phase = FixedValidatorLockPhaseV0::Precommit;
        Ok(FixedValidatorUnsignedVoteEffectV0::new(
            self,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Nil,
        ))
    }

    /// Decides nil precommit when no current-round prevote quorum is available.
    ///
    /// Both the existing lock and latest valid value are preserved.
    pub fn decide_precommit_without_quorum(
        &mut self,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorLockStateError> {
        self.require_phase(FixedValidatorLockPhaseV0::Prevote)?;
        self.phase = FixedValidatorLockPhaseV0::Precommit;
        Ok(FixedValidatorUnsignedVoteEffectV0::new(
            self,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Nil,
        ))
    }

    /// Advances to one exact branch-derived sequential round cursor.
    ///
    /// Advancement is available only after the current precommit effect and
    /// accepts exactly `R + 1` at the unchanged height and parent branch.
    /// Existing lock and valid state are preserved. This is not a timeout or a
    /// higher-round certificate/jump API; the caller must derive the supplied
    /// cursor separately and cannot use this method to move more than one round.
    pub fn advance_round(
        &mut self,
        next_round: &FixedConsensusRoundV0<'_>,
    ) -> Result<(), FixedValidatorLockStateError> {
        self.require_phase(FixedValidatorLockPhaseV0::Precommit)?;
        let next_position = self.validate_next_round(next_round)?;

        self.apply_round_advance(next_position);
        Ok(())
    }

    /// Advances after one exact current-round precommit/nil quorum.
    ///
    /// The current cursor is checked and its exact sequential successor is
    /// derived before certificate work. The canonical certificate is then
    /// strictly verified against the current cursor's private positioned
    /// fixed-set snapshot and must authenticate a strict-supermajority
    /// precommit for nil. That evidence may preempt the local Proposal, Prevote,
    /// or Precommit phase, but it can move only to the internally derived next
    /// same-branch round. Lock and complete valid-value state are preserved, and
    /// no value is finalized.
    ///
    /// This operation does not infer or schedule a timeout, create a signature,
    /// persist evidence, select a branch, or trust a peer.
    pub fn advance_round_for_nil_precommit_quorum<'branch>(
        &mut self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorLockStateError> {
        self.validate_current_round(current_round)?;
        let next_round = current_round
            .derive_next_round()
            .map_err(FixedValidatorLockStateError::NextRoundDerivation)?;
        let certificate = current_round
            .decode_and_verify_quorum_certificate(canonical_certificate)
            .map_err(FixedValidatorLockStateError::QuorumVerification)?;
        if certificate.role() != ConsensusVoteRole::Precommit {
            return Err(
                FixedValidatorLockStateError::NilPrecommitQuorumRoleMismatch {
                    actual: certificate.role(),
                },
            );
        }
        if certificate.target() != ConsensusVoteTarget::Nil {
            return Err(
                FixedValidatorLockStateError::NilPrecommitQuorumTargetMismatch {
                    actual: certificate.target(),
                },
            );
        }

        self.apply_round_advance(next_round.position());
        Ok(next_round)
    }

    /// Prepares a bounded phase-only jump to an authenticated higher round.
    ///
    /// The current cursor and positive caller-local inclusive maximum are
    /// checked before the canonical certificate's strictly framed embedded
    /// position is used. The position must name the same height and a round
    /// `P` with `current < P <= maximum`; only then are sequential same-branch
    /// cursors derived internally and the same bytes fully verified against
    /// `P`'s private positioned fixed-set snapshot. Either prevote target lands
    /// at `P/Prevote`; either precommit target lands at `P/Precommit`.
    ///
    /// Success does not mutate this state or emit a vote. The returned sealed
    /// transition retains the exact QC and complete post-jump checkpoint while
    /// binding application to this unchanged live state.
    pub fn prepare_higher_round_quorum_advance<'branch>(
        &self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<VerifiedFixedValidatorHigherRoundAdvanceV0<'branch>, FixedValidatorLockStateError>
    {
        self.validate_current_round(current_round)?;
        if inclusive_maximum_round.value() == 0 {
            return Err(FixedValidatorLockStateError::HigherRoundWorkLimitNotPositive);
        }
        let position = VerifiedQuorumCertificateV0::strictly_peek_position(canonical_certificate)
            .map_err(FixedValidatorLockStateError::HigherRoundCertificatePosition)?;
        if position.height() != self.position.height() {
            return Err(FixedValidatorLockStateError::HigherRoundHeightMismatch {
                expected: self.position.height(),
                actual: position.height(),
            });
        }
        if position.round() <= self.position.round() {
            return Err(
                FixedValidatorLockStateError::HigherRoundNotStrictlyGreater {
                    current: self.position.round(),
                    actual: position.round(),
                },
            );
        }
        if position.round() > inclusive_maximum_round {
            return Err(FixedValidatorLockStateError::HigherRoundLimitExceeded {
                round: position.round(),
                maximum: inclusive_maximum_round,
            });
        }

        let mut target_round = current_round
            .derive_next_round()
            .map_err(FixedValidatorLockStateError::HigherRoundDerivation)?;
        while target_round.position().round() < position.round() {
            target_round = target_round
                .derive_next_round()
                .map_err(FixedValidatorLockStateError::HigherRoundDerivation)?;
        }
        debug_assert_eq!(target_round.position(), position);
        let certificate = target_round
            .decode_and_verify_quorum_certificate(canonical_certificate)
            .map_err(FixedValidatorLockStateError::QuorumVerification)?;
        let role = certificate.role();
        let target = certificate.target();
        let certificate_id = certificate.id();
        let target_phase = phase_for_role(role);
        let canonical_certificate = try_copy_certificate(canonical_certificate)?;

        let source_snapshot = vote_snapshot_from_lock_state(self);
        let source_state_binding = higher_round_source_state_binding(&source_snapshot);
        let mut target_snapshot = source_snapshot.clone();
        target_snapshot.position = position;
        target_snapshot.phase = target_phase;
        let canonical_checkpoint = encode_higher_round_checkpoint(
            self.position,
            self.phase,
            source_state_binding,
            &target_snapshot,
            &canonical_certificate,
        )
        .map_err(|_| FixedValidatorLockStateError::HigherRoundCheckpointAllocationFailed)?;

        Ok(VerifiedFixedValidatorHigherRoundAdvanceV0 {
            target_round,
            source_state_binding,
            live_lineage_seal: Arc::clone(&self.live_lineage_seal),
            target_phase,
            role,
            target,
            certificate_id,
            canonical_certificate,
            canonical_checkpoint,
        })
    }

    /// Applies one still-current prepared higher-round transition.
    ///
    /// Pointer-identical live-lineage provenance and the complete source-state
    /// binding are rechecked before only position and phase change. Lock and
    /// complete valid-value evidence remain byte-identical. Consuming the token
    /// returns the internally derived target cursor and publishes no vote or
    /// finality authority.
    pub fn apply_prepared_higher_round_quorum_advance<'branch>(
        &mut self,
        prepared: VerifiedFixedValidatorHigherRoundAdvanceV0<'branch>,
    ) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorLockStateError> {
        if !Arc::ptr_eq(&self.live_lineage_seal, &prepared.live_lineage_seal) {
            return Err(FixedValidatorLockStateError::HigherRoundAdvanceLineageMismatch);
        }
        let source_snapshot = vote_snapshot_from_lock_state(self);
        if higher_round_source_state_binding(&source_snapshot) != prepared.source_state_binding {
            return Err(FixedValidatorLockStateError::HigherRoundAdvanceStateMismatch);
        }

        self.position = prepared.target_round.position();
        self.phase = prepared.target_phase;
        Ok(prepared.target_round)
    }

    fn validate_next_round(
        &self,
        next_round: &FixedConsensusRoundV0<'_>,
    ) -> Result<ConsensusPosition, FixedValidatorLockStateError> {
        if next_round.parent_coordinate() != self.parent_coordinate
            || next_round.post_height_proposer_priority_state_id()
                != self.post_height_proposer_priority_state_id
        {
            return Err(FixedValidatorLockStateError::RoundBranchMismatch);
        }

        let expected_round = self
            .position
            .round()
            .value()
            .checked_add(1)
            .map(ConsensusRound::new)
            .ok_or(FixedValidatorLockStateError::RoundExhausted)?;
        let expected = ConsensusPosition::new(self.position.height(), expected_round);
        if next_round.position() != expected {
            return Err(FixedValidatorLockStateError::NonSequentialRound {
                expected,
                actual: next_round.position(),
            });
        }

        Ok(expected)
    }

    fn apply_round_advance(&mut self, next_position: ConsensusPosition) {
        self.position = next_position;
        self.phase = FixedValidatorLockPhaseV0::Proposal;
    }

    /// Validates one owned verified direct-child transition without mutation.
    ///
    /// The transition must have been verified from this state's exact parent
    /// coordinate and current height, and its sealed child must derive an exact
    /// round-zero cursor. The returned position describes that cursor without
    /// exposing or consuming the child branch.
    ///
    /// Validation grants no signing, persistence, branch-selection, finality,
    /// networking, or peer-trust authority.
    pub fn validate_height_transition(
        &self,
        transition: &OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<ConsensusPosition, FixedValidatorLockStateError> {
        if transition.parent_coordinate() != self.parent_coordinate {
            return Err(FixedValidatorLockStateError::HeightTransitionParentMismatch);
        }

        let actual = transition.position().height();
        let expected = self.position.height();
        if actual != expected {
            return Err(
                FixedValidatorLockStateError::HeightTransitionHeightMismatch { expected, actual },
            );
        }

        transition
            .child_round_zero_position()
            .map_err(FixedValidatorLockStateError::HeightTransitionRoundZero)
    }

    /// Resets this local lock state at one exact verified direct child height.
    ///
    /// The supplied transition must have been verified from this state's exact
    /// parent coordinate and current height. The operation consumes that proof,
    /// derives the child only from its sealed internal branch, and derives round
    /// zero only from that child before replacing the state. Existing lock and
    /// valid-value evidence are cleared because they belong to the completed
    /// parent height. The exact child is returned so the caller can derive the
    /// same round cursor for later state-bound operations.
    ///
    /// This is a caller-selected local signing-lineage transition. It does not
    /// select a globally canonical branch, install durable finality, persist the
    /// child, or grant networking or peer-trust authority.
    pub fn advance_height_with_verified_transition(
        &mut self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorLockStateError> {
        let expected_position = self.validate_height_transition(&transition)?;

        let child = transition.into_branch();
        let round_zero = child
            .begin_round_zero()
            .expect("a validated child still derives its exact round-zero cursor");
        debug_assert_eq!(round_zero.position(), expected_position);
        let next_state = Self::try_from_round_zero(&round_zero)
            .expect("a child branch always derives an exact round-zero cursor");
        *self = next_state;
        Ok(child)
    }

    fn decide_prevote_for_observation(
        &mut self,
        proposal: AdmittedProposalObservation<'_>,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorLockStateError> {
        self.require_phase(FixedValidatorLockPhaseV0::Proposal)?;
        self.validate_proposal(&proposal)?;
        let prepared_valid = self.prepare_newer_valid_value(&proposal)?;

        let (target, clear_lock) = match self.locked {
            None => (
                ConsensusVoteTarget::Proposal(proposal.proposal_signing_root),
                false,
            ),
            Some(locked) if locked.value == proposal.value => (
                ConsensusVoteTarget::Proposal(proposal.proposal_signing_root),
                false,
            ),
            Some(locked) => {
                let unlocks = proposal.valid_round.is_some_and(|valid_round| {
                    locked.round < valid_round && valid_round < self.position.round()
                });
                if unlocks {
                    (
                        ConsensusVoteTarget::Proposal(proposal.proposal_signing_root),
                        true,
                    )
                } else {
                    (
                        ConsensusVoteTarget::Proposal(locked.proposal_signing_root()),
                        false,
                    )
                }
            }
        };

        if let Some(valid) = prepared_valid {
            self.valid = Some(valid);
        }
        if clear_lock {
            self.locked = None;
        }
        self.phase = FixedValidatorLockPhaseV0::Prevote;
        Ok(FixedValidatorUnsignedVoteEffectV0::new(
            self,
            ConsensusVoteRole::Prevote,
            target,
        ))
    }

    fn decide_precommit_for_proposal_observation(
        &mut self,
        proposal: AdmittedProposalObservation<'_>,
        certificate: PrevoteQuorumObservation,
    ) -> Result<FixedValidatorUnsignedVoteEffectV0, FixedValidatorLockStateError> {
        self.require_phase(FixedValidatorLockPhaseV0::Prevote)?;
        self.validate_proposal(&proposal)?;
        let target = ConsensusVoteTarget::Proposal(proposal.proposal_signing_root);
        self.validate_current_prevote_quorum(&certificate, target)?;
        let canonical_prevote_certificate = certificate.canonical_bytes;
        let valid = FixedValidatorValidValueV0 {
            value: proposal.value,
            round: self.position.round(),
            prevote_certificate_id: certificate.id,
            canonical_prevote_certificate,
        };
        let locked = FixedValidatorLockedValueV0 {
            value: proposal.value,
            round: self.position.round(),
        };

        self.valid = Some(valid);
        self.locked = Some(locked);
        self.phase = FixedValidatorLockPhaseV0::Precommit;
        Ok(FixedValidatorUnsignedVoteEffectV0::new(
            self,
            ConsensusVoteRole::Precommit,
            target,
        ))
    }

    fn validate_proposal(
        &self,
        proposal: &AdmittedProposalObservation<'_>,
    ) -> Result<(), FixedValidatorLockStateError> {
        if proposal.parent_coordinate != self.parent_coordinate {
            return Err(FixedValidatorLockStateError::ProposalBranchMismatch);
        }
        if proposal.position != self.position {
            return Err(FixedValidatorLockStateError::ProposalPositionMismatch {
                expected: self.position,
                actual: proposal.position,
            });
        }
        if proposal.value.context() != self.parent_coordinate.context()
            || proposal.value.height() != self.position.height()
            || proposal.value.parent_ancestry_id() != self.parent_coordinate.ancestry_id()
            || proposal.value.proposal_signing_root() != proposal.proposal_signing_root
        {
            return Err(FixedValidatorLockStateError::ProposalBranchMismatch);
        }
        match (
            proposal.valid_round,
            proposal.valid_round_certificate_id,
            proposal.valid_round_certificate_bytes,
        ) {
            (None, None, None) => Ok(()),
            (Some(valid_round), Some(_), Some(_)) => {
                if valid_round >= self.position.round() {
                    Err(FixedValidatorLockStateError::InvalidValidRound {
                        valid_round,
                        current_round: self.position.round(),
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(FixedValidatorLockStateError::InconsistentValidRoundProof),
        }
    }

    fn prepare_newer_valid_value(
        &self,
        proposal: &AdmittedProposalObservation<'_>,
    ) -> Result<Option<FixedValidatorValidValueV0>, FixedValidatorLockStateError> {
        let Some(round) = proposal.valid_round else {
            return Ok(None);
        };
        let id = proposal
            .valid_round_certificate_id
            .ok_or(FixedValidatorLockStateError::InconsistentValidRoundProof)?;
        let bytes = proposal
            .valid_round_certificate_bytes
            .ok_or(FixedValidatorLockStateError::InconsistentValidRoundProof)?;

        if let Some(current) = &self.valid {
            if round < current.round {
                return Ok(None);
            }
            if round == current.round {
                if proposal.value != current.value {
                    return Err(FixedValidatorLockStateError::ConflictingValidValue {
                        round,
                        retained: current.value.proposal_signing_root(),
                        observed: proposal.proposal_signing_root,
                    });
                }
                return Ok(None);
            }
        }

        Ok(Some(FixedValidatorValidValueV0 {
            value: proposal.value,
            round,
            prevote_certificate_id: id,
            canonical_prevote_certificate: try_copy_certificate(bytes)?,
        }))
    }

    fn validate_current_prevote_quorum(
        &self,
        certificate: &PrevoteQuorumObservation,
        expected_target: ConsensusVoteTarget,
    ) -> Result<(), FixedValidatorLockStateError> {
        if certificate.context != self.parent_coordinate.context() {
            return Err(FixedValidatorLockStateError::QuorumContextMismatch);
        }
        if certificate.position != self.position {
            return Err(FixedValidatorLockStateError::QuorumPositionMismatch {
                expected: self.position,
                actual: certificate.position,
            });
        }
        if certificate.role != ConsensusVoteRole::Prevote {
            return Err(FixedValidatorLockStateError::QuorumRoleMismatch {
                actual: certificate.role,
            });
        }
        if certificate.target != expected_target {
            return Err(FixedValidatorLockStateError::QuorumTargetMismatch {
                expected: expected_target,
                actual: certificate.target,
            });
        }
        Ok(())
    }

    fn validate_current_round(
        &self,
        round: &FixedConsensusRoundV0<'_>,
    ) -> Result<(), FixedValidatorLockStateError> {
        if round.parent_coordinate() != self.parent_coordinate
            || round.post_height_proposer_priority_state_id()
                != self.post_height_proposer_priority_state_id
        {
            return Err(FixedValidatorLockStateError::CurrentRoundBranchMismatch);
        }
        if round.position() != self.position {
            return Err(FixedValidatorLockStateError::CurrentRoundPositionMismatch {
                expected: self.position,
                actual: round.position(),
            });
        }
        Ok(())
    }

    fn require_phase(
        &self,
        expected: FixedValidatorLockPhaseV0,
    ) -> Result<(), FixedValidatorLockStateError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(FixedValidatorLockStateError::UnexpectedPhase {
                expected,
                actual: self.phase,
            })
        }
    }
}

fn vote_snapshot_from_lock_state(
    state: &FixedValidatorLockStateV0,
) -> FixedValidatorVoteStateSnapshotV0 {
    let parent = state.parent_coordinate;
    FixedValidatorVoteStateSnapshotV0 {
        context: parent.context(),
        parent_verified_height: parent.verified_height(),
        parent_ancestry_id: parent.ancestry_id(),
        artifact_head_block_id: parent.artifact_head_block_id(),
        artifact_set_root: parent.artifact_set_root(),
        fixed_agreement_set_id: parent.fixed_agreement_set_id(),
        parent_proposer_priority_state_id: *parent.proposer_priority_state_id().as_bytes(),
        post_height_proposer_priority_state_id: *state
            .post_height_proposer_priority_state_id
            .as_bytes(),
        position: state.position,
        phase: state.phase,
        locked: state.locked,
        valid: state.valid.clone(),
    }
}

fn vote_effect_state_binding(snapshot: &FixedValidatorVoteStateSnapshotV0) -> [u8; 32] {
    lock_state_binding(VOTE_EFFECT_STATE_BINDING_DOMAIN, snapshot)
}

fn higher_round_source_state_binding(snapshot: &FixedValidatorVoteStateSnapshotV0) -> [u8; 32] {
    lock_state_binding(HIGHER_ROUND_SOURCE_STATE_BINDING_DOMAIN, snapshot)
}

fn lock_state_binding(domain: &[u8], snapshot: &FixedValidatorVoteStateSnapshotV0) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(snapshot.context.chain_id().as_bytes());
    hasher.update(snapshot.context.genesis_id().as_bytes());
    hasher.update(snapshot.context.protocol_version().value().to_be_bytes());
    match snapshot.parent_verified_height {
        None => {
            hasher.update([ABSENT_TAG]);
            hasher.update(0_u64.to_be_bytes());
        }
        Some(height) => {
            hasher.update([PRESENT_TAG]);
            hasher.update(height.value().to_be_bytes());
        }
    }
    hasher.update(snapshot.parent_ancestry_id.as_bytes());
    hasher.update(snapshot.artifact_head_block_id.as_bytes());
    hasher.update(snapshot.artifact_set_root.as_bytes());
    hasher.update(snapshot.fixed_agreement_set_id.as_bytes());
    hasher.update(snapshot.parent_proposer_priority_state_id);
    hasher.update(snapshot.post_height_proposer_priority_state_id);
    hasher.update(snapshot.position.height().value().to_be_bytes());
    hasher.update(snapshot.position.round().value().to_be_bytes());
    hasher.update([phase_tag(snapshot.phase)]);
    match snapshot.locked {
        None => hasher.update([ABSENT_TAG]),
        Some(locked) => {
            hasher.update([PRESENT_TAG]);
            hasher.update(locked.value.to_canonical_bytes());
            hasher.update(locked.round.value().to_be_bytes());
        }
    }
    match snapshot.valid.as_ref() {
        None => hasher.update([ABSENT_TAG]),
        Some(valid) => {
            hasher.update([PRESENT_TAG]);
            hasher.update(valid.value.to_canonical_bytes());
            hasher.update(valid.round.value().to_be_bytes());
            hasher.update(valid.prevote_certificate_id.as_bytes());
            hasher.update(
                u32::try_from(valid.canonical_prevote_certificate.len())
                    .expect("bounded quorum certificates fit u32")
                    .to_be_bytes(),
            );
            hasher.update(&valid.canonical_prevote_certificate);
        }
    }
    hasher.finalize().into()
}

fn validate_effect_for_snapshot(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
    effect: &FixedValidatorUnsignedVoteEffectV0,
) -> Result<(), FixedValidatorVoteIntentError> {
    if effect.state_binding != vote_effect_state_binding(snapshot) {
        return Err(FixedValidatorVoteIntentError::EffectStateMismatch);
    }
    if effect.position != snapshot.position {
        return Err(FixedValidatorVoteIntentError::EffectPositionMismatch {
            state: snapshot.position,
            effect: effect.position,
        });
    }
    let expected_phase = match effect.role {
        ConsensusVoteRole::Prevote => FixedValidatorLockPhaseV0::Prevote,
        ConsensusVoteRole::Precommit => FixedValidatorLockPhaseV0::Precommit,
    };
    if snapshot.phase != expected_phase {
        return Err(FixedValidatorVoteIntentError::EffectPhaseMismatch {
            phase: snapshot.phase,
            role: effect.role,
        });
    }
    if let Some(locked) = snapshot.locked {
        if effect.role == ConsensusVoteRole::Prevote
            && effect.target != ConsensusVoteTarget::Proposal(locked.proposal_signing_root())
        {
            return Err(FixedValidatorVoteIntentError::EffectTargetMismatch);
        }
        if effect.role == ConsensusVoteRole::Precommit
            && matches!(effect.target, ConsensusVoteTarget::Proposal(_))
            && (effect.target != ConsensusVoteTarget::Proposal(locked.proposal_signing_root())
                || locked.round != snapshot.position.round())
        {
            return Err(FixedValidatorVoteIntentError::EffectTargetMismatch);
        }
        if effect.role == ConsensusVoteRole::Precommit
            && effect.target == ConsensusVoteTarget::Nil
            && locked.round == snapshot.position.round()
        {
            return Err(FixedValidatorVoteIntentError::EffectTargetMismatch);
        }
    } else if effect.role == ConsensusVoteRole::Precommit
        && matches!(effect.target, ConsensusVoteTarget::Proposal(_))
    {
        return Err(FixedValidatorVoteIntentError::EffectTargetMismatch);
    }
    validate_snapshot_invariants(snapshot)
}

fn validate_snapshot_invariants(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
) -> Result<(), FixedValidatorVoteIntentError> {
    if snapshot.position.height().value() == 0 {
        return Err(FixedValidatorVoteIntentError::ReservedGenesisHeight);
    }
    let expected_height = match snapshot.parent_verified_height {
        None => 1,
        Some(parent) => parent
            .value()
            .checked_add(1)
            .ok_or(FixedValidatorVoteIntentError::ParentHeightExhausted)?,
    };
    if snapshot.position.height().value() != expected_height {
        return Err(FixedValidatorVoteIntentError::NonSequentialHeight {
            parent: snapshot.parent_verified_height,
            current: snapshot.position.height(),
        });
    }
    for value in snapshot
        .locked
        .iter()
        .map(|locked| locked.value)
        .chain(snapshot.valid.iter().map(|valid| valid.value))
    {
        if value.context() != snapshot.context
            || value.height() != snapshot.position.height()
            || value.parent_ancestry_id() != snapshot.parent_ancestry_id
        {
            return Err(FixedValidatorVoteIntentError::StateValueBranchMismatch);
        }
    }
    if let Some(locked) = snapshot.locked {
        if locked.round > snapshot.position.round() {
            return Err(FixedValidatorVoteIntentError::FutureLockedRound {
                locked: locked.round,
                current: snapshot.position.round(),
            });
        }
        let Some(valid) = snapshot.valid.as_ref() else {
            return Err(FixedValidatorVoteIntentError::LockWithoutValidValue);
        };
        if valid.round < locked.round {
            return Err(FixedValidatorVoteIntentError::ValidRoundBeforeLock {
                locked: locked.round,
                valid: valid.round,
            });
        }
        if valid.value != locked.value {
            return Err(FixedValidatorVoteIntentError::LockValidValueMismatch {
                locked_round: locked.round,
                valid_round: valid.round,
            });
        }
        if locked.round == snapshot.position.round()
            && snapshot.phase != FixedValidatorLockPhaseV0::Precommit
        {
            return Err(FixedValidatorVoteIntentError::CurrentRoundLockBeforePrecommit);
        }
    }
    if let Some(valid) = snapshot.valid.as_ref() {
        if valid.round > snapshot.position.round() {
            return Err(FixedValidatorVoteIntentError::FutureValidRound {
                valid: valid.round,
                current: snapshot.position.round(),
            });
        }
        if valid.round == snapshot.position.round() {
            let current_lock_matches = snapshot
                .locked
                .is_some_and(|locked| locked.round == valid.round && locked.value == valid.value);
            if snapshot.phase != FixedValidatorLockPhaseV0::Precommit || !current_lock_matches {
                return Err(FixedValidatorVoteIntentError::CurrentValidWithoutMatchingLock);
            }
        }
    }
    Ok(())
}

fn encode_state_and_vote_intent(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
    effect: &FixedValidatorUnsignedVoteEffectV0,
    signer: ConsensusKey,
) -> Result<Vec<u8>, FixedValidatorVoteIntentError> {
    let length = VOTE_INTENT_HEADER.len()
        + state_snapshot_length(snapshot)?
        + 1
        + VOTE_TARGET_BYTES
        + CONSENSUS_KEY_BYTES;
    if length > ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooLong {
            actual: length,
            maximum: ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH,
        });
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
    bytes.extend_from_slice(VOTE_INTENT_HEADER);
    append_state_snapshot(&mut bytes, snapshot);
    bytes.push(role_tag(effect.role));
    append_target(&mut bytes, effect.target);
    bytes.extend_from_slice(signer.as_bytes());
    debug_assert_eq!(bytes.len(), length);
    Ok(bytes)
}

fn state_snapshot_length(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
) -> Result<usize, FixedValidatorVoteIntentError> {
    let valid_certificate_len = snapshot
        .valid
        .as_ref()
        .map_or(0, |valid| valid.canonical_prevote_certificate.len());
    let length = STATE_SNAPSHOT_FIXED_BYTES
        + snapshot.locked.map_or(0, |_| LOCK_SNAPSHOT_BYTES)
        + snapshot
            .valid
            .as_ref()
            .map_or(0, |_| VALID_SNAPSHOT_FIXED_BYTES + valid_certificate_len);
    if valid_certificate_len > VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooLong {
            actual: valid_certificate_len,
            maximum: VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH,
        });
    }
    Ok(length)
}

fn append_state_snapshot(bytes: &mut Vec<u8>, snapshot: &FixedValidatorVoteStateSnapshotV0) {
    bytes.extend_from_slice(snapshot.context.chain_id().as_bytes());
    bytes.extend_from_slice(snapshot.context.genesis_id().as_bytes());
    bytes.extend_from_slice(&snapshot.context.protocol_version().value().to_be_bytes());
    match snapshot.parent_verified_height {
        None => {
            bytes.push(ABSENT_TAG);
            bytes.extend_from_slice(&0_u64.to_be_bytes());
        }
        Some(height) => {
            bytes.push(PRESENT_TAG);
            bytes.extend_from_slice(&height.value().to_be_bytes());
        }
    }
    bytes.extend_from_slice(snapshot.parent_ancestry_id.as_bytes());
    bytes.extend_from_slice(snapshot.artifact_head_block_id.as_bytes());
    bytes.extend_from_slice(snapshot.artifact_set_root.as_bytes());
    bytes.extend_from_slice(snapshot.fixed_agreement_set_id.as_bytes());
    bytes.extend_from_slice(&snapshot.parent_proposer_priority_state_id);
    bytes.extend_from_slice(&snapshot.post_height_proposer_priority_state_id);
    bytes.extend_from_slice(&snapshot.position.height().value().to_be_bytes());
    bytes.extend_from_slice(&snapshot.position.round().value().to_be_bytes());
    bytes.push(phase_tag(snapshot.phase));
    match snapshot.locked {
        None => bytes.push(ABSENT_TAG),
        Some(locked) => {
            bytes.push(PRESENT_TAG);
            bytes.extend_from_slice(&locked.value.to_canonical_bytes());
            bytes.extend_from_slice(&locked.round.value().to_be_bytes());
        }
    }
    match snapshot.valid.as_ref() {
        None => bytes.push(ABSENT_TAG),
        Some(valid) => {
            bytes.push(PRESENT_TAG);
            bytes.extend_from_slice(&valid.value.to_canonical_bytes());
            bytes.extend_from_slice(&valid.round.value().to_be_bytes());
            bytes.extend_from_slice(valid.prevote_certificate_id.as_bytes());
            bytes.extend_from_slice(
                &u32::try_from(valid.canonical_prevote_certificate.len())
                    .expect("bounded quorum certificates fit u32")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&valid.canonical_prevote_certificate);
        }
    }
}

fn decode_state_snapshot(
    decoder: &mut VoteIntentDecoder<'_>,
    expected_context: ConsensusContextV0,
    expected_fixed_agreement_set_id: FixedAgreementSetId,
) -> Result<FixedValidatorVoteStateSnapshotV0, FixedValidatorVoteIntentError> {
    if decoder.take_array::<32>()? != *expected_context.chain_id().as_bytes()
        || decoder.take_array::<32>()? != *expected_context.genesis_id().as_bytes()
        || decoder.take_array::<4>()? != expected_context.protocol_version().value().to_be_bytes()
    {
        return Err(FixedValidatorVoteIntentError::ContextMismatch);
    }
    let parent_verified_tag = decoder.take_byte()?;
    let parent_verified_value = decoder.take_u64()?;
    let parent_verified_height = match parent_verified_tag {
        ABSENT_TAG if parent_verified_value == 0 => None,
        ABSENT_TAG => return Err(FixedValidatorVoteIntentError::NonCanonicalAbsentHeight),
        PRESENT_TAG if parent_verified_value > 0 => {
            Some(ConsensusHeight::new(parent_verified_value))
        }
        PRESENT_TAG => return Err(FixedValidatorVoteIntentError::ReservedGenesisHeight),
        actual => return Err(FixedValidatorVoteIntentError::UnknownPresenceTag { actual }),
    };
    let parent_ancestry_id = ConsensusAncestryId::from_bytes(decoder.take_array()?);
    let artifact_head_block_id = ArtifactBlockId::from_bytes(decoder.take_array()?);
    let artifact_set_root = ArtifactSetRoot::from_bytes(decoder.take_array()?);
    if decoder.take_array::<32>()? != *expected_fixed_agreement_set_id.as_bytes() {
        return Err(FixedValidatorVoteIntentError::FixedAgreementSetMismatch);
    }
    let parent_proposer_priority_state_id = decoder.take_array()?;
    let post_height_proposer_priority_state_id = decoder.take_array()?;
    let height = ConsensusHeight::new(decoder.take_u64()?);
    let round = ConsensusRound::new(decoder.take_u64()?);
    let position = ConsensusPosition::new(height, round);
    let phase = decode_phase(decoder.take_byte()?)?;
    let locked = match decoder.take_byte()? {
        ABSENT_TAG => None,
        PRESENT_TAG => {
            let value = ConsensusValueV0::from_canonical_bytes(
                decoder.take_slice(ConsensusValueV0::BYTE_LENGTH)?,
            )
            .map_err(FixedValidatorVoteIntentError::Value)?;
            Some(FixedValidatorLockedValueV0 {
                value,
                round: ConsensusRound::new(decoder.take_u64()?),
            })
        }
        actual => return Err(FixedValidatorVoteIntentError::UnknownPresenceTag { actual }),
    };
    let valid = match decoder.take_byte()? {
        ABSENT_TAG => None,
        PRESENT_TAG => {
            let value = ConsensusValueV0::from_canonical_bytes(
                decoder.take_slice(ConsensusValueV0::BYTE_LENGTH)?,
            )
            .map_err(FixedValidatorVoteIntentError::Value)?;
            let valid_round = ConsensusRound::new(decoder.take_u64()?);
            let encoded_id = decoder.take_array::<32>()?;
            let certificate_length = usize::try_from(decoder.take_u32()?)
                .expect("u32 always fits usize on supported targets");
            let certificate = decoder.take_slice(certificate_length)?;
            let header = decode_canonical_quorum_certificate_header(certificate)
                .map_err(FixedValidatorVoteIntentError::RetainedCertificate)?;
            if header.id.as_bytes() != &encoded_id {
                return Err(FixedValidatorVoteIntentError::RetainedCertificateIdMismatch);
            }
            let expected_certificate_position =
                ConsensusPosition::new(position.height(), valid_round);
            if header.context != expected_context
                || header.position != expected_certificate_position
                || header.role != ConsensusVoteRole::Prevote
                || header.target != ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            {
                return Err(FixedValidatorVoteIntentError::RetainedCertificateStateMismatch);
            }
            let mut canonical_prevote_certificate = Vec::new();
            canonical_prevote_certificate
                .try_reserve_exact(certificate.len())
                .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
            canonical_prevote_certificate.extend_from_slice(certificate);
            Some(FixedValidatorValidValueV0 {
                value,
                round: valid_round,
                prevote_certificate_id: header.id,
                canonical_prevote_certificate,
            })
        }
        actual => return Err(FixedValidatorVoteIntentError::UnknownPresenceTag { actual }),
    };
    let snapshot = FixedValidatorVoteStateSnapshotV0 {
        context: expected_context,
        parent_verified_height,
        parent_ancestry_id,
        artifact_head_block_id,
        artifact_set_root,
        fixed_agreement_set_id: expected_fixed_agreement_set_id,
        parent_proposer_priority_state_id,
        post_height_proposer_priority_state_id,
        position,
        phase,
        locked,
        valid,
    };
    validate_snapshot_invariants(&snapshot)?;
    Ok(snapshot)
}

fn decode_observed_vote_intent(
    bytes: &[u8],
    expected_context: ConsensusContextV0,
    expected_fixed_agreement_set_id: FixedAgreementSetId,
    expected_signer: ConsensusKey,
) -> Result<ObservedFixedValidatorVoteIntentV0, FixedValidatorVoteIntentError> {
    if bytes.len() > ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooLong {
            actual: bytes.len(),
            maximum: ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH,
        });
    }
    if bytes.len() < ObservedFixedValidatorVoteIntentV0::MIN_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooShort {
            actual: bytes.len(),
            minimum: ObservedFixedValidatorVoteIntentV0::MIN_BYTE_LENGTH,
        });
    }
    let mut decoder = VoteIntentDecoder::new(bytes);
    if decoder.take_slice(VOTE_INTENT_HEADER.len())? != VOTE_INTENT_HEADER {
        return Err(FixedValidatorVoteIntentError::InvalidHeader);
    }
    let snapshot = decode_state_snapshot(
        &mut decoder,
        expected_context,
        expected_fixed_agreement_set_id,
    )?;
    let role = decode_role(decoder.take_byte()?)?;
    let target = decode_target(&mut decoder)?;
    let signer_bytes = decoder.take_array::<CONSENSUS_KEY_BYTES>()?;
    if signer_bytes != *expected_signer.as_bytes() {
        return Err(FixedValidatorVoteIntentError::SignerMismatch);
    }
    decoder.finish()?;

    let effect = FixedValidatorUnsignedVoteEffectV0::from_snapshot(&snapshot, role, target);
    validate_effect_for_snapshot(&snapshot, &effect)?;
    let canonical_state_and_vote_intent_bytes =
        encode_state_and_vote_intent(&snapshot, &effect, expected_signer)?;
    if canonical_state_and_vote_intent_bytes != bytes {
        return Err(FixedValidatorVoteIntentError::NonCanonicalEncoding);
    }
    Ok(ObservedFixedValidatorVoteIntentV0 {
        snapshot,
        effect,
        signer: expected_signer,
        canonical_state_and_vote_intent_bytes,
    })
}

fn encode_higher_round_checkpoint(
    source_position: ConsensusPosition,
    source_phase: FixedValidatorLockPhaseV0,
    source_state_binding: [u8; OPAQUE_ID_BYTES],
    target_snapshot: &FixedValidatorVoteStateSnapshotV0,
    canonical_certificate: &[u8],
) -> Result<Vec<u8>, FixedValidatorVoteIntentError> {
    let length = HIGHER_ROUND_CHECKPOINT_HEADER.len()
        + HIGHER_ROUND_SOURCE_BYTES
        + state_snapshot_length(target_snapshot)?
        + CERTIFICATE_LENGTH_BYTES
        + canonical_certificate.len();
    if length > ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorVoteIntentError::InputTooLong {
            actual: length,
            maximum: ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH,
        });
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| FixedValidatorVoteIntentError::AllocationFailed)?;
    bytes.extend_from_slice(HIGHER_ROUND_CHECKPOINT_HEADER);
    bytes.extend_from_slice(&source_position.height().value().to_be_bytes());
    bytes.extend_from_slice(&source_position.round().value().to_be_bytes());
    bytes.push(phase_tag(source_phase));
    bytes.extend_from_slice(&source_state_binding);
    append_state_snapshot(&mut bytes, target_snapshot);
    bytes.extend_from_slice(
        &u32::try_from(canonical_certificate.len())
            .expect("bounded quorum certificates fit u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(canonical_certificate);
    debug_assert_eq!(bytes.len(), length);
    Ok(bytes)
}

fn decode_observed_higher_round_checkpoint(
    bytes: &[u8],
    expected_context: ConsensusContextV0,
    expected_fixed_agreement_set_id: FixedAgreementSetId,
) -> Result<ObservedFixedValidatorHigherRoundCheckpointV0, FixedValidatorHigherRoundCheckpointErrorV0>
{
    if bytes.len() > ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::InputTooLong {
            actual: bytes.len(),
            maximum: ObservedFixedValidatorHigherRoundCheckpointV0::MAX_BYTE_LENGTH,
        });
    }
    if bytes.len() < ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::InputTooShort {
            actual: bytes.len(),
            minimum: ObservedFixedValidatorHigherRoundCheckpointV0::MIN_BYTE_LENGTH,
        });
    }
    let mut decoder = VoteIntentDecoder::new(bytes);
    if decoder
        .take_slice(HIGHER_ROUND_CHECKPOINT_HEADER.len())
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?
        != HIGHER_ROUND_CHECKPOINT_HEADER
    {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::InvalidHeader);
    }
    let source_position = ConsensusPosition::new(
        ConsensusHeight::new(
            decoder
                .take_u64()
                .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?,
        ),
        ConsensusRound::new(
            decoder
                .take_u64()
                .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?,
        ),
    );
    let source_phase = decode_phase(
        decoder
            .take_byte()
            .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?,
    )
    .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    let source_state_binding = decoder
        .take_array::<OPAQUE_ID_BYTES>()
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    let target_snapshot = decode_state_snapshot(
        &mut decoder,
        expected_context,
        expected_fixed_agreement_set_id,
    )
    .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    let certificate_length = usize::try_from(
        decoder
            .take_u32()
            .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?,
    )
    .expect("u32 always fits usize on supported targets");
    let certificate = decoder
        .take_slice(certificate_length)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    decoder
        .finish()
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;

    if source_position.height() != target_snapshot.position.height() {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::HeightMismatch {
            source: source_position.height(),
            target: target_snapshot.position.height(),
        });
    }
    if target_snapshot.position.round() <= source_position.round() {
        return Err(
            FixedValidatorHigherRoundCheckpointErrorV0::NotStrictlyHigher {
                source: source_position.round(),
                target: target_snapshot.position.round(),
            },
        );
    }
    let mut source_snapshot = target_snapshot.clone();
    source_snapshot.position = source_position;
    source_snapshot.phase = source_phase;
    validate_snapshot_invariants(&source_snapshot)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    if higher_round_source_state_binding(&source_snapshot) != source_state_binding {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::SourceStateBindingMismatch);
    }

    let header = decode_canonical_quorum_certificate_header(certificate)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::Certificate)?;
    if header.context != expected_context {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::CertificateContextMismatch);
    }
    if header.position != target_snapshot.position {
        return Err(
            FixedValidatorHigherRoundCheckpointErrorV0::CertificatePositionMismatch {
                expected: target_snapshot.position,
                actual: header.position,
            },
        );
    }
    let expected_phase = phase_for_role(header.role);
    if target_snapshot.phase != expected_phase {
        return Err(
            FixedValidatorHigherRoundCheckpointErrorV0::PhaseRoleMismatch {
                phase: target_snapshot.phase,
                role: header.role,
            },
        );
    }

    let canonical_checkpoint = encode_higher_round_checkpoint(
        source_position,
        source_phase,
        source_state_binding,
        &target_snapshot,
        certificate,
    )
    .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    if canonical_checkpoint != bytes {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::NonCanonicalEncoding);
    }
    let mut canonical_certificate = Vec::new();
    canonical_certificate
        .try_reserve_exact(certificate.len())
        .map_err(|_| FixedValidatorHigherRoundCheckpointErrorV0::AllocationFailed)?;
    canonical_certificate.extend_from_slice(certificate);

    Ok(ObservedFixedValidatorHigherRoundCheckpointV0 {
        source_position,
        source_phase,
        source_state_binding,
        target_snapshot,
        role: header.role,
        target: header.target,
        certificate_id: header.id,
        canonical_certificate,
        canonical_checkpoint,
    })
}

fn restore_higher_round_checkpoint_for_round(
    observed: &ObservedFixedValidatorHigherRoundCheckpointV0,
    round: &FixedConsensusRoundV0<'_>,
) -> Result<FixedValidatorLockStateV0, FixedValidatorHigherRoundCheckpointErrorV0> {
    let lock_state = restore_snapshot_for_round(&observed.target_snapshot, round)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::State)?;
    let certificate = round
        .decode_and_verify_quorum_certificate(&observed.canonical_certificate)
        .map_err(FixedValidatorHigherRoundCheckpointErrorV0::Certificate)?;
    if certificate.position() != observed.target_snapshot.position
        || certificate.role() != observed.role
        || certificate.target() != observed.target
        || certificate.id() != observed.certificate_id
    {
        return Err(FixedValidatorHigherRoundCheckpointErrorV0::CertificateStateMismatch);
    }
    Ok(lock_state)
}

fn restore_lock_state_for_round(
    observed: &ObservedFixedValidatorVoteIntentV0,
    round: &FixedConsensusRoundV0<'_>,
) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteIntentError> {
    if !round.verifies_consensus_signer(observed.signer) {
        return Err(FixedValidatorVoteIntentError::SignerNotInFixedSet {
            signer: observed.signer,
        });
    }
    restore_snapshot_for_round(&observed.snapshot, round)
}

fn restore_snapshot_for_round(
    snapshot: &FixedValidatorVoteStateSnapshotV0,
    round: &FixedConsensusRoundV0<'_>,
) -> Result<FixedValidatorLockStateV0, FixedValidatorVoteIntentError> {
    let parent = round.parent_coordinate();
    if snapshot.context != round.context()
        || snapshot.parent_verified_height != parent.verified_height()
        || snapshot.parent_ancestry_id != parent.ancestry_id()
        || snapshot.artifact_head_block_id != parent.artifact_head_block_id()
        || snapshot.artifact_set_root != parent.artifact_set_root()
        || snapshot.fixed_agreement_set_id != parent.fixed_agreement_set_id()
        || snapshot.parent_proposer_priority_state_id
            != *parent.proposer_priority_state_id().as_bytes()
        || snapshot.post_height_proposer_priority_state_id
            != *round.post_height_proposer_priority_state_id().as_bytes()
    {
        return Err(FixedValidatorVoteIntentError::RoundBranchMismatch);
    }
    if snapshot.position != round.position() {
        return Err(FixedValidatorVoteIntentError::RoundPositionMismatch {
            record: snapshot.position,
            round: round.position(),
        });
    }
    if let Some(valid) = snapshot.valid.as_ref() {
        let position = ConsensusPosition::new(snapshot.position.height(), valid.round);
        let target = ConsensusVoteTarget::Proposal(valid.value.proposal_signing_root());
        let matches = round
            .verify_retained_prevote_certificate(
                &valid.canonical_prevote_certificate,
                position,
                target,
                valid.prevote_certificate_id,
            )
            .map_err(FixedValidatorVoteIntentError::RetainedCertificate)?;
        if !matches {
            return Err(FixedValidatorVoteIntentError::RetainedCertificateStateMismatch);
        }
    }
    Ok(FixedValidatorLockStateV0 {
        live_lineage_seal: Arc::new(()),
        parent_coordinate: parent,
        post_height_proposer_priority_state_id: round.post_height_proposer_priority_state_id(),
        position: snapshot.position,
        phase: snapshot.phase,
        locked: snapshot.locked,
        valid: snapshot.valid.clone(),
    })
}

fn phase_tag(phase: FixedValidatorLockPhaseV0) -> u8 {
    match phase {
        FixedValidatorLockPhaseV0::Proposal => PROPOSAL_PHASE_TAG,
        FixedValidatorLockPhaseV0::Prevote => PREVOTE_PHASE_TAG,
        FixedValidatorLockPhaseV0::Precommit => PRECOMMIT_PHASE_TAG,
    }
}

const fn phase_for_role(role: ConsensusVoteRole) -> FixedValidatorLockPhaseV0 {
    match role {
        ConsensusVoteRole::Prevote => FixedValidatorLockPhaseV0::Prevote,
        ConsensusVoteRole::Precommit => FixedValidatorLockPhaseV0::Precommit,
    }
}

fn decode_phase(tag: u8) -> Result<FixedValidatorLockPhaseV0, FixedValidatorVoteIntentError> {
    match tag {
        PROPOSAL_PHASE_TAG => Ok(FixedValidatorLockPhaseV0::Proposal),
        PREVOTE_PHASE_TAG => Ok(FixedValidatorLockPhaseV0::Prevote),
        PRECOMMIT_PHASE_TAG => Ok(FixedValidatorLockPhaseV0::Precommit),
        actual => Err(FixedValidatorVoteIntentError::UnknownPhaseTag { actual }),
    }
}

fn role_tag(role: ConsensusVoteRole) -> u8 {
    match role {
        ConsensusVoteRole::Prevote => PREVOTE_ROLE_TAG,
        ConsensusVoteRole::Precommit => PRECOMMIT_ROLE_TAG,
    }
}

fn decode_role(tag: u8) -> Result<ConsensusVoteRole, FixedValidatorVoteIntentError> {
    match tag {
        PREVOTE_ROLE_TAG => Ok(ConsensusVoteRole::Prevote),
        PRECOMMIT_ROLE_TAG => Ok(ConsensusVoteRole::Precommit),
        actual => Err(FixedValidatorVoteIntentError::UnknownRoleTag { actual }),
    }
}

fn append_target(bytes: &mut Vec<u8>, target: ConsensusVoteTarget) {
    match target {
        ConsensusVoteTarget::Nil => {
            bytes.push(NIL_TARGET_TAG);
            bytes.extend_from_slice(&[0_u8; ProposalSigningRoot::BYTE_LENGTH]);
        }
        ConsensusVoteTarget::Proposal(root) => {
            bytes.push(PROPOSAL_TARGET_TAG);
            bytes.extend_from_slice(root.as_bytes());
        }
    }
}

fn decode_target(
    decoder: &mut VoteIntentDecoder<'_>,
) -> Result<ConsensusVoteTarget, FixedValidatorVoteIntentError> {
    let tag = decoder.take_byte()?;
    let payload = decoder.take_array::<{ ProposalSigningRoot::BYTE_LENGTH }>()?;
    match tag {
        NIL_TARGET_TAG if payload == [0_u8; ProposalSigningRoot::BYTE_LENGTH] => {
            Ok(ConsensusVoteTarget::Nil)
        }
        NIL_TARGET_TAG => Err(FixedValidatorVoteIntentError::NonCanonicalNilTarget),
        PROPOSAL_TARGET_TAG => Ok(ConsensusVoteTarget::Proposal(
            ProposalSigningRoot::from_bytes(payload),
        )),
        actual => Err(FixedValidatorVoteIntentError::UnknownTargetTag { actual }),
    }
}

struct VoteIntentDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> VoteIntentDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], FixedValidatorVoteIntentError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FixedValidatorVoteIntentError::TruncatedEncoding)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(FixedValidatorVoteIntentError::TruncatedEncoding)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], FixedValidatorVoteIntentError> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| FixedValidatorVoteIntentError::TruncatedEncoding)
    }

    fn take_byte(&mut self) -> Result<u8, FixedValidatorVoteIntentError> {
        Ok(self.take_array::<1>()?[0])
    }

    fn take_u32(&mut self) -> Result<u32, FixedValidatorVoteIntentError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, FixedValidatorVoteIntentError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn finish(self) -> Result<(), FixedValidatorVoteIntentError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(FixedValidatorVoteIntentError::TrailingBytes {
                actual: self.bytes.len(),
                expected: self.offset,
            })
        }
    }
}

struct AdmittedProposalObservation<'evidence> {
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    value: ConsensusValueV0,
    proposal_signing_root: ProposalSigningRoot,
    valid_round: Option<ConsensusRound>,
    valid_round_certificate_id: Option<QuorumCertificateId>,
    valid_round_certificate_bytes: Option<&'evidence [u8]>,
}

impl<'evidence> AdmittedProposalObservation<'evidence> {
    fn from_verified(proposal: &'evidence VerifiedFixedConsensusProposalV0<'_, '_>) -> Self {
        Self {
            parent_coordinate: proposal.parent_coordinate(),
            position: proposal.position(),
            value: proposal.value(),
            proposal_signing_root: proposal.proposal_signing_root(),
            valid_round: proposal.valid_round(),
            valid_round_certificate_id: proposal.valid_round_certificate_id(),
            valid_round_certificate_bytes: proposal.valid_round_certificate_bytes(),
        }
    }
}

struct PrevoteQuorumObservation {
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    id: QuorumCertificateId,
    canonical_bytes: Vec<u8>,
}

impl PrevoteQuorumObservation {
    fn from_verified(
        certificate: &VerifiedQuorumCertificateV0<'_>,
        canonical_bytes: Vec<u8>,
    ) -> Self {
        Self {
            context: certificate.context(),
            position: certificate.position(),
            role: certificate.role(),
            target: certificate.target(),
            id: certificate.id(),
            canonical_bytes,
        }
    }
}

fn try_copy_certificate(bytes: &[u8]) -> Result<Vec<u8>, FixedValidatorLockStateError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(bytes.len())
        .map_err(|_| FixedValidatorLockStateError::CertificateAllocationFailed)?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

/// A rejected durable higher-round checkpoint decode or typed reconstruction.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorHigherRoundCheckpointErrorV0 {
    InputTooLong {
        actual: usize,
        maximum: usize,
    },
    InputTooShort {
        actual: usize,
        minimum: usize,
    },
    InvalidHeader,
    State(FixedValidatorVoteIntentError),
    HeightMismatch {
        source: ConsensusHeight,
        target: ConsensusHeight,
    },
    NotStrictlyHigher {
        source: ConsensusRound,
        target: ConsensusRound,
    },
    SourceStateBindingMismatch,
    Certificate(QuorumCertificateVerifyError),
    CertificateContextMismatch,
    CertificatePositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    PhaseRoleMismatch {
        phase: FixedValidatorLockPhaseV0,
        role: ConsensusVoteRole,
    },
    CertificateStateMismatch,
    NonCanonicalEncoding,
    AllocationFailed,
}

impl fmt::Display for FixedValidatorHigherRoundCheckpointErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "higher-round checkpoint length {actual} exceeds {maximum} bytes"
            ),
            Self::InputTooShort { actual, minimum } => write!(
                formatter,
                "higher-round checkpoint length {actual} is shorter than {minimum} bytes"
            ),
            Self::InvalidHeader => formatter.write_str("invalid higher-round checkpoint header"),
            Self::State(source) => write!(formatter, "invalid checkpoint lock state: {source}"),
            Self::HeightMismatch { source, target } => write!(
                formatter,
                "higher-round checkpoint moves from height {} to height {}",
                source.value(),
                target.value()
            ),
            Self::NotStrictlyHigher { source, target } => write!(
                formatter,
                "checkpoint target round {} is not higher than source round {}",
                target.value(),
                source.value()
            ),
            Self::SourceStateBindingMismatch => {
                formatter.write_str("checkpoint source-state binding does not match its state")
            }
            Self::Certificate(source) => source.fmt(formatter),
            Self::CertificateContextMismatch => {
                formatter.write_str("checkpoint certificate belongs to another context")
            }
            Self::CertificatePositionMismatch { expected, actual } => write!(
                formatter,
                "checkpoint certificate position {actual:?} differs from target {expected:?}"
            ),
            Self::PhaseRoleMismatch { phase, role } => write!(
                formatter,
                "checkpoint phase {phase:?} does not correspond to certificate role {role:?}"
            ),
            Self::CertificateStateMismatch => formatter
                .write_str("typed checkpoint certificate differs from retained checkpoint state"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("higher-round checkpoint differs from canonical re-encoding")
            }
            Self::AllocationFailed => {
                formatter.write_str("memory allocation failed for higher-round checkpoint")
            }
        }
    }
}

impl Error for FixedValidatorHigherRoundCheckpointErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::State(source) => Some(source),
            Self::Certificate(source) => Some(source),
            _ => None,
        }
    }
}

/// A rejected vote-intent preparation, replay, or typed-round reconstruction.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorVoteIntentError {
    InputTooLong {
        actual: usize,
        maximum: usize,
    },
    InputTooShort {
        actual: usize,
        minimum: usize,
    },
    InvalidHeader,
    ContextMismatch,
    FixedAgreementSetMismatch,
    SignerMismatch,
    SignerNotInFixedSet {
        signer: ConsensusKey,
    },
    UnknownPresenceTag {
        actual: u8,
    },
    NonCanonicalAbsentHeight,
    ReservedGenesisHeight,
    ParentHeightExhausted,
    NonSequentialHeight {
        parent: Option<ConsensusHeight>,
        current: ConsensusHeight,
    },
    UnknownPhaseTag {
        actual: u8,
    },
    UnknownRoleTag {
        actual: u8,
    },
    UnknownTargetTag {
        actual: u8,
    },
    NonCanonicalNilTarget,
    TruncatedEncoding,
    TrailingBytes {
        actual: usize,
        expected: usize,
    },
    NonCanonicalEncoding,
    AllocationFailed,
    Value(ConsensusValueError),
    RetainedCertificate(QuorumCertificateVerifyError),
    RetainedCertificateIdMismatch,
    RetainedCertificateStateMismatch,
    StateValueBranchMismatch,
    LockWithoutValidValue,
    LockValidValueMismatch {
        locked_round: ConsensusRound,
        valid_round: ConsensusRound,
    },
    CurrentRoundLockBeforePrecommit,
    CurrentValidWithoutMatchingLock,
    FutureLockedRound {
        locked: ConsensusRound,
        current: ConsensusRound,
    },
    FutureValidRound {
        valid: ConsensusRound,
        current: ConsensusRound,
    },
    ValidRoundBeforeLock {
        locked: ConsensusRound,
        valid: ConsensusRound,
    },
    EffectPositionMismatch {
        state: ConsensusPosition,
        effect: ConsensusPosition,
    },
    EffectPhaseMismatch {
        phase: FixedValidatorLockPhaseV0,
        role: ConsensusVoteRole,
    },
    EffectStateMismatch,
    EffectLineageMismatch,
    EffectTargetMismatch,
    RoundBranchMismatch,
    RoundPositionMismatch {
        record: ConsensusPosition,
        round: ConsensusPosition,
    },
    LockState(FixedValidatorLockStateError),
}

impl fmt::Display for FixedValidatorVoteIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "fixed-validator vote-intent record length {actual} exceeds {maximum} bytes"
            ),
            Self::InputTooShort { actual, minimum } => write!(
                formatter,
                "fixed-validator vote-intent record length {actual} is shorter than {minimum} bytes"
            ),
            Self::InvalidHeader => {
                formatter.write_str("invalid fixed-validator vote-intent header")
            }
            Self::ContextMismatch => {
                formatter.write_str("vote-intent context differs from the expected context")
            }
            Self::FixedAgreementSetMismatch => {
                formatter.write_str("vote-intent fixed agreement set differs from the expected set")
            }
            Self::SignerMismatch => {
                formatter.write_str("vote-intent signer differs from the expected local signer")
            }
            Self::SignerNotInFixedSet { signer } => write!(
                formatter,
                "vote-intent signer is not active in the fixed set: {signer:?}"
            ),
            Self::UnknownPresenceTag { actual } => {
                write!(formatter, "unknown vote-intent presence tag {actual}")
            }
            Self::NonCanonicalAbsentHeight => {
                formatter.write_str("absent parent height has nonzero payload")
            }
            Self::ReservedGenesisHeight => {
                formatter.write_str("vote-intent state uses reserved consensus height zero")
            }
            Self::ParentHeightExhausted => {
                formatter.write_str("vote-intent parent height has no representable child")
            }
            Self::NonSequentialHeight { parent, current } => write!(
                formatter,
                "vote-intent height {current:?} is not the direct child of parent height {parent:?}"
            ),
            Self::UnknownPhaseTag { actual } => {
                write!(formatter, "unknown vote-intent phase tag {actual}")
            }
            Self::UnknownRoleTag { actual } => {
                write!(formatter, "unknown vote-intent role tag {actual}")
            }
            Self::UnknownTargetTag { actual } => {
                write!(formatter, "unknown vote-intent target tag {actual}")
            }
            Self::NonCanonicalNilTarget => {
                formatter.write_str("nil vote-intent target has nonzero payload")
            }
            Self::TruncatedEncoding => {
                formatter.write_str("vote-intent record ends inside a declared field")
            }
            Self::TrailingBytes { actual, expected } => write!(
                formatter,
                "vote-intent record has {actual} bytes; decoded fields consume {expected}"
            ),
            Self::NonCanonicalEncoding => {
                formatter.write_str("vote-intent record differs from its canonical re-encoding")
            }
            Self::AllocationFailed => {
                formatter.write_str("memory allocation failed for the bounded vote-intent record")
            }
            Self::Value(error) => error.fmt(formatter),
            Self::RetainedCertificate(error) => error.fmt(formatter),
            Self::RetainedCertificateIdMismatch => formatter
                .write_str("retained prevote certificate identity does not match its exact bytes"),
            Self::RetainedCertificateStateMismatch => formatter.write_str(
                "retained prevote certificate does not match the retained valid value and round",
            ),
            Self::StateValueBranchMismatch => {
                formatter.write_str("retained lock or valid value belongs to another branch state")
            }
            Self::LockWithoutValidValue => {
                formatter.write_str("retained lock has no retained valid value evidence")
            }
            Self::LockValidValueMismatch {
                locked_round,
                valid_round,
            } => write!(
                formatter,
                "lock at round {locked_round:?} and valid value at round {valid_round:?} differ"
            ),
            Self::CurrentRoundLockBeforePrecommit => {
                formatter.write_str("current-round lock exists before the post-precommit phase")
            }
            Self::CurrentValidWithoutMatchingLock => formatter
                .write_str("current-round valid value lacks the matching post-precommit lock"),
            Self::FutureLockedRound { locked, current } => write!(
                formatter,
                "locked round {locked:?} is later than current round {current:?}"
            ),
            Self::FutureValidRound { valid, current } => write!(
                formatter,
                "valid round {valid:?} is later than current round {current:?}"
            ),
            Self::ValidRoundBeforeLock { locked, valid } => write!(
                formatter,
                "valid round {valid:?} is earlier than locked round {locked:?}"
            ),
            Self::EffectPositionMismatch { state, effect } => write!(
                formatter,
                "vote effect position {effect:?} differs from state position {state:?}"
            ),
            Self::EffectPhaseMismatch { phase, role } => write!(
                formatter,
                "vote role {role:?} is inconsistent with post-effect phase {phase:?}"
            ),
            Self::EffectStateMismatch => {
                formatter.write_str("vote effect was emitted for another post-effect state")
            }
            Self::EffectLineageMismatch => {
                formatter.write_str("vote effect was emitted by another live lock-state lineage")
            }
            Self::EffectTargetMismatch => formatter
                .write_str("vote target is inconsistent with the retained post-effect lock"),
            Self::RoundBranchMismatch => {
                formatter.write_str("vote-intent state belongs to another typed consensus branch")
            }
            Self::RoundPositionMismatch { record, round } => write!(
                formatter,
                "vote-intent position {record:?} differs from typed round {round:?}"
            ),
            Self::LockState(error) => error.fmt(formatter),
        }
    }
}

impl Error for FixedValidatorVoteIntentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Value(error) => Some(error),
            Self::RetainedCertificate(error) => Some(error),
            Self::LockState(error) => Some(error),
            _ => None,
        }
    }
}

/// A rejected in-memory fixed-validator locking operation.
///
/// Every error leaves position, phase, lock, and valid value unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorLockStateError {
    /// Empty lock state may start only at round zero.
    InitialRoundNotZero { actual: ConsensusRound },
    /// The operation is not valid in the current local decision phase.
    UnexpectedPhase {
        expected: FixedValidatorLockPhaseV0,
        actual: FixedValidatorLockPhaseV0,
    },
    /// The proposal was admitted against another parent branch.
    ProposalBranchMismatch,
    /// The proposal does not belong to the state's exact current position.
    ProposalPositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// A proof-derived proposal valid round is not strictly earlier than current.
    InvalidValidRound {
        valid_round: ConsensusRound,
        current_round: ConsensusRound,
    },
    /// Valid-round metadata and retained certificate evidence disagree.
    InconsistentValidRoundProof,
    /// Another exact value has verified prevote-quorum evidence at the same
    /// latest valid round.
    ///
    /// The state remains unchanged and returns no vote effect. This volatile
    /// error does not persist the conflict or itself establish durable halt,
    /// equivocation adjudication, punishment, or finality authority.
    ConflictingValidValue {
        round: ConsensusRound,
        retained: ProposalSigningRoot,
        observed: ProposalSigningRoot,
    },
    /// The quorum certificate belongs to another consensus context.
    QuorumContextMismatch,
    /// Exact-round quorum verification against the fixed set failed.
    QuorumVerification(QuorumCertificateVerifyError),
    /// The quorum certificate does not belong to the exact current position.
    QuorumPositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// The supplied quorum certificate authenticates precommits, not prevotes.
    QuorumRoleMismatch { actual: ConsensusVoteRole },
    /// The quorum target does not equal the exact expected nil or proposal root.
    QuorumTargetMismatch {
        expected: ConsensusVoteTarget,
        actual: ConsensusVoteTarget,
    },
    /// Nil-precommit round advancement received another quorum vote role.
    NilPrecommitQuorumRoleMismatch { actual: ConsensusVoteRole },
    /// Nil-precommit round advancement received a non-nil quorum target.
    NilPrecommitQuorumTargetMismatch { actual: ConsensusVoteTarget },
    /// A sequential cursor belongs to another parent branch or height base.
    RoundBranchMismatch,
    /// The supplied current-round cursor belongs to another parent or height base.
    CurrentRoundBranchMismatch,
    /// The supplied current-round cursor is not the state's exact position.
    CurrentRoundPositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// The caller-local higher-round work ceiling is reserved at zero.
    HigherRoundWorkLimitNotPositive,
    /// The unauthenticated certificate routing position failed strict framing.
    HigherRoundCertificatePosition(QuorumCertificateVerifyError),
    /// The embedded higher-round certificate names another height.
    HigherRoundHeightMismatch {
        expected: ConsensusHeight,
        actual: ConsensusHeight,
    },
    /// The embedded certificate round is not strictly above current state.
    HigherRoundNotStrictlyGreater {
        current: ConsensusRound,
        actual: ConsensusRound,
    },
    /// The embedded round exceeds caller-local sequential work policy.
    HigherRoundLimitExceeded {
        round: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The exact internally selected higher-round cursor could not be derived.
    HigherRoundDerivation(ProposerSelectionError),
    /// The durable checkpoint bytes could not be allocated.
    HigherRoundCheckpointAllocationFailed,
    /// A prepared higher-round transition belongs to another live lineage.
    HigherRoundAdvanceLineageMismatch,
    /// State changed after a higher-round transition was prepared.
    HigherRoundAdvanceStateMismatch,
    /// The current round cannot be incremented without overflow.
    RoundExhausted,
    /// The exact next branch-derived round could not be constructed.
    NextRoundDerivation(ProposerSelectionError),
    /// The supplied cursor is not the exact next position.
    NonSequentialRound {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// A verified height transition was produced from another parent branch.
    HeightTransitionParentMismatch,
    /// A verified transition does not complete the lock state's current height.
    HeightTransitionHeightMismatch {
        expected: ConsensusHeight,
        actual: ConsensusHeight,
    },
    /// The verified child cannot derive the next height's round-zero cursor.
    HeightTransitionRoundZero(ProposerSelectionError),
    /// Retaining canonical verified quorum evidence could not allocate memory.
    CertificateAllocationFailed,
}

impl fmt::Display for FixedValidatorLockStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialRoundNotZero { actual } => write!(
                formatter,
                "fixed-validator lock state must begin at round zero, not {actual:?}"
            ),
            Self::UnexpectedPhase { expected, actual } => write!(
                formatter,
                "fixed-validator lock operation requires phase {expected:?}, current phase is {actual:?}"
            ),
            Self::ProposalBranchMismatch => formatter
                .write_str("admitted proposal belongs to another fixed consensus parent branch"),
            Self::ProposalPositionMismatch { expected, actual } => write!(
                formatter,
                "admitted proposal position {actual:?} differs from current position {expected:?}"
            ),
            Self::InvalidValidRound {
                valid_round,
                current_round,
            } => write!(
                formatter,
                "proposal valid round {valid_round:?} is not earlier than current round {current_round:?}"
            ),
            Self::InconsistentValidRoundProof => formatter.write_str(
                "proposal valid-round metadata and canonical prevote proof are inconsistent",
            ),
            Self::ConflictingValidValue {
                round,
                retained,
                observed,
            } => write!(
                formatter,
                "valid round {round:?} has conflicting retained {retained:?} and observed {observed:?} proposal roots"
            ),
            Self::QuorumContextMismatch => formatter
                .write_str("prevote quorum context differs from the current consensus context"),
            Self::QuorumVerification(error) => error.fmt(formatter),
            Self::QuorumPositionMismatch { expected, actual } => write!(
                formatter,
                "prevote quorum position {actual:?} differs from current position {expected:?}"
            ),
            Self::QuorumRoleMismatch { actual } => write!(
                formatter,
                "current-round quorum must authenticate prevotes, not {actual:?}"
            ),
            Self::QuorumTargetMismatch { expected, actual } => write!(
                formatter,
                "prevote quorum target {actual:?} differs from expected target {expected:?}"
            ),
            Self::NilPrecommitQuorumRoleMismatch { actual } => write!(
                formatter,
                "round advancement requires precommit quorum evidence, not {actual:?}"
            ),
            Self::NilPrecommitQuorumTargetMismatch { actual } => write!(
                formatter,
                "round advancement requires a nil precommit quorum, not {actual:?}"
            ),
            Self::RoundBranchMismatch => formatter.write_str(
                "sequential round cursor belongs to another fixed consensus parent branch",
            ),
            Self::CurrentRoundBranchMismatch => formatter
                .write_str("current round cursor belongs to another fixed consensus parent branch"),
            Self::CurrentRoundPositionMismatch { expected, actual } => write!(
                formatter,
                "current round cursor position {actual:?} differs from lock-state position {expected:?}"
            ),
            Self::HigherRoundWorkLimitNotPositive => {
                formatter.write_str("higher-round caller-local inclusive maximum must be positive")
            }
            Self::HigherRoundCertificatePosition(error) => write!(
                formatter,
                "higher-round certificate position could not be strictly inspected: {error}"
            ),
            Self::HigherRoundHeightMismatch { expected, actual } => write!(
                formatter,
                "higher-round certificate height {actual:?} differs from current height {expected:?}"
            ),
            Self::HigherRoundNotStrictlyGreater { current, actual } => write!(
                formatter,
                "certificate round {actual:?} is not strictly higher than current round {current:?}"
            ),
            Self::HigherRoundLimitExceeded { round, maximum } => write!(
                formatter,
                "certificate round {round:?} exceeds caller-local inclusive maximum {maximum:?}"
            ),
            Self::HigherRoundDerivation(error) => write!(
                formatter,
                "higher-round fixed-validator cursor cannot be derived: {error}"
            ),
            Self::HigherRoundCheckpointAllocationFailed => formatter
                .write_str("memory allocation failed while sealing higher-round checkpoint bytes"),
            Self::HigherRoundAdvanceLineageMismatch => formatter
                .write_str("prepared higher-round transition belongs to another live lock lineage"),
            Self::HigherRoundAdvanceStateMismatch => formatter
                .write_str("lock state changed after the higher-round transition was prepared"),
            Self::RoundExhausted => formatter
                .write_str("fixed-validator lock state cannot advance beyond the terminal round"),
            Self::NextRoundDerivation(error) => {
                write!(
                    formatter,
                    "next fixed-validator round cannot be derived: {error}"
                )
            }
            Self::NonSequentialRound { expected, actual } => write!(
                formatter,
                "next round cursor position {actual:?} differs from exact successor {expected:?}"
            ),
            Self::HeightTransitionParentMismatch => formatter.write_str(
                "verified height transition belongs to another fixed consensus parent branch",
            ),
            Self::HeightTransitionHeightMismatch { expected, actual } => write!(
                formatter,
                "verified transition height {actual:?} differs from lock-state height {expected:?}"
            ),
            Self::HeightTransitionRoundZero(error) => write!(
                formatter,
                "verified child cannot derive its next round-zero cursor: {error}"
            ),
            Self::CertificateAllocationFailed => formatter
                .write_str("memory allocation failed while retaining canonical quorum evidence"),
        }
    }
}

impl Error for FixedValidatorLockStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::QuorumVerification(error) | Self::HigherRoundCertificatePosition(error) => {
                Some(error)
            }
            Self::NextRoundDerivation(error) | Self::HigherRoundDerivation(error) => Some(error),
            Self::HeightTransitionRoundZero(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "fixed_validator_lock_state/tests.rs"]
mod tests;
