//! Live vote intents and distinct inert replay records.

use super::*;

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
    pub(super) snapshot: FixedValidatorVoteStateSnapshotV0,
    pub(super) effect: FixedValidatorUnsignedVoteEffectV0,
    pub(super) signer: ConsensusKey,
    pub(super) canonical_state_and_vote_intent_bytes: Vec<u8>,
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
    pub(super) observed: ObservedFixedValidatorVoteIntentV0,
    pub(super) signing_transcript: Vec<u8>,
}

/// One canonical record reconstructed against its exact typed round.
///
/// Restart verification reconstructs the lock state but deliberately does not
/// recreate live signing authority. If a crash occurred after preparing an
/// intent but before durably storing a completed signed vote, V0 fails closed.
#[derive(Debug)]
#[must_use]
pub struct VerifiedReplayFixedValidatorVoteIntentV0 {
    pub(super) lock_state: FixedValidatorLockStateV0,
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

    pub(super) fn from_observed(observed: ObservedFixedValidatorVoteIntentV0) -> Self {
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
