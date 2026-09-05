//! Verified higher-round effects and inert checkpoint records.

use super::*;

/// One verified phase-only higher-round transition prepared by a live lock state.
///
/// The target cursor is derived internally from the exact current cursor and the
/// embedded quorum-certificate position. Private fields bind the transition to
/// the originating live state, retain the exact canonical certificate and
/// complete post-jump checkpoint bytes, and expose no unsigned vote, signing,
/// proposal, selection, or finality authority.
#[must_use]
pub struct VerifiedFixedValidatorHigherRoundAdvanceV0<'branch> {
    pub(super) target_round: FixedConsensusRoundV0<'branch>,
    pub(super) source_state_binding: [u8; OPAQUE_ID_BYTES],
    pub(super) live_lineage_seal: Arc<()>,
    pub(super) target_phase: FixedValidatorLockPhaseV0,
    pub(super) role: ConsensusVoteRole,
    pub(super) target: ConsensusVoteTarget,
    pub(super) certificate_id: QuorumCertificateId,
    pub(super) canonical_certificate: Vec<u8>,
    pub(super) canonical_checkpoint: Vec<u8>,
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
    pub(super) source_position: ConsensusPosition,
    pub(super) source_phase: FixedValidatorLockPhaseV0,
    pub(super) source_state_binding: [u8; OPAQUE_ID_BYTES],
    pub(super) target_snapshot: FixedValidatorVoteStateSnapshotV0,
    pub(super) role: ConsensusVoteRole,
    pub(super) target: ConsensusVoteTarget,
    pub(super) certificate_id: QuorumCertificateId,
    pub(super) canonical_certificate: Vec<u8>,
    pub(super) canonical_checkpoint: Vec<u8>,
}

/// One exact higher-round checkpoint reconstructed against its typed target.
///
/// This value carries only a non-signing lock state. A key-owning journal may
/// publish it as live state only after its own exact external-anchor and session
/// issuance checks succeed.
#[derive(Debug)]
#[must_use]
pub struct VerifiedReplayFixedValidatorHigherRoundCheckpointV0 {
    pub(super) lock_state: FixedValidatorLockStateV0,
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
