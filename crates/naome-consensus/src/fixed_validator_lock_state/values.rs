//! Lock phases, retained values, and live unsigned effects.

use super::*;

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
    pub(super) value: ConsensusValueV0,
    pub(super) round: ConsensusRound,
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
    pub(super) value: ConsensusValueV0,
    pub(super) round: ConsensusRound,
    pub(super) prevote_certificate_id: QuorumCertificateId,
    pub(super) canonical_prevote_certificate: Vec<u8>,
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
    pub(super) position: ConsensusPosition,
    pub(super) role: ConsensusVoteRole,
    pub(super) target: ConsensusVoteTarget,
    pub(super) state_binding: [u8; 32],
    pub(super) live_lineage_seal: Option<Arc<()>>,
}

impl FixedValidatorUnsignedVoteEffectV0 {
    pub(super) fn new(
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

    pub(super) fn from_snapshot(
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

    pub(super) fn belongs_to(&self, state: &FixedValidatorLockStateV0) -> bool {
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
