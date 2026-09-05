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
        self.prepare_higher_round_quorum_advance_inner(
            current_round,
            canonical_certificate,
            inclusive_maximum_round,
            None,
        )
    }

    /// Prepares one exact higher-round proposal-prevote transition.
    ///
    /// The quorum is fully authenticated by the general higher-round path
    /// before its position, prevote role, and proposal target are compared with
    /// the caller's exact expected values. A mismatch returns no transition and
    /// changes no lock state. This is a pairing constraint only: success still
    /// grants neither a precommit vote nor finality authority.
    pub fn prepare_higher_round_proposal_prevote_advance<'branch>(
        &self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        expected_position: ConsensusPosition,
        expected_proposal_root: ProposalSigningRoot,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<VerifiedFixedValidatorHigherRoundAdvanceV0<'branch>, FixedValidatorLockStateError>
    {
        self.prepare_higher_round_quorum_advance_inner(
            current_round,
            canonical_certificate,
            inclusive_maximum_round,
            Some((
                expected_position,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(expected_proposal_root),
            )),
        )
    }

    fn prepare_higher_round_quorum_advance_inner<'branch>(
        &self,
        current_round: &FixedConsensusRoundV0<'branch>,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
        expected: Option<(ConsensusPosition, ConsensusVoteRole, ConsensusVoteTarget)>,
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
        if let Some((expected_position, expected_role, expected_target)) = expected {
            if position != expected_position {
                return Err(
                    FixedValidatorLockStateError::HigherRoundQuorumPositionMismatch {
                        expected: expected_position,
                        actual: position,
                    },
                );
            }
            if role != expected_role {
                return Err(
                    FixedValidatorLockStateError::HigherRoundQuorumRoleMismatch {
                        expected: expected_role,
                        actual: role,
                    },
                );
            }
            if target != expected_target {
                return Err(
                    FixedValidatorLockStateError::HigherRoundQuorumTargetMismatch {
                        expected: expected_target,
                        actual: target,
                    },
                );
            }
        }
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

#[cfg(test)]
mod tests;

mod checkpoint;
mod codec;
mod errors;
mod replay;
mod snapshot;
mod values;
mod vote_intent;
pub use checkpoint::*;
use codec::*;
pub use errors::*;
use replay::*;
pub(crate) use snapshot::FixedValidatorProposalStateSnapshotV0;
use snapshot::*;
pub use values::*;
pub use vote_intent::*;
