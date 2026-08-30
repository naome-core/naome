//! In-memory fixed-validator locking and valid-value effects for one height.
//!
//! This kernel starts only from a branch-derived round-zero cursor and moves
//! through proposal, prevote, and precommit effects at one exact position. It
//! retains exact locked and valid values, but creates no signatures and grants
//! no persistence, timeout, networking, peer-trust, branch-selection, or
//! finality authority. Direct jumps to arbitrary higher rounds are deliberately
//! outside V0; callers must supply the next branch-derived sequential cursor.

use std::error::Error;
use std::fmt;

use super::fixed_consensus_branch::{
    FixedConsensusBranchCoordinateV0, FixedConsensusRoundV0, VerifiedFixedConsensusProposalV0,
};
use super::{
    ConsensusContextV0, ConsensusPosition, ConsensusRound, ConsensusValueV0, ConsensusVoteRole,
    ConsensusVoteTarget, ProposalSigningRoot, QuorumCertificateId, QuorumCertificateVerifyError,
    VerifiedQuorumCertificateV0,
};

/// The exact local effect phase for one fixed-validator consensus round.
///
/// The phase records only which unsigned effect this kernel may decide next.
/// It is not a timer, network-delivery claim, or proof that any vote was signed
/// or broadcast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorLockPhaseV0 {
    /// The kernel may evaluate one admitted proposal or the absent/invalid path.
    Proposal,
    /// The kernel has returned a prevote effect and may evaluate prevote quorum.
    Prevote,
    /// The kernel has returned a precommit effect and may advance sequentially.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorUnsignedVoteEffectV0 {
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
}

impl FixedValidatorUnsignedVoteEffectV0 {
    fn new(
        position: ConsensusPosition,
        role: ConsensusVoteRole,
        target: ConsensusVoteTarget,
    ) -> Self {
        Self {
            position,
            role,
            target,
        }
    }

    /// Returns the exact height and round for the unsigned effect.
    pub const fn position(self) -> ConsensusPosition {
        self.position
    }

    /// Returns whether this effect is a prevote or precommit.
    pub const fn role(self) -> ConsensusVoteRole {
        self.role
    }

    /// Returns the exact nil-or-proposal target.
    pub const fn target(self) -> ConsensusVoteTarget {
        self.target
    }
}

/// One sealed, volatile fixed-validator lock state for a single height.
///
/// Construction requires the exact branch-derived round-zero cursor. All state
/// fields are private, and every fallible mutation validates and prepares its
/// complete effect before changing the state. The state does not own a round
/// cursor, so callers retain the authority and cost of deriving exactly one
/// sequential successor through [`FixedConsensusRoundV0::advance_round`].
#[derive(Debug)]
#[must_use]
pub struct FixedValidatorLockStateV0 {
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

    /// Returns the exact current local effect phase.
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
            self.position,
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
            self.position,
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
            self.position,
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

        self.position = expected;
        self.phase = FixedValidatorLockPhaseV0::Proposal;
        Ok(())
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
            self.position,
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
            self.position,
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

/// A rejected in-memory fixed-validator locking operation.
///
/// Every error leaves position, phase, lock, and valid value unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedValidatorLockStateError {
    /// Empty lock state may start only at round zero.
    InitialRoundNotZero { actual: ConsensusRound },
    /// The operation is not valid in the current local effect phase.
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
    /// A sequential cursor belongs to another parent branch or height base.
    RoundBranchMismatch,
    /// The supplied current-round cursor belongs to another parent or height base.
    CurrentRoundBranchMismatch,
    /// The supplied current-round cursor is not the state's exact position.
    CurrentRoundPositionMismatch {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
    /// The current round cannot be incremented without overflow.
    RoundExhausted,
    /// The supplied cursor is not the exact next position.
    NonSequentialRound {
        expected: ConsensusPosition,
        actual: ConsensusPosition,
    },
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
            Self::RoundBranchMismatch => formatter.write_str(
                "sequential round cursor belongs to another fixed consensus parent branch",
            ),
            Self::CurrentRoundBranchMismatch => formatter
                .write_str("current round cursor belongs to another fixed consensus parent branch"),
            Self::CurrentRoundPositionMismatch { expected, actual } => write!(
                formatter,
                "current round cursor position {actual:?} differs from lock-state position {expected:?}"
            ),
            Self::RoundExhausted => formatter
                .write_str("fixed-validator lock state cannot advance beyond the terminal round"),
            Self::NonSequentialRound { expected, actual } => write!(
                formatter,
                "next round cursor position {actual:?} differs from exact successor {expected:?}"
            ),
            Self::CertificateAllocationFailed => formatter.write_str(
                "memory allocation failed while retaining canonical prevote quorum evidence",
            ),
        }
    }
}

impl Error for FixedValidatorLockStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::QuorumVerification(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "fixed_validator_lock_state/tests.rs"]
mod tests;
