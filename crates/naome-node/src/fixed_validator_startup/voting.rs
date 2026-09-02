use std::borrow::Cow;
use std::error::Error;
use std::fmt;

use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_consensus::{
    ConsensusContextV0, ConsensusHeight, ConsensusPosition, ConsensusProposalVerifyError,
    ConsensusRound, ConsensusVoteRole, ConsensusVoteTarget, FixedConsensusBranchV0,
    FixedConsensusRoundV0, FixedValidatorLockPhaseV0, FixedValidatorLockStateError,
    FixedValidatorUnsignedVoteEffectV0, ProposerSelectionError, QuorumCertificateBuildError,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError, FixedValidatorSignedVoteV0,
    FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyHaltV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::candidate_backed_proposal::{
    CandidateBackedProposalSourceErrorV0,
    load_candidate_backed_proposal_payload as load_candidate_backed_proposal_payload_source,
};
use super::{
    FixedValidatorNodeCurrentRoundErrorV0, FixedValidatorNodeSigningScopeV0,
    FixedValidatorNodeVotingSessionV0, fixed_validator_node_current_round,
};

/// Complete result of one node-owned current-round vote execution.
///
/// A signed result returns continued node authority only after the exact vote
/// preparation, independent anchor, signature, completion, and updated anchor
/// are all durable. A rejection returns the unchanged scope because no kernel
/// effect or signer write occurred. A terminal signer conflict returns no scope.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeVoteExecutionOutcomeV0<'node> {
    /// One exact current-round vote completed durably and may be released.
    Signed {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        vote: FixedValidatorSignedVoteV0,
    },
    /// A source or explicit input failed before any volatile or durable signer effect.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeVoteRejectionV0>,
    },
    /// A non-identical intent at the same slot durably stopped this signer.
    SignerStopped(FixedValidatorVoteSafetyHaltV0),
}

/// A pre-effect current-round source or input failure that preserves the signing scope.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeVoteRejectionV0 {
    /// Reconstructing the signer's current round would exceed local work policy.
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The caller-routed phase-close event belongs to another consensus context.
    PhaseCloseContextMismatch {
        required_phase: FixedValidatorLockPhaseV0,
        current: Box<ConsensusContextV0>,
        event: Box<ConsensusContextV0>,
    },
    /// The caller-routed phase-close event belongs to another height or round.
    PhaseClosePositionMismatch {
        required_phase: FixedValidatorLockPhaseV0,
        current: ConsensusPosition,
        event: ConsensusPosition,
    },
    /// The candidate store belongs to another artifact chain.
    CandidateChainMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// Exact candidate lookup or integrity verification failed.
    CandidateStore(Box<ArtifactBlockCandidateStoreError>),
    /// The exact caller-selected candidate is not retained.
    CandidateUnavailable { target: ArtifactBlockId },
    /// The proposal embeds another block than the caller-selected target.
    ProposalTargetMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The retained candidate bytes differ from the proposal's exact block.
    CandidateBlockMismatch { target: ArtifactBlockId },
    /// Exact payload lookup or integrity verification failed.
    PayloadStore(Box<CanonicalArtifactPayloadStoreError>),
    /// The retained candidate's exact committed payload is unavailable.
    PayloadUnavailable { target: ArtifactBlockId },
    /// Complete proposal-control and artifact admission failed.
    Proposal(Box<ConsensusProposalVerifyError>),
    /// The exact caller-routed signed-prevote batch could not form one quorum.
    QuorumConstruction(Box<QuorumCertificateBuildError>),
    /// The current lock kernel rejected the exact event before mutation.
    Decision(Box<FixedValidatorLockStateError>),
}

impl fmt::Display for FixedValidatorNodeVoteRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds local vote-execution ceiling {maximum:?}"
            ),
            Self::PhaseCloseContextMismatch {
                required_phase,
                current,
                event,
            } => write!(
                formatter,
                "{required_phase:?} close context {event:?} differs from current node context {current:?}"
            ),
            Self::PhaseClosePositionMismatch {
                required_phase,
                current,
                event,
            } => write!(
                formatter,
                "{required_phase:?} close position {event:?} differs from current signer position {current:?}"
            ),
            Self::CandidateChainMismatch { expected, actual } => write!(
                formatter,
                "candidate store chain mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateStore(source) => source.fmt(formatter),
            Self::CandidateUnavailable { target } => {
                write!(formatter, "candidate {target:?} is not retained")
            }
            Self::ProposalTargetMismatch { expected, actual } => write!(
                formatter,
                "proposal target mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateBlockMismatch { target } => write!(
                formatter,
                "retained candidate {target:?} differs from the proposal block"
            ),
            Self::PayloadStore(source) => source.fmt(formatter),
            Self::PayloadUnavailable { target } => {
                write!(
                    formatter,
                    "payload for candidate {target:?} is not retained"
                )
            }
            Self::Proposal(source) => {
                write!(formatter, "current node proposal was rejected: {source}")
            }
            Self::QuorumConstruction(source) => {
                write!(
                    formatter,
                    "current node prevote batch was rejected: {source}"
                )
            }
            Self::Decision(source) => {
                write!(formatter, "current node vote event was rejected: {source}")
            }
        }
    }
}

impl Error for FixedValidatorNodeVoteRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CandidateStore(source) => Some(source.as_ref()),
            Self::PayloadStore(source) => Some(source.as_ref()),
            Self::Proposal(source) => Some(source.as_ref()),
            Self::QuorumConstruction(source) => Some(source.as_ref()),
            Self::Decision(source) => Some(source.as_ref()),
            Self::RoundWorkLimitExceeded { .. }
            | Self::PhaseCloseContextMismatch { .. }
            | Self::PhaseClosePositionMismatch { .. }
            | Self::CandidateChainMismatch { .. }
            | Self::CandidateUnavailable { .. }
            | Self::ProposalTargetMismatch { .. }
            | Self::CandidateBlockMismatch { .. }
            | Self::PayloadUnavailable { .. } => None,
        }
    }
}

/// A fatal node or signer error during current-round vote execution.
///
/// Every variant consumes the signing scope and grants no signed bytes. Strict
/// restart is the only classifier after an ambiguous durable step.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeVoteExecutionErrorV0 {
    /// The node-owned signer and branch do not name the same next height.
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    /// The exact node-owned branch round could not be reconstructed.
    Round(ProposerSelectionError),
    /// The signer is above the node-owned finality journal's durable ceiling.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The signing session was not operational before a lock effect was emitted.
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// The exact post-effect vote intent could not be durably prepared.
    Prepare(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// The anchored preparation could not issue exact key-use authority.
    Acknowledge(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// Key use, self-verification, completion, or completion anchoring failed.
    Sign(Box<FixedValidatorVoteSafetyJournalErrorV0>),
}

impl fmt::Display for FixedValidatorNodeVoteExecutionErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            } => write!(
                formatter,
                "signer position {signer:?} differs from node branch next height {branch_next_height:?}"
            ),
            Self::Round(source) => write!(
                formatter,
                "current node vote round could not be reconstructed: {source}"
            ),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds node finality ceiling {maximum:?}"
            ),
            Self::Session(source) => {
                write!(formatter, "node vote session is not operational: {source}")
            }
            Self::Prepare(source) => {
                write!(formatter, "node vote preparation failed: {source}")
            }
            Self::Acknowledge(source) => write!(
                formatter,
                "node vote preparation acknowledgement failed: {source}"
            ),
            Self::Sign(source) => write!(formatter, "node vote signing failed: {source}"),
        }
    }
}

impl Error for FixedValidatorNodeVoteExecutionErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Session(source)
            | Self::Prepare(source)
            | Self::Acknowledge(source)
            | Self::Sign(source) => Some(source.as_ref()),
            Self::SignerBranchHeightMismatch { .. } | Self::FinalityRoundLimitExceeded { .. } => {
                None
            }
        }
    }
}

enum CurrentRoundErrorV0 {
    Rejected(FixedValidatorNodeVoteRejectionV0),
    Fatal(FixedValidatorNodeVoteExecutionErrorV0),
}

enum FinishedVoteV0 {
    Signed(FixedValidatorSignedVoteV0),
    SignerStopped(FixedValidatorVoteSafetyHaltV0),
}

enum ProposalVoteKindV0<'input> {
    Prevote,
    Precommit {
        quorum: PrevoteQuorumInputV0<'input>,
    },
}

enum PrevoteQuorumInputV0<'input> {
    CanonicalCertificate(&'input [u8]),
    ExactSignedVotes(&'input [&'input [u8]]),
}

enum ProposalVoteErrorV0 {
    Rejected(FixedValidatorNodeVoteRejectionV0),
    Fatal(FixedValidatorNodeVoteExecutionErrorV0),
}

impl<'node> FixedValidatorNodeSigningScopeV0<'node> {
    /// Fully admits one exact proposal and durably signs its derived prevote.
    ///
    /// The caller supplies one proposal-control representation and complete
    /// canonical artifact bytes. This method derives the signer's exact current
    /// round under both the node finality and caller-local ceilings and applies
    /// the existing lock rule; a lock may therefore cause the signed target to
    /// differ from the supplied value.
    pub fn sign_prevote_for_proposal(
        mut self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        let finality_maximum_round = self.finality.replay_limit().max_round();
        let round = match current_round(
            &self.branch,
            &self.signing_session,
            inclusive_maximum_round,
            finality_maximum_round,
        ) {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };
        let proposal = match round.decode_and_verify_proposal_control(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeVoteRejectionV0::Proposal(Box::new(source)),
                ));
            }
        };
        let finished = match decide_and_finish_proposal_vote(
            &mut self.signing_session,
            &round,
            &proposal,
            ProposalVoteKindV0::Prevote,
        ) {
            Ok(finished) => finished,
            Err(ProposalVoteErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(ProposalVoteErrorV0::Fatal(error)) => return Err(error),
        };
        Ok(finished_outcome(self, finished))
    }

    /// Loads one exact caller-selected candidate and payload, fully admits the
    /// proposal, and durably signs the unchanged lock-derived prevote.
    pub fn sign_candidate_backed_prevote_for_proposal(
        mut self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: ArtifactBlockId,
        canonical_proposal_control_bytes: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        let finality_maximum_round = self.finality.replay_limit().max_round();
        let round = match current_round(
            &self.branch,
            &self.signing_session,
            inclusive_maximum_round,
            finality_maximum_round,
        ) {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };
        if let Err(rejection) =
            require_phase(&self.signing_session, FixedValidatorLockPhaseV0::Proposal)
        {
            drop(round);
            return Ok(rejected(self, rejection));
        }
        let canonical_artifact_bytes = match load_candidate_backed_proposal_payload(
            &round,
            candidates,
            payloads,
            expected_target,
            canonical_proposal_control_bytes,
        ) {
            Ok(bytes) => bytes,
            Err(rejection) => {
                drop(round);
                return Ok(rejected(self, rejection));
            }
        };
        let proposal = match round.decode_and_verify_proposal_control(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeVoteRejectionV0::Proposal(Box::new(source)),
                ));
            }
        };
        let finished = match decide_and_finish_proposal_vote(
            &mut self.signing_session,
            &round,
            &proposal,
            ProposalVoteKindV0::Prevote,
        ) {
            Ok(finished) => finished,
            Err(ProposalVoteErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(ProposalVoteErrorV0::Fatal(error)) => return Err(error),
        };
        Ok(finished_outcome(self, finished))
    }

    /// Explicitly closes one exact Proposal phase and durably signs its prevote.
    ///
    /// The caller supplies the consensus context and source position attached to
    /// its close event. Both must match the exact node-derived current round
    /// before the unchanged lock rule may create a locked-value or nil prevote.
    /// This does not infer that a timeout elapsed or that no proposal exists
    /// elsewhere.
    pub fn sign_prevote_after_proposal_close(
        mut self,
        event_context: ConsensusContextV0,
        event_position: ConsensusPosition,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        let finality_maximum_round = self.finality.replay_limit().max_round();
        let round = match current_round(
            &self.branch,
            &self.signing_session,
            inclusive_maximum_round,
            finality_maximum_round,
        ) {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };
        if let Err(rejection) = admit_phase_close_identity(
            &round,
            FixedValidatorLockPhaseV0::Proposal,
            event_context,
            event_position,
        ) {
            drop(round);
            return Ok(rejected(self, rejection));
        }
        let effect = match self.signing_session.decide_prevote_without_proposal() {
            Ok(effect) => effect,
            Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeVoteRejectionV0::Decision(Box::new(source)),
                ));
            }
            Err(source) => {
                return Err(FixedValidatorNodeVoteExecutionErrorV0::Session(Box::new(
                    source,
                )));
            }
        };
        let finished = finish_vote(&mut self.signing_session, &round, effect)?;
        Ok(finished_outcome(self, finished))
    }

    /// Fully admits one exact proposal and current-round proposal prevote quorum,
    /// then durably signs the resulting proposal precommit.
    pub fn sign_precommit_for_proposal_quorum(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_prevote_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        sign_precommit_for_direct_proposal(
            self,
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            PrevoteQuorumInputV0::CanonicalCertificate(canonical_prevote_certificate),
            inclusive_maximum_round,
        )
    }

    /// Fully admits one exact proposal and constructs its current-round prevote
    /// quorum from the complete caller-routed signed-vote batch before durably
    /// signing the resulting proposal precommit.
    ///
    /// Every supplied vote must match this node's exact current round, prevote
    /// role, and admitted proposal target. The batch is not filtered,
    /// deduplicated, retained, grouped, or selected.
    pub fn sign_precommit_for_proposal_vote_batch(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_signed_prevotes: &[&[u8]],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        sign_precommit_for_direct_proposal(
            self,
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            PrevoteQuorumInputV0::ExactSignedVotes(canonical_signed_prevotes),
            inclusive_maximum_round,
        )
    }

    /// Loads one exact caller-selected candidate and payload, fully admits its
    /// proposal and current-round prevote quorum, and durably signs precommit.
    pub fn sign_candidate_backed_precommit_for_proposal_quorum(
        self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: ArtifactBlockId,
        canonical_proposal_control_bytes: &[u8],
        canonical_prevote_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        sign_candidate_backed_precommit_for_proposal(
            self,
            candidates,
            payloads,
            expected_target,
            canonical_proposal_control_bytes,
            PrevoteQuorumInputV0::CanonicalCertificate(canonical_prevote_certificate),
            inclusive_maximum_round,
        )
    }

    /// Loads one exact caller-selected candidate and payload, constructs its
    /// current-round prevote quorum from the complete caller-routed signed-vote
    /// batch, and durably signs the resulting proposal precommit.
    ///
    /// Candidate and payload admission remains unchanged. The vote batch grants
    /// no discovery, availability, arrival-order, or certificate-selection
    /// authority.
    pub fn sign_candidate_backed_precommit_for_proposal_vote_batch(
        self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: ArtifactBlockId,
        canonical_proposal_control_bytes: &[u8],
        canonical_signed_prevotes: &[&[u8]],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        sign_candidate_backed_precommit_for_proposal(
            self,
            candidates,
            payloads,
            expected_target,
            canonical_proposal_control_bytes,
            PrevoteQuorumInputV0::ExactSignedVotes(canonical_signed_prevotes),
            inclusive_maximum_round,
        )
    }

    /// Verifies one exact current-round nil prevote quorum and durably signs nil
    /// precommit while preserving the latest valid value.
    pub fn sign_precommit_for_nil_quorum(
        self,
        canonical_prevote_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        sign_precommit_for_nil(
            self,
            PrevoteQuorumInputV0::CanonicalCertificate(canonical_prevote_certificate),
            inclusive_maximum_round,
        )
    }

    /// Constructs one exact current-round nil prevote quorum from the complete
    /// caller-routed signed-vote batch, then durably signs nil precommit while
    /// preserving the latest valid value.
    ///
    /// The batch is a synchronous input only. This method does not observe or
    /// retain messages, infer quorum availability, or choose an event.
    pub fn sign_precommit_for_nil_vote_batch(
        self,
        canonical_signed_prevotes: &[&[u8]],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        sign_precommit_for_nil(
            self,
            PrevoteQuorumInputV0::ExactSignedVotes(canonical_signed_prevotes),
            inclusive_maximum_round,
        )
    }

    /// Explicitly closes one exact Prevote phase and durably signs nil precommit.
    ///
    /// The caller supplies the consensus context and source position attached to
    /// its close event. Both must match the exact node-derived current round
    /// before the unchanged lock rule preserves lock and valid-value state and
    /// emits nil. This infers no timeout or network condition.
    pub fn sign_precommit_after_prevote_close(
        mut self,
        event_context: ConsensusContextV0,
        event_position: ConsensusPosition,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
        FixedValidatorNodeVoteExecutionErrorV0,
    > {
        let finality_maximum_round = self.finality.replay_limit().max_round();
        let round = match current_round(
            &self.branch,
            &self.signing_session,
            inclusive_maximum_round,
            finality_maximum_round,
        ) {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };
        if let Err(rejection) = admit_phase_close_identity(
            &round,
            FixedValidatorLockPhaseV0::Prevote,
            event_context,
            event_position,
        ) {
            drop(round);
            return Ok(rejected(self, rejection));
        }
        let effect = match self.signing_session.decide_precommit_without_quorum() {
            Ok(effect) => effect,
            Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeVoteRejectionV0::Decision(Box::new(source)),
                ));
            }
            Err(source) => {
                return Err(FixedValidatorNodeVoteExecutionErrorV0::Session(Box::new(
                    source,
                )));
            }
        };
        let finished = finish_vote(&mut self.signing_session, &round, effect)?;
        Ok(finished_outcome(self, finished))
    }
}

fn sign_precommit_for_direct_proposal<'node>(
    mut scope: FixedValidatorNodeSigningScopeV0<'node>,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: Vec<u8>,
    quorum: PrevoteQuorumInputV0<'_>,
    inclusive_maximum_round: ConsensusRound,
) -> Result<FixedValidatorNodeVoteExecutionOutcomeV0<'node>, FixedValidatorNodeVoteExecutionErrorV0>
{
    let finality_maximum_round = scope.finality.replay_limit().max_round();
    let round = match current_round(
        &scope.branch,
        &scope.signing_session,
        inclusive_maximum_round,
        finality_maximum_round,
    ) {
        Ok(round) => round,
        Err(CurrentRoundErrorV0::Rejected(rejection)) => {
            return Ok(rejected(scope, rejection));
        }
        Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
    };
    if matches!(&quorum, PrevoteQuorumInputV0::ExactSignedVotes(_))
        && let Err(rejection) =
            require_phase(&scope.signing_session, FixedValidatorLockPhaseV0::Prevote)
    {
        drop(round);
        return Ok(rejected(scope, rejection));
    }
    let proposal = match round.decode_and_verify_proposal_control(
        canonical_proposal_control_bytes,
        canonical_artifact_bytes,
    ) {
        Ok(proposal) => proposal,
        Err(source) => {
            return Ok(rejected(
                scope,
                FixedValidatorNodeVoteRejectionV0::Proposal(Box::new(source)),
            ));
        }
    };
    let finished = match decide_and_finish_proposal_vote(
        &mut scope.signing_session,
        &round,
        &proposal,
        ProposalVoteKindV0::Precommit { quorum },
    ) {
        Ok(finished) => finished,
        Err(ProposalVoteErrorV0::Rejected(rejection)) => {
            return Ok(rejected(scope, rejection));
        }
        Err(ProposalVoteErrorV0::Fatal(error)) => return Err(error),
    };
    Ok(finished_outcome(scope, finished))
}

fn sign_candidate_backed_precommit_for_proposal<'node>(
    mut scope: FixedValidatorNodeSigningScopeV0<'node>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_proposal_control_bytes: &[u8],
    quorum: PrevoteQuorumInputV0<'_>,
    inclusive_maximum_round: ConsensusRound,
) -> Result<FixedValidatorNodeVoteExecutionOutcomeV0<'node>, FixedValidatorNodeVoteExecutionErrorV0>
{
    let finality_maximum_round = scope.finality.replay_limit().max_round();
    let round = match current_round(
        &scope.branch,
        &scope.signing_session,
        inclusive_maximum_round,
        finality_maximum_round,
    ) {
        Ok(round) => round,
        Err(CurrentRoundErrorV0::Rejected(rejection)) => {
            return Ok(rejected(scope, rejection));
        }
        Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
    };
    if let Err(rejection) =
        require_phase(&scope.signing_session, FixedValidatorLockPhaseV0::Prevote)
    {
        drop(round);
        return Ok(rejected(scope, rejection));
    }
    let canonical_artifact_bytes = match load_candidate_backed_proposal_payload(
        &round,
        candidates,
        payloads,
        expected_target,
        canonical_proposal_control_bytes,
    ) {
        Ok(bytes) => bytes,
        Err(rejection) => {
            drop(round);
            return Ok(rejected(scope, rejection));
        }
    };
    let proposal = match round.decode_and_verify_proposal_control(
        canonical_proposal_control_bytes,
        canonical_artifact_bytes,
    ) {
        Ok(proposal) => proposal,
        Err(source) => {
            return Ok(rejected(
                scope,
                FixedValidatorNodeVoteRejectionV0::Proposal(Box::new(source)),
            ));
        }
    };
    let finished = match decide_and_finish_proposal_vote(
        &mut scope.signing_session,
        &round,
        &proposal,
        ProposalVoteKindV0::Precommit { quorum },
    ) {
        Ok(finished) => finished,
        Err(ProposalVoteErrorV0::Rejected(rejection)) => {
            return Ok(rejected(scope, rejection));
        }
        Err(ProposalVoteErrorV0::Fatal(error)) => return Err(error),
    };
    Ok(finished_outcome(scope, finished))
}

fn sign_precommit_for_nil<'node>(
    mut scope: FixedValidatorNodeSigningScopeV0<'node>,
    quorum: PrevoteQuorumInputV0<'_>,
    inclusive_maximum_round: ConsensusRound,
) -> Result<FixedValidatorNodeVoteExecutionOutcomeV0<'node>, FixedValidatorNodeVoteExecutionErrorV0>
{
    let finality_maximum_round = scope.finality.replay_limit().max_round();
    let round = match current_round(
        &scope.branch,
        &scope.signing_session,
        inclusive_maximum_round,
        finality_maximum_round,
    ) {
        Ok(round) => round,
        Err(CurrentRoundErrorV0::Rejected(rejection)) => {
            return Ok(rejected(scope, rejection));
        }
        Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
    };
    if matches!(&quorum, PrevoteQuorumInputV0::ExactSignedVotes(_))
        && let Err(rejection) =
            require_phase(&scope.signing_session, FixedValidatorLockPhaseV0::Prevote)
    {
        drop(round);
        return Ok(rejected(scope, rejection));
    }
    let canonical_prevote_certificate = match quorum {
        PrevoteQuorumInputV0::CanonicalCertificate(bytes) => Cow::Borrowed(bytes),
        PrevoteQuorumInputV0::ExactSignedVotes(canonical_signed_prevotes) => {
            let certificate = match round.build_quorum_certificate_from_signed_votes(
                canonical_signed_prevotes,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Nil,
            ) {
                Ok(certificate) => certificate,
                Err(source) => {
                    return Ok(rejected(
                        scope,
                        FixedValidatorNodeVoteRejectionV0::QuorumConstruction(Box::new(source)),
                    ));
                }
            };
            Cow::Owned(certificate.to_canonical_bytes())
        }
    };
    let effect = match scope
        .signing_session
        .decide_precommit_for_nil_quorum(&round, canonical_prevote_certificate.as_ref())
    {
        Ok(effect) => effect,
        Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
            return Ok(rejected(
                scope,
                FixedValidatorNodeVoteRejectionV0::Decision(Box::new(source)),
            ));
        }
        Err(source) => {
            return Err(FixedValidatorNodeVoteExecutionErrorV0::Session(Box::new(
                source,
            )));
        }
    };
    let finished = finish_vote(&mut scope.signing_session, &round, effect)?;
    Ok(finished_outcome(scope, finished))
}

fn require_phase(
    signing_session: &FixedValidatorNodeVotingSessionV0<'_>,
    expected: FixedValidatorLockPhaseV0,
) -> Result<(), FixedValidatorNodeVoteRejectionV0> {
    let actual = signing_session.phase();
    if actual != expected {
        return Err(FixedValidatorNodeVoteRejectionV0::Decision(Box::new(
            FixedValidatorLockStateError::UnexpectedPhase { expected, actual },
        )));
    }
    Ok(())
}

fn load_candidate_backed_proposal_payload(
    round: &FixedConsensusRoundV0<'_>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_proposal_control_bytes: &[u8],
) -> Result<Vec<u8>, FixedValidatorNodeVoteRejectionV0> {
    load_candidate_backed_proposal_payload_source(
        round,
        candidates,
        payloads,
        expected_target,
        canonical_proposal_control_bytes,
    )
    .map_err(candidate_backed_proposal_rejection)
}

fn candidate_backed_proposal_rejection(
    source: CandidateBackedProposalSourceErrorV0,
) -> FixedValidatorNodeVoteRejectionV0 {
    match source {
        CandidateBackedProposalSourceErrorV0::Proposal(source) => {
            FixedValidatorNodeVoteRejectionV0::Proposal(source)
        }
        CandidateBackedProposalSourceErrorV0::CandidateChainMismatch { expected, actual } => {
            FixedValidatorNodeVoteRejectionV0::CandidateChainMismatch { expected, actual }
        }
        CandidateBackedProposalSourceErrorV0::CandidateStore(source) => {
            FixedValidatorNodeVoteRejectionV0::CandidateStore(source)
        }
        CandidateBackedProposalSourceErrorV0::CandidateUnavailable { target } => {
            FixedValidatorNodeVoteRejectionV0::CandidateUnavailable { target }
        }
        CandidateBackedProposalSourceErrorV0::ProposalTargetMismatch { expected, actual } => {
            FixedValidatorNodeVoteRejectionV0::ProposalTargetMismatch { expected, actual }
        }
        CandidateBackedProposalSourceErrorV0::CandidateBlockMismatch { target } => {
            FixedValidatorNodeVoteRejectionV0::CandidateBlockMismatch { target }
        }
        CandidateBackedProposalSourceErrorV0::PayloadStore(source) => {
            FixedValidatorNodeVoteRejectionV0::PayloadStore(source)
        }
        CandidateBackedProposalSourceErrorV0::PayloadUnavailable { target } => {
            FixedValidatorNodeVoteRejectionV0::PayloadUnavailable { target }
        }
    }
}

fn decide_and_finish_proposal_vote(
    signing_session: &mut FixedValidatorNodeVotingSessionV0<'_>,
    round: &FixedConsensusRoundV0<'_>,
    proposal: &VerifiedFixedConsensusProposalV0<'_, '_>,
    kind: ProposalVoteKindV0<'_>,
) -> Result<FinishedVoteV0, ProposalVoteErrorV0> {
    let decision = match kind {
        ProposalVoteKindV0::Prevote => signing_session.decide_prevote_for_proposal(proposal),
        ProposalVoteKindV0::Precommit { quorum } => {
            if let Err(rejection) =
                require_phase(signing_session, FixedValidatorLockPhaseV0::Prevote)
            {
                return Err(ProposalVoteErrorV0::Rejected(rejection));
            }
            let canonical_prevote_certificate = match quorum {
                PrevoteQuorumInputV0::CanonicalCertificate(bytes) => Cow::Borrowed(bytes),
                PrevoteQuorumInputV0::ExactSignedVotes(canonical_signed_prevotes) => {
                    let certificate = round
                        .build_quorum_certificate_from_signed_votes(
                            canonical_signed_prevotes,
                            ConsensusVoteRole::Prevote,
                            ConsensusVoteTarget::Proposal(proposal.proposal_signing_root()),
                        )
                        .map_err(|source| {
                            ProposalVoteErrorV0::Rejected(
                                FixedValidatorNodeVoteRejectionV0::QuorumConstruction(Box::new(
                                    source,
                                )),
                            )
                        })?;
                    Cow::Owned(certificate.to_canonical_bytes())
                }
            };
            signing_session.decide_precommit_for_proposal_quorum(
                round,
                proposal,
                canonical_prevote_certificate.as_ref(),
            )
        }
    };
    let effect = match decision {
        Ok(effect) => effect,
        Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
            return Err(ProposalVoteErrorV0::Rejected(
                FixedValidatorNodeVoteRejectionV0::Decision(Box::new(source)),
            ));
        }
        Err(source) => {
            return Err(ProposalVoteErrorV0::Fatal(
                FixedValidatorNodeVoteExecutionErrorV0::Session(Box::new(source)),
            ));
        }
    };
    finish_vote(signing_session, round, effect).map_err(ProposalVoteErrorV0::Fatal)
}

fn admit_phase_close_identity(
    round: &FixedConsensusRoundV0<'_>,
    required_phase: FixedValidatorLockPhaseV0,
    event_context: ConsensusContextV0,
    event_position: ConsensusPosition,
) -> Result<(), FixedValidatorNodeVoteRejectionV0> {
    let current_context = round.context();
    if event_context != current_context {
        return Err(
            FixedValidatorNodeVoteRejectionV0::PhaseCloseContextMismatch {
                required_phase,
                current: Box::new(current_context),
                event: Box::new(event_context),
            },
        );
    }
    let current_position = round.position();
    if event_position != current_position {
        return Err(
            FixedValidatorNodeVoteRejectionV0::PhaseClosePositionMismatch {
                required_phase,
                current: current_position,
                event: event_position,
            },
        );
    }
    Ok(())
}

fn current_round<'branch>(
    branch: &'branch FixedConsensusBranchV0,
    signing_session: &FixedValidatorNodeVotingSessionV0<'_>,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: u64,
) -> Result<FixedConsensusRoundV0<'branch>, CurrentRoundErrorV0> {
    fixed_validator_node_current_round(
        branch,
        signing_session,
        inclusive_maximum_round,
        finality_maximum_round,
    )
    .map_err(|error| match error {
        FixedValidatorNodeCurrentRoundErrorV0::SignerBranchHeightMismatch {
            signer,
            branch_next_height,
        } => CurrentRoundErrorV0::Fatal(
            FixedValidatorNodeVoteExecutionErrorV0::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            },
        ),
        FixedValidatorNodeCurrentRoundErrorV0::Round(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeVoteExecutionErrorV0::Round(source))
        }
        FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Fatal(
                FixedValidatorNodeVoteExecutionErrorV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Rejected(
                FixedValidatorNodeVoteRejectionV0::RoundWorkLimitExceeded { required, maximum },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::Session(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeVoteExecutionErrorV0::Session(source))
        }
    })
}

fn rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeVoteRejectionV0,
) -> FixedValidatorNodeVoteExecutionOutcomeV0<'node> {
    FixedValidatorNodeVoteExecutionOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}

fn finish_vote(
    signing_session: &mut FixedValidatorNodeVotingSessionV0<'_>,
    round: &FixedConsensusRoundV0<'_>,
    effect: FixedValidatorUnsignedVoteEffectV0,
) -> Result<FinishedVoteV0, FixedValidatorNodeVoteExecutionErrorV0> {
    let preparation = signing_session
        .prepare_vote(round, effect)
        .map_err(|source| FixedValidatorNodeVoteExecutionErrorV0::Prepare(Box::new(source)))?;
    let vote = match preparation {
        FixedValidatorVotePrepareOutcomeV0::Prepared(prepared)
        | FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(prepared) => {
            let acknowledgement = signing_session
                .acknowledge_prepared_vote(prepared)
                .map_err(|source| {
                    FixedValidatorNodeVoteExecutionErrorV0::Acknowledge(Box::new(source))
                })?;
            signing_session
                .sign_prepared_vote(acknowledgement)
                .map_err(|source| FixedValidatorNodeVoteExecutionErrorV0::Sign(Box::new(source)))?
        }
        FixedValidatorVotePrepareOutcomeV0::AlreadySigned(vote) => vote,
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => {
            return Ok(FinishedVoteV0::SignerStopped(halt));
        }
    };
    Ok(FinishedVoteV0::Signed(vote))
}

fn finished_outcome<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    finished: FinishedVoteV0,
) -> FixedValidatorNodeVoteExecutionOutcomeV0<'node> {
    match finished {
        FinishedVoteV0::Signed(vote) => FixedValidatorNodeVoteExecutionOutcomeV0::Signed {
            scope: Box::new(scope),
            vote,
        },
        FinishedVoteV0::SignerStopped(halt) => {
            FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(halt)
        }
    }
}
