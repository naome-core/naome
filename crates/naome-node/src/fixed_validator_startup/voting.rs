use std::error::Error;
use std::fmt;

use naome_consensus::{
    ConsensusContextV0, ConsensusHeight, ConsensusPosition, ConsensusProposalVerifyError,
    ConsensusRound, FixedConsensusBranchV0, FixedConsensusRoundV0, FixedValidatorLockPhaseV0,
    FixedValidatorLockStateError, FixedValidatorUnsignedVoteEffectV0, ProposerSelectionError,
};
use naome_storage::{
    FixedValidatorSignedVoteV0, FixedValidatorVotePrepareOutcomeV0, FixedValidatorVoteSafetyHaltV0,
    FixedValidatorVoteSafetyJournalErrorV0,
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
    /// Explicit input was rejected before any volatile or durable signer effect.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeVoteRejectionV0>,
    },
    /// A non-identical intent at the same slot durably stopped this signer.
    SignerStopped(FixedValidatorVoteSafetyHaltV0),
}

/// A pre-effect current-round input rejection that preserves the signing scope.
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
    /// Complete proposal-control and artifact admission failed.
    Proposal(Box<ConsensusProposalVerifyError>),
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
            Self::Proposal(source) => {
                write!(formatter, "current node proposal was rejected: {source}")
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
            Self::Proposal(source) => Some(source.as_ref()),
            Self::Decision(source) => Some(source.as_ref()),
            Self::RoundWorkLimitExceeded { .. }
            | Self::PhaseCloseContextMismatch { .. }
            | Self::PhaseClosePositionMismatch { .. } => None,
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
        let effect = match self.signing_session.decide_prevote_for_proposal(&proposal) {
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
        mut self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_prevote_certificate: &[u8],
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
        let effect = match self.signing_session.decide_precommit_for_proposal_quorum(
            &round,
            &proposal,
            canonical_prevote_certificate,
        ) {
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

    /// Verifies one exact current-round nil prevote quorum and durably signs nil
    /// precommit while preserving the latest valid value.
    pub fn sign_precommit_for_nil_quorum(
        mut self,
        canonical_prevote_certificate: &[u8],
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
        let effect = match self
            .signing_session
            .decide_precommit_for_nil_quorum(&round, canonical_prevote_certificate)
        {
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
