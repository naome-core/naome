use std::error::Error;
use std::fmt;

use naome_consensus::{
    ConsensusContextV0, ConsensusHeight, ConsensusPosition, ConsensusRound, FixedConsensusBranchV0,
    FixedConsensusRoundV0, FixedValidatorLockPhaseV0, FixedValidatorLockStateError,
    ProposerSelectionError,
};
use naome_storage::FixedValidatorVoteSafetyJournalErrorV0;

use super::{
    FixedValidatorNodeCurrentRoundErrorV0, FixedValidatorNodeSigningScopeV0,
    FixedValidatorNodeVotingSessionV0, fixed_validator_node_current_round,
};

/// Complete result of one node-owned explicit-event or quorum-driven progression.
///
/// A successful result returns continued node authority only after the exact
/// destination is established. Explicit-close and current-round nil-precommit
/// progression remain volatile; higher-round progression returns only after its
/// checkpoint and independent anchor are durable and the same live session
/// acknowledges it. A rejection returns the unchanged scope because no volatile
/// or durable state changed.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeRoundAdvanceOutcomeV0<'node> {
    /// The signer reached the exact admitted destination.
    Advanced {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        position: ConsensusPosition,
        phase: FixedValidatorLockPhaseV0,
    },
    /// Explicit input or caller-local capacity was rejected before mutation.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeRoundAdvanceRejectionV0>,
    },
}

/// A pre-effect round-progression rejection that preserves the signing scope.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeRoundAdvanceRejectionV0 {
    /// The caller-routed close event belongs to another consensus context.
    PrecommitCloseContextMismatch {
        current: Box<ConsensusContextV0>,
        event: Box<ConsensusContextV0>,
    },
    /// The caller-routed close event belongs to another height or round.
    PrecommitClosePositionMismatch {
        current: ConsensusPosition,
        event: ConsensusPosition,
    },
    /// The caller-routed close event does not match the current local phase.
    PrecommitClosePhaseMismatch {
        required: FixedValidatorLockPhaseV0,
        actual: FixedValidatorLockPhaseV0,
    },
    /// The required destination exceeds the persisted node finality ceiling.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The required destination exceeds the caller's inclusive work ceiling.
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The exact quorum evidence was not admissible for this transition.
    Quorum(Box<FixedValidatorLockStateError>),
}

impl fmt::Display for FixedValidatorNodeRoundAdvanceRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrecommitCloseContextMismatch { current, event } => write!(
                formatter,
                "precommit close context {event:?} differs from current node context {current:?}"
            ),
            Self::PrecommitClosePositionMismatch { current, event } => write!(
                formatter,
                "precommit close position {event:?} differs from current signer position {current:?}"
            ),
            Self::PrecommitClosePhaseMismatch { required, actual } => write!(
                formatter,
                "precommit close requires phase {required:?}, current phase is {actual:?}"
            ),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "round progression requires {required:?}, above node finality ceiling {maximum:?}"
            ),
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "round progression requires {required:?}, above caller-local ceiling {maximum:?}"
            ),
            Self::Quorum(source) => {
                write!(formatter, "round-progression quorum was rejected: {source}")
            }
        }
    }
}

impl Error for FixedValidatorNodeRoundAdvanceRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Quorum(source) => Some(source.as_ref()),
            Self::PrecommitCloseContextMismatch { .. }
            | Self::PrecommitClosePositionMismatch { .. }
            | Self::PrecommitClosePhaseMismatch { .. }
            | Self::FinalityRoundLimitExceeded { .. }
            | Self::RoundWorkLimitExceeded { .. } => None,
        }
    }
}

/// A fatal node or signer error during node-owned round progression.
///
/// Every variant consumes the signing scope. Strict restart is the only
/// classifier after a checkpoint, journal, anchor, or acknowledgement failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeRoundAdvanceErrorV0 {
    /// The node-owned signer and branch do not name the same next height.
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    /// The exact node-owned branch round could not be reconstructed.
    Round(ProposerSelectionError),
    /// The current round has no representable successor.
    RoundExhausted { current: ConsensusRound },
    /// The signer's current round exceeds the node finality journal's ceiling.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The signing session was not operational before input admission.
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// An internal branch, derivation, allocation, or live-state invariant failed.
    Transition(Box<FixedValidatorLockStateError>),
    /// The verified higher-round checkpoint did not complete durable preparation.
    Prepare(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// An anchored higher-round checkpoint could not enter this live session.
    Acknowledge(Box<FixedValidatorVoteSafetyJournalErrorV0>),
}

impl fmt::Display for FixedValidatorNodeRoundAdvanceErrorV0 {
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
                "current node round could not be reconstructed: {source}"
            ),
            Self::RoundExhausted { current } => {
                write!(formatter, "current node round {current:?} has no successor")
            }
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds node finality ceiling {maximum:?}"
            ),
            Self::Session(source) => {
                write!(
                    formatter,
                    "node round-progression session is not operational: {source}"
                )
            }
            Self::Transition(source) => {
                write!(
                    formatter,
                    "node round-progression invariant failed: {source}"
                )
            }
            Self::Prepare(source) => {
                write!(
                    formatter,
                    "higher-round checkpoint preparation failed: {source}"
                )
            }
            Self::Acknowledge(source) => write!(
                formatter,
                "higher-round checkpoint acknowledgement failed: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeRoundAdvanceErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Session(source) | Self::Prepare(source) | Self::Acknowledge(source) => {
                Some(source.as_ref())
            }
            Self::Transition(source) => Some(source.as_ref()),
            Self::SignerBranchHeightMismatch { .. }
            | Self::RoundExhausted { .. }
            | Self::FinalityRoundLimitExceeded { .. } => None,
        }
    }
}

enum CurrentRoundErrorV0 {
    Rejected(FixedValidatorNodeRoundAdvanceRejectionV0),
    Fatal(FixedValidatorNodeRoundAdvanceErrorV0),
}

impl<'node> FixedValidatorNodeSigningScopeV0<'node> {
    /// Explicitly closes one exact Precommit phase and advances to `R + 1`.
    ///
    /// The caller supplies the consensus context and source position attached to
    /// its close event. After session-readiness and bounded current-round
    /// reconstruction, both must match the node-derived round exactly and the
    /// live phase must be Precommit. The destination must fit the persisted node
    /// finality and caller-local ceilings. Success derives the sole sequential
    /// cursor internally, preserves lock and complete valid-value evidence, and
    /// writes no journal or anchor bytes. This operation neither proves nor
    /// infers that a timeout elapsed.
    pub fn advance_round_after_precommit_close(
        mut self,
        event_context: ConsensusContextV0,
        event_position: ConsensusPosition,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<FixedValidatorNodeRoundAdvanceOutcomeV0<'node>, FixedValidatorNodeRoundAdvanceErrorV0>
    {
        let finality_maximum_round = self.finality.replay_limit().max_round();
        let current_round = match current_round(
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
        let current_context = current_round.context();
        if event_context != current_context {
            drop(current_round);
            return Ok(rejected(
                self,
                FixedValidatorNodeRoundAdvanceRejectionV0::PrecommitCloseContextMismatch {
                    current: Box::new(current_context),
                    event: Box::new(event_context),
                },
            ));
        }
        let current_position = current_round.position();
        if event_position != current_position {
            drop(current_round);
            return Ok(rejected(
                self,
                FixedValidatorNodeRoundAdvanceRejectionV0::PrecommitClosePositionMismatch {
                    current: current_position,
                    event: event_position,
                },
            ));
        }
        let phase = self.signing_session.phase();
        if phase != FixedValidatorLockPhaseV0::Precommit {
            drop(current_round);
            return Ok(rejected(
                self,
                FixedValidatorNodeRoundAdvanceRejectionV0::PrecommitClosePhaseMismatch {
                    required: FixedValidatorLockPhaseV0::Precommit,
                    actual: phase,
                },
            ));
        }
        let required = match successor_capacity(
            current_position.round(),
            inclusive_maximum_round,
            ConsensusRound::new(finality_maximum_round),
        ) {
            Ok(required) => required,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                drop(current_round);
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };
        let next_round = current_round.advance_round().map_err(|source| {
            FixedValidatorNodeRoundAdvanceErrorV0::Transition(Box::new(
                FixedValidatorLockStateError::NextRoundDerivation(source),
            ))
        })?;
        match self.signing_session.advance_round(&next_round) {
            Ok(()) => {}
            Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
                return Err(FixedValidatorNodeRoundAdvanceErrorV0::Transition(Box::new(
                    source,
                )));
            }
            Err(source) => {
                return Err(FixedValidatorNodeRoundAdvanceErrorV0::Session(Box::new(
                    source,
                )));
            }
        }
        let position = next_round.position();
        let phase = self.signing_session.phase();
        debug_assert_eq!(position.round(), required);
        debug_assert_eq!(phase, FixedValidatorLockPhaseV0::Proposal);
        drop(next_round);
        Ok(advanced_outcome(self, position, phase))
    }

    /// Advances to `R + 1` after one exact current-round precommit/nil quorum.
    ///
    /// Session readiness, exact current-round reconstruction, and destination
    /// capacity under both the node finality and caller-local ceilings precede
    /// certificate verification. Success preserves lock and valid-value state,
    /// enters Proposal at the exact sequential round, and writes no journal or
    /// anchor bytes. It does not infer a timeout or finalize a value.
    pub fn advance_round_for_nil_precommit_quorum(
        mut self,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<FixedValidatorNodeRoundAdvanceOutcomeV0<'node>, FixedValidatorNodeRoundAdvanceErrorV0>
    {
        let finality_maximum_round = self.finality.replay_limit().max_round();
        let current_round = match current_round(
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
        let required = match successor_capacity(
            current_round.position().round(),
            inclusive_maximum_round,
            ConsensusRound::new(finality_maximum_round),
        ) {
            Ok(required) => required,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                drop(current_round);
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };
        let advanced = match self
            .signing_session
            .advance_round_for_nil_precommit_quorum(&current_round, canonical_certificate)
        {
            Ok(advanced) => advanced,
            Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
                drop(current_round);
                return match classify_nil_lock_error(source) {
                    Ok(rejection) => Ok(rejected(self, rejection)),
                    Err(error) => Err(error),
                };
            }
            Err(source) => {
                return Err(FixedValidatorNodeRoundAdvanceErrorV0::Session(Box::new(
                    source,
                )));
            }
        };
        let position = advanced.position();
        let phase = self.signing_session.phase();
        debug_assert_eq!(position.round(), required);
        debug_assert_eq!(phase, FixedValidatorLockPhaseV0::Proposal);
        drop(advanced);
        drop(current_round);
        Ok(advanced_outcome(self, position, phase))
    }

    /// Advances to the exact authenticated higher-round quorum phase.
    ///
    /// The caller supplies one canonical prevote or precommit quorum and an
    /// inclusive local work ceiling. The exact target must fit both that ceiling
    /// and the persisted node finality ceiling. The method returns continued
    /// scope only after the checkpoint journal and independent anchor are
    /// durable and the same live session has acknowledged the sealed transition.
    pub fn advance_to_higher_round_quorum(
        mut self,
        canonical_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<FixedValidatorNodeRoundAdvanceOutcomeV0<'node>, FixedValidatorNodeRoundAdvanceErrorV0>
    {
        let finality_maximum_round = ConsensusRound::new(self.finality.replay_limit().max_round());
        let current_round = match current_round(
            &self.branch,
            &self.signing_session,
            inclusive_maximum_round,
            finality_maximum_round.value(),
        ) {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };
        match successor_capacity(
            current_round.position().round(),
            inclusive_maximum_round,
            finality_maximum_round,
        ) {
            Ok(_) => {}
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                drop(current_round);
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        }
        let effective_maximum = ConsensusRound::new(
            inclusive_maximum_round
                .value()
                .min(finality_maximum_round.value()),
        );
        let prepared = match self.signing_session.prepare_higher_round_quorum_advance(
            &current_round,
            canonical_certificate,
            effective_maximum,
        ) {
            Ok(prepared) => prepared,
            Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
                drop(current_round);
                return match classify_higher_lock_error(
                    source,
                    inclusive_maximum_round,
                    finality_maximum_round,
                ) {
                    Ok(rejection) => Ok(rejected(self, rejection)),
                    Err(error) => Err(error),
                };
            }
            Err(source) => {
                return Err(FixedValidatorNodeRoundAdvanceErrorV0::Prepare(Box::new(
                    source,
                )));
            }
        };
        let advanced = self
            .signing_session
            .acknowledge_prepared_higher_round(prepared)
            .map_err(|source| {
                FixedValidatorNodeRoundAdvanceErrorV0::Acknowledge(Box::new(source))
            })?;
        let position = advanced.position();
        let phase = self.signing_session.phase();
        drop(advanced);
        drop(current_round);
        Ok(advanced_outcome(self, position, phase))
    }
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
            FixedValidatorNodeRoundAdvanceErrorV0::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            },
        ),
        FixedValidatorNodeCurrentRoundErrorV0::Round(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeRoundAdvanceErrorV0::Round(source))
        }
        FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Fatal(
                FixedValidatorNodeRoundAdvanceErrorV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Rejected(
                FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::Session(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeRoundAdvanceErrorV0::Session(source))
        }
    })
}

fn successor_capacity(
    current: ConsensusRound,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: ConsensusRound,
) -> Result<ConsensusRound, CurrentRoundErrorV0> {
    let required = current
        .value()
        .checked_add(1)
        .map(ConsensusRound::new)
        .ok_or(CurrentRoundErrorV0::Fatal(
            FixedValidatorNodeRoundAdvanceErrorV0::RoundExhausted { current },
        ))?;
    if required > finality_maximum_round {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeRoundAdvanceRejectionV0::FinalityRoundLimitExceeded {
                required,
                maximum: finality_maximum_round,
            },
        ));
    }
    if required > inclusive_maximum_round {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                required,
                maximum: inclusive_maximum_round,
            },
        ));
    }
    Ok(required)
}

fn classify_nil_lock_error(
    source: FixedValidatorLockStateError,
) -> Result<FixedValidatorNodeRoundAdvanceRejectionV0, FixedValidatorNodeRoundAdvanceErrorV0> {
    match source {
        FixedValidatorLockStateError::QuorumVerification(_)
        | FixedValidatorLockStateError::NilPrecommitQuorumRoleMismatch { .. }
        | FixedValidatorLockStateError::NilPrecommitQuorumTargetMismatch { .. } => Ok(
            FixedValidatorNodeRoundAdvanceRejectionV0::Quorum(Box::new(source)),
        ),
        _ => Err(FixedValidatorNodeRoundAdvanceErrorV0::Transition(Box::new(
            source,
        ))),
    }
}

fn classify_higher_lock_error(
    source: FixedValidatorLockStateError,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: ConsensusRound,
) -> Result<FixedValidatorNodeRoundAdvanceRejectionV0, FixedValidatorNodeRoundAdvanceErrorV0> {
    match source {
        FixedValidatorLockStateError::HigherRoundLimitExceeded { round, .. } => {
            if round > finality_maximum_round {
                Ok(
                    FixedValidatorNodeRoundAdvanceRejectionV0::FinalityRoundLimitExceeded {
                        required: round,
                        maximum: finality_maximum_round,
                    },
                )
            } else {
                Ok(
                    FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                        required: round,
                        maximum: inclusive_maximum_round,
                    },
                )
            }
        }
        FixedValidatorLockStateError::HigherRoundCertificatePosition(_)
        | FixedValidatorLockStateError::HigherRoundHeightMismatch { .. }
        | FixedValidatorLockStateError::HigherRoundNotStrictlyGreater { .. }
        | FixedValidatorLockStateError::QuorumVerification(_) => Ok(
            FixedValidatorNodeRoundAdvanceRejectionV0::Quorum(Box::new(source)),
        ),
        _ => Err(FixedValidatorNodeRoundAdvanceErrorV0::Transition(Box::new(
            source,
        ))),
    }
}

fn rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeRoundAdvanceRejectionV0,
) -> FixedValidatorNodeRoundAdvanceOutcomeV0<'node> {
    FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}

fn advanced_outcome<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    position: ConsensusPosition,
    phase: FixedValidatorLockPhaseV0,
) -> FixedValidatorNodeRoundAdvanceOutcomeV0<'node> {
    FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced {
        scope: Box::new(scope),
        position,
        phase,
    }
}
