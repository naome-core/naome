use std::error::Error;
use std::fmt;

use naome_consensus::{
    ConsensusHeight, ConsensusPosition, ConsensusRound, FixedConsensusBranchV0,
    FixedConsensusRoundV0, FixedValidatorProposalIntentErrorV0, FixedValidatorProposalSourceV0,
    ProposerSelectionError,
};
use naome_storage::{
    FixedValidatorProposalPrepareOutcomeV0, FixedValidatorProposalSafetyHaltV0,
    FixedValidatorSignedProposalV0, FixedValidatorVoteSafetyJournalErrorV0,
};

use super::{
    FixedValidatorNodeCurrentRoundErrorV0, FixedValidatorNodeSigningScopeV0,
    FixedValidatorNodeVotingSessionV0, fixed_validator_node_current_round,
};

/// Complete result of one node-owned current-round proposal-authoring attempt.
///
/// An authored result returns continued node authority only after the exact
/// intent, independent anchor, producer signature, completion, and updated
/// anchor are all durable. A rejection returns the unchanged scope because no
/// journal write occurred. A same-slot conflicting intent returns no scope.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalAuthoringOutcomeV0<'node> {
    /// One exact current-round proposal completed durably and may be released.
    Authored {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        proposal: FixedValidatorSignedProposalV0,
    },
    /// Explicit input was rejected before any durable signer effect.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeProposalAuthoringRejectionV0>,
    },
    /// A non-identical intent at the same proposal slot durably stopped the signer.
    SignerStopped(FixedValidatorProposalSafetyHaltV0),
}

/// A pre-effect proposal-authoring rejection that preserves the signing scope.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalAuthoringRejectionV0 {
    /// Reconstructing the signer's current round would exceed local work policy.
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The current phase, proposer, source, artifact, or retained value was invalid.
    Proposal(Box<FixedValidatorProposalIntentErrorV0>),
}

impl fmt::Display for FixedValidatorNodeProposalAuthoringRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds local proposal-authoring ceiling {maximum:?}"
            ),
            Self::Proposal(source) => {
                write!(
                    formatter,
                    "current node proposal intent was rejected: {source}"
                )
            }
        }
    }
}

impl Error for FixedValidatorNodeProposalAuthoringRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Proposal(source) => Some(source.as_ref()),
            Self::RoundWorkLimitExceeded { .. } => None,
        }
    }
}

/// A fatal node or signer error during current-round proposal authoring.
///
/// Every variant consumes the signing scope and grants no proposal bytes.
/// Strict restart is the only classifier after an ambiguous durable step.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalAuthoringErrorV0 {
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
    /// The signing session was not operational before proposal admission.
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// The exact proposal intent could not be durably prepared.
    Prepare(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// The anchored preparation could not issue exact key-use authority.
    Acknowledge(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// Key use, self-verification, completion, or completion anchoring failed.
    Sign(Box<FixedValidatorVoteSafetyJournalErrorV0>),
}

impl fmt::Display for FixedValidatorNodeProposalAuthoringErrorV0 {
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
                "current node proposal round could not be reconstructed: {source}"
            ),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds node finality ceiling {maximum:?}"
            ),
            Self::Session(source) => {
                write!(
                    formatter,
                    "node proposal session is not operational: {source}"
                )
            }
            Self::Prepare(source) => {
                write!(formatter, "node proposal preparation failed: {source}")
            }
            Self::Acknowledge(source) => write!(
                formatter,
                "node proposal preparation acknowledgement failed: {source}"
            ),
            Self::Sign(source) => write!(formatter, "node proposal signing failed: {source}"),
        }
    }
}

impl Error for FixedValidatorNodeProposalAuthoringErrorV0 {
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
    Rejected(FixedValidatorNodeProposalAuthoringRejectionV0),
    Fatal(FixedValidatorNodeProposalAuthoringErrorV0),
}

impl<'node> FixedValidatorNodeSigningScopeV0<'node> {
    /// Validates, durably prepares, signs, and completes one current-round proposal.
    ///
    /// The private signer state decides whether the caller must supply a fresh
    /// artifact candidate or the exact retained valid value. The node derives
    /// its scheduled proposer and current round, fully verifies the selected
    /// source, and releases proposal-control bytes only after durable completion.
    pub fn author_proposal(
        mut self,
        source: FixedValidatorProposalSourceV0,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeProposalAuthoringErrorV0,
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

        let preparation = match self.signing_session.prepare_proposal(&round, source) {
            Ok(preparation) => preparation,
            Err(FixedValidatorVoteSafetyJournalErrorV0::ProposalPreparation(source)) => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(Box::new(source)),
                ));
            }
            Err(source) => {
                return Err(FixedValidatorNodeProposalAuthoringErrorV0::Prepare(
                    Box::new(source),
                ));
            }
        };

        let proposal = match preparation {
            FixedValidatorProposalPrepareOutcomeV0::Prepared(prepared)
            | FixedValidatorProposalPrepareOutcomeV0::AlreadyPrepared(prepared) => {
                let acknowledgement = self
                    .signing_session
                    .acknowledge_prepared_proposal(prepared)
                    .map_err(|source| {
                        FixedValidatorNodeProposalAuthoringErrorV0::Acknowledge(Box::new(source))
                    })?;
                self.signing_session
                    .sign_prepared_proposal(acknowledgement)
                    .map_err(|source| {
                        FixedValidatorNodeProposalAuthoringErrorV0::Sign(Box::new(source))
                    })?
            }
            FixedValidatorProposalPrepareOutcomeV0::AlreadySigned(proposal) => proposal,
            FixedValidatorProposalPrepareOutcomeV0::Halted(halt) => {
                return Ok(FixedValidatorNodeProposalAuthoringOutcomeV0::SignerStopped(
                    halt,
                ));
            }
        };

        Ok(FixedValidatorNodeProposalAuthoringOutcomeV0::Authored {
            scope: Box::new(self),
            proposal,
        })
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
            FixedValidatorNodeProposalAuthoringErrorV0::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            },
        ),
        FixedValidatorNodeCurrentRoundErrorV0::Round(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeProposalAuthoringErrorV0::Round(source))
        }
        FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Fatal(
                FixedValidatorNodeProposalAuthoringErrorV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Rejected(
                FixedValidatorNodeProposalAuthoringRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::Session(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeProposalAuthoringErrorV0::Session(source))
        }
    })
}

fn rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeProposalAuthoringRejectionV0,
) -> FixedValidatorNodeProposalAuthoringOutcomeV0<'node> {
    FixedValidatorNodeProposalAuthoringOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}
