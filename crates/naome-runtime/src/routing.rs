//! Descriptive routing and two independently verified current-proposal copies.

use std::{collections::TryReserveError, error::Error, fmt};

use naome_consensus::{
    ConsensusContextV0, ConsensusPosition, ConsensusProposalVerifyError, ConsensusVoteDecodeError,
    ConsensusVoteRole, ConsensusVoteTarget, UnverifiedConsensusVoteRouteV0,
    UnverifiedFixedConsensusProposalRouteV0,
};
use naome_network::{ConsensusPushMessage, ConsensusPushSize, PeerId};
use naome_node::{
    FixedValidatorNodeDriverAdmissionDispositionV0, FixedValidatorNodeDriverAdmissionRejectionV0,
    FixedValidatorNodeDriverEventV0,
};

#[derive(Clone, Copy)]
pub(crate) enum MessageRef<'a> {
    Proposal {
        control: &'a [u8],
        artifact: &'a [u8],
    },
    Vote(&'a [u8]),
}

impl<'a> From<&'a ConsensusPushMessage> for MessageRef<'a> {
    fn from(message: &'a ConsensusPushMessage) -> Self {
        match message {
            ConsensusPushMessage::Proposal {
                canonical_proposal,
                canonical_artifact,
            } => Self::Proposal {
                control: canonical_proposal,
                artifact: canonical_artifact,
            },
            ConsensusPushMessage::Vote { canonical_vote } => Self::Vote(canonical_vote),
        }
    }
}

impl MessageRef<'_> {
    pub(crate) fn size(self) -> ConsensusPushSize {
        match self {
            Self::Proposal { control, artifact } => ConsensusPushSize::Proposal {
                control_bytes: control.len(),
                payload_bytes: artifact.len(),
            },
            Self::Vote(vote) => ConsensusPushSize::Vote { bytes: vote.len() },
        }
    }

    pub(crate) fn copy_message(self) -> Result<ConsensusPushMessage, TryReserveError> {
        Ok(match self {
            Self::Proposal { control, artifact } => ConsensusPushMessage::Proposal {
                canonical_proposal: copy_bytes(control)?,
                canonical_artifact: copy_bytes(artifact)?,
            },
            Self::Vote(vote) => ConsensusPushMessage::Vote {
                canonical_vote: copy_bytes(vote)?,
            },
        })
    }

    // Two inline contexts are bounded diagnostics; rejecting an untrusted header
    // need not allocate another error wrapper before reserving admission copies.
    #[allow(clippy::result_large_err)]
    pub(crate) fn prepare(
        self,
        context: ConsensusContextV0,
        position: ConsensusPosition,
    ) -> Result<PreparedAdmission, FixedValidatorRuntimeRoutingErrorV0> {
        let (actual_context, actual_position) = match self {
            Self::Proposal { control, .. } => {
                let route =
                    UnverifiedFixedConsensusProposalRouteV0::inspect(control).map_err(|error| {
                        FixedValidatorRuntimeRoutingErrorV0::Proposal(Box::new(error))
                    })?;
                (route.context(), route.position())
            }
            Self::Vote(bytes) => {
                let route = UnverifiedConsensusVoteRouteV0::inspect(bytes)
                    .map_err(FixedValidatorRuntimeRoutingErrorV0::Vote)?;
                (route.context(), route.position())
            }
        };
        if actual_context != context {
            return Err(FixedValidatorRuntimeRoutingErrorV0::OtherContext {
                observed: actual_context,
                expected: context,
            });
        }
        if actual_position.height() != position.height()
            || actual_position.round() < position.round()
        {
            return Err(FixedValidatorRuntimeRoutingErrorV0::UnsupportedPosition {
                observed: actual_position,
                current: position,
            });
        }
        let higher = actual_position.round() > position.round();
        let mut events = [None, None];
        let mut routes = [None, None];
        match self {
            Self::Proposal { control, artifact } if higher => {
                events[0] = Some(FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                    proposal_round: actual_position.round(),
                    canonical_proposal_control_bytes: copy_box(control)?,
                    canonical_artifact_bytes: copy_box(artifact)?,
                });
                routes[0] = Some(FixedValidatorRuntimeRouteV0::HigherProposal);
            }
            Self::Proposal { control, artifact } => {
                // Both copies are reserved before either full admission starts.
                events[0] = Some(
                    FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                        canonical_proposal_control_bytes: copy_box(control)?,
                        canonical_artifact_bytes: copy_box(artifact)?,
                    },
                );
                events[1] = Some(FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                    canonical_proposal_control_bytes: copy_box(control)?,
                    canonical_artifact_bytes: copy_box(artifact)?,
                });
                routes = [
                    Some(FixedValidatorRuntimeRouteV0::CurrentFinalityProposal),
                    Some(FixedValidatorRuntimeRouteV0::CurrentVotingProposal),
                ];
            }
            Self::Vote(bytes) => {
                let route = UnverifiedConsensusVoteRouteV0::inspect(bytes)
                    .map_err(FixedValidatorRuntimeRoutingErrorV0::Vote)?;
                let (event, kind) = match (higher, route.role(), route.target()) {
                    (true, ConsensusVoteRole::Prevote, ConsensusVoteTarget::Proposal(_)) => (
                        FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
                            canonical_signed_prevote: copy_box(bytes)?,
                        },
                        FixedValidatorRuntimeRouteV0::HigherProposalPrevote,
                    ),
                    (true, _, _) => {
                        return Err(FixedValidatorRuntimeRoutingErrorV0::UnsupportedHigherVote {
                            position: actual_position,
                            role: route.role(),
                            target: route.target(),
                        });
                    }
                    (false, ConsensusVoteRole::Prevote, ConsensusVoteTarget::Proposal(_)) => (
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                            canonical_signed_prevote: copy_box(bytes)?,
                        },
                        FixedValidatorRuntimeRouteV0::CurrentProposalPrevote,
                    ),
                    (false, ConsensusVoteRole::Prevote, ConsensusVoteTarget::Nil) => (
                        FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
                            canonical_signed_prevote: copy_box(bytes)?,
                        },
                        FixedValidatorRuntimeRouteV0::CurrentNilPrevote,
                    ),
                    (false, ConsensusVoteRole::Precommit, ConsensusVoteTarget::Proposal(_)) => (
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
                            canonical_signed_precommit: copy_box(bytes)?,
                        },
                        FixedValidatorRuntimeRouteV0::CurrentProposalPrecommit,
                    ),
                    (false, ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil) => (
                        FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit {
                            canonical_signed_precommit: copy_box(bytes)?,
                        },
                        FixedValidatorRuntimeRouteV0::CurrentNilPrecommit,
                    ),
                };
                events[0] = Some(event);
                routes[0] = Some(kind);
            }
        }
        Ok(PreparedAdmission { events, routes })
    }
}

pub(crate) struct PreparedAdmission {
    pub(crate) events: [Option<FixedValidatorNodeDriverEventV0>; 2],
    pub(crate) routes: [Option<FixedValidatorRuntimeRouteV0>; 2],
}

pub(crate) fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, TryReserveError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn copy_box(bytes: &[u8]) -> Result<Box<[u8]>, TryReserveError> {
    Ok(copy_bytes(bytes)?.into_boxed_slice())
}

/// Provenance observation only; a Noise peer is not a consensus signer identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedValidatorRuntimeInputSourceV0 {
    LocalPublication,
    Peer(PeerId),
    CallerInput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedValidatorRuntimeRouteV0 {
    CurrentFinalityProposal,
    CurrentVotingProposal,
    CurrentProposalPrevote,
    CurrentNilPrevote,
    CurrentProposalPrecommit,
    CurrentNilPrecommit,
    HigherProposal,
    HigherProposalPrevote,
}

#[derive(Debug)]
pub struct FixedValidatorRuntimeAdmissionResultV0 {
    pub route: FixedValidatorRuntimeRouteV0,
    pub result: Result<
        FixedValidatorNodeDriverAdmissionDispositionV0,
        Box<FixedValidatorNodeDriverAdmissionRejectionV0>,
    >,
}

/// Independent sequential results; success on one route is never rolled back.
///
/// Peer and caller input allocations transfer in `input`, even after partial
/// admission. Authored originals remain in the pending publication. A
/// caller retaining reports must bound that memory separately from this runtime.
#[must_use]
pub struct FixedValidatorRuntimeAdmissionReportV0 {
    pub source: FixedValidatorRuntimeInputSourceV0,
    pub receipt_queued: Option<bool>,
    pub input: Option<ConsensusPushMessage>,
    pub results: [Option<FixedValidatorRuntimeAdmissionResultV0>; 2],
    pub routing_error: Option<FixedValidatorRuntimeRoutingErrorV0>,
    pub(crate) completed: bool,
}

impl FixedValidatorRuntimeAdmissionReportV0 {
    pub fn all_admitted(&self) -> bool {
        self.completed
            && self.results.iter().any(Option::is_some)
            && self.routing_error.is_none()
            && self
                .results
                .iter()
                .flatten()
                .all(|result| result.result.is_ok())
    }

    /// True only when all prepared strict admissions returned normal results.
    pub const fn completed(&self) -> bool {
        self.completed
    }
}

/// A routing hint or bounded copy failed; none of these imply verified validity.
#[derive(Debug)]
pub enum FixedValidatorRuntimeRoutingErrorV0 {
    Proposal(Box<ConsensusProposalVerifyError>),
    Vote(ConsensusVoteDecodeError),
    OtherContext {
        observed: ConsensusContextV0,
        expected: ConsensusContextV0,
    },
    UnsupportedPosition {
        observed: ConsensusPosition,
        current: ConsensusPosition,
    },
    UnsupportedHigherVote {
        position: ConsensusPosition,
        role: ConsensusVoteRole,
        target: ConsensusVoteTarget,
    },
    Reservation(TryReserveError),
}

impl From<TryReserveError> for FixedValidatorRuntimeRoutingErrorV0 {
    fn from(error: TryReserveError) -> Self {
        Self::Reservation(error)
    }
}

impl fmt::Display for FixedValidatorRuntimeRoutingErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixed-validator runtime routing rejected: {self:?}")
    }
}

impl Error for FixedValidatorRuntimeRoutingErrorV0 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_admission_does_not_report_historical_success_as_complete() {
        let mut report = FixedValidatorRuntimeAdmissionReportV0 {
            source: FixedValidatorRuntimeInputSourceV0::LocalPublication,
            receipt_queued: None,
            input: None,
            results: [None, None],
            routing_error: None,
            completed: false,
        };
        assert!(!report.completed());
        assert!(!report.all_admitted());
        report.results[0] = Some(FixedValidatorRuntimeAdmissionResultV0 {
            route: FixedValidatorRuntimeRouteV0::CurrentFinalityProposal,
            result: Ok(FixedValidatorNodeDriverAdmissionDispositionV0::Inserted),
        });
        assert!(!report.completed());
        assert!(!report.all_admitted());
    }
}
