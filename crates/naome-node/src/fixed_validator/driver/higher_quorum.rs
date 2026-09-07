//! Complete bounded higher-vote snapshots and checkpoint-only execution.

use super::*;

/// Descriptive identity of one authenticated higher-round quorum group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[must_use]
pub struct FixedValidatorNodeDriverHigherQuorumV0 {
    pub position: ConsensusPosition,
    pub role: ConsensusVoteRole,
    pub target: ConsensusVoteTarget,
}

/// Rejection before a higher-round vote changes consensus or signer state.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeDriverHigherVoteRejectionV0 {
    /// Canonical framing, context, or signature verification failed.
    Vote(ConsensusVoteVerifyError),
    /// The authenticated position is not same-height, strictly higher, and bounded.
    Position {
        current: ConsensusPosition,
        event: ConsensusPosition,
        maximum_round: ConsensusRound,
    },
    /// Exact typed-round active proposal-prevote admission failed.
    ProposalPrevote(FixedConsensusProposalPrevoteVerifyErrorV0),
    /// Exact typed-round active nil-prevote admission failed.
    NilPrevote(FixedConsensusNilPrevoteVerifyErrorV0),
    /// Exact typed-round active proposal-precommit admission failed.
    ProposalPrecommit(FixedConsensusProposalPrecommitVerifyErrorV0),
    /// Exact typed-round active nil-precommit admission failed.
    NilPrecommit(FixedConsensusNilPrecommitVerifyErrorV0),
    /// Combined higher-round capacity denied retention, preserving the prefix.
    Saturated {
        saturation: FixedValidatorNodeHigherRoundInboxSaturationV0,
        newly_saturated: bool,
    },
    /// Fallible retention allocation failed without changing custody.
    Reservation(TryReserveError),
}

impl fmt::Display for FixedValidatorNodeDriverHigherVoteRejectionV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vote(e) => e.fmt(f),
            Self::Position {
                current,
                event,
                maximum_round,
            } => write!(
                f,
                "higher vote at {event:?} is outside same-height rounds above {current:?} through {maximum_round:?}"
            ),
            Self::ProposalPrevote(e) => e.fmt(f),
            Self::NilPrevote(e) => e.fmt(f),
            Self::ProposalPrecommit(e) => e.fmt(f),
            Self::NilPrecommit(e) => e.fmt(f),
            Self::Saturated { saturation, .. } => saturation.fmt(f),
            Self::Reservation(e) => e.fmt(f),
        }
    }
}
impl Error for FixedValidatorNodeDriverHigherVoteRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Vote(e) => Some(e),
            Self::ProposalPrevote(e) => Some(e),
            Self::NilPrevote(e) => Some(e),
            Self::ProposalPrecommit(e) => Some(e),
            Self::NilPrecommit(e) => Some(e),
            Self::Reservation(e) => Some(e),
            Self::Position { .. } | Self::Saturated { .. } => None,
        }
    }
}

pub(super) enum HigherQuorumSelection {
    None,
    One {
        certificate: Vec<u8>,
    },
    Ambiguous {
        first: FixedValidatorNodeDriverHigherQuorumV0,
        second: FixedValidatorNodeDriverHigherQuorumV0,
    },
    Reservation(TryReserveError),
    Rejected(QuorumCertificateBuildError),
}

impl<'node> FixedValidatorNodeDriverV0<'node> {
    pub(super) fn admit_higher_vote(
        mut self,
        canonical_signed_vote: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let result = self.retain_higher_vote(&canonical_signed_vote)?;
        Ok(match result {
            Ok(disposition) => FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted {
                driver: Box::new(self),
                disposition,
            },
            Err(rejection) => FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                driver: Box::new(self),
                event: Box::new(FixedValidatorNodeDriverEventV0::HigherRoundVote {
                    canonical_signed_vote,
                }),
                rejection: Box::new(FixedValidatorNodeDriverAdmissionRejectionV0::HigherVote(
                    Box::new(rejection),
                )),
            },
        })
    }

    fn retain_higher_vote(
        &mut self,
        bytes: &[u8],
    ) -> Result<
        Result<
            FixedValidatorNodeDriverAdmissionDispositionV0,
            FixedValidatorNodeDriverHigherVoteRejectionV0,
        >,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        use FixedValidatorNodeDriverHigherVoteRejectionV0 as Rejection;
        let vote = match VerifiedConsensusVoteV0::decode_and_verify(
            bytes,
            self.scope().branch.context(),
        ) {
            Ok(vote) => vote,
            Err(e) => return Ok(Err(Rejection::Vote(e))),
        };
        let current = self.position();
        let position = vote.position();
        let maximum_round = self.inclusive_maximum_round.min(ConsensusRound::new(
            self.scope().finality.replay_limit().max_round(),
        ));
        if position.height() != current.height()
            || position.round() <= current.round()
            || position.round() > maximum_round
        {
            return Ok(Err(Rejection::Position {
                current,
                event: position,
                maximum_round,
            }));
        }
        let scope = self.scope.as_ref().expect("live driver owns scope");
        let round = derive_round(&scope.branch, position.round())
            .map_err(FixedValidatorNodeDriverAdmissionErrorV0::Round)?;
        let verified = match (vote.role(), vote.target()) {
            (ConsensusVoteRole::Prevote, ConsensusVoteTarget::Proposal(_)) => round
                .decode_and_verify_active_proposal_prevote(bytes)
                .map_err(Rejection::ProposalPrevote),
            (ConsensusVoteRole::Prevote, ConsensusVoteTarget::Nil) => round
                .decode_and_verify_active_nil_prevote(bytes)
                .map_err(Rejection::NilPrevote),
            (ConsensusVoteRole::Precommit, ConsensusVoteTarget::Proposal(_)) => round
                .decode_and_verify_active_proposal_precommit(bytes)
                .map_err(Rejection::ProposalPrecommit),
            (ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil) => round
                .decode_and_verify_active_nil_precommit(bytes)
                .map_err(Rejection::NilPrecommit),
        };
        let parent = round.parent_coordinate();
        drop(round);
        let vote = match verified {
            Ok(vote) => vote,
            Err(e) => return Ok(Err(e)),
        };
        Ok(match self.inbox.try_insert_verified_vote(parent, vote) {
            Ok(FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0::Inserted) => {
                Ok(FixedValidatorNodeDriverAdmissionDispositionV0::Inserted)
            }
            Ok(FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0::AlreadyRetained) => {
                Ok(FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained)
            }
            Err(FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Saturated {
                saturation,
                newly_saturated,
            }) => Err(Rejection::Saturated {
                saturation,
                newly_saturated,
            }),
            Err(FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Reservation(e)) => {
                Err(Rejection::Reservation(e))
            }
            Err(FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Admission(_)) => {
                unreachable!("verified retention does not perform admission")
            }
        })
    }

    pub(super) fn select_higher_quorum(
        &self,
    ) -> Result<HigherQuorumSelection, FixedValidatorNodeDriverStepErrorV0> {
        let current = self.position();
        let parent = self.scope().branch.coordinate();
        let mut votes = Vec::new();
        if let Err(e) = votes.try_reserve_exact(self.inbox.votes.len()) {
            return Ok(HigherQuorumSelection::Reservation(e));
        }
        votes.extend(self.inbox.votes.iter().filter(|v| {
            v.parent_coordinate() == parent
                && v.position().height() == current.height()
                && v.position().round() > current.round()
                && v.position().round() <= self.inclusive_maximum_round
        }));
        votes.sort_unstable_by(|a, b| {
            (a.position(), a.role, a.target, a.signer())
                .cmp(&(b.position(), b.role, b.target, b.signer()))
                .then_with(|| a.canonical_bytes().cmp(b.canonical_bytes()))
        });
        if votes.is_empty() {
            return Ok(HigherQuorumSelection::None);
        }
        let mut round = self
            .scope()
            .branch
            .begin_round_zero()
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
        let mut selected = None;
        let mut start = 0;
        let mut refs = Vec::new();
        if let Err(e) = refs.try_reserve_exact(votes.len()) {
            return Ok(HigherQuorumSelection::Reservation(e));
        }
        while start < votes.len() {
            let vote = votes[start];
            let action = FixedValidatorNodeDriverHigherQuorumV0 {
                position: vote.position(),
                role: vote.role,
                target: vote.target,
            };
            while round.position().round() < action.position.round() {
                round = round
                    .advance_round()
                    .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
            }
            let mut end = start;
            refs.clear();
            let mut previous_signer = None;
            while end < votes.len()
                && (votes[end].position(), votes[end].role, votes[end].target)
                    == (action.position, action.role, action.target)
            {
                let vote = votes[end];
                if previous_signer != Some(vote.signer()) {
                    refs.push(vote.canonical_bytes());
                    previous_signer = Some(vote.signer());
                }
                end += 1;
            }
            match round.build_quorum_certificate_from_signed_votes(
                &refs,
                action.role,
                action.target,
            ) {
                Ok(certificate) => {
                    if let Some((first, _)) = selected {
                        return Ok(HigherQuorumSelection::Ambiguous {
                            first,
                            second: action,
                        });
                    }
                    selected = Some((action, certificate.to_canonical_bytes()));
                }
                Err(
                    QuorumCertificateBuildError::EmptyVoteBatch
                    | QuorumCertificateBuildError::InsufficientAgreementWeight { .. },
                ) => {}
                Err(e) => return Ok(HigherQuorumSelection::Rejected(e)),
            }
            start = end;
        }
        Ok(match selected {
            Some((_, certificate)) => HigherQuorumSelection::One { certificate },
            None => HigherQuorumSelection::None,
        })
    }

    pub(super) fn execute_higher_quorum(
        mut self,
        certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let generation = self.next_generation()?;
        let maximum = self.inclusive_maximum_round;
        let scope = self.take_scope();
        match scope.advance_to_higher_round_quorum(&certificate, maximum) {
            Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. }) => {
                self.scope = Some(*scope);
                let timeout = self.install_next_timeout(generation);
                self.pending_command = Some(PendingCommandV0::Arm(timeout));
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(
                        rejection,
                    )),
                })
            }
            Err(e) => Err(FixedValidatorNodeDriverStepErrorV0::RoundAdvance(Box::new(
                e,
            ))),
        }
    }
}
