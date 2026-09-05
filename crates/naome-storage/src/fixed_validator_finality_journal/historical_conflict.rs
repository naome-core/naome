//! Complete supplied proofs for the existing selected-sibling terminal rule.

use super::*;

/// A complete historical proof was rejected or its terminal persistence failed.
///
/// Preliminary height and distinctness checks grant no authentication. Only
/// complete verification against the journal's retained selected parent may
/// reach the existing conflict append. Pre-append errors preserve the journal;
/// persistence errors retain its poison-and-strict-reopen contract.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorHistoricalFinalityConflictErrorV0 {
    /// The finality journal is unavailable or terminal persistence failed.
    FinalityJournal(FixedValidatorFinalityJournalErrorV0),
    /// The operation ceiling exceeds the journal's persisted replay ceiling.
    RoundWorkLimitExceedsJournal { requested: u64, journal: u64 },
    /// The explicit batch round exceeds the operation ceiling.
    EvidenceRoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The proof does not address an already selected positive height.
    SelectedHeightUnavailable { height: ConsensusHeight },
    /// The preliminary value equals the selected value; it is not a sibling.
    SelectedValueNotDistinct { height: ConsensusHeight },
    /// Exact bounded historical round reconstruction failed.
    Round(ProposerSelectionError),
    /// Complete envelope or payload verification failed.
    Envelope(FixedConsensusBoundedEnvelopeVerifyError),
    /// Complete proposal-control or payload verification failed.
    Proposal(ConsensusProposalVerifyError),
    /// The exact signed-precommit batch failed complete verification.
    PrecommitBatch(FixedConsensusPrecommitBatchSealErrorV0),
    /// An unreachable replay outcome violated the distinct-sibling preflight.
    UnexpectedSelectedValueReplay { height: ConsensusHeight },
    /// An unreachable new-height outcome violated the historical preflight.
    UnexpectedNewFinality { height: ConsensusHeight },
}

impl fmt::Display for FixedValidatorHistoricalFinalityConflictErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinalityJournal(source) => source.fmt(formatter),
            Self::RoundWorkLimitExceedsJournal { requested, journal } => write!(
                formatter,
                "historical conflict work ceiling {requested} exceeds journal replay ceiling {journal}"
            ),
            Self::EvidenceRoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "historical conflict evidence round {required:?} exceeds caller-local ceiling {maximum:?}"
            ),
            Self::SelectedHeightUnavailable { height } => write!(
                formatter,
                "historical conflict requires an already selected height, but height {} is unavailable",
                height.value()
            ),
            Self::SelectedValueNotDistinct { height } => write!(
                formatter,
                "historical conflict input at height {} names the selected value",
                height.value()
            ),
            Self::Round(source) => source.fmt(formatter),
            Self::Envelope(source) => source.fmt(formatter),
            Self::Proposal(source) => source.fmt(formatter),
            Self::PrecommitBatch(source) => source.fmt(formatter),
            Self::UnexpectedSelectedValueReplay { height } => write!(
                formatter,
                "historical conflict unexpectedly replayed selected height {}",
                height.value()
            ),
            Self::UnexpectedNewFinality { height } => write!(
                formatter,
                "historical conflict unexpectedly finalized new height {}",
                height.value()
            ),
        }
    }
}

impl Error for FixedValidatorHistoricalFinalityConflictErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FinalityJournal(source) => Some(source),
            Self::Round(source) => Some(source),
            Self::Envelope(source) => Some(source),
            Self::Proposal(source) => Some(source),
            Self::PrecommitBatch(source) => Some(source),
            _ => None,
        }
    }
}

type ConflictError = FixedValidatorHistoricalFinalityConflictErrorV0;

pub(super) enum HistoricalFinalityProofV0<'input> {
    Envelope(&'input [u8]),
    VoteBatch {
        proposal: &'input [u8],
        precommits: &'input [&'input [u8]],
        evidence_round: ConsensusRound,
    },
}

impl FixedValidatorAnchoredFinalityJournalV0 {
    /// Verifies a complete supplied finalized sibling and anchors its halt.
    ///
    /// Height and target come only from the bounded envelope value. The height
    /// must already be selected and the value must differ from its retained
    /// selected value before complete verification against that exact parent.
    /// Success grants no new selection, operable branch, winner, or rollback.
    pub fn commit_historical_finality_conflict(
        &mut self,
        canonical_envelope_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<FixedValidatorFinalityHaltV0, FixedValidatorHistoricalFinalityConflictErrorV0> {
        self.journal.core.commit_historical_finality_conflict(
            HistoricalFinalityProofV0::Envelope(canonical_envelope_bytes),
            canonical_artifact_bytes,
            inclusive_maximum_round,
        )
    }

    /// Verifies a supplied historical proposal, payload, and exact precommit batch.
    ///
    /// The explicit evidence round is bounded before any sequential proposer
    /// work. Every proposal and vote is independently verified against the exact
    /// retained selected parent before the same anchored sibling halt as the
    /// complete-envelope method. No source store or caller parent is accepted.
    pub fn commit_historical_finality_conflict_vote_batch(
        &mut self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<FixedValidatorFinalityHaltV0, FixedValidatorHistoricalFinalityConflictErrorV0> {
        self.journal.core.commit_historical_finality_conflict(
            HistoricalFinalityProofV0::VoteBatch {
                proposal: canonical_proposal_control_bytes,
                precommits: canonical_signed_precommits,
                evidence_round,
            },
            canonical_artifact_bytes,
            inclusive_maximum_round,
        )
    }
}

impl<F: StoreIo> FixedValidatorFinalityJournalCore<F> {
    pub(super) fn commit_historical_finality_conflict(
        &mut self,
        proof: HistoricalFinalityProofV0<'_>,
        canonical_artifact_bytes: Vec<u8>,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<FixedValidatorFinalityHaltV0, ConflictError> {
        self.ensure_operational()
            .map_err(ConflictError::FinalityJournal)?;
        if inclusive_maximum_round.value() > self.replay_limit.max_round() {
            return Err(ConflictError::RoundWorkLimitExceedsJournal {
                requested: inclusive_maximum_round.value(),
                journal: self.replay_limit.max_round(),
            });
        }
        let value = match proof {
            HistoricalFinalityProofV0::Envelope(bytes) => {
                proof_routing::decode_finality_envelope_value(self.context, bytes)
                    .map_err(ConflictError::Envelope)?
            }
            HistoricalFinalityProofV0::VoteBatch {
                proposal,
                evidence_round,
                ..
            } => {
                if evidence_round > inclusive_maximum_round {
                    return Err(ConflictError::EvidenceRoundWorkLimitExceeded {
                        required: evidence_round,
                        maximum: inclusive_maximum_round,
                    });
                }
                proof_routing::decode_finality_proposal_value(self.context, proposal)
                    .map_err(ConflictError::Proposal)?
            }
        };
        let parent = proof_routing::selected_sibling_parent(self, value).map_err(|error| {
            use proof_routing::SelectedSiblingParentErrorV0 as ParentError;
            match error {
                ParentError::FinalityJournal(source) => ConflictError::FinalityJournal(source),
                ParentError::SelectedHeightUnavailable { height } => {
                    ConflictError::SelectedHeightUnavailable { height }
                }
                ParentError::SelectedValueNotDistinct { height } => {
                    ConflictError::SelectedValueNotDistinct { height }
                }
            }
        })?;
        let transition = match proof {
            HistoricalFinalityProofV0::Envelope(bytes) => parent
                .decode_and_verify_envelope_with_round_limit(
                    bytes,
                    canonical_artifact_bytes,
                    inclusive_maximum_round,
                )
                .map_err(ConflictError::Envelope)?,
            HistoricalFinalityProofV0::VoteBatch {
                proposal,
                precommits,
                evidence_round,
            } => {
                let mut round = parent.begin_round_zero().map_err(ConflictError::Round)?;
                for _ in 0..evidence_round.value() {
                    round = round.advance_round().map_err(ConflictError::Round)?;
                }
                round
                    .decode_and_verify_proposal_control(proposal, canonical_artifact_bytes)
                    .map_err(ConflictError::Proposal)?
                    .seal_with_precommit_vote_batch(precommits)
                    .map(VerifiedFixedConsensusTransitionV0::into_owned)
                    .map_err(ConflictError::PrecommitBatch)?
            }
        };
        match self
            .commit_verified(transition)
            .map_err(ConflictError::FinalityJournal)?
        {
            FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => Ok(halt),
            FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { height, .. } => {
                Err(ConflictError::UnexpectedSelectedValueReplay { height })
            }
            FixedValidatorFinalityCommitOutcomeV0::Finalized { position, .. } => {
                Err(ConflictError::UnexpectedNewFinality {
                    height: position.height(),
                })
            }
        }
    }
}
