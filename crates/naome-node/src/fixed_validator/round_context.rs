//! Shared checked round derivation; operation policy stays with each caller.

use super::*;

pub(super) enum FixedValidatorNodeCurrentRoundErrorV0 {
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    Round(ProposerSelectionError),
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    CallerRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
}

pub(super) fn fixed_validator_node_current_round<'branch>(
    branch: &'branch FixedConsensusBranchV0,
    signing_session: &FixedValidatorNodeVotingSessionV0<'_>,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: u64,
) -> Result<FixedConsensusRoundV0<'branch>, FixedValidatorNodeCurrentRoundErrorV0> {
    signing_session
        .ensure_current_vote_ready()
        .map_err(|source| FixedValidatorNodeCurrentRoundErrorV0::Session(Box::new(source)))?;
    let signer_position = signing_session.position();
    let mut round = branch
        .begin_round_zero()
        .map_err(FixedValidatorNodeCurrentRoundErrorV0::Round)?;
    if round.position().height() != signer_position.height() {
        return Err(
            FixedValidatorNodeCurrentRoundErrorV0::SignerBranchHeightMismatch {
                signer: signer_position,
                branch_next_height: round.position().height(),
            },
        );
    }
    let finality_maximum_round = ConsensusRound::new(finality_maximum_round);
    if signer_position.round() > finality_maximum_round {
        return Err(
            FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded {
                required: signer_position.round(),
                maximum: finality_maximum_round,
            },
        );
    }
    if signer_position.round() > inclusive_maximum_round {
        return Err(
            FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded {
                required: signer_position.round(),
                maximum: inclusive_maximum_round,
            },
        );
    }
    for _ in 0..signer_position.round().value() {
        round = round
            .advance_round()
            .map_err(FixedValidatorNodeCurrentRoundErrorV0::Round)?;
    }
    debug_assert_eq!(round.position(), signer_position);
    Ok(round)
}

pub(super) fn derive_round(
    branch: &FixedConsensusBranchV0,
    required_round: ConsensusRound,
) -> Result<FixedConsensusRoundV0<'_>, ProposerSelectionError> {
    let mut round = branch.begin_round_zero()?;
    for _ in 0..required_round.value() {
        round = round.advance_round()?;
    }
    debug_assert_eq!(round.position().round(), required_round);
    Ok(round)
}
