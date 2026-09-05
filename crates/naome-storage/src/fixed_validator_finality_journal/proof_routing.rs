//! Bounded preliminary proof routing; these values grant no proof authority.

use super::*;

pub(super) enum SelectedSiblingParentErrorV0 {
    FinalityJournal(FixedValidatorFinalityJournalErrorV0),
    SelectedHeightUnavailable { height: ConsensusHeight },
    SelectedValueNotDistinct { height: ConsensusHeight },
}

pub(super) fn selected_sibling_parent<F: StoreIo>(
    journal: &FixedValidatorFinalityJournalCore<F>,
    value: ConsensusValueV0,
) -> Result<&FixedConsensusBranchV0, SelectedSiblingParentErrorV0> {
    let height = value.height();
    let height_index = height_index(height).map_err(|()| {
        SelectedSiblingParentErrorV0::FinalityJournal(
            FixedValidatorFinalityJournalErrorV0::CommitHeightIndexOverflow { height },
        )
    })?;
    let Some(parent_index) = height_index.checked_sub(1) else {
        return Err(SelectedSiblingParentErrorV0::SelectedHeightUnavailable { height });
    };
    if height_index >= journal.branches.len() {
        return Err(SelectedSiblingParentErrorV0::SelectedHeightUnavailable { height });
    }
    let parent = journal
        .branches
        .get(parent_index)
        .expect("every selected height retains its exact parent branch");
    let selected = journal
        .records
        .get(parent_index)
        .expect("every selected positive height retains one finality record");
    if selected.value == value {
        return Err(SelectedSiblingParentErrorV0::SelectedValueNotDistinct { height });
    }
    Ok(parent)
}

pub(super) fn decode_finality_envelope_value(
    expected_context: ConsensusContextV0,
    canonical_envelope_bytes: &[u8],
) -> Result<ConsensusValueV0, FixedConsensusBoundedEnvelopeVerifyError> {
    let envelope_error = FixedConsensusBoundedEnvelopeVerifyError::Envelope;
    if canonical_envelope_bytes.len() > VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH {
        return Err(envelope_error(ConsensusEnvelopeVerifyError::InputTooLong {
            actual: canonical_envelope_bytes.len(),
            maximum: VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH,
        }));
    }
    if canonical_envelope_bytes.len() < VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH {
        return Err(envelope_error(
            ConsensusEnvelopeVerifyError::InvalidLength {
                actual: canonical_envelope_bytes.len(),
                minimum: VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH,
            },
        ));
    }
    let value = ConsensusValueV0::from_canonical_bytes(
        &canonical_envelope_bytes[..ConsensusValueV0::BYTE_LENGTH],
    )
    .map_err(|error| envelope_error(ConsensusEnvelopeVerifyError::Value(error)))?;
    let actual_context = value.context();
    if actual_context.chain_id() != expected_context.chain_id() {
        return Err(envelope_error(
            ConsensusEnvelopeVerifyError::ChainIdMismatch {
                expected: expected_context.chain_id(),
                actual: actual_context.chain_id(),
            },
        ));
    }
    if actual_context.genesis_id() != expected_context.genesis_id() {
        return Err(envelope_error(
            ConsensusEnvelopeVerifyError::GenesisIdMismatch {
                expected: expected_context.genesis_id(),
                actual: actual_context.genesis_id(),
            },
        ));
    }
    if actual_context.protocol_version() != expected_context.protocol_version() {
        return Err(envelope_error(
            ConsensusEnvelopeVerifyError::ProtocolVersionMismatch {
                expected: expected_context.protocol_version(),
                actual: actual_context.protocol_version(),
            },
        ));
    }
    Ok(value)
}

pub(super) fn decode_finality_proposal_value(
    expected_context: ConsensusContextV0,
    canonical_proposal_control_bytes: &[u8],
) -> Result<ConsensusValueV0, ConsensusProposalVerifyError> {
    if canonical_proposal_control_bytes.len() > VerifiedFixedConsensusProposalV0::MAX_BYTE_LENGTH {
        return Err(ConsensusProposalVerifyError::InputTooLong {
            actual: canonical_proposal_control_bytes.len(),
            maximum: VerifiedFixedConsensusProposalV0::MAX_BYTE_LENGTH,
        });
    }
    if canonical_proposal_control_bytes.len() < VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH {
        return Err(ConsensusProposalVerifyError::InvalidLength {
            actual: canonical_proposal_control_bytes.len(),
            minimum: VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH,
        });
    }
    let value = ConsensusValueV0::from_canonical_bytes(
        &canonical_proposal_control_bytes[..ConsensusValueV0::BYTE_LENGTH],
    )
    .map_err(ConsensusProposalVerifyError::Value)?;
    let actual_context = value.context();
    if actual_context.chain_id() != expected_context.chain_id() {
        return Err(ConsensusProposalVerifyError::ChainIdMismatch {
            expected: expected_context.chain_id(),
            actual: actual_context.chain_id(),
        });
    }
    if actual_context.genesis_id() != expected_context.genesis_id() {
        return Err(ConsensusProposalVerifyError::GenesisIdMismatch {
            expected: expected_context.genesis_id(),
            actual: actual_context.genesis_id(),
        });
    }
    if actual_context.protocol_version() != expected_context.protocol_version() {
        return Err(ConsensusProposalVerifyError::ProtocolVersionMismatch {
            expected: expected_context.protocol_version(),
            actual: actual_context.protocol_version(),
        });
    }
    Ok(value)
}
