use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_consensus::{
    ConsensusProposalVerifyError, ConsensusValueV0, FixedConsensusRoundV0,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
};

/// One pre-effect failure while loading an exact caller-selected proposal payload.
#[derive(Debug)]
pub(super) enum CandidateBackedProposalSourceErrorV0 {
    Proposal(Box<ConsensusProposalVerifyError>),
    CandidateChainMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    CandidateStore(Box<ArtifactBlockCandidateStoreError>),
    CandidateUnavailable {
        target: ArtifactBlockId,
    },
    ProposalTargetMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    CandidateBlockMismatch {
        target: ArtifactBlockId,
    },
    PayloadStore(Box<CanonicalArtifactPayloadStoreError>),
    PayloadUnavailable {
        target: ArtifactBlockId,
    },
}

/// Loads one exact retained block's complete canonical payload after structural
/// proposal identity checks against the already derived round.
///
/// The stores are caller-routed availability sources only. This helper neither
/// discovers nor selects a target, and it mutates no retained entry. Existing
/// store integrity failures may still poison only their owning live handle.
pub(super) fn load_candidate_backed_proposal_payload(
    round: &FixedConsensusRoundV0<'_>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_proposal_control_bytes: &[u8],
) -> Result<Vec<u8>, CandidateBackedProposalSourceErrorV0> {
    let value = decode_candidate_backed_proposal_value(
        round,
        expected_target,
        canonical_proposal_control_bytes,
    )?;
    let expected_chain = round.context().chain_id();
    if candidates.chain_id() != expected_chain {
        return Err(
            CandidateBackedProposalSourceErrorV0::CandidateChainMismatch {
                expected: expected_chain,
                actual: candidates.chain_id(),
            },
        );
    }
    let candidate = candidates
        .get(expected_target)
        .map_err(|source| CandidateBackedProposalSourceErrorV0::CandidateStore(Box::new(source)))?
        .ok_or(CandidateBackedProposalSourceErrorV0::CandidateUnavailable {
            target: expected_target,
        })?;
    if candidate != value.artifact_block() {
        return Err(
            CandidateBackedProposalSourceErrorV0::CandidateBlockMismatch {
                target: expected_target,
            },
        );
    }
    let artifact_id = candidate.artifact_id();
    let payload = payloads
        .get(artifact_id)
        .map_err(|source| CandidateBackedProposalSourceErrorV0::PayloadStore(Box::new(source)))?
        .ok_or(CandidateBackedProposalSourceErrorV0::PayloadUnavailable {
            target: expected_target,
        })?;
    debug_assert_eq!(payload.artifact_id(), artifact_id);
    Ok(payload.into_canonical_artifact_bytes().into_vec())
}

fn decode_candidate_backed_proposal_value(
    round: &FixedConsensusRoundV0<'_>,
    expected_target: ArtifactBlockId,
    canonical_proposal_control_bytes: &[u8],
) -> Result<ConsensusValueV0, CandidateBackedProposalSourceErrorV0> {
    let proposal_error = |source| CandidateBackedProposalSourceErrorV0::Proposal(Box::new(source));
    if canonical_proposal_control_bytes.len() > VerifiedFixedConsensusProposalV0::MAX_BYTE_LENGTH {
        return Err(proposal_error(ConsensusProposalVerifyError::InputTooLong {
            actual: canonical_proposal_control_bytes.len(),
            maximum: VerifiedFixedConsensusProposalV0::MAX_BYTE_LENGTH,
        }));
    }
    if canonical_proposal_control_bytes.len() < VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH {
        return Err(proposal_error(
            ConsensusProposalVerifyError::InvalidLength {
                actual: canonical_proposal_control_bytes.len(),
                minimum: VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH,
            },
        ));
    }
    let value = ConsensusValueV0::from_canonical_bytes(
        &canonical_proposal_control_bytes[..ConsensusValueV0::BYTE_LENGTH],
    )
    .map_err(|source| proposal_error(ConsensusProposalVerifyError::Value(source)))?;
    let expected_context = round.context();
    let actual_context = value.context();
    if actual_context.chain_id() != expected_context.chain_id() {
        return Err(proposal_error(
            ConsensusProposalVerifyError::ChainIdMismatch {
                expected: expected_context.chain_id(),
                actual: actual_context.chain_id(),
            },
        ));
    }
    if actual_context.genesis_id() != expected_context.genesis_id() {
        return Err(proposal_error(
            ConsensusProposalVerifyError::GenesisIdMismatch {
                expected: expected_context.genesis_id(),
                actual: actual_context.genesis_id(),
            },
        ));
    }
    if actual_context.protocol_version() != expected_context.protocol_version() {
        return Err(proposal_error(
            ConsensusProposalVerifyError::ProtocolVersionMismatch {
                expected: expected_context.protocol_version(),
                actual: actual_context.protocol_version(),
            },
        ));
    }
    let snapshot = round.position();
    if value.height() != snapshot.height() {
        return Err(proposal_error(
            ConsensusProposalVerifyError::SnapshotHeightMismatch {
                value: value.height(),
                snapshot,
            },
        ));
    }
    let actual_target = value.artifact_block().id();
    if actual_target != expected_target {
        return Err(
            CandidateBackedProposalSourceErrorV0::ProposalTargetMismatch {
                expected: expected_target,
                actual: actual_target,
            },
        );
    }
    Ok(value)
}
