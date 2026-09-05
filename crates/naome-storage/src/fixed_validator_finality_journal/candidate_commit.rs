//! Caller-selected candidate availability and fully verified finality.

use super::*;

/// Strictly installs one exact retained candidate as the current head's next child.
///
/// The caller selects `expected_target`; that choice grants no preference or
/// finality authority. This operation requires an operable fixed-validator
/// journal, the matching chain-scoped candidate, its exact archived Foundation
/// payload, and one complete canonical envelope. It bounds the envelope's sole
/// embedded round by both the caller-local ceiling and the journal ceiling,
/// fully verifies the envelope against the exact current head, and delegates
/// only the resulting sealed transition to the journal's durable commit.
///
/// Success changes only the finality journal. Candidate and payload entries are
/// integrity-read but never removed, marked, or rewritten. The operation does
/// no discovery, ranking, fork choice, sibling-conflict admission, rollback,
/// peer trust, or multi-height promotion.
pub fn commit_candidate_backed_finality_v0(
    journal: &mut FixedValidatorFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityCommitV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_core_v0(
        &mut journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )
}

/// Strictly installs one exact retained candidate through an anchored journal.
///
/// This has the same caller-selected verification and source-store boundaries as
/// [`commit_candidate_backed_finality_v0`], but every resulting finality frame
/// also advances the paired anchor before the commit outcome is published.
pub fn commit_candidate_backed_anchored_finality_v0(
    journal: &mut FixedValidatorAnchoredFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityCommitV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_core_v0(
        &mut journal.journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )
}

pub(super) fn commit_candidate_backed_finality_core_v0<F: StoreIo>(
    journal: &mut FixedValidatorFinalityJournalCore<F>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityCommitV0, CandidateBackedFinalityErrorV0> {
    journal
        .ensure_operational()
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    if inclusive_maximum_round.value() > journal.replay_limit.max_round() {
        return Err(
            CandidateBackedFinalityErrorV0::RoundWorkLimitExceedsJournal {
                requested: inclusive_maximum_round.value(),
                journal: journal.replay_limit.max_round(),
            },
        );
    }
    let head = journal
        .branches
        .last()
        .expect("every finality journal retains its virtual-genesis branch");
    let envelope_value = decode_candidate_backed_envelope_value(
        journal.context,
        canonical_envelope_bytes,
        expected_target,
    )?;
    let expected_height = head
        .next_height()
        .map_err(FixedConsensusBoundedEnvelopeVerifyError::Proposer)
        .map_err(CandidateBackedFinalityErrorV0::Envelope)?;
    if envelope_value.height() != expected_height {
        return Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::ValueHeightMismatch {
                expected: expected_height,
                actual: envelope_value.height(),
            },
        ));
    }
    let transition = verify_candidate_backed_transition(
        head,
        candidates,
        payloads,
        expected_target,
        envelope_value,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )?;
    let outcome = journal
        .commit_verified(transition)
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    match outcome {
        FixedValidatorFinalityCommitOutcomeV0::Finalized {
            position,
            ancestry_id,
            envelope_id,
            state_id,
        } => Ok(CandidateBackedFinalityCommitV0 {
            target: expected_target,
            position,
            ancestry_id,
            envelope_id,
            state_id,
        }),
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { height, .. } => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedAlreadyFinalized { height })
        }
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedConflictHalt {
                height: halt.height(),
            })
        }
    }
}

/// Verifies one exact retained candidate as a distinct finalized sibling.
///
/// This deny-only boundary accepts only an already selected positive height. It
/// rejects the evidence-free selected value before source reads, then requires
/// complete branch-relative authentication of a distinct sibling before the
/// existing terminal conflict record may be appended. Candidate and payload
/// entries and durable bytes remain unchanged; an integrity/read failure may
/// poison only the owning live source handle under its existing reopen contract.
/// Success grants no branch or winner.
pub fn commit_candidate_backed_finality_conflict_v0(
    journal: &mut FixedValidatorFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_conflict_core_v0(
        &mut journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )
}

/// Verifies and anchors one exact candidate-backed finalized sibling conflict.
///
/// This has the same deny-only verification and source-store boundaries as
/// [`commit_candidate_backed_finality_conflict_v0`], but the terminal finality
/// frame advances the paired anchor before the halt is published.
pub fn commit_candidate_backed_anchored_finality_conflict_v0(
    journal: &mut FixedValidatorAnchoredFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_conflict_core_v0(
        &mut journal.journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )
}

/// Verifies one exact retained candidate as a distinct finalized sibling from
/// separate proposal-control and signed-precommit-batch inputs.
///
/// The caller supplies the exact candidate target and evidence round. This
/// deny-only sibling applies the same selected-height, selected-value, source,
/// and terminal-halt boundaries as [`commit_candidate_backed_finality_conflict_v0`].
/// The explicit round is bounded before proposer work, and every vote is
/// independently authenticated against the retained selected parent before the
/// existing conflict record may be appended. Success grants no branch or winner.
#[allow(clippy::too_many_arguments)]
pub fn commit_candidate_backed_finality_conflict_vote_batch_v0(
    journal: &mut FixedValidatorFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_proposal_control_bytes: &[u8],
    canonical_signed_precommits: &[&[u8]],
    evidence_round: ConsensusRound,
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_conflict_vote_batch_core_v0(
        &mut journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_proposal_control_bytes,
        canonical_signed_precommits,
        evidence_round,
        inclusive_maximum_round,
    )
}

/// Verifies and anchors one exact candidate-backed finalized sibling conflict
/// from separate proposal-control and signed-precommit-batch inputs.
///
/// This has the same explicit routing and complete verification boundary as
/// [`commit_candidate_backed_finality_conflict_vote_batch_v0`], but the terminal
/// finality frame advances the paired anchor before the halt is published.
#[allow(clippy::too_many_arguments)]
pub fn commit_candidate_backed_anchored_finality_conflict_vote_batch_v0(
    journal: &mut FixedValidatorAnchoredFinalityJournalV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_proposal_control_bytes: &[u8],
    canonical_signed_precommits: &[&[u8]],
    evidence_round: ConsensusRound,
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    commit_candidate_backed_finality_conflict_vote_batch_core_v0(
        &mut journal.journal.core,
        candidates,
        payloads,
        expected_target,
        canonical_proposal_control_bytes,
        canonical_signed_precommits,
        evidence_round,
        inclusive_maximum_round,
    )
}

pub(super) fn commit_candidate_backed_finality_conflict_core_v0<F: StoreIo>(
    journal: &mut FixedValidatorFinalityJournalCore<F>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    journal
        .ensure_operational()
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    if inclusive_maximum_round.value() > journal.replay_limit.max_round() {
        return Err(
            CandidateBackedFinalityErrorV0::RoundWorkLimitExceedsJournal {
                requested: inclusive_maximum_round.value(),
                journal: journal.replay_limit.max_round(),
            },
        );
    }
    let envelope_value = decode_candidate_backed_envelope_value(
        journal.context,
        canonical_envelope_bytes,
        expected_target,
    )?;
    let parent = candidate_backed_conflict_parent(journal, envelope_value)?;
    let transition = verify_candidate_backed_transition(
        parent,
        candidates,
        payloads,
        expected_target,
        envelope_value,
        canonical_envelope_bytes,
        inclusive_maximum_round,
    )?;
    let outcome = journal
        .commit_verified(transition)
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    match outcome {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => {
            Ok(CandidateBackedFinalityConflictV0 {
                target: expected_target,
                halt,
            })
        }
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { height, .. } => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedSelectedValueReplay { height })
        }
        FixedValidatorFinalityCommitOutcomeV0::Finalized { position, .. } => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedNewFinality {
                height: position.height(),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn commit_candidate_backed_finality_conflict_vote_batch_core_v0<F: StoreIo>(
    journal: &mut FixedValidatorFinalityJournalCore<F>,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    canonical_proposal_control_bytes: &[u8],
    canonical_signed_precommits: &[&[u8]],
    evidence_round: ConsensusRound,
    inclusive_maximum_round: ConsensusRound,
) -> Result<CandidateBackedFinalityConflictV0, CandidateBackedFinalityErrorV0> {
    journal
        .ensure_operational()
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    if inclusive_maximum_round.value() > journal.replay_limit.max_round() {
        return Err(
            CandidateBackedFinalityErrorV0::RoundWorkLimitExceedsJournal {
                requested: inclusive_maximum_round.value(),
                journal: journal.replay_limit.max_round(),
            },
        );
    }
    if evidence_round > inclusive_maximum_round {
        return Err(
            CandidateBackedFinalityErrorV0::EvidenceRoundWorkLimitExceeded {
                required: evidence_round,
                maximum: inclusive_maximum_round,
            },
        );
    }

    let proposal_value = decode_candidate_backed_proposal_value(
        journal.context,
        canonical_proposal_control_bytes,
        expected_target,
    )?;
    let parent = candidate_backed_conflict_parent(journal, proposal_value)?;
    let mut round = parent
        .begin_round_zero()
        .map_err(CandidateBackedFinalityErrorV0::Round)?;
    for _ in 0..evidence_round.value() {
        round = round
            .advance_round()
            .map_err(CandidateBackedFinalityErrorV0::Round)?;
    }
    let canonical_artifact_bytes = load_candidate_backed_artifact_bytes(
        parent,
        candidates,
        payloads,
        expected_target,
        proposal_value,
    )?;
    let proposal = round
        .decode_and_verify_proposal_control(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
        )
        .map_err(CandidateBackedFinalityErrorV0::Proposal)?;
    let transition = proposal
        .seal_with_precommit_vote_batch(canonical_signed_precommits)
        .map(VerifiedFixedConsensusTransitionV0::into_owned)
        .map_err(CandidateBackedFinalityErrorV0::PrecommitBatch)?;
    drop(round);

    let outcome = journal
        .commit_verified(transition)
        .map_err(CandidateBackedFinalityErrorV0::FinalityJournal)?;
    match outcome {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => {
            Ok(CandidateBackedFinalityConflictV0 {
                target: expected_target,
                halt,
            })
        }
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { height, .. } => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedSelectedValueReplay { height })
        }
        FixedValidatorFinalityCommitOutcomeV0::Finalized { position, .. } => {
            Err(CandidateBackedFinalityErrorV0::UnexpectedNewFinality {
                height: position.height(),
            })
        }
    }
}

pub(super) fn candidate_backed_conflict_parent<F: StoreIo>(
    journal: &FixedValidatorFinalityJournalCore<F>,
    value: ConsensusValueV0,
) -> Result<&FixedConsensusBranchV0, CandidateBackedFinalityErrorV0> {
    let height = value.height();
    let height_index = height_index(height).map_err(|()| {
        CandidateBackedFinalityErrorV0::FinalityJournal(
            FixedValidatorFinalityJournalErrorV0::CommitHeightIndexOverflow { height },
        )
    })?;
    let Some(parent_index) = height_index.checked_sub(1) else {
        return Err(CandidateBackedFinalityErrorV0::SelectedHeightUnavailable { height });
    };
    if height_index >= journal.branches.len() {
        return Err(CandidateBackedFinalityErrorV0::SelectedHeightUnavailable { height });
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
        return Err(CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height });
    }
    Ok(parent)
}

pub(super) fn decode_candidate_backed_envelope_value(
    expected_context: ConsensusContextV0,
    canonical_envelope_bytes: &[u8],
    expected_target: ArtifactBlockId,
) -> Result<ConsensusValueV0, CandidateBackedFinalityErrorV0> {
    let envelope_error = |error| {
        CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(error),
        )
    };
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
    let actual_target = value.artifact_block().id();
    if actual_target != expected_target {
        return Err(CandidateBackedFinalityErrorV0::EnvelopeTargetMismatch {
            expected: expected_target,
            actual: actual_target,
        });
    }
    Ok(value)
}

pub(super) fn decode_candidate_backed_proposal_value(
    expected_context: ConsensusContextV0,
    canonical_proposal_control_bytes: &[u8],
    expected_target: ArtifactBlockId,
) -> Result<ConsensusValueV0, CandidateBackedFinalityErrorV0> {
    let proposal_error = CandidateBackedFinalityErrorV0::Proposal;
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
    let actual_target = value.artifact_block().id();
    if actual_target != expected_target {
        return Err(CandidateBackedFinalityErrorV0::ProposalTargetMismatch {
            expected: expected_target,
            actual: actual_target,
        });
    }
    Ok(value)
}

pub(super) fn verify_candidate_backed_transition(
    parent: &FixedConsensusBranchV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    envelope_value: ConsensusValueV0,
    canonical_envelope_bytes: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<OwnedVerifiedFixedConsensusTransitionV0, CandidateBackedFinalityErrorV0> {
    let canonical_artifact_bytes = load_candidate_backed_artifact_bytes(
        parent,
        candidates,
        payloads,
        expected_target,
        envelope_value,
    )?;

    parent
        .decode_and_verify_envelope_with_round_limit(
            canonical_envelope_bytes,
            canonical_artifact_bytes,
            inclusive_maximum_round,
        )
        .map_err(CandidateBackedFinalityErrorV0::Envelope)
}

pub(super) fn load_candidate_backed_artifact_bytes(
    parent: &FixedConsensusBranchV0,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    expected_target: ArtifactBlockId,
    value: ConsensusValueV0,
) -> Result<Vec<u8>, CandidateBackedFinalityErrorV0> {
    let expected_chain = parent.context().chain_id();
    if candidates.chain_id() != expected_chain {
        return Err(CandidateBackedFinalityErrorV0::CandidateChainMismatch {
            expected: expected_chain,
            actual: candidates.chain_id(),
        });
    }
    let candidate = candidates
        .get(expected_target)
        .map_err(CandidateBackedFinalityErrorV0::CandidateStore)?
        .ok_or(CandidateBackedFinalityErrorV0::CandidateUnavailable {
            target: expected_target,
        })?;
    if candidate != value.artifact_block() {
        return Err(CandidateBackedFinalityErrorV0::CandidateBlockMismatch {
            target: expected_target,
        });
    }

    let artifact_id = candidate.artifact_id();
    let payload = payloads
        .get(artifact_id)
        .map_err(CandidateBackedFinalityErrorV0::PayloadStore)?
        .ok_or(CandidateBackedFinalityErrorV0::PayloadUnavailable { artifact_id })?;
    debug_assert_eq!(payload.artifact_id(), artifact_id);

    Ok(payload.into_canonical_artifact_bytes().into_vec())
}
