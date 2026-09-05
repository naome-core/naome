//! Canonical record encodings and shared validation helpers.

use super::*;

pub(super) fn prepared_capability(
    slot: VoteSlot,
    retained: &RetainedVote,
) -> FixedValidatorPreparedVoteV0 {
    FixedValidatorPreparedVoteV0 {
        slot,
        target: retained.observed_intent.target(),
        prepared_state_id: retained.prepared_state_id,
    }
}

pub(super) fn prepared_proposal_capability(
    position: ConsensusPosition,
    retained: &RetainedProposal,
) -> FixedValidatorPreparedProposalV0 {
    FixedValidatorPreparedProposalV0 {
        position,
        proposal_signing_root: retained.observed_intent.proposal_signing_root(),
        prepared_state_id: retained.prepared_state_id,
    }
}

pub(super) fn signed_proposal_from_completed(
    completed: CompletedFixedValidatorProposalV0,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
) -> FixedValidatorSignedProposalV0 {
    FixedValidatorSignedProposalV0 {
        position: completed.position(),
        proposal_signing_root: completed.proposal_signing_root(),
        canonical_proposal_control_bytes: completed.into_canonical_proposal_control_bytes(),
        state_id,
    }
}

pub(super) fn proposal_intent_digest(intent: &ObservedFixedValidatorProposalIntentV0) -> [u8; 32] {
    const DOMAIN: &[u8] = b"naome:fixed-validator-proposal-intent-digest:v0\0";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(intent.canonical_intent_bytes());
    hasher.finalize().into()
}

pub(super) fn proposal_halt(
    position: ConsensusPosition,
    retained: &ObservedFixedValidatorProposalIntentV0,
    conflicting: &ObservedFixedValidatorProposalIntentV0,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
) -> FixedValidatorProposalSafetyHaltV0 {
    FixedValidatorProposalSafetyHaltV0 {
        position,
        retained_root: retained.proposal_signing_root(),
        conflicting_root: conflicting.proposal_signing_root(),
        retained_intent_digest: proposal_intent_digest(retained),
        conflicting_intent_digest: proposal_intent_digest(conflicting),
        state_id,
    }
}

pub(super) fn observed_intent_slot(intent: &ObservedFixedValidatorVoteIntentV0) -> VoteSlot {
    VoteSlot::new(intent.position(), intent.role())
}

pub(super) const fn phase_for_vote_role(role: ConsensusVoteRole) -> FixedValidatorLockPhaseV0 {
    match role {
        ConsensusVoteRole::Prevote => FixedValidatorLockPhaseV0::Prevote,
        ConsensusVoteRole::Precommit => FixedValidatorLockPhaseV0::Precommit,
    }
}

const fn phase_rank(phase: FixedValidatorLockPhaseV0) -> u8 {
    match phase {
        FixedValidatorLockPhaseV0::Proposal => 0,
        FixedValidatorLockPhaseV0::Prevote => 1,
        FixedValidatorLockPhaseV0::Precommit => 2,
    }
}

pub(super) fn state_coordinate_cmp(
    left_position: ConsensusPosition,
    left_phase: FixedValidatorLockPhaseV0,
    right_position: ConsensusPosition,
    right_phase: FixedValidatorLockPhaseV0,
) -> std::cmp::Ordering {
    (
        left_position.height().value(),
        left_position.round().value(),
        phase_rank(left_phase),
    )
        .cmp(&(
            right_position.height().value(),
            right_position.round().value(),
            phase_rank(right_phase),
        ))
}

pub(super) fn signed_vote_from_verified(
    verified: &VerifiedConsensusVoteV0,
    canonical_bytes: Vec<u8>,
    state_id: FixedValidatorVoteSafetyJournalStateIdV0,
) -> FixedValidatorSignedVoteV0 {
    FixedValidatorSignedVoteV0 {
        position: verified.position(),
        role: verified.role(),
        target: verified.target(),
        vote_id: verified.id(),
        canonical_bytes,
        state_id,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One field by which signed bytes can fail to match their prepared intent.
pub enum FixedValidatorVoteCompletionMismatchV0 {
    /// The verified signer differs from the header-bound local key.
    Signer,
    /// The verified height or round differs from the prepared position.
    Position,
    /// The verified prevote or precommit role differs from the prepared role.
    Role,
    /// The verified nil-or-proposal target differs from the prepared target.
    Target,
}

pub(super) fn require_verified_vote(
    verified: &VerifiedConsensusVoteV0,
    signer: ConsensusKey,
    slot: VoteSlot,
    target: ConsensusVoteTarget,
) -> Result<(), FixedValidatorVoteCompletionMismatchV0> {
    if verified.signer() != signer {
        return Err(FixedValidatorVoteCompletionMismatchV0::Signer);
    }
    if verified.position() != slot.position {
        return Err(FixedValidatorVoteCompletionMismatchV0::Position);
    }
    if verified.role() != slot.role {
        return Err(FixedValidatorVoteCompletionMismatchV0::Role);
    }
    if verified.target() != target {
        return Err(FixedValidatorVoteCompletionMismatchV0::Target);
    }
    Ok(())
}

pub(crate) fn signing_lineage_id(
    coordinate: FixedConsensusBranchCoordinateV0,
    height: ConsensusHeight,
    signer: ConsensusKey,
) -> SigningLineageIdV0 {
    let context = coordinate.context();
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_LINEAGE_DOMAIN);
    hasher.update(context.chain_id().as_bytes());
    hasher.update(context.genesis_id().as_bytes());
    hasher.update(context.protocol_version().value().to_be_bytes());
    match coordinate.verified_height() {
        None => {
            hasher.update([0]);
            hasher.update(0_u64.to_be_bytes());
        }
        Some(parent_height) => {
            hasher.update([1]);
            hasher.update(parent_height.value().to_be_bytes());
        }
    }
    hasher.update(coordinate.ancestry_id().as_bytes());
    hasher.update(coordinate.artifact_head_block_id().as_bytes());
    hasher.update(coordinate.artifact_set_root().as_bytes());
    hasher.update(coordinate.fixed_agreement_set_id().as_bytes());
    hasher.update(coordinate.proposer_priority_state_id().as_bytes());
    hasher.update(height.value().to_be_bytes());
    hasher.update(signer.as_bytes());
    SigningLineageIdV0(hasher.finalize().into())
}

pub(super) fn signing_lineage_record(
    height: ConsensusHeight,
    id: SigningLineageIdV0,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut payload = [0_u8; SIGNING_LINEAGE_PAYLOAD_BYTES];
    payload[..8].copy_from_slice(&height.value().to_be_bytes());
    payload[8..].copy_from_slice(&id.0);
    tagged_record(SIGNING_LINEAGE_RECORD, &payload, entry)
}

pub(super) fn finality_conflict_stop_record(
    stop: FixedValidatorFinalityConflictSignerStopV0,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut payload = [0_u8; FINALITY_CONFLICT_STOP_PAYLOAD_BYTES];
    payload[..32].copy_from_slice(stop.finality_state_id.as_bytes());
    payload[32..40].copy_from_slice(&stop.height.value().to_be_bytes());
    payload[40..72].copy_from_slice(stop.first_ancestry.as_bytes());
    payload[72..104].copy_from_slice(stop.first_envelope_id.as_bytes());
    payload[104..136].copy_from_slice(stop.second_ancestry.as_bytes());
    payload[136..168].copy_from_slice(stop.second_envelope_id.as_bytes());
    let tag = match stop.kind {
        FixedValidatorFinalityHaltKindV0::SelectedSibling => FINALITY_CONFLICT_STOP_RECORD,
        FixedValidatorFinalityHaltKindV0::PreselectionPair => PRESELECTION_CONFLICT_STOP_RECORD,
    };
    tagged_record(tag, &payload, entry)
}

pub(super) fn tagged_record(
    tag: u8,
    payload: &[u8],
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let length = payload
        .len()
        .checked_add(1)
        .expect("bounded vote-safety record length cannot overflow usize");
    let mut body = Vec::new();
    body.try_reserve_exact(length).map_err(|_| {
        FixedValidatorVoteSafetyJournalErrorV0::Allocation {
            entry,
            bytes: length,
        }
    })?;
    body.push(tag);
    body.extend_from_slice(payload);
    Ok(body)
}

pub(super) fn canonical_prefix(
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    signer: ConsensusKey,
    replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(JOURNAL_PREFIX_BYTES)
        .map_err(|_| FixedValidatorVoteSafetyJournalErrorV0::Allocation {
            entry: 0,
            bytes: JOURNAL_PREFIX_BYTES,
        })?;
    prefix.extend_from_slice(JOURNAL_HEADER);
    prefix.extend_from_slice(context.chain_id().as_bytes());
    prefix.extend_from_slice(context.genesis_id().as_bytes());
    prefix.extend_from_slice(&context.protocol_version().value().to_be_bytes());
    prefix.extend_from_slice(fixed_set_id.as_bytes());
    prefix.extend_from_slice(signer.as_bytes());
    prefix.extend_from_slice(&replay_limit.max_prepared_votes().to_be_bytes());
    debug_assert_eq!(prefix.len(), JOURNAL_PREFIX_BYTES);
    Ok(prefix)
}

pub(super) fn consensus_key(signing_key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes())
}

pub(super) fn keyed_paths(
    directory: &Path,
    signer: ConsensusKey,
) -> Result<(PathBuf, PathBuf), FixedValidatorVoteSafetyJournalErrorV0> {
    let mut stem = String::new();
    stem.try_reserve_exact(FILE_STEM.len() + CONSENSUS_KEY_BYTES * 2)
        .map_err(|_| FixedValidatorVoteSafetyJournalErrorV0::PathAllocation)?;
    stem.push_str(FILE_STEM);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in signer.as_bytes() {
        stem.push(HEX[usize::from(byte >> 4)] as char);
        stem.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    let mut lock_name = stem.clone();
    lock_name.push_str(LOCK_SUFFIX);
    let mut journal_name = stem;
    journal_name.push_str(JOURNAL_SUFFIX);
    Ok((directory.join(lock_name), directory.join(journal_name)))
}

pub(super) fn open_key_lock(path: &Path) -> Result<File, FixedValidatorVoteSafetyJournalErrorV0> {
    let directory = path.parent().expect("keyed lock path always has a parent");
    let file_name = path
        .file_name()
        .expect("keyed lock path always has a file name")
        .to_string_lossy();
    open_exclusive_lock(directory, &file_name).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => {
            FixedValidatorVoteSafetyJournalErrorV0::LockFile { source }
        }
        ExclusiveLockError::Locked => FixedValidatorVoteSafetyJournalErrorV0::Locked,
        ExclusiveLockError::Lock(source) => FixedValidatorVoteSafetyJournalErrorV0::Lock { source },
    })
}

pub(super) fn genesis_state_id(prefix: &[u8]) -> FixedValidatorVoteSafetyJournalStateIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_STATE_DOMAIN);
    hasher.update(prefix);
    FixedValidatorVoteSafetyJournalStateIdV0::from_bytes(hasher.finalize().into())
}

pub(super) fn step_state_id(
    prior: FixedValidatorVoteSafetyJournalStateIdV0,
    body_length: [u8; 4],
    body: &[u8],
) -> FixedValidatorVoteSafetyJournalStateIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(STEP_STATE_DOMAIN);
    hasher.update(prior.as_bytes());
    hasher.update(body_length);
    hasher.update(body);
    FixedValidatorVoteSafetyJournalStateIdV0::from_bytes(hasher.finalize().into())
}

pub(super) fn allocate_bytes(
    length: usize,
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| {
        FixedValidatorVoteSafetyJournalErrorV0::Allocation {
            entry,
            bytes: length,
        }
    })?;
    bytes.resize(length, 0);
    Ok(bytes)
}

pub(super) fn clone_bytes(
    bytes: &[u8],
    entry: u64,
) -> Result<Vec<u8>, FixedValidatorVoteSafetyJournalErrorV0> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len()).map_err(|_| {
        FixedValidatorVoteSafetyJournalErrorV0::Allocation {
            entry,
            bytes: bytes.len(),
        }
    })?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

pub(super) fn read_exact_at<F: StoreIo>(
    file: &mut F,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), FixedValidatorVoteSafetyJournalErrorV0> {
    file.read_exact(bytes)
        .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Read { offset, source })
}

impl<F: StoreIo> FixedValidatorVoteSafetyJournalCore<F> {
    pub(super) fn decode_observed_intent(
        &self,
        bytes: &[u8],
        entry: u64,
        offset: u64,
    ) -> Result<ObservedFixedValidatorVoteIntentV0, FixedValidatorVoteSafetyJournalErrorV0> {
        ObservedFixedValidatorVoteIntentV0::decode_and_verify(
            bytes,
            self.context,
            self.fixed_set_id,
            self.signer,
        )
        .map_err(|source| FixedValidatorVoteSafetyJournalErrorV0::Intent {
            entry,
            offset,
            source,
        })
    }

    pub(super) fn decode_observed_proposal_intent(
        &self,
        bytes: &[u8],
        entry: u64,
        offset: u64,
    ) -> Result<ObservedFixedValidatorProposalIntentV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        ObservedFixedValidatorProposalIntentV0::decode_and_verify(
            bytes,
            self.context,
            self.fixed_set_id,
            self.signer,
        )
        .map_err(
            |source| FixedValidatorVoteSafetyJournalErrorV0::ProposalIntent {
                entry,
                offset,
                source,
            },
        )
    }
}
