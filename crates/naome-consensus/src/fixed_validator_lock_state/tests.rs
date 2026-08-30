use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{
    ArtifactBlock, ArtifactBlockId, ArtifactChainDefinition, ArtifactChainState, ArtifactSetRoot,
};
use naome_proof::ArtifactId;

use super::*;
use crate::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementWeight, ConsensusGenesisId,
    ConsensusHeight, ConsensusKey, ConsensusProtocolVersion, FixedConsensusBranchV0,
};

const VOTE_BODY_BYTES: usize = 118;

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn consensus_key(key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(key.verifying_key().to_bytes())
}

fn context(chain_id: naome_chain::ArtifactChainId) -> ConsensusContextV0 {
    ConsensusContextV0::new(
        chain_id,
        ConsensusGenesisId::from_bytes([0x61; 32]),
        ConsensusProtocolVersion::new(7),
    )
}

fn fixture(chain_seed: u8) -> (FixedConsensusBranchV0, SigningKey, ConsensusContextV0) {
    let definition = ArtifactChainDefinition::new([chain_seed; 32]);
    let context = context(definition.id());
    let signing_key = signing_key(chain_seed);
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &[ActiveAgreementEntry::new(
            consensus_key(&signing_key),
            AgreementWeight::new(1),
        )],
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .unwrap();
    (branch, signing_key, context)
}

fn value(round: &FixedConsensusRoundV0<'_>, byte: u8) -> ConsensusValueV0 {
    round.value_for_artifact_block(ArtifactBlock::new(
        ArtifactBlockId::from_bytes([byte; 32]),
        ArtifactSetRoot::from_bytes([byte.wrapping_add(1); 32]),
        ArtifactSetRoot::from_bytes([byte.wrapping_add(2); 32]),
        ArtifactId::from_bytes([byte.wrapping_add(3); 32]),
    ))
}

fn snapshot(
    _context: ConsensusContextV0,
    position: ConsensusPosition,
    signing_key: &SigningKey,
) -> ActiveAgreementSnapshot {
    ActiveAgreementSnapshot::try_from_preselected(
        position,
        &[ActiveAgreementEntry::new(
            consensus_key(signing_key),
            AgreementWeight::new(1),
        )],
    )
    .unwrap()
}

fn vote_body(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> [u8; VOTE_BODY_BYTES] {
    let mut bytes = [0_u8; VOTE_BODY_BYTES];
    bytes[0] = match role {
        ConsensusVoteRole::Prevote => 1,
        ConsensusVoteRole::Precommit => 2,
    };
    bytes[1..33].copy_from_slice(context.chain_id().as_bytes());
    bytes[33..65].copy_from_slice(context.genesis_id().as_bytes());
    bytes[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    bytes[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    bytes[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => bytes[85] = 0,
        ConsensusVoteTarget::Proposal(root) => {
            bytes[85] = 1;
            bytes[86..].copy_from_slice(root.as_bytes());
        }
    }
    bytes
}

fn certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signing_key: &SigningKey,
) -> Vec<u8> {
    let body = vote_body(context, position, role, target);
    let signer = consensus_key(signing_key);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut transcript = Vec::new();
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(signer.as_bytes());
    let signature = signing_key.sign(&transcript).to_bytes();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(signer.as_bytes());
    bytes.extend_from_slice(&signature);
    bytes
}

fn quorum<'snapshot>(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signing_key: &SigningKey,
    snapshot: &'snapshot ActiveAgreementSnapshot,
) -> VerifiedQuorumCertificateV0<'snapshot> {
    VerifiedQuorumCertificateV0::decode_and_verify(
        &certificate_bytes(context, position, role, target, signing_key),
        context,
        snapshot,
    )
    .unwrap()
}

fn proposal_observation<'evidence>(
    state: &FixedValidatorLockStateV0,
    value: ConsensusValueV0,
    valid: Option<(ConsensusRound, QuorumCertificateId, &'evidence [u8])>,
) -> AdmittedProposalObservation<'evidence> {
    let (valid_round, valid_round_certificate_id, valid_round_certificate_bytes) = valid
        .map_or((None, None, None), |(round, id, bytes)| {
            (Some(round), Some(id), Some(bytes))
        });
    AdmittedProposalObservation {
        parent_coordinate: state.parent_coordinate,
        position: state.position,
        value,
        proposal_signing_root: value.proposal_signing_root(),
        valid_round,
        valid_round_certificate_id,
        valid_round_certificate_bytes,
    }
}

fn valid_snapshot(
    state: &FixedValidatorLockStateV0,
) -> Option<(
    ConsensusValueV0,
    ConsensusRound,
    QuorumCertificateId,
    Vec<u8>,
)> {
    state.valid_value().map(|valid| {
        (
            valid.value(),
            valid.round(),
            valid.prevote_certificate_id(),
            valid.canonical_prevote_certificate().to_vec(),
        )
    })
}

fn lock_current_proposal(
    state: &mut FixedValidatorLockStateV0,
    proposed: ConsensusValueV0,
    context: ConsensusContextV0,
    signing_key: &SigningKey,
) {
    let proposal = proposal_observation(state, proposed, None);
    let effect = state
        .decide_prevote_for_observation(proposal_observation(state, proposed, None))
        .unwrap();
    assert_eq!(effect.role(), ConsensusVoteRole::Prevote);
    assert_eq!(
        effect.target(),
        ConsensusVoteTarget::Proposal(proposed.proposal_signing_root())
    );

    let snapshot = snapshot(context, state.position(), signing_key);
    let certificate = quorum(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(proposed.proposal_signing_root()),
        signing_key,
        &snapshot,
    );
    let _ = state
        .decide_precommit_for_proposal_observation(
            proposal,
            PrevoteQuorumObservation::from_verified(&certificate, certificate.to_canonical_bytes()),
        )
        .unwrap();
}

#[test]
fn round_zero_starts_empty_and_absent_proposal_decides_nil_without_authority() {
    let (branch, _, _) = fixture(0x11);
    let round_zero = branch.begin_round_zero().unwrap();
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();

    assert_eq!(state.position(), round_zero.position());
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), None);

    let prevote = state.decide_prevote_without_proposal().unwrap();
    assert_eq!(prevote.position(), round_zero.position());
    assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
    assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
    let precommit = state.decide_precommit_without_quorum().unwrap();
    assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
    assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), None);
}

#[test]
fn proposal_prevote_quorum_locks_exact_value_and_retains_exact_proof() {
    let (branch, signing_key, context) = fixture(0x12);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x41);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);

    let locked = state.locked_value().unwrap();
    assert_eq!(locked.value(), proposed);
    assert_eq!(locked.round(), ConsensusRound::new(0));
    let valid = state.valid_value().unwrap();
    assert_eq!(valid.value(), proposed);
    assert_eq!(valid.round(), ConsensusRound::new(0));
    assert!(!valid.canonical_prevote_certificate().is_empty());
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Precommit);
}

#[test]
fn same_value_is_prevoted_without_changing_the_older_lock() {
    let (branch, signing_key, context) = fixture(0x13);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x42);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);
    let valid_before = valid_snapshot(&state);

    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let effect = state
        .decide_prevote_for_observation(proposal_observation(&state, proposed, None))
        .unwrap();

    assert_eq!(
        effect.target(),
        ConsensusVoteTarget::Proposal(proposed.proposal_signing_root())
    );
    assert_eq!(
        state.locked_value(),
        Some(FixedValidatorLockedValueV0 {
            value: proposed,
            round: ConsensusRound::new(0),
        })
    );
    assert_eq!(valid_snapshot(&state), valid_before);
}

#[test]
fn same_round_conflict_fails_closed_while_strictly_newer_proof_unlocks() {
    let (branch, signing_key, context) = fixture(0x14);
    let round_zero = branch.begin_round_zero().unwrap();
    let locked_value = value(&round_zero, 0x43);
    let conflicting = value(&round_zero, 0x53);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, locked_value, context, &signing_key);

    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let round_zero_snapshot = snapshot(
        context,
        ConsensusPosition::new(state.position().height(), ConsensusRound::new(0)),
        &signing_key,
    );
    let round_zero_conflict_qc = quorum(
        context,
        round_zero_snapshot.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(conflicting.proposal_signing_root()),
        &signing_key,
        &round_zero_snapshot,
    );
    let round_zero_conflict_bytes = round_zero_conflict_qc.to_canonical_bytes();
    let lock_before_conflict = state.locked_value();
    let valid_before_conflict = valid_snapshot(&state);
    let error = state
        .decide_prevote_for_observation(proposal_observation(
            &state,
            conflicting,
            Some((
                ConsensusRound::new(0),
                round_zero_conflict_qc.id(),
                &round_zero_conflict_bytes,
            )),
        ))
        .unwrap_err();
    assert_eq!(
        error,
        FixedValidatorLockStateError::ConflictingValidValue {
            round: ConsensusRound::new(0),
            retained: locked_value.proposal_signing_root(),
            observed: conflicting.proposal_signing_root(),
        }
    );
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(state.locked_value(), lock_before_conflict);
    assert_eq!(valid_snapshot(&state), valid_before_conflict);

    let effect = state.decide_prevote_without_proposal().unwrap();
    assert_eq!(
        effect.target(),
        ConsensusVoteTarget::Proposal(locked_value.proposal_signing_root())
    );
    let _ = state.decide_precommit_without_quorum().unwrap();
    let round_two = round_one.advance_round().unwrap();
    state.advance_round(&round_two).unwrap();
    let round_one_snapshot = snapshot(
        context,
        ConsensusPosition::new(state.position().height(), ConsensusRound::new(1)),
        &signing_key,
    );
    let round_one_conflict_qc = quorum(
        context,
        round_one_snapshot.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(conflicting.proposal_signing_root()),
        &signing_key,
        &round_one_snapshot,
    );
    let round_one_conflict_bytes = round_one_conflict_qc.to_canonical_bytes();
    let effect = state
        .decide_prevote_for_observation(proposal_observation(
            &state,
            conflicting,
            Some((
                ConsensusRound::new(1),
                round_one_conflict_qc.id(),
                &round_one_conflict_bytes,
            )),
        ))
        .unwrap();

    assert_eq!(
        effect.target(),
        ConsensusVoteTarget::Proposal(conflicting.proposal_signing_root())
    );
    assert_eq!(state.locked_value(), None);
    let valid = state.valid_value().unwrap();
    assert_eq!(valid.value(), conflicting);
    assert_eq!(valid.round(), ConsensusRound::new(1));
    assert_eq!(
        valid.canonical_prevote_certificate(),
        round_one_conflict_bytes
    );
}

#[test]
fn invalid_valid_round_is_all_or_nothing() {
    let (branch, signing_key, context) = fixture(0x15);
    let round_zero = branch.begin_round_zero().unwrap();
    let locked_value = value(&round_zero, 0x44);
    let conflicting = value(&round_zero, 0x54);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, locked_value, context, &signing_key);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();

    let before_lock = state.locked_value();
    let before_valid = valid_snapshot(&state);
    let current_snapshot = snapshot(context, state.position(), &signing_key);
    let current_qc = quorum(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(conflicting.proposal_signing_root()),
        &signing_key,
        &current_snapshot,
    );
    let current_bytes = current_qc.to_canonical_bytes();
    let error = state
        .decide_prevote_for_observation(proposal_observation(
            &state,
            conflicting,
            Some((state.position().round(), current_qc.id(), &current_bytes)),
        ))
        .unwrap_err();

    assert_eq!(
        error,
        FixedValidatorLockStateError::InvalidValidRound {
            valid_round: ConsensusRound::new(1),
            current_round: ConsensusRound::new(1),
        }
    );
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(state.locked_value(), before_lock);
    assert_eq!(valid_snapshot(&state), before_valid);
}

#[test]
fn nil_quorum_clears_lock_but_preserves_latest_valid_value() {
    let (branch, signing_key, context) = fixture(0x16);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x45);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);
    let valid_before = valid_snapshot(&state);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();

    let current_snapshot = snapshot(context, state.position(), &signing_key);
    let nil_qc = quorum(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &signing_key,
        &current_snapshot,
    );
    let nil_bytes = nil_qc.to_canonical_bytes();
    let effect = state
        .decide_precommit_for_nil_quorum(&round_one, &nil_bytes)
        .unwrap();

    assert_eq!(effect.role(), ConsensusVoteRole::Precommit);
    assert_eq!(effect.target(), ConsensusVoteTarget::Nil);
    assert_eq!(state.locked_value(), None);
    assert_eq!(valid_snapshot(&state), valid_before);
}

#[test]
fn missing_current_quorum_preserves_lock_and_valid_value() {
    let (branch, signing_key, context) = fixture(0x17);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x46);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);
    let lock_before = state.locked_value();
    let valid_before = valid_snapshot(&state);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let _ = state.decide_precommit_without_quorum().unwrap();

    assert_eq!(state.locked_value(), lock_before);
    assert_eq!(valid_snapshot(&state), valid_before);
}

#[test]
fn current_proposal_quorum_relocks_and_supersedes_valid_proof() {
    let (branch, signing_key, context) = fixture(0x18);
    let round_zero = branch.begin_round_zero().unwrap();
    let first = value(&round_zero, 0x47);
    let second = value(&round_zero, 0x57);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, first, context, &signing_key);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let round_one_snapshot = snapshot(context, state.position(), &signing_key);
    let nil_qc = quorum(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &signing_key,
        &round_one_snapshot,
    );
    let nil_bytes = nil_qc.to_canonical_bytes();
    let _ = state
        .decide_precommit_for_nil_quorum(&round_one, &nil_bytes)
        .unwrap();
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value().unwrap().value(), first);

    let round_two = round_one.advance_round().unwrap();
    state.advance_round(&round_two).unwrap();
    let _ = state
        .decide_prevote_for_observation(proposal_observation(&state, second, None))
        .unwrap();
    let current_snapshot = snapshot(context, state.position(), &signing_key);
    let second_qc = quorum(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(second.proposal_signing_root()),
        &signing_key,
        &current_snapshot,
    );
    let canonical = second_qc.to_canonical_bytes();
    let effect = state
        .decide_precommit_for_proposal_observation(
            proposal_observation(&state, second, None),
            PrevoteQuorumObservation::from_verified(&second_qc, canonical.clone()),
        )
        .unwrap();

    assert_eq!(
        effect.target(),
        ConsensusVoteTarget::Proposal(second.proposal_signing_root())
    );
    assert_eq!(state.locked_value().unwrap().value(), second);
    assert_eq!(
        state.locked_value().unwrap().round(),
        ConsensusRound::new(2)
    );
    assert_eq!(state.valid_value().unwrap().value(), second);
    assert_eq!(state.valid_value().unwrap().round(), ConsensusRound::new(2));
    assert_eq!(
        state.valid_value().unwrap().canonical_prevote_certificate(),
        canonical
    );
}

#[test]
fn sequential_advance_preserves_state_and_rejects_skip_or_other_branch() {
    let (branch, signing_key, context) = fixture(0x19);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x48);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);
    let lock_before = state.locked_value();
    let valid_before = valid_snapshot(&state);

    let round_one = round_zero.advance_round().unwrap();
    let round_two = round_one.advance_round().unwrap();
    assert_eq!(
        state.advance_round(&round_two),
        Err(FixedValidatorLockStateError::NonSequentialRound {
            expected: ConsensusPosition::new(ConsensusHeight::new(1), ConsensusRound::new(1)),
            actual: ConsensusPosition::new(ConsensusHeight::new(1), ConsensusRound::new(2)),
        })
    );
    assert_eq!(state.position().round(), ConsensusRound::new(0));
    assert_eq!(state.locked_value(), lock_before);
    assert_eq!(valid_snapshot(&state), valid_before);

    let (other_branch, _, _) = fixture(0x29);
    let other_round_one = other_branch
        .begin_round_zero()
        .unwrap()
        .advance_round()
        .unwrap();
    assert_eq!(
        state.advance_round(&other_round_one),
        Err(FixedValidatorLockStateError::RoundBranchMismatch)
    );
    assert_eq!(state.position().round(), ConsensusRound::new(0));

    let valid_round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    state.advance_round(&valid_round_one).unwrap();
    assert_eq!(state.position().round(), ConsensusRound::new(1));
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(state.locked_value(), lock_before);
    assert_eq!(valid_snapshot(&state), valid_before);
}

#[test]
fn wrong_quorum_target_leaves_phase_lock_and_valid_unchanged() {
    let (branch, signing_key, context) = fixture(0x1a);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x49);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let _ = state
        .decide_prevote_for_observation(proposal_observation(&state, proposed, None))
        .unwrap();
    let before_lock = state.locked_value();
    let before_valid = valid_snapshot(&state);
    let current_snapshot = snapshot(context, state.position(), &signing_key);
    let nil_qc = quorum(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &signing_key,
        &current_snapshot,
    );
    let error = state
        .decide_precommit_for_proposal_observation(
            proposal_observation(&state, proposed, None),
            PrevoteQuorumObservation::from_verified(&nil_qc, nil_qc.to_canonical_bytes()),
        )
        .unwrap_err();

    assert_eq!(
        error,
        FixedValidatorLockStateError::QuorumTargetMismatch {
            expected: ConsensusVoteTarget::Proposal(proposed.proposal_signing_root()),
            actual: ConsensusVoteTarget::Nil,
        }
    );
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(state.locked_value(), before_lock);
    assert_eq!(valid_snapshot(&state), before_valid);
}

#[test]
fn round_bound_quorum_rejects_another_fixed_set_without_mutation() {
    let attacker = signing_key(0xee);
    let (branch, validator_key, context) = fixture(0x1c);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x4a);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &validator_key);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let before_lock = state.locked_value();
    let before_valid = valid_snapshot(&state);

    let attacker_certificate = certificate_bytes(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &attacker,
    );
    let error = state
        .decide_precommit_for_nil_quorum(&round_one, &attacker_certificate)
        .unwrap_err();

    assert_eq!(
        error,
        FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::UnknownSigner {
                signer: consensus_key(&attacker),
            }
        )
    );
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(state.locked_value(), before_lock);
    assert_eq!(valid_snapshot(&state), before_valid);
}

#[test]
fn quorum_context_position_and_role_errors_are_all_or_nothing() {
    let (branch, signing_key, context) = fixture(0x1d);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x4b);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let before_lock = state.locked_value();
    let before_valid = valid_snapshot(&state);

    let wrong_context = ConsensusContextV0::new(
        naome_chain::ArtifactChainId::from_bytes([0xfe; 32]),
        context.genesis_id(),
        context.protocol_version(),
    );
    let wrong_context_certificate = certificate_bytes(
        wrong_context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &signing_key,
    );
    assert_eq!(
        state.decide_precommit_for_nil_quorum(&round_one, &wrong_context_certificate),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::ChainIdMismatch {
                expected: context.chain_id(),
                actual: wrong_context.chain_id(),
            }
        ))
    );

    let prior_position = ConsensusPosition::new(state.position().height(), ConsensusRound::new(0));
    let prior_round_certificate = certificate_bytes(
        context,
        prior_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &signing_key,
    );
    assert_eq!(
        state.decide_precommit_for_nil_quorum(&round_one, &prior_round_certificate),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::SnapshotPositionMismatch {
                certificate: prior_position,
                snapshot: state.position(),
            }
        ))
    );

    let precommit_certificate = certificate_bytes(
        context,
        state.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &signing_key,
    );
    assert_eq!(
        state.decide_precommit_for_nil_quorum(&round_one, &precommit_certificate),
        Err(FixedValidatorLockStateError::QuorumRoleMismatch {
            actual: ConsensusVoteRole::Precommit,
        })
    );

    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Prevote);
    assert_eq!(state.locked_value(), before_lock);
    assert_eq!(valid_snapshot(&state), before_valid);
}

fn assert_lock_implies_at_least_as_new_valid(state: &FixedValidatorLockStateV0) {
    if let Some(locked) = state.locked_value() {
        let valid = state
            .valid_value()
            .expect("every reachable lock has retained quorum evidence");
        assert!(valid.round() >= locked.round());
    }
}

#[test]
fn reachable_transitions_preserve_lock_valid_round_invariant() {
    let (branch, signing_key, context) = fixture(0x1e);
    let round_zero = branch.begin_round_zero().unwrap();
    let first = value(&round_zero, 0x4c);
    let second = value(&round_zero, 0x5c);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, first, context, &signing_key);
    assert_lock_implies_at_least_as_new_valid(&state);

    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    assert_lock_implies_at_least_as_new_valid(&state);
    let _ = state.decide_prevote_without_proposal().unwrap();
    let _ = state.decide_precommit_without_quorum().unwrap();
    assert_lock_implies_at_least_as_new_valid(&state);

    let round_two = round_one.advance_round().unwrap();
    state.advance_round(&round_two).unwrap();
    let round_one_snapshot = snapshot(
        context,
        ConsensusPosition::new(state.position().height(), ConsensusRound::new(1)),
        &signing_key,
    );
    let first_p1 = quorum(
        context,
        round_one_snapshot.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(first.proposal_signing_root()),
        &signing_key,
        &round_one_snapshot,
    );
    let first_p1_bytes = first_p1.to_canonical_bytes();
    let _ = state
        .decide_prevote_for_observation(proposal_observation(
            &state,
            first,
            Some((ConsensusRound::new(1), first_p1.id(), &first_p1_bytes)),
        ))
        .unwrap();
    assert_eq!(
        state.locked_value().unwrap().round(),
        ConsensusRound::new(0)
    );
    assert_eq!(state.valid_value().unwrap().round(), ConsensusRound::new(1));
    assert_lock_implies_at_least_as_new_valid(&state);
    let _ = state.decide_precommit_without_quorum().unwrap();

    let round_three = round_two.advance_round().unwrap();
    state.advance_round(&round_three).unwrap();
    let round_two_snapshot = snapshot(
        context,
        ConsensusPosition::new(state.position().height(), ConsensusRound::new(2)),
        &signing_key,
    );
    let second_p2 = quorum(
        context,
        round_two_snapshot.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(second.proposal_signing_root()),
        &signing_key,
        &round_two_snapshot,
    );
    let second_p2_bytes = second_p2.to_canonical_bytes();
    let second_proposal = proposal_observation(
        &state,
        second,
        Some((ConsensusRound::new(2), second_p2.id(), &second_p2_bytes)),
    );
    let _ = state
        .decide_prevote_for_observation(second_proposal)
        .unwrap();
    assert_eq!(state.locked_value(), None);

    let round_three_snapshot = snapshot(context, state.position(), &signing_key);
    let second_p3 = quorum(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(second.proposal_signing_root()),
        &signing_key,
        &round_three_snapshot,
    );
    let second_p3_bytes = second_p3.to_canonical_bytes();
    let second_proposal = proposal_observation(
        &state,
        second,
        Some((ConsensusRound::new(2), second_p2.id(), &second_p2_bytes)),
    );
    let _ = state
        .decide_precommit_for_proposal_observation(
            second_proposal,
            PrevoteQuorumObservation::from_verified(&second_p3, second_p3_bytes),
        )
        .unwrap();
    assert_lock_implies_at_least_as_new_valid(&state);

    let round_four = round_three.advance_round().unwrap();
    state.advance_round(&round_four).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let round_four_nil = certificate_bytes(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &signing_key,
    );
    let _ = state
        .decide_precommit_for_nil_quorum(&round_four, &round_four_nil)
        .unwrap();
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value().unwrap().round(), ConsensusRound::new(3));
    assert_lock_implies_at_least_as_new_valid(&state);
}

#[test]
fn later_round_cannot_initialize_empty_state() {
    let (branch, _, _) = fixture(0x1b);
    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    assert!(matches!(
        FixedValidatorLockStateV0::try_from_round_zero(&round_one),
        Err(FixedValidatorLockStateError::InitialRoundNotZero { actual })
            if actual == ConsensusRound::new(1)
    ));
}
