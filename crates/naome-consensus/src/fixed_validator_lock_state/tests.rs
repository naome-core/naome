use ed25519_dalek::{Signer, SigningKey};
use naome_chain::{
    ArtifactBlock, ArtifactBlockId, ArtifactChainDefinition, ArtifactChainState, ArtifactDag,
    ArtifactSetRoot,
};
use naome_foundation::ZfcAxiom;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};

use super::*;
use crate::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementWeight, ConsensusGenesisId,
    ConsensusHeight, ConsensusKey, ConsensusProtocolVersion, FixedConsensusBranchV0,
    FixedValidatorProposalIntentErrorV0, FixedValidatorProposalSourceV0,
    ObservedFixedValidatorProposalIntentV0, VerifiedProducerAuthorizationV0,
};

const VOTE_BODY_BYTES: usize = 118;
const AUTHORIZATION_BODY_BYTES: usize = 116;

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

fn three_validator_fixture(
    chain_seed: u8,
) -> (FixedConsensusBranchV0, [SigningKey; 3], ConsensusContextV0) {
    let definition = ArtifactChainDefinition::new([chain_seed; 32]);
    let context = context(definition.id());
    let signing_keys = [
        signing_key(chain_seed),
        signing_key(chain_seed.wrapping_add(1)),
        signing_key(chain_seed.wrapping_add(2)),
    ];
    let mut entries = signing_keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.consensus_key()
            .as_bytes()
            .cmp(right.consensus_key().as_bytes())
    });
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &entries,
        ArtifactChainState::new(definition).branch_snapshot(),
    )
    .unwrap();
    (branch, signing_keys, context)
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
    certificate_bytes_for_signers(context, position, role, target, &[signing_key])
}

fn certificate_bytes_for_signers(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signing_keys: &[&SigningKey],
) -> Vec<u8> {
    let body = vote_body(context, position, role, target);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut signatures = signing_keys
        .iter()
        .map(|signing_key| {
            let signer = consensus_key(signing_key);
            let mut transcript = Vec::new();
            transcript.extend_from_slice(domain);
            transcript.extend_from_slice(&body);
            transcript.extend_from_slice(signer.as_bytes());
            let signature = signing_key.sign(&transcript).to_bytes();
            (signer, signature)
        })
        .collect::<Vec<_>>();
    signatures.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(
        &u16::try_from(signatures.len())
            .expect("test certificate signer count fits u16")
            .to_be_bytes(),
    );
    for (signer, signature) in signatures {
        bytes.extend_from_slice(signer.as_bytes());
        bytes.extend_from_slice(&signature);
    }
    bytes
}

fn authorization_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    root: ProposalSigningRoot,
    proposer: &SigningKey,
) -> Vec<u8> {
    let mut body = [0_u8; AUTHORIZATION_BODY_BYTES];
    body[..32].copy_from_slice(context.chain_id().as_bytes());
    body[32..64].copy_from_slice(context.genesis_id().as_bytes());
    body[64..68].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[68..76].copy_from_slice(&position.height().value().to_be_bytes());
    body[76..84].copy_from_slice(&position.round().value().to_be_bytes());
    body[84..].copy_from_slice(root.as_bytes());

    let proposer_key = consensus_key(proposer);
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"naome:consensus-producer-authorization:v0\0");
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(proposer_key.as_bytes());

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(proposer_key.as_bytes());
    bytes.extend_from_slice(&proposer.sign(&transcript).to_bytes());
    bytes
}

fn proof_payload() -> Vec<u8> {
    let certificate = ProofCertificate::new(vec![ProofStep::ZfcAxiom(ZfcAxiom::Pairing)])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone();
    ArtifactPayload::Proof(certificate).to_canonical_bytes()
}

fn artifact_id_for(payload: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.to_vec())
        .unwrap()
        .artifact_id()
}

fn proposal_candidate(chain_seed: u8) -> (ArtifactBlock, Vec<u8>) {
    let payload = proof_payload();
    let block = ArtifactChainState::new(ArtifactChainDefinition::new([chain_seed; 32]))
        .prepare_block(artifact_id_for(&payload))
        .unwrap();
    (block, payload)
}

#[test]
fn proposal_intent_authors_one_fully_validated_fresh_value() {
    let chain_seed = 0x72;
    let (branch, signing_key, context) = fixture(chain_seed);
    let round = branch.begin_round_zero().unwrap();
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
    let (artifact_block, payload) = proposal_candidate(chain_seed);
    let intent = state
        .prepare_proposal_intent(
            &round,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block,
                canonical_artifact_bytes: payload.clone(),
            },
            consensus_key(&signing_key),
        )
        .unwrap();
    let observed = ObservedFixedValidatorProposalIntentV0::decode_and_verify(
        intent.canonical_intent_bytes(),
        context,
        branch.fixed_agreement_set_id(),
        consensus_key(&signing_key),
    )
    .unwrap();
    let signature =
        ConsensusSignature::from_bytes(signing_key.sign(&intent.signing_transcript()).to_bytes());
    let completed = intent.complete_with_signature(signature).unwrap();
    let proposal_control = completed.canonical_proposal_control_bytes();
    let authorization_start = ConsensusValueV0::BYTE_LENGTH;
    let authorization_end = authorization_start + VerifiedProducerAuthorizationV0::BYTE_LENGTH;
    let recovered = observed
        .verify_completed_producer_authorization(
            &proposal_control[authorization_start..authorization_end],
        )
        .unwrap();
    let verified = round
        .decode_and_verify_proposal_control(proposal_control, payload)
        .unwrap();

    let mut oversized_authorization =
        proposal_control[authorization_start..authorization_end].to_vec();
    oversized_authorization.push(0);
    assert!(matches!(
        observed.verify_completed_producer_authorization(&oversized_authorization),
        Err(FixedValidatorProposalIntentErrorV0::InvalidProducerAuthorizationLength {
            actual,
            expected,
        }) if actual == VerifiedProducerAuthorizationV0::BYTE_LENGTH + 1
            && expected == VerifiedProducerAuthorizationV0::BYTE_LENGTH
    ));
    let minimum_control_length =
        ConsensusValueV0::BYTE_LENGTH + VerifiedProducerAuthorizationV0::BYTE_LENGTH + 1;
    assert!(matches!(
        observed.verify_completed_proposal_control(&vec![0; minimum_control_length - 1]),
        Err(FixedValidatorProposalIntentErrorV0::InvalidCompletionLength {
            actual,
            minimum,
        }) if actual == minimum_control_length - 1 && minimum == minimum_control_length
    ));

    assert_eq!(observed.position(), round.position());
    assert_eq!(
        recovered.canonical_proposal_control_bytes(),
        proposal_control
    );
    assert_eq!(observed.value(), verified.value());
    assert_eq!(completed.proposer(), consensus_key(&signing_key));
    assert_eq!(verified.valid_round(), None);
}

#[test]
fn proposal_intent_rejects_unscheduled_signer_before_artifact_validation() {
    let (branch, signing_keys, _) = three_validator_fixture(0x73);
    let round = branch.begin_round_zero().unwrap();
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round).unwrap();
    let unscheduled = signing_keys
        .iter()
        .find(|key| consensus_key(key) != round.proposer())
        .unwrap();
    let invalid_block = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0x91; 32]),
        ArtifactSetRoot::from_bytes([0x92; 32]),
        ArtifactSetRoot::from_bytes([0x93; 32]),
        ArtifactId::from_bytes([0x94; 32]),
    );

    assert!(matches!(
        state.prepare_proposal_intent(
            &round,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block: invalid_block,
                canonical_artifact_bytes: Vec::new(),
            },
            consensus_key(unscheduled),
        ),
        Err(FixedValidatorProposalIntentErrorV0::NotScheduledProposer {
            scheduled,
            signer,
        }) if scheduled == round.proposer() && signer == consensus_key(unscheduled)
    ));
}

#[test]
fn proposal_intent_reauthors_exact_retained_value_and_prevote_proof() {
    let chain_seed = 0x74;
    let (branch, signing_key, context) = fixture(chain_seed);
    let round_zero = branch.begin_round_zero().unwrap();
    let (artifact_block, payload) = proposal_candidate(chain_seed);
    let value = round_zero.value_for_artifact_block(artifact_block);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, value, context, &signing_key);
    let retained_certificate = state
        .valid_value()
        .unwrap()
        .canonical_prevote_certificate()
        .to_vec();
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();

    assert!(matches!(
        state.prepare_proposal_intent(
            &round_one,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block,
                canonical_artifact_bytes: payload.clone(),
            },
            consensus_key(&signing_key),
        ),
        Err(FixedValidatorProposalIntentErrorV0::RetainedValidValueRequired)
    ));

    let intent = state
        .prepare_proposal_intent(
            &round_one,
            FixedValidatorProposalSourceV0::RetainedValid {
                canonical_artifact_bytes: payload.clone(),
            },
            consensus_key(&signing_key),
        )
        .unwrap();
    let signature =
        ConsensusSignature::from_bytes(signing_key.sign(&intent.signing_transcript()).to_bytes());
    let completed = intent.complete_with_signature(signature).unwrap();
    let verified = round_one
        .decode_and_verify_proposal_control(completed.canonical_proposal_control_bytes(), payload)
        .unwrap();

    assert_eq!(verified.value(), value);
    assert_eq!(verified.valid_round(), Some(ConsensusRound::new(0)));
    assert_eq!(
        verified.valid_round_certificate_bytes(),
        Some(retained_certificate.as_slice())
    );
}

fn owned_transition(chain_seed: u8) -> OwnedVerifiedFixedConsensusTransitionV0 {
    let definition = ArtifactChainDefinition::new([chain_seed; 32]);
    let context = context(definition.id());
    let proposer = signing_key(chain_seed);
    let payload = proof_payload();
    let artifact_state = ArtifactChainState::new(definition);
    let block = artifact_state
        .prepare_block(artifact_id_for(&payload))
        .unwrap();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        context,
        &[ActiveAgreementEntry::new(
            consensus_key(&proposer),
            AgreementWeight::new(1),
        )],
        artifact_state.branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let value = round.value_for_artifact_block(block);
    let root = value.proposal_signing_root();
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&value.to_canonical_bytes());
    envelope.extend_from_slice(&authorization_bytes(
        context,
        round.position(),
        root,
        &proposer,
    ));
    envelope.extend_from_slice(&certificate_bytes(
        context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &proposer,
    ));
    round
        .decode_and_verify(&envelope, payload)
        .unwrap()
        .into_owned()
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

type ValidSnapshot = (
    ConsensusValueV0,
    ConsensusRound,
    QuorumCertificateId,
    Vec<u8>,
);

type LockStateSnapshot = (
    ConsensusPosition,
    FixedValidatorLockPhaseV0,
    Option<FixedValidatorLockedValueV0>,
    Option<ValidSnapshot>,
);

fn valid_snapshot(state: &FixedValidatorLockStateV0) -> Option<ValidSnapshot> {
    state.valid_value().map(|valid| {
        (
            valid.value(),
            valid.round(),
            valid.prevote_certificate_id(),
            valid.canonical_prevote_certificate().to_vec(),
        )
    })
}

fn lock_state_snapshot(state: &FixedValidatorLockStateV0) -> LockStateSnapshot {
    (
        state.position(),
        state.phase(),
        state.locked_value(),
        valid_snapshot(state),
    )
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
fn nil_precommit_quorum_preempts_every_phase_and_preserves_lock_and_valid_proof() {
    for (case, phase) in [
        FixedValidatorLockPhaseV0::Proposal,
        FixedValidatorLockPhaseV0::Prevote,
        FixedValidatorLockPhaseV0::Precommit,
    ]
    .into_iter()
    .enumerate()
    {
        let (branch, signing_key, context) = fixture(0x60 + case as u8);
        let round_zero = branch.begin_round_zero().unwrap();
        let proposed = value(&round_zero, 0x70 + case as u8);
        let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
        lock_current_proposal(&mut state, proposed, context, &signing_key);
        let round_one = round_zero.advance_round().unwrap();
        state.advance_round(&round_one).unwrap();

        let stale_effect = match phase {
            FixedValidatorLockPhaseV0::Proposal => None,
            FixedValidatorLockPhaseV0::Prevote => {
                Some(state.decide_prevote_without_proposal().unwrap())
            }
            FixedValidatorLockPhaseV0::Precommit => {
                let _ = state.decide_prevote_without_proposal().unwrap();
                Some(state.decide_precommit_without_quorum().unwrap())
            }
        };
        assert_eq!(state.phase(), phase);
        let before_lock = state.locked_value();
        let before_valid = valid_snapshot(&state);
        let certificate = certificate_bytes(
            context,
            round_one.position(),
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Nil,
            &signing_key,
        );

        let round_two = state
            .advance_round_for_nil_precommit_quorum(&round_one, &certificate)
            .unwrap();

        let expected = ConsensusPosition::new(
            round_one.position().height(),
            ConsensusRound::new(round_one.position().round().value() + 1),
        );
        assert_eq!(round_two.position(), expected);
        assert_eq!(state.position(), expected);
        assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
        assert_eq!(state.locked_value(), before_lock);
        assert_eq!(valid_snapshot(&state), before_valid);
        if let Some(stale_effect) = stale_effect {
            assert!(matches!(
                state.prepare_vote_intent(&round_two, stale_effect, consensus_key(&signing_key),),
                Err(FixedValidatorVoteIntentError::EffectStateMismatch)
            ));
        }
    }
}

#[test]
fn nil_precommit_quorum_rejects_wrong_evidence_and_current_cursor_without_mutation() {
    let (branch, validator_key, context) = fixture(0x64);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x74);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &validator_key);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();

    let wrong_role = certificate_bytes(
        context,
        round_one.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &validator_key,
    );
    let before = lock_state_snapshot(&state);
    assert_eq!(
        state
            .advance_round_for_nil_precommit_quorum(&round_one, &wrong_role)
            .err()
            .expect("prevote evidence must not advance a round"),
        FixedValidatorLockStateError::NilPrecommitQuorumRoleMismatch {
            actual: ConsensusVoteRole::Prevote,
        }
    );
    assert_eq!(lock_state_snapshot(&state), before);

    let wrong_target = certificate_bytes(
        context,
        round_one.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(proposed.proposal_signing_root()),
        &validator_key,
    );
    let before = lock_state_snapshot(&state);
    assert_eq!(
        state
            .advance_round_for_nil_precommit_quorum(&round_one, &wrong_target)
            .err()
            .expect("proposal precommit evidence belongs to finality"),
        FixedValidatorLockStateError::NilPrecommitQuorumTargetMismatch {
            actual: ConsensusVoteTarget::Proposal(proposed.proposal_signing_root()),
        }
    );
    assert_eq!(lock_state_snapshot(&state), before);

    let stale_position = ConsensusPosition::new(
        round_one.position().height(),
        ConsensusRound::new(round_one.position().round().value() - 1),
    );
    let stale = certificate_bytes(
        context,
        stale_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &validator_key,
    );
    let before = lock_state_snapshot(&state);
    assert_eq!(
        state
            .advance_round_for_nil_precommit_quorum(&round_one, &stale)
            .err()
            .expect("stale precommit evidence must not advance a round"),
        FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::SnapshotPositionMismatch {
                certificate: stale_position,
                snapshot: round_one.position(),
            }
        )
    );
    assert_eq!(lock_state_snapshot(&state), before);

    let wrong_context = ConsensusContextV0::new(
        naome_chain::ArtifactChainId::from_bytes([0xfe; 32]),
        context.genesis_id(),
        context.protocol_version(),
    );
    let foreign_context = certificate_bytes(
        wrong_context,
        round_one.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &validator_key,
    );
    let before = lock_state_snapshot(&state);
    assert!(matches!(
        state.advance_round_for_nil_precommit_quorum(&round_one, &foreign_context),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::ChainIdMismatch { .. }
        ))
    ));
    assert_eq!(lock_state_snapshot(&state), before);

    let outsider = signing_key(0xee);
    let foreign_set = certificate_bytes(
        context,
        round_one.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &outsider,
    );
    let before = lock_state_snapshot(&state);
    assert_eq!(
        state
            .advance_round_for_nil_precommit_quorum(&round_one, &foreign_set)
            .err()
            .expect("another fixed set must not advance a round"),
        FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::UnknownSigner {
                signer: consensus_key(&outsider),
            }
        )
    );
    assert_eq!(lock_state_snapshot(&state), before);

    let (other_branch, _, _) = fixture(0x65);
    let other_round_one = other_branch
        .begin_round_zero()
        .unwrap()
        .advance_round()
        .unwrap();
    let before = lock_state_snapshot(&state);
    assert_eq!(
        state
            .advance_round_for_nil_precommit_quorum(&other_round_one, &[])
            .err()
            .expect("another current branch must fail before certificate decoding"),
        FixedValidatorLockStateError::CurrentRoundBranchMismatch
    );
    assert_eq!(lock_state_snapshot(&state), before);

    let valid = certificate_bytes(
        context,
        round_one.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &validator_key,
    );
    let round_two = state
        .advance_round_for_nil_precommit_quorum(&round_one, &valid)
        .unwrap();
    let advanced = lock_state_snapshot(&state);
    assert_eq!(
        state
            .advance_round_for_nil_precommit_quorum(&round_one, &valid)
            .err()
            .expect("the old current cursor must become stale"),
        FixedValidatorLockStateError::CurrentRoundPositionMismatch {
            expected: round_two.position(),
            actual: round_one.position(),
        }
    );
    assert_eq!(lock_state_snapshot(&state), advanced);
}

#[test]
fn nil_precommit_round_advance_strictly_verifies_threshold_framing_and_signature() {
    let (branch, signing_keys, context) = three_validator_fixture(0x66);
    let round_zero = branch.begin_round_zero().unwrap();
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let before = lock_state_snapshot(&state);

    let exact_two_thirds = certificate_bytes_for_signers(
        context,
        round_zero.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1]],
    );
    assert_eq!(
        state
            .advance_round_for_nil_precommit_quorum(&round_zero, &exact_two_thirds)
            .err()
            .expect("exactly two thirds is not a strict quorum"),
        FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::InsufficientAgreementWeight {
                signed: AgreementWeight::new(2),
                total: AgreementWeight::new(3),
            }
        )
    );
    assert_eq!(lock_state_snapshot(&state), before);

    let complete = certificate_bytes_for_signers(
        context,
        round_zero.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    );
    assert!(matches!(
        state.advance_round_for_nil_precommit_quorum(&round_zero, &[]),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::InvalidLength { .. }
        ))
    ));
    assert_eq!(lock_state_snapshot(&state), before);

    let mut trailing = complete.clone();
    trailing.push(0);
    assert!(matches!(
        state.advance_round_for_nil_precommit_quorum(&round_zero, &trailing),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::LengthMismatch { .. }
        ))
    ));
    assert_eq!(lock_state_snapshot(&state), before);

    let mut invalid_signature = complete.clone();
    *invalid_signature.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        state.advance_round_for_nil_precommit_quorum(&round_zero, &invalid_signature),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::InvalidSignature { .. }
        ))
    ));
    assert_eq!(lock_state_snapshot(&state), before);

    let round_one = state
        .advance_round_for_nil_precommit_quorum(&round_zero, &complete)
        .unwrap();
    assert_eq!(state.position(), round_one.position());
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), None);
}

#[test]
fn higher_round_quorums_cross_every_phase_role_target_and_preserve_exact_state() {
    let mut case = 0_u8;
    for phase in [
        FixedValidatorLockPhaseV0::Proposal,
        FixedValidatorLockPhaseV0::Prevote,
        FixedValidatorLockPhaseV0::Precommit,
    ] {
        for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
            for proposal_target in [false, true] {
                for target_round_value in [2_u64, 4] {
                    let (branch, signing_key, context) = fixture(0x80_u8.wrapping_add(case));
                    case = case.wrapping_add(1);
                    let round_zero = branch.begin_round_zero().unwrap();
                    let proposed = value(&round_zero, 0xa0_u8.wrapping_add(case));
                    let mut state =
                        FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
                    lock_current_proposal(&mut state, proposed, context, &signing_key);
                    let round_one = round_zero.advance_round().unwrap();
                    state.advance_round(&round_one).unwrap();
                    let stale_effect = match phase {
                        FixedValidatorLockPhaseV0::Proposal => None,
                        FixedValidatorLockPhaseV0::Prevote => {
                            Some(state.decide_prevote_without_proposal().unwrap())
                        }
                        FixedValidatorLockPhaseV0::Precommit => {
                            let _ = state.decide_prevote_without_proposal().unwrap();
                            Some(state.decide_precommit_without_quorum().unwrap())
                        }
                    };
                    let target = if proposal_target {
                        ConsensusVoteTarget::Proposal(proposed.proposal_signing_root())
                    } else {
                        ConsensusVoteTarget::Nil
                    };
                    let target_position = ConsensusPosition::new(
                        round_one.position().height(),
                        ConsensusRound::new(target_round_value),
                    );
                    let certificate =
                        certificate_bytes(context, target_position, role, target, &signing_key);
                    let before = lock_state_snapshot(&state);

                    let prepared = state
                        .prepare_higher_round_quorum_advance(
                            &round_one,
                            &certificate,
                            ConsensusRound::new(target_round_value),
                        )
                        .unwrap();
                    assert_eq!(lock_state_snapshot(&state), before);
                    assert_eq!(prepared.position(), target_position);
                    assert_eq!(prepared.phase(), phase_for_role(role));
                    assert_eq!(prepared.role(), role);
                    assert_eq!(prepared.target(), target);
                    assert_eq!(prepared.canonical_certificate(), certificate);
                    let checkpoint_bytes = prepared.canonical_checkpoint_bytes().to_vec();

                    let target_round = state
                        .apply_prepared_higher_round_quorum_advance(prepared)
                        .unwrap();
                    assert_eq!(target_round.position(), target_position);
                    assert_eq!(state.position(), target_position);
                    assert_eq!(state.phase(), phase_for_role(role));
                    assert_eq!(state.locked_value(), before.2);
                    assert_eq!(valid_snapshot(&state), before.3);

                    let observed =
                        ObservedFixedValidatorHigherRoundCheckpointV0::decode_and_verify(
                            &checkpoint_bytes,
                            context,
                            target_round.parent_coordinate().fixed_agreement_set_id(),
                        )
                        .unwrap();
                    assert_eq!(observed.source_position(), round_one.position());
                    assert_eq!(observed.source_phase(), phase);
                    assert_eq!(observed.position(), target_position);
                    assert_eq!(observed.canonical_certificate(), certificate);
                    let replayed = observed.verify_for_round(&target_round).unwrap();
                    assert_eq!(
                        lock_state_snapshot(replayed.lock_state()),
                        lock_state_snapshot(&state)
                    );

                    if let Some(stale_effect) = stale_effect {
                        assert!(matches!(
                            state.prepare_vote_intent(
                                &target_round,
                                stale_effect,
                                consensus_key(&signing_key),
                            ),
                            Err(FixedValidatorVoteIntentError::EffectStateMismatch)
                                | Err(FixedValidatorVoteIntentError::EffectPositionMismatch { .. })
                        ));
                    }
                }
            }
        }
    }
}

#[test]
fn higher_round_prepare_rejects_routing_bounds_and_invalid_quorum_without_mutation() {
    let (branch, signing_keys, context) = three_validator_fixture(0x98);
    let round_zero = branch.begin_round_zero().unwrap();
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let before = lock_state_snapshot(&state);
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(3));
    let complete = certificate_bytes_for_signers(
        context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    );

    assert_eq!(
        state
            .prepare_higher_round_quorum_advance(&round_zero, &complete, ConsensusRound::new(0),)
            .err()
            .unwrap(),
        FixedValidatorLockStateError::HigherRoundWorkLimitNotPositive
    );
    assert_eq!(lock_state_snapshot(&state), before);

    let same_round = certificate_bytes_for_signers(
        context,
        round_zero.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    );
    assert_eq!(
        state
            .prepare_higher_round_quorum_advance(&round_zero, &same_round, ConsensusRound::new(3),)
            .err()
            .unwrap(),
        FixedValidatorLockStateError::HigherRoundNotStrictlyGreater {
            current: ConsensusRound::new(0),
            actual: ConsensusRound::new(0),
        }
    );

    let mut later_state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let round_one_certificate = certificate_bytes_for_signers(
        context,
        round_zero.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    );
    let round_one = later_state
        .advance_round_for_nil_precommit_quorum(&round_zero, &round_one_certificate)
        .unwrap();
    let round_two_certificate = certificate_bytes_for_signers(
        context,
        round_one.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    );
    let round_two = later_state
        .advance_round_for_nil_precommit_quorum(&round_one, &round_two_certificate)
        .unwrap();
    let stale_certificate = certificate_bytes_for_signers(
        context,
        round_one.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    );
    let later_before = lock_state_snapshot(&later_state);
    assert_eq!(
        later_state
            .prepare_higher_round_quorum_advance(
                &round_two,
                &stale_certificate,
                ConsensusRound::new(3),
            )
            .err()
            .unwrap(),
        FixedValidatorLockStateError::HigherRoundNotStrictlyGreater {
            current: ConsensusRound::new(2),
            actual: ConsensusRound::new(1),
        }
    );
    assert_eq!(lock_state_snapshot(&later_state), later_before);

    let wrong_height = ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(3));
    let wrong_height_certificate = certificate_bytes_for_signers(
        context,
        wrong_height,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    );
    assert_eq!(
        state
            .prepare_higher_round_quorum_advance(
                &round_zero,
                &wrong_height_certificate,
                ConsensusRound::new(3),
            )
            .err()
            .unwrap(),
        FixedValidatorLockStateError::HigherRoundHeightMismatch {
            expected: ConsensusHeight::new(1),
            actual: ConsensusHeight::new(2),
        }
    );

    let wrong_context = ConsensusContextV0::new(
        naome_chain::ArtifactChainId::from_bytes([0xfe; 32]),
        context.genesis_id(),
        context.protocol_version(),
    );
    let foreign_context = certificate_bytes_for_signers(
        wrong_context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1], &signing_keys[2]],
    );
    assert!(matches!(
        state.prepare_higher_round_quorum_advance(
            &round_zero,
            &foreign_context,
            ConsensusRound::new(3),
        ),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::ChainIdMismatch { .. }
        ))
    ));

    let outsider = signing_key(0xee);
    let foreign_set = certificate_bytes(
        context,
        target_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &outsider,
    );
    assert_eq!(
        state
            .prepare_higher_round_quorum_advance(&round_zero, &foreign_set, ConsensusRound::new(3),)
            .err()
            .unwrap(),
        FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::UnknownSigner {
                signer: consensus_key(&outsider),
            }
        )
    );

    let (other_branch, _, _) = fixture(0x9a);
    let other_round_zero = other_branch.begin_round_zero().unwrap();
    assert_eq!(
        state
            .prepare_higher_round_quorum_advance(&other_round_zero, &[], ConsensusRound::new(3),)
            .err()
            .unwrap(),
        FixedValidatorLockStateError::CurrentRoundBranchMismatch
    );

    let mut invalid_above_limit = complete.clone();
    *invalid_above_limit.last_mut().unwrap() ^= 0x80;
    assert_eq!(
        state
            .prepare_higher_round_quorum_advance(
                &round_zero,
                &invalid_above_limit,
                ConsensusRound::new(2),
            )
            .err()
            .unwrap(),
        FixedValidatorLockStateError::HigherRoundLimitExceeded {
            round: ConsensusRound::new(3),
            maximum: ConsensusRound::new(2),
        }
    );

    let exact_two_thirds = certificate_bytes_for_signers(
        context,
        target_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &[&signing_keys[0], &signing_keys[1]],
    );
    assert!(matches!(
        state.prepare_higher_round_quorum_advance(
            &round_zero,
            &exact_two_thirds,
            ConsensusRound::new(3),
        ),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::InsufficientAgreementWeight { .. }
        ))
    ));
    assert!(matches!(
        state.prepare_higher_round_quorum_advance(&round_zero, &[], ConsensusRound::new(3),),
        Err(
            FixedValidatorLockStateError::HigherRoundCertificatePosition(
                QuorumCertificateVerifyError::InvalidLength { .. }
            )
        )
    ));
    let mut trailing = complete.clone();
    trailing.push(0);
    assert!(matches!(
        state.prepare_higher_round_quorum_advance(&round_zero, &trailing, ConsensusRound::new(3),),
        Err(
            FixedValidatorLockStateError::HigherRoundCertificatePosition(
                QuorumCertificateVerifyError::LengthMismatch { .. }
            )
        )
    ));
    let mut invalid_signature = complete.clone();
    *invalid_signature.last_mut().unwrap() ^= 0x40;
    assert!(matches!(
        state.prepare_higher_round_quorum_advance(
            &round_zero,
            &invalid_signature,
            ConsensusRound::new(3),
        ),
        Err(FixedValidatorLockStateError::QuorumVerification(
            QuorumCertificateVerifyError::InvalidSignature { .. }
        ))
    ));
    assert_eq!(lock_state_snapshot(&state), before);
}

#[test]
fn prepared_higher_round_transition_is_single_lineage_and_exact_source_bound() {
    let (branch, signing_key, context) = fixture(0x99);
    let round_zero = branch.begin_round_zero().unwrap();
    let position = ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(2));
    let certificate = certificate_bytes(
        context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &signing_key,
    );
    let mut first = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let mut parallel = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let foreign = first
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    assert_eq!(
        parallel
            .apply_prepared_higher_round_quorum_advance(foreign)
            .err()
            .unwrap(),
        FixedValidatorLockStateError::HigherRoundAdvanceLineageMismatch
    );

    let stale = first
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let _ = first.decide_prevote_without_proposal().unwrap();
    assert_eq!(
        first
            .apply_prepared_higher_round_quorum_advance(stale)
            .err()
            .unwrap(),
        FixedValidatorLockStateError::HigherRoundAdvanceStateMismatch
    );

    let mut clean = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let winner = clean
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let loser = clean
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(2))
        .unwrap();
    let _ = clean
        .apply_prepared_higher_round_quorum_advance(winner)
        .unwrap();
    assert_eq!(
        clean
            .apply_prepared_higher_round_quorum_advance(loser)
            .err()
            .unwrap(),
        FixedValidatorLockStateError::HigherRoundAdvanceStateMismatch
    );
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

#[test]
fn verified_child_height_reset_clears_parent_lock_and_returns_exact_child() {
    let chain_seed = 0x37;
    let (branch, signing_key, context) = fixture(chain_seed);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x97);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Precommit);
    assert!(state.locked_value().is_some());
    assert!(state.valid_value().is_some());

    let transition = owned_transition(chain_seed);
    let expected_ancestry = transition.value().ancestry_id();
    let expected_child_coordinate = transition.child_coordinate();
    let position = state.position();
    let phase = state.phase();
    let locked = state.locked_value();
    let valid = valid_snapshot(&state);
    let child_round_zero_position = state.validate_height_transition(&transition).unwrap();

    assert_eq!(
        child_round_zero_position,
        ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(0))
    );
    assert_eq!(state.position(), position);
    assert_eq!(state.phase(), phase);
    assert_eq!(state.locked_value(), locked);
    assert_eq!(valid_snapshot(&state), valid);

    let child = state
        .advance_height_with_verified_transition(transition)
        .unwrap();
    let child_round_zero = child.begin_round_zero().unwrap();

    assert_eq!(child.coordinate(), expected_child_coordinate);
    assert_eq!(child.verified_height(), Some(ConsensusHeight::new(1)));
    assert_eq!(child.ancestry_id(), expected_ancestry);
    assert_eq!(state.parent_coordinate, child.coordinate());
    assert_eq!(state.position(), child_round_zero.position());
    assert_eq!(state.position().height(), ConsensusHeight::new(2));
    assert_eq!(state.position().round(), ConsensusRound::new(0));
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), None);
    state.validate_current_round(&child_round_zero).unwrap();
}

#[test]
fn verified_child_height_reset_rejects_another_parent_without_mutation() {
    let (branch, signing_key, context) = fixture(0x38);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x98);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);
    let position = state.position();
    let phase = state.phase();
    let locked = state.locked_value();
    let valid = valid_snapshot(&state);
    let transition = owned_transition(0x39);

    let validation_error = state.validate_height_transition(&transition).err().unwrap();
    assert_eq!(
        validation_error,
        FixedValidatorLockStateError::HeightTransitionParentMismatch
    );
    assert_eq!(state.position(), position);
    assert_eq!(state.phase(), phase);
    assert_eq!(state.locked_value(), locked);
    assert_eq!(valid_snapshot(&state), valid);

    let advance_error = state
        .advance_height_with_verified_transition(transition)
        .err()
        .unwrap();
    assert_eq!(advance_error, validation_error);
    assert_eq!(state.position(), position);
    assert_eq!(state.phase(), phase);
    assert_eq!(state.locked_value(), locked);
    assert_eq!(valid_snapshot(&state), valid);
}

#[test]
fn verified_child_height_reset_rejects_a_different_current_height_without_mutation() {
    let chain_seed = 0x3a;
    let (branch, _, _) = fixture(chain_seed);
    let round_zero = branch.begin_round_zero().unwrap();
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    state.position = ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(0));
    let transition = owned_transition(chain_seed);

    let validation_error = state.validate_height_transition(&transition).err().unwrap();
    assert!(matches!(
        validation_error,
        FixedValidatorLockStateError::HeightTransitionHeightMismatch {
            expected,
            actual,
        } if expected == ConsensusHeight::new(2) && actual == ConsensusHeight::new(1)
    ));
    assert_eq!(
        state.position(),
        ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(0))
    );
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), None);

    let advance_error = state
        .advance_height_with_verified_transition(transition)
        .err()
        .unwrap();
    assert_eq!(advance_error, validation_error);
    assert_eq!(
        state.position(),
        ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(0))
    );
    assert_eq!(state.phase(), FixedValidatorLockPhaseV0::Proposal);
    assert_eq!(state.locked_value(), None);
    assert_eq!(state.valid_value(), None);
}

#[test]
fn runtime_vote_intent_round_trips_and_completes_exact_existing_vote() {
    let (branch, signing_key, context) = fixture(0x31);
    let round_zero = branch.begin_round_zero().unwrap();
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let effect = state.decide_prevote_without_proposal().unwrap();
    let signer = consensus_key(&signing_key);
    let intent = state
        .prepare_vote_intent(&round_zero, effect.clone(), signer)
        .unwrap();

    assert_eq!(
        intent.canonical_state_and_vote_intent_bytes().len(),
        FixedValidatorVoteIntentV0::MIN_BYTE_LENGTH
    );
    assert_eq!(FixedValidatorVoteIntentV0::MIN_BYTE_LENGTH, 391);
    assert_eq!(FixedValidatorVoteIntentV0::MAX_BYTE_LENGTH, 25_675);
    assert_eq!(intent.context(), context);
    assert_eq!(intent.position(), round_zero.position());
    assert_eq!(intent.position(), effect.position());
    assert_eq!(intent.role(), effect.role());
    assert_eq!(intent.target(), effect.target());
    assert_eq!(intent.signer(), signer);
    assert_eq!(intent.signing_transcript().len(), 35 + 118 + 32);
    let canonical = intent.canonical_state_and_vote_intent_bytes();
    assert_eq!(&canonical[..37], VOTE_INTENT_HEADER);
    assert_eq!(&canonical[37..69], context.chain_id().as_bytes());
    assert_eq!(&canonical[69..101], context.genesis_id().as_bytes());
    assert_eq!(
        &canonical[101..105],
        &context.protocol_version().value().to_be_bytes()
    );
    assert_eq!(canonical[105], ABSENT_TAG);
    assert_eq!(&canonical[106..114], &0_u64.to_be_bytes());
    assert_eq!(canonical[322], PREVOTE_PHASE_TAG);
    assert_eq!(canonical[323], ABSENT_TAG);
    assert_eq!(canonical[324], ABSENT_TAG);
    assert_eq!(canonical[325], PREVOTE_ROLE_TAG);
    assert_eq!(canonical[326], NIL_TARGET_TAG);
    assert_eq!(&canonical[327..359], &[0_u8; 32]);
    assert_eq!(&canonical[359..391], signer.as_bytes());

    let observed = ObservedFixedValidatorVoteIntentV0::decode_and_verify(
        intent.canonical_state_and_vote_intent_bytes(),
        context,
        branch.fixed_agreement_set_id(),
        signer,
    )
    .unwrap();
    assert_eq!(
        observed.canonical_state_and_vote_intent_bytes(),
        intent.canonical_state_and_vote_intent_bytes()
    );
    let replay = observed.verify_for_round(&round_zero).unwrap();
    assert_eq!(replay.lock_state().position(), state.position());
    assert_eq!(replay.lock_state().phase(), state.phase());
    assert_eq!(replay.lock_state().locked_value(), state.locked_value());
    assert_eq!(valid_snapshot(replay.lock_state()), valid_snapshot(&state));

    let signature =
        ConsensusSignature::from_bytes(signing_key.sign(intent.signing_transcript()).to_bytes());
    let completed = intent.complete_with_signature(signature).unwrap();
    assert_eq!(completed.context(), context);
    assert_eq!(completed.position(), effect.position());
    assert_eq!(completed.role(), effect.role());
    assert_eq!(completed.target(), effect.target());
    assert_eq!(completed.signer(), signer);
    assert_eq!(completed.signature(), signature);
    assert_eq!(completed.to_canonical_bytes().len(), 214);
    assert!(matches!(
        intent.complete_with_signature(ConsensusSignature::from_bytes([0x55; 64])),
        Err(ConsensusVoteVerifyError::InvalidSignature { signer: actual }) if actual == signer
    ));
}

#[test]
fn locked_vote_intent_retains_exact_qc_and_reconstructs_only_for_exact_round() {
    let (branch, signing_key, context) = fixture(0x32);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x72);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let _ = state
        .decide_prevote_for_observation(proposal_observation(&state, proposed, None))
        .unwrap();
    let positioned = snapshot(context, state.position(), &signing_key);
    let certificate = quorum(
        context,
        state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(proposed.proposal_signing_root()),
        &signing_key,
        &positioned,
    );
    let certificate_bytes = certificate.to_canonical_bytes();
    let effect = state
        .decide_precommit_for_proposal_observation(
            proposal_observation(&state, proposed, None),
            PrevoteQuorumObservation::from_verified(&certificate, certificate_bytes.clone()),
        )
        .unwrap();
    let signer = consensus_key(&signing_key);
    let intent = state
        .prepare_vote_intent(&round_zero, effect, signer)
        .unwrap();
    assert_eq!(
        intent.canonical_state_and_vote_intent_bytes().len(),
        FixedValidatorVoteIntentV0::MIN_BYTE_LENGTH
            + LOCK_SNAPSHOT_BYTES
            + VALID_SNAPSHOT_FIXED_BYTES
            + certificate_bytes.len()
    );

    let replay = VerifiedReplayFixedValidatorVoteIntentV0::decode_and_verify_for_round(
        intent.canonical_state_and_vote_intent_bytes(),
        &round_zero,
        signer,
    )
    .unwrap();
    assert_eq!(replay.lock_state().locked_value(), state.locked_value());
    assert_eq!(
        replay
            .lock_state()
            .valid_value()
            .unwrap()
            .canonical_prevote_certificate(),
        certificate_bytes
    );

    let round_one = round_zero.advance_round().unwrap();
    assert!(matches!(
        VerifiedReplayFixedValidatorVoteIntentV0::decode_and_verify_for_round(
            intent.canonical_state_and_vote_intent_bytes(),
            &round_one,
            signer,
        ),
        Err(FixedValidatorVoteIntentError::RoundPositionMismatch { .. })
    ));

    let mut wrong_id = intent.canonical_state_and_vote_intent_bytes().to_vec();
    let certificate_start = wrong_id
        .windows(certificate_bytes.len())
        .position(|window| window == certificate_bytes)
        .unwrap();
    wrong_id[certificate_start - 4 - QuorumCertificateId::BYTE_LENGTH] ^= 0x80;
    assert!(matches!(
        ObservedFixedValidatorVoteIntentV0::decode_and_verify(
            &wrong_id,
            context,
            branch.fixed_agreement_set_id(),
            signer,
        ),
        Err(FixedValidatorVoteIntentError::RetainedCertificateIdMismatch)
    ));
}

#[test]
fn stale_effect_and_nonmember_signer_cannot_prepare_vote_intent() {
    let (branch, validator_key, context) = fixture(0x33);
    let round_zero = branch.begin_round_zero().unwrap();
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let stale_prevote = state.decide_prevote_without_proposal().unwrap();
    let current_precommit = state.decide_precommit_without_quorum().unwrap();
    let signer = consensus_key(&validator_key);

    assert!(matches!(
        state.prepare_vote_intent(&round_zero, stale_prevote, signer),
        Err(FixedValidatorVoteIntentError::EffectStateMismatch)
    ));
    assert!(
        state
            .prepare_vote_intent(&round_zero, current_precommit.clone(), signer)
            .is_ok()
    );

    let outsider = consensus_key(&signing_key(0xf3));
    assert!(matches!(
        state.prepare_vote_intent(&round_zero, current_precommit.clone(), outsider),
        Err(FixedValidatorVoteIntentError::SignerNotInFixedSet { signer: actual })
            if actual == outsider
    ));

    let proposed = value(&round_zero, 0x93);
    let mut different_state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let _ = different_state
        .decide_prevote_for_observation(proposal_observation(&different_state, proposed, None))
        .unwrap();
    let positioned = snapshot(context, different_state.position(), &validator_key);
    let certificate = quorum(
        context,
        different_state.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(proposed.proposal_signing_root()),
        &validator_key,
        &positioned,
    );
    let _ = different_state
        .decide_precommit_for_proposal_observation(
            proposal_observation(&different_state, proposed, None),
            PrevoteQuorumObservation::from_verified(&certificate, certificate.to_canonical_bytes()),
        )
        .unwrap();
    assert!(matches!(
        different_state.prepare_vote_intent(&round_zero, current_precommit, signer),
        Err(FixedValidatorVoteIntentError::EffectStateMismatch)
    ));
}

#[test]
fn same_post_state_effect_from_parallel_lineage_cannot_prepare_vote_intent() {
    let (branch, validator_key, _) = fixture(0x3a);
    let round_zero = branch.begin_round_zero().unwrap();
    let signer = consensus_key(&validator_key);

    let mut nil_lineage = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let nil_effect = nil_lineage.decide_prevote_without_proposal().unwrap();

    let proposed = value(&round_zero, 0x9a);
    let mut proposal_lineage = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let proposal_effect = proposal_lineage
        .decide_prevote_for_observation(proposal_observation(&proposal_lineage, proposed, None))
        .unwrap();

    assert_eq!(
        vote_effect_state_binding(&vote_snapshot_from_lock_state(&nil_lineage)),
        vote_effect_state_binding(&vote_snapshot_from_lock_state(&proposal_lineage))
    );
    assert_ne!(nil_effect.target(), proposal_effect.target());
    assert!(matches!(
        nil_lineage.prepare_vote_intent(&round_zero, proposal_effect, signer),
        Err(FixedValidatorVoteIntentError::EffectLineageMismatch)
    ));
    assert!(
        nil_lineage
            .prepare_vote_intent(&round_zero, nil_effect, signer)
            .is_ok()
    );
}

#[test]
fn old_lock_and_missing_current_quorum_can_prepare_nil_precommit_intent() {
    let (branch, signing_key, context) = fixture(0x35);
    let round_zero = branch.begin_round_zero().unwrap();
    let proposed = value(&round_zero, 0x95);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, proposed, context, &signing_key);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let effect = state.decide_precommit_without_quorum().unwrap();

    assert_eq!(effect.role(), ConsensusVoteRole::Precommit);
    assert_eq!(effect.target(), ConsensusVoteTarget::Nil);
    assert_eq!(
        state.locked_value().unwrap().round(),
        ConsensusRound::new(0)
    );
    let signer = consensus_key(&signing_key);
    let intent = state
        .prepare_vote_intent(&round_one, effect, signer)
        .unwrap();
    assert_eq!(intent.role(), ConsensusVoteRole::Precommit);
    assert_eq!(intent.target(), ConsensusVoteTarget::Nil);
    let replay = VerifiedReplayFixedValidatorVoteIntentV0::decode_and_verify_for_round(
        intent.canonical_state_and_vote_intent_bytes(),
        &round_one,
        signer,
    )
    .unwrap();
    assert_eq!(replay.lock_state().locked_value(), state.locked_value());
}

#[test]
fn structural_replay_rejects_unreachable_effects_and_record_bounds() {
    let (branch, signing_key, context) = fixture(0x34);
    let round_zero = branch.begin_round_zero().unwrap();
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let _ = state.decide_precommit_without_quorum().unwrap();
    let snapshot = vote_snapshot_from_lock_state(&state);
    let signer = consensus_key(&signing_key);
    let forged = FixedValidatorUnsignedVoteEffectV0::from_snapshot(
        &snapshot,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes([0x91; 32])),
    );
    let forged_bytes = encode_state_and_vote_intent(&snapshot, &forged, signer).unwrap();
    assert!(matches!(
        ObservedFixedValidatorVoteIntentV0::decode_and_verify(
            &forged_bytes,
            context,
            branch.fixed_agreement_set_id(),
            signer,
        ),
        Err(FixedValidatorVoteIntentError::EffectTargetMismatch)
    ));

    let too_short = vec![0_u8; ObservedFixedValidatorVoteIntentV0::MIN_BYTE_LENGTH - 1];
    assert!(matches!(
        ObservedFixedValidatorVoteIntentV0::decode_and_verify(
            &too_short,
            context,
            branch.fixed_agreement_set_id(),
            signer,
        ),
        Err(FixedValidatorVoteIntentError::InputTooShort { .. })
    ));
    let too_long = vec![0_u8; ObservedFixedValidatorVoteIntentV0::MAX_BYTE_LENGTH + 1];
    assert!(matches!(
        ObservedFixedValidatorVoteIntentV0::decode_and_verify(
            &too_long,
            context,
            branch.fixed_agreement_set_id(),
            signer,
        ),
        Err(FixedValidatorVoteIntentError::InputTooLong { .. })
    ));
}

#[test]
fn structural_replay_rejects_old_lock_with_newer_different_valid_value() {
    let (branch, signing_key, context) = fixture(0x36);
    let round_zero = branch.begin_round_zero().unwrap();
    let locked = value(&round_zero, 0x96);
    let conflicting = value(&round_zero, 0xa6);
    let mut state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    lock_current_proposal(&mut state, locked, context, &signing_key);
    let round_one = round_zero.advance_round().unwrap();
    state.advance_round(&round_one).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();
    let _ = state.decide_precommit_without_quorum().unwrap();
    let round_two = round_one.advance_round().unwrap();
    state.advance_round(&round_two).unwrap();
    let _ = state.decide_prevote_without_proposal().unwrap();

    let valid_position = ConsensusPosition::new(state.position().height(), ConsensusRound::new(1));
    let positioned = snapshot(context, valid_position, &signing_key);
    let certificate = quorum(
        context,
        valid_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(conflicting.proposal_signing_root()),
        &signing_key,
        &positioned,
    );
    let certificate_bytes = certificate.to_canonical_bytes();
    let mut unreachable = vote_snapshot_from_lock_state(&state);
    unreachable.valid = Some(FixedValidatorValidValueV0 {
        value: conflicting,
        round: ConsensusRound::new(1),
        prevote_certificate_id: certificate.id(),
        canonical_prevote_certificate: certificate_bytes,
    });
    let effect = FixedValidatorUnsignedVoteEffectV0::from_snapshot(
        &unreachable,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(locked.proposal_signing_root()),
    );
    let signer = consensus_key(&signing_key);
    let bytes = encode_state_and_vote_intent(&unreachable, &effect, signer).unwrap();
    assert!(matches!(
        ObservedFixedValidatorVoteIntentV0::decode_and_verify(
            &bytes,
            context,
            branch.fixed_agreement_set_id(),
            signer,
        ),
        Err(FixedValidatorVoteIntentError::LockValidValueMismatch {
            locked_round,
            valid_round,
        }) if locked_round == ConsensusRound::new(0)
            && valid_round == ConsensusRound::new(1)
    ));
}
