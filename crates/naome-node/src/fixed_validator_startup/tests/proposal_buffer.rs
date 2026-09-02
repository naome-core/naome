use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusProposalVerifyError, ConsensusVoteRole, ConsensusVoteTarget, FixedConsensusBranchV0,
    FixedConsensusRoundV0, FixedValidatorLockPhaseV0, FixedValidatorLockStateError,
    ProducerAuthorizationVerifyError, QuorumCertificateVerifyError,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::FixedValidatorSignedVoteV0;

use super::*;

fn expect_deferred<'node>(
    outcome: FixedValidatorNodeProposalDeferralOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    Box<FixedValidatorNodeDeferredProposalV0>,
) {
    match outcome {
        FixedValidatorNodeProposalDeferralOutcomeV0::Deferred { scope, proposal } => {
            (*scope, proposal)
        }
        FixedValidatorNodeProposalDeferralOutcomeV0::Rejected { .. } => {
            panic!("expected one fully admitted deferred proposal")
        }
    }
}

fn expect_advanced<'node>(
    outcome: FixedValidatorNodeRoundAdvanceOutcomeV0<'node>,
) -> FixedValidatorNodeSigningScopeV0<'node> {
    match outcome {
        FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. } => *scope,
        FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { .. } => {
            panic!("expected admitted independent round progression")
        }
    }
}

fn expect_vote_rejected<'node>(
    outcome: FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorNodeVoteRejectionV0,
) {
    match outcome {
        FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeVoteExecutionOutcomeV0::Signed { .. } => {
            panic!("expected full re-verification to reject the raw inputs")
        }
        FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(_) => {
            panic!("invalid raw inputs must not stop the signer")
        }
    }
}

fn expect_signed<'node>(
    outcome: FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorSignedVoteV0,
) {
    match outcome {
        FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote } => (*scope, vote),
        FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { .. } => {
            panic!("expected one completed signed vote")
        }
        FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(_) => {
            panic!("expected continued signing authority")
        }
    }
}

fn expect_buffered_precommit_signed<'node>(
    outcome: FixedValidatorNodeBufferedProposalPrecommitOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorSignedVoteV0,
    Box<FixedValidatorNodeDeferredProposalV0>,
) {
    match outcome {
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Signed {
            scope,
            vote,
            proposal,
        } => (*scope, vote, proposal),
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Rejected { .. } => {
            panic!("expected exact pairing to complete one signed precommit")
        }
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::SignerStopped(_) => {
            panic!("expected continued signing authority")
        }
    }
}

fn expect_buffered_precommit_rejected<'node>(
    outcome: FixedValidatorNodeBufferedProposalPrecommitOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorNodeBufferedProposalPrecommitRejectionV0,
) {
    match outcome {
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Signed { .. } => {
            panic!("expected exact pairing to reject without signing")
        }
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::SignerStopped(_) => {
            panic!("input rejection must not stop the signer")
        }
    }
}

fn expect_inserted(
    buffer: &mut FixedValidatorNodeProposalBufferV0,
    proposal: Box<FixedValidatorNodeDeferredProposalV0>,
) {
    match buffer.try_insert(proposal) {
        Ok(FixedValidatorNodeProposalBufferInsertOutcomeV0::Inserted) => {}
        Ok(FixedValidatorNodeProposalBufferInsertOutcomeV0::AlreadyRetained { .. }) => {
            panic!("expected a byte-distinct token")
        }
        Err(error) => panic!("expected insertion within capacity: {error:?}"),
    }
}

fn expect_insert_error(
    result: Result<
        FixedValidatorNodeProposalBufferInsertOutcomeV0,
        FixedValidatorNodeProposalBufferInsertErrorV0,
    >,
) -> FixedValidatorNodeProposalBufferInsertErrorV0 {
    match result {
        Err(error) => error,
        Ok(FixedValidatorNodeProposalBufferInsertOutcomeV0::Inserted) => {
            panic!("expected insertion to be rejected")
        }
        Ok(FixedValidatorNodeProposalBufferInsertOutcomeV0::AlreadyRetained { .. }) => {
            panic!("expected saturated insertion to be rejected")
        }
    }
}

fn expect_access_error(
    result: Result<
        Option<Box<FixedValidatorNodeDeferredProposalV0>>,
        FixedValidatorNodeProposalBufferAccessErrorV0,
    >,
) -> FixedValidatorNodeProposalBufferAccessErrorV0 {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected saturated retrieval to be denied"),
    }
}

fn round_at(branch: &FixedConsensusBranchV0, round: u64) -> FixedConsensusRoundV0<'_> {
    let mut cursor = branch.begin_round_zero().unwrap();
    for _ in 0..round {
        cursor = cursor.advance_round().unwrap();
    }
    cursor
}

fn proposal_control_bytes(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
) -> Vec<u8> {
    let mut bytes = value.to_canonical_bytes().to_vec();
    bytes.extend_from_slice(&authorization_bytes(
        value.context(),
        position,
        value.proposal_signing_root(),
        proposer,
    ));
    bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    bytes
}

fn proposal_control_bytes_with_valid_round(
    value: ConsensusValueV0,
    position: ConsensusPosition,
    proposer: &SigningKey,
    valid_round_certificate: &[u8],
) -> Vec<u8> {
    let mut bytes = value.to_canonical_bytes().to_vec();
    bytes.extend_from_slice(&authorization_bytes(
        value.context(),
        position,
        value.proposal_signing_root(),
        proposer,
    ));
    bytes.push(VerifiedFixedConsensusProposalV0::VALID_ROUND_PROOF_TAG);
    bytes.extend_from_slice(valid_round_certificate);
    bytes
}

fn vote_body_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
) -> [u8; VOTE_BODY_BYTES] {
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = match role {
        ConsensusVoteRole::Prevote => 1,
        ConsensusVoteRole::Precommit => 2,
    };
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => body[85] = 0,
        ConsensusVoteTarget::Proposal(root) => {
            body[85] = 1;
            body[86..].copy_from_slice(root.as_bytes());
        }
    }
    body
}

fn quorum_certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signer: &SigningKey,
) -> Vec<u8> {
    let body = vote_body_bytes(context, position, role, target);
    let signer_key = consensus_key(signer);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut transcript = Vec::new();
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(signer_key.as_bytes());
    let mut bytes = body.to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(signer_key.as_bytes());
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    bytes
}

fn proposal_inputs(
    fixture: &Fixture,
    branch: &FixedConsensusBranchV0,
    proposal_round: u64,
    axiom: ZfcAxiom,
) -> (ConsensusValueV0, Vec<u8>, Vec<u8>) {
    let payload = proof_payload(axiom);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let round = round_at(branch, proposal_round);
    let value = round.value_for_artifact_block(block);
    let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());
    (value, control, payload)
}

fn defer<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    control: &[u8],
    payload: Vec<u8>,
    round: u64,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    Box<FixedValidatorNodeDeferredProposalV0>,
) {
    expect_deferred(
        scope
            .defer_higher_round_proposal(
                control,
                payload,
                FixedValidatorNodeHigherRoundProposalRouteV0::new(
                    ConsensusRound::new(round),
                    ConsensusRound::new(round),
                ),
            )
            .unwrap(),
    )
}

fn canonical_input_len(control: &[u8], payload: &[u8]) -> u64 {
    u64::try_from(control.len())
        .unwrap()
        .checked_add(u64::try_from(payload.len()).unwrap())
        .unwrap()
}

fn next_anchor_collision(directory: &std::path::Path, sequence: u64) -> PathBuf {
    let anchor_name = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".anchor"))
        .expect("one typed anchor file must exist");
    let collision = directory.join(format!("{anchor_name}.tmp-{sequence:016x}"));
    fs::write(&collision, b"deterministic anchor collision").unwrap();
    collision
}

fn assert_empty_proposal_phase(
    scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
    position: ConsensusPosition,
) {
    assert_eq!(scope.signing_session().position(), position);
    assert_eq!(
        scope.signing_session().phase(),
        FixedValidatorLockPhaseV0::Proposal
    );
    assert_eq!(scope.signing_session().locked_value(), None);
    assert_eq!(scope.signing_session().valid_value(), None);
}

#[test]
fn exact_variants_and_competing_roots_survive_the_callback_without_preference() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("proposal-buffer-variants");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let limits = FixedValidatorNodeProposalBufferLimitsV0::new(3, u64::MAX).unwrap();
    let mut buffer = FixedValidatorNodeProposalBufferV0::new(limits);
    let before = layout.images();

    let (plain_control, proof_control, payload, competing_control, competing_payload, total) =
        ready
            .run_with_signing_session(|scope| {
                let branch = scope.branch().clone();
                let round_one = round_at(&branch, 1);
                let round_two = round_at(&branch, 2);
                let (value, plain_control, payload) =
                    proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
                let proof = quorum_certificate_bytes(
                    fixture.context,
                    round_one.position(),
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                    &fixture.signing_key(),
                );
                let proof_control = proposal_control_bytes_with_valid_round(
                    value,
                    round_two.position(),
                    &fixture.signing_key(),
                    &proof,
                );
                let (competing_value, competing_control, competing_payload) =
                    proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
                assert_ne!(
                    value.proposal_signing_root(),
                    competing_value.proposal_signing_root()
                );
                assert_ne!(plain_control, proof_control);

                let (scope, plain) = defer(scope, &plain_control, payload.clone(), 2);
                let (scope, duplicate_below_capacity) =
                    defer(scope, &plain_control, payload.clone(), 2);
                let (scope, proof_variant) = defer(scope, &proof_control, payload.clone(), 2);
                let (scope, competing) =
                    defer(scope, &competing_control, competing_payload.clone(), 2);
                let (mut scope, duplicate) = defer(scope, &plain_control, payload.clone(), 2);
                assert_eq!(
                    plain.proposal_signing_root(),
                    proof_variant.proposal_signing_root()
                );
                assert_ne!(
                    plain.proposal_signing_root(),
                    competing.proposal_signing_root()
                );

                expect_inserted(&mut buffer, plain);
                match buffer.try_insert(duplicate_below_capacity).unwrap() {
                    FixedValidatorNodeProposalBufferInsertOutcomeV0::AlreadyRetained {
                        proposal,
                    } => {
                        assert_eq!(proposal.canonical_proposal_control_bytes(), plain_control);
                        assert_eq!(buffer.len(), 1);
                        assert_eq!(buffer.saturation(), None);
                    }
                    FixedValidatorNodeProposalBufferInsertOutcomeV0::Inserted => {
                        panic!("exact duplicate below capacity must be no-growth")
                    }
                }
                expect_inserted(&mut buffer, proof_variant);
                expect_inserted(&mut buffer, competing);
                match buffer.try_insert(duplicate).unwrap() {
                    FixedValidatorNodeProposalBufferInsertOutcomeV0::AlreadyRetained {
                        proposal,
                    } => {
                        assert_eq!(proposal.canonical_proposal_control_bytes(), plain_control);
                        assert_eq!(proposal.canonical_artifact_bytes(), payload);
                    }
                    FixedValidatorNodeProposalBufferInsertOutcomeV0::Inserted => {
                        panic!("exact duplicate must not grow a full healthy buffer")
                    }
                }

                let total = canonical_input_len(&plain_control, &payload)
                    + canonical_input_len(&proof_control, &payload)
                    + canonical_input_len(&competing_control, &competing_payload);
                assert_eq!(buffer.len(), 3);
                assert_eq!(buffer.total_canonical_input_bytes(), total);
                assert_eq!(buffer.saturation(), None);
                assert_empty_proposal_phase(
                    &mut scope,
                    branch.begin_round_zero().unwrap().position(),
                );
                assert_eq!(layout.images(), before);
                (
                    plain_control,
                    proof_control,
                    payload,
                    competing_control,
                    competing_payload,
                    total,
                )
            })
            .unwrap();

    assert_eq!(layout.images(), before);
    let mut missing = plain_control.clone();
    missing[0] ^= 0x01;
    assert!(buffer.take_exact(&missing, &payload).unwrap().is_none());
    assert_eq!(buffer.len(), 3);
    assert_eq!(buffer.total_canonical_input_bytes(), total);

    let proof_variant = buffer
        .take_exact(&proof_control, &payload)
        .unwrap()
        .unwrap();
    assert_eq!(
        proof_variant.canonical_proposal_control_bytes(),
        proof_control
    );
    assert_eq!(buffer.len(), 2);
    assert!(
        buffer
            .take_exact(&competing_control, &payload)
            .unwrap()
            .is_none()
    );
    let competing = buffer
        .take_exact(&competing_control, &competing_payload)
        .unwrap()
        .unwrap();
    assert_ne!(
        proof_variant.proposal_signing_root(),
        competing.proposal_signing_root()
    );
    assert!(
        buffer
            .take_exact(&plain_control, &payload)
            .unwrap()
            .is_some()
    );
    assert!(buffer.is_empty());
    assert_eq!(buffer.total_canonical_input_bytes(), 0);
}

#[test]
fn item_saturation_returns_tokens_denies_access_and_resets_losslessly() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("proposal-buffer-item-saturation");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let limits = FixedValidatorNodeProposalBufferLimitsV0::new(1, u64::MAX).unwrap();
    let mut buffer = FixedValidatorNodeProposalBufferV0::new(limits);

    let (
        first_control,
        first_payload,
        second_control,
        second_payload,
        second,
        late_duplicate,
        late_distinct,
    ) = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let (_, first_control, first_payload) =
                proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
            let (_, second_control, second_payload) =
                proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
            let (_, third_control, third_payload) =
                proposal_inputs(&fixture, &branch, 2, ZfcAxiom::PowerSet);
            let (scope, first) = defer(scope, &first_control, first_payload.clone(), 2);
            let (scope, duplicate) = defer(scope, &first_control, first_payload.clone(), 2);
            let (scope, second) = defer(scope, &second_control, second_payload.clone(), 2);
            let (scope, late_duplicate) = defer(scope, &first_control, first_payload.clone(), 2);
            let (_, late_distinct) = defer(scope, &third_control, third_payload, 2);
            expect_inserted(&mut buffer, first);
            match buffer.try_insert(duplicate).unwrap() {
                FixedValidatorNodeProposalBufferInsertOutcomeV0::AlreadyRetained { proposal } => {
                    assert_eq!(proposal.canonical_proposal_control_bytes(), first_control);
                }
                FixedValidatorNodeProposalBufferInsertOutcomeV0::Inserted => {
                    panic!("duplicate at the item limit must be no-growth")
                }
            }
            (
                first_control,
                first_payload,
                second_control,
                second_payload,
                second,
                late_duplicate,
                late_distinct,
            )
        })
        .unwrap();

    let retained_bytes = buffer.total_canonical_input_bytes();
    let error = expect_insert_error(buffer.try_insert(second));
    assert!(error.newly_saturated());
    assert_eq!(
        error.saturation(),
        Some(FixedValidatorNodeProposalBufferSaturationV0::Capacity {
            attempted_entries: 2,
            maximum_entries: 1,
            attempted_canonical_input_bytes: retained_bytes
                + canonical_input_len(&second_control, &second_payload),
            maximum_canonical_input_bytes: u64::MAX,
        })
    );
    let second = error.into_attempted_proposal();
    assert_eq!(second.canonical_proposal_control_bytes(), second_control);
    assert_eq!(second.canonical_artifact_bytes(), second_payload);
    assert_eq!(buffer.len(), 1);
    assert_eq!(buffer.total_canonical_input_bytes(), retained_bytes);

    let late_error = expect_insert_error(buffer.try_insert(late_duplicate));
    assert!(!late_error.newly_saturated());
    assert_eq!(late_error.saturation(), buffer.saturation());
    let later_distinct_error = expect_insert_error(buffer.try_insert(late_distinct));
    assert!(!later_distinct_error.newly_saturated());
    assert_eq!(later_distinct_error.saturation(), buffer.saturation());
    let denied = expect_access_error(buffer.take_exact(&first_control, &first_payload));
    assert_eq!(Some(denied.saturation()), buffer.saturation());
    assert_eq!(buffer.len(), 1);
    assert_eq!(buffer.total_canonical_input_bytes(), retained_bytes);

    let drained = buffer.drain_and_reset().collect::<Vec<_>>();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].canonical_proposal_control_bytes(), first_control);
    assert_eq!(drained[0].canonical_artifact_bytes(), first_payload);
    assert!(buffer.is_empty());
    assert_eq!(buffer.total_canonical_input_bytes(), 0);
    assert_eq!(buffer.saturation(), None);
    expect_inserted(&mut buffer, second);
}

#[test]
fn exact_byte_limit_normalizes_spare_capacity_and_saturates_without_mutation() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("proposal-buffer-byte-saturation");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    let (first, duplicate, second, first_control, first_payload, second_control, second_payload) =
        ready
            .run_with_signing_session(|scope| {
                let branch = scope.branch().clone();
                let (value, first_control, canonical_payload) =
                    proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
                let mut first_payload = Vec::with_capacity(canonical_payload.len() + 4096);
                first_payload.extend_from_slice(&canonical_payload);
                assert!(first_payload.capacity() > first_payload.len());
                let (_, second_control, second_payload) =
                    proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
                let (scope, first) = defer(scope, &first_control, first_payload, 2);
                let (scope, duplicate) = defer(scope, &first_control, canonical_payload.clone(), 2);
                let (_, second) = defer(scope, &second_control, second_payload.clone(), 2);
                assert_eq!(first.proposal_signing_root(), value.proposal_signing_root());
                (
                    first,
                    duplicate,
                    second,
                    first_control,
                    canonical_payload,
                    second_control,
                    second_payload,
                )
            })
            .unwrap();
    let exact_limit = canonical_input_len(&first_control, &first_payload);
    let limits = FixedValidatorNodeProposalBufferLimitsV0::new(3, exact_limit).unwrap();
    let mut buffer = FixedValidatorNodeProposalBufferV0::new(limits);
    expect_inserted(&mut buffer, first);
    assert_eq!(buffer.total_canonical_input_bytes(), exact_limit);

    let duplicate = match buffer.try_insert(duplicate).unwrap() {
        FixedValidatorNodeProposalBufferInsertOutcomeV0::AlreadyRetained { proposal } => proposal,
        FixedValidatorNodeProposalBufferInsertOutcomeV0::Inserted => {
            panic!("duplicate at the byte limit must be no-growth")
        }
    };
    let (normalized_control, normalized_payload) = duplicate.into_unverified_canonical_inputs();
    assert_eq!(normalized_control, first_control);
    assert_eq!(normalized_payload, first_payload);

    let error = expect_insert_error(buffer.try_insert(second));
    assert!(error.newly_saturated());
    assert_eq!(
        error.saturation(),
        Some(FixedValidatorNodeProposalBufferSaturationV0::Capacity {
            attempted_entries: 2,
            maximum_entries: 3,
            attempted_canonical_input_bytes: exact_limit
                + canonical_input_len(&second_control, &second_payload),
            maximum_canonical_input_bytes: exact_limit,
        })
    );
    assert_eq!(buffer.saturation(), error.saturation());
    assert_eq!(buffer.len(), 1);
    assert_eq!(buffer.total_canonical_input_bytes(), exact_limit);
    let second = error.into_attempted_proposal();
    assert_eq!(second.canonical_proposal_control_bytes(), second_control);
    assert_eq!(second.canonical_artifact_bytes(), second_payload);
    let drained = buffer.drain_and_reset().collect::<Vec<_>>();
    assert_eq!(drained.len(), 1);
    let retained = drained.into_iter().next().unwrap();
    let (normalized_control, normalized_payload) = retained.into_unverified_canonical_inputs();
    assert_eq!(normalized_control.capacity(), normalized_control.len());
    assert_eq!(normalized_payload.capacity(), normalized_payload.len());
    assert_eq!(normalized_control, first_control);
    assert_eq!(normalized_payload, first_payload);
    assert!(buffer.is_empty());

    drop(buffer);
    let fresh = FixedValidatorNodeProposalBufferV0::new(limits);
    assert!(fresh.is_empty());
    assert_eq!(fresh.saturation(), None);
}

#[test]
fn retrieved_variants_require_full_live_reverification_after_strict_reopen() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("proposal-buffer-reverify");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let limits = FixedValidatorNodeProposalBufferLimitsV0::new(4, u64::MAX).unwrap();
    let mut buffer = FixedValidatorNodeProposalBufferV0::new(limits);
    let before = layout.images();

    let (controls, payload, expected_root) = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_three = round_at(&branch, 3);
            let (value, plain_control, payload) =
                proposal_inputs(&fixture, &branch, 3, ZfcAxiom::Pairing);
            let mut controls = vec![plain_control];
            for proof_round in 0..3 {
                let certificate = quorum_certificate_bytes(
                    fixture.context,
                    round_at(&branch, proof_round).position(),
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                    &fixture.signing_key(),
                );
                controls.push(proposal_control_bytes_with_valid_round(
                    value,
                    round_three.position(),
                    &fixture.signing_key(),
                    &certificate,
                ));
            }
            let mut scope = scope;
            for control in &controls {
                let (next, proposal) = defer(scope, control, payload.clone(), 3);
                expect_inserted(&mut buffer, proposal);
                scope = next;
            }
            assert_empty_proposal_phase(&mut scope, branch.begin_round_zero().unwrap().position());
            assert_eq!(layout.images(), before);
            (controls, payload, value.proposal_signing_root())
        })
        .unwrap();
    assert_eq!(buffer.len(), 4);
    assert_eq!(layout.images(), before);

    let reopened = expect_ready(
        fixture
            .provision(&layout, 3)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let mut scope = scope;
            for round in 0..3 {
                let cursor = round_at(&branch, round);
                let certificate = quorum_certificate_bytes(
                    fixture.context,
                    cursor.position(),
                    ConsensusVoteRole::Precommit,
                    ConsensusVoteTarget::Nil,
                    &fixture.signing_key(),
                );
                scope = expect_advanced(
                    scope
                        .advance_round_for_nil_precommit_quorum(
                            &certificate,
                            ConsensusRound::new(3),
                        )
                        .unwrap(),
                );
            }
            let round_three = round_at(&branch, 3);
            assert_empty_proposal_phase(&mut scope, round_three.position());
            assert_eq!(layout.images(), before);

            let producer_tampered = buffer.take_exact(&controls[0], &payload).unwrap().unwrap();
            let (mut changed_control, unchanged_payload) =
                producer_tampered.into_unverified_canonical_inputs();
            let signature_byte = VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_BYTE_LENGTH - 2;
            changed_control[signature_byte] ^= 0x01;
            let (mut scope, rejection) = expect_vote_rejected(
                scope
                    .sign_prevote_for_proposal(
                        &changed_control,
                        unchanged_payload,
                        ConsensusRound::new(3),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::ProducerAuthorization(
                            ProducerAuthorizationVerifyError::InvalidSignature { .. }
                        )
                    )
            ));
            assert_empty_proposal_phase(&mut scope, round_three.position());
            assert_eq!(layout.images(), before);

            let proof_tampered = buffer.take_exact(&controls[1], &payload).unwrap().unwrap();
            let (mut changed_control, unchanged_payload) =
                proof_tampered.into_unverified_canonical_inputs();
            *changed_control.last_mut().unwrap() ^= 0x01;
            let (mut scope, rejection) = expect_vote_rejected(
                scope
                    .sign_prevote_for_proposal(
                        &changed_control,
                        unchanged_payload,
                        ConsensusRound::new(3),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::ValidRoundCertificate(
                            QuorumCertificateVerifyError::InvalidSignature { .. }
                        )
                    )
            ));
            assert_empty_proposal_phase(&mut scope, round_three.position());
            assert_eq!(layout.images(), before);

            let payload_tampered = buffer.take_exact(&controls[2], &payload).unwrap().unwrap();
            let (unchanged_control, mut changed_payload) =
                payload_tampered.into_unverified_canonical_inputs();
            *changed_payload.last_mut().unwrap() ^= 0x01;
            let (mut scope, rejection) = expect_vote_rejected(
                scope
                    .sign_prevote_for_proposal(
                        &unchanged_control,
                        changed_payload,
                        ConsensusRound::new(3),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(_)
            ));
            assert_empty_proposal_phase(&mut scope, round_three.position());
            assert_eq!(layout.images(), before);

            let valid = buffer.take_exact(&controls[3], &payload).unwrap().unwrap();
            let (control, payload) = valid.into_unverified_canonical_inputs();
            let (mut scope, vote) = expect_signed(
                scope
                    .sign_prevote_for_proposal(&control, payload, ConsensusRound::new(3))
                    .unwrap(),
            );
            assert_eq!(vote.position(), round_three.position());
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Proposal(expected_root));
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            assert!(buffer.is_empty());
            assert_eq!(layout.images()[0], before[0]);
            assert_eq!(layout.images()[1], before[1]);
            assert_ne!(layout.images()[2], before[2]);
            assert_ne!(layout.images()[3], before[3]);
        })
        .unwrap();

    let after_vote = layout.images();
    let reopened = expect_ready(
        fixture
            .provision(&layout, 3)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(
                scope.signing_session().position().round(),
                ConsensusRound::new(3)
            );
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            assert_eq!(layout.images(), after_vote);
        })
        .unwrap();
}

#[test]
fn exact_buffered_proposal_and_prevote_quorum_sign_precommit_and_preserve_siblings() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("proposal-buffer-paired-precommit");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut buffer = FixedValidatorNodeProposalBufferV0::new(
        FixedValidatorNodeProposalBufferLimitsV0::new(3, u64::MAX).unwrap(),
    );
    let before = layout.images();

    let (root, certificate, control, proof_control, payload, competing_control, competing_payload) =
        ready
            .run_with_signing_session(|scope| {
                let branch = scope.branch().clone();
                let round_one = round_at(&branch, 1);
                let round_two = round_at(&branch, 2);
                let (value, control, payload) =
                    proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
                let (_competing_value, competing_control, competing_payload) =
                    proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
                let valid_round_certificate = quorum_certificate_bytes(
                    fixture.context,
                    round_one.position(),
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                    &fixture.signing_key(),
                );
                let proof_control = proposal_control_bytes_with_valid_round(
                    value,
                    round_two.position(),
                    &fixture.signing_key(),
                    &valid_round_certificate,
                );
                let certificate = quorum_certificate_bytes(
                    fixture.context,
                    round_two.position(),
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                    &fixture.signing_key(),
                );
                let (scope, proposal) = defer(scope, &control, payload.clone(), 2);
                let (scope, proof_variant) = defer(scope, &proof_control, payload.clone(), 2);
                let (scope, competing) =
                    defer(scope, &competing_control, competing_payload.clone(), 2);
                expect_inserted(&mut buffer, proposal);
                expect_inserted(&mut buffer, proof_variant);
                expect_inserted(&mut buffer, competing);

                let (mut scope, vote, released) = expect_buffered_precommit_signed(
                    scope
                        .sign_precommit_for_buffered_higher_round_proposal_quorum(
                            &mut buffer,
                            &control,
                            &payload,
                            &certificate,
                            ConsensusRound::new(2),
                        )
                        .unwrap(),
                );
                assert_eq!(vote.position(), round_two.position());
                assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
                assert_eq!(
                    vote.target(),
                    ConsensusVoteTarget::Proposal(value.proposal_signing_root())
                );
                assert_eq!(released.canonical_proposal_control_bytes(), control);
                assert_eq!(released.canonical_artifact_bytes(), payload);
                assert_eq!(scope.signing_session().position(), round_two.position());
                assert_eq!(
                    scope.signing_session().phase(),
                    FixedValidatorLockPhaseV0::Precommit
                );
                assert_eq!(
                    scope
                        .signing_session()
                        .locked_value()
                        .unwrap()
                        .proposal_signing_root(),
                    value.proposal_signing_root()
                );
                assert_eq!(
                    scope
                        .signing_session()
                        .valid_value()
                        .unwrap()
                        .canonical_prevote_certificate(),
                    certificate
                );
                assert_eq!(buffer.len(), 2);
                assert_eq!(layout.images()[0], before[0]);
                assert_eq!(layout.images()[1], before[1]);
                assert_ne!(layout.images()[2], before[2]);
                assert_ne!(layout.images()[3], before[3]);

                (
                    value.proposal_signing_root(),
                    certificate,
                    control,
                    proof_control,
                    payload,
                    competing_control,
                    competing_payload,
                )
            })
            .unwrap();

    assert!(buffer.take_exact(&control, &payload).unwrap().is_none());
    let proof_variant = buffer
        .take_exact(&proof_control, &payload)
        .unwrap()
        .unwrap();
    assert_eq!(proof_variant.proposal_signing_root(), root);
    let competing = buffer
        .take_exact(&competing_control, &competing_payload)
        .unwrap()
        .unwrap();
    assert_ne!(competing.proposal_signing_root(), root);
    assert!(buffer.is_empty());

    let reopened = expect_ready(
        fixture
            .provision(&layout, 2)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(
                scope.signing_session().position().round(),
                ConsensusRound::new(2)
            );
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert_eq!(
                scope
                    .signing_session()
                    .locked_value()
                    .unwrap()
                    .proposal_signing_root(),
                root
            );
            assert_eq!(
                scope
                    .signing_session()
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate(),
                certificate
            );
            assert_eq!(layout.images()[0], before[0]);
            assert_eq!(layout.images()[1], before[1]);
        })
        .unwrap();
}

#[test]
fn buffered_pairing_rejects_missing_mismatched_and_malformed_inputs_without_effect() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("proposal-buffer-pairing-rejections");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut buffer = FixedValidatorNodeProposalBufferV0::new(
        FixedValidatorNodeProposalBufferLimitsV0::new(3, u64::MAX).unwrap(),
    );
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let round_one = round_at(&branch, 1);
            let round_two = round_at(&branch, 2);
            let (value, control, payload) =
                proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
            let (competing_value, competing_control, competing_payload) =
                proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
            let valid_round_certificate = quorum_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &fixture.signing_key(),
            );
            let proof_control = proposal_control_bytes_with_valid_round(
                value,
                round_two.position(),
                &fixture.signing_key(),
                &valid_round_certificate,
            );
            let valid = quorum_certificate_bytes(
                fixture.context,
                round_two.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &fixture.signing_key(),
            );
            let wrong_round = quorum_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &fixture.signing_key(),
            );
            let wrong_role = quorum_certificate_bytes(
                fixture.context,
                round_two.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &fixture.signing_key(),
            );
            let nil = quorum_certificate_bytes(
                fixture.context,
                round_two.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let wrong_root = quorum_certificate_bytes(
                fixture.context,
                round_two.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(competing_value.proposal_signing_root()),
                &fixture.signing_key(),
            );
            let (scope, proof_variant) = defer(scope, &proof_control, payload.clone(), 2);
            let (scope, proposal) = defer(scope, &control, payload.clone(), 2);
            let (scope, competing) = defer(scope, &competing_control, competing_payload.clone(), 2);
            expect_inserted(&mut buffer, proof_variant);
            expect_inserted(&mut buffer, proposal);
            expect_inserted(&mut buffer, competing);
            assert_eq!(layout.images(), before);

            let mut missing_control = control.clone();
            missing_control[0] ^= 0x01;
            let (mut scope, rejection) = expect_buffered_precommit_rejected(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &missing_control,
                        &payload,
                        &valid,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::ProposalUnavailable
            ));
            assert_eq!(buffer.len(), 3);
            assert_eq!(layout.images(), before);
            assert_empty_proposal_phase(&mut scope, round_zero.position());

            let (scope, rejection) = expect_buffered_precommit_rejected(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &wrong_round,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Quorum(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::HigherRoundQuorumPositionMismatch { .. }
                    )
            ));
            assert_eq!(buffer.len(), 3);
            assert_eq!(layout.images(), before);
            let retained = buffer.drain_and_reset().collect::<Vec<_>>();
            assert_eq!(retained.len(), 3);
            assert_eq!(
                retained[0].canonical_proposal_control_bytes(),
                proof_control
            );
            assert_eq!(retained[0].canonical_artifact_bytes(), payload);
            assert_eq!(retained[1].canonical_proposal_control_bytes(), control);
            assert_eq!(retained[1].canonical_artifact_bytes(), payload);
            assert_eq!(
                retained[2].canonical_proposal_control_bytes(),
                competing_control
            );
            assert_eq!(retained[2].canonical_artifact_bytes(), competing_payload);
            for proposal in retained {
                expect_inserted(&mut buffer, proposal);
            }

            let (scope, rejection) = expect_buffered_precommit_rejected(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &wrong_role,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Quorum(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::HigherRoundQuorumRoleMismatch { .. }
                    )
            ));
            assert_eq!(buffer.len(), 3);
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_buffered_precommit_rejected(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &nil,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Quorum(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::HigherRoundQuorumTargetMismatch { .. }
                    )
            ));
            assert_eq!(buffer.len(), 3);
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_buffered_precommit_rejected(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &wrong_root,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Quorum(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::HigherRoundQuorumTargetMismatch { .. }
                    )
            ));
            assert_eq!(buffer.len(), 3);
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_buffered_precommit_rejected(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &[0_u8],
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Quorum(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::HigherRoundCertificatePosition(_)
                    )
            ));
            assert_eq!(buffer.len(), 3);
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_buffered_precommit_rejected(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &valid,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(2) && maximum == ConsensusRound::new(1)
            ));
            assert_eq!(buffer.len(), 3);
            assert_eq!(layout.images(), before);

            let (mut scope, vote, released) = expect_buffered_precommit_signed(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &valid,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert_eq!(released.canonical_proposal_control_bytes(), control);
            assert_eq!(released.canonical_artifact_bytes(), payload);
            assert_eq!(vote.position(), round_two.position());
            assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
            assert_eq!(
                vote.target(),
                ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            );
            assert_eq!(buffer.len(), 2);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert_ne!(layout.images(), before);

            let retained = buffer.drain_and_reset().collect::<Vec<_>>();
            assert_eq!(retained.len(), 2);
            assert_eq!(
                retained[0].canonical_proposal_control_bytes(),
                proof_control
            );
            assert_eq!(retained[0].canonical_artifact_bytes(), payload);
            assert_eq!(
                retained[1].canonical_proposal_control_bytes(),
                competing_control
            );
            assert_eq!(retained[1].canonical_artifact_bytes(), competing_payload);
        })
        .unwrap();
}

#[test]
fn saturated_buffer_denies_pairing_until_explicit_lossless_reset() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("proposal-buffer-pairing-saturation");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut buffer = FixedValidatorNodeProposalBufferV0::new(
        FixedValidatorNodeProposalBufferLimitsV0::new(1, u64::MAX).unwrap(),
    );
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_two = round_at(&branch, 2);
            let (value, control, payload) =
                proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
            let (_, second_control, second_payload) =
                proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
            let certificate = quorum_certificate_bytes(
                fixture.context,
                round_two.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &fixture.signing_key(),
            );
            let (scope, proposal) = defer(scope, &control, payload.clone(), 2);
            let (scope, second) = defer(scope, &second_control, second_payload.clone(), 2);
            expect_inserted(&mut buffer, proposal);
            let saturation = expect_insert_error(buffer.try_insert(second));
            assert!(saturation.newly_saturated());
            let second = saturation.into_attempted_proposal();
            assert_eq!(second.canonical_proposal_control_bytes(), second_control);
            assert_eq!(second.canonical_artifact_bytes(), second_payload);
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_buffered_precommit_rejected(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &certificate,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Buffer(source)
                    if source.saturation() == buffer.saturation().unwrap()
            ));
            assert_eq!(buffer.len(), 1);
            assert_eq!(layout.images(), before);

            let retained = buffer.drain_and_reset().collect::<Vec<_>>();
            assert_eq!(retained.len(), 1);
            let retained = retained.into_iter().next().unwrap();
            assert_eq!(retained.canonical_proposal_control_bytes(), control);
            assert_eq!(retained.canonical_artifact_bytes(), payload);
            assert_eq!(buffer.saturation(), None);
            expect_inserted(&mut buffer, retained);

            let (mut scope, vote, released) = expect_buffered_precommit_signed(
                scope
                    .sign_precommit_for_buffered_higher_round_proposal_quorum(
                        &mut buffer,
                        &control,
                        &payload,
                        &certificate,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert_eq!(released.canonical_proposal_control_bytes(), control);
            assert_eq!(released.canonical_artifact_bytes(), payload);
            assert_eq!(vote.position(), round_two.position());
            assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
            assert_eq!(
                vote.target(),
                ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            );
            assert!(buffer.is_empty());
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
        })
        .unwrap();
}

#[test]
fn buffered_pairing_durable_failures_retain_token_and_require_strict_restart() {
    for (label, sequence) in [
        ("checkpoint", 3_u64),
        ("precommit-prepare", 4_u64),
        ("precommit-complete", 5_u64),
    ] {
        let fixture = Fixture::new();
        let layout = TestLayout::new(&format!("proposal-buffer-pairing-{label}"));
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let mut buffer = FixedValidatorNodeProposalBufferV0::new(
            FixedValidatorNodeProposalBufferLimitsV0::new(1, u64::MAX).unwrap(),
        );
        let before = layout.images();

        let (error, control, payload) = ready
            .run_with_signing_session(|scope| {
                let branch = scope.branch().clone();
                let round_two = round_at(&branch, 2);
                let (value, control, payload) =
                    proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
                let certificate = quorum_certificate_bytes(
                    fixture.context,
                    round_two.position(),
                    ConsensusVoteRole::Prevote,
                    ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                    &fixture.signing_key(),
                );
                let (scope, proposal) = defer(scope, &control, payload.clone(), 2);
                expect_inserted(&mut buffer, proposal);
                let collision = next_anchor_collision(&layout.vote_anchor, sequence);
                let error = match scope.sign_precommit_for_buffered_higher_round_proposal_quorum(
                    &mut buffer,
                    &control,
                    &payload,
                    &certificate,
                    ConsensusRound::new(2),
                ) {
                    Err(error) => error,
                    Ok(_) => panic!("anchor collision must consume scope without a vote"),
                };
                assert_eq!(buffer.len(), 1);
                fs::remove_file(collision).unwrap();
                (error, control, payload)
            })
            .unwrap();

        match sequence {
            3 => assert!(matches!(
                error,
                FixedValidatorNodeBufferedProposalPrecommitErrorV0::Prepare(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                    )
            )),
            4 => assert!(matches!(
                error,
                FixedValidatorNodeBufferedProposalPrecommitErrorV0::Vote(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorNodeVoteExecutionErrorV0::Prepare(inner)
                            if matches!(
                                inner.as_ref(),
                                FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                            )
                    )
            )),
            5 => assert!(matches!(
                error,
                FixedValidatorNodeBufferedProposalPrecommitErrorV0::Vote(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorNodeVoteExecutionErrorV0::Sign(inner)
                            if matches!(
                                inner.as_ref(),
                                FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                            )
                    )
            )),
            _ => unreachable!(),
        }
        let retained = buffer.take_exact(&control, &payload).unwrap().unwrap();
        assert_eq!(retained.canonical_proposal_control_bytes(), control);
        assert_eq!(retained.canonical_artifact_bytes(), payload);
        assert_eq!(layout.images()[0], before[0]);
        assert_eq!(layout.images()[1], before[1]);
        assert!(matches!(
            fixture.provision(&layout, 8).open(fixture.signing_key()),
            Err(FixedValidatorNodeStartupErrorV0::VotePair(source))
                if matches!(
                    source.as_ref(),
                    FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                        if matches!(
                            inner.as_ref(),
                            FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }
                        )
                )
        ));
    }
}
