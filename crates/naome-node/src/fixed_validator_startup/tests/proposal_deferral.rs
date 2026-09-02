use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusProposalVerifyError, ConsensusVoteRole, ConsensusVoteTarget, FixedConsensusRoundV0,
    FixedValidatorLockPhaseV0, ProducerAuthorizationVerifyError, VerifiedFixedConsensusProposalV0,
};
use naome_storage::{FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyJournalErrorV0};

use super::*;

fn expect_deferred<'node>(
    outcome: FixedValidatorNodeProposalDeferralOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorNodeDeferredProposalV0,
) {
    match outcome {
        FixedValidatorNodeProposalDeferralOutcomeV0::Deferred { scope, proposal } => {
            (*scope, *proposal)
        }
        FixedValidatorNodeProposalDeferralOutcomeV0::Rejected { .. } => {
            panic!("expected one fully admitted deferred proposal")
        }
    }
}

fn expect_deferral_rejected<'node>(
    outcome: FixedValidatorNodeProposalDeferralOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorNodeProposalDeferralRejectionV0,
) {
    match outcome {
        FixedValidatorNodeProposalDeferralOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeProposalDeferralOutcomeV0::Deferred { .. } => {
            panic!("expected a no-effect proposal-deferral rejection")
        }
    }
}

fn expect_advanced<'node>(
    outcome: FixedValidatorNodeRoundAdvanceOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    ConsensusPosition,
    FixedValidatorLockPhaseV0,
) {
    match outcome {
        FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced {
            scope,
            position,
            phase,
        } => (*scope, position, phase),
        FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { .. } => {
            panic!("expected admitted independent round progression")
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

fn assert_empty_scope(
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

fn provision_with_finality_round_limit<'layout>(
    fixture: &'layout Fixture,
    layout: &'layout TestLayout,
    finality_maximum_round: u64,
    recovery_maximum_round: u64,
) -> FixedValidatorNodeProvisionV0<'layout> {
    FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(finality_maximum_round).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(recovery_maximum_round),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    )
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

#[test]
fn far_future_proposal_token_owns_exact_inputs_without_advancing_or_writing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-deferral-owned");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    let (proposal, control, payload, parent, position, value, root) = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let round_one = round_at(&branch, 1);
            let round_five = round_at(&branch, 5);
            let payload = proof_payload(ZfcAxiom::Pairing);
            let block = ArtifactChainState::new(fixture.definition)
                .prepare_block(artifact_id(&payload))
                .unwrap();
            let value = round_five.value_for_artifact_block(block);
            let valid_round_certificate = quorum_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &fixture.signing_key(),
            );
            let control = proposal_control_bytes_with_valid_round(
                value,
                round_five.position(),
                &fixture.signing_key(),
                &valid_round_certificate,
            );
            let route = FixedValidatorNodeHigherRoundProposalRouteV0::new(
                ConsensusRound::new(5),
                ConsensusRound::new(5),
            );
            let (mut scope, proposal) = expect_deferred(
                scope
                    .defer_higher_round_proposal(&control, payload.clone(), route)
                    .unwrap(),
            );

            assert_empty_scope(&mut scope, round_zero.position());
            assert_eq!(layout.images(), before);
            assert_eq!(proposal.parent_coordinate(), branch.coordinate());
            assert_eq!(proposal.position(), round_five.position());
            assert_eq!(proposal.value(), value);
            assert_eq!(
                proposal.proposal_signing_root(),
                value.proposal_signing_root()
            );
            assert_eq!(proposal.canonical_proposal_control_bytes(), control);
            assert_eq!(proposal.canonical_artifact_bytes(), payload);
            (
                proposal,
                control,
                payload,
                branch.coordinate(),
                round_five.position(),
                value,
                value.proposal_signing_root(),
            )
        })
        .unwrap();

    assert_eq!(proposal.parent_coordinate(), parent);
    assert_eq!(proposal.position(), position);
    assert_eq!(proposal.value(), value);
    assert_eq!(proposal.proposal_signing_root(), root);
    assert_eq!(proposal.canonical_proposal_control_bytes(), control);
    assert_eq!(proposal.canonical_artifact_bytes(), payload);
    assert_eq!(layout.images(), before);
    drop(proposal);

    let reopened = expect_ready(
        fixture
            .provision(&layout, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            let expected = scope.branch().begin_round_zero().unwrap().position();
            assert_empty_scope(&mut scope, expected);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn retained_inputs_are_reverified_after_independent_progression_before_signing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-deferral-reverify");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    let (first, second, valid, expected_root) = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let (value, control, payload) =
                proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
            let route = FixedValidatorNodeHigherRoundProposalRouteV0::new(
                ConsensusRound::new(2),
                ConsensusRound::new(2),
            );
            let (scope, first) = expect_deferred(
                scope
                    .defer_higher_round_proposal(&control, payload.clone(), route)
                    .unwrap(),
            );
            let (scope, second) = expect_deferred(
                scope
                    .defer_higher_round_proposal(&control, payload.clone(), route)
                    .unwrap(),
            );
            let (mut scope, valid) = expect_deferred(
                scope
                    .defer_higher_round_proposal(&control, payload, route)
                    .unwrap(),
            );
            assert_empty_scope(&mut scope, branch.begin_round_zero().unwrap().position());
            assert_eq!(layout.images(), before);
            (first, second, valid, value.proposal_signing_root())
        })
        .unwrap();

    assert_eq!(layout.images(), before);
    let reopened = expect_ready(
        fixture
            .provision(&layout, 2)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = round_at(&branch, 0);
            let round_one = round_at(&branch, 1);
            let round_two = round_at(&branch, 2);
            let round_zero_nil = quorum_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let (scope, position, phase) = expect_advanced(
                scope
                    .advance_round_for_nil_precommit_quorum(&round_zero_nil, ConsensusRound::new(2))
                    .unwrap(),
            );
            assert_eq!(position, round_one.position());
            assert_eq!(phase, FixedValidatorLockPhaseV0::Proposal);
            let round_one_nil = quorum_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let (scope, position, phase) = expect_advanced(
                scope
                    .advance_round_for_nil_precommit_quorum(&round_one_nil, ConsensusRound::new(2))
                    .unwrap(),
            );
            assert_eq!(position, round_two.position());
            assert_eq!(phase, FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), before);

            let (mut changed_control, unchanged_payload) = first.into_unverified_canonical_inputs();
            let signature_byte = VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_BYTE_LENGTH - 2;
            changed_control[signature_byte] ^= 0x01;
            let (mut scope, rejection) = expect_vote_rejected(
                scope
                    .sign_prevote_for_proposal(
                        &changed_control,
                        unchanged_payload,
                        ConsensusRound::new(2),
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
            assert_empty_scope(&mut scope, round_two.position());
            assert_eq!(layout.images(), before);

            let (unchanged_control, mut changed_payload) =
                second.into_unverified_canonical_inputs();
            *changed_payload.last_mut().unwrap() ^= 0x01;
            let (mut scope, rejection) = expect_vote_rejected(
                scope
                    .sign_prevote_for_proposal(
                        &unchanged_control,
                        changed_payload,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(_)
            ));
            assert_empty_scope(&mut scope, round_two.position());
            assert_eq!(layout.images(), before);

            let (control, payload) = valid.into_unverified_canonical_inputs();
            let (mut scope, vote) = expect_signed(
                scope
                    .sign_prevote_for_proposal(&control, payload, ConsensusRound::new(2))
                    .unwrap(),
            );
            assert_eq!(vote.position(), round_two.position());
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Proposal(expected_root));
            assert_eq!(scope.signing_session().position(), round_two.position());
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            assert_eq!(layout.images()[0], before[0]);
            assert_eq!(layout.images()[1], before[1]);
            assert_ne!(layout.images()[2], before[2]);
            assert_ne!(layout.images()[3], before[3]);
        })
        .unwrap();

    let after_vote = layout.images();
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
                FixedValidatorLockPhaseV0::Prevote
            );
            assert_eq!(layout.images(), after_vote);
        })
        .unwrap();
}

#[test]
fn route_and_proposal_rejections_preserve_scope_and_authority_images() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-deferral-rejections");
    let ready = provision_with_finality_round_limit(&fixture, &layout, 2, 2)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = round_at(&branch, 0);
            let round_one = round_at(&branch, 1);
            let round_two = round_at(&branch, 2);
            let (_, round_one_control, round_one_payload) =
                proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Pairing);
            let (_, round_two_control, _) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);

            let (scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &[0_u8],
                        Vec::new(),
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(2),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::NotHigherThanSigner {
                    signer,
                    proposal,
                } if signer == ConsensusRound::new(0) && proposal == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &[0_u8],
                        Vec::new(),
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(3),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(3) && maximum == ConsensusRound::new(2)
            ));
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &[0_u8],
                        Vec::new(),
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(2),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(2) && maximum == ConsensusRound::new(1)
            ));
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &[0_u8],
                        Vec::new(),
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::Proposal(_)
            ));
            assert_eq!(layout.images(), before);

            let mut invalid_proof = round_one_control.clone();
            *invalid_proof.last_mut().unwrap() =
                VerifiedFixedConsensusProposalV0::VALID_ROUND_PROOF_TAG;
            invalid_proof.push(0);
            let (scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &invalid_proof,
                        round_one_payload.clone(),
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::Proposal(_)
            ));
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &round_two_control,
                        round_one_payload.clone(),
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::ProducerAuthorization(
                            ProducerAuthorizationVerifyError::SnapshotPositionMismatch {
                                authorization,
                                snapshot,
                            }
                        ) if *authorization == round_two.position()
                            && *snapshot == round_one.position()
                    )
            ));
            assert_eq!(layout.images(), before);

            let mut wrong_payload = round_one_payload.clone();
            *wrong_payload.last_mut().unwrap() ^= 0x01;
            let (scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &round_one_control,
                        wrong_payload,
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::Proposal(_)
            ));
            assert_eq!(layout.images(), before);

            let (mut scope, proposal) = expect_deferred(
                scope
                    .defer_higher_round_proposal(
                        &round_one_control,
                        round_one_payload,
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert_eq!(proposal.position(), round_one.position());
            assert_empty_scope(&mut scope, round_zero.position());
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn healthy_prevote_and_precommit_phases_can_defer_without_an_effect() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-deferral-all-phases");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = round_at(&branch, 0);
            let round_one = round_at(&branch, 1);
            let (current_value, current_control, current_payload) =
                proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
            let (future_value, future_control, future_payload) =
                proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
            let route = FixedValidatorNodeHigherRoundProposalRouteV0::new(
                ConsensusRound::new(1),
                ConsensusRound::new(1),
            );

            let (mut scope, _) = expect_signed(
                scope
                    .sign_prevote_for_proposal(
                        &current_control,
                        current_payload.clone(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let before_prevote_position = scope.signing_session().position();
            let before_prevote_phase = scope.signing_session().phase();
            let before_prevote_lock = scope.signing_session().locked_value();
            let before_prevote_valid = scope.signing_session().valid_value().cloned();
            let before_prevote_deferral = layout.images();
            let (mut scope, proposal) = expect_deferred(
                scope
                    .defer_higher_round_proposal(&future_control, future_payload.clone(), route)
                    .unwrap(),
            );
            assert_eq!(proposal.parent_coordinate(), branch.coordinate());
            assert_eq!(proposal.position(), round_one.position());
            assert_eq!(proposal.value(), future_value);
            assert_eq!(
                proposal.proposal_signing_root(),
                future_value.proposal_signing_root()
            );
            assert_eq!(proposal.canonical_proposal_control_bytes(), future_control);
            assert_eq!(proposal.canonical_artifact_bytes(), future_payload);
            assert_eq!(scope.signing_session().position(), before_prevote_position);
            assert_eq!(scope.signing_session().phase(), before_prevote_phase);
            assert_eq!(scope.signing_session().locked_value(), before_prevote_lock);
            assert_eq!(
                scope.signing_session().valid_value(),
                before_prevote_valid.as_ref()
            );
            assert_eq!(layout.images(), before_prevote_deferral);

            let prevote_certificate = quorum_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
                &fixture.signing_key(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_for_proposal_quorum(
                        &current_control,
                        current_payload,
                        &prevote_certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(scope.signing_session().locked_value().is_some());
            assert!(scope.signing_session().valid_value().is_some());
            let before_precommit_position = scope.signing_session().position();
            let before_precommit_phase = scope.signing_session().phase();
            let before_precommit_lock = scope.signing_session().locked_value();
            let before_precommit_valid = scope.signing_session().valid_value().cloned();
            let before_precommit_deferral = layout.images();
            let (mut scope, proposal) = expect_deferred(
                scope
                    .defer_higher_round_proposal(&future_control, future_payload.clone(), route)
                    .unwrap(),
            );
            assert_eq!(proposal.parent_coordinate(), branch.coordinate());
            assert_eq!(proposal.position(), round_one.position());
            assert_eq!(proposal.value(), future_value);
            assert_eq!(
                proposal.proposal_signing_root(),
                future_value.proposal_signing_root()
            );
            assert_eq!(proposal.canonical_proposal_control_bytes(), future_control);
            assert_eq!(proposal.canonical_artifact_bytes(), future_payload);
            assert_eq!(
                scope.signing_session().position(),
                before_precommit_position
            );
            assert_eq!(scope.signing_session().phase(), before_precommit_phase);
            assert_eq!(
                scope.signing_session().locked_value(),
                before_precommit_lock
            );
            assert_eq!(
                scope.signing_session().valid_value(),
                before_precommit_valid.as_ref()
            );
            assert_eq!(layout.images(), before_precommit_deferral);
        })
        .unwrap();
}

#[test]
fn zero_first_successor_capacity_precedes_proposal_round_and_input_inspection() {
    let fixture = Fixture::new();
    let finality_layout = TestLayout::new("node-proposal-deferral-finality-first-successor");
    let finality_ready = provision_with_finality_round_limit(&fixture, &finality_layout, 1, 1)
        .create(fixture.signing_key())
        .unwrap();
    finality_ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = round_at(&branch, 0);
            let round_one = round_at(&branch, 1);
            let round_zero_nil = quorum_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let (scope, position, phase) = expect_advanced(
                scope
                    .advance_round_for_nil_precommit_quorum(&round_zero_nil, ConsensusRound::new(1))
                    .unwrap(),
            );
            assert_eq!(position, round_one.position());
            assert_eq!(phase, FixedValidatorLockPhaseV0::Proposal);
            let finality_before = finality_layout.images();
            let (mut scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &[0_u8],
                        Vec::new(),
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(2) && maximum == ConsensusRound::new(1)
            ));
            assert_empty_scope(&mut scope, round_one.position());
            assert_eq!(finality_layout.images(), finality_before);
        })
        .unwrap();

    let caller_layout = TestLayout::new("node-proposal-deferral-caller-first-successor");
    let caller_ready = fixture
        .provision(&caller_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let caller_before = caller_layout.images();
    caller_ready
        .run_with_signing_session(|scope| {
            let (mut scope, rejection) = expect_deferral_rejected(
                scope
                    .defer_higher_round_proposal(
                        &[0_u8],
                        Vec::new(),
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalDeferralRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            let position = scope.branch().begin_round_zero().unwrap().position();
            assert_empty_scope(&mut scope, position);
            assert_eq!(caller_layout.images(), caller_before);
        })
        .unwrap();
}

#[test]
fn premature_and_stale_deferred_inputs_cannot_vote() {
    let fixture = Fixture::new();
    let early_layout = TestLayout::new("node-proposal-deferral-premature");
    let early_ready = fixture
        .provision(&early_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let early_before = early_layout.images();
    early_ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
            let (scope, proposal) = expect_deferred(
                scope
                    .defer_higher_round_proposal(
                        &control,
                        payload,
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(2),
                            ConsensusRound::new(3),
                        ),
                    )
                    .unwrap(),
            );
            let (control, payload) = proposal.into_unverified_canonical_inputs();
            let (mut scope, rejection) = expect_vote_rejected(
                scope
                    .sign_prevote_for_proposal(&control, payload, ConsensusRound::new(3))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::ProducerAuthorization(
                            ProducerAuthorizationVerifyError::SnapshotPositionMismatch { .. }
                        )
                    )
            ));
            assert_empty_scope(&mut scope, branch.begin_round_zero().unwrap().position());
            assert_eq!(early_layout.images(), early_before);
        })
        .unwrap();

    let stale_layout = TestLayout::new("node-proposal-deferral-stale");
    let stale_ready = fixture
        .provision(&stale_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let stale_before = stale_layout.images();
    stale_ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
            let (scope, proposal) = expect_deferred(
                scope
                    .defer_higher_round_proposal(
                        &control,
                        payload,
                        FixedValidatorNodeHigherRoundProposalRouteV0::new(
                            ConsensusRound::new(2),
                            ConsensusRound::new(3),
                        ),
                    )
                    .unwrap(),
            );
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
                let (next, _, _) = expect_advanced(
                    scope
                        .advance_round_for_nil_precommit_quorum(
                            &certificate,
                            ConsensusRound::new(3),
                        )
                        .unwrap(),
                );
                scope = next;
            }
            let (control, payload) = proposal.into_unverified_canonical_inputs();
            let (mut scope, rejection) = expect_vote_rejected(
                scope
                    .sign_prevote_for_proposal(&control, payload, ConsensusRound::new(3))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::ProducerAuthorization(
                            ProducerAuthorizationVerifyError::SnapshotPositionMismatch { .. }
                        )
                    )
            ));
            assert_empty_scope(&mut scope, round_at(&branch, 3).position());
            assert_eq!(stale_layout.images(), stale_before);
        })
        .unwrap();
}

#[test]
fn pending_higher_round_checkpoint_precedes_proposal_round_and_input_inspection() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-deferral-pending-precedence");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    let error = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_zero = round_at(&branch, 0);
            let round_one = round_at(&branch, 1);
            let certificate = quorum_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let prepared = scope
                .signing_session_mut()
                .prepare_higher_round_quorum_advance(
                    &round_zero,
                    &certificate,
                    ConsensusRound::new(1),
                )
                .unwrap();
            drop(prepared);

            let before_deferral = layout.images();
            let error = match scope.defer_higher_round_proposal(
                &[0_u8],
                Vec::new(),
                FixedValidatorNodeHigherRoundProposalRouteV0::new(
                    ConsensusRound::new(0),
                    ConsensusRound::new(0),
                ),
            ) {
                Err(error) => error,
                Ok(_) => panic!(
                    "pending signer work must consume the scope before proposal-round or input parsing"
                ),
            };
            assert_eq!(layout.images(), before_deferral);
            error
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeProposalDeferralErrorV0::Session(source)
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance { .. }
            )
    ));

    let reopened = expect_ready(
        fixture
            .provision(&layout, 1)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(
                scope.signing_session().position().round(),
                ConsensusRound::new(1)
            );
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
        })
        .unwrap();
}
