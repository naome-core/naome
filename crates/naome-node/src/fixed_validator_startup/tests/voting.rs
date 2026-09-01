use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusVoteRole, ConsensusVoteTarget, FixedValidatorLockPhaseV0,
    FixedValidatorLockStateError, VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorSignedVoteV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::*;

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

fn expect_rejected<'node>(
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
            panic!("expected the input to be rejected before signing")
        }
        FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(_) => {
            panic!("an input rejection must not stop the signer")
        }
    }
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

fn prevote_certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    target: ConsensusVoteTarget,
    signer: &SigningKey,
) -> Vec<u8> {
    let mut body = [0_u8; VOTE_BODY_BYTES];
    body[0] = 1;
    body[1..33].copy_from_slice(context.chain_id().as_bytes());
    body[33..65].copy_from_slice(context.genesis_id().as_bytes());
    body[65..69].copy_from_slice(&context.protocol_version().value().to_be_bytes());
    body[69..77].copy_from_slice(&position.height().value().to_be_bytes());
    body[77..85].copy_from_slice(&position.round().value().to_be_bytes());
    match target {
        ConsensusVoteTarget::Nil => {
            body[85] = 0;
        }
        ConsensusVoteTarget::Proposal(root) => {
            body[85] = 1;
            body[86..].copy_from_slice(root.as_bytes());
        }
    }
    let key = consensus_key(signer);
    let mut transcript = b"naome:consensus-prevote-signing:v0\0".to_vec();
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(key.as_bytes());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    bytes
}

fn next_anchor_collision(directory: &Path, sequence: u64) -> PathBuf {
    let anchor_name = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".anchor"))
        .expect("one typed anchor file must exist");
    let collision = directory.join(format!("{anchor_name}.tmp-{sequence:016x}"));
    fs::write(&collision, b"deterministic anchor collision").unwrap();
    collision
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
        FixedValidatorSignerRecoveryRoundLimitV0::new(recovery_maximum_round),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    )
}

#[test]
fn proposal_and_matching_prevote_quorum_release_only_anchored_votes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-proposal");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let (root, certificate) = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let value = round.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());

            let (scope, prevote) = expect_signed(
                scope
                    .sign_prevote_for_proposal(&control, payload.clone(), ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(prevote.position(), round.position());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            assert!(!prevote.canonical_bytes().is_empty());

            let certificate = prevote_certificate_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            let (mut scope, precommit) = expect_signed(
                scope
                    .sign_precommit_for_proposal_quorum(
                        &control,
                        payload,
                        &certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(precommit.position(), round.position());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
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
            (root, certificate)
        })
        .unwrap();

    let after = layout.images();
    assert_eq!(before[0], after[0]);
    assert_eq!(before[1], after[1]);
    assert_ne!(before[2], after[2]);
    assert_ne!(before[3], after[3]);

    let reopened = expect_ready(
        fixture
            .provision(&layout, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(
                scope.signing_session().position().round(),
                ConsensusRound::new(0)
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
        })
        .unwrap();
}

#[test]
fn explicit_phase_closes_sign_nil_without_inferring_timeouts() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-explicit-closes");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (scope, prevote) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);

            let (mut scope, precommit) = expect_signed(
                scope
                    .sign_precommit_without_quorum(ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
            assert!(scope.signing_session().locked_value().is_none());
            assert!(scope.signing_session().valid_value().is_none());
        })
        .unwrap();
}

#[test]
fn exact_nil_prevote_quorum_signs_nil_precommit() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-nil-quorum");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    let valid_certificate = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let payload = proof_payload(ZfcAxiom::Pairing);
            let block = ArtifactChainState::new(fixture.definition)
                .prepare_block(artifact_id(&payload))
                .unwrap();
            let value = round_zero.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let control =
                proposal_control_bytes(value, round_zero.position(), &fixture.signing_key());
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_for_proposal(&control, payload.clone(), ConsensusRound::new(0))
                    .unwrap(),
            );
            let valid_certificate = prevote_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_for_proposal_quorum(
                        &control,
                        payload,
                        &valid_certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );

            let round_one = round_zero.advance_round().unwrap();
            scope.signing_session().advance_round(&round_one).unwrap();
            let (scope, prevote) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(1))
                    .unwrap(),
            );
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            let nil_certificate = prevote_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let (mut scope, precommit) = expect_signed(
                scope
                    .sign_precommit_for_nil_quorum(&nil_certificate, ConsensusRound::new(1))
                    .unwrap(),
            );
            assert_eq!(precommit.position(), round_one.position());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            assert!(scope.signing_session().locked_value().is_none());
            assert_eq!(
                scope
                    .signing_session()
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate(),
                valid_certificate
            );
            valid_certificate
        })
        .unwrap();

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
            assert!(scope.signing_session().locked_value().is_none());
            assert_eq!(
                scope
                    .signing_session()
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate(),
                valid_certificate
            );
        })
        .unwrap();
}

#[test]
fn invalid_quorum_is_a_no_write_rejection_and_preserves_the_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-invalid-quorum");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(0))
                    .unwrap(),
            );
            let before = layout.images();
            let (scope, rejection) = expect_rejected(
                scope
                    .sign_precommit_for_nil_quorum(&[0_u8], ConsensusRound::new(0))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Decision(source)
                    if matches!(source.as_ref(), FixedValidatorLockStateError::QuorumVerification(_))
            ));
            assert_eq!(layout.images(), before);

            let (_, vote) = expect_signed(
                scope
                    .sign_precommit_without_quorum(ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
            assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
        })
        .unwrap();
}

#[test]
fn pending_higher_round_work_precedes_caller_round_rejection() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-pending-before-round-limit");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    let error = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            let round_two = branch
                .begin_round_zero()
                .unwrap()
                .advance_round()
                .unwrap()
                .advance_round()
                .unwrap();
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(0))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_without_quorum(ConsensusRound::new(0))
                    .unwrap(),
            );
            scope.signing_session().advance_round(&round_one).unwrap();
            let payload = proof_payload(ZfcAxiom::Pairing);
            let block = ArtifactChainState::new(fixture.definition)
                .prepare_block(artifact_id(&payload))
                .unwrap();
            let root = round_two
                .value_for_artifact_block(block)
                .proposal_signing_root();
            let certificate = certificate_bytes(
                fixture.context,
                round_two.position(),
                root,
                &fixture.signing_key(),
            );
            let prepared = scope
                .signing_session()
                .prepare_higher_round_quorum_advance(
                    &round_one,
                    &certificate,
                    ConsensusRound::new(2),
                )
                .unwrap();
            drop(prepared);

            match scope.sign_prevote_without_proposal(ConsensusRound::new(0)) {
                Err(error) => error,
                Ok(_) => panic!("pending session work must consume the scope"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeVoteExecutionErrorV0::Session(source)
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::PendingHigherRoundAdvance { .. }
            )
    ));

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
        })
        .unwrap();
}

#[test]
fn pending_higher_round_work_precedes_malformed_proposal_rejection() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-pending-before-proposal");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    let error = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            let payload = proof_payload(ZfcAxiom::Pairing);
            let block = ArtifactChainState::new(fixture.definition)
                .prepare_block(artifact_id(&payload))
                .unwrap();
            let root = round_one
                .value_for_artifact_block(block)
                .proposal_signing_root();
            let certificate = certificate_bytes(
                fixture.context,
                round_one.position(),
                root,
                &fixture.signing_key(),
            );
            let prepared = scope
                .signing_session()
                .prepare_higher_round_quorum_advance(
                    &round_zero,
                    &certificate,
                    ConsensusRound::new(1),
                )
                .unwrap();
            drop(prepared);

            match scope.sign_prevote_for_proposal(&[0_u8], Vec::new(), ConsensusRound::new(0)) {
                Err(error) => error,
                Ok(_) => panic!("pending session work must precede proposal rejection"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeVoteExecutionErrorV0::Session(source)
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

#[test]
fn rejected_proposal_preserves_the_scope_for_an_explicit_close() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-rejected-proposal");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let value = round.value_for_artifact_block(block);
            let mut control =
                proposal_control_bytes(value, round.position(), &fixture.signing_key());
            let signature_byte =
                ConsensusValueV0::BYTE_LENGTH + VerifiedProducerAuthorizationV0::BYTE_LENGTH - 1;
            control[signature_byte] ^= 1;
            let before = layout.images();

            let (scope, rejection) = expect_rejected(
                scope
                    .sign_prevote_for_proposal(&control, payload, ConsensusRound::new(0))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(_)
            ));
            assert_eq!(layout.images(), before);

            let (_, vote) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
        })
        .unwrap();
}

#[test]
fn round_work_ceiling_rejection_preserves_scope_and_durable_state() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-round-ceiling");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(0))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_without_quorum(ConsensusRound::new(0))
                    .unwrap(),
            );
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            scope.signing_session().advance_round(&round_one).unwrap();
            let before = layout.images();

            let (scope, rejection) = expect_rejected(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(0))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);

            let (_, vote) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(1))
                    .unwrap(),
            );
            assert_eq!(vote.position(), round_one.position());
            assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
        })
        .unwrap();
}

#[test]
fn signer_above_the_node_finality_round_ceiling_returns_no_scope_or_vote() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-finality-round-ceiling");
    let ready = provision_with_finality_round_limit(&fixture, &layout, 1, 2)
        .create(fixture.signing_key())
        .unwrap();

    let (error, before) = ready
        .run_with_signing_session(|scope| {
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(0))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_without_quorum(ConsensusRound::new(0))
                    .unwrap(),
            );
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            scope.signing_session().advance_round(&round_one).unwrap();
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(1))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_without_quorum(ConsensusRound::new(1))
                    .unwrap(),
            );
            let round_two = round_one.advance_round().unwrap();
            scope.signing_session().advance_round(&round_two).unwrap();
            let before = layout.images();
            let error = match scope.sign_prevote_without_proposal(ConsensusRound::new(2)) {
                Err(error) => error,
                Ok(_) => panic!("a signer above finality capacity must return no scope or vote"),
            };
            (error, before)
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeVoteExecutionErrorV0::FinalityRoundLimitExceeded {
            required,
            maximum,
        } if required == ConsensusRound::new(2) && maximum == ConsensusRound::new(1)
    ));
    assert_eq!(layout.images(), before);

    let reopened = expect_ready(
        provision_with_finality_round_limit(&fixture, &layout, 1, 1)
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

#[test]
fn later_proposal_cannot_override_an_older_lock_without_valid_round_proof() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-locked-prevote");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let first_payload = proof_payload(ZfcAxiom::Pairing);
    let second_payload = proof_payload(ZfcAxiom::Union);
    let selected = ArtifactChainState::new(fixture.definition);
    let first_block = selected.prepare_block(artifact_id(&first_payload)).unwrap();
    let second_block = selected
        .prepare_block(artifact_id(&second_payload))
        .unwrap();

    let first_root = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let first_value = round_zero.value_for_artifact_block(first_block);
            let first_root = first_value.proposal_signing_root();
            let first_control =
                proposal_control_bytes(first_value, round_zero.position(), &fixture.signing_key());
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_for_proposal(
                        &first_control,
                        first_payload,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let quorum = prevote_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteTarget::Proposal(first_root),
                &fixture.signing_key(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_for_proposal_quorum(
                        &first_control,
                        proof_payload(ZfcAxiom::Pairing),
                        &quorum,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );

            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            scope.signing_session().advance_round(&round_one).unwrap();
            let second_value = round_one.value_for_artifact_block(second_block);
            let second_root = second_value.proposal_signing_root();
            assert_ne!(first_root, second_root);
            let second_control =
                proposal_control_bytes(second_value, round_one.position(), &fixture.signing_key());
            let (mut scope, prevote) = expect_signed(
                scope
                    .sign_prevote_for_proposal(
                        &second_control,
                        second_payload,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(first_root));
            assert_eq!(
                scope
                    .signing_session()
                    .locked_value()
                    .unwrap()
                    .proposal_signing_root(),
                first_root
            );
            first_root
        })
        .unwrap();

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
                FixedValidatorLockPhaseV0::Prevote
            );
            assert_eq!(
                scope
                    .signing_session()
                    .locked_value()
                    .unwrap()
                    .proposal_signing_root(),
                first_root
            );
        })
        .unwrap();
}

#[test]
fn vote_anchor_failure_returns_no_scope_and_reopens_only_as_anchor_behind() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.vote_anchor, 2);

    let error = ready
        .run_with_signing_session(|scope| {
            match scope.sign_prevote_without_proposal(ConsensusRound::new(0)) {
                Err(error) => error,
                Ok(_) => panic!("the vote anchor collision must return no scope or vote"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeVoteExecutionErrorV0::Prepare(source)
            if matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
    ));
    fs::remove_file(collision).unwrap();
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

#[test]
fn vote_completion_anchor_failure_returns_no_scope_vote_or_false_reopen() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-completion-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);

    let error = ready
        .run_with_signing_session(|scope| {
            match scope.sign_prevote_without_proposal(ConsensusRound::new(0)) {
                Err(error) => error,
                Ok(_) => panic!("the completion-anchor collision must return no scope or vote"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeVoteExecutionErrorV0::Sign(source)
            if matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
    ));
    fs::remove_file(collision).unwrap();
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
