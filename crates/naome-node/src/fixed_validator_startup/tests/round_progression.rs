use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusVoteRole, ConsensusVoteTarget, FixedValidatorLockPhaseV0,
    FixedValidatorLockStateError, ProposalSigningRoot,
};
use naome_storage::{
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorSignedVoteV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::*;

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
            panic!("expected authenticated round progression")
        }
    }
}

fn expect_rejected<'node>(
    outcome: FixedValidatorNodeRoundAdvanceOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorNodeRoundAdvanceRejectionV0,
) {
    match outcome {
        FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { .. } => {
            panic!("expected no-effect round-progression rejection")
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

fn quorum_certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signer: &SigningKey,
) -> Vec<u8> {
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
    let signer_key = consensus_key(signer);
    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut transcript = Vec::new();
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&body);
    transcript.extend_from_slice(signer_key.as_bytes());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(signer_key.as_bytes());
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

#[test]
fn nil_precommit_quorum_is_no_write_until_a_later_vote_persists_the_advanced_round() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-round-current-nil");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let (scope, rejection) = expect_rejected(
                scope
                    .advance_round_for_nil_precommit_quorum(&[0_u8], ConsensusRound::new(1))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeRoundAdvanceRejectionV0::Quorum(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::QuorumVerification(_)
                    )
            ));
            assert_eq!(layout.images(), before);

            let nil_precommit_quorum = quorum_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let (scope, position, phase) = expect_advanced(
                scope
                    .advance_round_for_nil_precommit_quorum(
                        &nil_precommit_quorum,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(position, round_at(&branch, 1).position());
            assert_eq!(phase, FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), before);

            let (scope, vote) = expect_signed(
                scope
                    .sign_prevote_without_proposal(ConsensusRound::new(1))
                    .unwrap(),
            );
            assert_eq!(vote.position(), position);
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
            drop(scope);
        })
        .unwrap();

    let after = layout.images();
    assert_eq!(after[0], before[0]);
    assert_eq!(after[1], before[1]);
    assert_ne!(after[2], before[2]);
    assert_ne!(after[3], before[3]);

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
        })
        .unwrap();
}

#[test]
fn higher_round_prevote_and_precommit_destinations_are_anchored_and_restart_exactly() {
    for (label, role, target, round_value, expected_phase) in [
        (
            "node-round-higher-prevote",
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Nil,
            2,
            FixedValidatorLockPhaseV0::Prevote,
        ),
        (
            "node-round-higher-precommit",
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes([0x93; 32])),
            3,
            FixedValidatorLockPhaseV0::Precommit,
        ),
    ] {
        let fixture = Fixture::new();
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, round_value)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();

        ready
            .run_with_signing_session(|scope| {
                let branch = scope.branch().clone();
                let target_round = round_at(&branch, round_value);
                let quorum = quorum_certificate_bytes(
                    fixture.context,
                    target_round.position(),
                    role,
                    target,
                    &fixture.signing_key(),
                );
                let (mut scope, position, phase) = expect_advanced(
                    scope
                        .advance_to_higher_round_quorum(&quorum, ConsensusRound::new(round_value))
                        .unwrap(),
                );
                assert_eq!(position, target_round.position());
                assert_eq!(phase, expected_phase);
                assert_eq!(scope.signing_session().position(), position);
                assert_eq!(scope.signing_session().phase(), phase);
                drop(scope);
            })
            .unwrap();

        let after = layout.images();
        assert_eq!(after[0], before[0]);
        assert_eq!(after[1], before[1]);
        assert_ne!(after[2], before[2]);
        assert_ne!(after[3], before[3]);

        let reopened = expect_ready(
            fixture
                .provision(&layout, round_value)
                .open(fixture.signing_key())
                .unwrap(),
        );
        reopened
            .run_with_signing_session(|mut scope| {
                assert_eq!(
                    scope.signing_session().position().round(),
                    ConsensusRound::new(round_value)
                );
                assert_eq!(scope.signing_session().phase(), expected_phase);
            })
            .unwrap();
    }
}

#[test]
fn destination_limits_and_malformed_higher_quorum_preserve_scope_and_bytes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-round-rejections");
    let ready = provision_with_finality_round_limit(&fixture, &layout, 1, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            let round_two = round_at(&branch, 2);
            let round_two_quorum = quorum_certificate_bytes(
                fixture.context,
                round_two.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let (scope, rejection) = expect_rejected(
                scope
                    .advance_to_higher_round_quorum(&round_two_quorum, ConsensusRound::new(1))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeRoundAdvanceRejectionV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(2)
                    && maximum == ConsensusRound::new(1)
            ));
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_rejected(
                scope
                    .advance_to_higher_round_quorum(&round_two_quorum, ConsensusRound::new(0))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1)
                    && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);

            let round_one_quorum = quorum_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let (scope, rejection) = expect_rejected(
                scope
                    .advance_to_higher_round_quorum(&round_one_quorum, ConsensusRound::new(0))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1)
                    && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);

            let (scope, rejection) = expect_rejected(
                scope
                    .advance_to_higher_round_quorum(&[0_u8], ConsensusRound::new(1))
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeRoundAdvanceRejectionV0::Quorum(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::HigherRoundCertificatePosition(_)
                    )
            ));
            assert_eq!(layout.images(), before);

            let (scope, position, phase) = expect_advanced(
                scope
                    .advance_to_higher_round_quorum(&round_one_quorum, ConsensusRound::new(1))
                    .unwrap(),
            );
            assert_eq!(position, round_one.position());
            assert_eq!(phase, FixedValidatorLockPhaseV0::Prevote);

            let after_higher = layout.images();
            let nil_precommit_quorum = quorum_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let (scope, rejection) = expect_rejected(
                scope
                    .advance_round_for_nil_precommit_quorum(
                        &nil_precommit_quorum,
                        ConsensusRound::new(2),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeRoundAdvanceRejectionV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(2)
                    && maximum == ConsensusRound::new(1)
            ));
            assert_eq!(layout.images(), after_higher);
            drop(scope);
        })
        .unwrap();
}

#[test]
fn pending_higher_round_checkpoint_precedes_malformed_input() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-round-pending-precedence");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    let error = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let round_one = round_at(&branch, 1);
            let quorum = quorum_certificate_bytes(
                fixture.context,
                round_one.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            let prepared = scope
                .signing_session()
                .prepare_higher_round_quorum_advance(&round_zero, &quorum, ConsensusRound::new(1))
                .unwrap();
            drop(prepared);

            match scope.advance_to_higher_round_quorum(&[0_u8], ConsensusRound::new(1)) {
                Err(error) => error,
                Ok(_) => panic!("pending session work must consume the scope before input parsing"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeRoundAdvanceErrorV0::Session(source)
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
fn higher_round_anchor_failure_consumes_scope_and_reopens_only_as_anchor_behind() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-round-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);

    let error = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_two = round_at(&branch, 2);
            let quorum = quorum_certificate_bytes(
                fixture.context,
                round_two.position(),
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Nil,
                &fixture.signing_key(),
            );
            match scope.advance_to_higher_round_quorum(&quorum, ConsensusRound::new(2)) {
                Err(error) => error,
                Ok(_) => panic!("the checkpoint anchor collision must return no scope"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeRoundAdvanceErrorV0::Prepare(source)
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
            )
    ));
    fs::remove_file(collision).unwrap();

    let after = layout.images();
    assert_eq!(after[0], before[0]);
    assert_eq!(after[1], before[1]);
    assert_ne!(after[2], before[2]);
    assert_eq!(after[3], before[3]);
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
