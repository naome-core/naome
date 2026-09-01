use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusEnvelopeVerifyError, ConsensusProposalVerifyError, ConsensusVoteRole,
    ConsensusVoteTarget, FixedConsensusBoundedSeparateFinalityVerifyError,
    PrecommitCertificateVerifyError, VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    CandidateBackedFinalityErrorV0, FixedValidatorAnchoredFinalityJournalErrorV0,
    FixedValidatorAnchoredVoteSafetyJournalErrorV0, FixedValidatorFinalityJournalErrorV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::super::finality::{
    FixedValidatorNodeCurrentRoundFinalityErrorV0, FixedValidatorNodeCurrentRoundFinalityOutcomeV0,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0, FixedValidatorNodeLowerRoundFinalityErrorV0,
    FixedValidatorNodeLowerRoundFinalityOutcomeV0, FixedValidatorNodeLowerRoundFinalityRejectionV0,
};
use super::*;

fn expect_continuation(
    outcome: FixedValidatorNodeFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection } => (*scope, selection),
        FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(_) => {
            panic!("expected continued signing authority")
        }
    }
}

fn expect_current_round_finality(
    outcome: FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(outcome) => {
            expect_continuation(outcome)
        }
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected { .. } => {
            panic!("expected exact-current-round finality")
        }
    }
}

fn expect_current_round_finality_rejection(
    outcome: FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0,
) {
    match outcome {
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(_) => {
            panic!("expected a no-effect current-round finality rejection")
        }
    }
}

fn expect_lower_round_finality(
    outcome: FixedValidatorNodeLowerRoundFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeLowerRoundFinalityOutcomeV0::Finality(outcome) => {
            expect_continuation(outcome)
        }
        FixedValidatorNodeLowerRoundFinalityOutcomeV0::Rejected { .. } => {
            panic!("expected strictly lower-round finality")
        }
    }
}

fn expect_lower_round_finality_rejection(
    outcome: FixedValidatorNodeLowerRoundFinalityOutcomeV0<'_>,
) -> (
    FixedValidatorNodeSigningScopeV0<'_>,
    FixedValidatorNodeLowerRoundFinalityRejectionV0,
) {
    match outcome {
        FixedValidatorNodeLowerRoundFinalityOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeLowerRoundFinalityOutcomeV0::Finality(_) => {
            panic!("expected a no-effect lower-round finality rejection")
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SigningScopeDiagnosticsV0 {
    position: ConsensusPosition,
    phase: FixedValidatorLockPhaseV0,
    locked_value: Option<FixedValidatorLockedValueV0>,
    valid_value: Option<FixedValidatorValidValueV0>,
}

fn signing_scope_diagnostics(
    scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
) -> SigningScopeDiagnosticsV0 {
    let session = scope.signing_session();
    SigningScopeDiagnosticsV0 {
        position: session.position(),
        phase: session.phase(),
        locked_value: session.locked_value(),
        valid_value: session.valid_value().cloned(),
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

fn quorum_certificate_bytes(
    context: ConsensusContextV0,
    position: ConsensusPosition,
    role: ConsensusVoteRole,
    target: ConsensusVoteTarget,
    signers: &[&SigningKey],
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

    let domain: &[u8] = match role {
        ConsensusVoteRole::Prevote => b"naome:consensus-prevote-signing:v0\0",
        ConsensusVoteRole::Precommit => b"naome:consensus-precommit-signing:v0\0",
    };
    let mut entries = signers
        .iter()
        .map(|signer| {
            let key = consensus_key(signer);
            let mut transcript = Vec::new();
            transcript.extend_from_slice(domain);
            transcript.extend_from_slice(&body);
            transcript.extend_from_slice(key.as_bytes());
            (key, signer.sign(&transcript).to_bytes())
        })
        .collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(key, _)| *key);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(
        &u16::try_from(entries.len())
            .expect("test certificates remain within the validator bound")
            .to_be_bytes(),
    );
    for (key, signature) in entries {
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&signature);
    }
    bytes
}

fn round_at(branch: &FixedConsensusBranchV0, round: u64) -> FixedConsensusRoundV0<'_> {
    let mut cursor = branch.begin_round_zero().unwrap();
    for _ in 0..round {
        cursor = cursor.advance_round().unwrap();
    }
    cursor
}

fn advance_signer_round_without_writing(
    scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
    next_round: &FixedConsensusRoundV0<'_>,
) {
    let _ = scope
        .signing_session()
        .decide_prevote_without_proposal()
        .unwrap();
    let _ = scope
        .signing_session()
        .decide_precommit_without_quorum()
        .unwrap();
    scope.signing_session().advance_round(next_round).unwrap();
}

fn current_round_finality_inputs(
    branch: &FixedConsensusBranchV0,
    selected: &ArtifactChainState,
    axiom: ZfcAxiom,
    round: u64,
    proposer: &SigningKey,
    certificate_signers: &[&SigningKey],
) -> (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    ConsensusPosition,
    ConsensusValueV0,
) {
    let payload = proof_payload(axiom);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let cursor = round_at(branch, round);
    let position = cursor.position();
    let value = cursor.value_for_artifact_block(block);
    let root = value.proposal_signing_root();
    let control = proposal_control_bytes(value, position, proposer);
    let certificate = quorum_certificate_bytes(
        value.context(),
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        certificate_signers,
    );
    (control, payload, certificate, position, value)
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

#[test]
fn new_finality_advances_both_anchors_before_returning_the_next_signer() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-success");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let original_branch = scope.branch().clone();
            let before_first = layout.images();
            let first = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let (scope, selection) =
                expect_continuation(scope.commit_verified_finality(first).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 1
            ));
            assert_eq!(scope.signing_session.position().height().value(), 2);
            assert_eq!(scope.signing_session.position().round().value(), 0);
            assert_eq!(
                scope.finality.head().unwrap().coordinate(),
                scope.branch.coordinate()
            );
            let after_first = layout.images();
            for (index, (before, after)) in before_first.iter().zip(&after_first).enumerate() {
                assert_ne!(before, after, "durable image {index} did not advance");
            }

            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 1);
            let (mut scope, selection) =
                expect_continuation(scope.commit_verified_finality(second).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 2 && position.round().value() == 1
            ));
            assert_eq!(scope.signing_session().position().height().value(), 3);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.finality().head().unwrap().coordinate(),
                scope.branch().coordinate()
            );
            let after_second = layout.images();
            for (index, (before, after)) in after_first.iter().zip(&after_second).enumerate() {
                assert_ne!(before, after, "durable image {index} did not advance");
            }

            let stale_round = original_branch.begin_round_zero().unwrap();
            let current_branch = scope.branch().clone();
            let current_round = current_branch.begin_round_zero().unwrap();
            let session = scope.signing_session();
            let stale_effect = session.decide_prevote_without_proposal().unwrap();
            assert!(session.prepare_vote(&stale_round, stale_effect).is_err());
            let current_effect = session.decide_precommit_without_quorum().unwrap();
            let prepared = match session
                .prepare_vote(&current_round, current_effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the child-height precommit must prepare exactly once"),
            };
            prepare_and_sign(session, &current_round, prepared);
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();
    assert_eq!(signer_position.height().value(), 3);

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn one_child_continuation_strictly_reopens_without_signer_catch_up() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-one-child-reopen");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let (mut scope, selection) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 1
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "durable image {index} did not advance");
            }
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn current_round_finality_at_nonzero_round_advances_all_four_files_and_strictly_reopens() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-success");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            assert_eq!(layout.images(), before);

            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                1,
                &proposer,
                &[&proposer],
            );
            let (mut scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload,
                        &certificate,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual_position,
                    ancestry_id,
                    ..
                } if actual_position == position && ancestry_id == value.ancestry_id()
            ));
            assert_eq!(scope.signing_session().position().height().value(), 2);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.finality().head().unwrap().coordinate(),
                scope.branch().coordinate()
            );
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "durable image {index} did not advance");
            }
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn nonzero_lower_round_finality_ignores_later_local_phase_and_strictly_reopens() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-success");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_two);
            let _ = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            assert_eq!(layout.images(), before);

            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                1,
                &proposer,
                &[&proposer],
            );
            let (mut scope, selection) = expect_lower_round_finality(
                scope
                    .commit_lower_round_finality(
                        &control,
                        payload,
                        &certificate,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual_position,
                    ancestry_id,
                    ..
                } if actual_position == position && ancestry_id == value.ancestry_id()
            ));
            assert_eq!(scope.signing_session().position().height().value(), 2);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            assert_eq!(
                scope.finality().head().unwrap().coordinate(),
                scope.branch().coordinate()
            );
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "durable image {index} did not advance");
            }
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
        })
        .unwrap();
}

#[test]
fn current_round_finality_from_healthy_prevote_phase_returns_child_continuation() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-prevote");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared = match scope
                .signing_session()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first prevote must prepare"),
            };
            prepare_and_sign(scope.signing_session(), &round, prepared);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );

            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                &proposer,
                &[&proposer],
            );
            let (mut scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload,
                        &certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual_position,
                    ancestry_id,
                    ..
                } if actual_position == position && ancestry_id == value.ancestry_id()
            ));
            assert_eq!(scope.signing_session().position().height().value(), 2);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
        })
        .unwrap();
}

#[test]
fn current_round_finality_commits_before_a_pending_signer_handoff_fails() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-pending");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let (prepared_vote, finality_state_id) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                &proposer,
                &[&proposer],
            );
            let effect = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first vote must leave one durable preparation"),
            };
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            let before_finality = layout.images();
            let finality_state_id = match scope.commit_current_round_finality(
                &control,
                payload,
                &certificate,
                ConsensusRound::new(0),
            ) {
                Err(FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(source)) => {
                    match source.as_ref() {
                        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                            selection,
                            source,
                        } => {
                            assert!(matches!(
                                source.as_ref(),
                                FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. }
                            ));
                            match selection.as_ref() {
                                FixedValidatorNodeFinalitySelectionV0::Finalized {
                                    position: actual_position,
                                    ancestry_id,
                                    state_id,
                                    ..
                                } => {
                                    assert_eq!(*actual_position, position);
                                    assert_eq!(*ancestry_id, value.ancestry_id());
                                    *state_id
                                }
                                _ => panic!("the failure must retain the direct finality result"),
                            }
                        }
                        _ => panic!("pending signer work must fail at the height handoff"),
                    }
                }
                _ => panic!("valid finality must not be suppressed by pending signer work"),
            };
            let after_finality = layout.images();
            assert_ne!(after_finality[0], before_finality[0]);
            assert_ne!(after_finality[1], before_finality[1]);
            assert_eq!(after_finality[2], before_finality[2]);
            assert_eq!(after_finality[3], before_finality[3]);
            (prepared_vote, finality_state_id)
        })
        .unwrap();

    let finality = fixture.open_finality(&layout);
    assert_eq!(finality.state_id().unwrap(), finality_state_id);
    drop(finality);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), prepared_vote.position());
            assert_eq!(pending.role(), prepared_vote.role());
            assert_eq!(pending.target(), prepared_vote.target());
            assert_eq!(pending.state_id(), prepared_vote.state_id());
        }
        _ => panic!("strict restart must expose the durable pending signer state"),
    }
}

#[test]
fn lower_round_finality_commits_before_a_pending_signer_handoff_fails() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-pending");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let (prepared_vote, finality_state_id) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                &proposer,
                &[&proposer],
            );
            let effect = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session()
                .prepare_vote(&round_one, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first later-round vote must leave one durable preparation"),
            };
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            let before_finality = layout.images();
            let finality_state_id = match scope.commit_lower_round_finality(
                &control,
                payload,
                &certificate,
                ConsensusRound::new(0),
            ) {
                Err(FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(source)) => {
                    match source.as_ref() {
                        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                            selection,
                            source,
                        } => {
                            assert!(matches!(
                                source.as_ref(),
                                FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. }
                            ));
                            match selection.as_ref() {
                                FixedValidatorNodeFinalitySelectionV0::Finalized {
                                    position: actual_position,
                                    ancestry_id,
                                    state_id,
                                    ..
                                } => {
                                    assert_eq!(*actual_position, position);
                                    assert_eq!(*ancestry_id, value.ancestry_id());
                                    *state_id
                                }
                                _ => panic!(
                                    "the failure must retain the lower-round finality result"
                                ),
                            }
                        }
                        _ => panic!("pending signer work must fail at the height handoff"),
                    }
                }
                _ => panic!("valid lower-round finality must not be suppressed by pending work"),
            };
            let after_finality = layout.images();
            assert_ne!(after_finality[0], before_finality[0]);
            assert_ne!(after_finality[1], before_finality[1]);
            assert_eq!(after_finality[2], before_finality[2]);
            assert_eq!(after_finality[3], before_finality[3]);
            (prepared_vote, finality_state_id)
        })
        .unwrap();

    let finality = fixture.open_finality(&layout);
    assert_eq!(finality.state_id().unwrap(), finality_state_id);
    drop(finality);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), prepared_vote.position());
            assert_eq!(pending.role(), prepared_vote.role());
            assert_eq!(pending.target(), prepared_vote.target());
            assert_eq!(pending.state_id(), prepared_vote.state_id());
        }
        _ => panic!("strict restart must expose the durable pending signer state"),
    }
}

#[test]
fn current_round_finality_input_rejections_preserve_all_files_and_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-rejections");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                1,
                &proposer,
                &[&proposer],
            );
            let root = value.proposal_signing_root();
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);

            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &[0_u8],
                        payload.clone(),
                        &certificate,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::InvalidLength { .. }
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let mismatching_payload = proof_payload(ZfcAxiom::Union);
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        mismatching_payload,
                        &certificate,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::ArtifactValidation(_)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &[0_u8],
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::InvalidLength { .. }
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let prevote = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(root),
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &prevote,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::WrongVoteRole {
                                actual: ConsensusVoteRole::Prevote,
                            }
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let nil_precommit = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &nil_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::NilCertificateTarget
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let wrong_root = ProposalSigningRoot::from_bytes([0x5a; 32]);
            assert_ne!(wrong_root, root);
            let wrong_root_precommit = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(wrong_root),
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &wrong_root_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificateRootMismatch {
                            expected,
                            actual,
                        } if *expected == root && *actual == wrong_root
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let other_position = ConsensusPosition::new(position.height(), ConsensusRound::new(2));
            let other_round_precommit = quorum_certificate_bytes(
                fixture.context,
                other_position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &other_round_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::SnapshotPositionMismatch {
                                certificate,
                                snapshot,
                            }
                        ) if *certificate == other_position && *snapshot == position
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let wrong_context = ConsensusContextV0::new(
                fixture.context.chain_id(),
                ConsensusGenesisId::from_bytes([0x93; 32]),
                fixture.context.protocol_version(),
            );
            let wrong_context_precommit = quorum_certificate_bytes(
                wrong_context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &wrong_context_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::GenesisIdMismatch {
                                expected,
                                actual,
                            }
                        ) if *expected == fixture.context.genesis_id()
                            && *actual == wrong_context.genesis_id()
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let foreign_signer = SigningKey::from_bytes(&signing_seed(93));
            let foreign_set_precommit = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                &[&foreign_signer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &foreign_set_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::UnknownSigner { signer }
                        ) if *signer == consensus_key(&foreign_signer)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let mut invalid_signature = certificate.clone();
            *invalid_signature
                .last_mut()
                .expect("one-signer certificate has a signature") ^= 0x80;
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &invalid_signature,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::InvalidSignature { signer }
                        ) if *signer == consensus_key(&proposer)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (_scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload,
                        &certificate,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual,
                    ..
                } if actual == position
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "retry did not advance durable image {index}");
            }
        })
        .unwrap();
}

#[test]
fn lower_round_finality_rejections_preserve_scope_files_and_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-rejections");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_two);
            let (control_zero, payload_zero, certificate_zero, position_zero, value_zero) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Pairing,
                    0,
                    &proposer,
                    &[&proposer],
                );
            let (_control_one, payload_one, certificate_one, _, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Union,
                    1,
                    &proposer,
                    &[&proposer],
                );
            let (_, payload_two, certificate_two, _, _) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Infinity,
                2,
                &proposer,
                &[&proposer],
            );
            let (_, payload_three, certificate_three, _, _) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Extensionality,
                3,
                &proposer,
                &[&proposer],
            );
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_one,
                        &certificate_one,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_two,
                        &certificate_two,
                        ConsensusRound::new(8),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                    evidence,
                    signer,
                } if evidence == ConsensusRound::new(2) && signer == ConsensusRound::new(2)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_three,
                        &certificate_three,
                        ConsensusRound::new(8),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                    evidence,
                    signer,
                } if evidence == ConsensusRound::new(3) && signer == ConsensusRound::new(2)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let wrong_height = ConsensusPosition::new(
                ConsensusHeight::new(position_zero.height().value() + 1),
                ConsensusRound::new(0),
            );
            let wrong_height_certificate = quorum_certificate_bytes(
                fixture.context,
                wrong_height,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value_zero.proposal_signing_root()),
                &[&proposer],
            );
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_zero.clone(),
                        &wrong_height_certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::CertificateHeightMismatch {
                            expected,
                            actual,
                        } if *expected == position_zero.height() && *actual == wrong_height.height()
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero.clone(),
                        &[0_u8],
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::EmbeddedCertificatePosition(_)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_zero.clone(),
                        &certificate_zero,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                            ConsensusProposalVerifyError::InvalidLength { .. }
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        proof_payload(ZfcAxiom::Union),
                        &certificate_zero,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                            ConsensusProposalVerifyError::ArtifactValidation(_)
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let mut invalid_signature = certificate_zero.clone();
            *invalid_signature
                .last_mut()
                .expect("one-signer certificate has a signature") ^= 0x80;
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero.clone(),
                        &invalid_signature,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(
                            ConsensusEnvelopeVerifyError::PrecommitCertificate(
                                PrecommitCertificateVerifyError::InvalidSignature { signer }
                            )
                        ) if *signer == consensus_key(&proposer)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let prevote = quorum_certificate_bytes(
                fixture.context,
                position_zero,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(value_zero.proposal_signing_root()),
                &[&proposer],
            );
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero.clone(),
                        &prevote,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(
                            ConsensusEnvelopeVerifyError::PrecommitCertificate(
                                PrecommitCertificateVerifyError::WrongVoteRole {
                                    actual: ConsensusVoteRole::Prevote,
                                }
                            )
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let nil_precommit = quorum_certificate_bytes(
                fixture.context,
                position_zero,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &[&proposer],
            );
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero.clone(),
                        &nil_precommit,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(
                            ConsensusEnvelopeVerifyError::PrecommitCertificate(
                                PrecommitCertificateVerifyError::NilCertificateTarget
                            )
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (_scope, selection) = expect_lower_round_finality(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero,
                        &certificate_zero,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual,
                    ..
                } if actual == position_zero
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "retry did not advance durable image {index}");
            }
        })
        .unwrap();
}

#[test]
fn insufficient_current_round_precommits_preserve_scope_before_a_quorum_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-insufficient");
    let local_seed = signing_seed(41);
    let local = SigningKey::from_bytes(&local_seed);
    let other = SigningKey::from_bytes(&signing_seed(42));
    let entries = [
        ActiveAgreementEntry::new(consensus_key(&local), AgreementWeight::new(1)),
        ActiveAgreementEntry::new(consensus_key(&other), AgreementWeight::new(2)),
    ];
    let ready = FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        &entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    )
    .create(SigningKey::from_bytes(&local_seed))
    .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let proposer = if round.proposer() == consensus_key(&local) {
                &local
            } else {
                assert_eq!(round.proposer(), consensus_key(&other));
                &other
            };
            let (control, payload, insufficient, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                proposer,
                &[&local],
            );
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);
            let (mut scope, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &insufficient,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::InsufficientAgreementWeight {
                                signed,
                                total,
                            }
                        ) if *signed == AgreementWeight::new(1)
                            && *total == AgreementWeight::new(3)
                    )
            ));
            assert_eq!(layout.images(), before);
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let sufficient = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &[&local, &other],
            );
            let (_scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload,
                        &sufficient,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual,
                    ..
                } if actual == position
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(
                    old, new,
                    "quorum retry did not advance durable image {index}"
                );
            }
        })
        .unwrap();
}

#[test]
fn insufficient_lower_round_precommits_preserve_scope_before_a_quorum_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-insufficient");
    let local_seed = signing_seed(41);
    let local = SigningKey::from_bytes(&local_seed);
    let other = SigningKey::from_bytes(&signing_seed(42));
    let entries = [
        ActiveAgreementEntry::new(consensus_key(&local), AgreementWeight::new(1)),
        ActiveAgreementEntry::new(consensus_key(&other), AgreementWeight::new(2)),
    ];
    let ready = FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        &entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    )
    .create(SigningKey::from_bytes(&local_seed))
    .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let proposer = if round_zero.proposer() == consensus_key(&local) {
                &local
            } else {
                assert_eq!(round_zero.proposer(), consensus_key(&other));
                &other
            };
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let (control, payload, insufficient, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                proposer,
                &[&local],
            );
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);
            let (mut scope, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control,
                        payload.clone(),
                        &insufficient,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(
                            ConsensusEnvelopeVerifyError::PrecommitCertificate(
                                PrecommitCertificateVerifyError::InsufficientAgreementWeight {
                                    signed,
                                    total,
                                }
                            )
                        ) if *signed == AgreementWeight::new(1)
                            && *total == AgreementWeight::new(3)
                    )
            ));
            assert_eq!(layout.images(), before);
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let sufficient = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &[&local, &other],
            );
            let (_scope, selection) = expect_lower_round_finality(
                scope
                    .commit_lower_round_finality(
                        &control,
                        payload,
                        &sufficient,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual,
                    ..
                } if actual == position
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(
                    old, new,
                    "quorum retry did not advance durable image {index}"
                );
            }
        })
        .unwrap();
}

#[test]
fn persisted_finality_round_ceiling_is_fatal_before_input_parsing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-persisted-ceiling");
    let ready = provision_with_finality_round_limit(&fixture, &layout, 1, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_one);
            advance_signer_round_without_writing(&mut scope, &round_two);
            assert!(matches!(
                scope.commit_current_round_finality(
                    &[0_u8],
                    Vec::new(),
                    &[0_u8],
                    ConsensusRound::new(0),
                ),
                Err(
                    FixedValidatorNodeCurrentRoundFinalityErrorV0::FinalityRoundLimitExceeded {
                        required,
                        maximum,
                    }
                ) if required == ConsensusRound::new(2)
                    && maximum == ConsensusRound::new(1)
            ));
            assert_eq!(layout.images(), before);
        })
        .unwrap();

    let reopened = expect_ready(
        provision_with_finality_round_limit(&fixture, &layout, 1, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn lower_round_finality_checks_persisted_signer_ceiling_before_input_parsing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-persisted-ceiling");
    let ready = provision_with_finality_round_limit(&fixture, &layout, 1, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_one);
            advance_signer_round_without_writing(&mut scope, &round_two);
            assert!(matches!(
                scope.commit_lower_round_finality(
                    &[0_u8],
                    Vec::new(),
                    &[0_u8],
                    ConsensusRound::new(0),
                ),
                Err(
                    FixedValidatorNodeLowerRoundFinalityErrorV0::FinalityRoundLimitExceeded {
                        required,
                        maximum,
                    }
                ) if required == ConsensusRound::new(2)
                    && maximum == ConsensusRound::new(1)
            ));
            assert_eq!(layout.images(), before);
        })
        .unwrap();

    let reopened = expect_ready(
        provision_with_finality_round_limit(&fixture, &layout, 1, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn candidate_backed_children_advance_the_node_without_mutating_sources() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-live-finality");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let first = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let first_target = first_block.id();
            retain_transition_inputs(&mut candidates, &mut payloads, scope.branch(), &first);
            let node_before_first = layout.images();
            let sources_before_first = layout.source_images();
            let (scope, selection) = expect_continuation(
                scope
                    .commit_candidate_backed_finality(
                        &mut candidates,
                        &mut payloads,
                        first_target,
                        first.canonical_envelope_bytes(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let first_state_id = match selection {
                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                    target,
                    position,
                    ancestry_id,
                    envelope_id,
                    state_id,
                } => {
                    assert_eq!(target, first_target);
                    assert_eq!(position, first.position());
                    assert_eq!(ancestry_id, first.value().ancestry_id());
                    assert_eq!(envelope_id, first.envelope_id());
                    state_id
                }
                _ => panic!("the retained child must report candidate-backed finality"),
            };
            let node_after_first = layout.images();
            for (index, (before, after)) in
                node_before_first.iter().zip(&node_after_first).enumerate()
            {
                assert_ne!(before, after, "node durable image {index} did not advance");
            }
            assert_eq!(layout.source_images(), sources_before_first);
            assert_eq!(scope.finality.state_id().unwrap(), first_state_id);
            assert_eq!(
                scope
                    .finality
                    .head()
                    .unwrap()
                    .artifact_snapshot()
                    .head_block_id(),
                first_target
            );
            assert_eq!(
                scope.branch.artifact_snapshot().head_block_id(),
                first_target
            );
            assert_eq!(scope.signing_session.position().height().value(), 2);
            assert_eq!(scope.signing_session.position().round().value(), 0);
            assert_eq!(
                scope.finality.head().unwrap().coordinate(),
                scope.branch.coordinate()
            );

            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 1);
            let second_target = second.value().artifact_block().id();
            retain_transition_inputs(&mut candidates, &mut payloads, scope.branch(), &second);
            let sources_before_second = layout.source_images();
            let (mut scope, selection) = expect_continuation(
                scope
                    .commit_candidate_backed_finality(
                        &mut candidates,
                        &mut payloads,
                        second_target,
                        second.canonical_envelope_bytes(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            let second_state_id = match selection {
                FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                    target,
                    position,
                    ancestry_id,
                    envelope_id,
                    state_id,
                } => {
                    assert_eq!(target, second_target);
                    assert_eq!(position, second.position());
                    assert_eq!(ancestry_id, second.value().ancestry_id());
                    assert_eq!(envelope_id, second.envelope_id());
                    state_id
                }
                _ => panic!("the retained child must report candidate-backed finality"),
            };
            let node_after_second = layout.images();
            for (index, (before, after)) in
                node_after_first.iter().zip(&node_after_second).enumerate()
            {
                assert_ne!(before, after, "node durable image {index} did not advance");
            }
            assert_eq!(layout.source_images(), sources_before_second);
            assert_eq!(scope.finality().state_id().unwrap(), second_state_id);
            assert_eq!(
                scope
                    .finality()
                    .head()
                    .unwrap()
                    .artifact_snapshot()
                    .head_block_id(),
                second_target
            );
            assert_eq!(
                scope.branch().artifact_snapshot().head_block_id(),
                second_target
            );
            assert_eq!(scope.signing_session().position().height().value(), 3);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.finality().head().unwrap().coordinate(),
                scope.branch().coordinate()
            );
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn missing_candidate_consumes_the_scope_without_mutating_any_store() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-missing");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let target = transition.value().artifact_block().id();
            let node_before = layout.images();
            let sources_before = layout.source_images();
            assert!(matches!(
                scope.commit_candidate_backed_finality(
                    &mut candidates,
                    &mut payloads,
                    target,
                    transition.canonical_envelope_bytes(),
                    ConsensusRound::new(0),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::CandidateUnavailable { target: actual }
                            if *actual == target
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();
}

#[test]
fn pending_vote_after_candidate_finality_returns_the_known_selection_without_a_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-pending");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let (prepared_vote, finality_state_id) = ready
        .run_with_signing_session(|mut scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let target = transition.value().artifact_block().id();
            retain_transition_inputs(&mut candidates, &mut payloads, scope.branch(), &transition);
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first vote must leave one durable preparation"),
            };
            let node_before = layout.images();
            let sources_before = layout.source_images();
            let finality_state_id = match scope.commit_candidate_backed_finality(
                &mut candidates,
                &mut payloads,
                target,
                transition.canonical_envelope_bytes(),
                ConsensusRound::new(0),
            ) {
                Err(FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                    selection,
                    source,
                }) => {
                    assert!(matches!(
                        source.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. }
                    ));
                    match selection.as_ref() {
                        FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                            target: actual,
                            position,
                            ancestry_id,
                            envelope_id,
                            state_id,
                        } => {
                            assert_eq!(*actual, target);
                            assert_eq!(*position, transition.position());
                            assert_eq!(*ancestry_id, transition.value().ancestry_id());
                            assert_eq!(*envelope_id, transition.envelope_id());
                            *state_id
                        }
                        _ => panic!("the failure must retain the candidate-backed selection"),
                    }
                }
                _ => panic!("the pending vote must prevent signer height preparation"),
            };
            let node_after = layout.images();
            assert_ne!(node_after[0], node_before[0]);
            assert_ne!(node_after[1], node_before[1]);
            assert_eq!(node_after[2], node_before[2]);
            assert_eq!(node_after[3], node_before[3]);
            assert_eq!(layout.source_images(), sources_before);
            (prepared_vote, finality_state_id)
        })
        .unwrap();
    drop(candidates);
    drop(payloads);
    let finality = fixture.open_finality(&layout);
    assert_eq!(finality.state_id().unwrap(), finality_state_id);
    drop(finality);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), prepared_vote.position());
            assert_eq!(pending.role(), prepared_vote.role());
            assert_eq!(pending.target(), prepared_vote.target());
            assert_eq!(pending.state_id(), prepared_vote.state_id());
        }
        _ => panic!("strict restart must expose the durable pending signer state"),
    }
}

#[test]
fn exact_selected_replay_is_no_write_and_returns_the_unchanged_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-replay");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let retained_envelope_id = first.envelope_id();
            let replay = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 1);
            assert_ne!(replay.envelope_id(), retained_envelope_id);
            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            let coordinate = scope.branch().coordinate();
            let position = scope.signing_session.position();
            let before_replay = layout.images();
            let (scope, selection) =
                expect_continuation(scope.commit_verified_finality(replay).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::AlreadyFinalized {
                    height,
                    retained_envelope_id: actual,
                    ..
                } if height.value() == 1 && actual == retained_envelope_id
            ));
            assert_eq!(scope.branch().coordinate(), coordinate);
            assert_eq!(scope.signing_session.position(), position);
            assert_eq!(layout.images(), before_replay);
        })
        .unwrap();
}

#[test]
fn verified_sibling_conflict_returns_only_terminal_signer_stop_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-conflict");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let stopped = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let left = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let right = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 0);
            let (mut scope, _) = expect_continuation(scope.commit_verified_finality(left).unwrap());
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            assert!(matches!(
                scope
                    .signing_session()
                    .prepare_vote(&round, effect)
                    .unwrap(),
                FixedValidatorVotePrepareOutcomeV0::Prepared(_)
            ));
            match scope.commit_verified_finality(right).unwrap() {
                FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(stopped) => *stopped,
                FixedValidatorNodeFinalityOutcomeV0::Continues { .. } => {
                    panic!("a distinct verified sibling must not return signing authority")
                }
            }
        })
        .unwrap();
    assert_eq!(
        stopped.signer_stop().height(),
        stopped.finality_halt().height()
    );
    assert_eq!(
        stopped.signer_stop().finality_state_id(),
        stopped.finality_halt().state_id()
    );
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must preserve the coordinated terminal state"),
    }
}

#[test]
fn candidate_backed_historical_sibling_stops_finality_and_signer_without_mutating_sources() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-finality-conflict");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let stopped = ready
        .run_with_signing_session(|scope| {
            let genesis = scope.branch().clone();
            let mut selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(&genesis, &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let selected_ancestry = first.value().ancestry_id();

            let sibling = fixture.transition(&genesis, &selected, ZfcAxiom::Union, 2);
            let sibling_target = sibling.value().artifact_block().id();
            let sibling_ancestry = sibling.value().ancestry_id();
            let sibling_envelope = sibling.canonical_envelope_bytes().to_vec();
            retain_transition_inputs(&mut candidates, &mut payloads, &genesis, &sibling);

            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::PowerSet, 0);
            let (mut scope, _) =
                expect_continuation(scope.commit_verified_finality(second).unwrap());

            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            assert!(matches!(
                scope
                    .signing_session()
                    .prepare_vote(&round, effect)
                    .unwrap(),
                FixedValidatorVotePrepareOutcomeV0::Prepared(_)
            ));

            let node_before = layout.images();
            let sources_before = layout.source_images();
            let stopped = scope
                .commit_candidate_backed_finality_conflict(
                    &mut candidates,
                    &mut payloads,
                    sibling_target,
                    &sibling_envelope,
                    ConsensusRound::new(2),
                )
                .unwrap();
            let node_after = layout.images();
            for (index, (before, after)) in node_before.iter().zip(&node_after).enumerate() {
                assert_ne!(before, after, "node durable image {index} did not advance");
            }
            assert_eq!(layout.source_images(), sources_before);
            assert_eq!(stopped.finality_halt().height().value(), 1);
            assert_eq!(
                stopped.finality_halt().selected_ancestry(),
                selected_ancestry
            );
            assert_eq!(
                stopped.finality_halt().conflicting_ancestry(),
                sibling_ancestry
            );
            assert_eq!(
                stopped.signer_stop().finality_state_id(),
                stopped.finality_halt().state_id()
            );
            stopped
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must preserve the candidate-backed terminal state"),
    }
}

#[test]
fn candidate_backed_same_selected_value_consumes_scope_without_source_or_node_writes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("candidate-backed-finality-conflict-same-value");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let target = transition.value().artifact_block().id();
            let envelope = transition.canonical_envelope_bytes().to_vec();
            let (scope, _) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            let node_before = layout.images();
            let sources_before = layout.source_images();
            assert!(matches!(
                scope.commit_candidate_backed_finality_conflict(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &envelope,
                    ConsensusRound::new(0),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height }
                            if height.value() == 1
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();
}

#[test]
fn unselected_parent_rejection_changes_no_durable_bytes_and_consumes_the_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-unselected");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let genesis_state = ArtifactChainState::new(fixture.definition);
            let selected = fixture.transition(scope.branch(), &genesis_state, ZfcAxiom::Pairing, 0);
            let unselected_parent =
                fixture.transition(scope.branch(), &genesis_state, ZfcAxiom::Union, 0);
            let unselected_block = unselected_parent.value().artifact_block();
            let unselected_payload = unselected_parent.canonical_artifact_bytes().to_vec();
            let unselected_branch = unselected_parent.into_branch();
            let mut unselected_state = ArtifactChainState::new(fixture.definition);
            unselected_state
                .apply_block(&unselected_block, unselected_payload)
                .unwrap();
            let unreachable_child =
                fixture.transition(&unselected_branch, &unselected_state, ZfcAxiom::PowerSet, 0);

            let (scope, _) = expect_continuation(scope.commit_verified_finality(selected).unwrap());
            let before_rejection = layout.images();
            assert!(matches!(
                scope.commit_verified_finality(unreachable_child),
                Err(FixedValidatorNodeFinalityErrorV0::Commit(source))
                    if matches!(
                        source.as_ref(),
                        FixedValidatorFinalityJournalErrorV0::UnselectedParent { height }
                            if height.value() == 2
                    )
            ));
            assert_eq!(layout.images(), before_rejection);
        })
        .unwrap();
}

#[test]
fn durable_pending_vote_makes_post_finality_handoff_fail_closed() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-pending");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let prepared_vote = ready
        .run_with_signing_session(|mut scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared_vote = match scope
                .signing_session()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first vote must leave one durable preparation"),
            };
            assert!(matches!(
                scope.commit_verified_finality(transition),
                Err(FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                    selection,
                    source,
                }) if matches!(
                        selection.as_ref(),
                        FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                            if position.height().value() == 1
                    )
                    && matches!(
                        source.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::PendingPreparation { .. }
                    )
            ));
            prepared_vote
        })
        .unwrap();
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::PendingPreparation(pending) => {
            assert_eq!(pending.position(), prepared_vote.position());
            assert_eq!(pending.state_id(), prepared_vote.state_id());
        }
        _ => panic!("strict restart must expose the durable pending signer state"),
    }
}

#[test]
fn finality_anchor_failure_returns_no_scope_and_reopens_only_as_anchor_behind() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.finality_anchor, 1);
    let error = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            match scope.commit_verified_finality(transition) {
                Err(error) => error,
                Ok(_) => panic!("the finality anchor collision must fail closed"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeFinalityErrorV0::Commit(source)
            if matches!(source.as_ref(), FixedValidatorFinalityJournalErrorV0::Commit { .. })
    ));
    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::FinalityPair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                    FixedValidatorFinalityJournalErrorV0::AnchorBehind { .. }
                )
            )
    ));
}

#[test]
fn signer_anchor_failure_preserves_known_finality_but_returns_no_scope() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-signer-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);
    let error = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            match scope.commit_verified_finality(transition) {
                Err(error) => error,
                Ok(_) => panic!("the signer anchor collision must fail closed"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
            selection,
            source,
        } if matches!(
                selection.as_ref(),
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 1
            )
            && matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
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
fn conflict_stop_anchor_failure_returns_no_scope_and_no_false_terminal_outcome() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-conflict-stop-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let error = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let left = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let right = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 0);
            let (scope, _) = expect_continuation(scope.commit_verified_finality(left).unwrap());
            let collision = next_anchor_collision(&layout.vote_anchor, 4);
            let error = match scope.commit_verified_finality(right) {
                Err(error) => error,
                Ok(_) => panic!("the signer-stop anchor collision must fail closed"),
            };
            fs::remove_file(collision).unwrap();
            error
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeFinalityErrorV0::SignerStop { halt, source }
            if halt.height().value() == 1
                && matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
    ));
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
