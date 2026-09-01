use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusContextV0, ConsensusPosition, ConsensusVoteTarget, FixedValidatorLockPhaseV0,
    FixedValidatorProposalIntentErrorV0, FixedValidatorProposalSourceV0,
};
use naome_storage::FixedValidatorSignedProposalV0;

use super::*;

fn expect_authored<'node>(
    outcome: FixedValidatorNodeProposalAuthoringOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorSignedProposalV0,
) {
    match outcome {
        FixedValidatorNodeProposalAuthoringOutcomeV0::Authored { scope, proposal } => {
            (*scope, proposal)
        }
        FixedValidatorNodeProposalAuthoringOutcomeV0::Rejected { .. } => {
            panic!("expected one durably completed proposal")
        }
        FixedValidatorNodeProposalAuthoringOutcomeV0::SignerStopped(_) => {
            panic!("expected continued signing authority")
        }
    }
}

fn expect_rejected<'node>(
    outcome: FixedValidatorNodeProposalAuthoringOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorNodeProposalAuthoringRejectionV0,
) {
    match outcome {
        FixedValidatorNodeProposalAuthoringOutcomeV0::Rejected { scope, rejection } => {
            (*scope, *rejection)
        }
        FixedValidatorNodeProposalAuthoringOutcomeV0::Authored { .. } => {
            panic!("expected proposal input rejection before durable preparation")
        }
        FixedValidatorNodeProposalAuthoringOutcomeV0::SignerStopped(_) => {
            panic!("pre-effect proposal rejection must not stop the signer")
        }
    }
}

fn expect_signed_vote<'node>(
    outcome: FixedValidatorNodeVoteExecutionOutcomeV0<'node>,
) -> FixedValidatorNodeSigningScopeV0<'node> {
    match outcome {
        FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, .. } => *scope,
        FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { .. } => {
            panic!("expected a completed vote")
        }
        FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(_) => {
            panic!("expected continued signing authority")
        }
    }
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
        ConsensusVoteTarget::Nil => body[85] = 0,
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

#[test]
fn fresh_proposal_authors_and_exact_replay_changes_no_durable_bytes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-fresh-replay");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let expected_root = round
                .value_for_artifact_block(block)
                .proposal_signing_root();
            let (scope, authored) = expect_authored(
                scope
                    .author_proposal(
                        FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: block,
                            canonical_artifact_bytes: payload.clone(),
                        },
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(authored.position(), round.position());
            assert_eq!(authored.proposal_signing_root(), expected_root);
            let verified = round
                .decode_and_verify_proposal_control(
                    authored.canonical_proposal_control_bytes(),
                    payload.clone(),
                )
                .unwrap();
            assert_eq!(verified.proposal_signing_root(), expected_root);

            let completed = layout.images();
            assert_eq!(completed[0], before[0]);
            assert_eq!(completed[1], before[1]);
            assert_ne!(completed[2], before[2]);
            assert_ne!(completed[3], before[3]);

            let (mut scope, replay) = expect_authored(
                scope
                    .author_proposal(
                        FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: block,
                            canonical_artifact_bytes: payload,
                        },
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(replay, authored);
            assert_eq!(layout.images(), completed);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            assert!(scope.signing_session().valid_value().is_none());
        })
        .unwrap();
}

#[test]
fn invalid_fresh_payload_preserves_scope_and_all_durable_files_for_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-rejected-payload");
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
            let before = layout.images();
            let (scope, rejection) = expect_rejected(
                scope
                    .author_proposal(
                        FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: block,
                            canonical_artifact_bytes: Vec::new(),
                        },
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorProposalIntentErrorV0::Value(_)
                    )
            ));
            assert_eq!(layout.images(), before);

            let (_, authored) = expect_authored(
                scope
                    .author_proposal(
                        FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: block,
                            canonical_artifact_bytes: payload,
                        },
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(!authored.canonical_proposal_control_bytes().is_empty());
        })
        .unwrap();
}

#[test]
fn retained_valid_value_is_reauthored_with_its_exact_earlier_prevote_proof() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-retained-valid");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let root = round_zero
                .value_for_artifact_block(block)
                .proposal_signing_root();
            let (scope, authored) = expect_authored(
                scope
                    .author_proposal(
                        FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: block,
                            canonical_artifact_bytes: payload.clone(),
                        },
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let scope = expect_signed_vote(
                scope
                    .sign_prevote_for_proposal(
                        authored.canonical_proposal_control_bytes(),
                        payload.clone(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let certificate = prevote_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            let mut scope = expect_signed_vote(
                scope
                    .sign_precommit_for_proposal_quorum(
                        authored.canonical_proposal_control_bytes(),
                        payload.clone(),
                        &certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let round_one = round_zero.advance_round().unwrap();
            scope.signing_session().advance_round(&round_one).unwrap();

            let before_wrong_source = layout.images();
            let (scope, rejection) = expect_rejected(
                scope
                    .author_proposal(
                        FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: block,
                            canonical_artifact_bytes: payload.clone(),
                        },
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorProposalIntentErrorV0::RetainedValidValueRequired
                    )
            ));
            assert_eq!(layout.images(), before_wrong_source);

            let (_, retained) = expect_authored(
                scope
                    .author_proposal(
                        FixedValidatorProposalSourceV0::RetainedValid {
                            canonical_artifact_bytes: payload.clone(),
                        },
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            let verified = round_one
                .decode_and_verify_proposal_control(
                    retained.canonical_proposal_control_bytes(),
                    payload,
                )
                .unwrap();
            assert_eq!(verified.proposal_signing_root(), root);
            assert_eq!(verified.valid_round(), Some(ConsensusRound::new(0)));
            assert_eq!(
                verified.valid_round_certificate_bytes(),
                Some(certificate.as_slice())
            );
        })
        .unwrap();

    let after = layout.images();
    // Proposal and vote safety state is durable, but no selected-finality
    // authority is implied by either the retained proof or local key use.
    assert_eq!(after[0], before[0]);
    assert_eq!(after[1], before[1]);
    assert_ne!(after[2], before[2]);
    assert_ne!(after[3], before[3]);
}

#[test]
fn conflicting_same_slot_proposal_stops_signer_and_restart_reports_proposal_safety() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-conflict-stop");
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
    let before = layout.images();

    let halt = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let first_root = round
                .value_for_artifact_block(first_block)
                .proposal_signing_root();
            let second_root = round
                .value_for_artifact_block(second_block)
                .proposal_signing_root();
            assert_ne!(first_root, second_root);

            let (scope, first) = expect_authored(
                scope
                    .author_proposal(
                        FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: first_block,
                            canonical_artifact_bytes: first_payload,
                        },
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(first.proposal_signing_root(), first_root);
            match scope
                .author_proposal(
                    FixedValidatorProposalSourceV0::Fresh {
                        artifact_block: second_block,
                        canonical_artifact_bytes: second_payload,
                    },
                    ConsensusRound::new(0),
                )
                .unwrap()
            {
                FixedValidatorNodeProposalAuthoringOutcomeV0::SignerStopped(halt) => {
                    assert_eq!(halt.position(), round.position());
                    assert_eq!(halt.retained_root(), first_root);
                    assert_eq!(halt.conflicting_root(), second_root);
                    halt
                }
                FixedValidatorNodeProposalAuthoringOutcomeV0::Authored { .. } => {
                    panic!("a second non-identical same-slot intent must not be signed")
                }
                FixedValidatorNodeProposalAuthoringOutcomeV0::Rejected { .. } => {
                    panic!("a fully valid conflicting intent must durably stop the signer")
                }
            }
        })
        .unwrap();

    let after = layout.images();
    // Proposal authoring changes only the signer pair. It neither selects the
    // candidate nor mutates the node-owned finality journal or anchor.
    assert_eq!(after[0], before[0]);
    assert_eq!(after[1], before[1]);
    assert_ne!(after[2], before[2]);
    assert_ne!(after[3], before[3]);

    match fixture
        .provision(&layout, 0)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::SignerStopped(
            FixedValidatorNodeSignerStopV0::ProposalSafety(restarted),
        ) => assert_eq!(restarted, halt),
        FixedValidatorNodeStartupV0::Ready(_)
        | FixedValidatorNodeStartupV0::FinalityStopped(_)
        | FixedValidatorNodeStartupV0::SignerStopped(_)
        | FixedValidatorNodeStartupV0::PendingProposal(_)
        | FixedValidatorNodeStartupV0::PendingPreparation(_) => {
            panic!("strict restart must expose the exact proposal-safety halt")
        }
    }
}
