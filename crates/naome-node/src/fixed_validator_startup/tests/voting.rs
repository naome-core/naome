use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use naome_chain::ArtifactBlock;
use naome_consensus::{
    ConsensusProposalVerifyError, ConsensusVoteRole, ConsensusVoteTarget,
    FixedValidatorLockPhaseV0, FixedValidatorLockStateError, QuorumCertificateBuildError,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::{
    ArtifactBlockCandidateStoreError, CanonicalArtifactPayloadStoreError,
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

fn expect_current_round_finality<'node>(
    outcome: FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'node>,
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    FixedValidatorNodeFinalitySelectionV0,
) {
    match outcome {
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(
            FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection },
        ) => (*scope, selection),
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(
            FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(_),
        ) => panic!("expected continued signing authority after first finality"),
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected { .. } => {
            panic!("expected exact-current-round finality")
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
            panic!("expected admitted round progression")
        }
    }
}

fn assert_empty_session_state(
    scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
    position: ConsensusPosition,
    phase: FixedValidatorLockPhaseV0,
) {
    assert_eq!(scope.signing_session().position(), position);
    assert_eq!(scope.signing_session().phase(), phase);
    assert!(scope.signing_session().locked_value().is_none());
    assert!(scope.signing_session().valid_value().is_none());
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

fn retain_candidate_inputs(
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    predecessor: &naome_chain::ArtifactChainBranchSnapshot,
    block: &ArtifactBlock,
    canonical_artifact_bytes: &[u8],
) {
    let _ = candidates.insert(block).unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(predecessor, block, canonical_artifact_bytes.to_vec())
        .unwrap();
}

fn flip_last_store_byte(directory: &PathBuf) {
    let path = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "log"))
        .expect("one typed store log must exist");
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes
        .last_mut()
        .expect("a committed store image cannot be empty");
    *last ^= 0x01;
    fs::write(path, bytes).unwrap();
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

fn provision_with_fixed_entries<'layout>(
    fixture: &'layout Fixture,
    layout: &'layout TestLayout,
    entries: &'layout [ActiveAgreementEntry],
) -> FixedValidatorNodeProvisionV0<'layout> {
    FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(0),
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
fn proposal_vote_batch_wrong_phase_precedes_proposal_and_vote_reads() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-proposal-batch-wrong-phase");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let malformed_vote = [0_u8];
            let (_, rejection) = expect_rejected(
                scope
                    .sign_precommit_for_proposal_vote_batch(
                        &[0_u8],
                        vec![0_u8],
                        &[malformed_vote.as_slice()],
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Decision(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::UnexpectedPhase {
                            expected: FixedValidatorLockPhaseV0::Prevote,
                            actual: FixedValidatorLockPhaseV0::Proposal,
                        }
                    )
            ));
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn exact_signed_vote_batches_drive_proposal_and_nil_precommits_all_or_nothing() {
    let fixture = Fixture::new();
    let proposal_layout = TestLayout::new("node-voting-proposal-vote-batch");
    let ready = fixture
        .provision(&proposal_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let payload = proof_payload(ZfcAxiom::Pairing);
            let block = ArtifactChainState::new(fixture.definition)
                .prepare_block(artifact_id(&payload))
                .unwrap();
            let value = round.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());
            let (scope, prevote) = expect_signed(
                scope
                    .sign_prevote_for_proposal(
                        &control,
                        payload.clone(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let prevote_bytes = prevote.canonical_bytes().to_vec();
            let before_rejection = proposal_layout.images();
            let duplicate_batch = [prevote_bytes.as_slice(), prevote_bytes.as_slice()];
            let (scope, rejection) = expect_rejected(
                scope
                    .sign_precommit_for_proposal_vote_batch(
                        &control,
                        payload.clone(),
                        &duplicate_batch,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::QuorumConstruction(source)
                    if matches!(source.as_ref(), QuorumCertificateBuildError::DuplicateSigner { .. })
            ));
            assert_eq!(proposal_layout.images(), before_rejection);

            let (mut scope, precommit) = expect_signed(
                scope
                    .sign_precommit_for_proposal_vote_batch(
                        &control,
                        payload,
                        &[prevote_bytes.as_slice()],
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
        })
        .unwrap();

    let nil_layout = TestLayout::new("node-voting-nil-vote-batch");
    let ready = fixture
        .provision(&nil_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (scope, prevote) = expect_signed(
                scope
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
            let prevote_bytes = prevote.canonical_bytes().to_vec();
            let (mut scope, precommit) = expect_signed(
                scope
                    .sign_precommit_for_nil_vote_batch(
                        &[prevote_bytes.as_slice()],
                        ConsensusRound::new(0),
                    )
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
fn candidate_backed_proposal_votes_preserve_sources_and_restart_exactly() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-candidate-success");
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &block,
        &payload,
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let node_before = layout.images();
    let sources_before = layout.source_images();

    let (root, certificate) = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let value = round.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());

            let (scope, prevote) = expect_signed(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(prevote.position(), round.position());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            let after_prevote = layout.images();
            assert_eq!(after_prevote[0], node_before[0]);
            assert_eq!(after_prevote[1], node_before[1]);
            assert_ne!(after_prevote[2], node_before[2]);
            assert_ne!(after_prevote[3], node_before[3]);
            assert_eq!(layout.source_images(), sources_before);

            let certificate = prevote_certificate_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            let (scope, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_precommit_for_proposal_quorum(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        &[0_u8],
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Decision(source)
                    if matches!(source.as_ref(), FixedValidatorLockStateError::QuorumVerification(_))
            ));
            assert_eq!(layout.images(), after_prevote);
            assert_eq!(layout.source_images(), sources_before);

            let (mut scope, precommit) = expect_signed(
                scope
                    .sign_candidate_backed_precommit_for_proposal_quorum(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
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
            let after_precommit = layout.images();
            assert_eq!(after_precommit[0], node_before[0]);
            assert_eq!(after_precommit[1], node_before[1]);
            assert_ne!(after_precommit[2], after_prevote[2]);
            assert_ne!(after_precommit[3], after_prevote[3]);
            assert_eq!(layout.source_images(), sources_before);
            (root, certificate)
        })
        .unwrap();
    let completed = layout.images();

    let reopened = expect_ready(
        fixture
            .provision(&layout, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(layout.images(), completed);
            assert_eq!(layout.source_images(), sources_before);
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
fn three_nodes_build_exact_quorums_from_anchored_votes_then_finalize_and_restart() {
    let fixture = Fixture::new();
    let layouts = [
        TestLayout::new("node-vote-batch-e2e-a"),
        TestLayout::new("node-vote-batch-e2e-b"),
        TestLayout::new("node-vote-batch-e2e-c"),
    ];
    let signing_keys = [
        SigningKey::from_bytes(&signing_seed(21)),
        SigningKey::from_bytes(&signing_seed(22)),
        SigningKey::from_bytes(&signing_seed(23)),
    ];
    let entries = signing_keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect::<Vec<_>>();

    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        selected.branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let proposer = signing_keys
        .iter()
        .find(|key| consensus_key(key) == round.proposer())
        .expect("the scheduled proposer belongs to the fixed set");
    let value = round.value_for_artifact_block(block);
    let proposal_root = value.proposal_signing_root();
    let control = proposal_control_bytes(value, round.position(), proposer);

    let mut candidates = create_candidate_store(&layouts[0], fixture.definition);
    let mut payloads = create_payload_store(&layouts[0]);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &block,
        &payload,
    );
    let source_images = layouts[0].source_images();

    let mut prevotes = Vec::new();
    for (layout, signing_key) in layouts.iter().zip(&signing_keys) {
        let ready = provision_with_fixed_entries(&fixture, layout, &entries)
            .create(signing_key.clone())
            .unwrap();
        let prevote = ready
            .run_with_signing_session(|scope| {
                let (_scope, vote) = expect_signed(
                    scope
                        .sign_candidate_backed_prevote_for_proposal(
                            &mut candidates,
                            &mut payloads,
                            block.id(),
                            &control,
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                vote
            })
            .unwrap();
        assert_eq!(prevote.position(), round.position());
        assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
        assert_eq!(
            prevote.target(),
            ConsensusVoteTarget::Proposal(proposal_root)
        );
        prevotes.push(prevote);
    }
    assert_eq!(layouts[0].source_images(), source_images);

    let prevote_refs = prevotes
        .iter()
        .rev()
        .map(|vote| vote.canonical_bytes())
        .collect::<Vec<_>>();
    let expected_prevote_certificate = round
        .build_quorum_certificate_from_signed_votes(
            &prevote_refs,
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(proposal_root),
        )
        .unwrap()
        .to_canonical_bytes();

    let mut precommits = Vec::new();
    for (layout, signing_key) in layouts.iter().zip(&signing_keys) {
        let ready = expect_ready(
            provision_with_fixed_entries(&fixture, layout, &entries)
                .open(signing_key.clone())
                .unwrap(),
        );
        let precommit = ready
            .run_with_signing_session(|scope| {
                let (mut scope, vote) = expect_signed(
                    scope
                        .sign_candidate_backed_precommit_for_proposal_vote_batch(
                            &mut candidates,
                            &mut payloads,
                            block.id(),
                            &control,
                            &prevote_refs,
                            ConsensusRound::new(0),
                        )
                        .unwrap(),
                );
                assert_eq!(
                    scope
                        .signing_session()
                        .valid_value()
                        .unwrap()
                        .canonical_prevote_certificate(),
                    expected_prevote_certificate
                );
                vote
            })
            .unwrap();
        assert_eq!(precommit.position(), round.position());
        assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
        assert_eq!(
            precommit.target(),
            ConsensusVoteTarget::Proposal(proposal_root)
        );
        precommits.push(precommit);
    }
    assert_eq!(layouts[0].source_images(), source_images);

    let precommit_refs = precommits
        .iter()
        .map(|vote| vote.canonical_bytes())
        .collect::<Vec<_>>();
    let precommit_certificate = round
        .build_quorum_certificate_from_signed_votes(
            &precommit_refs,
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(proposal_root),
        )
        .unwrap()
        .to_canonical_bytes();
    let before_finality = layouts[0].images();

    let ready = expect_ready(
        provision_with_fixed_entries(&fixture, &layouts[0], &entries)
            .open(signing_keys[0].clone())
            .unwrap(),
    );
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let (mut scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &precommit_certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position,
                    ancestry_id,
                    ..
                } if position == round.position() && ancestry_id == value.ancestry_id()
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
    for (index, (before, after)) in before_finality.iter().zip(layouts[0].images()).enumerate() {
        assert_ne!(before, &after, "durable node image {index} did not advance");
    }
    assert_eq!(layouts[0].source_images(), source_images);

    let reopened = expect_ready(
        provision_with_fixed_entries(&fixture, &layouts[0], &entries)
            .open(signing_keys[0].clone())
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
            assert_eq!(layouts[0].source_images(), source_images);
        })
        .unwrap();
}

#[test]
fn candidate_backed_missing_sources_preserve_scope_for_incremental_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-candidate-missing-retry");
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let node_before = layout.images();
    let empty_sources = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let value = round.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());

            let (scope, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::CandidateUnavailable { target }
                    if target == block.id()
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), empty_sources);

            let _ = candidates.insert(&block).unwrap();
            let candidate_only = layout.source_images();
            let (scope, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::PayloadUnavailable { target }
                    if target == block.id()
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), candidate_only);

            let _ = payloads
                .validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, payload)
                .unwrap();
            let complete_sources = layout.source_images();
            let mut invalid_control = control.clone();
            let signature_byte =
                ConsensusValueV0::BYTE_LENGTH + VerifiedProducerAuthorizationV0::BYTE_LENGTH - 1;
            invalid_control[signature_byte] ^= 1;
            let (scope, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &invalid_control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(_)
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), complete_sources);

            let (_, vote) = expect_signed(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(vote.position(), round.position());
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Proposal(root));
            let node_after = layout.images();
            assert_eq!(node_after[0], node_before[0]);
            assert_eq!(node_after[1], node_before[1]);
            assert_ne!(node_after[2], node_before[2]);
            assert_ne!(node_after[3], node_before[3]);
            assert_eq!(layout.source_images(), complete_sources);
        })
        .unwrap();
}

#[test]
fn candidate_backed_identity_preflight_and_candidate_corruption_preserve_direct_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-candidate-preflight-corruption");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let other_payload = proof_payload(ZfcAxiom::Union);
    let other_block = selected.prepare_block(artifact_id(&other_payload)).unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &block,
        &payload,
    );
    flip_last_store_byte(&layout.candidate_store);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let node_before = layout.images();
    let sources_before = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let value = round.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());

            let wrong_context = ConsensusContextV0::new(
                fixture.definition.id(),
                ConsensusGenesisId::from_bytes([0x99; 32]),
                fixture.context.protocol_version(),
            );
            let wrong_branch = FixedConsensusBranchV0::try_from_virtual_genesis(
                wrong_context,
                &fixture.entries,
                selected.branch_snapshot(),
            )
            .unwrap();
            let wrong_round = wrong_branch.begin_round_zero().unwrap();
            let wrong_value = wrong_round.value_for_artifact_block(block);
            let wrong_control =
                proposal_control_bytes(wrong_value, wrong_round.position(), &fixture.signing_key());
            let (scope, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &wrong_control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::GenesisIdMismatch { expected, actual }
                            if *expected == fixture.context.genesis_id()
                                && *actual == wrong_context.genesis_id()
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);

            let other_value = round.value_for_artifact_block(other_block);
            let other_control =
                proposal_control_bytes(other_value, round.position(), &fixture.signing_key());
            let (scope, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &other_control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::ProposalTargetMismatch { expected, actual }
                    if expected == block.id() && actual == other_block.id()
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);

            let (scope, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::CandidateStore(source)
                    if matches!(
                        source.as_ref(),
                        ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id }
                            if *block_id == block.id()
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
            assert!(matches!(
                candidates.contains(block.id()),
                Err(ArtifactBlockCandidateStoreError::Poisoned)
            ));
            assert!(payloads.contains(block.artifact_id()).unwrap());

            let (_, vote) = expect_signed(
                scope
                    .sign_prevote_for_proposal(&control, payload, ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(vote.position(), round.position());
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Proposal(root));
            let node_after = layout.images();
            assert_eq!(node_after[0], node_before[0]);
            assert_eq!(node_after[1], node_before[1]);
            assert_ne!(node_after[2], node_before[2]);
            assert_ne!(node_after[3], node_before[3]);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();
}

#[test]
fn candidate_backed_payload_corruption_preserves_direct_quorum_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-payload-corruption");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &block,
        &payload,
    );
    flip_last_store_byte(&layout.payload_store);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let initial = layout.images();
    let sources_before = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let value = round.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());
            let certificate = prevote_certificate_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            let (scope, prevote) = expect_signed(
                scope
                    .sign_prevote_for_proposal(&control, payload.clone(), ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            let before_rejection = layout.images();
            assert_eq!(before_rejection[0], initial[0]);
            assert_eq!(before_rejection[1], initial[1]);
            assert_ne!(before_rejection[2], initial[2]);
            assert_ne!(before_rejection[3], initial[3]);

            let (scope, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_precommit_for_proposal_quorum(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        &certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::PayloadStore(source)
                    if matches!(
                        source.as_ref(),
                        CanonicalArtifactPayloadStoreError::StoredEntryChanged { artifact_id }
                            if *artifact_id == block.artifact_id()
                    )
            ));
            assert_eq!(layout.images(), before_rejection);
            assert_eq!(layout.source_images(), sources_before);
            assert!(candidates.contains(block.id()).unwrap());
            assert!(matches!(
                payloads.contains(block.artifact_id()),
                Err(CanonicalArtifactPayloadStoreError::Poisoned)
            ));

            let (_, precommit) = expect_signed(
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
            let completed = layout.images();
            assert_eq!(completed[0], initial[0]);
            assert_eq!(completed[1], initial[1]);
            assert_ne!(completed[2], before_rejection[2]);
            assert_ne!(completed[3], before_rejection[3]);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();
}

#[test]
fn candidate_backed_foreign_chain_rejects_before_candidate_integrity_read() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-candidate-foreign-chain");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let foreign_definition = ArtifactChainDefinition::new([0x91; 32]);
    let foreign_selected = ArtifactChainState::new(foreign_definition);
    let foreign_payload = proof_payload(ZfcAxiom::Union);
    let foreign_block = foreign_selected
        .prepare_block(artifact_id(&foreign_payload))
        .unwrap();
    let mut candidates = create_candidate_store(&layout, foreign_definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &foreign_selected.branch_snapshot(),
        &foreign_block,
        &foreign_payload,
    );
    flip_last_store_byte(&layout.candidate_store);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let node_before = layout.images();
    let sources_before = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let value = round.value_for_artifact_block(block);
            let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());
            let (_, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::CandidateChainMismatch {
                    expected,
                    actual,
                } if expected == fixture.definition.id() && actual == foreign_definition.id()
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();

    assert!(matches!(
        candidates.get(foreign_block.id()),
        Err(ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id })
            if block_id == foreign_block.id()
    ));
    assert!(payloads.contains(foreign_block.artifact_id()).unwrap());
}

#[test]
fn candidate_backed_wrong_phase_precedes_candidate_and_certificate_reads() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-candidate-wrong-phase");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &block,
        &payload,
    );
    flip_last_store_byte(&layout.candidate_store);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let node_before = layout.images();
    let sources_before = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let value = round.value_for_artifact_block(block);
            let control = proposal_control_bytes(value, round.position(), &fixture.signing_key());
            let (_, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_precommit_for_proposal_quorum(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        &[0_u8],
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Decision(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::UnexpectedPhase {
                            expected: FixedValidatorLockPhaseV0::Prevote,
                            actual: FixedValidatorLockPhaseV0::Proposal,
                        }
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();

    assert!(matches!(
        candidates.get(block.id()),
        Err(ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id })
            if block_id == block.id()
    ));
    assert!(payloads.contains(block.artifact_id()).unwrap());
}

#[test]
fn candidate_backed_caller_round_ceiling_precedes_candidate_integrity_read() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-candidate-caller-ceiling");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &block,
        &payload,
    );
    flip_last_store_byte(&layout.candidate_store);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let value = round_one.value_for_artifact_block(block);
            let control =
                proposal_control_bytes(value, round_one.position(), &fixture.signing_key());
            let node_before = layout.images();
            let sources_before = layout.source_images();
            let (_, rejection) = expect_rejected(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        &control,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();

    assert!(matches!(
        candidates.get(block.id()),
        Err(ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id })
            if block_id == block.id()
    ));
    assert!(payloads.contains(block.artifact_id()).unwrap());
}

#[test]
fn candidate_backed_persisted_round_ceiling_precedes_candidate_integrity_read() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-candidate-persisted-ceiling");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &block,
        &payload,
    );
    flip_last_store_byte(&layout.candidate_store);
    let ready = provision_with_finality_round_limit(&fixture, &layout, 1, 2)
        .create(fixture.signing_key())
        .unwrap();

    let (error, node_before, sources_before) = ready
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
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(1))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(1))
                    .unwrap(),
            );
            scope
                .signing_session_mut()
                .advance_round(&round_two)
                .unwrap();
            let value = round_two.value_for_artifact_block(block);
            let control =
                proposal_control_bytes(value, round_two.position(), &fixture.signing_key());
            let node_before = layout.images();
            let sources_before = layout.source_images();
            let error = match scope.sign_candidate_backed_prevote_for_proposal(
                &mut candidates,
                &mut payloads,
                block.id(),
                &control,
                ConsensusRound::new(2),
            ) {
                Err(error) => error,
                Ok(_) => panic!("persisted finality capacity must consume the signing scope"),
            };
            (error, node_before, sources_before)
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeVoteExecutionErrorV0::FinalityRoundLimitExceeded {
            required,
            maximum,
        } if required == ConsensusRound::new(2) && maximum == ConsensusRound::new(1)
    ));
    assert_eq!(layout.images(), node_before);
    assert_eq!(layout.source_images(), sources_before);
    assert!(matches!(
        candidates.get(block.id()),
        Err(ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id })
            if block_id == block.id()
    ));
    assert!(payloads.contains(block.artifact_id()).unwrap());
}

#[test]
fn candidate_backed_prevote_keeps_the_older_lock_as_its_vote_target() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-candidate-locked-prevote");
    let selected = ArtifactChainState::new(fixture.definition);
    let first_payload = proof_payload(ZfcAxiom::Pairing);
    let second_payload = proof_payload(ZfcAxiom::Union);
    let first_block = selected.prepare_block(artifact_id(&first_payload)).unwrap();
    let second_block = selected
        .prepare_block(artifact_id(&second_payload))
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &second_block,
        &second_payload,
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
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
                        first_payload.clone(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let first_certificate = prevote_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteTarget::Proposal(first_root),
                &fixture.signing_key(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_for_proposal_quorum(
                        &first_control,
                        first_payload,
                        &first_certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let round_one = round_zero.advance_round().unwrap();
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let second_value = round_one.value_for_artifact_block(second_block);
            let second_root = second_value.proposal_signing_root();
            assert_ne!(first_root, second_root);
            let second_control =
                proposal_control_bytes(second_value, round_one.position(), &fixture.signing_key());
            let node_before = layout.images();
            let sources_before = layout.source_images();
            let (mut scope, prevote) = expect_signed(
                scope
                    .sign_candidate_backed_prevote_for_proposal(
                        &mut candidates,
                        &mut payloads,
                        second_block.id(),
                        &second_control,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(prevote.position(), round_one.position());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(first_root));
            assert_eq!(
                scope
                    .signing_session()
                    .locked_value()
                    .unwrap()
                    .proposal_signing_root(),
                first_root
            );
            assert_eq!(
                scope
                    .signing_session()
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate(),
                first_certificate
            );
            let node_after = layout.images();
            assert_eq!(node_after[0], node_before[0]);
            assert_eq!(node_after[1], node_before[1]);
            assert_ne!(node_after[2], node_before[2]);
            assert_ne!(node_after[3], node_before[3]);
            assert_eq!(layout.source_images(), sources_before);
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
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);

            let (mut scope, precommit) = expect_signed(
                scope
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(0))
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
fn exact_phase_close_identity_rejections_preserve_scope_and_authority_images() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-bound-phase-closes");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let initial = layout.images();
    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );

    ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_prevote_after_proposal_close(
                        wrong_context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::PhaseCloseContextMismatch {
                    required_phase: FixedValidatorLockPhaseV0::Proposal,
                    current,
                    event,
                } if *current == fixture.context && *event == wrong_context
            ));
            assert_empty_session_state(
                &mut scope,
                round_zero.position(),
                FixedValidatorLockPhaseV0::Proposal,
            );
            assert_eq!(layout.images(), initial);

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_prevote_after_proposal_close(
                        fixture.context,
                        round_one.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::PhaseClosePositionMismatch {
                    required_phase: FixedValidatorLockPhaseV0::Proposal,
                    current,
                    event,
                } if current == round_zero.position() && event == round_one.position()
            ));
            assert_empty_session_state(
                &mut scope,
                round_zero.position(),
                FixedValidatorLockPhaseV0::Proposal,
            );
            assert_eq!(layout.images(), initial);

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_precommit_after_prevote_close(
                        fixture.context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Decision(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::UnexpectedPhase {
                            expected: FixedValidatorLockPhaseV0::Prevote,
                            actual: FixedValidatorLockPhaseV0::Proposal,
                        }
                    )
            ));
            assert_empty_session_state(
                &mut scope,
                round_zero.position(),
                FixedValidatorLockPhaseV0::Proposal,
            );
            assert_eq!(layout.images(), initial);

            let (scope, prevote) = expect_signed(
                scope
                    .sign_prevote_after_proposal_close(
                        fixture.context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(prevote.position(), round_zero.position());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
            let after_round_zero_prevote = layout.images();
            assert_eq!(after_round_zero_prevote[0], initial[0]);
            assert_eq!(after_round_zero_prevote[1], initial[1]);
            assert_ne!(after_round_zero_prevote[2], initial[2]);
            assert_ne!(after_round_zero_prevote[3], initial[3]);

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_prevote_after_proposal_close(
                        fixture.context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Decision(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::UnexpectedPhase {
                            expected: FixedValidatorLockPhaseV0::Proposal,
                            actual: FixedValidatorLockPhaseV0::Prevote,
                        }
                    )
            ));
            assert_empty_session_state(
                &mut scope,
                round_zero.position(),
                FixedValidatorLockPhaseV0::Prevote,
            );
            assert_eq!(layout.images(), after_round_zero_prevote);

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_precommit_after_prevote_close(
                        wrong_context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::PhaseCloseContextMismatch {
                    required_phase: FixedValidatorLockPhaseV0::Prevote,
                    current,
                    event,
                } if *current == fixture.context && *event == wrong_context
            ));
            assert_empty_session_state(
                &mut scope,
                round_zero.position(),
                FixedValidatorLockPhaseV0::Prevote,
            );
            assert_eq!(layout.images(), after_round_zero_prevote);

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_precommit_after_prevote_close(
                        fixture.context,
                        round_one.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::PhaseClosePositionMismatch {
                    required_phase: FixedValidatorLockPhaseV0::Prevote,
                    current,
                    event,
                } if current == round_zero.position() && event == round_one.position()
            ));
            assert_empty_session_state(
                &mut scope,
                round_zero.position(),
                FixedValidatorLockPhaseV0::Prevote,
            );
            assert_eq!(layout.images(), after_round_zero_prevote);

            let (scope, precommit) = expect_signed(
                scope
                    .sign_precommit_after_prevote_close(
                        fixture.context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(precommit.position(), round_zero.position());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            let after_round_zero_precommit = layout.images();
            assert_eq!(after_round_zero_precommit[0], initial[0]);
            assert_eq!(after_round_zero_precommit[1], initial[1]);
            assert_ne!(after_round_zero_precommit[2], after_round_zero_prevote[2]);
            assert_ne!(after_round_zero_precommit[3], after_round_zero_prevote[3]);

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_precommit_after_prevote_close(
                        fixture.context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::Decision(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorLockStateError::UnexpectedPhase {
                            expected: FixedValidatorLockPhaseV0::Prevote,
                            actual: FixedValidatorLockPhaseV0::Precommit,
                        }
                    )
            ));
            assert_eq!(layout.images(), after_round_zero_precommit);
            assert_empty_session_state(
                &mut scope,
                round_zero.position(),
                FixedValidatorLockPhaseV0::Precommit,
            );
        })
        .unwrap();

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
            assert!(scope.signing_session().locked_value().is_none());
            assert!(scope.signing_session().valid_value().is_none());
        })
        .unwrap();
}

#[test]
fn stale_phase_closes_cannot_retarget_a_later_round_or_change_retained_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-voting-stale-phase-closes");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let initial = layout.images();
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();

    let (root, certificate) = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round_zero = branch.begin_round_zero().unwrap();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            let value = round_zero.value_for_artifact_block(block);
            let root = value.proposal_signing_root();
            let control =
                proposal_control_bytes(value, round_zero.position(), &fixture.signing_key());

            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_for_proposal(&control, payload.clone(), ConsensusRound::new(0))
                    .unwrap(),
            );
            let certificate = prevote_certificate_bytes(
                fixture.context,
                round_zero.position(),
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            let (scope, _) = expect_signed(
                scope
                    .sign_precommit_for_proposal_quorum(
                        &control,
                        payload,
                        &certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let before_round_one = layout.images();
            let (mut scope, position, phase) = expect_advanced(
                scope
                    .advance_round_after_precommit_close(
                        fixture.context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(position, round_one.position());
            assert_eq!(phase, FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), before_round_one);
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

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_prevote_after_proposal_close(
                        fixture.context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::PhaseClosePositionMismatch {
                    required_phase: FixedValidatorLockPhaseV0::Proposal,
                    current,
                    event,
                } if current == round_one.position() && event == round_zero.position()
            ));
            assert_eq!(layout.images(), before_round_one);
            assert_eq!(scope.signing_session().position(), round_one.position());
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
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

            let (mut scope, prevote) = expect_signed(
                scope
                    .sign_prevote_after_proposal_close(
                        fixture.context,
                        round_one.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(prevote.position(), round_one.position());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
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
            let after_round_one_prevote = layout.images();
            assert_eq!(after_round_one_prevote[0], initial[0]);
            assert_eq!(after_round_one_prevote[1], initial[1]);
            assert_ne!(after_round_one_prevote[2], before_round_one[2]);
            assert_ne!(after_round_one_prevote[3], before_round_one[3]);

            let (mut scope, rejection) = expect_rejected(
                scope
                    .sign_precommit_after_prevote_close(
                        fixture.context,
                        round_zero.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeVoteRejectionV0::PhaseClosePositionMismatch {
                    required_phase: FixedValidatorLockPhaseV0::Prevote,
                    current,
                    event,
                } if current == round_one.position() && event == round_zero.position()
            ));
            assert_eq!(layout.images(), after_round_one_prevote);
            assert_eq!(scope.signing_session().position(), round_one.position());
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

            let (mut scope, precommit) = expect_signed(
                scope
                    .sign_precommit_after_prevote_close(
                        fixture.context,
                        round_one.position(),
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(precommit.position(), round_one.position());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
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
            let after_round_one_precommit = layout.images();
            assert_eq!(after_round_one_precommit[0], initial[0]);
            assert_eq!(after_round_one_precommit[1], initial[1]);
            assert_ne!(after_round_one_precommit[2], after_round_one_prevote[2]);
            assert_ne!(after_round_one_precommit[3], after_round_one_prevote[3]);
            (root, certificate)
        })
        .unwrap();

    let completed = layout.images();
    let reopened = expect_ready(
        fixture
            .provision(&layout, 1)
            .open(fixture.signing_key())
            .unwrap(),
    );
    assert_eq!(layout.images(), completed);
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
    assert_eq!(layout.images(), completed);
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
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let (scope, prevote) = expect_signed(
                scope
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(1))
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
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
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
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(0))
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
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
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
                .signing_session_mut()
                .prepare_higher_round_quorum_advance(
                    &round_one,
                    &certificate,
                    ConsensusRound::new(2),
                )
                .unwrap();
            drop(prepared);

            match scope.sign_prevote_after_current_proposal_close(ConsensusRound::new(0)) {
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
                .signing_session_mut()
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
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
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
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let before = layout.images();

            let (scope, rejection) = expect_rejected(
                scope
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
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
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(1))
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
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let (scope, _) = expect_signed(
                scope
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(1))
                    .unwrap(),
            );
            let (mut scope, _) = expect_signed(
                scope
                    .sign_precommit_after_current_prevote_close(ConsensusRound::new(1))
                    .unwrap(),
            );
            let round_two = round_one.advance_round().unwrap();
            scope
                .signing_session_mut()
                .advance_round(&round_two)
                .unwrap();
            let before = layout.images();
            let error = match scope
                .sign_prevote_after_current_proposal_close(ConsensusRound::new(2))
            {
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
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
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
    let collision = next_anchor_collision(&layout.vote_anchor, 3);

    let error = ready
        .run_with_signing_session(|scope| {
            match scope.sign_prevote_after_current_proposal_close(ConsensusRound::new(0)) {
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
    let collision = next_anchor_collision(&layout.vote_anchor, 4);

    let error = ready
        .run_with_signing_session(|scope| {
            match scope.sign_prevote_after_current_proposal_close(ConsensusRound::new(0)) {
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
