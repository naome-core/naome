use ed25519_dalek::{Signer, SigningKey};
use naome_chain::ArtifactBlock;
use naome_consensus::{
    ConsensusContextV0, ConsensusPosition, ConsensusVoteTarget, FixedValidatorLockPhaseV0,
    FixedValidatorProposalIntentErrorV0, FixedValidatorProposalSourceV0,
};
use naome_storage::{
    ArtifactBlockCandidateStoreError, CanonicalArtifactPayloadStoreError,
    FixedValidatorSignedProposalV0,
};

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

fn establish_retained_valid_value<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    fixture: &Fixture,
    block: ArtifactBlock,
    payload: &[u8],
) -> (
    FixedValidatorNodeSigningScopeV0<'node>,
    ProposalSigningRoot,
    Vec<u8>,
) {
    let branch = scope.branch().clone();
    let round = branch.begin_round_zero().unwrap();
    let root = round
        .value_for_artifact_block(block)
        .proposal_signing_root();
    let (scope, authored) = expect_authored(
        scope
            .author_proposal(
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: block,
                    canonical_artifact_bytes: payload.to_vec(),
                },
                ConsensusRound::new(0),
            )
            .unwrap(),
    );
    let scope = expect_signed_vote(
        scope
            .sign_prevote_for_proposal(
                authored.canonical_proposal_control_bytes(),
                payload.to_vec(),
                ConsensusRound::new(0),
            )
            .unwrap(),
    );
    let certificate = prevote_certificate_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let scope = expect_signed_vote(
        scope
            .sign_precommit_for_proposal_quorum(
                authored.canonical_proposal_control_bytes(),
                payload.to_vec(),
                &certificate,
                ConsensusRound::new(0),
            )
            .unwrap(),
    );
    (scope, root, certificate)
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
fn candidate_backed_fresh_proposal_authors_and_replays_at_the_exact_cap() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-replay");
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
        .provision_with_proposal_limit(&layout, 8, 1)
        .create(fixture.signing_key())
        .unwrap();
    let node_before = layout.images();
    let sources_before = layout.source_images();

    let authored = ready
        .run_with_signing_session(|scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let expected_root = round
                .value_for_artifact_block(block)
                .proposal_signing_root();
            let (scope, authored) = expect_authored(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
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
            assert_eq!(completed[0], node_before[0]);
            assert_eq!(completed[1], node_before[1]);
            assert_ne!(completed[2], node_before[2]);
            assert_ne!(completed[3], node_before[3]);
            assert_eq!(layout.source_images(), sources_before);

            let (scope, replay) = expect_authored(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(replay, authored);
            assert_eq!(layout.images(), completed);
            assert_eq!(layout.source_images(), sources_before);
            drop(scope);
            authored
        })
        .unwrap();
    let completed = layout.images();

    let reopened = expect_ready(
        fixture
            .provision_with_proposal_limit(&layout, 0, 1)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(
                scope.signing_session().position(),
                ConsensusPosition::new(
                    scope.branch().next_height().unwrap(),
                    ConsensusRound::new(0),
                )
            );
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            let (_, replay) = expect_authored(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(replay, authored);
            assert_eq!(layout.images(), completed);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();
}

#[test]
fn candidate_backed_missing_sources_preserve_scope_for_incremental_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-missing-retry");
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
            let (scope, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::CandidateUnavailable { target }
                    if target == block.id()
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), empty_sources);

            let _ = candidates.insert(&block).unwrap();
            let candidate_only = layout.source_images();
            let (scope, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::PayloadUnavailable { target }
                    if target == block.id()
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), candidate_only);

            let _ = payloads
                .validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, payload)
                .unwrap();
            let complete_sources = layout.source_images();
            let (_, authored) = expect_authored(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(!authored.canonical_proposal_control_bytes().is_empty());
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
fn candidate_backed_foreign_chain_rejects_before_reading_a_corrupt_candidate() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-foreign-chain");
    let foreign_definition = ArtifactChainDefinition::new([0x91; 32]);
    let foreign_selected = ArtifactChainState::new(foreign_definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = foreign_selected
        .prepare_block(artifact_id(&payload))
        .unwrap();
    let mut candidates = create_candidate_store(&layout, foreign_definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &foreign_selected.branch_snapshot(),
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
            let (_, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::CandidateChainMismatch {
                    expected,
                    actual,
                } if expected == fixture.definition.id() && actual == foreign_definition.id()
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
    assert!(payloads.get(block.artifact_id()).unwrap().is_some());
}

#[test]
fn candidate_backed_candidate_corruption_preserves_signer_for_direct_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-corrupt-candidate");
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
            let (scope, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::CandidateStore(source)
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
fn candidate_backed_payload_corruption_preserves_signer_for_direct_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-corrupt-payload");
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
    let node_before = layout.images();
    let sources_before = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let (scope, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::PayloadStore(source)
                    if matches!(
                        source.as_ref(),
                        CanonicalArtifactPayloadStoreError::StoredEntryChanged { artifact_id }
                            if *artifact_id == block.artifact_id()
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
            assert!(candidates.get(block.id()).unwrap().is_some());
            assert!(matches!(
                payloads.contains(block.artifact_id()),
                Err(CanonicalArtifactPayloadStoreError::Poisoned)
            ));

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
fn candidate_backed_wrong_phase_rejects_before_reading_a_corrupt_candidate() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-wrong-phase");
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
                        payload,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            let node_before = layout.images();
            let sources_before = layout.source_images();
            let (_, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorProposalIntentErrorV0::WrongPhase { actual }
                            if *actual != FixedValidatorLockPhaseV0::Proposal
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
}

#[test]
fn candidate_backed_unscheduled_signer_rejects_before_reading_a_corrupt_candidate() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-unscheduled");
    let first_seed = signing_seed(51);
    let second_seed = signing_seed(52);
    let first = SigningKey::from_bytes(&first_seed);
    let second = SigningKey::from_bytes(&second_seed);
    let entries = [
        ActiveAgreementEntry::new(consensus_key(&first), AgreementWeight::new(1)),
        ActiveAgreementEntry::new(consensus_key(&second), AgreementWeight::new(1)),
    ];
    let selected = ArtifactChainState::new(fixture.definition);
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        selected.branch_snapshot(),
    )
    .unwrap();
    let scheduled = branch.begin_round_zero().unwrap().proposer();
    let signer = if scheduled == consensus_key(&first) {
        SigningKey::from_bytes(&second_seed)
    } else {
        assert_eq!(scheduled, consensus_key(&second));
        SigningKey::from_bytes(&first_seed)
    };
    let signer_key = consensus_key(&signer);
    assert_ne!(scheduled, signer_key);

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
    .create(signer)
    .unwrap();
    let node_before = layout.images();
    let sources_before = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let (_, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorProposalIntentErrorV0::NotScheduledProposer {
                            scheduled: actual_scheduled,
                            signer: actual_signer,
                        } if *actual_scheduled == scheduled && *actual_signer == signer_key
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
}

#[test]
fn candidate_backed_deep_candidate_is_revalidated_before_a_valid_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-deep-retry");
    let selected = ArtifactChainState::new(fixture.definition);
    let first_payload = proof_payload(ZfcAxiom::Pairing);
    let first_block = selected.prepare_block(artifact_id(&first_payload)).unwrap();
    let mut deep = selected.clone();
    let _ = deep
        .apply_block(&first_block, first_payload.clone())
        .unwrap();
    let second_payload = proof_payload(ZfcAxiom::Union);
    let second_block = deep.prepare_block(artifact_id(&second_payload)).unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &deep.branch_snapshot(),
        &second_block,
        &second_payload,
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let node_before = layout.images();
    let deep_sources = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let (scope, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        second_block.id(),
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
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), deep_sources);

            retain_candidate_inputs(
                &mut candidates,
                &mut payloads,
                &selected.branch_snapshot(),
                &first_block,
                &first_payload,
            );
            let complete_sources = layout.source_images();
            let (_, authored) = expect_authored(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        first_block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(!authored.canonical_proposal_control_bytes().is_empty());
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
fn candidate_backed_conflict_at_the_exact_cap_stops_and_restarts_stopped() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-candidate-proposal-cap-conflict");
    let selected = ArtifactChainState::new(fixture.definition);
    let first_payload = proof_payload(ZfcAxiom::Pairing);
    let second_payload = proof_payload(ZfcAxiom::Union);
    let first_block = selected.prepare_block(artifact_id(&first_payload)).unwrap();
    let second_block = selected
        .prepare_block(artifact_id(&second_payload))
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let predecessor = selected.branch_snapshot();
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &predecessor,
        &first_block,
        &first_payload,
    );
    retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &predecessor,
        &second_block,
        &second_payload,
    );
    let ready = fixture
        .provision_with_proposal_limit(&layout, 8, 1)
        .create(fixture.signing_key())
        .unwrap();
    let node_before = layout.images();
    let sources_before = layout.source_images();

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
            let (scope, first) = expect_authored(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        first_block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert_eq!(first.proposal_signing_root(), first_root);
            let halt = match scope
                .author_candidate_backed_fresh_proposal(
                    &mut candidates,
                    &mut payloads,
                    second_block.id(),
                    ConsensusRound::new(0),
                )
                .unwrap()
            {
                FixedValidatorNodeProposalAuthoringOutcomeV0::SignerStopped(halt) => halt,
                FixedValidatorNodeProposalAuthoringOutcomeV0::Authored { .. } => {
                    panic!("the non-identical same-slot target must not be signed")
                }
                FixedValidatorNodeProposalAuthoringOutcomeV0::Rejected { .. } => {
                    panic!("the exact cap must not mask a same-slot proposal conflict")
                }
            };
            assert_eq!(halt.position(), round.position());
            assert_eq!(halt.retained_root(), first_root);
            assert_eq!(halt.conflicting_root(), second_root);
            assert_eq!(layout.source_images(), sources_before);
            halt
        })
        .unwrap();

    let node_after = layout.images();
    assert_eq!(node_after[0], node_before[0]);
    assert_eq!(node_after[1], node_before[1]);
    assert_ne!(node_after[2], node_before[2]);
    assert_ne!(node_after[3], node_before[3]);
    assert_eq!(layout.source_images(), sources_before);
    match fixture
        .provision_with_proposal_limit(&layout, 0, 1)
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
fn payload_store_backed_retained_proposal_authors_after_restart_and_replays_at_cap() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-retained-payload-restart-replay");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut payloads = create_payload_store(&layout);
    let _ = payloads
        .validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, payload.clone())
        .unwrap();
    let sources_before = layout.source_images();
    let ready = fixture
        .provision_with_proposal_limit(&layout, 8, 2)
        .create(fixture.signing_key())
        .unwrap();

    let (root, certificate) = ready
        .run_with_signing_session(|scope| {
            let (mut scope, root, certificate) =
                establish_retained_valid_value(scope, &fixture, block, &payload);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Precommit
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
    let after_retention = layout.images();
    assert_eq!(layout.source_images(), sources_before);

    let restarted = expect_ready(
        fixture
            .provision_with_proposal_limit(&layout, 1, 2)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let retained = restarted
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
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate(),
                certificate
            );
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let before_authoring = layout.images();

            let (scope, authored) = expect_authored(
                scope
                    .author_payload_store_backed_retained_proposal(
                        &mut payloads,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            let verified = round_one
                .decode_and_verify_proposal_control(
                    authored.canonical_proposal_control_bytes(),
                    payload.clone(),
                )
                .unwrap();
            assert_eq!(verified.proposal_signing_root(), root);
            assert_eq!(verified.valid_round(), Some(ConsensusRound::new(0)));
            assert_eq!(
                verified.valid_round_certificate_bytes(),
                Some(certificate.as_slice())
            );
            let completed = layout.images();
            assert_eq!(completed[0], before_authoring[0]);
            assert_eq!(completed[1], before_authoring[1]);
            assert_ne!(completed[2], before_authoring[2]);
            assert_ne!(completed[3], before_authoring[3]);
            assert_eq!(layout.source_images(), sources_before);

            let (_, replay) = expect_authored(
                scope
                    .author_payload_store_backed_retained_proposal(
                        &mut payloads,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(replay, authored);
            assert_eq!(layout.images(), completed);
            assert_eq!(layout.source_images(), sources_before);
            authored
        })
        .unwrap();
    let completed = layout.images();
    assert_eq!(completed[0], after_retention[0]);
    assert_eq!(completed[1], after_retention[1]);
    assert_ne!(completed[2], after_retention[2]);
    assert_ne!(completed[3], after_retention[3]);

    let reopened = expect_ready(
        fixture
            .provision_with_proposal_limit(&layout, 1, 2)
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
                FixedValidatorLockPhaseV0::Proposal
            );
            let (_, replay) = expect_authored(
                scope
                    .author_payload_store_backed_retained_proposal(
                        &mut payloads,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert_eq!(replay, retained);
            assert_eq!(layout.images(), completed);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();
}

#[test]
fn payload_store_backed_retained_missing_payload_preserves_scope_for_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-retained-payload-missing-retry");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut payloads = create_payload_store(&layout);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (mut scope, root, certificate) =
                establish_retained_valid_value(scope, &fixture, block, &payload);
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let node_before = layout.images();
            let sources_before = layout.source_images();

            let (scope, rejection) = expect_rejected(
                scope
                    .author_payload_store_backed_retained_proposal(
                        &mut payloads,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::PayloadUnavailable { target }
                    if target == block.id()
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);

            let _ = payloads
                .validate_and_insert_branch_payload(
                    &selected.branch_snapshot(),
                    &block,
                    payload.clone(),
                )
                .unwrap();
            let retained_sources = layout.source_images();
            let (_, authored) = expect_authored(
                scope
                    .author_payload_store_backed_retained_proposal(
                        &mut payloads,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            let verified = round_one
                .decode_and_verify_proposal_control(
                    authored.canonical_proposal_control_bytes(),
                    payload,
                )
                .unwrap();
            assert_eq!(verified.proposal_signing_root(), root);
            assert_eq!(
                verified.valid_round_certificate_bytes(),
                Some(certificate.as_slice())
            );
            let node_after = layout.images();
            assert_eq!(node_after[0], node_before[0]);
            assert_eq!(node_after[1], node_before[1]);
            assert_ne!(node_after[2], node_before[2]);
            assert_ne!(node_after[3], node_before[3]);
            assert_eq!(layout.source_images(), retained_sources);
        })
        .unwrap();
}

#[test]
fn retained_payload_preconditions_precede_a_corrupt_store_read() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-retained-payload-precedence");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut payloads = create_payload_store(&layout);
    let _ = payloads
        .validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, payload)
        .unwrap();
    flip_last_store_byte(&layout.payload_store);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let sources_before = layout.source_images();

    ready
        .run_with_signing_session(|scope| {
            let scope = expect_signed_vote(
                scope
                    .sign_prevote_after_current_proposal_close(ConsensusRound::new(0))
                    .unwrap(),
            );
            let mut scope = expect_signed_vote(
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
            let node_before = layout.images();

            let (scope, rejection) = expect_rejected(
                scope
                    .author_payload_store_backed_retained_proposal(
                        &mut payloads,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);

            let (_, rejection) = expect_rejected(
                scope
                    .author_payload_store_backed_retained_proposal(
                        &mut payloads,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        FixedValidatorProposalIntentErrorV0::FreshValueRequired
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
        })
        .unwrap();

    assert!(matches!(
        payloads.get(block.artifact_id()),
        Err(CanonicalArtifactPayloadStoreError::StoredEntryChanged { artifact_id })
            if artifact_id == block.artifact_id()
    ));
}

#[test]
fn retained_payload_corruption_preserves_signer_for_direct_fallback() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-retained-payload-corrupt-fallback");
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = proof_payload(ZfcAxiom::Pairing);
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let mut payloads = create_payload_store(&layout);
    let _ = payloads
        .validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, payload.clone())
        .unwrap();
    flip_last_store_byte(&layout.payload_store);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (mut scope, root, certificate) =
                establish_retained_valid_value(scope, &fixture, block, &payload);
            let branch = scope.branch().clone();
            let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();
            let node_before = layout.images();
            let sources_before = layout.source_images();

            let (scope, rejection) = expect_rejected(
                scope
                    .author_payload_store_backed_retained_proposal(
                        &mut payloads,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::PayloadStore(source)
                    if matches!(
                        source.as_ref(),
                        CanonicalArtifactPayloadStoreError::StoredEntryChanged { artifact_id }
                            if *artifact_id == block.artifact_id()
                    )
            ));
            assert_eq!(layout.images(), node_before);
            assert_eq!(layout.source_images(), sources_before);
            assert!(matches!(
                payloads.contains(block.artifact_id()),
                Err(CanonicalArtifactPayloadStoreError::Poisoned)
            ));

            let (_, authored) = expect_authored(
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
                    authored.canonical_proposal_control_bytes(),
                    payload,
                )
                .unwrap();
            assert_eq!(verified.proposal_signing_root(), root);
            assert_eq!(
                verified.valid_round_certificate_bytes(),
                Some(certificate.as_slice())
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
fn retained_valid_value_is_reauthored_with_its_exact_earlier_prevote_proof() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("node-proposal-retained-valid");
    let payload = proof_payload(ZfcAxiom::Pairing);
    let selected = ArtifactChainState::new(fixture.definition);
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
    assert!(matches!(
        candidates.get(block.id()),
        Err(ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id })
            if block_id == block.id()
    ));
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
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
            scope
                .signing_session_mut()
                .advance_round(&round_one)
                .unwrap();

            let before_wrong_source = layout.images();
            let sources_before = layout.source_images();
            let (scope, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeProposalAuthoringRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before_wrong_source);
            assert_eq!(layout.source_images(), sources_before);

            let (scope, rejection) = expect_rejected(
                scope
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
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
            assert_eq!(layout.source_images(), sources_before);

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
