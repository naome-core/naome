use naome_chain::ArtifactBlock;
use naome_consensus::{FixedValidatorProposalIntentErrorV0, FixedValidatorProposalSourceV0};
use naome_storage::{CanonicalArtifactPayloadStoreError, FixedValidatorSignedProposalV0};

use super::*;

fn source(block: ArtifactBlock, payload: &[u8]) -> FixedValidatorProposalSourceV0 {
    FixedValidatorProposalSourceV0::Fresh {
        artifact_block: block,
        canonical_artifact_bytes: payload.to_vec(),
    }
}

fn authored(
    outcome: FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'_>,
) -> FixedValidatorNodeDriverV0<'_> {
    match outcome {
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Authored { driver } => *driver,
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Rejected { rejection, .. } => {
            panic!("authoring rejected: {rejection:?}")
        }
        _ => panic!("expected pending durable proposal publication"),
    }
}

fn rejected(
    outcome: FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'_>,
) -> (
    FixedValidatorNodeDriverV0<'_>,
    FixedValidatorNodeProposalAuthoringRejectionV0,
) {
    match outcome {
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Rejected { driver, rejection } => {
            (*driver, *rejection)
        }
        _ => panic!("expected unchanged driver rejection"),
    }
}

fn publish(
    driver: FixedValidatorNodeDriverV0<'_>,
) -> (
    FixedValidatorNodeDriverV0<'_>,
    FixedValidatorSignedProposalV0,
    Vec<u8>,
) {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Command {
            driver,
            command:
                FixedValidatorNodeDriverCommandV0::PublishProposal {
                    proposal,
                    canonical_artifact_bytes,
                },
        } => (*driver, proposal, canonical_artifact_bytes),
        _ => panic!("expected one proposal publication command"),
    }
}

fn idle(driver: FixedValidatorNodeDriverV0<'_>) -> FixedValidatorNodeDriverV0<'_> {
    match driver.step().unwrap() {
        FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => *driver,
        _ => panic!("proposal publication must leave ordinary driver idle"),
    }
}

fn defer<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    block: ArtifactBlock,
) -> FixedValidatorNodeDriverV0<'node> {
    match driver.author_proposal(source(block, &[0])).unwrap() {
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0::StepWorkPending { driver } => *driver,
        _ => panic!("ordinary step work must precede malformed authoring input"),
    }
}

fn retain_inputs(
    layout: &TestLayout,
    fixture: &Fixture,
    block: ArtifactBlock,
    payload: &[u8],
) -> (ArtifactBlockCandidateStore, CanonicalArtifactPayloadStore) {
    let mut candidates = create_candidate_store(layout, fixture.definition);
    let mut payloads = create_payload_store(layout);
    let _ = candidates.insert(&block).unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            &ArtifactChainState::new(fixture.definition).branch_snapshot(),
            &block,
            payload.to_vec(),
        )
        .unwrap();
    (candidates, payloads)
}

#[test]
fn fresh_direct_and_candidate_authoring_match_and_require_explicit_local_readmission() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, _, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let block = value.artifact_block();
    let mut results = Vec::new();
    for stores in [false, true] {
        let layout = TestLayout::new("driver-authoring-fresh-parity");
        let (mut candidates, mut payloads) = retain_inputs(&layout, &fixture, block, &payload);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        let sources = layout.source_images();
        let result = ready
            .run_with_signing_session(|scope| {
                let (driver, timeout) = step_arm(driver(scope, 8, 4));
                let custody = candidate_backed::custody(&driver);
                let outcome = if stores {
                    driver.author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                    )
                } else {
                    driver.author_proposal(source(block, &payload))
                }
                .unwrap();
                let driver = authored(outcome);
                assert_eq!(candidate_backed::custody(&driver), custody);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                let completed = layout.images();
                assert_eq!(completed[0], before[0]);
                assert_eq!(completed[1], before[1]);
                assert_ne!(completed[2], before[2]);
                assert_ne!(completed[3], before[3]);
                assert_eq!(layout.source_images(), sources);
                let (driver, proposal, published_payload) = publish(driver);
                assert_eq!(published_payload, payload);
                assert_eq!(
                    proposal.proposal_signing_root(),
                    value.proposal_signing_root()
                );
                let _ = round_at(&branch, 0)
                    .decode_and_verify_proposal_control(
                        proposal.canonical_proposal_control_bytes(),
                        published_payload.clone(),
                    )
                    .unwrap();
                assert!(!driver.has_pending_command());
                let driver = idle(driver);
                assert_eq!(layout.images(), completed);
                let (driver, _) = admit(
                    driver,
                    current_proposal_event(
                        proposal.canonical_proposal_control_bytes(),
                        &published_payload,
                    ),
                );
                let (driver, disposition) = admit_due(driver, timeout);
                assert_eq!(
                    disposition,
                    FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                );
                let driver = step_transition(driver);
                let (_, vote, released) = step_publish(driver);
                assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                assert_eq!(
                    vote.target(),
                    ConsensusVoteTarget::Proposal(value.proposal_signing_root())
                );
                assert!(released.is_none());
                (proposal, published_payload, completed)
            })
            .unwrap();
        results.push(result);
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn publication_custody_survives_drains_and_source_corruption_at_exhausted_timer_generation() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let layout = TestLayout::new("driver-authoring-owned-custody");
    let (mut candidates, mut payloads) =
        retain_inputs(&layout, &fixture, value.artifact_block(), &payload);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver_with_finality_limits(
                scope,
                8,
                1 << 20,
                8,
                1 << 20,
                1,
                1 << 20,
                4,
            ));
            let (mut driver, _) =
                admit(driver, proposal_event(2, &higher_control, &higher_payload));
            (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (_, denied) = higher_round::quorum(
                &fixture,
                0,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
            );
            driver = reject_current_finality_precommit(driver, &denied, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                        newly_saturated: true,
                        ..
                    }
                ))
            });
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }
            ));
            driver.set_timer_generation_for_test(u64::MAX);
            let custody = candidate_backed::custody(&driver);
            let driver = authored(
                driver
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        value.artifact_block().id(),
                    )
                    .unwrap(),
            );
            assert_eq!(candidate_backed::custody(&driver), custody);
            let completed = layout.images();
            super::super::proposal_authoring::flip_last_store_byte(&layout.payload_store);
            assert!(matches!(
                payloads.get(value.artifact_block().artifact_id()),
                Err(CanonicalArtifactPayloadStoreError::StoredEntryChanged { .. })
            ));
            let driver = match driver
                .author_candidate_backed_fresh_proposal(
                    &mut candidates,
                    &mut payloads,
                    value.artifact_block().id(),
                )
                .unwrap()
            {
                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::CommandPending { driver } => {
                    *driver
                }
                _ => panic!("pending publication must precede poisoned sources"),
            };
            let event = current_proposal_event(&[0], &[0]);
            let driver = match driver.admit_event(event).unwrap() {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal { .. }
                    ));
                    *driver
                }
                _ => panic!("publication must retain custody before event parsing"),
            };
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(
                drained_contents(drained),
                (
                    vec![(higher_control.clone(), higher_payload.clone())],
                    vec![]
                )
            );
            let (driver, _) = driver.drain_current_inbox_and_reset().into_parts();
            let (driver, _) = driver.drain_current_finality_inbox_and_reset().into_parts();
            let (driver, _) = driver
                .drain_current_nil_precommit_inbox_and_reset()
                .into_parts();
            let (driver, proposal, bytes) = publish(*driver);
            assert_eq!(bytes, payload);
            assert_eq!(
                proposal.proposal_signing_root(),
                value.proposal_signing_root()
            );
            assert!(!driver.has_pending_command());
            drop(idle(driver));
            assert_eq!(layout.images(), completed);
        })
        .unwrap();
}

#[test]
fn completed_replay_and_restart_at_exact_proposal_cap_preserve_payload_and_timer() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, _, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let layout = TestLayout::new("driver-authoring-replay-restart");
    let ready = fixture
        .provision_with_proposal_limit(&layout, 8, 1)
        .create(fixture.signing_key())
        .unwrap();
    let (proposal, old_timeout) = ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let driver = authored(
                driver
                    .author_proposal(source(value.artifact_block(), &payload))
                    .unwrap(),
            );
            let (driver, first, bytes) = publish(driver);
            assert_eq!(bytes, payload);
            let completed = layout.images();
            let driver = authored(
                driver
                    .author_proposal(source(value.artifact_block(), &payload))
                    .unwrap(),
            );
            assert_eq!(layout.images(), completed);
            let (driver, replay, bytes) = publish(driver);
            assert_eq!(replay, first);
            assert_eq!(bytes, payload);
            let driver = authored(
                driver
                    .author_proposal(source(value.artifact_block(), &payload))
                    .unwrap(),
            );
            drop(driver); // A pending volatile publication is not a restart outbox.
            assert_eq!(layout.images(), completed);
            (first, timeout)
        })
        .unwrap();
    let completed = layout.images();
    let ready = expect_ready(
        fixture
            .provision_with_proposal_limit(&layout, 0, 1)
            .open(fixture.signing_key())
            .unwrap(),
    );
    assert!(ready.vote.pending_vote().unwrap().is_none());
    assert!(
        ready
            .vote
            .retained_signed_vote(proposal.position(), ConsensusVoteRole::Prevote)
            .unwrap()
            .is_none()
    );
    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            assert_ne!(timeout, old_timeout);
            let driver = idle(driver);
            let driver = authored(
                driver
                    .author_proposal(source(value.artifact_block(), &payload))
                    .unwrap(),
            );
            let (driver, replay, bytes) = publish(driver);
            assert_eq!(replay, proposal);
            assert_eq!(bytes, payload);
            assert_eq!(layout.images(), completed);
            let (_, disposition) = admit_due(driver, timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
        })
        .unwrap();
}

fn retained_driver<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    fixture: &Fixture,
) -> (
    FixedValidatorNodeDriverV0<'node>,
    ProposalSigningRoot,
    Vec<u8>,
) {
    let branch = scope.branch().clone();
    let (value, control, payload) = proposal_inputs(fixture, &branch, 0, ZfcAxiom::Pairing);
    let vote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let certificate = round_at(&branch, 0)
        .build_quorum_certificate_from_signed_votes(
            &[&vote],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        )
        .unwrap()
        .to_canonical_bytes();
    let (driver, _) = step_arm(driver(scope, 8, 4));
    let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
    let driver = step_transition(driver);
    let (driver, _, _) = step_publish(driver);
    let (driver, _) = step_arm(driver);
    let (driver, _) = admit(driver, current_prevote_event(&vote));
    let driver = step_transition(driver);
    let (driver, _, _) = step_publish(driver);
    let (driver, timeout) = step_arm(driver);
    let (driver, _) = admit_due(driver, timeout);
    let driver = step_transition(driver);
    let (driver, _) = step_arm(driver);
    (driver, value.proposal_signing_root(), certificate)
}

#[test]
fn retained_direct_and_payload_store_authoring_preserve_exact_proof_and_custody_on_restart() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, _, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let mut results = Vec::new();
    for stores in [false, true] {
        let layout = TestLayout::new("driver-authoring-retained");
        let (_, mut payloads) = retain_inputs(&layout, &fixture, value.artifact_block(), &payload);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let sources = layout.source_images();
        let (proposal, certificate) = ready
            .run_with_signing_session(|scope| {
                let (driver, root, certificate) = retained_driver(scope, &fixture);
                let custody = candidate_backed::custody(&driver);
                assert!(driver.current_inbox_len() > 0);
                let before = layout.images();
                let driver = authored(
                    if stores {
                        driver.author_payload_store_backed_retained_proposal(&mut payloads)
                    } else {
                        driver.author_proposal(FixedValidatorProposalSourceV0::RetainedValid {
                            canonical_artifact_bytes: payload.clone(),
                        })
                    }
                    .unwrap(),
                );
                assert_eq!(candidate_backed::custody(&driver), custody);
                let (driver, proposal, bytes) = publish(driver);
                assert_eq!(bytes, payload);
                let round = round_at(&branch, 1);
                let verified = round
                    .decode_and_verify_proposal_control(
                        proposal.canonical_proposal_control_bytes(),
                        bytes,
                    )
                    .unwrap();
                assert_eq!(verified.proposal_signing_root(), root);
                assert_eq!(
                    verified.valid_round_certificate_bytes(),
                    Some(certificate.as_slice())
                );
                drop(idle(driver));
                let completed = layout.images();
                assert_eq!(completed[0], before[0]);
                assert_eq!(completed[1], before[1]);
                assert_ne!(completed[2], before[2]);
                assert_ne!(completed[3], before[3]);
                assert_eq!(layout.source_images(), sources);
                results.push((proposal.clone(), completed));
                (proposal, certificate)
            })
            .unwrap();
        let completed = layout.images();
        let ready = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        ready
            .run_with_signing_session(|mut scope| {
                let session = scope.signing_session();
                let valid = session.valid_value().unwrap();
                assert_eq!(
                    valid.value().proposal_signing_root(),
                    value.proposal_signing_root()
                );
                assert_eq!(valid.canonical_prevote_certificate(), certificate);
                assert_eq!(valid.round(), ConsensusRound::new(0));
                assert_eq!(
                    session.locked_value().unwrap().proposal_signing_root(),
                    value.proposal_signing_root()
                );
                let (driver, _) = step_arm(driver(scope, 8, 4));
                let driver = authored(
                    driver
                        .author_payload_store_backed_retained_proposal(&mut payloads)
                        .unwrap(),
                );
                let (_, replay, bytes) = publish(driver);
                assert_eq!(replay, proposal);
                assert_eq!(bytes, payload);
                assert_eq!(layout.images(), completed);
            })
            .unwrap();
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn source_rejections_preserve_driver_for_incremental_fill_and_direct_fallback() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, _, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let block = value.artifact_block();
    let layout = TestLayout::new("driver-authoring-rejections");
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (mut driver, timeout) = step_arm(driver(scope, 8, 4));
            let before = layout.images();
            let custody = candidate_backed::custody(&driver);
            for mode in [
                "missing-candidate",
                "missing-payload",
                "wrong-source",
                "bad-payload",
                "oversized",
                "corrupt-store",
            ] {
                let outcome = match mode {
                    "missing-candidate" => driver.author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
                    ),
                    "missing-payload" => {
                        let _ = candidates.insert(&block).unwrap();
                        driver.author_candidate_backed_fresh_proposal(
                            &mut candidates,
                            &mut payloads,
                            block.id(),
                        )
                    }
                    "wrong-source" => {
                        driver.author_payload_store_backed_retained_proposal(&mut payloads)
                    }
                    "bad-payload" => driver.author_proposal(source(block, &[0])),
                    "oversized" => driver.author_proposal(source(
                        block,
                        &vec![0; naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES + 1],
                    )),
                    "corrupt-store" => {
                        let _ = payloads
                            .validate_and_insert_branch_payload(
                                branch.artifact_snapshot(),
                                &block,
                                payload.clone(),
                            )
                            .unwrap();
                        super::super::proposal_authoring::flip_last_store_byte(
                            &layout.payload_store,
                        );
                        driver.author_candidate_backed_fresh_proposal(
                            &mut candidates,
                            &mut payloads,
                            block.id(),
                        )
                    }
                    _ => unreachable!(),
                }
                .unwrap();
                let (next, rejection) = rejected(outcome);
                driver = next;
                match (mode, rejection) {
                    (
                        "missing-candidate",
                        FixedValidatorNodeProposalAuthoringRejectionV0::CandidateUnavailable {
                            target,
                        },
                    ) => assert_eq!(target, block.id()),
                    (
                        "missing-payload",
                        FixedValidatorNodeProposalAuthoringRejectionV0::PayloadUnavailable {
                            target,
                        },
                    ) => assert_eq!(target, block.id()),
                    (
                        "wrong-source",
                        FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(error),
                    ) => assert!(matches!(
                        *error,
                        FixedValidatorProposalIntentErrorV0::FreshValueRequired
                    )),
                    (
                        "bad-payload",
                        FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(_),
                    ) => {}
                    (
                        "oversized",
                        FixedValidatorNodeProposalAuthoringRejectionV0::PublicationPayloadTooLong {
                            ..
                        },
                    ) => {}
                    (
                        "corrupt-store",
                        FixedValidatorNodeProposalAuthoringRejectionV0::PayloadStore(error),
                    ) => assert!(matches!(
                        *error,
                        CanonicalArtifactPayloadStoreError::StoredEntryChanged { .. }
                    )),
                    (mode, error) => panic!("unexpected {mode} error: {error:?}"),
                }
                assert_eq!(layout.images(), before);
                assert_eq!(candidate_backed::custody(&driver), custody);
                assert!(!driver.timeout_is_due());
                assert!(!driver.has_pending_command());
                assert_eq!(driver.position(), timeout.position());
                assert_eq!(driver.phase(), timeout.phase());
            }
            assert!(matches!(
                payloads.contains(block.artifact_id()),
                Err(CanonicalArtifactPayloadStoreError::Poisoned)
            ));
            assert!(candidates.get(block.id()).unwrap().is_some());
            let driver = authored(driver.author_proposal(source(block, &payload)).unwrap());
            let (driver, _, bytes) = publish(driver);
            assert_eq!(bytes, payload);
            let (_, disposition) = admit_due(driver, timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
        })
        .unwrap();
}

#[test]
fn pending_commands_precede_authoring_and_same_slot_conflict_stops_only_after_publication() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (first, _, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (second, _, other_payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let layout = TestLayout::new("driver-authoring-conflict");
    let ready = fixture
        .provision_with_proposal_limit(&layout, 8, 1)
        .create(fixture.signing_key())
        .unwrap();
    let halt = ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            let before = layout.images();
            let driver = match driver
                .author_proposal(source(first.artifact_block(), &[0]))
                .unwrap()
            {
                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::CommandPending { driver } => {
                    *driver
                }
                _ => panic!("initial arm precedes input inspection"),
            };
            assert_eq!(layout.images(), before);
            let (driver, _) = step_arm(driver);
            let driver = authored(
                driver
                    .author_proposal(source(first.artifact_block(), &payload))
                    .unwrap(),
            );
            let completed = layout.images();
            let driver = match driver
                .author_proposal(source(second.artifact_block(), &other_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::CommandPending { driver } => {
                    *driver
                }
                _ => panic!("unpublished first proposal must retain custody"),
            };
            assert_eq!(layout.images(), completed);
            let (driver, proposal, bytes) = publish(driver);
            assert_eq!(
                proposal.proposal_signing_root(),
                first.proposal_signing_root()
            );
            assert_eq!(bytes, payload);
            match driver
                .author_proposal(source(second.artifact_block(), &other_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::SignerStopped(halt) => {
                    assert_eq!(halt.retained_root(), first.proposal_signing_root());
                    assert_eq!(halt.conflicting_root(), second.proposal_signing_root());
                    halt
                }
                _ => panic!("second valid same-slot intent must consume driver and durably stop"),
            }
        })
        .unwrap();
    match fixture
        .provision(&layout, 0)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::SignerStopped(
            FixedValidatorNodeSignerStopV0::ProposalSafety(restarted),
        ) => assert_eq!(restarted, halt),
        _ => panic!("strict reopen must report exact proposal safety halt"),
    }
}

#[test]
fn prepare_and_completion_anchor_failures_consume_driver_without_outward_bytes() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, _, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    for sequence in [3, 4] {
        let layout = TestLayout::new("driver-authoring-anchor-failure");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let collision = next_anchor_collision(&layout.vote_anchor, sequence);
        ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 8, 4));
                let before = layout.images();
                match driver.author_proposal(source(value.artifact_block(), &payload)) {
                    Err(FixedValidatorNodeDriverStepErrorV0::ProposalAuthoring(error)) => {
                        match (sequence, *error) {
                            (3, FixedValidatorNodeProposalAuthoringErrorV0::Prepare(_))
                            | (4, FixedValidatorNodeProposalAuthoringErrorV0::Sign(_)) => {}
                            (_, error) => panic!("unexpected anchor failure: {error:?}"),
                        }
                    }
                    _ => panic!("anchor failure must return neither driver nor proposal"),
                }
                let after = layout.images();
                assert_eq!(after[0], before[0]);
                assert_eq!(after[1], before[1]);
                assert_ne!(after[2], before[2]);
                if sequence == 3 {
                    assert_eq!(after[3], before[3]);
                } else {
                    assert_ne!(after[3], before[3]);
                }
            })
            .unwrap();
        fs::remove_file(collision).unwrap();
        assert!(
            matches!(fixture.provision(&layout, 8).open(fixture.signing_key()),
            Err(FixedValidatorNodeStartupErrorV0::VotePair(source)) if matches!(source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner) if matches!(inner.as_ref(),
                    FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. })))
        );
    }
}
#[test]
fn all_current_finality_classes_precede_authoring() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (left, left_control, left_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (right, right_control, right_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (_, left_vote) = higher_round::quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(left.proposal_signing_root()),
    );
    let (_, right_vote) = higher_round::quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(right.proposal_signing_root()),
    );
    {
        for mode in ["missing", "ready", "conflicting", "pair", "saturated-pair"] {
            let layout = TestLayout::new("driver-authoring-finality-priority");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready.run_with_signing_session(|scope| {
                let (mut driver, timeout) = step_arm(driver_with_finality_limits(scope, 8, 1 << 20, 8, 1 << 20, 4, 1 << 20, 4));
                (driver, _) = admit(driver, current_finality_precommit_event(&left_vote));
                if mode != "missing" { (driver, _) = admit(driver, current_finality_proposal_event(&left_control, &left_payload)); }
                if matches!(mode, "conflicting" | "pair" | "saturated-pair") { (driver, _) = admit(driver, current_finality_precommit_event(&right_vote)); }
                if matches!(mode, "pair" | "saturated-pair") { (driver, _) = admit(driver, current_finality_proposal_event(&right_control, &right_payload)); }
                if mode == "saturated-pair" {
                    let denied = signed_vote_bytes_with_test_only_nonce_prefix(fixture.context, timeout.position(), ConsensusVoteRole::Precommit,
                        ConsensusVoteTarget::Proposal(left.proposal_signing_root()), &fixture.signing_key(), 0x35);
                    driver = reject_current_finality_precommit(driver, &denied, |rejection| assert!(matches!(rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated { newly_saturated: true, .. })));
                }
                (driver, _) = admit_due(driver, timeout);
                let before = candidate_backed::custody(&driver);
                let classification = driver.classify_current_finality_evidence().unwrap();
                let images = layout.images();
                driver.set_timer_generation_for_test(u64::MAX);
                driver = defer(driver, left.artifact_block());
                assert_eq!(driver.classify_current_finality_evidence().unwrap(), classification);
                assert_eq!(candidate_backed::custody(&driver), before);
                assert_eq!(layout.images(), images);
                assert_eq!(driver.position(), timeout.position());
                assert_eq!(driver.phase(), timeout.phase());
                assert!(driver.timeout_is_due());
                driver.set_timer_generation_for_test(timeout.generation());
                match (mode, driver.step().unwrap()) {
                    ("ready", FixedValidatorNodeDriverStepOutcomeV0::Finality { selection, .. }) => assert!(matches!(selection,
                        FixedValidatorNodeFinalitySelectionV0::Finalized { ancestry_id, .. } if ancestry_id == left.ancestry_id())),
                    ("pair" | "saturated-pair", FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(_)) => {},
                    ("missing" | "conflicting", FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, .. }) => {
                        assert_eq!(candidate_backed::custody(&driver), before); assert_eq!(layout.images(), images);
                    }
                    _ => panic!("step must retain original finality behavior"),
                }
            }).unwrap();
        }
    }
}

#[test]
fn higher_current_nil_and_due_work_precede_authoring_without_latching_or_consuming_input() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (left, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, second_control, second_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (higher, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (other, other_control, other_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let (_, higher_vote) = higher_round::quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher.proposal_signing_root()),
    );
    let (_, other_vote) = higher_round::quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(other.proposal_signing_root()),
    );
    let (_, nil) = higher_round::quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    for mode in [
        "higher-action",
        "higher-derived",
        "higher-latched",
        "higher-saturated",
        "current-action",
        "current-ambiguous",
        "current-saturated",
        "nil",
        "due",
        "pending-vote",
    ] {
        let layout = TestLayout::new("driver-authoring-step-priority");
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (mut driver, timeout) = step_arm(driver(
                    scope,
                    if mode.ends_with("saturated") { 1 } else { 8 },
                    4,
                ));
                match mode {
                    "higher-action" | "higher-derived" | "higher-latched" | "higher-saturated" => {
                        (driver, _) =
                            admit(driver, proposal_event(2, &higher_control, &higher_payload));
                        if mode == "higher-saturated" {
                            driver = reject_prevote(driver, &higher_vote, |_| {});
                        } else {
                            (driver, _) = admit(driver, prevote_event(&higher_vote));
                        }
                        if matches!(mode, "higher-derived" | "higher-latched") {
                            (driver, _) =
                                admit(driver, proposal_event(2, &other_control, &other_payload));
                            (driver, _) = admit(driver, prevote_event(&other_vote));
                        }
                        if mode == "higher-latched" {
                            driver = match driver.step().unwrap() {
                                FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                                    driver, ..
                                } => *driver,
                                _ => panic!("expected higher ambiguity"),
                            };
                        }
                    }
                    "current-action" | "current-ambiguous" | "current-saturated" => {
                        (driver, _) = admit(driver, current_proposal_event(&control, &payload));
                        if mode == "current-ambiguous" {
                            (driver, _) = admit(
                                driver,
                                current_proposal_event(&second_control, &second_payload),
                            );
                        }
                        if mode == "current-saturated" {
                            let (_, vote) = higher_round::quorum(
                                &fixture,
                                0,
                                ConsensusVoteRole::Prevote,
                                ConsensusVoteTarget::Nil,
                            );
                            driver = reject_current_nil_prevote(driver, &vote, |_| {});
                        }
                    }
                    "nil" => {
                        (driver, _) = admit(driver, current_nil_precommit_event(&nil));
                    }
                    "due" | "pending-vote" => {
                        (driver, _) = admit_due(driver, timeout);
                        if mode == "pending-vote" {
                            driver = step_transition(driver);
                        }
                    }
                    _ => unreachable!(),
                }
                let before = layout.images();
                let custody = candidate_backed::custody(&driver);
                let position = driver.position();
                let phase = driver.phase();
                let due = driver.timeout_is_due();
                if mode == "pending-vote" {
                    driver = match driver
                        .author_proposal(source(left.artifact_block(), &[0]))
                        .unwrap()
                    {
                        FixedValidatorNodeDriverProposalAuthoringOutcomeV0::CommandPending {
                            driver,
                        } => *driver,
                        _ => panic!("vote publication precedes proposal input"),
                    };
                } else {
                    driver = defer(driver, left.artifact_block());
                }
                assert_eq!(layout.images(), before);
                assert_eq!(candidate_backed::custody(&driver), custody);
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), phase);
                assert_eq!(driver.timeout_is_due(), due);
                match mode {
                    "higher-action" | "current-action" | "nil" | "due" => {
                        drop(step_transition(driver));
                    }
                    "pending-vote" => {
                        let (_, vote, _) = step_publish(driver);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                    }
                    _ => {
                        match driver.step().unwrap() {
                            FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, .. } => {
                                assert_eq!(candidate_backed::custody(&driver), custody)
                            }
                            _ => panic!("original {mode} blocker must remain"),
                        }
                        assert_eq!(layout.images(), before);
                    }
                }
            })
            .unwrap();
    }
}
#[test]
fn driver_unscheduled_signer_rejects_before_reading_a_corrupt_candidate() {
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
    super::super::proposal_authoring::retain_candidate_inputs(
        &mut candidates,
        &mut payloads,
        &selected.branch_snapshot(),
        &block,
        &payload,
    );
    super::super::proposal_authoring::flip_last_store_byte(&layout.candidate_store);
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
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (_, rejection) = rejected(
                driver
                    .author_candidate_backed_fresh_proposal(
                        &mut candidates,
                        &mut payloads,
                        block.id(),
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
fn wrong_phase_and_retained_source_kind_precede_corrupt_store_reads_and_keep_retry_authority() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, _, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    for retained in [false, true] {
        let layout = TestLayout::new("driver-authoring-source-preflight");
        let (mut candidates, mut payloads) =
            retain_inputs(&layout, &fixture, value.artifact_block(), &payload);
        super::super::proposal_authoring::flip_last_store_byte(&layout.candidate_store);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready.run_with_signing_session(|scope| {
            let driver = if retained { retained_driver(scope, &fixture).0 } else {
                let (driver, timeout) = step_arm(driver(scope, 8, 4));
                let (driver, _) = admit_due(driver, timeout);
                let driver = step_transition(driver);
                let (driver, _, _) = step_publish(driver);
                step_arm(driver).0
            };
            let before = layout.images(); let sources = layout.source_images();
            let custody = candidate_backed::custody(&driver);
            let (driver, rejection) = rejected(driver.author_candidate_backed_fresh_proposal(&mut candidates, &mut payloads, value.artifact_block().id()).unwrap());
            assert!(matches!(rejection, FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(error)
                if matches!((retained, error.as_ref()),
                    (true, FixedValidatorProposalIntentErrorV0::RetainedValidValueRequired)
                    | (false, FixedValidatorProposalIntentErrorV0::WrongPhase { actual: FixedValidatorLockPhaseV0::Prevote }))));
            assert_eq!(layout.images(), before); assert_eq!(layout.source_images(), sources);
            assert_eq!(candidate_backed::custody(&driver), custody);
            assert!(matches!(candidates.get(value.artifact_block().id()), Err(ArtifactBlockCandidateStoreError::StoredEntryChanged { .. })));
            if retained {
                super::super::proposal_authoring::flip_last_store_byte(&layout.payload_store);
                let (driver, rejection) = rejected(driver.author_payload_store_backed_retained_proposal(&mut payloads).unwrap());
                assert!(matches!(rejection, FixedValidatorNodeProposalAuthoringRejectionV0::PayloadStore(error)
                    if matches!(*error, CanonicalArtifactPayloadStoreError::StoredEntryChanged { .. })));
                assert_eq!(layout.images(), before); assert_eq!(candidate_backed::custody(&driver), custody);
                let driver = authored(driver.author_proposal(FixedValidatorProposalSourceV0::RetainedValid { canonical_artifact_bytes: payload.clone() }).unwrap());
                let (_, proposal, bytes) = publish(driver);
                assert_eq!(bytes, payload); assert_eq!(proposal.proposal_signing_root(), value.proposal_signing_root());
            }
        }).unwrap();
    }
}
