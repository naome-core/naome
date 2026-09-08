use super::higher_round::quorum;
use super::*;

#[test]
fn evidence_ahead_of_reopened_volatile_round_is_reclassified_then_fully_verified_for_finality() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("evidence-ahead-of-reopened-round");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (_, precommit) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let image = ready
        .run_with_signing_session(|scope| {
            let (mut driver, _) = step_arm(driver(scope, 8, 4));
            for round in 0..2 {
                let (_, vote) = quorum(
                    &fixture,
                    round,
                    ConsensusVoteRole::Precommit,
                    ConsensusVoteTarget::Nil,
                );
                (driver, _) = admit(driver, current_nil_precommit_event(&vote));
                driver = step_transition(driver);
                (driver, _) = step_arm(driver);
            }
            assert_eq!(driver.position().round().value(), 2);
            let (driver, _) = driver
                .drain_current_nil_precommit_inbox_and_reset()
                .into_parts();
            let driver = *driver;
            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            assert_eq!(layout.images(), before, "these two nil closes are volatile");
            driver.retained_evidence_image().unwrap()
        })
        .unwrap();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4)
                .restore_retained_evidence(&image)
                .unwrap();
            assert_eq!(driver.position().round().value(), 0);
            let (driver, _) = step_arm(driver);
            let driver = step_transition(driver);
            assert_eq!(driver.position().round().value(), 2);
            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Finality { driver, .. } => *driver,
                _ => panic!("full re-verification must permit the retained complete proof"),
            };
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.publication_history().unwrap().entries().count(), 0);
        })
        .unwrap();
}

fn higher_vote(bytes: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundVote {
        canonical_signed_vote: bytes.to_vec().into_boxed_slice(),
    }
}

#[test]
fn explicit_authoring_cannot_bypass_a_retained_proposal_that_has_become_current() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("evidence-explicit-authoring");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (mut driver, _) = admit(driver, proposal_event(2, &control, &payload));
            for round in 0..2 {
                let (_, vote) = quorum(
                    &fixture,
                    round,
                    ConsensusVoteRole::Precommit,
                    ConsensusVoteTarget::Nil,
                );
                (driver, _) = admit(driver, current_nil_precommit_event(&vote));
                driver = step_transition(driver);
                (driver, _) = step_arm(driver);
            }
            assert_eq!(driver.position().round().value(), 2);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            let before = layout.images();
            let image = driver.retained_evidence_image().unwrap();
            let driver = match driver
                .author_proposal(naome_consensus::FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: value.artifact_block(),
                    canonical_artifact_bytes: vec![0],
                })
                .unwrap()
            {
                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::StepWorkPending { driver } => {
                    *driver
                }
                _ => panic!("retained normalization must precede even malformed authoring input"),
            };
            assert_eq!(layout.images(), before);
            assert_eq!(driver.retained_evidence_image().unwrap(), image);
            let driver = step_transition(driver);
            let (_, vote, _) = step_publish(driver);
            assert_eq!(
                vote.target(),
                ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            );
        })
        .unwrap();
}

#[test]
fn restored_saturation_keeps_raw_prefix_and_deny_state_until_exact_class_disposal() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("evidence-restored-saturation");
    let branch = fixed_branch(&fixture);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (_, vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let image = ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 1, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let driver = match driver.admit_event(higher_vote(&vote)).unwrap() {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { driver, .. } => *driver,
                _ => panic!("capacity must refuse the additional input"),
            };
            driver.retained_evidence_image().unwrap()
        })
        .unwrap();
    let before = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 1, 4)
                .restore_retained_evidence(&image)
                .unwrap();
            assert_eq!(driver.retained_evidence_image().unwrap(), image);
            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                    driver,
                    reason:
                        FixedValidatorNodeDriverBlockReasonV0::RetainedEvidenceRequiresDisposal {
                            class: FixedValidatorNodeEvidenceClassV0::Higher,
                        },
                } => *driver,
                _ => panic!("reopen must not turn refused custody into a healthy snapshot"),
            };
            let (driver, _) = driver.drain_current_inbox_and_reset().into_parts();
            assert_eq!(driver.retained_evidence_image().unwrap(), image);
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(drained.len(), 1);
            drop(step_idle(*driver));
        })
        .unwrap();
    assert_eq!(layout.images(), before);
}

#[test]
fn raw_evidence_restore_rejects_malformed_binding_signature_payload_lengths_and_duplicates() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("evidence-strict-parser");
    let branch = fixed_branch(&fixture);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (_, vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let (empty, image) = ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            let empty = driver.retained_evidence_image().unwrap();
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, higher_vote(&vote));
            (empty, driver.retained_evidence_image().unwrap())
        })
        .unwrap();
    let mut cases = vec![vec![], image[..image.len() - 1].to_vec()];
    for needle in [&control[..], &payload[..], &vote[..]] {
        let start = image
            .windows(needle.len())
            .position(|v| v == needle)
            .unwrap();
        let mut corrupt = image.clone();
        corrupt[start + needle.len() - 1] ^= 0x80;
        cases.push(corrupt);
        let mut huge = image.clone();
        huge[start - 8..start].copy_from_slice(&u64::MAX.to_be_bytes());
        cases.push(huge);
    }
    for index in [0, empty.len() - 9, empty.len()] {
        let mut corrupt = image.clone();
        corrupt[index] = 0xff;
        cases.push(corrupt);
    }
    let mut trailing = image.clone();
    trailing.push(0);
    cases.push(trailing);
    // Both authenticated records remain intact, but canonical export groups
    // proposals before votes within each class. Restore must not normalize an
    // otherwise well-framed complete image into different canonical bytes.
    let vote_start = empty.len() + 18 + control.len() + payload.len();
    let mut reordered = image[..empty.len()].to_vec();
    reordered.extend_from_slice(&image[vote_start..]);
    reordered.extend_from_slice(&image[empty.len()..vote_start]);
    cases.push(reordered);
    let mut duplicate = image.clone();
    duplicate[empty.len() - 8..empty.len()].copy_from_slice(&4u64.to_be_bytes());
    duplicate.extend_from_slice(&image[empty.len()..]);
    cases.push(duplicate);
    let before = layout.images();
    for bytes in cases {
        let ready = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        ready
            .run_with_signing_session(|scope| {
                assert!(
                    driver(scope, 8, 4)
                        .restore_retained_evidence(&bytes)
                        .is_err()
                );
            })
            .unwrap();
        assert_eq!(layout.images(), before);
    }
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            assert!(
                driver(scope, 7, 4)
                    .restore_retained_evidence(&image)
                    .is_err(),
                "limits are bound"
            );
        })
        .unwrap();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4)
                .restore_retained_evidence(&image)
                .unwrap();
            assert_eq!(driver.retained_evidence_image().unwrap(), image);
        })
        .unwrap();
    assert_eq!(layout.images(), before);
}

#[test]
fn one_delivery_of_higher_proposal_and_precommit_finalizes_after_checkpoint_without_a_signature() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("evidence-one-delivery");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (_, vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let image = ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, higher_vote(&vote));
            let driver = step_transition(driver);
            assert_eq!(driver.position().round().value(), 2);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.inbox_len(), 2);
            let (driver, _) = step_arm(driver);
            let before = layout.images();
            let retained = driver.retained_evidence_image().unwrap();
            let driver = match driver.advance_to_higher_round_quorum(&[0]).unwrap() {
                FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::CurrentFinalityUnresolved { driver } => *driver,
                _ => panic!("explicit higher checkpoint must wait for retained class movement"),
            };
            let driver = match driver.commit_current_round_finality(&[0], vec![0], &[0]).unwrap() {
                FixedValidatorNodeDriverCurrentRoundFinalityOutcomeV0::CurrentFinalityUnresolved { driver } => *driver,
                _ => panic!("explicit current proof must wait for retained class movement"),
            };
            let driver = match driver.commit_lower_round_finality(&[0], vec![0], &[0]).unwrap() {
                FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0::CurrentFinalityUnresolved { driver } => *driver,
                _ => panic!("explicit lower proof must wait for retained class movement"),
            };
            let driver = match driver.commit_finality_envelope(&[0], vec![0]).unwrap() {
                FixedValidatorNodeDriverEnvelopeOutcomeV0::CurrentFinalityUnresolved { driver } => *driver,
                _ => panic!("explicit envelope must wait for retained class movement"),
            };
            assert_eq!(layout.images(), before);
            assert_eq!(driver.retained_evidence_image().unwrap(), retained);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Finality { driver, .. } => *driver,
                _ => panic!("retained evidence must finalize without another admission"),
            };
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.inbox_len(), 0);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.publication_history().unwrap().entries().count(),
                0,
                "checkpoint and finality create no proposal or vote"
            );
            driver.retained_evidence_image().unwrap()
        })
        .unwrap();
    let before = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4)
                .restore_retained_evidence(&image)
                .unwrap();
            assert_eq!(
                driver.retained_evidence_image().unwrap(),
                image,
                "historical raw custody must verify against retained selected parents"
            );
            let (driver, _) = step_arm(driver);
            drop(step_idle(driver));
        })
        .unwrap();
    assert_eq!(layout.images(), before);
}

#[test]
fn restored_higher_nil_quorum_is_reused_once_without_peer_redelivery() {
    let fixture = Fixture::new();
    for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
        let layout = TestLayout::new("evidence-nil-reuse");
        let (_, vote) = quorum(&fixture, 2, role, ConsensusVoteTarget::Nil);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let image = ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 8, 4));
                let (driver, _) = admit(driver, higher_vote(&vote));
                let driver = step_transition(driver);
                driver.retained_evidence_image().unwrap()
            })
            .unwrap();
        let ready = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        ready
            .run_with_signing_session(|scope| {
                let driver = driver(scope, 8, 4)
                    .restore_retained_evidence(&image)
                    .unwrap();
                let (driver, _) = step_arm(driver);
                let driver = step_transition(driver);
                assert_eq!(driver.inbox_len(), 0);
                if role == ConsensusVoteRole::Prevote {
                    assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
                    let (driver, signed, proposal) = step_publish(driver);
                    assert!(proposal.is_none());
                    assert_eq!(signed.position().round().value(), 2);
                    assert_eq!(signed.role(), ConsensusVoteRole::Precommit);
                    assert_eq!(signed.target(), ConsensusVoteTarget::Nil);
                    let (driver, _) = step_arm(driver);
                    drop(step_idle(driver));
                } else {
                    assert_eq!(driver.position().round().value(), 3);
                    assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                    assert_eq!(driver.publication_history().unwrap().entries().count(), 0);
                    let (driver, _) = step_arm(driver);
                    drop(step_idle(driver));
                }
            })
            .unwrap();
    }
}

#[test]
fn over_capacity_reuse_preserves_every_source_input_and_blocks_until_explicit_disposal() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("evidence-atomic-capacity");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (_, vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let driver = FixedValidatorNodeDriverV0::new(
                scope,
                FixedValidatorNodeHigherRoundInboxLimitsV0::new(8, 1 << 20).unwrap(),
                FixedValidatorNodeCurrentRoundInboxLimitsV0::new(8, 1 << 20).unwrap(),
                FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(1, 1 << 20).unwrap(),
                FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(8, 1 << 20).unwrap(),
                ConsensusRound::new(4),
            )
            .unwrap();
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, higher_vote(&vote));
            let driver = step_transition(driver);
            let (driver, _) = step_arm(driver);
            let before = layout.images();
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                    driver,
                    reason:
                        FixedValidatorNodeDriverBlockReasonV0::RetainedEvidenceRequiresDisposal {
                            class: FixedValidatorNodeEvidenceClassV0::Finality,
                        },
                } => *driver,
                _ => panic!(
                    "whole batch must refuse before any destination custody or authority change"
                ),
            };
            assert_eq!(driver.inbox_len(), 2);
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(layout.images(), before);
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            let mut proposals = 0;
            let mut votes = 0;
            for item in drained {
                match item {
                    FixedValidatorNodeHigherRoundInboxDrainItemV0::Proposal(p) => {
                        assert_eq!(p.canonical_proposal_control_bytes(), control);
                        assert_eq!(p.canonical_artifact_bytes(), payload);
                        proposals += 1;
                    }
                    FixedValidatorNodeHigherRoundInboxDrainItemV0::QuorumVote(bytes) => {
                        assert_eq!(bytes.as_slice(), vote);
                        votes += 1;
                    }
                    _ => panic!("unexpected source class"),
                }
            }
            assert_eq!((proposals, votes), (1, 1));
            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            assert_eq!(drained.len(), 0);
            drop(step_idle(*driver));
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn all_raw_evidence_classes_have_an_independent_frame_and_mutation_corpus() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("raw-evidence-codec-corpus");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let (_, higher) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    let (_, prevote) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
    );
    let (_, precommit) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
    );
    let (_, nil) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let (empty, actual) = ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            let empty = driver.retained_evidence_image().unwrap();
            let (mut driver, _) = step_arm(driver);
            for event in [
                proposal_event(2, &higher_control, &higher_payload),
                higher_vote(&higher),
                current_proposal_event(&control, &payload),
                current_prevote_event(&prevote),
                current_finality_proposal_event(&control, &payload),
                current_finality_precommit_event(&precommit),
                current_nil_precommit_event(&nil),
            ] {
                (driver, _) = admit(driver, event);
            }
            (empty, driver.retained_evidence_image().unwrap())
        })
        .unwrap();
    let mut expected = empty.clone();
    let count_start = expected.len() - 8;
    expected[count_start..].copy_from_slice(&7_u64.to_be_bytes());
    let field = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    for (class, first, second) in [
        (
            0,
            higher_control.as_slice(),
            Some(higher_payload.as_slice()),
        ),
        (0, higher.as_slice(), None),
        (1, control.as_slice(), Some(payload.as_slice())),
        (1, prevote.as_slice(), None),
        (2, control.as_slice(), Some(payload.as_slice())),
        (2, precommit.as_slice(), None),
        (3, nil.as_slice(), None),
    ] {
        expected.extend_from_slice(&[class, if second.is_some() { 0 } else { 1 }]);
        field(&mut expected, first);
        if let Some(second) = second {
            field(&mut expected, second);
        }
    }
    assert_eq!(actual, expected);
    let before = layout.images();
    let reconstruct = |bytes: &[u8]| {
        let ready = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        ready
            .run_with_signing_session(|scope| {
                driver(scope, 8, 4)
                    .restore_retained_evidence(bytes)
                    .ok()?
                    .retained_evidence_image()
                    .ok()
            })
            .unwrap()
    };
    crate::codec_corpus::check(
        "raw retained evidence classes",
        &[empty.clone(), expected.clone()],
        reconstruct,
    );
    for mask in 0..=15 {
        let mut image = expected.clone();
        image[count_start - 1] = mask;
        assert_eq!(reconstruct(&image), Some(image));
    }
    let mut excessive = expected.clone();
    excessive[count_start..count_start + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(reconstruct(&excessive).is_none());
    assert_eq!(
        layout.images(),
        before,
        "codec acceptance must never write signer or finality authority"
    );
}
