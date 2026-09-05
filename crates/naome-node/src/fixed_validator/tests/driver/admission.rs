use super::*;

#[test]
fn precommit_due_round_capacity_rejection_is_stable_and_retryable() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-precommit-due-capacity");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, proposal_timeout) = step_arm(driver(scope, 8, 0));
            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);

            let (driver, prevote_timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = step_transition(driver);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);

            let (driver, precommit_timeout) = step_arm(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, disposition) = admit_due(driver, precommit_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
            let before_rejection = layout.images();

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Rejected { driver, rejection } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                                    required,
                                    maximum,
                                } if *required == ConsensusRound::new(1)
                                    && *maximum == ConsensusRound::new(0)
                            )
                    ));
                    *driver
                }
                _ => panic!("Precommit due must reject an unavailable destination round"),
            };
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(driver.timeout_is_due());
            assert!(!driver.has_pending_command());
            assert_eq!(layout.images(), before_rejection);

            let (driver, disposition) = admit_due(driver, precommit_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue
            );
            match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Rejected { driver, rejection } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeRoundAdvanceRejectionV0::RoundWorkLimitExceeded {
                                    required,
                                    maximum,
                                } if *required == ConsensusRound::new(1)
                                    && *maximum == ConsensusRound::new(0)
                            )
                    ));
                    assert_eq!(driver.position().round(), ConsensusRound::new(0));
                    assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
                    assert!(driver.timeout_is_due());
                    assert_eq!(layout.images(), before_rejection);
                }
                _ => panic!("the exact retained due state must retry the same rejection"),
            }
        })
        .unwrap();
}

#[test]
fn pending_commands_precede_event_admission_and_publication_is_already_durable() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-pending-command-order");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = match driver(scope, 8, 4)
                .admit_event(proposal_event(2, &control, &payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                            ..
                        } => {
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ref(),
                                control.as_slice()
                            );
                            assert_eq!(canonical_artifact_bytes.as_ref(), payload.as_slice());
                        }
                        _ => panic!("pending-command rejection must return the exact event"),
                    }
                    *driver
                }
                _ => panic!("initial arm command must transfer before event admission"),
            };

            let (driver, initial_timeout) = step_arm(driver);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));
            assert_eq!(initial_timeout.generation(), 0);
            assert_eq!(layout.images(), before);

            let driver = step_transition(driver);
            let durable = layout.images();
            assert_ne!(durable, before);
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);

            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(initial_timeout))
                .unwrap()
            {
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
                        FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                            if returned == initial_timeout
                    ));
                    *driver
                }
                _ => panic!("pending vote custody must transfer before another event"),
            };

            let (driver, signed, released_proposal) = step_publish(driver);
            let released_proposal = released_proposal
                .expect("higher-round publication must transfer the selected proposal");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), payload);
            assert_eq!(layout.images(), durable);
            assert_eq!(signed.position(), position);
            assert_eq!(
                signed.target(),
                ConsensusVoteTarget::Proposal(value.proposal_signing_root())
            );
            let (_, successor_timeout) = step_arm(driver);
            assert_eq!(layout.images(), durable);
            assert_eq!(successor_timeout.position(), position);
            assert_eq!(
                successor_timeout.phase(),
                FixedValidatorLockPhaseV0::Precommit
            );
        })
        .unwrap();
}

#[test]
fn untrusted_event_forms_are_returned_and_mutation_free_while_duplicates_are_no_growth() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-event-admission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let round_zero = round_at(&branch, 0).position();
    let round_two = round_at(&branch, 2).position();
    let round_five = round_at(&branch, 5).position();
    let root = value.proposal_signing_root();
    let malformed = vec![0x01, 0x02, 0x03];
    let non_higher = signed_vote_bytes(
        fixture.context,
        round_zero,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let over_ceiling = signed_vote_bytes(
        fixture.context,
        round_five,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_role = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let inactive_signer = SigningKey::from_bytes(&signing_seed(2));
    let inactive = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &inactive_signer,
    );
    let valid_prevote = signed_vote_bytes(
        fixture.context,
        round_two,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let mut invalid_signature = valid_prevote.clone();
    *invalid_signature.last_mut().unwrap() ^= 0x01;
    let oversized_payload = vec![0_u8; naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES + 1];
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = reject_prevote(driver, &malformed, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRouting(_)
                ));
            });
            let driver = reject_prevote(driver, &non_higher, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteNotHigher { .. }
                ));
            });
            let driver = reject_prevote(driver, &over_ceiling, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRoundWorkLimitExceeded {
                        ..
                    }
                ));
            });
            let driver = reject_prevote(driver, &wrong_role, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_)
                ));
            });
            let driver = reject_prevote(driver, &nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_)
                ));
            });
            let driver = reject_prevote(driver, &inactive, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_)
                ));
            });
            let driver = reject_prevote(driver, &invalid_signature, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRouting(_)
                ));
            });
            let driver = match driver
                .admit_event(proposal_event(0, &control, &oversized_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeProposalDeferralRejectionV0::NotHigherThanSigner {
                                    ..
                                }
                            )
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            canonical_artifact_bytes,
                            ..
                        } => assert_eq!(
                            canonical_artifact_bytes.as_ref(),
                            oversized_payload.as_slice()
                        ),
                        _ => panic!("route-preflight rejection must return its exact raw event"),
                    }
                    *driver
                }
                _ => panic!("proposal route preflight must precede payload inspection"),
            };
            let driver = match driver
                .admit_event(proposal_event(2, &control, &oversized_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadTooLong {
                            actual,
                            maximum: naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES,
                        } if actual == oversized_payload.len()
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            canonical_artifact_bytes,
                            ..
                        } => assert_eq!(
                            canonical_artifact_bytes.as_ref(),
                            oversized_payload.as_slice()
                        ),
                        _ => panic!("oversized proposal must return its exact raw event"),
                    }
                    *driver
                }
                _ => panic!("oversized proposal payload must be rejected before copying"),
            };
            let driver = match driver
                .admit_event(proposal_event(3, &control, &payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(_)
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            proposal_round,
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(proposal_round, ConsensusRound::new(3));
                            assert_eq!(canonical_proposal_control_bytes.as_ref(), control.as_slice());
                            assert_eq!(canonical_artifact_bytes.as_ref(), payload.as_slice());
                        }
                        _ => panic!("rejected proposal must return its exact raw event"),
                    }
                    *driver
                }
                _ => panic!("descriptive proposal route must match authenticated position"),
            };
            assert_eq!(driver.inbox_len(), 0);
            assert!(!driver.timeout_is_due());
            assert!(!driver.has_pending_command());
            assert_eq!(layout.images(), before);

            let (driver, disposition) = admit(driver, proposal_event(2, &control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, proposal_event(2, &control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.inbox_len(), 1);
            let (driver, disposition) = admit(driver, prevote_event(&valid_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, prevote_event(&valid_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.inbox_len(), 2);
            assert_eq!(layout.images(), before);

            let (_, drained) = driver.drain_inbox_and_reset().into_parts();
            let (proposals, prevotes) = drained_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert_eq!(prevotes, vec![valid_prevote.clone()]);
        })
        .unwrap();
}

#[test]
fn valid_route_rejects_malformed_control_before_consuming_a_maximum_payload() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-proposal-control-framing");
    let malformed_control = vec![0x01, 0x02, 0x03].into_boxed_slice();
    let maximum_payload = vec![0_u8; naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES].into_boxed_slice();
    let control_pointer = malformed_control.as_ptr();
    let payload_pointer = maximum_payload.as_ptr();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            match driver
                .admit_event(FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                    proposal_round: ConsensusRound::new(2),
                    canonical_proposal_control_bytes: malformed_control,
                    canonical_artifact_bytes: maximum_payload,
                })
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    match rejection.as_ref() {
                        FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(source) => {
                            match source.as_ref() {
                                FixedValidatorNodeProposalDeferralRejectionV0::Proposal(source) => {
                                    assert!(matches!(
                                        source.as_ref(),
                                        naome_consensus::ConsensusProposalVerifyError::InvalidLength {
                                            actual,
                                            minimum,
                                        } if *actual == 3
                                            && *minimum
                                                == VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH
                                    ));
                                }
                                _ => panic!("valid route must reach proposal-control framing"),
                            }
                        }
                        _ => panic!("malformed control must be a proposal rejection"),
                    }
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            proposal_round,
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(proposal_round, ConsensusRound::new(2));
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ptr(),
                                control_pointer
                            );
                            assert_eq!(canonical_artifact_bytes.as_ptr(), payload_pointer);
                            assert_eq!(canonical_proposal_control_bytes.as_ref(), [0x01, 0x02, 0x03]);
                            assert_eq!(
                                canonical_artifact_bytes.len(),
                                naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES
                            );
                        }
                        _ => panic!("proposal-control rejection must return its exact event"),
                    }
                    assert_eq!(driver.inbox_len(), 0);
                    assert!(!driver.timeout_is_due());
                    assert!(!driver.has_pending_command());
                }
                _ => panic!("malformed proposal control must be rejected"),
            }
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn saturation_blocks_a_retained_prefix_until_lossless_reset() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-saturation");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 1, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let driver = match driver.admit_event(prevote_event(&prevote)).unwrap() {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(_)
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
                            canonical_signed_prevote,
                        } => assert_eq!(canonical_signed_prevote.as_ref(), prevote.as_slice()),
                        _ => panic!("saturation must return the rejected prevote"),
                    }
                    *driver
                }
                _ => panic!("distinct input above the cap must saturate"),
            };
            assert_eq!(driver.inbox_len(), 1);
            let driver = match driver
                .admit_event(proposal_event(2, &control, &payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(
                            FixedValidatorNodeDriverBlockReasonV0::Saturated(_)
                        )
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                            ..
                        } => {
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ref(),
                                control.as_slice()
                            );
                            assert_eq!(canonical_artifact_bytes.as_ref(), payload.as_slice());
                        }
                        _ => panic!("blocked admission must return the exact proposal event"),
                    }
                    *driver
                }
                _ => panic!("latched saturation must deny even a duplicate admission"),
            };
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::Saturated(_)
                    ));
                    *driver
                }
                _ => panic!("latched saturation must keep blocking"),
            };
            assert_eq!(layout.images(), before);
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(drained.len(), 1);
            let (proposals, prevotes) = drained_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert!(prevotes.is_empty());
            assert!(driver.timeout_is_due());
            let driver = step_transition(*driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
        })
        .unwrap();
}

#[test]
fn current_nil_prevote_variants_share_capacity_and_select_canonically() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let round = round_at(&branch, 0);
    let standard = signed_vote_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
        0x01,
    );
    assert_ne!(standard, alternate);
    let preferred = if standard < alternate {
        standard.as_slice()
    } else {
        alternate.as_slice()
    };
    let expected_certificate = round
        .build_quorum_certificate_from_signed_votes(
            &[preferred],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Nil,
        )
        .unwrap()
        .to_canonical_bytes();

    for (first, second) in [
        (standard.as_slice(), alternate.as_slice()),
        (alternate.as_slice(), standard.as_slice()),
    ] {
        let limits = FixedValidatorNodeCurrentRoundInboxLimitsV0::new(
            2,
            u64::try_from(first.len() + second.len()).unwrap(),
        )
        .unwrap();
        let mut inbox = CurrentRoundInboxV0::new(limits);
        assert!(matches!(
            inbox.try_insert_nil_prevote(&round, first),
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted)
        ));
        assert!(matches!(
            inbox.try_insert_nil_prevote(&round, first),
            Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained)
        ));
        assert!(matches!(
            inbox.try_insert_nil_prevote(&round, second),
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted)
        ));
        assert_eq!(inbox.len(), 2);
        assert_eq!(
            inbox.total_canonical_input_bytes(),
            u64::try_from(first.len() + second.len()).unwrap()
        );
        match inbox.select_nil_quorum(&round) {
            Ok(CurrentRoundQuorumSelectionV0::One {
                canonical_certificate,
            }) => assert_eq!(canonical_certificate, expected_certificate),
            _ => panic!("the canonical nil quorum must be actionable"),
        }
        let (_, proposal_prevotes, mut nil_prevotes) =
            drained_current_contents(inbox.drain_and_reset());
        assert!(proposal_prevotes.is_empty());
        nil_prevotes.sort_unstable();
        let mut expected = vec![first.to_vec(), second.to_vec()];
        expected.sort_unstable();
        assert_eq!(nil_prevotes, expected);
    }
}

#[test]
fn current_nil_prevote_admission_is_target_typed_and_shares_current_limits() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-prevote-admission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let proposal_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let inactive_signer = SigningKey::from_bytes(&signing_seed(2));
    let inactive_nil_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &inactive_signer,
    );
    let wrong_position_nil_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 1).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );
    let wrong_context_nil_prevote = signed_vote_bytes(
        wrong_context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut invalid_signature_nil_prevote = nil_prevote.clone();
    *invalid_signature_nil_prevote.last_mut().unwrap() ^= 0x01;
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver_with_inbox_limits(scope, 8, 1, 4));
            let driver = reject_current_nil_prevote(driver, &proposal_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                        naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::ProposalTarget {
                            actual
                        }
                    ) if *actual == value.proposal_signing_root()
                ));
            });
            let driver = reject_current_nil_prevote(driver, &nil_precommit, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                        naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::RoleMismatch {
                            actual: ConsensusVoteRole::Precommit
                        }
                    )
                ));
            });
            let driver = reject_current_nil_prevote(driver, &inactive_nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                        naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::InactiveSigner { .. }
                    )
                ));
            });
            let driver = reject_current_nil_prevote(
                driver,
                &wrong_position_nil_prevote,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                            naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::PositionMismatch {
                                ..
                            }
                        )
                    ));
                },
            );
            let driver = reject_current_nil_prevote(
                driver,
                &wrong_context_nil_prevote,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                            naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::GenesisIdMismatch { .. }
                            )
                        )
                    ));
                },
            );
            let driver = reject_current_nil_prevote(
                driver,
                &invalid_signature_nil_prevote,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(
                            naome_consensus::FixedConsensusNilPrevoteVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::InvalidSignature { .. }
                            )
                        )
                    ));
                },
            );
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(layout.images(), before);

            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let driver = reject_current_nil_prevote(driver, &nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                        position: saturated_position,
                        newly_saturated: true,
                        ..
                    } if *saturated_position == position
                ));
            });
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(layout.images(), before);
            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, proposal_prevotes, nil_prevotes) =
                drained_current_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert!(proposal_prevotes.is_empty());
            assert!(nil_prevotes.is_empty());
        })
        .unwrap();
}

#[test]
fn current_evidence_after_due_is_returned_without_mutation() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-due-fence");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let valid_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let control = control.into_boxed_slice();
    let payload = payload.into_boxed_slice();
    let control_pointer = control.as_ptr();
    let payload_pointer = payload.as_ptr();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let position = driver.position();
            let (driver, _) = admit_due(driver, timeout);
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                    canonical_proposal_control_bytes: control,
                    canonical_artifact_bytes: payload,
                })
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                            position: rejected_position,
                            phase: FixedValidatorLockPhaseV0::Proposal,
                        } if rejected_position == position
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(canonical_proposal_control_bytes.as_ptr(), control_pointer);
                            assert_eq!(canonical_artifact_bytes.as_ptr(), payload_pointer);
                        }
                        _ => panic!("due-fenced proposal must return its exact event"),
                    }
                    *driver
                }
                _ => panic!("current proposal after due must be rejected"),
            };
            assert_eq!(driver.current_inbox_len(), 0);
            assert!(driver.timeout_is_due());
            assert_eq!(layout.images(), before);

            let driver = step_transition(driver);
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Nil);
            let valid_nil_prevote = prevote.canonical_bytes().to_vec();
            assert_eq!(driver.current_inbox_len(), 0);
            let (driver, prevote_timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, prevote_timeout);
            let driver = reject_current_prevote(driver, &valid_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                        position: rejected_position,
                        phase: FixedValidatorLockPhaseV0::Prevote,
                    } if *rejected_position == position
                ));
            });
            let driver = reject_current_nil_prevote(driver, &valid_nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                        position: rejected_position,
                        phase: FixedValidatorLockPhaseV0::Prevote,
                    } if *rejected_position == position
                ));
            });
            assert!(driver.timeout_is_due());
            assert_eq!(driver.current_inbox_len(), 0);
            let driver = step_transition(driver);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Nil);
            assert_eq!(driver.current_inbox_len(), 0);
        })
        .unwrap();
}

#[test]
fn current_saturation_uses_a_separate_budget_and_preserves_higher_escape() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-separate-saturation");
    let branch = fixed_branch(&fixture);
    let (_, retained_control, retained_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, rejected_control, rejected_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Union);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::PowerSet);
    let higher_position = round_at(&branch, 2).position();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, current_timeout) = step_arm(driver_with_inbox_limits(scope, 4, 1, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&retained_control, &retained_payload),
            );
            let driver = match driver
                .admit_event(current_proposal_event(&rejected_control, &rejected_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                            newly_saturated: true,
                            ..
                        }
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ref(),
                                rejected_control.as_slice()
                            );
                            assert_eq!(
                                canonical_artifact_bytes.as_ref(),
                                rejected_payload.as_slice()
                            );
                        }
                        _ => panic!("current saturation must return the rejected event"),
                    }
                    *driver
                }
                _ => panic!("the second current input must exceed its separate cap"),
            };
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 0);
            let (driver, _) = admit_due(driver, current_timeout);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated { .. }
                    ));
                    *driver
                }
                _ => panic!("current saturation must block the exact due path"),
            };

            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            assert_eq!(driver.inbox_len(), 2);
            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, _, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_some());
            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated { .. }
                    ));
                    *driver
                }
                _ => panic!("current saturation must require an explicit drain after advance"),
            };

            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            assert_eq!(
                proposals,
                vec![(retained_control.clone(), retained_payload.clone())]
            );
            assert!(prevotes.is_empty());
            assert!(nil_prevotes.is_empty());
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.inbox_len(), 1);
            assert!(matches!(
                driver.step().unwrap(),
                FixedValidatorNodeDriverStepOutcomeV0::Idle { .. }
            ));
        })
        .unwrap();
}

#[test]
fn current_byte_saturation_does_not_consume_higher_inbox_capacity() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-separate-byte-saturation");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 0).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let current_exact_bytes = u64::try_from(current_control.len() + current_payload.len()).unwrap();
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher_position = round_at(&branch, 2).position();
    let higher_root = higher_value.proposal_signing_root();
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver_with_limits(
                scope,
                4,
                1024 * 1024,
                4,
                current_exact_bytes,
                4,
            ));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                current_exact_bytes
            );
            let driver = reject_current_prevote(driver, &current_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                        saturation:
                            FixedValidatorNodeCurrentRoundInboxSaturationV0::Capacity { .. },
                        newly_saturated: true,
                        ..
                    }
                ));
            });
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 0);

            let (driver, _) = admit(
                driver,
                proposal_event(2, &higher_control, &higher_payload),
            );
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            assert_eq!(driver.inbox_len(), 2);
            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            let (driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.target(), ConsensusVoteTarget::Proposal(higher_root));
            assert!(released_proposal.is_some());
            assert_eq!(driver.current_inbox_len(), 1);
        })
        .unwrap();
}

#[test]
fn current_admission_returns_invalid_inputs_and_deduplicates_verified_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-admission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let valid_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_position_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 1).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );
    let wrong_context_prevote = signed_vote_bytes(
        wrong_context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let inactive_signer = SigningKey::from_bytes(&signing_seed(2));
    let inactive_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &inactive_signer,
    );
    let mut invalid_signature_prevote = valid_prevote.clone();
    *invalid_signature_prevote.last_mut().unwrap() ^= 0x01;
    let mismatched_payload = proof_payload(ZfcAxiom::Union);
    let malformed_control = vec![0x01, 0x02, 0x03].into_boxed_slice();
    let malformed_payload = payload.clone().into_boxed_slice();
    let malformed_control_pointer = malformed_control.as_ptr();
    let malformed_payload_pointer = malformed_payload.as_ptr();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                    canonical_proposal_control_bytes: malformed_control,
                    canonical_artifact_bytes: malformed_payload,
                })
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(source)
                            if matches!(
                                source.as_ref(),
                                naome_consensus::ConsensusProposalVerifyError::InvalidLength {
                                    actual: 3,
                                    ..
                                }
                            )
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(
                                canonical_proposal_control_bytes.as_ptr(),
                                malformed_control_pointer
                            );
                            assert_eq!(
                                canonical_artifact_bytes.as_ptr(),
                                malformed_payload_pointer
                            );
                        }
                        _ => panic!("invalid current proposal must return its exact event"),
                    }
                    *driver
                }
                _ => panic!("malformed current proposal must be rejected"),
            };
            assert_eq!(driver.current_inbox_len(), 0);

            let driver = match driver
                .admit_event(current_proposal_event(&control, &mismatched_payload))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(_)
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } if canonical_proposal_control_bytes.as_ref() == control.as_slice()
                            && canonical_artifact_bytes.as_ref() == mismatched_payload.as_slice()
                    ));
                    *driver
                }
                _ => panic!("a mismatched current proposal payload must be rejected"),
            };
            assert_eq!(driver.current_inbox_len(), 0);

            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            let driver = reject_current_prevote(driver, &nil_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(_)
                ));
            });
            let driver = reject_current_prevote(driver, &precommit, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(_)
                ));
            });
            let driver = reject_current_prevote(driver, &wrong_position_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(_)
                ));
            });
            let driver = reject_current_prevote(driver, &wrong_context_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(
                        naome_consensus::FixedConsensusProposalPrevoteVerifyErrorV0::Vote(
                            naome_consensus::ConsensusVoteVerifyError::GenesisIdMismatch { .. }
                        )
                    )
                ));
            });
            let driver = reject_current_prevote(driver, &inactive_prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(
                        naome_consensus::FixedConsensusProposalPrevoteVerifyErrorV0::InactiveSigner {
                            ..
                        }
                    )
                ));
            });
            let driver =
                reject_current_prevote(driver, &invalid_signature_prevote, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(
                            naome_consensus::FixedConsensusProposalPrevoteVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::InvalidSignature { .. }
                            )
                        )
                    ));
                });
            let (driver, disposition) = admit(driver, current_prevote_event(&valid_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(driver, current_prevote_event(&valid_prevote));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_inbox_len(), 2);
            assert_eq!(layout.images(), before);

            let (_, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, prevotes, nil_prevotes) = drained_current_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert_eq!(prevotes, vec![valid_prevote.clone()]);
            assert!(nil_prevotes.is_empty());
        })
        .unwrap();
}
