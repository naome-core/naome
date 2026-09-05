use super::*;

#[test]
fn fatal_finality_handoff_failure_returns_no_driver_and_reopens_strictly() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-handoff-failure");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);

    let error = ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            match driver.step() {
                Err(error) => error,
                Ok(_) => panic!("fatal finality handoff failure must return no live driver"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeDriverStepErrorV0::CurrentFinality(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                            selection,
                            source,
                        } if matches!(
                            selection.as_ref(),
                            FixedValidatorNodeFinalitySelectionV0::Finalized {
                                position: finalized,
                                ..
                            } if *finalized == position
                        ) && matches!(
                            source.as_ref(),
                            FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                        )
                    )
            )
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
fn current_finality_executes_from_every_phase_and_due_state() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let finality_bytes = u64::try_from(control.len() + payload.len() + precommit.len()).unwrap();
    let child_height = position.height().value().checked_add(1).unwrap();

    for (label, expected_phase, mark_due) in [
        (
            "driver-current-finality-proposal-live",
            FixedValidatorLockPhaseV0::Proposal,
            false,
        ),
        (
            "driver-current-finality-proposal-due",
            FixedValidatorLockPhaseV0::Proposal,
            true,
        ),
        (
            "driver-current-finality-prevote-live",
            FixedValidatorLockPhaseV0::Prevote,
            false,
        ),
        (
            "driver-current-finality-prevote-due",
            FixedValidatorLockPhaseV0::Prevote,
            true,
        ),
        (
            "driver-current-finality-precommit-live",
            FixedValidatorLockPhaseV0::Precommit,
            false,
        ),
        (
            "driver-current-finality-precommit-due",
            FixedValidatorLockPhaseV0::Precommit,
            true,
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, proposal_timeout) = step_arm(driver(scope, 8, 4));
                let (driver, active_timeout) = match expected_phase {
                    FixedValidatorLockPhaseV0::Proposal => (driver, proposal_timeout),
                    FixedValidatorLockPhaseV0::Prevote => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                    FixedValidatorLockPhaseV0::Precommit => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        let (driver, prevote_timeout) = step_arm(driver);
                        let (driver, _) = admit_due(driver, prevote_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
                        assert_eq!(vote.role(), ConsensusVoteRole::Precommit);
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                };
                let driver = if mark_due {
                    let (driver, disposition) = admit_due(driver, active_timeout);
                    assert_eq!(
                        disposition,
                        FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                    );
                    driver
                } else {
                    driver
                };
                assert_eq!(driver.phase(), expected_phase);
                assert_eq!(driver.timeout_is_due(), mark_due);
                let before_finality = layout.images();

                let (driver, _) =
                    admit(driver, current_finality_proposal_event(&control, &payload));
                let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)
                        if action.position() == position
                            && action.proposal_signing_root() == root
                ));
                let (driver, selection) = step_finality(driver);
                assert!(matches!(
                    selection,
                    FixedValidatorNodeFinalitySelectionV0::Finalized {
                        position: finalized,
                        ..
                    } if finalized == position
                ));
                assert_eq!(driver.position().height().value(), child_height);
                assert_eq!(driver.position().round().value(), 0);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                assert!(!driver.timeout_is_due());
                assert!(driver.has_pending_command());
                assert_eq!(driver.current_finality_inbox_len(), 2);
                assert_eq!(
                    driver.current_finality_inbox_canonical_input_bytes(),
                    finality_bytes
                );
                let after_finality = layout.images();
                for (before, after) in before_finality.iter().zip(after_finality.iter()) {
                    assert_ne!(before, after, "each authority image must advance");
                }

                let (driver, child_timeout) = step_arm(driver);
                assert_eq!(child_timeout.position(), driver.position());
                assert_eq!(child_timeout.phase(), FixedValidatorLockPhaseV0::Proposal);
                assert_eq!(
                    child_timeout.generation(),
                    active_timeout.generation().checked_add(1).unwrap()
                );
                let driver = match driver
                    .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(active_timeout))
                    .unwrap()
                {
                    FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                        driver,
                        event,
                        rejection,
                    } => {
                        assert!(matches!(
                            *event,
                            FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                                if returned == active_timeout
                        ));
                        assert!(matches!(
                            rejection.as_ref(),
                            FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                        ));
                        *driver
                    }
                    FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted { .. } => {
                        panic!("the pre-finality timer must be stale")
                    }
                };
                let (driver, drained) =
                    driver.drain_current_finality_inbox_and_reset().into_parts();
                let (proposals, precommits) = drained_current_finality_contents(drained);
                assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
                assert_eq!(precommits, vec![precommit.clone()]);
                assert_eq!(driver.position().height().value(), child_height);
            })
            .unwrap();

        let reopened = expect_ready(
            fixture
                .provision(&layout, 8)
                .open(fixture.signing_key())
                .unwrap(),
        );
        reopened
            .run_with_signing_session(|mut scope| {
                assert_eq!(
                    scope.signing_session().position().height().value(),
                    child_height
                );
                assert_eq!(scope.signing_session().position().round().value(), 0);
                assert_eq!(
                    scope.signing_session().phase(),
                    FixedValidatorLockPhaseV0::Proposal
                );
            })
            .unwrap();
    }
}

#[test]
fn current_finality_precommit_rejections_preserve_each_typed_admission_error() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-precommit-errors");
    let branch = fixed_branch(&fixture);
    let (value, _, _) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let valid = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let wrong_position = round_at(&branch, 1).position();
    let wrong_position_precommit = signed_vote_bytes(
        fixture.context,
        wrong_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let inactive = SigningKey::from_bytes(&signing_seed(2));
    let inactive_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &inactive,
    );
    let wrong_context = ConsensusContextV0::new(
        fixture.definition.id(),
        ConsensusGenesisId::from_bytes([0x99; 32]),
        fixture.context.protocol_version(),
    );
    let wrong_context_precommit = signed_vote_bytes(
        wrong_context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let mut invalid_signature = valid;
    *invalid_signature.last_mut().unwrap() ^= 0x01;
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = reject_current_finality_precommit(
                driver,
                &wrong_context_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::GenesisIdMismatch { .. }
                            )
                        )
                    ));
                },
            );
            let driver = reject_current_finality_precommit(
                driver,
                &invalid_signature,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::InvalidSignature { .. }
                            )
                        )
                    ));
                },
            );
            let driver = reject_current_finality_precommit(
                driver,
                &wrong_position_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::PositionMismatch {
                                expected,
                                actual,
                            }
                        ) if *expected == position && *actual == wrong_position
                    ));
                },
            );
            let driver = reject_current_finality_precommit(driver, &prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                        naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::RoleMismatch {
                            actual: ConsensusVoteRole::Prevote,
                        }
                    )
                ));
            });
            let driver = reject_current_finality_precommit(driver, &nil_precommit, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                        naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::NilTarget
                    )
                ));
            });
            let driver = reject_current_finality_precommit(
                driver,
                &inactive_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::InactiveSigner {
                                signer,
                            }
                        ) if *signer == consensus_key(&inactive)
                    ));
                },
            );
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
            ));
            let _driver = step_idle(driver);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_finality_budget_accounting_saturation_and_lossless_drain_are_isolated() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-budget-drain");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
    let root = value.proposal_signing_root();
    let position = round_at(&branch, 0).position();
    let standard = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
        0x01,
    );
    assert_ne!(standard, alternate);
    let proposal_bytes = u64::try_from(control.len() + payload.len()).unwrap();
    let exact_finality_bytes = proposal_bytes + u64::try_from(standard.len()).unwrap();
    let attempted_finality_bytes = exact_finality_bytes + u64::try_from(alternate.len()).unwrap();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_finality_limits(
                scope,
                1,
                1024 * 1024,
                1,
                1024 * 1024,
                2,
                exact_finality_bytes,
                4,
            );
            let (driver, _) = step_arm(driver);
            let (driver, disposition) = admit(driver, current_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) =
                admit(driver, proposal_event(1, &higher_control, &higher_payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);

            let (driver, disposition) =
                admit(driver, current_finality_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                proposal_bytes
            );
            let (driver, disposition) =
                admit(driver, current_finality_proposal_event(&control, &payload));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                proposal_bytes
            );

            let (driver, disposition) = admit(driver, current_finality_precommit_event(&standard));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                exact_finality_bytes
            );
            let (driver, disposition) = admit(driver, current_finality_precommit_event(&standard));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                exact_finality_bytes
            );

            let driver = reject_current_finality_precommit(driver, &alternate, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                        position: saturated_position,
                        saturation:
                            FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                                attempted_entries: 3,
                                maximum_entries: 2,
                                attempted_canonical_input_bytes,
                                maximum_canonical_input_bytes,
                            },
                        newly_saturated: true,
                    } if *saturated_position == position
                        && *attempted_canonical_input_bytes == attempted_finality_bytes
                        && *maximum_canonical_input_bytes == exact_finality_bytes
                ));
            });
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                exact_finality_bytes
            );
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated {
                    position: saturated_position,
                    saturation:
                        FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                            attempted_entries: 3,
                            maximum_entries: 2,
                            ..
                        },
                } if saturated_position == position
            ));

            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            let (proposals, precommits) = drained_current_finality_contents(drained);
            assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
            assert_eq!(precommits, vec![standard.clone()]);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);

            let (driver, disposition) =
                admit(*driver, current_finality_precommit_event(&alternate));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                u64::try_from(alternate.len()).unwrap()
            );
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_finality_same_signer_variants_choose_one_certificate_in_every_order() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let round = round_at(&branch, 0);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let root = round
        .decode_and_verify_proposal_control(&control, payload)
        .unwrap()
        .proposal_signing_root();
    let standard = signed_vote_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
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
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();

    for (first, second) in [
        (standard.as_slice(), alternate.as_slice()),
        (alternate.as_slice(), standard.as_slice()),
    ] {
        let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
            2,
            u64::try_from(first.len() + second.len()).unwrap(),
        )
        .unwrap();
        let mut inbox = CurrentRoundFinalityInboxV0::new(limits);
        assert!(matches!(
            inbox.try_insert_precommit(&round, first),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
        assert!(matches!(
            inbox.try_insert_precommit(&round, second),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
        match inbox.classify(&round) {
            Ok(CurrentRoundFinalityClassificationV0::OneQuorumMissingProposal {
                proposal_signing_root,
                canonical_precommit_certificate,
            }) => {
                assert_eq!(proposal_signing_root, root);
                assert_eq!(canonical_precommit_certificate, expected_certificate);
            }
            Ok(_) => panic!("same-signer variants must yield one canonical proposal quorum"),
            Err(_) => panic!("individually admitted votes must satisfy classifier invariants"),
        }
        let (_, mut precommits) = drained_current_finality_contents(inbox.drain_and_reset());
        precommits.sort_unstable();
        let mut expected = vec![first.to_vec(), second.to_vec()];
        expected.sort_unstable();
        assert_eq!(precommits, expected);
    }
}

#[test]
fn finality_classifier_skips_a_lower_missing_proposal_and_pairs_the_first_two_complete_roots() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let round = round_at(&branch, 0);
    let mut candidates = [ZfcAxiom::Pairing, ZfcAxiom::Union, ZfcAxiom::PowerSet]
        .into_iter()
        .map(|axiom| {
            let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, axiom);
            let root = value.proposal_signing_root();
            let precommit = signed_vote_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                &fixture.signing_key(),
            );
            (root, control, payload, precommit)
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|candidate| candidate.0);
    assert!(candidates.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let retained_bytes = candidates
        .iter()
        .map(|(_, control, payload, precommit)| control.len() + payload.len() + precommit.len())
        .sum::<usize>()
        - candidates[0].1.len()
        - candidates[0].2.len();
    let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
        5,
        u64::try_from(retained_bytes).unwrap(),
    )
    .unwrap();
    let mut inbox = CurrentRoundFinalityInboxV0::new(limits);
    for (_, _, _, precommit) in &candidates {
        assert!(matches!(
            inbox.try_insert_precommit(&round, precommit),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
    }
    for (_, control, payload, _) in &candidates[1..] {
        let proposal = verify_deferred_proposal_at_round(&round, control, payload.clone()).unwrap();
        assert!(matches!(
            inbox.try_insert_proposal(proposal),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
    }
    match inbox.classify(&round) {
        Ok(CurrentRoundFinalityClassificationV0::Pair { first, second }) => {
            assert_eq!(first.proposal_signing_root, candidates[1].0);
            assert_eq!(second.proposal_signing_root, candidates[2].0);
            assert_eq!(first.canonical_proposal_control_bytes, candidates[1].1);
            assert_eq!(first.canonical_artifact_bytes, candidates[1].2);
            assert_eq!(second.canonical_proposal_control_bytes, candidates[2].1);
            assert_eq!(second.canonical_artifact_bytes, candidates[2].2);
        }
        Ok(_) => panic!("a missing lower proposal must not hide two later complete roots"),
        Err(_) => panic!("individually verified retained evidence must classify"),
    }
}

#[test]
fn current_finality_classifier_is_four_way_and_variant_order_stable() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let other_root = ProposalSigningRoot::from_bytes([0xf3; 32]);
    assert_ne!(root, other_root);
    let standard = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
        0x01,
    );
    let conflicting = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(other_root),
        &fixture.signing_key(),
    );
    let expected_roots = if root < other_root {
        (root, other_root)
    } else {
        (other_root, root)
    };
    let mut outcomes = Vec::new();

    for (label, first, second) in [
        (
            "driver-current-finality-standard-first",
            standard.as_slice(),
            alternate.as_slice(),
        ),
        (
            "driver-current-finality-alternate-first",
            alternate.as_slice(),
            standard.as_slice(),
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        let outcome = ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver(scope, 8, 4));
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
                ));

                let (driver, _) = admit(driver, current_finality_precommit_event(first));
                let missing = match driver.classify_current_finality_evidence().unwrap() {
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::QuorumMissingProposal(
                        action,
                    ) => {
                        assert_eq!(action.position(), position);
                        assert_eq!(action.proposal_signing_root(), root);
                        (action.position(), action.proposal_signing_root())
                    }
                    _ => panic!("one quorate root without proposal must be classified explicitly"),
                };
                let (driver, _) = admit(driver, current_finality_precommit_event(second));
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::QuorumMissingProposal(
                        action,
                    ) if action.position() == position
                        && action.proposal_signing_root() == root
                ));
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing {
                                position: blocked_position,
                                proposal_signing_root,
                            } if blocked_position == position && proposal_signing_root == root
                        ));
                        *driver
                    }
                    _ => panic!("a finality quorum missing its proposal must block"),
                };
                assert_eq!(layout.images(), before);

                let (driver, _) =
                    admit(driver, current_finality_proposal_event(&control, &payload));
                let ready = match driver.classify_current_finality_evidence().unwrap() {
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action) => {
                        assert_eq!(action.position(), position);
                        assert_eq!(action.proposal_signing_root(), root);
                        (action.position(), action.proposal_signing_root())
                    }
                    _ => panic!("one proposal-bearing quorum must be ready"),
                };

                let (driver, _) = admit(driver, current_finality_precommit_event(&conflicting));
                let conflict = match driver.classify_current_finality_evidence().unwrap() {
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                        position: classified_position,
                        first,
                        second,
                    } => {
                        assert_eq!(classified_position, position);
                        assert_eq!((first, second), expected_roots);
                        (classified_position, first, second)
                    }
                    _ => panic!("two quorate roots must fail closed without selection"),
                };
                assert_eq!(driver.current_finality_inbox_len(), 4);
                let driver = match driver.step().unwrap() {
                    FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                        assert!(matches!(
                            reason,
                            FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityRootsConflicting {
                                position: blocked_position,
                                first,
                                second,
                            } if blocked_position == position
                                && (first, second) == expected_roots
                        ));
                        *driver
                    }
                    _ => panic!("conflicting finality quorums must choose no winner and block"),
                };
                assert_eq!(driver.current_finality_inbox_len(), 4);
                assert_eq!(layout.images(), before);
                (missing, ready, conflict)
            })
            .unwrap();
        outcomes.push(outcome);
    }

    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn current_finality_evidence_is_volatile_and_readmittable_after_strict_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-restart-readmission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let root = value.proposal_signing_root();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)
                    if action.position() == position
                        && action.proposal_signing_root() == root
            ));
            assert_eq!(layout.images(), before);
            drop(driver);
        })
        .unwrap();
    assert_eq!(layout.images(), before);

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
            ));
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)
                    if action.position() == position
                        && action.proposal_signing_root() == root
            ));
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn pending_command_precedes_and_malformed_finality_events_are_returned_losslessly() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-custody-malformed");
    let malformed_control = vec![0x01, 0x02, 0x03].into_boxed_slice();
    let malformed_payload = vec![0x04, 0x05].into_boxed_slice();
    let control_pointer = malformed_control.as_ptr();
    let payload_pointer = malformed_payload.as_ptr();
    let malformed_precommit = vec![0x06, 0x07, 0x08].into_boxed_slice();
    let precommit_pointer = malformed_precommit.as_ptr();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 4);
            let (driver, malformed_control, malformed_payload) = match driver
                .admit_event(
                    FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                        canonical_proposal_control_bytes: malformed_control,
                        canonical_artifact_bytes: malformed_payload,
                    },
                )
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(canonical_proposal_control_bytes.as_ptr(), control_pointer);
                            assert_eq!(canonical_artifact_bytes.as_ptr(), payload_pointer);
                            (
                                *driver,
                                canonical_proposal_control_bytes,
                                canonical_artifact_bytes,
                            )
                        }
                        _ => panic!("pending custody must return the exact finality proposal"),
                    }
                }
                _ => panic!("pending timeout command must precede finality proposal inspection"),
            };
            let (driver, malformed_precommit) = match driver
                .admit_event(
                    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
                        canonical_signed_precommit: malformed_precommit,
                    },
                )
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
                            canonical_signed_precommit,
                        } => {
                            assert_eq!(canonical_signed_precommit.as_ptr(), precommit_pointer);
                            (*driver, canonical_signed_precommit)
                        }
                        _ => panic!("pending custody must return the exact finality precommit"),
                    }
                }
                _ => panic!("pending timeout command must precede finality precommit inspection"),
            };
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(layout.images(), before);

            let (driver, _) = step_arm(driver);
            let driver = match driver
                .admit_event(
                    FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                        canonical_proposal_control_bytes: malformed_control,
                        canonical_artifact_bytes: malformed_payload,
                    },
                )
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        rejection.as_ref(),
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityProposal(
                            source
                        ) if matches!(
                            source.as_ref(),
                            naome_consensus::ConsensusProposalVerifyError::InvalidLength {
                                actual: 3,
                                ..
                            }
                        )
                    ));
                    match *event {
                        FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        } => {
                            assert_eq!(canonical_proposal_control_bytes.as_ptr(), control_pointer);
                            assert_eq!(canonical_artifact_bytes.as_ptr(), payload_pointer);
                        }
                        _ => panic!("malformed finality proposal must return its exact event"),
                    }
                    *driver
                }
                _ => panic!("malformed finality proposal must be rejected after custody clears"),
            };
            let driver =
                reject_current_finality_precommit(driver, &malformed_precommit, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(
                            naome_consensus::FixedConsensusProposalPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::Decode(
                                    naome_consensus::ConsensusVoteDecodeError::InvalidLength {
                                        actual: 3,
                                        ..
                                    }
                                )
                            )
                        )
                    ));
                });
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn finality_admission_bypasses_latched_current_and_higher_saturation() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-bypasses-voting-saturation");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
    let current_position = round_at(&branch, 0).position();
    let higher_position = round_at(&branch, 1).position();
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let finality_precommit = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let current_input_bytes = u64::try_from(current_control.len() + current_payload.len()).unwrap();
    let finality_input_bytes = current_input_bytes
        .checked_add(u64::try_from(finality_precommit.len()).unwrap())
        .unwrap();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_finality_limits(
                scope,
                1,
                1024 * 1024,
                1,
                1024 * 1024,
                2,
                1024 * 1024,
                4,
            );
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let mut current_saturation = None;
            let driver =
                reject_current_prevote(driver, &current_prevote, |rejection| match rejection {
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                        saturation,
                        newly_saturated: true,
                        ..
                    } => current_saturation = Some(*saturation),
                    _ => panic!("current voting inbox must newly saturate"),
                });
            let current_saturation = current_saturation.unwrap();
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                current_input_bytes
            );

            let (driver, _) = admit(driver, proposal_event(1, &higher_control, &higher_payload));
            let mut higher_saturation = None;
            let driver = reject_prevote(driver, &higher_prevote, |rejection| match rejection {
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(source) => {
                    match source.as_ref() {
                        FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0::Saturated {
                            saturation,
                            newly_saturated: true,
                        } => higher_saturation = Some(*saturation),
                        _ => panic!("higher voting inbox must newly saturate"),
                    }
                }
                _ => panic!("higher prevote must be rejected by its inbox"),
            });
            let higher_saturation = higher_saturation.unwrap();
            assert_eq!(driver.inbox_len(), 1);

            let (driver, disposition) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let (driver, disposition) = admit(
                driver,
                current_finality_precommit_event(&finality_precommit),
            );
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                current_input_bytes
            );
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                finality_input_bytes
            );
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)
                    if action.position() == current_position
                        && action.proposal_signing_root()
                            == current_value.proposal_signing_root()
            ));
            assert_eq!(layout.images(), before);

            let (driver, selection) = step_finality(driver);
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: finalized,
                    ..
                } if finalized == current_position
            ));
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round().value(), 0);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_inbox_canonical_input_bytes(),
                current_input_bytes
            );
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                finality_input_bytes
            );
            assert_ne!(layout.images(), before);

            let (driver, _) = step_arm(driver);
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::Saturated(saturation)
                            if saturation == higher_saturation
                    ));
                    *driver
                }
                _ => panic!("stale higher saturation must remain until its explicit drain"),
            };
            let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
            let (proposals, prevotes) = drained_contents(drained);
            assert_eq!(
                proposals,
                vec![(higher_control.clone(), higher_payload.clone())]
            );
            assert!(prevotes.is_empty());

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated {
                            position,
                            saturation,
                        } if position == current_position && saturation == current_saturation
                    ));
                    *driver
                }
                _ => panic!("stale current saturation must remain until its explicit drain"),
            };
            let (driver, drained) = driver.drain_current_inbox_and_reset().into_parts();
            let (proposals, proposal_prevotes, nil_prevotes) = drained_current_contents(drained);
            assert_eq!(
                proposals,
                vec![(current_control.clone(), current_payload.clone())]
            );
            assert!(proposal_prevotes.is_empty());
            assert!(nil_prevotes.is_empty());

            let driver = step_idle(*driver);
            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            let (proposals, precommits) = drained_current_finality_contents(drained);
            assert_eq!(
                proposals,
                vec![(current_control.clone(), current_payload.clone())]
            );
            assert_eq!(precommits, vec![finality_precommit.clone()]);
            assert_eq!(driver.position().height().value(), 2);
        })
        .unwrap();
}

#[test]
fn ready_current_finality_precedes_higher_current_and_due_work() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-priority");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
    let current_position = round_at(&branch, 0).position();
    let higher_position = round_at(&branch, 1).position();
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher_position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let finality_precommit = signed_vote_bytes(
        fixture.context,
        current_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 16, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(driver, proposal_event(1, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(
                driver,
                current_finality_precommit_event(&finality_precommit),
            );

            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing {
                            position,
                            proposal_signing_root,
                        } if position == current_position
                            && proposal_signing_root == current_value.proposal_signing_root()
                    ));
                    *driver
                }
                _ => panic!("missing finality proposal must block every lower-priority action"),
            };
            assert_eq!(layout.images(), before);
            assert!(driver.timeout_is_due());

            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, selection) = step_finality(driver);
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position,
                    ..
                } if position == current_position
            ));
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round().value(), 0);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            assert_eq!(driver.inbox_len(), 2);
            assert_eq!(driver.current_inbox_len(), 2);
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_ne!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn finality_count_and_byte_saturation_latch_and_reset_independently() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let (_, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 1, ZfcAxiom::Union);
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let proposal_bytes = u64::try_from(control.len() + payload.len()).unwrap();
    let attempted_bytes = proposal_bytes + u64::try_from(precommit.len()).unwrap();

    for (label, max_entries, max_bytes) in [
        (
            "driver-current-finality-count-saturation",
            1,
            attempted_bytes,
        ),
        ("driver-current-finality-byte-saturation", 2, proposal_bytes),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let before = layout.images();
        ready
            .run_with_signing_session(|scope| {
                let driver = driver_with_finality_limits(
                    scope,
                    2,
                    1024 * 1024,
                    2,
                    1024 * 1024,
                    max_entries,
                    max_bytes,
                    4,
                );
                let (driver, timeout) = step_arm(driver);
                let (driver, _) =
                    admit(driver, current_proposal_event(&control, &payload));
                let (driver, _) = admit(
                    driver,
                    proposal_event(1, &higher_control, &higher_payload),
                );
                let (driver, _) = admit_due(driver, timeout);
                let (driver, _) = admit(
                    driver,
                    current_finality_proposal_event(&control, &payload),
                );
                let driver = reject_current_finality_precommit(
                    driver,
                    &precommit,
                    |rejection| {
                        assert!(matches!(
                            rejection,
                            FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                                position: saturated_position,
                                saturation:
                                    FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0::Capacity {
                                        attempted_entries: 2,
                                        maximum_entries,
                                        attempted_canonical_input_bytes,
                                        maximum_canonical_input_bytes,
                                    },
                                newly_saturated: true,
                            } if *saturated_position == position
                                && *maximum_entries == max_entries
                                && *attempted_canonical_input_bytes == attempted_bytes
                                && *maximum_canonical_input_bytes == max_bytes
                        ));
                    },
                );
                assert_eq!(driver.current_finality_inbox_len(), 1);
                assert_eq!(
                    driver.current_finality_inbox_canonical_input_bytes(),
                    proposal_bytes
                );
                assert_eq!(driver.current_inbox_len(), 1);
                assert_eq!(driver.inbox_len(), 1);
                assert!(driver.timeout_is_due());

                let driver = reject_current_finality_precommit(
                    driver,
                    &precommit,
                    |rejection| {
                        assert!(matches!(
                            rejection,
                            FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                                position: saturated_position,
                                newly_saturated: false,
                                ..
                            } if *saturated_position == position
                        ));
                    },
                );
                assert!(matches!(
                    driver.classify_current_finality_evidence().unwrap(),
                    FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated {
                        position: saturated_position,
                        ..
                    } if saturated_position == position
                ));

                let (driver, drained) = driver
                    .drain_current_finality_inbox_and_reset()
                    .into_parts();
                let (proposals, precommits) =
                    drained_current_finality_contents(drained);
                assert_eq!(proposals, vec![(control.clone(), payload.clone())]);
                assert!(precommits.is_empty());
                assert_eq!(driver.current_finality_inbox_len(), 0);
                assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
                assert_eq!(driver.current_inbox_len(), 1);
                assert_eq!(driver.inbox_len(), 1);
                assert!(driver.timeout_is_due());

                let (driver, disposition) = admit(
                    *driver,
                    current_finality_precommit_event(&precommit),
                );
                assert_eq!(
                    disposition,
                    FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
                );
                assert_eq!(driver.current_finality_inbox_len(), 1);
                assert_eq!(driver.current_inbox_len(), 1);
                assert_eq!(driver.inbox_len(), 1);
                assert!(driver.timeout_is_due());
                assert_eq!(layout.images(), before);
            })
            .unwrap();
    }
}

#[test]
fn finality_saturation_supersedes_healthy_missing_proposal_block() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-block-then-saturation");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
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
            let driver = driver_with_finality_limits(
                scope,
                8,
                1024 * 1024,
                8,
                1024 * 1024,
                1,
                1024 * 1024,
                4,
            );
            let (driver, timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, current_finality_precommit_event(&precommit));
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing {
                            position: blocked_position,
                            proposal_signing_root,
                        } if blocked_position == position
                            && proposal_signing_root == value.proposal_signing_root()
                    ));
                    *driver
                }
                _ => panic!("healthy missing-proposal finality must block due work"),
            };
            assert_eq!(layout.images(), before);

            let driver = reject_current_finality_proposal(
                driver,
                &control,
                &payload,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                            position: saturated_position,
                            newly_saturated: true,
                            ..
                        } if *saturated_position == position
                    ));
                },
            );
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated {
                    position: saturated_position,
                    ..
                } if saturated_position == position
            ));
            assert_eq!(layout.images(), before);

            let driver = step_transition(driver);
            let (_driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
            assert!(released_proposal.is_none());
        })
        .unwrap();
}

#[test]
fn saturated_finality_inbox_leaves_due_step_and_authority_state_unchanged() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let position = round_at(&branch, 0).position();
    let precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let mut outcomes = Vec::new();

    for (label, saturate_finality) in [
        ("driver-current-finality-step-baseline", false),
        ("driver-current-finality-step-saturated", true),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        let outcome = ready
            .run_with_signing_session(|scope| {
                let driver = driver_with_finality_limits(
                    scope,
                    8,
                    1024 * 1024,
                    8,
                    1024 * 1024,
                    1,
                    1024 * 1024,
                    4,
                );
                let (driver, timeout) = step_arm(driver);
                let driver = if saturate_finality {
                    let (driver, _) = admit(
                        driver,
                        current_finality_proposal_event(&control, &payload),
                    );
                    let driver = reject_current_finality_precommit(
                        driver,
                        &precommit,
                        |rejection| {
                            assert!(matches!(
                                rejection,
                                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                                    newly_saturated: true,
                                    ..
                                }
                            ));
                        },
                    );
                    assert!(matches!(
                        driver.classify_current_finality_evidence().unwrap(),
                        FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated { .. }
                    ));
                    driver
                } else {
                    driver
                };
                let (driver, disposition) = admit_due(driver, timeout);
                assert_eq!(
                    disposition,
                    FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
                );
                let driver = step_transition(driver);
                let (driver, vote, released_proposal) = step_publish(driver);
                assert!(released_proposal.is_none());
                assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
                assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
                assert!(!driver.timeout_is_due());
                assert!(driver.has_pending_command());
                (
                    vote.canonical_bytes().to_vec(),
                    driver.position(),
                    driver.phase(),
                    driver.timeout_is_due(),
                    driver.has_pending_command(),
                    layout.images(),
                )
            })
            .unwrap();
        outcomes.push(outcome);
    }

    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn incomplete_current_finality_evidence_becomes_nonmatching_after_position_advance() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-finality-former-position");
    let signing_keys = [
        SigningKey::from_bytes(&signing_seed(1)),
        SigningKey::from_bytes(&signing_seed(2)),
        SigningKey::from_bytes(&signing_seed(3)),
    ];
    let entries = signing_keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect::<Vec<_>>();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let current_round = round_at(&branch, 0);
    let current_proposer = signing_keys
        .iter()
        .find(|key| consensus_key(key) == current_round.proposer())
        .unwrap();
    let (current_value, current_control, current_payload) =
        proposal_inputs_with_signing_key(&fixture, &branch, 0, ZfcAxiom::Pairing, current_proposer);
    let current_precommit = signed_vote_bytes(
        fixture.context,
        current_round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
        &signing_keys[0],
    );
    let higher_round = round_at(&branch, 1);
    let higher_proposer = signing_keys
        .iter()
        .find(|key| consensus_key(key) == higher_round.proposer())
        .unwrap();
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs_with_signing_key(&fixture, &branch, 1, ZfcAxiom::Union, higher_proposer);
    let higher_position = higher_round.position();
    let higher_prevotes = signing_keys
        .iter()
        .map(|key| {
            signed_vote_bytes(
                fixture.context,
                higher_position,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
                key,
            )
        })
        .collect::<Vec<_>>();
    let retained_bytes =
        u64::try_from(current_control.len() + current_payload.len() + current_precommit.len())
            .unwrap();
    let ready = provision_with_fixed_entries(&fixture, &layout, &entries)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_finality_precommit_event(&current_precommit));
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
            ));
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                retained_bytes
            );

            let (driver, _) = admit(driver, proposal_event(1, &higher_control, &higher_payload));
            let mut driver = driver;
            for higher_prevote in &higher_prevotes {
                (driver, _) = admit(driver, prevote_event(higher_prevote));
            }
            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(matches!(
                driver.classify_current_finality_evidence().unwrap(),
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete
            ));
            assert_eq!(driver.current_finality_inbox_len(), 2);
            assert_eq!(
                driver.current_finality_inbox_canonical_input_bytes(),
                retained_bytes
            );

            let (driver, drained) = driver.drain_current_finality_inbox_and_reset().into_parts();
            let (proposals, precommits) = drained_current_finality_contents(drained);
            assert_eq!(
                proposals,
                vec![(current_control.clone(), current_payload.clone())]
            );
            assert_eq!(precommits, vec![current_precommit.clone()]);
            assert_eq!(driver.position(), higher_position);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_canonical_input_bytes(), 0);
        })
        .unwrap();
}

#[test]
fn current_finality_preclassification_routes_only_matching_precommits_to_round_work() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let round = round_at(&branch, 0);
    let next_round = round_at(&branch, 1);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let precommit = signed_vote_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
        &fixture.signing_key(),
    );
    let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(2, 1024 * 1024).unwrap();

    let empty = CurrentRoundFinalityInboxV0::new(limits);
    assert_eq!(
        empty.preclassify(round.parent_coordinate(), round.position()),
        CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit
    );

    let mut proposal_only = CurrentRoundFinalityInboxV0::new(limits);
    let proposal = verify_deferred_proposal_at_round(&round, &control, payload.clone()).unwrap();
    assert!(matches!(
        proposal_only.try_insert_proposal(proposal),
        Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
    ));
    assert_eq!(
        proposal_only.preclassify(round.parent_coordinate(), round.position()),
        CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit
    );

    let mut precommit_only = CurrentRoundFinalityInboxV0::new(
        FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(1, 1024 * 1024).unwrap(),
    );
    assert!(matches!(
        precommit_only.try_insert_precommit(&round, &precommit),
        Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
    ));
    assert_eq!(
        precommit_only.preclassify(next_round.parent_coordinate(), next_round.position()),
        CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit
    );
    assert_eq!(
        precommit_only.preclassify(round.parent_coordinate(), round.position()),
        CurrentRoundFinalityPreclassificationV0::NeedsRound
    );

    let proposal = verify_deferred_proposal_at_round(&round, &control, payload).unwrap();
    assert!(precommit_only.try_insert_proposal(proposal).is_err());
    let (saturated_position, saturation) = precommit_only.saturation().unwrap();
    assert_eq!(
        precommit_only.preclassify(round.parent_coordinate(), round.position()),
        CurrentRoundFinalityPreclassificationV0::Saturated {
            position: saturated_position,
            saturation,
        }
    );
}

#[test]
fn current_finality_classifier_keeps_offline_weight_in_exact_two_thirds_denominator() {
    let fixture = Fixture::new();
    let signing_keys = [
        SigningKey::from_bytes(&signing_seed(1)),
        SigningKey::from_bytes(&signing_seed(2)),
        SigningKey::from_bytes(&signing_seed(3)),
    ];
    let entries = signing_keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect::<Vec<_>>();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let round = branch.begin_round_zero().unwrap();
    let root = ProposalSigningRoot::from_bytes([0xa7; 32]);
    let votes = signing_keys
        .iter()
        .map(|key| {
            signed_vote_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                key,
            )
        })
        .collect::<Vec<_>>();
    let limits = FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
        3,
        u64::try_from(votes.iter().map(Vec::len).sum::<usize>()).unwrap(),
    )
    .unwrap();
    let mut inbox = CurrentRoundFinalityInboxV0::new(limits);

    for vote in &votes[..2] {
        assert!(matches!(
            inbox.try_insert_precommit(&round, vote),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
    }
    assert!(matches!(
        inbox.classify(&round),
        Ok(CurrentRoundFinalityClassificationV0::None)
    ));

    assert!(matches!(
        inbox.try_insert_precommit(&round, &votes[2]),
        Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
    ));
    assert!(matches!(
        inbox.classify(&round),
        Ok(CurrentRoundFinalityClassificationV0::OneQuorumMissingProposal {
            proposal_signing_root,
            ..
        }) if proposal_signing_root == root
    ));
}

#[test]
fn current_finality_same_root_proposal_variants_select_lexicographically_in_every_order() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (value, plain_control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let prior_round = round_at(&branch, 1);
    let prior_prevote = signed_vote_bytes(
        fixture.context,
        prior_round.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let valid_round_certificate = prior_round
        .build_quorum_certificate_from_signed_votes(
            &[prior_prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let round = round_at(&branch, 2);
    let proof_control = proposal_control_with_valid_round(
        &fixture,
        value,
        round.position(),
        &valid_round_certificate,
    );
    assert_ne!(plain_control, proof_control);
    let selected_control = if plain_control < proof_control {
        plain_control.as_slice()
    } else {
        proof_control.as_slice()
    };
    let precommit = signed_vote_bytes(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round
        .build_quorum_certificate_from_signed_votes(
            &[precommit.as_slice()],
            ConsensusVoteRole::Precommit,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let total_bytes = u64::try_from(
        plain_control.len() + payload.len() + proof_control.len() + payload.len() + precommit.len(),
    )
    .unwrap();

    for (first, second) in [
        (plain_control.as_slice(), proof_control.as_slice()),
        (proof_control.as_slice(), plain_control.as_slice()),
    ] {
        let limits =
            FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(3, total_bytes).unwrap();
        let mut inbox = CurrentRoundFinalityInboxV0::new(limits);
        for control in [first, second] {
            let proposal = verify_deferred_proposal_at_round(&round, control, payload.clone())
                .expect("both same-root proposal representations must verify");
            assert!(matches!(
                inbox.try_insert_proposal(proposal),
                Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
            ));
        }
        assert!(matches!(
            inbox.try_insert_precommit(&round, &precommit),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted)
        ));
        match inbox.classify(&round) {
            Ok(CurrentRoundFinalityClassificationV0::One {
                proposal_signing_root,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_precommit_certificate,
            }) => {
                assert_eq!(proposal_signing_root, root);
                assert_eq!(canonical_proposal_control_bytes, selected_control);
                assert_eq!(canonical_artifact_bytes, payload);
                assert_eq!(canonical_precommit_certificate, expected_certificate);
            }
            Ok(_) => panic!("one same-root proposal quorum must have one stable representative"),
            Err(_) => panic!("fully admitted proposal-finality inputs must classify"),
        }
        assert_eq!(inbox.len(), 3);
        assert_eq!(inbox.total_canonical_input_bytes(), total_bytes);
        let (mut proposals, precommits) =
            drained_current_finality_contents(inbox.drain_and_reset());
        proposals.sort_unstable();
        let mut expected_proposals = vec![
            (first.to_vec(), payload.clone()),
            (second.to_vec(), payload.clone()),
        ];
        expected_proposals.sort_unstable();
        assert_eq!(proposals, expected_proposals);
        assert_eq!(precommits, vec![precommit.clone()]);
    }
}

#[test]
fn current_nil_precommit_priority_follows_finality_then_higher_evidence() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current = round_at(&branch, 0);
    let current_root = current_value.proposal_signing_root();
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_root),
        &fixture.signing_key(),
    );
    let current_precommit = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Proposal(current_root),
        &fixture.signing_key(),
    );
    let current_nil_precommit = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let (higher_value, higher_control, higher_payload) =
        proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Union);
    let higher = round_at(&branch, 2);
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root()),
        &fixture.signing_key(),
    );

    let finality_layout = TestLayout::new("driver-current-nil-precommit-finality-first");
    let ready = fixture
        .provision(&finality_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let (driver, _) = admit(driver, current_nil_precommit_event(&current_nil_precommit));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_finality_precommit_event(&current_precommit));
            let (driver, _) = admit_due(driver, timeout);
            let custody = (
                driver.inbox_len(),
                driver.current_inbox_len(),
                driver.current_finality_inbox_len(),
                driver.current_nil_precommit_inbox_len(),
            );

            let (driver, selection) = step_finality(driver);
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position == current.position()
            ));
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
            assert_eq!(
                (
                    driver.inbox_len(),
                    driver.current_inbox_len(),
                    driver.current_finality_inbox_len(),
                    driver.current_nil_precommit_inbox_len(),
                ),
                custody
            );
        })
        .unwrap();

    let higher_layout = TestLayout::new("driver-current-nil-precommit-higher-first");
    let ready = fixture
        .provision(&higher_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_prevote_event(&current_prevote));
            let (driver, _) = admit(
                driver,
                current_finality_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_nil_precommit_event(&current_nil_precommit));
            let (driver, _) = admit(driver, proposal_event(2, &higher_control, &higher_payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let (driver, _) = admit_due(driver, timeout);
            let custody = (
                driver.inbox_len(),
                driver.current_inbox_len(),
                driver.current_finality_inbox_len(),
                driver.current_nil_precommit_inbox_len(),
            );

            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher.position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(
                (
                    driver.inbox_len(),
                    driver.current_inbox_len(),
                    driver.current_finality_inbox_len(),
                    driver.current_nil_precommit_inbox_len(),
                ),
                (custody.0 - 1, custody.1, custody.2, custody.3)
            );
            let (_driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.position(), higher.position());
            let released_proposal =
                released_proposal.expect("higher action transfers its selected proposal");
            assert_eq!(
                released_proposal.canonical_proposal_control_bytes(),
                higher_control
            );
            assert_eq!(released_proposal.canonical_artifact_bytes(), higher_payload);
        })
        .unwrap();

    let current_layout = TestLayout::new("driver-current-nil-precommit-before-current-action");
    let ready = fixture
        .provision(&current_layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = current_layout.images();
    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(
                driver,
                current_proposal_event(&current_control, &current_payload),
            );
            let (driver, _) = admit(driver, current_nil_precommit_event(&current_nil_precommit));
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);

            let driver = step_transition(driver);
            assert_eq!(driver.position().height(), current.position().height());
            assert_eq!(driver.position().round(), ConsensusRound::new(1));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(current_layout.images(), before);

            let (driver, successor) = step_arm(driver);
            assert_eq!(successor.position(), driver.position());
            assert_eq!(successor.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(current_layout.images(), before);
        })
        .unwrap();
}
