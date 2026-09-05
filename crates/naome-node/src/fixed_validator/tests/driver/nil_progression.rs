use super::*;

#[test]
fn current_nil_precommit_admission_is_exact_typed_and_duplicate_no_growth() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-admission");
    let branch = fixed_branch(&fixture);
    let position = round_at(&branch, 0).position();
    let root = ProposalSigningRoot::from_bytes([0x71; 32]);
    let valid = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let proposal_precommit = signed_vote_bytes(
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
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let inactive = SigningKey::from_bytes(&signing_seed(2));
    let inactive_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
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
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let mut invalid_signature = valid.clone();
    *invalid_signature.last_mut().unwrap() ^= 0x01;
    let malformed = valid[..valid.len() - 1].to_vec();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let driver = reject_current_nil_precommit(driver, &malformed, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                        naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::Vote(
                            naome_consensus::ConsensusVoteVerifyError::Decode(_)
                        )
                    )
                ));
            });
            let driver = reject_current_nil_precommit(
                driver,
                &wrong_context_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::GenesisIdMismatch { .. }
                            )
                        )
                    ));
                },
            );
            let driver =
                reject_current_nil_precommit(driver, &invalid_signature, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::Vote(
                                naome_consensus::ConsensusVoteVerifyError::InvalidSignature { .. }
                            )
                        )
                    ));
                });
            let driver = reject_current_nil_precommit(
                driver,
                &wrong_position_precommit,
                |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::PositionMismatch {
                                expected,
                                actual,
                            }
                        ) if *expected == position && *actual == wrong_position
                    ));
                },
            );
            let driver = reject_current_nil_precommit(driver, &prevote, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                        naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::RoleMismatch {
                            actual: ConsensusVoteRole::Prevote,
                        }
                    )
                ));
            });
            let driver =
                reject_current_nil_precommit(driver, &proposal_precommit, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::ProposalTarget {
                                actual,
                            }
                        ) if *actual == root
                    ));
                });
            let driver =
                reject_current_nil_precommit(driver, &inactive_precommit, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(
                            naome_consensus::FixedConsensusNilPrecommitVerifyErrorV0::InactiveSigner {
                                signer,
                            }
                        ) if *signer == consensus_key(&inactive)
                    ));
                });
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            assert_eq!(driver.current_nil_precommit_inbox_canonical_input_bytes(), 0);

            let (driver, disposition) = admit(driver, current_nil_precommit_event(&valid));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let retained_bytes = u64::try_from(valid.len()).unwrap();
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
                retained_bytes
            );
            let (driver, disposition) = admit(driver, current_nil_precommit_event(&valid));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained
            );
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
                retained_bytes
            );
            assert_eq!(driver.inbox_len(), 0);
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_quorum_is_strict_and_selects_smallest_signer_variants() {
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
    let standard = signing_keys
        .iter()
        .map(|key| {
            signed_vote_bytes(
                fixture.context,
                round.position(),
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                key,
            )
        })
        .collect::<Vec<_>>();
    let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        round.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &signing_keys[0],
        0x41,
    );
    assert_ne!(standard[0], alternate);

    let limits = FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(
        4,
        u64::try_from(standard.iter().map(Vec::len).sum::<usize>() + alternate.len()).unwrap(),
    )
    .unwrap();
    let mut exact_two_thirds = CurrentRoundNilPrecommitInboxV0::new(limits);
    for vote in &standard[..2] {
        assert!(matches!(
            exact_two_thirds.try_insert_nil_precommit(&round, vote),
            Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
        ));
    }
    assert!(matches!(
        exact_two_thirds.select_nil_quorum(&round),
        Ok(CurrentRoundNilPrecommitQuorumSelectionV0::None)
    ));
    assert!(matches!(
        exact_two_thirds.try_insert_nil_precommit(&round, &standard[2]),
        Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
    ));
    assert!(matches!(
        exact_two_thirds.select_nil_quorum(&round),
        Ok(CurrentRoundNilPrecommitQuorumSelectionV0::One { .. })
    ));

    let preferred_first = standard[0].as_slice().min(alternate.as_slice()).to_vec();
    let mut expected = vec![
        (consensus_key(&signing_keys[0]), preferred_first),
        (consensus_key(&signing_keys[1]), standard[1].clone()),
        (consensus_key(&signing_keys[2]), standard[2].clone()),
    ];
    expected.sort_unstable_by_key(|entry| entry.0);
    let expected = expected
        .into_iter()
        .map(|(_, vote)| vote)
        .collect::<Vec<_>>();
    let all_votes = [&standard[0], &alternate, &standard[1], &standard[2]];
    let mut expected_retained = all_votes
        .iter()
        .map(|vote| vote.as_slice().to_vec())
        .collect::<Vec<_>>();
    expected_retained.sort_unstable();
    for order in [
        [0, 1, 2, 3],
        [1, 0, 3, 2],
        [2, 3, 0, 1],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [1, 3, 0, 2],
    ] {
        let mut inbox = CurrentRoundNilPrecommitInboxV0::new(limits);
        for index in order {
            assert!(matches!(
                inbox.try_insert_nil_precommit(&round, all_votes[index]),
                Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
            ));
        }
        match inbox.select_nil_quorum(&round) {
            Ok(CurrentRoundNilPrecommitQuorumSelectionV0::One {
                canonical_signed_precommits,
            }) => assert_eq!(
                canonical_signed_precommits
                    .into_iter()
                    .map(Vec::from)
                    .collect::<Vec<_>>(),
                expected
            ),
            Ok(CurrentRoundNilPrecommitQuorumSelectionV0::None) => {
                panic!("three active signers must exceed the exact two-thirds threshold")
            }
            Err(_) => panic!("fully admitted nil precommits must classify"),
        }
        assert_eq!(inbox.len(), all_votes.len());
        assert_eq!(
            drained_current_nil_precommit_contents(inbox.drain_and_reset()),
            expected_retained
        );
    }
}

#[test]
fn current_nil_precommit_advances_from_every_phase_and_due_state_without_writes() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let position = round_at(&branch, 0).position();
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let retained_bytes = u64::try_from(nil_precommit.len()).unwrap();

    for (label, expected_phase, mark_due) in [
        (
            "driver-current-nil-precommit-proposal-live",
            FixedValidatorLockPhaseV0::Proposal,
            false,
        ),
        (
            "driver-current-nil-precommit-proposal-due",
            FixedValidatorLockPhaseV0::Proposal,
            true,
        ),
        (
            "driver-current-nil-precommit-prevote-live",
            FixedValidatorLockPhaseV0::Prevote,
            false,
        ),
        (
            "driver-current-nil-precommit-prevote-due",
            FixedValidatorLockPhaseV0::Prevote,
            true,
        ),
        (
            "driver-current-nil-precommit-precommit-live",
            FixedValidatorLockPhaseV0::Precommit,
            false,
        ),
        (
            "driver-current-nil-precommit-precommit-due",
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
                        assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
                        assert!(released_proposal.is_none());
                        step_arm(driver)
                    }
                    FixedValidatorLockPhaseV0::Precommit => {
                        let (driver, _) = admit_due(driver, proposal_timeout);
                        let driver = step_transition(driver);
                        let (driver, vote, released_proposal) = step_publish(driver);
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
                assert_eq!(driver.position(), position);
                assert_eq!(driver.phase(), expected_phase);
                assert_eq!(driver.timeout_is_due(), mark_due);
                let (driver, disposition) =
                    admit(driver, current_nil_precommit_event(&nil_precommit));
                assert_eq!(
                    disposition,
                    FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
                );
                assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                assert_eq!(
                    driver.current_nil_precommit_inbox_canonical_input_bytes(),
                    retained_bytes
                );
                let before_advance = layout.images();

                let driver = step_transition(driver);
                assert_eq!(driver.position().height(), position.height());
                assert_eq!(driver.position().round(), ConsensusRound::new(1));
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                assert!(!driver.timeout_is_due());
                assert!(driver.has_pending_command());
                assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                assert_eq!(layout.images(), before_advance);

                let (driver, successor_timeout) = step_arm(driver);
                assert_eq!(successor_timeout.position(), driver.position());
                assert_eq!(
                    successor_timeout.phase(),
                    FixedValidatorLockPhaseV0::Proposal
                );
                assert_eq!(
                    successor_timeout.generation(),
                    active_timeout.generation().checked_add(1).unwrap()
                );
                assert_eq!(layout.images(), before_advance);
            })
            .unwrap();
    }
}

#[test]
fn current_nil_precommit_round_advance_preserves_populated_lock_and_valid_evidence() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-lock-valid");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let round_two = round_at(&branch, 2);
    let proposal_prevote = signed_vote_bytes(
        fixture.context,
        round_two.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round_two
        .build_quorum_certificate_from_signed_votes(
            &[proposal_prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        round_two.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&proposal_prevote));
            let driver = step_transition(driver);
            assert_eq!(driver.position(), round_two.position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            assert!(released_proposal.is_some());
            let (driver, _) = step_arm(driver);
            let before_nil_advance = layout.images();
            let (driver, _) = admit(driver, current_nil_precommit_event(&nil_precommit));

            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(3));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), before_nil_advance);
            let (driver, proposal_timeout) = step_arm(driver);
            assert_eq!(layout.images(), before_nil_advance);

            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert_eq!(prevote.position(), driver.position());
            assert_eq!(prevote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            assert!(released_proposal.is_none());
            drop(driver);
        })
        .unwrap();

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            let signing = scope.signing_session();
            assert_eq!(signing.position().round(), ConsensusRound::new(3));
            assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Prevote);
            let locked = signing
                .locked_value()
                .expect("nil-precommit round advance must preserve the existing lock");
            assert_eq!(locked.round(), ConsensusRound::new(2));
            assert_eq!(locked.proposal_signing_root(), root);
            let valid = signing
                .valid_value()
                .expect("nil-precommit round advance must preserve valid evidence");
            assert_eq!(valid.round(), ConsensusRound::new(2));
            assert_eq!(valid.value().proposal_signing_root(), root);
            assert_eq!(
                valid.canonical_prevote_certificate(),
                expected_certificate.as_slice()
            );
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_saturation_is_independent_and_retained_quorum_still_advances() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let current = round_at(&branch, 0);
    let higher = round_at(&branch, 1);
    let root = ProposalSigningRoot::from_bytes([0x72; 32]);
    let (_, finality_control, finality_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let retained = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let denied = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
        0x42,
    );
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        higher.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let vote_bytes = u64::try_from(retained.len()).unwrap();

    for (label, maximum_entries, maximum_bytes) in [
        (
            "driver-current-nil-precommit-count-saturation",
            1,
            vote_bytes.checked_mul(2).unwrap(),
        ),
        (
            "driver-current-nil-precommit-byte-saturation",
            2,
            vote_bytes,
        ),
    ] {
        let layout = TestLayout::new(label);
        let ready = fixture
            .provision(&layout, 8)
            .create(fixture.signing_key())
            .unwrap();
        ready
            .run_with_signing_session(|scope| {
                let (driver, _) = step_arm(driver_with_nil_precommit_limits(
                    scope,
                    maximum_entries,
                    maximum_bytes,
                    4,
                ));
                let (driver, _) = admit(driver, current_nil_prevote_event(&current_prevote));
                let (driver, _) = admit(
                    driver,
                    current_finality_proposal_event(&finality_control, &finality_payload),
                );
                let (driver, _) = admit(driver, prevote_event(&higher_prevote));
                let (driver, _) = admit(driver, current_nil_precommit_event(&retained));
                let before_other_counts = (
                    driver.inbox_len(),
                    driver.current_inbox_len(),
                    driver.current_finality_inbox_len(),
                );
                let before_images = layout.images();
                let driver = reject_current_nil_precommit(driver, &denied, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                            position,
                            saturation:
                                FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0::Capacity {
                                    attempted_entries: 2,
                                    maximum_entries: actual_maximum_entries,
                                    attempted_canonical_input_bytes,
                                    maximum_canonical_input_bytes,
                                },
                            newly_saturated: true,
                        } if *position == current.position()
                            && *actual_maximum_entries == maximum_entries
                            && *attempted_canonical_input_bytes
                                == vote_bytes.checked_mul(2).unwrap()
                            && *maximum_canonical_input_bytes == maximum_bytes
                    ));
                });
                assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                assert_eq!(
                    driver.current_nil_precommit_inbox_canonical_input_bytes(),
                    vote_bytes
                );
                assert_eq!(
                    (
                        driver.inbox_len(),
                        driver.current_inbox_len(),
                        driver.current_finality_inbox_len(),
                    ),
                    before_other_counts
                );
                assert_eq!(layout.images(), before_images);

                let driver = reject_current_nil_precommit(driver, &denied, |rejection| {
                    assert!(matches!(
                        rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                            position,
                            newly_saturated: false,
                            ..
                        } if *position == current.position()
                    ));
                });
                let driver = step_transition(driver);
                assert_eq!(driver.position(), higher.position());
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
                assert_eq!(
                    (
                        driver.inbox_len(),
                        driver.current_inbox_len(),
                        driver.current_finality_inbox_len(),
                    ),
                    before_other_counts
                );
                assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                assert_eq!(layout.images(), before_images);

                let (driver, drained) = driver
                    .drain_current_nil_precommit_inbox_and_reset()
                    .into_parts();
                assert_eq!(
                    drained_current_nil_precommit_contents(drained),
                    vec![retained.clone()]
                );
                assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
                assert_eq!(
                    driver.current_nil_precommit_inbox_canonical_input_bytes(),
                    0
                );
                assert_eq!(
                    (
                        driver.inbox_len(),
                        driver.current_inbox_len(),
                        driver.current_finality_inbox_len(),
                    ),
                    before_other_counts
                );
                assert_eq!(layout.images(), before_images);
            })
            .unwrap();
    }
}

#[test]
fn saturated_nonquorate_nil_precommit_prefix_falls_through_to_idle_and_due() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-nonquorum-saturation");
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
    let position = branch.begin_round_zero().unwrap().position();
    let first = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &signing_keys[0],
    );
    let second = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &signing_keys[1],
    );
    let ready = provision_with_fixed_entries(&fixture, &layout, &entries)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|scope| {
            let (driver, proposal_timeout) = step_arm(driver_with_nil_precommit_limits(
                scope,
                1,
                u64::try_from(first.len() + second.len()).unwrap(),
                4,
            ));
            let (driver, _) = admit(driver, current_nil_precommit_event(&first));
            let driver = reject_current_nil_precommit(driver, &second, |rejection| {
                assert!(matches!(
                    rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                        newly_saturated: true,
                        ..
                    }
                ));
            });
            let driver = step_idle(driver);
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(layout.images(), before);

            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_precedes_competing_current_votes_and_due_without_custody_loss() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-before-current-and-due");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current = round_at(&branch, 0);
    let root = value.proposal_signing_root();
    let proposal_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let nil_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let higher_prevote = signed_vote_bytes(
        fixture.context,
        round_at(&branch, 2).position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_prevote_event(&proposal_prevote));
            let (driver, _) = admit(driver, current_nil_prevote_event(&nil_prevote));
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            let (driver, local_prevote, released_proposal) = step_publish(driver);
            assert_eq!(local_prevote.target(), ConsensusVoteTarget::Proposal(root));
            assert!(released_proposal.is_none());
            let (driver, timeout) = step_arm(driver);
            let (driver, _) = admit(driver, current_finality_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, prevote_event(&higher_prevote));
            let (driver, _) = admit_due(driver, timeout);
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(driver.current_inbox_len(), 3);
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            let before_block = layout.images();
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                            position,
                            proposal_signing_root,
                        } if position == current.position() && proposal_signing_root == root
                    ));
                    *driver
                }
                _ => panic!("competing exact-current proposal and nil quorums must block"),
            };
            assert!(driver.timeout_is_due());
            assert_eq!(layout.images(), before_block);

            let (driver, _) = admit(driver, current_nil_precommit_event(&nil_precommit));
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            let before = layout.images();

            let driver = step_transition(driver);
            assert_eq!(driver.position().height(), current.position().height());
            assert_eq!(driver.position().round(), ConsensusRound::new(1));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(!driver.timeout_is_due());
            assert_eq!(driver.inbox_len(), 1);
            assert_eq!(driver.current_inbox_len(), 3);
            assert_eq!(driver.current_finality_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(layout.images(), before);
            let (driver, successor) = step_arm(driver);
            assert_eq!(successor.position(), driver.position());
            assert_eq!(successor.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(layout.images(), before);
            match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason } => {
                    assert!(matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                            position,
                            proposal_signing_root,
                        } if position == current.position() && proposal_signing_root == root
                    ));
                    assert_eq!(driver.position().round(), ConsensusRound::new(1));
                    assert_eq!(driver.current_inbox_len(), 3);
                    assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
                }
                _ => panic!("the old-position current ambiguity latch must remain until drain"),
            }
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_bypasses_current_inbox_saturation_without_custody_loss() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-current-saturation-escape");
    let branch = fixed_branch(&fixture);
    let position = round_at(&branch, 0).position();
    let retained_prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let denied_prevote = signed_vote_bytes_with_test_only_nonce_prefix(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
        0x43,
    );
    let nil_precommit = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let driver = driver_with_all_limits(
                scope,
                8,
                1024 * 1024,
                1,
                1024 * 1024,
                8,
                1024 * 1024,
                8,
                1024 * 1024,
                4,
            );
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, current_nil_prevote_event(&retained_prevote));
            let driver = reject_current_nil_prevote(driver, &denied_prevote, |rejection| {
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
            let (driver, disposition) = admit(driver, current_nil_precommit_event(&nil_precommit));
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted
            );
            let before = layout.images();

            let driver = step_transition(driver);
            assert_eq!(driver.position().round(), ConsensusRound::new(1));
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Proposal);
            assert_eq!(driver.current_inbox_len(), 1);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}

#[test]
fn current_nil_precommit_preclassification_routes_only_the_exact_retained_position() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let current = round_at(&branch, 0);
    let next = round_at(&branch, 1);
    let vote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let limits =
        FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(1, 1024 * 1024).unwrap();
    let mut inbox = CurrentRoundNilPrecommitInboxV0::new(limits);
    assert_eq!(
        inbox.preclassify(current.parent_coordinate(), current.position()),
        super::super::current_round_nil_precommit_inbox::CurrentRoundNilPrecommitPreclassificationV0::NoMatchingPrecommit
    );
    assert!(matches!(
        inbox.try_insert_nil_precommit(&current, &vote),
        Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted)
    ));
    assert_eq!(
        inbox.preclassify(current.parent_coordinate(), current.position()),
        super::super::current_round_nil_precommit_inbox::CurrentRoundNilPrecommitPreclassificationV0::NeedsRound
    );
    assert_eq!(
        inbox.preclassify(next.parent_coordinate(), next.position()),
        super::super::current_round_nil_precommit_inbox::CurrentRoundNilPrecommitPreclassificationV0::NoMatchingPrecommit
    );
}

#[test]
fn stale_nil_precommit_custody_is_lossless_class_only_and_empty_after_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-nil-precommit-stale-drain-restart");
    let branch = fixed_branch(&fixture);
    let (current_value, current_control, current_payload) =
        proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let current = round_at(&branch, 0);
    let current_prevote = signed_vote_bytes(
        fixture.context,
        current.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(current_value.proposal_signing_root()),
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
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
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

            let driver = step_transition(driver);
            assert_eq!(driver.position(), higher.position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(driver.has_pending_command());
            assert_eq!(driver.current_nil_precommit_inbox_len(), 1);
            let other_custody = (
                driver.inbox_len(),
                driver.current_inbox_len(),
                driver.current_finality_inbox_len(),
            );
            let before_drain = layout.images();

            let (driver, drained) = driver
                .drain_current_nil_precommit_inbox_and_reset()
                .into_parts();
            assert_eq!(
                drained_current_nil_precommit_contents(drained),
                vec![current_nil_precommit.clone()]
            );
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            assert_eq!(
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
                0
            );
            assert_eq!(
                (
                    driver.inbox_len(),
                    driver.current_inbox_len(),
                    driver.current_finality_inbox_len(),
                ),
                other_custody
            );
            assert!(driver.has_pending_command());
            assert_eq!(layout.images(), before_drain);

            let (driver, precommit, released_proposal) = step_publish(*driver);
            assert_eq!(precommit.position(), higher.position());
            assert_eq!(
                precommit.target(),
                ConsensusVoteTarget::Proposal(higher_value.proposal_signing_root())
            );
            assert!(released_proposal.is_some());
            let (driver, _) = step_arm(driver);
            drop(driver);
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
            let driver = driver(scope, 8, 4);
            assert_eq!(driver.position(), higher.position());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.inbox_len(), 0);
            assert_eq!(driver.current_inbox_len(), 0);
            assert_eq!(driver.current_finality_inbox_len(), 0);
            assert_eq!(driver.current_nil_precommit_inbox_len(), 0);
            assert_eq!(
                driver.current_nil_precommit_inbox_canonical_input_bytes(),
                0
            );
        })
        .unwrap();
}
