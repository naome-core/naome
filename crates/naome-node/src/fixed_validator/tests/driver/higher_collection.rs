use super::higher_round::quorum;
use super::*;

fn event(bytes: &[u8]) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundVote {
        canonical_signed_vote: bytes.to_vec().into_boxed_slice(),
    }
}

#[test]
fn collected_higher_quorums_checkpoint_all_roles_targets_phases_and_restart_without_signing() {
    let fixture = Fixture::new();
    for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
        for target in [
            ConsensusVoteTarget::Nil,
            ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes([0x71; 32])),
        ] {
            let (certificate, vote) = quorum(&fixture, 2, role, target);
            for phase in 0..3 {
                for due in [false, true] {
                    let mut expected_images = None;
                    for collected in [false, true] {
                        let layout = TestLayout::new("higher-collection-parity");
                        let ready = fixture
                            .provision(&layout, 8)
                            .create(fixture.signing_key())
                            .unwrap();
                        ready.run_with_signing_session(|scope| {
                            let (mut driver, mut ticket) = step_arm(driver(scope, 8, 4));
                            for _ in 0..phase {
                                (driver, _) = admit_due(driver, ticket);
                                driver = step_transition(driver);
                                let (next, _, _) = step_publish(driver);
                                (driver, ticket) = step_arm(next);
                            }
                            if due { (driver, _) = admit_due(driver, ticket); }
                            let before = layout.images();
                            driver = if collected {
                                let (next, _) = admit(driver, event(&vote));
                                let (next, disposition) = admit(next, event(&vote));
                                assert_eq!(disposition, FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained);
                                assert_eq!(next.inbox_len(), 1);
                                assert_eq!(layout.images(), before);
                                step_transition(next)
                            } else {
                                match driver.advance_to_higher_round_quorum(&certificate).unwrap() {
                                    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::Advanced { driver } => *driver,
                                    _ => panic!("explicit control must advance"),
                                }
                            };
                            assert_eq!(driver.position().round(), ConsensusRound::new(2));
                            assert_eq!(driver.phase(), if role == ConsensusVoteRole::Prevote { FixedValidatorLockPhaseV0::Prevote } else { FixedValidatorLockPhaseV0::Precommit });
                            assert!(!driver.timeout_is_due());
                            assert_eq!(layout.images()[0..2], before[0..2]);
                            let (driver, replacement) = step_arm(driver);
                            assert_eq!(replacement.generation(), ticket.generation() + 1);
                            // Compare exactly the checkpoint boundary. The next
                            // step may now reuse the collected raw quorum.
                            drop(driver);
                        }).unwrap();
                        let images = layout.images();
                        if collected {
                            assert_eq!(Some(&images), expected_images.as_ref());
                        } else {
                            expected_images = Some(images.clone());
                        }
                        let ready = expect_ready(
                            fixture
                                .provision(&layout, 8)
                                .open(fixture.signing_key())
                                .unwrap(),
                        );
                        let position = round_at(&fixed_branch(&fixture), 2).position();
                        for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
                            assert!(
                                ready
                                    .vote
                                    .retained_signed_vote(position, role)
                                    .unwrap()
                                    .is_none()
                            );
                        }
                        ready
                            .run_with_signing_session(|mut scope| {
                                assert_eq!(scope.signing_session().position(), position);
                                let (driver, _) = step_arm(driver(scope, 8, 4));
                                assert_eq!(driver.inbox_len(), 0);
                                drop(step_idle(driver));
                            })
                            .unwrap();
                        assert_eq!(layout.images(), images);
                    }
                }
            }
        }
    }
}

#[test]
fn complete_higher_snapshot_blocks_competing_round_role_and_target_quorums_until_lossless_drain() {
    let fixture = Fixture::new();
    let root = ProposalSigningRoot::from_bytes([0x72; 32]);
    let (_, first) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Nil,
    );
    for (round, role, target) in [
        (3, ConsensusVoteRole::Prevote, ConsensusVoteTarget::Nil),
        (2, ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil),
        (
            2,
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        ),
    ] {
        let (_, second) = quorum(&fixture, round, role, target);
        for reversed in [false, true] {
            let layout = TestLayout::new("higher-collection-ambiguity");
            let ready = fixture
                .provision(&layout, 8)
                .create(fixture.signing_key())
                .unwrap();
            ready
                .run_with_signing_session(|scope| {
                    let (mut driver, ticket) = step_arm(driver(scope, 8, 4));
                    let before = layout.images();
                    for bytes in if reversed {
                        [&second, &first]
                    } else {
                        [&first, &second]
                    } {
                        (driver, _) = admit(driver, event(bytes));
                    }
                    (driver, _) = admit_due(driver, ticket);
                    let driver = match driver.step().unwrap() {
                        FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                            driver,
                            reason:
                                FixedValidatorNodeDriverBlockReasonV0::HigherQuorumsAmbiguous {
                                    first,
                                    second,
                                },
                        } => {
                            assert_ne!(first, second);
                            *driver
                        }
                        _ => panic!("complete buffer must not choose a quorum"),
                    };
                    assert_eq!(driver.position(), ticket.position());
                    assert!(driver.timeout_is_due());
                    assert_eq!(layout.images(), before);
                    let (driver, drained) = driver.drain_inbox_and_reset().into_parts();
                    let mut actual = drained
                        .map(|item| match item {
                            FixedValidatorNodeHigherRoundInboxDrainItemV0::ProposalPrevote(
                                bytes,
                            )
                            | FixedValidatorNodeHigherRoundInboxDrainItemV0::QuorumVote(bytes) => {
                                bytes.to_vec()
                            }
                            _ => panic!("no proposal was inserted"),
                        })
                        .collect::<Vec<_>>();
                    actual.sort();
                    let mut expected = vec![first.clone(), second.clone()];
                    expected.sort();
                    assert_eq!(actual, expected);
                    let (driver, _) = admit(*driver, event(&first));
                    let driver = step_transition(driver);
                    assert_eq!(driver.position().round(), ConsensusRound::new(2));
                })
                .unwrap();
        }
    }
}

#[test]
fn higher_collection_rejects_invalid_and_unbounded_votes_without_custody_or_authority_growth() {
    let fixture = Fixture::new();
    let (_, valid) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    let (_, stale) = quorum(
        &fixture,
        0,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    let (_, beyond) = quorum(
        &fixture,
        5,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    let mut corrupt = valid.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let inactive = signed_vote_bytes(
        fixture.context,
        round_at(&fixed_branch(&fixture), 2).position(),
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &SigningKey::from_bytes(&signing_seed(9)),
    );
    let layout = TestLayout::new("higher-collection-rejection");
    fixture.provision(&layout, 8).create(fixture.signing_key()).unwrap().run_with_signing_session(|scope| {
        let (mut driver, ticket) = step_arm(driver(scope, 8, 4));
        let before = layout.images();
        for bytes in [&[][..], &valid[..valid.len()-1], &stale, &beyond, &corrupt, &inactive] {
            driver = match driver.admit_event(event(bytes)).unwrap() {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { driver, event, rejection } => {
                    assert!(matches!(*rejection, FixedValidatorNodeDriverAdmissionRejectionV0::HigherVote(_)));
                    assert!(matches!(*event, FixedValidatorNodeDriverEventV0::HigherRoundVote { canonical_signed_vote } if canonical_signed_vote.as_ref() == bytes));
                    *driver
                }
                _ => panic!("invalid vote admitted"),
            };
            assert_eq!(driver.inbox_len(), 0);
            assert_eq!(driver.position(), ticket.position());
            assert_eq!(layout.images(), before);
        }
        let (driver, _) = admit(driver, event(&valid));
        drop(step_transition(driver));
    }).unwrap();
}

#[test]
fn higher_collection_uses_immutable_weight_and_counts_signature_variants_only_once() {
    let fixture = Fixture::new();
    for (weights, prefix) in [([2_u128, 1, 1, 2], 3), ([3, 2, 1, 1], 1)] {
        let mut keys = (0..4)
            .map(|i| SigningKey::from_bytes(&signing_seed(151 + i)))
            .collect::<Vec<_>>();
        keys.sort_by_key(consensus_key);
        let entries = keys
            .iter()
            .zip(weights)
            .map(|(key, weight)| {
                ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(weight))
            })
            .collect::<Vec<_>>();
        for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
            for target in [
                ConsensusVoteTarget::Nil,
                ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes([0x73; 32])),
            ] {
                let layout = TestLayout::new("higher-collection-weight");
                provision_with_fixed_entries(&fixture, &layout, &entries)
                    .create(keys[0].clone())
                    .unwrap()
                    .run_with_signing_session(|scope| {
                        let position = round_at(scope.branch(), 2).position();
                        let votes = keys
                            .iter()
                            .map(|key| {
                                signed_vote_bytes(fixture.context, position, role, target, key)
                            })
                            .collect::<Vec<_>>();
                        let alternate = signed_vote_bytes_with_test_only_nonce_prefix(
                            fixture.context,
                            position,
                            role,
                            target,
                            &keys[0],
                            17,
                        );
                        assert_ne!(alternate, votes[0]);
                        let (mut driver, ticket) = step_arm(driver(scope, 12, 4));
                        let before = layout.images();
                        for bytes in votes.iter().take(prefix).chain(std::iter::once(&alternate)) {
                            (driver, _) = admit(driver, event(bytes));
                            driver = step_idle(driver);
                            assert_eq!(driver.position(), ticket.position());
                            assert_eq!(layout.images(), before);
                        }
                        assert_eq!(driver.inbox_len(), prefix + 1);
                        let prefix_weight: u128 = weights[..prefix].iter().sum();
                        let total: u128 = weights.iter().sum();
                        assert!(3 * prefix_weight <= 2 * total);
                        assert!(3 * (prefix_weight + weights[prefix]) > 2 * total);
                        (driver, _) = admit(driver, event(&votes[prefix]));
                        let driver = step_transition(driver);
                        assert_eq!(driver.position(), position);
                        assert_eq!(driver.inbox_len(), prefix + 2);
                        assert_eq!(layout.images()[0..2], before[0..2]);
                    })
                    .unwrap();
            }
        }
    }
}

#[test]
fn higher_collection_shares_proposal_capacity_and_saturation_denies_even_a_retained_quorum() {
    let fixture = Fixture::new();
    let branch = fixed_branch(&fixture);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let (_, first) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    let (_, second) = quorum(
        &fixture,
        3,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    for bytes_limited in [false, true] {
        let layout = TestLayout::new("higher-collection-shared-capacity");
        fixture.provision(&layout, 8).create(fixture.signing_key()).unwrap().run_with_signing_session(|scope| {
            let max_bytes = if bytes_limited { (control.len() + payload.len() + first.len()) as u64 } else { 1 << 20 };
            let (driver, ticket) = step_arm(driver_with_limits(scope, if bytes_limited { 8 } else { 2 }, max_bytes, 8, 1 << 20, 4));
            let before = layout.images();
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, event(&first));
            let driver = match driver.admit_event(event(&second)).unwrap() {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { driver, rejection, .. } => {
                    assert!(matches!(*rejection, FixedValidatorNodeDriverAdmissionRejectionV0::HigherVote(source) if matches!(*source, FixedValidatorNodeDriverHigherVoteRejectionV0::Saturated { newly_saturated: true, .. })));
                    *driver
                }
                _ => panic!("shared capacity must reject"),
            };
            let driver = match driver.step().unwrap() {
                FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason: FixedValidatorNodeDriverBlockReasonV0::Saturated(_) } => *driver,
                _ => panic!("saturated prefix cannot advance"),
            };
            assert_eq!(driver.position(), ticket.position());
            assert_eq!(layout.images(), before);
            let (driver, mut drained) = driver.drain_inbox_and_reset().into_parts();
            assert_eq!(drained.len(), 2);
            assert!(matches!(drained.next(), Some(FixedValidatorNodeHigherRoundInboxDrainItemV0::Proposal(_))));
            assert!(matches!(drained.next(), Some(FixedValidatorNodeHigherRoundInboxDrainItemV0::QuorumVote(bytes)) if bytes.as_slice() == first));
            let (driver, _) = admit(*driver, event(&first));
            drop(step_transition(driver));
        }).unwrap();
    }
}

#[test]
fn collected_checkpoint_anchor_failure_returns_no_driver_and_reopen_fails_closed() {
    let fixture = Fixture::new();
    let (_, vote) = quorum(
        &fixture,
        2,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
    );
    let layout = TestLayout::new("higher-collection-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);
    ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, event(&vote));
            assert!(matches!(
                driver.step(),
                Err(FixedValidatorNodeDriverStepErrorV0::RoundAdvance(_))
            ));
        })
        .unwrap();
    fs::remove_file(collision).unwrap();
    let after = layout.images();
    assert_eq!(after[0..2], before[0..2]);
    assert_ne!(after[2], before[2]);
    assert_eq!(after[3], before[3]);
    assert!(
        matches!(fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source)) if matches!(source.as_ref(),
            FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner) if matches!(inner.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. })))
    );
}
