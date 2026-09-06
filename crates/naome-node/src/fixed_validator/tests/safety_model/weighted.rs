//! Representative real coordinator replay and exact weighted batch boundaries.

use std::collections::BTreeSet;

use naome_consensus::QuorumCertificateBuildError;

use super::*;

#[test]
fn weighted_witnesses_match_real_anchored_coordinators() {
    let mut selected = BTreeSet::new();
    let mut replayed = 0;
    for (profile, report) in profiles::representatives()
        .iter()
        .zip(profiles::explorations())
    {
        assert!(report.counterexample.is_none());
        for (&label, trace) in &report.witnesses {
            let finality = label == "certificate_a" || label == "certificate_b";
            // Both certificates for every class; additionally each critical
            // transition from an unequal-weight execution, once across classes.
            let critical = profile.weights != [1; 4] && selected.insert(label);
            if finality || critical {
                replay_witness(*profile, label, trace);
                replayed += 1;
            }
        }
    }
    for label in model::WITNESS_LABELS {
        assert!(selected.contains(label), "missing weighted replay: {label}");
    }
    for label in ["repeated_proposer_authors", "three_round_proposer_authors"] {
        assert!(selected.contains(label), "missing weighted replay: {label}");
    }
    assert_eq!(replayed, 50);
}

#[test]
fn weighted_batches_match_independent_full_width_arithmetic() {
    let mut single_quorum = false;
    let mut pair_quorum = false;
    let mut triple_rejected = false;
    let mut equality_rejected = false;
    let mut checked = 0;
    let all_profiles = profiles::representatives()
        .iter()
        .flat_map(|&profile| [profile, profile.scaled()])
        .chain([profiles::boundary_profile()]);
    for (index, profile) in all_profiles.enumerate() {
        assert_eq!(profiles::wide_quorums(profile.weights), profile.quorums);
        with_replay(
            profile,
            &format!("weight-boundary-{index}"),
            |replay, scopes| {
                let mut observations = Vec::new();
                let proposer = replay.model.proposers[0];
                if proposer != profile.faulty {
                    let slot = &mut scopes[usize::from(proposer)];
                    *slot = Some(replay.step(
                        slot.take().unwrap(),
                        Action::Author {
                            actor: proposer,
                            proposal: 1,
                        },
                    ));
                }
                // The same three anchored journals supply both roles. No honest
                // signature is fabricated or combined with another execution.
                for role in 0..=1 {
                    for actor in 0..4 {
                        if actor == profile.faulty {
                            continue;
                        }
                        let action = if role == 0 {
                            Action::Prevote { actor, proposal: 1 }
                        } else {
                            Action::Precommit { actor, target: 1 }
                        };
                        let slot = &mut scopes[usize::from(actor)];
                        *slot = Some(replay.step(slot.take().unwrap(), action));
                    }
                    let votes = std::array::from_fn::<_, 4, _>(|actor| {
                        if actor as u8 == profile.faulty {
                            replay.faulty_vote(0, role, 1)
                        } else {
                            replay.votes[&(actor as u8, 0, role)].clone()
                        }
                    });
                    for mask in 0_u16..16 {
                        let refs = votes
                            .iter()
                            .enumerate()
                            .filter(|&(actor, _)| mask & (1 << actor) != 0)
                            .map(|(_, bytes)| bytes.as_slice())
                            .collect::<Vec<_>>();
                        let expected = profile.quorums & (1 << mask) != 0;
                        let signed: u128 = profile
                            .weights
                            .iter()
                            .enumerate()
                            .filter(|&(actor, _)| mask & (1 << actor) != 0)
                            .map(|(_, &weight)| weight)
                            .sum();
                        let total: u128 = profile.weights.iter().sum();
                        let cursor = replay.cursor(0);
                        let certificate = cursor.build_quorum_certificate_from_signed_votes(
                            &refs,
                            Replay::role(role),
                            replay.target(1),
                        );
                        assert_eq!(
                            certificate.is_ok(),
                            expected,
                            "profile={profile:?} role={role} mask={mask:04b}"
                        );
                        if !expected {
                            match certificate.unwrap_err() {
                                QuorumCertificateBuildError::EmptyVoteBatch => assert_eq!(mask, 0),
                                QuorumCertificateBuildError::InsufficientAgreementWeight {
                                    signed: actual_signed,
                                    total: actual_total,
                                } => {
                                    assert_eq!(actual_signed, AgreementWeight::new(signed));
                                    assert_eq!(actual_total, AgreementWeight::new(total));
                                }
                                other => panic!("unexpected rejection: {other:?}"),
                            }
                        }
                        if role == 1 {
                            let bytes = replay.proposal(0, 1);
                            let admitted = cursor
                                .decode_and_verify_proposal_control(
                                    &bytes,
                                    replay.payloads[0].clone(),
                                )
                                .unwrap();
                            assert_eq!(
                                admitted.seal_with_precommit_vote_batch(&refs).is_ok(),
                                expected,
                                "finality seal: profile={profile:?} mask={mask:04b}"
                            );
                        }
                        if role == 1 && expected {
                            observations.extend(replay.finalize_batch(0, 1, &refs, scopes));
                            assert!(
                                observations.iter().all(|seen| seen == &observations[0]),
                                "weighted subset finalizations disagree: {profile:?}"
                            );
                        }
                        single_quorum |= expected && mask.count_ones() == 1;
                        pair_quorum |= expected && mask.count_ones() == 2;
                        triple_rejected |= !expected && mask.count_ones() == 3;
                        equality_rejected |= !expected
                            && profiles::multiple(signed, 3) == profiles::multiple(total, 2);
                        checked += 1;
                    }
                }
                assert_eq!(
                    observations.len(),
                    3 * profile.quorums.count_ones() as usize
                );
            },
        );
    }
    assert_eq!(checked, 39 * 2 * 16);
    assert!(single_quorum && pair_quorum && triple_rejected && equality_rejected);
}
