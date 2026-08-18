use super::*;

const REFERENCE_NON_GENESIS_HEIGHTS_PER_EPOCH: u64 = 8_192;
const REFERENCE_TERMINAL_EPOCH: u64 = 2_251_799_813_685_247;
const COMPILE_TIME_PROJECTED_EPOCH_VALUE: Option<u64> =
    match ConsensusHeight::new(8_193).non_genesis_epoch() {
        Some(epoch) => Some(epoch.value()),
        None => None,
    };
const COMPILE_TIME_CHECKPOINT_FRESHNESS: Option<(bool, bool)> = match (
    ConsensusHeight::new(1).non_genesis_epoch(),
    ConsensusHeight::new(237_569).non_genesis_epoch(),
    ConsensusHeight::new(245_761).non_genesis_epoch(),
) {
    (Some(checkpoint), Some(age_29_minimum), Some(age_30_minimum)) => Some((
        checkpoint_epoch_is_within_numeric_freshness_window(checkpoint, age_29_minimum),
        checkpoint_epoch_is_within_numeric_freshness_window(checkpoint, age_30_minimum),
    )),
    _ => None,
};
const COMPILE_TIME_GENESIS_BOOTSTRAP_CAP: Option<u128> =
    match ConsensusHeight::new(1).non_genesis_epoch() {
        Some(epoch) => match project_linear_genesis_bootstrap_cap(epoch) {
            Some(cap) => Some(cap.units()),
            None => None,
        },
        None => None,
    };
const COMPILE_TIME_EXPIRED_GENESIS_BOOTSTRAP_CAP: Option<GenesisBootstrapWeightCap> =
    match ConsensusHeight::new(5_980_161).non_genesis_epoch() {
        Some(epoch) => project_linear_genesis_bootstrap_cap(epoch),
        None => None,
    };
const COMPILE_TIME_UPGRADE_ACTIVATION_DELAY: Option<(bool, bool)> = match (
    ConsensusHeight::new(57_345).non_genesis_epoch(),
    ConsensusHeight::new(172_033).non_genesis_epoch(),
    ConsensusHeight::new(180_225).non_genesis_epoch(),
) {
    (Some(readiness), Some(age_14), Some(age_15)) => Some((
        upgrade_activation_epoch_meets_numeric_minimum_delay(readiness, age_14),
        upgrade_activation_epoch_meets_numeric_minimum_delay(readiness, age_15),
    )),
    _ => None,
};

fn projected_epoch_value(height: u64) -> Option<u64> {
    ConsensusHeight::new(height)
        .non_genesis_epoch()
        .map(ConsensusEpoch::value)
}

fn projected_epoch(value: u64) -> ConsensusEpoch {
    let height = value * REFERENCE_NON_GENESIS_HEIGHTS_PER_EPOCH + 1;
    ConsensusHeight::new(height)
        .non_genesis_epoch()
        .expect("positive reference height projects to an epoch")
}

fn key(index: u16) -> ConsensusKey {
    let mut bytes = [0_u8; CONSENSUS_KEY_BYTES];
    bytes[..2].copy_from_slice(&index.to_be_bytes());
    ConsensusKey::from_bytes(bytes)
}

fn position(height: u64, round: u64) -> ConsensusPosition {
    ConsensusPosition::new(ConsensusHeight::new(height), ConsensusRound::new(round))
}

fn entry(index: u16, weight: u128) -> ActiveAgreementEntry {
    ActiveAgreementEntry::new(key(index), AgreementWeight::new(weight))
}

fn snapshot(weights: &[u128]) -> ActiveAgreementSnapshot {
    let entries = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| entry(index as u16, *weight))
        .collect::<Vec<_>>();
    ActiveAgreementSnapshot::try_from_preselected(position(7, 3), &entries).unwrap()
}

#[test]
fn coordinate_and_value_types_preserve_exact_values() {
    let height = ConsensusHeight::new(u64::MAX);
    let round = ConsensusRound::new(u64::MAX - 1);
    let position = ConsensusPosition::new(height, round);
    let consensus_key = ConsensusKey::from_bytes([0_u8; CONSENSUS_KEY_BYTES]);
    let weight = AgreementWeight::new(u128::MAX);

    assert_eq!(height.value(), u64::MAX);
    assert_eq!(round.value(), u64::MAX - 1);
    assert_eq!(position.height(), height);
    assert_eq!(position.round(), round);
    assert_eq!(consensus_key.as_bytes(), &[0_u8; CONSENSUS_KEY_BYTES]);
    assert_eq!(weight.units(), u128::MAX);
    assert!(AgreementWeight::ZERO.is_zero());
}

#[test]
fn non_genesis_epoch_width_and_const_projection_match_literal_contract() {
    assert_eq!(
        NON_GENESIS_HEIGHTS_PER_EPOCH,
        REFERENCE_NON_GENESIS_HEIGHTS_PER_EPOCH
    );
    assert_eq!(COMPILE_TIME_PROJECTED_EPOCH_VALUE, Some(1));
}

#[test]
fn non_genesis_epoch_projection_covers_origin_and_literal_boundaries() {
    for (height, expected_epoch) in [
        (0, None),
        (1, Some(0)),
        (8_192, Some(0)),
        (8_193, Some(1)),
        (16_384, Some(1)),
        (16_385, Some(2)),
    ] {
        assert_eq!(
            projected_epoch_value(height),
            expected_epoch,
            "height={height}"
        );
    }
}

#[test]
fn non_genesis_epoch_projection_matches_fixed_interval_oracle() {
    for expected_epoch in 0..=1_024_u64 {
        for offset in [0_u64, 4_095, 8_191] {
            let height = expected_epoch * REFERENCE_NON_GENESIS_HEIGHTS_PER_EPOCH + offset + 1;
            assert_eq!(
                projected_epoch_value(height),
                Some(expected_epoch),
                "height={height}, offset={offset}"
            );
        }
    }
}

#[test]
fn non_genesis_epoch_projection_covers_terminal_transition() {
    const TERMINAL_START: u64 =
        REFERENCE_TERMINAL_EPOCH * REFERENCE_NON_GENESIS_HEIGHTS_PER_EPOCH + 1;

    assert_eq!(TERMINAL_START, u64::MAX - 8_190);
    assert_eq!(
        projected_epoch_value(TERMINAL_START - 1),
        Some(REFERENCE_TERMINAL_EPOCH - 1)
    );
    assert_eq!(
        projected_epoch_value(TERMINAL_START),
        Some(REFERENCE_TERMINAL_EPOCH)
    );
    assert_eq!(
        projected_epoch_value(u64::MAX),
        Some(REFERENCE_TERMINAL_EPOCH)
    );
}

#[test]
fn checkpoint_freshness_is_const_and_matches_literal_boundaries() {
    assert_eq!(COMPILE_TIME_CHECKPOINT_FRESHNESS, Some((true, false)));
}

#[test]
fn checkpoint_freshness_covers_exact_age_boundaries_and_newer_values() {
    let operator_minimum = projected_epoch(40);

    for (checkpoint, expected) in [(9, false), (10, false), (11, true), (40, true), (41, true)] {
        assert_eq!(
            checkpoint_epoch_is_within_numeric_freshness_window(
                projected_epoch(checkpoint),
                operator_minimum
            ),
            expected,
            "checkpoint={checkpoint}"
        );
    }
}

#[test]
fn checkpoint_freshness_matches_independent_bounded_oracle() {
    const REFERENCE_FRESHNESS_WINDOW: u64 = 30;

    for operator_minimum in 0..=64_u64 {
        for checkpoint in 0..=64_u64 {
            let expected = checkpoint >= operator_minimum
                || operator_minimum - checkpoint < REFERENCE_FRESHNESS_WINDOW;
            assert_eq!(
                checkpoint_epoch_is_within_numeric_freshness_window(
                    projected_epoch(checkpoint),
                    projected_epoch(operator_minimum)
                ),
                expected,
                "checkpoint={checkpoint}, operator_minimum={operator_minimum}"
            );
        }
    }
}

#[test]
fn checkpoint_freshness_is_safe_at_origin_and_terminal_epochs() {
    let terminal = ConsensusHeight::new(u64::MAX)
        .non_genesis_epoch()
        .expect("maximum positive height projects to the terminal epoch");

    assert!(checkpoint_epoch_is_within_numeric_freshness_window(
        projected_epoch(0),
        projected_epoch(0)
    ));
    assert_eq!(terminal.value(), REFERENCE_TERMINAL_EPOCH);
    assert!(checkpoint_epoch_is_within_numeric_freshness_window(
        projected_epoch(REFERENCE_TERMINAL_EPOCH - 29),
        terminal
    ));
    assert!(!checkpoint_epoch_is_within_numeric_freshness_window(
        projected_epoch(REFERENCE_TERMINAL_EPOCH - 30),
        terminal
    ));
    assert!(checkpoint_epoch_is_within_numeric_freshness_window(
        terminal,
        projected_epoch(0)
    ));
}

#[test]
fn linear_genesis_bootstrap_cap_is_const_and_matches_literal_boundaries() {
    assert_eq!(
        COMPILE_TIME_GENESIS_BOOTSTRAP_CAP,
        Some(10_000_000_000_000_000)
    );
    assert_eq!(COMPILE_TIME_EXPIRED_GENESIS_BOOTSTRAP_CAP, None);

    for (epoch, expected_units) in [
        (0, 10_000_000_000_000_000),
        (1, 9_986_301_369_863_013),
        (365, 5_000_000_000_000_000),
        (728, 27_397_260_273_972),
        (729, 13_698_630_136_986),
    ] {
        assert_eq!(
            project_linear_genesis_bootstrap_cap(projected_epoch(epoch))
                .map(GenesisBootstrapWeightCap::units),
            Some(expected_units),
            "epoch={epoch}"
        );
    }
}

#[test]
fn linear_genesis_bootstrap_cap_matches_independent_complete_domain_oracle() {
    const REFERENCE_INITIAL_UNITS: u128 = 10_000_000_000_000_000;
    const REFERENCE_EPOCHS: u128 = 730;
    const REFERENCE_QUOTIENT: u128 = REFERENCE_INITIAL_UNITS / REFERENCE_EPOCHS;
    const REFERENCE_REMAINDER: u128 = REFERENCE_INITIAL_UNITS % REFERENCE_EPOCHS;
    let mut previous = REFERENCE_INITIAL_UNITS;

    for epoch in 0..730_u64 {
        let remaining = REFERENCE_EPOCHS - epoch as u128;
        let expected =
            REFERENCE_QUOTIENT * remaining + REFERENCE_REMAINDER * remaining / REFERENCE_EPOCHS;
        let actual = project_linear_genesis_bootstrap_cap(projected_epoch(epoch))
            .expect("every pre-sunset epoch has a numeric cap")
            .units();

        assert_eq!(actual, expected, "epoch={epoch}");
        assert!(actual <= previous, "epoch={epoch}");
        previous = actual;
    }
}

#[test]
fn linear_genesis_bootstrap_cap_has_no_post_sunset_numeric_output() {
    let terminal = ConsensusHeight::new(u64::MAX)
        .non_genesis_epoch()
        .expect("maximum positive height projects to the terminal epoch");

    for epoch in [projected_epoch(730), projected_epoch(731), terminal] {
        assert_eq!(project_linear_genesis_bootstrap_cap(epoch), None);
    }
}

#[test]
fn upgrade_activation_delay_is_const_and_covers_literal_boundaries() {
    assert_eq!(COMPILE_TIME_UPGRADE_ACTIVATION_DELAY, Some((false, true)));
    let readiness = projected_epoch(40);

    for (candidate, expected) in [
        (39, false),
        (40, false),
        (54, false),
        (55, true),
        (56, true),
    ] {
        assert_eq!(
            upgrade_activation_epoch_meets_numeric_minimum_delay(
                readiness,
                projected_epoch(candidate)
            ),
            expected,
            "candidate={candidate}"
        );
    }
}

#[test]
fn upgrade_activation_delay_matches_independent_bounded_oracle() {
    const REFERENCE_MINIMUM_DELAY: u64 = 15;

    for readiness in 0..=64_u64 {
        for candidate in 0..=80_u64 {
            let expected = candidate
                .checked_sub(readiness)
                .is_some_and(|elapsed| elapsed >= REFERENCE_MINIMUM_DELAY);
            assert_eq!(
                upgrade_activation_epoch_meets_numeric_minimum_delay(
                    projected_epoch(readiness),
                    projected_epoch(candidate)
                ),
                expected,
                "readiness={readiness}, candidate={candidate}"
            );
        }
    }
}

#[test]
fn upgrade_activation_delay_is_safe_at_terminal_epoch() {
    let terminal = ConsensusHeight::new(u64::MAX)
        .non_genesis_epoch()
        .expect("maximum positive height projects to the terminal epoch");

    assert!(upgrade_activation_epoch_meets_numeric_minimum_delay(
        projected_epoch(REFERENCE_TERMINAL_EPOCH - 15),
        terminal
    ));
    assert!(!upgrade_activation_epoch_meets_numeric_minimum_delay(
        projected_epoch(REFERENCE_TERMINAL_EPOCH - 14),
        terminal
    ));
    assert!(!upgrade_activation_epoch_meets_numeric_minimum_delay(
        terminal, terminal
    ));
    assert!(!upgrade_activation_epoch_meets_numeric_minimum_delay(
        terminal,
        projected_epoch(0)
    ));
}

#[test]
fn snapshots_are_bound_to_their_exact_position() {
    let entries = [entry(1, 5)];
    let first = ActiveAgreementSnapshot::try_from_preselected(position(4, 1), &entries).unwrap();
    let second = ActiveAgreementSnapshot::try_from_preselected(position(4, 2), &entries).unwrap();

    assert_eq!(first.position(), position(4, 1));
    assert_eq!(second.position(), position(4, 2));
    assert_ne!(first, second);
}

#[test]
fn empty_snapshot_represents_zero_authority() {
    let snapshot = ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &[]).unwrap();

    assert!(snapshot.is_empty());
    assert_eq!(snapshot.len(), 0);
    assert_eq!(snapshot.entries(), &[]);
    assert_eq!(snapshot.total_weight(), AgreementWeight::ZERO);
    assert_eq!(snapshot.signed_weight(&[]), Ok(AgreementWeight::ZERO));
    assert_eq!(snapshot.has_strict_supermajority(&[]), Ok(false));
    assert_eq!(snapshot.has_strict_one_third(&[]), Ok(false));
}

#[test]
fn snapshot_construction_is_key_ordered_and_permutation_independent() {
    let forward = [entry(3, 30), entry(1, 10), entry(2, 20)];
    let reverse = [entry(2, 20), entry(1, 10), entry(3, 30)];
    let first = ActiveAgreementSnapshot::try_from_preselected(position(2, 1), &forward).unwrap();
    let second = ActiveAgreementSnapshot::try_from_preselected(position(2, 1), &reverse).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.total_weight(), AgreementWeight::new(60));
    assert_eq!(
        first
            .entries()
            .iter()
            .map(|entry| entry.consensus_key())
            .collect::<Vec<_>>(),
        vec![key(1), key(2), key(3)]
    );
}

#[test]
fn snapshot_constructor_enforces_entry_bound() {
    let maximum = (0..MAX_ACTIVE_VALIDATORS)
        .map(|index| entry(index as u16, 1))
        .collect::<Vec<_>>();
    let too_many = (0..=MAX_ACTIVE_VALIDATORS)
        .map(|index| entry(index as u16, 1))
        .collect::<Vec<_>>();

    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &maximum)
            .unwrap()
            .len(),
        MAX_ACTIVE_VALIDATORS
    );
    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &too_many),
        Err(ActiveAgreementSnapshotError::TooManyValidators {
            actual: MAX_ACTIVE_VALIDATORS + 1,
            maximum: MAX_ACTIVE_VALIDATORS,
        })
    );
}

#[test]
fn snapshot_constructor_rejects_duplicate_zero_and_overflow() {
    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(
            position(1, 0),
            &[entry(2, 1), entry(1, 2), entry(1, 3)]
        ),
        Err(ActiveAgreementSnapshotError::DuplicateConsensusKey {
            consensus_key: key(1),
        })
    );
    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &[entry(2, 1), entry(1, 0)]),
        Err(ActiveAgreementSnapshotError::ZeroAgreementWeight {
            consensus_key: key(1),
        })
    );
    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(
            position(1, 0),
            &[entry(1, u128::MAX), entry(2, 1)]
        ),
        Err(ActiveAgreementSnapshotError::TotalWeightOverflow)
    );
}

#[test]
fn snapshot_error_precedence_is_permutation_independent() {
    let first = [
        entry(5, 0),
        entry(3, 1),
        entry(3, 2),
        entry(1, 0),
        entry(7, 1),
    ];
    let second = [
        entry(1, 0),
        entry(7, 1),
        entry(3, 2),
        entry(5, 0),
        entry(3, 1),
    ];
    let expected_duplicate = Err(ActiveAgreementSnapshotError::DuplicateConsensusKey {
        consensus_key: key(3),
    });

    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &first),
        expected_duplicate
    );
    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &second),
        expected_duplicate
    );

    let first = [entry(5, 0), entry(1, 0), entry(7, 1)];
    let second = [entry(7, 1), entry(5, 0), entry(1, 0)];
    let expected_zero = Err(ActiveAgreementSnapshotError::ZeroAgreementWeight {
        consensus_key: key(1),
    });

    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &first),
        expected_zero
    );
    assert_eq!(
        ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &second),
        expected_zero
    );
}

#[test]
fn snapshot_constructor_accepts_maximum_exact_total() {
    let snapshot = ActiveAgreementSnapshot::try_from_preselected(
        position(1, 0),
        &[entry(1, u128::MAX - 1), entry(2, 1)],
    )
    .unwrap();

    assert_eq!(snapshot.total_weight(), AgreementWeight::new(u128::MAX));
}

#[test]
fn strict_supermajority_boundaries_cover_all_total_remainders() {
    for (weights, false_signers, true_signers) in [
        (&[1_u128][..], vec![], vec![key(0)]),
        (&[1_u128, 1][..], vec![key(0)], vec![key(0), key(1)]),
        (&[2_u128, 1][..], vec![key(0)], vec![key(0), key(1)]),
        (&[2_u128, 1, 1][..], vec![key(0)], vec![key(0), key(1)]),
    ] {
        let snapshot = snapshot(weights);
        assert_eq!(snapshot.has_strict_supermajority(&false_signers), Ok(false));
        assert_eq!(snapshot.has_strict_supermajority(&true_signers), Ok(true));
    }
}

#[test]
fn strict_one_third_boundaries_cover_all_total_remainders() {
    for (weights, false_signers, true_signers) in [
        (&[1_u128][..], vec![], vec![key(0)]),
        (&[1_u128, 1][..], vec![], vec![key(0)]),
        (&[1_u128, 2][..], vec![key(0)], vec![key(1)]),
        (&[1_u128, 1, 2][..], vec![key(0)], vec![key(2)]),
        (&[1_u128, 2, 2][..], vec![key(0)], vec![key(1)]),
    ] {
        let snapshot = snapshot(weights);
        assert_eq!(snapshot.has_strict_one_third(&false_signers), Ok(false));
        assert_eq!(snapshot.has_strict_one_third(&true_signers), Ok(true));
    }
}

#[test]
fn small_domain_matches_independent_multiplication_oracle() {
    for validator_count in 1..=4_usize {
        let combinations = 3_usize.pow(validator_count as u32);
        for mut encoded_weights in 0..combinations {
            let mut weights = Vec::with_capacity(validator_count);
            for _ in 0..validator_count {
                weights.push((encoded_weights % 3 + 1) as u128);
                encoded_weights /= 3;
            }
            let snapshot = snapshot(&weights);
            for signer_mask in 0..(1_usize << validator_count) {
                let signers = (0..validator_count)
                    .filter(|index| signer_mask & (1 << index) != 0)
                    .map(|index| key(index as u16))
                    .collect::<Vec<_>>();
                let signed = weights
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| signer_mask & (1 << index) != 0)
                    .map(|(_, weight)| *weight)
                    .sum::<u128>();
                let total = weights.iter().sum::<u128>();
                assert_eq!(
                    snapshot.has_strict_supermajority(&signers),
                    Ok(signed * 3 > total * 2),
                    "weights={weights:?}, signer_mask={signer_mask:#b}"
                );
                assert_eq!(
                    snapshot.has_strict_one_third(&signers),
                    Ok(signed * 3 > total),
                    "weights={weights:?}, signer_mask={signer_mask:#b}"
                );
            }
        }
    }
}

#[test]
fn near_maximum_thresholds_cover_every_remainder_without_overflow() {
    for total in [u128::MAX, u128::MAX - 1, u128::MAX - 2] {
        let ceil_one_third = total / 3 + u128::from(total % 3 != 0);
        let floor_two_thirds = total - ceil_one_third;
        let at_supermajority_boundary = snapshot(&[floor_two_thirds, total - floor_two_thirds]);
        let above_supermajority_boundary =
            snapshot(&[floor_two_thirds + 1, total - floor_two_thirds - 1]);
        let floor_one_third = total / 3;
        let at_one_third_boundary = snapshot(&[floor_one_third, total - floor_one_third]);
        let above_one_third_boundary =
            snapshot(&[floor_one_third + 1, total - floor_one_third - 1]);

        assert_eq!(
            at_supermajority_boundary.has_strict_supermajority(&[key(0)]),
            Ok(false),
            "total={total}"
        );
        assert_eq!(
            above_supermajority_boundary.has_strict_supermajority(&[key(0)]),
            Ok(true),
            "total={total}"
        );
        assert_eq!(
            at_one_third_boundary.has_strict_one_third(&[key(0)]),
            Ok(false),
            "total={total}"
        );
        assert_eq!(
            above_one_third_boundary.has_strict_one_third(&[key(0)]),
            Ok(true),
            "total={total}"
        );
    }
}

#[test]
fn offline_weight_remains_in_the_denominator() {
    let snapshot = snapshot(&[34, 33, 33]);

    assert_eq!(
        snapshot.has_strict_supermajority(&[key(0), key(1)]),
        Ok(true)
    );
    assert_eq!(
        snapshot.has_strict_supermajority(&[key(1), key(2)]),
        Ok(false)
    );
    assert_eq!(snapshot.has_strict_one_third(&[key(0)]), Ok(true));
    assert_eq!(snapshot.has_strict_one_third(&[key(1)]), Ok(false));
}

#[test]
fn duplicate_and_unknown_signers_fail_before_quorum_result() {
    let snapshot = snapshot(&[80, 10, 10]);

    assert_eq!(
        snapshot.has_strict_supermajority(&[key(0), key(0)]),
        Err(AgreementSignerError::DuplicateSigner {
            consensus_key: key(0),
        })
    );
    assert_eq!(
        snapshot.has_strict_supermajority(&[key(0), key(9)]),
        Err(AgreementSignerError::UnknownSigner {
            consensus_key: key(9),
        })
    );
}

#[test]
fn signer_error_precedence_is_permutation_independent() {
    let snapshot = snapshot(&[70, 10, 10, 10]);
    let first = [key(3), key(3), key(2), key(2), key(9), key(0)];
    let second = [key(9), key(0), key(2), key(3), key(2), key(3)];
    let expected_duplicate = Err(AgreementSignerError::DuplicateSigner {
        consensus_key: key(2),
    });

    assert_eq!(
        snapshot.has_strict_supermajority(&first),
        expected_duplicate
    );
    assert_eq!(
        snapshot.has_strict_supermajority(&second),
        expected_duplicate
    );
    assert_eq!(snapshot.has_strict_one_third(&first), expected_duplicate);
    assert_eq!(snapshot.has_strict_one_third(&second), expected_duplicate);

    let first = [key(9), key(0), key(8)];
    let second = [key(8), key(9), key(0)];
    let expected_unknown = Err(AgreementSignerError::UnknownSigner {
        consensus_key: key(8),
    });

    assert_eq!(snapshot.has_strict_supermajority(&first), expected_unknown);
    assert_eq!(snapshot.has_strict_supermajority(&second), expected_unknown);
    assert_eq!(snapshot.has_strict_one_third(&first), expected_unknown);
    assert_eq!(snapshot.has_strict_one_third(&second), expected_unknown);
}

#[test]
fn signer_entry_bound_precedes_duplicate_lookup() {
    let snapshot = snapshot(&[1]);
    let signers = vec![key(0); MAX_ACTIVE_VALIDATORS + 1];

    assert_eq!(
        snapshot.signed_weight(&signers),
        Err(AgreementSignerError::TooManySigners {
            actual: MAX_ACTIVE_VALIDATORS + 1,
            maximum: MAX_ACTIVE_VALIDATORS,
        })
    );
    assert_eq!(
        snapshot.has_strict_one_third(&signers),
        Err(AgreementSignerError::TooManySigners {
            actual: MAX_ACTIVE_VALIDATORS + 1,
            maximum: MAX_ACTIVE_VALIDATORS,
        })
    );
}

#[test]
fn signer_permutations_produce_the_same_weight_and_result() {
    let snapshot = snapshot(&[40, 30, 20, 10]);
    let first = [key(0), key(1)];
    let second = [key(1), key(0)];

    assert_eq!(snapshot.signed_weight(&first), Ok(AgreementWeight::new(70)));
    assert_eq!(
        snapshot.signed_weight(&second),
        Ok(AgreementWeight::new(70))
    );
    assert_eq!(
        snapshot.has_strict_supermajority(&first),
        snapshot.has_strict_supermajority(&second)
    );
    assert_eq!(
        snapshot.has_strict_one_third(&first),
        snapshot.has_strict_one_third(&second)
    );
}

#[test]
fn complete_256_signer_list_is_accepted() {
    let entries = (0..MAX_ACTIVE_VALIDATORS)
        .map(|index| entry(index as u16, 1))
        .collect::<Vec<_>>();
    let signers = (0..MAX_ACTIVE_VALIDATORS)
        .map(|index| key(index as u16))
        .collect::<Vec<_>>();
    let snapshot = ActiveAgreementSnapshot::try_from_preselected(position(1, 0), &entries).unwrap();

    assert_eq!(
        snapshot.signed_weight(&signers),
        Ok(AgreementWeight::new(MAX_ACTIVE_VALIDATORS as u128))
    );
    assert_eq!(snapshot.has_strict_supermajority(&signers), Ok(true));
    assert_eq!(snapshot.has_strict_one_third(&signers), Ok(true));
}

#[test]
fn splitting_active_weight_preserves_corresponding_aggregate_result() {
    let unsplit = snapshot(&[70, 30]);
    let split = snapshot(&[30, 40, 30]);

    assert_eq!(
        unsplit.signed_weight(&[key(0)]),
        split.signed_weight(&[key(0), key(1)])
    );
    assert_eq!(
        unsplit.has_strict_supermajority(&[key(0)]),
        split.has_strict_supermajority(&[key(0), key(1)])
    );
    assert_eq!(
        unsplit.has_strict_one_third(&[key(0)]),
        split.has_strict_one_third(&[key(0), key(1)])
    );
    assert_eq!(split.has_strict_supermajority(&[key(1)]), Ok(false));
    assert_eq!(split.has_strict_one_third(&[key(1)]), Ok(true));
}
