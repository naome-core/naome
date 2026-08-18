use super::*;

const TEST_FEE_PARTS: u128 = 5;
const REFERENCE_MINIMUM_ARTIFACT_BASE_FEE_ATOMS: u128 = 5;
const REFERENCE_MINIMUM_NON_ARTIFACT_OPERATION_FEE_ATOMS: u128 = 1;

const CONSTANT_QUALIFIED_ARTIFACT_BASE_FEE: FloorQualifiedArtifactBaseFee =
    match FloorQualifiedArtifactBaseFee::try_from_fee_atoms(MINIMUM_ARTIFACT_BASE_FEE) {
        Ok(fee) => fee,
        Err(_) => panic!("the minimum artifact base fee must qualify"),
    };
const CONSTANT_QUALIFIED_FEE_ATOMS: NaoAtoms = CONSTANT_QUALIFIED_ARTIFACT_BASE_FEE.fee_atoms();
const CONSTANT_QUALIFIED_PARTITION: FeePartition = CONSTANT_QUALIFIED_ARTIFACT_BASE_FEE.partition();
const CONSTANT_BELOW_FLOOR_RESULT: Result<
    FloorQualifiedArtifactBaseFee,
    ArtifactBaseFeeFloorError,
> = FloorQualifiedArtifactBaseFee::try_from_fee_atoms(NaoAtoms::new(4));
const CONSTANT_QUALIFIED_NON_ARTIFACT_OPERATION_FEE: FloorQualifiedNonArtifactOperationFee =
    match FloorQualifiedNonArtifactOperationFee::try_from_fee_atoms(
        MINIMUM_NON_ARTIFACT_OPERATION_FEE,
    ) {
        Ok(fee) => fee,
        Err(_) => panic!("the minimum non-artifact operation fee must qualify"),
    };
const CONSTANT_QUALIFIED_OPERATION_FEE_ATOMS: NaoAtoms =
    CONSTANT_QUALIFIED_NON_ARTIFACT_OPERATION_FEE.fee_atoms();
const CONSTANT_QUALIFIED_OPERATION_PARTITION: FeePartition =
    CONSTANT_QUALIFIED_NON_ARTIFACT_OPERATION_FEE.partition();
const CONSTANT_ZERO_OPERATION_FEE_RESULT: Result<
    FloorQualifiedNonArtifactOperationFee,
    NonArtifactOperationFeeFloorError,
> = FloorQualifiedNonArtifactOperationFee::try_from_fee_atoms(NaoAtoms::ZERO);
const CONSTANT_AGGREGATED_VALIDATOR_POOL: Result<NaoAtoms, ValidatorPoolAggregationError> =
    aggregate_validator_pool(&[
        FeePartition::from_artifact_base_fee(NaoAtoms::new(5)),
        FeePartition::from_non_artifact_operation_fee(NaoAtoms::new(5)),
    ]);

fn assert_standard_error(_: &dyn std::error::Error) {}

fn assert_citation_pool_allocation_matches_oracle(
    partition: FeePartition,
    distinct_eligible_target_count: u128,
) {
    let allocation = partition.allocate_citation_pool(distinct_eligible_target_count);
    let pool_atoms = partition.citation_pool().atoms();

    assert_eq!(
        allocation.citation_pool(),
        partition.citation_pool(),
        "pool={pool_atoms}, count={distinct_eligible_target_count}"
    );
    assert_eq!(
        allocation.distinct_eligible_target_count(),
        distinct_eligible_target_count,
        "pool={pool_atoms}, count={distinct_eligible_target_count}"
    );

    if distinct_eligible_target_count == 0 {
        assert_eq!(
            allocation.per_target_reward(),
            NaoAtoms::ZERO,
            "pool={pool_atoms}, count={distinct_eligible_target_count}"
        );
        assert_eq!(
            allocation.burned_remainder(),
            partition.citation_pool(),
            "pool={pool_atoms}, count={distinct_eligible_target_count}"
        );
        return;
    }

    let expected_reward = pool_atoms
        .checked_div(distinct_eligible_target_count)
        .expect("the target count is nonzero");
    let expected_remainder = pool_atoms
        .checked_rem(distinct_eligible_target_count)
        .expect("the target count is nonzero");
    assert_eq!(
        allocation.per_target_reward().atoms(),
        expected_reward,
        "pool={pool_atoms}, count={distinct_eligible_target_count}"
    );
    assert_eq!(
        allocation.burned_remainder().atoms(),
        expected_remainder,
        "pool={pool_atoms}, count={distinct_eligible_target_count}"
    );
    assert_eq!(
        allocation.per_target_reward().atoms() * distinct_eligible_target_count
            + allocation.burned_remainder().atoms(),
        pool_atoms,
        "pool={pool_atoms}, count={distinct_eligible_target_count}"
    );
}

#[test]
fn validator_pool_aggregation_is_const_evaluable_and_empty_is_zero() {
    assert_eq!(CONSTANT_AGGREGATED_VALIDATOR_POOL, Ok(NaoAtoms::new(2)));
    assert_eq!(aggregate_validator_pool(&[]), Ok(NaoAtoms::ZERO));
}

#[test]
fn validator_pool_aggregation_matches_independent_mixed_fee_oracle() {
    for artifact_fee_atoms in 0_u128..=64 {
        for operation_fee_atoms in 0_u128..=64 {
            let artifact = FeePartition::from_artifact_base_fee(NaoAtoms::new(artifact_fee_atoms));
            let operation =
                FeePartition::from_non_artifact_operation_fee(NaoAtoms::new(operation_fee_atoms));
            let expected =
                artifact_fee_atoms / TEST_FEE_PARTS + operation_fee_atoms / TEST_FEE_PARTS;

            assert_eq!(
                aggregate_validator_pool(&[artifact, operation]),
                Ok(NaoAtoms::new(expected)),
                "artifact_fee_atoms={artifact_fee_atoms}, operation_fee_atoms={operation_fee_atoms}"
            );
            assert_eq!(
                aggregate_validator_pool(&[operation, artifact]),
                Ok(NaoAtoms::new(expected)),
                "reversed artifact_fee_atoms={artifact_fee_atoms}, operation_fee_atoms={operation_fee_atoms}"
            );
        }
    }
}

#[test]
fn validator_pool_aggregation_is_exact_at_full_u128_and_errors_past_it() {
    let maximum_partition = FeePartition::from_artifact_base_fee(NaoAtoms::new(u128::MAX));
    let minimum_partition = FeePartition::from_artifact_base_fee(MINIMUM_ARTIFACT_BASE_FEE);
    let exact = [maximum_partition; 5];
    let overflow_last = [
        maximum_partition,
        maximum_partition,
        maximum_partition,
        maximum_partition,
        maximum_partition,
        minimum_partition,
    ];
    let mut overflow_first = overflow_last;
    overflow_first.reverse();

    assert_eq!(u128::MAX % TEST_FEE_PARTS, 0);
    assert_eq!(
        aggregate_validator_pool(&[maximum_partition]),
        Ok(NaoAtoms::new(u128::MAX / TEST_FEE_PARTS))
    );
    assert_eq!(
        aggregate_validator_pool(&exact),
        Ok(NaoAtoms::new(u128::MAX))
    );
    let error = aggregate_validator_pool(&overflow_last).unwrap_err();
    assert_eq!(error, ValidatorPoolAggregationError::Overflow);
    assert_eq!(
        aggregate_validator_pool(&overflow_first),
        Err(ValidatorPoolAggregationError::Overflow)
    );
    assert_eq!(
        error.to_string(),
        "validator pool total exceeds u128 capacity"
    );
    assert_standard_error(&error);
}

#[test]
fn artifact_base_fee_floor_rejects_every_below_minimum_amount() {
    assert_eq!(
        MINIMUM_ARTIFACT_BASE_FEE.atoms(),
        REFERENCE_MINIMUM_ARTIFACT_BASE_FEE_ATOMS
    );

    for actual_atoms in 0_u128..REFERENCE_MINIMUM_ARTIFACT_BASE_FEE_ATOMS {
        let actual = NaoAtoms::new(actual_atoms);
        assert_eq!(
            FloorQualifiedArtifactBaseFee::try_from_fee_atoms(actual),
            Err(ArtifactBaseFeeFloorError::BelowMinimum {
                actual,
                minimum: NaoAtoms::new(REFERENCE_MINIMUM_ARTIFACT_BASE_FEE_ATOMS),
            }),
            "actual_atoms={actual_atoms}"
        );
    }
}

#[test]
fn artifact_base_fee_floor_qualified_domain_matches_raw_partition() {
    for fee_atoms in (REFERENCE_MINIMUM_ARTIFACT_BASE_FEE_ATOMS..=1_024).chain([u128::MAX]) {
        let fee = NaoAtoms::new(fee_atoms);
        let qualified = FloorQualifiedArtifactBaseFee::try_from_fee_atoms(fee).unwrap();
        let partition = qualified.partition();

        assert_eq!(qualified.fee_atoms(), fee, "fee_atoms={fee_atoms}");
        assert_eq!(
            partition,
            FeePartition::from_artifact_base_fee(fee),
            "fee_atoms={fee_atoms}"
        );
        assert!(
            !partition.citation_pool().is_zero(),
            "fee_atoms={fee_atoms}"
        );
        assert!(
            !partition.validator_pool().is_zero(),
            "fee_atoms={fee_atoms}"
        );
        assert_eq!(
            partition.citation_pool().atoms()
                + partition.validator_pool().atoms()
                + partition.burned().atoms(),
            fee_atoms,
            "fee_atoms={fee_atoms}"
        );
    }
}

#[test]
fn artifact_base_fee_floor_public_api_is_const_evaluable() {
    assert_eq!(CONSTANT_QUALIFIED_FEE_ATOMS, MINIMUM_ARTIFACT_BASE_FEE);
    assert_eq!(
        CONSTANT_QUALIFIED_PARTITION.citation_pool(),
        NaoAtoms::new(2)
    );
    assert_eq!(
        CONSTANT_QUALIFIED_PARTITION.validator_pool(),
        NaoAtoms::new(1)
    );
    assert_eq!(CONSTANT_QUALIFIED_PARTITION.burned(), NaoAtoms::new(2));
    assert_eq!(
        CONSTANT_BELOW_FLOOR_RESULT,
        Err(ArtifactBaseFeeFloorError::BelowMinimum {
            actual: NaoAtoms::new(4),
            minimum: MINIMUM_ARTIFACT_BASE_FEE,
        })
    );
}

#[test]
fn artifact_base_fee_floor_error_has_exact_display_and_standard_error() {
    let error = ArtifactBaseFeeFloorError::BelowMinimum {
        actual: NaoAtoms::new(4),
        minimum: MINIMUM_ARTIFACT_BASE_FEE,
    };

    assert_eq!(
        error.to_string(),
        "artifact base fee has 4 atoms, below numeric minimum 5"
    );
    assert_standard_error(&error);
}

#[test]
fn non_artifact_operation_fee_qualified_domain_matches_raw_partition() {
    for fee_atoms in (REFERENCE_MINIMUM_NON_ARTIFACT_OPERATION_FEE_ATOMS..=1_024).chain([u128::MAX])
    {
        let fee = NaoAtoms::new(fee_atoms);
        let qualified = FloorQualifiedNonArtifactOperationFee::try_from_fee_atoms(fee).unwrap();
        let partition = qualified.partition();

        assert_eq!(qualified.fee_atoms(), fee, "fee_atoms={fee_atoms}");
        assert_eq!(
            partition,
            FeePartition::from_non_artifact_operation_fee(fee),
            "fee_atoms={fee_atoms}"
        );
    }
}

#[test]
fn non_artifact_operation_fee_floor_boundary_and_const_api_are_exact() {
    assert_eq!(
        MINIMUM_NON_ARTIFACT_OPERATION_FEE.atoms(),
        REFERENCE_MINIMUM_NON_ARTIFACT_OPERATION_FEE_ATOMS
    );
    assert_eq!(
        FloorQualifiedNonArtifactOperationFee::try_from_fee_atoms(NaoAtoms::ZERO),
        Err(NonArtifactOperationFeeFloorError::BelowMinimum {
            actual: NaoAtoms::ZERO,
            minimum: NaoAtoms::new(REFERENCE_MINIMUM_NON_ARTIFACT_OPERATION_FEE_ATOMS),
        })
    );
    assert_eq!(
        CONSTANT_QUALIFIED_OPERATION_FEE_ATOMS,
        MINIMUM_NON_ARTIFACT_OPERATION_FEE
    );
    assert_eq!(
        CONSTANT_QUALIFIED_OPERATION_PARTITION.citation_pool(),
        NaoAtoms::ZERO
    );
    assert_eq!(
        CONSTANT_QUALIFIED_OPERATION_PARTITION.validator_pool(),
        NaoAtoms::ZERO
    );
    assert_eq!(
        CONSTANT_QUALIFIED_OPERATION_PARTITION.burned(),
        NaoAtoms::new(1)
    );
    assert_eq!(
        CONSTANT_ZERO_OPERATION_FEE_RESULT,
        Err(NonArtifactOperationFeeFloorError::BelowMinimum {
            actual: NaoAtoms::ZERO,
            minimum: MINIMUM_NON_ARTIFACT_OPERATION_FEE,
        })
    );
}

#[test]
fn non_artifact_operation_fee_floor_error_has_exact_display_and_standard_error() {
    let error = NonArtifactOperationFeeFloorError::BelowMinimum {
        actual: NaoAtoms::ZERO,
        minimum: MINIMUM_NON_ARTIFACT_OPERATION_FEE,
    };

    assert_eq!(
        error.to_string(),
        "non-artifact operation fee has 0 atoms, below numeric minimum 1"
    );
    assert_standard_error(&error);
}

#[test]
fn artifact_fee_partitions_match_small_boundaries() {
    let expected = [
        (0, 0, 0),
        (0, 0, 1),
        (0, 0, 2),
        (1, 0, 2),
        (1, 0, 3),
        (2, 1, 2),
        (2, 1, 3),
        (2, 1, 4),
        (3, 1, 4),
        (3, 1, 5),
        (4, 2, 4),
    ];

    for (fee, (citation, validator, burned)) in expected.into_iter().enumerate() {
        let fee = NaoAtoms::new(fee as u128);
        let partition = FeePartition::from_artifact_base_fee(fee);

        assert_eq!(partition.fee(), fee);
        assert_eq!(partition.citation_pool(), NaoAtoms::new(citation));
        assert_eq!(partition.validator_pool(), NaoAtoms::new(validator));
        assert_eq!(partition.burned(), NaoAtoms::new(burned));
    }

    assert!(NaoAtoms::ZERO.is_zero());
    assert!(!NaoAtoms::new(1).is_zero());
}

#[test]
fn non_artifact_fee_partitions_match_small_boundaries() {
    let expected = [
        (0, 0),
        (0, 1),
        (0, 2),
        (0, 3),
        (0, 4),
        (1, 4),
        (1, 5),
        (1, 6),
        (1, 7),
        (1, 8),
        (2, 8),
    ];

    for (fee, (validator, burned)) in expected.into_iter().enumerate() {
        let fee = NaoAtoms::new(fee as u128);
        let partition = FeePartition::from_non_artifact_operation_fee(fee);

        assert_eq!(partition.fee(), fee);
        assert_eq!(partition.citation_pool(), NaoAtoms::ZERO);
        assert_eq!(partition.validator_pool(), NaoAtoms::new(validator));
        assert_eq!(partition.burned(), NaoAtoms::new(burned));
    }
}

#[test]
fn fee_partitions_match_direct_oracles_and_conserve_atoms() {
    for fee_atoms in 0_u128..=10_000 {
        let fee = NaoAtoms::new(fee_atoms);
        let artifact = FeePartition::from_artifact_base_fee(fee);
        let operation = FeePartition::from_non_artifact_operation_fee(fee);

        let expected_citation = (2 * fee_atoms) / 5;
        let expected_validator = fee_atoms / 5;
        assert_eq!(artifact.citation_pool().atoms(), expected_citation);
        assert_eq!(artifact.validator_pool().atoms(), expected_validator);
        assert_eq!(
            artifact.citation_pool().atoms()
                + artifact.validator_pool().atoms()
                + artifact.burned().atoms(),
            fee_atoms
        );

        assert_eq!(operation.citation_pool(), NaoAtoms::ZERO);
        assert_eq!(operation.validator_pool().atoms(), expected_validator);
        assert_eq!(
            operation.validator_pool().atoms() + operation.burned().atoms(),
            fee_atoms
        );
    }
}

#[test]
fn near_maximum_fee_partitions_cover_every_remainder_without_overflow() {
    let maximum_remainder = u128::MAX % FEE_PARTS;

    for target_remainder in 0_u128..FEE_PARTS {
        let distance = (maximum_remainder + FEE_PARTS - target_remainder) % FEE_PARTS;
        let fee_atoms = u128::MAX - distance;
        let quotient = fee_atoms / FEE_PARTS;
        let fee = NaoAtoms::new(fee_atoms);
        let artifact = FeePartition::from_artifact_base_fee(fee);
        let operation = FeePartition::from_non_artifact_operation_fee(fee);
        let citation_remainder = u128::from(target_remainder >= 3);

        assert_eq!(fee_atoms % FEE_PARTS, target_remainder);
        assert_eq!(
            artifact.citation_pool().atoms(),
            2 * quotient + citation_remainder
        );
        assert_eq!(artifact.validator_pool().atoms(), quotient);
        assert_eq!(
            artifact.burned().atoms(),
            2 * quotient + target_remainder - citation_remainder
        );
        assert_eq!(
            artifact.citation_pool().atoms()
                + artifact.validator_pool().atoms()
                + artifact.burned().atoms(),
            fee_atoms
        );

        assert_eq!(operation.citation_pool(), NaoAtoms::ZERO);
        assert_eq!(operation.validator_pool().atoms(), quotient);
        assert_eq!(operation.burned().atoms(), fee_atoms - quotient);
        assert_eq!(
            operation.validator_pool().atoms() + operation.burned().atoms(),
            fee_atoms
        );
    }
}

#[test]
fn citation_pool_allocations_match_literal_boundaries() {
    let expected = [
        (0, 0, 0, 0, 0),
        (10, 0, 4, 0, 4),
        (10, 1, 4, 4, 0),
        (10, 2, 4, 2, 0),
        (13, 2, 5, 2, 1),
        (3, 2, 1, 0, 1),
    ];

    for (fee, count, pool, per_target, burned) in expected {
        let allocation =
            FeePartition::from_artifact_base_fee(NaoAtoms::new(fee)).allocate_citation_pool(count);

        assert_eq!(allocation.citation_pool(), NaoAtoms::new(pool));
        assert_eq!(allocation.distinct_eligible_target_count(), count);
        assert_eq!(allocation.per_target_reward(), NaoAtoms::new(per_target));
        assert_eq!(allocation.burned_remainder(), NaoAtoms::new(burned));
    }
}

#[test]
fn non_artifact_partitions_allocate_only_their_zero_citation_pool() {
    let partition = FeePartition::from_non_artifact_operation_fee(NaoAtoms::new(25));

    assert_eq!(partition.fee(), NaoAtoms::new(25));
    assert_eq!(partition.validator_pool(), NaoAtoms::new(5));
    assert_eq!(partition.burned(), NaoAtoms::new(20));

    for count in [0, 7] {
        let allocation = partition.allocate_citation_pool(count);

        assert_eq!(allocation.citation_pool(), NaoAtoms::ZERO);
        assert_eq!(allocation.distinct_eligible_target_count(), count);
        assert_eq!(allocation.per_target_reward(), NaoAtoms::ZERO);
        assert_eq!(allocation.burned_remainder(), NaoAtoms::ZERO);
    }
}

#[test]
fn every_small_pool_and_count_matches_division_oracles_and_conserves_atoms() {
    for pool_atoms in 0_u128..=255 {
        let fee_atoms = (TEST_FEE_PARTS * pool_atoms).div_ceil(2);
        let partition = FeePartition::from_artifact_base_fee(NaoAtoms::new(fee_atoms));
        assert_eq!(partition.citation_pool(), NaoAtoms::new(pool_atoms));

        for count in 0_u128..=255 {
            assert_citation_pool_allocation_matches_oracle(partition, count);
        }
    }
}

#[test]
fn near_maximum_citation_pools_cover_count_boundaries_without_overflow() {
    let maximum_remainder = u128::MAX % TEST_FEE_PARTS;

    for target_remainder in 0_u128..TEST_FEE_PARTS {
        let distance = (maximum_remainder + TEST_FEE_PARTS - target_remainder) % TEST_FEE_PARTS;
        let fee_atoms = u128::MAX - distance;
        let partition = FeePartition::from_artifact_base_fee(NaoAtoms::new(fee_atoms));
        let pool_atoms = partition.citation_pool().atoms();

        for count in [0, 1, 2, 3, 5, pool_atoms, pool_atoms + 1, u128::MAX] {
            assert_citation_pool_allocation_matches_oracle(partition, count);
        }
    }
}

#[test]
fn matured_citation_atoms_map_one_to_one_to_initial_weight() {
    for atoms in [0, 1, u128::MAX] {
        let batch = KnowledgeWeightBatch::from_matured_citation_atoms(atoms);

        assert_eq!(batch.original_weight(), KnowledgeWeight::new(atoms));
        assert_eq!(batch.live_weight_at_age(0), KnowledgeWeight::new(atoms));
    }

    assert!(KnowledgeWeight::ZERO.is_zero());
    assert!(!KnowledgeWeight::new(1).is_zero());
}

#[test]
fn decay_boundaries_cover_last_live_and_every_terminal_age() {
    let batch = KnowledgeWeightBatch::from_matured_citation_atoms(730);

    assert_eq!(batch.live_weight_at_age(0), KnowledgeWeight::new(730));
    assert_eq!(batch.live_weight_at_age(729), KnowledgeWeight::new(1));
    assert_eq!(batch.live_weight_at_age(730), KnowledgeWeight::ZERO);
    assert_eq!(batch.live_weight_at_age(731), KnowledgeWeight::ZERO);
    assert_eq!(batch.live_weight_at_age(u64::MAX), KnowledgeWeight::ZERO);
}

#[test]
fn every_age_and_remainder_matches_direct_multiplication_when_safe() {
    for remainder in 0_u128..BATCH_LIFETIME_UNITS {
        let original = 123 * BATCH_LIFETIME_UNITS + remainder;
        let batch = KnowledgeWeightBatch::from_matured_citation_atoms(original);

        for age in 0..=BATCH_LIFETIME_EPOCHS {
            let expected = if age == BATCH_LIFETIME_EPOCHS {
                0
            } else {
                original * u128::from(BATCH_LIFETIME_EPOCHS - age) / BATCH_LIFETIME_UNITS
            };
            assert_eq!(
                batch.live_weight_at_age(age).units(),
                expected,
                "original={original}, age={age}"
            );
        }
    }
}

#[test]
fn near_maximum_values_satisfy_independent_decay_identities() {
    let maximum_remainder = u128::MAX % BATCH_LIFETIME_UNITS;

    for target_remainder in 0_u128..BATCH_LIFETIME_UNITS {
        let distance =
            (maximum_remainder + BATCH_LIFETIME_UNITS - target_remainder) % BATCH_LIFETIME_UNITS;
        let original = u128::MAX - distance;
        let batch = KnowledgeWeightBatch::from_matured_citation_atoms(original);

        assert_eq!(original % BATCH_LIFETIME_UNITS, target_remainder);
        assert_eq!(batch.live_weight_at_age(0).units(), original);
        assert_eq!(
            batch.live_weight_at_age(1).units(),
            original - original.div_ceil(730)
        );
        assert_eq!(batch.live_weight_at_age(365).units(), original / 2);
        assert_eq!(batch.live_weight_at_age(729).units(), original / 730);
        assert_eq!(batch.live_weight_at_age(730), KnowledgeWeight::ZERO);

        let mut previous = original;
        for age in 1..=BATCH_LIFETIME_EPOCHS {
            let live = batch.live_weight_at_age(age).units();
            assert!(live <= previous, "original={original}, age={age}");
            assert!(live <= original, "original={original}, age={age}");
            previous = live;
        }
    }
}
