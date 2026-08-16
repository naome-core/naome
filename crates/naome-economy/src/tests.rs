use super::*;

const TEST_FEE_PARTS: u128 = 5;

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
