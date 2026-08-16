use super::*;

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
