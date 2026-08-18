use std::error::Error;

use naome_consensus::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementSignerError, AgreementWeight,
    ConsensusHeight, ConsensusKey, ConsensusPosition, ConsensusRound, MAX_ACTIVE_VALIDATORS,
};
use naome_economy::{FeePartition, NaoAtoms, ValidatorPoolAggregationError};

use super::{
    ValidatorFeeAllocationFromPartitionsError, ValidatorFeeShareError,
    project_fee_funded_validator_allocation,
    project_fee_funded_validator_allocation_from_partitions, project_fee_funded_validator_share,
};

fn key(marker: u8) -> ConsensusKey {
    ConsensusKey::from_bytes([marker; 32])
}

fn numbered_key(index: usize) -> ConsensusKey {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
    ConsensusKey::from_bytes(bytes)
}

fn snapshot(entries: &[(u8, u128)]) -> ActiveAgreementSnapshot {
    let entries = entries
        .iter()
        .map(|(marker, weight)| {
            ActiveAgreementEntry::new(key(*marker), AgreementWeight::new(*weight))
        })
        .collect::<Vec<_>>();

    ActiveAgreementSnapshot::try_from_preselected(
        ConsensusPosition::new(ConsensusHeight::new(9), ConsensusRound::new(2)),
        &entries,
    )
    .unwrap()
}

fn assert_standard_error(_: &(dyn Error + 'static)) {}

#[test]
fn inactive_signer_fails_before_pool_arithmetic() {
    let missing = key(9);

    for active_snapshot in [snapshot(&[]), snapshot(&[(1, 7)])] {
        let error = project_fee_funded_validator_share(NaoAtoms::ZERO, &active_snapshot, missing)
            .unwrap_err();
        assert_eq!(
            error,
            ValidatorFeeShareError::InactiveSigner {
                consensus_key: missing,
            }
        );
        assert_eq!(
            error.to_string(),
            format!("consensus key {missing:?} is not active in the supplied agreement snapshot")
        );
        assert_standard_error(&error);
    }
}

#[test]
fn zero_pool_and_full_weight_preserve_exact_identities() {
    let active_snapshot = snapshot(&[(1, 17)]);

    assert_eq!(
        project_fee_funded_validator_share(NaoAtoms::ZERO, &active_snapshot, key(1)),
        Ok(NaoAtoms::ZERO)
    );
    assert_eq!(
        project_fee_funded_validator_share(NaoAtoms::new(91), &active_snapshot, key(1)),
        Ok(NaoAtoms::new(91))
    );
}

#[test]
fn aggregate_pool_is_projected_once_before_floor_rounding() {
    let active_snapshot = snapshot(&[(1, 1), (2, 1)]);
    let source_pools = [
        FeePartition::from_artifact_base_fee(NaoAtoms::new(5)).validator_pool(),
        FeePartition::from_non_artifact_operation_fee(NaoAtoms::new(5)).validator_pool(),
    ];
    assert_eq!(source_pools, [NaoAtoms::new(1), NaoAtoms::new(1)]);

    let separately_rounded = source_pools
        .into_iter()
        .map(|pool| {
            project_fee_funded_validator_share(pool, &active_snapshot, key(1))
                .unwrap()
                .atoms()
        })
        .sum::<u128>();
    assert_eq!(separately_rounded, 0);

    let aggregate_pool = NaoAtoms::new(source_pools.into_iter().map(NaoAtoms::atoms).sum());
    assert_eq!(aggregate_pool, NaoAtoms::new(2));
    assert_eq!(
        project_fee_funded_validator_share(aggregate_pool, &active_snapshot, key(1)),
        Ok(NaoAtoms::new(1))
    );
}

#[test]
fn literal_unequal_weights_use_the_unchanged_total_denominator() {
    let active_snapshot = snapshot(&[(3, 3), (1, 1), (2, 2)]);

    for (marker, expected) in [(1, 1), (2, 3), (3, 5)] {
        assert_eq!(
            project_fee_funded_validator_share(NaoAtoms::new(11), &active_snapshot, key(marker),),
            Ok(NaoAtoms::new(expected)),
            "marker={marker}"
        );
    }
}

#[test]
fn bounded_domain_matches_independent_direct_product_oracle() {
    for total in 1_u128..=64 {
        for signer_weight in 1_u128..=total {
            let active_snapshot = if signer_weight == total {
                snapshot(&[(1, signer_weight)])
            } else {
                snapshot(&[(1, signer_weight), (2, total - signer_weight)])
            };

            for pool in 0_u128..=255 {
                let expected = pool * signer_weight / total;
                let actual = project_fee_funded_validator_share(
                    NaoAtoms::new(pool),
                    &active_snapshot,
                    key(1),
                )
                .unwrap();
                assert_eq!(
                    actual,
                    NaoAtoms::new(expected),
                    "pool={pool}, signer_weight={signer_weight}, total={total}"
                );
                assert!(actual.atoms() <= pool);
            }
        }
    }
}

#[test]
fn full_u128_domain_avoids_intermediate_product_overflow() {
    let maximum = u128::MAX;
    let full_weight = snapshot(&[(1, maximum)]);
    assert_eq!(
        project_fee_funded_validator_share(NaoAtoms::new(maximum), &full_weight, key(1)),
        Ok(NaoAtoms::new(maximum))
    );

    let extreme_split = snapshot(&[(1, 1), (2, maximum - 1)]);
    assert_eq!(
        project_fee_funded_validator_share(NaoAtoms::new(maximum), &extreme_split, key(1)),
        Ok(NaoAtoms::new(1))
    );
    assert_eq!(
        project_fee_funded_validator_share(NaoAtoms::new(maximum), &extreme_split, key(2)),
        Ok(NaoAtoms::new(maximum - 1))
    );

    let equal_split = snapshot(&[(1, 1), (2, 1)]);
    for marker in [1, 2] {
        assert_eq!(
            project_fee_funded_validator_share(NaoAtoms::new(maximum), &equal_split, key(marker)),
            Ok(NaoAtoms::new(maximum / 2)),
            "marker={marker}"
        );
    }
}

#[test]
fn snapshot_entry_order_does_not_change_the_share() {
    let ascending = snapshot(&[(1, 2), (2, 3), (3, 5)]);
    let descending = snapshot(&[(3, 5), (2, 3), (1, 2)]);

    for marker in [1, 2, 3] {
        assert_eq!(
            project_fee_funded_validator_share(NaoAtoms::new(97), &ascending, key(marker)),
            project_fee_funded_validator_share(NaoAtoms::new(97), &descending, key(marker)),
            "marker={marker}"
        );
    }
    assert_eq!(
        project_fee_funded_validator_share(NaoAtoms::new(97), &ascending, key(1)),
        Ok(NaoAtoms::new(19))
    );
}

#[test]
fn allocation_reuses_complete_signer_list_error_precedence_before_arithmetic() {
    let active_snapshot = snapshot(&[(1, 7), (2, 3)]);
    let too_many = (0..=MAX_ACTIVE_VALIDATORS)
        .map(numbered_key)
        .collect::<Vec<_>>();
    assert_eq!(
        project_fee_funded_validator_allocation(NaoAtoms::ZERO, &active_snapshot, &too_many),
        Err(AgreementSignerError::TooManySigners {
            actual: MAX_ACTIVE_VALIDATORS + 1,
            maximum: MAX_ACTIVE_VALIDATORS,
        })
    );

    assert_eq!(
        project_fee_funded_validator_allocation(
            NaoAtoms::ZERO,
            &active_snapshot,
            &[key(2), key(1), key(1), key(9)],
        ),
        Err(AgreementSignerError::DuplicateSigner {
            consensus_key: key(1),
        })
    );
    assert_eq!(
        project_fee_funded_validator_allocation(
            NaoAtoms::ZERO,
            &active_snapshot,
            &[key(9), key(8)],
        ),
        Err(AgreementSignerError::UnknownSigner {
            consensus_key: key(8),
        })
    );
}

#[test]
fn empty_signer_list_leaves_the_complete_pool_unassigned() {
    for active_snapshot in [snapshot(&[]), snapshot(&[(1, 7)])] {
        let allocation =
            project_fee_funded_validator_allocation(NaoAtoms::new(19), &active_snapshot, &[])
                .unwrap();

        assert_eq!(allocation.validator_pool(), NaoAtoms::new(19));
        assert_eq!(allocation.shares(), &[]);
        assert_eq!(allocation.unassigned(), NaoAtoms::new(19));
    }
}

#[test]
fn allocation_is_canonically_ordered_and_omission_keeps_the_denominator() {
    let active_snapshot = snapshot(&[(3, 5), (1, 2), (2, 3)]);
    let first = project_fee_funded_validator_allocation(
        NaoAtoms::new(97),
        &active_snapshot,
        &[key(3), key(1)],
    )
    .unwrap();
    let second = project_fee_funded_validator_allocation(
        NaoAtoms::new(97),
        &active_snapshot,
        &[key(1), key(3)],
    )
    .unwrap();

    assert_eq!(first, second);
    assert_eq!(first.validator_pool(), NaoAtoms::new(97));
    assert_eq!(
        first
            .shares()
            .iter()
            .map(|entry| (entry.consensus_key(), entry.share()))
            .collect::<Vec<_>>(),
        vec![(key(1), NaoAtoms::new(19)), (key(3), NaoAtoms::new(48))]
    );
    assert_eq!(first.unassigned(), NaoAtoms::new(30));

    let full = project_fee_funded_validator_allocation(
        NaoAtoms::new(97),
        &active_snapshot,
        &[key(1), key(2), key(3)],
    )
    .unwrap();
    assert_eq!(full.shares()[0].share(), first.shares()[0].share());
    assert_eq!(full.shares()[2].share(), first.shares()[1].share());
}

#[test]
fn every_small_signer_subset_matches_an_independent_direct_product_oracle() {
    let active_snapshot = snapshot(&[(1, 1), (2, 2), (3, 3)]);
    let weights = [(1_u8, 1_u128), (2, 2), (3, 3)];
    let total_weight = 6_u128;

    for pool in 0_u128..=64 {
        for mask in 0_u8..8 {
            let signer_keys = weights
                .iter()
                .rev()
                .filter(|(marker, _)| mask & (1 << (*marker - 1)) != 0)
                .map(|(marker, _)| key(*marker))
                .collect::<Vec<_>>();
            let allocation = project_fee_funded_validator_allocation(
                NaoAtoms::new(pool),
                &active_snapshot,
                &signer_keys,
            )
            .unwrap();
            let expected = weights
                .iter()
                .filter(|(marker, _)| mask & (1 << (*marker - 1)) != 0)
                .map(|(marker, weight)| (key(*marker), pool * *weight / total_weight))
                .collect::<Vec<_>>();
            let actual = allocation
                .shares()
                .iter()
                .map(|entry| (entry.consensus_key(), entry.share().atoms()))
                .collect::<Vec<_>>();
            let assigned = expected.iter().map(|(_, share)| *share).sum::<u128>();

            assert_eq!(actual, expected, "pool={pool}, mask={mask}");
            assert_eq!(
                allocation.unassigned().atoms(),
                pool - assigned,
                "pool={pool}, mask={mask}"
            );
        }
    }
}

#[test]
fn full_u128_allocation_conserves_every_atom_without_product_overflow() {
    let maximum = u128::MAX;
    let extreme_split = snapshot(&[(1, 1), (2, maximum - 1)]);
    let allocation = project_fee_funded_validator_allocation(
        NaoAtoms::new(maximum),
        &extreme_split,
        &[key(2), key(1)],
    )
    .unwrap();
    assert_eq!(allocation.shares()[0].share(), NaoAtoms::new(1));
    assert_eq!(allocation.shares()[1].share(), NaoAtoms::new(maximum - 1));
    assert_eq!(allocation.unassigned(), NaoAtoms::ZERO);

    let equal_split = snapshot(&[(1, 1), (2, 1)]);
    let allocation = project_fee_funded_validator_allocation(
        NaoAtoms::new(maximum),
        &equal_split,
        &[key(1), key(2)],
    )
    .unwrap();
    assert_eq!(allocation.shares()[0].share(), NaoAtoms::new(maximum / 2));
    assert_eq!(allocation.shares()[1].share(), NaoAtoms::new(maximum / 2));
    assert_eq!(allocation.unassigned(), NaoAtoms::new(1));
}

#[test]
fn partition_composition_matches_the_single_aggregate_pipeline() {
    let active_snapshot = snapshot(&[(1, 1), (2, 1)]);
    let partitions = [
        FeePartition::from_artifact_base_fee(NaoAtoms::new(5)),
        FeePartition::from_non_artifact_operation_fee(NaoAtoms::new(5)),
    ];
    let signers = [key(2), key(1)];
    let expected_pool = naome_economy::aggregate_validator_pool(&partitions).unwrap();
    let expected =
        project_fee_funded_validator_allocation(expected_pool, &active_snapshot, &signers).unwrap();
    let allocation = project_fee_funded_validator_allocation_from_partitions(
        &partitions,
        &active_snapshot,
        &signers,
    )
    .unwrap();

    assert_eq!(allocation, expected);
    assert_eq!(allocation.validator_pool(), NaoAtoms::new(2));
    assert_eq!(
        allocation
            .shares()
            .iter()
            .map(|share| (share.consensus_key(), share.share()))
            .collect::<Vec<_>>(),
        vec![(key(1), NaoAtoms::new(1)), (key(2), NaoAtoms::new(1))]
    );
    assert_eq!(allocation.unassigned(), NaoAtoms::ZERO);
}

#[test]
fn partition_composition_preserves_empty_and_full_u128_boundaries() {
    let empty_snapshot = snapshot(&[]);
    let empty =
        project_fee_funded_validator_allocation_from_partitions(&[], &empty_snapshot, &[]).unwrap();
    assert_eq!(empty.validator_pool(), NaoAtoms::ZERO);
    assert_eq!(empty.shares(), &[]);
    assert_eq!(empty.unassigned(), NaoAtoms::ZERO);

    let maximum_partition = FeePartition::from_artifact_base_fee(NaoAtoms::new(u128::MAX));
    let exact = [maximum_partition; 5];
    let full_weight = snapshot(&[(1, 1)]);
    let maximum =
        project_fee_funded_validator_allocation_from_partitions(&exact, &full_weight, &[key(1)])
            .unwrap();
    assert_eq!(maximum.validator_pool(), NaoAtoms::new(u128::MAX));
    assert_eq!(maximum.shares()[0].share(), NaoAtoms::new(u128::MAX));
    assert_eq!(maximum.unassigned(), NaoAtoms::ZERO);
}

#[test]
fn partition_composition_reports_aggregation_before_signer_errors() {
    let maximum_partition = FeePartition::from_artifact_base_fee(NaoAtoms::new(u128::MAX));
    let overflow = [maximum_partition; 6];
    let active_snapshot = snapshot(&[(1, 1)]);
    let duplicate_signers = [key(1), key(1)];

    let aggregation_error = project_fee_funded_validator_allocation_from_partitions(
        &overflow,
        &active_snapshot,
        &duplicate_signers,
    )
    .unwrap_err();
    assert_eq!(
        aggregation_error,
        ValidatorFeeAllocationFromPartitionsError::PoolAggregation(
            ValidatorPoolAggregationError::Overflow
        )
    );
    assert_eq!(
        aggregation_error.to_string(),
        "validator pool aggregation failed: validator pool total exceeds u128 capacity"
    );
    assert_standard_error(&aggregation_error);
    assert!(aggregation_error.source().is_some());

    let signer_error = project_fee_funded_validator_allocation_from_partitions(
        &[],
        &active_snapshot,
        &duplicate_signers,
    )
    .unwrap_err();
    assert_eq!(
        signer_error,
        ValidatorFeeAllocationFromPartitionsError::SignerList(
            AgreementSignerError::DuplicateSigner {
                consensus_key: key(1),
            }
        )
    );
    assert_eq!(
        signer_error.to_string(),
        format!(
            "validator signer list is invalid: agreement signer list repeats key {:?}",
            key(1)
        )
    );
    assert_standard_error(&signer_error);
    assert!(signer_error.source().is_some());
}
