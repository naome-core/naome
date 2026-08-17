use std::error::Error;

use naome_consensus::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementWeight, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusRound,
};
use naome_economy::{FeePartition, NaoAtoms};

use super::{ValidatorFeeShareError, project_fee_funded_validator_share};

fn key(marker: u8) -> ConsensusKey {
    ConsensusKey::from_bytes([marker; 32])
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
