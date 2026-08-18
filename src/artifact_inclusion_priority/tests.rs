use std::cmp::Ordering;

use naome_economy::NaoAtoms;
use naome_proof::ArtifactId;

use super::ArtifactInclusionPriority;

const CONSTANT_PRIORITY: ArtifactInclusionPriority =
    ArtifactInclusionPriority::new(ArtifactId::from_bytes([0x11; 32]), NaoAtoms::new(7));

fn priority(id_marker: u8, bid: u128) -> ArtifactInclusionPriority {
    ArtifactInclusionPriority::new(ArtifactId::from_bytes([id_marker; 32]), NaoAtoms::new(bid))
}

#[test]
fn public_value_is_const_evaluable_and_preserves_inputs() {
    assert_eq!(
        CONSTANT_PRIORITY.artifact_id(),
        ArtifactId::from_bytes([0x11; 32])
    );
    assert_eq!(CONSTANT_PRIORITY.inclusion_bid(), NaoAtoms::new(7));
}

#[test]
fn higher_bid_ranks_ahead_across_zero_and_full_u128_boundaries() {
    for (lower, higher) in [(0, 1), (1, 2), (u128::MAX - 1, u128::MAX)] {
        let lower_priority = priority(0x00, lower);
        let higher_priority = priority(0xff, higher);

        assert_eq!(higher_priority.cmp(&lower_priority), Ordering::Greater);
        assert_eq!(lower_priority.cmp(&higher_priority), Ordering::Less);
    }
}

#[test]
fn equal_bid_ranks_lower_artifact_id_ahead() {
    let lower_id = priority(0x00, 11);
    let higher_id = priority(0xff, 11);

    assert_eq!(lower_id.cmp(&higher_id), Ordering::Greater);
    assert_eq!(higher_id.cmp(&lower_id), Ordering::Less);
    assert_eq!(lower_id.cmp(&lower_id), Ordering::Equal);
}

#[test]
fn ordering_is_total_and_transitive_over_literal_domain() {
    let values = [
        priority(0x00, 0),
        priority(0x01, 0),
        priority(0xff, 0),
        priority(0x00, 1),
        priority(0x01, 1),
        priority(0xff, 1),
        priority(0x00, u128::MAX),
        priority(0xff, u128::MAX),
    ];

    for left in &values {
        for right in &values {
            assert_eq!(left.cmp(right), right.cmp(left).reverse());

            for third in &values {
                if left >= right && right >= third {
                    assert!(
                        left >= third,
                        "left={left:?}, right={right:?}, third={third:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn every_arrival_permutation_has_the_same_highest_priority() {
    let low_bid = priority(0x00, 4);
    let high_id_tie = priority(0xff, 9);
    let expected = priority(0x01, 9);

    for arrival in [
        [low_bid, high_id_tie, expected],
        [low_bid, expected, high_id_tie],
        [high_id_tie, low_bid, expected],
        [high_id_tie, expected, low_bid],
        [expected, low_bid, high_id_tie],
        [expected, high_id_tie, low_bid],
    ] {
        assert_eq!(arrival.into_iter().max(), Some(expected));
    }
}
