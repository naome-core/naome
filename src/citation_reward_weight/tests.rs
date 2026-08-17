use naome_consensus::{ConsensusEpoch, ConsensusHeight};
use naome_economy::{KnowledgeWeight, NaoAtoms};

use super::live_citation_reward_weight;

const REFERENCE_HEIGHTS_PER_EPOCH: u64 = 8_192;
const REFERENCE_MATURITY_DELAY_EPOCHS: u64 = 2;
const REFERENCE_BATCH_LIFETIME_EPOCHS: u64 = 730;

const CONSTANT_EARNED_EPOCH: ConsensusEpoch = match ConsensusHeight::new(1).non_genesis_epoch() {
    Some(epoch) => epoch,
    None => panic!("height one must project to epoch zero"),
};
const CONSTANT_ACTIVATION_EPOCH: ConsensusEpoch =
    match ConsensusHeight::new(16_385).non_genesis_epoch() {
        Some(epoch) => epoch,
        None => panic!("height 16,385 must project to epoch two"),
    };
const CONSTANT_LIVE_WEIGHT: KnowledgeWeight = live_citation_reward_weight(
    NaoAtoms::new(7),
    CONSTANT_EARNED_EPOCH,
    CONSTANT_ACTIVATION_EPOCH,
);

fn projected_epoch(value: u64) -> ConsensusEpoch {
    let height = value
        .checked_mul(REFERENCE_HEIGHTS_PER_EPOCH)
        .and_then(|height| height.checked_add(1))
        .expect("test epoch must have a representable first height");
    ConsensusHeight::new(height)
        .non_genesis_epoch()
        .expect("positive test height must project to an epoch")
}

#[test]
fn chronology_returns_zero_until_two_epochs_then_activates() {
    let reward = NaoAtoms::new(730);
    let earned_epoch = projected_epoch(3);

    for (evaluated, expected) in [(2, 0), (3, 0), (4, 0), (5, 730), (6, 729)] {
        assert_eq!(
            live_citation_reward_weight(reward, earned_epoch, projected_epoch(evaluated)),
            KnowledgeWeight::new(expected),
            "evaluated={evaluated}, expected={expected}"
        );
    }
}

#[test]
fn activation_and_decay_cover_exact_boundaries_and_full_atom_range() {
    let earned_epoch = projected_epoch(0);
    let maximum = u128::MAX;

    for (reward, elapsed, expected) in [
        (0_u128, 2_u64, 0_u128),
        (1, 2, 1),
        (730, 2, 730),
        (730, 3, 729),
        (730, 367, 365),
        (730, 731, 1),
        (730, 732, 0),
        (730, 733, 0),
        (maximum, 2, maximum),
        (
            maximum,
            3,
            maximum - (maximum / 730 + u128::from(maximum % 730 != 0)),
        ),
        (maximum, 367, maximum / 2),
        (maximum, 731, maximum / 730),
        (maximum, 732, 0),
    ] {
        assert_eq!(
            live_citation_reward_weight(
                NaoAtoms::new(reward),
                earned_epoch,
                projected_epoch(elapsed),
            ),
            KnowledgeWeight::new(expected),
            "reward={reward}, elapsed={elapsed}"
        );
    }
}

#[test]
fn bounded_domain_matches_independent_direct_product_oracle() {
    for earned in 1_u64..=16 {
        assert_eq!(
            live_citation_reward_weight(
                NaoAtoms::new(u128::MAX),
                projected_epoch(earned),
                projected_epoch(earned - 1),
            ),
            KnowledgeWeight::ZERO,
            "earned={earned}, reverse order"
        );
    }

    for earned in 0_u64..=16 {
        let earned_epoch = projected_epoch(earned);

        for elapsed in 0_u64..=733 {
            let evaluated_epoch = projected_epoch(earned + elapsed);
            let age = elapsed.saturating_sub(REFERENCE_MATURITY_DELAY_EPOCHS);

            for reward in 0_u128..=64 {
                let expected = if elapsed < REFERENCE_MATURITY_DELAY_EPOCHS
                    || age >= REFERENCE_BATCH_LIFETIME_EPOCHS
                {
                    0
                } else {
                    reward * u128::from(REFERENCE_BATCH_LIFETIME_EPOCHS - age)
                        / u128::from(REFERENCE_BATCH_LIFETIME_EPOCHS)
                };

                assert_eq!(
                    live_citation_reward_weight(
                        NaoAtoms::new(reward),
                        earned_epoch,
                        evaluated_epoch,
                    ),
                    KnowledgeWeight::new(expected),
                    "reward={reward}, earned={earned}, elapsed={elapsed}"
                );
            }
        }
    }
}

#[test]
fn terminal_epochs_activate_without_addition_overflow() {
    const TERMINAL_EPOCH: u64 = 2_251_799_813_685_247;

    let evaluated_epoch = ConsensusHeight::new(u64::MAX)
        .non_genesis_epoch()
        .expect("maximum height must project to the terminal epoch");
    assert_eq!(evaluated_epoch.value(), TERMINAL_EPOCH);

    assert_eq!(
        live_citation_reward_weight(
            NaoAtoms::new(11),
            projected_epoch(TERMINAL_EPOCH - 2),
            evaluated_epoch,
        ),
        KnowledgeWeight::new(11)
    );
    for earned_epoch in [projected_epoch(TERMINAL_EPOCH - 1), evaluated_epoch] {
        assert_eq!(
            live_citation_reward_weight(NaoAtoms::new(11), earned_epoch, evaluated_epoch),
            KnowledgeWeight::ZERO
        );
    }
}

#[test]
fn public_projection_is_const_evaluable() {
    assert_eq!(CONSTANT_EARNED_EPOCH.value(), 0);
    assert_eq!(CONSTANT_ACTIVATION_EPOCH.value(), 2);
    assert_eq!(CONSTANT_LIVE_WEIGHT, KnowledgeWeight::new(7));
}

#[test]
fn live_weight_never_increases_after_activation() {
    let reward = NaoAtoms::new(u128::MAX);
    let earned_epoch = projected_epoch(0);
    let mut previous = KnowledgeWeight::new(u128::MAX);

    for elapsed in 2_u64..=733 {
        let current = live_citation_reward_weight(reward, earned_epoch, projected_epoch(elapsed));
        assert!(
            current <= previous,
            "elapsed={elapsed}, current={current:?}, previous={previous:?}"
        );
        previous = current;
    }

    assert_eq!(previous, KnowledgeWeight::ZERO);
}
