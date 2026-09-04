use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::*;
use crate::MAX_ACTIVE_VALIDATORS;

fn key(byte: u8) -> ConsensusKey {
    ConsensusKey::from_bytes([byte; 32])
}

fn entry(byte: u8, weight: u128) -> ActiveAgreementEntry {
    ActiveAgreementEntry::new(key(byte), AgreementWeight::new(weight))
}

fn signed(value: i128) -> [u8; SIGNED_PRIORITY_BYTES] {
    encode_signed_i256(&BigInt::from(value)).unwrap()
}

fn snapshot(height: u64, round: u64, entries: &[ActiveAgreementEntry]) -> ActiveAgreementSnapshot {
    ActiveAgreementSnapshot::try_from_preselected(
        ConsensusPosition::new(ConsensusHeight::new(height), ConsensusRound::new(round)),
        entries,
    )
    .unwrap()
}

fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut bytes = [0_u8; N];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |value: u8| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid lowercase hexadecimal test vector"),
        };
        bytes[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    bytes
}

#[test]
fn fixed_set_and_priority_state_identity_layouts_have_independent_goldens() {
    let state = FixedProposerStateV0::try_from_preselected(&[entry(1, 1), entry(2, 3)]).unwrap();

    let mut set_preimage = Vec::new();
    set_preimage.extend_from_slice(b"naome:fixed-agreement-set:v0\0");
    set_preimage.extend_from_slice(&2_u16.to_be_bytes());
    set_preimage.extend_from_slice(&[1; 32]);
    set_preimage.extend_from_slice(&1_u128.to_be_bytes());
    set_preimage.extend_from_slice(&[2; 32]);
    set_preimage.extend_from_slice(&3_u128.to_be_bytes());
    assert_eq!(set_preimage.len(), 127);
    let set_digest: [u8; 32] = Sha256::digest(&set_preimage).into();
    assert_eq!(state.fixed_set_id().as_bytes(), &set_digest);
    assert_eq!(
        set_digest,
        hex_array("6d7ec3d2041ff9ed420b678baa7195690ea482883cb56020f5401280645a5b15")
    );

    let mut zero_preimage = Vec::new();
    zero_preimage.extend_from_slice(b"naome:proposer-priority-state:v0\0");
    zero_preimage.extend_from_slice(&set_digest);
    zero_preimage.extend_from_slice(&2_u16.to_be_bytes());
    zero_preimage.extend_from_slice(&[0; 32]);
    zero_preimage.extend_from_slice(&[0; 32]);
    assert_eq!(zero_preimage.len(), 131);
    let zero_digest: [u8; 32] = Sha256::digest(&zero_preimage).into();
    assert_eq!(state.id().as_bytes(), &zero_digest);
    assert_eq!(
        zero_digest,
        hex_array("888bf6b1a006afc02b97e969fb677beaf06051582cab6b7243c8effa8fe7ab39")
    );

    let (_, successor) = state.select_next().unwrap();
    let mut post_step_preimage = Vec::new();
    post_step_preimage.extend_from_slice(b"naome:proposer-priority-state:v0\0");
    post_step_preimage.extend_from_slice(&set_digest);
    post_step_preimage.extend_from_slice(&2_u16.to_be_bytes());
    let mut positive_one = [0; 32];
    positive_one[31] = 1;
    post_step_preimage.extend_from_slice(&positive_one);
    post_step_preimage.extend_from_slice(&[u8::MAX; 32]);
    assert_eq!(post_step_preimage.len(), 131);
    let post_step_digest: [u8; 32] = Sha256::digest(&post_step_preimage).into();
    assert_eq!(successor.id().as_bytes(), &post_step_digest);
    assert_eq!(
        post_step_digest,
        hex_array("4776d8a1d03e5cbffd90d1c7434886ca8202aaaf397e68002275c84b269af31e")
    );
}

#[test]
fn weighted_sequence_matches_the_reference_schedule() {
    let mut state =
        FixedProposerStateV0::try_from_preselected(&[entry(1, 1), entry(2, 3)]).unwrap();

    let expected = [
        (key(2), vec![signed(1), signed(-1)]),
        (key(1), vec![signed(-2), signed(2)]),
        (key(2), vec![signed(-1), signed(1)]),
        (key(2), vec![signed(0), signed(0)]),
    ];
    for (expected_proposer, expected_priorities) in expected {
        let (proposer, successor) = state.select_next().unwrap();
        assert_eq!(proposer, expected_proposer);
        assert_eq!(
            successor.canonical_priorities().unwrap(),
            expected_priorities
        );
        state = successor;
    }
}

#[test]
fn equal_priority_ties_use_the_lowest_consensus_key() {
    let state = FixedProposerStateV0::try_from_preselected(&[entry(9, 1), entry(3, 1)]).unwrap();
    let (proposer, successor) = state.select_next().unwrap();

    assert_eq!(proposer, key(3));
    assert_eq!(
        successor.canonical_priorities().unwrap(),
        vec![signed(-1), signed(1)]
    );
}

#[test]
fn input_order_does_not_change_set_state_or_schedule() {
    let entries = [entry(1, 2), entry(2, 5), entry(3, 3)];
    let reversed = [entry(3, 3), entry(2, 5), entry(1, 2)];
    let mut left = FixedProposerStateV0::try_from_preselected(&entries).unwrap();
    let mut right = FixedProposerStateV0::try_from_preselected(&reversed).unwrap();

    assert_eq!(left.fixed_set_id(), right.fixed_set_id());
    assert_eq!(left.id(), right.id());
    for _ in 0..64 {
        let (left_proposer, left_successor) = left.select_next().unwrap();
        let (right_proposer, right_successor) = right.select_next().unwrap();
        assert_eq!(left_proposer, right_proposer);
        assert_eq!(left_successor.id(), right_successor.id());
        left = left_successor;
        right = right_successor;
    }
}

#[test]
fn empty_fixed_set_halts_proposer_selection() {
    let state = FixedProposerStateV0::try_from_preselected(&[]).unwrap();
    assert_eq!(
        state.select_next(),
        Err(ProposerSelectionError::NoActiveValidators)
    );
}

#[test]
fn one_maximum_weight_validator_remains_stable() {
    let state = FixedProposerStateV0::try_from_preselected(&[entry(1, u128::MAX)]).unwrap();
    let (proposer, successor) = state.select_next().unwrap();

    assert_eq!(proposer, key(1));
    assert_eq!(successor.canonical_priorities().unwrap(), vec![signed(0)]);
    assert_eq!(successor.id(), state.id());
}

#[test]
fn maximum_validator_count_is_scheduled_without_overflow() {
    let entries = (0..MAX_ACTIVE_VALIDATORS)
        .map(|index| {
            let mut bytes = [0_u8; 32];
            bytes[30..].copy_from_slice(&(index as u16).to_be_bytes());
            ActiveAgreementEntry::new(ConsensusKey::from_bytes(bytes), AgreementWeight::new(1))
        })
        .collect::<Vec<_>>();
    let mut state = FixedProposerStateV0::try_from_preselected(&entries).unwrap();

    for expected in entries {
        let (proposer, successor) = state.select_next().unwrap();
        assert_eq!(proposer, expected.consensus_key());
        state = successor;
    }
    assert_eq!(state.canonical_priorities().unwrap(), vec![signed(0); 256]);
}

#[test]
fn normalization_rescales_only_above_twice_total_weight() {
    let weight = AgreementWeight::new(10);
    let mut at_threshold = vec![BigInt::from(-10), BigInt::from(10)];
    normalize_priorities(&mut at_threshold, weight).unwrap();
    assert_eq!(at_threshold, vec![BigInt::from(-10), BigInt::from(10)]);

    let mut above_threshold = vec![BigInt::from(-11), BigInt::from(10)];
    normalize_priorities(&mut above_threshold, weight).unwrap();
    assert_eq!(above_threshold, vec![BigInt::from(-5), BigInt::from(5)]);
}

#[test]
fn normalization_centers_on_the_floor_average() {
    let mut priorities = vec![BigInt::from(-2), BigInt::from(1), BigInt::from(0)];
    normalize_priorities(&mut priorities, AgreementWeight::new(10)).unwrap();

    assert_eq!(
        priorities,
        vec![BigInt::from(-1), BigInt::from(2), BigInt::from(1)]
    );
}

#[test]
fn signed_i256_encoding_has_exact_twos_complement_boundaries() {
    assert_eq!(encode_signed_i256(&BigInt::from(0)).unwrap(), [0; 32]);
    assert_eq!(encode_signed_i256(&BigInt::from(1)).unwrap()[31], 1);
    assert_eq!(
        encode_signed_i256(&BigInt::from(-1)).unwrap(),
        [u8::MAX; 32]
    );
    assert_eq!(
        encode_signed_i256(&BigInt::from(-256)).unwrap()[30..],
        [u8::MAX, 0]
    );

    let positive_limit = (BigInt::from(1_u8) << 255_usize) - 1_u8;
    let negative_limit: BigInt = -(BigInt::from(1_u8) << 255_usize);
    assert_eq!(encode_signed_i256(&positive_limit).unwrap()[0], 0x7f);
    assert_eq!(encode_signed_i256(&negative_limit).unwrap()[0], 0x80);
    assert_eq!(
        encode_signed_i256(&(positive_limit + 1_u8)),
        Err(ProposerSelectionError::PriorityOutOfRange)
    );
    assert_eq!(
        encode_signed_i256(&(negative_limit - 1_u8)),
        Err(ProposerSelectionError::PriorityOutOfRange)
    );
}

#[test]
fn small_weight_schedules_return_to_zero_with_exact_counts() {
    for first_weight in 1_u128..=5 {
        for second_weight in 1_u128..=5 {
            for third_weight in 1_u128..=5 {
                let weights = [first_weight, second_weight, third_weight];
                let period = weights.iter().sum::<u128>() as usize;
                let mut state = FixedProposerStateV0::try_from_preselected(&[
                    entry(1, first_weight),
                    entry(2, second_weight),
                    entry(3, third_weight),
                ])
                .unwrap();
                let mut counts = [0_u128; 3];
                for _ in 0..period {
                    let (proposer, successor) = state.select_next().unwrap();
                    counts[(proposer.as_bytes()[0] - 1) as usize] += 1;
                    state = successor;
                }
                assert_eq!(counts, weights);
                assert_eq!(state.canonical_priorities().unwrap(), vec![signed(0); 3]);
            }
        }
    }
}

#[test]
fn combined_rescale_and_negative_floor_vector_is_exact() {
    let fixed_set = FixedAgreementSetV0::try_from_preselected(&[
        entry(1, 1),
        entry(2, 1),
        entry(3, 1),
        entry(4, 2),
    ])
    .unwrap();
    let priorities = [-4, -4, 1, 7]
        .into_iter()
        .map(BigInt::from)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let state = FixedProposerStateV0 {
        id: derive_priority_state_id(fixed_set.id(), &priorities).unwrap(),
        fixed_set: Arc::new(fixed_set),
        priorities,
    };

    let (proposer, successor) = state.select_next().unwrap();
    assert_eq!(proposer, key(4));
    assert_eq!(
        successor.canonical_priorities().unwrap(),
        vec![signed(0), signed(0), signed(2), signed(1)]
    );
}

#[test]
fn each_step_normalizes_instead_of_reusing_one_batched_normalization() {
    let fixed_set = FixedAgreementSetV0::try_from_preselected(&[
        entry(1, 1),
        entry(2, 1),
        entry(3, 2),
        entry(4, 3),
    ])
    .unwrap();
    let priorities = [-6, -6, 8, 7]
        .into_iter()
        .map(BigInt::from)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let mut state = FixedProposerStateV0 {
        id: derive_priority_state_id(fixed_set.id(), &priorities).unwrap(),
        fixed_set: Arc::new(fixed_set),
        priorities,
    };

    let mut proposers = Vec::new();
    for _ in 0..3 {
        let (proposer, successor) = state.select_next().unwrap();
        proposers.push(proposer);
        state = successor;
    }
    assert_eq!(proposers, vec![key(3), key(4), key(3)]);
    assert_eq!(
        state.canonical_priorities().unwrap(),
        vec![signed(0), signed(0), signed(-2), signed(4)]
    );
}

#[test]
fn snapshot_transition_matches_the_mixed_membership_and_reweight_golden() {
    let fixed_set =
        FixedAgreementSetV0::try_from_preselected(&[entry(1, 2), entry(2, 3), entry(3, 5)])
            .unwrap();
    let priorities = [6, -1, -5]
        .into_iter()
        .map(BigInt::from)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let source = FixedProposerStateV0 {
        id: derive_priority_state_id(fixed_set.id(), &priorities).unwrap(),
        fixed_set: Arc::new(fixed_set),
        priorities,
    };
    let source_before = source.clone();
    let final_snapshot = snapshot(2, 0, &[entry(4, 1), entry(2, 7), entry(1, 2)]);

    let transitioned = source
        .transition_to_preselected_snapshot(&final_snapshot)
        .unwrap();

    assert_eq!(source, source_before);
    assert_eq!(
        transitioned.canonical_priorities().unwrap(),
        vec![signed(5), signed(2), signed(-6)]
    );
    assert_eq!(
        transitioned.fixed_set_id().as_bytes(),
        &hex_array("c55fe9d882faa3a47b162c959c1eebea546dae07f47ac37414e428357da8bc45")
    );
    assert_eq!(
        transitioned.id().as_bytes(),
        &hex_array("cb383dcbab9fe21db1fb0ad115252450bb66328ae59a969a6fa62f5df6cc4834")
    );
    assert_ne!(transitioned.fixed_set_id(), source.fixed_set_id());
    assert_ne!(transitioned.id(), source.id());

    let (proposer, successor) = transitioned.select_next().unwrap();
    assert_eq!(proposer, key(2));
    assert_eq!(
        successor.canonical_priorities().unwrap(),
        vec![signed(7), signed(-1), signed(-5)]
    );
}

#[test]
fn snapshot_transition_ignores_input_permutation_and_snapshot_position() {
    let mut source =
        FixedProposerStateV0::try_from_preselected(&[entry(1, 2), entry(2, 5)]).unwrap();
    for _ in 0..3 {
        source = source.select_next().unwrap().1;
    }

    let ordered = snapshot(2, 0, &[entry(1, 3), entry(2, 5), entry(3, 2)]);
    let permuted = snapshot(999, 42, &[entry(3, 2), entry(1, 3), entry(2, 5)]);
    let left = source.transition_to_preselected_snapshot(&ordered).unwrap();
    let right = source
        .transition_to_preselected_snapshot(&permuted)
        .unwrap();

    assert_eq!(left, right);
    assert_eq!(left.fixed_set_id(), right.fixed_set_id());
    assert_eq!(left.id(), right.id());
    assert_eq!(
        left.select_next().unwrap().0,
        right.select_next().unwrap().0
    );
}

#[test]
fn snapshot_transition_uses_exact_pre_removal_total_above_u128() {
    let mut source =
        FixedProposerStateV0::try_from_preselected(&[entry(1, 1), entry(2, u128::MAX - 1)])
            .unwrap();
    source = source.select_next().unwrap().1;
    assert_eq!(
        source.canonical_priorities().unwrap(),
        vec![signed(1), signed(-1)]
    );

    let final_snapshot = snapshot(2, 0, &[entry(1, u128::MAX - 1), entry(3, 1)]);
    let transitioned = source
        .transition_to_preselected_snapshot(&final_snapshot)
        .unwrap();
    let magnitude = (BigInt::from(1_u8) << 127_usize) + (BigInt::from(1_u8) << 124_usize) - 1_u8;

    assert_eq!(
        transitioned.canonical_priorities().unwrap(),
        vec![
            encode_signed_i256(&magnitude).unwrap(),
            encode_signed_i256(&-magnitude).unwrap(),
        ]
    );
}

#[test]
fn snapshot_transition_to_empty_publishes_only_the_existing_halt_state() {
    let mut source =
        FixedProposerStateV0::try_from_preselected(&[entry(1, 1), entry(2, 3)]).unwrap();
    source = source.select_next().unwrap().1;
    let source_before = source.clone();

    let halted = source
        .transition_to_preselected_snapshot(&snapshot(2, 0, &[]))
        .unwrap();

    assert_eq!(source, source_before);
    assert_eq!(
        halted.canonical_priorities().unwrap(),
        Vec::<[u8; 32]>::new()
    );
    assert_eq!(
        halted,
        FixedProposerStateV0::try_from_preselected(&[]).unwrap()
    );
    assert_eq!(
        halted.select_next(),
        Err(ProposerSelectionError::NoActiveValidators)
    );
}

#[test]
fn all_new_keys_receive_one_penalty_before_raw_key_tie_selection() {
    let source = FixedProposerStateV0::try_from_preselected(&[entry(9, 10)]).unwrap();
    let transitioned = source
        .transition_to_preselected_snapshot(&snapshot(2, 0, &[entry(3, 1), entry(1, 1)]))
        .unwrap();

    assert_eq!(
        transitioned.canonical_priorities().unwrap(),
        vec![signed(0), signed(0)]
    );
    assert_eq!(transitioned.select_next().unwrap().0, key(1));
}

#[test]
fn snapshot_transition_rejects_an_unrepresentable_source_priority() {
    let fixed_set = FixedAgreementSetV0::try_from_preselected(&[entry(1, 1)]).unwrap();
    let priorities = vec![BigInt::from(1_u8) << 255_usize].into_boxed_slice();
    let source = FixedProposerStateV0 {
        id: ProposerPriorityStateId([0; ProposerPriorityStateId::BYTE_LENGTH]),
        fixed_set: Arc::new(fixed_set),
        priorities,
    };

    assert_eq!(
        source.transition_to_preselected_snapshot(&snapshot(2, 0, &[entry(1, 1)])),
        Err(ProposerSelectionError::PriorityOutOfRange)
    );
}

#[test]
fn small_snapshot_transitions_match_an_independent_i128_model() {
    fn normalize(weights: &[i128], priorities: &mut [i128]) {
        let total = weights.iter().sum::<i128>();
        let spread = priorities.iter().max().unwrap() - priorities.iter().min().unwrap();
        if spread > 2 * total {
            let ratio = (spread + 2 * total - 1) / (2 * total);
            for priority in priorities.iter_mut() {
                *priority /= ratio;
            }
        }
        let average = priorities
            .iter()
            .sum::<i128>()
            .div_euclid(priorities.len() as i128);
        for priority in priorities {
            *priority -= average;
        }
    }

    let old_entries = [entry(1, 1), entry(2, 2), entry(3, 3)];
    let mut source = FixedProposerStateV0::try_from_preselected(&old_entries).unwrap();
    for _ in 0..7 {
        source = source.select_next().unwrap().1;
    }
    let old_priorities = source
        .canonical_priorities()
        .unwrap()
        .into_iter()
        .map(|bytes| i128::from_be_bytes(bytes[16..].try_into().unwrap()))
        .collect::<Vec<_>>();

    for mask in 1_u8..16 {
        let final_entries = (1_u8..=4)
            .filter(|key_byte| mask & (1 << (key_byte - 1)) != 0)
            .map(|key_byte| entry(key_byte, u128::from(key_byte % 3 + 1)))
            .rev()
            .collect::<Vec<_>>();
        let final_snapshot = snapshot(2, u64::from(mask), &final_entries);
        let mut expected_entries = final_snapshot.entries().to_vec();
        expected_entries.sort_unstable_by_key(|entry| entry.consensus_key());
        let final_weight = expected_entries
            .iter()
            .map(|entry| entry.agreement_weight().units() as i128)
            .sum::<i128>();
        let removed_weight = old_entries
            .iter()
            .filter(|old| {
                !expected_entries
                    .iter()
                    .any(|new| new.consensus_key() == old.consensus_key())
            })
            .map(|entry| entry.agreement_weight().units() as i128)
            .sum::<i128>();
        let updated_total = final_weight + removed_weight;
        let joiner_priority = -(updated_total + updated_total.div_euclid(8));
        let mut expected_priorities = expected_entries
            .iter()
            .map(|new_entry| {
                old_entries
                    .iter()
                    .position(|old| old.consensus_key() == new_entry.consensus_key())
                    .map_or(joiner_priority, |index| old_priorities[index])
            })
            .collect::<Vec<_>>();
        let weights = expected_entries
            .iter()
            .map(|entry| entry.agreement_weight().units() as i128)
            .collect::<Vec<_>>();
        normalize(&weights, &mut expected_priorities);

        let transitioned = source
            .transition_to_preselected_snapshot(&final_snapshot)
            .unwrap();
        assert_eq!(
            transitioned.canonical_priorities().unwrap(),
            expected_priorities
                .into_iter()
                .map(signed)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn maximum_count_can_sum_to_maximum_total_weight() {
    let mut entries = (0..MAX_ACTIVE_VALIDATORS)
        .map(|index| {
            let mut bytes = [0_u8; 32];
            bytes[30..].copy_from_slice(&(index as u16).to_be_bytes());
            ActiveAgreementEntry::new(ConsensusKey::from_bytes(bytes), AgreementWeight::new(1))
        })
        .collect::<Vec<_>>();
    entries[MAX_ACTIVE_VALIDATORS - 1] = ActiveAgreementEntry::new(
        entries[MAX_ACTIVE_VALIDATORS - 1].consensus_key(),
        AgreementWeight::new(u128::MAX - (MAX_ACTIVE_VALIDATORS as u128 - 1)),
    );
    let state = FixedProposerStateV0::try_from_preselected(&entries).unwrap();

    let (proposer, successor) = state.select_next().unwrap();
    assert_eq!(proposer, entries[MAX_ACTIVE_VALIDATORS - 1].consensus_key());
    let priorities = successor.canonical_priorities().unwrap();
    assert_eq!(
        priorities[..MAX_ACTIVE_VALIDATORS - 1],
        vec![signed(1); 255]
    );
    assert_eq!(priorities[MAX_ACTIVE_VALIDATORS - 1], signed(-255));
}

#[test]
fn small_reachable_states_match_an_independent_i128_model() {
    fn step(weights: &[i128], priorities: &mut [i128]) -> usize {
        for (priority, weight) in priorities.iter_mut().zip(weights) {
            *priority += weight;
        }
        let mut winner = 0;
        for index in 1..priorities.len() {
            if priorities[index] > priorities[winner] {
                winner = index;
            }
        }
        priorities[winner] -= weights.iter().sum::<i128>();
        winner
    }

    for first in 1_u128..=4 {
        for second in 1_u128..=4 {
            for third in 1_u128..=4 {
                let mut state = FixedProposerStateV0::try_from_preselected(&[
                    entry(1, first),
                    entry(2, second),
                    entry(3, third),
                ])
                .unwrap();
                let weights = [first as i128, second as i128, third as i128];
                let mut model = [0_i128; 3];
                for _ in 0..128 {
                    let expected_winner = step(&weights, &mut model);
                    let (proposer, successor) = state.select_next().unwrap();
                    assert_eq!(proposer, key(expected_winner as u8 + 1));
                    assert_eq!(
                        successor.canonical_priorities().unwrap(),
                        model.into_iter().map(signed).collect::<Vec<_>>()
                    );
                    state = successor;
                }
            }
        }
    }
}
