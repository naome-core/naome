//! Independent bounded configuration enumeration and integer oracles.
//! This module deliberately has no production protocol imports.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::model::{Exploration, Model, Rules, explore_with_limit, protocol_explorations};

#[derive(Clone, Copy, Debug)]
pub(super) struct Profile {
    pub weights: [u128; 4],
    pub faulty: u8,
    pub proposers: [u8; 3],
    pub quorums: u16,
}

impl Profile {
    pub fn small(weights: [u8; 4], faulty: u8) -> Self {
        let total: u16 = weights.iter().map(|&w| u16::from(w)).sum();
        assert!(weights.iter().all(|&w| (1..=9).contains(&w)));
        assert!(3 * u16::from(weights[usize::from(faulty)]) < total);
        let mut quorums = 0;
        for mask in 0..16 {
            let signed: u16 = weights
                .iter()
                .enumerate()
                .filter(|&(actor, _)| mask & (1 << actor) != 0)
                .map(|(_, &w)| u16::from(w))
                .sum();
            quorums |= u16::from(3 * signed > 2 * total) << mask;
        }
        Self {
            weights: weights.map(u128::from),
            faulty,
            proposers: schedule(weights),
            quorums,
        }
    }

    pub fn model(self) -> Model {
        Model {
            faulty: self.faulty,
            proposers: self.proposers,
            quorums: self.quorums,
            rules: Rules::Protocol,
        }
    }

    pub fn scaled(self) -> Self {
        let total: u128 = self.weights.iter().sum();
        let factor = u128::MAX / total;
        let weights = self.weights.map(|w| w * factor);
        assert_eq!(wide_quorums(weights), self.quorums);
        // The small oracle asserts that all three pre-step normalizations are
        // identity. Common positive scaling therefore preserves this schedule.
        Self { weights, ..self }
    }
}

fn schedule(weights: [u8; 4]) -> [u8; 3] {
    let total: i16 = weights.iter().map(|&w| i16::from(w)).sum();
    let mut priorities = [0_i16; 4];
    std::array::from_fn(|_| {
        let spread = priorities.iter().max().unwrap() - priorities.iter().min().unwrap();
        let divisor = if spread > 2 * total {
            (spread + 2 * total - 1) / (2 * total)
        } else {
            1
        };
        let rescaled = priorities.map(|p| p / divisor); // truncation toward zero
        let average = rescaled.iter().sum::<i16>().div_euclid(4);
        let normalized = rescaled.map(|p| p - average);
        assert_eq!(
            normalized, priorities,
            "three-round scaling argument does not apply"
        );
        priorities = normalized;
        for (priority, &weight) in priorities.iter_mut().zip(&weights) {
            *priority += i16::from(weight);
        }
        let proposer = (0..4)
            .max_by_key(|&actor| (priorities[actor], std::cmp::Reverse(actor)))
            .unwrap();
        priorities[proposer] -= total;
        proposer as u8
    })
}

// Widen by repeated addition and explicit carry, independently of production's
// division/remainder threshold arithmetic. At most three u128 limbs are added.
pub(super) fn multiple(value: u128, count: u8) -> (u8, u128) {
    let mut high = 0;
    let mut low = 0_u128;
    for _ in 0..count {
        let (sum, carry) = low.overflowing_add(value);
        low = sum;
        high += u8::from(carry);
    }
    (high, low)
}

pub(super) fn wide_quorums(weights: [u128; 4]) -> u16 {
    let total = weights
        .iter()
        .try_fold(0_u128, |sum, &w| sum.checked_add(w))
        .unwrap();
    let mut table = 0;
    for mask in 0..16 {
        let signed: u128 = weights
            .iter()
            .enumerate()
            .filter(|&(actor, _)| mask & (1 << actor) != 0)
            .map(|(_, &w)| w)
            .sum();
        table |= u16::from(multiple(signed, 3) > multiple(total, 2)) << mask;
    }
    table
}

pub(super) fn boundary_profile() -> Profile {
    let k = u128::MAX / 3;
    let weights = [2 * k - 1, 1, 1, k - 1];
    assert_eq!(weights.iter().sum::<u128>(), u128::MAX);
    let quorums = wide_quorums(weights);
    assert_eq!(quorums & (1 << 1), 0); // 2k-1, one unit below the boundary
    assert_eq!(quorums & (1 << 3), 0); // 2k, exactly two thirds
    assert_ne!(quorums & (1 << 7), 0); // 2k+1, one unit above
    // From zero, the three post-increment maxima select 0,3,0. All
    // pre-step sums are zero and spreads stay below twice the total.
    Profile {
        weights,
        faulty: 1,
        proposers: [0, 3, 0],
        quorums,
    }
}

type Signature = (u8, [u8; 3]);

fn signature(profile: Profile, canonical_to_actual: [u8; 4]) -> Signature {
    assert_eq!(canonical_to_actual[3], profile.faulty);
    let mut table = 0_u8;
    for subset in 0..8 {
        let mut actual = 1 << profile.faulty;
        for (canonical, &actor) in canonical_to_actual.iter().take(3).enumerate() {
            if subset & (1 << canonical) != 0 {
                actual |= 1 << actor;
            }
        }
        table |= u8::from(profile.quorums & (1 << actual) != 0) << subset;
    }
    let schedule = profile.proposers.map(|actor| {
        canonical_to_actual
            .iter()
            .position(|&a| a == actor)
            .unwrap() as u8
    });
    (table, schedule)
}

fn canonical(profile: Profile) -> (Signature, [u8; 4]) {
    let honest = (0..4).filter(|&a| a != profile.faulty).collect::<Vec<_>>();
    let permutations = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    permutations
        .map(|p| {
            let mapping = [honest[p[0]], honest[p[1]], honest[p[2]], profile.faulty];
            (signature(profile, mapping), mapping)
        })
        .into_iter()
        .min()
        .unwrap()
}

pub(super) fn representatives() -> &'static [Profile] {
    static PROFILES: OnceLock<Vec<Profile>> = OnceLock::new();
    PROFILES.get_or_init(|| {
        let mut representatives = Vec::<Profile>::new();
        let mut classes = BTreeMap::new();
        let mut covered = 0;
        for a in 1..=9 {
            for b in 1..=9 {
                for c in 1..=9 {
                    for d in 1..=9 {
                        let weights = [a, b, c, d];
                        let total: u16 = weights.iter().map(|&w| u16::from(w)).sum();
                        for faulty in 0..4 {
                            if 3 * u16::from(weights[usize::from(faulty)]) >= total {
                                continue;
                            }
                            let profile = Profile::small(weights, faulty);
                            let (key, mapping) = canonical(profile);
                            let index = *classes.entry(key).or_insert_with(|| {
                                representatives.push(profile);
                                representatives.len() - 1
                            });
                            let (representative_key, representative_mapping) =
                                canonical(representatives[index]);
                            // Check the full eight-subset truth table and complete schedule
                            // under an explicit bijection for every eligible input.
                            assert_eq!(
                                signature(profile, mapping),
                                signature(representatives[index], representative_mapping)
                            );
                            assert_eq!(key, representative_key);
                            covered += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(covered, 19_164);
        assert_eq!(representatives.len(), 19);
        representatives
    })
}

pub(super) fn explorations() -> &'static [Exploration] {
    static REPORTS: OnceLock<Vec<Exploration>> = OnceLock::new();
    REPORTS.get_or_init(|| {
        representatives()
            .iter()
            .map(|profile| {
                if profile.weights == [1; 4] {
                    protocol_explorations()[usize::from(profile.faulty)].clone()
                } else {
                    let report = explore_with_limit(profile.model(), 5_000_000);
                    eprintln!(
                        "explored {profile:?}: states={}, transitions={}",
                        report.states, report.transitions
                    );
                    report
                }
            })
            .collect()
    })
}

#[test]
fn independent_weight_and_schedule_boundaries() {
    assert_eq!(schedule([1; 4]), [0, 1, 2]);
    assert_eq!(schedule([1, 1, 1, 6]), [3, 3, 0]);
    assert_eq!(schedule([9, 1, 1, 1]), [0, 0, 0]);
    let k = u128::MAX / 3;
    assert_eq!(multiple(u128::MAX, 2), (1, u128::MAX - 1));
    assert_eq!(multiple(2 * k - 1, 3), (1, u128::MAX - 4));
    assert_eq!(multiple(2 * k, 3), (1, u128::MAX - 1));
    assert_eq!(multiple(2 * k + 1, 3), (2, 1));
    boundary_profile();
    for profile in representatives() {
        assert_eq!(wide_quorums(profile.weights), profile.quorums);
        profile.scaled();
    }
}

#[test]
fn bounded_weighted_safety_exploration() {
    for (profile, report) in representatives().iter().zip(explorations()) {
        eprintln!(
            "weighted {profile:?}: states={}, transitions={}, coverage={:?}",
            report.states,
            report.transitions,
            report.witnesses.keys()
        );
        assert!(
            report.counterexample.is_none(),
            "weighted safety counterexample: {profile:?} {:?}",
            report.counterexample
        );
        for label in ["certificate_a", "certificate_b"] {
            assert!(
                report.witnesses.contains_key(label),
                "vacuous weighted coverage: {profile:?} {label}"
            );
        }
    }
}
