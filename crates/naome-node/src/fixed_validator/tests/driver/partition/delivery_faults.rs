//! Reproducible logical-time delivery faults over real anchored publications.
use super::*;

#[derive(Clone, Copy, Debug)]
struct Policy {
    duplicate: bool,
    reorder: bool,
    delay: bool,
    drop_precommits: bool,
}

struct Scheduled {
    at: u64,
    order: u64,
    to: usize,
    envelope: Envelope,
}

pub(super) struct Delivery {
    policy: Policy,
    random: u64,
    tick: u64,
    ordinal: u64,
    pending: Vec<Scheduled>,
    lost: Vec<(usize, Envelope)>,
    duplicated: usize,
    delayed: usize,
    reordered: usize,
    trace: Vec<(u64, u64, usize)>,
}

impl Delivery {
    fn new(policy: Policy, seed: u64) -> Self {
        Self {
            policy,
            random: seed,
            tick: 0,
            ordinal: 0,
            pending: Vec::new(),
            lost: Vec::new(),
            duplicated: 0,
            delayed: 0,
            reordered: 0,
            trace: Vec::new(),
        }
    }

    fn next_random(&mut self) -> u64 {
        // A fully specified test scheduler, never a consensus randomness source.
        self.random ^= self.random << 13;
        self.random ^= self.random >> 7;
        self.random ^= self.random << 17;
        self.random
    }

    pub(super) fn enqueue(&mut self, to: usize, envelope: Envelope) {
        if self.policy.drop_precommits
            && matches!(
                envelope.wire,
                Wire::Vote {
                    role: ConsensusVoteRole::Precommit,
                    ..
                }
            )
        {
            self.lost.push((to, envelope));
            return;
        }
        let delay = if self.policy.delay {
            self.delayed += 1;
            1 + self.next_random() % 7
        } else {
            1
        };
        self.schedule(to, envelope.clone(), delay);
        if self.policy.duplicate {
            self.duplicated += 1;
            self.schedule(to, envelope, delay + 2);
        }
    }

    fn schedule(&mut self, to: usize, envelope: Envelope, delay: u64) {
        assert!(
            self.pending.len() < 8192,
            "fault schedule exceeded explicit pending limit"
        );
        self.ordinal += 1;
        let order = if self.policy.reorder {
            self.next_random()
        } else {
            self.ordinal
        };
        self.pending.push(Scheduled {
            at: self.tick + delay,
            order,
            to,
            envelope,
        });
    }

    pub(super) fn next_wave(&mut self) -> Vec<(usize, Envelope)> {
        let Some(next) = self.pending.iter().map(|item| item.at).min() else {
            return Vec::new();
        };
        self.tick = next;
        let mut wave = Vec::new();
        let mut index = 0;
        while index < self.pending.len() {
            if self.pending[index].at == next {
                wave.push(self.pending.remove(index));
            } else {
                index += 1;
            }
        }
        let original = wave.iter().map(|item| item.order).collect::<Vec<_>>();
        wave.sort_by_key(|item| item.order);
        if wave.iter().map(|item| item.order).collect::<Vec<_>>() != original {
            self.reordered += 1;
        }
        wave.into_iter()
            .map(|item| {
                self.trace.push((item.at, item.order, item.to));
                (item.to, item.envelope)
            })
            .collect()
    }
}

fn run_faults(weights: &'static [u16], policy: Policy, seed: u64) -> Vec<(u64, u64, usize)> {
    let scenario = Scenario {
        name: "delivery-faults",
        weights,
        groups: [0; 4],
        cut: Cut::Cold,
        winners: 0b1111,
    };
    let mut trace = None;
    with_nodes(scenario, |scopes, fixture, keys, layouts| {
        let mut sim = Simulation::new(scopes, fixture, keys, layouts, scenario, false);
        sim.fault_delivery = Some(Delivery::new(policy, seed));
        sim.settle(0, FixedValidatorLockPhaseV0::Proposal);
        sim.round(0, None);
        if policy.drop_precommits {
            assert_eq!(sim.selected, [None; 4]);
            assert!(sim.received.iter().all(BTreeMap::is_empty));
            sim.check_history();
            let delivery = sim.fault_delivery.as_mut().unwrap();
            assert!(!delivery.lost.is_empty());
            delivery.policy.drop_precommits = false;
            // Explicit sender replay of its original signed bytes, after a
            // checked no-finality prefix. The simulator creates no new vote.
            let originals = std::mem::take(&mut delivery.lost);
            for (to, envelope) in originals {
                sim.enqueue(to, envelope);
            }
            sim.settle(0, FixedValidatorLockPhaseV0::Precommit);
        }
        assert_eq!(sim.selected, [Some(sim.values[0].ancestry_id()); 4]);
        sim.check_history();
        let delivery = sim.fault_delivery.as_ref().unwrap();
        assert!(delivery.pending.is_empty());
        assert!(!delivery.trace.is_empty());
        assert!(
            delivery.tick <= 100,
            "logical time exceeded the documented bound"
        );
        if policy.duplicate {
            assert!(delivery.duplicated > 0);
            assert!(sim.duplicates + sim.late_rejections > 0);
        }
        if policy.delay {
            assert!(delivery.delayed > 0);
            assert!(delivery.tick > 3);
        }
        if policy.reorder {
            assert!(delivery.reordered > 0);
        }
        assert_eq!(sim.published.len(), 8);
        eprintln!(
            "faults={policy:?} seed={seed} weights={weights:?} logical_ticks={} deliveries={} duplicates={} late_rejections={} reorder_waves={}",
            delivery.tick, sim.deliveries, sim.duplicates, sim.late_rejections, delivery.reordered
        );
        trace = Some(delivery.trace.clone());
    });
    trace.unwrap()
}

#[test]
fn deterministic_duplicate_reorder_delay_and_loss_schedules_preserve_recipient_quorum_and_finality()
{
    for weights in [&[1, 1, 1, 1][..], &[3, 2, 1, 1][..]] {
        for policy in [
            Policy {
                duplicate: true,
                reorder: false,
                delay: false,
                drop_precommits: false,
            },
            Policy {
                duplicate: false,
                reorder: true,
                delay: false,
                drop_precommits: false,
            },
            Policy {
                duplicate: false,
                reorder: false,
                delay: true,
                drop_precommits: false,
            },
            Policy {
                duplicate: false,
                reorder: false,
                delay: false,
                drop_precommits: true,
            },
            Policy {
                duplicate: true,
                reorder: true,
                delay: true,
                drop_precommits: true,
            },
        ] {
            for seed in [7, 29, 101] {
                let first = run_faults(weights, policy, seed);
                let repeated = run_faults(weights, policy, seed);
                assert_eq!(
                    first, repeated,
                    "identical seed must replay the complete delivery trace"
                );
            }
        }
    }
}

#[test]
fn seeded_conflicting_authorized_proposals_resolve_only_with_one_actual_precommit_quorum() {
    let scenario = Scenario {
        name: "conflicting-proposals-delayed-precommits",
        weights: &[2, 2, 2, 2, 3],
        groups: [0, 0, 0, 1],
        cut: Cut::Cold,
        winners: 0b0111,
    };
    for seed in [7, 29, 101] {
        with_nodes(scenario, |scopes, fixture, keys, layouts| {
            let mut sim = Simulation::new(scopes, fixture, keys, layouts, scenario, false);
            sim.fault_delivery = Some(Delivery::new(
                Policy {
                    duplicate: true,
                    reorder: true,
                    delay: true,
                    drop_precommits: true,
                },
                seed,
            ));
            sim.settle(0, FixedValidatorLockPhaseV0::Proposal);
            sim.round(0, keys.get(4));
            assert_eq!(sim.selected, [None; 4]);
            for actor in 0..4 {
                let expected =
                    sim.values[usize::from(scenario.groups[actor])].proposal_signing_root();
                assert_eq!(
                    sim.published[&(actor, 0, 0)],
                    ConsensusVoteTarget::Proposal(expected)
                );
                assert_eq!(
                    sim.published[&(actor, 0, 1)],
                    if actor < 3 {
                        ConsensusVoteTarget::Proposal(sim.values[0].proposal_signing_root())
                    } else {
                        ConsensusVoteTarget::Nil
                    }
                );
            }
            sim.check_history();
            let delivery = sim.fault_delivery.as_mut().unwrap();
            assert!(!delivery.lost.is_empty());
            delivery.policy.drop_precommits = false;
            let mut originals = std::mem::take(&mut delivery.lost);
            originals.sort_by_key(|(_, envelope)| match &envelope.wire {
                Wire::Vote { bytes, .. } => bytes.clone(),
                _ => unreachable!(),
            });
            originals.dedup_by(|a, b| match (&a.1.wire, &b.1.wire) {
                (Wire::Vote { bytes: a, .. }, Wire::Vote { bytes: b, .. }) => a == b,
                _ => false,
            });
            sim.healed = true;
            for (_, envelope) in originals {
                for to in 0..4 {
                    sim.enqueue(to, envelope.clone());
                }
            }
            // Deliver the already-authorized majority proposal to the minority's
            // finality path. The Byzantine proposer may send both variants, but
            // its weight is below one third and never counted twice per root.
            let position = round_at(&sim.branch, 0).position();
            let mut control = sim.values[0].to_canonical_bytes().to_vec();
            control.extend_from_slice(&authorization_bytes(
                fixture.context,
                position,
                sim.values[0].proposal_signing_root(),
                &keys[4],
            ));
            control.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
            sim.enqueue(
                3,
                Envelope {
                    from: 4,
                    wire: Wire::Proposal {
                        control,
                        payload: sim.payloads[0].clone(),
                    },
                },
            );
            sim.settle(0, FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(sim.selected, [Some(sim.values[0].ancestry_id()); 4]);
            assert!(
                sim.selected
                    .iter()
                    .all(|value| *value != Some(sim.values[1].ancestry_id()))
            );
            assert_eq!(
                sim.published.len(),
                8,
                "healing must create no replacement honest votes"
            );
            sim.check_history();
            eprintln!(
                "conflicting_proposal_seed={seed} honest_precommits_for_majority=3 minority_nil=1 finalizations=4 deliveries={} late_rejections={}",
                sim.deliveries, sim.late_rejections
            );
        });
    }
}
