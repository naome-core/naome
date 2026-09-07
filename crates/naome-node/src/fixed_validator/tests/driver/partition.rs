//! Deterministic recipient-local delivery through intact, independently anchored
//! drivers. The transport never builds a certificate or manufactures honest votes.

use std::collections::{BTreeMap, VecDeque};

use naome_chain::ArtifactBlock;
use naome_consensus::{ConsensusAncestryId, FixedValidatorProposalSourceV0};

use super::*;

mod delivery_faults;

#[derive(Clone, Copy, Debug)]
enum Cut {
    Cold,
    Precommit,
}

#[derive(Clone, Copy, Debug)]
struct Scenario {
    name: &'static str,
    weights: &'static [u16],
    groups: [u8; 4],
    cut: Cut,
    // Honest recipients permitted to finalize before healing; checked against
    // the independent immutable-total weight calculation at fixture creation.
    winners: u8,
}

#[derive(Clone)]
enum Wire {
    Proposal {
        control: Vec<u8>,
        payload: Vec<u8>,
    },
    Vote {
        round: u64,
        role: ConsensusVoteRole,
        target: ConsensusVoteTarget,
        bytes: Vec<u8>,
    },
}

#[derive(Clone)]
struct Envelope {
    from: usize,
    wire: Wire,
}

type FinalityImages = [Vec<(String, Vec<u8>)>; 2];

pub(super) fn finality_images(layout: &TestLayout) -> FinalityImages {
    [
        directory_image(&layout.finality_journal),
        directory_image(&layout.finality_anchor),
    ]
}

struct Simulation<'node, 'layout> {
    nodes: [Option<FixedValidatorNodeDriverV0<'node>>; 4],
    tickets: [Option<FixedValidatorNodePhaseTimeoutV0>; 4],
    queues: [VecDeque<Envelope>; 4],
    held: Vec<(usize, Envelope)>,
    // Only actually delivered non-nil precommits enter this oracle. Each signer
    // contributes once, even when the transport duplicates a canonical message.
    received: [BTreeMap<(u64, ProposalSigningRoot), u8>; 4],
    published: BTreeMap<(usize, u64, u8), ConsensusVoteTarget>,
    selected: [Option<ConsensusAncestryId>; 4],
    scenario: Scenario,
    reversed_duplicates: bool,
    healed: bool,
    dropped: usize,
    deliveries: usize,
    duplicates: usize,
    steps: usize,
    fault_delivery: Option<delivery_faults::Delivery>,
    late_rejections: usize,
    values: [ConsensusValueV0; 2],
    blocks: [ArtifactBlock; 2],
    payloads: [Vec<u8>; 2],
    keys: Vec<ConsensusKey>,
    branch: FixedConsensusBranchV0,
    layouts: &'layout [TestLayout; 4],
    initial_finality: [FinalityImages; 4],
}

impl Simulation<'_, '_> {
    fn enqueue(&mut self, to: usize, envelope: Envelope) {
        if let Some(delivery) = &mut self.fault_delivery {
            delivery.enqueue(to, envelope);
            return;
        }
        if self.reversed_duplicates {
            self.queues[to].push_back(envelope.clone());
        }
        self.queues[to].push_back(envelope);
    }

    fn publish(&mut self, from: usize, wire: Wire) {
        for to in 0..4 {
            let envelope = Envelope {
                from,
                wire: wire.clone(),
            };
            let cross = from < 4 && self.scenario.groups[from] != self.scenario.groups[to];
            let connected = self.healed
                || !cross
                || matches!(self.scenario.cut, Cut::Precommit)
                    && !matches!(
                        wire,
                        Wire::Vote {
                            role: ConsensusVoteRole::Precommit,
                            ..
                        }
                    );
            if connected {
                self.enqueue(to, envelope);
            } else if matches!(self.scenario.cut, Cut::Precommit) {
                self.held.push((to, envelope));
            } else {
                self.dropped += 1;
            }
        }
    }

    fn admission(&mut self, to: usize, event: FixedValidatorNodeDriverEventV0) -> bool {
        let before = self
            .fault_delivery
            .as_ref()
            .map(|_| self.layouts[to].images());
        let mut accepted = true;
        let node = self.nodes[to].take().unwrap();
        match node.admit_event(event).unwrap() {
            FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted {
                driver,
                disposition,
            } => {
                // A duplicate must be recognized at the driver boundary rather
                // than discarded by a test-side set before admission.
                if disposition == FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained {
                    self.duplicates += 1;
                }
                self.nodes[to] = Some(*driver);
            }
            FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                driver, rejection, ..
            } if self.fault_delivery.is_some() => {
                assert!(
                    matches!(*rejection,
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(_)
                    | FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue { .. }
                    | FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase { .. }
                    | FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(_)
                    | FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(_)
                    | FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(_)
                    | FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityProposal(_)
                    | FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(_)
                    | FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(_)
                ),
                    "fault schedule unexpected rejection: {rejection:?}"
                );
                self.nodes[to] = Some(*driver);
                assert_eq!(Some(self.layouts[to].images()), before);
                self.late_rejections += 1;
                accepted = false;
            }
            FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected { rejection, .. } => {
                panic!(
                    "{} recipient {to}: unexpected admission rejection {rejection:?}",
                    self.scenario.name
                )
            }
        }
        self.check_history();
        accepted
    }

    fn deliver(&mut self, to: usize, envelope: Envelope) {
        assert!(
            self.fault_delivery.is_some() || self.selected[to].is_none(),
            "no post-finality envelope in this schedule"
        );
        self.deliveries += 1;
        match envelope.wire {
            Wire::Proposal { control, payload } => {
                self.admission(to, current_finality_proposal_event(&control, &payload));
                self.admission(to, current_proposal_event(&control, &payload));
            }
            Wire::Vote {
                round,
                role,
                target,
                bytes,
            } => {
                let event = match (role, target) {
                    (ConsensusVoteRole::Prevote, ConsensusVoteTarget::Proposal(_)) => {
                        current_prevote_event(&bytes)
                    }
                    (ConsensusVoteRole::Prevote, ConsensusVoteTarget::Nil) => {
                        current_nil_prevote_event(&bytes)
                    }
                    (ConsensusVoteRole::Precommit, ConsensusVoteTarget::Proposal(root)) => {
                        let _ = root;
                        current_finality_precommit_event(&bytes)
                    }
                    (ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil) => {
                        current_nil_precommit_event(&bytes)
                    }
                };
                if self.admission(to, event)
                    && role == ConsensusVoteRole::Precommit
                    && let ConsensusVoteTarget::Proposal(root) = target
                {
                    *self.received[to].entry((round, root)).or_default() |= 1 << envelope.from;
                }
            }
        }
    }

    fn check_history(&self) {
        let mut common = None;
        for (actor, node) in self.nodes.iter().enumerate() {
            let node = node.as_ref().unwrap();
            if let Some(ancestry) = self.selected[actor] {
                assert!(
                    self.healed || self.scenario.winners & (1 << actor) != 0,
                    "{} finalized in an insufficient-weight partition",
                    self.scenario.name
                );
                assert_eq!(node.position().height().value(), 2);
                let value = self
                    .values
                    .iter()
                    .find(|value| value.ancestry_id() == ancestry)
                    .unwrap();
                assert_eq!(
                    node.selected_artifact_history()
                        .selected_head_block_id()
                        .unwrap(),
                    value.artifact_block().id()
                );
                if let Some(previous) = common {
                    assert_eq!(ancestry, previous, "conflicting honest history");
                }
                common = Some(ancestry);
            } else {
                assert_eq!(
                    finality_images(&self.layouts[actor]),
                    self.initial_finality[actor],
                    "partition changed finality authority before selection"
                );
                assert_eq!(node.position().height().value(), 1);
                assert_eq!(
                    node.selected_artifact_history()
                        .selected_head_block_id()
                        .unwrap(),
                    self.blocks[0].parent_block_id()
                );
            }
        }
    }

    fn step(&mut self, actor: usize) -> bool {
        self.steps += 1;
        assert!(self.steps <= 4_000, "incomplete deterministic schedule");
        let node = self.nodes[actor].take().unwrap();
        let (node, command, progress) = match node.step().unwrap() {
            FixedValidatorNodeDriverStepOutcomeV0::Command { driver, command } => {
                (*driver, Some(command), true)
            }
            FixedValidatorNodeDriverStepOutcomeV0::Transitioned { driver } => (*driver, None, true),
            FixedValidatorNodeDriverStepOutcomeV0::Idle { driver } => (*driver, None, false),
            FixedValidatorNodeDriverStepOutcomeV0::Finality { driver, selection } => {
                let FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position,
                    ancestry_id,
                    ..
                } = selection
                else {
                    panic!("expected first direct-child finality");
                };
                let value = self
                    .values
                    .iter()
                    .find(|value| value.ancestry_id() == ancestry_id)
                    .unwrap();
                let mask = self.received[actor]
                    [&(position.round().value(), value.proposal_signing_root())];
                let weight: u16 = self
                    .scenario
                    .weights
                    .iter()
                    .enumerate()
                    .filter(|(signer, _)| mask & (1 << signer) != 0)
                    .map(|(_, weight)| *weight)
                    .sum();
                let total: u16 = self.scenario.weights.iter().sum();
                assert!(
                    3 * weight > 2 * total,
                    "finality lacks recipient-local strict quorum"
                );
                assert!(self.selected[actor].replace(ancestry_id).is_none());
                (*driver, None, true)
            }
            FixedValidatorNodeDriverStepOutcomeV0::Blocked { driver, reason }
                if self.fault_delivery.is_some()
                    && matches!(
                        reason,
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing { .. }
                            | FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous { .. }
                    ) =>
            {
                (*driver, None, false)
            }
            FixedValidatorNodeDriverStepOutcomeV0::Blocked { reason, .. } => {
                panic!("partition must not masquerade as blocked inbox: {reason:?}")
            }
            FixedValidatorNodeDriverStepOutcomeV0::Rejected { rejection, .. } => {
                panic!("unexpected step rejection: {rejection:?}")
            }
            _ => panic!("partition must not stop an honest signer or finality"),
        };
        self.nodes[actor] = Some(node);
        if let Some(command) = command {
            match command {
                FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(ticket) => {
                    self.tickets[actor] = Some(ticket)
                }
                FixedValidatorNodeDriverCommandV0::PublishProposal {
                    proposal,
                    canonical_artifact_bytes,
                } => {
                    self.publish(
                        actor,
                        Wire::Proposal {
                            control: proposal.canonical_proposal_control_bytes().to_vec(),
                            payload: canonical_artifact_bytes,
                        },
                    );
                }
                FixedValidatorNodeDriverCommandV0::PublishVote {
                    vote,
                    released_proposal,
                } => {
                    assert!(released_proposal.is_none());
                    assert_eq!(
                        &vote.canonical_bytes()[VOTE_BODY_BYTES..VOTE_BODY_BYTES + 32],
                        self.keys[actor].as_bytes()
                    );
                    let role = if vote.role() == ConsensusVoteRole::Prevote {
                        0
                    } else {
                        1
                    };
                    assert!(
                        self.published
                            .insert(
                                (actor, vote.position().round().value(), role),
                                vote.target()
                            )
                            .is_none(),
                        "honest vote intent repeated"
                    );
                    self.publish(
                        actor,
                        Wire::Vote {
                            round: vote.position().round().value(),
                            role: vote.role(),
                            target: vote.target(),
                            bytes: vote.canonical_bytes().to_vec(),
                        },
                    );
                }
            }
        }
        self.check_history();
        progress
    }

    // Phase barriers keep every duplicate/reordered wave inside ordinary input
    // admission's phase contract. They make no wall-clock timing assumption.
    fn settle(&mut self, round: u64, phase: FixedValidatorLockPhaseV0) {
        fn rank(phase: FixedValidatorLockPhaseV0) -> u8 {
            match phase {
                FixedValidatorLockPhaseV0::Proposal => 0,
                FixedValidatorLockPhaseV0::Prevote => 1,
                FixedValidatorLockPhaseV0::Precommit => 2,
            }
        }
        loop {
            let mut progress = false;
            if let Some(delivery) = &mut self.fault_delivery {
                for (to, envelope) in delivery.next_wave() {
                    self.queues[to].push_back(envelope);
                    progress = true;
                }
            }
            for actor in 0..4 {
                while self.nodes[actor].as_ref().unwrap().has_pending_command() {
                    progress |= self.step(actor);
                }
            }
            for actor in 0..4 {
                loop {
                    let envelope = if self.reversed_duplicates {
                        self.queues[actor].pop_back()
                    } else {
                        self.queues[actor].pop_front()
                    };
                    let Some(envelope) = envelope else {
                        break;
                    };
                    self.deliver(actor, envelope);
                    progress = true;
                }
            }
            for actor in 0..4 {
                let node = self.nodes[actor].as_ref().unwrap();
                if self.selected[actor].is_none()
                    && node.position().round().value() == round
                    && rank(node.phase()) <= rank(phase)
                {
                    progress |= self.step(actor);
                }
            }
            if !progress {
                break;
            }
        }
    }

    fn expire(&mut self, round: u64, phase: FixedValidatorLockPhaseV0) {
        for actor in 0..4 {
            let node = self.nodes[actor].as_ref().unwrap();
            if self.selected[actor].is_none()
                && node.position().round().value() == round
                && node.phase() == phase
            {
                let ticket = self.tickets[actor].unwrap();
                assert_eq!(ticket.position(), node.position());
                assert_eq!(ticket.phase(), phase);
                self.admission(actor, FixedValidatorNodeDriverEventV0::TimeoutDue(ticket));
            }
        }
        self.settle(round, phase);
    }

    fn author(&mut self, round: u64, faulty: Option<&SigningKey>) {
        let cursor = round_at(&self.branch, round);
        let actor = self
            .keys
            .iter()
            .position(|&key| key == cursor.proposer())
            .unwrap();
        let position = cursor.position();
        if actor == 4 {
            let faulty = faulty.expect("faulty proposer must have the designated key");
            for to in 0..4 {
                let value = usize::from(self.scenario.groups[to]);
                let mut control = self.values[value].to_canonical_bytes().to_vec();
                control.extend_from_slice(&authorization_bytes(
                    self.values[value].context(),
                    position,
                    self.values[value].proposal_signing_root(),
                    faulty,
                ));
                control.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
                self.enqueue(
                    to,
                    Envelope {
                        from: 4,
                        wire: Wire::Proposal {
                            control,
                            payload: self.payloads[value].clone(),
                        },
                    },
                );
            }
        } else {
            let node = self.nodes[actor].take().unwrap();
            self.nodes[actor] = Some(
                match node
                    .author_proposal(FixedValidatorProposalSourceV0::Fresh {
                        artifact_block: self.blocks[0],
                        canonical_artifact_bytes: self.payloads[0].clone(),
                    })
                    .unwrap()
                {
                    FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Authored { driver } => {
                        *driver
                    }
                    FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Rejected {
                        rejection,
                        ..
                    } => panic!("author rejected: {rejection:?}"),
                    _ => panic!("expected fresh honest author"),
                },
            );
            self.check_history();
        }
    }

    fn faulty_votes(&mut self, round: u64, role: ConsensusVoteRole, key: Option<&SigningKey>) {
        let Some(key) = key else {
            return;
        };
        let position = round_at(&self.branch, round).position();
        for to in 0..4 {
            let target = ConsensusVoteTarget::Proposal(
                self.values[usize::from(self.scenario.groups[to])].proposal_signing_root(),
            );
            let bytes = signed_vote_bytes(self.values[0].context(), position, role, target, key);
            self.enqueue(
                to,
                Envelope {
                    from: 4,
                    wire: Wire::Vote {
                        round,
                        role,
                        target,
                        bytes,
                    },
                },
            );
        }
    }

    fn round(&mut self, round: u64, faulty: Option<&SigningKey>) {
        self.author(round, faulty);
        self.settle(round, FixedValidatorLockPhaseV0::Proposal);
        self.expire(round, FixedValidatorLockPhaseV0::Proposal);
        self.faulty_votes(round, ConsensusVoteRole::Prevote, faulty);
        self.settle(round, FixedValidatorLockPhaseV0::Prevote);
        self.expire(round, FixedValidatorLockPhaseV0::Prevote);
        self.faulty_votes(round, ConsensusVoteRole::Precommit, faulty);
        self.settle(round, FixedValidatorLockPhaseV0::Precommit);
    }
}

fn run(scenario: Scenario, reversed_duplicates: bool) {
    let total: u16 = scenario.weights.iter().sum();
    assert!(scenario.weights.len() == 4 || scenario.weights.len() == 5);
    for actor in 0..4 {
        let available: u16 = (0..scenario.weights.len())
            .filter(|&other| other == 4 || scenario.groups[actor] == scenario.groups[other])
            .map(|other| scenario.weights[other])
            .sum();
        assert_eq!(
            3 * available > 2 * total,
            scenario.winners & (1 << actor) != 0
        );
    }
    if scenario.weights.len() == 5 {
        assert!(3 * scenario.weights[4] < total);
    }
    with_nodes(scenario, |scopes, fixture, keys, layouts| {
        let mut sim = Simulation::new(
            scopes,
            fixture,
            keys,
            layouts,
            scenario,
            reversed_duplicates,
        );
        let values = sim.values;
        sim.settle(0, FixedValidatorLockPhaseV0::Proposal);
        let rounds = if matches!(scenario.cut, Cut::Cold) && scenario.winners == 0 {
            3
        } else {
            1
        };
        for round in 0..rounds {
            sim.round(round, keys.get(4));
            if round == 0 && keys.len() == 5 {
                for actor in 0..4 {
                    assert_eq!(
                        sim.published[&(actor, 0, 0)],
                        ConsensusVoteTarget::Proposal(
                            values[usize::from(scenario.groups[actor])].proposal_signing_root()
                        ),
                        "both Byzantine proposal variants must cause actual honest prevotes"
                    );
                }
            }
            for actor in 0..4 {
                assert_eq!(
                    sim.selected[actor].is_some(),
                    scenario.winners & (1 << actor) != 0
                );
            }
            if matches!(scenario.cut, Cut::Cold) && scenario.winners == 0 {
                sim.expire(round, FixedValidatorLockPhaseV0::Precommit);
                for node in &sim.nodes {
                    assert_eq!(node.as_ref().unwrap().position().round().value(), round + 1);
                    assert_eq!(
                        node.as_ref().unwrap().phase(),
                        FixedValidatorLockPhaseV0::Proposal
                    );
                }
            }
        }
        if scenario.winners == 0 {
            sim.healed = true;
            if matches!(scenario.cut, Cut::Precommit) {
                assert!(!sim.held.is_empty());
                for actor in 0..4 {
                    assert_eq!(
                        sim.published[&(actor, 0, 1)],
                        ConsensusVoteTarget::Proposal(values[0].proposal_signing_root())
                    );
                    let expected_mask = (0..4)
                        .filter(|&from| scenario.groups[from] == scenario.groups[actor])
                        .fold(0, |mask, from| mask | (1 << from));
                    assert_eq!(
                        sim.received[actor][&(0, values[0].proposal_signing_root())],
                        expected_mask,
                        "every within-group non-nil precommit must have reached its recipient"
                    );
                }
                for (to, envelope) in std::mem::take(&mut sim.held) {
                    sim.enqueue(to, envelope);
                }
                sim.settle(0, FixedValidatorLockPhaseV0::Precommit);
            } else {
                assert!(sim.dropped > 0);
                // Dropped bytes stay dropped. New round-3 messages
                // alone drive this finite heal; the faulty key is silent.
                sim.round(3, None);
            }
            assert_eq!(sim.selected, [Some(values[0].ancestry_id()); 4]);
        }
        assert!(sim.deliveries > 0);
        let voted_rounds = if matches!(scenario.cut, Cut::Cold) && scenario.winners == 0 {
            4
        } else {
            1
        };
        for actor in 0..4 {
            for round in 0..voted_rounds {
                for role in 0..2 {
                    assert!(sim.published.contains_key(&(actor, round, role)));
                }
            }
        }
        if reversed_duplicates {
            assert!(sim.duplicates > 0);
        }
        sim.check_history();
        eprintln!(
            "partition={} reversed_duplicates={} publications={} finalizations={} deliveries={} drops={} duplicate_admissions={} steps={}",
            scenario.name,
            reversed_duplicates,
            sim.published.len(),
            sim.selected.iter().flatten().count(),
            sim.deliveries,
            sim.dropped,
            sim.duplicates,
            sim.steps
        );
    });
}

fn with_nodes(
    scenario: Scenario,
    run: impl FnOnce(
        [FixedValidatorNodeSigningScopeV0<'_>; 4],
        &Fixture,
        &[SigningKey],
        &[TestLayout; 4],
    ),
) {
    let fixture = Fixture::new();
    let mut keys = (0..scenario.weights.len())
        .map(|actor| SigningKey::from_bytes(&signing_seed(actor as u16 + 121)))
        .collect::<Vec<_>>();
    keys.sort_by_key(consensus_key);
    let entries = keys
        .iter()
        .zip(scenario.weights)
        .map(|(key, &weight)| {
            ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(u128::from(weight)))
        })
        .collect::<Vec<_>>();
    let layouts = std::array::from_fn::<_, 4, _>(|actor| {
        TestLayout::new(&format!("partition-{}-{actor}", scenario.name))
    });
    let [first, second, third, fourth] = std::array::from_fn::<_, 4, _>(|actor| {
        provision_with_fixed_entries(&fixture, &layouts[actor], &entries)
            .create(keys[actor].clone())
            .unwrap()
    });
    first
        .run_with_signing_session(|first| {
            second
                .run_with_signing_session(|second| {
                    third
                        .run_with_signing_session(|third| {
                            fourth
                                .run_with_signing_session(|fourth| {
                                    run([first, second, third, fourth], &fixture, &keys, &layouts);
                                })
                                .unwrap();
                        })
                        .unwrap();
                })
                .unwrap();
        })
        .unwrap();
}

#[test]
fn deterministic_partitions_preserve_finality_with_real_driver_publications() {
    for scenario in [
        Scenario {
            name: "unit-two-two",
            weights: &[1, 1, 1, 1],
            groups: [0, 0, 1, 1],
            cut: Cut::Cold,
            winners: 0,
        },
        Scenario {
            name: "three-keys-exact-two-thirds",
            weights: &[2, 1, 1, 2],
            groups: [0, 0, 0, 1],
            cut: Cut::Cold,
            winners: 0,
        },
        Scenario {
            name: "three-keys-below-two-thirds",
            weights: &[4, 1, 1, 1],
            groups: [0, 1, 1, 1],
            cut: Cut::Cold,
            winners: 0,
        },
        Scenario {
            name: "byzantine-bridge",
            weights: &[2, 2, 2, 2, 3],
            groups: [0, 0, 1, 1],
            cut: Cut::Cold,
            winners: 0,
        },
        Scenario {
            name: "unit-quorum-control",
            weights: &[1, 1, 1, 1],
            groups: [0, 0, 0, 1],
            cut: Cut::Cold,
            winners: 0b0111,
        },
        Scenario {
            name: "two-key-quorum-control",
            weights: &[3, 2, 1, 1],
            groups: [0, 0, 1, 1],
            cut: Cut::Cold,
            winners: 0b0011,
        },
    ] {
        for reversed_duplicates in [false, true] {
            run(scenario, reversed_duplicates);
        }
    }
}

#[test]
fn precommit_delivery_cut_retains_real_votes_until_same_round_healing() {
    for scenario in [
        Scenario {
            name: "precommit-two-two",
            weights: &[1, 1, 1, 1],
            groups: [0, 0, 1, 1],
            cut: Cut::Precommit,
            winners: 0,
        },
        Scenario {
            name: "precommit-exact-two-thirds",
            weights: &[2, 1, 1, 2],
            groups: [0, 0, 0, 1],
            cut: Cut::Precommit,
            winners: 0,
        },
    ] {
        for reversed_duplicates in [false, true] {
            run(scenario, reversed_duplicates);
        }
    }
}

impl<'node, 'layout> Simulation<'node, 'layout> {
    fn new(
        scopes: [FixedValidatorNodeSigningScopeV0<'node>; 4],
        fixture: &Fixture,
        keys: &[SigningKey],
        layouts: &'layout [TestLayout; 4],
        scenario: Scenario,
        reversed_duplicates: bool,
    ) -> Self {
        let branch = scopes[0].branch().clone();
        let payloads = [
            proof_payload(ZfcAxiom::Pairing),
            proof_payload(ZfcAxiom::Union),
        ];
        let selected = ArtifactChainState::new(fixture.definition);
        let blocks = payloads
            .each_ref()
            .map(|payload| selected.prepare_block(artifact_id(payload)).unwrap());
        let values = blocks.map(|block| {
            branch
                .begin_round_zero()
                .unwrap()
                .value_for_artifact_block(block)
        });
        assert_ne!(values[0], values[1]);
        Self {
            nodes: scopes.map(|scope| {
                Some(driver_with_all_limits(
                    scope,
                    128,
                    1 << 20,
                    128,
                    1 << 20,
                    128,
                    1 << 20,
                    128,
                    1 << 20,
                    4,
                ))
            }),
            tickets: [None; 4],
            queues: std::array::from_fn(|_| VecDeque::new()),
            held: Vec::new(),
            received: std::array::from_fn(|_| BTreeMap::new()),
            published: BTreeMap::new(),
            selected: [None; 4],
            scenario,
            reversed_duplicates,
            healed: false,
            dropped: 0,
            deliveries: 0,
            duplicates: 0,
            steps: 0,
            fault_delivery: None,
            late_rejections: 0,
            values,
            blocks,
            payloads,
            keys: keys.iter().map(consensus_key).collect(),
            branch,
            layouts,
            initial_finality: layouts.each_ref().map(finality_images),
        }
    }
}
