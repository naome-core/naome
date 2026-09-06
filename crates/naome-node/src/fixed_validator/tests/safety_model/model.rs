//! Independent, finite decision-event model. No production protocol helpers.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

pub(super) const ROUNDS: u8 = 3;
const VALIDATORS: u8 = 4;
const NIL: u8 = 3;
const STATE_LIMIT: usize = 2_000_000;

// Targets: absent=0, A=1, B=2, nil=3. Proofs: absent=0,
// (round, value)=1+2*round+(value-1). Proposal codes use a leading
// no-proof A/B pair, followed by the proof codes plus two.
pub(super) fn proof(round: u8, value: u8) -> u8 {
    1 + 2 * round + value - 1
}
pub(super) fn proof_round(encoded: u8) -> u8 {
    (encoded - 1) / 2
}
pub(super) fn proof_value(encoded: u8) -> u8 {
    1 + (encoded - 1) % 2
}
pub(super) fn proposal_value(encoded: u8) -> u8 {
    1 + (encoded - 1) % 2
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(super) struct Local {
    // 3*round+phase; phases are Proposal=0, Prevote=1, Precommit=2.
    pub cursor: u8,
    pub locked: u8,
    pub valid: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(super) struct State {
    pub nodes: [Local; 4],
    pub proposals: [u8; 3],
    votes: u64,
}

impl State {
    pub fn vote(self, actor: u8, round: u8, role: u8) -> u8 {
        ((self.votes >> (2 * (actor + 4 * (role + 2 * round)))) & 3) as u8
    }

    fn emit(&mut self, actor: u8, round: u8, role: u8, target: u8) {
        assert_eq!(self.vote(actor, round, role), 0, "honest double vote");
        self.votes |= u64::from(target) << (2 * (actor + 4 * (role + 2 * round)));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Action {
    Author {
        actor: u8,
        proposal: u8,
    },
    Prevote {
        actor: u8,
        proposal: u8,
    }, // zero explicitly closes Proposal
    Precommit {
        actor: u8,
        target: u8,
    }, // zero explicitly closes Prevote
    Advance {
        actor: u8,
        nil_quorum: bool,
    },
    Higher {
        actor: u8,
        round: u8,
        role: u8,
        target: u8,
    },
}

impl Action {
    pub fn actor(self) -> u8 {
        match self {
            Self::Author { actor, .. }
            | Self::Prevote { actor, .. }
            | Self::Precommit { actor, .. }
            | Self::Advance { actor, .. }
            | Self::Higher { actor, .. } => actor,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Rules {
    Protocol,
    WeakQuorum,
    ForgetLockOnRoundClose,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Model {
    pub faulty: u8,
    pub rules: Rules,
}

impl Model {
    fn key(self, state: State) -> u128 {
        let encode = |swap: bool| {
            let target = |value| {
                if swap && (value == 1 || value == 2) {
                    3 - value
                } else {
                    value
                }
            };
            let slot = |value| {
                if value == 0 {
                    0
                } else {
                    proof(proof_round(value), target(proof_value(value)))
                }
            };
            let mut key = 0_u128;
            let mut shift = 0;
            let mut push = |value: u8, bits| {
                key |= u128::from(value) << shift;
                shift += bits;
            };
            for (actor, local) in state.nodes.iter().enumerate() {
                if actor == usize::from(self.faulty) || local.cursor >= 3 * ROUNDS {
                    push(3 * ROUNDS, 4);
                    push(0, 6);
                } else {
                    push(local.cursor, 4);
                    push(slot(local.locked), 3);
                    push(slot(local.valid), 3);
                }
            }
            for proposal in state.proposals {
                push(
                    if proposal == 0 {
                        0
                    } else {
                        target(proposal_value(proposal))
                    },
                    2,
                );
            }
            for round in 0..ROUNDS {
                let closed = (0..VALIDATORS).all(|actor| {
                    actor == self.faulty || state.nodes[usize::from(actor)].cursor / 3 > round
                });
                for role in 0..=1 {
                    for actor in 0..VALIDATORS {
                        push(
                            if closed {
                                0
                            } else {
                                target(state.vote(actor, round, role))
                            },
                            2,
                        );
                    }
                    for value in 1..=NIL {
                        push(
                            u8::from(closed && self.quorum(state, round, role, target(value))),
                            1,
                        );
                    }
                }
            }
            key
        };
        // A/B are interchangeable valid semantic values. Once every honest
        // node has left a round, only its immutable quorum facts can affect a
        // future step. Keep actual emissions in the replay path, not this key.
        encode(false).min(encode(true))
    }

    pub fn quorum(self, state: State, round: u8, role: u8, target: u8) -> bool {
        // The faulty validator may sign every target at every position. Honest
        // votes must come from this execution. Withholding is always permitted.
        let signed = 1
            + (0..VALIDATORS)
                .filter(|&actor| actor != self.faulty && state.vote(actor, round, role) == target)
                .count();
        match self.rules {
            Rules::WeakQuorum => 2 * signed >= usize::from(VALIDATORS),
            _ => 3 * signed > 2 * usize::from(VALIDATORS),
        }
    }

    pub fn proposals(self, state: State, round: u8) -> Vec<u8> {
        // Equal weights and initially zero priorities select sorted keys 0,1,2.
        let mut proposals = if round == self.faulty {
            vec![1, 2]
        } else {
            match state.proposals[usize::from(round)] {
                0 => return Vec::new(),
                proposal => vec![proposal_value(proposal)],
            }
        };
        // Producer authorization binds the value/root, not optional proof bytes.
        // An adversary may strip or attach any available valid proof, including
        // on a root authored by an honest proposer.
        let roots = proposals.clone();
        for earlier in 0..round {
            for &value in &roots {
                if self.quorum(state, earlier, 0, value) {
                    proposals.push(proof(earlier, value) + 2);
                }
            }
        }
        proposals
    }

    pub fn certified_values(self, state: State) -> u8 {
        let mut values = 0;
        for round in 0..ROUNDS {
            for value in 1..=2 {
                if self.quorum(state, round, 1, value)
                    && self
                        .proposals(state, round)
                        .iter()
                        .any(|&p| proposal_value(p) == value)
                {
                    values |= 1 << (value - 1);
                }
            }
        }
        values
    }

    pub fn actions(self, state: State) -> Vec<Action> {
        let mut actions = Vec::new();
        for actor in 0..VALIDATORS {
            let local = state.nodes[usize::from(actor)];
            let round = local.cursor / 3;
            let phase = local.cursor % 3;
            if actor == self.faulty || round >= ROUNDS {
                continue;
            }
            if phase == 0 {
                if actor == round && state.proposals[usize::from(round)] == 0 {
                    if local.valid == 0 {
                        for proposal in 1..=2 {
                            actions.push(Action::Author { actor, proposal });
                        }
                    } else {
                        actions.push(Action::Author {
                            actor,
                            proposal: local.valid + 2,
                        });
                    }
                }
                for proposal in self.proposals(state, round) {
                    actions.push(Action::Prevote { actor, proposal });
                }
                actions.push(Action::Prevote { actor, proposal: 0 });
            } else if phase == 1 {
                for target in 1..=NIL {
                    if self.quorum(state, round, 0, target)
                        && (target == NIL
                            || self
                                .proposals(state, round)
                                .iter()
                                .any(|&p| proposal_value(p) == target))
                    {
                        actions.push(Action::Precommit { actor, target });
                    }
                }
                actions.push(Action::Precommit { actor, target: 0 });
            } else {
                actions.push(Action::Advance {
                    actor,
                    nil_quorum: false,
                });
            }
            if self.quorum(state, round, 1, NIL) {
                actions.push(Action::Advance {
                    actor,
                    nil_quorum: true,
                });
            }
            for higher in round + 1..ROUNDS {
                for role in 0..=1 {
                    // Target changes no checkpoint state; one witness suffices
                    // for each equivalent phase-only successor.
                    if let Some(target) =
                        (1..=NIL).find(|&target| self.quorum(state, higher, role, target))
                    {
                        actions.push(Action::Higher {
                            actor,
                            round: higher,
                            role,
                            target,
                        });
                    }
                }
            }
        }
        actions
    }

    pub fn apply(self, state: State, action: Action) -> Option<State> {
        let actor = action.actor();
        let mut next = state;
        let local = &mut next.nodes[usize::from(actor)];
        let round = local.cursor / 3;
        match action {
            Action::Author { proposal, .. } => next.proposals[usize::from(round)] = proposal,
            Action::Prevote { proposal, .. } => {
                let value = if proposal == 0 {
                    NIL
                } else {
                    proposal_value(proposal)
                };
                let incoming = proposal.saturating_sub(2);
                if incoming > 0 {
                    if local.valid > 0
                        && proof_round(incoming) == proof_round(local.valid)
                        && proof_value(incoming) != proof_value(local.valid)
                    {
                        return None; // equal-round valid-value conflict rejects unchanged
                    }
                    if local.valid == 0 || proof_round(incoming) > proof_round(local.valid) {
                        local.valid = incoming;
                    }
                    if local.locked > 0
                        && proof_value(local.locked) != value
                        && proof_round(incoming) > proof_round(local.locked)
                    {
                        local.locked = 0;
                    }
                }
                let target = if local.locked == 0 {
                    value
                } else {
                    proof_value(local.locked)
                };
                local.cursor += 1;
                next.emit(actor, round, 0, target);
            }
            Action::Precommit { target, .. } => {
                match target {
                    1 | 2 => {
                        local.locked = proof(round, target);
                        local.valid = local.locked;
                    }
                    NIL => local.locked = 0,
                    0 => {}
                    _ => unreachable!(),
                }
                local.cursor += 1;
                next.emit(actor, round, 1, if target == 0 { NIL } else { target });
            }
            Action::Advance { nil_quorum, .. } => {
                local.cursor = 3 * (round + 1);
                if !nil_quorum && self.rules == Rules::ForgetLockOnRoundClose {
                    local.locked = 0;
                }
            }
            Action::Higher { round, role, .. } => local.cursor = 3 * round + role + 1,
        }
        Some(next)
    }
}

#[derive(Debug)]
pub(super) struct Exploration {
    pub states: usize,
    pub transitions: usize,
    pub witnesses: BTreeMap<&'static str, Vec<Action>>,
    pub counterexample: Option<Vec<Action>>,
}

fn observe(model: Model, before: State, after: State, action: Action) -> Vec<&'static str> {
    let mut labels = Vec::new();
    let old = before.nodes[usize::from(action.actor())];
    let new = after.nodes[usize::from(action.actor())];
    match action {
        Action::Prevote { proposal, .. } => {
            if old.locked > 0 && new.locked == 0 {
                labels.push("proof_unlock");
            }
            if proposal > 0
                && old.locked > 0
                && proposal_value(proposal) != proof_value(old.locked)
                && new.locked == old.locked
            {
                labels.push("conflicting_proposal_keeps_lock");
            }
            if old.valid != new.valid && old.valid > 0 {
                labels.push("newer_valid_proof");
            }
        }
        Action::Precommit { actor, target } => {
            if target == NIL && old.locked > 0 {
                labels.push("nil_quorum_clears_lock");
            }
            if target == 0 && old.locked > 0 {
                labels.push("close_preserves_lock");
            }
            if (1..=2).contains(&target) && before.vote(actor, old.cursor / 3, 0) != target {
                labels.push("precommit_differs_from_own_prevote");
                if before.vote(actor, old.cursor / 3, 0) == NIL {
                    labels.push("precommit_after_nil_prevote");
                }
            }
        }
        Action::Higher { role: 0, .. } => labels.push("higher_prevote"),
        Action::Higher { role: 1, .. } => labels.push("higher_precommit"),
        Action::Advance {
            nil_quorum: true, ..
        } if old.cursor % 3 != 2 => labels.push("nil_precommit_preempts"),
        _ => {}
    }
    match model.certified_values(after) {
        1 => labels.push("certificate_a"),
        2 => labels.push("certificate_b"),
        _ => {}
    }
    labels
}

pub(super) fn explore(model: Model) -> Exploration {
    fn visit(
        model: Model,
        state: State,
        seen: &mut HashSet<u128>,
        path: &mut Vec<Action>,
        report: &mut Exploration,
    ) -> bool {
        if !seen.insert(model.key(state)) {
            return false;
        }
        assert!(
            seen.len() <= STATE_LIMIT,
            "incomplete model exploration: state limit {STATE_LIMIT} exceeded, model={model:?}"
        );
        report.states += 1;
        if model.certified_values(state) == 3 {
            report.counterexample = Some(path.clone());
            return true;
        }
        for action in model.actions(state) {
            if let Some(next) = model.apply(state, action) {
                report.transitions += 1;
                path.push(action);
                for label in observe(model, state, next, action) {
                    report
                        .witnesses
                        .entry(label)
                        .or_insert_with(|| path.clone());
                }
                if visit(model, next, seen, path, report) {
                    return true;
                }
                path.pop();
            }
        }
        false
    }
    let mut report = Exploration {
        states: 0,
        transitions: 0,
        witnesses: BTreeMap::new(),
        counterexample: None,
    };
    visit(
        model,
        State::default(),
        &mut HashSet::new(),
        &mut Vec::new(),
        &mut report,
    );
    report
}

#[test]
fn bounded_safety_exploration() {
    for (faulty, report) in protocol_explorations().iter().enumerate() {
        let faulty = faulty as u8;
        let model = Model {
            faulty,
            rules: Rules::Protocol,
        };
        eprintln!(
            "{model:?}: states={}, transitions={}, coverage={:?}",
            report.states,
            report.transitions,
            report.witnesses.keys()
        );
        assert!(
            report.counterexample.is_none(),
            "model safety counterexample: {model:?} {:?}",
            report.counterexample
        );
        for label in [
            "certificate_a",
            "certificate_b",
            "proof_unlock",
            "conflicting_proposal_keeps_lock",
            "newer_valid_proof",
            "nil_quorum_clears_lock",
            "close_preserves_lock",
            "precommit_differs_from_own_prevote",
            "precommit_after_nil_prevote",
            "higher_prevote",
            "higher_precommit",
            "nil_precommit_preempts",
        ] {
            assert!(
                report.witnesses.contains_key(label),
                "vacuous coverage: {model:?} missing {label}"
            );
        }
    }
}

pub(super) fn protocol_explorations() -> &'static [Exploration; 4] {
    static REPORTS: OnceLock<[Exploration; 4]> = OnceLock::new();
    REPORTS.get_or_init(|| {
        std::array::from_fn(|faulty| {
            explore(Model {
                faulty: faulty as u8,
                rules: Rules::Protocol,
            })
        })
    })
}

#[test]
fn weakened_models_have_counterexamples() {
    for rules in [Rules::WeakQuorum, Rules::ForgetLockOnRoundClose] {
        let model = Model { faulty: 0, rules };
        let report = explore(model);
        assert!(
            report.counterexample.is_some(),
            "mutant survived: {model:?}"
        );
        let mut state = State::default();
        for &action in report.counterexample.as_ref().unwrap() {
            assert!(model.actions(state).contains(&action));
            state = model.apply(state, action).unwrap();
        }
        assert_eq!(model.certified_values(state), 3);
        eprintln!(
            "deliberately weakened-model counterexample: {model:?} {:?}",
            report.counterexample
        );
    }
}
