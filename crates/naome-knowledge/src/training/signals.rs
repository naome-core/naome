//! Scheduling hypotheses, independent of checker validity and model training.
use super::*;
use crate::structure::{SCALE, SIGNALS};
use naome_foundation::ZfcAxiom;
use naome_proof::ProofStep;

pub(super) const RULES: usize = 21;
pub(super) const NAMES: [&str; RULES] = [
    "simplification",
    "frege",
    "classical_contraposition",
    "universal_distribution",
    "vacuous_universal",
    "universal_instantiation",
    "equality_reflexivity",
    "equality_substitution",
    "extensionality",
    "pairing",
    "union",
    "power_set",
    "infinity",
    "foundation",
    "choice",
    "separation",
    "replacement",
    "proof_reference",
    "modus_ponens",
    "generalization",
    "definition_reference",
];
pub(super) fn rules(steps: &[ProofStep], present: &mut [bool; RULES]) {
    for step in steps {
        let index = match step {
            ProofStep::Simplification { .. } => 0,
            ProofStep::Frege { .. } => 1,
            ProofStep::ClassicalContraposition { .. } => 2,
            ProofStep::UniversalDistribution { .. } => 3,
            ProofStep::VacuousUniversal { .. } => 4,
            ProofStep::UniversalInstantiation { .. } => 5,
            ProofStep::EqualityReflexivity { .. } => 6,
            ProofStep::EqualitySubstitution { .. } => 7,
            ProofStep::ZfcAxiom(axiom) => match axiom {
                ZfcAxiom::Extensionality => 8,
                ZfcAxiom::Pairing => 9,
                ZfcAxiom::Union => 10,
                ZfcAxiom::PowerSet => 11,
                ZfcAxiom::Infinity => 12,
                ZfcAxiom::Foundation => 13,
                ZfcAxiom::Choice => 14,
            },
            ProofStep::Separation(_) => 15,
            ProofStep::Replacement(_) => 16,
            ProofStep::ProofReference { .. } => 17,
            ProofStep::ModusPonens { .. } => 18,
            ProofStep::Generalization { .. } => 19,
        };
        present[index] = true;
        present[20] |= !step.definition_references().is_empty();
    }
}

/// Prefer a measured boundary of mixed success to already mastered or uniformly
/// unsuccessful work. Unknown ability is neutral, not an invented failure rate.
pub(crate) fn opportunity(successes: u64, attempts: u64) -> u64 {
    if attempts < 2 {
        return SCALE;
    }
    let rate =
        (u128::from(successes.min(attempts)) * u128::from(SCALE) / u128::from(attempts)) as u64;
    SCALE + 12 * rate * (SCALE - rate) / SCALE
}

#[derive(Default)]
pub(super) struct Signals {
    covered: [u64; SIGNALS],
    rules: [u64; RULES],
    attempts: [u64; SIGNALS],
    solved: [u64; SIGNALS],
    gains: [i64; SIGNALS],
}
impl Signals {
    pub(super) fn new(graph: &Graph, request: &Request) -> Result<Self, Error> {
        let mut signals = Self::default();
        match (&request.development, &request.previous_development) {
            (None, Some(_)) => return Err("prior development requires a current report".into()),
            (None, None) => return Ok(signals),
            _ => {}
        }
        let development = request.development.as_ref().expect("current report");
        if development.solver != request.solver {
            return Err("development checkpoint or allowance differs".into());
        }
        let current = probes(
            graph,
            &development.solver,
            &development.knowledge,
            &development.probes,
            Partition::Development,
        )?;
        let previous = if let Some(previous) = &request.previous_development {
            if previous.solver.budget != development.solver.budget
                || previous.solver.checkpoint == development.solver.checkpoint
            {
                return Err(
                    "development progress requires distinct checkpoints and equal allowances"
                        .into(),
                );
            }
            let previous = probes(
                graph,
                &previous.solver,
                &previous.knowledge,
                &previous.probes,
                Partition::Development,
            )?;
            if !previous.keys().eq(current.keys())
                || current
                    .iter()
                    .any(|(id, observed)| previous[id].input != observed.input)
            {
                return Err("development progress questions differ".into());
            }
            Some(previous)
        } else {
            None
        };
        for (id, observed) in &current {
            let features = &observed.features;
            let outcome = observed.solved;
            for (index, _) in features.counts.iter().enumerate().filter(|(_, n)| **n > 0) {
                if let Some(solved) = outcome {
                    signals.attempts[index] += 1;
                    signals.solved[index] += u64::from(solved);
                }
                if let Some(before) = previous.as_ref().and_then(|p| p.get(id))
                    && let (Some(before), Some(after)) = (before.solved, outcome)
                {
                    signals.gains[index] += i64::from(after) - i64::from(before);
                }
            }
        }
        Ok(signals)
    }
    pub(super) fn covered(&mut self, features: &Features, rules: &[bool; RULES]) {
        for (total, count) in self.covered.iter_mut().zip(features.counts) {
            *total = total.saturating_add(u64::from(count > 0));
        }
        for (total, present) in self.rules.iter_mut().zip(rules) {
            *total = total.saturating_add(u64::from(*present));
        }
    }
    pub(super) fn priority(&self, features: &Features, rules: &[bool; RULES], cost: usize) -> u64 {
        let mut value = 0u64;
        let mut count = 0;
        for (index, _) in features.counts.iter().enumerate().filter(|(_, n)| **n > 0) {
            let scarcity = SCALE / (1 + self.covered[index]);
            let weakness = SCALE
                + SCALE * self.attempts[index].saturating_sub(self.solved[index])
                    / (self.attempts[index] + 2);
            let boundary = opportunity(self.solved[index], self.attempts[index]);
            // Development progress is a prioritization hint, not a causal
            // estimate. Matched reserved evaluation remains independent.
            let gain = self.gains[index].clamp(-4, 4);
            let improvement = (8 + gain) as u64;
            value += scarcity * weakness / SCALE * boundary / SCALE * improvement / 8;
            count += 1;
        }
        for (index, _) in rules.iter().enumerate().filter(|(_, p)| **p) {
            value += SCALE / (1 + self.rules[index]);
            count += 1;
        }
        // Certificate steps approximate teaching/processing cost, not measured
        // search time. Expensive examples retain nonzero exploration mass.
        (value / count.max(1) / (1 + cost / 64) as u64).max(1)
    }
}
