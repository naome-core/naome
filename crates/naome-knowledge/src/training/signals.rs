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
    ability: Option<(super::ability::Profile, u32)>,
    regressions: [u16; super::ability::SKILLS],
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
        let mut ability = super::ability::Profile::new(request.solver.checkpoint.clone());
        for (id, observed) in &current {
            ability.observe_features(
                &observed.features,
                &crate::hex(id),
                request.solver.budget.work_units,
                observed.solved,
                observed.micros,
            );
            if let Some(before) = previous.as_ref().and_then(|p| p.get(id))
                && before.solved == Some(true)
                && observed.solved == Some(false)
            {
                let (skills, _) = super::ability::signature_features(&observed.features);
                for (index, present) in skills.into_iter().enumerate() {
                    if present {
                        signals.regressions[index] += 1;
                    }
                }
            }
        }
        signals.ability = Some((ability, request.solver.budget.work_units));
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
            value += scarcity;
            count += 1;
        }
        for (index, _) in rules.iter().enumerate().filter(|(_, p)| **p) {
            value += SCALE / (1 + self.rules[index]);
            count += 1;
        }
        if let Some((ability, budget)) = &self.ability {
            let readiness = ability.priority_features(features, *budget);
            let (skills, _) = super::ability::signature_features(features);
            let regression = skills
                .into_iter()
                .enumerate()
                .filter(|(_, p)| *p)
                .map(|(i, _)| u64::from(self.regressions[i].min(4)))
                .max()
                .unwrap_or(0);
            value = value
                .saturating_mul(readiness)
                .saturating_mul(1 + regression)
                / SCALE;
        }
        // Certificate steps approximate teaching/processing cost, not measured
        // search time. Expensive examples retain nonzero exploration mass.
        (value / count.max(1) / (1 + cost / 64) as u64).max(1)
    }
}
