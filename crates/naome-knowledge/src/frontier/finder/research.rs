//! A bounded, checked-outcome policy for choosing which formal work to try.
//! The published checkpoint changes only on held-out comparisons under matched
//! solver, catalogue and search allowances. Proof authority remains with the checker.
use super::analysis::{BINDINGS, Descriptor};
use crate::structure::SIGNALS;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};

const CONTEXT: usize = 12;
const SUMMARY: usize = 2 + BINDINGS + CONTEXT;
const WIDTH: usize = SIGNALS + SUMMARY;
type Weights = ([f32; SIGNALS], [f32; SUMMARY]);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    syntax: [u8; SIGNALS],
    context: [u8; SUMMARY],
}
impl Projection {
    fn values(&self) -> impl Iterator<Item = u8> + '_ {
        self.syntax.iter().chain(&self.context).copied()
    }
}

fn magnitude(value: u16) -> u8 {
    (f32::from(value).ln_1p() * 32.).min(255.) as u8
}
const PER_GROUP: usize = 12;
const CHECK_EVERY: u64 = 8;
const PROTECTED: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Decision {
    pub resolution: [u8; 32],
    pub knowledge: [u8; 32],
    pub goal: Option<[u8; 32]>,
    pub finder_draw: u64,
    pub finder_updates: u64,
    pub checked_inputs: bool,
    pub forecast: Option<crate::research_value::Forecast>,
    pub work_units: u32,
    pub horizon_ms: u64,
    features: Projection,
}
impl Decision {
    pub(in crate::frontier) fn new(
        resolution: [u8; 32],
        knowledge: [u8; 32],
        goal: Option<[u8; 32]>,
        descriptor: &Descriptor,
        context: [u8; CONTEXT],
        draw: (u64, u64),
        limits: crate::jobs::Limits,
    ) -> Self {
        let mut summary = [0; SUMMARY];
        summary[0] = magnitude(descriptor.features.nodes);
        summary[1] = magnitude(descriptor.features.depth);
        for (output, input) in summary[2..2 + BINDINGS].iter_mut().zip(descriptor.bindings) {
            *output = (input * 128.).min(255.) as u8;
        }
        summary[2 + BINDINGS..].copy_from_slice(&context);
        let features = Projection {
            syntax: descriptor.features.counts.map(magnitude),
            context: summary,
        };
        Self {
            resolution,
            knowledge,
            goal,
            finder_draw: draw.0,
            finder_updates: draw.1,
            checked_inputs: false,
            forecast: None,
            work_units: limits.work_units,
            horizon_ms: limits.horizon_ms,
            features,
        }
    }
    pub(crate) fn action(&self) -> crate::research_value::Action {
        use crate::research_value::Action;
        if self.checked_inputs {
            Action::Reuse
        } else if self.goal.is_some() {
            Action::Solve
        } else {
            Action::Explore
        }
    }
    pub fn validate(&self) -> Result<(), crate::Error> {
        if let Some(forecast) = self.forecast {
            forecast.validate()?;
            if forecast.action != self.action() {
                return Err(crate::ResearchFailure::ResearchValueInvalid.into());
            }
        }
        if self.work_units == 0 || self.horizon_ms == 0 {
            return Err(crate::ResearchFailure::FinderDecisionInvalid.into());
        }
        Ok(())
    }
    fn held_out(&self) -> bool {
        self.resolution[0] & 3 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Exhausted,
    Checked,
    Reused,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    decision: Decision,
    solver: [u8; 32],
    search_limit: u32,
    job: u64,
    outcome: Outcome,
}
impl Transition {
    fn group(&self) -> (bool, bool) {
        (self.decision.held_out(), self.outcome > Outcome::Exhausted)
    }
    fn comparable(&self, other: &Self) -> bool {
        self.solver == other.solver
            && self.search_limit == other.search_limit
            && self.decision.knowledge == other.decision.knowledge
            && self.decision.work_units == other.decision.work_units
            && self.decision.horizon_ms == other.decision.horizon_ms
            && self.decision.checked_inputs == other.decision.checked_inputs
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preference {
    checked: Projection,
    exhausted: Projection,
}
impl Preference {
    fn margin(&self, weights: &Weights) -> f32 {
        project(weights, &self.checked) - project(weights, &self.exhausted)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::frontier) struct Policy {
    weights: Weights,
    transitions: VecDeque<Transition>,
    observations: u64,
    checked_at: u64,
    promotions: u64,
    validation_pairs: usize,
    qualified_through: u64,
    protected: Vec<Preference>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            weights: ([0.; SIGNALS], [0.; SUMMARY]),
            transitions: VecDeque::new(),
            observations: 0,
            checked_at: 0,
            promotions: 0,
            validation_pairs: 0,
            qualified_through: 0,
            protected: Vec::new(),
        }
    }
}
impl Policy {
    pub fn reservation() -> usize {
        2 * (4 * PER_GROUP * std::mem::size_of::<Transition>()
            + (2 * PER_GROUP * PER_GROUP) * std::mem::size_of::<(&Transition, &Transition)>()
            + PROTECTED * std::mem::size_of::<Preference>())
    }

    pub fn validate(&self) -> Result<(), crate::Error> {
        let mut groups = [[0; 2]; 2];
        let mut resolutions = BTreeSet::new();
        for row in &self.transitions {
            row.decision.validate()?;
            let (held_out, checked) = row.group();
            groups[usize::from(held_out)][usize::from(checked)] += 1;
            if row.job == 0 || row.search_limit == 0 || !resolutions.insert(row.decision.resolution)
            {
                return Err(crate::ResearchFailure::FinderDecisionInvalid.into());
            }
        }
        if groups.into_iter().flatten().any(|n| n > PER_GROUP)
            || self.transitions.len() as u64 > self.observations
            || self.checked_at > self.observations
            || !self.checked_at.is_multiple_of(CHECK_EVERY)
            || self.promotions > self.checked_at / CHECK_EVERY
            || self.validation_pairs > PER_GROUP * PER_GROUP
            || (self.promotions == 0) != (self.qualified_through == 0)
            || self.promotions == 0 && self.weights != ([0.; SIGNALS], [0.; SUMMARY])
            || self.protected.len() > PROTECTED
            || self
                .protected
                .iter()
                .any(|pair| pair.margin(&self.weights) <= 0.)
            || self
                .weights
                .0
                .iter()
                .chain(&self.weights.1)
                .any(|w| !w.is_finite() || w.abs() > 2.)
        {
            return Err(crate::ResearchFailure::FinderDecisionInvalid.into());
        }
        Ok(())
    }

    pub fn promotions(&self) -> u64 {
        self.promotions
    }

    pub fn active(&self) -> bool {
        self.promotions > 0
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "observations":self.observations, "checked_at":self.checked_at,
            "promotions":self.promotions, "validation_pairs":self.validation_pairs,
            "qualified_through":self.qualified_through, "protected_pairs":self.protected.len(),
        })
    }

    pub fn demonstrated_reuse(&self, resolution: &[u8; 32]) -> bool {
        self.transitions
            .iter()
            .any(|row| &row.decision.resolution == resolution && row.outcome == Outcome::Reused)
    }

    pub fn multiplier(&self, decision: &Decision) -> u64 {
        let score = score(&self.weights, decision).clamp(-1., 1.);
        (1024. * (1. + 0.375 * score)) as u64
    }

    pub fn observe(
        &mut self,
        decision: &Decision,
        experience: &crate::learning::experience::ExperienceSummary,
        checked: bool,
    ) -> Result<(), crate::Error> {
        self.record(
            decision,
            experience,
            if checked {
                Outcome::Checked
            } else {
                Outcome::Exhausted
            },
        )
    }

    pub fn reused(
        &mut self,
        decision: &Decision,
        experience: &crate::learning::experience::ExperienceSummary,
    ) -> Result<(), crate::Error> {
        self.record(decision, experience, Outcome::Reused)
    }

    fn record(
        &mut self,
        decision: &Decision,
        experience: &crate::learning::experience::ExperienceSummary,
        outcome: Outcome,
    ) -> Result<(), crate::Error> {
        decision.validate()?;
        if experience.job == 0
            || experience.search_limit == 0
            || crate::object::id_bytes(&experience.question)? != decision.resolution
        {
            return Err(crate::ResearchFailure::FinderDecisionInvalid.into());
        }
        let previous = self
            .transitions
            .iter()
            .position(|r| r.decision.resolution == decision.resolution);
        if let Some(i) = previous {
            let old = &self.transitions[i];
            if old.job > experience.job
                || old.outcome > outcome
                || old.job == experience.job && old.outcome == outcome
            {
                return Ok(());
            }
            self.transitions.remove(i);
        }
        let row = Transition {
            decision: decision.clone(),
            solver: crate::object::id_bytes(&experience.checkpoint)?,
            search_limit: experience.search_limit,
            job: experience.job,
            outcome,
        };
        let group = row.group();
        let mut group_rows = self
            .transitions
            .iter()
            .enumerate()
            .filter(|(_, r)| r.group() == group);
        let first = group_rows.next().map(|(i, _)| i);
        if group_rows.count() + usize::from(first.is_some()) >= PER_GROUP {
            self.transitions
                .remove(first.expect("full transition group"));
        }
        self.transitions.push_back(row);
        self.advance()
    }

    fn pairs(&self, held_out: bool) -> Vec<(&Transition, &Transition)> {
        let mut pairs = Vec::new();
        for good in &self.transitions {
            if good.group() != (held_out, true) {
                continue;
            }
            for bad in &self.transitions {
                if bad.group() == (held_out, false) && good.comparable(bad) {
                    pairs.push((good, bad));
                }
            }
        }
        pairs
    }

    fn advance(&mut self) -> Result<(), crate::Error> {
        self.observations = self
            .observations
            .checked_add(1)
            .ok_or(crate::ResearchFailure::FinderDecisionInvalid)?;
        if !self.observations.is_multiple_of(CHECK_EVERY) {
            return Ok(());
        }
        self.checked_at = self.observations;
        self.qualify();
        Ok(())
    }

    fn qualify(&mut self) {
        let training = self.pairs(false);
        let validation = self.pairs(true);
        let enough_distinct = |checked| {
            let ids = validation
                .iter()
                .map(|(good, bad)| if checked { good.job } else { bad.job })
                .collect::<BTreeSet<_>>();
            ids.len() >= 2
        };
        if training.len() < 4 || !enough_distinct(true) || !enough_distinct(false) {
            return;
        }
        let mut candidate = self.weights;
        for _ in 0..8 {
            let mut direction = [0.; WIDTH];
            for (good, bad) in &training {
                let margin = score(&candidate, &good.decision) - score(&candidate, &bad.decision);
                let credit = if good.outcome == Outcome::Reused {
                    2.
                } else {
                    1.
                };
                let step = credit / (1. + margin.clamp(-12., 12.).exp());
                for ((value, a), b) in direction
                    .iter_mut()
                    .zip(good.decision.features.values())
                    .zip(bad.decision.features.values())
                {
                    *value += step * (f32::from(a) - f32::from(b)) / 255.;
                }
            }
            for (weight, direction) in candidate
                .0
                .iter_mut()
                .chain(&mut candidate.1)
                .zip(direction)
            {
                *weight = (*weight + 0.25 * (direction / training.len() as f32 - 0.01 * *weight))
                    .clamp(-2., 2.);
            }
        }
        if self
            .protected
            .iter()
            .any(|pair| pair.margin(&candidate) <= 0.)
        {
            return;
        }
        let mut latest_gain = self.qualified_through;
        let mut new_protected = Vec::new();
        for (good, bad) in &validation {
            let pair = Preference {
                checked: good.decision.features,
                exhausted: bad.decision.features,
            };
            let before = pair.margin(&self.weights);
            let after = pair.margin(&candidate);
            if after < 0. && before >= 0. || after <= 0. && before > 0. {
                return;
            }
            if after > 0. && before <= 0. {
                latest_gain = latest_gain.max(good.job.max(bad.job));
                if self.protected.len() + new_protected.len() < PROTECTED
                    && !self.protected.contains(&pair)
                    && !new_protected.contains(&pair)
                {
                    new_protected.push(pair);
                }
            }
        }
        if latest_gain > self.qualified_through {
            self.validation_pairs = validation.len();
            self.weights = candidate;
            self.promotions += 1;
            self.qualified_through = latest_gain;
            self.protected.extend(new_protected);
        }
    }
}

fn project(weights: &Weights, features: &Projection) -> f32 {
    weights
        .0
        .iter()
        .chain(&weights.1)
        .zip(features.values())
        .map(|(w, f)| w * f32::from(f) / 255.)
        .sum()
}

fn score(weights: &Weights, decision: &Decision) -> f32 {
    project(weights, &decision.features)
}

#[cfg(test)]
mod tests;
