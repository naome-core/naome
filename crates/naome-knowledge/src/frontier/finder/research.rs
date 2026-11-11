//! A bounded, checked-outcome policy for choosing which formal work to try.
//! The published checkpoint changes only on held-out comparisons under matched
//! solver, catalogue and search allowances. Proof authority remains with the checker.
use super::analysis::{BINDINGS, Descriptor};
use crate::structure::SIGNALS;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

    fn block(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.solver);
        hash.update(self.decision.knowledge);
        hash.update(self.search_limit.to_le_bytes());
        hash.update(self.decision.work_units.to_le_bytes());
        hash.update(self.decision.horizon_ms.to_le_bytes());
        hash.update([u8::from(self.decision.checked_inputs)]);
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preference {
    block: [u8; 32],
    checked_resolution: [u8; 32],
    exhausted_resolution: [u8; 32],
    checked: Projection,
    exhausted: Projection,
    reused: bool,
}
impl Preference {
    fn margin(&self, weights: &Weights) -> f32 {
        project(weights, &self.checked) - project(weights, &self.exhausted)
    }

    fn same_inputs(&self, other: &Self) -> bool {
        self.block == other.block
            && self.checked_resolution == other.checked_resolution
            && self.exhausted_resolution == other.exhausted_resolution
            && self.checked == other.checked
            && self.exhausted == other.exhausted
    }

    fn value(&self, weights: &Weights) -> i64 {
        let order = self
            .margin(weights)
            .partial_cmp(&0.)
            .expect("finite policy");
        crate::research_value::measured_selection(order, self.reused)
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
    assessment: Option<crate::research_value::Assessment>,
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
            assessment: None,
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
        if let Some(assessment) = self.assessment {
            assessment.validate()?;
        }
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
            || (self.promotions > 0) != self.assessment.is_some_and(|a| a.accepts())
            || self.promotions == 0 && self.weights != ([0.; SIGNALS], [0.; SUMMARY])
            || self.protected.len() > PROTECTED
            || self.protected.iter().enumerate().any(|(i, pair)| {
                pair.checked == pair.exhausted
                    || pair.checked_resolution == pair.exhausted_resolution
                    || self.protected[..i]
                        .iter()
                        .any(|other| pair.same_inputs(other))
            })
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
            "assessment":self.assessment,
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
        if outcome == Outcome::Reused {
            let block = row.block();
            for pair in &mut self.protected {
                if pair.block == block && pair.checked_resolution == row.decision.resolution {
                    pair.reused = true;
                }
            }
        }
        let group = row.group();
        let mut group_rows = self
            .transitions
            .iter()
            .enumerate()
            .filter(|(_, r)| r.group() == group);
        let first = group_rows.next().map(|(i, _)| i);
        if group_rows.count() + usize::from(first.is_some()) >= PER_GROUP {
            let oldest = first.expect("full transition group");
            let evicted = if group.0 {
                self.redundant_validation_row(&row).unwrap_or(oldest)
            } else {
                oldest
            };
            self.transitions.remove(evicted);
        }
        self.transitions.push_back(row);
        self.advance()
    }

    /// Prefer dropping the oldest row whose removal would leave the same
    /// comparable validation blocks. The incoming row can replace a witness
    /// for its own block. If every row represents a distinct block, age wins.
    fn redundant_validation_row(&self, incoming: &Transition) -> Option<usize> {
        let group = incoming.group();
        let opposite = (group.0, !group.1);
        self.transitions
            .iter()
            .enumerate()
            .filter(|(_, row)| row.group() == group)
            .find_map(|(index, row)| {
                let paired = self
                    .transitions
                    .iter()
                    .any(|other| other.group() == opposite && row.comparable(other));
                let replaced = row.comparable(incoming)
                    || self
                        .transitions
                        .iter()
                        .enumerate()
                        .any(|(other_index, other)| {
                            index != other_index && other.group() == group && row.comparable(other)
                        });
                (!paired || replaced).then_some(index)
            })
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
        if training.is_empty() || validation.is_empty() {
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
        let mut used = BTreeSet::new();
        let mut evaluated = self.protected.clone();
        let mut latest_gain = self.qualified_through;
        let mut new_protected = Vec::new();
        let mut matched = 0;
        for (good, bad) in &validation {
            if used.contains(&good.job) || used.contains(&bad.job) {
                continue;
            }
            used.extend([good.job, bad.job]);
            matched += 1;
            let pair = Preference {
                block: good.block(),
                checked_resolution: good.decision.resolution,
                exhausted_resolution: bad.decision.resolution,
                checked: good.decision.features,
                exhausted: bad.decision.features,
                reused: good.outcome == Outcome::Reused,
            };
            let before = pair.margin(&self.weights);
            let after = pair.margin(&candidate);
            if let Some(prior) = evaluated.iter_mut().find(|p| pair.same_inputs(p)) {
                prior.reused |= pair.reused;
            } else {
                evaluated.push(pair.clone());
            }
            if after > 0. && before <= 0. {
                latest_gain = latest_gain.max(good.job.max(bad.job));
                if self.protected.len() + new_protected.len() < PROTECTED
                    && !self.protected.iter().any(|p| pair.same_inputs(p))
                    && !new_protected.iter().any(|p| pair.same_inputs(p))
                {
                    new_protected.push(pair);
                }
            }
        }
        let mut comparison = crate::research_value::Comparison::default();
        for pair in &evaluated {
            comparison.record(
                pair.block,
                pair.value(&self.weights),
                pair.value(&candidate),
            );
        }
        let assessment = comparison.assess();
        if latest_gain > self.qualified_through && assessment.accepts() {
            self.validation_pairs = matched;
            self.weights = candidate;
            self.promotions += 1;
            self.qualified_through = latest_gain;
            self.protected.extend(new_protected);
            self.assessment = Some(assessment);
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
