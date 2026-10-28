//! Bounded procedural autocurriculum and checkpoint-aware rehearsal.
//! All values schedule research; none establish mathematical validity.
use super::{Model, analysis::Descriptor};
use naome_authoring::CompiledQuestion;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

const OPERATORS: usize = 10;
const LEVELS: usize = 3;
const CELLS: usize = OPERATORS * LEVELS;
const MEMORY: usize = 48;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::frontier) struct Recipe {
    pub operator: u8,
    pub level: u8,
}
impl Recipe {
    fn index(self) -> usize {
        self.level as usize * OPERATORS + self.operator as usize
    }
    fn validate(self) -> Result<(), String> {
        if self.operator as usize >= OPERATORS || self.level as usize >= LEVELS {
            return Err("finder construction recipe differs".into());
        }
        Ok(())
    }
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cell {
    attempts: u64,
    solved: u64,
    millis: u64,
    last: u64,
    utility_count: u64,
    utility_sum: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    id: [u8; 32],
    recipe: Option<Recipe>,
    descriptor: Descriptor,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    offer: Offer,
    checkpoint: Option<String>,
    resolved: Option<bool>,
    millis: Option<u64>,
    support: Option<bool>,
    utility: Option<f32>,
    utility_checkpoint: String,
    observed: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::frontier) struct Learning {
    #[cfg(test)]
    #[serde(skip)]
    pub treatment: crate::frontier::Treatment,
    checkpoint: String,
    utility_receipt: String,
    progress_receipt: String,
    cells: Vec<Cell>,
    pending: VecDeque<Offer>,
    samples: VecDeque<Sample>,
    cursor: u64,
    pub rounds: u64,
    pub acquired: u64,
    pub regressed: u64,
}
impl Learning {
    pub fn fresh(checkpoint: String) -> Self {
        Self {
            #[cfg(test)]
            treatment: crate::frontier::Treatment::Full,
            checkpoint,
            utility_receipt: String::new(),
            progress_receipt: String::new(),
            cells: vec![Cell::default(); CELLS],
            pending: VecDeque::new(),
            samples: VecDeque::new(),
            cursor: 0,
            rounds: 0,
            acquired: 0,
            regressed: 0,
        }
    }
    pub fn reservation() -> usize {
        2 * (Self::budget() + CELLS * std::mem::size_of::<Cell>() + 4096)
    }
    fn budget() -> usize {
        crate::resources::adaptive::cache(
            crate::resources::active_limits().question_cache_bytes / 4,
        )
        .min(64 * 1024)
    }
    fn trim(&mut self) {
        let limit = (Self::budget() / 1024).min(MEMORY);
        while self.pending.len() > limit {
            self.pending.pop_front();
        }
        while self.samples.len() > limit {
            let mut counts = BTreeMap::new();
            for sample in &self.samples {
                *counts
                    .entry((
                        sample.offer.descriptor.features.family,
                        if self.family_only() {
                            None
                        } else {
                            sample.resolved
                        },
                    ))
                    .or_insert(0usize) += 1;
            }
            let family = counts
                .into_iter()
                .max_by_key(|(family, count)| (*count, std::cmp::Reverse(*family)))
                .map(|x| x.0)
                .unwrap();
            let index = self
                .samples
                .iter()
                .position(|s| {
                    (
                        s.offer.descriptor.features.family,
                        if self.family_only() { None } else { s.resolved },
                    ) == family
                })
                .unwrap();
            self.samples.remove(index);
        }
    }
    fn family_only(&self) -> bool {
        #[cfg(test)]
        if matches!(
            self.treatment,
            crate::frontier::Treatment::FamilyReplay
                | crate::frontier::Treatment::FamilyReplayNoUtility
        ) {
            return true;
        }
        false
    }
    pub fn validate(&self) -> Result<(), String> {
        crate::object::id_bytes(&self.checkpoint)?;
        if !self.utility_receipt.is_empty() {
            crate::object::id_bytes(&self.utility_receipt)?;
        }
        if self.cells.len() != CELLS || self.pending.len() > MEMORY || self.samples.len() > MEMORY {
            return Err("finder curriculum capacity differs".into());
        }
        for cell in &self.cells {
            if cell.solved > cell.attempts
                || cell.utility_sum > cell.utility_count.saturating_mul(65535)
            {
                return Err("finder curriculum counters differ".into());
            }
        }
        let mut ids = std::collections::BTreeSet::new();
        for sample in &self.samples {
            if !ids.insert(sample.offer.id)
                || sample.observed == 0
                || sample
                    .utility
                    .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
            {
                return Err("finder rehearsal identity or labels differ".into());
            }
            if let Some(checkpoint) = &sample.checkpoint {
                crate::object::id_bytes(checkpoint)?;
            }
            crate::object::id_bytes(&sample.utility_checkpoint)?;
        }
        for offer in self
            .pending
            .iter()
            .chain(self.samples.iter().map(|s| &s.offer))
        {
            offer.descriptor.validate()?;
            if let Some(recipe) = offer.recipe {
                recipe.validate()?;
            }
        }
        Ok(())
    }
    pub fn bind(&mut self, checkpoint: &str) {
        if self.checkpoint != checkpoint {
            self.checkpoint = checkpoint.to_owned();
            // Completion, cost and gradient alignment belong to this exact
            // solver. Checked downstream support and replay survive.
            for cell in &mut self.cells {
                cell.attempts = 0;
                cell.solved = 0;
                cell.millis = 0;
                cell.utility_count = 0;
                cell.utility_sum = 0;
            }
            self.rounds = self.rounds.saturating_add(1);
        }
    }
    pub fn recipes(&self, cursor: u64, draw: u64) -> Vec<Recipe> {
        let mut random = crate::sampling::Random::new(
            cursor.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(draw),
        );
        let mut options = (0..CELLS).collect::<Vec<_>>();
        let mut result = Vec::new();
        for _ in 0..20 {
            let weights = options
                .iter()
                .map(|i| self.priority(*i, draw))
                .collect::<Vec<_>>();
            let total = weights.iter().sum::<u64>();
            let mut ticket = random.below(total);
            let mut chosen = 0;
            for (index, weight) in weights.iter().enumerate() {
                if ticket < *weight {
                    chosen = index;
                    break;
                }
                ticket -= weight;
            }
            let index = options.remove(chosen);
            result.push(Recipe {
                operator: (index % OPERATORS) as u8,
                level: (index / OPERATORS) as u8,
            });
        }
        result
    }
    fn priority(&self, index: usize, draw: u64) -> u64 {
        #[cfg(test)]
        if matches!(
            self.treatment,
            crate::frontier::Treatment::Previous
                | crate::frontier::Treatment::Uniform
                | crate::frontier::Treatment::NoGeneration
        ) {
            return 65536;
        }
        let cell = &self.cells[index];
        let n = cell.attempts as f64;
        let p = (cell.solved as f64 + 1.) / (n + 2.);
        let regret = if cell.solved == 0 && cell.attempts >= 4 {
            0.05
        } else {
            1. - p
        };
        let uncertainty = 1. / (n + 1.).sqrt();
        let utility = if cell.utility_count == 0 {
            0.5
        } else {
            cell.utility_sum as f64 / (65535. * cell.utility_count as f64)
        };
        let cost = cell.millis as f64 / (n + 1.);
        let stale = draw.saturating_sub(cell.last).min(64) as f64 / 64.;
        1 + ((regret + uncertainty / 2. + stale / 4.) * (0.5 + utility) / (1. + cost.ln_1p() / 16.)
            * 65536.) as u64
    }
    pub fn selected(&mut self, q: &CompiledQuestion, recipe: Option<Recipe>) {
        self.trim();
        if self.pending.iter().any(|o| &o.id == q.resolution_id()) {
            return;
        }
        let old = self
            .samples
            .iter()
            .find(|s| &s.offer.id == q.resolution_id())
            .and_then(|s| s.offer.recipe);
        self.pending.push_back(Offer {
            id: *q.resolution_id(),
            recipe: recipe.or(old),
            descriptor: Descriptor::of(q),
        });
        self.trim();
    }
    pub fn remember(
        &mut self,
        model: &mut Model,
        q: &CompiledQuestion,
        checkpoint: Option<&str>,
        resolved: bool,
        millis: u64,
        draw: u64,
    ) -> Result<(), String> {
        let existing = self
            .samples
            .iter()
            .position(|s| &s.offer.id == q.resolution_id())
            .and_then(|i| self.samples.remove(i));
        let pending = self
            .pending
            .iter()
            .position(|o| &o.id == q.resolution_id())
            .and_then(|i| self.pending.remove(i));
        let offer = pending
            .or_else(|| existing.as_ref().map(|s| s.offer.clone()))
            .unwrap_or_else(|| Offer {
                id: *q.resolution_id(),
                recipe: None,
                descriptor: Descriptor::of(q),
            });
        if let Some(recipe) = offer
            .recipe
            .filter(|_| checkpoint == Some(self.checkpoint.as_str()))
        {
            let cell = &mut self.cells[recipe.index()];
            cell.attempts = cell.attempts.saturating_add(1);
            cell.solved = cell.solved.saturating_add(u64::from(resolved));
            cell.millis = cell.millis.saturating_add(millis);
            cell.last = draw;
        }
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or("finder replay cursor overflow")?;
        self.samples.push_back(Sample {
            offer,
            checkpoint: checkpoint.map(str::to_owned),
            resolved: Some(resolved),
            millis: Some(millis),
            support: existing
                .as_ref()
                .and_then(|s| s.support)
                .or(resolved.then_some(false)),
            utility: None,
            utility_checkpoint: self.checkpoint.clone(),
            observed: self.cursor,
        });
        self.trim();
        self.rehearse(model)
    }
    pub fn support(&mut self, model: &mut Model, q: &CompiledQuestion) -> Result<(), String> {
        if let Some(sample) = self
            .samples
            .iter_mut()
            .find(|s| &s.offer.id == q.resolution_id())
        {
            sample.support = Some(true);
        }
        self.rehearse(model)
    }
    fn rehearse(&mut self, model: &mut Model) -> Result<(), String> {
        #[cfg(test)]
        if matches!(
            self.treatment,
            crate::frontier::Treatment::Previous
                | crate::frontier::Treatment::Uniform
                | crate::frontier::Treatment::NoReplay
        ) {
            return Ok(());
        }
        self.trim();
        let choices = self.rehearsal_indices();
        for index in choices {
            let sample = &self.samples[index];
            let fresh = sample.checkpoint.as_deref() == Some(self.checkpoint.as_str());
            let (resolved, millis) = if fresh {
                (sample.resolved, sample.millis)
            } else {
                (None, None)
            };
            let utility = (sample.utility_checkpoint == self.checkpoint)
                .then_some(sample.utility)
                .flatten();
            // A newly checked lemma has not yet had a chance to help another
            // proof. Its pending-use observation must not become a repeated
            // negative target. Only checked downstream use survives replay.
            let support = sample.support.filter(|value| *value);
            #[cfg(test)]
            let support = if matches!(
                self.treatment,
                crate::frontier::Treatment::FamilyReplay
                    | crate::frontier::Treatment::FamilyReplayNoUtility
                    | crate::frontier::Treatment::OutcomeReplay
            ) {
                sample.support
            } else {
                support
            };
            if resolved.is_some() || sample.support == Some(true) || utility.is_some() {
                model.rehearse(&sample.offer.descriptor, resolved, millis, support, utility)?;
            }
        }
        Ok(())
    }
    fn rehearsal_indices(&self) -> Vec<usize> {
        let mut families = BTreeMap::new();
        for (i, s) in self.samples.iter().enumerate() {
            families
                .entry(s.offer.descriptor.features.family)
                .or_insert_with(Vec::new)
                .push(i);
        }
        // Keep the original update ceiling. Choose observed completion classes
        // before families, so a flood of misses cannot erase scarce successes.
        // A late old-checkpoint completion never supplies a current class.
        let groups = families.values().collect::<Vec<_>>();
        let mut outcomes = BTreeMap::<Option<bool>, BTreeMap<u16, Vec<usize>>>::new();
        if !self.family_only() {
            for (index, sample) in self.samples.iter().enumerate() {
                let fresh = sample.checkpoint.as_deref() == Some(self.checkpoint.as_str());
                let class = if fresh { sample.resolved } else { None };
                if class.is_some()
                    || sample.support == Some(true)
                    || sample.utility.is_some() && sample.utility_checkpoint == self.checkpoint
                {
                    outcomes
                        .entry(class)
                        .or_default()
                        .entry(sample.offer.descriptor.features.family)
                        .or_default()
                        .push(index);
                }
            }
        }
        let outcomes = outcomes.values().collect::<Vec<_>>();
        let mut result = Vec::new();
        for offset in 0..groups.len().min(3) {
            let index = if outcomes.len() > 1 {
                let ordinal = self.cursor as usize + offset;
                let classes = outcomes[ordinal % outcomes.len()]
                    .values()
                    .collect::<Vec<_>>();
                let position = ordinal / outcomes.len();
                let group = classes[position % classes.len()];
                group[(position / classes.len()) % group.len()]
            } else {
                let group = groups[(self.cursor as usize + offset) % groups.len()];
                group[(self.cursor as usize / groups.len()) % group.len()]
            };
            result.push(index);
        }
        result
    }
    pub fn utility(
        &mut self,
        model: &mut Model,
        snapshot: &crate::learning::finder::Utility,
    ) -> Result<bool, String> {
        #[cfg(test)]
        if matches!(
            self.treatment,
            crate::frontier::Treatment::Previous
                | crate::frontier::Treatment::Uniform
                | crate::frontier::Treatment::NoUtility
                | crate::frontier::Treatment::FamilyReplayNoUtility
        ) {
            return Ok(false);
        }
        snapshot.validate()?;
        if snapshot.checkpoint != self.checkpoint {
            return Ok(false);
        }
        let receipt = crate::learning::digest(snapshot);
        if receipt == self.utility_receipt {
            return Ok(false);
        }
        for score in &snapshot.scores {
            if let Some(sample) = self
                .samples
                .iter_mut()
                .find(|s| crate::hex(&s.offer.id) == score.resolution)
            {
                let value = ((f32::from(score.alignment) / 32767.) * f32::from(score.novelty)
                    / 65535.
                    + 1.)
                    / 2.;
                model.observe_utility(&sample.offer.descriptor, value)?;
                sample.utility = Some(value);
                sample.utility_checkpoint = self.checkpoint.clone();
                if let Some(recipe) = sample.offer.recipe {
                    let cell = &mut self.cells[recipe.index()];
                    cell.utility_count = cell.utility_count.saturating_add(1);
                    cell.utility_sum = cell.utility_sum.saturating_add((value * 65535.) as u64);
                }
            }
        }
        self.utility_receipt = receipt;
        self.rehearse(model)?;
        Ok(true)
    }
    pub fn feedback(
        &mut self,
        model: &mut Model,
        feedback: &crate::training::ability::Feedback,
    ) -> Result<bool, String> {
        feedback.validate()?;
        let changed = self.checkpoint != feedback.checkpoint;
        self.bind(&feedback.checkpoint);
        let progress = crate::learning::digest(&(
            &feedback.checkpoint,
            &feedback.development,
            &feedback.gains,
            &feedback.regressions,
        ));
        let progress_changed = progress != self.progress_receipt;
        if progress_changed && changed {
            self.acquired = self
                .acquired
                .saturating_add(feedback.gains.iter().map(|n| u64::from(*n)).sum());
            self.regressed = self
                .regressed
                .saturating_add(feedback.regressions.iter().map(|n| u64::from(*n)).sum());
        }
        self.progress_receipt = progress;
        let utility_changed = if let Some(utility) = &feedback.utility {
            self.utility(model, utility)?
        } else {
            false
        };
        Ok(changed || progress_changed || utility_changed)
    }
    pub fn utility_current(&self) -> bool {
        self.samples
            .iter()
            .any(|s| s.utility.is_some() && s.utility_checkpoint == self.checkpoint)
    }
}
