//! Shared forecasts for local research. Effects are estimates of future checked
//! progress. The checker, job owner and model qualification gate retain authority.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const SCALE: u64 = 1_000;
const ACTIONS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Explore,
    Solve,
    Reuse,
    Train,
}
impl Action {
    const fn index(self) -> usize {
        match self {
            Self::Explore => 0,
            Self::Solve => 1,
            Self::Reuse => 2,
            Self::Train => 3,
        }
    }
}

/// Projection of a checked research state at the decision boundary. Raw
/// formulae, plans and model blobs remain in their original authoritative owners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frame {
    pub knowledge: [u8; 32],
    pub solver: String,
    pub solver_revision: u64,
    pub catalogue: u64,
    pub open_goals: u8,
    pub backlog: u8,
    pub finder_updates: u64,
    pub finder_rehearsals: u64,
    pub finder_utility: u64,
    pub finder_promotions: u64,
    pub draws: u64,
    pub solving_slots: u8,
    pub memory_bytes: u64,
    pub paid_work_units: u32,
    pub horizon_ms: u64,
    pub effects: Effects,
}
impl Frame {
    pub fn validate(&self) -> Result<(), crate::Error> {
        crate::object::id_bytes(&self.solver)?;
        self.effects.validate()?;
        if self.open_goals > 8
            || self.paid_work_units == 0
            || self.horizon_ms == 0
            || self.effects.solver.as_deref() != Some(self.solver.as_str())
        {
            return Err(crate::ResearchFailure::ResearchValueInvalid.into());
        }
        Ok(())
    }

    pub fn training(&self, prediction: [f32; 3]) -> Forecast {
        let [retained, risk, cost] = prediction;
        let continuation = (u64::from(self.open_goals) + u64::from(self.backlog.min(8))) * 62;
        self.forecast(
            Action::Train,
            quantize(retained),
            continuation,
            quantize(risk),
            quantize(cost / 2.),
        )
    }

    pub fn question(&self, action: Action, predictions: [f32; 3], overlap: u64) -> Forecast {
        let [solvable, cost, useful] = predictions;
        let opportunity = (quantize(useful) + overlap.min(8) * 125) / 2;
        self.forecast(action, quantize(solvable), opportunity, 0, quantize(cost))
    }

    /// Estimate the immediate transition and two later opportunities. A
    /// successor only contributes after the current action makes it possible.
    /// Failed qualification is a risk term, never positive mathematical credit.
    pub fn forecast(
        &self,
        action: Action,
        prior: u64,
        opportunity: u64,
        risk: u64,
        cost: u64,
    ) -> Forecast {
        let observed = &self.effects.by_action[action.index()];
        let reference = prior.min(SCALE);
        let candidate = if action == Action::Train {
            prior.min(SCALE)
        } else {
            let weight = observed.attempts.min(12);
            let checked = if observed.attempts == 0 {
                0
            } else {
                (u128::from(observed.checked) * u128::from(SCALE) / u128::from(observed.attempts))
                    as u64
            };
            (prior.min(SCALE) * 8 + checked * weight) / (8 + weight)
        };
        let immediate = if observed.qualified() {
            candidate
        } else {
            reference
        };
        let opportunity = opportunity.min(SCALE);
        let (downstream, continuation) = if action == Action::Train {
            (opportunity, opportunity)
        } else {
            // Catalogue age censors unused results. Count only confirmed
            // contributing paths. Catalogue size supplies a conservative exposure
            // scale without assigning failures to proofs still open to reuse.
            let uses = observed.reused.min(self.catalogue);
            let reuse = ratio(uses, self.catalogue.saturating_add(4));
            let continues = ratio(
                self.effects.continued,
                self.effects.reused.saturating_add(4),
            );
            ((opportunity + reuse) / 2, (opportunity + continues) / 2)
        };
        let next = immediate * downstream / SCALE;
        let following = next * continuation / SCALE;
        let work = if action == Action::Train {
            let queued_per_slot = u64::from(self.backlog) / u64::from(self.solving_slots.max(1));
            cost.min(SCALE)
                .saturating_add(queued_per_slot * 50)
                .min(SCALE)
        } else if !observed.qualified() || observed.attempts == 0 {
            cost.min(SCALE)
        } else {
            let millis = observed.spent_ms / observed.attempts;
            let measured = quantize((millis as f32).ln_1p() / 16.);
            (cost.min(SCALE) + measured) / 2
        };
        Forecast {
            action,
            immediate: immediate as u16,
            reference: reference as u16,
            candidate: candidate as u16,
            next: next as u16,
            following: following as u16,
            risk: risk.min(SCALE) as u16,
            cost: work as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Forecast {
    pub action: Action,
    pub immediate: u16,
    pub reference: u16,
    pub candidate: u16,
    pub next: u16,
    pub following: u16,
    pub risk: u16,
    pub cost: u16,
}
impl Forecast {
    pub fn validate(self) -> Result<(), crate::Error> {
        if [
            self.immediate,
            self.reference,
            self.candidate,
            self.next,
            self.following,
            self.risk,
            self.cost,
        ]
        .into_iter()
        .any(|value| u64::from(value) > SCALE)
            || self.following > self.next
            || self.next > self.immediate
            || self.immediate != self.reference && self.immediate != self.candidate
        {
            return Err(crate::ResearchFailure::ResearchValueInvalid.into());
        }
        Ok(())
    }

    pub fn value(self) -> i64 {
        value(
            self.immediate,
            self.next,
            self.following,
            self.risk,
            self.cost,
        )
    }
}

fn value(immediate: u16, next: u16, following: u16, risk: u16, cost: u16) -> i64 {
    let retained = i64::from(immediate) + i64::from(next) / 2 + i64::from(following) / 4;
    retained * SCALE as i64 / (SCALE as i64 + i64::from(cost)) - i64::from(risk)
}

/// Realized proof progress at the common paid allowance. Each arm sees the
/// same knowledge, so credit comes from what the arm actually checks.
pub(crate) fn measured_proof(checked: bool, paid: u64, allowance: u64) -> i64 {
    let cost = ratio(paid, allowance.max(1));
    value(u16::from(checked) * SCALE as u16, 0, 0, 0, cost as u16)
}

/// Credit a checked selection and, when observed, its verified contribution
/// to a later proof. The scale is shared with other paired observations.
pub(crate) fn measured_selection(order: std::cmp::Ordering, reused: bool) -> i64 {
    let chance = match order {
        std::cmp::Ordering::Greater => SCALE as u16,
        std::cmp::Ordering::Equal => SCALE as u16 / 2,
        std::cmp::Ordering::Less => 0,
    };
    let next = if reused { chance } else { 0 };
    value(chance, next, 0, 0, 0) * 2 / 3
}

/// Compare attributable value on independent blocks. Related variants share
/// one vote, and the positive balance must survive omitting its strongest
/// block. A loss contributes its measured cost without vetoing other gains.
#[derive(Default)]
pub(crate) struct Comparison {
    blocks: BTreeMap<[u8; 32], (i64, u32)>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Assessment {
    pub blocks: u32,
    pub gains: u32,
    pub losses: u32,
    pub mean: i32,
    pub without_best: i32,
}

impl Assessment {
    pub fn accepts(self) -> bool {
        self.blocks > 1 && self.without_best > 0
    }

    pub fn validate(self) -> Result<(), crate::Error> {
        if self.gains.saturating_add(self.losses) > self.blocks
            || i64::from(self.mean).abs() > SCALE as i64
            || i64::from(self.without_best).abs() > SCALE as i64
            || self.blocks < 2 && self.without_best != 0
            || self.blocks == 0 && self.mean != 0
            || self.blocks > 1 && self.without_best > self.mean
        {
            return Err(crate::ResearchFailure::ResearchValueInvalid.into());
        }
        Ok(())
    }

    /// Keep the lower measured advantage across work and CPU accounting.
    /// Timing may expose an expensive result, while timing alone cannot
    /// establish a benefit that the paid-work comparison did not observe.
    pub fn with_resource_bound(mut self, measured: Self) -> Self {
        self.mean = self.mean.min(measured.mean);
        self.without_best = self.without_best.min(measured.without_best);
        self
    }
}

impl Comparison {
    pub fn record(&mut self, block: [u8; 32], incumbent: i64, candidate: i64) {
        let (delta, count) = self.blocks.entry(block).or_default();
        *delta += candidate - incumbent;
        *count += 1;
    }

    pub fn assess(&self) -> Assessment {
        let blocks = self.blocks.len() as u32;
        let mut deltas = self
            .blocks
            .values()
            .map(|(sum, count)| sum / i64::from(*count));
        let Some(first) = deltas.next() else {
            return Assessment::default();
        };
        let (mut sum, mut best) = (first, first);
        let mut gains = u32::from(first > 0);
        let mut losses = u32::from(first < 0);
        for delta in deltas {
            sum += delta;
            best = best.max(delta);
            gains += u32::from(delta > 0);
            losses += u32::from(delta < 0);
        }
        Assessment {
            blocks,
            gains,
            losses,
            mean: (sum / i64::from(blocks)) as i32,
            without_best: if blocks > 1 {
                ((sum - best) / i64::from(blocks - 1)) as i32
            } else {
                0
            },
        }
    }
}

pub(crate) fn quantize(value: f32) -> u64 {
    (value.clamp(0., 1.) * SCALE as f32).round() as u64
}

fn ratio(numerator: u64, denominator: u64) -> u64 {
    (u128::from(numerator.min(denominator)) * u128::from(SCALE) / u128::from(denominator)) as u64
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observations {
    attempts: u64,
    checked: u64,
    spent_ms: u64,
    reused: u64,
    held_out: [u64; 2],
    reference_error: [u64; 2],
    candidate_error: [u64; 2],
}
impl Observations {
    fn qualified(&self) -> bool {
        self.held_out.iter().all(|n| *n >= 2)
            && self
                .candidate_error
                .iter()
                .zip(self.reference_error)
                .all(|(a, b)| *a <= b)
            && self.candidate_error != self.reference_error
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Effects {
    by_action: [Observations; ACTIONS],
    solver: Option<String>,
    pub reused: u64,
    pub continued: u64,
}
impl Effects {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if let Some(solver) = &self.solver {
            crate::object::id_bytes(solver)?;
        }
        if self.continued > self.reused
            || self.by_action.iter().any(|row| {
                row.checked > row.attempts
                    || row.reused > self.reused
                    || (0..2).any(|i| {
                        let maximum = row.held_out[i].saturating_mul(SCALE);
                        row.reference_error[i] > maximum || row.candidate_error[i] > maximum
                    })
            })
        {
            return Err(crate::ResearchFailure::ResearchValueInvalid.into());
        }
        Ok(())
    }

    pub fn bind(&mut self, solver: &str) -> bool {
        if self.solver.as_deref() == Some(solver) {
            return false;
        }
        self.solver = Some(solver.to_owned());
        self.by_action = Default::default();
        true
    }

    pub fn observe(
        &mut self,
        forecast: Forecast,
        resolution: &[u8; 32],
        solver: &str,
        checked: bool,
        millis: u64,
    ) -> bool {
        if self.solver.as_deref() != Some(solver) {
            return false;
        }
        let row = &mut self.by_action[forecast.action.index()];
        if resolution[0] & 3 == 0 {
            // Both predictions were bound before the same held-out solve.
            // Preserve each outcome class while admitting a lower-error blend.
            let class = usize::from(checked);
            let actual = if checked { SCALE } else { 0 };
            row.held_out[class] = row.held_out[class].saturating_add(1);
            row.reference_error[class] = row.reference_error[class]
                .saturating_add(u64::from(forecast.reference).abs_diff(actual));
            row.candidate_error[class] = row.candidate_error[class]
                .saturating_add(u64::from(forecast.candidate).abs_diff(actual));
        } else {
            row.attempts = row.attempts.saturating_add(1);
            row.checked = row.checked.saturating_add(u64::from(checked));
            row.spent_ms = row.spent_ms.saturating_add(millis);
        }
        true
    }

    pub fn reuse(&mut self, forecast: Option<(Forecast, &str)>, first: bool, continuation: bool) {
        if first {
            self.reused = self.reused.saturating_add(1);
            if let Some((forecast, checkpoint)) = forecast
                && self.solver.as_deref() == Some(checkpoint)
            {
                let row = &mut self.by_action[forecast.action.index()];
                row.reused = row.reused.saturating_add(1);
            }
        }
        if continuation {
            self.continued = self.continued.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_assessment_requires_replicated_value_and_balances_losses() {
        let failed = measured_proof(false, 32, 32);
        let checked = measured_proof(true, 32, 32);
        let mut comparison = Comparison::default();
        for _ in 0..8 {
            comparison.record([1; 32], failed, checked);
        }
        assert!(!comparison.assess().accepts());
        comparison.record([2; 32], checked, failed);
        comparison.record([3; 32], failed, checked);
        assert!(!comparison.assess().accepts());
        comparison.record([4; 32], failed, checked);
        let assessment = comparison.assess();
        assert!(assessment.accepts());
        assert!(assessment.validate().is_ok());
        assert_eq!(
            (assessment.blocks, assessment.gains, assessment.losses),
            (4, 3, 1)
        );
    }

    #[test]
    fn recurring_paid_savings_contribute_to_system_value() {
        let before = measured_proof(true, 32, 32);
        let after = measured_proof(true, 12, 32);
        let mut comparison = Comparison::default();
        comparison.record([1; 32], before, after);
        comparison.record([2; 32], before, after);
        assert!(comparison.assess().accepts());
        assert!(after > before);
    }

    fn frame() -> Frame {
        Frame {
            knowledge: [4; 32],
            solver: crate::hex(&[5; 32]),
            solver_revision: 2,
            catalogue: 16,
            open_goals: 2,
            backlog: 2,
            finder_updates: 4,
            finder_rehearsals: 2,
            finder_utility: 1,
            finder_promotions: 0,
            draws: 20,
            solving_slots: 1,
            memory_bytes: 512 << 20,
            paid_work_units: 128,
            horizon_ms: 30_000,
            effects: Effects::default(),
        }
    }

    #[test]
    fn matched_outcomes_qualify_contextual_forecasts_without_class_regression() {
        let mut state = frame();
        let solver = state.solver.clone();
        let action = Action::Explore;
        assert!(state.effects.bind(&solver));
        let seed = state.forecast(action, 500, 500, 0, 250);
        for (id, checked) in [(1, false), (2, true), (3, true), (5, false)] {
            assert!(state.effects.observe(seed, &[id; 32], &solver, checked, 50));
        }
        let positive = state.forecast(action, 100, 500, 0, 250);
        let negative = state.forecast(action, 900, 500, 0, 250);
        assert_eq!((positive.immediate, negative.immediate), (100, 900));
        assert!(
            !state
                .effects
                .observe(negative, &[0; 32], &crate::hex(&[6; 32]), false, 50)
        );
        for id in [0, 4] {
            assert!(
                state
                    .effects
                    .observe(positive, &[id; 32], &solver, true, 50)
            );
        }
        assert!(
            state
                .effects
                .observe(positive, &[8; 32], &solver, false, 50)
        );
        assert!(
            state
                .effects
                .observe(positive, &[12; 32], &solver, false, 50)
        );
        assert_eq!(state.forecast(action, 100, 500, 0, 250).immediate, 100);
        for id in [16, 20] {
            assert!(
                state
                    .effects
                    .observe(negative, &[id; 32], &solver, false, 50)
            );
        }
        let qualified = state.forecast(action, 100, 500, 0, 250);
        assert!(qualified.immediate > 100);
        assert!(qualified.validate().is_ok());
        assert!(state.effects.bind(&crate::hex(&[6; 32])));
        assert_eq!(state.forecast(action, 100, 500, 0, 250).immediate, 100);
    }

    #[test]
    fn observed_paths_and_competing_costs_change_common_value() {
        let mut state = frame();
        let solver = state.solver.clone();
        state.effects.bind(&solver);
        let estimate = |state: &Frame| state.forecast(Action::Reuse, 550, 600, 0, 250);
        let original = estimate(&state);
        state.effects.reuse(Some((original, &solver)), true, false);
        let direct = estimate(&state);
        assert!(direct.next > original.next);
        state.effects.reuse(Some((direct, &solver)), true, true);
        let continued = estimate(&state);
        assert!(continued.following > direct.following);
        assert!(continued.value() > original.value());
        assert!(state.validate().is_ok());
        let train = state.training([0.2, 0.6, 0.1]);
        assert!(train.value() > state.training([0.2, 0.6, 1.]).value());
        assert!(train.value() > state.training([0.2, 0.9, 0.1]).value());
        state.open_goals = 0;
        state.backlog = 0;
        assert_eq!(state.training([0.2, 0.6, 0.1]).following, 0);
    }
}
