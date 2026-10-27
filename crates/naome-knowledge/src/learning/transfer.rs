//! Whole-family transfer outcomes. Search misses are operational outcomes,
//! never mathematical falsity or authority to admit a proof.
use serde::{Deserialize, Serialize};
pub const FAMILIES: usize = 12;
pub const CASES: usize = FAMILIES * 2;
const ALL: u32 = (1 << CASES) - 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub before: u32,
    pub after: u32,
    pub observed: u32,
}
impl Summary {
    pub fn prefix(count: usize) -> u32 {
        (1u32 << count.min(CASES)) - 1
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.observed & !ALL != 0
            || self.observed & self.observed.wrapping_add(1) != 0
            || (self.before | self.after) & !self.observed != 0
        {
            return Err("noncanonical transfer outcome coverage".into());
        }
        Ok(())
    }
    pub fn record(&mut self, index: usize, before: bool, after: bool) -> Result<(), String> {
        self.validate()?;
        if index >= CASES || self.observed != Self::prefix(index) {
            return Err("transfer evaluation sequence differs".into());
        }
        self.before |= u32::from(before) << index;
        self.after |= u32::from(after) << index;
        self.observed |= 1 << index;
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.observed == ALL
    }
    pub fn families(&self) -> [[u8; 2]; FAMILIES] {
        std::array::from_fn(|index| {
            let shift = index * 2;
            [
                ((self.before >> shift) & 3).count_ones() as u8,
                ((self.after >> shift) & 3).count_ones() as u8,
            ]
        })
    }
    pub fn gain(&self) -> f32 {
        (self.after.count_ones() as f32 - self.before.count_ones() as f32) / CASES as f32
    }
    pub fn loss(&self) -> f32 {
        self.families().iter().filter(|p| p[1] < p[0]).count() as f32 / FAMILIES as f32
    }
    pub fn accepts(&self) -> bool {
        self.complete() && self.gain() > 0. && self.loss() == 0.
    }
}
pub(super) struct Outcome {
    pub solved: bool,
    pub diagnostic: String,
    pub micros: u64,
}
pub(super) struct Evaluation {
    pub before: Outcome,
    pub after: Outcome,
}
pub(super) fn evaluate<I: super::ArtifactIo + ?Sized>(
    source: &str,
    base: &super::State,
    candidate: &super::Checkpoint,
    engine: &mut super::Engine,
    io: &mut I,
    job: u64,
) -> Result<Evaluation, String> {
    let mut solve = |checkpoint: &super::Checkpoint| {
        let start = std::time::Instant::now();
        let (solution, diagnostic, _) = engine.with(checkpoint, io, |runtime| {
            super::solve_with_definitions(
                source,
                runtime,
                32,
                job,
                &base.definitions,
                &base.knowledge,
            )
        })?;
        Ok::<_, String>(Outcome {
            solved: solution.is_some(),
            diagnostic,
            micros: start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        })
    };
    Ok(Evaluation {
        before: solve(&base.model)?,
        after: solve(candidate)?,
    })
}
#[cfg(test)]
mod tests;
