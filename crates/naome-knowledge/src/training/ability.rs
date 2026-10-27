//! Model- and allowance-bound scheduling evidence. These estimates concern
//! bounded solver completion, never mathematical truth or universal difficulty.
use super::*;

pub(crate) const SKILLS: usize = 6;
const LEVELS: u32 = 4;
const CELLS: usize = SKILLS * LEVELS as usize * 3;

/// A bounded search miss measures ability only when its actual search or time
/// allowance ended. Unsupported representations and technical errors are
/// unavailable observations, never unsuccessful mathematical outcomes.
pub(crate) fn completion(solved: bool, diagnostic: &str) -> Option<bool> {
    (solved || diagnostic.contains("search_budget") || diagnostic.contains("deadline"))
        .then_some(solved)
}

/// Coarse, overlapping operation families derived from actual primitive syntax.
/// A syntax signature is a scheduling hypothesis, not an oracle proof label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Skill {
    Logic,
    Instantiation,
    Equality,
    Lemma,
    Construction,
    Composition,
}
impl Skill {
    pub(crate) fn of_rule(kind: i32) -> Self {
        match kind {
            12 => Self::Instantiation,
            13 => Self::Equality,
            17 => Self::Lemma,
            14 | 15 | 18 => Self::Construction,
            16 => Self::Composition,
            _ => Self::Logic,
        }
    }
}

pub(crate) fn signature(q: &CompiledQuestion) -> ([bool; SKILLS], u32) {
    signature_features(&Features::of(q))
}
pub(crate) fn signature_features(f: &Features) -> ([bool; SKILLS], u32) {
    let mut skills = [false; SKILLS];
    skills[Skill::Logic as usize] = true;
    skills[Skill::Instantiation as usize] = f.counts[19] > 0 || f.counts[14] > 0;
    skills[Skill::Equality as usize] = f.counts[25] + f.counts[26] > 0;
    skills[Skill::Lemma as usize] = f.counts[30] > 2;
    skills[Skill::Construction as usize] = f.counts[31] > 2 && f.counts[29] > 1;
    skills[Skill::Composition as usize] = f.counts[30] > 4;
    let level = match u32::from(f.nodes).max(u32::from(f.depth) * 2) {
        0..=12 => 0,
        13..=32 => 1,
        33..=72 => 2,
        _ => 3,
    };
    (skills, level)
}

/// Compact operational cells: attempts, checked completions, microseconds,
/// unavailable observations and a coverage sketch. The sketch is not a count
/// of independent mathematical families and must not be used as a sample size.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub checkpoint: String,
    #[serde(deserialize_with = "numeric_cells")]
    cells: BTreeMap<u32, [u64; 5]>,
}
// JSON object keys are strings. Explicit decoding also works inside Serde's
// internally tagged supervisor frame, whose buffered map lacks JSON's numeric
// key coercion. Preserve one canonical numeric-key encoding on every boundary.
fn numeric_cells<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<u32, [u64; 5]>, D::Error> {
    BTreeMap::<String, [u64; 5]>::deserialize(deserializer)?
        .into_iter()
        .map(|(key, value)| {
            let index = key.parse::<u32>().map_err(serde::de::Error::custom)?;
            if index.to_string() != key {
                return Err(serde::de::Error::custom("noncanonical ability cell"));
            }
            Ok((index, value))
        })
        .collect()
}
impl Profile {
    pub(crate) fn new(checkpoint: String) -> Self {
        Self {
            checkpoint,
            cells: BTreeMap::new(),
        }
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        crate::object::id_bytes(&self.checkpoint)?;
        if self.cells.len() > CELLS
            || self.cells.iter().any(|(key, c)| {
                *key / (SKILLS as u32 * LEVELS) == 0
                    || *key / (SKILLS as u32 * LEVELS) > u16::MAX.into()
                    || c[1] > c[0]
            })
        {
            return Err("ability observations exceed their bounded contract".into());
        }
        Ok(())
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
    pub(crate) fn summary(&self) -> [(u64, u64, u64); SKILLS] {
        let mut out = [(0u64, 0u64, 0u64); SKILLS];
        for (key, c) in &self.cells {
            let skill = ((*key % (SKILLS as u32 * LEVELS)) / LEVELS) as usize;
            out[skill].0 = out[skill].0.saturating_add(c[0]);
            out[skill].1 = out[skill].1.saturating_add(c[1]);
            out[skill].2 = out[skill].2.saturating_add(c[3]);
        }
        out
    }
    fn key(budget: u32, skill: usize, level: u32) -> u32 {
        budget * (SKILLS as u32 * LEVELS) + skill as u32 * LEVELS + level
    }
    pub(crate) fn observe(
        &mut self,
        q: &CompiledQuestion,
        budget: u32,
        solved: Option<bool>,
        micros: u64,
    ) {
        if budget == 0 || budget > u16::MAX.into() {
            return;
        }
        self.observe_features(&Features::of(q), &group(q), budget, solved, micros);
    }
    pub(crate) fn observe_features(
        &mut self,
        features: &Features,
        group: &str,
        budget: u32,
        solved: Option<bool>,
        micros: u64,
    ) {
        if budget == 0 || budget > u16::MAX.into() {
            return;
        }
        let (skills, level) = signature_features(features);
        let group = Sha256::digest(group.as_bytes());
        for (skill, present) in skills.into_iter().enumerate() {
            if !present {
                continue;
            }
            let key = Self::key(budget, skill, level);
            if !self.cells.contains_key(&key) && self.cells.len() >= CELLS {
                continue;
            }
            let cell = self.cells.entry(key).or_default();
            cell[2] = cell[2].saturating_add(micros);
            cell[4] |= 1u64 << (group[0] % 64);
            if let Some(solved) = solved {
                cell[0] = cell[0].saturating_add(1);
                cell[1] = cell[1].saturating_add(u64::from(solved));
            } else {
                cell[3] = cell[3].saturating_add(1);
            }
        }
    }
    fn estimate(&self, skill: usize, level: u32, budget: u32) -> (f64, f64, f64) {
        if budget == 0 || budget > u16::MAX.into() {
            return (0.5, 1.0, 1.0);
        }
        let nearest = (0..LEVELS)
            .filter_map(|other| {
                self.cells
                    .get(&Self::key(budget, skill, other))
                    .filter(|c| c[0] > 0)
                    .map(|c| (level.abs_diff(other), other, c))
            })
            .min_by_key(|(distance, other, _)| (*distance, *other));
        let Some((distance, other, cell)) = nearest else {
            return (0.5, 1.0, 1.0);
        };
        let mut probability = (cell[1] as f64 + 1.0) / (cell[0] as f64 + 2.0);
        // Extrapolation is deliberately uncertain. Mastered levels expose the
        // next harder band; repeated substantive failure favors smaller goals.
        let scale = 0.5f64.powi(distance as i32);
        if level > other {
            probability *= scale;
        }
        if level < other {
            probability = 1.0 - (1.0 - probability) * scale;
        }
        let uncertainty = ((1.0 + distance as f64) / (cell[0] as f64 + 2.0))
            .sqrt()
            .min(1.0);
        let cost = cell[2] as f64 / cell[0].saturating_add(cell[3]).max(1) as f64 / 1000.0;
        (probability, uncertainty, cost.max(1.0))
    }
    pub(crate) fn priority(&self, q: &CompiledQuestion, budget: u32) -> u64 {
        self.priority_features(&Features::of(q), budget)
    }
    pub(crate) fn priority_features(&self, features: &Features, budget: u32) -> u64 {
        let (skills, level) = signature_features(features);
        let mut value = 0.0;
        let mut count = 0;
        for (skill, present) in skills.into_iter().enumerate() {
            if !present {
                continue;
            }
            let (p, uncertainty, cost) = self.estimate(skill, level, budget);
            // Expected reachable information and uncertainty per observed cost.
            // No fixed success rate is asserted to be optimal. Every case keeps
            // positive mass, in addition to the caller's uniform exploration.
            value += (p * (1.0 - p) * (1.5 - p / 2.0) + uncertainty / 4.0) / (1.0 + cost.sqrt());
            count += 1;
        }
        (value * 1_000_000.0 / f64::from(count.max(1))) as u64 + 1
    }
    pub(crate) fn need(&self, skill: Skill, budget: u32) -> u64 {
        let (attempts, successes) = (0..LEVELS)
            .filter_map(|level| self.cells.get(&Self::key(budget, skill as usize, level)))
            .fold((0u64, 0u64), |(n, s), c| {
                (n.saturating_add(c[0]), s.saturating_add(c[1]))
            });
        1 + (4 * u128::from(attempts.saturating_sub(successes)) / u128::from(attempts.max(1)))
            as u64
    }
}

/// Read-only scheduling view of the canonical learner. Its fields are never
/// formula/model inputs, work grants or accepted mathematical artifacts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Feedback {
    pub checkpoint: String,
    pub revision: u64,
    pub attempts: Profile,
    pub development: Profile,
    pub regressions: [u16; SKILLS],
    pub gains: [u16; SKILLS],
}
impl Feedback {
    pub(crate) fn fresh(checkpoint: String) -> Self {
        Self {
            attempts: Profile::new(checkpoint.clone()),
            development: Profile::new(checkpoint.clone()),
            checkpoint,
            revision: 0,
            regressions: [0; SKILLS],
            gains: [0; SKILLS],
        }
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.attempts.checkpoint != self.checkpoint
            || self.development.checkpoint != self.checkpoint
        {
            return Err("ability checkpoint binding differs".into());
        }
        self.attempts.validate()?;
        self.development.validate()
    }
    pub(crate) fn priority(&self, q: &CompiledQuestion, budget: u32) -> u64 {
        if self.development.is_empty() {
            self.attempts.priority(q, budget)
        } else {
            self.development.priority(q, 32)
        }
    }
    pub(crate) fn rule_weight(&self, kind: i32) -> u64 {
        let skill = Skill::of_rule(kind);
        self.development.need(skill, 32) + u64::from(self.regressions[skill as usize].min(4))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mastery_and_failure_change_reachable_bands_without_mixing_checkpoints_or_budgets() {
        let easy = CompiledQuestion::compile("goal=all(a,imp(mem(a,a),mem(a,a)))").unwrap();
        let hard = CompiledQuestion::compile(
            "goal=all(x,all(y,imp(mem(x,y),imp(mem(y,x),and(mem(x,y),mem(y,x))))))",
        )
        .unwrap();
        assert!(signature(&easy).1 < signature(&hard).1);
        let mut mastered = Profile::new("11".repeat(32));
        let mut blocked = Profile::new("11".repeat(32));
        for _ in 0..64 {
            mastered.observe(&easy, 128, Some(true), 1000);
            blocked.observe(&hard, 128, Some(false), 1000);
        }
        assert!(mastered.priority(&hard, 128) > mastered.priority(&easy, 128));
        assert!(blocked.priority(&easy, 128) > blocked.priority(&hard, 128));
        assert_eq!(
            mastered.priority(&easy, 32),
            Profile::new("22".repeat(32)).priority(&easy, 32)
        );
        let before = blocked.priority(&hard, 128);
        blocked.observe(&hard, 128, None, 1000);
        assert_eq!(blocked.priority(&hard, 128), before);
        assert!(Feedback::fresh("22".repeat(32)).validate().is_ok());
    }
}
