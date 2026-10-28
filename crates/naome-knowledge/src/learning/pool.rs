//! A bounded on-demand proof pool. Features never contain sampling provenance.
use super::graph::Graph;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod reference;

type Rules = BTreeMap<i32, Vec<usize>>;
type Proofs = BTreeMap<String, Rules>;
type Families = BTreeMap<(String, String), Proofs>;
const WORK_BYTES: usize = super::MODEL_REQUIREMENTS.work_bytes / 16;
#[derive(Default)]
pub struct Pool {
    graphs: Vec<Graph>,
    work_bytes: usize,
    work_capacity: Option<usize>,
    keys: BTreeMap<String, usize>,
    origins: BTreeMap<bool, Families>,
    priorities: Vec<u64>,
    #[cfg(test)]
    reference: bool,
}
impl Pool {
    pub fn add(
        &mut self,
        peer: bool,
        dependency: &str,
        family: &str,
        proof: &str,
        graphs: Vec<Graph>,
    ) -> Result<(), String> {
        for mut graph in graphs {
            graph.successes.sort_unstable();
            graph.successes.dedup();
            let key = graph.key();
            let index = if let Some(index) = self.keys.get(&key) {
                let index = *index;
                let existing = &mut self.graphs[index];
                existing.successes.extend(&graph.successes);
                existing.successes.sort_unstable();
                existing.successes.dedup();
                index
            } else {
                self.work_bytes = self
                    .work_bytes
                    .checked_add(graph.work_bytes())
                    .ok_or("native pool work overflow")?;
                if self.work_bytes > self.work_capacity.unwrap_or(WORK_BYTES) {
                    return Err("native pool work capacity".into());
                }
                let index = self.graphs.len();
                self.graphs.push(graph);
                self.keys.insert(key, index);
                index
            };
            let graph = &self.graphs[index];
            let rules = graph
                .successes
                .iter()
                .map(|i| graph.nodes[graph.candidates[*i]].kind)
                .collect::<BTreeSet<_>>();
            let pool = self
                .origins
                .entry(peer)
                .or_default()
                .entry((dependency.into(), family.into()))
                .or_default()
                .entry(proof.into())
                .or_default();
            for rule in rules {
                let cases = pool.entry(rule).or_default();
                if !cases.contains(&index) {
                    cases.push(index);
                }
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn from_graphs(graphs: &[Graph]) -> Self {
        let mut pool = Self::default();
        pool.add(false, "test", "test", "test", graphs.to_vec())
            .unwrap();
        pool
    }
    pub fn graphs(&self) -> &[Graph] {
        &self.graphs
    }
    pub fn is_empty(&self) -> bool {
        self.graphs.is_empty()
    }
    /// Reference material shares the original pool allowance; it does not
    /// create a second memory reservation beside the training pool.
    pub(super) fn remaining(&self) -> Self {
        Self {
            work_capacity: Some(
                self.work_capacity
                    .unwrap_or(WORK_BYTES)
                    .saturating_sub(self.work_bytes),
            ),
            ..Self::default()
        }
    }
    pub fn unfocus(&mut self) {
        self.priorities.clear();
        #[cfg(test)]
        {
            self.reference = false;
        }
    }
    /// Reweight actual checked decision states. Their features, available
    /// alternatives and successful-action sets stay byte-for-byte unchanged.
    /// Unobserved alternatives remain unlabelled, not mathematical negatives.
    pub fn focus(
        &mut self,
        feedback: &crate::training::ability::Feedback,
        mut scores: impl FnMut(&Graph) -> Result<Vec<f32>, String>,
    ) -> Result<(), String> {
        #[cfg(test)]
        {
            self.reference = false;
        }
        self.priorities.clear();
        for graph in &self.graphs {
            let scores = scores(graph)?;
            if scores.len() != graph.candidates.len() || scores.iter().any(|x| !x.is_finite()) {
                return Err("preparation prediction shape or value differs".into());
            }
            let maximum = scores.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let exp = scores
                .iter()
                .map(|s| f64::from(*s - maximum).exp())
                .collect::<Vec<_>>();
            let known =
                graph.successes.iter().map(|i| exp[*i]).sum::<f64>() / exp.iter().sum::<f64>();
            let chance = graph.successes.len() as f64 / graph.candidates.len() as f64;
            let difficulty = ((1.0 - known) / (1.0 - chance).max(f64::EPSILON)).clamp(0.0, 1.0);
            let need = graph
                .successes
                .iter()
                .map(|i| feedback.rule_weight(graph.nodes[graph.candidates[*i]].kind))
                .max()
                .unwrap_or(1)
                .clamp(1, 9);
            self.priorities
                .push(1 + (difficulty * (4.0 + 3.0 * (need - 1) as f64 / 8.0)).round() as u64);
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn reference_focus(
        &mut self,
        feedback: &crate::training::ability::Feedback,
        scores: impl FnMut(&Graph) -> Result<Vec<f32>, String>,
    ) -> Result<(), String> {
        reference::focus(self, feedback, scores)
    }
    /// Origins, families, proofs and successful rule types keep the same cyclic
    /// allocation. Three complete decision cycles retain broad coverage; only
    /// the fourth uses bounded current-model priorities within that stratum.
    pub fn batch(&self, cursor: &mut u64) -> Vec<&Graph> {
        #[cfg(test)]
        if self.reference {
            return reference::batch(self, cursor);
        }
        let mut result = Vec::with_capacity(16);
        for _ in 0..16 {
            let mut position = *cursor;
            *cursor = cursor.wrapping_add(1);
            let family = select(&self.origins, &mut position);
            let proof = select(family, &mut position);
            let rules = select(proof, &mut position);
            let cases = select(rules, &mut position);
            let length = cases.len() as u64;
            let cycle = position / length;
            let index = position % length;
            let mut stride = 1 + ((cycle.wrapping_mul(0x9e3779b97f4a7c15)) % length);
            while gcd(stride, length) != 1 {
                stride = stride % length + 1;
            }
            let offset = cycle.wrapping_mul(0xbf58476d1ce4e5b9) % length;
            let mut selected = ((index.wrapping_mul(stride) + offset) % length) as usize;
            if !self.priorities.is_empty() && cycle % 4 == 3 {
                let mut random =
                    crate::sampling::Random::new((*cursor).wrapping_mul(0x9e3779b97f4a7c15));
                let mut draw = random.below(cases.iter().map(|i| self.priorities[*i]).sum());
                selected = cases
                    .iter()
                    .position(|i| {
                        if draw < self.priorities[*i] {
                            true
                        } else {
                            draw -= self.priorities[*i];
                            false
                        }
                    })
                    .expect("positive preparation weights");
            }
            result.push(&self.graphs[cases[selected]]);
        }
        result
    }
}
fn select<'a, K: Ord, V>(map: &'a BTreeMap<K, V>, position: &mut u64) -> &'a V {
    let index = *position % map.len() as u64;
    *position /= map.len() as u64;
    map.values()
        .nth(index as usize)
        .expect("nonempty proof sampling stratum")
}
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

#[cfg(test)]
mod tests;
