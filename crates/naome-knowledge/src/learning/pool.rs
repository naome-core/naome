//! A bounded on-demand proof pool. Features never contain sampling provenance.
use super::graph::Graph;
use std::collections::{BTreeMap, BTreeSet};

type Rules = BTreeMap<i32, Vec<usize>>;
type Proofs = BTreeMap<String, Rules>;
type Families = BTreeMap<(String, String), Proofs>;
#[derive(Default)]
pub struct Pool {
    graphs: Vec<Graph>,
    work_bytes: usize,
    keys: BTreeMap<String, usize>,
    origins: BTreeMap<bool, Families>,
    priorities: Vec<u64>,
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
                if self.work_bytes > super::MODEL_REQUIREMENTS.work_bytes / 16 {
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
    /// Reweight actual checked decision states. Their features, available
    /// alternatives and successful-action sets stay byte-for-byte unchanged.
    /// Unobserved alternatives remain unlabelled, not mathematical negatives.
    pub fn focus(
        &mut self,
        feedback: &crate::training::ability::Feedback,
        mut scores: impl FnMut(&Graph) -> Result<Vec<f32>, String>,
    ) -> Result<(), String> {
        self.priorities.clear();
        for graph in &self.graphs {
            let scores = scores(graph)?;
            if scores.len() != graph.candidates.len() || scores.iter().any(|x| !x.is_finite()) {
                return Err("preparation prediction shape or value differs".into());
            }
            let best = scores
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.total_cmp(b.1))
                .map(|(i, _)| i)
                .unwrap();
            let correction = if graph.successes.contains(&best) {
                1
            } else {
                4
            };
            let need = graph
                .successes
                .iter()
                .map(|i| feedback.rule_weight(graph.nodes[graph.candidates[*i]].kind))
                .max()
                .unwrap_or(1);
            self.priorities.push((correction * need).clamp(1, 32));
        }
        Ok(())
    }
    fn average<'a>(&self, values: impl Iterator<Item = &'a usize>) -> u64 {
        let (sum, count) = values.fold((0u64, 0u64), |(s, n), i| (s + self.priorities[*i], n + 1));
        sum / count.max(1)
    }
    /// A hierarchical cyclic draw balances origins, families, proofs and rule
    /// types. A bijective per-cycle permutation reaches the entire decision
    /// pool; rebuilding an unchanged pool never resets it to a fixed prefix.
    pub fn batch(&self, cursor: &mut u64) -> Vec<&Graph> {
        let mut result = Vec::with_capacity(16);
        for _ in 0..16 {
            let mut position = *cursor;
            *cursor = cursor.wrapping_add(1);
            if !self.priorities.is_empty() && (*cursor).is_multiple_of(5) {
                position = *cursor / 5;
            }
            let focused = !self.priorities.is_empty() && !(*cursor).is_multiple_of(5);
            let mut random =
                crate::sampling::Random::new((*cursor).wrapping_mul(0x9e3779b97f4a7c15));
            let family = select(&self.origins, &mut position);
            let proof = if focused {
                weighted(family, &mut position, &mut random, |proofs| {
                    let values = proofs
                        .values()
                        .flat_map(|rules| rules.values())
                        .flat_map(|cases| cases.iter());
                    self.average(values)
                })
            } else {
                select(family, &mut position)
            };
            let rules = select(proof, &mut position);
            let cases = if focused {
                weighted(rules, &mut position, &mut random, |cases| {
                    self.average(cases.iter())
                })
            } else {
                select(rules, &mut position)
            };
            let length = cases.len() as u64;
            let cycle = position / length;
            let index = position % length;
            let mut stride = 1 + ((cycle.wrapping_mul(0x9e3779b97f4a7c15)) % length);
            while gcd(stride, length) != 1 {
                stride = stride % length + 1;
            }
            let offset = cycle.wrapping_mul(0xbf58476d1ce4e5b9) % length;
            let index = (index.wrapping_mul(stride) + offset) % length;
            let index = if !focused {
                index as usize
            } else {
                let total = cases.iter().map(|i| self.priorities[*i]).sum::<u64>();
                let mut selected = random.below(total);
                cases
                    .iter()
                    .position(|i| {
                        let weight = self.priorities[*i];
                        if selected < weight {
                            true
                        } else {
                            selected -= weight;
                            false
                        }
                    })
                    .expect("positive preparation weights")
            };
            result.push(&self.graphs[cases[index]]);
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
fn weighted<'a, K: Ord, V>(
    map: &'a BTreeMap<K, V>,
    position: &mut u64,
    random: &mut crate::sampling::Random,
    weight: impl Fn(&V) -> u64,
) -> &'a V {
    *position /= map.len() as u64;
    let weights = map.values().map(|v| weight(v).max(1)).collect::<Vec<_>>();
    map.values()
        .nth(crate::sampling::draw(random, &weights))
        .unwrap()
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
mod tests {
    use super::*;
    use crate::learning::graph::Node;
    fn case(number: usize) -> Graph {
        Graph {
            binding: String::new(),
            nodes: vec![
                Node {
                    kind: 0,
                    left: 0,
                    right: 0,
                    role: 0,
                },
                Node {
                    kind: 10,
                    left: 0,
                    right: 0,
                    role: 0,
                },
            ],
            goal: number,
            context: vec![],
            candidates: vec![1],
            expert: 0,
            successes: vec![0],
        }
    }
    #[test]
    fn large_pools_are_fully_reached_after_rebuilds_without_repeating_a_prefix() {
        let graphs = (0..1009).map(case).collect::<Vec<_>>();
        let mut cursor = 0;
        let mut seen = BTreeSet::new();
        for _ in 0..64 {
            let pool = Pool::from_graphs(&graphs);
            for graph in pool.batch(&mut cursor) {
                seen.insert(graph.goal);
            }
        }
        assert_eq!(seen.len(), 1009);
        let pool = Pool::from_graphs(&graphs);
        let mut second = cursor;
        assert_eq!(
            pool.batch(&mut cursor)
                .iter()
                .map(|g| g.goal)
                .collect::<Vec<_>>(),
            pool.batch(&mut second)
                .iter()
                .map(|g| g.goal)
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn checked_alternatives_merge_only_for_the_same_fully_bound_state() {
        let mut a = case(3);
        a.candidates.push(1);
        a.successes = vec![0];
        let mut b = a.clone();
        b.expert = 1;
        b.successes = vec![1];
        let mut other = b.clone();
        other.context.push(1);
        let mut pool = Pool::default();
        pool.add(false, "d", "f", "first", vec![a]).unwrap();
        pool.add(true, "d", "f", "later", vec![b, other]).unwrap();
        assert_eq!(pool.graphs.len(), 2);
        assert_eq!(pool.graphs[0].successes, vec![0, 1]);
        assert_eq!(pool.graphs[1].successes, vec![1]);
    }
    #[test]
    fn targeting_changes_batches_but_not_states_labels_or_source_coverage() {
        let mut easy = case(0);
        easy.nodes.push(Node {
            kind: 17,
            left: 0,
            right: 0,
            role: 0,
        });
        easy.candidates.push(2);
        let mut hard = easy.clone();
        hard.goal = 1;
        let mut pool = Pool::default();
        pool.add(false, "old", "old", "p0", vec![easy]).unwrap();
        pool.add(false, "weak", "weak", "p1", vec![hard]).unwrap();
        let keys = pool.graphs.iter().map(Graph::key).collect::<Vec<_>>();
        let labels = pool
            .graphs
            .iter()
            .map(|g| g.successes.clone())
            .collect::<Vec<_>>();
        let feedback = crate::training::ability::Feedback::fresh("12".repeat(32));
        pool.focus(&feedback, |g| {
            Ok(if g.goal == 0 {
                vec![1., 0.]
            } else {
                vec![0., 1.]
            })
        })
        .unwrap();
        assert_eq!(keys, pool.graphs.iter().map(Graph::key).collect::<Vec<_>>());
        assert_eq!(
            labels,
            pool.graphs
                .iter()
                .map(|g| g.successes.clone())
                .collect::<Vec<_>>()
        );
        let mut cursor = 0;
        let mut hits = [0usize; 2];
        for _ in 0..256 {
            for graph in pool.batch(&mut cursor) {
                hits[graph.goal] += 1;
            }
        }
        assert!(hits[1] > hits[0] * 2, "{hits:?}");
        assert!(hits[0] > 256, "older source retains exploration and replay");
    }
}
