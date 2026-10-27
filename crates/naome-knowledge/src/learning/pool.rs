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
    /// A hierarchical cyclic draw balances origins, families, proofs and rule
    /// types. A bijective per-cycle permutation reaches the entire decision
    /// pool; rebuilding an unchanged pool never resets it to a fixed prefix.
    pub fn batch(&self, cursor: &mut u64) -> Vec<Graph> {
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
            let index = (index.wrapping_mul(stride) + offset) % length;
            result.push(self.graphs[cases[index as usize]].clone());
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
}
