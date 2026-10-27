//! Shared exploration-preserving lottery for research and training.
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(crate) struct Random(pub(crate) u64);
impl Random {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub(crate) fn below(&mut self, limit: u64) -> u64 {
        let threshold = limit.wrapping_neg() % limit;
        loop {
            let value = self.next();
            if value >= threshold {
                return value % limit;
            }
        }
    }
}

pub(crate) fn draw(random: &mut Random, weights: &[u64]) -> usize {
    let mut selected = random.below(weights.iter().sum());
    for (index, weight) in weights.iter().enumerate() {
        if selected < *weight {
            return index;
        }
        selected -= weight;
    }
    unreachable!("draw lies in total weight")
}

/// Uniform-question baseline, or 80% weighted family sampling and 20% uniform
/// family exploration. Weights must be positive and the input nonempty.
pub(crate) fn choose<K: Ord + Clone>(
    random: &mut Random,
    candidates: &[(K, u64)],
    random_only: bool,
) -> usize {
    if random_only {
        return random.below(candidates.len() as u64) as usize;
    }
    let mut groups = BTreeMap::<K, Vec<(usize, u64)>>::new();
    for (index, (family, weight)) in candidates.iter().enumerate() {
        groups
            .entry(family.clone())
            .or_default()
            .push((index, *weight));
    }
    let explore = random.below(5) == 0;
    let weights = groups
        .values()
        .map(|members| {
            if explore {
                1
            } else {
                members.iter().map(|(_, w)| w).sum::<u64>() / members.len() as u64
            }
        })
        .collect::<Vec<_>>();
    let group = groups
        .values()
        .nth(draw(random, &weights))
        .expect("sampled family");
    let weights = group
        .iter()
        .map(|(_, w)| if explore { 1 } else { *w })
        .collect::<Vec<_>>();
    group[draw(random, &weights)].0
}
