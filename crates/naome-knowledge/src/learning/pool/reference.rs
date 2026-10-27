//! Frozen scientific control matching the previous targeted sampler only.
//! Compiled exclusively for explicit research comparisons, never a provider.
use super::*;

pub(super) fn focus(
    pool: &mut Pool,
    feedback: &crate::training::ability::Feedback,
    mut scores: impl FnMut(&Graph) -> Result<Vec<f32>, String>,
) -> Result<(), String> {
    pool.reference = true;
    pool.priorities.clear();
    for graph in &pool.graphs {
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
        pool.priorities.push((correction * need).clamp(1, 32));
    }
    Ok(())
}
fn average<'a>(pool: &Pool, values: impl Iterator<Item = &'a usize>) -> u64 {
    let (sum, count) = values.fold((0u64, 0u64), |(s, n), i| (s + pool.priorities[*i], n + 1));
    sum / count.max(1)
}

pub(super) fn batch<'a>(pool: &'a Pool, cursor: &mut u64) -> Vec<&'a Graph> {
    let mut result = Vec::with_capacity(16);
    for _ in 0..16 {
        let mut position = *cursor;
        *cursor = cursor.wrapping_add(1);
        if !pool.priorities.is_empty() && (*cursor).is_multiple_of(5) {
            position = *cursor / 5;
        }
        let focused = !pool.priorities.is_empty() && !(*cursor).is_multiple_of(5);
        let mut random = crate::sampling::Random::new((*cursor).wrapping_mul(0x9e3779b97f4a7c15));
        let family = select(&pool.origins, &mut position);
        let proof = if focused {
            weighted(family, &mut position, &mut random, |proofs| {
                let values = proofs
                    .values()
                    .flat_map(|rules| rules.values())
                    .flat_map(|cases| cases.iter());
                average(pool, values)
            })
        } else {
            select(family, &mut position)
        };
        let rules = select(proof, &mut position);
        let cases = if focused {
            weighted(rules, &mut position, &mut random, |cases| {
                average(pool, cases.iter())
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
            let total = cases.iter().map(|i| pool.priorities[*i]).sum::<u64>();
            let mut selected = random.below(total);
            cases
                .iter()
                .position(|i| {
                    let weight = pool.priorities[*i];
                    if selected < weight {
                        true
                    } else {
                        selected -= weight;
                        false
                    }
                })
                .expect("positive preparation weights")
        };
        result.push(&pool.graphs[cases[index]]);
    }
    result
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
