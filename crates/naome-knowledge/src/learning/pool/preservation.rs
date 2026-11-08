//! Reconstructed checked-proof prefixes for functional preservation.
//! These edges are proof ancestry, not observed search chronology.
use super::*;
use serde::Serialize;

#[derive(Serialize)]
pub(in crate::learning) struct Source<'a> {
    proof: &'a str,
    tree: &'a str,
    step: usize,
    witness: &'a str,
}

pub(in crate::learning) struct References<'a> {
    pub samples: Vec<Sample<'a>>,
    pub sources: Vec<Option<Source<'a>>>,
}

impl Pool {
    /// Reuse the existing sixteen reference slots and cyclic seed schedule.
    /// A checked ancestor occupies a slot; no extra examples or latent state
    /// are stored. Truncated prefixes start from zero under current weights.
    pub(in crate::learning) fn preservation_batch(
        &self,
        cursor: &mut u64,
    ) -> Result<References<'_>, String> {
        let seeds = self.batch(cursor);
        let mut samples = Vec::with_capacity(16);
        let mut sources = Vec::with_capacity(16);
        while samples.len() < seeds.len() {
            let slot = samples.len();
            let seed = seeds[slot];
            let key = seed.key();
            let mut found = None;
            for offset in 0..self.derivations.len() {
                let source =
                    &self.derivations[cursor.wrapping_add(slot as u64).wrapping_add(offset as u64)
                        as usize
                        % self.derivations.len()];
                if source.source_proof.is_none() {
                    continue;
                }
                if let Some(index) = source.steps.iter().position(|step| {
                    step.graph.binding == seed.binding
                        && step.graph.key() == key
                        && seed.successes.contains(&step.graph.expert)
                }) {
                    found = Some((source, index));
                    break;
                }
            }
            if let Some((source, index)) = found {
                let mut window = vec![index];
                while window.len() < 4.min(16 - slot) {
                    let index = *window.last().expect("nonempty checked prefix");
                    let step = &source.steps[index];
                    let Some((parent, child)) = step.parent else {
                        if !step.branch.is_empty() {
                            return Err("preservation prefix root branch differs".into());
                        }
                        break;
                    };
                    if parent >= index {
                        return Err("preservation prefix predecessor differs".into());
                    }
                    let previous = &source.steps[parent];
                    if child >= previous.children
                        || step.branch.len() != previous.branch.len() + 1
                        || step.branch[..previous.branch.len()] != previous.branch
                        || step.branch.last() != Some(&child)
                    {
                        return Err("preservation prefix crosses a checked branch".into());
                    }
                    window.push(parent);
                }
                for (offset, index) in window.into_iter().rev().enumerate() {
                    let step = &source.steps[index];
                    let graph = self
                        .keys
                        .get(&step.graph.key())
                        .map_or(&step.graph, |index| &self.graphs[*index]);
                    if !graph.successes.contains(&step.graph.expert) {
                        return Err("preservation prefix action lacks a checked label".into());
                    }
                    samples.push(Sample {
                        graph,
                        selected: step.graph.expert,
                        parent: (offset > 0).then(|| samples.len() - 1),
                        auxiliary: false,
                    });
                    sources.push(Some(Source {
                        proof: source.source_proof.as_deref().expect("admitted source"),
                        tree: &source.source_tree,
                        step: index,
                        witness: &step.witness,
                    }));
                }
            } else {
                samples.push(Sample {
                    graph: seed,
                    selected: seed.expert,
                    parent: None,
                    auxiliary: false,
                });
                sources.push(None);
            }
        }
        Ok(References { samples, sources })
    }
}

#[cfg(test)]
mod tests;
