//! Bounded backpropagation through actual observed, checked predecessor edges.
use super::*;
use burn::tensor::{Int, TensorData};

impl Runtime {
    pub(super) fn preservation_scores(
        &mut self,
        pool: &Pool,
        cursor: &mut u64,
    ) -> Result<(Batch, Tensor<2>), String> {
        let contextual = self.recurrence == Recurrence::Carry && {
            #[cfg(test)]
            {
                !self.independent_preservation
            }
            #[cfg(not(test))]
            {
                true
            }
        };
        if contextual {
            let references = pool.preservation_batch(cursor)?;
            let graphs: Vec<_> = references.samples.iter().map(|s| s.graph).collect();
            let batch = Batch::from_graphs(&graphs, &self.device)?;
            if self.observe_batches() {
                self.measurements
                    .reference_prefixes(&references, self.recurrence);
            }
            let scores = self.sequence_scores(&batch, &references.samples)?;
            Ok((batch, scores))
        } else {
            // Keep the independent-graph control's original numerical path.
            let references = pool.batch(cursor);
            let batch = Batch::from_graphs(&references, &self.device)?;
            if self.observe_batches() {
                self.measurements.reference(&references, self.recurrence);
            }
            let memory = self
                .recurrent()
                .then(|| Tensor::zeros([batch.goal.dims()[0], policy::WIDTH], &self.device));
            let scores = self.policy.readout(self.policy.encode(&batch), memory).0;
            Ok((batch, scores))
        }
    }

    pub(super) fn sequence_scores(
        &self,
        batch: &Batch,
        sample: &[super::super::pool::Sample<'_>],
    ) -> Result<Tensor<2>, String> {
        if sample.len() != batch.goal.dims()[0] || sample.len() > 16 {
            return Err("native sequence batch shape differs".into());
        }
        let mut depths = Vec::with_capacity(sample.len());
        for (index, member) in sample.iter().enumerate() {
            let depth = if let Some(parent) = member.parent {
                if parent >= index {
                    return Err("native sequence predecessor differs".into());
                }
                depths[parent] + 1
            } else {
                0
            };
            if depth >= 4 || member.selected >= member.graph.candidates.len() {
                return Err("native sequence depth or selected action differs".into());
            }
            depths.push(depth);
        }
        // Disjoint adjacency and attention masks prevent one encoded example
        // from observing another. Only checked chronological edges below carry
        // gradients across examples. For preservation these are reconstructed
        // checked-proof edges, not observed chronology. Truncation starts at zero.
        let encoded = self.policy.encode(batch);
        let mut scores: Vec<Option<Tensor<2>>> = vec![None; sample.len()];
        let mut memories: Vec<Option<Tensor<2>>> = vec![None; sample.len()];
        for depth in 0..4 {
            let indices: Vec<_> = depths
                .iter()
                .enumerate()
                .filter_map(|(i, d)| (*d == depth).then_some(i))
                .collect();
            if indices.is_empty() {
                continue;
            }
            let selected: Tensor<1, Int> = Tensor::from_data(
                TensorData::new(indices.iter().map(|i| *i as i32).collect(), [indices.len()]),
                &self.device,
            );
            let initial = if self.recurrence == Recurrence::Disabled {
                None
            } else {
                let states = indices
                    .iter()
                    .map(|i| {
                        if self.recurrence == Recurrence::Carry
                            && let Some(parent) = sample[*i].parent
                        {
                            memories[parent].clone().ok_or_else(|| {
                                "native sequence memory predecessor missing".to_string()
                            })
                        } else {
                            Ok(Tensor::zeros([1, policy::WIDTH], &self.device))
                        }
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Some(Tensor::cat(states, 0))
            };
            let (logits, successors) = self.policy.readout(encoded.select(selected), initial);
            let candidates = logits.dims()[1];
            for (row, index) in indices.iter().copied().enumerate() {
                scores[index] = Some(logits.clone().slice([row..row + 1, 0..candidates]));
                // Reset control computes the same candidate transitions; their
                // tensors are discarded only at the next actual decision.
                memories[index] = successors.as_ref().map(|values| {
                    values
                        .clone()
                        .slice([
                            row..row + 1,
                            sample[index].selected..sample[index].selected + 1,
                            0..policy::WIDTH,
                        ])
                        .squeeze_dim::<2>(1)
                });
            }
        }
        Ok(Tensor::cat(
            scores
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or("native sequence output missing")?,
            0,
        ))
    }

    pub(super) fn sequence_loss(
        &self,
        logits: Tensor<2>,
        batch: &Batch,
        sample: &[super::super::pool::Sample<'_>],
        pool: &Pool,
        phase: super::super::meta::Phase,
    ) -> Tensor<1> {
        let count = sample.len();
        let mask = Tensor::from_data(
            TensorData::new(
                sample
                    .iter()
                    .map(|s| u8::from(!s.auxiliary || self.rich_targets) as f32)
                    .collect(),
                [count, 1],
            ),
            &self.device,
        );
        let denominator = mask.clone().sum().clamp_min(1.);
        let probability = burn::tensor::activation::log_softmax(logits.clone(), 1).exp();
        let marginal = -(probability * batch.successes.clone())
            .sum_dim(1)
            .clamp_min(1e-12)
            .log();
        let per_graph = if phase.ranking_quarters == 0 {
            marginal
        } else {
            let good = logits
                .clone()
                .mask_fill(batch.successes.clone().equal_elem(0.), -10000.)
                .max_dim(1);
            let other = logits
                .clone()
                .mask_fill(batch.successes.clone().greater_elem(0.), -10000.)
                .mask_fill(batch.invalid.clone(), -10000.)
                .max_dim(1);
            let ranking = (other - good + 0.2).clamp_min(0.);
            let weight = f32::from(phase.ranking_quarters) / 4.;
            marginal * (1. - weight) + ranking * weight
        };
        let mut loss = (per_graph * mask).sum() / denominator;
        if !self.rich_targets {
            return loss;
        }
        let mut costs = Vec::new();
        let mut preferences = Vec::new();
        for (row, sample) in sample.iter().enumerate() {
            let witnesses = pool.witnesses(sample.graph);
            for (index, witness) in witnesses.iter().enumerate() {
                // This predicts checked symbolic suffix work. It is not a
                // measurement or label for physical CPU or future search time.
                let score = logits
                    .clone()
                    .slice([row..row + 1, witness.action..witness.action + 1])
                    .reshape([1]);
                let residual = score.clone() + (witness.remaining_steps as f32).ln_1p();
                costs.push(residual.clone() * residual);
                for other in &witnesses[index + 1..] {
                    if witness.source == other.source
                        || witness.remaining_steps == other.remaining_steps
                    {
                        continue;
                    }
                    let other_score = logits
                        .clone()
                        .slice([row..row + 1, other.action..other.action + 1])
                        .reshape([1]);
                    let difference = if witness.remaining_steps < other.remaining_steps {
                        other_score - score.clone()
                    } else {
                        score.clone() - other_score
                    };
                    preferences.push((difference + 0.2).clamp_min(0.));
                }
            }
        }
        if !costs.is_empty() {
            loss = loss + Tensor::cat(costs, 0).mean() * 0.05;
        }
        if !preferences.is_empty() {
            loss = loss + Tensor::cat(preferences, 0).mean() * 0.05;
        }
        loss
    }
}
