//! Checkpoint-local embeddings for exact token rows.
use super::*;
use std::collections::HashMap;

const ROWS: usize = 1024;

#[derive(Default)]
pub(in crate::learning::model) struct RowCache {
    ids: HashMap<Row, usize>,
    rows: Vec<[f32; WIDTH]>,
}

impl RowCache {
    #[cfg(test)]
    pub(in crate::learning::model) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(in crate::learning::model) fn clear(&mut self) {
        self.ids.clear();
        self.rows.clear();
    }
}

impl Policy {
    pub(in crate::learning::model) fn encode_cached(
        &self,
        batch: &Batch,
        roots: &[usize],
        cache: &mut RowCache,
    ) -> Result<Encoded, crate::Error> {
        let device = batch.device();
        if batch.rows.len() > ROWS {
            return Err(crate::ResearchFailure::FormulaCacheBatchCapacity.into());
        }
        let (indices, missing) = loop {
            if cache.rows.is_empty() {
                cache.rows.push([0.; WIDTH]);
            }
            let start = cache.rows.len();
            let mut indices = Vec::with_capacity(batch.rows.len());
            indices.push(0);
            let mut missing = Vec::new();
            for &row in batch.rows.iter().skip(1) {
                let index = *cache.ids.entry(row).or_insert_with(|| {
                    let index = start + missing.len();
                    missing.push(row);
                    index
                });
                indices.push(index);
            }
            if start + missing.len() <= ROWS {
                break (indices, missing);
            }
            cache.clear();
        };
        if !missing.is_empty() {
            let result = self
                .embed(&missing, &device)
                .into_data()
                .try_to_vec::<f32>();
            let values = match result {
                Ok(values)
                    if values.len() == missing.len() * WIDTH
                        && values.iter().all(|value| value.is_finite()) =>
                {
                    values
                }
                _ => {
                    cache.clear();
                    return Err(crate::ResearchFailure::MemoryTensorDecode.into());
                }
            };
            for row in values.chunks_exact(WIDTH) {
                cache
                    .rows
                    .push(row.try_into().expect("validated token row width"));
            }
        }
        let rows = indices
            .iter()
            .flat_map(|index| cache.rows[*index])
            .collect::<Vec<_>>();
        let activations =
            Tensor::from_data(TensorData::new(rows, [1, indices.len(), WIDTH]), &device);
        Ok(self.encode_with_context(batch, activations, Some(roots)))
    }
}
