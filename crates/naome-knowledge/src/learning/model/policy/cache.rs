//! Checkpoint-local formula activations. Keys contain exact structural operands.
use super::*;
use burn::tensor::TensorData;
use std::collections::HashMap;

const ROWS: usize = 1024;
type Stages = [[f32; WIDTH]; LAYERS + 1];

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    kind: i32,
    symbol: i32,
    left: usize,
    right: usize,
}

/// Owns at most 1024 structural nodes per live model, including six
/// intermediate rows per node. Weight changes discard the whole cache.
#[derive(Default)]
pub(in crate::learning::model) struct FormulaCache {
    ids: HashMap<Key, usize>,
    rows: Vec<Stages>,
}

impl FormulaCache {
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
        cache: &mut FormulaCache,
    ) -> Result<Encoded, String> {
        let device = batch.kinds.device();
        if batch.nodes.len() > ROWS {
            return Err("formula activation cache batch capacity".into());
        }
        let (indices, missing) = loop {
            if cache.rows.is_empty() {
                cache.rows.push([[0.; WIDTH]; LAYERS + 1]);
            }
            let start = cache.rows.len();
            let mut indices = vec![0];
            let mut missing = Vec::new();
            for node in batch.nodes.iter().skip(1) {
                let key = Key {
                    kind: node.kind,
                    symbol: node.symbol,
                    left: indices[node.left],
                    right: indices[node.right],
                };
                let id = *cache.ids.entry(key).or_insert_with(|| {
                    let id = start + missing.len();
                    missing.push(key);
                    id
                });
                indices.push(id);
            }
            if start + missing.len() <= ROWS {
                break (indices, missing);
            }
            cache.clear();
        };
        if !missing.is_empty()
            && let Err(error) = self.fill(&device, cache, &missing)
        {
            // A failed conversion cannot publish a partially initialized row.
            cache.clear();
            return Err(error);
        }
        let rows = indices
            .iter()
            .flat_map(|id| cache.rows[*id][LAYERS])
            .collect::<Vec<_>>();
        let h = Tensor::from_data(TensorData::new(rows, [1, indices.len(), WIDTH]), &device);
        Ok(self.encode_with_context(batch, h))
    }

    fn fill(
        &self,
        device: &Device,
        cache: &mut FormulaCache,
        missing: &[Key],
    ) -> Result<(), String> {
        let start = cache.rows.len();
        let n = missing.len();
        let input = |column| {
            let values = missing
                .iter()
                .map(|key| if column == 0 { key.kind } else { key.symbol })
                .collect::<Vec<_>>();
            Tensor::from_data(TensorData::new(values, [1, n]), device)
        };
        let mut h = self.embedding(input(0), input(1));
        cache.rows.resize(start + n, [[0.; WIDTH]; LAYERS + 1]);
        for stage in 0..=LAYERS {
            let values = h
                .clone()
                .into_data()
                .try_to_vec::<f32>()
                .map_err(|e| e.to_string())?;
            for (i, row) in values.chunks_exact(WIDTH).enumerate() {
                cache.rows[start + i][stage].copy_from_slice(row);
            }
            if let Some(layer) = self.messages.get(stage) {
                let gather = |left| {
                    let values = missing
                        .iter()
                        .flat_map(|key| cache.rows[if left { key.left } else { key.right }][stage])
                        .collect::<Vec<_>>();
                    Tensor::from_data(TensorData::new(values, [1, n, WIDTH]), device)
                };
                h = Self::message(layer, h, gather(true), gather(false));
            }
        }
        Ok(())
    }
}
