//! Exact counterfactual parameter substitutions. Coordinate order is the
//! canonical tensor path and the tensor's row-major scalar index.
use super::{Runtime, pack_failure, record_failure};
use burn::{module::Module, store::ModuleRecord, tensor::Bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::learning) struct Span {
    pub start: u32,
    pub end: u32,
}

pub(in crate::learning) struct Weights {
    tensors: Vec<Pair>,
    metadata: Vec<(String, String)>,
    scalars: Vec<(String, burn_pack::Scalar)>,
    pub modules: Vec<(String, Span)>,
    pub parameters: u32,
}

struct Pair {
    tensor: burn_pack::Tensor,
    origin: Bytes,
    trained: Bytes,
    span: Span,
}

impl Weights {
    pub fn capture(parent: &Runtime, candidate: &Runtime) -> Result<Self, crate::Error> {
        let snapshot = |runtime: &Runtime| {
            burn_pack::Reader::from_bytes(
                runtime
                    .policy
                    .clone()
                    .into_record()
                    .into_bytes()
                    .map_err(record_failure)?,
            )
            .map_err(pack_failure)
        };
        let parent = snapshot(parent)?;
        let candidate = snapshot(candidate)?;
        let invalid = || crate::ResearchFailure::ModelCheckpointBinding;
        if parent.metadata() != candidate.metadata() || parent.scalars() != candidate.scalars() {
            return Err(invalid().into());
        }
        let metadata = parent
            .metadata()
            .iter()
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect();
        let scalars = parent
            .scalars()
            .iter()
            .map(|(a, b)| (a.clone(), *b))
            .collect();
        let mut origin = parent.into_tensors().map_err(pack_failure)?;
        let mut trained = candidate.into_tensors().map_err(pack_failure)?;
        origin.sort_by(|a, b| a.name.cmp(&b.name));
        trained.sort_by(|a, b| a.name.cmp(&b.name));
        if origin.len() != trained.len() {
            return Err(invalid().into());
        }
        let mut end = 0;
        let mut modules: Vec<(String, Span)> = Vec::new();
        let mut tensors = Vec::new();
        let mut parameter_ids = BTreeSet::new();
        for (a, b) in origin.into_iter().zip(trained) {
            if a.name != b.name
                || a.shape != b.shape
                || a.param_id != b.param_id
                || a.dtype != burn_pack::DType::F32
                || b.dtype != a.dtype
                || a.byte_len() != b.byte_len()
                || a.byte_len() % 4 != 0
                || !a.param_id.is_some_and(|id| parameter_ids.insert(id))
            {
                return Err(invalid().into());
            }
            let start = end;
            end += u32::try_from(a.byte_len() / 4).map_err(|_| invalid())?;
            let span = Span { start, end };
            let name = a.name.split('.').next().ok_or_else(invalid)?;
            if let Some((_, range)) = modules.last_mut().filter(|(prior, _)| prior == name) {
                range.end = end;
            } else {
                modules.push((name.to_owned(), span));
            }
            tensors.push(Pair {
                origin: a.to_bytes().map_err(pack_failure)?,
                trained: b.into_bytes().map_err(pack_failure)?,
                tensor: a,
                span,
            });
        }
        if end as usize != super::PARAMETERS {
            return Err(invalid().into());
        }
        Ok(Self {
            tensors,
            metadata,
            scalars,
            modules,
            parameters: end,
        })
    }

    pub fn patch(&self, ranges: &[Span], removal: bool) -> Result<ModuleRecord, crate::Error> {
        if ranges
            .iter()
            .any(|r| r.start >= r.end || r.end > self.parameters)
            || !ranges.windows(2).all(|w| w[0].end <= w[1].start)
        {
            return Err(crate::ResearchFailure::ModelCheckpointBinding.into());
        }
        let mut tensors = Vec::with_capacity(self.tensors.len());
        for pair in &self.tensors {
            let (baseline, changes) = if removal {
                (&pair.trained, &pair.origin)
            } else {
                (&pair.origin, &pair.trained)
            };
            let intersect = ranges.iter().filter_map(|r| {
                let start = r.start.max(pair.span.start);
                let end = r.end.min(pair.span.end);
                (start < end).then_some((start, end))
            });
            let mut merged = None;
            for (start, end) in intersect {
                let start = 4 * (start - pair.span.start) as usize;
                let end = 4 * (end - pair.span.start) as usize;
                let bytes = merged.get_or_insert_with(|| baseline.to_vec());
                bytes[start..end].copy_from_slice(&changes[start..end]);
            }
            let bytes = merged.map_or_else(|| baseline.clone(), Bytes::from_bytes_vec);
            tensors.push(burn_pack::Tensor::new(
                pair.tensor.name.clone(),
                pair.tensor.dtype,
                pair.tensor.shape.clone(),
                pair.tensor.param_id,
                bytes,
            ));
        }
        let mut writer = burn_pack::Writer::new(tensors);
        for (key, value) in &self.metadata {
            writer = writer.with_metadata(key, value);
        }
        for (key, value) in &self.scalars {
            writer = writer.with_scalar(key, *value);
        }
        ModuleRecord::from_bytes(writer.into_bytes().map_err(pack_failure)?).map_err(record_failure)
    }

    pub fn changed(&self, ranges: &[Span]) -> usize {
        let mut total = 0;
        for pair in &self.tensors {
            for range in ranges {
                let start = range.start.max(pair.span.start);
                let end = range.end.min(pair.span.end);
                if start < end {
                    let from = 4 * (start - pair.span.start) as usize;
                    let to = 4 * (end - pair.span.start) as usize;
                    total += pair.origin[from..to]
                        .chunks_exact(4)
                        .zip(pair.trained[from..to].chunks_exact(4))
                        .filter(|(a, b)| a != b)
                        .count();
                }
            }
        }
        total
    }

    /// Adam uses a shared step for each tensor. Reset only a touched
    /// tensor's moments so the optimizer starts a coherent new trajectory for it.
    pub(super) fn touched_ids(&self, ranges: &[Span]) -> BTreeSet<u64> {
        self.tensors
            .iter()
            .filter_map(|pair| {
                let mut touched = false;
                for range in ranges {
                    let start = range.start.max(pair.span.start);
                    let end = range.end.min(pair.span.end);
                    if start < end {
                        let from = 4 * (start - pair.span.start) as usize;
                        let to = 4 * (end - pair.span.start) as usize;
                        touched |= pair.origin[from..to] != pair.trained[from..to];
                    }
                }
                touched.then_some(pair.tensor.param_id.expect("validated parameter identity"))
            })
            .collect()
    }
}

pub(super) fn without_touched_moments(
    bytes: Bytes,
    touched: &BTreeSet<u64>,
) -> Result<Bytes, crate::Error> {
    let reader = burn_pack::Reader::from_bytes(bytes).map_err(pack_failure)?;
    let belongs = |name: &str| {
        name.split('.')
            .next()
            .and_then(|part| part.parse().ok())
            .is_some_and(|id| touched.contains(&id))
    };
    let scalars = reader
        .scalars()
        .iter()
        .filter(|(name, _)| !belongs(name))
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    let metadata = reader
        .metadata()
        .iter()
        .filter(|(name, _)| !belongs(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();
    let mut tensors = reader.into_tensors().map_err(pack_failure)?;
    tensors.retain(|tensor| tensor.param_id.is_none_or(|id| !touched.contains(&id)));
    tensors.sort_by(|a, b| a.name.cmp(&b.name));
    let mut writer = burn_pack::Writer::new(tensors);
    for (key, value) in metadata {
        writer = writer.with_metadata(&key, &value);
    }
    for (key, value) in scalars {
        writer = writer.with_scalar(&key, value);
    }
    writer.into_bytes().map_err(pack_failure)
}

#[cfg(test)]
mod tests;
