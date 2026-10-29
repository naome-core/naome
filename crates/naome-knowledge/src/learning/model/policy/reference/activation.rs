//! Opt-in detached measurements; this module is absent from product builds.
//! The fixed projections summarize representations, never formal truth.
use super::super::*;
use crate::learning::{digest, graph::Graph};
use serde::Serialize;

pub(in crate::learning::model) const MAX_GRAPHS: usize = 8;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(in crate::learning::model) struct Signature {
    rows: usize,
    rms: f64,
    maximum_abs: f32,
    mean_norm: f64,
    projection: [f64; 8],
}

impl Signature {
    fn of(values: &[f32]) -> Result<Self, String> {
        if values.is_empty()
            || !values.len().is_multiple_of(WIDTH)
            || values.iter().any(|v| !v.is_finite())
        {
            return Err("activation measurement shape or value differs".into());
        }
        let rows = values.len() / WIDTH;
        let mut mean = [0f64; WIDTH];
        let mut squared = 0.;
        let mut maximum_abs = 0f32;
        for row in values.chunks_exact(WIDTH) {
            for (i, &v) in row.iter().enumerate() {
                let v64 = f64::from(v);
                mean[i] += v64 / rows as f64;
                squared += v64 * v64;
                maximum_abs = maximum_abs.max(v.abs());
            }
        }
        let mean_norm = mean.iter().map(|v| v * v).sum::<f64>().sqrt();
        let mut projection = [0.; 8];
        if mean_norm > 0. {
            for (p, output) in projection.iter_mut().enumerate() {
                // Fixed Walsh signs; no random generator or learned projection.
                *output = mean
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let sign = if ((i & (p + 1)).count_ones() & 1) == 0 {
                            1.
                        } else {
                            -1.
                        };
                        sign * v / mean_norm / (WIDTH as f64).sqrt()
                    })
                    .sum();
            }
        }
        Ok(Self {
            rows,
            rms: (squared / values.len() as f64).sqrt(),
            maximum_abs,
            mean_norm,
            projection,
        })
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub(in crate::learning::model) struct Activation {
    pub graph: String,
    pub state: String,
    pub node_count: usize,
    pub candidate_count: usize,
    pub embedding_nodes: Signature,
    pub message_three_nodes: Signature,
    pub goal: Signature,
    pub context: Signature,
    pub actions: Vec<Signature>,
    pub score_bits: Vec<u32>,
}

fn values<const D: usize>(tensor: Tensor<D>) -> Result<Vec<f32>, String> {
    if tensor.is_autodiff() {
        return Err("activation observer requires detached inference".into());
    }
    tensor
        .into_data()
        .try_to_vec::<f32>()
        .map_err(|e| e.to_string())
}

fn node_summaries(h: Tensor<3>, graphs: &[&Graph]) -> Result<Vec<Signature>, String> {
    let data = values(h)?;
    let expected = (1 + graphs.iter().map(|g| g.nodes.len() - 1).sum::<usize>()) * WIDTH;
    if data.len() != expected || data[..WIDTH].iter().any(|v| *v != 0.) {
        return Err("activation packed sentinel or graph mapping differs".into());
    }
    let mut offset = WIDTH;
    graphs
        .iter()
        .map(|graph| {
            let end = offset + (graph.nodes.len() - 1) * WIDTH;
            let summary = Signature::of(&data[offset..end]);
            offset = end;
            summary
        })
        .collect()
}

impl Policy {
    pub(in crate::learning::model) fn activation_definition() -> String {
        digest(&(
            include_str!("activation.rs"),
            "detached ordinary encoder; node means exclude shared sentinel; 8 Walsh signs; L2-normalized mean; zero search memory; no historical-state claim",
        ))
    }

    pub(in crate::learning::model) fn activations(
        &self,
        graphs: &[&Graph],
        device: &Device,
        recurrent: bool,
    ) -> Result<Vec<Activation>, String> {
        if graphs.is_empty() || graphs.len() > MAX_GRAPHS {
            return Err("activation observer graph capacity or mapping differs".into());
        }
        let batch = Batch::from_graphs(graphs, device)?;
        let [_, n] = batch.kinds.dims();
        let left = batch.left.clone().reshape([n]);
        let right = batch.right.clone().reshape([n]);
        let mut h = (self.kinds.forward(batch.kinds.clone())
            + self.roles.forward(batch.roles.clone()))
            * batch.valid.clone();
        if h.is_autodiff() {
            return Err("activation observer requires detached inference".into());
        }
        let embedding = node_summaries(h.clone(), graphs)?;
        // Replay only the first three ordinary layers for their intermediate
        // measurement. All final representations and scores below use encode.
        // This extra work is measured and charged to the diagnostic, never free.
        for layer in self.messages.iter().take(3) {
            let flat = h.clone().squeeze_dim::<2>(0);
            let parent = Tensor::zeros([n, WIDTH], &flat.device())
                .select_assign(0, left.clone(), flat.clone(), IndexingUpdateOp::Add)
                .select_assign(0, right.clone(), flat.clone(), IndexingUpdateOp::Add)
                .unsqueeze_dim::<3>(0)
                * batch.parent_scale.clone();
            let joined = Tensor::cat(
                vec![
                    h.clone(),
                    flat.clone().select(0, left.clone()).unsqueeze_dim::<3>(0),
                    flat.select(0, right.clone()).unsqueeze_dim::<3>(0),
                    parent,
                ],
                2,
            );
            h = (h + tanh(layer.forward(joined)))
                * std::f32::consts::FRAC_1_SQRT_2
                * batch.valid.clone();
        }
        let middle = node_summaries(h, graphs)?;
        let encoded = self.encode(&batch);
        let goal = values(encoded.goal.clone())?;
        let context = values(encoded.context.clone())?;
        let actions = values(encoded.candidate.clone())?;
        let memory = recurrent.then(|| Tensor::zeros([graphs.len(), WIDTH], &batch.kinds.device()));
        let scores = values(self.readout(encoded, memory).0)?;
        let c = batch.candidates.dims()[1];
        graphs
            .iter()
            .enumerate()
            .map(|(i, graph)| {
                let offset = i * c * WIDTH;
                Ok(Activation {
                    graph: graph.key(),
                    state: graph.binding.clone(),
                    node_count: graph.nodes.len() - 1,
                    candidate_count: graph.candidates.len(),
                    embedding_nodes: embedding[i].clone(),
                    message_three_nodes: middle[i].clone(),
                    goal: Signature::of(&goal[offset..offset + WIDTH])?,
                    context: Signature::of(&context[offset..offset + WIDTH])?,
                    actions: actions[offset..offset + graph.candidates.len() * WIDTH]
                        .chunks_exact(WIDTH)
                        .map(Signature::of)
                        .collect::<Result<_, _>>()?,
                    score_bits: scores[i * c..i * c + graph.candidates.len()]
                        .iter()
                        .map(|v| v.to_bits())
                        .collect(),
                })
            })
            .collect()
    }
}
