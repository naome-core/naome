//! A small learned graph representation and shared proof-action scorer.

use super::super::graph::Batch;
use burn::{
    module::Module,
    nn::{Embedding, EmbeddingConfig, Linear, LinearConfig},
    tensor::{Device, Tensor, activation::tanh, ops::IndexingUpdateOp},
};

pub const WIDTH: usize = 160;
pub const LAYERS: usize = 6;
pub const READOUT: usize = 480;

#[derive(Module, Debug)]
pub struct Policy {
    kinds: Embedding,
    roles: Embedding,
    messages: Vec<Linear>,
    readout: Linear,
    output: Linear,
}

impl Policy {
    pub fn new(device: &Device) -> Self {
        Self {
            kinds: EmbeddingConfig::new(19, WIDTH).init(device),
            roles: EmbeddingConfig::new(4, WIDTH).init(device),
            messages: (0..LAYERS)
                .map(|_| LinearConfig::new(4 * WIDTH, WIDTH).init(device))
                .collect(),
            readout: LinearConfig::new(5 * WIDTH, READOUT).init(device),
            output: LinearConfig::new(READOUT, 1).init(device),
        }
    }

    pub fn forward(&self, batch: &Batch) -> Tensor<2> {
        let [_, n] = batch.kinds.dims();
        let left = batch.left.clone().reshape([n]);
        let right = batch.right.clone().reshape([n]);
        let left_channels = batch
            .left
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([1, n, WIDTH]);
        let right_channels = batch
            .right
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([1, n, WIDTH]);
        self.forward_using(batch, |h| {
            if h.is_autodiff() {
                // Preserve the original autodiff graph and accumulation order.
                Tensor::zeros([1, n, WIDTH], &h.device())
                    .scatter(1, left_channels.clone(), h.clone(), IndexingUpdateOp::Add)
                    .scatter(1, right_channels.clone(), h, IndexingUpdateOp::Add)
                    * batch.parent_scale.clone()
            } else {
                let flat = h.squeeze_dim::<2>(0);
                // Preserve left-then-right and node order for every channel,
                // while indexing each contiguous row only once.
                Tensor::zeros([n, WIDTH], &flat.device())
                    .select_assign(0, left.clone(), flat.clone(), IndexingUpdateOp::Add)
                    .select_assign(0, right.clone(), flat, IndexingUpdateOp::Add)
                    .unsqueeze_dim::<3>(0)
                    * batch.parent_scale.clone()
            }
        })
    }
    fn forward_using(&self, batch: &Batch, parents: impl Fn(Tensor<3>) -> Tensor<3>) -> Tensor<2> {
        let [_, n] = batch.kinds.dims();
        let b = batch.goal.dims()[0];
        let c = batch.candidates.dims()[1];
        let left = batch.left.clone().reshape([n]);
        let right = batch.right.clone().reshape([n]);
        let left_channels = batch
            .left
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([1, n, WIDTH]);
        let right_channels = batch
            .right
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([1, n, WIDTH]);
        let mut h = (self.kinds.forward(batch.kinds.clone())
            + self.roles.forward(batch.roles.clone()))
            * batch.valid.clone();
        // Gradient retention is a leaf flag, not the active autodiff context.
        let differentiable = h.is_autodiff();
        for layer in &self.messages {
            let (left, right) = if differentiable {
                (
                    h.clone().gather(1, left_channels.clone()),
                    h.clone().gather(1, right_channels.clone()),
                )
            } else {
                let flat = h.clone().squeeze_dim::<2>(0);
                (
                    flat.clone().select(0, left.clone()).unsqueeze_dim::<3>(0),
                    flat.select(0, right.clone()).unsqueeze_dim::<3>(0),
                )
            };
            let joined = Tensor::cat(vec![h.clone(), left, right, parents(h.clone())], 2);
            h = (h + tanh(layer.forward(joined)))
                * std::f32::consts::FRAC_1_SQRT_2
                * batch.valid.clone();
        }
        let flat = h.clone().squeeze_dim::<2>(0);
        let (goal, candidate) = if differentiable {
            let goal_indices = batch.goal.clone().reshape([b, 1]).expand([b, WIDTH]);
            let candidate_indices = batch
                .candidates
                .clone()
                .reshape([b * c, 1])
                .expand([b * c, WIDTH]);
            (
                flat.clone()
                    .gather(0, goal_indices)
                    .reshape([b, 1, WIDTH])
                    .expand([b, c, WIDTH]),
                flat.gather(0, candidate_indices).reshape([b, c, WIDTH]),
            )
        } else {
            (
                flat.clone()
                    .select(0, batch.goal.clone().reshape([b]))
                    .reshape([b, 1, WIDTH])
                    .expand([b, c, WIDTH]),
                flat.select(0, batch.candidates.clone().reshape([b * c]))
                    .reshape([b, c, WIDTH]),
            )
        };
        let context_mask = batch.context.clone().squeeze_dim::<2>(1).equal_elem(0.);
        let query = goal
            .clone()
            .slice([0..b, 0..1, 0..WIDTH])
            .squeeze_dim::<2>(1);
        let keys = h.clone().squeeze_dim::<2>(0).transpose();
        let weights = burn::tensor::activation::softmax(
            (query.matmul(keys) / (WIDTH as f32).sqrt()).mask_fill(context_mask.clone(), -10000.),
            1,
        )
        .mask_fill(context_mask, 0.)
        .unsqueeze_dim::<3>(1);
        let context = weights.matmul(h).expand([b, c, WIDTH]);
        let joined = Tensor::cat(
            vec![
                goal.clone(),
                candidate.clone(),
                context,
                goal.clone() - candidate.clone(),
                goal * candidate,
            ],
            2,
        );
        self.output
            .forward(tanh(self.readout.forward(joined)))
            .squeeze_dim::<2>(2)
            .mask_fill(batch.invalid.clone(), -10000.)
    }
    #[cfg(test)]
    pub fn forward_dense(&self, batch: &Batch) -> Tensor<2> {
        let n = batch.kinds.dims()[1];
        let left = batch.left.clone().into_data().try_to_vec::<i32>().unwrap();
        let right = batch.right.clone().into_data().try_to_vec::<i32>().unwrap();
        let mut weights = vec![0f32; n * n];
        for parent in 1..n {
            for child in [left[parent], right[parent]]
                .into_iter()
                .filter(|i| *i != 0)
            {
                weights[child as usize * n + parent] += 1.;
            }
        }
        for row in weights.chunks_mut(n) {
            let total: f32 = row.iter().sum();
            if total > 0. {
                for v in row {
                    *v /= total;
                }
            }
        }
        let weights = Tensor::from_data(
            burn::tensor::TensorData::new(weights, [1, n, n]),
            &batch.kinds.device(),
        );
        self.forward_using(batch, |h| weights.clone().matmul(h))
    }
}

#[cfg(test)]
mod reference;
