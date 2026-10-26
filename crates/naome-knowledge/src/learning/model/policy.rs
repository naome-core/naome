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
            kinds: EmbeddingConfig::new(17, WIDTH).init(device),
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
        let left = batch
            .left
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([1, n, WIDTH]);
        let right = batch
            .right
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([1, n, WIDTH]);
        self.forward_using(batch, |h| {
            Tensor::zeros([1, n, WIDTH], &h.device())
                .scatter(1, left.clone(), h.clone(), IndexingUpdateOp::Add)
                .scatter(1, right.clone(), h, IndexingUpdateOp::Add)
                * batch.parent_scale.clone()
        })
    }
    fn forward_using(&self, batch: &Batch, parents: impl Fn(Tensor<3>) -> Tensor<3>) -> Tensor<2> {
        let [_, n] = batch.kinds.dims();
        let b = batch.goal.dims()[0];
        let c = batch.candidates.dims()[1];
        let left = batch
            .left
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([1, n, WIDTH]);
        let right = batch
            .right
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([1, n, WIDTH]);
        let mut h = (self.kinds.forward(batch.kinds.clone())
            + self.roles.forward(batch.roles.clone()))
            * batch.valid.clone();
        for layer in &self.messages {
            let joined = Tensor::cat(
                vec![
                    h.clone(),
                    h.clone().gather(1, left.clone()),
                    h.clone().gather(1, right.clone()),
                    parents(h.clone()),
                ],
                2,
            );
            h = (h + tanh(layer.forward(joined)))
                * std::f32::consts::FRAC_1_SQRT_2
                * batch.valid.clone();
        }
        let flat = h.clone().squeeze_dim::<2>(0);
        let goal_indices = batch.goal.clone().reshape([b, 1]).expand([b, WIDTH]);
        let candidate_indices = batch
            .candidates
            .clone()
            .reshape([b * c, 1])
            .expand([b * c, WIDTH]);
        let goal = flat
            .clone()
            .gather(0, goal_indices)
            .reshape([b, 1, WIDTH])
            .expand([b, c, WIDTH]);
        let candidate = flat.gather(0, candidate_indices).reshape([b, c, WIDTH]);
        let context = batch.context.clone().matmul(h).expand([b, c, WIDTH]);
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
