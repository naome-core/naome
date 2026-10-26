//! A small learned graph representation and shared proof-action scorer.

use super::super::graph::Batch;
use burn::{
    module::Module,
    nn::{Embedding, EmbeddingConfig, Linear, LinearConfig},
    tensor::{Device, Tensor, activation::tanh},
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
            kinds: EmbeddingConfig::new(15, WIDTH).init(device),
            roles: EmbeddingConfig::new(4, WIDTH).init(device),
            messages: (0..LAYERS)
                .map(|_| LinearConfig::new(4 * WIDTH, WIDTH).init(device))
                .collect(),
            readout: LinearConfig::new(5 * WIDTH, READOUT).init(device),
            output: LinearConfig::new(READOUT, 1).init(device),
        }
    }

    pub fn forward(&self, batch: &Batch) -> Tensor<2> {
        let [b, n] = batch.kinds.dims();
        let c = batch.candidates.dims()[1];
        let left = batch
            .left
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([b, n, WIDTH]);
        let right = batch
            .right
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([b, n, WIDTH]);
        let mut h = (self.kinds.forward(batch.kinds.clone())
            + self.roles.forward(batch.roles.clone()))
            * batch.valid.clone();
        for layer in &self.messages {
            let joined = Tensor::cat(
                vec![
                    h.clone(),
                    h.clone().gather(1, left.clone()),
                    h.clone().gather(1, right.clone()),
                    batch.parents.clone().matmul(h.clone()),
                ],
                2,
            );
            h = (h + tanh(layer.forward(joined)))
                * std::f32::consts::FRAC_1_SQRT_2
                * batch.valid.clone();
        }
        let goal_indices = batch
            .goal
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([b, 1, WIDTH]);
        let candidate_indices = batch
            .candidates
            .clone()
            .unsqueeze_dim::<3>(2)
            .expand([b, c, WIDTH]);
        let goal = h.clone().gather(1, goal_indices).expand([b, c, WIDTH]);
        let candidate = h.clone().gather(1, candidate_indices);
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
}
