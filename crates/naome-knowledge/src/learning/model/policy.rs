//! A small learned graph representation and shared proof-action scorer.

use super::super::graph::Batch;
use burn::{
    module::Module,
    nn::{Embedding, EmbeddingConfig, Linear, LinearConfig},
    tensor::{Bool, Device, Int, Tensor, activation::tanh, ops::IndexingUpdateOp},
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

pub(super) struct Encoded {
    goal: Tensor<3>,
    candidate: Tensor<3>,
    context: Tensor<3>,
    invalid: Tensor<2, Bool>,
}
impl Encoded {
    pub(super) fn select(&self, indices: Tensor<1, Int>) -> Self {
        Self {
            goal: self.goal.clone().select(0, indices.clone()),
            candidate: self.candidate.clone().select(0, indices.clone()),
            context: self.context.clone().select(0, indices.clone()),
            invalid: self.invalid.clone().select(0, indices),
        }
    }
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

    #[cfg(test)]
    pub fn forward(&self, batch: &Batch) -> Tensor<2> {
        self.independent(batch, false)
    }
    pub(super) fn independent(&self, batch: &Batch, recurrent: bool) -> Tensor<2> {
        let memory =
            recurrent.then(|| Tensor::zeros([batch.goal.dims()[0], WIDTH], &batch.kinds.device()));
        self.readout(self.encode(batch), memory).0
    }
    pub(super) fn encode(&self, batch: &Batch) -> Encoded {
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
        self.encode_using(batch, |h| {
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
    fn encode_using(&self, batch: &Batch, parents: impl Fn(Tensor<3>) -> Tensor<3>) -> Encoded {
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
        Encoded {
            goal,
            candidate,
            context,
            invalid: batch.invalid.clone(),
        }
    }
    /// The graph encoder remains disjoint across packed examples. Only these
    /// small pooled states are carried across independently checked, observed
    /// predecessor edges; no extra parameters or imagined symbolic facts exist.
    pub(super) fn readout(
        &self,
        encoded: Encoded,
        memory: Option<Tensor<2>>,
    ) -> (Tensor<2>, Option<Tensor<3>>) {
        let Encoded {
            goal,
            candidate,
            mut context,
            invalid,
        } = encoded;
        let [b, c, _] = goal.dims();
        let successors = memory.map(|memory| {
            let fixed_goal = goal
                .clone()
                .slice([0..b, 0..1, 0..WIDTH])
                .squeeze_dim::<2>(1);
            let fixed_context = context
                .clone()
                .slice([0..b, 0..1, 0..WIDTH])
                .squeeze_dim::<2>(1);
            let input =
                (fixed_goal.clone() + fixed_context.clone()) * std::f32::consts::FRAC_1_SQRT_2;
            let mut state = memory;
            let block = self.messages.last().expect("fixed message layers");
            for _ in 0..2 {
                let update = block.forward(Tensor::cat(
                    vec![
                        state.clone(),
                        fixed_goal.clone(),
                        fixed_context.clone(),
                        input.clone(),
                    ],
                    1,
                ));
                state = tanh((state + update) * std::f32::consts::FRAC_1_SQRT_2);
            }
            let state = state.unsqueeze_dim::<3>(1).expand([b, c, WIDTH]);
            let update = block.forward(Tensor::cat(
                vec![
                    state.clone(),
                    goal.clone(),
                    context.clone(),
                    candidate.clone(),
                ],
                2,
            ));
            let successors = tanh((state.clone() + update) * std::f32::consts::FRAC_1_SQRT_2);
            context = (context.clone() + state) * std::f32::consts::FRAC_1_SQRT_2;
            successors
        });
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
        let scores = self
            .output
            .forward(tanh(self.readout.forward(joined)))
            .squeeze_dim::<2>(2)
            .mask_fill(invalid, -10000.);
        (scores, successors)
    }
    #[cfg(test)]
    pub fn forward_dense(&self, batch: &Batch, recurrent: bool) -> Tensor<2> {
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
        let memory =
            recurrent.then(|| Tensor::zeros([batch.goal.dims()[0], WIDTH], &batch.kinds.device()));
        self.readout(
            self.encode_using(batch, |h| weights.clone().matmul(h)),
            memory,
        )
        .0
    }
}

#[cfg(test)]
mod reference;
