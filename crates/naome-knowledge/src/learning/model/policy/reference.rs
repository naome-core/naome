//! Reference routing with expanded gather indices for inference and autodiff.
use super::*;
mod activation;

impl Policy {
    pub(in crate::learning::model) fn forward_reference(&self, batch: &Batch) -> Tensor<2> {
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
        let mut h =
            self.embedding(batch.kinds.clone(), batch.symbols.clone()) * batch.valid.clone();
        for layer in &self.messages {
            h = Self::message(
                layer,
                h.clone(),
                h.clone().gather(1, left.clone()),
                h.gather(1, right.clone()),
            ) * batch.valid.clone();
        }
        h = h + self.roles.forward(batch.roles.clone()) * batch.valid.clone();
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
        let context_mask = batch.context_mask();
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
}
