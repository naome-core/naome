//! Frozen pre-optimization routing, including its exact autodiff graph.
//! Differential tests compare full model and optimizer bytes.
use super::*;

impl Policy {
    pub(in crate::learning::model) fn forward_reference(&self, batch: &Batch) -> Tensor<2> {
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
        self.forward_reference_using(batch, |h| {
            Tensor::zeros([1, n, WIDTH], &h.device())
                .scatter(1, left.clone(), h.clone(), IndexingUpdateOp::Add)
                .scatter(1, right.clone(), h, IndexingUpdateOp::Add)
                * batch.parent_scale.clone()
        })
    }
    fn forward_reference_using(
        &self,
        batch: &Batch,
        parents: impl Fn(Tensor<3>) -> Tensor<3>,
    ) -> Tensor<2> {
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
}
