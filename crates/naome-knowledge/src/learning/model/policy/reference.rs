//! Dense row routing used to check the indexed inference path.
use super::*;
mod activation;

impl Policy {
    pub(in crate::learning::model) fn forward_reference(&self, batch: &Batch) -> Tensor<2> {
        let [b, c] = batch.candidates.dims();
        let h = self.formula_rows(batch)
            + self.roles.forward(batch.roles.clone()) * batch.valid.clone();
        let flat = h.clone().squeeze_dim::<2>(0);
        let goal_indices = batch.goal.clone().reshape([b, 1]).expand([b, WIDTH]);
        let candidate_indices = batch
            .candidates
            .clone()
            .reshape([b * c, 1])
            .expand([b * c, WIDTH]);
        let query = flat.clone().gather(0, goal_indices);
        let goal = query.clone().reshape([b, 1, WIDTH]).expand([b, c, WIDTH]);
        let candidate = flat
            .clone()
            .gather(0, candidate_indices)
            .reshape([b, c, WIDTH]);
        let mask = batch.context_mask();
        let attention = burn::tensor::activation::softmax(
            (query.matmul(flat.transpose()) / (WIDTH as f32).sqrt())
                .mask_fill(mask.clone(), -10000.),
            1,
        )
        .mask_fill(mask, 0.)
        .unsqueeze_dim::<3>(1);
        let context = attention.matmul(h).expand([b, c, WIDTH]);
        let edges =
            self.embed(&batch.edges, &batch.device())
                .reshape([b, batch.edges.len() / b, WIDTH]);
        self.action_scores(
            Encoded {
                goal,
                context,
                candidate,
                invalid: batch.invalid.clone(),
                edges,
                priors: batch.priors.clone(),
                siblings: batch.siblings.clone(),
                paths: batch.paths.clone(),
                aliases: batch.aliases.clone(),
            },
            None,
        )
    }
}
