//! Read-only first-order learning utility. Scoring never steps an optimizer.
use super::*;

#[cfg(test)]
mod tests;

fn cosine([dot, left, right]: [f64; 3]) -> Result<Option<f32>, String> {
    if [dot, left, right].iter().any(|n| !n.is_finite()) || left < 0. || right < 0. {
        return Err("non-finite native utility gradient".into());
    }
    if left == 0. || right == 0. {
        return Ok(None);
    }
    Ok(Some(
        (dot / (left.sqrt() * right.sqrt())).clamp(-1., 1.) as f32
    ))
}
impl Runtime {
    pub(in crate::learning) fn utility_alignment(
        &self,
        candidate: &Graph,
        reference: &[Graph],
    ) -> Result<Option<f32>, String> {
        if reference.is_empty() || reference.len() > 4 {
            return Err("native utility reference capacity".into());
        }
        let reference = Batch::from_graphs(reference, &self.device)?;
        let loss = checked_marginal(
            self.policy.independent(&reference, self.recurrent()),
            &reference,
        );
        loss_value(&loss)?;
        let anchor = GradientsParams::from_grads(loss.backward(), &self.policy);
        let batch = Batch::from_graphs(std::slice::from_ref(candidate), &self.device)?;
        let loss = checked_marginal(self.policy.independent(&batch, self.recurrent()), &batch);
        loss_value(&loss)?;
        let proposed = GradientsParams::from_grads(loss.backward(), &self.policy);
        struct Alignment<'a> {
            left: &'a GradientsParams,
            right: &'a GradientsParams,
            sums: [f64; 3],
            error: Option<String>,
        }
        impl ModuleMapper for Alignment<'_> {
            fn map_float<const D: usize>(&mut self, param: Param<Tensor<D>>) -> Param<Tensor<D>> {
                let id = param.id;
                let template = param.val().inner();
                let left: Tensor<D> = self
                    .left
                    .get(id)
                    .unwrap_or_else(|| Tensor::zeros(template.shape(), &template.device()));
                let right: Tensor<D> = self
                    .right
                    .get(id)
                    .unwrap_or_else(|| Tensor::zeros(template.shape(), &template.device()));
                for (i, value) in [
                    left.clone() * right.clone(),
                    left.clone() * left,
                    right.clone() * right,
                ]
                .into_iter()
                .enumerate()
                {
                    match value.sum().into_data().try_to_vec::<f32>() {
                        Ok(values) => self.sums[i] += f64::from(values[0]),
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
                param
            }
        }
        let mut alignment = Alignment {
            left: &proposed,
            right: &anchor,
            sums: [0.; 3],
            error: None,
        };
        drop(self.policy.clone().map(&mut alignment));
        if let Some(error) = alignment.error {
            return Err(error);
        }
        cosine(alignment.sums)
    }
}
