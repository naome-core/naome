//! Inference-only question generation from the active Solver token policy.
use super::*;
use crate::learning::QUESTION_RECIPES;

/// Inference-only view of the selected Solver checkpoint.
pub(crate) struct QuestionPolicy {
    policy: Policy,
    device: Device,
    trained: bool,
    _memory: std::sync::Arc<crate::resources::MemoryLease>,
}

impl QuestionPolicy {
    pub(in crate::learning) fn load(
        checkpoint: &Checkpoint,
        read: impl FnMut(&Blob, std::ops::Range<usize>) -> Result<Vec<u8>, crate::Error>,
    ) -> Result<Self, crate::Error> {
        checkpoint.validate()?;
        let bytes = PARAMETERS * size_of::<f32>();
        let _scratch = crate::resources::MemoryLease::acquire(
            2 * (bytes + checkpoint.model.as_ref().map_or(0, |blob| blob.bytes)),
        )?;
        let memory = crate::resources::MemoryLease::acquire(bytes)?;
        let device = Device::flex().autodiff();
        let policy = load_policy(checkpoint, &device, |model| {
            artifact::load_with(model, read)
        })?;
        Ok(Self {
            policy: policy.valid(),
            device: device.inner(),
            trained: checkpoint.updates > 0,
            _memory: memory,
        })
    }

    #[cfg(test)]
    pub(crate) fn fresh() -> Result<Self, crate::Error> {
        Self::load(&Checkpoint::fresh(), |_, _| {
            unreachable!("fresh checkpoint")
        })
    }

    pub(crate) fn trained(&self) -> bool {
        self.trained
    }

    pub(crate) fn recipe_weights(
        &self,
        relations: &[&Formula],
    ) -> Result<[u32; QUESTION_RECIPES], crate::Error> {
        let _scratch = crate::resources::MemoryLease::acquire(REQUIREMENTS.work_bytes / 128)?;
        let (batch, context) = Batch::for_question_recipes(relations, &self.device)?;
        let (scores, _) = self.policy.infer(
            self.policy
                .encode_cached(&batch, &context, &mut Default::default())?,
            Some(Tensor::zeros([1, policy::WIDTH], &self.device)),
        );
        let scores = memory::decode_scores(scores, QUESTION_RECIPES)?;
        let scores: [f32; QUESTION_RECIPES] = scores
            .try_into()
            .map_err(|_| crate::ResearchFailure::MemoryPrediction)?;
        let peak = scores.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        // Relative odds refine the checked curriculum prior. Preserve bounded
        // exploration even when a checkpoint puts almost no mass on a recipe.
        Ok(scores.map(|score| (512. + 512. * (score - peak).exp()).round() as u32))
    }
}
