//! Shared neural policy over legal, typed action prefixes.

use super::{
    batch::Batch,
    token::{FEATURES, Row, VOCABULARY},
};
mod cache;
use burn::{
    module::Module,
    nn::{Embedding, EmbeddingConfig, Linear, LinearConfig},
    tensor::{Bool, Device, Int, Tensor, TensorData, activation::tanh},
};
pub(super) use cache::RowCache;

pub const WIDTH: usize = 96;
pub const READOUT: usize = 256;

#[derive(Module, Debug)]
pub struct Policy {
    tokens: Embedding,
    roles: Embedding,
    transition: Linear,
    readout: Linear,
    output: Linear,
}

pub(super) struct Encoded {
    goal: Tensor<3>,
    candidate: Tensor<3>,
    context: Tensor<3>,
    invalid: Tensor<2, Bool>,
    edges: Tensor<3>,
    priors: Tensor<2>,
    siblings: Tensor<3, Bool>,
    paths: Tensor<3>,
    aliases: Tensor<2>,
}
/// One inference decision's transition inputs. Only entered actions need a
/// successor; siblings reuse the selected action's computed row.
#[derive(Clone)]
pub(super) struct Successors {
    transition: Linear,
    state: Tensor<3>,
    goal: Tensor<3>,
    context: Tensor<3>,
    candidates: Tensor<3>,
}
impl Successors {
    pub(super) fn selected(&self, index: usize) -> Tensor<3> {
        let candidate = self
            .candidates
            .clone()
            .slice([0..1, index..index + 1, 0..WIDTH]);
        Policy::successors(
            &self.transition,
            self.state.clone(),
            self.goal.clone(),
            self.context.clone(),
            candidate,
        )
    }
}

impl Encoded {
    pub(super) fn select(&self, indices: Tensor<1, Int>) -> Self {
        Self {
            goal: self.goal.clone().select(0, indices.clone()),
            candidate: self.candidate.clone().select(0, indices.clone()),
            context: self.context.clone().select(0, indices.clone()),
            invalid: self.invalid.clone().select(0, indices.clone()),
            edges: self.edges.clone().select(0, indices.clone()),
            priors: self.priors.clone().select(0, indices.clone()),
            siblings: self.siblings.clone().select(0, indices.clone()),
            paths: self.paths.clone().select(0, indices.clone()),
            aliases: self.aliases.clone().select(0, indices),
        }
    }
}

impl Policy {
    /// Keep the native formula encoder and recurrent transition fixed while
    /// adapting the existing action readout. This changes no inference feature.
    pub(super) fn readout_training(mut self) -> Self {
        self.tokens = self.tokens.no_grad();
        self.roles = self.roles.no_grad();
        self.transition = self.transition.no_grad();
        self
    }

    pub fn new(device: &Device) -> Self {
        Self {
            tokens: EmbeddingConfig::new(VOCABULARY, WIDTH).init(device),
            roles: EmbeddingConfig::new(4, WIDTH).init(device),
            transition: LinearConfig::new(4 * WIDTH, WIDTH).init(device),
            readout: LinearConfig::new(5 * WIDTH, READOUT).init(device),
            output: LinearConfig::new(READOUT, 1).init(device),
        }
    }

    #[cfg(test)]
    pub(super) fn forward(&self, batch: &Batch) -> Tensor<2> {
        self.independent(batch, false)
    }
    pub(super) fn independent(&self, batch: &Batch, recurrent: bool) -> Tensor<2> {
        let memory =
            recurrent.then(|| Tensor::zeros([batch.goal.dims()[0], WIDTH], &batch.device()));
        let encoded = self.encode(batch);
        let state = memory.map(|memory| self.recurrent_state(&encoded, memory));
        self.action_scores(encoded, state)
    }
    pub(super) fn encode(&self, batch: &Batch) -> Encoded {
        self.encode_with_context(batch, self.formula_rows(batch), None)
    }

    fn embed(&self, rows: &[Row], device: &Device) -> Tensor<2> {
        let input = Tensor::from_data(
            TensorData::new(
                rows.iter().flatten().copied().collect::<Vec<_>>(),
                [rows.len(), FEATURES],
            ),
            device,
        );
        self.tokens.forward(input).sum_dim(1).squeeze_dim::<2>(1) / (FEATURES as f32).sqrt()
    }

    fn formula_rows(&self, batch: &Batch) -> Tensor<3> {
        self.embed(&batch.rows, &batch.device())
            .unsqueeze_dim::<3>(0)
            * batch.valid.clone()
    }

    fn encode_with_context(
        &self,
        batch: &Batch,
        formula_rows: Tensor<3>,
        roots: Option<&[usize]>,
    ) -> Encoded {
        let b = batch.goal.dims()[0];
        let c = batch.candidates.dims()[1];
        // Node roles depend on the current decision and are added only after
        // the shared structural encoder. The ranker sees context and actions.
        let h = formula_rows + self.roles.forward(batch.roles.clone()) * batch.valid.clone();
        let differentiable = h.is_autodiff();
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
                flat.clone()
                    .gather(0, candidate_indices)
                    .reshape([b, c, WIDTH]),
            )
        } else {
            (
                flat.clone()
                    .select(0, batch.goal.clone().reshape([b]))
                    .reshape([b, 1, WIDTH])
                    .expand([b, c, WIDTH]),
                flat.clone()
                    .select(0, batch.candidates.clone().reshape([b * c]))
                    .reshape([b, c, WIDTH]),
            )
        };
        let query = goal
            .clone()
            .slice([0..b, 0..1, 0..WIDTH])
            .squeeze_dim::<2>(1);
        let context = if let Some(roots) = roots {
            // Inference scores one graph. The dense mask uses membership
            // without multiplicity, so preserve its ascending unique rows.
            let mut roots: Vec<_> = roots.iter().map(|&root| root as i32).collect();
            roots.sort_unstable();
            roots.dedup();
            if roots.is_empty() {
                Tensor::zeros([1, 1, WIDTH], &h.device())
            } else {
                let count = roots.len();
                let roots =
                    Tensor::from_data(burn::tensor::TensorData::new(roots, [count]), &h.device());
                let context = flat.select(0, roots);
                let weights = burn::tensor::activation::softmax(
                    query.matmul(context.clone().transpose()) / (WIDTH as f32).sqrt(),
                    1,
                );
                weights.matmul(context).unsqueeze_dim::<3>(1)
            }
        } else {
            let context_mask = batch.context_mask();
            let keys = flat.transpose();
            let weights = burn::tensor::activation::softmax(
                (query.matmul(keys) / (WIDTH as f32).sqrt())
                    .mask_fill(context_mask.clone(), -10000.),
                1,
            )
            .mask_fill(context_mask, 0.)
            .unsqueeze_dim::<3>(1);
            weights.matmul(h)
        }
        .expand([b, c, WIDTH]);
        let edges =
            self.embed(&batch.edges, &batch.device())
                .reshape([b, batch.edges.len() / b, WIDTH]);
        Encoded {
            goal,
            candidate,
            context,
            invalid: batch.invalid.clone(),
            edges,
            priors: batch.priors.clone(),
            siblings: batch.siblings.clone(),
            paths: batch.paths.clone(),
            aliases: batch.aliases.clone(),
        }
    }
    fn recurrent_state(&self, encoded: &Encoded, mut state: Tensor<2>) -> Tensor<3> {
        let [b, _, _] = encoded.goal.dims();
        let goal = encoded
            .goal
            .clone()
            .slice([0..b, 0..1, 0..WIDTH])
            .squeeze_dim::<2>(1);
        let context = encoded
            .context
            .clone()
            .slice([0..b, 0..1, 0..WIDTH])
            .squeeze_dim::<2>(1);
        let input = (goal.clone() + context.clone()) * std::f32::consts::FRAC_1_SQRT_2;
        for _ in 0..2 {
            let update = self.transition.forward(Tensor::cat(
                vec![state.clone(), goal.clone(), context.clone(), input.clone()],
                1,
            ));
            state = tanh((state + update) * std::f32::consts::FRAC_1_SQRT_2);
        }
        state.unsqueeze_dim::<3>(1)
    }

    fn successors(
        transition: &Linear,
        state: Tensor<3>,
        goal: Tensor<3>,
        context: Tensor<3>,
        candidates: Tensor<3>,
    ) -> Tensor<3> {
        let shape = candidates.dims();
        let state = state.expand(shape);
        let update = transition.forward(Tensor::cat(
            vec![
                state.clone(),
                goal.expand(shape),
                context.expand(shape),
                candidates,
            ],
            2,
        ));
        tanh((state + update) * std::f32::consts::FRAC_1_SQRT_2)
    }

    fn action_scores(&self, encoded: Encoded, state: Option<Tensor<3>>) -> Tensor<2> {
        let Encoded {
            goal,
            context,
            invalid,
            edges,
            priors,
            siblings,
            paths,
            aliases,
            ..
        } = encoded;
        let [b, e, _] = edges.dims();
        let goal = goal.slice([0..b, 0..1, 0..WIDTH]).expand([b, e, WIDTH]);
        let mut context = context.slice([0..b, 0..1, 0..WIDTH]).expand([b, e, WIDTH]);
        if let Some(state) = state {
            context = (context + state.expand([b, e, WIDTH])) * std::f32::consts::FRAC_1_SQRT_2;
        }
        let joined = Tensor::cat(
            vec![
                goal.clone(),
                edges.clone(),
                context,
                goal.clone() - edges.clone(),
                goal * edges,
            ],
            2,
        );
        let logits = self
            .output
            .forward(tanh(self.readout.forward(joined)))
            .squeeze_dim::<2>(2);
        let scores = prefix_probabilities(logits + priors, siblings, paths) - aliases;
        scores.mask_fill(invalid, -10000.)
    }

    pub(super) fn readout(
        &self,
        encoded: Encoded,
        memory: Option<Tensor<2>>,
    ) -> (Tensor<2>, Option<Tensor<3>>) {
        let state = memory.map(|memory| self.recurrent_state(&encoded, memory));
        let successors = state.as_ref().map(|state| {
            Self::successors(
                &self.transition,
                state.clone(),
                encoded.goal.clone(),
                encoded.context.clone(),
                encoded.candidate.clone(),
            )
        });
        (self.action_scores(encoded, state), successors)
    }

    pub(super) fn infer(
        &self,
        encoded: Encoded,
        memory: Option<Tensor<2>>,
    ) -> (Tensor<2>, Option<Successors>) {
        let state = memory.map(|memory| self.recurrent_state(&encoded, memory));
        let pending = state.as_ref().map(|state| Successors {
            transition: self.transition.clone(),
            state: state.clone(),
            goal: encoded.goal.clone().slice([0..1, 0..1, 0..WIDTH]),
            context: encoded.context.clone().slice([0..1, 0..1, 0..WIDTH]),
            candidates: encoded.candidate.clone(),
        });
        (self.action_scores(encoded, state), pending)
    }
}

/// The probability of an action is the product of the conditional token
/// probabilities along its legal prefix. Every row has a finite normalizer.
fn prefix_probabilities(
    logits: Tensor<2>,
    siblings: Tensor<3, Bool>,
    paths: Tensor<3>,
) -> Tensor<2> {
    let [batch, edges] = logits.dims();
    let grouped = logits
        .clone()
        .unsqueeze_dim::<3>(1)
        .expand([batch, edges, edges])
        .mask_fill(siblings, f32::NEG_INFINITY);
    let maximum = grouped.clone().max_dim(2);
    let normalizer = (grouped - maximum.clone()).exp().sum_dim(2).log() + maximum;
    let log_tokens = logits - normalizer.squeeze_dim::<2>(2);
    paths
        .matmul(log_tokens.unsqueeze_dim::<3>(2))
        .squeeze_dim::<2>(2)
}

#[cfg(test)]
mod reference;

#[cfg(test)]
mod tests;
