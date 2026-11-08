//! A small learned graph representation and shared proof-action scorer.

use super::super::graph::{Batch, SYMBOLS};
mod cache;
use burn::{
    module::{Module, Param},
    nn::{Embedding, EmbeddingConfig, Initializer, Linear, LinearConfig},
    tensor::{Bool, Device, Int, Tensor, activation::tanh},
};
pub(super) use cache::FormulaCache;

pub const WIDTH: usize = 160;
pub const LAYERS: usize = 6;
pub const READOUT: usize = 480;

#[derive(Module, Debug)]
pub struct Policy {
    kinds: Embedding,
    symbols: Embedding,
    roles: Embedding,
    messages: Vec<Param<Tensor<2>>>,
    transition: Linear,
    readout: Linear,
    output: Linear,
}

pub(super) struct Encoded {
    goal: Tensor<3>,
    candidate: Tensor<3>,
    context: Tensor<3>,
    invalid: Tensor<2, Bool>,
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
            invalid: self.invalid.clone().select(0, indices),
        }
    }
}

impl Policy {
    /// Keep the native formula encoder and recurrent transition fixed while
    /// adapting the existing action readout. This changes no inference feature.
    pub(super) fn readout_training(mut self) -> Self {
        self.kinds = self.kinds.no_grad();
        self.symbols = self.symbols.no_grad();
        self.roles = self.roles.no_grad();
        self.messages = self.messages.into_iter().map(Module::no_grad).collect();
        self.transition = self.transition.no_grad();
        self
    }

    pub fn new(device: &Device) -> Self {
        Self {
            kinds: EmbeddingConfig::new(19, WIDTH).init(device),
            symbols: EmbeddingConfig::new(SYMBOLS, WIDTH).init(device),
            roles: EmbeddingConfig::new(4, WIDTH).init(device),
            messages: (0..LAYERS)
                .map(|_| {
                    Initializer::Uniform {
                        min: -0.5,
                        max: 0.5,
                    }
                    .init([4, WIDTH], device)
                })
                .collect(),
            transition: LinearConfig::new(4 * WIDTH, WIDTH).init(device),
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
        let encoded = self.encode(batch);
        let state = memory.map(|memory| self.recurrent_state(&encoded, memory));
        self.action_scores(encoded, state)
    }
    pub(super) fn encode(&self, batch: &Batch) -> Encoded {
        self.encode_with_context(batch, self.formula_rows(batch), None)
    }

    fn embedding(&self, kinds: Tensor<2, Int>, symbols: Tensor<2, Int>) -> Tensor<3> {
        self.kinds.forward(kinds) + self.symbols.forward(symbols)
    }

    fn message(
        layer: &Param<Tensor<2>>,
        current: Tensor<3>,
        left: Tensor<3>,
        right: Tensor<3>,
    ) -> Tensor<3> {
        let weight = layer.val();
        let row = |i| {
            weight
                .clone()
                .slice([i..i + 1, 0..WIDTH])
                .unsqueeze_dim::<3>(0)
        };
        // Ordered operands have different trainable channels. Mixing adjacent
        // channels also lets successive layers combine features.
        let shifted = Tensor::cat(
            vec![
                current
                    .clone()
                    .slice([0..1, 0..current.dims()[1], 1..WIDTH]),
                current.clone().slice([0..1, 0..current.dims()[1], 0..1]),
            ],
            2,
        );
        (current + tanh(shifted * row(0) + left * row(1) + right * row(2) + row(3)))
            * std::f32::consts::FRAC_1_SQRT_2
    }

    fn next_rows(&self, batch: &Batch, layer: &Param<Tensor<2>>, h: Tensor<3>) -> Tensor<3> {
        let n = batch.nodes.len();
        let child = |indices: &Tensor<2, Int>| {
            if h.is_autodiff() {
                h.clone().gather(
                    1,
                    indices.clone().unsqueeze_dim::<3>(2).expand([1, n, WIDTH]),
                )
            } else {
                h.clone()
                    .squeeze_dim::<2>(0)
                    .select(0, indices.clone().reshape([n]))
                    .unsqueeze_dim::<3>(0)
            }
        };
        Self::message(layer, h.clone(), child(&batch.left), child(&batch.right))
            * batch.valid.clone()
    }

    fn formula_rows(&self, batch: &Batch) -> Tensor<3> {
        let mut h =
            self.embedding(batch.kinds.clone(), batch.symbols.clone()) * batch.valid.clone();
        for layer in &self.messages {
            h = self.next_rows(batch, layer, h);
        }
        h
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
        Encoded {
            goal,
            candidate,
            context,
            invalid: batch.invalid.clone(),
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
            candidate,
            mut context,
            invalid,
        } = encoded;
        if let Some(state) = state {
            context = (context + state.expand(goal.dims())) * std::f32::consts::FRAC_1_SQRT_2;
        }
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
            .mask_fill(invalid, -10000.)
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

#[cfg(test)]
mod reference;
