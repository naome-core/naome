//! A bounded prior for solvability, observed cost and demonstrated goal support.
use super::super::{Features, SIGNALS};
use naome_authoring::CompiledQuestion;
use serde::{Deserialize, Serialize};
const INPUTS: usize = SIGNALS + 3;
const HIDDEN: usize = 8;
const OUTPUTS: usize = 3;
const PARAMETERS: usize = INPUTS * HIDDEN + HIDDEN + HIDDEN * OUTPUTS + OUTPUTS;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::frontier) struct Model {
    weights: Vec<f32>,
    pub updates: u64,
    pub resolved: u64,
    pub unresolved: u64,
    pub supports: u64,
}
fn input(question: &CompiledQuestion) -> [f32; INPUTS] {
    let features = Features::of(question);
    let mut input = [0.; INPUTS];
    for (value, count) in input.iter_mut().zip(features.counts) {
        *value = f32::from(count).ln_1p() / 8.;
    }
    input[SIGNALS] = f32::from(features.nodes) / 1024.;
    input[SIGNALS + 1] = f32::from(features.depth) / 32.;
    input[SIGNALS + 2] = 1.;
    input
}
fn sigmoid(value: f32) -> f32 {
    1. / (1. + (-value.clamp(-20., 20.)).exp())
}
impl Model {
    pub fn memory_bytes() -> usize {
        PARAMETERS * std::mem::size_of::<f32>()
    }
    pub fn fresh() -> Self {
        let mut random = crate::sampling::Random::new(0x66696e646572);
        Self {
            weights: (0..PARAMETERS)
                .map(|_| (random.below(2001) as f32 - 1000.) / 20_000.)
                .collect(),
            updates: 0,
            resolved: 0,
            unresolved: 0,
            supports: 0,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.weights.len() != PARAMETERS
            || self.weights.iter().any(|w| !w.is_finite() || w.abs() > 4.)
            || self
                .resolved
                .checked_add(self.unresolved)
                .and_then(|n| n.checked_add(self.supports))
                != Some(self.updates)
        {
            return Err("finder predictor shape, weights or observation counts differ".into());
        }
        Ok(())
    }
    fn forward(&self, input: &[f32; INPUTS]) -> ([f32; HIDDEN], [f32; OUTPUTS]) {
        let mut hidden = [0.; HIDDEN];
        for (h, value) in hidden.iter_mut().enumerate() {
            *value = (input
                .iter()
                .enumerate()
                .map(|(i, x)| x * self.weights[h * INPUTS + i])
                .sum::<f32>()
                + self.weights[INPUTS * HIDDEN + h])
                .tanh();
        }
        let start = INPUTS * HIDDEN + HIDDEN;
        let mut output = [0.; OUTPUTS];
        for (o, value) in output.iter_mut().enumerate() {
            *value = sigmoid(
                hidden
                    .iter()
                    .enumerate()
                    .map(|(h, x)| x * self.weights[start + o * HIDDEN + h])
                    .sum::<f32>()
                    + self.weights[start + OUTPUTS * HIDDEN + o],
            );
        }
        (hidden, output)
    }
    /// Moderate solvability keeps the frontier away from both repeated easy
    /// wins and hopeless work. Actual support outweighs a small cost advantage.
    pub fn weight(&self, question: &CompiledQuestion) -> u64 {
        let [resolved, cost, useful] = self.predictions(question);
        let frontier = 0.25 + 4. * resolved * (1. - resolved);
        (1024. * (0.05 + 4. * useful * useful) * frontier / (1. + cost)) as u64 + 1
    }
    pub fn predictions(&self, question: &CompiledQuestion) -> [f32; OUTPUTS] {
        self.forward(&input(question)).1
    }
    fn train(&mut self, question: &CompiledQuestion, labels: [Option<f32>; OUTPUTS]) {
        let input = input(question);
        let (hidden, output) = self.forward(&input);
        let errors = std::array::from_fn::<_, OUTPUTS, _>(|o| {
            labels[o].map_or(0., |target| {
                let error = output[o] - target;
                if o == 1 {
                    error * output[o] * (1. - output[o])
                } else {
                    error
                }
            })
        });
        let start = INPUTS * HIDDEN + HIDDEN;
        let mut hidden_errors = [0.; HIDDEN];
        for (h, value) in hidden_errors.iter_mut().enumerate() {
            *value = errors
                .iter()
                .enumerate()
                .map(|(o, error)| error * self.weights[start + o * HIDDEN + h])
                .sum::<f32>()
                * (1. - hidden[h] * hidden[h]);
        }
        let update = |weight: &mut f32, error: f32| {
            *weight = (*weight - 0.05 * error).clamp(-4., 4.);
        };
        for (o, error) in errors.into_iter().enumerate() {
            for (h, value) in hidden.into_iter().enumerate() {
                update(&mut self.weights[start + o * HIDDEN + h], error * value);
            }
            update(&mut self.weights[start + OUTPUTS * HIDDEN + o], error);
        }
        for (h, error) in hidden_errors.into_iter().enumerate() {
            for (i, value) in input.into_iter().enumerate() {
                update(&mut self.weights[h * INPUTS + i], error * value);
            }
            update(&mut self.weights[INPUTS * HIDDEN + h], error);
        }
    }
    /// A newly proved statement has not yet demonstrated assistance. The zero
    /// support observation is provisional, not a label of mathematical futility.
    /// A later checked use supplies the positive observation through `support`.
    pub fn observe(
        &mut self,
        question: &CompiledQuestion,
        resolved: bool,
        millis: u64,
    ) -> Result<(), String> {
        self.train(
            question,
            [
                Some(f32::from(resolved)),
                Some(((millis as f32).ln_1p() / 16.).min(1.)),
                resolved.then_some(0.),
            ],
        );
        self.updates = self
            .updates
            .checked_add(1)
            .ok_or("finder update overflow")?;
        if resolved {
            self.resolved = self
                .resolved
                .checked_add(1)
                .ok_or("finder success overflow")?;
        } else {
            self.unresolved = self
                .unresolved
                .checked_add(1)
                .ok_or("finder attempt overflow")?;
        }
        self.validate()
    }
    pub fn support(&mut self, question: &CompiledQuestion) -> Result<(), String> {
        self.train(question, [None, None, Some(1.)]);
        self.updates = self
            .updates
            .checked_add(1)
            .ok_or("finder update overflow")?;
        self.supports = self
            .supports
            .checked_add(1)
            .ok_or("finder support overflow")?;
        self.validate()
    }
}
