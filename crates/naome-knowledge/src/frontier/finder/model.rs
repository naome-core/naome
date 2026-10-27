//! A bounded historical prior for the configured solver, never formula truth.
use super::super::{Features, SIGNALS};
use naome_authoring::CompiledQuestion;
use serde::{Deserialize, Serialize};

const INPUTS: usize = SIGNALS + 3;
const HIDDEN: usize = 8;
const OUTPUTS: usize = 2;
const PARAMETERS: usize = INPUTS * HIDDEN + HIDDEN + HIDDEN * OUTPUTS + OUTPUTS;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::frontier) struct Model {
    weights: Vec<f32>,
    pub updates: u64,
    pub resolved: u64,
    pub unresolved: u64,
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
    pub fn fresh() -> Self {
        let mut random = crate::sampling::Random::new(0x66696e646572);
        let weights = (0..PARAMETERS)
            .map(|_| (random.below(2001) as f32 - 1000.) / 20_000.)
            .collect();
        Self {
            weights,
            updates: 0,
            resolved: 0,
            unresolved: 0,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.weights.len() != PARAMETERS
            || self.weights.iter().any(|w| !w.is_finite() || w.abs() > 4.)
            || self.resolved.checked_add(self.unresolved) != Some(self.updates)
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
        let mut output = [0.; OUTPUTS];
        let start = INPUTS * HIDDEN + HIDDEN;
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

    /// Positive mass preserves exploration even for poorly predicted questions.
    pub fn weight(&self, question: &CompiledQuestion) -> u64 {
        let (_, [resolved, cost]) = self.forward(&input(question));
        (1024. * (0.2 + resolved) / (0.5 + cost)) as u64 + 1
    }

    /// The second head estimates log observed service cost. Unresolved means
    /// only that the named solver returned no candidate in its actual attempt.
    pub fn observe(
        &mut self,
        question: &CompiledQuestion,
        resolved: bool,
        millis: u64,
    ) -> Result<(), String> {
        let input = input(question);
        let (hidden, output) = self.forward(&input);
        let cost = ((millis as f32).ln_1p() / 16.).min(1.);
        let errors = [
            output[0] - f32::from(resolved),
            (output[1] - cost) * output[1] * (1. - output[1]),
        ];
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
}
