//! A small real neural value model with paired exact Adam state. No tensor RNG
//! or lower-model weights are shared, and no result field enters its inputs.
use super::{Experience, FEATURES};
pub const HIDDEN: usize = 12;
pub const OUTPUTS: usize = 3;
pub const PARAMETERS: usize = FEATURES * HIDDEN + HIDDEN + HIDDEN * OUTPUTS + OUTPUTS;
const B1: usize = FEATURES * HIDDEN;
const W2: usize = B1 + HIDDEN;
const B2: usize = W2 + HIDDEN * OUTPUTS;
#[derive(Clone)]
pub struct Network {
    pub weights: Vec<f32>,
    pub first: Vec<f32>,
    pub second: Vec<f32>,
    pub updates: u64,
}
impl Network {
    pub fn fresh(mut seed: u64) -> Self {
        let weights = (0..PARAMETERS)
            .map(|i| {
                if (B1..W2).contains(&i) || i >= B2 {
                    0.
                } else {
                    let value =
                        (super::super::model::random(&mut seed) >> 40) as f32 / (1u32 << 24) as f32;
                    (value * 2. - 1.) * (6f32 / (FEATURES + HIDDEN) as f32).sqrt()
                }
            })
            .collect();
        Self {
            weights,
            first: vec![0.; PARAMETERS],
            second: vec![0.; PARAMETERS],
            updates: 0,
        }
    }
    pub fn forward(&self, input: &[f32; FEATURES]) -> ([f32; HIDDEN], [f32; OUTPUTS]) {
        let mut hidden = [0.; HIDDEN];
        let mut output = [0.; OUTPUTS];
        for (j, h) in hidden.iter_mut().enumerate() {
            *h = (self.weights[B1 + j]
                + input
                    .iter()
                    .enumerate()
                    .map(|(i, x)| x * self.weights[j * FEATURES + i])
                    .sum::<f32>())
            .tanh();
        }
        for (k, o) in output.iter_mut().enumerate() {
            *o = self.weights[B2 + k]
                + hidden
                    .iter()
                    .enumerate()
                    .map(|(j, h)| h * self.weights[W2 + k * HIDDEN + j])
                    .sum::<f32>();
        }
        (hidden, output)
    }
    pub fn gradient(&self, experience: &Experience) -> (f32, Vec<f32>) {
        let input = experience.features();
        let (hidden, output) = self.forward(&input);
        let target = experience.targets();
        let mask = experience.mask();
        let mut gradient = vec![0.; PARAMETERS];
        let mut error = [0.; OUTPUTS];
        let mut loss = 0.;
        for k in 0..OUTPUTS {
            error[k] = mask[k] * 2. * (output[k] - target[k]) / OUTPUTS as f32;
            loss += mask[k] * (output[k] - target[k]).powi(2) / OUTPUTS as f32;
            gradient[B2 + k] = error[k];
            for j in 0..HIDDEN {
                gradient[W2 + k * HIDDEN + j] = error[k] * hidden[j];
            }
        }
        for j in 0..HIDDEN {
            let delta = (0..OUTPUTS)
                .map(|k| error[k] * self.weights[W2 + k * HIDDEN + j])
                .sum::<f32>()
                * (1. - hidden[j] * hidden[j]);
            gradient[B1 + j] = delta;
            for i in 0..FEATURES {
                gradient[j * FEATURES + i] = delta * input[i];
            }
        }
        (loss, gradient)
    }
    pub fn update(&mut self, batch: &[&Experience]) -> Result<f32, String> {
        if batch.is_empty() {
            return Err("meta update lacks real trial experience".into());
        }
        let mut gradient = vec![0.; PARAMETERS];
        let mut loss = 0.;
        for example in batch {
            let (value, g) = self.gradient(example);
            loss += value / batch.len() as f32;
            for (total, g) in gradient.iter_mut().zip(g) {
                *total += g / batch.len() as f32;
            }
        }
        if !loss.is_finite() || gradient.iter().any(|g| !g.is_finite()) {
            return Err("non-finite meta optimization".into());
        }
        self.updates = self
            .updates
            .checked_add(1)
            .ok_or("meta optimizer counter overflow")?;
        let b1 = 1. - 0.9f32.powf(self.updates as f32);
        let b2 = 1. - 0.999f32.powf(self.updates as f32);
        for (i, g) in gradient.into_iter().enumerate() {
            let g = g.clamp(-5., 5.);
            self.first[i] = 0.9 * self.first[i] + 0.1 * g;
            self.second[i] = 0.999 * self.second[i] + 0.001 * g * g;
            self.weights[i] -= 0.003 * (self.first[i] / b1) / ((self.second[i] / b2).sqrt() + 1e-8);
        }
        Ok(loss)
    }
    pub fn encode(&self) -> (Vec<u8>, Vec<u8>) {
        let weights = self.weights.iter().flat_map(|x| x.to_le_bytes()).collect();
        let optimizer = self
            .updates
            .to_le_bytes()
            .into_iter()
            .chain(
                self.first
                    .iter()
                    .chain(&self.second)
                    .flat_map(|x| x.to_le_bytes()),
            )
            .collect();
        (weights, optimizer)
    }
    pub fn decode(weights: &[u8], optimizer: &[u8], updates: u64) -> Result<Self, String> {
        if weights.len() != PARAMETERS * 4
            || optimizer.len() != 8 + PARAMETERS * 8
            || u64::from_le_bytes(optimizer[..8].try_into().unwrap()) != updates
        {
            return Err("meta paired checkpoint dimensions or counter differ".into());
        }
        let floats = |bytes: &[u8]| {
            bytes
                .chunks_exact(4)
                .map(|x| f32::from_le_bytes(x.try_into().unwrap()))
                .collect::<Vec<_>>()
        };
        let weights = floats(weights);
        let values = floats(&optimizer[8..]);
        if weights.iter().chain(&values).any(|x| !x.is_finite())
            || values[PARAMETERS..].iter().any(|x| *x < 0.)
        {
            return Err("invalid meta checkpoint value".into());
        }
        Ok(Self {
            weights,
            first: values[..PARAMETERS].to_vec(),
            second: values[PARAMETERS..].to_vec(),
            updates,
        })
    }
}
