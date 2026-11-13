use crate::lean::{Signature, View};
use crate::model::{Rng, fingerprint};
use crate::{ACTIONS, Action, Reference};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

const FEATURES: usize = 30;
const RATE: f64 = 0.045;
const EPOCHS: usize = 12;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningSignal {
    StepAcceptance,
    CheckedContinuation,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ActionValues {
    weights: [[f64; FEATURES]; ACTIONS],
}

pub(crate) type Features = [f64; FEATURES];

#[derive(Clone, Copy)]
pub(crate) struct Observation {
    pub action: u8,
    pub features: Features,
    pub accepted: bool,
    pub continuation: Option<f64>,
}

#[derive(Default, Serialize)]
pub struct TrainingEvidence {
    pub attempts: usize,
    pub checked_proofs: usize,
    pub proof_actions: usize,
    pub exhausted_accepted_actions: usize,
    pub rejected_actions: usize,
    pub censored_actions: usize,
    pub compared_siblings: usize,
}

#[derive(Default)]
pub struct Experience {
    pub(crate) observations: Vec<Observation>,
    pub(crate) preferences: Vec<(Observation, Observation)>,
    pub evidence: TrainingEvidence,
}

impl ActionValues {
    pub(crate) fn bundled() -> &'static Self {
        static VALUES: LazyLock<ActionValues> = LazyLock::new(|| {
            serde_json::from_str(include_str!("../models/acceptance.json"))
                .expect("bundled acceptance checkpoint")
        });
        &VALUES
    }

    pub(crate) fn fingerprint(&self) -> u64 {
        fingerprint(self.weights.iter().flatten())
    }

    pub fn fit(experience: &Experience, signal: LearningSignal, seed: u64) -> Self {
        let mut model = Self::default();
        let mut rng = Rng::new(seed);
        let mut positives = Vec::new();
        let mut negatives = Vec::new();
        for observation in &experience.observations {
            // Use the same observations for both signals. A globally interrupted
            // subtree has no measured continuation return.
            let Some(continuation) = observation.continuation else {
                continue;
            };
            let target = match signal {
                LearningSignal::StepAcceptance => f64::from(observation.accepted),
                LearningSignal::CheckedContinuation => continuation,
            };
            let sample = (observation, target);
            if target > 0.0 {
                positives.push(sample);
            } else {
                negatives.push(sample);
            }
        }
        let total = positives.len() + negatives.len();
        for _ in 0..EPOCHS {
            rng.shuffle(&mut positives);
            rng.shuffle(&mut negatives);
            let mut samples: Vec<_> = positives.iter().chain(&negatives).copied().collect();
            rng.shuffle(&mut samples);
            for (observation, target) in samples {
                let class_size = if target > 0.0 {
                    positives.len()
                } else {
                    negatives.len()
                };
                let balance = (total as f64 / (2 * class_size) as f64).min(5.0);
                model.update(observation, target, balance);
            }
        }
        model
    }

    pub fn fit_sibling_preferences(&self, experience: &Experience, seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let mut correction = Self::default();
        let mut preferences = experience.preferences.clone();
        for _ in 0..16 {
            rng.shuffle(&mut preferences);
            for (winner, sibling) in &preferences {
                let difference = self.score(winner.action, &winner.features)
                    - self.score(sibling.action, &sibling.features)
                    + correction.score(winner.action, &winner.features)
                    - correction.score(sibling.action, &sibling.features);
                let error = 0.025 / (1.0 + difference.exp());
                for (index, (&higher, &lower)) in
                    winner.features.iter().zip(&sibling.features).enumerate()
                {
                    let winner_row = usize::from(winner.action);
                    let sibling_row = usize::from(sibling.action);
                    if winner_row == sibling_row {
                        let weight = &mut correction.weights[winner_row][index];
                        *weight = (*weight + error * (higher - lower)).clamp(-0.6, 0.6);
                    } else {
                        let weight = &mut correction.weights[winner_row][index];
                        *weight = (*weight + error * higher).clamp(-0.6, 0.6);
                        let weight = &mut correction.weights[sibling_row][index];
                        *weight = (*weight - error * lower).clamp(-0.6, 0.6);
                    }
                }
            }
        }
        let mut model = self.clone();
        for (row, delta) in model.weights.iter_mut().zip(correction.weights) {
            for (weight, shift) in row.iter_mut().zip(delta) {
                *weight += shift;
            }
        }
        model
    }

    pub(crate) fn score(&self, action: u8, features: &Features) -> f64 {
        self.weights[usize::from(action)]
            .iter()
            .zip(features)
            .map(|(weight, feature)| weight * feature)
            .sum()
    }

    fn update(&mut self, observation: &Observation, target: f64, balance: f64) {
        let logit = self.score(observation.action, &observation.features);
        let error = 1.0 / (1.0 + (-logit).exp()) - target;
        let row = &mut self.weights[usize::from(observation.action)];
        for (weight, feature) in row.iter_mut().zip(observation.features) {
            *weight -= RATE * (error * feature * balance + 0.0005 * *weight);
        }
    }
}

pub(crate) fn features(
    view: &View,
    action: &Action,
    signature: Option<&Signature>,
    depth: usize,
    related_ancestors: usize,
    identical_ancestors: usize,
) -> Features {
    let mut result = [0.0; FEATURES];
    result[0] = 1.0;
    let head = match view.head.as_str() {
        "forall" => 1,
        "Eq" => 2,
        "And" | "Iff" | "True" => 3,
        "Or" => 4,
        "Exists" => 5,
        "False" => 6,
        "LE.le" | "LT.lt" => 7,
        _ => 8,
    };
    result[head] = 1.0;
    result[9] = fraction(view.locals.len(), 16);
    result[10] = fraction(view.pending.saturating_sub(1), 8);
    result[11] = fraction(depth, 24);
    result[12] = fraction(related_ancestors, 6);
    result[13] = fraction(identical_ancestors, 2);
    result[14] = f64::from(view.locals.contains(&view.target));
    match action.argument.as_ref() {
        Some(Reference::Local(index)) => {
            result[15] = 1.0;
            result[16] = f64::from(view.locals[*index] == view.target);
        }
        Some(Reference::Declaration(_)) => result[17] = 1.0,
        Some(Reference::Catalog(_) | Reference::Archived(_)) => result[18] = 1.0,
        None => {}
    }
    if let Some(signature) = signature {
        result[19] = f64::from(signature.conclusion == view.head);
        result[20] = f64::from(signature.conclusion.is_empty());
        result[21] = fraction(signature.premises.len(), 4);
        result[22] = f64::from(signature.premises.contains(&view.head));
        let available = signature
            .premises
            .iter()
            .filter(|premise| {
                !premise.is_empty()
                    && view
                        .local_signatures
                        .iter()
                        .any(|local| local.premises.is_empty() && local.conclusion == **premise)
            })
            .count();
        result[23] = fraction(available, signature.premises.len());
        result[24] = f64::from(signature.premises.is_empty());
        result[25] = overlap(&view.target_symbols, &signature.conclusion_symbols);
        let mut support = 0.0;
        let mut self_similarity = 0.0;
        let mut unsupported = 0;
        for premise in &signature.premise_symbols {
            let best = view
                .local_signatures
                .iter()
                .map(|local| overlap(premise, &local.conclusion_symbols))
                .fold(0.0, f64::max);
            support += best;
            unsupported += usize::from(best == 0.0);
            self_similarity += overlap(premise, &view.target_symbols);
        }
        let arity = signature.premise_symbols.len().max(1) as f64;
        result[26] = support / arity;
        result[27] = self_similarity / arity;
        result[28] = unsupported as f64 / arity;
        result[29] = result[26] - result[27];
    }
    result
}

fn fraction(value: usize, scale: usize) -> f64 {
    value.min(scale) as f64 / scale.max(1) as f64
}

fn overlap(left: &[String], right: &[String]) -> f64 {
    let shared = left.iter().filter(|symbol| right.contains(symbol)).count();
    (2 * shared) as f64 / (left.len() + right.len()).max(1) as f64
}
