//! A bounded prior for solvability, observed cost and demonstrated goal support.
use super::super::SIGNALS;
use super::analysis::{BINDINGS, Descriptor};
use naome_checker::question::ResearchQuestion;
use serde::{Deserialize, Serialize};
const INPUTS: usize = SIGNALS + 3;
const HIDDEN: usize = 8;
const OUTPUTS: usize = 3;
const ROLE_START: usize = INPUTS * HIDDEN + HIDDEN + HIDDEN * OUTPUTS + OUTPUTS;
const PARAMETERS: usize = ROLE_START + BINDINGS * OUTPUTS;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::frontier) struct Model {
    #[cfg(test)]
    #[serde(skip)]
    frozen: bool,
    weights: Vec<f32>,
    utility: Vec<f32>,
    pub utility_observations: u64,
    pub rehearsals: u64,
    pub updates: u64,
    pub resolved: u64,
    pub unresolved: u64,
    pub supports: u64,
}
fn input(descriptor: &Descriptor) -> [f32; INPUTS] {
    let features = &descriptor.features;
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
        (PARAMETERS + INPUTS + BINDINGS + 1) * std::mem::size_of::<f32>()
    }
    pub fn fresh() -> Self {
        Self::from_seed(0x66696e646572)
    }
    #[cfg(test)]
    pub fn seeded(seed: u64) -> Self {
        Self::from_seed(seed)
    }
    #[cfg(test)]
    pub fn freeze(&mut self) {
        self.frozen = true;
    }
    fn from_seed(seed: u64) -> Self {
        let mut random = crate::sampling::Random::new(seed);
        let mut weights = Vec::with_capacity(PARAMETERS);
        weights.extend((0..ROLE_START).map(|_| (random.below(2001) as f32 - 1000.) / 20_000.));
        // Direct role terms begin neutral and learn without a second small
        // random projection attenuating their already bounded input signal.
        weights.extend([0.; BINDINGS * OUTPUTS]);
        Self {
            #[cfg(test)]
            frozen: false,
            weights,
            utility: vec![0.; INPUTS + BINDINGS + 1],
            utility_observations: 0,
            rehearsals: 0,
            updates: 0,
            resolved: 0,
            unresolved: 0,
            supports: 0,
        }
    }
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.weights.len() != PARAMETERS {
            return Err(crate::Error::ResearchMismatch {
                code: crate::ResearchFailure::FinderPredictorWidth,
                expected: PARAMETERS as u64,
                actual: self.weights.len() as u64,
            });
        }
        if let Some(index) = self
            .weights
            .iter()
            .position(|w| !w.is_finite() || w.abs() > 4.)
        {
            return Err(crate::Error::ResearchIndex {
                code: crate::ResearchFailure::FinderPredictorWeight,
                index,
            });
        }
        if self.utility.len() != INPUTS + BINDINGS + 1 {
            return Err(crate::Error::ResearchMismatch {
                code: crate::ResearchFailure::FinderUtilityWidth,
                expected: (INPUTS + BINDINGS + 1) as u64,
                actual: self.utility.len() as u64,
            });
        }
        if let Some(index) = self
            .utility
            .iter()
            .position(|w| !w.is_finite() || w.abs() > 4.)
        {
            return Err(crate::Error::ResearchIndex {
                code: crate::ResearchFailure::FinderUtilityWeight,
                index,
            });
        }
        if self
            .resolved
            .checked_add(self.unresolved)
            .and_then(|n| n.checked_add(self.supports))
            != Some(self.updates)
        {
            return Err(crate::ResearchFailure::FinderObservationCounts.into());
        }
        Ok(())
    }
    fn forward(
        &self,
        input: &[f32; INPUTS],
        bindings: &[f32; BINDINGS],
    ) -> ([f32; HIDDEN], [f32; OUTPUTS]) {
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
                    + self.weights[start + OUTPUTS * HIDDEN + o]
                    + bindings
                        .iter()
                        .enumerate()
                        .map(|(i, x)| x * self.weights[ROLE_START + o * BINDINGS + i])
                        .sum::<f32>(),
            );
        }
        (hidden, output)
    }
    /// Moderate solvability keeps the frontier away from both repeated easy
    /// wins and hopeless work. Actual support outweighs a small cost advantage.
    pub fn weight(&self, question: &ResearchQuestion) -> u64 {
        self.weight_from(&Descriptor::of(question))
    }
    pub fn weight_from(&self, descriptor: &Descriptor) -> u64 {
        let [resolved, cost, useful] = self.predictions_from(descriptor);
        let frontier = 0.25 + 4. * resolved * (1. - resolved);
        (1024. * (0.05 + 4. * useful * useful) * frontier / (1. + cost)) as u64 + 1
    }
    #[cfg(test)]
    pub fn predictions(&self, question: &ResearchQuestion) -> [f32; OUTPUTS] {
        self.predictions_from(&Descriptor::of(question))
    }
    pub fn predictions_from(&self, descriptor: &Descriptor) -> [f32; OUTPUTS] {
        self.forward(&input(descriptor), &descriptor.bindings).1
    }
    fn train(&mut self, question: &ResearchQuestion, labels: [Option<f32>; OUTPUTS]) {
        self.train_descriptor(&Descriptor::of(question), labels);
    }
    fn train_descriptor(&mut self, descriptor: &Descriptor, labels: [Option<f32>; OUTPUTS]) {
        let input = input(descriptor);
        let (hidden, output) = self.forward(&input, &descriptor.bindings);
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
            for (i, value) in descriptor.bindings.into_iter().enumerate() {
                update(
                    &mut self.weights[ROLE_START + o * BINDINGS + i],
                    error * value,
                );
            }
        }
        for (h, error) in hidden_errors.into_iter().enumerate() {
            for (i, value) in input.into_iter().enumerate() {
                update(&mut self.weights[h * INPUTS + i], error * value);
            }
            update(&mut self.weights[INPUTS * HIDDEN + h], error);
        }
    }
    pub fn utility(&self, descriptor: &Descriptor) -> f32 {
        let mut features = input(descriptor).to_vec();
        features.extend(descriptor.bindings);
        features.push(1.);
        sigmoid(features.iter().zip(&self.utility).map(|(x, w)| x * w).sum())
    }
    fn train_utility(&mut self, descriptor: &Descriptor, target: f32) {
        let error = self.utility(descriptor) - target;
        let mut features = input(descriptor).to_vec();
        features.extend(descriptor.bindings);
        features.push(1.);
        for (weight, value) in self.utility.iter_mut().zip(features) {
            *weight = (*weight - 0.05 * error * value).clamp(-4., 4.);
        }
    }
    pub fn observe_utility(
        &mut self,
        descriptor: &Descriptor,
        target: f32,
    ) -> Result<(), crate::Error> {
        if !target.is_finite() || !(0.0..=1.0).contains(&target) {
            return Err(crate::ResearchFailure::FinderUtilityLabel.into());
        }
        descriptor.validate()?;
        #[cfg(test)]
        if self.frozen {
            return Ok(());
        }
        let next = self
            .utility_observations
            .checked_add(1)
            .ok_or(crate::ResearchFailure::FinderUtilityOverflow)?;
        self.train_utility(descriptor, target);
        self.utility_observations = next;
        self.validate()
    }
    pub fn rehearse(
        &mut self,
        descriptor: &Descriptor,
        resolved: Option<bool>,
        millis: Option<u64>,
        support: Option<bool>,
        utility: Option<f32>,
    ) -> Result<(), crate::Error> {
        descriptor.validate()?;
        // Reject the entire observation before any parameter can change.
        if utility.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
            return Err(crate::ResearchFailure::FinderReplayUtility.into());
        }
        #[cfg(test)]
        if self.frozen {
            return Ok(());
        }
        let next = self
            .rehearsals
            .checked_add(1)
            .ok_or(crate::ResearchFailure::FinderRehearsalOverflow)?;
        self.train_descriptor(
            descriptor,
            [
                resolved.map(f32::from),
                millis.map(|v| ((v as f32).ln_1p() / 16.).min(1.)),
                support.map(f32::from),
            ],
        );
        if let Some(target) = utility {
            self.train_utility(descriptor, target);
        }
        self.rehearsals = next;
        self.validate()
    }
    /// A newly proved statement has not yet had an observed opportunity to help
    /// another proof. Its support label stays unavailable until a checked use.
    pub fn observe(
        &mut self,
        question: &ResearchQuestion,
        resolved: bool,
        millis: u64,
    ) -> Result<(), crate::Error> {
        self.observe_labels(question, resolved, millis, None)
    }
    #[cfg(test)]
    pub fn observe_provisional(
        &mut self,
        question: &ResearchQuestion,
        resolved: bool,
        millis: u64,
    ) -> Result<(), crate::Error> {
        self.observe_labels(question, resolved, millis, resolved.then_some(0.))
    }
    fn observe_labels(
        &mut self,
        question: &ResearchQuestion,
        resolved: bool,
        millis: u64,
        support: Option<f32>,
    ) -> Result<(), crate::Error> {
        #[cfg(test)]
        if self.frozen {
            return Ok(());
        }
        let updates = self
            .updates
            .checked_add(1)
            .ok_or(crate::ResearchFailure::FinderUpdateOverflow)?;
        let count = if resolved {
            self.resolved
                .checked_add(1)
                .ok_or(crate::ResearchFailure::FinderSuccessOverflow)?
        } else {
            self.unresolved
                .checked_add(1)
                .ok_or(crate::ResearchFailure::FinderAttemptOverflow)?
        };
        self.train(
            question,
            [
                Some(f32::from(resolved)),
                Some(((millis as f32).ln_1p() / 16.).min(1.)),
                support,
            ],
        );
        self.updates = updates;
        if resolved {
            self.resolved = count;
        } else {
            self.unresolved = count;
        }
        self.validate()
    }
    pub fn support(&mut self, question: &ResearchQuestion) -> Result<(), crate::Error> {
        #[cfg(test)]
        if self.frozen {
            return Ok(());
        }
        let updates = self
            .updates
            .checked_add(1)
            .ok_or(crate::ResearchFailure::FinderUpdateOverflow)?;
        let supports = self
            .supports
            .checked_add(1)
            .ok_or(crate::ResearchFailure::FinderSupportOverflow)?;
        self.train(question, [None, None, Some(1.)]);
        self.updates = updates;
        self.supports = supports;
        self.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overflowing_observation_counters_leave_model_unchanged() {
        let q = ResearchQuestion::from_hex(&crate::mocks::create_question(0)).unwrap();
        let descriptor = Descriptor::of(&q);
        let mut model = Model::fresh();
        model.utility_observations = u64::MAX;
        let before = model.clone();
        assert_eq!(
            model.observe_utility(&descriptor, 0.5).unwrap_err(),
            crate::Error::from(crate::ResearchFailure::FinderUtilityOverflow)
        );
        assert_eq!(model, before);
        model.rehearsals = u64::MAX;
        let before = model.clone();
        assert_eq!(
            model
                .rehearse(&descriptor, Some(true), Some(1), Some(true), Some(0.5))
                .unwrap_err(),
            crate::Error::from(crate::ResearchFailure::FinderRehearsalOverflow)
        );
        assert_eq!(model, before);
        model.updates = u64::MAX;
        model.resolved = u64::MAX;
        let before = model.clone();
        assert_eq!(
            model.observe(&q, true, 1).unwrap_err(),
            crate::Error::from(crate::ResearchFailure::FinderUpdateOverflow)
        );
        assert_eq!(model, before);
        assert_eq!(
            model.support(&q).unwrap_err(),
            crate::Error::from(crate::ResearchFailure::FinderUpdateOverflow)
        );
        assert_eq!(model, before);
    }
}
