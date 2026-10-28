//! Compact observations of completed training units, not stored examples.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrainingMeasurements {
    pub input_digest: String,
    pub target_digest: String,
    pub slots: usize,
    pub auxiliary_slots: usize,
    pub active_auxiliary_slots: usize,
    pub masked_auxiliary_slots: usize,
    pub additional_positive_targets: usize,
    pub active_additional_positive_targets: usize,
    pub cost_targets: usize,
    pub preference_targets: usize,
    pub internal_steps: usize,
    pub candidate_transitions: usize,
    pub reference_slots: usize,
    pub reference_digest: String,
}
impl Default for TrainingMeasurements {
    fn default() -> Self {
        let initial = super::super::digest(&"native-training-observation");
        Self {
            input_digest: initial.clone(),
            target_digest: initial.clone(),
            reference_digest: initial,
            slots: 0,
            auxiliary_slots: 0,
            active_auxiliary_slots: 0,
            masked_auxiliary_slots: 0,
            additional_positive_targets: 0,
            active_additional_positive_targets: 0,
            cost_targets: 0,
            preference_targets: 0,
            internal_steps: 0,
            candidate_transitions: 0,
            reference_slots: 0,
        }
    }
}
impl TrainingMeasurements {
    pub(in crate::learning) fn include(&mut self, unit: &Self) -> Result<(), String> {
        self.input_digest = super::super::digest(&(&self.input_digest, &unit.input_digest));
        self.target_digest = super::super::digest(&(&self.target_digest, &unit.target_digest));
        self.reference_digest =
            super::super::digest(&(&self.reference_digest, &unit.reference_digest));
        macro_rules! add {
            ($($field:ident),+ $(,)?) => { $(self.$field = self.$field.checked_add(unit.$field).ok_or("native measurement counter overflow")?;)+ };
        }
        add!(
            slots,
            auxiliary_slots,
            active_auxiliary_slots,
            masked_auxiliary_slots,
            additional_positive_targets,
            active_additional_positive_targets,
            cost_targets,
            preference_targets,
            internal_steps,
            candidate_transitions,
            reference_slots
        );
        Ok(())
    }

    pub(super) fn observe(
        &mut self,
        pool: &Pool,
        sample: &[super::super::pool::Sample<'_>],
        targets: &[Graph],
        cursor: u64,
        recurrence: Recurrence,
        rich: bool,
    ) {
        let inputs: Vec<_> = sample
            .iter()
            .map(|s| (s.graph.key(), s.selected, s.parent, s.auxiliary))
            .collect();
        self.input_digest = super::super::digest(&(&self.input_digest, cursor, inputs));
        let mut labels = Vec::with_capacity(sample.len());
        for (sample, target) in sample.iter().zip(targets) {
            let active = !sample.auxiliary || rich;
            let base = pool.target_graph(sample.graph, false);
            let additional = if sample.auxiliary {
                sample.graph.successes.len()
            } else {
                sample
                    .graph
                    .successes
                    .iter()
                    .filter(|i| !base.successes.contains(i))
                    .count()
            };
            self.slots += 1;
            self.auxiliary_slots += usize::from(sample.auxiliary);
            self.active_auxiliary_slots += usize::from(sample.auxiliary && active);
            self.masked_auxiliary_slots += usize::from(sample.auxiliary && !active);
            self.additional_positive_targets += additional;
            self.active_additional_positive_targets += if rich { additional } else { 0 };
            let witnesses = if rich {
                pool.witnesses(sample.graph)
            } else {
                Vec::new()
            };
            self.cost_targets += witnesses.len();
            for (index, witness) in witnesses.iter().enumerate() {
                self.preference_targets += witnesses[index + 1..]
                    .iter()
                    .filter(|other| {
                        witness.source != other.source
                            && witness.remaining_steps != other.remaining_steps
                    })
                    .count();
            }
            labels.push((
                active.then_some(&target.successes),
                witnesses
                    .iter()
                    .map(|w| (w.action, w.remaining_steps, w.source.clone()))
                    .collect::<Vec<_>>(),
            ));
        }
        self.target_digest = super::super::digest(&(&self.target_digest, labels));
        if recurrence != Recurrence::Disabled {
            self.internal_steps += 2 * sample.len();
            self.candidate_transitions += sample.len()
                * sample
                    .iter()
                    .map(|s| s.graph.candidates.len())
                    .max()
                    .unwrap_or(0);
        }
    }
    pub(super) fn reference(&mut self, graphs: &[&Graph], recurrence: Recurrence) {
        self.reference_slots += graphs.len();
        self.reference_digest = super::super::digest(&(
            &self.reference_digest,
            graphs
                .iter()
                .map(|g| (g.key(), &g.successes))
                .collect::<Vec<_>>(),
        ));
        if recurrence != Recurrence::Disabled {
            self.internal_steps += 2 * graphs.len();
            self.candidate_transitions +=
                graphs.len() * graphs.iter().map(|g| g.candidates.len()).max().unwrap_or(0);
        }
    }
}
