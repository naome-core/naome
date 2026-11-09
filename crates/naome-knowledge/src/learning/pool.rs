//! A bounded on-demand proof pool. Features never contain sampling provenance.
use super::graph::Graph;
use std::collections::{BTreeMap, BTreeSet};

mod preservation;
#[cfg(test)]
mod reference;
pub(super) use preservation::References;

type Rules = BTreeMap<i32, Vec<usize>>;
type Proofs = BTreeMap<String, Rules>;
type Families = BTreeMap<(String, String), Proofs>;
const WORK_BYTES: usize = super::MODEL_REQUIREMENTS.work_bytes / 16;
#[derive(Default)]
pub struct Pool {
    graphs: Vec<Graph>,
    work_bytes: usize,
    work_capacity: Option<usize>,
    keys: BTreeMap<String, usize>,
    origins: BTreeMap<bool, Families>,
    priorities: Vec<u64>,
    repairs: Vec<usize>,
    derivations: Vec<super::search::derivation::Derivation>,
    witnesses: BTreeMap<String, BTreeMap<usize, Witness>>,
    hindsight: BTreeSet<(u64, String, usize, String)>,
    auxiliary: BTreeSet<String>,
    baseline_successes: BTreeMap<String, Vec<usize>>,
    sequences: BTreeMap<String, Vec<Vec<(usize, usize)>>>,
    #[cfg(test)]
    reference: bool,
}

#[derive(Default)]
pub(super) struct DerivedCounts {
    pub transitions: usize,
    pub fragments: usize,
    pub omitted: usize,
    pub unavailable: usize,
    pub preferences: usize,
    pub hindsight: usize,
    pub repairs: usize,
    pub sequences: usize,
}

#[derive(Clone)]
pub(super) struct Witness {
    pub action: usize,
    pub remaining_steps: usize,
    pub source: String,
}
pub(super) struct Sample<'a> {
    pub graph: &'a Graph,
    pub selected: usize,
    pub parent: Option<usize>,
    pub auxiliary: bool,
}
impl Pool {
    pub(super) fn reconcile(
        &mut self,
        observations: &[super::experience::Observation],
        rich_targets: bool,
    ) -> Result<(), crate::Error> {
        if observations.len() > super::history::SOURCES {
            return Err(crate::ResearchFailure::PoolHindsightSourceCapacity.into());
        }
        self.hindsight.clear();
        for graph in &self.graphs {
            let key = graph.key();
            if !self.auxiliary.contains(&key) && !self.baseline_successes.contains_key(&key) {
                self.baseline_successes.insert(key, graph.successes.clone());
                self.work_bytes = self
                    .work_bytes
                    .checked_add(256 + 8 * graph.successes.len())
                    .ok_or(crate::ResearchFailure::PoolMaskWorkOverflow)?;
            }
        }
        if self.work_bytes > self.work_capacity.unwrap_or(WORK_BYTES) {
            return Err(crate::ResearchFailure::PoolMaskWorkCapacity.into());
        }
        for observation in observations {
            observation.validate()?;
            if let super::experience::TerminalEvidence::CertifiedCandidate { proof_id, .. } =
                &observation.summary.terminal
            {
                for derivation in &self.derivations {
                    if derivation.source_proof.as_ref() != Some(proof_id)
                        || observation.summary.trace.checked_trajectory.as_ref()
                            != Some(&derivation.source_tree)
                    {
                        continue;
                    }
                    for execution in &observation.executions {
                        for (event, witness) in execution.reconcile(derivation)? {
                            if self.hindsight.insert((
                                observation.summary.job,
                                execution.target.clone(),
                                event,
                                witness,
                            )) {
                                self.work_bytes = self
                                    .work_bytes
                                    .checked_add(512)
                                    .ok_or(crate::ResearchFailure::PoolHindsightWorkOverflow)?;
                                if self.work_bytes > self.work_capacity.unwrap_or(WORK_BYTES) {
                                    return Err(
                                        crate::ResearchFailure::PoolHindsightWorkCapacity.into()
                                    );
                                }
                            }
                        }
                    }
                }
            }
            let case = super::curriculum::owned::case(&observation.question)
                .ok_or(crate::ResearchFailure::PoolObservationLineage)?;
            for derivation in super::search::derivation::observed(observation)? {
                if let Some(fragment) = derivation.fragments.first() {
                    let graphs: Vec<_> = derivation
                        .steps
                        .iter()
                        .filter(|step| step.graph.candidates.len() > 1)
                        .map(|step| step.graph.clone())
                        .collect();
                    for graph in &graphs {
                        if !self.keys.contains_key(&graph.key())
                            && self.auxiliary.insert(graph.key())
                        {
                            self.work_bytes = self
                                .work_bytes
                                .checked_add(256)
                                .ok_or(crate::ResearchFailure::PoolMaskWorkOverflow)?;
                        }
                    }
                    self.add(
                        matches!(observation.summary.origin, super::Origin::Peer { .. }),
                        &case.dependency,
                        &case.family,
                        &fragment.proof_id,
                        graphs,
                    )?;
                }
                self.add_derivation(derivation, true)?;
            }
            let checked: Vec<_> = self.derivations.iter().enumerate().filter(|(_, d)| {
                let admitted = matches!(&observation.summary.terminal,
                    super::experience::TerminalEvidence::CertifiedCandidate { proof_id, .. }
                    if d.source_proof.as_ref() == Some(proof_id)
                        && observation.summary.trace.checked_trajectory.as_ref() == Some(&d.source_tree));
                let partial = d.fragments.iter().any(|f| matches!(&f.parent,
                    super::search::derivation::Parent::Observed { receipt, .. }
                    if receipt == &observation.summary.receipt));
                admitted || partial
            }).collect();
            for execution in &observation.executions {
                for window in execution.windows(&checked)? {
                    let (source, step) = *window.last().expect("nonempty observed window");
                    let key = self.derivations[source].steps[step].graph.key();
                    self.work_bytes = self
                        .work_bytes
                        .checked_add(256 + 32 * window.len())
                        .ok_or(crate::ResearchFailure::PoolSequenceWorkOverflow)?;
                    if self.work_bytes > self.work_capacity.unwrap_or(WORK_BYTES) {
                        return Err(crate::ResearchFailure::PoolSequenceWorkCapacity.into());
                    }
                    self.sequences.entry(key).or_default().push(window);
                }
            }
        }
        if rich_targets {
            for observation in observations {
                self.reconcile_repair(observation)?;
            }
        }
        Ok(())
    }

    fn reconcile_repair(
        &mut self,
        observation: &super::experience::Observation,
    ) -> Result<(), crate::Error> {
        let super::experience::TerminalEvidence::CertifiedCandidate { proof_id, refuted } =
            &observation.summary.terminal
        else {
            return Ok(());
        };
        if !matches!(observation.summary.origin, super::Origin::Local)
            || !observation
                .executions
                .iter()
                .any(|trace| trace.has_repair())
        {
            return Ok(());
        }
        let question = naome_checker::question::ResearchQuestion::from_hex(&observation.question)?;
        let target = if *refuted {
            question.refuted_target()
        } else {
            question.proved_target()
        };
        let case = super::curriculum::owned::case(&observation.question)
            .ok_or(crate::ResearchFailure::PoolObservationLineage)?;
        for execution in &observation.executions {
            // A supplemental replay must fit the same proof checking capacity
            // as other training material. An unusable replay contributes no label.
            if let Ok(Some(graph)) = execution.checked_repair(target, &observation.knowledge) {
                self.add_repair(&case, proof_id, graph)?;
            }
        }
        Ok(())
    }

    pub fn add_derivation(
        &mut self,
        derivation: super::search::derivation::Derivation,
        active: bool,
    ) -> Result<(), crate::Error> {
        for step in &derivation.steps {
            // Single-choice transitions carry sequence state, not a missing
            // competing-action label. Ambiguous states must be the same ones
            // produced by the ordinary native checked proof replay.
            if active
                && step.graph.candidates.len() > 1
                && !self.keys.contains_key(&step.graph.key())
            {
                return Err(crate::ResearchFailure::PoolSequenceBinding.into());
            }
            let key = step.graph.key();
            let candidates = self.witnesses.entry(key).or_default();
            let next = Witness {
                action: step.graph.expert,
                remaining_steps: step.remaining_steps,
                source: step.witness.clone(),
            };
            match candidates.get_mut(&next.action) {
                Some(previous)
                    if (next.remaining_steps, &next.source)
                        < (previous.remaining_steps, &previous.source) =>
                {
                    *previous = next
                }
                None => {
                    self.work_bytes = self
                        .work_bytes
                        .checked_add(1024 + std::mem::size_of::<Witness>())
                        .ok_or(crate::ResearchFailure::PoolWitnessWorkOverflow)?;
                    candidates.insert(next.action, next);
                }
                _ => {}
            }
        }
        self.work_bytes = self
            .work_bytes
            .checked_add(derivation.work_bytes())
            .ok_or(crate::ResearchFailure::PoolDerivedWorkOverflow)?;
        if self.work_bytes > self.work_capacity.unwrap_or(WORK_BYTES) {
            return Err(crate::ResearchFailure::PoolDerivedWorkCapacity.into());
        }
        self.derivations.push(derivation);
        Ok(())
    }
    /// Compare only different actions with separately checked completions of
    /// the exact same state. Costs are symbolic suffix lengths, not timings.
    pub(super) fn witnesses(&self, graph: &Graph) -> Vec<Witness> {
        self.witnesses
            .get(&graph.key())
            .map_or_else(Vec::new, |w| w.values().cloned().collect())
    }
    pub(super) fn derived_counts(&self) -> DerivedCounts {
        let mut counts = DerivedCounts {
            hindsight: self.hindsight.len(),
            repairs: self.repairs.len(),
            sequences: self.sequences.values().map(Vec::len).sum(),
            ..DerivedCounts::default()
        };
        for derivation in &self.derivations {
            counts.transitions += derivation.steps.len();
            counts.fragments += derivation.fragments.len();
            counts.omitted += derivation.omitted_steps;
            counts.unavailable +=
                derivation.oversized_fragments + derivation.rejected_fragments.len();
        }
        for graph in &self.graphs {
            let witnesses = self.witnesses(graph);
            for (index, a) in witnesses.iter().enumerate() {
                counts.preferences += witnesses[index + 1..]
                    .iter()
                    .filter(|b| a.remaining_steps != b.remaining_steps && a.source != b.source)
                    .count();
            }
        }
        counts
    }
    fn add_repair(
        &mut self,
        case: &super::curriculum::Case,
        proof: &str,
        graph: Graph,
    ) -> Result<(), crate::Error> {
        let key = graph.key();
        let needed = self
            .keys
            .get(&key)
            .map_or_else(|| graph.work_bytes(), |_| 0);
        if self.work_bytes.saturating_add(needed).saturating_add(64)
            > self.work_capacity.unwrap_or(WORK_BYTES)
        {
            return Ok(());
        }
        self.add(false, &case.dependency, &case.family, proof, vec![graph])?;
        let index = self.keys[&key];
        if !self.repairs.contains(&index) {
            self.repairs.push(index);
            self.work_bytes += 64;
        }
        Ok(())
    }

    pub fn add(
        &mut self,
        peer: bool,
        dependency: &str,
        family: &str,
        proof: &str,
        graphs: Vec<Graph>,
    ) -> Result<(), crate::Error> {
        for mut graph in graphs {
            graph.successes.sort_unstable();
            graph.successes.dedup();
            let key = graph.key();
            let index = if let Some(index) = self.keys.get(&key) {
                let index = *index;
                let existing = &mut self.graphs[index];
                existing.successes.extend(&graph.successes);
                existing.successes.sort_unstable();
                existing.successes.dedup();
                index
            } else {
                self.work_bytes = self
                    .work_bytes
                    .checked_add(graph.work_bytes())
                    .ok_or(crate::ResearchFailure::PoolGraphWorkOverflow)?;
                if self.work_bytes > self.work_capacity.unwrap_or(WORK_BYTES) {
                    return Err(crate::ResearchFailure::PoolGraphWorkCapacity.into());
                }
                let index = self.graphs.len();
                self.graphs.push(graph);
                self.keys.insert(key, index);
                index
            };
            let graph = &self.graphs[index];
            let rules = graph
                .successes
                .iter()
                .map(|i| graph.nodes[graph.candidates[*i]].kind)
                .collect::<BTreeSet<_>>();
            let pool = self
                .origins
                .entry(peer)
                .or_default()
                .entry((dependency.into(), family.into()))
                .or_default()
                .entry(proof.into())
                .or_default();
            for rule in rules {
                let cases = pool.entry(rule).or_default();
                if !cases.contains(&index) {
                    cases.push(index);
                }
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn from_graphs(graphs: &[Graph]) -> Self {
        let mut pool = Self::default();
        pool.add(false, "test", "test", "test", graphs.to_vec())
            .unwrap();
        pool
    }
    pub(super) fn target_graph(&self, graph: &Graph, rich: bool) -> Graph {
        let mut selected = graph.clone();
        if !rich && let Some(successes) = self.baseline_successes.get(&graph.key()) {
            selected.successes = successes.clone();
        }
        selected
    }
    pub fn graphs(&self) -> &[Graph] {
        &self.graphs
    }
    pub fn is_empty(&self) -> bool {
        self.graphs.is_empty()
    }
    /// Reference material shares the original pool allowance; it does not
    /// create a second memory reservation beside the training pool.
    pub(super) fn remaining(&self) -> Self {
        Self {
            work_capacity: Some(
                self.work_capacity
                    .unwrap_or(WORK_BYTES)
                    .saturating_sub(self.work_bytes),
            ),
            ..Self::default()
        }
    }
    pub fn unfocus(&mut self) {
        self.priorities.clear();
        #[cfg(test)]
        {
            self.reference = false;
        }
    }
    /// Reweight actual checked decision states. Their features, available
    /// alternatives and successful-action sets stay byte-for-byte unchanged.
    /// Unobserved alternatives remain unlabelled, not mathematical negatives.
    pub fn focus(
        &mut self,
        feedback: &crate::training::ability::Feedback,
        mut scores: impl FnMut(&Graph) -> Result<Vec<f32>, String>,
    ) -> Result<(), String> {
        #[cfg(test)]
        {
            self.reference = false;
        }
        self.priorities.clear();
        for graph in &self.graphs {
            let scores = scores(graph)?;
            if scores.len() != graph.candidates.len() || scores.iter().any(|x| !x.is_finite()) {
                return Err("preparation prediction shape or value differs".into());
            }
            let maximum = scores.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let exp = scores
                .iter()
                .map(|s| f64::from(*s - maximum).exp())
                .collect::<Vec<_>>();
            let known =
                graph.successes.iter().map(|i| exp[*i]).sum::<f64>() / exp.iter().sum::<f64>();
            let chance = graph.successes.len() as f64 / graph.candidates.len() as f64;
            let difficulty = ((1.0 - known) / (1.0 - chance).max(f64::EPSILON)).clamp(0.0, 1.0);
            let need = graph
                .successes
                .iter()
                .map(|i| feedback.rule_weight(graph.nodes[graph.candidates[*i]].kind))
                .max()
                .unwrap_or(1)
                .clamp(1, 9);
            self.priorities
                .push(1 + (difficulty * (4.0 + 3.0 * (need - 1) as f64 / 8.0)).round() as u64);
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn reference_focus(
        &mut self,
        feedback: &crate::training::ability::Feedback,
        scores: impl FnMut(&Graph) -> Result<Vec<f32>, String>,
    ) -> Result<(), String> {
        reference::focus(self, feedback, scores)
    }
    /// Origins, families, proofs and successful rule types keep the same cyclic
    /// allocation. Three complete decision cycles retain broad coverage; only
    /// the fourth uses bounded current-model priorities within that stratum.
    /// Every treatment consumes the same 16-slot schedule. Only real observed
    /// ancestry enables carry; independent graphs remain single-step windows.
    pub(super) fn sequence_batch(&self, cursor: &mut u64) -> Vec<Sample<'_>> {
        let seeds = self.batch(cursor);
        let mut result = Vec::with_capacity(16);
        while result.len() < seeds.len() {
            let slot = result.len();
            let seed = seeds[slot];
            let window = self.sequences.get(&seed.key()).and_then(|windows| {
                windows.get(cursor.wrapping_add(slot as u64) as usize % windows.len())
            });
            if let Some(window) = window {
                let first = window.len().saturating_sub(16 - slot);
                for (offset, (source, index)) in window[first..].iter().enumerate() {
                    let step = &self.derivations[*source].steps[*index];
                    let key = step.graph.key();
                    let graph = self
                        .keys
                        .get(&key)
                        .map_or(&step.graph, |index| &self.graphs[*index]);
                    result.push(Sample {
                        graph,
                        selected: step.graph.expert,
                        parent: (offset > 0).then(|| result.len() - 1),
                        auxiliary: self.auxiliary.contains(&key),
                    });
                }
            } else {
                result.push(Sample {
                    graph: seed,
                    selected: seed.expert,
                    parent: None,
                    auxiliary: self.auxiliary.contains(&seed.key()),
                });
            }
        }
        result
    }

    pub fn batch(&self, cursor: &mut u64) -> Vec<&Graph> {
        #[cfg(test)]
        if self.reference {
            return reference::batch(self, cursor);
        }
        let mut result = Vec::with_capacity(16);
        for slot in 0..16 {
            let mut position = *cursor;
            *cursor = cursor.wrapping_add(1);
            if slot == 15 && !self.repairs.is_empty() {
                let repair = (position / 16 % self.repairs.len() as u64) as usize;
                result.push(&self.graphs[self.repairs[repair]]);
                continue;
            }
            let family = select(&self.origins, &mut position);
            let proof = select(family, &mut position);
            let rules = select(proof, &mut position);
            let cases = select(rules, &mut position);
            let length = cases.len() as u64;
            let cycle = position / length;
            let index = position % length;
            let mut stride = 1 + ((cycle.wrapping_mul(0x9e3779b97f4a7c15)) % length);
            while gcd(stride, length) != 1 {
                stride = stride % length + 1;
            }
            let offset = cycle.wrapping_mul(0xbf58476d1ce4e5b9) % length;
            let mut selected = ((index.wrapping_mul(stride) + offset) % length) as usize;
            if !self.priorities.is_empty() && cycle % 4 == 3 {
                let mut random =
                    crate::sampling::Random::new((*cursor).wrapping_mul(0x9e3779b97f4a7c15));
                let mut draw = random.below(cases.iter().map(|i| self.priorities[*i]).sum());
                selected = cases
                    .iter()
                    .position(|i| {
                        if draw < self.priorities[*i] {
                            true
                        } else {
                            draw -= self.priorities[*i];
                            false
                        }
                    })
                    .expect("positive preparation weights");
            }
            result.push(&self.graphs[cases[selected]]);
        }
        result
    }
}
fn select<'a, K: Ord, V>(map: &'a BTreeMap<K, V>, position: &mut u64) -> &'a V {
    let index = *position % map.len() as u64;
    *position /= map.len() as u64;
    map.values()
        .nth(index as usize)
        .expect("nonempty proof sampling stratum")
}
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

#[cfg(test)]
mod tests;
