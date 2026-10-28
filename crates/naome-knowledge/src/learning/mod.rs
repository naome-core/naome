//! Local operational learning state; never a mathematical artifact or gossip item.
mod artifact;
mod calculus;
mod construction;
mod coverage;
mod curriculum;
pub(crate) mod definitions;
pub(crate) mod evidence;
mod graph;
pub(crate) mod history;
pub(crate) mod knowledge;
pub(crate) mod meta;
mod model;
pub(crate) mod peer;
mod pool;
pub(crate) mod program;
pub(crate) mod proof;
mod search;
mod state;
mod transfer;
pub(crate) use artifact::{ArtifactIo, Blob};
use model::Checkpoint;

/// Bind scheduling observations to the installed native input/optimizer contract.
pub(crate) fn input_specification() -> String {
    Checkpoint::fresh().specification
}
pub(crate) use model::{Engine, REQUIREMENTS as MODEL_REQUIREMENTS, TRAINING_UNITS};
use naome_authoring::CompiledQuestion;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One bounded page from the canonical question-only construction corpus.
/// The caller still applies formal admission, family exploration and its
/// checkpoint-bound ability feedback before reserving actual solver work.
pub(crate) fn research_questions(draw: u64) -> Vec<CompiledQuestion> {
    let cases = &curriculum::adaptive::BANK.learning;
    (0..12)
        .filter_map(|offset| {
            let index = (draw as usize * 11 + offset) % cases.len();
            CompiledQuestion::compile(&cases[index].source).ok()
        })
        .collect()
}
pub(crate) const PROVIDER: &str = "naome-native-proof-learning";
const REPLAY: usize = 32;
const EVALUATIONS: u32 = curriculum::DEVELOPMENT as u32 + 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Preparation {
    Balanced,
    Targeted,
    Meta,
    #[cfg(test)]
    FixedMixture,
    #[cfg(test)]
    RandomMixture,
    #[cfg(test)]
    ReferenceTargeted,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Origin {
    Local,
    Peer { artifact: String, peer: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Example {
    pub origin: Origin,
    pub job: u64,
    pub question: String,
    pub proof_id: String,
    pub refuted: bool,
    pub tree: search::Tree,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Evidence {
    pub job: u64,
    pub proof_id: String,
    pub trace: search::Tree,
}
impl Example {
    fn trajectory<'a>(&'a self, evidence: &'a [Evidence]) -> Result<&'a search::Tree, String> {
        let search::Tree::Stored {
            bytes,
            ref binding,
            ref coverage,
            ..
        } = self.tree
        else {
            return Ok(&self.tree);
        };
        let source = evidence
            .iter()
            .find(|e| e.job == self.job && e.proof_id == self.proof_id)
            .ok_or("owned replay snapshot missing")?;
        if serde_json::to_vec(&source.trace)
            .map_err(|e| e.to_string())?
            .len()
            != bytes
            || digest(&source.trace) != *binding
        {
            return Err("owned replay snapshot binding differs".into());
        }
        let restored = Self {
            tree: source.trace.clone(),
            ..self.clone()
        };
        if coverage::Profile::of(&restored)? != *coverage {
            return Err("owned replay coverage binding differs".into());
        }
        Ok(&source.trace)
    }
    pub fn evidence_job(&self) -> Option<u64> {
        matches!(self.tree, search::Tree::Stored { .. }).then_some(self.job)
    }
    pub fn matches_solution(&self, solution: &Solution) -> bool {
        if let search::Tree::Stored {
            steps,
            bytes,
            binding,
            coverage,
        } = &self.tree
        {
            let Ok(q) = CompiledQuestion::compile(&self.question) else {
                return false;
            };
            let target = if self.refuted {
                q.refuted_target()
            } else {
                q.proved_target()
            };
            let reconstructed = Self {
                tree: solution.tree.clone(),
                ..self.clone()
            };
            return solution.proof_id == self.proof_id
                && solution.refuted == self.refuted
                && coverage::Profile::of(&reconstructed).is_ok_and(|actual| actual == *coverage)
                && *binding == digest(&solution.tree)
                && serde_json::to_vec(&solution.tree).is_ok_and(|b| b.len() == *bytes)
                && state::proof_steps(target, &solution.tree).is_ok_and(|n| n == *steps);
        }
        solution.proof_id == self.proof_id
            && solution.refuted == self.refuted
            && digest(&self.tree) == digest(&solution.tree)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    model: Checkpoint,
    definitions: Vec<definitions::Entry>,
    definition_uses: BTreeMap<String, u64>,
    knowledge: Vec<knowledge::Entry>,
    replay: Vec<Example>,
    anchors: Vec<Example>,
    accepted: u64,
    epoch: u64,
    draws: u64,
    trained: u64,
    attempted: u64,
    pub peer_cursor: u64,
    history_cursor: Option<String>,
    local_examples: u64,
    peer_examples: u64,
    promotions: u64,
    rejections: u64,
    feedback: crate::training::ability::Feedback,
    preparation: Preparation,
    meta: meta::State,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Progress {
    prepared: Option<history::Prepared>,
    pub cost: Option<GenerationCost>,
    pub training_cost: model::TrainingCost,
    pub unit: u32,
    model: Checkpoint,
    trained: u64,
    promotions: u64,
    rejections: u64,
    candidate: Option<Checkpoint>,
    rng: u64,
    first_loss: Option<f32>,
    last_loss: Option<f32>,
    incumbent_score: u32,
    candidate_score: u32,
    anchor_regression: bool,
    development_regression: bool,
    original_score: [u32; 2],
    transfer: transfer::Summary,
    development_before: crate::training::ability::Profile,
    development_after: crate::training::ability::Profile,
    regressions: [u16; crate::training::ability::SKILLS],
    gains: [u16; crate::training::ability::SKILLS],
    pub plan: Option<meta::Selection>,
    pub meta_update: Option<meta::Update>,
    pub cpu_micros: u64,
    pub wall_micros: u64,
    pub meta_cpu_micros: u64,
    pub meta_wall_micros: u64,
    pub result: Option<Solution>,
    pub diagnostic: String,
}
impl Progress {
    fn observe_qualification(
        &mut self,
        source: &str,
        candidate: &Checkpoint,
        result: &transfer::Evaluation,
    ) -> Result<(), String> {
        let target = CompiledQuestion::compile(source).map_err(|e| e.to_string())?;
        self.development_before.observe(
            &target,
            32,
            crate::training::ability::completion(result.before.solved, &result.before.diagnostic),
            result.before.micros,
        );
        self.development_after.checkpoint = digest(candidate);
        self.development_after.observe(
            &target,
            32,
            crate::training::ability::completion(result.after.solved, &result.after.diagnostic),
            result.after.micros,
        );
        let (skills, _) = crate::training::ability::signature(&target);
        for (skill, present) in skills.into_iter().enumerate() {
            if present {
                self.regressions[skill] += u16::from(result.before.solved && !result.after.solved);
                self.gains[skill] += u16::from(!result.before.solved && result.after.solved);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job {
    pub history_request: Option<history::Request>,
    pub history: Option<history::Receipt>,
    pub evidence: Vec<Evidence>,
    pub training: bool,
    pub base_hash: String,
    pub base: State,
    pub progress: Option<Progress>,
    pub written: Vec<(u32, Blob)>,
    pub io_bytes: usize,
    pub io_operations: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationCost {
    pub search_expansions: usize,
    pub checker_calls: u64,
    pub submitted_checker_steps: u64,
    pub retrieved_lemmas: usize,
    pub retrieval_micros: u64,
    pub dependency_check_steps: usize,
    pub original_steps: usize,
    pub useful_steps: usize,
    pub unique_states: usize,
    pub core_work: usize,
    pub generation_micros: u64,
    pub definition_candidates: usize,
    pub definition_references: usize,
    pub definition_check_steps: usize,
    pub definition_micros: u64,
    pub definition_failure: Option<String>,
    pub certificate_failures: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Solution {
    pub cost: Box<GenerationCost>,
    pub source: String,
    pub helpers: Vec<String>,
    pub proof_id: String,
    pub refuted: bool,
    pub tree: search::Tree,
}
impl Solution {
    pub fn checked(&self) -> Result<naome_authoring::CompiledProof, String> {
        if self.helpers != definitions::helpers(&self.tree)? {
            return Err("definition helper source binding differs".into());
        }
        let context = definitions::proof_context(&self.tree)?;
        let proof = naome_authoring::compile_against_proof_context(&self.source, &context)
            .map_err(|e| e.to_string())?;
        if crate::hex(proof.proof_id().as_bytes()) != self.proof_id {
            return Err("native source identity differs".into());
        }
        Ok(proof)
    }
}
pub(crate) fn digest(value: &impl Serialize) -> String {
    use sha2::{Digest, Sha256};
    crate::hex(&Sha256::digest(
        serde_json::to_vec(value).expect("finite typed learning state"),
    ))
}
impl Job {
    /// Bind worker reports to the plan and candidate already retained by this
    /// job owner. Re-delivery of a persisted unit is exactly idempotent.
    pub fn retain_progress(&mut self, job: u64, next: Progress) -> Result<(), String> {
        if next
            .meta_update
            .as_ref()
            .is_some_and(|u| u.experience.job != job)
        {
            return Err("meta experience source job differs".into());
        }
        if let Some(previous) = &self.progress {
            if next.unit == previous.unit {
                return if digest(&next) == digest(previous) {
                    Ok(())
                } else {
                    Err("repeated learning checkpoint differs".into())
                };
            }
            if next.unit != previous.unit + 1
                || next.plan != previous.plan
                || next.prepared != previous.prepared
                || next.cpu_micros < previous.cpu_micros
                || next.wall_micros < previous.wall_micros
                || next.meta_cpu_micros < previous.meta_cpu_micros
                || next.meta_wall_micros < previous.meta_wall_micros
                || previous.transfer.observed & next.transfer.observed != previous.transfer.observed
                || (previous.transfer.before ^ next.transfer.before) & previous.transfer.observed
                    != 0
                || (previous.transfer.after ^ next.transfer.after) & previous.transfer.observed != 0
            {
                return Err("learning plan or measured continuation differs".into());
            }
            if let Some(update) = &next.meta_update
                && (update.experience.candidate_model != previous.candidate.as_ref().map(digest)
                    || update.experience.lower_cpu_micros
                        != previous.cpu_micros.saturating_sub(previous.meta_cpu_micros)
                    || update.experience.lower_wall_micros
                        != previous
                            .wall_micros
                            .saturating_sub(previous.meta_wall_micros))
            {
                return Err("meta outcome differs from its retained trial".into());
            }
        } else if next.unit != 1 {
            return Err("learning checkpoint lacks its first unit".into());
        }
        let previous = self.progress.replace(next);
        if let Err(error) = self.validate() {
            self.progress = previous;
            return Err(error);
        }
        Ok(())
    }
    pub fn blobs(&self) -> Vec<&Blob> {
        let mut blobs: Vec<_> = self.base.blobs().collect();
        if let Some(history) = &self.history {
            blobs.push(&history.blob);
        }
        if let Some(p) = &self.progress {
            if let Some(prepared) = &p.prepared {
                blobs.push(&prepared.blob);
            }
            blobs.extend(p.model.blobs());
            if let Some(candidate) = &p.candidate {
                blobs.extend(candidate.blobs());
            }
            if let Some(update) = &p.meta_update {
                blobs.extend(update.model.blobs());
            }
        }
        blobs
    }
    pub fn allows_read(&self, blob: &Blob) -> bool {
        self.blobs().into_iter().any(|b| b == blob)
    }
    pub fn units(&self) -> u32 {
        if self.training && self.base.epoch > self.base.trained {
            model::TRAINING_UNITS + EVALUATIONS + 1
        } else {
            1
        }
    }
    pub fn validate_generated_trace(&self) -> Result<(), String> {
        fn generated(tree: &search::Tree) -> bool {
            match tree {
                search::Tree::Certificate(_)
                | search::Tree::Stored { .. }
                | search::Tree::Constructed {
                    selection: None, ..
                } => false,
                search::Tree::Knowledge { proof, .. } | search::Tree::Definitions { proof, .. } => {
                    generated(proof)
                }
                search::Tree::Step { children, .. } => children.iter().all(generated),
                _ => true,
            }
        }
        if self
            .progress
            .as_ref()
            .and_then(|p| p.result.as_ref())
            .is_some_and(|s| !generated(&s.tree))
        {
            return Err("local discovery lacks its generated decision trace".into());
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), String> {
        if digest(&self.base) != self.base_hash {
            return Err("learning parent snapshot differs".into());
        }
        self.base.validate()?;
        if let Some(request) = &self.history_request {
            request.validate()?;
            if !self.training || request.after != self.base.history_cursor {
                return Err("history request differs from its training parent".into());
            }
            if let Some(receipt) = &self.history {
                receipt.validate(request)?;
            }
        } else if self.history.is_some() {
            return Err("history receipt lacks its original request".into());
        }
        let mut expected = if self.training {
            self.base
                .training_sources()
                .filter_map(Example::evidence_job)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        expected.sort_unstable();
        expected.dedup();
        let actual = self.evidence.iter().map(|e| e.job).collect::<Vec<_>>();
        if expected != actual
            || serde_json::to_vec(&self.evidence)
                .map_err(|e| e.to_string())?
                .len()
                > REPLAY * 8 * 1024 + 4096
            || self.evidence.iter().any(|e| {
                !self.base.examples().any(|r| {
                    r.job == e.job
                        && r.proof_id == e.proof_id
                        && matches!(&r.tree,
                        search::Tree::Stored { bytes, binding, .. } if
                        serde_json::to_vec(&e.trace).is_ok_and(|b| b.len() == *bytes)
                        && digest(&e.trace) == *binding)
                })
            })
        {
            return Err("peer replay snapshot binding differs".into());
        }

        if self.written.len() > 2 * (model::TRAINING_UNITS as usize + 2)
            || self.io_bytes > crate::resources::limits().native_model_io_bytes
            || self.io_operations
                > crate::resources::limits().native_model_io_bytes
                    / crate::resources::limits().native_model_chunk_bytes
                    * 2
        {
            return Err("native artifact lifetime allowance".into());
        }
        for (unit, blob) in &self.written {
            if *unit == 0 || *unit > self.units() {
                return Err("native artifact reservation differs".into());
            }
            blob.validate()?;
        }
        if let Some(p) = &self.progress {
            if let Some(prepared) = &p.prepared {
                prepared.blob.validate()?;
                if self.units() == 1
                    || Some(&prepared.page) != self.history.as_ref()
                    || prepared.blob.bytes > history::PAGE_BYTES + 32 * 1024 + 8192
                    || prepared.available > history::SOURCES
                    || prepared.retained > prepared.available
                {
                    return Err("prepared replay lacks its original history receipt".into());
                }
            } else if self.history_request.is_some() && self.units() > 1 {
                return Err("training progress lacks its frozen replay preparation".into());
            }
            if let Some(selection) = &p.plan {
                selection.validate()?;
                if selection.context
                    != p.prepared
                        .as_ref()
                        .map_or_else(|| meta::context(&self.base), |r| r.context)
                {
                    return Err("meta plan context differs from its parent".into());
                }
            } else if self.units() > 1 && self.base.preparation == Preparation::Meta {
                return Err("native meta trial lacks its selected plan".into());
            }
            if p.meta_cpu_micros > p.cpu_micros || p.meta_wall_micros > p.wall_micros {
                return Err("meta cost exceeds actual job cost".into());
            }
            if let Some(update) = &p.meta_update {
                update.model.validate()?;
                update.experience.validate()?;
                let selected = p.plan.as_ref().ok_or("meta update without selected plan")?;
                if self.units() == 1
                    || p.unit != self.units()
                    || self.base.preparation != Preparation::Meta
                    || update.model.updates
                        != self.base.meta.model.updates.saturating_add(meta::UPDATES)
                    || update.experience.context != selected.context
                    || update.experience.plan != selected.plan
                    || update.experience.source_model != digest(&self.base.model)
                    || update.experience.selected_model != digest(&p.model)
                    || update.experience.source_epoch != self.base.epoch
                    || update.experience.job == 0
                    || u32::from(update.experience.before) != p.incumbent_score
                    || u32::from(update.experience.after) != p.candidate_score
                    || update.experience.protected_loss != p.development_regression
                    || update.experience.anchor_loss != p.anchor_regression
                    || update.experience.transfer != p.transfer
                    || update.experience.lower_cpu_micros > p.cpu_micros
                    || update.experience.lower_wall_micros > p.wall_micros
                    || !update.first_loss.is_finite()
                    || !update.last_loss.is_finite()
                {
                    return Err(
                        "meta experience or optimizer is not bound to the actual completed trial"
                            .into(),
                    );
                }
            } else if self.units() > 1
                && p.unit == self.units()
                && self.base.preparation == Preparation::Meta
            {
                return Err("completed meta trial lacks its real update".into());
            }
            if serde_json::to_vec(p)
                .map_err(|e| e.to_string())?
                .len()
                .checked_mul(self.units() as usize)
                .is_none_or(|bytes| bytes > crate::resources::limits().provider_stream_bytes / 2)
            {
                return Err("local checkpoints exceed original provider stream capacity".into());
            }

            p.model.validate()?;
            if p.promotions > self.base.promotions
                && (p.candidate_score <= p.incumbent_score
                    || p.anchor_regression
                    || p.development_regression
                    || !p.transfer.accepts())
            {
                return Err("retained promotion lacks complete protected transfer gain".into());
            }
            p.transfer.validate()?;
            let expected_transfer = transfer::Summary::prefix(
                p.unit
                    .saturating_sub(model::TRAINING_UNITS)
                    .min(transfer::CASES as u32) as usize,
            );
            if p.first_loss.is_some() && p.transfer.observed != expected_transfer {
                return Err("transfer coverage differs from the retained unit".into());
            }
            p.development_before.validate()?;
            p.development_after.validate()?;
            if p.development_before.checkpoint != digest(&self.base.model) {
                return Err("development observations differ from their incumbent".into());
            }
            if let Some(solution) = &p.result {
                let checked = solution.checked()?.into_checked_proof();
                knowledge::validate_availability(
                    checked.conclusion(),
                    &solution.tree,
                    &self.base.knowledge,
                    &self.base.definitions,
                )?;
            }
            if p.unit < self.units()
                && (p.model != self.base.model
                    || p.promotions != self.base.promotions
                    || p.rejections != self.base.rejections)
                || p.unit == self.units()
                    && p.promotions == self.base.promotions
                    && p.model != self.base.model
            {
                return Err("native model changed before successful qualification".into());
            }
            if p.rng < self.base.draws
                || p.rng.saturating_sub(self.base.draws)
                    > u64::from(model::TRAINING_UNITS) * model::UPDATES_PER_UNIT * 16
            {
                return Err("native sampling continuation differs".into());
            }
            if p.promotions < self.base.promotions
                || p.promotions > self.base.promotions.saturating_add(1)
                || p.rejections < self.base.rejections
                || p.rejections > self.base.rejections.saturating_add(1)
                || p.trained < self.base.trained
                || p.trained > self.base.epoch
            {
                return Err("native qualification sequence differs".into());
            }
            if p.unit == 0 || p.unit > self.units() {
                return Err("learning checkpoint unit differs".into());
            }
            if let Some(candidate) = &p.candidate {
                candidate.validate()?;
            }
        }
        Ok(())
    }
    pub fn execute<I: ArtifactIo + ?Sized>(
        &mut self,
        unit: u32,
        question: Option<&str>,
        job: u64,
        engine: &mut Engine,
        io: &mut I,
    ) -> Result<(), String> {
        if self.progress.as_ref().is_some_and(|p| p.unit == unit) {
            return Ok(());
        }
        if unit != self.progress.as_ref().map_or(1, |p| p.unit + 1) {
            return Err("learning checkpoint sequence differs".into());
        }
        let wall_started = std::time::Instant::now();
        let cpu_started = meta::cpu_micros()?;
        let mut p = self.progress.clone().unwrap_or(Progress {
            prepared: None,
            cost: None,
            training_cost: model::TrainingCost::default(),
            unit: 0,
            model: self.base.model.clone(),
            trained: self.base.trained,
            promotions: self.base.promotions,
            rejections: self.base.rejections,
            candidate: None,
            rng: self.base.draws,
            first_loss: None,
            last_loss: None,
            incumbent_score: 0,
            candidate_score: 0,
            anchor_regression: false,
            development_regression: false,
            original_score: [0, 0],
            transfer: transfer::Summary::default(),
            development_before: crate::training::ability::Profile::new(digest(&self.base.model)),
            development_after: crate::training::ability::Profile::new(digest(&self.base.model)),
            regressions: [0; crate::training::ability::SKILLS],
            gains: [0; crate::training::ability::SKILLS],
            plan: None,
            meta_update: None,
            cpu_micros: 0,
            wall_micros: 0,
            meta_cpu_micros: 0,
            meta_wall_micros: 0,
            result: None,
            diagnostic: "no_new_accepted_solutions".into(),
        });
        let working = if self.units() > 1 && unit <= model::TRAINING_UNITS {
            self.prepare_history(&mut p, engine, io)?
        } else {
            None
        };
        let (training_state, training_evidence) = working.as_ref().map_or(
            (&self.base, self.evidence.as_slice()),
            |(state, evidence)| (state, evidence.as_slice()),
        );
        if self.units() > 1 && unit == 1 {
            let wall = std::time::Instant::now();
            let cpu = meta::cpu_micros()?;
            let selection = engine.meta.select(training_state, io)?;
            p.plan = Some(selection);
            p.meta_cpu_micros += meta::cpu_micros()?.saturating_sub(cpu);
            p.meta_wall_micros += wall.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        }
        if self.units() > 1 && unit <= model::TRAINING_UNITS {
            let parent = p.candidate.as_ref().unwrap_or(&self.base.model);
            let phase = p
                .plan
                .as_ref()
                .ok_or("training plan absent")?
                .plan
                .phase(unit - 1);
            if let Some((candidate, first, last)) = engine.train_replay_using(
                parent,
                training_state,
                training_evidence,
                &mut p.rng,
                phase,
                io,
            )? {
                p.training_cost.preparation_micros = p
                    .training_cost
                    .preparation_micros
                    .saturating_add(engine.cost.preparation_micros);
                p.training_cost.replay_micros = p
                    .training_cost
                    .replay_micros
                    .saturating_add(engine.cost.replay_micros);
                p.training_cost.load_micros = p
                    .training_cost
                    .load_micros
                    .saturating_add(engine.cost.load_micros);
                p.training_cost.update_micros = p
                    .training_cost
                    .update_micros
                    .saturating_add(engine.cost.update_micros);
                p.training_cost.preservation_micros = p
                    .training_cost
                    .preservation_micros
                    .saturating_add(engine.cost.preservation_micros);
                p.training_cost.preservation_states = engine.cost.preservation_states;
                p.training_cost.checkpoint_micros = p
                    .training_cost
                    .checkpoint_micros
                    .saturating_add(engine.cost.checkpoint_micros);
                p.training_cost.states = engine.cost.states;
                p.first_loss.get_or_insert(first);
                p.last_loss = Some(last);
                p.candidate = Some(candidate);
                p.diagnostic = if p.last_loss < p.first_loss {
                    "candidate_requires_qualification"
                } else {
                    "optimization_or_representation_unresolved"
                }
                .into();
            } else {
                p.diagnostic = "no_ambiguous_training_decisions".into();
            }
            if unit == model::TRAINING_UNITS {
                p.trained = self.base.epoch;
            }
        } else if self.units() > 1 && unit <= model::TRAINING_UNITS + EVALUATIONS {
            if let Some(candidate) = p.candidate.clone() {
                let index = (unit - model::TRAINING_UNITS - 1) as usize;
                let source = if index < curriculum::DEVELOPMENT {
                    curriculum::development()
                        .get(index)
                        .map(|q| q.source.clone())
                } else {
                    self.base
                        .anchors
                        .get(index - curriculum::DEVELOPMENT)
                        .map(|e| e.question.clone())
                };
                if let Some(source) = source {
                    let result =
                        transfer::evaluate(&source, &self.base, &candidate, engine, io, job)?;
                    let (before, after) = (result.before.solved, result.after.solved);
                    if index < curriculum::DEVELOPMENT {
                        p.observe_qualification(&source, &candidate, &result)?;
                        p.incumbent_score += u32::from(before);
                        p.candidate_score += u32::from(after);
                        if index < curriculum::CORPUS_DEVELOPMENT {
                            p.original_score[0] += u32::from(before);
                            p.original_score[1] += u32::from(after);
                            p.development_regression |= before && !after;
                        }
                    } else if before && !after {
                        p.anchor_regression = true;
                    }
                }
                if let Some(case) = curriculum::adaptive::BANK.transfer.get(index) {
                    let result =
                        transfer::evaluate(&case.source, &self.base, &candidate, engine, io, job)?;
                    p.transfer
                        .record(index, result.before.solved, result.after.solved)?;
                    p.observe_qualification(&case.source, &candidate, &result)?;
                }
            }
        } else {
            let candidate_model = p.candidate.as_ref().map(digest);
            if let Some(candidate) = p.candidate.take() {
                if p.candidate_score > p.incumbent_score
                    && !p.anchor_regression
                    && !p.development_regression
                    && p.transfer.accepts()
                {
                    p.model = candidate;
                    p.promotions += 1;
                    p.diagnostic = "candidate_promoted".into();
                } else {
                    p.rejections += 1;
                    p.diagnostic = if p.development_regression {
                        "development_regression_rejected"
                    } else if p.anchor_regression {
                        "forgetting_rejected"
                    } else if p.candidate_score <= p.incumbent_score {
                        "no_development_gain_rejected"
                    } else if !p.transfer.complete() {
                        "incomplete_transfer_rejected"
                    } else if p.transfer.loss() > 0. {
                        "transfer_regression_rejected"
                    } else {
                        "no_transfer_gain_rejected"
                    }
                    .into();
                }
            }
            if self.units() > 1 && self.base.preparation == Preparation::Meta {
                let selection = p.plan.as_ref().ok_or("meta trial plan absent")?;
                let experience = meta::Experience {
                    job,
                    context: selection.context,
                    plan: selection.plan.clone(),
                    source_model: digest(&self.base.model),
                    selected_model: digest(&p.model),
                    candidate_model,
                    source_epoch: self.base.epoch,
                    before: p.incumbent_score as u16,
                    after: p.candidate_score as u16,
                    protected_loss: p.development_regression,
                    anchor_loss: p.anchor_regression,
                    transfer: p.transfer,
                    lower_cpu_micros: p.cpu_micros.saturating_sub(p.meta_cpu_micros),
                    lower_wall_micros: p.wall_micros.saturating_sub(p.meta_wall_micros),
                };
                let wall = std::time::Instant::now();
                let cpu = meta::cpu_micros()?;
                let update = engine
                    .meta
                    .learn(&self.base, experience, selection.draw, io)?;
                p.meta_update = Some(update);
                p.meta_cpu_micros += meta::cpu_micros()?.saturating_sub(cpu);
                p.meta_wall_micros += wall.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            }
            if let Some(question) = question {
                let q = CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
                if curriculum::reserved(&crate::hex(q.resolution_id())) {
                    p.diagnostic = "reserved_question_excluded".into();
                } else {
                    let budget = if p.rejections % 3 == 2 { 256 } else { 128 };
                    let (solution, failure, cost) = engine.with(&p.model, io, |runtime| {
                        solve_with_definitions(
                            question,
                            runtime,
                            budget,
                            job,
                            &self.base.definitions,
                            &self.base.knowledge,
                        )
                    })?;
                    p.cost = Some(cost);
                    if solution.is_none() {
                        p.diagnostic = failure;
                    }
                    p.result = solution;
                }
            }
        }
        if unit == 1
            && io.external_history_cpu()
            && let Some(receipt) = &self.history
        {
            p.cpu_micros = p.cpu_micros.saturating_add(receipt.read_cpu_micros);
        }
        p.cpu_micros = p
            .cpu_micros
            .saturating_add(meta::cpu_micros()?.saturating_sub(cpu_started));
        p.wall_micros = p
            .wall_micros
            .saturating_add(wall_started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
        p.unit = unit;
        self.progress = Some(p);
        Ok(())
    }
}
struct Exploring<'a> {
    model: &'a mut model::Runtime,
    seed: u64,
    explore: bool,
}
impl model::Ranker for Exploring<'_> {
    fn scores(&mut self, d: &model::Decision) -> Result<Vec<f32>, String> {
        let mut scores = self.model.scores(d)?;
        if self.explore && model::random(&mut self.seed).is_multiple_of(5) {
            for s in &mut scores {
                *s = (model::random(&mut self.seed) >> 11) as f32 / 9007199254740992.;
            }
        }
        Ok(scores)
    }
}
fn solve_with_definitions(
    source: &str,
    model: &mut model::Runtime,
    budget: usize,
    job: u64,
    known: &[definitions::Entry],
    theorems: &[knowledge::Entry],
) -> Result<(Option<Solution>, String, GenerationCost), String> {
    let checking = proof::checking_work();
    let started = std::time::Instant::now();
    let mut ranker = Exploring {
        model,
        seed: job.max(1),
        explore: budget >= 128,
    };
    let (mut solution, diagnostic, mut cost) =
        search_question_with_knowledge(source, &mut ranker, budget, theorems, known)?;
    if let Some(solution) = &mut solution {
        if matches!(solution.tree, search::Tree::Constructed { .. }) {
            return Ok((Some(solution.clone()), diagnostic, cost));
        }
        let definition_started = std::time::Instant::now();
        let question = CompiledQuestion::compile(source).map_err(|e| e.to_string())?;
        let target = if solution.refuted {
            question.refuted_target()
        } else {
            question.proved_target()
        };
        if let Some((entries, selected)) = definitions::choose(target, known, model)? {
            cost.definition_candidates = entries.len();
            let available = entries
                .iter()
                .take_while(|entry| known.contains(entry))
                .count();
            let tree = search::Tree::Definitions {
                entries,
                selected,
                available,
                proof: Box::new(solution.tree.clone()),
            };
            match search::core::checked(target, &tree) {
                Ok((tree, _, checked)) => {
                    cost.definition_check_steps = checked.certificate.steps().len();
                    let source = proof::source(&checked)?;
                    let helpers = definitions::helpers(&tree)?;
                    if source.len() + helpers.iter().map(String::len).sum::<usize>()
                        <= crate::resources::limits().closure_bytes
                        && source.len() <= crate::resources::limits().proof_bytes
                        && checked.payload_bytes <= crate::resources::limits().proof_bytes
                        && helpers
                            .iter()
                            .all(|source| source.len() <= crate::resources::limits().proof_bytes)
                    {
                        solution.source = source;
                        solution.helpers = helpers;
                        solution.proof_id = crate::hex(checked.native_id.as_bytes());
                        solution.tree = tree;
                        cost.definition_references = checked
                            .certificate
                            .steps()
                            .iter()
                            .map(|s| s.definition_references().len())
                            .sum();
                    } else {
                        cost.definition_failure =
                            Some("definition certificate or helper capacity".into());
                    }
                }
                Err(error) => cost.definition_failure = Some(error),
            }
        }
        cost.definition_micros = definition_started
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        cost.generation_micros = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let work = proof::checking_work();
        cost.checker_calls = work.calls.saturating_sub(checking.calls);
        cost.submitted_checker_steps = work.steps.saturating_sub(checking.steps);
        *solution.cost = cost.clone();
    }
    Ok((solution, diagnostic, cost))
}
#[cfg(test)]
fn search_question(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
) -> Result<(Option<Solution>, String), String> {
    let (solution, diagnostic, _) = search_question_measured(source, ranker, budget)?;
    Ok((solution, diagnostic))
}
#[cfg(test)]
fn search_question_measured(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
) -> Result<(Option<Solution>, String, GenerationCost), String> {
    search_question_with_knowledge(source, ranker, budget, &[], &[])
}
fn search_question_with_knowledge(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
    theorems: &[knowledge::Entry],
    definitions: &[definitions::Entry],
) -> Result<(Option<Solution>, String, GenerationCost), String> {
    let checking = proof::checking_work();
    let started = std::time::Instant::now();
    let q = CompiledQuestion::compile(source).map_err(|e| e.to_string())?;
    let mut retrieval_micros = 0;
    let mut retrieved = 0;
    let mut dependency_steps = 0;
    let mut failure = "calculus_or_strategy_unresolved".to_owned();
    let mut remaining = budget;
    let mut certificate_failures = 0;
    for refuted in [false, true] {
        if remaining == 0 {
            break;
        }
        let target = if refuted {
            q.refuted_target().clone()
        } else {
            q.proved_target().clone()
        };
        let orientation_started = std::time::Instant::now();
        let retrieval_started = std::time::Instant::now();
        let selected = knowledge::retrieve(&target, theorems)?;
        retrieved += selected.len();
        dependency_steps += selected
            .iter()
            .map(|e| evidence::steps(&e.packet))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<usize>();
        retrieval_micros += retrieval_started
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        let (constructed, work, selection) = match construction::construct_with(
            &target,
            remaining,
            orientation_started,
            ranker,
            &selected,
            definitions,
        ) {
            Ok(result) => result,
            Err(error) => {
                certificate_failures += 1;
                remaining = 0;
                failure = format!("construction_unresolved: {error}");
                break;
            }
        };
        remaining = remaining.saturating_sub(work);
        let found = if let Some(verified) = constructed {
            search::ResultTree {
                tree: Some(search::Tree::Constructed {
                    packet: match evidence::pack(&verified) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            certificate_failures += 1;
                            failure = format!("construction_capacity: {error}");
                            continue;
                        }
                    },
                    selection,
                }),
                expansions: 0,
                failure: None,
            }
        } else {
            search::solve_with_knowledge(
                &target,
                ranker,
                remaining,
                orientation_started,
                &selected,
            )?
        };
        remaining = remaining.saturating_sub(found.expansions);
        if let Some(tree) = found.tree {
            let (tree, cost, verified) = match search::core::checked(&target, &tree) {
                Ok(checked) => checked,
                Err(error) => {
                    certificate_failures += 1;
                    failure = format!("certificate_unresolved: {error}");
                    continue;
                }
            };
            match Ok::<_, String>(verified).and_then(|verified| {
                Ok((
                    proof::source(&verified)?,
                    crate::hex(verified.native_id.as_bytes()),
                    verified.payload_bytes,
                    verified
                        .certificate
                        .steps()
                        .iter()
                        .chain(verified.lemmas.iter().flat_map(|c| c.steps().iter()))
                        .map(|step| step.definition_references().len())
                        .sum::<usize>(),
                    verified.certificate.steps().len()
                        + verified
                            .lemmas
                            .iter()
                            .map(|c| c.steps().len())
                            .sum::<usize>()
                        + verified.definitions.len(),
                ))
            }) {
                Ok((source, proof_id, payload_bytes, references, check_steps))
                    if source.len() <= crate::resources::limits().proof_bytes
                        && payload_bytes
                            <= crate::resources::limits()
                                .proof_bytes
                                .min(crate::resources::limits().closure_bytes) =>
                {
                    let helpers = definitions::helpers(&tree)?;
                    if helpers.len() >= crate::resources::limits().closure_objects
                        || helpers
                            .iter()
                            .any(|s| s.len() > crate::resources::limits().proof_bytes)
                        || source.len() + helpers.iter().map(String::len).sum::<usize>()
                            > crate::resources::limits().closure_bytes
                    {
                        failure = "certificate_closure_capacity".into();
                        continue;
                    }
                    let unique_states = search::compile(&target, &tree)?
                        .1
                        .iter()
                        .map(graph::Graph::key)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len();
                    let work = proof::checking_work();
                    let measured = GenerationCost {
                        checker_calls: work.calls.saturating_sub(checking.calls),
                        submitted_checker_steps: work.steps.saturating_sub(checking.steps),
                        retrieved_lemmas: retrieved,
                        retrieval_micros,
                        dependency_check_steps: dependency_steps,
                        definition_candidates: definitions::selected(&tree)?.len(),
                        definition_references: references,
                        definition_check_steps: if references > 0 { check_steps } else { 0 },
                        certificate_failures,
                        search_expansions: budget - remaining,
                        original_steps: cost.original_steps,
                        useful_steps: cost.useful_steps,
                        core_work: cost.replay_work,
                        unique_states,
                        generation_micros: started.elapsed().as_micros().min(u128::from(u64::MAX))
                            as u64,
                        ..GenerationCost::default()
                    };
                    return Ok((
                        Some(Solution {
                            helpers,
                            cost: Box::new(measured.clone()),
                            source,
                            proof_id,
                            refuted,
                            tree,
                        }),
                        "certified_candidate".into(),
                        measured,
                    ));
                }
                Ok(_) => failure = "certificate_capacity".into(),
                Err(error) => failure = format!("certificate_unresolved: {error}"),
            }
        } else if let Some(reason) = found.failure {
            failure = reason;
        }
    }
    Ok((
        None,
        failure,
        GenerationCost {
            checker_calls: proof::checking_work().calls.saturating_sub(checking.calls),
            submitted_checker_steps: proof::checking_work().steps.saturating_sub(checking.steps),
            retrieved_lemmas: retrieved,
            retrieval_micros,
            dependency_check_steps: dependency_steps,
            certificate_failures,
            search_expansions: budget - remaining,
            generation_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            ..GenerationCost::default()
        },
    ))
}

#[cfg(test)]
mod experiment;
#[cfg(test)]
pub(crate) mod tests;
