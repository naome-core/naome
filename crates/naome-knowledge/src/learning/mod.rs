//! Local operational learning state; never a mathematical artifact or gossip item.
use crate::outcome::{GenerationOutcome, Qualification};
mod artifact;
mod calculus;
mod construction;
pub(crate) use construction::logic::conjunction as conjunction_operands;
mod coverage;
mod curriculum;
pub(crate) mod definitions;
pub(crate) mod evidence;
pub(crate) mod experience;
pub(crate) mod finder;
mod graph;
pub(crate) mod history;
pub(crate) mod knowledge;
pub(crate) mod meta;
mod model;
pub(crate) mod peer;
mod pool;
mod prerequisites;
pub(crate) use prerequisites::Prerequisites;
pub(crate) mod program;
pub(crate) mod proof;
mod search;
pub(crate) use search::frontier::Frontier as SearchFrontier;
pub(crate) use search::trace::Trace as SearchTrace;
mod state;
mod transfer;
pub(crate) use artifact::{ArtifactIo, Blob};
use model::Checkpoint;

/// Bind scheduling observations to the installed native input/optimizer contract.
pub(crate) fn input_specification() -> String {
    Checkpoint::fresh().specification
}
pub(crate) use model::{Engine, REQUIREMENTS as MODEL_REQUIREMENTS, TRAINING_UNITS};
use naome_checker::question::ResearchQuestion;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    fn trajectory<'a>(
        &'a self,
        evidence: &'a [Evidence],
    ) -> Result<&'a search::Tree, crate::Error> {
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
            .ok_or(crate::ResearchFailure::ReplaySnapshotMissing)?;
        if crate::checkpoint::encode(&source.trace)?.len() != bytes
            || digest(&source.trace) != *binding
        {
            return Err(crate::ResearchFailure::ReplaySnapshotBinding.into());
        }
        let restored = Self {
            tree: source.trace.clone(),
            ..self.clone()
        };
        if coverage::Profile::of(&restored)? != *coverage {
            return Err(crate::ResearchFailure::ReplayCoverageBinding.into());
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
            let Ok(q) = ResearchQuestion::from_hex(&self.question) else {
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
    history_cursor: history::Cursor,
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
    pub finder: Option<finder::Utility>,
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
    pub qualification: Qualification,
    pub generation: Option<GenerationOutcome>,
    pub frontier: Option<SearchFrontier>,
    pub executions: Vec<SearchTrace>,
    pub terminal: experience::TerminalEvidence,
}
impl Progress {
    fn observe_qualification(
        &mut self,
        source: &str,
        candidate: &Checkpoint,
        result: &transfer::Evaluation,
    ) -> Result<(), crate::Error> {
        let target = ResearchQuestion::from_hex(source)?;
        self.development_before.observe(
            &target,
            32,
            crate::training::ability::completion(result.before.solved, &result.before.terminal),
            result.before.micros,
        );
        self.development_after.checkpoint = digest(candidate);
        self.development_after.observe(
            &target,
            32,
            crate::training::ability::completion(result.after.solved, &result.after.terminal),
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
    pub required: Vec<String>,
    pub prerequisites: Prerequisites,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_peak_rss_bytes: Option<u64>,
    pub definition_candidates: usize,
    pub definition_references: usize,
    pub definition_check_steps: usize,
    pub definition_micros: u64,
    pub(crate) definition_failure: Option<GenerationOutcome>,
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
    /// The local acceptance receipt publishes this bounded hint atomically
    /// with replay; the canonical graph remains the mathematical owner.
    pub fn theorem(
        &self,
        question: &ResearchQuestion,
    ) -> Result<Option<knowledge::Entry>, crate::Error> {
        if matches!(self.tree, search::Tree::Program(_)) {
            return Ok(None);
        }
        let target = if self.refuted {
            question.refuted_target()
        } else {
            question.proved_target()
        };
        let (_, _, verified) = search::core::checked(target, &self.tree)?;
        if crate::hex(verified.native_id.as_bytes()) != self.proof_id {
            return Err(crate::ResearchFailure::TheoremIdentityMismatch.into());
        }
        let packet = evidence::pack(&verified)?;
        Ok((packet.len() <= knowledge::BYTES).then_some(knowledge::Entry { packet }))
    }
    pub fn check_target(&self, question: &ResearchQuestion) -> Result<(), crate::Error> {
        let target = if self.refuted {
            question.refuted_target()
        } else {
            question.proved_target()
        };
        if let search::Tree::Program(packet) = &self.tree {
            if !self.source.is_empty()
                || self.proof_id != crate::hex(packet.manifest.proof_id().as_bytes())
                || &packet.target()? != target
            {
                return Err(crate::ResearchFailure::NativeProgramBinding.into());
            }
        } else if self.checked()?.conclusion() != target {
            return Err(crate::ResearchFailure::NativeCertificateConclusion.into());
        }
        Ok(())
    }

    pub fn checked(&self) -> Result<naome_checker::CheckedProof, crate::Error> {
        if self.helpers != definitions::helpers(&self.tree)? {
            return Err(crate::ResearchFailure::NativeDefinitionHelpers.into());
        }
        let context = definitions::proof_context(&self.tree)?;
        let proof = crate::learning::proof::check_artifact(&self.source, &context)?;
        if crate::hex(proof.proof_id().as_bytes()) != self.proof_id {
            return Err(crate::ResearchFailure::NativeSourceIdentity.into());
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
    pub(crate) fn model_checkpoint(&self) -> String {
        digest(
            self.progress
                .as_ref()
                .map_or(&self.base.model, |p| &p.model),
        )
    }
    fn preserves_incumbent_transfer(&self, progress: &Progress) -> bool {
        progress.promotions <= self.base.promotions || progress.transfer.accepts()
    }

    /// Bind worker reports to the plan and candidate already retained by this
    /// job owner. Re-delivery of a persisted unit is exactly idempotent.
    pub fn retain_progress(&mut self, job: u64, next: Progress) -> Result<(), crate::Error> {
        if next
            .meta_update
            .as_ref()
            .is_some_and(|u| u.experience.job != job)
        {
            return Err(crate::ResearchFailure::ProgressMetaJobBinding.into());
        }
        if let Some(previous) = &self.progress {
            if next.unit == previous.unit {
                return if digest(&next) == digest(previous) {
                    Ok(())
                } else {
                    Err(crate::ResearchFailure::ProgressRepeatedMismatch.into())
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
                return Err(crate::ResearchFailure::ProgressContinuationMismatch.into());
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
                return Err(crate::ResearchFailure::ProgressMetaTrialBinding.into());
            }
        } else if next.unit != 1 {
            return Err(crate::ResearchFailure::ProgressFirstUnit.into());
        }
        if !self.preserves_incumbent_transfer(&next) {
            return Err(crate::ResearchFailure::ProgressTransferLoss.into());
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
    pub fn validate_generated_trace(&self) -> Result<(), crate::Error> {
        fn generated(tree: &search::Tree) -> Result<(), crate::Error> {
            match tree {
                search::Tree::Composed {
                    packet,
                    inputs,
                    work,
                    ..
                } => construction::composition::validate(packet, inputs, *work),
                search::Tree::Certificate(_)
                | search::Tree::Stored { .. }
                | search::Tree::Constructed {
                    selection: None, ..
                } => Err(crate::ResearchFailure::GeneratedTraceMissing.into()),
                search::Tree::Knowledge { proof, .. } | search::Tree::Definitions { proof, .. } => {
                    generated(proof)
                }
                search::Tree::Step { children, .. } => {
                    for child in children {
                        generated(child)?;
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }
        if let Some(solution) = self.progress.as_ref().and_then(|p| p.result.as_ref()) {
            generated(&solution.tree)?;
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), crate::Error> {
        if digest(&self.base) != self.base_hash {
            return Err(crate::ResearchFailure::JobParentSnapshot.into());
        }
        self.base.validate()?;
        if !self.prerequisites.is_empty()
            && (self.training
                || self.required.is_empty() && !self.prerequisites.has_optional_context())
        {
            return Err(crate::ResearchFailure::JobPrerequisiteRole.into());
        }
        if self.required.len() > knowledge::CAPACITY
            || self
                .required
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.required.len()
        {
            return Err(crate::InputFault::RequiredTheorems.into());
        }
        self.prerequisites.require(&self.base, &self.required)?;
        if let Some(request) = &self.history_request {
            request.validate()?;
            if !self.training || !self.base.history_cursor.matches(request) {
                return Err(crate::ResearchFailure::JobHistoryRequestBinding.into());
            }
            if let Some(receipt) = &self.history {
                receipt.validate(request)?;
            }
        } else if self.history.is_some() {
            return Err(crate::ResearchFailure::JobHistoryRequestMissing.into());
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
            || crate::checkpoint::encode(&self.evidence)?.len() > REPLAY * 8 * 1024 + 4096
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
            return Err(crate::ResearchFailure::JobReplaySnapshotBinding.into());
        }

        if self.written.len() > 2 * (model::TRAINING_UNITS as usize + 2)
            || self.io_bytes > crate::resources::limits().native_model_io_bytes
            || self.io_operations
                > crate::resources::limits().native_model_io_bytes
                    / crate::resources::limits().native_model_chunk_bytes
                    * 2
        {
            return Err(crate::ResearchFailure::JobArtifactLifetimeCapacity.into());
        }
        for (unit, blob) in &self.written {
            if *unit == 0 || *unit > self.units() {
                return Err(crate::ResearchFailure::JobArtifactReservation.into());
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
                    return Err(crate::ResearchFailure::JobReplayReceiptBinding.into());
                }
            } else if self.history_request.is_some() && self.units() > 1 {
                return Err(crate::ResearchFailure::JobReplayPreparationMissing.into());
            }
            p.terminal.validate(p.result.as_ref())?;
            if p.executions.len() > 2
                || matches!(p.terminal, experience::TerminalEvidence::NoSearch(_))
                    && !p.executions.is_empty()
                || p.executions
                    .iter()
                    .map(|t| &t.target)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != p.executions.len()
                || p.executions.iter().try_fold(
                    0usize,
                    |n, trace| -> Result<usize, crate::Error> {
                        trace.validate()?;
                        n.checked_add(trace.attempts).ok_or_else(|| {
                            crate::ResearchFailure::JobObservationWorkOverflow.into()
                        })
                    },
                )? > p.cost.as_ref().map_or(0, |cost| cost.search_expansions)
            {
                return Err(crate::ResearchFailure::JobObservationBinding.into());
            }
            if let Some(selection) = &p.plan {
                selection.validate()?;
                if selection.context
                    != p.prepared
                        .as_ref()
                        .map_or_else(|| meta::context(&self.base), |r| r.context)
                {
                    return Err(crate::ResearchFailure::JobMetaPlanContext.into());
                }
            } else if self.units() > 1 && self.base.preparation == Preparation::Meta {
                return Err(crate::ResearchFailure::JobMetaPlanMissing.into());
            }
            if p.meta_cpu_micros > p.cpu_micros || p.meta_wall_micros > p.wall_micros {
                return Err(crate::ResearchFailure::JobMetaCost.into());
            }
            if let Some(update) = &p.meta_update {
                update.model.validate()?;
                update.experience.validate()?;
                let selected = p
                    .plan
                    .as_ref()
                    .ok_or(crate::ResearchFailure::JobMetaUpdatePlanMissing)?;
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
                    return Err(crate::ResearchFailure::JobMetaUpdateBinding.into());
                }
            } else if self.units() > 1
                && p.unit == self.units()
                && self.base.preparation == Preparation::Meta
            {
                return Err(crate::ResearchFailure::JobMetaUpdateMissing.into());
            }
            if crate::checkpoint::encode(p)?
                .len()
                .checked_mul(self.units() as usize)
                .is_none_or(|bytes| bytes > crate::resources::limits().provider_stream_bytes / 2)
            {
                return Err(crate::ResearchFailure::JobCheckpointCapacity.into());
            }

            p.model.validate()?;
            if p.promotions > self.base.promotions
                && (p.candidate_score <= p.incumbent_score
                    || p.anchor_regression
                    || p.development_regression
                    || !p.transfer.supports_recorded_promotion())
            {
                return Err(crate::ResearchFailure::JobPromotionBinding.into());
            }
            p.transfer.validate()?;
            let expected_transfer = transfer::Summary::prefix(
                p.unit
                    .saturating_sub(model::TRAINING_UNITS)
                    .min(transfer::CASES as u32) as usize,
            );
            if p.first_loss.is_some() && p.transfer.observed != expected_transfer {
                return Err(crate::ResearchFailure::JobTransferCoverage.into());
            }
            p.development_before.validate()?;
            p.development_after.validate()?;
            if p.development_before.checkpoint != digest(&self.base.model) {
                return Err(crate::ResearchFailure::JobDevelopmentBinding.into());
            }
            if let Some(solution) = &p.result
                && !matches!(&solution.tree, search::Tree::Program(_))
            {
                let checked = solution.checked()?;
                if let Some(inputs) = solution.tree.composition()
                    && inputs.iter().any(|id| !self.required.contains(id))
                {
                    return Err(crate::ResearchFailure::JobCompositionBinding.into());
                }
                let definitions = self
                    .prerequisites
                    .definitions(&self.base.definitions, &self.required)?;
                knowledge::validate_offered(
                    checked.conclusion(),
                    &solution.tree,
                    &self.base.knowledge,
                    &definitions,
                    self.prerequisites.has_definitions(),
                    &self.required,
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
                return Err(crate::ResearchFailure::JobModelQualification.into());
            }
            if p.rng < self.base.draws
                || p.rng.saturating_sub(self.base.draws)
                    > u64::from(model::TRAINING_UNITS) * model::UPDATES_PER_UNIT * 16
            {
                return Err(crate::ResearchFailure::JobSamplingContinuation.into());
            }
            if p.promotions < self.base.promotions
                || p.promotions > self.base.promotions.saturating_add(1)
                || p.rejections < self.base.rejections
                || p.rejections > self.base.rejections.saturating_add(1)
                || p.trained < self.base.trained
                || p.trained > self.base.epoch
            {
                return Err(crate::ResearchFailure::JobQualificationSequence.into());
            }
            if let Some(utility) = &p.finder {
                utility.validate()?;
                if utility.checkpoint != digest(&p.model) || p.unit != self.units() {
                    return Err(crate::ResearchFailure::JobFinderBinding.into());
                }
            }
            if p.unit == 0 || p.unit > self.units() {
                return Err(crate::ResearchFailure::JobCheckpointUnit.into());
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
    ) -> Result<(), crate::Error> {
        if self.progress.as_ref().is_some_and(|p| p.unit == unit) {
            return Ok(());
        }
        if unit != self.progress.as_ref().map_or(1, |p| p.unit + 1) {
            return Err(crate::ResearchFailure::LearningUnitSequence.into());
        }
        let wall_started = std::time::Instant::now();
        let cpu_started = meta::cpu_micros()?;
        let mut p = self.progress.clone().unwrap_or(Progress {
            finder: None,
            prepared: None,
            cost: None,
            frontier: None,
            executions: Vec::new(),
            terminal: experience::TerminalEvidence::NoSearch(experience::NoSearch::TrainingOnly),
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
            qualification: Qualification::NoNewAcceptedSolutions,
            generation: None,
        });
        let working = if self.units() > 1 && unit <= model::TRAINING_UNITS {
            self.prepare_history(&mut p, engine, io)?
        } else {
            None
        };
        let (training_state, training_evidence, observations) = working.as_ref().map_or(
            (&self.base, self.evidence.as_slice(), [].as_slice()),
            |sources| {
                (
                    &sources.state,
                    sources.evidence.as_slice(),
                    sources.observations.as_slice(),
                )
            },
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
                .ok_or(crate::ResearchFailure::TrainingPlanMissing)?
                .plan
                .phase(unit - 1);
            if let Some((candidate, first, last)) = engine.train_replay_using(
                parent,
                training_state,
                (training_evidence, observations),
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
                p.training_cost.checked_transitions = engine.cost.checked_transitions;
                p.training_cost.checked_fragments = engine.cost.checked_fragments;
                p.training_cost.omitted_transitions = engine.cost.omitted_transitions;
                p.training_cost.unavailable_fragments = engine.cost.unavailable_fragments;
                p.training_cost.witnessed_preferences = engine.cost.witnessed_preferences;
                p.training_cost.hindsight_matches = engine.cost.hindsight_matches;
                p.training_cost.checked_repairs = engine.cost.checked_repairs;
                p.training_cost.observed_sequences = engine.cost.observed_sequences;
                p.training_cost.sampled_sequence_edges = p
                    .training_cost
                    .sampled_sequence_edges
                    .checked_add(engine.cost.sampled_sequence_edges)
                    .ok_or(crate::ResearchFailure::SampledSequenceOverflow)?;
                p.training_cost
                    .measurements
                    .include(&engine.cost.measurements)?;
                p.first_loss.get_or_insert(first);
                p.last_loss = Some(last);
                p.candidate = Some(candidate);
                p.qualification = if p.last_loss < p.first_loss {
                    Qualification::Pending
                } else {
                    Qualification::OptimizationUnresolved
                };
            } else {
                p.qualification = Qualification::NoAmbiguousTrainingDecisions;
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
                    p.qualification = Qualification::Promoted;
                } else {
                    p.rejections += 1;
                    p.qualification = if p.development_regression {
                        Qualification::DevelopmentRegression
                    } else if p.anchor_regression {
                        Qualification::AnchorRegression
                    } else if p.candidate_score <= p.incumbent_score {
                        Qualification::NoDevelopmentGain
                    } else if !p.transfer.complete() {
                        Qualification::IncompleteTransfer
                    } else if p.transfer.loss() > 0. {
                        Qualification::TransferRegression
                    } else {
                        Qualification::NoTransferGain
                    };
                }
            }
            if self.units() > 1 && self.base.preparation == Preparation::Meta {
                let selection = p
                    .plan
                    .as_ref()
                    .ok_or(crate::ResearchFailure::MetaTrialPlanMissing)?;
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
                let update = engine.meta.learn(&self.base, selection, experience, io)?;
                p.meta_update = Some(update);
                p.meta_cpu_micros += meta::cpu_micros()?.saturating_sub(cpu);
                p.meta_wall_micros += wall.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            }
            if let Some(question) = question {
                let q = ResearchQuestion::from_hex(question)?;
                if curriculum::reserved(&crate::hex(q.resolution_id())) {
                    p.terminal = experience::TerminalEvidence::NoSearch(
                        experience::NoSearch::ReservedQuestion,
                    );
                } else {
                    let budget = if p.rejections % 3 == 2 { 256 } else { 128 };
                    let generated = engine.with_error(&p.model, io, |runtime| {
                        solve_with_report_typed(
                            question,
                            runtime,
                            budget,
                            job,
                            SolveContext {
                                definitions: &self.base.definitions,
                                theorems: &self.base.knowledge,
                                required: &self.required,
                                prerequisites: Some(&self.prerequisites),
                                native_programs: true,
                            },
                        )
                    })?;
                    p.cost = Some(generated.cost);
                    p.frontier = generated.frontier;
                    p.executions = generated.executions;
                    p.terminal = generated.terminal;
                    p.generation = Some(generated.diagnostic);
                    p.result = generated.solution;
                }
            }
        }
        if self.units() > 1 && unit == self.units() {
            p.finder = self
                .base
                .finder_utility(&p.model, &self.evidence, engine, io)?;
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
struct Generation {
    solution: Option<Solution>,
    diagnostic: GenerationOutcome,
    cost: GenerationCost,
    frontier: Option<SearchFrontier>,
    executions: Vec<SearchTrace>,
    terminal: experience::TerminalEvidence,
}
struct Exploring<'a> {
    model: &'a mut model::Runtime,
    seed: u64,
    explore: bool,
}
impl Exploring<'_> {
    fn scores_encoded(&mut self, graph: &graph::Graph) -> Result<Vec<f32>, crate::Error> {
        // Commit the draw only after the input passes the model's gates.
        let mut next = self.seed;
        let scores = if self.explore && model::random(&mut next).is_multiple_of(5) {
            self.model.validate_graph(graph)?;
            (0..graph.candidates.len())
                .map(|_| (model::random(&mut next) >> 11) as f32 / 9007199254740992.)
                .collect()
        } else {
            self.model.scores_graph(graph)?
        };
        self.seed = next;
        Ok(scores)
    }
}
impl model::Ranker for Exploring<'_> {
    fn scores(&mut self, d: &model::Decision) -> Result<Vec<f32>, crate::Error> {
        self.scores_encoded(&graph::Graph::encode(d)?)
    }
    fn plan(
        &mut self,
        d: &model::Decision,
        graph: &graph::Graph,
        offered: &str,
        memory: Option<&model::Memory>,
    ) -> Result<model::Plan, crate::Error> {
        let mut plan = if self.model.recurrent() {
            let mut plan = self.model.plan(d, graph, offered, memory)?;
            let mut next = self.seed;
            if d.candidates.len() > 1 && self.explore && model::random(&mut next).is_multiple_of(5)
            {
                plan.scores = (0..d.candidates.len())
                    .map(|_| (model::random(&mut next) >> 11) as f32 / 9007199254740992.)
                    .collect();
            }
            self.seed = next;
            plan
        } else {
            if memory.is_some() {
                return Err(crate::ResearchFailure::StatelessExplorationMemory.into());
            }
            model::Plan::scores(if d.candidates.len() == 1 {
                vec![0.]
            } else {
                self.scores_encoded(graph)?
            })
        };
        search::focus::rank(d, &mut plan.scores);
        Ok(plan)
    }
    fn identity(&self) -> Option<String> {
        self.model.identity()
    }
}
#[derive(Default)]
struct SolveContext<'a> {
    definitions: &'a [definitions::Entry],
    theorems: &'a [knowledge::Entry],
    required: &'a [String],
    prerequisites: Option<&'a Prerequisites>,
    native_programs: bool,
}
fn program_generation(
    packet: peer::Packet,
    helpers: Vec<String>,
    target: &naome_foundation::Formula,
    refuted: bool,
    mut cost: GenerationCost,
    executions: Vec<search::trace::Trace>,
) -> Result<Generation, crate::Error> {
    let steps = packet.manifest.commands as usize;
    cost.original_steps = steps;
    cost.useful_steps = steps;
    cost.core_work = steps;
    cost.unique_states = peer::program_states(target, &packet)?;
    cost.definition_references = packet
        .commands()?
        .iter()
        .filter(|command| {
            matches!(
                command,
                naome_proof::program::Command::DefinedRelation { .. }
            )
        })
        .count();
    let proof_id = crate::hex(packet.manifest.proof_id().as_bytes());
    Ok(Generation {
        solution: Some(Solution {
            cost: Box::new(cost.clone()),
            source: String::new(),
            helpers,
            proof_id: proof_id.clone(),
            refuted,
            tree: search::Tree::Program(Box::new(packet)),
        }),
        diagnostic: GenerationOutcome::CertifiedProgram,
        cost,
        frontier: None,
        executions,
        terminal: experience::TerminalEvidence::CertifiedCandidate { proof_id, refuted },
    })
}
fn solve_with_report(
    source: &str,
    model: &mut model::Runtime,
    budget: usize,
    job: u64,
    context: SolveContext<'_>,
) -> Result<Generation, String> {
    solve_with_report_typed(source, model, budget, job, context).map_err(Into::into)
}
fn solve_with_report_typed(
    source: &str,
    model: &mut model::Runtime,
    budget: usize,
    job: u64,
    context: SolveContext<'_>,
) -> Result<Generation, crate::Error> {
    let question = ResearchQuestion::from_hex(source)?;
    let definitions = context
        .prerequisites
        .map(|inputs| inputs.definitions(context.definitions, context.required))
        .transpose()?;
    let context = SolveContext {
        definitions: definitions.as_deref().unwrap_or(context.definitions),
        ..context
    };
    let checking = proof::checking_work();
    let started = std::time::Instant::now();
    let mut ranker = Exploring {
        model,
        seed: job.max(1),
        explore: budget >= 128,
    };
    if budget != 0
        && !context.required.is_empty()
        && let Some(inputs) = context.prerequisites.filter(|inputs| inputs.has_programs())
        && let Some(packet) = inputs.native_proof(question.proved_target(), context.required)?
    {
        return program_generation(
            packet,
            Vec::new(),
            question.proved_target(),
            false,
            GenerationCost {
                search_expansions: 1,
                generation_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                ..GenerationCost::default()
            },
            Vec::new(),
        );
    }
    let mut lemma_work = 0;
    if budget != 0
        && context.native_programs
        && context.required.is_empty()
        && let Some(inputs) = context.prerequisites.filter(|inputs| inputs.has_offer())
    {
        let (packet, work) =
            inputs.search_native_lemma(question.proved_target(), &mut ranker, budget, started)?;
        lemma_work = work;
        if let Some(packet) = packet {
            return program_generation(
                packet,
                Vec::new(),
                question.proved_target(),
                false,
                GenerationCost {
                    search_expansions: lemma_work,
                    retrieved_lemmas: 1,
                    generation_micros: started.elapsed().as_micros().min(u128::from(u64::MAX))
                        as u64,
                    ..GenerationCost::default()
                },
                Vec::new(),
            );
        }
    }
    let Generation {
        mut solution,
        diagnostic,
        mut cost,
        frontier,
        executions,
        mut terminal,
    } = search_compiled_question(
        &question,
        &mut ranker,
        budget.saturating_sub(lemma_work),
        &context,
    )?;
    cost.search_expansions += lemma_work;
    if let Some(solution) = &mut solution {
        solution.cost.search_expansions += lemma_work;
    }
    if let Some(solution) = &mut solution {
        if matches!(
            solution.tree,
            search::Tree::Constructed { .. }
                | search::Tree::Scoped { .. }
                | search::Tree::Program(_)
        ) {
            return Ok(Generation {
                solution: Some(solution.clone()),
                diagnostic,
                cost,
                frontier,
                executions,
                terminal,
            });
        }
        let definition_started = std::time::Instant::now();
        let target = if solution.refuted {
            question.refuted_target()
        } else {
            question.proved_target()
        };
        if let Some((entries, selected)) = definitions::choose(
            target,
            context.definitions,
            context
                .prerequisites
                .is_some_and(Prerequisites::has_definitions),
            model,
        )? {
            cost.definition_candidates = entries.len();
            let available = entries
                .iter()
                .take_while(|entry| context.definitions.contains(entry))
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
                    let source = proof::source(&checked);
                    let helpers = definitions::helpers(&tree)?;
                    if source.len() + helpers.iter().map(String::len).sum::<usize>()
                        <= 2 * crate::resources::limits().closure_bytes
                        && source.len() <= 2 * crate::resources::limits().proof_bytes
                        && checked.payload_bytes <= crate::resources::limits().proof_bytes
                        && helpers.iter().all(|source| {
                            source.len() <= 2 * crate::resources::limits().proof_bytes
                        })
                    {
                        solution.source = source;
                        solution.helpers = helpers;
                        solution.proof_id = crate::hex(checked.native_id.as_bytes());
                        solution.tree = tree;
                        cost.definition_references = checked
                            .certificate
                            .steps()
                            .iter()
                            .map(|step| step.definition_references().len())
                            .sum();
                        if let search::Tree::Definitions {
                            entries,
                            selected,
                            proof,
                            ..
                        } = &solution.tree
                            && let Some(operands) = construction::composition::scoped_operands(
                                target,
                                proof,
                                &entries[*selected],
                            )?
                        {
                            cost.definition_references = operands
                                .iter()
                                .map(|(_, formula)| formula.definition_references().len())
                                .sum();
                        }
                    } else {
                        cost.definition_failure = Some(GenerationOutcome::DefinitionLimit);
                    }
                }
                Err(_) => cost.definition_failure = Some(GenerationOutcome::DefinitionCheckFailed),
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
        terminal = experience::TerminalEvidence::certified(solution);
    }
    Ok(Generation {
        solution,
        diagnostic,
        cost,
        frontier,
        executions,
        terminal,
    })
}
#[cfg(test)]
fn solve_with_definitions(
    source: &str,
    model: &mut model::Runtime,
    budget: usize,
    job: u64,
    known: &[definitions::Entry],
    theorems: &[knowledge::Entry],
) -> Result<(Option<Solution>, GenerationOutcome, GenerationCost), String> {
    solve_with_report(
        source,
        model,
        budget,
        job,
        SolveContext {
            definitions: known,
            theorems,
            ..Default::default()
        },
    )
    .map(|g| (g.solution, g.diagnostic, g.cost))
}
#[cfg(test)]
fn search_question_with_knowledge(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
    theorems: &[knowledge::Entry],
    definitions: &[definitions::Entry],
) -> Result<(Option<Solution>, GenerationOutcome, GenerationCost), String> {
    search_question_report(
        source,
        ranker,
        budget,
        &SolveContext {
            theorems,
            definitions,
            ..Default::default()
        },
    )
    .map(|g| (g.solution, g.diagnostic, g.cost))
    .map_err(Into::into)
}
#[cfg(test)]
fn search_question(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
) -> Result<(Option<Solution>, GenerationOutcome), String> {
    let (solution, diagnostic, _) = search_question_measured(source, ranker, budget)?;
    Ok((solution, diagnostic))
}
#[cfg(test)]
fn search_question_measured(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
) -> Result<(Option<Solution>, GenerationOutcome, GenerationCost), String> {
    search_question_with_knowledge(source, ranker, budget, &[], &[])
}
#[cfg(test)]
fn search_question_report(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
    context: &SolveContext<'_>,
) -> Result<Generation, crate::Error> {
    let question = ResearchQuestion::from_hex(source)?;
    search_compiled_question(&question, ranker, budget, context)
}

fn search_compiled_question(
    q: &ResearchQuestion,
    ranker: &mut dyn model::Ranker,
    budget: usize,
    context: &SolveContext<'_>,
) -> Result<Generation, crate::Error> {
    let checking = proof::checking_work();
    let started = std::time::Instant::now();
    let mut retrieval_micros = 0;
    let mut retrieved = 0;
    let mut dependency_steps = 0;
    let mut failure = GenerationOutcome::Unresolved;
    let mut terminal = if budget == 0 {
        experience::TerminalEvidence::Budget(experience::Budget::Expansions)
    } else {
        experience::TerminalEvidence::Unknown
    };
    let mut remaining = budget;
    let mut frontier = None;
    let mut executions = Vec::new();
    let mut certificate_failures = 0;
    let retrieval_started = std::time::Instant::now();
    let dependency_checking = proof::checking_work().steps;
    let terms = context
        .prerequisites
        .map(|p| p.terms(context.required))
        .transpose()?
        .unwrap_or_default();
    dependency_steps += proof::checking_work()
        .steps
        .saturating_sub(dependency_checking) as usize;
    retrieved += terms.len();
    retrieval_micros += retrieval_started
        .elapsed()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;
    let mut knowledge = None;
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
        let (scoped, scoped_work) = if context.required.is_empty() {
            search::scope::search(&target, ranker, remaining, orientation_started)?
        } else {
            (None, 0)
        };
        remaining = remaining.saturating_sub(scoped_work);
        if context.native_programs
            && let Some(search::Tree::Scoped { actions, .. }) = &scoped
        {
            let commands = search::scope::commands(&target, actions)?;
            let packet = peer::Packet::compose(&target, &commands, &[], [])?;
            return program_generation(
                packet,
                Vec::new(),
                &target,
                refuted,
                GenerationCost {
                    search_expansions: budget - remaining,
                    generation_micros: started.elapsed().as_micros().min(u128::from(u64::MAX))
                        as u64,
                    ..GenerationCost::default()
                },
                executions,
            );
        }
        if context.native_programs && !terms.is_empty() && scoped.is_none() && remaining != 0 {
            let (term, work) = construction::composition::construct_term(
                &target,
                &terms,
                remaining,
                orientation_started,
                true,
            )?;
            remaining = remaining.saturating_sub(work);
            if let Some(term) = term {
                let recipe = proof::recipe(&term, &target)?;
                if recipe.steps.iter().any(|step| {
                    matches!(step,
                    naome_proof::ProofStep::ProofReference { proof_id }
                        if context.required.contains(&crate::hex(proof_id.as_bytes())))
                }) {
                    let candidate = construction::program_from_recipe(&target, recipe)?;
                    return program_generation(
                        candidate.packet,
                        candidate.helpers,
                        &target,
                        refuted,
                        GenerationCost {
                            search_expansions: budget - remaining,
                            retrieved_lemmas: retrieved,
                            retrieval_micros,
                            dependency_check_steps: dependency_steps,
                            generation_micros: started
                                .elapsed()
                                .as_micros()
                                .min(u128::from(u64::MAX))
                                as u64,
                            ..GenerationCost::default()
                        },
                        executions,
                    );
                }
            }
        }
        let composed =
            if context.native_programs || scoped.is_some() || terms.is_empty() || remaining == 0 {
                None
            } else {
                let attempt = construction::composition::construct(
                    &target,
                    &terms,
                    remaining,
                    orientation_started,
                );
                let (verified, work) = match attempt {
                    Ok(result) => result,
                    Err(_) => {
                        certificate_failures += 1;
                        failure = GenerationOutcome::CompositionFailed;
                        terminal = experience::TerminalEvidence::TechnicalFailure;
                        // An interrupted generator cannot claim unused allowance.
                        (None, remaining.min(16))
                    }
                };
                remaining = remaining.saturating_sub(work);
                verified.and_then(|verified| {
                    let inputs =
                        construction::composition::used(&verified, context.required).ok()?;
                    if inputs.is_empty() {
                        return None;
                    }
                    Some((verified, inputs, work))
                })
            };
        let found = if let Some(tree) = scoped {
            search::ResultTree {
                execution: None,
                tree: Some(tree),
                expansions: 0,
                failure: None,
                frontier: None,
                terminal: experience::TerminalEvidence::Unknown,
            }
        } else if let Some((verified, inputs, work)) = composed {
            search::ResultTree {
                execution: None,
                tree: Some(search::Tree::Composed {
                    packet: match evidence::pack(&verified) {
                        Ok(packet) => packet,
                        Err(_) => {
                            certificate_failures += 1;
                            failure = GenerationOutcome::CompositionLimit;
                            terminal = experience::TerminalEvidence::Unsupported(
                                experience::Capacity::Certificate,
                            );
                            continue;
                        }
                    },
                    inputs,
                    work,
                }),
                expansions: 0,
                failure: None,
                frontier: None,
                terminal: experience::TerminalEvidence::Unknown,
            }
        } else {
            let selection = (|| {
                if knowledge.is_none() {
                    knowledge = Some(knowledge::Snapshot::new(context.theorems)?);
                }
                knowledge
                    .as_ref()
                    .expect("checked theorem snapshot")
                    .offer(&target, context.required)
            })();
            let (selected, steps) = match selection {
                Ok(selected) => selected,
                Err(_error) if !terms.is_empty() => {
                    failure = GenerationOutcome::PrerequisiteCompositionFailed;
                    terminal = experience::TerminalEvidence::Unsupported(
                        experience::Capacity::Dependencies,
                    );
                    break;
                }
                Err(error) => return Err(error),
            };
            retrieved += selected.len();
            dependency_steps += steps;
            retrieval_micros += retrieval_started
                .elapsed()
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
            if context.native_programs && context.required.is_empty() {
                let (candidate, work) = construction::construct_program(
                    &target,
                    remaining,
                    orientation_started,
                    ranker,
                    &selected,
                    context.definitions,
                )?;
                remaining = remaining.saturating_sub(work);
                if let Some(candidate) = candidate {
                    return program_generation(
                        candidate.packet,
                        candidate.helpers,
                        &target,
                        refuted,
                        GenerationCost {
                            search_expansions: budget - remaining,
                            retrieved_lemmas: retrieved,
                            retrieval_micros,
                            dependency_check_steps: dependency_steps,
                            generation_micros: started
                                .elapsed()
                                .as_micros()
                                .min(u128::from(u64::MAX))
                                as u64,
                            ..GenerationCost::default()
                        },
                        executions,
                    );
                }
            }
            let (constructed, work, selection) = if context.native_programs {
                (None, 0, None)
            } else {
                match construction::construct_with(
                    &target,
                    remaining,
                    orientation_started,
                    ranker,
                    &selected,
                    context.definitions,
                ) {
                    Ok(result) => result,
                    Err(_) => {
                        certificate_failures += 1;
                        remaining = 0;
                        failure = GenerationOutcome::ConstructionFailed;
                        terminal = experience::TerminalEvidence::TechnicalFailure;
                        break;
                    }
                }
            };
            remaining = remaining.saturating_sub(work);
            if let Some(verified) = constructed {
                search::ResultTree {
                    execution: None,
                    tree: Some(search::Tree::Constructed {
                        packet: match construction::pack_candidate(
                            &verified,
                            selection.as_ref(),
                            orientation_started,
                            &mut remaining,
                        ) {
                            Ok(bytes) => bytes,
                            Err(_) => {
                                certificate_failures += 1;
                                failure = GenerationOutcome::ConstructionLimit;
                                terminal = experience::TerminalEvidence::Unsupported(
                                    experience::Capacity::Certificate,
                                );
                                continue;
                            }
                        },
                        selection,
                    }),
                    expansions: 0,
                    failure: None,
                    frontier: None,
                    terminal: experience::TerminalEvidence::Unknown,
                }
            } else {
                search::solve_with_knowledge(
                    &target,
                    ranker,
                    remaining,
                    orientation_started,
                    &selected,
                )?
            }
        };
        remaining = remaining.saturating_sub(found.expansions);
        if let Some(execution) = found.execution {
            executions.push(execution);
        }
        if frontier.is_none() {
            frontier = found.frontier;
        }
        if let Some(tree) = found.tree {
            if context.native_programs {
                let (term, _) = search::compile(&target, &tree)?;
                let mut recipe = proof::recipe(&term, &target)?;
                for entry in definitions::construction_choices(&target, context.definitions)? {
                    if !recipe.definitions.contains(&entry) {
                        recipe.definitions.push(entry);
                    }
                }
                match construction::program_from_recipe(&target, recipe) {
                    Ok(candidate) => {
                        return program_generation(
                            candidate.packet,
                            candidate.helpers,
                            &target,
                            refuted,
                            GenerationCost {
                                search_expansions: budget - remaining,
                                retrieved_lemmas: retrieved,
                                retrieval_micros,
                                dependency_check_steps: dependency_steps,
                                generation_micros: started
                                    .elapsed()
                                    .as_micros()
                                    .min(u128::from(u64::MAX))
                                    as u64,
                                ..GenerationCost::default()
                            },
                            executions,
                        );
                    }
                    Err(_) => {
                        failure = GenerationOutcome::ProgramFailed;
                        terminal = experience::TerminalEvidence::CheckerRejected;
                        continue;
                    }
                }
            }
            let (tree, cost, verified) = match search::core::checked(&target, &tree) {
                Ok(checked) => checked,
                Err(_) => {
                    certificate_failures += 1;
                    failure = GenerationOutcome::CertificateFailed;
                    terminal = experience::TerminalEvidence::CheckerRejected;
                    continue;
                }
            };
            let (source, proof_id, payload_bytes, references, check_steps) = (
                proof::source(&verified),
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
            );
            if source.len() <= 2 * crate::resources::limits().proof_bytes
                && payload_bytes
                    <= crate::resources::limits()
                        .proof_bytes
                        .min(crate::resources::limits().closure_bytes)
            {
                let helpers = definitions::helpers(&tree)?;
                if helpers.len() >= crate::resources::limits().closure_objects
                    || helpers
                        .iter()
                        .any(|s| s.len() > 2 * crate::resources::limits().proof_bytes)
                    || source.len() + helpers.iter().map(String::len).sum::<usize>()
                        > 2 * crate::resources::limits().closure_bytes
                {
                    failure = GenerationOutcome::CertificateClosureLimit;
                    terminal = experience::TerminalEvidence::Unsupported(
                        experience::Capacity::Certificate,
                    );
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
                return Ok(Generation {
                    executions,
                    terminal: experience::TerminalEvidence::CertifiedCandidate {
                        proof_id: proof_id.clone(),
                        refuted,
                    },
                    solution: Some(Solution {
                        helpers,
                        cost: Box::new(measured.clone()),
                        source,
                        proof_id,
                        refuted,
                        tree,
                    }),
                    diagnostic: GenerationOutcome::CertifiedCertificate,
                    cost: measured,
                    frontier: None,
                });
            } else {
                failure = GenerationOutcome::CertificateLimit;
                terminal =
                    experience::TerminalEvidence::Unsupported(experience::Capacity::Certificate);
            }
        } else {
            if let Some(reason) = found.failure {
                failure = reason;
            }
            // Unknown is not evidence of exhausted search. Preserve an earlier
            // explicit limitation if the other orientation never made progress.
            if !matches!(found.terminal, experience::TerminalEvidence::Unknown) {
                terminal.include(found.terminal);
            }
        }
    }
    if remaining == 0 && matches!(terminal, experience::TerminalEvidence::Unknown) {
        terminal = experience::TerminalEvidence::Budget(experience::Budget::Expansions);
    }
    Ok(Generation {
        executions,
        solution: None,
        terminal,
        diagnostic: failure,
        cost: GenerationCost {
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
        frontier,
    })
}

#[cfg(test)]
mod experiment;
#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod exploration_tests;
