//! Local operational learning state; never a mathematical artifact or gossip item.
mod artifact;
mod calculus;
mod curriculum;
mod graph;
mod model;
mod proof;
mod search;
mod state;
pub(crate) use artifact::{ArtifactIo, Blob};
use model::Checkpoint;
pub(crate) use model::{Engine, REQUIREMENTS as MODEL_REQUIREMENTS, TRAINING_UNITS};
use naome_authoring::CompiledQuestion;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) const PROVIDER: &str = "naome-native-proof-learning";
const REPLAY: usize = 32;
const EVALUATIONS: u32 = curriculum::DEVELOPMENT as u32 + 4;
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Statistics {
    selections: u64,
    attempts: u64,
    successes: u64,
    recent: u32,
    previous: u32,
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
pub(crate) struct State {
    model: Checkpoint,
    replay: Vec<Example>,
    anchors: Vec<Example>,
    accepted: u64,
    trained: u64,
    attempted: u64,
    pub peer_cursor: u64,
    local_examples: u64,
    peer_examples: u64,
    promotions: u64,
    rejections: u64,
    statistics: BTreeMap<String, Statistics>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Progress {
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
    pub result: Option<Solution>,
    pub diagnostic: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job {
    pub training: bool,
    pub base_hash: String,
    pub base: State,
    pub progress: Option<Progress>,
    pub written: Vec<(u32, Blob)>,
    pub io_bytes: usize,
    pub io_operations: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Solution {
    pub source: String,
    pub proof_id: String,
    pub refuted: bool,
    pub tree: search::Tree,
}
pub(crate) fn digest(value: &impl Serialize) -> String {
    use sha2::{Digest, Sha256};
    crate::hex(&Sha256::digest(
        serde_json::to_vec(value).expect("finite typed learning state"),
    ))
}
impl Job {
    pub fn blobs(&self) -> Vec<&Blob> {
        let mut blobs: Vec<_> = self.base.model.blobs().collect();
        if let Some(p) = &self.progress {
            blobs.extend(p.model.blobs());
            if let Some(candidate) = &p.candidate {
                blobs.extend(candidate.blobs());
            }
        }
        blobs
    }
    pub fn allows_read(&self, blob: &Blob) -> bool {
        self.blobs().into_iter().any(|b| b == blob)
    }
    pub fn units(&self) -> u32 {
        if self.training && self.base.accepted > self.base.trained {
            model::TRAINING_UNITS + EVALUATIONS + 1
        } else {
            1
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if digest(&self.base) != self.base_hash {
            return Err("learning parent snapshot differs".into());
        }
        self.base.validate()?;
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
            if serde_json::to_vec(p)
                .map_err(|e| e.to_string())?
                .len()
                .checked_mul(self.units() as usize)
                .is_none_or(|bytes| bytes > crate::resources::limits().provider_stream_bytes / 2)
            {
                return Err("local checkpoints exceed original provider stream capacity".into());
            }

            p.model.validate()?;
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
            if p.promotions < self.base.promotions
                || p.promotions > self.base.promotions.saturating_add(1)
                || p.rejections < self.base.rejections
                || p.rejections > self.base.rejections.saturating_add(1)
                || p.trained < self.base.trained
                || p.trained > self.base.accepted
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
        let mut p = self.progress.clone().unwrap_or(Progress {
            unit: 0,
            model: self.base.model.clone(),
            trained: self.base.trained,
            promotions: self.base.promotions,
            rejections: self.base.rejections,
            candidate: None,
            rng: self.base.model.seed ^ job ^ self.base.accepted,
            first_loss: None,
            last_loss: None,
            incumbent_score: 0,
            candidate_score: 0,
            anchor_regression: false,
            result: None,
            diagnostic: "no_new_accepted_solutions".into(),
        });
        if self.units() > 1 && unit <= model::TRAINING_UNITS {
            let graphs = self.base.training_graphs()?;
            if !graphs.is_empty() {
                let parent = p.candidate.as_ref().unwrap_or(&self.base.model);
                let (candidate, first, last) = engine.train(parent, &graphs, &mut p.rng, io)?;
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
                p.trained = self.base.accepted;
            }
        } else if self.units() > 1 && unit <= model::TRAINING_UNITS + EVALUATIONS {
            if let Some(candidate) = &p.candidate {
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
                    let before = engine
                        .with(&self.base.model, io, |runtime| {
                            solve(&source, runtime, 32, job)
                        })?
                        .0
                        .is_some();
                    let after = engine
                        .with(candidate, io, |runtime| solve(&source, runtime, 32, job))?
                        .0
                        .is_some();
                    if index < curriculum::DEVELOPMENT {
                        p.incumbent_score += u32::from(before);
                        p.candidate_score += u32::from(after);
                    } else if before && !after {
                        p.anchor_regression = true;
                    }
                }
            }
        } else {
            if let Some(candidate) = p.candidate.take() {
                if p.candidate_score > p.incumbent_score && !p.anchor_regression {
                    p.model = candidate;
                    p.promotions += 1;
                    p.diagnostic = "candidate_promoted".into();
                } else {
                    p.rejections += 1;
                    p.diagnostic = if p.anchor_regression {
                        "forgetting_rejected"
                    } else {
                        "no_development_gain_rejected"
                    }
                    .into();
                }
            }
            if let Some(question) = question {
                let q = CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
                if curriculum::reserved(&crate::hex(q.resolution_id())) {
                    p.diagnostic = "reserved_question_excluded".into();
                } else {
                    let budget = if p.rejections % 3 == 2 { 256 } else { 128 };
                    let (solution, failure) = engine.with(&p.model, io, |runtime| {
                        solve(question, runtime, budget, job)
                    })?;
                    if solution.is_none() {
                        p.diagnostic = failure;
                    }
                    p.result = solution;
                }
            }
        }
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
fn solve(
    source: &str,
    model: &mut model::Runtime,
    budget: usize,
    job: u64,
) -> Result<(Option<Solution>, String), String> {
    let mut ranker = Exploring {
        model,
        seed: job.max(1),
        explore: budget >= 128,
    };
    search_question(source, &mut ranker, budget)
}
fn search_question(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
) -> Result<(Option<Solution>, String), String> {
    let q = CompiledQuestion::compile(source).map_err(|e| e.to_string())?;
    let mut failure = "calculus_or_strategy_unresolved".to_owned();
    let mut remaining = budget;
    for refuted in [false, true] {
        if remaining == 0 {
            break;
        }
        let target = if refuted {
            q.refuted_target().clone()
        } else {
            q.proved_target().clone()
        };
        let found = search::solve(&target, ranker, remaining)?;
        remaining = remaining.saturating_sub(found.expansions);
        if let Some(tree) = found.tree {
            match search::compile(&target, &tree)
                .and_then(|(term, _)| proof::verify(&term, &target))
                .and_then(|verified| {
                    Ok((
                        proof::source(&verified)?,
                        crate::hex(verified.native_id.as_bytes()),
                        verified.payload_bytes,
                    ))
                }) {
                Ok((source, proof_id, payload_bytes))
                    if source.len() <= crate::resources::limits().proof_bytes
                        && payload_bytes
                            <= crate::resources::limits()
                                .proof_bytes
                                .min(crate::resources::limits().closure_bytes) =>
                {
                    return Ok((
                        Some(Solution {
                            source,
                            proof_id,
                            refuted,
                            tree,
                        }),
                        "certified_candidate".into(),
                    ));
                }
                Ok(_) => failure = "certificate_capacity".into(),
                Err(error) => failure = format!("certificate_unresolved: {error}"),
            }
        } else if let Some(reason) = found.failure {
            failure = reason;
        }
    }
    Ok((None, failure))
}

#[cfg(test)]
mod experiment;
#[cfg(test)]
pub(crate) mod tests;
