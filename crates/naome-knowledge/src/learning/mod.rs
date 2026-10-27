//! Local operational learning state; never a mathematical artifact or gossip item.
mod artifact;
mod calculus;
mod construction;
mod curriculum;
pub(crate) mod definitions;
mod graph;
mod model;
pub(crate) mod peer;
mod pool;
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
    failures: [u64; 6],
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
    pub certificate: Vec<u8>,
}
impl Example {
    pub fn peer_job(&self) -> Option<u64> {
        matches!(self.tree, search::Tree::Peer { .. }).then_some(self.job)
    }
    pub fn matches_solution(&self, solution: &Solution) -> bool {
        match (&self.tree, &solution.tree) {
            (search::Tree::Peer { steps }, search::Tree::Certificate(bytes)) => {
                matches!(self.origin, Origin::Peer { .. }) && *steps == peer::step_count(bytes)
            }
            _ => digest(&self.tree) == digest(&solution.tree),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    model: Checkpoint,
    definitions: Vec<definitions::Entry>,
    replay: Vec<Example>,
    anchors: Vec<Example>,
    accepted: u64,
    epoch: u64,
    draws: u64,
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
    pub cost: Option<GenerationCost>,
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
    pub result: Option<Solution>,
    pub diagnostic: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job {
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
        let context = if let search::Tree::Constructed(bytes) = &self.tree {
            construction::evidence::context(bytes)?
        } else {
            definitions::context(&definitions::selected(&self.tree)?)?
        };
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
        if self.training && self.base.epoch > self.base.trained {
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
        let mut expected = if self.training {
            self.base
                .replay
                .iter()
                .filter_map(Example::peer_job)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        expected.sort_unstable();
        expected.dedup();
        let actual = self.evidence.iter().map(|e| e.job).collect::<Vec<_>>();
        if expected != actual
            || self.evidence.iter().any(|e| {
                e.certificate.len() > 8 * 1024
                    || !self.base.replay.iter().any(|r| {
                        r.job == e.job && r.proof_id == e.proof_id && r.peer_job().is_some()
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
        let mut p = self.progress.clone().unwrap_or(Progress {
            cost: None,
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
            result: None,
            diagnostic: "no_new_accepted_solutions".into(),
        });
        if self.units() > 1 && unit <= model::TRAINING_UNITS {
            let parent = p.candidate.as_ref().unwrap_or(&self.base.model);
            if let Some((candidate, first, last)) =
                engine.train_replay(parent, &self.base, &self.evidence, &mut p.rng, io)?
            {
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
                        if index < curriculum::CORPUS_DEVELOPMENT {
                            p.original_score[0] += u32::from(before);
                            p.original_score[1] += u32::from(after);
                            p.development_regression |= before && !after;
                        }
                    } else if before && !after {
                        p.anchor_regression = true;
                    }
                }
            }
        } else {
            if let Some(candidate) = p.candidate.take() {
                if p.candidate_score > p.incumbent_score
                    && !p.anchor_regression
                    && !p.development_regression
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
                    let (solution, failure, cost) = engine.with(&p.model, io, |runtime| {
                        solve_with_definitions(
                            question,
                            runtime,
                            budget,
                            job,
                            &self.base.definitions,
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
    let (solution, diagnostic, _) = solve_measured(source, model, budget, job)?;
    Ok((solution, diagnostic))
}
fn solve_measured(
    source: &str,
    model: &mut model::Runtime,
    budget: usize,
    job: u64,
) -> Result<(Option<Solution>, String, GenerationCost), String> {
    let mut ranker = Exploring {
        model,
        seed: job.max(1),
        explore: budget >= 128,
    };
    search_question_measured(source, &mut ranker, budget)
}
fn solve_with_definitions(
    source: &str,
    model: &mut model::Runtime,
    budget: usize,
    job: u64,
    known: &[definitions::Entry],
) -> Result<(Option<Solution>, String, GenerationCost), String> {
    let started = std::time::Instant::now();
    let (mut solution, diagnostic, mut cost) = solve_measured(source, model, budget, job)?;
    if let Some(solution) = &mut solution {
        if matches!(solution.tree, search::Tree::Constructed(_)) {
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
            let tree = search::Tree::Definitions {
                entries,
                selected,
                available: known.len().min(definitions::CAPACITY - 1),
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
fn search_question_measured(
    source: &str,
    ranker: &mut dyn model::Ranker,
    budget: usize,
) -> Result<(Option<Solution>, String, GenerationCost), String> {
    let started = std::time::Instant::now();
    let q = CompiledQuestion::compile(source).map_err(|e| e.to_string())?;
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
        let (constructed, work) =
            match construction::construct(&target, remaining, orientation_started) {
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
                tree: Some(search::Tree::Constructed(
                    match construction::evidence::pack(&verified) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            certificate_failures += 1;
                            failure = format!("construction_capacity: {error}");
                            continue;
                        }
                    },
                )),
                expansions: 0,
                failure: None,
            }
        } else {
            search::solve_started(&target, ranker, remaining, orientation_started)?
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
                    let measured = GenerationCost {
                        definition_candidates: definitions::selected(&tree)?.len(),
                        definition_references: references,
                        definition_check_steps: if references > 0 { check_steps } else { 0 },
                        certificate_failures,
                        search_expansions: budget - remaining,
                        original_steps: cost.original_steps,
                        useful_steps: cost.useful_steps,
                        core_work: cost.replay_work,
                        unique_states: search::compile(&target, &tree)?
                            .1
                            .iter()
                            .map(graph::Graph::key)
                            .collect::<std::collections::BTreeSet<_>>()
                            .len(),
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
