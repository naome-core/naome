//! Bounded curricula over the checked graph, without a model-training authority.
//!
//! A learner supplies its checkpoint, original search allowance, a bounded
//! sample of its actual training roots and development diagnostics. Only checked
//! graph certificates become targets. Exhaustion and technical errors are never
//! mathematical negatives. Dataset provenance stays outside model inputs.
//!
//! The selector uses conservative structural groups and proof dependencies to
//! separate training, development and reserved evaluation. These groups do not
//! decide arbitrary mathematical equivalence or replace authored source lineage.
//! A consumer must additionally keep descendants of the same authored source in
//! one split. Reserved evaluation results have a separate, non-adaptive API.
use crate::{Envelope, Error, Graph, structure::Features};
use naome_authoring::CompiledQuestion;
use naome_proof::ArtifactId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) mod ability;
mod command;
mod evaluation;
mod planning;
mod selection;
mod signals;
#[cfg(test)]
mod tests;

pub use crate::jobs::Limits as SearchBudget;
pub use command::{Command, HELP, QuestionPage, Response, execute, questions, run};
pub use evaluation::{Comparison, Compute, Evaluation, Results, compare};
pub use planning::{Plan, PlannedQuestion, plan};
pub(crate) use planning::{continuation, continuation_parent};
use signals::Signals;
pub(crate) use signals::opportunity;

/// One exact model checkpoint and the per-question search allowance.
/// The learner must change `checkpoint` whenever weights or search policy change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Solver {
    pub checkpoint: String,
    pub budget: SearchBudget,
}
impl Solver {
    fn validate(&self) -> Result<(), Error> {
        crate::object::id_bytes(&self.checkpoint)?;
        if self.budget.work_units == 0 || self.budget.horizon_ms == 0 {
            return Err("training search allowance must be positive".into());
        }
        Ok(())
    }
}

/// Disjoint, deterministic structural partitions. Final results cannot enter
/// the development-feedback API. The split is fixed independently of outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Partition {
    Training,
    Development,
    Reserved,
}

/// A conservative syntax group: alpha-renamings, opposite resolutions and
/// identical primitive signal patterns share a group. Formula counts intentionally
/// over-group examples; neither topic labels nor semantic independence is claimed.
pub fn group(question: &CompiledQuestion) -> String {
    let features = Features::of(question);
    let mut digest = Sha256::new();
    digest.update(b"naome:training-structure\0");
    for count in features.counts {
        digest.update(count.to_be_bytes());
    }
    digest.update(features.depth.to_be_bytes());
    crate::hex(&digest.finalize())
}

pub fn partition(question: &CompiledQuestion) -> Partition {
    // group() produces a canonical digest; use all bytes, not a displayed name.
    let digest = Sha256::digest(group(question).as_bytes());
    match u16::from_be_bytes([digest[0], digest[1]]) % 5 {
        0 => Partition::Development,
        1 => Partition::Reserved,
        _ => Partition::Training,
    }
}

/// Solver outcomes are operational observations. Only `Verified` carries a
/// mathematical target, which is re-bound to the exact checked graph statement.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Verified { artifact: String },
    Exhausted,
    Unavailable,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub question: String,
    pub spent_ms: u64,
    pub work_units: u32,
    pub result: Outcome,
}

/// Only development questions may influence adaptive priorities. The knowledge
/// root and budget bind comparisons; a prior report must use the same questions
/// and context before its difference can count as observed development progress.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Development {
    pub solver: Solver,
    pub knowledge: String,
    pub probes: Vec<Probe>,
}

/// One bounded selection opportunity. `training_roots` is a representative
/// replay/coverage sample, not a claim to have enumerated a learner's full corpus.
/// Scan repeatedly with `next_after`; do not silently truncate a corpus scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub solver: Solver,
    pub training_roots: Vec<String>,
    pub development: Option<Development>,
    pub previous_development: Option<Development>,
    pub after: Option<String>,
    pub scan: usize,
    pub take: usize,
    pub seed: u64,
    /// A matched uniform baseline over the same eligible, checked pool.
    pub random_only: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    pub question: String,
    /// Available checked dependencies, never the root target certificate.
    pub context: Vec<Envelope>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub proof: Envelope,
    pub refuted: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub resolution: String,
    pub structural_group: String,
    pub proof_rules: Vec<String>,
    pub priority: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    pub input: Problem,
    pub target: Target,
    pub provenance: Provenance,
    #[serde(skip)]
    _memory: Vec<std::sync::Arc<crate::resources::MemoryLease>>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub scanned: usize,
    pub eligible: usize,
    pub reserved: usize,
    pub unsupported: usize,
    pub dependent_on_other_split: usize,
    pub duplicates: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub solver: Solver,
    pub knowledge: String,
    pub request_digest: String,
    pub next_after: Option<String>,
    pub counts: Counts,
    pub examples: Vec<Example>,
}

/// Selects existing independently checked proof targets, including known
/// theorems the learner has not mastered. This never admits a research question,
/// runs a model, allocates a provider allowance or updates model weights.
pub fn select(graph: &Graph, request: &Request) -> Result<Batch, Error> {
    selection::select(graph, request)
}

fn question(graph: &Graph, root: &str) -> Result<CompiledQuestion, Error> {
    let id = ArtifactId::from_bytes(crate::object::id_bytes(root)?);
    let metadata = describe(graph, id)?.ok_or("training target is not a checked proof")?;
    metadata.compile().map(|(_, _, question)| question)
}

struct Observation {
    input: [u8; 32],
    features: Features,
    solved: Option<bool>,
    micros: u64,
}
type Observations = BTreeMap<[u8; 32], Observation>;

fn probes(
    graph: &Graph,
    solver: &Solver,
    knowledge: &str,
    observations: &[Probe],
    expected: Partition,
) -> Result<Observations, Error> {
    solver.validate()?;
    if knowledge != crate::hex(&graph.content_root()) {
        return Err("training evaluation knowledge differs".into());
    }
    if observations.len() > crate::resources::active_limits().question_page {
        return Err(Error::InputLimit("training diagnostic page limit"));
    }
    let mut result = BTreeMap::new();
    for probe in observations {
        let target = CompiledQuestion::compile(&probe.question)?;
        if partition(&target) != expected {
            return Err("training evaluation partition differs".into());
        }
        let solved = match &probe.result {
            Outcome::Verified { artifact } => {
                if probe.spent_ms > solver.budget.horizon_ms
                    || probe.work_units > solver.budget.work_units
                {
                    return Err(
                        "verified training diagnostic exceeds its original allowance".into(),
                    );
                }
                let checked = question(graph, artifact)?;
                if checked.resolution_id() != target.resolution_id()
                    || checked.core() != target.core()
                {
                    return Err("training diagnostic proof target differs".into());
                }
                Some(true)
            }
            Outcome::Exhausted => Some(false),
            Outcome::Unavailable => None,
        };
        if result
            .insert(
                *target.resolution_id(),
                Observation {
                    input: *target.source_hash(),
                    features: Features::of(&target),
                    solved,
                    micros: probe.spent_ms.saturating_mul(1000),
                },
            )
            .is_some()
        {
            return Err("duplicate training evaluation question".into());
        }
    }
    Ok(result)
}

fn request_digest(request: &impl Serialize) -> Result<String, Error> {
    let bytes = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    Ok(crate::hex(&Sha256::digest(bytes)))
}

fn describe(graph: &Graph, id: ArtifactId) -> Result<Option<crate::object::Metadata>, Error> {
    let Some(header) = graph.checked_context().artifact_proof_header(id)? else {
        return Ok(None);
    };
    if header.canonical_length() > crate::resources::limits().proof_bytes {
        return Ok(None);
    }
    let _memory = crate::resources::MemoryLease::acquire(
        header
            .canonical_length()
            .saturating_mul(8)
            .saturating_add(2048),
    )?;
    match graph.describe(id) {
        Err(error) if !error.fatal() && !error.retryable() => Ok(None),
        result => result,
    }
}
