//! Offline developer/learner interface. Graph::open retains exclusive node
//! ownership; the node must be stopped before operating on its directory.
use super::*;
use std::{io::Write, path::Path};

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Select {
        request: Request,
    },
    Plan {
        request: Request,
        candidates: Vec<String>,
    },
    Questions {
        partition: Partition,
        after: Option<String>,
        scan: usize,
    },
    Compare {
        baseline: Evaluation,
        targeted: Evaluation,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionPage {
    pub knowledge: String,
    pub partition: Partition,
    pub questions: Vec<String>,
    pub next_after: Option<String>,
    #[serde(skip)]
    _memory: Option<std::sync::Arc<crate::resources::MemoryLease>>,
}

/// Exposes question-only pages for freezing a development or final suite. Root
/// certificates, outcome labels and family names never enter the problem input.
pub fn questions(
    graph: &Graph,
    partition: Partition,
    after: Option<&str>,
    scan: usize,
) -> Result<QuestionPage, Error> {
    crate::resources::require_work_admission()?;
    if scan == 0 || scan > crate::resources::active_limits().id_page.min(16) {
        return Err(Error::InputLimit("training suite page limit"));
    }
    let memory = crate::resources::MemoryLease::acquire(
        crate::resources::active_limits().question_cache_bytes,
    )?;
    let after = after
        .map(crate::object::id_bytes)
        .transpose()?
        .map(ArtifactId::from_bytes);
    let ids = graph.ids_page(after, scan)?;
    let mut questions = Vec::new();
    for id in &ids {
        if !selection::canonical(graph, *id)? {
            continue;
        }
        match describe(graph, *id) {
            Ok(Some(metadata)) => {
                let (_, _, target) = metadata.compile()?;
                if super::partition(&target) == partition {
                    questions.push(target.source().into());
                }
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(QuestionPage {
        knowledge: crate::hex(&graph.content_root()),
        partition,
        questions,
        _memory: Some(memory),
        next_after: (ids.len() == scan)
            .then(|| ids.last().map(|id| crate::hex(id.as_bytes())))
            .flatten(),
    })
}

/// Typed responses retain their resource leases during streaming serialization.
#[derive(Serialize)]
#[serde(untagged)]
pub enum Response {
    Batch(Batch),
    Plan(Plan),
    Questions(QuestionPage),
    Comparison(Comparison),
}

/// Executes one bounded command against an already owned checked graph.
pub fn execute(graph: &Graph, command: &Command) -> Result<Response, Error> {
    match command {
        Command::Select { request } => select(graph, request).map(Response::Batch),
        Command::Plan {
            request,
            candidates,
        } => plan(graph, request, candidates).map(Response::Plan),
        Command::Questions {
            partition,
            after,
            scan,
        } => questions(graph, *partition, after.as_deref(), *scan).map(Response::Questions),
        Command::Compare { baseline, targeted } => {
            compare(graph, baseline, targeted).map(Response::Comparison)
        }
    }
}

/// Reads one owned regular bounded JSON request and streams one JSON response.
/// The external learner owns training, resource metering and immutable model
/// identities. This command never enables training in the ordinary node.
pub fn run(directory: &Path, input: &Path) -> Result<(), String> {
    let limits = crate::resources::limits();
    let budget = limits
        .command_parse_budget()
        .ok_or("training command parse budget")?;
    let _memory = crate::resources::MemoryLease::acquire(budget).map_err(|e| e.to_string())?;
    let bytes = crate::storage::read_owned(input, limits.command_bytes)?
        .ok_or("training request file missing")?;
    crate::resources::json::allocation_bound(&bytes, budget).map_err(|e| e.to_string())?;
    let command: Command = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let graph = Graph::open(directory).map_err(|e| e.to_string())?;
    let response = execute(&graph, &command).map_err(|e| e.to_string())?;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &response).map_err(|e| e.to_string())?;
    output.write_all(b"\n").map_err(|e| e.to_string())
}

pub const HELP: &str = "usage: naome-knowledge-dev training <node-directory> <request.json>\n\
Stop the node first. Input is one owned regular bounded JSON file; output is one JSON response.\n\
Operations (strict JSON; unknown fields are rejected):\n\
  select: {operation, request} exports checked native proof targets with their dependency context.\n\
  plan: {operation, request, candidates:[question-source,...]} selects new question-only solver work.\n\
  questions: {operation, partition:training|development|reserved, after:null|ArtifactId, scan:1..16}\n\
    returns question-only pages for freezing diagnostics and final evaluation.\n\
  compare: {operation, baseline, targeted} validates a matched reserved evaluation.\n\
Request fields: solver:{checkpoint:SHA256,budget:{work_units,horizon_ms}}, training_roots:[ArtifactId,...],\n\
  development:null|{solver,knowledge,probes}, previous_development:null|{solver,knowledge,probes},\n\
  after:null|ArtifactId, scan:1..16 (select) or 1..32 (plan), take:1..scan, seed:u64, random_only:bool.\n\
Use next_after for the next scan page. Coverage roots are a bounded representative replay sample.\n\
Probe: {question,spent_ms,work_units, result:{outcome:verified,artifact:ArtifactId}|{outcome:exhausted}|{outcome:unavailable}}.\n\
Only development probes can adapt selection; successes must finish inside the original allowance; verified results must bind to exact checked roots.\n\
Evaluation fields: initial_checkpoint,solver,knowledge,total_budget_micros,compute,probes.\n\
Compute fields: selection_micros,generation_and_checking_micros,training_micros,evaluation_micros.\n\
Both arms require identical starting checkpoint, context, questions and allowance/total ceiling.\n\
The external learner runs training and measures actual CPU. Reports grant no work or validity authority.\n\
Inputs expose question and available context only; proof targets and provenance are separate fields.\n\
Partitions conservatively group syntax and exclude cross-split proof dependencies. Keep authored source\n\
lineages together as well. These signals do not establish mathematical novelty or semantic independence.\n\
Streamed proof programs are counted as unsupported; a manifest is never exported as a proof target.";
