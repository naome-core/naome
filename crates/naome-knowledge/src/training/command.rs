//! Bounded learner operations against an already owned checked graph.
use super::*;

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
        return Err(Error::InputLimit(crate::InputLimit::TrainingSuitePageLimit));
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
                let (_, _, target) = metadata.compile(graph.checked_context())?;
                if super::partition(&target) == partition {
                    questions.push(target.to_hex());
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
