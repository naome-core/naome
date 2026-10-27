//! Prospective research shares the curriculum's measured deficits. Outputs are
//! unproved obligations and must still pass the node's real admission path.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedQuestion {
    pub question: String,
    pub structural_group: String,
    pub priority: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub solver: Solver,
    pub knowledge: String,
    pub request_digest: String,
    pub excluded: usize,
    pub questions: Vec<PlannedQuestion>,
    #[serde(skip)]
    _memory: Option<std::sync::Arc<crate::resources::MemoryLease>>,
}

/// Select question-only solver work from a bounded candidate page. Confirmed
/// answers, reserved groups and exact duplicates are excluded. Similarity is a
/// soft penalty; randomized family exploration retains useful generalizations.
/// No proof labels, new allowances or accepted-store authority are produced.
pub fn plan(graph: &Graph, request: &Request, candidates: &[String]) -> Result<Plan, Error> {
    crate::resources::require_work_admission()?;
    request.solver.validate()?;
    let limits = crate::resources::active_limits();
    if request.scan == 0
        || request.scan > limits.question_page.min(32)
        || candidates.len() > request.scan
        || request.take == 0
        || request.take > request.scan
        || request.training_roots.len() > limits.question_page
    {
        return Err(Error::InputLimit("training question page limit"));
    }
    let memory = crate::resources::MemoryLease::acquire(limits.question_cache_bytes)?;
    let signals = selection::profile(graph, request)?;
    let mut formal =
        crate::question::LocalQuestions::new(Some(crate::mocks::select_question as fn(_) -> _));
    let mut seen = BTreeSet::new();
    let mut eligible = Vec::new();
    for source in candidates {
        let target = CompiledQuestion::compile(source)?;
        if partition(&target) != Partition::Training
            || !seen.insert(*target.resolution_id())
            || !formal.generation_decision(graph, &target).passed()
        {
            continue;
        }
        eligible.push((Features::of(&target), target));
    }
    let excluded = candidates.len() - eligible.len();
    let mut random = crate::sampling::Random::new(request.seed);
    let mut chosen = Vec::<Features>::new();
    let mut questions = Vec::new();
    while !eligible.is_empty() && questions.len() < request.take {
        let weighted = eligible
            .iter()
            .map(|(features, question)| {
                let similarity = chosen
                    .iter()
                    .map(|previous| features.similarity(previous))
                    .max()
                    .unwrap_or(0);
                let weight =
                    signals.priority(features, &[false; signals::RULES], features.nodes as usize)
                        / (1 + 8 * similarity / crate::structure::SCALE);
                (group(question), weight.max(1))
            })
            .collect::<Vec<_>>();
        let index = crate::sampling::choose(&mut random, &weighted, request.random_only);
        let priority = weighted[index].1;
        let (features, target) = eligible.remove(index);
        chosen.push(features);
        questions.push(PlannedQuestion {
            structural_group: group(&target),
            question: target.source().into(),
            priority,
        });
    }
    Ok(Plan {
        solver: request.solver.clone(),
        knowledge: crate::hex(&graph.content_root()),
        request_digest: request_digest(&(request, candidates))?,
        excluded,
        questions,
        _memory: Some(memory),
    })
}
