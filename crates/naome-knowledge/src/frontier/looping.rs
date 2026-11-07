//! Recoverable finite prerequisite plans, subordinate to checker and job owners.
use super::*;
pub(crate) struct Work {
    pub target: CompiledQuestion,
    pub planned: Vec<CompiledQuestion>,
    pub pending: Vec<CompiledQuestion>,
    pub required: Vec<String>,
    ready: bool,
    _memory: Vec<Arc<crate::resources::MemoryLease>>,
}
const DEPTH: usize = 2;
struct Node {
    question: CompiledQuestion,
    record: Option<evidence::Record>,
    children: Vec<usize>,
    checked: Option<(String, u64)>,
    depth: usize,
    available: bool,
}
impl Node {
    fn load(
        frontier: &Frontier,
        question: CompiledQuestion,
        graph: &Graph,
        depth: usize,
        memory: &mut Vec<Arc<crate::resources::MemoryLease>>,
    ) -> Result<Self, crate::Error> {
        let record = frontier.evidence.get(&question)?;
        let bytes = question.source().len().saturating_mul(24)
            + record.as_ref().map_or(0, |r| {
                r.helpers.iter().map(|s| s.len() * 24 + 768).sum::<usize>()
            })
            + 8192;
        memory.push(crate::resources::MemoryLease::acquire(bytes)?);
        let checked = if let Some(record) = &record
            && let Some(root) = &record.verified
        {
            let root = ArtifactId::from_bytes(crate::object::id_bytes(root)?);
            if Frontier::checked_target(graph, root, &question)? {
                graph
                    .describe(root)?
                    .map(|m| (m.proof_id, record.verified_at))
            } else {
                None
            }
        } else {
            None
        };
        Ok(Self {
            question,
            record,
            children: vec![],
            checked,
            depth,
            available: true,
        })
    }
}
struct Choice {
    target: usize,
    pending: Vec<usize>,
    required: Vec<(String, u64)>,
}
fn next(nodes: &[Node], index: usize, depth: usize) -> Choice {
    let mut work = Choice {
        target: index,
        pending: vec![],
        required: vec![],
    };
    for &child in &nodes[index].children {
        let node = &nodes[child];
        if !node.available {
            continue;
        }
        if let Some(proof) = &node.checked {
            work.required.push(proof.clone());
        } else if node.record.is_none() && !node.children.is_empty() && depth + 1 < DEPTH {
            let mut nested = next(nodes, child, depth + 1);
            if nested.pending.is_empty() {
                nested.pending.push(child);
            }
            return nested;
        } else if node
            .record
            .as_ref()
            .is_none_or(|r| r.last_outcome == Outcome::Candidate && !r.publication_abandoned)
        {
            work.pending.push(child);
        } else if depth + 1 < DEPTH
            && let Some(record) = &node.record
            && record.last_outcome == Outcome::NoCandidate
            && !record.loop_disabled
        {
            let mut nested = next(nodes, child, depth + 1);
            if !nested.pending.is_empty() {
                // Only one failed subtree is active. Its original siblings
                // remain durable, rather than multiplying in-flight plans.
                return nested;
            }
            if nested
                .required
                .iter()
                .any(|(_, at)| *at > record.last_attempt_at)
            {
                nested.pending.push(child);
                return nested;
            }
        }
    }
    work
}
impl Frontier {
    #[cfg(test)]
    pub(crate) fn support_updates(&self) -> u64 {
        self.evidence.model().supports
    }
    pub(crate) fn loop_focus(
        &mut self,
        graph: &Graph,
        mut available: impl FnMut(&CompiledQuestion) -> bool,
    ) -> Result<Option<(CompiledQuestion, Work)>, crate::Error> {
        let mut sources = Vec::new();
        let mut children = std::collections::BTreeSet::new();
        for goal in &self.goals {
            if let Some(record) = self.evidence.get(goal)?
                && record.verified.is_none()
                && !record.loop_disabled
                && !record.helpers.is_empty()
            {
                for source in record.helpers {
                    let helper = CompiledQuestion::compile(&source).map_err(|e| e.to_string())?;
                    children.insert(*helper.resolution_id());
                }
                sources.push(goal.clone());
            }
        }
        for goal in sources {
            if !children.contains(goal.resolution_id()) {
                let work = self.loop_work(&goal, graph, &mut available)?;
                // Exhaustion parks an optional focus without deleting its
                // evidence, spending a trial or replenishing plan membership.
                if work.ready {
                    return Ok(Some((goal, work)));
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn abandon_publication(
        &mut self,
        question: &CompiledQuestion,
        job: u64,
    ) -> Result<(), crate::Error> {
        self.evidence.abandon_publication(question, job)
    }
    pub(crate) fn exhaust_helpers(
        &mut self,
        question: &CompiledQuestion,
    ) -> Result<(), crate::Error> {
        self.evidence.exhaust_helpers(question)
    }
    /// Recover a depth-two plan with at most four durably admitted helper
    /// identities per root. Checked descendants release their original parent
    /// once; failed leaves never become mathematical negative evidence.
    pub(crate) fn loop_work(
        &mut self,
        goal: &CompiledQuestion,
        graph: &Graph,
        mut available: impl FnMut(&CompiledQuestion) -> bool,
    ) -> Result<Work, crate::Error> {
        let mut memory = Vec::new();
        let mut nodes = Vec::<Node>::new();
        nodes.push(Node::load(self, goal.clone(), graph, 0, &mut memory)?);
        let mut index = 0;
        while index < nodes.len() {
            if nodes[index].depth < DEPTH && nodes[index].checked.is_none() {
                let sources = if let Some(record) = &nodes[index].record {
                    if record.loop_disabled
                        || (index > 0 && record.last_outcome != Outcome::NoCandidate)
                    {
                        Vec::new()
                    } else {
                        record.helpers.clone()
                    }
                } else if index > 0 {
                    // Invertible conjunction structure needs no failed neural
                    // attempt before exposing its exact closed prerequisites.
                    finder::conjuncts(&nodes[index].question)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|q| q.source().to_owned())
                        .collect()
                } else {
                    Vec::new()
                };
                for source in sources {
                    let helper = CompiledQuestion::compile(&source).map_err(|e| e.to_string())?;
                    if helper.formula().view().node_count_and_depth().0
                        >= nodes[index]
                            .question
                            .formula()
                            .view()
                            .node_count_and_depth()
                            .0
                        || !self.evidence.admit_loop_member(goal, &helper)?
                    {
                        continue;
                    }
                    let child = if let Some(i) = nodes
                        .iter()
                        .position(|n| n.question.resolution_id() == helper.resolution_id())
                    {
                        i
                    } else {
                        let i = nodes.len();
                        let depth = nodes[index].depth + 1;
                        nodes.push(Node::load(self, helper, graph, depth, &mut memory)?);
                        i
                    };
                    nodes[index].children.push(child);
                }
            }
            index += 1;
        }
        for node in nodes.iter_mut().skip(1) {
            // A failed intake gate is a current scheduling constraint, never
            // a negative theorem label or a permanent loss of eligibility.
            node.available = node.checked.is_some() || available(&node.question);
        }
        let choice = next(&nodes, 0, 0);
        let ready = !choice.pending.is_empty()
            || nodes[choice.target].record.as_ref().is_none_or(|record| {
                choice
                    .required
                    .iter()
                    .any(|(_, at)| *at > record.last_attempt_at)
            });
        Ok(Work {
            target: nodes[choice.target].question.clone(),
            planned: nodes.iter().skip(1).map(|n| n.question.clone()).collect(),
            pending: choice
                .pending
                .iter()
                .map(|i| nodes[*i].question.clone())
                .collect(),
            required: choice.required.into_iter().map(|(id, _)| id).collect(),
            ready,
            _memory: memory,
        })
    }
}

#[cfg(test)]
mod flat;
#[cfg(test)]
mod recursive;

#[cfg(test)]
mod tests;
