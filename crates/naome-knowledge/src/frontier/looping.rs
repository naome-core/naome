//! Recoverable finite prerequisite plans, subordinate to checker and job owners.
use super::*;
pub(crate) struct Work {
    pub target: ResearchQuestion,
    pub planned: Vec<ResearchQuestion>,
    pub pending: Vec<ResearchQuestion>,
    pub required: Vec<String>,
    ready: bool,
    _memory: Vec<Arc<crate::resources::MemoryLease>>,
}
const DEPTH: usize = 2;
struct Node {
    question: ResearchQuestion,
    record: Option<evidence::Record>,
    children: Vec<usize>,
    cuts: Vec<usize>,
    checked: Option<Checked>,
    depth: usize,
    available: bool,
}
struct Checked {
    proof_id: String,
    at: u64,
    proves_requested_side: bool,
}
impl Node {
    fn load(
        frontier: &Frontier,
        question: ResearchQuestion,
        graph: &Graph,
        depth: usize,
        memory: &mut Vec<Arc<crate::resources::MemoryLease>>,
    ) -> Result<Self, crate::Error> {
        let record = frontier.evidence.get(&question)?;
        let bytes = question.to_hex().len().saturating_mul(24)
            + record.as_ref().map_or(0, |r| {
                r.helpers.iter().map(|s| s.len() * 24 + 768).sum::<usize>()
            })
            + 8192;
        memory.push(crate::resources::MemoryLease::acquire(bytes)?);
        let checked = if let Some(record) = &record
            && let Some(root) = &record.verified
            && let Some(metadata) =
                graph.describe(ArtifactId::from_bytes(crate::object::id_bytes(root)?))?
        {
            let (_, statement, target) = metadata.compile(graph.checked_context())?;
            if target.resolution_id() == question.resolution_id()
                && target.core() == question.core()
            {
                Some(Checked {
                    proof_id: metadata.proof_id,
                    at: record.verified_at,
                    proves_requested_side: statement
                        == crate::object::target_id(question.proved_target())?,
                })
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
            cuts: vec![],
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
    let node = &nodes[index];
    let last_attempt = node
        .record
        .as_ref()
        .map_or(0, |record| record.last_attempt_at);
    if let Some(checked) = node
        .cuts
        .iter()
        .filter_map(|&child| nodes[child].checked.as_ref())
        .find(|checked| checked.proves_requested_side && checked.at > last_attempt)
    {
        work.required.push((checked.proof_id.clone(), checked.at));
        return work;
    }
    for &child in &nodes[index].children {
        let alternative = nodes[index].cuts.contains(&child);
        let node = &nodes[child];
        if !node.available {
            continue;
        }
        if let Some(proof) = &node.checked {
            if !alternative {
                work.required.push((proof.proof_id.clone(), proof.at));
            }
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
            if alternative {
                return Choice {
                    target: index,
                    pending: vec![child],
                    required: vec![],
                };
            }
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
    /// Exact checked inputs available to this open goal. Question definition
    /// references retain their artifact identity through the job snapshot.
    pub(crate) fn solving_inputs(
        &self,
        graph: &Graph,
        question: &ResearchQuestion,
        planned: &[String],
    ) -> Result<(Vec<String>, crate::learning::Prerequisites), crate::Error> {
        use naome_checker::ContextView;
        use naome_proof::StatementId;
        let definitions = question.dependencies();
        if planned.is_empty() {
            let witness = |operand: &Formula| -> Result<Option<String>, crate::Error> {
                let bytes = operand
                    .encode_canonical()
                    .map_err(|error| error.to_string())?;
                let statement = StatementId::of_canonical_formula(&bytes)
                    .ok_or("checked Finder operand statement width")?;
                Ok(graph
                    .checked_context()
                    .statement_header(statement)?
                    .map(|header| crate::hex(header.proof_id().as_bytes())))
            };
            if let Some((left, right)) =
                crate::learning::conjunction_operands(question.proved_target())
                && left != right
                && left.is_closed()
                && right.is_closed()
                && let (Some(left), Some(right)) = (witness(&left)?, witness(&right)?)
            {
                let witnesses = vec![left, right];
                if let Some(inputs) = graph.solving_inputs(&witnesses, definitions)? {
                    return Ok((witnesses, inputs));
                }
            }
            if self.native
                && let Some(helper) = crate::learning::scoped_cut_question(question.proved_target())
                && let Some(id) = witness(helper.proved_target())?
            {
                let selected = vec![id];
                if let Some(inputs) = graph.solving_inputs(&selected, definitions)? {
                    return Ok((selected, inputs));
                }
            }
            let routes = crate::learning::closed_cut_routes(question.proved_target(), self.native);
            let mut witnesses = Vec::new();
            let mut best_exact = usize::MAX;
            for (antecedent, distance) in routes.exact {
                if let Some(id) = witness(&antecedent)?
                    && !witnesses.contains(&id)
                {
                    best_exact = best_exact.min(distance);
                    witnesses.push(id);
                    if witnesses.len() == 4 {
                        break;
                    }
                }
            }
            // A strictly shorter route needs just one checked witness. Extra
            // alternatives can trigger inferences that spend its allowance.
            for (antecedent, distance) in routes.quantified {
                if distance >= best_exact {
                    break;
                }
                if let Some(id) = witness(&antecedent)? {
                    let selected = vec![id];
                    if let Some(inputs) = graph.solving_inputs(&selected, definitions)? {
                        return Ok((selected, inputs));
                    }
                }
            }
            if !witnesses.is_empty()
                && let Some(inputs) = graph.solving_inputs(&witnesses, definitions)?
            {
                return Ok((witnesses, inputs));
            }
        }
        let inputs = graph
            .solving_inputs(planned, definitions)?
            .unwrap_or_default();
        Ok((planned.to_vec(), inputs))
    }

    /// Exact planned cuts for an earlier open goal. The formal owner decides
    /// whether it can already supply an independently checked local proof.
    pub(crate) fn local_cut_candidates(
        &self,
        question: &ResearchQuestion,
    ) -> Result<Vec<ResearchQuestion>, crate::Error> {
        let Some(record) = self.evidence.get(question)? else {
            return Ok(Vec::new());
        };
        if !self.native
            || record.first_unresolved_job == 0
            || record.verified.is_some()
            || record.loop_disabled
            || record.helpers.is_empty()
        {
            return Ok(Vec::new());
        }
        let routes = crate::learning::closed_cut_routes(question.proved_target(), true);
        let mut candidates = Vec::new();
        for source in record.helpers {
            let helper = ResearchQuestion::from_hex(&source)?;
            if routes.contains(helper.proved_target()) {
                candidates.push(helper);
            }
        }
        Ok(candidates)
    }

    pub(crate) fn loop_focus(
        &mut self,
        graph: &Graph,
        mut available: impl FnMut(&ResearchQuestion) -> bool,
    ) -> Result<Option<(ResearchQuestion, Work)>, crate::Error> {
        let mut sources = Vec::new();
        let mut children = std::collections::BTreeSet::new();
        for goal in &self.goals {
            if let Some(record) = self.evidence.get(goal)?
                && record.verified.is_none()
                && !record.loop_disabled
                && !record.helpers.is_empty()
            {
                for source in record.helpers {
                    let helper = ResearchQuestion::from_hex(&source).map_err(|e| e.to_string())?;
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
        question: &ResearchQuestion,
        job: u64,
    ) -> Result<(), crate::Error> {
        self.evidence.abandon_publication(question, job)
    }
    pub(crate) fn exhaust_helpers(
        &mut self,
        question: &ResearchQuestion,
    ) -> Result<(), crate::Error> {
        self.evidence.exhaust_helpers(question)
    }
    /// Recover a depth-two plan with at most four durably admitted helper
    /// identities per root. Checked descendants release their original parent
    /// once; failed leaves never become mathematical negative evidence.
    pub(crate) fn loop_work(
        &mut self,
        goal: &ResearchQuestion,
        graph: &Graph,
        mut available: impl FnMut(&ResearchQuestion) -> bool,
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
                        .map(|q| q.to_hex())
                        .collect()
                } else {
                    Vec::new()
                };
                let routes = (self.native && !sources.is_empty()).then(|| {
                    crate::learning::closed_cut_routes(nodes[index].question.proved_target(), true)
                });
                let scoped = if routes.is_some() {
                    crate::learning::scoped_cut_question(nodes[index].question.proved_target())
                } else {
                    None
                };
                for source in sources {
                    let helper = ResearchQuestion::from_hex(&source).map_err(|e| e.to_string())?;
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
                    if scoped.as_ref().is_some_and(|cut| {
                        cut.resolution_id() == nodes[child].question.resolution_id()
                    }) || routes.as_ref().is_some_and(|routes| {
                        routes.contains(nodes[child].question.proved_target())
                    }) {
                        nodes[index].cuts.push(child);
                    }
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
