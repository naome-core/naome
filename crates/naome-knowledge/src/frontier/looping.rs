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
    cuts: Vec<Vec<usize>>,
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
fn cut_member_can_advance(nodes: &[Node], index: usize, depth: usize) -> bool {
    let node = &nodes[index];
    if let Some(proof) = &node.checked {
        return proof.proves_requested_side;
    }
    if !node.available {
        return false;
    }
    let Some(record) = &node.record else {
        return true;
    };
    if record.last_outcome == Outcome::Candidate && !record.publication_abandoned {
        return true;
    }
    if record.last_outcome != Outcome::NoCandidate
        || record.loop_disabled
        || depth + 1 >= DEPTH
        || node.children.is_empty()
    {
        return false;
    }
    let nested = next(nodes, index, depth + 1);
    !nested.pending.is_empty()
        || nested
            .required
            .iter()
            .any(|(_, at)| *at > record.last_attempt_at)
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
    for group in &node.cuts {
        if let Some(checked) = group
            .iter()
            .map(|&child| {
                nodes[child]
                    .checked
                    .as_ref()
                    .filter(|proof| proof.proves_requested_side)
            })
            .collect::<Option<Vec<_>>>()
            && checked.iter().any(|proof| proof.at > last_attempt)
        {
            work.required = checked
                .into_iter()
                .map(|proof| (proof.proof_id.clone(), proof.at))
                .collect();
            return work;
        }
    }
    let available_cuts = node
        .cuts
        .iter()
        .filter(|group| {
            group.len() == 1
                || group
                    .iter()
                    .all(|&child| cut_member_can_advance(nodes, child, depth))
        })
        .flatten()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for &child in &node.children {
        let alternative = node.cuts.iter().flatten().any(|&cut| cut == child);
        if alternative && !available_cuts.contains(&child) {
            continue;
        }
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
                let bytes = operand.encode_canonical()?;
                let statement = StatementId::of_canonical_formula(&bytes)
                    .ok_or(crate::InputFault::FinderOperandStatementWidth)?;
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
            if self.native {
                for group in finder::cut_groups(question.proved_target()) {
                    let mut selected = Vec::new();
                    for helper in &group {
                        if let Some(id) = witness(helper.proved_target())? {
                            selected.push(id);
                        } else {
                            break;
                        }
                    }
                    if selected.len() == group.len()
                        && let Some(inputs) = graph.solving_inputs(&selected, definitions)?
                    {
                        return Ok((selected, inputs));
                    }
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
        if self.native && planned.is_empty() {
            let target = question.proved_target();
            let mut candidates = Vec::new();
            for proof in self.lemmas.offers(&lemma_index::Index::query(question)) {
                let Some(header) = graph.checked_context().proof_header(proof)? else {
                    continue;
                };
                let bytes = header.canonical_length();
                if bytes > naome_checker::question::QUESTION_BYTES {
                    continue;
                }
                let Ok(_projection) = crate::resources::MemoryLease::acquire(bytes * 8 + 2048)
                else {
                    continue;
                };
                let Some(formula) = graph.checked_context().proof_formula(header, bytes)? else {
                    continue;
                };
                let applies =
                    crate::learning::knowledge::directly_applies(target, formula.as_ref())?;
                let value = ResearchQuestion::from_formula(formula.as_ref().clone())
                    .ok()
                    .and_then(|lemma| {
                        let reuse = self
                            .evidence
                            .policy()
                            .demonstrated_reuse(lemma.resolution_id());
                        let descriptor = finder::Descriptor::of(&lemma);
                        self.research_forecast(
                            graph,
                            ResearchAction::Reuse,
                            self.evidence.model().predictions_from(&descriptor),
                            if reuse { 8 } else { 0 },
                        )
                    })
                    .map_or(0, Forecast::value);
                candidates.push((!applies, std::cmp::Reverse(value), proof));
            }
            candidates.sort_by_key(|&(indirect, value, _)| (indirect, value));
            for (_, _, proof) in candidates {
                if let Some(inputs) = graph.offered_solving_inputs(proof, definitions)? {
                    return Ok((Vec::new(), inputs));
                }
            }
        }
        let inputs = graph
            .solving_inputs(planned, definitions)?
            .unwrap_or_default();
        Ok((planned.to_vec(), inputs))
    }

    pub(crate) fn catalog_retry(
        &self,
        graph: &Graph,
        question: &ResearchQuestion,
    ) -> Result<Option<crate::jobs::CatalogSource>, crate::Error> {
        if self.paid_catalog_retry(question)? {
            crate::jobs::CatalogSource::for_local_scope(graph, question.proved_target())
        } else {
            Ok(None)
        }
    }

    pub(crate) fn planned_catalog_retry(
        &self,
        graph: &Graph,
        question: &ResearchQuestion,
        required: &[String],
    ) -> Result<Option<crate::jobs::CatalogSource>, crate::Error> {
        let [proof] = required else {
            return Ok(None);
        };
        if !question.dependencies().is_empty() || !self.paid_catalog_retry(question)? {
            return Ok(None);
        }
        let proof = naome_proof::ProofId::from_bytes(crate::object::id_bytes(proof)?);
        crate::jobs::CatalogSource::for_planned_local_scope(graph, question.proved_target(), proof)
    }

    fn paid_catalog_retry(&self, question: &ResearchQuestion) -> Result<bool, crate::Error> {
        Ok(self.native
            && self
                .evidence
                .get(question)?
                .is_some_and(|record| record.paid_open_search()))
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
                    let helper = ResearchQuestion::from_hex(&source)?;
                    children.insert(*helper.resolution_id());
                }
                sources.push(goal.clone());
            }
        }
        sources.retain(|goal| !children.contains(goal.resolution_id()));
        if self.native && sources.len() > 1 && self.feedback.is_some() {
            let mut ranked = Vec::with_capacity(sources.len());
            for goal in sources {
                let decision = self.research_decision(&goal, graph, self.research_limits, false)?;
                let value = decision.forecast.map_or(0, Forecast::value);
                let preference = self.evidence.policy().multiplier(&decision) as i64;
                ranked.push((value * preference, goal));
            }
            ranked.sort_by_key(|(weight, _)| std::cmp::Reverse(*weight));
            sources = ranked.into_iter().map(|(_, goal)| goal).collect();
        }
        for goal in sources {
            let work = self.loop_work(&goal, graph, &mut available)?;
            // Exhaustion parks an optional focus without deleting its
            // evidence, spending a trial or replenishing plan membership.
            if work.ready {
                return Ok(Some((goal, work)));
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
                let groups = if routes.is_some() {
                    finder::cut_groups(nodes[index].question.proved_target())
                } else {
                    Vec::new()
                };
                for source in sources {
                    let helper = ResearchQuestion::from_hex(&source)?;
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
                let mut incomplete = Vec::new();
                for group in groups {
                    let members = group
                        .iter()
                        .filter_map(|helper| {
                            nodes[index].children.iter().copied().find(|&child| {
                                helper.resolution_id() == nodes[child].question.resolution_id()
                            })
                        })
                        .collect::<Vec<_>>();
                    if members.len() == group.len() {
                        nodes[index].cuts.push(members);
                    } else {
                        incomplete.extend(members);
                    }
                }
                if let Some(routes) = routes {
                    let independent = nodes[index]
                        .children
                        .iter()
                        .filter(|&&child| {
                            !nodes[index].cuts.iter().flatten().any(|&cut| cut == child)
                                && routes.contains(nodes[child].question.proved_target())
                        })
                        .map(|&child| vec![child])
                        .collect::<Vec<_>>();
                    nodes[index].cuts.extend(independent);
                }
                let node = &mut nodes[index];
                node.children.retain(|child| {
                    !incomplete.contains(child)
                        || node.cuts.iter().flatten().any(|cut| cut == child)
                });
            }
            index += 1;
        }
        for node in nodes.iter_mut().skip(1) {
            // A failed intake gate is a current scheduling constraint, never
            // a negative theorem label or a permanent loss of eligibility.
            node.available = node.checked.is_some() || available(&node.question);
        }
        if nodes.len() > 2
            && let Some(frame) = self.research_frame(graph, 0)
        {
            let mut values = Vec::with_capacity(nodes.len());
            values.push(0);
            let parent = self.analyses.get(goal)?;
            for node in nodes.iter().skip(1) {
                let analysis = self.analyses.get(&node.question)?;
                let [solvable, cost, useful] =
                    self.evidence.model().predictions_from(&analysis.descriptor);
                let action = if node.checked.is_some() {
                    ResearchAction::Reuse
                } else {
                    ResearchAction::Solve
                };
                let opportunity = (quantize(useful) + analysis.relevance(&parent).min(8) * 125) / 2;
                let prior = if node.checked.is_some() {
                    1_000
                } else {
                    quantize(solvable)
                };
                let cost = node.record.as_ref().map_or(quantize(cost), |record| {
                    quantize(((record.spent_ms as f32).ln_1p() / 16.).max(cost))
                });
                values.push(frame.forecast(action, prior, opportunity, 0, cost).value());
            }
            for node in &mut nodes {
                node.children
                    .sort_by_key(|&child| std::cmp::Reverse(values[child]));
                node.cuts.sort_by_key(|members| {
                    std::cmp::Reverse(members.iter().map(|&member| values[member]).min())
                });
            }
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
