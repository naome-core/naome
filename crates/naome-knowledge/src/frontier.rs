//! Structural research scheduling over checked local knowledge. Scores are
//! hypotheses about useful work, never mathematical evidence or job allowances.
use crate::{Graph, jobs};
use naome_authoring::CompiledQuestion;
use naome_checker::ContextView;
use naome_foundation::{Formula, FreeVariable, Separation};
use naome_proof::ArtifactId;
use sha2::Digest;
use std::{collections::VecDeque, path::Path, sync::Arc};

pub(crate) mod evidence;
mod finder;
use evidence::{Evidence, Outcome};
pub(crate) const PROVIDER: &str = "naome-structural-finder";
#[cfg(test)]
mod comparison;
#[cfg(test)]
mod tests;

use crate::structure::{Features, SCALE, SIGNALS};

pub(crate) use crate::sampling::Random;

#[derive(Clone, Copy)]
struct AttemptHint {
    knowledge: [u8; 32],
    last_draw: u64,
    unverified_attempts: u64,
    verified: bool,
}

pub(crate) struct Frontier {
    evidence: Evidence,
    native: bool,
    feedback: Option<crate::training::ability::Feedback>,
    solver_contract: String,
    // Bounded scheduling hints. Durable writes evict the affected entry;
    // selection still crosses the generation-checked checkpoint before work.
    recent: VecDeque<([u8; 32], Option<AttemptHint>)>,
    random: Random,
    coverage: [u64; SIGNALS],
    building: [u64; SIGNALS],
    successes: [u64; SIGNALS],
    attempts: [u64; SIGNALS],
    success_units: [u64; SIGNALS],
    success_millis: [u64; SIGNALS],
    knowledge: VecDeque<Features>,
    proposals: VecDeque<CompiledQuestion>,
    predicates: VecDeque<Formula>,
    goals: VecDeque<CompiledQuestion>,
    after: Option<ArtifactId>,
    observed_root: Option<[u8; 32]>,
    _memory: Arc<crate::resources::MemoryLease>,
}
impl Frontier {
    pub(crate) fn open(
        directory: &Path,
        graph: &Graph,
        seed: u64,
        settings: jobs::Settings,
    ) -> Result<Self, String> {
        let evidence = Evidence::open(directory, seed, settings)?;
        let random = Random::new(evidence.random());
        let mut local = Self {
            evidence,
            native: settings.native_proof_learning,
            feedback: None,
            solver_contract: jobs::solver_identity(settings),
            recent: VecDeque::new(),
            random,
            coverage: [0; SIGNALS],
            building: [0; SIGNALS],
            successes: [0; SIGNALS],
            attempts: [0; SIGNALS],
            success_units: [0; SIGNALS],
            success_millis: [0; SIGNALS],
            knowledge: VecDeque::new(),
            proposals: VecDeque::new(),
            predicates: VecDeque::new(),
            goals: VecDeque::new(),
            after: None,
            observed_root: None,
            _memory: crate::resources::MemoryLease::acquire(
                // Resident goals, proposals and returned candidate copies have
                // separate lifetimes. Reserve their bounded working sets.
                crate::resources::active_limits()
                    .question_cache_bytes
                    .saturating_mul(4)
                    .saturating_add(std::mem::size_of::<Self>())
                    .saturating_add(32 * std::mem::size_of::<Features>())
                    .saturating_add(finder::Model::memory_bytes()),
            )
            .map_err(|e| e.to_string())?,
        };
        // A durable success flag alone cannot restore demonstrated ability.
        let mut successes = [0u64; SIGNALS];
        let mut attempts = [0u64; SIGNALS];
        let mut success_units = [0u64; SIGNALS];
        let mut success_millis = [0u64; SIGNALS];
        let mut goals = VecDeque::new();
        local.evidence.replay(|record| {
            let question =
                CompiledQuestion::compile(&record.question).map_err(|e| e.to_string())?;
            if record.first_unresolved_job > 0 && record.verified.is_none() {
                Self::retain_goal(&mut goals, question.clone());
            }
            for (total, count) in attempts.iter_mut().zip(Features::of(&question).counts) {
                if count > 0 {
                    *total = total.saturating_add(record.substantive_attempts());
                }
            }
            if let Some(root) = record.verified.as_ref().or(record.prepared.as_ref()) {
                let question =
                    CompiledQuestion::compile(&record.question).map_err(|e| e.to_string())?;
                let root = ArtifactId::from_bytes(crate::object::id_bytes(root)?);
                if Self::checked_target(graph, root, &question).map_err(|e| e.to_string())? {
                    let features = Features::of(&question);
                    for index in 0..SIGNALS {
                        if features.counts[index] > 0 {
                            successes[index] = successes[index].saturating_add(1);
                            success_units[index] = success_units[index]
                                .saturating_add(u64::from(record.verified_units));
                            success_millis[index] =
                                success_millis[index].saturating_add(record.verified_ms);
                        }
                    }
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        local.successes = successes;
        local.attempts = attempts;
        local.success_units = success_units;
        local.success_millis = success_millis;
        local.goals = goals;
        // A crash may separate the resolution receipt from its utility credit.
        // Replay checked dependency edges in bounded pages; receipts make this
        // idempotent even when the last commit acknowledgement was uncertain.
        if local.native {
            let mut after = None;
            loop {
                let page = local.evidence.page(after.as_deref())?;
                if page.is_empty() {
                    break;
                }
                for (key, record) in page {
                    if let Some(root) = &record.verified
                        && record.solver == local.solver_contract
                    {
                        let root = ArtifactId::from_bytes(crate::object::id_bytes(root)?);
                        let question = CompiledQuestion::compile(&record.question)
                            .map_err(|e| e.to_string())?;
                        if Self::checked_target(graph, root, &question)
                            .map_err(|e| e.to_string())?
                        {
                            local
                                .verified(&question, graph, record.verified_job, root)
                                .map_err(|e| e.to_string())?;
                        }
                    }
                    after = Some(key);
                }
            }
        }
        Ok(local)
    }
    fn retain_goal(goals: &mut VecDeque<CompiledQuestion>, question: CompiledQuestion) {
        let limits = crate::resources::active_limits();
        let bytes = |q: &CompiledQuestion| q.source().len() * 8 + 256;
        let cost = bytes(&question);
        if limits.question_page == 0
            || cost > limits.question_cache_bytes
            || !crate::learning::State::eligible(question.source())
            || goals
                .iter()
                .any(|q| q.resolution_id() == question.resolution_id())
        {
            return;
        }
        while !goals.is_empty()
            && (goals.len() >= limits.question_page.min(8)
                || goals.iter().map(bytes).sum::<usize>() + cost > limits.question_cache_bytes)
        {
            goals.pop_front();
        }
        goals.push_back(question);
    }
    pub(crate) fn focus(&mut self, question: CompiledQuestion) {
        Self::retain_goal(&mut self.goals, question);
    }
    pub(crate) fn helpers_needed(&self, question: &CompiledQuestion) -> Result<bool, crate::Error> {
        Ok(self
            .evidence
            .get(question)?
            .is_some_and(|record| record.first_unresolved_job > 0 && record.verified.is_none()))
    }
    pub(crate) fn retain_goals(&mut self, mut open: impl FnMut(&CompiledQuestion) -> bool) {
        self.goals.retain(|q| open(q));
    }
    pub(crate) fn feedback(&mut self, feedback: Option<crate::training::ability::Feedback>) {
        if !self.native {
            return;
        }
        if let Some(current) = &feedback
            && self
                .feedback
                .as_ref()
                .is_none_or(|p| p.checkpoint != current.checkpoint)
        {
            let solver = crate::learning::digest(&(&self.solver_contract, &current.checkpoint));
            self.evidence.bind_solver(solver);
            self.recent.clear();
        }
        self.feedback = feedback;
    }
    fn checked_target(
        graph: &Graph,
        root: ArtifactId,
        question: &CompiledQuestion,
    ) -> Result<bool, crate::Error> {
        let Some(metadata) = graph.describe(root)? else {
            return Ok(false);
        };
        let (_, _, target) = metadata.compile()?;
        Ok(target.resolution_id() == question.resolution_id() && target.core() == question.core())
    }
    fn demonstrated(&mut self, features: &Features, units: u32, millis: u64) {
        for (index, _) in features
            .counts
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
        {
            self.successes[index] = self.successes[index].saturating_add(1);
            self.success_units[index] = self.success_units[index].saturating_add(u64::from(units));
            self.success_millis[index] = self.success_millis[index].saturating_add(millis);
        }
    }
    fn retain(
        &mut self,
        question: CompiledQuestion,
        eligible: &mut dyn FnMut(&CompiledQuestion) -> bool,
    ) {
        let limits = crate::resources::active_limits();
        let limit = limits.question_page.min(32);
        let budget = limits.question_cache_bytes / 4;
        let cost = question.source().len() * 8 + 256;
        // An item that cannot fit must not evict the useful resident pool.
        if limit == 0
            || cost > budget
            || self
                .proposals
                .iter()
                .any(|q| q.resolution_id() == question.resolution_id())
        {
            return;
        }
        if self.native
            && (!finder::meaningful(&question)
                || self
                    .proposals
                    .iter()
                    .any(|q| finder::key(q) == finder::key(&question)))
        {
            return;
        }
        if !eligible(&question) {
            return;
        }
        let bytes = |questions: &VecDeque<CompiledQuestion>| {
            questions
                .iter()
                .map(|q| q.source().len() * 8 + 256)
                .sum::<usize>()
        };
        while !self.proposals.is_empty()
            && (self.proposals.len() >= limit
                || bytes(&self.proposals).saturating_add(cost) > budget)
        {
            self.proposals.pop_front();
        }
        self.proposals.push_back(question);
    }
    fn conjecture(
        &mut self,
        mut formula: Formula,
        eligible: &mut dyn FnMut(&CompiledQuestion) -> bool,
    ) {
        for variable in formula.free_variables() {
            formula = Formula::for_all(variable, formula);
        }
        if let Ok(question) = CompiledQuestion::compile(&format!("goal = {}", formula.to_source()))
        {
            self.retain(question, eligible);
        }
    }
    fn open_outer(formula: &Formula) -> Option<Formula> {
        let fresh = formula
            .free_variables()
            .iter()
            .map(|v| v.identifier())
            .max()
            .unwrap_or(0)
            .checked_add(1)?;
        formula.open_outer_universal(FreeVariable::new(fresh))
    }
    fn explore(&mut self, formula: Formula, eligible: &mut dyn FnMut(&CompiledQuestion) -> bool) {
        let mut open = formula.clone();
        for _ in 0..naome_authoring::QUESTION_TARGET_MAX_DEPTH {
            let Some(body) = Self::open_outer(&open) else {
                break;
            };
            open = body;
        }
        if let Some((left, right)) = open.implication_parts() {
            self.conjecture(Formula::implies(right, left), eligible);
        }
        if !formula.free_variables().is_empty() {
            if let Some(previous) = self.predicates.back().cloned() {
                self.conjecture(
                    Formula::implies(previous.clone(), formula.clone()),
                    eligible,
                );
                self.conjecture(Formula::implies(formula.clone(), previous), eligible);
            }
            self.retain_predicate(formula.clone());
        }
        self.conjecture(formula.clone(), eligible);
        let free = formula.free_variables();
        // Binary relations expose small existence/quantifier-order questions
        // even when a whole theorem's schema wrappers do not fit the cache.
        // These are conjectures about the observed relation, not truth labels.
        if free.len() == 2 {
            let mut variables = free.iter().copied();
            let a = variables.next().expect("binary relation argument");
            let b = variables.next().expect("binary relation argument");
            self.conjecture(Formula::exists(b, formula.clone()), eligible);
            self.conjecture(Formula::exists(a, formula.clone()), eligible);
            self.conjecture(
                Formula::exists(a, Formula::for_all(b, formula.clone())),
                eligible,
            );
            self.conjecture(
                Formula::exists(b, Formula::for_all(a, formula.clone())),
                eligible,
            );
        }
        let next = free
            .iter()
            .map(|v| v.identifier())
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        if !self.native
            && let Some(result) = next.checked_add(1)
        {
            let element = free.first().copied().unwrap_or(FreeVariable::new(0));
            if let Ok(schema) = (Separation {
                predicate: formula,
                element,
                source: FreeVariable::new(next),
                result: FreeVariable::new(result),
                parameters: free.into_iter().filter(|v| *v != element).collect(),
            })
            .formula()
            {
                self.conjecture(schema, eligible);
            }
        }
    }
    fn retain_predicate(&mut self, formula: Formula) {
        let cost = formula.view().node_count_and_depth().0 * 64;
        let budget = crate::resources::active_limits().question_cache_bytes / 8;
        if cost > budget || self.predicates.contains(&formula) {
            return;
        }
        while self.predicates.len() >= 8
            || self
                .predicates
                .iter()
                .map(|p| p.view().node_count_and_depth().0 * 64)
                .sum::<usize>()
                + cost
                > budget
        {
            self.predicates.pop_front();
        }
        self.predicates.push_back(formula);
    }
    /// Mine bounded, capture-free subproblems from checked structure. Dropping
    /// a connective or opening a binder proposes a conjecture, never a theorem.
    fn explore_parts(
        &mut self,
        formula: Formula,
        eligible: &mut dyn FnMut(&CompiledQuestion) -> bool,
    ) -> Result<(), crate::Error> {
        const PARTS: usize = 16;
        let nodes = formula.view().node_count_and_depth().0;
        let _memory = crate::resources::MemoryLease::acquire(
            nodes.saturating_mul(64).saturating_mul(PARTS + 1),
        )?;
        let original = CompiledQuestion::from_formula(formula.clone())
            .ok()
            .filter(|q| q.formula().is_closed());
        let mut pending = vec![formula];
        for _ in 0..PARTS {
            let Some(part) = pending.pop() else {
                break;
            };
            if let Some(body) = Self::open_outer(&part) {
                pending.push(body);
            } else if let Some(body) = part.view().negated() {
                pending.push(body.to_owned());
            } else if let Some((left, right)) = part.implication_parts() {
                pending.push(right);
                pending.push(left);
            }
            if self.native {
                // A proved relation is universally true; wrapping it in new
                // quantifiers or relation laws creates cheap posthoc variants.
                // Keep proper relation fragments for goal-directed generation.
                if part.free_variables().len() == 2 && part.view().node_count_and_depth().0 <= 24 {
                    let mut closed = part.clone();
                    for variable in closed.free_variables().into_iter().rev() {
                        closed = Formula::for_all(variable, closed);
                    }
                    if let Ok(question) = CompiledQuestion::from_formula(closed)
                        && finder::meaningful(&question)
                        && original
                            .as_ref()
                            .is_none_or(|source| finder::key(source) != finder::key(&question))
                    {
                        self.retain_predicate(part);
                    }
                }
            } else {
                self.explore(part, eligible);
            }
        }
        Ok(())
    }
    /// Reuse eligible resident work before scanning one checked entry. Completed
    /// sweeps replace coverage; insertions before the cursor appear next sweep.
    pub(crate) fn refresh(
        &mut self,
        graph: &Graph,
        mut eligible: impl FnMut(&CompiledQuestion) -> bool,
    ) -> Result<(), crate::Error> {
        crate::resources::require_work_admission()?;
        self.proposals.retain(|question| eligible(question));
        let root = graph.content_root();
        if self.observed_root == Some(root) && !self.proposals.is_empty() {
            return Ok(());
        }
        // One checked entry per opportunity; a second ID is only lookahead.
        // Keep the state owner available for serving and accepting peer proofs.
        let limit = crate::resources::active_limits().id_page.min(2);
        let page = graph.ids_page(self.after, limit)?;
        let ids = &page[..page.len().min(1)];
        for id in ids {
            // Research uses only question-sized projections. Very large valid
            // theorems remain stored and served without materializing them here.
            let header = graph.checked_context().artifact_proof_header(*id)?;
            if let Some(header) = header
                && let Some(witness) = graph
                    .checked_context()
                    .statement_header(header.statement_id())?
                && ArtifactId::from_proof_id(witness.proof_id()) != *id
            {
                continue;
            }
            let definition = if header.is_none() {
                graph.checked_context().artifact_definition_id(*id)?
            } else {
                None
            };
            let length = if let Some(header) = header {
                header.canonical_length()
            } else if let Some(definition) = definition {
                graph
                    .checked_context()
                    .definition_canonical_length(definition)?
                    .unwrap_or(0)
            } else {
                0
            };
            if length > naome_authoring::QUESTION_SOURCE_MAX_BYTES {
                continue;
            }
            let Ok(_projection) = crate::resources::MemoryLease::acquire(length * 8 + 2048) else {
                continue;
            };
            let description = match graph.describe(*id) {
                Ok(description) => description,
                Err(error) if !error.fatal() => continue,
                Err(error) => return Err(error),
            };
            if let Some(metadata) = description {
                let (_, _, question) = metadata.compile()?;
                // A development/reserved source cannot create trainable
                // descendants through a newly spelled graph projection.
                if self.native && !crate::learning::State::eligible(question.source()) {
                    continue;
                }
                let features = Features::of(&question);
                for (total, count) in self.building.iter_mut().zip(features.counts) {
                    *total = total.saturating_add(u64::from(count > 0));
                }
                self.knowledge.push_back(features);
                while self.knowledge.len() > 32 {
                    self.knowledge.pop_front();
                }
                self.explore_parts(question.core().clone(), &mut eligible)?;
            } else if let Some(definition) = definition
                && let Some(certificate) =
                    graph.checked_context().definition_certificate(definition)?
                && let Ok((body, _)) = certificate.body().expand_with_node_limit(
                    graph.checked_context(),
                    naome_authoring::QUESTION_TARGET_MAX_NODES,
                )
            {
                self.explore_parts(body, &mut eligible)?;
            }
        }
        self.observed_root = Some(root);
        self.after = ids.last().copied();
        if page.is_empty() || (limit > 1 && page.len() == 1) {
            self.coverage = self.building;
            self.building = [0; SIGNALS];
            self.after = None;
        }
        Ok(())
    }
    pub(crate) fn goal_candidates(
        &self,
        cursor: u64,
        goal: &CompiledQuestion,
    ) -> Vec<CompiledQuestion> {
        if !crate::learning::State::eligible(goal.source()) {
            return vec![goal.clone()];
        }
        let limits = crate::resources::active_limits();
        let nodes = goal.formula().view().node_count_and_depth().0;
        let mut candidates = if let Ok(_scratch) =
            crate::resources::MemoryLease::acquire(nodes.saturating_mul(64).saturating_mul(32))
        {
            finder::for_goal(
                cursor,
                goal,
                limits.question_page,
                limits.question_cache_bytes / 2,
            )
        } else {
            Vec::new()
        };
        if !candidates
            .iter()
            .any(|q| q.resolution_id() == goal.resolution_id())
        {
            candidates.push(goal.clone());
        }
        candidates
    }
    pub(crate) fn candidates(&self, cursor: u64) -> Vec<CompiledQuestion> {
        let mut candidates = if self.native {
            let limits = crate::resources::active_limits();
            let nodes = self
                .goals
                .iter()
                .map(|q| q.formula().view().node_count_and_depth().0)
                .sum::<usize>()
                .saturating_add(
                    self.predicates
                        .iter()
                        .map(|p| p.view().node_count_and_depth().0)
                        .sum::<usize>(),
                )
                .saturating_add(32);
            let Ok(_scratch) =
                crate::resources::MemoryLease::acquire(nodes.saturating_mul(64).saturating_mul(32))
            else {
                return self.goals.iter().cloned().collect();
            };
            finder::questions(
                cursor,
                &self.predicates,
                &self.goals,
                limits.question_page,
                limits.question_cache_bytes / 2,
            )
        } else {
            (0..3)
                .filter_map(|index| {
                    CompiledQuestion::compile(&crate::mocks::create_question(index)).ok()
                })
                .collect::<Vec<_>>()
        };
        for goal in &self.goals {
            if !candidates
                .iter()
                .any(|q| q.resolution_id() == goal.resolution_id())
            {
                candidates.push(goal.clone());
            }
        }
        for question in &self.proposals {
            if !candidates
                .iter()
                .any(|q| q.resolution_id() == question.resolution_id())
            {
                candidates.push(question.clone());
            }
        }
        candidates
    }
    fn previous(
        &mut self,
        question: &CompiledQuestion,
    ) -> Result<Option<AttemptHint>, crate::Error> {
        if let Some((_, hint)) = self
            .recent
            .iter()
            .find(|(id, _)| id == question.resolution_id())
        {
            return Ok(*hint);
        }
        let hint = self
            .evidence
            .get(question)?
            .map(|record| {
                Ok::<_, crate::Error>(AttemptHint {
                    knowledge: crate::object::id_bytes(&record.knowledge)
                        .map_err(crate::Error::storage)?,
                    last_draw: record.last_draw,
                    unverified_attempts: record.unverified_attempts(),
                    verified: record.verified.is_some(),
                })
            })
            .transpose()?;
        let capacity = (crate::resources::active_limits().question_cache_bytes / 4048).min(128);
        self.recent.push_back((*question.resolution_id(), hint));
        while self.recent.len() > capacity {
            self.recent.pop_front();
        }
        Ok(hint)
    }
    fn forget_hint(&mut self, question: &CompiledQuestion) {
        self.recent.retain(|(id, _)| id != question.resolution_id());
    }
    fn weight(
        &mut self,
        question: &CompiledQuestion,
        graph: &Graph,
        settings: jobs::RoleSettings,
    ) -> Result<u64, crate::Error> {
        let features = Features::of(question);
        let mut novelty = 0u64;
        let mut ability = 0u64;
        let mut cost = u64::from(features.nodes).div_ceil(64).max(1);
        let mut millis = 1u64;
        let mut signals = 0;
        for index in 0..SIGNALS {
            if features.counts[index] == 0 {
                continue;
            }
            signals += 1;
            novelty += SCALE / self.coverage[index].saturating_add(1);
            ability += crate::training::opportunity(self.successes[index], self.attempts[index]);
            if let Some(units) = self.success_units[index].checked_div(self.successes[index]) {
                ability +=
                    crate::training::opportunity(self.successes[index], self.attempts[index]);
                cost = cost.max(units);
                millis = millis.max(
                    self.success_millis[index]
                        .checked_div(self.successes[index])
                        .expect("observed solving count"),
                );
            }
        }
        if self.native {
            ability = self
                .feedback
                .as_ref()
                .map_or(SCALE, |feedback| feedback.priority(question, 128))
                .saturating_mul(signals.max(1));
            // Native costs and abilities come from the current checkpoint view,
            // not the historical non-neural evidence replay above.
            cost = u64::from(features.nodes).div_ceil(64).max(1);
            millis = 1;
        }
        let similarity = self
            .knowledge
            .iter()
            .map(|known| features.similarity(known))
            .max()
            .unwrap_or(0);
        // Similarity is a soft penalty; novel structure in a generalization
        // still earns coverage weight and every candidate retains nonzero mass.
        let penalty = 1 + similarity * 8 / SCALE;
        let mut weight = (novelty / signals.max(1)).saturating_mul(ability / signals.max(1))
            / SCALE
            / cost.max(1)
            / penalty;
        if cost > u64::from(settings.limits.work_units) || millis > settings.limits.horizon_ms {
            weight /= 8;
        }
        if let Some(record) = self.previous(question)?
            && record.knowledge == graph.content_root()
            && !record.verified
        {
            let cooldown = 1u64 << record.unverified_attempts.min(8);
            if self.evidence.draws().saturating_sub(record.last_draw) < cooldown {
                weight /= 16;
            }
        }
        // Declared provider support is availability metadata, kept separate
        // from the independently checked observations in `successes`.
        if jobs::declared_solver_support(question, settings) {
            weight = weight.saturating_mul(8);
        }
        if self.native {
            weight = weight.saturating_mul(self.evidence.model().weight(question)) / 1024;
            let relevance = self
                .goals
                .iter()
                .filter(|goal| goal.resolution_id() != question.resolution_id())
                .map(|goal| finder::relevance(question, goal))
                .max()
                .unwrap_or(0);
            weight = weight.saturating_mul(1 + relevance.min(8) * 4);
            if !finder::meaningful(question) {
                weight /= 64;
            }
        }
        Ok(weight.max(1))
    }
    /// Draw a family first, avoiding a flood of nearly identical candidates.
    /// Twenty percent of draws explore uniformly across represented families.
    pub(crate) fn choose(
        &mut self,
        candidates: &[&CompiledQuestion],
        graph: &Graph,
        settings: jobs::RoleSettings,
        random_only: bool,
    ) -> Result<Option<usize>, crate::Error> {
        if candidates.is_empty() {
            return Ok(None);
        }
        if random_only {
            let index = self.random.below(candidates.len() as u64) as usize;
            self.evidence.selected(self.random.0)?;
            return Ok(Some(index));
        }
        let weighted = candidates
            .iter()
            .map(|question| {
                Ok((
                    Features::of(question).family,
                    self.weight(question, graph, settings)?,
                ))
            })
            .collect::<Result<Vec<_>, crate::Error>>()?;
        let index = crate::sampling::choose(&mut self.random, &weighted, random_only);
        self.evidence.selected(self.random.0)?;
        if self.native
            && let Some(feedback) = &self.feedback
        {
            crate::network::emit(
                serde_json::json!({"event":"native_curriculum_selected", "checkpoint":feedback.checkpoint,
                "feedback_revision":feedback.revision,"resolution_id":crate::hex(candidates[index].resolution_id()),
                "priority":weighted[index].1,"candidates":candidates.len(),"structural_group":crate::training::group(candidates[index])}),
            );
        }
        if self.native {
            crate::network::emit(serde_json::json!({
                "event":"finder_selected", "resolution_id":crate::hex(candidates[index].resolution_id()),
                "question":candidates[index].source(), "model_updates":self.evidence.model().updates,
                "model_weight":self.evidence.model().weight(candidates[index]), "candidates":candidates.len()
            }));
        }
        Ok(Some(index))
    }
    pub(crate) fn prepared(
        &mut self,
        question: &CompiledQuestion,
        job: u64,
        root: ArtifactId,
    ) -> Result<(), crate::Error> {
        self.evidence.prepared(question, job, root)
    }
    pub(crate) fn rejected(
        &mut self,
        question: &CompiledQuestion,
        job: u64,
    ) -> Result<(), crate::Error> {
        self.evidence.rejected(question, job)?;
        self.forget_hint(question);
        Ok(())
    }
    pub(crate) fn attempted(
        &mut self,
        question: &CompiledQuestion,
        graph: &Graph,
        completion: &jobs::Completion,
        outcome: Outcome,
    ) -> Result<(), crate::Error> {
        let new = completion.id != 0
            && self
                .evidence
                .get(question)?
                .is_none_or(|record| completion.id > record.last_job);
        let before = self.evidence.model().updates;
        self.evidence
            .attempted(question, graph.content_root(), completion, outcome)?;
        self.learning_event(question, before, false);
        if new
            && matches!(
                outcome,
                Outcome::Candidate | Outcome::NoCandidate | Outcome::Rejected
            )
        {
            for (total, count) in self.attempts.iter_mut().zip(Features::of(question).counts) {
                *total = total.saturating_add(u64::from(count > 0));
            }
            if outcome == Outcome::NoCandidate {
                if self.native {
                    self.focus(question.clone());
                } else {
                    let mut open = question.core().clone();
                    for _ in 0..naome_authoring::QUESTION_TARGET_MAX_DEPTH {
                        let Some(body) = Self::open_outer(&open) else {
                            break;
                        };
                        open = body;
                    }
                    if let Some((left, right)) = open.implication_parts() {
                        self.conjecture(left, &mut |_| true);
                        self.conjecture(right, &mut |_| true);
                    }
                }
            }
        }
        self.forget_hint(question);
        Ok(())
    }
    /// Only the locally accepted, freshly checked exact target enters ability
    /// evidence. Received proofs contribute coverage, never local solver skill.
    pub(crate) fn verified(
        &mut self,
        question: &CompiledQuestion,
        graph: &Graph,
        job: u64,
        root: ArtifactId,
    ) -> Result<(), crate::Error> {
        if !Self::checked_target(graph, root, question)? {
            return Err("research evidence lacks a checked exact solution".into());
        }
        let before = self.evidence.model().updates;
        if let Some((units, millis)) = self.evidence.verified(question, job, root)? {
            self.demonstrated(&Features::of(question), units, millis);
            self.learning_event(question, before, true);
        }
        if self.native {
            let (_, _, actual_goal) = graph
                .describe(root)?
                .ok_or("checked goal disappeared")?
                .compile()?;
            for dependency in graph.direct_dependencies(root)? {
                if let Some(lemma) = self.evidence.support(
                    question,
                    &actual_goal,
                    job,
                    root,
                    dependency,
                    |lemma| {
                        if !Self::checked_target(graph, dependency, lemma)? {
                            return Ok(None);
                        }
                        graph
                            .describe(dependency)?
                            .map(|metadata| metadata.compile().map(|(_, _, q)| q))
                            .transpose()
                    },
                )? {
                    crate::network::emit(serde_json::json!({"event":"finder_goal_supported",
                        "lemma":crate::hex(dependency.as_bytes()), "goal":crate::hex(root.as_bytes()),
                        "lemma_resolution":crate::hex(lemma.resolution_id()), "goal_resolution":crate::hex(question.resolution_id()),
                        "support_updates":self.evidence.model().supports}));
                }
            }
        }
        self.goals
            .retain(|q| q.resolution_id() != question.resolution_id());
        self.forget_hint(question);
        Ok(())
    }
    fn learning_event(&self, question: &CompiledQuestion, before: u64, resolved: bool) {
        let model = self.evidence.model();
        if self.native && model.updates > before {
            crate::network::emit(serde_json::json!({
                "event":"finder_learned", "resolution_id":crate::hex(question.resolution_id()),
                "outcome":if resolved { "checked_resolution" } else { "unresolved_search" },
                "updates":model.updates, "resolved":model.resolved, "unresolved":model.unresolved,
                "supports":model.supports,
                "model_weight":model.weight(question)
            }));
        }
    }
}
