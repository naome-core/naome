//! Structural research scheduling over checked local knowledge. Scores are
//! hypotheses about useful work, never mathematical evidence or job allowances.
use crate::{Graph, jobs};
use naome_authoring::CompiledQuestion;
use naome_checker::ContextView;
use naome_foundation::{Formula, FreeVariable, Separation, graph::Node};
use naome_proof::ArtifactId;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    sync::Arc,
};

pub(crate) mod evidence;
use evidence::{Evidence, Outcome};
#[cfg(test)]
mod comparison;
#[cfg(test)]
mod tests;

const SIGNALS: usize = 32;
const SCALE: u64 = 65_536;

/// Primitive syntax and parent/child relationships, independent of spelling,
/// source names and variable names. Similarity never establishes equivalence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Features {
    counts: [u16; SIGNALS],
    nodes: u16,
    depth: u16,
    family: u16,
}
impl Features {
    pub(crate) fn of(question: &CompiledQuestion) -> Self {
        let mut counts = [0u16; SIGNALS];
        let _: Result<u8, std::convert::Infallible> = question.core().fold_graph(|node| {
            let tag = match node {
                Node::Equal(a, b) => {
                    counts[25 + usize::from(a != b)] += 1;
                    0
                }
                Node::Member(a, b) => {
                    counts[27 + usize::from(a != b)] += 1;
                    1
                }
                Node::Not(_) => 2,
                Node::Implies(..) => 3,
                Node::ForAll(_) => 4,
            };
            for child in node.children().into_iter().flatten() {
                counts[usize::from(tag) * 5 + usize::from(child)] += 1;
            }
            if tag == 4 {
                counts[29] += 1;
            }
            if tag == 3 {
                counts[30] += 1;
            }
            if tag == 2 {
                counts[31] += 1;
            }
            Ok(tag)
        });
        let (nodes, depth) = question.core().view().node_count_and_depth();
        let atoms =
            u16::from(counts[25] + counts[26] > 0) + 2 * u16::from(counts[27] + counts[28] > 0);
        let family = atoms * 16
            + counts[29].min(3) * 4
            + u16::from(counts[30] > 0)
            + 2 * u16::from(counts[31] > 0);
        Self {
            counts,
            nodes: nodes as u16,
            depth: depth as u16,
            family,
        }
    }
    fn similarity(&self, other: &Self) -> u64 {
        let (intersection, union) = self
            .counts
            .iter()
            .zip(other.counts)
            .fold((0u64, 0u64), |(a, b), (&x, y)| {
                (a + u64::from(x.min(y)), b + u64::from(x.max(y)))
            });
        intersection * SCALE / union.max(1)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Random(u64);
impl Random {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, limit: u64) -> u64 {
        let threshold = limit.wrapping_neg() % limit;
        loop {
            let value = self.next();
            if value >= threshold {
                return value % limit;
            }
        }
    }
}

#[derive(Clone, Copy)]
struct AttemptHint {
    knowledge: [u8; 32],
    last_draw: u64,
    unverified_attempts: u64,
    verified: bool,
}

pub(crate) struct Frontier {
    evidence: Evidence,
    // Bounded scheduling hints. Durable writes evict the affected entry;
    // selection still crosses the generation-checked checkpoint before work.
    recent: VecDeque<([u8; 32], Option<AttemptHint>)>,
    random: Random,
    coverage: [u64; SIGNALS],
    building: [u64; SIGNALS],
    successes: [u64; SIGNALS],
    success_units: [u64; SIGNALS],
    success_millis: [u64; SIGNALS],
    knowledge: VecDeque<Features>,
    proposals: VecDeque<CompiledQuestion>,
    predicates: VecDeque<Formula>,
    after: Option<ArtifactId>,
    _memory: Arc<crate::resources::MemoryLease>,
}
impl Frontier {
    pub(crate) fn open(
        directory: &Path,
        graph: &Graph,
        seed: u64,
        settings: jobs::RoleSettings,
    ) -> Result<Self, String> {
        let evidence = Evidence::open(directory, seed, settings)?;
        let random = Random::new(evidence.random());
        let mut local = Self {
            evidence,
            recent: VecDeque::new(),
            random,
            coverage: [0; SIGNALS],
            building: [0; SIGNALS],
            successes: [0; SIGNALS],
            success_units: [0; SIGNALS],
            success_millis: [0; SIGNALS],
            knowledge: VecDeque::new(),
            proposals: VecDeque::new(),
            predicates: VecDeque::new(),
            after: None,
            _memory: crate::resources::MemoryLease::acquire(
                crate::resources::active_limits().question_cache_bytes,
            )
            .map_err(|e| e.to_string())?,
        };
        // A durable success flag alone cannot restore demonstrated ability.
        let mut successes = [0u64; SIGNALS];
        let mut success_units = [0u64; SIGNALS];
        let mut success_millis = [0u64; SIGNALS];
        local.evidence.replay(|record| {
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
        local.success_units = success_units;
        local.success_millis = success_millis;
        Ok(local)
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
    fn retain(&mut self, question: CompiledQuestion) {
        if self
            .proposals
            .iter()
            .any(|q| q.resolution_id() == question.resolution_id())
        {
            return;
        }
        let limit = crate::resources::active_limits().question_page.min(32);
        let bytes = |questions: &VecDeque<CompiledQuestion>| {
            questions
                .iter()
                .map(|q| q.source().len() * 8 + 256)
                .sum::<usize>()
        };
        while !self.proposals.is_empty()
            && (self.proposals.len() >= limit
                || bytes(&self.proposals).saturating_add(question.source().len() * 8 + 256)
                    > crate::resources::active_limits().question_cache_bytes / 4)
        {
            self.proposals.pop_front();
        }
        if limit > 0
            && question.source().len() * 8 + 256
                <= crate::resources::active_limits().question_cache_bytes / 4
        {
            self.proposals.push_back(question);
        }
    }
    fn conjecture(&mut self, mut formula: Formula) {
        for variable in formula.free_variables() {
            formula = Formula::for_all(variable, formula);
        }
        if let Ok(question) = CompiledQuestion::compile(&format!("goal = {}", formula.to_source()))
        {
            self.retain(question);
        }
    }
    fn explore(&mut self, formula: Formula) {
        let mut open = formula.clone();
        for index in 0..naome_authoring::QUESTION_TARGET_MAX_DEPTH {
            let Some(body) = open.open_outer_universal(FreeVariable::new(index as u32)) else {
                break;
            };
            open = body;
        }
        if let Some((left, right)) = open.implication_parts() {
            self.conjecture(Formula::implies(right, left));
        }
        if !formula.free_variables().is_empty() {
            if let Some(previous) = self.predicates.back().cloned() {
                self.conjecture(Formula::implies(previous.clone(), formula.clone()));
                self.conjecture(Formula::implies(formula.clone(), previous));
            }
            let cost = formula.view().node_count_and_depth().0 * 64;
            while !self.predicates.is_empty()
                && (self.predicates.len() >= 8
                    || self
                        .predicates
                        .iter()
                        .map(|p| p.view().node_count_and_depth().0 * 64)
                        .sum::<usize>()
                        + cost
                        > crate::resources::active_limits().question_cache_bytes / 8)
            {
                self.predicates.pop_front();
            }
            if cost <= crate::resources::active_limits().question_cache_bytes / 8 {
                self.predicates.push_back(formula.clone());
            }
        }
        self.conjecture(formula.clone());
        let free = formula.free_variables();
        let next = free
            .iter()
            .map(|v| v.identifier())
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        if let Some(result) = next.checked_add(1) {
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
                self.conjecture(schema);
            }
        }
    }
    /// One bounded page per scheduling opportunity. Completed sweeps replace
    /// coverage, so new entries before the cursor appear on the next sweep.
    pub(crate) fn refresh(&mut self, graph: &Graph) -> Result<(), crate::Error> {
        crate::resources::require_work_admission()?;
        let limit = crate::resources::active_limits().id_page.min(16);
        let ids = graph.ids_page(self.after, limit)?;
        for id in &ids {
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
                let features = Features::of(&question);
                for (total, count) in self.building.iter_mut().zip(features.counts) {
                    *total = total.saturating_add(u64::from(count > 0));
                }
                self.knowledge.push_back(features);
                while self.knowledge.len() > 32 {
                    self.knowledge.pop_front();
                }
                self.explore(question.core().clone());
            } else if let Some(definition) = definition
                && let Some(certificate) =
                    graph.checked_context().definition_certificate(definition)?
                && let Ok((body, _)) = certificate.body().expand_with_node_limit(
                    graph.checked_context(),
                    naome_authoring::QUESTION_TARGET_MAX_NODES,
                )
            {
                self.explore(body);
            }
        }
        self.after = ids.last().copied();
        if ids.len() < limit {
            self.coverage = self.building;
            self.building = [0; SIGNALS];
            self.after = None;
        }
        Ok(())
    }
    pub(crate) fn candidates(&self) -> Vec<CompiledQuestion> {
        let mut candidates = (0..3)
            .filter_map(|cursor| {
                CompiledQuestion::compile(&crate::mocks::create_question(cursor)).ok()
            })
            .collect::<Vec<_>>();
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
            ability += SCALE;
            if let Some(units) = self.success_units[index].checked_div(self.successes[index]) {
                ability += SCALE;
                cost = cost.max(units);
                millis = millis.max(
                    self.success_millis[index]
                        .checked_div(self.successes[index])
                        .expect("observed solving count"),
                );
            }
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
        let mut groups: BTreeMap<u16, Vec<(usize, u64)>> = BTreeMap::new();
        for (index, question) in candidates.iter().enumerate() {
            groups
                .entry(Features::of(question).family)
                .or_default()
                .push((index, self.weight(question, graph, settings)?));
        }
        let explore = self.random.below(5) == 0;
        let family_weights = groups
            .values()
            .map(|group| {
                if explore {
                    1
                } else {
                    group.iter().map(|(_, w)| w).sum::<u64>() / group.len() as u64
                }
            })
            .collect::<Vec<_>>();
        let group_index = draw(&mut self.random, &family_weights);
        let group = groups.values().nth(group_index).expect("drawn family");
        let weights = group
            .iter()
            .map(|(_, w)| if explore { 1 } else { *w })
            .collect::<Vec<_>>();
        let index = group[draw(&mut self.random, &weights)].0;
        self.evidence.selected(self.random.0)?;
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
        self.evidence
            .attempted(question, graph.content_root(), completion, outcome)?;
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
        if let Some((units, millis)) = self.evidence.verified(question, job, root)? {
            self.demonstrated(&Features::of(question), units, millis);
        }
        self.forget_hint(question);
        Ok(())
    }
}
fn draw(random: &mut Random, weights: &[u64]) -> usize {
    let mut selected = random.below(weights.iter().sum());
    for (index, weight) in weights.iter().enumerate() {
        if selected < *weight {
            return index;
        }
        selected -= weight;
    }
    unreachable!("draw lies in total weight")
}
