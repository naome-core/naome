//! Durable attempt observations, subordinate to the checked graph and job owner.
use super::*;
use crate::checkpoint::{Checkpoint, Update};
use serde::{Deserialize, Serialize};
mod experience;
#[cfg(test)]
pub(crate) use experience::tests::observed_completion;
const DOMAIN: &str = "naome:research-evidence";
const MARKER: &[u8] = b"naome-research-evidence\n";
const MAX_RECORD: usize = 6 * naome_checker::question::QUESTION_BYTES + 4096;
pub(crate) use crate::outcome::FinderEvidenceOutcome as Outcome;

impl Outcome {
    const fn index(self) -> usize {
        match self {
            Self::Candidate => 0,
            Self::NoCandidate => 1,
            Self::Rejected => 2,
            Self::Failed => 3,
            Self::Expired => 4,
            Self::InDoubt => 5,
        }
    }
}
#[derive(Clone, Copy)]
enum Observation {
    Resolved(u64),
    Exhausted(u64),
    CutBlocked,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    random: u64,
    draws: u64,
    observations: u64,
    model_contract: String,
    model: finder::Model,
    learning: finder::Learning,
    policy: finder::research::Policy,
    effects: crate::research_value::Effects,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Support {
    lemma: String,
    goal: String,
    resolution: String,
    first_unresolved_job: u64,
    lemma_job: u64,
    goal_job: u64,
    first_unresolved_at: u64,
    lemma_at: u64,
    goal_at: u64,
    first_reuse: bool,
    continuation: bool,
    forecast: Option<crate::research_value::Forecast>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    goal: String,
    contract: String,
    members: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub question: String,
    pub model_checkpoint: Option<String>,
    pub experience: Option<crate::learning::experience::ExperienceSummary>,
    decision: Option<ResearchDecision>,
    value_observed: Option<String>,
    contributed: bool,
    used_own_proof: bool,
    continued: bool,
    pub solver: String,
    pub knowledge: String,
    pub last_draw: u64,
    pub last_job: u64,
    pub outcomes: [u64; 6],
    pub checkpoint_attempts: u64,
    pub last_outcome: Outcome,
    pub units: u64,
    pub spent_ms: u64,
    pub verified: Option<String>,
    pub prepared: Option<String>,
    pub verified_units: u32,
    pub verified_ms: u64,
    last_units: u32,
    pub first_unresolved_job: u64,
    pub verified_job: u64,
    first_unresolved_at: u64,
    pub(super) verified_at: u64,
    pub(super) last_attempt_at: u64,
    pub supports: u64,
    pub frontier: Option<crate::learning::SearchFrontier>,
    pub helpers: Vec<String>,
    pub loop_disabled: bool,
    pub publication_abandoned: bool,
}
impl Record {
    /// A returned candidate remains unverified until its exact checked solution
    /// is durable. This is scheduling feedback, never a mathematical negative.
    pub(super) fn unverified_attempts(&self) -> u64 {
        self.outcomes
            .iter()
            .fold(0u64, |sum, n| sum.saturating_add(*n))
            .saturating_sub(u64::from(self.verified.is_some()))
    }
    pub(super) fn substantive_attempts(&self) -> u64 {
        self.outcomes[..=Outcome::Rejected.index()]
            .iter()
            .fold(0u64, |sum, n| sum.saturating_add(*n))
    }
    pub(super) fn paid_open_search(&self) -> bool {
        use crate::learning::experience::{Capacity, TerminalEvidence};

        self.last_outcome == Outcome::NoCandidate
            && self.verified.is_none()
            && self.prepared.is_none()
            && self.experience.as_ref().is_some_and(|experience| {
                let expansions = experience
                    .cost
                    .as_ref()
                    .map_or(0, |cost| cost.search_expansions);
                experience.terminal.observed_search_failure(expansions)
                    || expansions > 0
                        && matches!(
                            experience.terminal,
                            TerminalEvidence::Unsupported(Capacity::Facts | Capacity::Graph)
                        )
            })
    }
    fn validate(&self, key: &str, observations: u64) -> Result<(), crate::Error> {
        let question = ResearchQuestion::from_hex(&self.question).map_err(crate::Error::from)?;
        experience::record(&question, self)?;
        if let Some(checkpoint) = &self.value_observed {
            crate::object::id_bytes(checkpoint)?;
        }
        if let Some(decision) = &self.decision {
            decision.validate()?;
            if &decision.resolution != question.resolution_id() || self.experience.is_none() {
                return Err(crate::ResearchFailure::FinderDecisionInvalid.into());
            }
        }
        if key != record_key(&self.solver, &question) || self.last_job == 0 {
            return Err(crate::ResearchFailure::EvidenceIdentity.into());
        }
        if self.helpers.len() > 4
            || self.helpers.iter().map(String::len).sum::<usize>()
                > 4 * (2 * naome_checker::question::QUESTION_BYTES)
        {
            return Err(crate::ResearchFailure::EvidenceHelperCapacity.into());
        }
        if let Some(frontier) = &self.frontier {
            frontier.validate(&question)?;
        }
        for source in &self.helpers {
            let helper = ResearchQuestion::from_hex(source).map_err(crate::Error::from)?;
            if helper.resolution_id() == question.resolution_id()
                || !crate::learning::State::eligible(source)
                || !crate::learning::State::eligible(&question.to_hex())
            {
                return Err(crate::ResearchFailure::EvidenceHelperSource.into());
            }
        }
        crate::object::id_bytes(&self.knowledge)?;
        crate::object::id_bytes(&self.solver)?;
        if let Some(checkpoint) = &self.model_checkpoint {
            crate::object::id_bytes(checkpoint)?;
        }
        for root in [&self.verified, &self.prepared].into_iter().flatten() {
            crate::object::id_bytes(root)?;
        }
        if self.checkpoint_attempts == 0
            || self.checkpoint_attempts
                > self
                    .outcomes
                    .iter()
                    .copied()
                    .fold(0u64, u64::saturating_add)
            || self.first_unresolved_job > self.last_job
            || self.verified_job > self.last_job
            || self.verified.is_some() != (self.verified_job > 0)
            || (self.first_unresolved_job > 0) != (self.first_unresolved_at > 0)
            || self.verified.is_some() != (self.verified_at > 0)
            || self.verified.is_none()
                && (self.contributed || self.used_own_proof || self.continued)
            || self.continued && (!self.contributed || !self.used_own_proof)
            || self.first_unresolved_at > observations
            || self.verified_at > observations
            || self.last_attempt_at > observations
            || self.prepared.is_some() && self.last_outcome != Outcome::Candidate
            || self.verified_units as u64 > self.units
            || self.last_units as u64 > self.units
        {
            return Err(crate::ResearchFailure::EvidenceOutcome.into());
        }
        Ok(())
    }
}
fn record_key(solver: &str, question: &ResearchQuestion) -> String {
    let mut hash = sha2::Sha256::new();
    hash.update(solver.as_bytes());
    hash.update(question.resolution_id());
    crate::hex(&hash.finalize())
}
pub(super) struct Evidence {
    checkpoint: Checkpoint,
    header: Header,
    solver: String,
    native: bool,
}
pub(super) struct EvidencePage {
    pub(super) records: Vec<(String, Record)>,
    _overflow: Option<Arc<crate::resources::MemoryLease>>,
}

impl Evidence {
    pub(super) fn open(
        directory: &Path,
        seed: u64,
        settings: jobs::Settings,
    ) -> Result<Self, crate::Error> {
        let directory = crate::storage::research_directory(directory)?;
        let path = directory.join("evidence.sqlite3");
        let marker = directory.join("evidence.initialized");
        let solver = jobs::solver_identity(settings);
        let checkpoint = if path.exists() {
            Checkpoint::open_for_replay(&path, DOMAIN)?
        } else {
            if crate::storage::marker_valid(&marker, MARKER)? {
                return Err(crate::ResearchFailure::EvidenceMissing.into());
            }
            Checkpoint::create(
                &path,
                DOMAIN,
                &Header {
                    random: seed.max(1),
                    draws: 0,
                    observations: 0,
                    model_contract: solver.clone(),
                    model: finder::Model::fresh(),
                    learning: finder::Learning::fresh(solver.clone()),
                    policy: finder::research::Policy::default(),
                    effects: Default::default(),
                },
                vec![],
            )?
        };
        let mut header: Header = checkpoint.header()?;
        if header.random == 0 {
            return Err(crate::ResearchFailure::EvidenceRandomState.into());
        }
        crate::object::id_bytes(&header.model_contract)?;
        header.model.validate()?;
        header.learning.validate()?;
        header.policy.validate()?;
        header.effects.validate()?;
        if header.observations < header.model.updates
            || header.learning.utility_current() && header.model.utility_observations == 0
        {
            return Err(crate::ResearchFailure::EvidenceObservationSequence.into());
        }
        if header.model_contract != solver {
            header.model_contract = solver.clone();
            header.model = finder::Model::fresh();
            header.learning = finder::Learning::fresh(solver.clone());
            header.policy = finder::research::Policy::default();
            header.effects = Default::default();
        }
        checkpoint.require_kinds(&["question", "proved", "support", "plan"])?;
        if !crate::storage::marker_valid(&marker, MARKER)? {
            crate::storage::write_marker(&marker, MARKER)?;
        }
        Ok(Self {
            checkpoint,
            header,
            solver,
            native: settings.native_proof_learning,
        })
    }
    pub(super) fn model(&self) -> &finder::Model {
        &self.header.model
    }
    pub(super) fn effects(&self) -> &crate::research_value::Effects {
        &self.header.effects
    }
    pub(super) fn policy(&self) -> &finder::research::Policy {
        &self.header.policy
    }
    pub(super) fn learning(&self) -> &finder::Learning {
        &self.header.learning
    }
    #[cfg(test)]
    pub(super) fn initial_parameters(&mut self, seed: u64) -> Result<(), crate::Error> {
        if self.header.observations != 0
            || self.header.draws != 0
            || self.header.model.updates != 0
            || self.header.model.rehearsals != 0
            || self.header.model.utility_observations != 0
        {
            return Err(crate::ResearchFailure::EvidenceInitialization.into());
        }
        let mut header = self.header.clone();
        header.model = finder::Model::seeded(seed);
        self.commit(&header, vec![])?;
        self.header = header;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn freeze_parameters(&mut self) {
        self.header.model.freeze();
    }
    #[cfg(test)]
    pub(super) fn treatment(&mut self, treatment: crate::frontier::Treatment) {
        self.header.learning.treatment = treatment;
    }
    pub(super) fn feedback(
        &mut self,
        graph: &Graph,
        feedback: &crate::training::ability::Feedback,
    ) -> Result<(), crate::Error> {
        let mut next = self.header.clone();
        let rebound = next.effects.bind(&feedback.checkpoint);
        if next.learning.feedback(&mut next.model, feedback, |score| {
            self.utility_source(graph, score)
        })? || rebound
        {
            next.learning.validate()?;
            self.commit(&next, vec![])?;
            self.header = next;
        }
        Ok(())
    }
    fn utility_source(
        &self,
        graph: &Graph,
        score: &crate::learning::finder::Score,
    ) -> Result<Option<ResearchQuestion>, crate::Error> {
        let proof = naome_proof::ProofId::from_bytes(crate::object::id_bytes(&score.proof)?);
        let root = ArtifactId::from_proof_id(proof);
        let Some((_, producer)) = self.proof_source(&crate::hex(root.as_bytes()))? else {
            return Ok(None);
        };
        let question = ResearchQuestion::from_hex(&producer.question)?;
        if question.resolution_id() != &crate::object::id_bytes(&score.resolution)? {
            return Err(crate::ResearchFailure::FinderUtilityIdentity.into());
        }
        Ok(Frontier::checked_target(graph, root, &question)?.then_some(question))
    }
    fn proof_source(&self, root: &str) -> Result<Option<(String, Record)>, crate::Error> {
        let Some(key) = self.checkpoint.get::<String>("proved", root, 128)? else {
            return Ok(None);
        };
        let record = self
            .checkpoint
            .get::<Record>("question", &key, MAX_RECORD)?
            .ok_or(crate::ResearchFailure::EvidenceProofSourceMissing)?;
        record.validate(&key, self.header.observations)?;
        if record.verified.as_deref() != Some(root) {
            return Err(crate::ResearchFailure::EvidenceProofIdentity.into());
        }
        Ok(Some((key, record)))
    }
    pub(super) fn random(&self) -> u64 {
        self.header.random
    }
    pub(super) fn draws(&self) -> u64 {
        self.header.draws
    }
    pub(super) fn replay(
        &mut self,
        mut visit: impl FnMut(&Record) -> Result<bool, crate::Error>,
    ) -> Result<(), crate::Error> {
        let mut after = None;
        loop {
            let page = self.page(after.as_deref())?;
            if page.records.is_empty() {
                return Ok(());
            }
            for (key, mut record) in page.records {
                if record.solver == self.solver && visit(&record)? && record.verified.is_none() {
                    record.verified = record.prepared.clone();
                    record.verified_job = record.last_job;
                    let question = ResearchQuestion::from_hex(&record.question)?;
                    self.put_observation(
                        &question,
                        &record,
                        Some(Observation::Resolved(record.verified_ms)),
                    )?;
                }
                after = Some(key);
            }
        }
    }
    pub(super) fn get(&self, question: &ResearchQuestion) -> Result<Option<Record>, crate::Error> {
        let key = record_key(&self.solver, question);
        let record: Option<Record> = self.checkpoint.get("question", &key, MAX_RECORD)?;
        if let Some(record) = &record {
            record.validate(&key, self.header.observations)?;
        }
        Ok(record)
    }
    pub(super) fn page(&self, after: Option<&str>) -> Result<EvidencePage, crate::Error> {
        self.page_with_budget(
            after,
            crate::resources::active_limits().question_cache_bytes,
        )
    }

    fn page_with_budget(
        &self,
        after: Option<&str>,
        bytes: usize,
    ) -> Result<EvidencePage, crate::Error> {
        // A profile change may make a formerly admitted record larger than
        // the bulk page. Keep the bulk budget and lease one canonical record
        // through decoding and replay. The key and row overhead are bounded.
        const SINGLE_RECORD_PAGE: usize = MAX_RECORD + 256;
        let (rows, overflow) = match self.checkpoint.page("question", after, 16, bytes) {
            Ok(rows) => (rows, None),
            Err(crate::Error::InputFault(
                crate::InputFault::CheckpointRecordReadLimit
                | crate::InputFault::CheckpointPageMemoryLimit,
            )) if bytes < SINGLE_RECORD_PAGE => {
                let lease = crate::resources::MemoryLease::acquire(4 * SINGLE_RECORD_PAGE)?;
                let rows = self
                    .checkpoint
                    .page("question", after, 1, SINGLE_RECORD_PAGE)?;
                (rows, Some(lease))
            }
            Err(error) => return Err(error),
        };
        let records = rows
            .into_iter()
            .map(|(key, bytes)| {
                if bytes.len() > MAX_RECORD {
                    return Err(crate::InputFault::CheckpointRecordReadLimit.into());
                }
                let record: Record = crate::checkpoint::decode(&bytes)?;
                record.validate(&key, self.header.observations)?;
                Ok((key, record))
            })
            .collect::<Result<_, crate::Error>>()?;
        Ok(EvidencePage {
            records,
            _overflow: overflow,
        })
    }
    pub(super) fn selected(&mut self, random: u64) -> Result<(), crate::Error> {
        self.select(random, None)
    }
    pub(super) fn selected_question(
        &mut self,
        random: u64,
        question: &ResearchQuestion,
        recipe: Option<finder::Recipe>,
    ) -> Result<(), crate::Error> {
        self.select(random, Some((question, recipe)))
    }
    fn select(
        &mut self,
        random: u64,
        question: Option<(&ResearchQuestion, Option<finder::Recipe>)>,
    ) -> Result<(), crate::Error> {
        let mut next = Header {
            random,
            draws: self
                .header
                .draws
                .checked_add(1)
                .ok_or(crate::ResearchFailure::EvidenceDrawOverflow)?,
            ..self.header.clone()
        };
        if let Some((question, recipe)) = question {
            next.learning.selected(question, recipe);
        }
        self.commit(&next, vec![])?;
        self.header = next;
        Ok(())
    }
    fn commit(&mut self, header: &Header, updates: Vec<Update>) -> Result<(), crate::Error> {
        let needed = updates
            .iter()
            .map(|update| match update {
                Update::Put { payload, .. } => payload.len() as u64,
                _ => 0,
            })
            .sum::<u64>()
            .saturating_add(crate::checkpoint::encode(header)?.len() as u64)
            .saturating_add(8192)
            .saturating_add(crate::checkpoint::encode(header)?.len() as u64 * 3);
        let _disk = crate::resources::DiskLease::acquire(self.checkpoint.directory(), needed)?;
        self.checkpoint
            .commit(header, updates)
            .map_err(crate::Error::from)
    }
    fn put(&mut self, question: &ResearchQuestion, record: &Record) -> Result<(), crate::Error> {
        self.put_observation(question, record, None)
    }
    fn put_observation(
        &mut self,
        question: &ResearchQuestion,
        record: &Record,
        observation: Option<Observation>,
    ) -> Result<(), crate::Error> {
        let mut header = self.header.clone();
        let mut record = record.clone();
        let mut effect = None;
        if let Some(observation) = observation {
            header.observations = header
                .observations
                .checked_add(1)
                .ok_or(crate::ResearchFailure::EvidenceObservationOverflow)?;
            if matches!(observation, Observation::Resolved(_)) {
                if record.verified_at == 0 {
                    record.verified_at = header.observations;
                }
            } else if record.first_unresolved_at == 0 {
                record.first_unresolved_at = header.observations;
            }
            let label = match observation {
                Observation::Resolved(millis) => Some((true, millis)),
                Observation::Exhausted(millis) => Some((false, millis)),
                Observation::CutBlocked => None,
            };
            if let Some((resolved, millis)) = label
                && crate::learning::State::eligible(&question.to_hex())
            {
                if let (Some(decision), Some(experience)) = (&record.decision, &record.experience) {
                    header.policy.observe(decision, experience, resolved)?;
                    if let Some(forecast) = decision.forecast
                        && record.value_observed.as_ref() != Some(&experience.checkpoint)
                        && header.effects.observe(
                            forecast,
                            &decision.resolution,
                            &experience.checkpoint,
                            resolved,
                            millis,
                        )
                    {
                        record.value_observed = Some(experience.checkpoint.clone());
                        effect = Some((forecast, resolved, millis));
                    }
                }
                header
                    .learning
                    .observe(&mut header.model, question, resolved, millis)?;
                let checkpoint = record
                    .model_checkpoint
                    .as_deref()
                    .or((!self.native).then_some(header.model_contract.as_str()));
                header.learning.remember(
                    &mut header.model,
                    question,
                    checkpoint,
                    resolved,
                    millis,
                    header.draws,
                )?;
            }
        }
        let key = record_key(&self.solver, question);
        let mut updates = vec![Update::put("question", &key, &record)?];
        if let Some(root) = &record.verified
            && self
                .checkpoint
                .get::<String>("proved", root, 128)?
                .is_none()
        {
            updates.push(Update::put("proved", root, &key)?);
        }
        self.commit(&header, updates)?;
        self.header = header;
        if let Some((forecast, checked, spent_ms)) = effect {
            crate::network::emit(serde_json::json!({
                "event":crate::outcome::NodeEvent::ResearchValueObserved, "job":record.last_job,
                "resolution_id":crate::hex(question.resolution_id()), "forecast":forecast,
                "checked":checked, "spent_ms":spent_ms,
            }));
        }
        Ok(())
    }
    pub(super) fn attempted(
        &mut self,
        question: &ResearchQuestion,
        knowledge: [u8; 32],
        completion: &jobs::Completion,
        outcome: Outcome,
    ) -> Result<bool, crate::Error> {
        if completion.id == 0 {
            return Ok(false);
        }
        let experience = experience::completion(question, completion, outcome)?;
        // Evidence is keyed by the expanded resolution and must be replayable
        // without depending on a node's mutable definition context.
        let evidence_question = ResearchQuestion::from_formula(question.formula().clone())
            .map_err(crate::Error::from)?;
        let mut record = self.get(question)?.unwrap_or(Record {
            question: evidence_question.to_hex(),
            model_checkpoint: None,
            experience: None,
            decision: None,
            value_observed: None,
            contributed: false,
            used_own_proof: false,
            continued: false,
            solver: self.solver.clone(),
            knowledge: crate::hex(&knowledge),
            last_draw: 0,
            last_job: 0,
            outcomes: [0; 6],
            checkpoint_attempts: 0,
            last_outcome: outcome,
            units: 0,
            spent_ms: 0,
            verified: None,
            prepared: None,
            verified_units: 0,
            verified_ms: 0,
            last_units: 0,
            first_unresolved_job: 0,
            verified_job: 0,
            first_unresolved_at: 0,
            verified_at: 0,
            last_attempt_at: 0,
            supports: 0,
            frontier: None,
            helpers: Vec::new(),
            loop_disabled: false,
            publication_abandoned: false,
        });
        if completion.id <= record.last_job {
            if completion.id == record.last_job
                && let (Some(incoming), Some(stored)) = (experience, &record.experience)
                && incoming.receipt != stored.receipt
            {
                return Err(crate::ResearchFailure::EvidenceCompletedReceipt.into());
            }
            return Ok(false);
        }
        let knowledge_changed = record.knowledge != crate::hex(&knowledge);
        record.knowledge = crate::hex(&knowledge);
        record.last_draw = self.header.draws;
        record.last_job = completion.id;
        if record.model_checkpoint != completion.model_checkpoint {
            record.checkpoint_attempts = 0;
        }
        record.checkpoint_attempts = record
            .checkpoint_attempts
            .checked_add(1)
            .ok_or(crate::ResearchFailure::EvidenceAttemptOverflow)?;
        record.model_checkpoint = completion.model_checkpoint.clone();
        record.experience = experience.cloned();
        record.decision = experience.and_then(|_| completion.binding.research.as_deref().cloned());
        record.last_outcome = outcome;
        record.outcomes[outcome.index()] = record.outcomes[outcome.index()]
            .checked_add(1)
            .ok_or(crate::ResearchFailure::EvidenceAttemptOverflow)?;
        record.units = record
            .units
            .checked_add(u64::from(completion.reserved_units))
            .ok_or(crate::ResearchFailure::EvidenceWorkOverflow)?;
        record.spent_ms = record
            .spent_ms
            .checked_add(completion.spent_ms)
            .ok_or(crate::ResearchFailure::EvidenceTimeOverflow)?;
        record.last_units = completion.reserved_units;
        record.prepared = None;
        record.publication_abandoned = false;
        if record.verified.is_none() {
            record.verified_units = record.last_units;
            record.verified_ms = completion.spent_ms;
        }
        use crate::learning::experience::{Capacity, TerminalEvidence};
        let completed_open =
            completion.state == jobs::State::Complete && outcome == Outcome::NoCandidate;
        let expansions = experience
            .and_then(|summary| summary.cost.as_ref())
            .map_or(0, |cost| cost.search_expansions);
        let exhausted = completed_open
            && (!self.native
                || experience
                    .is_some_and(|summary| summary.terminal.observed_search_failure(expansions)));
        let cut_blocked = self.native
            && completed_open
            && expansions > 0
            && experience.is_some_and(|summary| {
                matches!(
                    summary.terminal,
                    TerminalEvidence::Unsupported(Capacity::Facts | Capacity::Graph)
                )
            });
        let eligible =
            (exhausted || cut_blocked) && crate::learning::State::eligible(&question.to_hex());
        let bytes = crate::resources::active_limits().question_cache_bytes / 2;
        let mut candidates =
            if self.native && eligible && !record.loop_disabled && record.helpers.len() < 4 {
                let existing = record
                    .helpers
                    .iter()
                    .map(|source| ResearchQuestion::from_hex(source))
                    .collect::<Result<Vec<_>, _>>()?;
                finder::cut_helpers(question, &existing, 4, bytes)
            } else {
                Vec::new()
            };
        let catalog_sources =
            if cut_blocked && eligible && !record.loop_disabled && candidates.is_empty() {
                finder::catalog_cut_sources(question, &record.helpers, 4, bytes)
            } else {
                Vec::new()
            };
        // Capacity limits can motivate an exact decomposition. They establish
        // chronology for checked downstream use without training a miss.
        let observation = if exhausted {
            Some(Observation::Exhausted(completion.spent_ms))
        } else if cut_blocked
            && (!candidates.is_empty()
                || !catalog_sources.is_empty()
                || record.first_unresolved_job > 0 && !record.helpers.is_empty())
        {
            Some(Observation::CutBlocked)
        } else {
            None
        };
        record.last_attempt_at = self
            .header
            .observations
            .checked_add(u64::from(observation.is_some()))
            .ok_or(crate::ResearchFailure::EvidenceObservationOverflow)?;
        if exhausted
            && eligible
            && (record.frontier.is_none() || knowledge_changed)
            && let Ok(jobs::Output::Native {
                frontier: Some(frontier),
                ..
            }) = &completion.result
        {
            frontier.validate(question)?;
            candidates.extend(finder::from_frontier(question, frontier, 4, bytes));
            record.frontier = Some(frontier.clone());
        }
        record.helpers.extend(catalog_sources);
        for helper in candidates {
            if record.helpers.len() >= 4 {
                break;
            }
            if !record.helpers.iter().any(|source| {
                ResearchQuestion::from_hex(source)
                    .is_ok_and(|q| q.resolution_id() == helper.resolution_id())
            }) {
                record.helpers.push(helper.to_hex());
            }
        }
        if observation.is_some() && record.first_unresolved_job == 0 {
            record.first_unresolved_job = completion.id;
        }
        self.put_observation(question, &record, observation)?;
        Ok(observation.is_some())
    }
    pub(super) fn abandon_publication(
        &mut self,
        question: &ResearchQuestion,
        job: u64,
    ) -> Result<(), crate::Error> {
        if let Some(mut record) = self.get(question)?
            && record.last_job == job
            && record.verified.is_none()
        {
            record.publication_abandoned = true;
            self.put(question, &record)?;
        }
        Ok(())
    }
    /// Admission is durable before scheduling, so reopening cannot replenish a
    /// root's four-question allowance or replace previously attempted members.
    pub(super) fn admit_loop_member(
        &mut self,
        goal: &ResearchQuestion,
        helper: &ResearchQuestion,
    ) -> Result<bool, crate::Error> {
        let Some(record) = self.get(goal)? else {
            return Ok(false);
        };
        if record.loop_disabled || helper.resolution_id() == goal.resolution_id() {
            return Ok(false);
        }
        let mut members = self.plan_members(goal)?;
        let id = crate::hex(helper.resolution_id());
        if members.contains(&id) {
            return Ok(true);
        }
        if members.len() == 4 {
            return Ok(false);
        }
        members.push(id);
        let key = record_key(&self.header.model_contract, goal);
        let plan = Plan {
            goal: crate::hex(goal.resolution_id()),
            contract: self.header.model_contract.clone(),
            members,
        };
        let header = self.header.clone();
        self.commit(&header, vec![Update::put("plan", &key, &plan)?])?;
        Ok(true)
    }
    pub(super) fn plan_members(
        &self,
        goal: &ResearchQuestion,
    ) -> Result<Vec<String>, crate::Error> {
        let key = record_key(&self.header.model_contract, goal);
        let Some(plan): Option<Plan> = self.checkpoint.get("plan", &key, 1024)? else {
            return Ok(Vec::new());
        };
        if plan.goal != crate::hex(goal.resolution_id())
            || plan.contract != self.header.model_contract
            || plan.members.len() > 4
            || plan
                .members
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != plan.members.len()
        {
            return Err(crate::ResearchFailure::EvidencePlanBinding.into());
        }
        for id in &plan.members {
            if crate::object::id_bytes(id)? == *goal.resolution_id() {
                return Err(crate::ResearchFailure::EvidencePlanCycle.into());
            }
        }
        Ok(plan.members)
    }
    pub(super) fn exhaust_helpers(
        &mut self,
        question: &ResearchQuestion,
    ) -> Result<(), crate::Error> {
        if let Some(mut record) = self.get(question)? {
            record.loop_disabled = true;
            self.put(question, &record)?;
        }
        Ok(())
    }
    pub(super) fn prepared(
        &mut self,
        question: &ResearchQuestion,
        job: u64,
        root: ArtifactId,
    ) -> Result<(), crate::Error> {
        let Some(mut record) = self.get(question)? else {
            return Ok(());
        };
        if record.last_job != job {
            return Err(crate::ResearchFailure::EvidencePreparedJob.into());
        }
        if record.last_outcome != Outcome::Candidate {
            return Err(crate::ResearchFailure::EvidenceCandidateRequired.into());
        }
        record.prepared = Some(crate::hex(root.as_bytes()));
        self.put(question, &record)
    }
    pub(super) fn rejected(
        &mut self,
        question: &ResearchQuestion,
        job: u64,
    ) -> Result<(), crate::Error> {
        let Some(mut record) = self.get(question)? else {
            return Ok(());
        };
        if record.last_job != job || record.last_outcome == Outcome::Rejected {
            return Ok(());
        }
        record.last_outcome = Outcome::Rejected;
        record.prepared = None;
        record.outcomes[Outcome::Candidate.index()] =
            record.outcomes[Outcome::Candidate.index()].saturating_sub(1);
        record.outcomes[Outcome::Rejected.index()] =
            record.outcomes[Outcome::Rejected.index()].saturating_add(1);
        self.put(question, &record)
    }
    pub(super) fn verified(
        &mut self,
        question: &ResearchQuestion,
        job: u64,
        root: ArtifactId,
    ) -> Result<Option<(u32, u64)>, crate::Error> {
        let Some(mut record) = self.get(question)? else {
            return Ok(None);
        };
        if record.last_job != job || record.verified.is_some() {
            return Ok(None);
        }
        if record.last_outcome != Outcome::Candidate
            || record.prepared.as_deref() != Some(crate::hex(root.as_bytes()).as_str())
        {
            return Err(crate::InputFault::EvidenceCandidateBinding.into());
        }
        record.verified = Some(crate::hex(root.as_bytes()));
        record.verified_job = job;
        record.verified_units = record.last_units;
        self.put_observation(
            question,
            &record,
            Some(Observation::Resolved(record.verified_ms)),
        )?;
        Ok(Some((record.verified_units, record.verified_ms)))
    }

    pub(super) fn support_consumer(
        &self,
        goal: &ResearchQuestion,
        job: u64,
        root: ArtifactId,
    ) -> Result<Option<Record>, crate::Error> {
        if !crate::learning::State::eligible(&goal.to_hex()) {
            return Ok(None);
        }
        Ok(self.get(goal)?.filter(|consumer| {
            consumer.last_job == job
                && consumer.verified.as_deref() == Some(crate::hex(root.as_bytes()).as_str())
        }))
    }

    /// Attribute exact downstream reuse once. A dependency that appeared
    /// during an earlier open goal also supplies delayed Finder support.
    pub(super) fn support(
        &mut self,
        goal: &ResearchQuestion,
        actual_goal: &ResearchQuestion,
        consumer: &mut Record,
        root: ArtifactId,
        dependency: ArtifactId,
        mut checked: impl FnMut(&ResearchQuestion) -> Result<Option<ResearchQuestion>, crate::Error>,
    ) -> Result<Option<ResearchQuestion>, crate::Error> {
        let lemma = crate::hex(dependency.as_bytes());
        let Some((key, mut producer)) = self.proof_source(&lemma)? else {
            return Ok(None);
        };
        // Job IDs are allocated before execution; concurrent completions may
        // arrive in another order. Only durable observations establish timing.
        let delayed =
            consumer.first_unresolved_at > 0 && consumer.first_unresolved_at < producer.verified_at;
        let decision = producer
            .decision
            .as_ref()
            .zip(producer.experience.as_ref())
            .filter(|(_, experience)| experience.job == producer.verified_job);
        if producer.verified_at >= consumer.verified_at || !delayed && decision.is_none() {
            return Ok(None);
        }
        let question =
            ResearchQuestion::from_hex(&producer.question).map_err(crate::Error::from)?;
        let Some(actual_lemma) = checked(&question)? else {
            return Ok(None);
        };
        if !finder::independent_goal(&actual_lemma, actual_goal) {
            return Ok(None);
        }
        let resolution = crate::hex(goal.resolution_id());
        let receipt_key = crate::hex(&sha2::Sha256::digest(
            [dependency.as_bytes().as_slice(), goal.resolution_id()].concat(),
        ));
        if let Some(receipt) = self
            .checkpoint
            .get::<Support>("support", &receipt_key, 4096)?
        {
            crate::object::id_bytes(&receipt.goal)?;
            if let Some(forecast) = receipt.forecast {
                forecast.validate()?;
            }
            if receipt.lemma != lemma
                || receipt.resolution != resolution
                || (receipt.first_unresolved_job == 0) != (receipt.first_unresolved_at == 0)
                || receipt.lemma_job == 0
                || receipt.goal_job == 0
                || receipt.first_unresolved_at >= receipt.goal_at
                || receipt.lemma_at >= receipt.goal_at
                || receipt.goal_at > self.header.observations
            {
                return Err(crate::ResearchFailure::EvidenceSupportReceipt.into());
            }
            return Ok(None);
        }
        let mut header = self.header.clone();
        header.observations = header
            .observations
            .checked_add(1)
            .ok_or(crate::ResearchFailure::EvidenceObservationOverflow)?;
        if crate::learning::State::eligible(&question.to_hex()) {
            if delayed {
                header.model.support(&question)?;
                header.learning.support(&mut header.model, &question)?;
            }
            if let Some((decision, experience)) = decision {
                header.policy.reused(decision, experience)?;
            }
        }
        if delayed {
            producer.supports = producer
                .supports
                .checked_add(1)
                .ok_or(crate::ResearchFailure::EvidenceSupportOverflow)?;
        }
        let forecast = decision.and_then(|(decision, experience)| {
            decision
                .forecast
                .map(|forecast| (forecast, experience.checkpoint.as_str()))
        });
        let first_reuse = !producer.contributed;
        let continuation = producer.used_own_proof && !producer.continued;
        header.effects.reuse(forecast, first_reuse, continuation);
        let forecast = forecast.map(|(forecast, _)| forecast);
        producer.contributed = true;
        producer.continued |= continuation;
        let consumer_update = if consumer.used_own_proof {
            None
        } else {
            let mut updated = consumer.clone();
            updated.used_own_proof = true;
            Some(updated)
        };
        let receipt = Support {
            lemma,
            goal: crate::hex(root.as_bytes()),
            resolution,
            first_unresolved_job: consumer.first_unresolved_job,
            lemma_job: producer.verified_job,
            goal_job: consumer.verified_job,
            first_unresolved_at: consumer.first_unresolved_at,
            lemma_at: producer.verified_at,
            goal_at: consumer.verified_at,
            first_reuse,
            continuation,
            forecast,
        };
        let mut updates = vec![
            Update::put("question", key, &producer)?,
            Update::put("support", receipt_key, &receipt)?,
        ];
        if let Some(updated) = &consumer_update {
            updates.push(Update::put(
                "question",
                record_key(&self.solver, goal),
                updated,
            )?);
        }
        self.commit(&header, updates)?;
        self.header = header;
        if let Some(updated) = consumer_update {
            *consumer = updated;
        }
        if first_reuse || continuation {
            crate::network::emit(serde_json::json!({
                "event":crate::outcome::NodeEvent::ResearchValueObserved, "job":receipt.goal_job,
                "forecast":forecast, "producer":receipt.lemma, "consumer":receipt.goal,
                "first_reuse":first_reuse, "continuation":continuation,
            }));
        }
        Ok(delayed.then_some(question))
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn evidence_identity_failure_has_registered_code() {
        let directory = crate::checkpoint::tests::Directory::new();
        let question = ResearchQuestion::from_hex(&crate::mocks::create_question(0)).unwrap();
        let mut evidence = Evidence::open(&directory.0, 1, jobs::Settings::default()).unwrap();
        let completion = jobs::Completion {
            experience: None,
            model_checkpoint: None,
            id: 1,
            binding: jobs::Binding::new([1; 32], [2; 32]),
            spent_ms: 7,
            reserved_units: 2,
            state: jobs::State::Complete,
            result: Ok(jobs::Output::NoCandidate),
        };
        evidence
            .attempted(&question, [0; 32], &completion, Outcome::NoCandidate)
            .unwrap();
        let mut record = evidence.get(&question).unwrap().unwrap();
        let key = record_key(&record.solver, &question);
        record.last_job = 0;
        let error = record
            .validate(&key, evidence.header.observations)
            .unwrap_err();
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::ResearchFailure::EvidenceIdentity)
        );
    }

    #[test]
    fn an_admitted_record_larger_than_the_replay_page_survives_reopen() {
        let directory = crate::checkpoint::tests::Directory::new();
        let settings = jobs::Settings::default();
        let mut evidence = Evidence::open(&directory.0, 1, settings).unwrap();
        let mut expected = Vec::new();
        for index in 0..2 {
            let question =
                ResearchQuestion::from_hex(&crate::mocks::create_question(index)).unwrap();
            let completion = jobs::Completion {
                experience: None,
                model_checkpoint: None,
                id: index + 1,
                binding: jobs::Binding::new([1; 32], [2; 32]),
                spent_ms: 7,
                reserved_units: 2,
                state: jobs::State::Complete,
                result: Ok(jobs::Output::NoCandidate),
            };
            evidence
                .attempted(&question, [0; 32], &completion, Outcome::NoCandidate)
                .unwrap();
            let record = evidence.get(&question).unwrap().unwrap();
            assert!(crate::checkpoint::encode(&record).unwrap().len() > 256);
            expected.push((record_key(&record.solver, &question), record.last_job));
        }
        expected.sort_unstable();
        drop(evidence);

        let evidence = Evidence::open(&directory.0, 1, settings).unwrap();
        let mut after = None;
        for (key, job) in expected {
            let page = evidence.page_with_budget(after.as_deref(), 256).unwrap();
            assert!(page._overflow.is_some());
            assert_eq!(page.records.len(), 1);
            assert_eq!(page.records[0].0, key);
            assert_eq!(page.records[0].1.last_job, job);
            after = Some(key);
        }
        assert!(
            evidence
                .page_with_budget(after.as_deref(), 256)
                .unwrap()
                .records
                .is_empty()
        );
    }
}
