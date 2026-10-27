//! Durable attempt observations, subordinate to the checked graph and job owner.
use super::*;
use crate::checkpoint::{Checkpoint, Update};
use serde::{Deserialize, Serialize};
const DOMAIN: &str = "naome:research-evidence";
const MARKER: &[u8] = b"naome-research-evidence\n";
const MAX_RECORD: usize = 6 * naome_authoring::QUESTION_SOURCE_MAX_BYTES + 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Candidate,
    NoCandidate,
    Rejected,
    Failed,
    Expired,
    InDoubt,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    random: u64,
    draws: u64,
    observations: u64,
    model_contract: String,
    model: finder::Model,
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
    pub solver: String,
    pub knowledge: String,
    pub last_draw: u64,
    pub last_job: u64,
    pub outcomes: [u64; 6],
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
        self.outcomes[..=Outcome::Rejected as usize]
            .iter()
            .fold(0u64, |sum, n| sum.saturating_add(*n))
    }
    fn validate(&self, key: &str, observations: u64) -> Result<(), String> {
        let question = CompiledQuestion::compile(&self.question).map_err(|e| e.to_string())?;
        if key != record_key(&self.solver, &question) || self.last_job == 0 {
            return Err("research evidence identity differs".into());
        }
        if self.helpers.len() > 4
            || self.helpers.iter().map(String::len).sum::<usize>()
                > 4 * naome_authoring::QUESTION_SOURCE_MAX_BYTES
        {
            return Err("research helper plan capacity".into());
        }
        if let Some(frontier) = &self.frontier {
            frontier.validate(&question)?;
        }
        for source in &self.helpers {
            let helper = CompiledQuestion::compile(source).map_err(|e| e.to_string())?;
            if helper.resolution_id() == question.resolution_id()
                || !crate::learning::State::eligible(source)
                || !crate::learning::State::eligible(question.source())
            {
                return Err("research helper plan source differs".into());
            }
        }
        crate::object::id_bytes(&self.knowledge)?;
        crate::object::id_bytes(&self.solver)?;
        for root in [&self.verified, &self.prepared].into_iter().flatten() {
            crate::object::id_bytes(root)?;
        }
        if self.first_unresolved_job > self.last_job
            || self.verified_job > self.last_job
            || self.verified.is_some() != (self.verified_job > 0)
            || (self.first_unresolved_job > 0) != (self.first_unresolved_at > 0)
            || self.verified.is_some() != (self.verified_at > 0)
            || self.first_unresolved_at > observations
            || self.verified_at > observations
            || self.last_attempt_at > observations
            || self.prepared.is_some() && self.last_outcome != Outcome::Candidate
            || self.verified_units as u64 > self.units
            || self.last_units as u64 > self.units
        {
            return Err("research evidence outcome or cost differs".into());
        }
        Ok(())
    }
}
fn record_key(solver: &str, question: &CompiledQuestion) -> String {
    let mut hash = sha2::Sha256::new();
    hash.update(solver.as_bytes());
    hash.update(question.resolution_id());
    crate::hex(&hash.finalize())
}
pub(super) struct Evidence {
    checkpoint: Checkpoint,
    header: Header,
    solver: String,
}
impl Evidence {
    pub(super) fn open(
        directory: &Path,
        seed: u64,
        settings: jobs::Settings,
    ) -> Result<Self, String> {
        let directory = crate::storage::research_directory(directory)?;
        let path = directory.join("evidence.sqlite3");
        let marker = directory.join("evidence.initialized");
        let solver = jobs::solver_identity(settings);
        let checkpoint = if path.exists() {
            Checkpoint::open_for_replay(&path, DOMAIN)?
        } else {
            if crate::storage::marker_valid(&marker, MARKER)? {
                return Err("established research evidence is missing".into());
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
                },
                vec![],
            )?
        };
        let mut header: Header = checkpoint.header()?;
        if header.random == 0 {
            return Err("invalid research random state".into());
        }
        crate::object::id_bytes(&header.model_contract)?;
        header.model.validate()?;
        if header.observations < header.model.updates {
            return Err("finder observation sequence differs".into());
        }
        if header.model_contract != solver {
            header.model_contract = solver.clone();
            header.model = finder::Model::fresh();
        }
        checkpoint.require_kinds(&["question", "proved", "support", "plan"])?;
        if !crate::storage::marker_valid(&marker, MARKER)? {
            crate::storage::write_marker(&marker, MARKER)?;
        }
        Ok(Self {
            checkpoint,
            header,
            solver,
        })
    }
    pub(super) fn bind_solver(&mut self, solver: String) {
        // The small predictor is an online historical prior for the configured
        // solver, including in-flight earlier lower-model snapshots. Precise
        // current-checkpoint ability stays with the existing feedback owner.
        self.solver = solver;
    }
    pub(super) fn model(&self) -> &finder::Model {
        &self.header.model
    }
    pub(super) fn random(&self) -> u64 {
        self.header.random
    }
    pub(super) fn draws(&self) -> u64 {
        self.header.draws
    }
    pub(super) fn replay(
        &mut self,
        mut visit: impl FnMut(&Record) -> Result<bool, String>,
    ) -> Result<(), String> {
        let mut after = None;
        loop {
            let page = self
                .checkpoint
                .page(
                    "question",
                    after.as_deref(),
                    16,
                    crate::resources::active_limits().question_cache_bytes,
                )
                .map_err(|e| e.to_string())?;
            if page.is_empty() {
                return Ok(());
            }
            for (key, bytes) in page {
                let mut record: Record = crate::checkpoint::decode(&bytes)?;
                record.validate(&key, self.header.observations)?;
                if record.solver == self.solver && visit(&record)? && record.verified.is_none() {
                    record.verified = record.prepared.clone();
                    record.verified_job = record.last_job;
                    let question =
                        CompiledQuestion::compile(&record.question).map_err(|e| e.to_string())?;
                    self.put_observation(&question, &record, Some((true, record.verified_ms)))
                        .map_err(|e| e.to_string())?;
                }
                after = Some(key);
            }
        }
    }
    pub(super) fn get(&self, question: &CompiledQuestion) -> Result<Option<Record>, crate::Error> {
        let key = record_key(&self.solver, question);
        let record: Option<Record> = self.checkpoint.get("question", &key, MAX_RECORD)?;
        if let Some(record) = &record {
            record.validate(&key, self.header.observations)?;
        }
        Ok(record)
    }
    pub(super) fn page(&self, after: Option<&str>) -> Result<Vec<(String, Record)>, String> {
        self.checkpoint
            .page(
                "question",
                after,
                16,
                crate::resources::active_limits().question_cache_bytes,
            )?
            .into_iter()
            .map(|(key, bytes)| {
                let record: Record = crate::checkpoint::decode(&bytes)?;
                record.validate(&key, self.header.observations)?;
                Ok((key, record))
            })
            .collect()
    }
    pub(super) fn selected(&mut self, random: u64) -> Result<(), crate::Error> {
        let next = Header {
            random,
            draws: self
                .header
                .draws
                .checked_add(1)
                .ok_or("research draw overflow")?,
            ..self.header.clone()
        };
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
            .saturating_add(8192);
        let _disk = crate::resources::DiskLease::acquire(self.checkpoint.directory(), needed)?;
        self.checkpoint
            .commit(header, updates)
            .map_err(crate::Error::from)
    }
    fn put(&mut self, question: &CompiledQuestion, record: &Record) -> Result<(), crate::Error> {
        self.put_observation(question, record, None)
    }
    fn put_observation(
        &mut self,
        question: &CompiledQuestion,
        record: &Record,
        observation: Option<(bool, u64)>,
    ) -> Result<(), crate::Error> {
        let mut header = self.header.clone();
        let mut record = record.clone();
        if let Some((resolved, millis)) = observation {
            header.observations = header
                .observations
                .checked_add(1)
                .ok_or("finder observation overflow")?;
            if resolved && record.verified_at == 0 {
                record.verified_at = header.observations;
            } else if !resolved && record.first_unresolved_at == 0 {
                record.first_unresolved_at = header.observations;
            }
            if crate::learning::State::eligible(question.source()) {
                header.model.observe(question, resolved, millis)?;
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
        Ok(())
    }
    pub(super) fn attempted(
        &mut self,
        question: &CompiledQuestion,
        knowledge: [u8; 32],
        completion: &jobs::Completion,
        outcome: Outcome,
    ) -> Result<(), crate::Error> {
        if completion.id == 0 {
            return Ok(());
        }
        let mut record = self.get(question)?.unwrap_or(Record {
            question: question.source().into(),
            solver: self.solver.clone(),
            knowledge: crate::hex(&knowledge),
            last_draw: 0,
            last_job: 0,
            outcomes: [0; 6],
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
            return Ok(());
        }
        let knowledge_changed = record.knowledge != crate::hex(&knowledge);
        record.knowledge = crate::hex(&knowledge);
        record.last_draw = self.header.draws;
        record.last_job = completion.id;
        record.last_outcome = outcome;
        record.outcomes[outcome as usize] = record.outcomes[outcome as usize]
            .checked_add(1)
            .ok_or("research attempt overflow")?;
        record.units = record
            .units
            .checked_add(u64::from(completion.reserved_units))
            .ok_or("research work overflow")?;
        record.spent_ms = record
            .spent_ms
            .checked_add(completion.spent_ms)
            .ok_or("research time overflow")?;
        record.last_units = completion.reserved_units;
        record.prepared = None;
        record.publication_abandoned = false;
        if record.verified.is_none() {
            record.verified_units = record.last_units;
            record.verified_ms = completion.spent_ms;
        }
        let observation = (completion.state == jobs::State::Complete
            && outcome == Outcome::NoCandidate)
            .then_some((false, completion.spent_ms));
        record.last_attempt_at = self
            .header
            .observations
            .checked_add(u64::from(observation.is_some()))
            .ok_or("finder observation overflow")?;
        if observation.is_some()
            && (record.frontier.is_none() || knowledge_changed)
            && let Ok(jobs::Output::Native {
                frontier: Some(frontier),
                ..
            }) = &completion.result
            && crate::learning::State::eligible(question.source())
        {
            frontier.validate(question)?;
            for helper in finder::from_frontier(
                question,
                frontier,
                4,
                crate::resources::active_limits().question_cache_bytes / 2,
            ) {
                if record.helpers.len() >= 4 {
                    break;
                }
                if !record.helpers.iter().any(|source| {
                    CompiledQuestion::compile(source)
                        .is_ok_and(|q| q.resolution_id() == helper.resolution_id())
                }) {
                    record.helpers.push(helper.source().to_owned());
                }
            }
            record.frontier = Some(frontier.clone());
        }
        if observation.is_some() && record.first_unresolved_job == 0 {
            record.first_unresolved_job = completion.id;
        }
        self.put_observation(question, &record, observation)
    }
    pub(super) fn abandon_publication(
        &mut self,
        question: &CompiledQuestion,
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
        goal: &CompiledQuestion,
        helper: &CompiledQuestion,
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
        goal: &CompiledQuestion,
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
            return Err("research recursive plan binding or capacity".into());
        }
        for id in &plan.members {
            if crate::object::id_bytes(id)? == *goal.resolution_id() {
                return Err("research recursive plan cycle".into());
            }
        }
        Ok(plan.members)
    }
    pub(super) fn exhaust_helpers(
        &mut self,
        question: &CompiledQuestion,
    ) -> Result<(), crate::Error> {
        if let Some(mut record) = self.get(question)? {
            record.loop_disabled = true;
            self.put(question, &record)?;
        }
        Ok(())
    }
    pub(super) fn prepared(
        &mut self,
        question: &CompiledQuestion,
        job: u64,
        root: ArtifactId,
    ) -> Result<(), crate::Error> {
        let Some(mut record) = self.get(question)? else {
            return Ok(());
        };
        if record.last_job != job {
            return Err("research prepared job differs".into());
        }
        if record.last_outcome != Outcome::Candidate {
            return Err("only a candidate job can supply checked evidence".into());
        }
        record.prepared = Some(crate::hex(root.as_bytes()));
        self.put(question, &record)
    }
    pub(super) fn rejected(
        &mut self,
        question: &CompiledQuestion,
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
        record.outcomes[Outcome::Candidate as usize] =
            record.outcomes[Outcome::Candidate as usize].saturating_sub(1);
        record.outcomes[Outcome::Rejected as usize] =
            record.outcomes[Outcome::Rejected as usize].saturating_add(1);
        self.put(question, &record)
    }
    pub(super) fn verified(
        &mut self,
        question: &CompiledQuestion,
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
            return Err(
                "verified research evidence is not bound to the checked candidate job".into(),
            );
        }
        record.verified = Some(crate::hex(root.as_bytes()));
        record.verified_job = job;
        record.verified_units = record.last_units;
        self.put_observation(question, &record, Some((true, record.verified_ms)))?;
        Ok(Some((record.verified_units, record.verified_ms)))
    }

    /// Credit a distinct earlier unresolved goal once, after both exact
    /// checked targets and their actual dependency edge have been established.
    pub(super) fn support(
        &mut self,
        goal: &CompiledQuestion,
        actual_goal: &CompiledQuestion,
        job: u64,
        root: ArtifactId,
        dependency: ArtifactId,
        mut checked: impl FnMut(&CompiledQuestion) -> Result<Option<CompiledQuestion>, crate::Error>,
    ) -> Result<Option<CompiledQuestion>, crate::Error> {
        if !crate::learning::State::eligible(goal.source()) {
            return Ok(None);
        }
        let Some(consumer) = self.get(goal)? else {
            return Ok(None);
        };
        if consumer.last_job != job
            || consumer.verified.as_deref() != Some(crate::hex(root.as_bytes()).as_str())
            || consumer.first_unresolved_job == 0
        {
            return Ok(None);
        }
        let lemma = crate::hex(dependency.as_bytes());
        let Some(key) = self.checkpoint.get::<String>("proved", &lemma, 128)? else {
            return Ok(None);
        };
        let mut producer = self
            .checkpoint
            .get::<Record>("question", &key, MAX_RECORD)?
            .ok_or("finder proof index source is missing")?;
        producer.validate(&key, self.header.observations)?;
        if producer.verified.as_deref() != Some(lemma.as_str()) {
            return Err("finder proof index identity differs".into());
        }
        // Job IDs are allocated before execution; concurrent completions may
        // arrive in another order. Only durable observations establish timing.
        if consumer.first_unresolved_at >= producer.verified_at
            || producer.verified_at >= consumer.verified_at
        {
            return Ok(None);
        }
        let question = CompiledQuestion::compile(&producer.question).map_err(|e| e.to_string())?;
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
            if receipt.lemma != lemma
                || receipt.resolution != resolution
                || receipt.first_unresolved_job == 0
                || receipt.lemma_job == 0
                || receipt.goal_job == 0
                || receipt.first_unresolved_at == 0
                || receipt.first_unresolved_at >= receipt.lemma_at
                || receipt.lemma_at >= receipt.goal_at
                || receipt.goal_at > self.header.observations
            {
                return Err("finder support receipt identity differs".into());
            }
            return Ok(None);
        }
        let mut header = self.header.clone();
        header.observations = header
            .observations
            .checked_add(1)
            .ok_or("finder observation overflow")?;
        if crate::learning::State::eligible(question.source()) {
            header.model.support(&question)?;
        }
        producer.supports = producer
            .supports
            .checked_add(1)
            .ok_or("finder support count overflow")?;
        let receipt = Support {
            lemma,
            goal: crate::hex(root.as_bytes()),
            resolution,
            first_unresolved_job: consumer.first_unresolved_job,
            lemma_job: producer.verified_job,
            goal_job: job,
            first_unresolved_at: consumer.first_unresolved_at,
            lemma_at: producer.verified_at,
            goal_at: consumer.verified_at,
        };
        self.commit(
            &header,
            vec![
                Update::put("question", key, &producer)?,
                Update::put("support", receipt_key, &receipt)?,
            ],
        )?;
        self.header = header;
        Ok(Some(question))
    }
}
