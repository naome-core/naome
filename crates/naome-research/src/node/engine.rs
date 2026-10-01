//! Deterministic local transitions; durable records own all selected effects.

use super::{
    budget::{Phase, Usage, window},
    context::{self, Reference, StoredArtifact},
    model::*,
    store::{Change, Checkpoint, Record, Store, change, index_key},
};
use crate::{
    formal::check_answer,
    journal::{read_bounded, write_new},
    state::{Id, Question, hash, hex},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Action {
        signed: SignedAction,
        finalization: Option<Finalization>,
        artifacts: Vec<StoredArtifact>,
    },
    Tick {
        now: i64,
        admissions: Vec<PendingBlock>,
    },
    Observe {
        now: i64,
    },
    Scan {
        cursor: u64,
    },
    Reserve {
        reservation: Reservation,
    },
    Response {
        reservation: Id,
        outcome: ProviderOutcome,
        action: Option<SignedAction>,
        semantic_error: Option<String>,
    },
    Settle {
        settlement: Option<Settlement>,
        error: Option<String>,
    },
    Finish {
        reservation: Id,
        error: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionReceipt {
    pub action: Id,
    pub record: u64,
    pub finalization: Option<Finalization>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArtifactPointer {
    record: u64,
    position: usize,
}

pub struct Node {
    pub(super) config: Config,
    pub(super) profile: Profile,
    pub(super) key: SigningKey,
    pub(super) state: WorkingState,
    pub(super) store: Store,
}
impl Node {
    pub fn initialize(config: Config, now: i64) -> Result<Self, String> {
        config.validate()?;
        let key = key(&config.identity_file)?;
        let profile = Profile::sign(&config, &key);
        profile.verify(&config)?;
        let state = WorkingState::new(&config, now)?;
        let store = Store::create(&config.directory, profile.id(), &key, &state)?;
        write_new(&config.directory.join("profile.json"), &profile)?;
        super::index::sync_directory(&config.directory)?;
        Ok(Self {
            config,
            profile,
            key,
            state,
            store,
        })
    }
    pub fn open(config: Config) -> Result<Self, String> {
        Self::open_inner(config, false)
    }
    /// A signed checkpoint snapshot can be read while the sole writer runs.
    /// Every append/recovery API rejects this read-only store.
    pub fn inspect(config: Config) -> Result<Self, String> {
        Self::open_inner(config, true)
    }
    fn open_inner(config: Config, read_only: bool) -> Result<Self, String> {
        config.validate()?;
        let key = key(&config.identity_file)?;
        let profile: Profile = read_bounded(&config.directory.join("profile.json"), 8192)?;
        profile.verify(&config)?;
        if key.verifying_key().to_bytes() != profile.coordinator {
            return Err("wrong node identity".into());
        }
        let store = if read_only {
            Store::inspect(&config.directory, profile.id(), profile.coordinator)?
        } else {
            Store::open(&config.directory, profile.id(), profile.coordinator)?
        };
        let state: WorkingState =
            serde_json::from_value(store.checkpoint.state.clone()).map_err(|e| e.to_string())?;
        state.coherent()?;
        let mut node = Self {
            config,
            profile,
            key,
            state,
            store,
        };
        if !read_only && let Some(record) = node.store.unfinished_record()? {
            node.verify_transition(&record)?;
            node.store.recover(&record, &node.key)?;
            node.state = serde_json::from_value(record.body.state).map_err(|e| e.to_string())?;
        }
        Ok(node)
    }
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.store.checkpoint
    }
    pub fn next_nonce(&self) -> Result<u64, String> {
        let nonce: Option<u64> = self
            .store
            .get(index_key("nonce", &self.profile.coordinator))?;
        nonce
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| "action nonce exhausted".into())
    }
    pub fn sign(&self, action: Action) -> Result<SignedAction, String> {
        Ok(SignedAction::sign(
            self.profile.id(),
            self.next_nonce()?,
            action,
            &self.key,
        ))
    }
    pub fn question(&self, id: Id) -> Result<Option<Question>, String> {
        let Some(entry) = self.entry(id)? else {
            return Ok(None);
        };
        let operation = self.operation(entry.published)?;
        match operation {
            Operation::Action {
                signed:
                    SignedAction {
                        action: Action::Publish { question },
                        ..
                    },
                ..
            } => Ok(Some(question)),
            _ => Err("question index does not reference publication".into()),
        }
    }
    pub fn pending(&self, id: Id) -> Result<Option<PendingBlock>, String> {
        let Some(index) = self.entry(id)?.and_then(|e| e.pending) else {
            return Ok(None);
        };
        match self.operation(index)? {
            Operation::Tick { admissions, .. } => admissions
                .into_iter()
                .find(|p| p.question == id)
                .map(Some)
                .ok_or_else(|| "pending index does not reference admission".into()),
            _ => Err("pending index refers to wrong operation".into()),
        }
    }
    pub fn finalization(&self, id: Id) -> Result<Option<Finalization>, String> {
        let Some(index) = self.entry(id)?.and_then(|e| e.finalized) else {
            return Ok(None);
        };
        match self.operation(index)? {
            Operation::Action {
                finalization: Some(value),
                ..
            } if value.question == id => Ok(Some(value)),
            _ => Err("finalization index mismatch".into()),
        }
    }
    pub fn credit(&self, participant: Id) -> Result<u64, String> {
        Ok(self
            .store
            .get(index_key("credit", &participant))?
            .unwrap_or(0))
    }
    pub fn questions(
        &self,
        cursor: u64,
        limit: usize,
    ) -> Result<Vec<(Id, Question, Option<PendingBlock>, Option<Finalization>)>, String> {
        if limit == 0 || limit > PAGE_SIZE || cursor > self.state.questions {
            return Err("invalid bounded question page".into());
        }
        let mut rows = vec![];
        for ordinal in cursor
            ..self
                .state
                .questions
                .min(cursor.saturating_add(limit as u64))
        {
            let id: Id = self
                .store
                .get(index_key("question-ordinal", &ordinal))?
                .ok_or("question ordinal gap")?;
            rows.push((
                id,
                self.question(id)?.ok_or("question absent")?,
                self.pending(id)?,
                self.finalization(id)?,
            ));
        }
        Ok(rows)
    }
    pub(super) fn entry(&self, id: Id) -> Result<Option<QuestionEntry>, String> {
        self.store.get(index_key("question", &id))
    }
    pub(super) fn operation(&self, index: u64) -> Result<Operation, String> {
        serde_json::from_value(self.store.record(index)?.body.operation).map_err(|e| e.to_string())
    }
    pub(super) fn artifact(&self, reference: Reference) -> Result<Option<StoredArtifact>, String> {
        let (namespace, id) = match reference {
            Reference::Artifact(id) => ("artifact", id),
            Reference::Statement(id) => ("statement", id),
            Reference::Derivation(id) => ("derivation", id),
        };
        let Some(pointer) = self
            .store
            .get::<ArtifactPointer>(index_key(namespace, &id))?
        else {
            return Ok(None);
        };
        let operation = self.operation(pointer.record)?;
        let Operation::Action { artifacts, .. } = operation else {
            return Err("artifact index refers to nonartifact operation".into());
        };
        let artifact = artifacts
            .into_iter()
            .nth(pointer.position)
            .ok_or("artifact position invalid")?;
        let matches = match namespace {
            "artifact" => artifact.id == id,
            "statement" => artifact.statement == Some(id),
            "derivation" => artifact.derivation == Some(id),
            _ => false,
        };
        if !matches {
            return Err("artifact index binding mismatch".into());
        }
        Ok(Some(artifact))
    }
    pub fn submit(&mut self, signed: SignedAction) -> Result<ActionReceipt, String> {
        signed.verify(&self.profile)?;
        if let Some(index) = self.store.get::<u64>(index_key("action", &signed.id()))? {
            let Operation::Action {
                signed: stored,
                finalization,
                ..
            } = self.operation(index)?
            else {
                return Err("action index mismatch".into());
            };
            if stored != signed {
                return Err("conflicting signed retry".into());
            }
            return Ok(ActionReceipt {
                action: signed.id(),
                record: index,
                finalization,
            });
        }
        let (next, changes, finalization, artifacts) = self.derive_action(&signed)?;
        let receipt = ActionReceipt {
            action: signed.id(),
            record: self.store.checkpoint.count,
            finalization: finalization.clone(),
        };
        self.commit(
            Operation::Action {
                signed,
                finalization,
                artifacts,
            },
            next,
            changes,
        )?;
        Ok(receipt)
    }
    fn derive_action(
        &self,
        signed: &SignedAction,
    ) -> Result<
        (
            WorkingState,
            Vec<Change>,
            Option<Finalization>,
            Vec<StoredArtifact>,
        ),
        String,
    > {
        signed.verify(&self.profile)?;
        if signed.nonce != self.next_nonce()? {
            return Err("stale, conflicting or gapped action nonce".into());
        }
        let mut next = self.state.clone();
        let mut changes = vec![];
        let mut finalization = None;
        let mut artifacts = vec![];
        match &signed.action {
            Action::Publish { question } => {
                validate_sources(&question.definitions, None)?;
                let id = question.id()?;
                if self.entry(id)?.is_some() {
                    return Err("duplicate canonical question".into());
                }
                let sources: Vec<_> = question.definitions.iter().map(String::as_str).collect();
                let (base, prepared) =
                    context::prepare(&sources, |reference| self.artifact(reference))?;
                crate::formal::check_definitions(&question.definitions, &base)?;
                artifacts = prepared;
                let entry = QuestionEntry {
                    published: self.store.checkpoint.count,
                    ordinal: next.questions,
                    evaluated: None,
                    pending: None,
                    finalized: None,
                };
                changes.push(change("question", &id, &entry)?);
                changes.push(change("question-ordinal", &next.questions, &id)?);
                next.questions = next
                    .questions
                    .checked_add(1)
                    .ok_or("question ordinal overflow")?;
                next.unreviewed = next
                    .unreviewed
                    .checked_add(1)
                    .ok_or("evaluation queue overflow")?;
            }
            Action::Evaluate { question, yes } => {
                let mut entry = self
                    .entry(*question)?
                    .ok_or("unknown evaluation question")?;
                if entry.finalized.is_some() {
                    return Err("evaluation targets finalized block".into());
                }
                if entry.evaluated.is_none() {
                    next.unreviewed = next
                        .unreviewed
                        .checked_sub(1)
                        .ok_or("evaluation queue underflow")?;
                }
                if *yes && entry.evaluated != Some(true) {
                    next.eligible = next
                        .eligible
                        .checked_add(1)
                        .ok_or("eligible count overflow")?;
                }
                if !*yes && entry.evaluated == Some(true) {
                    next.eligible = next
                        .eligible
                        .checked_sub(1)
                        .ok_or("eligible count underflow")?;
                }
                entry.evaluated = Some(*yes);
                changes.push(change("question", question, &entry)?);
            }
            Action::Answer {
                question,
                outcome,
                file,
            } => {
                let mut entry = self.entry(*question)?.ok_or("unknown answer question")?;
                if entry.finalized.is_some() {
                    return Err("block already finalized".into());
                }
                let pending = self
                    .pending(*question)?
                    .ok_or("question has never been admitted")?;
                let q = self.question(*question)?.ok_or("question absent")?;
                validate_sources(&file.dependencies, Some(&file.source))?;
                let sources: Vec<_> = file
                    .dependencies
                    .iter()
                    .map(String::as_str)
                    .chain(std::iter::once(file.source.as_str()))
                    .collect();
                let (base, prepared) =
                    context::prepare(&sources, |reference| self.artifact(reference))?;
                let checked = check_answer(file, &q.formula()?, *outcome, &base)?;
                artifacts = prepared;
                let award = hash(
                    b"naome:research:award:v2\0",
                    &(self.profile.id(), pending.id()),
                );
                if self.store.get::<u64>(index_key("award", &award))?.is_some() {
                    return Err("award already issued".into());
                }
                let result = Finalization {
                    block: pending.id(),
                    question: *question,
                    action: signed.id(),
                    submitter: signed.participant,
                    outcome: *outcome,
                    canonical_proof: checked.canonical_bytes,
                    artifact_ids: checked.artifact_ids,
                    award,
                    credit: pending.credit,
                };
                let credit = self
                    .credit(signed.participant)?
                    .checked_add(pending.credit)
                    .ok_or("local credit numeric exhaustion")?;
                changes.push(change("credit", &signed.participant, &credit)?);
                changes.push(change("award", &award, &self.store.checkpoint.count)?);
                if entry.evaluated == Some(true) {
                    next.eligible = next
                        .eligible
                        .checked_sub(1)
                        .ok_or("eligible count underflow")?;
                }
                entry.finalized = Some(self.store.checkpoint.count);
                changes.push(change("question", question, &entry)?);
                next.finalized = next
                    .finalized
                    .checked_add(1)
                    .ok_or("finalization ordinal overflow")?;
                next.leases.retain(|lease| lease.question != *question);
                next.recent_results.push(next.tick);
                if next.recent_results.len() > 8 {
                    next.recent_results.remove(0);
                }
                finalization = Some(result);
            }
        }
        for (position, artifact) in artifacts.iter().enumerate() {
            if self.artifact(Reference::Artifact(artifact.id))?.is_some() {
                continue;
            }
            if let Some(derivation) = artifact.derivation
                && self.artifact(Reference::Derivation(derivation))?.is_some()
            {
                continue;
            }
            let pointer = ArtifactPointer {
                record: self.store.checkpoint.count,
                position,
            };
            changes.push(change("artifact", &artifact.id, &pointer)?);
            if let Some(statement) = artifact.statement {
                changes.push(change("statement", &statement, &pointer)?);
            }
            if let Some(derivation) = artifact.derivation {
                changes.push(change("derivation", &derivation, &pointer)?);
            }
        }
        changes.push(change("nonce", &signed.participant, &signed.nonce)?);
        changes.push(change(
            "action",
            &signed.id(),
            &self.store.checkpoint.count,
        )?);
        Ok((next, changes, finalization, artifacts))
    }
    pub(super) fn commit(
        &mut self,
        operation: Operation,
        next: WorkingState,
        changes: Vec<Change>,
    ) -> Result<(), String> {
        next.coherent()?;
        self.store.append(&operation, &next, changes, &self.key)?;
        self.state = next;
        Ok(())
    }
    pub fn observe(&mut self, now: i64) -> Result<bool, String> {
        if now < self.state.clock {
            return Ok(false);
        }
        if now == self.state.clock {
            return Ok(true);
        }
        let operation = Operation::Observe { now };
        let (next, changes) = self.derive(&operation)?;
        self.commit(operation, next, changes)?;
        Ok(true)
    }
    pub fn tick(&mut self, now: i64) -> Result<(), String> {
        let (next, changes, admissions) = self.derive_tick(now)?;
        self.commit(Operation::Tick { now, admissions }, next, changes)
    }
    fn derive_tick(
        &self,
        now: i64,
    ) -> Result<(WorkingState, Vec<Change>, Vec<PendingBlock>), String> {
        if now < self.state.clock {
            return Err("logical Tick wall-clock rollback".into());
        }
        let mut next = self.state.clone();
        let mut changes = vec![];
        let mut admissions = vec![];
        next.tick = next.tick.checked_add(1).ok_or("logical tick exhausted")?;
        next.next_tick = now.checked_add(60).ok_or("clock exhausted")?;
        let pool = &self.config.pool;
        if next.recent_results.last() == Some(&self.state.tick) {
            next.drought = 0;
        } else {
            next.drought = next.drought.saturating_add(1);
        }
        next.recent_results
            .retain(|tick| next.tick.saturating_sub(*tick) <= pool.quick_result_ticks);
        if next
            .last_adjustment
            .is_none_or(|tick| next.tick.saturating_sub(tick) >= pool.cooldown_ticks)
        {
            if next.recent_results.len() >= 2 && next.target > pool.minimum {
                next.target -= 1;
                next.drought = 0;
                next.last_adjustment = Some(next.tick);
                next.recent_results.clear();
            } else if next.drought >= pool.drought_ticks && next.target < pool.maximum {
                next.target += 1;
                next.drought = 0;
                next.last_adjustment = Some(next.tick);
                next.recent_results.clear();
            }
        }
        let mut ranked = vec![];
        for lease in &next.leases {
            let entry = self
                .entry(lease.question)?
                .ok_or("leased question absent")?;
            if entry.finalized.is_none() && entry.evaluated == Some(true) {
                ranked.push((
                    std::cmp::Reverse(entry.evaluated == Some(true)),
                    lease.question,
                    lease.clone(),
                ));
            }
        }
        ranked.sort_by_key(|(votes, id, _)| (*votes, *id));
        next.leases = ranked
            .into_iter()
            .take(next.target)
            .map(|(_, _, lease)| lease)
            .collect();
        let start = next.pool_cursor.min(next.questions);
        let end = next.questions.min(start.saturating_add(PAGE_SIZE as u64));
        let mut candidates = vec![];
        for ordinal in start..end {
            let id: Id = self
                .store
                .get(index_key("question-ordinal", &ordinal))?
                .ok_or("question page gap")?;
            let entry = self.entry(id)?.ok_or("indexed question absent")?;
            if entry.evaluated == Some(true)
                && entry.finalized.is_none()
                && !next.leases.iter().any(|l| l.question == id)
            {
                candidates.push((id, entry));
            }
        }
        candidates.sort_by_key(|(id, _)| *id);
        for (id, mut entry) in candidates
            .into_iter()
            .take(next.target.saturating_sub(next.leases.len()))
        {
            if entry.pending.is_none() {
                let q = self.question(id)?.ok_or("admission question absent")?;
                let pending = PendingBlock {
                    profile: self.profile.id(),
                    question: id,
                    formula: q.formula.canonical_bytes()?,
                    published_record: entry.published,
                    admission_record: self.store.checkpoint.count,
                    credit: self.config.credit,
                };
                entry.pending = Some(self.store.checkpoint.count);
                changes.push(change("question", &id, &entry)?);
                next.pending = next
                    .pending
                    .checked_add(1)
                    .ok_or("pending ordinal overflow")?;
                admissions.push(pending);
            }
            next.leases.push(Lease {
                question: id,
                since: next.tick,
            });
        }
        next.pool_cursor = if end == next.questions { 0 } else { end };
        Ok((next, changes, admissions))
    }
    pub(super) fn derive(
        &self,
        operation: &Operation,
    ) -> Result<(WorkingState, Vec<Change>), String> {
        match operation {
            Operation::Action {
                signed,
                finalization,
                artifacts,
            } => {
                let (next, changes, expected, prepared) = self.derive_action(signed)?;
                if expected != *finalization || prepared != *artifacts {
                    return Err("action derived artifact/finalization mismatch".into());
                }
                Ok((next, changes))
            }
            Operation::Tick { now, admissions } => {
                let (next, changes, expected) = self.derive_tick(*now)?;
                if expected != *admissions {
                    return Err("pending admission derivation mismatch".into());
                }
                Ok((next, changes))
            }
            Operation::Observe { now } => {
                if *now < self.state.clock {
                    return Err("observed clock rollback".into());
                }
                let mut next = self.state.clone();
                next.clock = *now;
                for phase in [Phase::Discover, Phase::Evaluate, Phase::Solve] {
                    let current = window(
                        *now,
                        &self.config.budgets.timezone,
                        self.config.budgets.allowance(phase).period,
                    )?;
                    next.bucket_mut(phase).renew(current)?;
                }
                Ok((next, vec![]))
            }
            Operation::Scan { cursor } => {
                let end = self
                    .state
                    .questions
                    .min(self.state.evaluated_cursor.saturating_add(PAGE_SIZE as u64));
                let expected = if end == self.state.questions { 0 } else { end };
                if *cursor != expected {
                    return Err("evaluation scan cursor mismatch".into());
                }
                let mut next = self.state.clone();
                next.evaluated_cursor = *cursor;
                Ok((next, vec![]))
            }
            _ => self.derive_provider(operation),
        }
    }
    fn verify_transition(&self, record: &Record) -> Result<(), String> {
        let operation: Operation =
            serde_json::from_value(record.body.operation.clone()).map_err(|e| e.to_string())?;
        let (next, changes) = self.derive(&operation)?;
        if serde_json::to_value(next).map_err(|e| e.to_string())? != record.body.state
            || changes != record.body.changes
        {
            return Err("replayed node transition differs from committed effects".into());
        }
        Ok(())
    }

    pub fn reserve(
        &mut self,
        phase: Phase,
        target: Option<Id>,
        now: i64,
        prompt: String,
        schema: Value,
    ) -> Result<Reservation, String> {
        if !self.observe(now)? {
            return Err("provider admission paused for clock rollback".into());
        }
        let reservation = Reservation {
            profile: self.profile.id(),
            ordinal: self.state.attempts,
            phase,
            target,
            admitted: now,
            window: self.state.bucket(phase).window,
            allocation: self.config.budgets.allowance(phase).amount,
            prompt: hash(b"naome:research:prompt:v2\0", &prompt),
            prompt_text: prompt,
            schema,
        };
        let operation = Operation::Reserve {
            reservation: reservation.clone(),
        };
        let (next, changes) = self.derive(&operation)?;
        self.commit(operation, next, changes)?;
        Ok(reservation)
    }
    fn reservation(&self) -> Result<Reservation, String> {
        let index = self
            .state
            .in_flight
            .or_else(|| {
                self.state
                    .received
                    .and_then(|r| match self.operation(r).ok()? {
                        Operation::Response { reservation, .. } => self
                            .store
                            .get::<u64>(index_key("reservation", &reservation))
                            .ok()
                            .flatten(),
                        _ => None,
                    })
            })
            .ok_or("no unresolved reservation")?;
        match self.operation(index)? {
            Operation::Reserve { reservation } => Ok(reservation),
            _ => Err("reservation index binding mismatch".into()),
        }
    }
    pub fn record_response(
        &mut self,
        reservation: &Reservation,
        outcome: ProviderOutcome,
    ) -> Result<(), String> {
        let (action, semantic_error) = match convert(reservation, &outcome) {
            Ok(Some(action)) => (Some(self.sign(action)?), None),
            Ok(None) => (None, None),
            Err(error) => (None, Some(bounded_error(error))),
        };
        let operation = Operation::Response {
            reservation: reservation.id(),
            outcome,
            action,
            semantic_error,
        };
        let (next, changes) = self.derive(&operation)?;
        self.commit(operation, next, changes)
    }
    /// Recover a saved response/settlement/action without another provider call.
    /// A reservation without a response remains uncertain and blocks all phases.
    pub fn recover_provider(&mut self) -> Result<bool, String> {
        if self.state.usage_unknown.is_some() {
            return Ok(false);
        }
        let Some(response_index) = self.state.received else {
            return Ok(self.state.in_flight.is_none());
        };
        let Operation::Response {
            reservation: reservation_id,
            outcome,
            action,
            semantic_error,
        } = self.operation(response_index)?
        else {
            return Err("response index mismatch".into());
        };
        if self.state.in_flight.is_some() {
            let reservation = self.reservation()?;
            let result = accounted_usage(&outcome);
            let (settlement, error) = match result {
                Ok(usage) => (
                    Some(Settlement {
                        reservation: reservation_id,
                        window: reservation.window,
                        phase: reservation.phase,
                        usage,
                    }),
                    None,
                ),
                Err(error) => (None, Some(error.to_owned())),
            };
            let operation = Operation::Settle { settlement, error };
            let (next, changes) = self.derive(&operation)?;
            self.commit(operation, next, changes)?;
            if self.state.usage_unknown.is_some() {
                return Ok(false);
            }
        }
        let mut error = semantic_error;
        if let Some(action) = action
            && let Err(reason) = self.submit(action)
        {
            error = Some(bounded_error(reason));
        }
        let operation = Operation::Finish {
            reservation: reservation_id,
            error,
        };
        let (next, changes) = self.derive(&operation)?;
        self.commit(operation, next, changes)?;
        Ok(true)
    }
    fn derive_provider(
        &self,
        operation: &Operation,
    ) -> Result<(WorkingState, Vec<Change>), String> {
        let mut next = self.state.clone();
        let mut changes = vec![];
        match operation {
            Operation::Reserve { reservation } => {
                let phase = reservation.phase;
                if self.state.in_flight.is_some()
                    || self.state.received.is_some()
                    || self.state.usage_unknown.is_some()
                    || reservation.profile != self.profile.id()
                    || reservation.ordinal != self.state.attempts
                    || reservation.admitted != self.state.clock
                    || reservation.window != self.state.bucket(phase).window
                    || reservation.allocation != self.config.budgets.allowance(phase).amount
                    || !self.state.available(&self.config, phase)
                    || reservation.admitted < self.state.backoff_until[phase_index(phase)]
                    || reservation.prompt_text.is_empty()
                    || reservation.prompt_text.len() > crate::provider::MAX_INPUT_BYTES
                    || reservation.prompt
                        != hash(b"naome:research:prompt:v2\0", &reservation.prompt_text)
                    || !reservation.schema.is_object()
                    || serde_json::to_vec(&reservation.schema)
                        .map_err(|e| e.to_string())?
                        .len()
                        > crate::provider::MAX_INPUT_BYTES
                {
                    return Err(
                        "provider reservation is unaffordable, unresolved or malformed".into(),
                    );
                }
                match phase {
                    Phase::Discover if reservation.target.is_some() => {
                        return Err("discovery cannot target a batch".into());
                    }
                    Phase::Evaluate => {
                        let id = reservation
                            .target
                            .ok_or("evaluation requires exactly one question")?;
                        let entry = self.entry(id)?.ok_or("evaluation target absent")?;
                        if entry.finalized.is_some() {
                            return Err("evaluation target finalized".into());
                        }
                        next.evaluated_cursor = if entry.ordinal + 1 == self.state.questions {
                            0
                        } else {
                            entry.ordinal + 1
                        };
                    }
                    Phase::Solve => {
                        let id = reservation
                            .target
                            .ok_or("solve requires one exact target")?;
                        if !self.state.leases.iter().any(|lease| lease.question == id)
                            || self.pending(id)?.is_none()
                            || self.finalization(id)?.is_some()
                        {
                            return Err("solve target has no active pending lease".into());
                        }
                        next.solve_cursor = self.state.solve_cursor.wrapping_add(1) % 8;
                    }
                    _ => {}
                }
                if phase != Phase::Solve {
                    next.bucket_mut(phase).charge(1)?;
                }
                let key = (phase, reservation.window.start);
                let mut ledger: WindowLedger = self
                    .store
                    .get(index_key("window", &key))?
                    .unwrap_or(WindowLedger::new(reservation));
                ledger.attempts = ledger
                    .attempts
                    .checked_add(1)
                    .ok_or("window attempt count overflow")?;
                if phase != Phase::Solve {
                    ledger.spent = ledger.spent.checked_add(1).ok_or("window count overflow")?;
                }
                changes.push(change("window", &key, &ledger)?);
                changes.push(change(
                    "reservation",
                    &reservation.id(),
                    &self.store.checkpoint.count,
                )?);
                next.in_flight = Some(self.store.checkpoint.count);
                next.attempts = next
                    .attempts
                    .checked_add(1)
                    .ok_or("attempt ordinal overflow")?;
                next.phase_cursor = (phase_index(phase) as u8 + 1) % 3;
            }
            Operation::Response {
                reservation,
                outcome,
                action,
                semantic_error,
            } => {
                let expected = self.reservation()?;
                if self.state.received.is_some()
                    || *reservation != expected.id()
                    || self.state.usage_unknown.is_some()
                {
                    return Err("response reservation binding mismatch".into());
                }
                let (expected_action, expected_error) = match convert(&expected, outcome) {
                    Ok(action) => (action, None),
                    Err(error) => (None, Some(bounded_error(error))),
                };
                if expected_error != *semantic_error
                    || expected_action.as_ref() != action.as_ref().map(|a| &a.action)
                {
                    return Err("response action does not match saved raw reply".into());
                }
                if let Some(action) = action {
                    action.verify(&self.profile)?;
                    if action.nonce != self.next_nonce()? {
                        return Err("response action nonce mismatch".into());
                    }
                }
                next.received = Some(self.store.checkpoint.count);
            }
            Operation::Settle { settlement, error } => {
                if self.state.usage_unknown.is_some() || self.state.in_flight.is_none() {
                    return Err("reservation already settled or usage unknown".into());
                }
                let reservation = self.reservation()?;
                let index = self
                    .state
                    .received
                    .ok_or("settlement without saved response")?;
                let Operation::Response { outcome, .. } = self.operation(index)? else {
                    return Err("response absent".into());
                };
                let reported = accounted_usage(&outcome);
                match reported {
                    Ok(usage) => {
                        let expected = Settlement {
                            reservation: reservation.id(),
                            window: reservation.window,
                            phase: reservation.phase,
                            usage,
                        };
                        if settlement.as_ref() != Some(&expected) || error.is_some() {
                            return Err("usage settlement derivation mismatch".into());
                        }
                        let ledger_key = (reservation.phase, reservation.window.start);
                        let mut ledger: WindowLedger = self
                            .store
                            .get(index_key("window", &ledger_key))?
                            .ok_or("admission window ledger missing")?;
                        ledger.add_usage(usage)?;
                        if reservation.phase == Phase::Solve {
                            ledger.spent = ledger
                                .spent
                                .checked_add(usage.total)
                                .ok_or("research usage overflow")?;
                            if next.research.window == reservation.window {
                                next.research.charge(usage.total)?;
                            }
                        }
                        changes.push(change("window", &ledger_key, &ledger)?);
                        changes.push(change(
                            "settlement",
                            &reservation.id(),
                            &self.store.checkpoint.count,
                        )?);
                        next.in_flight = None;
                    }
                    Err(reason) => {
                        if settlement.is_some() || error.as_deref() != Some(reason) {
                            return Err("unknown usage must be retained explicitly".into());
                        }
                        next.usage_unknown = Some(reason.to_owned());
                    }
                }
            }
            Operation::Finish { reservation, error } => {
                if self.state.in_flight.is_some() || self.state.usage_unknown.is_some() {
                    return Err("unfinished token accounting".into());
                }
                let expected = self.reservation()?;
                if *reservation != expected.id() || error.as_ref().is_some_and(|e| e.len() > 512) {
                    return Err("finish reservation mismatch".into());
                }
                let Operation::Response {
                    action,
                    semantic_error,
                    ..
                } = self.operation(self.state.received.ok_or("finish without response")?)?
                else {
                    return Err("finish response mismatch".into());
                };
                let expected_error = if let Some(action) = action {
                    if self
                        .store
                        .get::<u64>(index_key("action", &action.id()))?
                        .is_some()
                    {
                        None
                    } else {
                        match self.derive_action(&action) {
                            Err(reason) => Some(bounded_error(reason)),
                            Ok(_) => {
                                return Err(
                                    "finish cannot discard an uncommitted valid action".into()
                                );
                            }
                        }
                    }
                } else {
                    semantic_error
                };
                if *error != expected_error {
                    return Err("finish semantic error derivation mismatch".into());
                }
                if expected.phase == Phase::Solve {
                    next.leases.retain(|l| Some(l.question) != expected.target);
                }
                next.received = None;
                if error.is_some() {
                    next.backoff_until[phase_index(expected.phase)] =
                        next.clock.checked_add(30).ok_or("backoff clock overflow")?;
                }
                changes.push(change(
                    "receipt",
                    reservation,
                    &self.store.checkpoint.count,
                )?);
            }
            _ => return Err("unsupported provider operation".into()),
        }
        Ok((next, changes))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowLedger {
    pub phase: Phase,
    pub window: super::budget::Window,
    pub allocation: u64,
    pub attempts: u64,
    pub spent: u64,
    pub input: u64,
    pub output: u64,
    pub cached: u64,
    pub reasoning: u64,
}
impl WindowLedger {
    fn new(r: &Reservation) -> Self {
        Self {
            phase: r.phase,
            window: r.window,
            allocation: r.allocation,
            attempts: 0,
            spent: 0,
            input: 0,
            output: 0,
            cached: 0,
            reasoning: 0,
        }
    }
    fn add_usage(&mut self, u: Usage) -> Result<(), String> {
        self.input = self
            .input
            .checked_add(u.input)
            .ok_or("input usage overflow")?;
        self.output = self
            .output
            .checked_add(u.output)
            .ok_or("output usage overflow")?;
        self.cached = self
            .cached
            .checked_add(u.cached)
            .ok_or("cache usage overflow")?;
        self.reasoning = self
            .reasoning
            .checked_add(u.reasoning)
            .ok_or("reasoning usage overflow")?;
        Ok(())
    }
}
pub(super) fn phase_index(phase: Phase) -> usize {
    match phase {
        Phase::Discover => 0,
        Phase::Evaluate => 1,
        Phase::Solve => 2,
    }
}
fn bounded_error(value: String) -> String {
    value.chars().take(128).collect()
}

fn accounted_usage(outcome: &ProviderOutcome) -> Result<Usage, &'static str> {
    let value = outcome
        .reply
        .as_ref()
        .map_or(&outcome.known_usage, |reply| &reply.usage);
    Usage::from_complete_provider(value).map_err(|_| "provider token accounting unknown or invalid")
}

fn validate_sources(dependencies: &[String], source: Option<&String>) -> Result<(), String> {
    if dependencies.len() > crate::formal::DEPENDENCY_MAX_COUNT
        || dependencies
            .iter()
            .chain(source)
            .try_fold(0usize, |count, source| count.checked_add(source.len()))
            .is_none_or(|bytes| bytes > crate::formal::AUTHORING_MAX_BYTES)
    {
        return Err("authoring helper/source bounds exceeded".into());
    }
    Ok(())
}

fn convert(reservation: &Reservation, outcome: &ProviderOutcome) -> Result<Option<Action>, String> {
    let Some(reply) = &outcome.reply else {
        return Err(outcome
            .error
            .clone()
            .unwrap_or_else(|| "provider returned no reply".into()));
    };
    if outcome.error.is_some()
        || serde_json::from_str::<Value>(&reply.raw_response)
            .map_err(|_| "malformed retained response")?
            != reply.value
    {
        return Err("provider response provenance/value mismatch".into());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Discovery {
        title: String,
        context: String,
        formula_json: String,
        definitions: Vec<String>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Evaluation {
        question_id: String,
        yes: bool,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Solve {
        question_id: String,
        outcome: crate::formal::Outcome,
        source: String,
        dependencies: Vec<String>,
    }
    Ok(Some(match reservation.phase {
        Phase::Discover => {
            let reply: Discovery =
                serde_json::from_value(reply.value.clone()).map_err(|e| e.to_string())?;
            if reply.formula_json.len() > 8192 {
                return Err("formula projection byte bound".into());
            }
            Action::Publish {
                question: Question {
                    title: reply.title,
                    context: reply.context,
                    formula: serde_json::from_str(&reply.formula_json)
                        .map_err(|e| e.to_string())?,
                    definitions: reply.definitions,
                },
            }
        }
        Phase::Evaluate => {
            let reply: Evaluation =
                serde_json::from_value(reply.value.clone()).map_err(|e| e.to_string())?;
            let id = crate::run::parse_id(&reply.question_id)?;
            if Some(id) != reservation.target {
                return Err("evaluation replied for another question".into());
            }
            Action::Evaluate {
                question: id,
                yes: reply.yes,
            }
        }
        Phase::Solve => {
            let reply: Solve =
                serde_json::from_value(reply.value.clone()).map_err(|e| e.to_string())?;
            let id = crate::run::parse_id(&reply.question_id)?;
            if Some(id) != reservation.target {
                return Err("solve replied for another question".into());
            }
            Action::Answer {
                question: id,
                outcome: reply.outcome,
                file: crate::formal::AnswerFile {
                    source: reply.source,
                    dependencies: reply.dependencies,
                },
            }
        }
    }))
}

fn key(path: &Path) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&read_bounded::<[u8; 32]>(
        path, 1024,
    )?))
}
