//! Signed, replayable local coordinator order and a separate result-block chain.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use naome_checker::ArtifactState;
use naome_foundation::{FOUNDATION_ID, Formula};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::formal::{AnswerFile, FormulaInput, Outcome, check_answer, check_definitions};

pub type Id = [u8; 32];
pub const MAX_QUESTIONS: usize = 64;
pub const MAX_EVENTS: usize = 4096;
pub const MAX_ACTION_BYTES: usize = 96 * 1024;
pub const MAX_HISTORY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub questions: usize,
    pub events: usize,
    pub action_bytes: usize,
    pub history_bytes: usize,
    pub authoring_bytes: usize,
    pub helper_artifacts: usize,
    pub formula_depth: usize,
    pub formula_nodes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            questions: MAX_QUESTIONS,
            events: MAX_EVENTS,
            action_bytes: MAX_ACTION_BYTES,
            history_bytes: MAX_HISTORY_BYTES,
            authoring_bytes: crate::formal::AUTHORING_MAX_BYTES,
            helper_artifacts: crate::formal::DEPENDENCY_MAX_COUNT,
            formula_depth: crate::formal::QUESTION_MAX_DEPTH,
            formula_nodes: crate::formal::QUESTION_MAX_NODES,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    pub minimum: usize,
    pub initial: usize,
    pub maximum: usize,
    pub drought_ticks: u64,
    pub quick_result_ticks: u64,
    pub cooldown_ticks: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            minimum: 2,
            initial: 2,
            maximum: 4,
            drought_ticks: 3,
            quick_result_ticks: 3,
            cooldown_ticks: 3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub version: u32,
    pub foundation: String,
    pub checker_revision: String,
    pub limits: Limits,
    pub nominal_tick_seconds: u64,
    pub tick_driver: String,
    pub run_label: String,
    pub coordinator: Id,
    pub participants: Vec<Id>,
    pub pool: PoolConfig,
}

impl Genesis {
    pub fn new(
        run_label: String,
        coordinator: Id,
        mut participants: Vec<Id>,
        pool: PoolConfig,
    ) -> Result<Self, String> {
        participants.sort();
        let value = Self {
            version: 1,
            foundation: FOUNDATION_ID.into(),
            checker_revision: "1f7e38ffd7edfcda2dd87ecc5500f070766dfa4b".into(),
            limits: Limits::default(),
            nominal_tick_seconds: 60,
            tick_driver: "signed_fixture".into(),
            run_label,
            coordinator,
            participants,
            pool,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        let p = &self.pool;
        if self.version != 1
            || self.foundation != FOUNDATION_ID
            || self.limits != Limits::default()
            || self.checker_revision != "1f7e38ffd7edfcda2dd87ecc5500f070766dfa4b"
            || self.nominal_tick_seconds != 60
            || !["signed_fixture", "local_timer"].contains(&self.tick_driver.as_str())
            || self.run_label.is_empty()
            || self.run_label.len() > 128
            || !(2..=16).contains(&self.participants.len())
            || self.participants.windows(2).any(|w| w[0] >= w[1])
            || p.minimum == 0
            || p.minimum > p.initial
            || p.initial > p.maximum
            || p.maximum > 8
            || p.drought_ticks == 0
            || p.quick_result_ticks == 0
            || p.cooldown_ticks == 0
            || p.drought_ticks > 1024
            || p.quick_result_ticks > 1024
            || p.cooldown_ticks > 1024
        {
            return Err("invalid experimental genesis or bounded pool settings".into());
        }
        for key in self
            .participants
            .iter()
            .chain(std::iter::once(&self.coordinator))
        {
            let key = VerifyingKey::from_bytes(key).map_err(|e| e.to_string())?;
            if key.is_weak() {
                return Err("weak identity key".into());
            }
        }
        Ok(())
    }

    pub fn id(&self) -> Id {
        hash(b"naome:research:genesis:v1\0", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedGenesis {
    pub genesis: Genesis,
    pub signature: Vec<u8>,
}

impl SignedGenesis {
    pub fn sign(genesis: Genesis, key: &SigningKey) -> Result<Self, String> {
        genesis.validate()?;
        if key.verifying_key().to_bytes() != genesis.coordinator {
            return Err("wrong coordinator key".into());
        }
        let signature = key.sign(&genesis.id()).to_bytes().to_vec();
        Ok(Self { genesis, signature })
    }
    pub fn verify(&self) -> Result<(), String> {
        self.genesis.validate()?;
        verify(
            self.genesis.coordinator,
            &self.genesis.id(),
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Question {
    pub title: String,
    pub context: String,
    pub formula: FormulaInput,
    pub definitions: Vec<String>,
}

impl Question {
    pub fn id(&self) -> Result<Id, String> {
        if self.title.is_empty() || self.title.len() > 256 || self.context.len() > 4096 {
            return Err("question title/context exceeds bounds".into());
        }
        let bytes = self.formula.canonical_bytes()?;
        Formula::negate(self.formula.to_formula()?)
            .encode_canonical()
            .map_err(|e| e.to_string())?;
        // Canonical mathematical identity prevents differently worded duplicates.
        Ok(hash(b"naome:research:question:v1\0", &bytes))
    }
    pub fn formula(&self) -> Result<Formula, String> {
        self.formula.to_formula()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Publish {
        question: Question,
    },
    Vote {
        question: Id,
        yes: bool,
    },
    Answer {
        question: Id,
        outcome: Outcome,
        file: AnswerFile,
    },
    Tick,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub genesis: Id,
    pub participant: Id,
    pub nonce: u64,
    pub action: Action,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAction {
    pub body: ActionBody,
    pub signature: Vec<u8>,
}

impl SignedAction {
    pub fn sign(genesis: Id, nonce: u64, action: Action, key: &SigningKey) -> Self {
        let body = ActionBody {
            genesis,
            participant: key.verifying_key().to_bytes(),
            nonce,
            action,
        };
        let signature = key
            .sign(&hash(b"naome:research:action:v1\0", &body))
            .to_bytes()
            .to_vec();
        Self { body, signature }
    }
    fn verify(&self) -> Result<(), String> {
        if serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > MAX_ACTION_BYTES {
            return Err("action byte limit".into());
        }
        verify(
            self.body.participant,
            &hash(b"naome:research:action:v1\0", &self.body),
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResultBlock {
    pub genesis: Id,
    pub height: u64,
    pub previous: Id,
    pub confirmation_index: u64,
    pub logical_tick: u64,
    pub action_id: Id,
    pub question_formula: Vec<u8>,
    pub question: Id,
    pub winner: Id,
    pub outcome: Outcome,
    pub canonical_proof: Vec<u8>,
    pub artifact_ids: Vec<String>,
}
impl ResultBlock {
    pub fn id(&self) -> Id {
        hash(b"naome:research:result:v1\0", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventBody {
    pub index: u64,
    pub previous: Id,
    pub action: SignedAction,
    pub result: Option<ResultBlock>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub body: EventBody,
    pub signature: Vec<u8>,
}
impl Event {
    pub fn id(&self) -> Id {
        hash(b"naome:research:event:v1\0", &self.body)
    }
}

#[derive(Clone)]
pub struct ResearchState {
    genesis: SignedGenesis,
    events: Vec<Event>,
    questions: BTreeMap<Id, Question>,
    votes: BTreeMap<(Id, Id), bool>,
    nonces: BTreeMap<Id, u64>,
    active: BTreeSet<Id>,
    results: Vec<ResultBlock>,
    artifacts: ArtifactState,
    target: usize,
    tick: u64,
    drought: u64,
    last_adjustment: Option<u64>,
    recent_results: Vec<u64>,
    enabled: bool,
    answered_interval: bool,
    history_bytes: usize,
}

impl ResearchState {
    pub fn new(genesis: SignedGenesis) -> Result<Self, String> {
        genesis.verify()?;
        let target = genesis.genesis.pool.initial;
        Ok(Self {
            genesis,
            events: Vec::new(),
            questions: BTreeMap::new(),
            votes: BTreeMap::new(),
            nonces: BTreeMap::new(),
            active: BTreeSet::new(),
            results: Vec::new(),
            artifacts: ArtifactState::new(),
            target,
            tick: 0,
            drought: 0,
            last_adjustment: None,
            recent_results: Vec::new(),
            enabled: false,
            answered_interval: false,
            history_bytes: 0,
        })
    }
    pub fn genesis(&self) -> &SignedGenesis {
        &self.genesis
    }
    pub fn events(&self) -> &[Event] {
        &self.events
    }
    pub fn results(&self) -> &[ResultBlock] {
        &self.results
    }
    pub(crate) fn artifacts(&self) -> &ArtifactState {
        &self.artifacts
    }
    pub fn questions(&self) -> &BTreeMap<Id, Question> {
        &self.questions
    }
    pub fn active(&self) -> &BTreeSet<Id> {
        &self.active
    }
    pub fn target(&self) -> usize {
        self.target
    }
    pub fn tick(&self) -> u64 {
        self.tick
    }
    pub fn next_nonce(&self, participant: Id) -> u64 {
        self.nonces.get(&participant).copied().unwrap_or(0) + 1
    }
    pub fn vote(&self, participant: Id, question: Id) -> Option<bool> {
        self.votes.get(&(question, participant)).copied()
    }
    pub fn solved(&self, question: Id) -> bool {
        self.results.iter().any(|b| b.question == question)
    }
    pub fn yes_count(&self, question: Id) -> usize {
        self.votes
            .iter()
            .filter(|((q, _), yes)| *q == question && **yes)
            .count()
    }
    pub fn ranked_candidates(&self) -> Vec<Id> {
        let mut ids: Vec<_> = self
            .questions
            .keys()
            .copied()
            .filter(|id| !self.solved(*id) && !self.active.contains(id) && self.yes_count(*id) > 0)
            .collect();
        ids.sort_by_key(|id| (std::cmp::Reverse(self.yes_count(*id)), *id));
        ids
    }

    pub fn confirm(
        &mut self,
        action: SignedAction,
        coordinator: &SigningKey,
    ) -> Result<Event, String> {
        self.check_coordinator(coordinator)?;
        if let Some(existing) = self.events.iter().find(|e| e.body.action == action) {
            return Ok(existing.clone());
        }
        // Failed checking cannot mutate state or reserve a confirmation position.
        let mut next = self.clone();
        let event = next.append_confirmation(action, coordinator)?;
        *self = next;
        Ok(event)
    }

    /// Validate a whole local transaction in one isolated snapshot.
    /// The caller publishes it only after every returned event is persisted.
    pub(crate) fn stage_actions(
        &self,
        actions: Vec<Action>,
        signing: &SigningKey,
        coordinator: &SigningKey,
    ) -> Result<(Self, Vec<Event>), String> {
        let mut next = self.clone();
        let mut events = Vec::new();
        for action in actions {
            next.check_coordinator(coordinator)?;
            let signed = SignedAction::sign(
                next.genesis.genesis.id(),
                next.next_nonce(signing.verifying_key().to_bytes()),
                action,
                signing,
            );
            events.push(next.append_confirmation(signed, coordinator)?);
        }
        Ok((next, events))
    }

    fn check_coordinator(&self, coordinator: &SigningKey) -> Result<(), String> {
        if coordinator.verifying_key().to_bytes() != self.genesis.genesis.coordinator {
            return Err("wrong coordinator".into());
        }
        Ok(())
    }

    // Only mutate a disposable snapshot; any failure discards the entire state.
    // Callers check coordinator identity and supply a fresh action (or handle retry).
    fn append_confirmation(
        &mut self,
        action: SignedAction,
        coordinator: &SigningKey,
    ) -> Result<Event, String> {
        let result = self.apply(&action)?;
        let body = EventBody {
            index: self.events.len() as u64,
            previous: self.head(),
            action,
            result,
        };
        let signature = coordinator
            .sign(&hash(b"naome:research:event:v1\0", &body))
            .to_bytes()
            .to_vec();
        let event = Event { body, signature };
        self.charge_history(&event)?;
        self.events.push(event.clone());
        Ok(event)
    }

    pub fn replay(genesis: SignedGenesis, events: &[Event]) -> Result<Self, String> {
        let mut state = Self::new(genesis)?;
        for event in events {
            if event.body.index != state.events.len() as u64 || event.body.previous != state.head()
            {
                return Err("event order or predecessor mismatch".into());
            }
            verify(
                state.genesis.genesis.coordinator,
                &event.id(),
                &event.signature,
            )?;
            let result = state.apply(&event.body.action)?;
            if result != event.body.result {
                return Err("derived result block mismatch".into());
            }
            state.charge_history(event)?;
            state.events.push(event.clone());
        }
        Ok(state)
    }

    pub fn head(&self) -> Id {
        self.events
            .last()
            .map(Event::id)
            .unwrap_or_else(|| self.genesis.genesis.id())
    }

    fn apply(&mut self, signed: &SignedAction) -> Result<Option<ResultBlock>, String> {
        if self.events.len() >= MAX_EVENTS {
            return Err("event capacity reached".into());
        }
        signed.verify()?;
        let body = &signed.body;
        if body.genesis != self.genesis.genesis.id()
            || body.nonce != self.next_nonce(body.participant)
        {
            return Err("genesis or participant nonce mismatch".into());
        }
        let is_coordinator = body.participant == self.genesis.genesis.coordinator;
        let registered = self
            .genesis
            .genesis
            .participants
            .contains(&body.participant);
        if !registered && !matches!(body.action, Action::Tick) {
            return Err("unregistered participant".into());
        }
        let mut result = None;
        match &body.action {
            Action::Publish { question } => {
                let id = question.id()?;
                if self.questions.len() >= MAX_QUESTIONS || self.questions.contains_key(&id) {
                    return Err("duplicate question or capacity reached".into());
                }
                let definitions = check_definitions(&question.definitions, &self.artifacts)?;
                self.artifacts = definitions;
                self.questions.insert(id, question.clone());
            }
            Action::Vote { question, yes } => {
                if !self.questions.contains_key(question) || self.solved(*question) {
                    return Err("vote requires published unanswered question".into());
                }
                if self.vote(body.participant, *question) == Some(*yes) {
                    return Err("vote unchanged; explicit revision required".into());
                }
                self.votes.insert((*question, body.participant), *yes);
                // Existing active leases survive later relevance revisions.
            }
            Action::Answer {
                question,
                outcome,
                file,
            } => {
                if !self.active.contains(question) || self.solved(*question) {
                    return Err("answer requires active unanswered question".into());
                }
                let expected = self
                    .questions
                    .get(question)
                    .ok_or("unpublished question")?
                    .formula()?;
                let checked = check_answer(file, &expected, *outcome, &self.artifacts)?;
                self.artifacts = checked.resulting_state;
                let block = ResultBlock {
                    genesis: self.genesis.genesis.id(),
                    height: self.results.len() as u64 + 1,
                    previous: self
                        .results
                        .last()
                        .map(ResultBlock::id)
                        .unwrap_or_else(|| self.genesis.genesis.id()),
                    confirmation_index: self.events.len() as u64,
                    logical_tick: self.tick,
                    action_id: hash(b"naome:research:action:v1\0", body),
                    question_formula: expected.encode_canonical().map_err(|e| e.to_string())?,
                    question: *question,
                    winner: body.participant,
                    outcome: *outcome,
                    canonical_proof: checked.canonical_bytes,
                    artifact_ids: checked.artifact_ids,
                };
                self.results.push(block.clone());
                self.active.remove(question);
                self.drought = 0;
                self.answered_interval = true;
                self.recent_results.push(self.tick);
                result = Some(block);
            }
            Action::Tick => {
                if !is_coordinator {
                    return Err("only coordinator may advance logical clock".into());
                }
                self.tick = self.tick.checked_add(1).ok_or("logical clock exhausted")?;
                let lower = self
                    .tick
                    .saturating_sub(self.genesis.genesis.pool.quick_result_ticks);
                self.recent_results
                    .retain(|t| *t >= lower && *t < self.tick);
                if self.answered_interval || !self.enabled {
                    self.drought = 0;
                } else {
                    self.drought = self
                        .drought
                        .checked_add(1)
                        .ok_or("drought counter exhausted")?;
                }
                let mut adjusted = false;
                if self.can_adjust() {
                    if self.recent_results.len() >= 2
                        && self.target > self.genesis.genesis.pool.minimum
                    {
                        self.target -= 1;
                        adjusted = true;
                    } else if self.drought >= self.genesis.genesis.pool.drought_ticks
                        && self.target < self.genesis.genesis.pool.maximum
                        && !self.ranked_candidates().is_empty()
                    {
                        self.target += 1;
                        adjusted = true;
                    }
                }
                if adjusted {
                    self.drought = 0;
                    self.last_adjustment = Some(self.tick);
                    self.recent_results.clear();
                }
                self.shrink();
                self.fill();
                self.enabled = !self.active.is_empty();
                self.answered_interval = false;
            }
        }
        self.nonces.insert(body.participant, body.nonce);
        Ok(result)
    }

    fn can_adjust(&self) -> bool {
        self.last_adjustment
            .is_none_or(|t| self.tick.saturating_sub(t) >= self.genesis.genesis.pool.cooldown_ticks)
    }
    fn fill(&mut self) {
        let vacancies = self.target.saturating_sub(self.active.len());
        for id in self.ranked_candidates().into_iter().take(vacancies) {
            self.active.insert(id);
        }
    }
    fn shrink(&mut self) {
        let mut ids: Vec<_> = self.active.iter().copied().collect();
        ids.sort_by_key(|id| (std::cmp::Reverse(self.yes_count(*id)), *id));
        for id in ids.into_iter().skip(self.target) {
            self.active.remove(&id);
        }
    }
    fn charge_history(&mut self, event: &Event) -> Result<(), String> {
        self.history_bytes = self
            .history_bytes
            .checked_add(serde_json::to_vec(event).map_err(|e| e.to_string())?.len())
            .ok_or("history byte counter exhausted")?;
        if self.history_bytes > MAX_HISTORY_BYTES {
            return Err("history byte limit".into());
        }
        Ok(())
    }
}

pub fn hash(domain: &[u8], value: &impl Serialize) -> Id {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(serde_json::to_vec(value).expect("fixed research records serialize"));
    digest.finalize().into()
}

fn verify(key: Id, message: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(&key).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(signature).map_err(|e| e.to_string())?;
    key.verify_strict(message, &signature)
        .map_err(|_| "invalid research signature".into())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
