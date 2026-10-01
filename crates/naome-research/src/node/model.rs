//! Versioned local identities, authenticated actions and bounded working state.

use super::{
    budget::{Bucket, Budgets, Phase, Usage, Window, window},
    store::verify,
};
use crate::{
    formal::{AnswerFile, Outcome},
    provider::ProviderConfig,
    run::Interests,
    state::{Id, PoolConfig, Question, hash},
};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

pub(super) const CHECKER_REVISION: &str = "1f7e38ffd7edfcda2dd87ecc5500f070766dfa4b";
pub(super) const TIMEZONE_RULES: &str = "chrono-tz-0.10.4";
pub(super) const PAGE_SIZE: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub directory: PathBuf,
    pub identity_file: PathBuf,
    pub run_label: String,
    pub interests: Interests,
    pub provider: ProviderConfig,
    pub budgets: Budgets,
    pub credit: u64,
    pub pool: PoolConfig,
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        self.budgets.validate()?;
        self.provider.validate().map_err(|e| e.to_string())?;
        self.interests.validate()?;
        let pool = &self.pool;
        if self.version != 2
            || !self.directory.is_absolute()
            || !self.identity_file.is_absolute()
            || self.run_label.is_empty()
            || self.run_label.len() > 128
            || pool.minimum == 0
            || pool.minimum > pool.initial
            || pool.initial > pool.maximum
            || pool.maximum > 8
            || pool.drought_ticks == 0
            || pool.quick_result_ticks == 0
            || pool.cooldown_ticks == 0
            || pool.drought_ticks > 1024
            || pool.quick_result_ticks > 1024
            || pool.cooldown_ticks > 1024
        {
            return Err("invalid v2 local node profile".into());
        }
        Ok(())
    }
    pub fn digest(&self) -> Id {
        // Moving a saved node directory does not change its economic lineage.
        hash(
            b"naome:research:config:v2\0",
            &(
                self.version,
                &self.run_label,
                &self.interests,
                &self.provider,
                &self.budgets,
                self.credit,
                &self.pool,
            ),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub foundation: String,
    pub checker_revision: String,
    pub timezone_rules: String,
    pub config: Id,
    pub coordinator: Id,
    pub participants: Vec<Id>,
    pub signature: Vec<u8>,
}
impl Profile {
    pub fn id(&self) -> Id {
        hash(
            b"naome:research:profile:v2\0",
            &(
                self.version,
                &self.foundation,
                &self.checker_revision,
                &self.timezone_rules,
                self.config,
                self.coordinator,
                &self.participants,
            ),
        )
    }
    pub fn sign(config: &Config, key: &SigningKey) -> Self {
        let mut profile = Self {
            version: 2,
            foundation: naome_foundation::FOUNDATION_ID.into(),
            checker_revision: CHECKER_REVISION.into(),
            timezone_rules: TIMEZONE_RULES.into(),
            config: config.digest(),
            coordinator: key.verifying_key().to_bytes(),
            participants: vec![key.verifying_key().to_bytes()],
            signature: vec![],
        };
        profile.signature = key.sign(&profile.id()).to_bytes().to_vec();
        profile
    }
    pub fn verify(&self, config: &Config) -> Result<(), String> {
        if self.version != 2
            || self.foundation != naome_foundation::FOUNDATION_ID
            || self.checker_revision != CHECKER_REVISION
            || self.timezone_rules != TIMEZONE_RULES
            || self.config != config.digest()
            || self.participants != [self.coordinator]
        {
            return Err("v2 profile/configuration changed or unsupported".into());
        }
        verify(self.coordinator, &self.id(), &self.signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Publish {
        question: Question,
    },
    Evaluate {
        question: Id,
        yes: bool,
    },
    Answer {
        question: Id,
        outcome: Outcome,
        file: AnswerFile,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAction {
    pub profile: Id,
    pub participant: Id,
    pub nonce: u64,
    pub action: Action,
    pub signature: Vec<u8>,
}
impl SignedAction {
    pub fn sign(profile: Id, nonce: u64, action: Action, key: &SigningKey) -> Self {
        let mut signed = Self {
            profile,
            participant: key.verifying_key().to_bytes(),
            nonce,
            action,
            signature: vec![],
        };
        signed.signature = key.sign(&signed.id()).to_bytes().to_vec();
        signed
    }
    pub fn id(&self) -> Id {
        hash(
            b"naome:research:action:v2\0",
            &(self.profile, self.participant, self.nonce, &self.action),
        )
    }
    pub fn verify(&self, profile: &Profile) -> Result<(), String> {
        if self.profile != profile.id()
            || !profile.participants.contains(&self.participant)
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len()
                > crate::state::MAX_ACTION_BYTES
        {
            return Err("wrong action profile/participant or per-action size".into());
        }
        verify(self.participant, &self.id(), &self.signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingBlock {
    pub profile: Id,
    pub question: Id,
    pub formula: Vec<u8>,
    pub published_record: u64,
    pub admission_record: u64,
    pub credit: u64,
}
impl PendingBlock {
    pub fn id(&self) -> Id {
        hash(
            b"naome:research:pending:v2\0",
            &(self.profile, self.question),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finalization {
    pub block: Id,
    pub question: Id,
    pub action: Id,
    pub submitter: Id,
    pub outcome: Outcome,
    pub canonical_proof: Vec<u8>,
    pub artifact_ids: Vec<String>,
    pub award: Id,
    pub credit: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct QuestionEntry {
    pub published: u64,
    pub ordinal: u64,
    pub evaluated: Option<bool>,
    pub pending: Option<u64>,
    pub finalized: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Lease {
    pub question: Id,
    pub since: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub profile: Id,
    pub ordinal: u64,
    pub phase: Phase,
    pub target: Option<Id>,
    pub admitted: i64,
    pub window: Window,
    pub allocation: u64,
    pub prompt: Id,
    pub prompt_text: String,
    pub schema: Value,
}
impl Reservation {
    pub fn id(&self) -> Id {
        hash(b"naome:research:reservation:v2\0", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkingState {
    pub clock: i64,
    pub discovery: Bucket,
    pub evaluation: Bucket,
    pub research: Bucket,
    pub questions: u64,
    pub unreviewed: u64,
    pub eligible: u64,
    pub pending: u64,
    pub finalized: u64,
    pub attempts: u64,
    pub in_flight: Option<u64>,
    pub received: Option<u64>,
    pub usage_unknown: Option<String>,
    pub tick: u64,
    pub next_tick: i64,
    pub target: usize,
    pub drought: u64,
    pub last_adjustment: Option<u64>,
    pub recent_results: Vec<u64>,
    pub leases: Vec<Lease>,
    pub evaluated_cursor: u64,
    pub pool_cursor: u64,
    pub solve_cursor: usize,
    pub phase_cursor: u8,
    pub backoff_until: [i64; 3],
}
impl WorkingState {
    pub fn new(config: &Config, now: i64) -> Result<Self, String> {
        let make = |phase| {
            window(
                now,
                &config.budgets.timezone,
                config.budgets.allowance(phase).period,
            )
            .map(Bucket::new)
        };
        Ok(Self {
            clock: now,
            discovery: make(Phase::Discover)?,
            evaluation: make(Phase::Evaluate)?,
            research: make(Phase::Solve)?,
            questions: 0,
            unreviewed: 0,
            eligible: 0,
            pending: 0,
            finalized: 0,
            attempts: 0,
            in_flight: None,
            received: None,
            usage_unknown: None,
            tick: 0,
            next_tick: now.checked_add(60).ok_or("clock exhausted")?,
            target: config.pool.initial,
            drought: 0,
            last_adjustment: None,
            recent_results: vec![],
            leases: vec![],
            evaluated_cursor: 0,
            pool_cursor: 0,
            solve_cursor: 0,
            phase_cursor: 0,
            backoff_until: [0; 3],
        })
    }
    pub fn bucket(&self, phase: Phase) -> &Bucket {
        match phase {
            Phase::Discover => &self.discovery,
            Phase::Evaluate => &self.evaluation,
            Phase::Solve => &self.research,
        }
    }
    pub fn bucket_mut(&mut self, phase: Phase) -> &mut Bucket {
        match phase {
            Phase::Discover => &mut self.discovery,
            Phase::Evaluate => &mut self.evaluation,
            Phase::Solve => &mut self.research,
        }
    }
    pub fn available(&self, config: &Config, phase: Phase) -> bool {
        self.bucket(phase)
            .available(config.budgets.allowance(phase))
    }
    pub fn coherent(&self) -> Result<(), String> {
        if self.target == 0
            || self.target > 8
            || self.leases.len() > 8
            || self.recent_results.len() > 8
            || self.usage_unknown.as_ref().is_some_and(|s| s.len() > 512)
        {
            return Err("invalid bounded node working state".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderOutcome {
    pub reply: Option<crate::provider::ProviderReply>,
    pub error: Option<String>,
    pub known_usage: Value,
    pub provenance: Value,
    pub retained_raw_response: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Settlement {
    pub reservation: Id,
    pub window: Window,
    pub phase: Phase,
    pub usage: Usage,
}
