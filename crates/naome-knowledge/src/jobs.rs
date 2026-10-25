//! Bounded, durable research jobs. A result is a candidate, never admission.
//!
//! The ordinary node owns one service thread and a finite set of supervised
//! processes. No graph, accepted-store lock or participation key enters them.
//! Immutable inputs and reservations precede execution; acknowledged terminal
//! records may be compacted, but obligation budgets and sequence IDs survive.

mod allowance;
mod journal;
mod process;
mod program;
mod provider;
mod service;
mod tracked;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

pub(crate) use service::Recovery;
pub(crate) use service::Service;

fn max_frame_bytes() -> usize {
    8 * crate::resources::limits().closure_bytes
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub horizon_ms: u64,
    pub work_units: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            horizon_ms: crate::resources::limits().job_horizon.as_millis() as u64,
            work_units: crate::resources::limits().job_work_units,
        }
    }
}

/// Deterministic local provider workload. No model or external effect is used.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MockWork {
    pub step_ms: u64,
    /// Zero deliberately waits until its original job budget expires.
    pub steps: u32,
    pub cpu_ms: u64,
    pub outcome: MockOutcome,
    /// One same-group stand-in child exercises descendant cleanup.
    pub descendant: bool,
    /// Bounded source padding forces genuine pipe output backpressure in tests.
    pub proof_padding_bytes: usize,
    pub result_delay_ms: u64,
    /// Developer-only streamed candidate workload; zero uses the ordinary catalog.
    pub program_units: u32,
}

impl Default for MockWork {
    fn default() -> Self {
        Self {
            step_ms: 0,
            steps: 1,
            cpu_ms: 0,
            outcome: MockOutcome::Success,
            descendant: false,
            proof_padding_bytes: 0,
            result_delay_ms: 0,
            program_units: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MockOutcome {
    #[default]
    Success,
    Failed,
    Malformed,
    WrongTarget,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RoleSettings {
    pub limits: Limits,
    pub mock: MockWork,
    pub recovery: RecoveryPolicy,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPolicy {
    #[default]
    DeterministicCheckpoint,
    HoldInFlight,
}

/// Independent horizons; transport leases deliberately do not appear here.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub finding: RoleSettings,
    pub solving: RoleSettings,
    pub interest: RoleSettings,
}

impl RoleSettings {
    /// Historical allowances are validated against the current value format,
    /// never against defaults for newly admitted obligations.
    fn validate_history(self) -> Result<(), String> {
        if self.limits.horizon_ms == 0
            || self.limits.work_units == 0
            || self.mock.proof_padding_bytes > naome_authoring::AUTHORING_SOURCE_MAX_BYTES
            || [
                self.limits.horizon_ms,
                self.mock.step_ms,
                self.mock.cpu_ms,
                self.mock.result_delay_ms,
            ]
            .into_iter()
            .any(|ms| {
                std::time::Instant::now()
                    .checked_add(std::time::Duration::from_millis(ms))
                    .is_none()
            })
        {
            return Err("research historical role value exceeds its format".into());
        }
        Ok(())
    }
}

impl Settings {
    pub(crate) fn validate(self) -> Result<Self, String> {
        for role in [self.finding, self.solving, self.interest] {
            if role.limits.horizon_ms == 0
                || role.limits.work_units == 0
                || crate::jobs::wall_ms()?
                    .checked_add(role.limits.horizon_ms)
                    .is_none()
                || [
                    role.limits.horizon_ms,
                    role.mock.step_ms,
                    role.mock.cpu_ms,
                    role.mock.result_delay_ms,
                ]
                .into_iter()
                .any(|ms| {
                    std::time::Instant::now()
                        .checked_add(std::time::Duration::from_millis(ms))
                        .is_none()
                })
                || role.mock.proof_padding_bytes > crate::resources::limits().proof_bytes
            {
                return Err("research role horizon or workload limit".into());
            }
            #[cfg(not(feature = "developer-tools"))]
            if role.mock != MockWork::default() {
                return Err("controlled mock workloads require developer-tools".into());
            }
        }
        Ok(self)
    }

    fn for_input(&self, input: &Input) -> RoleSettings {
        match input {
            Input::Find { .. } => self.finding,
            Input::Solve { .. } => self.solving,
            Input::Interest { .. } => self.interest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub snapshot: String,
    pub policy: String,
    pub compatibility: String,
    pub selection: String,
}

impl Binding {
    pub(crate) fn new(snapshot: [u8; 32], policy: [u8; 32]) -> Self {
        Self {
            snapshot: crate::hex(&snapshot),
            policy: crate::hex(&policy),
            compatibility: crate::hex(&crate::compatibility()),
            selection: identity(&provider::DEFAULT_PROVIDER),
        }
    }

    pub(crate) fn with_selection(mut self, selection: [u8; 32]) -> Self {
        self.selection = crate::hex(&selection);
        self
    }

    fn validate(&self) -> Result<(), String> {
        for value in [
            &self.snapshot,
            &self.policy,
            &self.compatibility,
            &self.selection,
        ] {
            crate::object::id_bytes(value)?;
        }
        if self.compatibility != crate::hex(&crate::compatibility()) {
            return Err("research compatibility differs".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Purpose {
    Assessment,
    Admission,
    Initial,
    Final,
    Publication,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Input {
    Find {
        cursor: u64,
    },
    Solve {
        question: String,
    },
    Interest {
        question: String,
        purpose: Purpose,
        root: Option<String>,
    },
}

impl Input {
    fn feedback_role(&self) -> crate::resources::feedback::Role {
        use crate::resources::feedback::Role;
        match self {
            Self::Find { .. } => Role::Finding,
            Self::Solve { .. } => Role::Solving,
            Self::Interest { root: None, .. } => Role::LocalInterest,
            Self::Interest { root: Some(_), .. } => Role::PeerInterest,
        }
    }
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Find { .. } => {}
            Self::Solve { question } | Self::Interest { question, .. } => {
                naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
            }
        }
        if let Self::Interest {
            root: Some(root), ..
        } = self
        {
            crate::object::id_bytes(root)?;
        }
        Ok(())
    }

    fn lane(&self) -> usize {
        self.feedback_role().index()
    }

    fn account_key(&self) -> String {
        identity(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum Output {
    Question(String),
    Proof {
        source: String,
        helpers: Vec<String>,
    },
    Program {
        units: u32,
    },
    Interest(bool),
    NoCandidate,
}

impl Output {
    fn validate(&self, input: &Input) -> Result<(), String> {
        self.validate_with_limits(
            input,
            crate::resources::limits().proof_bytes,
            crate::resources::limits().closure_objects,
            crate::resources::limits().closure_bytes,
        )
    }
    fn validate_retained(&self, input: &Input) -> Result<(), String> {
        self.validate_with_limits(
            input,
            naome_authoring::AUTHORING_SOURCE_MAX_BYTES,
            naome_proof::CERTIFICATE_MAX_STEPS,
            crate::checkpoint::MAX_ROW / 8,
        )
    }
    fn validate_with_limits(
        &self,
        input: &Input,
        source_bytes: usize,
        objects: usize,
        bytes: usize,
    ) -> Result<(), String> {
        match (self, input) {
            (Self::Question(source), Input::Find { .. })
                if source.len() <= naome_authoring::QUESTION_SOURCE_MAX_BYTES =>
            {
                Ok(())
            }
            (Self::Proof { source, helpers }, Input::Solve { .. })
                if source.len() <= source_bytes
                    && helpers.len() < objects
                    && helpers.iter().all(|s| s.len() <= source_bytes)
                    && source.len() + helpers.iter().map(String::len).sum::<usize>() <= bytes =>
            {
                Ok(())
            }
            (Self::Program { units }, Input::Solve { .. }) if *units > 0 => Ok(()),
            (Self::NoCandidate, Input::Solve { .. })
            | (Self::Interest(_), Input::Interest { .. }) => Ok(()),
            _ => Err("provider result type or capacity differs".into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    Queued,
    Running,
    Suspended,
    Complete,
    Failed,
    Cancelled,
    Expired,
    InDoubt,
}

impl State {
    fn terminal(self) -> bool {
        !matches!(
            self,
            Self::Queued | Self::Running | Self::Suspended | Self::InDoubt
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub id: u64,
    pub input: Input,
    pub binding: Binding,
    pub provider: String,
    pub configuration: String,
    pub settings: RoleSettings,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub accounted_ms: u64,
    pub spent_ms: u64,
    /// Charged before starting each unit. Uncertain work is never refunded.
    pub reserved_units: u32,
    pub checkpoint: u32,
    pub state: State,
    pub result: Option<Output>,
    pub acknowledged: bool,
    pub failure: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Completion {
    pub id: u64,
    pub binding: Binding,
    pub spent_ms: u64,
    pub reserved_units: u32,
    pub state: State,
    pub result: Result<Output, String>,
}

pub(crate) struct Ticket {
    receiver: oneshot::Receiver<Completion>,
    client: Client,
    input: Input,
    binding: Binding,
    received: bool,
}

impl Ticket {
    pub(crate) fn try_recv(&mut self) -> Result<Completion, oneshot::error::TryRecvError> {
        let result = self.receiver.try_recv();
        if result.is_ok() {
            self.received = true;
        }
        result
    }
    pub(crate) async fn completed(&mut self) -> Result<Completion, String> {
        let result = (&mut self.receiver)
            .await
            .map_err(|_| "research service stopped".into());
        if result.is_ok() {
            self.received = true;
        }
        result
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.received {
            self.receiver.close();
            let _ = self
                .client
                .sender
                .try_send(Command::Discard(self.input.clone(), self.binding.clone()));
        }
    }
}

pub(crate) struct RecoveryPage {
    pub records: Vec<Record>,
    pub next: Option<u64>,
}

enum Command {
    Program {
        id: u64,
        unit: u32,
        reply: oneshot::Sender<Result<Vec<naome_proof::program::Command>, String>>,
    },
    Submit(Input, Binding, oneshot::Sender<Completion>),
    Acknowledge(u64),
    Discard(Input, Binding),
    Recover {
        after: u64,
        before: u64,
        reply: oneshot::Sender<Result<RecoveryPage, String>>,
    },
}

#[derive(Clone)]
pub(crate) struct Client {
    sender: mpsc::Sender<Command>,
}

impl Client {
    pub(crate) fn program(
        &self,
        id: u64,
        unit: u32,
    ) -> Result<oneshot::Receiver<Result<Vec<naome_proof::program::Command>, String>>, String> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .try_send(Command::Program { id, unit, reply })
            .map_err(|_| "research candidate capacity or stopped service")?;
        Ok(receive)
    }
    pub(crate) fn submit(&self, input: Input, binding: Binding) -> Result<Ticket, String> {
        input.validate()?;
        binding.validate()?;
        let (sender, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Submit(input.clone(), binding.clone(), sender))
            .map_err(|_| "research command capacity or stopped service")?;
        Ok(Ticket {
            receiver,
            client: self.clone(),
            input,
            binding,
            received: false,
        })
    }
    pub(crate) fn recover(
        &self,
        after: u64,
        before: u64,
    ) -> Result<oneshot::Receiver<Result<RecoveryPage, String>>, String> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .try_send(Command::Recover {
                after,
                before,
                reply,
            })
            .map_err(|_| "research recovery capacity or stopped service")?;
        Ok(receive)
    }
    pub(crate) fn acknowledge(&self, id: u64) -> Result<(), String> {
        self.sender
            .try_send(Command::Acknowledge(id))
            .map_err(|_| "research acknowledgement capacity or stopped service".into())
    }
    pub(crate) fn discard(&self, input: Input, binding: Binding) -> Result<(), String> {
        self.sender
            .try_send(Command::Discard(input, binding))
            .map_err(|_| "research retirement command capacity or stopped service".into())
    }
}

fn identity(value: &impl Serialize) -> String {
    crate::hex(&Sha256::digest(
        serde_json::to_vec(value).expect("finite research value"),
    ))
}

fn request_key(input: &Input, binding: &Binding, settings: RoleSettings) -> String {
    let mut hash = Sha256::new();
    hash.update(b"naome:research-request:v1\0");
    hash.update(serde_json::to_vec(&(input, binding, settings)).expect("finite typed request"));
    crate::hex(&hash.finalize())
}

fn wall_ms() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "wall clock is before research epoch".to_owned())?
        .as_millis()
        .try_into()
        .map_err(|_| "research clock overflow".into())
}

pub(crate) fn internal(arguments: &[std::ffi::OsString]) -> Option<Result<(), String>> {
    process::internal(arguments)
}

#[cfg(test)]
pub(crate) mod tests;
