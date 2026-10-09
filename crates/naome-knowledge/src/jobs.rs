//! Bounded, durable research jobs. A result is a candidate, never admission.
//!
//! The ordinary node owns one service thread and a finite set of supervised
//! processes. No graph, accepted-store lock or participation key enters them.
//! Immutable inputs and reservations precede execution; acknowledged terminal
//! records may be compacted, but obligation budgets and sequence IDs survive.

mod journal;
mod process;
mod service;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

pub(crate) use journal::{
    marker_valid, read as read_checkpoint, research_directory, write as write_checkpoint,
    write_marker,
};
pub(crate) use service::Recovery;
pub(crate) use service::Service;

pub(crate) const COMMAND_CAPACITY: usize = 32;
pub(crate) const MAX_RECORDS: usize = 96;
pub(crate) const MAX_ACCOUNTS: usize = 256;
pub(crate) const MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_FRAME_BYTES: usize = 8 * crate::intake::MAX_CLOSURE_BYTES;
pub(crate) const MAX_HORIZON_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub horizon_ms: u64,
    pub work_units: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            horizon_ms: 24 * 60 * 60 * 1_000,
            work_units: 4096,
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

impl Settings {
    pub(crate) fn validate(self) -> Result<Self, String> {
        for role in [self.finding, self.solving, self.interest] {
            if !(10..=MAX_HORIZON_MS).contains(&role.limits.horizon_ms)
                || !(1..=1_000_000).contains(&role.limits.work_units)
                || role.mock.step_ms > 60_000
                || role.mock.cpu_ms > 60_000
                || role.mock.steps > 1_000_000
                || role.mock.proof_padding_bytes > crate::MAX_PROOF_BYTES
                || role.mock.result_delay_ms > 60_000
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
            selection: identity(&"naome-deterministic-mocks-v1"),
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
        match self {
            Self::Find { .. } => 0,
            Self::Solve { .. } => 1,
            Self::Interest { root: None, .. } => 2,
            Self::Interest { root: Some(_), .. } => 3,
        }
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
    Interest(bool),
    NoCandidate,
}

impl Output {
    fn validate(&self, input: &Input) -> Result<(), String> {
        match (self, input) {
            (Self::Question(source), Input::Find { .. })
                if source.len() <= naome_authoring::QUESTION_SOURCE_MAX_BYTES =>
            {
                Ok(())
            }
            (Self::Proof { source, helpers }, Input::Solve { .. })
                if source.len() <= crate::MAX_PROOF_BYTES
                    && helpers.len() < crate::intake::MAX_CLOSURE_OBJECTS
                    && helpers.iter().all(|s| s.len() <= crate::MAX_PROOF_BYTES)
                    && source.len() + helpers.iter().map(String::len).sum::<usize>()
                        <= crate::intake::MAX_CLOSURE_BYTES =>
            {
                Ok(())
            }
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
    /// The exact completed provider request is immutable across recovery.
    /// Absence on a generation record is accepted only as legacy replay data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<crate::generation::Request>,
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

enum Command {
    Submit(
        Input,
        Binding,
        Option<Box<crate::generation::Request>>,
        oneshot::Sender<Completion>,
    ),
    Acknowledge(u64),
    Discard(Input, Binding),
}

#[derive(Clone)]
pub(crate) struct Client {
    sender: mpsc::Sender<Command>,
}

impl Client {
    /// Interest retains its existing bounded selector input. Generation must
    /// carry a completed request rather than inventing absent native context.
    pub(crate) fn submit(&self, input: Input, binding: Binding) -> Result<Ticket, String> {
        self.submit_request(input, binding, None)
    }
    pub(crate) fn submit_generation(
        &self,
        input: Input,
        binding: Binding,
        request: crate::generation::Request,
    ) -> Result<Ticket, String> {
        self.submit_request(input, binding, Some(request))
    }
    fn submit_request(
        &self,
        input: Input,
        binding: Binding,
        generation: Option<crate::generation::Request>,
    ) -> Result<Ticket, String> {
        input.validate()?;
        binding.validate()?;
        validate_generation(&input, &binding, generation.as_ref())?;
        let (sender, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Submit(
                input.clone(),
                binding.clone(),
                generation.map(Box::new),
                sender,
            ))
            .map_err(|_| "research command capacity or stopped service")?;
        Ok(Ticket {
            receiver,
            client: self.clone(),
            input,
            binding,
            received: false,
        })
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

/// Enforce the role and original input/binding before any provider can start.
fn validate_generation(
    input: &Input,
    binding: &Binding,
    request: Option<&crate::generation::Request>,
) -> Result<(), String> {
    match (input, request) {
        (Input::Find { .. } | Input::Solve { .. }, Some(request)) => {
            request.validate(input, binding)
        }
        (Input::Find { .. } | Input::Solve { .. }, None) => {
            Err("generation context unavailable: completed request required".into())
        }
        (Input::Interest { .. }, None) => Ok(()),
        (Input::Interest { .. }, Some(_)) => {
            Err("interest job carries a generation request".into())
        }
    }
}

fn identity(value: &impl Serialize) -> String {
    crate::hex(&Sha256::digest(
        serde_json::to_vec(value).expect("finite research value"),
    ))
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
