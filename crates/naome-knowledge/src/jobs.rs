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
    /// Enable the bounded local graph solver and learning loop at node start.
    /// Weights, optimizer and replay stay in the local job journal.
    pub native_proof_learning: bool,
    pub finding: RoleSettings,
    pub solving: RoleSettings,
    pub selection: RoleSettings,
}

impl RoleSettings {
    /// Historical allowances are validated against the current value format,
    /// never against defaults for newly admitted obligations.
    fn validate_history(self) -> Result<(), crate::Error> {
        if self.limits.horizon_ms == 0
            || self.limits.work_units == 0
            || self.mock.proof_padding_bytes > naome_proof::CERTIFICATE_MAX_BYTES
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
            return Err(crate::ResearchFailure::RoleHistoryFormat.into());
        }
        Ok(())
    }
}

impl Settings {
    pub(crate) fn validate(self) -> Result<Self, crate::Error> {
        if self.native_proof_learning {
            crate::resources::limits().native_model_capacity()?;
            if [self.finding, self.solving]
                .iter()
                .any(|role| role.mock != MockWork::default())
            {
                return Err(crate::ResearchFailure::ConflictingProviders.into());
            }
        }
        for role in [self.finding, self.solving, self.selection] {
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
                return Err(crate::ResearchFailure::InvalidRoleLimits.into());
            }
            #[cfg(not(feature = "developer-tools"))]
            if role.mock != MockWork::default() {
                return Err(crate::ResearchFailure::DeveloperWorkloadUnavailable.into());
            }
        }
        Ok(self)
    }

    fn for_input(&self, input: &Input) -> RoleSettings {
        match input {
            Input::Find { .. } => self.finding,
            Input::Solve { .. } | Input::Peer { .. } | Input::Train { .. } => self.solving,
            Input::Select { .. } => self.selection,
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
    /// Whether this finite solving job was offered by another node.
    pub cooperative: bool,
}

impl Binding {
    pub(crate) fn new(snapshot: [u8; 32], policy: [u8; 32]) -> Self {
        Self {
            snapshot: crate::hex(&snapshot),
            policy: crate::hex(&policy),
            compatibility: crate::hex(&crate::compatibility()),
            selection: identity(&provider::DEFAULT_PROVIDER),
            cooperative: false,
        }
    }

    pub(crate) fn with_selection(mut self, selection: [u8; 32]) -> Self {
        self.selection = crate::hex(&selection);
        self
    }

    pub(crate) fn for_cooperation(mut self) -> Self {
        self.cooperative = true;
        self
    }

    fn validate(&self) -> Result<(), crate::Error> {
        for value in [
            &self.snapshot,
            &self.policy,
            &self.compatibility,
            &self.selection,
        ] {
            crate::object::id_bytes(value)?;
        }
        if self.compatibility != crate::hex(&crate::compatibility()) {
            return Err(crate::InputFault::ResearchCompatibility.into());
        }
        Ok(())
    }

    fn validate_role(&self, input: &Input) -> Result<(), crate::Error> {
        self.validate()?;
        if self.cooperative && !matches!(input, Input::Solve { .. }) {
            return Err(crate::InputFault::CooperativeRole.into());
        }
        Ok(())
    }
}

pub(crate) use crate::outcome::SelectionPurpose as Purpose;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Input {
    Peer {
        evidence: crate::learning::peer::Source,
        question: String,
        artifact: String,
        peer: String,
    },
    Train {
        epoch: u64,
    },
    Find {
        cursor: u64,
        question: String,
    },
    Solve {
        question: String,
    },
    Select {
        question: String,
        purpose: Purpose,
        root: Option<String>,
    },
}

impl Input {
    fn internal(&self) -> bool {
        matches!(self, Self::Peer { .. } | Self::Train { .. })
    }
    #[cfg(test)]
    pub(crate) fn find(cursor: u64) -> Self {
        Self::Find {
            cursor,
            question: crate::mocks::create_question(cursor),
        }
    }

    fn feedback_role(&self) -> crate::resources::feedback::Role {
        use crate::resources::feedback::Role;
        match self {
            Self::Find { .. } => Role::Finding,
            Self::Solve { .. } | Self::Peer { .. } | Self::Train { .. } => Role::Solving,
            Self::Select { root: None, .. } => Role::LocalSelection,
            Self::Select { root: Some(_), .. } => Role::PeerSelection,
        }
    }
    fn validate(&self) -> Result<(), crate::Error> {
        match self {
            Self::Find { question, .. } | Self::Select { question, .. } => {
                naome_checker::question::ResearchQuestion::source_requires_definitions(question)
                    .map_err(crate::Error::from)?;
            }
            Self::Train { epoch } => {
                if *epoch == 0 {
                    return Err(crate::InputFault::EmptyTrainingEpoch.into());
                }
            }
            Self::Peer {
                evidence,
                question,
                artifact,
                peer,
            } => {
                evidence.validate_width()?;
                naome_checker::question::ResearchQuestion::from_hex(question)
                    .map_err(crate::Error::from)?;
                crate::object::id_bytes(artifact)?;
                let parsed: libp2p::PeerId = peer
                    .parse()
                    .map_err(|_| crate::InputFault::PeerIdentitySyntax)?;
                if parsed.to_string() != *peer {
                    return Err(crate::InputFault::PeerIdentityEncoding.into());
                }
            }
            Self::Solve { question } => {
                naome_checker::question::ResearchQuestion::from_hex(question)
                    .map_err(crate::Error::from)?;
            }
        }
        if let Self::Select {
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
    Native {
        solution: Option<crate::learning::Solution>,
        frontier: Option<crate::learning::SearchFrontier>,
        terminal: Box<crate::learning::experience::TerminalEvidence>,
    },
    Question(String),
    Proof {
        proof: String,
        helpers: Vec<String>,
    },
    Program {
        units: u32,
    },
    Selected(bool),
    NoCandidate,
}

impl Output {
    fn validate(&self, input: &Input) -> Result<(), crate::Error> {
        self.validate_with_limits(
            input,
            crate::resources::limits().proof_bytes,
            crate::resources::limits().closure_objects,
            crate::resources::limits().closure_bytes,
        )
    }
    fn validate_retained(&self, input: &Input) -> Result<(), crate::Error> {
        self.validate_with_limits(
            input,
            naome_proof::CERTIFICATE_MAX_BYTES,
            naome_proof::CERTIFICATE_MAX_STEPS,
            crate::checkpoint::MAX_ROW / 8,
        )
    }
    fn validate_with_limits(
        &self,
        input: &Input,
        artifact_bytes: usize,
        objects: usize,
        bytes: usize,
    ) -> Result<(), crate::Error> {
        match (self, input) {
            (
                Self::Native {
                    solution,
                    frontier,
                    terminal,
                },
                Input::Solve { .. } | Input::Peer { .. } | Input::Train { .. },
            ) if solution.as_ref().is_none_or(|s| {
                s.source.len() <= 2 * artifact_bytes
                    && s.helpers.len() < objects
                    && s.helpers
                        .iter()
                        .all(|source| source.len() <= 2 * artifact_bytes)
            }) && crate::checkpoint::encode(self)?.len() <= bytes =>
            {
                terminal.validate(solution.as_ref())?;
                if let Some(report) = frontier {
                    let Input::Solve { question } = input else {
                        return Err(crate::ResearchFailure::OutputFrontierRole.into());
                    };
                    if solution.is_some() {
                        return Err(crate::ResearchFailure::OutputFrontierResolved.into());
                    }
                    report.validate(&naome_checker::question::ResearchQuestion::from_hex(
                        question,
                    )?)?;
                }
                Ok(())
            }
            (Self::Question(source), Input::Find { question, .. })
                if source.len() <= 2 * naome_checker::question::QUESTION_BYTES
                    && source == question =>
            {
                Ok(())
            }
            (Self::Proof { proof, helpers }, Input::Solve { .. })
                if proof.len() <= 2 * artifact_bytes
                    && helpers.len() < objects
                    && helpers.iter().all(|s| s.len() <= 2 * artifact_bytes)
                    && proof.len() + helpers.iter().map(String::len).sum::<usize>()
                        <= 2 * bytes =>
            {
                Ok(())
            }
            (Self::Program { units }, Input::Solve { .. }) if *units > 0 => Ok(()),
            (Self::NoCandidate, Input::Solve { .. })
            | (Self::Selected(_), Input::Select { .. }) => Ok(()),
            _ => Err(crate::ResearchFailure::OutputTypeCapacity.into()),
        }
    }
}

pub(crate) use crate::outcome::JobState as State;

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
    pub native: Option<Box<crate::learning::Job>>,
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
    pub failure: Option<crate::outcome::JobFailureCode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompletionFailure {
    Admission(crate::outcome::AdmissionFailure),
    Worker(crate::outcome::JobFailureCode),
    NoResult(State),
}

#[derive(Clone, Debug)]
pub(crate) struct Completion {
    pub experience: Option<crate::learning::experience::ExperienceSummary>,
    pub id: u64,
    /// Actual selected native model used by this job, including warm jobs.
    pub model_checkpoint: Option<String>,
    pub binding: Binding,
    pub spent_ms: u64,
    pub reserved_units: u32,
    pub state: State,
    pub result: Result<Output, CompletionFailure>,
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
    pub(crate) async fn completed(&mut self) -> Result<Completion, crate::Error> {
        let result = (&mut self.receiver)
            .await
            .map_err(|_| crate::Error::from(crate::ResearchFailure::ServiceStopped));
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerAdmission {
    pub evidence: Option<crate::learning::peer::Source>,
    pub ordinal: u64,
    pub artifact: String,
    pub peer: String,
    pub question: Option<String>,
    pub binding: Binding,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerReceipt {
    admission: PeerAdmission,
    status: PeerStatus,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum PeerStatus {
    Queued,
    Running {
        job: u64,
    },
    Learned {
        conversion_job: u64,
        trace_proof: String,
    },
    Unsupported {
        reason: crate::outcome::JobFailureCode,
    },
}
enum Command {
    TheoremVerified {
        ordinal: u64,
        theorem: crate::learning::knowledge::Entry,
    },
    DefinitionVerified {
        ordinal: u64,
        definition: crate::learning::definitions::Entry,
    },
    PeerVerified(PeerAdmission),
    PeerCursor(u64),
    Accepted {
        id: u64,
        root: String,
    },
    Program {
        id: u64,
        unit: u32,
        reply: oneshot::Sender<Result<Vec<naome_proof::program::Command>, crate::Error>>,
    },
    Submit(
        Input,
        Binding,
        Vec<String>,
        crate::learning::Prerequisites,
        oneshot::Sender<Completion>,
    ),
    Acknowledge(u64),
    Discard(Input, Binding),
    Recover {
        after: u64,
        before: u64,
        reply: oneshot::Sender<Result<RecoveryPage, crate::Error>>,
    },
}

/// A completed owner's bounded receipt; queue pressure never changes its job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Receipt {
    Acknowledge(u64),
    Accepted { id: u64, root: String },
    Discard(Input, Binding),
}

#[derive(Clone)]
pub(crate) struct Client {
    sender: mpsc::Sender<Command>,
    // Derived read-only mirror. The jobs journal remains the sole state owner.
    feedback: std::sync::Arc<std::sync::Mutex<Option<crate::training::ability::Feedback>>>,
}

fn command_send_error<T>(error: mpsc::error::TrySendError<T>) -> crate::Error {
    match error {
        mpsc::error::TrySendError::Full(_) => crate::ResearchFailure::CommandQueueFull.into(),
        mpsc::error::TrySendError::Closed(_) => crate::ResearchFailure::ServiceStopped.into(),
    }
}

impl Client {
    pub(crate) fn feedback(&self) -> Option<crate::training::ability::Feedback> {
        self.feedback
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub(crate) fn theorem_verified(
        &self,
        ordinal: u64,
        theorem: crate::learning::knowledge::Entry,
    ) -> Result<(), crate::Error> {
        self.sender
            .try_send(Command::TheoremVerified { ordinal, theorem })
            .map_err(command_send_error)
    }
    pub(crate) fn definition_verified(
        &self,
        ordinal: u64,
        definition: crate::learning::definitions::Entry,
    ) -> Result<(), crate::Error> {
        self.sender
            .try_send(Command::DefinitionVerified {
                ordinal,
                definition,
            })
            .map_err(command_send_error)
    }
    pub(crate) fn peer_cursor(&self, ordinal: u64) -> Result<(), crate::Error> {
        self.sender
            .try_send(Command::PeerCursor(ordinal))
            .map_err(command_send_error)
    }
    pub(crate) fn peer_verified(&self, admission: PeerAdmission) -> Result<(), crate::Error> {
        self.sender
            .try_send(Command::PeerVerified(admission))
            .map_err(command_send_error)
    }
    pub(crate) fn try_receipt(&self, receipt: &Receipt) -> Result<bool, crate::Error> {
        let command = match receipt {
            Receipt::Acknowledge(id) => Command::Acknowledge(*id),
            Receipt::Accepted { id, root } => Command::Accepted {
                id: *id,
                root: root.clone(),
            },
            Receipt::Discard(input, binding) => Command::Discard(input.clone(), binding.clone()),
        };
        match self.sender.try_send(command) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(crate::ResearchFailure::ServiceStopped.into())
            }
        }
    }
    pub(crate) fn program(
        &self,
        id: u64,
        unit: u32,
    ) -> Result<
        oneshot::Receiver<Result<Vec<naome_proof::program::Command>, crate::Error>>,
        crate::Error,
    > {
        let (reply, receive) = oneshot::channel();
        self.sender
            .try_send(Command::Program { id, unit, reply })
            .map_err(command_send_error)?;
        Ok(receive)
    }
    pub(crate) fn submit(&self, input: Input, binding: Binding) -> Result<Ticket, crate::Error> {
        self.submit_after(input, binding, Vec::new(), Default::default())
    }
    pub(crate) fn submit_after(
        &self,
        input: Input,
        binding: Binding,
        required: Vec<String>,
        prerequisites: crate::learning::Prerequisites,
    ) -> Result<Ticket, crate::Error> {
        input.validate()?;
        binding.validate_role(&input)?;
        if required.len() > crate::learning::knowledge::CAPACITY
            || required
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != required.len()
            || !required.is_empty() && !matches!(input, Input::Solve { .. })
        {
            return Err(crate::InputFault::RequiredTheorems.into());
        }
        prerequisites.validate()?;
        if !prerequisites.is_empty()
            && (!matches!(input, Input::Solve { .. })
                || required.is_empty() && !prerequisites.has_optional_context())
        {
            return Err(crate::InputFault::PrerequisiteRoots.into());
        }
        for id in &required {
            crate::object::id_bytes(id)?;
        }
        let (sender, receiver) = oneshot::channel();
        self.sender
            .try_send(Command::Submit(
                input.clone(),
                binding.clone(),
                required,
                prerequisites,
                sender,
            ))
            .map_err(command_send_error)?;
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
    ) -> Result<oneshot::Receiver<Result<RecoveryPage, crate::Error>>, crate::Error> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .try_send(Command::Recover {
                after,
                before,
                reply,
            })
            .map_err(command_send_error)?;
        Ok(receive)
    }
    pub(crate) fn acknowledge(&self, id: u64) -> Result<(), crate::Error> {
        if self.try_receipt(&Receipt::Acknowledge(id))? {
            Ok(())
        } else {
            Err(crate::ResearchFailure::CommandQueueFull.into())
        }
    }
}

pub(crate) fn declared_solver_support(
    question: &naome_checker::question::ResearchQuestion,
    settings: RoleSettings,
) -> bool {
    settings.mock.outcome == MockOutcome::Success && crate::mocks::supports_question(question)
}

pub(crate) fn solver_identity(settings: Settings) -> String {
    if settings.native_proof_learning {
        identity(&(
            crate::learning::PROVIDER,
            crate::learning::input_specification(),
            settings.solving,
        ))
    } else {
        identity(&(provider::DEFAULT_PROVIDER, settings.solving))
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

fn wall_ms() -> Result<u64, crate::Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| crate::ResearchFailure::ClockBeforeEpoch)?
        .as_millis()
        .try_into()
        .map_err(|_| crate::ResearchFailure::ClockOverflow.into())
}

pub(crate) fn internal(arguments: &[std::ffi::OsString]) -> Option<Result<(), crate::Error>> {
    process::internal(arguments)
}

#[cfg(test)]
pub(crate) mod tests;
