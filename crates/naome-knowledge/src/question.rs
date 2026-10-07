//! Local formal prefilter, optional interest selection and atomic question intake.
//!
//! Assessment is read-only. Admission rechecks the receiver's current graph,
//! registry and policy after interest, then commits in the same serialized node
//! operation. Baseline import is a separate owner-held administrative capability.
//! The registry is in-memory local knowledge. Peer descriptions carry derived
//! obligations; neither their source nor an earlier result authorizes a write.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use naome_authoring::CompiledQuestion;
use naome_checker::question::{
    AssessmentQuestion, Identity, KnowledgeSnapshot, NodeLocalNovelty, PrefilterDecision,
    PrefilterPolicy, QuestionRegistry, RegisteredQuestion, RejectionReason, assess_question,
};
use naome_foundation::FOUNDATION_ID;
use tokio::sync::{mpsc, oneshot};

use crate::Graph;

pub const QUESTION_QUEUE: usize = 8;
pub const INTEREST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterestAssessment {
    NotRun,
    Assessed(bool),
    ProviderFailed,
    TimedOut,
    Stale,
}

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct QuestionAssessment {
    /// Supported finite formal checks, separate from interest selection.
    pub prefilter: PrefilterDecision,
    pub interest: InterestAssessment,
    pub submitted_negation_parity: bool,
}

impl QuestionAssessment {
    /// First discovery within the bound complete local world and finite rules.
    /// Interest failure or nonselection does not change this formal result.
    pub fn novelty(&self) -> Option<&NodeLocalNovelty> {
        self.prefilter.novelty()
    }
}

/// Observed local registry effect, emitted only after a successful insertion.
/// No API accepts this receipt or an earlier Pass as insertion authority.
///
/// ```compile_fail
/// fn rebind(receipt: &mut naome_knowledge::question::AdmissionReceipt) {
///     receipt.record = [0; 32];
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionReceipt {
    record: Identity,
    snapshot_after: Identity,
    registry_before: Identity,
    registry_after: Identity,
    novelty: NodeLocalNovelty,
}

impl AdmissionReceipt {
    pub const fn record(&self) -> Identity {
        self.record
    }
    pub const fn input(&self) -> Identity {
        self.novelty.input_id()
    }
    pub const fn policy(&self) -> Identity {
        self.novelty.policy_id()
    }
    pub const fn snapshot_before(&self) -> Identity {
        self.novelty.snapshot_id()
    }
    pub const fn snapshot_after(&self) -> Identity {
        self.snapshot_after
    }
    pub const fn registry_before(&self) -> Identity {
        self.registry_before
    }
    pub const fn registry_after(&self) -> Identity {
        self.registry_after
    }
    /// Fresh checker result for the world immediately before this insertion.
    pub const fn novelty(&self) -> &NodeLocalNovelty {
        &self.novelty
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionOutcome {
    Admitted(Box<AdmissionReceipt>),
    /// Formal rejection, stale context or no positive interest selection.
    /// Inspect prefilter and interest separately; selection is not correctness.
    NotInserted,
}

#[derive(Clone, Debug)]
pub struct QuestionAdmission {
    pub assessment: QuestionAssessment,
    pub outcome: AdmissionOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntakeError {
    QueueFull,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalQuestionContext {
    pub snapshot: Identity,
    pub policy: Identity,
    pub checked_proofs: usize,
    pub registered_questions: usize,
}

pub(crate) enum Command {
    Assess(CompiledQuestion, oneshot::Sender<QuestionAssessment>),
    Admit(CompiledQuestion, oneshot::Sender<QuestionAdmission>),
    ImportBaseline(
        CompiledQuestion,
        oneshot::Sender<Result<(), RejectionReason>>,
    ),
    Policy(PrefilterPolicy, oneshot::Sender<()>),
    Context(oneshot::Sender<LocalQuestionContext>),
    Stop(oneshot::Sender<()>),
}

/// Ordinary local intake. It cannot mint the administrative import capability.
///
/// ```compile_fail
/// fn bypass(handle: &naome_knowledge::question::QuestionHandle,
///           question: naome_authoring::CompiledQuestion) {
///     let _ = handle.import_baseline(question);
/// }
/// ```
#[derive(Clone)]
pub struct QuestionHandle {
    sender: mpsc::Sender<Command>,
}

/// Explicit capability retained by the receiving node's embedding owner.
/// Baseline import preserves known/preexisting questions and is not admission.
#[derive(Clone)]
pub struct QuestionAdminHandle {
    sender: mpsc::Sender<Command>,
}

pub struct QuestionInbox {
    receiver: mpsc::Receiver<Command>,
}

impl QuestionInbox {
    pub(crate) async fn receive(&mut self) -> Option<Command> {
        self.receiver.recv().await
    }
}

/// The creator chooses who receives the administrative capability; cloning an
/// ordinary handle never grants import or policy mutation.
pub fn channel() -> (QuestionHandle, QuestionAdminHandle, QuestionInbox) {
    let (sender, receiver) = mpsc::channel(QUESTION_QUEUE);
    (
        QuestionHandle {
            sender: sender.clone(),
        },
        QuestionAdminHandle { sender },
        QuestionInbox { receiver },
    )
}

async fn send<T>(
    sender: &mpsc::Sender<Command>,
    command: Command,
    reply: oneshot::Receiver<T>,
) -> Result<T, IntakeError> {
    sender.try_send(command).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => IntakeError::QueueFull,
        mpsc::error::TrySendError::Closed(_) => IntakeError::Stopped,
    })?;
    reply.await.map_err(|_| IntakeError::Stopped)
}

impl QuestionHandle {
    pub async fn assess(
        &self,
        question: CompiledQuestion,
    ) -> Result<QuestionAssessment, IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Assess(question, sender), reply).await
    }

    /// Fresh formal admission after positive optional interest selection.
    /// A changed graph, registry or policy invalidates the pending selection;
    /// an earlier assessment/receipt is never an argument or authorization.
    pub async fn admit_question(
        &self,
        question: CompiledQuestion,
    ) -> Result<QuestionAdmission, IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Admit(question, sender), reply).await
    }

    pub async fn context(&self) -> Result<LocalQuestionContext, IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Context(sender), reply).await
    }
}

impl QuestionAdminHandle {
    /// Imports parser-validated baseline knowledge, including already answered
    /// questions. This deliberate owner operation has no formal-admission claim.
    pub async fn import_baseline(
        &self,
        question: CompiledQuestion,
    ) -> Result<Result<(), RejectionReason>, IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(
            &self.sender,
            Command::ImportBaseline(question, sender),
            reply,
        )
        .await
    }

    pub async fn set_policy(&self, policy: PrefilterPolicy) -> Result<(), IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Policy(policy, sender), reply).await
    }

    pub async fn stop(&self) -> Result<(), IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Stop(sender), reply).await
    }
}

enum Reply {
    Assessment(oneshot::Sender<QuestionAssessment>),
    Admission(oneshot::Sender<QuestionAdmission>),
    Exchange {
        reply: oneshot::Sender<QuestionAssessment>,
        deadline: Instant,
    },
}

impl Reply {
    fn is_closed(&self) -> bool {
        match self {
            Self::Assessment(reply) | Self::Exchange { reply, .. } => reply.is_closed(),
            Self::Admission(reply) => reply.is_closed(),
        }
    }

    fn admission(&self) -> bool {
        matches!(self, Self::Admission(_))
    }

    fn exchange(&self) -> bool {
        matches!(self, Self::Exchange { .. })
    }

    fn send(self, assessment: QuestionAssessment, outcome: AdmissionOutcome) -> bool {
        match self {
            Self::Assessment(reply) | Self::Exchange { reply, .. } => {
                reply.send(assessment).is_ok()
            }
            Self::Admission(reply) => reply
                .send(QuestionAdmission {
                    assessment,
                    outcome,
                })
                .is_ok(),
        }
    }
}

struct Pending {
    question: CompiledQuestion,
    prefilter: PrefilterDecision,
    reply: Reply,
    future: Pin<Box<dyn Future<Output = InterestAssessment> + Send>>,
}

struct AdmittedProvenance {
    question: CompiledQuestion,
    receipt: AdmissionReceipt,
}

pub(crate) struct QuestionDelta {
    registry: QuestionRegistry,
}

pub(crate) struct LocalQuestions<F> {
    registry: QuestionRegistry,
    policy: PrefilterPolicy,
    provider: Option<F>,
    pending: Option<Pending>,
    /// One computed read-only decision, never an admission or interest receipt.
    cached: Option<PrefilterDecision>,
    /// Only successful local admission with an actually delivered receipt.
    admitted: BTreeMap<Identity, AdmittedProvenance>,
    #[cfg(test)]
    computations: usize,
}

impl<F, Fut> LocalQuestions<F>
where
    F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<bool, String>> + Send + 'static,
{
    pub(crate) fn new(provider: Option<F>) -> Self {
        Self {
            registry: QuestionRegistry::new(),
            policy: PrefilterPolicy::default(),
            provider,
            pending: None,
            cached: None,
            admitted: BTreeMap::new(),
            #[cfg(test)]
            computations: 0,
        }
    }

    fn snapshot<'a>(&'a self, graph: &'a Graph) -> KnowledgeSnapshot<'a> {
        KnowledgeSnapshot::new(
            crate::compatibility(),
            graph.checked_context(),
            &self.registry,
        )
    }

    pub(crate) fn context_key(&self, graph: &Graph) -> (Identity, Identity) {
        (self.snapshot(graph).identity(), self.policy.identity())
    }

    fn evaluate(
        &mut self,
        graph: &Graph,
        question: &CompiledQuestion,
        reuse: bool,
    ) -> PrefilterDecision {
        self.evaluate_record(graph, question, reuse, None)
    }

    fn evaluate_record(
        &mut self,
        graph: &Graph,
        question: &CompiledQuestion,
        reuse: bool,
        record: Option<Identity>,
    ) -> PrefilterDecision {
        let snapshot = self.snapshot(graph);
        let request = AssessmentQuestion::new(
            FOUNDATION_ID,
            question.core(),
            question.source().as_bytes(),
            &[],
            record,
        )
        .expect("bounded parser-validated question input");
        if reuse
            && let Some(cached) = &self.cached
            && cached.matches_inputs(&request, &snapshot, &self.policy)
        {
            return cached.clone();
        }
        let mut decision = assess_question(&request, &snapshot, &self.policy);
        #[cfg(test)]
        {
            self.computations += 1;
        }
        if question.negation_parity() {
            decision.reason = match decision.reason {
                Some(RejectionReason::KnownProof) => Some(RejectionReason::KnownRefutation),
                Some(RejectionReason::KnownRefutation) => Some(RejectionReason::KnownProof),
                other => other,
            };
        }
        self.cached = Some(decision.clone());
        decision
    }

    fn assess(&mut self, graph: &Graph, question: &CompiledQuestion) -> PrefilterDecision {
        self.evaluate(graph, question, true)
    }

    fn exchange_record(&self, question: &CompiledQuestion) -> Option<Identity> {
        self.admitted
            .get(question.resolution_id())
            .filter(|entry| entry.question == *question)
            .map(|entry| entry.receipt.record())
    }

    pub(crate) fn available(&self) -> bool {
        self.pending.is_none()
    }

    pub(crate) fn begin_exchange(
        &mut self,
        graph: &Graph,
        derived: CompiledQuestion,
        deadline: Instant,
    ) -> (CompiledQuestion, oneshot::Receiver<QuestionAssessment>) {
        // Family equality is only a lookup. The original source, orientation,
        // record and delivered first-admission evidence remain unchanged.
        let question = self
            .admitted
            .get(derived.resolution_id())
            .filter(|entry| {
                entry.question.core() == derived.core()
                    && entry.question.canonical_core() == derived.canonical_core()
            })
            .map(|entry| entry.question.clone())
            .unwrap_or(derived);
        let (reply, receiver) = oneshot::channel();
        self.begin(graph, question.clone(), Reply::Exchange { reply, deadline });
        (question, receiver)
    }

    pub(crate) fn exchange_eligible(
        &self,
        question: &CompiledQuestion,
        assessment: &QuestionAssessment,
    ) -> bool {
        assessment.prefilter.passed()
            && assessment.interest == InterestAssessment::Assessed(true)
            && (assessment.novelty().is_some() || self.exchange_record(question).is_some())
    }

    pub(crate) fn prepare_exchange(
        &mut self,
        graph: &Graph,
        question: &CompiledQuestion,
        assessment: &QuestionAssessment,
    ) -> Result<QuestionDelta, String> {
        let record = self.exchange_record(question);
        let fresh = self.evaluate_record(graph, question, false, record);
        if !fresh.same_context(&assessment.prefilter)
            || !fresh.passed()
            || !self.exchange_eligible(question, assessment)
        {
            return Err("stale or declined final question assessment".into());
        }
        let mut registry = self.registry.clone();
        if record.is_none() {
            if fresh.novelty().is_none() {
                return Err("missing fresh node-local novelty".into());
            }
            let entry = RegisteredQuestion::new(*question.source_hash(), question.core())
                .map_err(|reason| format!("question registration: {reason:?}"))?;
            registry
                .insert(entry)
                .map_err(|reason| format!("question registration: {reason:?}"))?;
        }
        Ok(QuestionDelta { registry })
    }

    pub(crate) fn apply_exchange(&mut self, delta: QuestionDelta) {
        self.registry = delta.registry;
        self.cached = None;
    }

    fn begin(&mut self, graph: &Graph, question: CompiledQuestion, reply: Reply) {
        if reply.is_closed() {
            return;
        }
        let mut prefilter = if reply.exchange() {
            self.evaluate_record(graph, &question, false, self.exchange_record(&question))
        } else {
            self.assess(graph, &question)
        };
        if prefilter.passed() && self.pending.is_some() {
            prefilter = prefilter.reject(RejectionReason::ReceivingLimit, "Q08_RECEIVING_LIMIT");
        }
        let remaining = match &reply {
            Reply::Exchange { deadline, .. } => deadline
                .saturating_duration_since(Instant::now())
                .min(INTEREST_TIMEOUT),
            _ => INTEREST_TIMEOUT,
        };
        if !prefilter.passed() || self.provider.is_none() || remaining.is_zero() {
            reply.send(
                QuestionAssessment {
                    prefilter,
                    interest: InterestAssessment::NotRun,
                    submitted_negation_parity: question.negation_parity(),
                },
                AdmissionOutcome::NotInserted,
            );
            return;
        }
        let bounded = tokio::time::timeout(
            remaining,
            self.provider.as_ref().expect("configured interest")(question.clone()),
        );
        let future = Box::pin(async move {
            match bounded.await {
                Ok(Ok(yes)) => InterestAssessment::Assessed(yes),
                Ok(Err(_)) => InterestAssessment::ProviderFailed,
                Err(_) => InterestAssessment::TimedOut,
            }
        });
        self.pending = Some(Pending {
            question,
            prefilter,
            reply,
            future,
        });
    }

    pub(crate) fn process(&mut self, command: Command, graph: &Graph) -> bool {
        match command {
            Command::Assess(question, reply) => {
                self.begin(graph, question, Reply::Assessment(reply))
            }
            Command::Admit(question, reply) => self.begin(graph, question, Reply::Admission(reply)),
            Command::ImportBaseline(question, reply) => {
                if !reply.is_closed() {
                    let previous = self.registry.clone();
                    let outcome = if self.registry.contains(question.core()) {
                        Err(RejectionReason::ExactDuplicate)
                    } else {
                        RegisteredQuestion::new(*question.source_hash(), question.core())
                            .and_then(|entry| self.registry.insert(entry))
                    };
                    if reply.send(outcome).is_err() {
                        self.registry = previous;
                    }
                }
            }
            Command::Policy(policy, reply) => {
                if !reply.is_closed() {
                    let previous = self.policy;
                    self.policy = policy;
                    if reply.send(()).is_err() {
                        self.policy = previous;
                    }
                }
            }
            Command::Context(reply) => {
                let _ = reply.send(LocalQuestionContext {
                    snapshot: self.snapshot(graph).identity(),
                    policy: self.policy.identity(),
                    checked_proofs: graph.ids().len(),
                    registered_questions: self.registry.len(),
                });
            }
            Command::Stop(reply) => {
                if !reply.is_closed() {
                    self.pending = None;
                    let _ = reply.send(());
                    return false;
                }
            }
        }
        true
    }

    pub(crate) async fn completed(&mut self) -> InterestAssessment {
        match self.pending.as_mut() {
            Some(pending) => pending.future.as_mut().await,
            None => std::future::pending().await,
        }
    }

    pub(crate) fn finish(&mut self, graph: &Graph, interest: InterestAssessment) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if pending.reply.is_closed() {
            return;
        }
        // Admission always computes again; a cached or caller-manufactured Pass
        // cannot authorize a write. Nothing below awaits or relinquishes ownership.
        let mut prefilter = if pending.reply.exchange() {
            self.evaluate_record(
                graph,
                &pending.question,
                false,
                self.exchange_record(&pending.question),
            )
        } else {
            self.evaluate(graph, &pending.question, !pending.reply.admission())
        };
        let interest = if pending.prefilter.same_context(&prefilter) {
            interest
        } else {
            prefilter = prefilter.reject(RejectionReason::StaleContext, "Q09_STALE_CONTEXT");
            InterestAssessment::Stale
        };
        let mut previous_registry = None;
        let mut outcome = AdmissionOutcome::NotInserted;
        let mut provenance = None;
        if pending.reply.admission()
            && prefilter.passed()
            && interest == InterestAssessment::Assessed(true)
            && let Some(novelty) = prefilter.novelty().cloned()
        {
            let previous = self.registry.clone();
            let registry_before = previous.identity();
            let record = *pending.question.source_hash();
            let inserted = RegisteredQuestion::new(record, pending.question.core())
                .and_then(|entry| self.registry.insert(entry));
            match inserted {
                Ok(()) => {
                    let receipt = AdmissionReceipt {
                        record,
                        snapshot_after: self.snapshot(graph).identity(),
                        registry_before,
                        registry_after: self.registry.identity(),
                        novelty,
                    };
                    provenance = Some(AdmittedProvenance {
                        question: pending.question.clone(),
                        receipt: receipt.clone(),
                    });
                    outcome = AdmissionOutcome::Admitted(Box::new(receipt));
                    previous_registry = Some(previous);
                    self.cached = None;
                }
                Err(reason) => {
                    prefilter = prefilter.reject(reason, "Q02_REGISTRY_INSERTION");
                }
            }
        }
        let delivered = pending.reply.send(
            QuestionAssessment {
                prefilter,
                interest,
                submitted_negation_parity: pending.question.negation_parity(),
            },
            outcome,
        );
        // Failed delivery rolls back within this serialized operation. A delivered
        // receipt linearizes the effect; later client disappearance cannot undo it.
        if !delivered && let Some(previous) = previous_registry {
            self.registry = previous;
        }
        if delivered && let Some(provenance) = provenance {
            self.admitted
                .insert(*provenance.question.resolution_id(), provenance);
        }
    }

    pub(crate) fn cancel_closed(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.reply.is_closed())
        {
            self.pending = None;
        }
    }
}
