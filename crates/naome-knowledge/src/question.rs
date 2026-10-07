//! Rust-only local question intake, separate from proof replication and interest.
//!
//! Sources are compiled by the existing bounded question parser before intake.
//! The local registry is explicit, in-memory receiver knowledge. Assessment
//! neither registers a question nor changes the checked graph. No question
//! messages, CLI commands or model implementation are introduced here.

use std::{future::Future, pin::Pin, time::Duration};

use naome_authoring::CompiledQuestion;
use naome_checker::question::{
    ApprovalDecision, ApprovalPolicy, AssessmentQuestion, KnowledgeSnapshot, QuestionRegistry,
    RegisteredQuestion, RejectionReason, assess_question,
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
    pub approval: ApprovalDecision,
    pub interest: InterestAssessment,
    /// Existing compiler orientation, without adding a negation heuristic.
    pub submitted_negation_parity: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntakeError {
    QueueFull,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalQuestionContext {
    pub snapshot: [u8; 32],
    pub policy: [u8; 32],
    pub checked_proofs: usize,
    pub registered_questions: usize,
}

pub(crate) enum Command {
    Assess(CompiledQuestion, oneshot::Sender<QuestionAssessment>),
    Register(
        CompiledQuestion,
        oneshot::Sender<Result<(), RejectionReason>>,
    ),
    Policy(ApprovalPolicy, oneshot::Sender<()>),
    Context(oneshot::Sender<LocalQuestionContext>),
    Stop(oneshot::Sender<()>),
}

/// Bounded local input for an embedding application; no network authority.
#[derive(Clone)]
pub struct QuestionHandle {
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

pub fn channel() -> (QuestionHandle, QuestionInbox) {
    let (sender, receiver) = mpsc::channel(QUESTION_QUEUE);
    (QuestionHandle { sender }, QuestionInbox { receiver })
}

impl QuestionHandle {
    async fn send<T>(
        &self,
        command: Command,
        reply: oneshot::Receiver<T>,
    ) -> Result<T, IntakeError> {
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => IntakeError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => IntakeError::Stopped,
        })?;
        reply.await.map_err(|_| IntakeError::Stopped)
    }

    pub async fn assess(
        &self,
        question: CompiledQuestion,
    ) -> Result<QuestionAssessment, IntakeError> {
        let (sender, reply) = oneshot::channel();
        self.send(Command::Assess(question, sender), reply).await
    }

    /// Registers independently supplied, parser-validated local knowledge.
    /// This explicit effect is separate from the read-only assessment API.
    pub async fn register(
        &self,
        question: CompiledQuestion,
    ) -> Result<Result<(), RejectionReason>, IntakeError> {
        let (sender, reply) = oneshot::channel();
        self.send(Command::Register(question, sender), reply).await
    }

    pub async fn set_policy(&self, policy: ApprovalPolicy) -> Result<(), IntakeError> {
        let (sender, reply) = oneshot::channel();
        self.send(Command::Policy(policy, sender), reply).await
    }

    pub async fn context(&self) -> Result<LocalQuestionContext, IntakeError> {
        let (sender, reply) = oneshot::channel();
        self.send(Command::Context(sender), reply).await
    }

    pub async fn stop(&self) -> Result<(), IntakeError> {
        let (sender, reply) = oneshot::channel();
        self.send(Command::Stop(sender), reply).await
    }
}

struct Pending {
    question: CompiledQuestion,
    approval: ApprovalDecision,
    reply: oneshot::Sender<QuestionAssessment>,
    future: Pin<Box<dyn Future<Output = InterestAssessment> + Send>>,
}

pub(crate) struct LocalQuestions<F> {
    registry: QuestionRegistry,
    policy: ApprovalPolicy,
    provider: F,
    pending: Option<Pending>,
    /// One computed decision, never a stored question or interest result.
    cached: Option<ApprovalDecision>,
    #[cfg(test)]
    computations: usize,
}

impl<F, Fut> LocalQuestions<F>
where
    F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<bool, String>> + Send + 'static,
{
    pub(crate) fn new(provider: F) -> Self {
        Self {
            registry: QuestionRegistry::new(),
            policy: ApprovalPolicy::default(),
            provider,
            pending: None,
            cached: None,
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

    fn assess(&mut self, graph: &Graph, question: &CompiledQuestion) -> ApprovalDecision {
        let snapshot = self.snapshot(graph);
        let request = AssessmentQuestion::new(
            FOUNDATION_ID,
            question.core(),
            question.source().as_bytes(),
            &[],
            None,
        )
        .expect("bounded parser-validated question input");
        if let Some(cached) = &self.cached
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

    pub(crate) fn process(&mut self, command: Command, graph: &Graph) -> bool {
        match command {
            Command::Assess(question, reply) => {
                if reply.is_closed() {
                    return true;
                }
                let mut approval = self.assess(graph, &question);
                if approval.approved() && self.pending.is_some() {
                    approval =
                        approval.reject(RejectionReason::ReceivingLimit, "Q08_RECEIVING_LIMIT");
                }
                if !approval.approved() {
                    let _ = reply.send(QuestionAssessment {
                        approval,
                        interest: InterestAssessment::NotRun,
                        submitted_negation_parity: question.negation_parity(),
                    });
                } else {
                    let bounded =
                        tokio::time::timeout(INTEREST_TIMEOUT, (self.provider)(question.clone()));
                    let future = Box::pin(async move {
                        match bounded.await {
                            Ok(Ok(yes)) => InterestAssessment::Assessed(yes),
                            Ok(Err(_)) => InterestAssessment::ProviderFailed,
                            Err(_) => InterestAssessment::TimedOut,
                        }
                    });
                    self.pending = Some(Pending {
                        question,
                        approval,
                        reply,
                        future,
                    });
                }
            }
            Command::Register(question, reply) => {
                let outcome = if self.registry.contains(question.core()) {
                    Err(RejectionReason::ExactDuplicate)
                } else {
                    RegisteredQuestion::new(*question.source_hash(), question.core())
                        .and_then(|entry| self.registry.insert(entry))
                };
                let _ = reply.send(outcome);
            }
            Command::Policy(policy, reply) => {
                self.policy = policy;
                let _ = reply.send(());
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
                let _ = reply.send(());
                return false;
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
        let mut approval = self.assess(graph, &pending.question);
        let interest = if pending.approval.same_context(&approval) {
            interest
        } else {
            approval = approval.reject(RejectionReason::StaleContext, "Q09_STALE_CONTEXT");
            InterestAssessment::Stale
        };
        let result = QuestionAssessment {
            approval,
            interest,
            submitted_negation_parity: pending.question.negation_parity(),
        };
        let _ = pending.reply.send(result);
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
