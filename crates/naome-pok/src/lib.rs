//! Experimental, in-memory PoK orchestration in local event order.
//!
//! Callers authenticate inputs and bind question/result/proof identities. An external
//! verifier supplies validity and comparable step counts. Publication and rewards are
//! intents, not blocks, finality or account mutations. Retry identities last only for
//! this instance; external adapters must deduplicate effects in their own scope.

pub mod adapters;

pub use naome_ledger::AccountId as ParticipantId;
pub use naome_proof::{ProofId, StatementId as ResultId};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::mpsc::{Receiver, RecvError};

macro_rules! ids {
    ($($name:ident),+ $(,)?) => {$ (
        /// Opaque local identity supplied by the caller; not a protocol identifier.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(pub u64);
    )+};
}
ids!(EventId, SubmissionId);

/// Full native research-question digest, distinct from a ledger operation ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct QuestionId(pub [u8; 32]);

/// One citation award per checked citing proof and referenced question.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CitationId {
    pub citing_proof: ProofId,
    pub question: QuestionId,
}

/// Fixed experimental settings. Amounts are whole NAO, with no adopted token codec.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub top_k: NonZeroUsize,
    pub citation_reward_nao: NonZeroU64,
}

/// Exact correlation contract for an external verification request and its receipt.
/// Step count is deliberately absent: only the external verifier may supply it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub submission: SubmissionId,
    pub question: QuestionId,
    pub result: ResultId,
    pub proof: ProofId,
    pub solver: ParticipantId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Invalid,
    Valid { verified_steps: NonZeroU64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationReceipt {
    pub request: Candidate,
    pub verdict: Verdict,
}

/// An externally admitted citation. The caller, not this algorithm, checks its origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Citation {
    pub citation: CitationId,
    pub question: QuestionId,
    pub result: ResultId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    RegisterQuestion(QuestionId),
    Approval {
        question: QuestionId,
        participant: ParticipantId,
        approved: bool,
    },
    Submit(Candidate),
    Verified(VerificationReceipt),
    Cite(Citation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: EventId,
    pub input: Input,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentProof {
    pub candidate: Candidate,
    pub verified_steps: NonZeroU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewardReason {
    FirstSolution(QuestionId),
    Citation(CitationId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardIntent {
    pub beneficiary: ParticipantId,
    pub amount_nao: u64,
    pub reason: RewardReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectKind {
    Verify(Candidate),
    Publish {
        current: CurrentProof,
        replaces: Option<ProofId>,
    },
    Reward(RewardIntent),
}

/// Stable across retries within this instance, regardless of delivery attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EffectId {
    pub event: EventId,
    pub slot: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effect {
    pub id: EffectId,
    pub kind: EffectKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    Accepted,
    Duplicate,
    InvalidProof,
    DifferentResult,
    NotImproved,
    Selected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    IdentityConflict,
    UnknownQuestion,
    NotSelected,
    UnknownSubmission,
    ReceiptMismatch,
    UnsolvedQuestion,
    ResultMismatch,
}

#[derive(Default)]
struct Question {
    approvals: BTreeSet<ParticipantId>,
    current: Option<CurrentProof>,
}

/// Owns local selection and an ordered outbox, never external system state.
/// History and retry keys are in memory and grow with accepted inputs; this prototype
/// provides no restart persistence, distributed ordering or adversarial resource cap.
pub struct Orchestrator {
    config: Config,
    questions: BTreeMap<QuestionId, Question>,
    events: BTreeMap<EventId, Input>,
    submissions: BTreeMap<SubmissionId, Candidate>,
    receipts: BTreeMap<SubmissionId, VerificationReceipt>,
    citations: BTreeMap<CitationId, Citation>,
    pending: VecDeque<Effect>,
}

impl Orchestrator {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            questions: BTreeMap::new(),
            events: BTreeMap::new(),
            submissions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            citations: BTreeMap::new(),
            pending: VecDeque::new(),
        }
    }

    /// Unsolved questions with at least one approval, count descending then ID ascending.
    /// An already solved question remains eligible for improvements outside this pool.
    pub fn top_questions(&self) -> Vec<QuestionId> {
        let mut ranked: Vec<_> = self
            .questions
            .iter()
            .filter(|(_, q)| q.current.is_none() && !q.approvals.is_empty())
            .collect();
        ranked.sort_by_key(|(id, q)| (std::cmp::Reverse(q.approvals.len()), **id));
        ranked
            .into_iter()
            .take(self.config.top_k.get())
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn current(&self, question: QuestionId) -> Option<CurrentProof> {
        self.questions.get(&question).and_then(|q| q.current)
    }

    pub fn pending_effects(&self) -> impl Iterator<Item = &Effect> {
        self.pending.iter()
    }

    /// Call only after the adapter has accepted this exact effect. Acknowledgment is
    /// idempotent; it does not confer publication, finality, validity or settlement.
    pub fn acknowledge(&mut self, id: EffectId) {
        self.pending.retain(|e| e.id != id);
    }

    fn emit(&mut self, event: EventId, slot: u8, kind: EffectKind) {
        self.pending.push_back(Effect {
            id: EffectId { event, slot },
            kind,
        });
    }

    /// Apply one input atomically in caller order. Rejected inputs consume no ID.
    /// Exact event and logical submission/citation retries never emit another effect.
    pub fn apply(&mut self, event: Event) -> Result<Applied, InputError> {
        if let Some(input) = self.events.get(&event.id) {
            return if *input == event.input {
                Ok(Applied::Duplicate)
            } else {
                Err(InputError::IdentityConflict)
            };
        }
        let outcome = match event.input {
            Input::RegisterQuestion(id) => {
                if let std::collections::btree_map::Entry::Vacant(entry) = self.questions.entry(id)
                {
                    entry.insert(Question::default());
                    Applied::Accepted
                } else {
                    Applied::Duplicate
                }
            }
            Input::Approval {
                question,
                participant,
                approved,
            } => {
                let q = self
                    .questions
                    .get_mut(&question)
                    .ok_or(InputError::UnknownQuestion)?;
                if approved {
                    q.approvals.insert(participant);
                } else {
                    q.approvals.remove(&participant);
                }
                Applied::Accepted
            }
            Input::Submit(candidate) => self.submit(event.id, candidate)?,
            Input::Verified(receipt) => self.verified(event.id, receipt)?,
            Input::Cite(citation) => self.cite(event.id, citation)?,
        };
        self.events.insert(event.id, event.input);
        Ok(outcome)
    }

    fn submit(&mut self, event: EventId, candidate: Candidate) -> Result<Applied, InputError> {
        if let Some(existing) = self.submissions.get(&candidate.submission) {
            return if *existing == candidate {
                Ok(Applied::Duplicate)
            } else {
                Err(InputError::IdentityConflict)
            };
        }
        let q = self
            .questions
            .get(&candidate.question)
            .ok_or(InputError::UnknownQuestion)?;
        if let Some(current) = q.current {
            if current.candidate.result != candidate.result {
                return Err(InputError::ResultMismatch);
            }
        } else if !self.top_questions().contains(&candidate.question) {
            return Err(InputError::NotSelected);
        }
        self.submissions.insert(candidate.submission, candidate);
        self.emit(event, 0, EffectKind::Verify(candidate));
        Ok(Applied::Accepted)
    }

    fn verified(
        &mut self,
        event: EventId,
        receipt: VerificationReceipt,
    ) -> Result<Applied, InputError> {
        let candidate = receipt.request;
        let request = self
            .submissions
            .get(&candidate.submission)
            .ok_or(InputError::UnknownSubmission)?;
        if *request != candidate {
            return Err(InputError::ReceiptMismatch);
        }
        if let Some(existing) = self.receipts.get(&candidate.submission) {
            return if *existing == receipt {
                Ok(Applied::Duplicate)
            } else {
                Err(InputError::IdentityConflict)
            };
        }
        self.receipts.insert(candidate.submission, receipt);
        self.pending
            .retain(|e| e.kind != EffectKind::Verify(candidate));
        let Verdict::Valid { verified_steps } = receipt.verdict else {
            return Ok(Applied::InvalidProof);
        };
        let previous = self.current(candidate.question);
        if let Some(old) = previous {
            if old.candidate.result != candidate.result {
                return Ok(Applied::DifferentResult);
            }
            if old.verified_steps <= verified_steps {
                return Ok(Applied::NotImproved);
            }
        }
        let current = CurrentProof {
            candidate,
            verified_steps,
        };
        self.questions
            .get_mut(&candidate.question)
            .expect("admitted question")
            .current = Some(current);
        self.emit(
            event,
            0,
            EffectKind::Publish {
                current,
                replaces: previous.map(|p| p.candidate.proof),
            },
        );
        if previous.is_none() {
            self.emit(
                event,
                1,
                EffectKind::Reward(RewardIntent {
                    beneficiary: candidate.solver,
                    amount_nao: 1,
                    reason: RewardReason::FirstSolution(candidate.question),
                }),
            );
        }
        Ok(Applied::Selected)
    }

    fn cite(&mut self, event: EventId, citation: Citation) -> Result<Applied, InputError> {
        if citation.citation.question != citation.question {
            return Err(InputError::IdentityConflict);
        }
        if let Some(existing) = self.citations.get(&citation.citation) {
            return if *existing == citation {
                Ok(Applied::Duplicate)
            } else {
                Err(InputError::IdentityConflict)
            };
        }
        if !self.questions.contains_key(&citation.question) {
            return Err(InputError::UnknownQuestion);
        }
        let current = self
            .current(citation.question)
            .ok_or(InputError::UnsolvedQuestion)?;
        if current.candidate.result != citation.result {
            return Err(InputError::ResultMismatch);
        }
        self.citations.insert(citation.citation, citation);
        self.emit(
            event,
            0,
            EffectKind::Reward(RewardIntent {
                beneficiary: current.candidate.solver,
                amount_nao: self.config.citation_reward_nao.get(),
                reason: RewardReason::Citation(citation.citation),
            }),
        );
        Ok(Applied::Accepted)
    }
}

/// External verification, publication and account adapters can route this small port.
/// `Ok` means accepted; uncertain outcomes return `Err` and must accept the same ID
/// on retry without another side effect. Adapter calls must terminate for cancellation.
pub trait EffectSink {
    type Error;
    fn deliver(&mut self, effect: Effect) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug)]
pub enum Command {
    Event(Event),
    RetryEffects,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    Cancelled,
    Disconnected,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RunReport {
    pub stop: StopReason,
    pub rejected_inputs: Vec<(EventId, InputError)>,
    pub failed_delivery_attempts: usize,
}

/// Waits on a channel when idle. Cancellation takes effect in receiver order between
/// commands; pending effects remain queryable. Input failures do not stop the
/// loop. Delivery failures retain the outbox in order and retry on the next command.
pub fn run<S: EffectSink>(
    core: &mut Orchestrator,
    receiver: &Receiver<Command>,
    sink: &mut S,
) -> RunReport {
    let mut report = RunReport {
        stop: StopReason::Disconnected,
        rejected_inputs: Vec::new(),
        failed_delivery_attempts: 0,
    };
    loop {
        match receiver.recv() {
            Ok(Command::Cancel) => {
                report.stop = StopReason::Cancelled;
                return report;
            }
            Err(RecvError) => return report,
            Ok(Command::Event(event)) => {
                if let Err(error) = core.apply(event) {
                    report.rejected_inputs.push((event.id, error));
                }
            }
            Ok(Command::RetryEffects) => {}
        }
        while let Some(effect) = core.pending.front().copied() {
            if sink.deliver(effect).is_err() {
                report.failed_delivery_attempts += 1;
                break;
            }
            core.acknowledge(effect.id);
        }
    }
}
