//! Bounded local production through real question admission and checked batches.
use crate::{Graph, graph::CheckedBatch, mocks, network::emit, question};
use naome_authoring::CompiledQuestion;
use naome_checker::question::Identity;
use naome_proof::ProofId;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::VecDeque,
    future::Future,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Intervals {
    pub question_interval_ms: u64,
    pub proof_interval_ms: u64,
}

impl Default for Intervals {
    fn default() -> Self {
        Self {
            question_interval_ms: 5_000,
            proof_interval_ms: 1_000,
        }
    }
}

impl Intervals {
    pub(crate) fn validate(self) -> Result<Self, String> {
        if [self.question_interval_ms, self.proof_interval_ms]
            .iter()
            .any(|ms| !(100..=3_600_000).contains(ms))
        {
            return Err("runtime intervals must be between 100 and 3600000 milliseconds".into());
        }
        Ok(self)
    }
}

enum Pending {
    Question(
        CompiledQuestion,
        oneshot::Receiver<question::QuestionAdmission>,
    ),
    Proof {
        question: CompiledQuestion,
        root: ProofId,
        batch: Box<CheckedBatch>,
        context: (Identity, Identity),
        reply: oneshot::Receiver<question::QuestionAssessment>,
    },
}

pub(crate) struct Autonomous {
    intervals: Intervals,
    cursor: u64,
    next_question: Instant,
    next_proof: Instant,
    unanswered: VecDeque<CompiledQuestion>,
    pending: Option<Pending>,
}

impl Autonomous {
    pub(crate) fn new(intervals: Intervals, cursor: u64) -> Self {
        let now = Instant::now();
        Self {
            intervals,
            cursor,
            next_question: now + Duration::from_millis(intervals.question_interval_ms),
            next_proof: now + Duration::from_millis(intervals.proof_interval_ms),
            unanswered: VecDeque::new(),
            pending: None,
        }
    }

    pub(crate) fn advance<F, Fut>(
        &mut self,
        graph: &mut Graph,
        questions: &mut question::LocalQuestions<F>,
    ) -> Vec<ProofId>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        if let Some(pending) = self.pending.take() {
            match pending {
                Pending::Question(question, mut reply) => match reply.try_recv() {
                    Ok(result) => {
                        emit(
                            json!({"event":"question_assessed","resolution_id":crate::hex(question.resolution_id()),
                            "formal_pass":result.assessment.prefilter.passed(),"interest":format!("{:?}",result.assessment.interest)}),
                        );
                        if matches!(result.outcome, question::AdmissionOutcome::Admitted(_))
                            && self.unanswered.len() < 128
                        {
                            self.unanswered.push_back(question);
                        }
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {
                        self.pending = Some(Pending::Question(question, reply));
                        return Vec::new();
                    }
                    Err(_) => {}
                },
                Pending::Proof {
                    question,
                    root,
                    batch,
                    context,
                    mut reply,
                } => match reply.try_recv() {
                    Ok(assessment) => {
                        let outcome: Result<Vec<ProofId>, String> = (|| {
                            if context != questions.context_key(graph)
                                || assessment.prefilter.snapshot != context.0
                                || assessment.prefilter.policy != context.1
                            {
                                return Err("stale generated proof context".into());
                            }
                            let delta =
                                questions.prepare_exchange(graph, &question, &assessment)?;
                            graph.persist_batch(root, &batch)?;
                            let accepted = graph.apply_batch(*batch);
                            questions.apply_exchange(delta);
                            Ok(accepted)
                        })();
                        match outcome {
                            Ok(accepted) => return accepted,
                            Err(error) => {
                                emit(json!({"event":"proof_candidate_rejected","error":error}));
                                self.unanswered.push_back(question);
                            }
                        }
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {
                        self.pending = Some(Pending::Proof {
                            question,
                            root,
                            batch,
                            context,
                            reply,
                        });
                        return Vec::new();
                    }
                    Err(_) => self.unanswered.push_back(question),
                },
            }
        }
        if !questions.available() {
            return Vec::new();
        }
        let now = Instant::now();
        if now >= self.next_proof {
            self.next_proof = now + Duration::from_millis(self.intervals.proof_interval_ms);
            if let Some(selected) = self.unanswered.pop_front() {
                let decision = questions.generation_decision(graph, &selected);
                if !decision.passed() {
                    if !matches!(
                        decision.reason,
                        Some(
                            naome_checker::question::RejectionReason::KnownProof
                                | naome_checker::question::RejectionReason::KnownRefutation
                        )
                    ) {
                        self.unanswered.push_back(selected);
                    }
                } else {
                    let result: Result<Option<Pending>, String> = (|| {
                        let Some(source) = mocks::create_proof(&selected) else {
                            return Ok(None);
                        };
                        let candidate = graph.author(&source)?.prepare()?;
                        if graph.contains(candidate.id) {
                            return Ok(None);
                        }
                        let root = candidate.id;
                        let batch =
                            graph.prepare_batch(root, [(root, candidate)].into(), &selected)?;
                        let context = questions.context_key(graph);
                        let (question, reply) = questions.begin_exchange(
                            graph,
                            selected.clone(),
                            now + crate::intake::ROOT_TTL,
                        );
                        emit(
                            json!({"event":"proof_generated","id":crate::hex(root.as_bytes()),"resolution_id":crate::hex(question.resolution_id())}),
                        );
                        Ok(Some(Pending::Proof {
                            question,
                            root,
                            batch: Box::new(batch),
                            context,
                            reply,
                        }))
                    })();
                    match result {
                        Ok(Some(pending)) => {
                            self.pending = Some(pending);
                            return Vec::new();
                        }
                        Ok(None) => self.unanswered.push_back(selected),
                        Err(error) => {
                            self.unanswered.push_back(selected);
                            emit(json!({"event":"proof_candidate_rejected","error":error}));
                        }
                    }
                }
            }
        }
        if now >= self.next_question {
            self.next_question = now + Duration::from_millis(self.intervals.question_interval_ms);
            let source = mocks::create_question(self.cursor);
            self.cursor = self.cursor.wrapping_add(1);
            match CompiledQuestion::compile(&source) {
                Ok(question) => {
                    emit(
                        json!({"event":"question_generated","resolution_id":crate::hex(question.resolution_id())}),
                    );
                    let (reply, receiver) = oneshot::channel();
                    questions.process(question::Command::Admit(question.clone(), reply), graph);
                    self.pending = Some(Pending::Question(question, receiver));
                }
                Err(error) => {
                    emit(json!({"event":"question_candidate_rejected","error":error.to_string()}))
                }
            }
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests;
