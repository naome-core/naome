//! Independent finite role coordination through untrusted durable job results.
use crate::{Graph, jobs, network::emit, question};
use naome_authoring::CompiledQuestion;
use naome_checker::question::{Identity, RejectionReason};
use naome_proof::ProofId;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Intervals {
    pub question_interval_ms: u64,
    pub proof_interval_ms: u64,
    pub jobs: jobs::Settings,
}

impl Default for Intervals {
    fn default() -> Self {
        Self {
            question_interval_ms: crate::resources::limits().finding_interval.as_millis() as u64,
            proof_interval_ms: crate::resources::limits().solving_interval.as_millis() as u64,
            jobs: jobs::Settings::default(),
        }
    }
}

impl Intervals {
    pub(crate) fn validate(self) -> Result<Self, String> {
        if [self.question_interval_ms, self.proof_interval_ms]
            .iter()
            .any(|ms| {
                *ms == 0
                    || Instant::now()
                        .checked_add(Duration::from_millis(*ms))
                        .is_none()
            })
        {
            return Err("runtime intervals must be positive and representable".into());
        }
        self.jobs.validate()?;
        Ok(self)
    }
}

struct Finding {
    ticket: jobs::Ticket,
}
struct Admission {
    question: CompiledQuestion,
    job: u64,
    reply: oneshot::Receiver<question::QuestionAdmission>,
}
struct Solving {
    question: CompiledQuestion,
    ticket: jobs::Ticket,
    seen: question::Revision,
}
struct Publication {
    question: CompiledQuestion,
    job: u64,
    source: String,
    helpers: Vec<String>,
    batch: Option<(ProofId, crate::graph::CheckedBatch)>,
    context: Option<(Identity, Identity)>,
    reply: Option<oneshot::Receiver<question::QuestionAssessment>>,
    attempts: u32,
    retry: Instant,
    expires: Instant,
    seen: Option<question::Revision>,
    eligible: bool,
}

pub(crate) struct Autonomous {
    intervals: Intervals,
    client: jobs::Client,
    cursor: u64,
    next_question: Instant,
    next_proof: Instant,
    unanswered: VecDeque<CompiledQuestion>,
    recovered_finding: VecDeque<jobs::Record>,
    recovered_other: VecDeque<jobs::Record>,
    archive_after: Option<u64>,
    archive_end: u64,
    recovery_reply: Option<oneshot::Receiver<Result<jobs::RecoveryPage, String>>>,
    finding: Option<Finding>,
    admissions: VecDeque<Admission>,
    solving: BTreeMap<Identity, Solving>,
    publications: VecDeque<Publication>,
    error: Option<String>,
}

impl Autonomous {
    pub(crate) fn new(
        intervals: Intervals,
        client: jobs::Client,
        recovery: jobs::Recovery,
        unanswered: Vec<CompiledQuestion>,
    ) -> Self {
        let now = Instant::now();
        let archive_end = recovery.archive_end;
        let (finding, other): (Vec<_>, Vec<_>) = recovery
            .records
            .into_iter()
            .partition(|r| matches!(r.input, jobs::Input::Find { .. }));
        Self {
            intervals,
            client,
            cursor: recovery.next_cursor,
            next_question: now + Duration::from_millis(intervals.question_interval_ms),
            next_proof: now + Duration::from_millis(intervals.proof_interval_ms),
            unanswered: unanswered
                .into_iter()
                .take(crate::resources::limits().question_page)
                .collect(),
            recovered_finding: finding.into(),
            recovered_other: other.into(),
            archive_after: (archive_end > 1).then_some(0),
            archive_end,
            recovery_reply: None,
            finding: None,
            admissions: VecDeque::new(),
            solving: BTreeMap::new(),
            publications: VecDeque::new(),
            error: None,
        }
    }

    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    pub(crate) fn selection_boundary_ready(&self) -> bool {
        self.publications
            .iter()
            .any(|p| p.reply.as_ref().is_some_and(|reply| !reply.is_empty()))
    }

    fn acknowledge(&mut self, job: u64) {
        if job != 0
            && let Err(error) = self.client.acknowledge(job)
        {
            self.error = Some(error);
        }
    }

    fn retire(&mut self, record: jobs::Record) {
        if record.state == jobs::State::InDoubt {
            emit(
                json!({"event":"research_recovery_hold","job":record.id,"reason":"provider effects or cleanup are uncertain"}),
            );
            return;
        }
        if let Err(error) = self.client.discard(record.input, record.binding) {
            self.error = Some(error);
        }
    }

    fn retain(&mut self, question: CompiledQuestion) {
        if self.unanswered.len() < crate::resources::limits().question_page
            && !self.unanswered.iter().any(|q| q == &question)
            && !self.solving.contains_key(question.resolution_id())
            && !self.publications.iter().any(|p| p.question == question)
        {
            self.unanswered.push_back(question);
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
        if self.recovered_finding.is_empty() && self.recovered_other.is_empty() {
            if let Some(mut reply) = self.recovery_reply.take() {
                match reply.try_recv() {
                    Ok(Ok(page)) => {
                        self.archive_after = page.next;
                        for record in page.records {
                            if matches!(record.input, jobs::Input::Find { .. }) {
                                self.recovered_finding.push_back(record);
                            } else {
                                self.recovered_other.push_back(record);
                            }
                        }
                    }
                    Ok(Err(error)) => self.error = Some(error),
                    Err(oneshot::error::TryRecvError::Empty) => self.recovery_reply = Some(reply),
                    Err(oneshot::error::TryRecvError::Closed) => {
                        self.error = Some("research archive recovery stopped".into())
                    }
                }
            } else if let Some(after) = self.archive_after {
                // A full command channel defers the page; it never loses history.
                if let Ok(reply) = self.client.recover(after, self.archive_end) {
                    self.recovery_reply = Some(reply);
                }
            }
        }
        let now = Instant::now();
        let mut accepted = Vec::new();
        // Reconcile at most one retained non-finding record per driver turn.
        // Interest is reacquired from current metadata/owner policy; solve
        // outputs remain untrusted and are resumed only for current obligations.
        if let Some(record) = self.recovered_other.pop_front() {
            if let jobs::Input::Solve { question: source } = &record.input {
                if record.state != jobs::State::InDoubt
                    && self.solving.len() >= crate::resources::limits().solving_jobs
                {
                    self.recovered_other.push_front(record);
                } else if record.state == jobs::State::InDoubt {
                    self.retire(record);
                } else if let Ok(question) = CompiledQuestion::compile(source) {
                    if self.solving.contains_key(question.resolution_id())
                        || self
                            .publications
                            .iter()
                            .any(|p| p.question.resolution_id() == question.resolution_id())
                    {
                        self.retire(record);
                        return accepted;
                    }
                    let fresh = questions.generation_decision(graph, &question);
                    if fresh.passed()
                        && self.publications.len() + self.solving.len()
                            < crate::resources::limits().publications
                    {
                        match self
                            .client
                            .submit(record.input.clone(), record.binding.clone())
                        {
                            Ok(ticket) => {
                                self.unanswered
                                    .retain(|q| q.resolution_id() != question.resolution_id());
                                self.solving.insert(
                                    *question.resolution_id(),
                                    Solving {
                                        question,
                                        ticket,
                                        seen: questions.revision(graph),
                                    },
                                );
                            }
                            Err(_) => self.recovered_other.push_front(record),
                        }
                    } else {
                        self.retire(record);
                    }
                } else {
                    self.retire(record);
                }
            } else {
                self.retire(record);
            }
        }
        for _ in 0..self.admissions.len() {
            let mut pending = self
                .admissions
                .pop_front()
                .expect("bounded admission queue");
            match pending.reply.try_recv() {
                Ok(result) => {
                    emit(
                        json!({"event":"question_assessed","resolution_id":crate::hex(pending.question.resolution_id()),
                        "formal_pass":result.assessment.prefilter.passed(),"interest":format!("{:?}",result.assessment.interest)}),
                    );
                    if matches!(result.outcome, question::AdmissionOutcome::Admitted(_)) {
                        self.retain(pending.question);
                    }
                    self.acknowledge(pending.job);
                }
                Err(oneshot::error::TryRecvError::Empty) => self.admissions.push_back(pending),
                Err(_) => self.acknowledge(pending.job),
            }
        }

        if let Some(mut finding) = self.finding.take() {
            match finding.ticket.try_recv() {
                Ok(completion) => match completion.result {
                    Ok(jobs::Output::Question(source)) => {
                        match CompiledQuestion::compile(&source) {
                            Ok(question) => {
                                emit(
                                    json!({"event":"question_generated","resolution_id":crate::hex(question.resolution_id()),"job":completion.id}),
                                );
                                let (reply, receiver) = oneshot::channel();
                                questions.process(
                                    question::Command::Admit(question.clone(), reply),
                                    graph,
                                );
                                self.admissions.push_back(Admission {
                                    question,
                                    job: completion.id,
                                    reply: receiver,
                                });
                            }
                            Err(error) => {
                                emit(
                                    json!({"event":"question_candidate_rejected","error":error.to_string()}),
                                );
                                self.acknowledge(completion.id);
                            }
                        }
                    }
                    _ => {
                        self.acknowledge(completion.id);
                        emit(json!({"event":"question_provider_failed","job":completion.id}));
                    }
                },
                Err(oneshot::error::TryRecvError::Empty) => self.finding = Some(finding),
                Err(_) => self.error = Some("finding job owner stopped".into()),
            }
        }

        let ids = self.solving.keys().copied().collect::<Vec<_>>();
        for id in ids {
            let mut solving = self.solving.remove(&id).expect("owned solving job");
            let revision = questions.revision(graph);
            if solving.seen != revision {
                solving.seen = revision;
                let fresh = questions.generation_decision(graph, &solving.question);
                if matches!(
                    fresh.reason,
                    Some(RejectionReason::KnownProof | RejectionReason::KnownRefutation)
                ) {
                    emit(
                        json!({"event":"solve_cancelled_by_answer","resolution_id":crate::hex(&id)}),
                    );
                    continue;
                }
            }
            match solving.ticket.try_recv() {
                Ok(completion)
                    if matches!(
                        completion.state,
                        jobs::State::Expired | jobs::State::InDoubt
                    ) =>
                {
                    self.acknowledge(completion.id);
                    questions.settle_backlog(&id);
                    emit(
                        json!({"event":"solve_obligation_held_or_expired","resolution_id":crate::hex(&id),
                        "state":format!("{:?}",completion.state)}),
                    );
                }
                Ok(completion) => match completion.result {
                    Ok(jobs::Output::Proof { source, helpers }) => {
                        match graph.prepare_generated(&source, &helpers, &solving.question) {
                            Ok((root, batch)) => {
                                emit(
                                    json!({"event":"proof_generated","id":crate::hex(root.as_bytes()),"resolution_id":crate::hex(&id),"job":completion.id}),
                                );
                                self.publications.push_back(Publication {
                                    question: solving.question,
                                    job: completion.id,
                                    source,
                                    helpers,
                                    batch: Some((root, batch)),
                                    context: None,
                                    reply: None,
                                    attempts: 0,
                                    retry: now,
                                    expires: now
                                        + Duration::from_millis(
                                            self.intervals.jobs.interest.limits.horizon_ms,
                                        ),
                                    seen: None,
                                    eligible: false,
                                });
                            }
                            Err(error) => {
                                emit(json!({"event":"proof_candidate_rejected","error":error}));
                                self.acknowledge(completion.id);
                                self.retain(solving.question);
                            }
                        }
                    }
                    Ok(jobs::Output::NoCandidate) => {
                        self.acknowledge(completion.id);
                        self.retain(solving.question);
                    }
                    _ => {
                        self.acknowledge(completion.id);
                        self.retain(solving.question);
                    }
                },
                Err(oneshot::error::TryRecvError::Empty) => {
                    self.solving.insert(id, solving);
                }
                Err(_) => self.error = Some("solving job owner stopped".into()),
            }
        }

        for _ in 0..self.publications.len() {
            let mut pending = self
                .publications
                .pop_front()
                .expect("bounded publication queue");
            if now >= pending.expires {
                self.acknowledge(pending.job);
                emit(
                    json!({"event":"publication_expired","resolution_id":crate::hex(pending.question.resolution_id())}),
                );
                continue;
            }
            let revision = questions.revision(graph);
            if pending.seen != Some(revision) || pending.reply.is_none() && now >= pending.retry {
                pending.seen = Some(revision);
                let fresh = questions.generation_decision(graph, &pending.question);
                pending.eligible = fresh.passed();
                if matches!(
                    fresh.reason,
                    Some(RejectionReason::KnownProof | RejectionReason::KnownRefutation)
                ) {
                    self.acknowledge(pending.job);
                    continue;
                }
                if !pending.eligible {
                    pending.retry = now
                        + Duration::from_millis(
                            self.intervals
                                .question_interval_ms
                                .max(crate::resources::limits().publication_backoff.as_millis()
                                    as u64),
                        );
                    pending.attempts = pending.attempts.saturating_add(1);
                }
            }
            if let Some(mut reply) = pending.reply.take() {
                match reply.try_recv() {
                    Ok(assessment) => {
                        let outcome = (|| -> Result<Vec<ProofId>, crate::Error> {
                            let context = pending.context.ok_or("publication context absent")?;
                            if context != questions.context_key(graph)
                                || assessment.prefilter.snapshot != context.0
                                || assessment.prefilter.policy != context.1
                            {
                                return Err("stale generated proof context".into());
                            }
                            let (root, batch) = match pending.batch.take() {
                                Some((root, batch)) if graph.batch_current(&batch)? => {
                                    (root, batch)
                                }
                                _ => graph.prepare_generated(
                                    &pending.source,
                                    &pending.helpers,
                                    &pending.question,
                                )?,
                            };
                            let delta = questions.prepare_exchange(
                                graph,
                                &pending.question,
                                &assessment,
                            )?;
                            questions.publish_exchange(
                                graph,
                                root,
                                batch,
                                delta,
                                None,
                                pending.expires,
                            )
                        })();
                        match outcome {
                            Ok(ids) => {
                                accepted.extend(ids);
                                self.acknowledge(pending.job);
                                continue;
                            }
                            Err(error) => {
                                emit(json!({"event":"proof_candidate_rejected","error":error}));
                                if let Some(error) = questions.storage_error() {
                                    self.error = Some(error.to_owned());
                                    return accepted;
                                }
                                pending.retry = now
                                    + Duration::from_millis(
                                        self.intervals.question_interval_ms.max(
                                            crate::resources::limits()
                                                .publication_backoff
                                                .as_millis()
                                                as u64,
                                        ),
                                    );
                            }
                        }
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {
                        pending.reply = Some(reply);
                        self.publications.push_back(pending);
                        continue;
                    }
                    Err(_) => {
                        pending.retry = now
                            + Duration::from_millis(
                                self.intervals.question_interval_ms.max(
                                    crate::resources::limits().publication_backoff.as_millis()
                                        as u64,
                                ),
                            )
                    }
                }
            }
            if pending.attempts >= crate::resources::limits().publication_retries {
                self.acknowledge(pending.job);
                emit(
                    json!({"event":"publication_retry_limit","resolution_id":crate::hex(pending.question.resolution_id())}),
                );
                continue;
            }
            if now >= pending.retry && questions.available_local() && pending.eligible {
                let context = questions.context_key(graph);
                let (selected, reply) = questions.begin_exchange(
                    graph,
                    pending.question.clone(),
                    now + Duration::from_millis(self.intervals.jobs.interest.limits.horizon_ms),
                );
                if selected != pending.question {
                    self.acknowledge(pending.job);
                    continue;
                }
                pending.context = Some(context);
                pending.reply = Some(reply);
                pending.attempts = pending.attempts.saturating_add(1);
            }
            self.publications.push_back(pending);
        }

        // Refill one fair FIFO item per turn. The complete backlog is durable;
        // the parsed queue is only a bounded working page, never a lifetime cap.
        if self.unanswered.len() < crate::resources::limits().question_page
            && let Some(question) = questions.next_backlog()
            && !self.solving.contains_key(question.resolution_id())
            && !self
                .publications
                .iter()
                .any(|p| p.question.resolution_id() == question.resolution_id())
        {
            self.retain(question);
        }

        if now >= self.next_proof
            && self.solving.len() < crate::resources::limits().solving_jobs
            && self.publications.len() + self.solving.len()
                < crate::resources::limits().publications
        {
            self.next_proof = now + Duration::from_millis(self.intervals.proof_interval_ms);
            if let Some(question) = self.unanswered.pop_front() {
                let decision = questions.generation_decision(graph, &question);
                if decision.passed() {
                    let (snapshot, policy) = questions.context_key(graph);
                    match self.client.submit(
                        jobs::Input::Solve {
                            question: question.source().to_owned(),
                        },
                        jobs::Binding::new(snapshot, policy),
                    ) {
                        Ok(ticket) => {
                            self.solving.insert(
                                *question.resolution_id(),
                                Solving {
                                    question,
                                    ticket,
                                    seen: questions.revision(graph),
                                },
                            );
                        }
                        Err(_) => self.retain(question),
                    }
                } else if !matches!(
                    decision.reason,
                    Some(RejectionReason::KnownProof | RejectionReason::KnownRefutation)
                ) {
                    self.retain(question);
                } else {
                    questions.settle_backlog(question.resolution_id());
                }
            }
        }
        if now >= self.next_question
            && self.finding.is_none()
            && self.admissions.len() < crate::resources::limits().finding_admissions
            && self.unanswered.len() < crate::resources::limits().question_page
            && questions.available_local()
        {
            self.next_question = now + Duration::from_millis(self.intervals.question_interval_ms);
            let (input, binding) = if let Some(record) = self.recovered_finding.pop_front() {
                (record.input, record.binding)
            } else {
                let cursor = self.cursor;
                let Some(next) = cursor.checked_add(1) else {
                    self.error = Some("finding cursor exhausted".into());
                    return accepted;
                };
                self.cursor = next;
                let (snapshot, policy) = questions.context_key(graph);
                (
                    jobs::Input::Find { cursor },
                    jobs::Binding::new(snapshot, policy),
                )
            };
            if let Ok(ticket) = self.client.submit(input, binding) {
                self.finding = Some(Finding { ticket });
            }
        }
        accepted
    }
}

#[cfg(test)]
mod tests;
