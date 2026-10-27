//! Independent finite role coordination through untrusted durable job results.
use crate::{Graph, jobs, network::emit, question};
use naome_authoring::CompiledQuestion;
use naome_checker::question::Identity;
use naome_proof::ArtifactId;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Intervals {
    /// Zero selects calibrated scheduling; positive values are owner pacing.
    pub question_interval_ms: u64,
    /// Zero selects calibrated scheduling; positive values are owner pacing.
    pub proof_interval_ms: u64,
    pub jobs: jobs::Settings,
}

impl Intervals {
    fn finding_ms(self) -> u64 {
        if self.question_interval_ms == 0 {
            crate::resources::active_limits()
                .finding_interval
                .as_millis() as u64
        } else {
            self.question_interval_ms
        }
    }
    fn solving_ms(self) -> u64 {
        if self.proof_interval_ms == 0 {
            crate::resources::active_limits()
                .solving_interval
                .as_millis() as u64
        } else {
            self.proof_interval_ms
        }
    }
    pub(crate) fn validate(self) -> Result<Self, String> {
        if [self.question_interval_ms, self.proof_interval_ms]
            .iter()
            .any(|ms| {
                Instant::now()
                    .checked_add(Duration::from_millis(*ms))
                    .is_none()
            })
        {
            return Err("runtime intervals must be representable".into());
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
    completion: Option<jobs::Completion>,
    question: CompiledQuestion,
    ticket: jobs::Ticket,
    seen: question::Revision,
}
mod program;
enum Candidate {
    Certificate {
        source: String,
        helpers: Vec<String>,
    },
    Program(Box<program::Generated>),
}
impl Candidate {
    fn prepare(
        &mut self,
        graph: &Graph,
        client: &jobs::Client,
        question: &CompiledQuestion,
    ) -> Result<Option<(ArtifactId, crate::graph::CheckedBatch)>, crate::Error> {
        match self {
            Self::Certificate { source, helpers } => {
                graph.prepare_generated(source, helpers, question).map(Some)
            }
            Self::Program(program) => program.prepare(graph, client, question),
        }
    }
}
struct Publication {
    question: CompiledQuestion,
    job: u64,
    candidate: Candidate,
    batch: Option<(ArtifactId, crate::graph::CheckedBatch)>,
    announced: bool,
    assessment: Option<question::QuestionAssessment>,
    reply: Option<oneshot::Receiver<question::QuestionAssessment>>,
    attempts: u32,
    retry: Instant,
    expires: Instant,
    seen: Option<question::Revision>,
    eligible: bool,
}

struct EvidencePublication {
    question: CompiledQuestion,
    job: u64,
    root: ArtifactId,
}

struct RecoveryRetry {
    seen: question::Revision,
    retry: Instant,
}

pub(crate) struct Autonomous {
    intervals: Intervals,
    client: jobs::Client,
    cursor: u64,
    formal_goal: Option<CompiledQuestion>,
    next_question: Instant,
    next_proof: Instant,
    unanswered: VecDeque<CompiledQuestion>,
    recovered_finding: VecDeque<jobs::Record>,
    recovered_other: VecDeque<jobs::Record>,
    // The service skips its bounded initial resident page during archive scans.
    // Only that page needs local retention; other deferred rows stay on disk.
    initial_recovery: BTreeSet<u64>,
    deferred_recovery: VecDeque<jobs::Record>,
    recovery_retry: Option<RecoveryRetry>,
    archive_after: Option<u64>,
    archive_end: u64,
    recovery_reply: Option<oneshot::Receiver<Result<jobs::RecoveryPage, String>>>,
    finding: Option<Finding>,
    admissions: VecDeque<Admission>,
    solving: BTreeMap<Identity, Solving>,
    publications: VecDeque<Publication>,
    error: Option<String>,
    pending_receipt: Option<jobs::Receipt>,
    frontier: Option<crate::frontier::Frontier>,
    evidence_publications: VecDeque<EvidencePublication>,
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
        let initial_recovery = recovery.records.iter().map(|record| record.id).collect();
        let (finding, other): (Vec<_>, Vec<_>) = recovery
            .records
            .into_iter()
            .partition(|r| matches!(r.input, jobs::Input::Find { .. }));
        Self {
            intervals,
            client,
            cursor: recovery.next_cursor,
            formal_goal: None,
            next_question: now + Duration::from_millis(intervals.finding_ms()),
            next_proof: now + Duration::from_millis(intervals.solving_ms()),
            unanswered: unanswered
                .into_iter()
                .take(crate::resources::active_limits().question_page)
                .collect(),
            recovered_finding: finding.into(),
            recovered_other: other.into(),
            initial_recovery,
            deferred_recovery: VecDeque::new(),
            recovery_retry: None,
            archive_after: (archive_end > 1).then_some(0),
            archive_end,
            recovery_reply: None,
            finding: None,
            admissions: VecDeque::new(),
            solving: BTreeMap::new(),
            publications: VecDeque::new(),
            error: None,
            pending_receipt: None,
            frontier: None,
            evidence_publications: VecDeque::new(),
        }
    }

    pub(crate) fn attach_frontier(
        &mut self,
        directory: &std::path::Path,
        graph: &Graph,
        seed: u64,
    ) -> Result<(), String> {
        self.frontier = Some(crate::frontier::Frontier::open(
            directory,
            graph,
            seed,
            self.intervals.jobs,
        )?);
        Ok(())
    }

    pub(crate) fn program_busy(&self) -> bool {
        self.publications.iter().any(|publication| {
            matches!(publication.candidate, Candidate::Program(_))
                && publication.batch.is_none()
                && publication.reply.is_none()
                && Instant::now() >= publication.retry
        })
    }
    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    /// A canonical question fixed by the stopped node's start configuration.
    pub(crate) fn formal_goal(&mut self, source: Option<CompiledQuestion>) {
        self.formal_goal = source;
    }

    fn receipt(&mut self, receipt: jobs::Receipt) -> bool {
        debug_assert!(self.pending_receipt.is_none());
        match self.client.try_receipt(&receipt) {
            Ok(true) => true,
            Ok(false) => {
                self.pending_receipt = Some(receipt);
                false
            }
            Err(error) => {
                self.error = Some(error);
                false
            }
        }
    }
    fn acknowledge(&mut self, job: u64) -> bool {
        job == 0 || self.receipt(jobs::Receipt::Acknowledge(job))
    }
    fn accepted_learning(&mut self, job: u64, root: ArtifactId) -> bool {
        job == 0
            || !self.intervals.jobs.native_proof_learning
            || self.receipt(jobs::Receipt::Accepted {
                id: job,
                root: crate::hex(root.as_bytes()),
            })
    }
    fn recover_learning(&mut self, graph: &Graph, record: &jobs::Record) -> bool {
        if let Some(jobs::Output::Native {
            solution: Some(solution),
            ..
        }) = &record.result
        {
            match crate::object::id_bytes(&solution.proof_id)
                .map(naome_proof::ProofId::from_bytes)
                .map(ArtifactId::from_proof_id)
                .and_then(|root| graph.contains(root).map(|yes| (root, yes)))
            {
                Ok((root, true)) => return self.accepted_learning(record.id, root),
                Ok(_) => {}
                Err(error) => {
                    self.error = Some(error.to_string());
                    return false;
                }
            }
        }
        true
    }
    fn retire(&mut self, record: jobs::Record) -> bool {
        if record.state == jobs::State::InDoubt {
            emit(
                json!({"event":"research_recovery_hold","job":record.id,"reason":"provider effects or cleanup are uncertain"}),
            );
            return true;
        }
        self.receipt(jobs::Receipt::Discard(record.input, record.binding))
    }

    fn retain(&mut self, question: CompiledQuestion) {
        if self.unanswered.len() < crate::resources::active_limits().question_page
            && !self.unanswered.iter().any(|q| q == &question)
            && !self.solving.contains_key(question.resolution_id())
            && !self.publications.iter().any(|p| p.question == question)
        {
            self.unanswered.push_back(question);
        }
    }

    fn retry<F, Fut>(
        &mut self,
        question: CompiledQuestion,
        questions: &mut question::LocalQuestions<F>,
    ) where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        // Rotate durable unresolved work before retrying a completed attempt.
        // Its original admission remains in the backlog even when the parsed
        // working page has room for only one question.
        self.retain(questions.next_backlog().unwrap_or(question));
    }

    fn defer_recovery(&mut self, record: jobs::Record, seen: question::Revision, now: Instant) {
        self.recovery_retry.get_or_insert(RecoveryRetry {
            seen,
            retry: now + crate::resources::limits().pending_retry,
        });
        if self.initial_recovery.contains(&record.id) {
            self.deferred_recovery.push_back(record);
        }
        // Archived rows remain unacknowledged in the original durable journal.
        // Rescan the fixed startup horizon after this pass, never accumulate
        // an unbounded in-memory retry list or block the next archive page.
    }

    pub(crate) fn advance<F, Fut>(
        &mut self,
        graph: &mut Graph,
        questions: &mut question::LocalQuestions<F>,
    ) -> Vec<ArtifactId>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        let mut accepted = Vec::new();
        // One owner-held receipt is the only extra working item. Until the
        // original bounded channel accepts it, no new autonomous work advances.
        if let Some(receipt) = self.pending_receipt.take()
            && !self.receipt(receipt)
        {
            return accepted;
        }
        let now = Instant::now();
        if (now >= self.next_question || now >= self.next_proof)
            && let Some(frontier) = &mut self.frontier
        {
            frontier.feedback(self.client.feedback());
        }
        while let Some(publication) = self.evidence_publications.pop_front() {
            let result = self
                .frontier
                .as_mut()
                .expect("research evidence owner")
                .verified(
                    &publication.question,
                    graph,
                    publication.job,
                    publication.root,
                );
            match result {
                Ok(()) => {
                    if !self.accepted_learning(publication.job, publication.root)
                        || !self.acknowledge(publication.job)
                    {
                        return accepted;
                    }
                }
                Err(error) if !error.fatal() => {
                    self.evidence_publications.push_front(publication);
                    return vec![];
                }
                Err(error) => {
                    self.error = Some(error.to_string());
                    return vec![];
                }
            }
        }
        let revision = questions.revision(graph);
        if self.recovered_finding.is_empty()
            && self.recovered_other.is_empty()
            && self.recovery_reply.is_none()
            && self.archive_after.is_none()
            && self
                .recovery_retry
                .as_ref()
                .is_some_and(|retry| retry.seen != revision || now >= retry.retry)
        {
            self.recovery_retry = None;
            self.recovered_other.append(&mut self.deferred_recovery);
            self.archive_after = (self.archive_end > 1).then_some(0);
        }
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
        // Reconcile at most one retained non-finding record per driver turn.
        // Selection is reacquired from current metadata/owner policy; solve
        // outputs remain untrusted and are resumed only for current obligations.
        if let Some(record) = self.recovered_other.pop_front() {
            if let jobs::Input::Solve { question: source } = &record.input {
                if record.state != jobs::State::InDoubt
                    && (self.solving.len() >= crate::resources::active_limits().solving_jobs
                        || self.publications.len()
                            + self.solving.len()
                            + self.evidence_publications.len()
                            >= crate::resources::active_limits().publications)
                {
                    self.recovered_other.push_back(record);
                } else if record.state == jobs::State::InDoubt {
                    if !self.retire(record) {
                        return accepted;
                    }
                } else if let Ok(question) = CompiledQuestion::compile(source) {
                    if self.solving.contains_key(question.resolution_id())
                        || self
                            .publications
                            .iter()
                            .any(|p| p.question.resolution_id() == question.resolution_id())
                    {
                        if !self.retire(record) {
                            return accepted;
                        }
                        return accepted;
                    }
                    let fresh = questions.generation_decision(graph, &question);
                    if fresh.passed()
                        && self.publications.len()
                            + self.solving.len()
                            + self.evidence_publications.len()
                            < crate::resources::active_limits().publications
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
                                        completion: None,
                                        question,
                                        ticket,
                                        seen: questions.revision(graph),
                                    },
                                );
                            }
                            Err(_) => self.defer_recovery(record, revision, now),
                        }
                    } else if fresh.inconclusive() {
                        self.defer_recovery(record, revision, now);
                    } else {
                        if fresh.has_answer() && !self.recover_learning(graph, &record) {
                            return accepted;
                        }
                        if !self.retire(record) {
                            return accepted;
                        }
                    }
                } else {
                    if !self.retire(record) {
                        return accepted;
                    }
                }
            } else {
                if !self.retire(record) {
                    return accepted;
                }
            }
        }
        for _ in 0..self.admissions.len() {
            let mut pending = self
                .admissions
                .pop_front()
                .expect("bounded admission queue");
            match pending.reply.try_recv() {
                Ok(result) => {
                    let admitted =
                        matches!(result.outcome, question::AdmissionOutcome::Admitted(_));
                    emit(
                        json!({"event":"question_assessed","resolution_id":crate::hex(pending.question.resolution_id()),
                        "admitted":admitted,
                        "formal_pass":result.assessment.prefilter.passed(),
                        "formal_outcome":result.assessment.prefilter.outcome.code(),
                        "formal_reason":result.assessment.prefilter.reason.map(|reason| reason.code()),
                        "formal_rule":result.assessment.prefilter.rule,
                        "selection":format!("{:?}",result.assessment.selection_result)}),
                    );
                    crate::resources::feedback::finding_result(admitted);
                    if admitted {
                        self.retain(pending.question);
                    }
                    if !self.acknowledge(pending.job) {
                        return accepted;
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => self.admissions.push_back(pending),
                Err(_) => {
                    if !self.acknowledge(pending.job) {
                        return accepted;
                    }
                }
            }
        }

        if let Some(mut finding) = self.finding.take() {
            match finding.ticket.try_recv() {
                Ok(completion) => match completion.result.clone() {
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
                                if !self.acknowledge(completion.id) {
                                    return accepted;
                                }
                            }
                        }
                    }
                    _ => {
                        if !self.acknowledge(completion.id) {
                            return accepted;
                        }
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
                if fresh.has_answer() {
                    emit(
                        json!({"event":"solve_cancelled_by_answer","resolution_id":crate::hex(&id)}),
                    );
                    continue;
                }
            }
            let completion = solving
                .completion
                .take()
                .map(Ok)
                .unwrap_or_else(|| solving.ticket.try_recv());
            if let (Some(frontier), Ok(observed)) = (&mut self.frontier, &completion) {
                use crate::frontier::evidence::Outcome;
                let outcome = match (observed.state, &observed.result) {
                    (jobs::State::Expired, _) => Outcome::Expired,
                    (jobs::State::InDoubt, _) => Outcome::InDoubt,
                    (_, Ok(jobs::Output::Proof { .. } | jobs::Output::Program { .. })) => {
                        Outcome::Candidate
                    }
                    (
                        _,
                        Ok(jobs::Output::Native {
                            solution: Some(_), ..
                        }),
                    ) => Outcome::Candidate,
                    (
                        _,
                        Ok(jobs::Output::NoCandidate | jobs::Output::Native { solution: None, .. }),
                    ) => Outcome::NoCandidate,
                    _ => Outcome::Failed,
                };
                if let Err(error) = frontier.attempted(&solving.question, graph, observed, outcome)
                {
                    if error.fatal() {
                        self.error = Some(error.to_string());
                    } else {
                        solving.completion = completion.ok();
                        self.solving.insert(id, solving);
                    }
                    return accepted;
                }
            }
            if let Ok(completion) = &completion
                && completion.id == 0
                && completion
                    .result
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.contains("required") && e.contains("prerequisites"))
                && let Some(frontier) = &mut self.frontier
            {
                if let Err(error) = frontier.exhaust_helpers(&solving.question) {
                    self.error = Some(error.to_string());
                    return accepted;
                }
                emit(
                    json!({"event":"lemma_loop_unavailable","resolution_id":crate::hex(&id),"reason":"checked prerequisite not retained by owner"}),
                );
            }
            match completion {
                Ok(completion)
                    if matches!(
                        completion.state,
                        jobs::State::Expired | jobs::State::InDoubt
                    ) =>
                {
                    questions.settle_backlog(&id);
                    emit(
                        json!({"event":"solve_obligation_held_or_expired","resolution_id":crate::hex(&id),
                        "state":format!("{:?}",completion.state)}),
                    );
                    if !self.acknowledge(completion.id) {
                        return accepted;
                    }
                }
                Ok(completion) => match completion.result.clone().map(jobs::Output::candidate) {
                    Ok(jobs::Output::Proof { source, helpers }) => {
                        match graph.prepare_generated(&source, &helpers, &solving.question) {
                            Ok((root, batch)) => {
                                self.publications.push_back(Publication {
                                    question: solving.question,
                                    job: completion.id,
                                    candidate: Candidate::Certificate { source, helpers },
                                    batch: Some((root, batch)),
                                    announced: false,
                                    assessment: None,
                                    reply: None,
                                    attempts: 0,
                                    retry: now,
                                    expires: now
                                        + Duration::from_millis(
                                            self.intervals.jobs.selection.limits.horizon_ms,
                                        ),
                                    seen: None,
                                    eligible: false,
                                });
                            }
                            Err(error) => {
                                emit(json!({"event":"proof_candidate_rejected","error":error}));
                                if let Some(frontier) = &mut self.frontier
                                    && let Err(error) =
                                        frontier.rejected(&solving.question, completion.id)
                                {
                                    if error.fatal() {
                                        self.error = Some(error.to_string());
                                    } else {
                                        solving.completion = Some(completion);
                                        self.solving.insert(id, solving);
                                    }
                                    return accepted;
                                }
                                if !self.acknowledge(completion.id) {
                                    return accepted;
                                }
                                self.retry(solving.question, questions);
                                if !self.acknowledge(completion.id) {
                                    return accepted;
                                }
                            }
                        }
                    }
                    Ok(jobs::Output::Program { units }) => {
                        self.publications.push_back(Publication {
                            question: solving.question,
                            job: completion.id,
                            candidate: Candidate::Program(Box::new(program::Generated::new(
                                completion.id,
                                units,
                            ))),
                            batch: None,
                            announced: false,
                            assessment: None,
                            reply: None,
                            attempts: 0,
                            retry: now,
                            expires: now
                                + Duration::from_millis(
                                    self.intervals.jobs.selection.limits.horizon_ms,
                                ),
                            seen: None,
                            eligible: false,
                        });
                    }
                    Ok(jobs::Output::NoCandidate) => {
                        self.retry(solving.question, questions);
                        if !self.acknowledge(completion.id) {
                            return accepted;
                        }
                    }
                    _ => {
                        self.retry(solving.question, questions);
                        if !self.acknowledge(completion.id) {
                            return accepted;
                        }
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
            if let Candidate::Program(program) = &mut pending.candidate {
                match program.restrict_cache(graph) {
                    Ok(()) => {}
                    Err(error) if error.retryable() => {
                        self.publications.push_back(pending);
                        continue;
                    }
                    Err(error) => {
                        graph.program_failure(&error);
                        if !self.acknowledge(pending.job) {
                            return accepted;
                        }
                        continue;
                    }
                }
            }
            if pending.batch.is_none() && pending.reply.is_none() {
                if now < pending.retry {
                    self.publications.push_back(pending);
                    continue;
                }

                if !pending.announced {
                    pending.expires = now
                        + Duration::from_millis(self.intervals.jobs.selection.limits.horizon_ms);
                }
                let decision = questions.generation_decision(graph, &pending.question);
                if decision.inconclusive() {
                    pending.retry = now + crate::resources::limits().pending_retry;
                    self.publications.push_back(pending);
                    continue;
                }
                if !decision.passed() {
                    if !self.acknowledge(pending.job) {
                        return accepted;
                    }
                    continue;
                }
                match pending
                    .candidate
                    .prepare(graph, &self.client, &pending.question)
                {
                    Ok(Some(batch)) => {
                        pending.batch = Some(batch);
                    }
                    Ok(None) => {
                        self.publications.push_back(pending);
                        continue;
                    }
                    Err(error) if error.retryable() => {
                        self.publications.push_back(pending);
                        continue;
                    }
                    Err(error) => {
                        emit(
                            json!({"event":"proof_candidate_rejected","job":pending.job,"error":error}),
                        );
                        self.retain(pending.question);
                        if !self.acknowledge(pending.job) {
                            return accepted;
                        }
                        continue;
                    }
                }
            }
            if let Some((root, _)) = &pending.batch
                && !pending.announced
            {
                if let Some(frontier) = &mut self.frontier
                    && let Err(error) = frontier.prepared(&pending.question, pending.job, *root)
                {
                    if error.fatal() {
                        self.error = Some(error.to_string());
                    } else {
                        self.publications.push_back(pending);
                    }
                    return accepted;
                }
                emit(
                    json!({"event":"proof_generated","id":crate::hex(root.as_bytes()),"resolution_id":crate::hex(pending.question.resolution_id()),"job":pending.job}),
                );
                pending.announced = true;
            }
            if now >= pending.expires {
                emit(
                    json!({"event":"publication_expired","resolution_id":crate::hex(pending.question.resolution_id())}),
                );
                if let Some(frontier) = &mut self.frontier
                    && let Err(error) = frontier.abandon_publication(&pending.question, pending.job)
                {
                    if error.fatal() {
                        self.error = Some(error.to_string());
                    } else {
                        self.publications.push_back(pending);
                    }
                    return accepted;
                }
                if !self.acknowledge(pending.job) {
                    return accepted;
                }
                continue;
            }
            let revision = questions.revision(graph);
            if pending.seen != Some(revision) || pending.reply.is_none() && now >= pending.retry {
                pending.seen = Some(revision);
                let fresh = questions.generation_decision(graph, &pending.question);
                pending.eligible = fresh.passed();
                if fresh.has_answer() {
                    if let Some((root, _)) = &pending.batch
                        && graph.contains(*root).unwrap_or(false)
                        && !self.accepted_learning(pending.job, *root)
                    {
                        return accepted;
                    }
                    if !self.acknowledge(pending.job) {
                        return accepted;
                    }
                    continue;
                }
                if !pending.eligible {
                    pending.retry = now
                        + Duration::from_millis(
                            self.intervals
                                .finding_ms()
                                .max(crate::resources::limits().publication_backoff.as_millis()
                                    as u64),
                        );
                    pending.attempts = pending.attempts.saturating_add(1);
                }
            }
            if let Some(mut reply) = pending.reply.take() {
                match reply.try_recv() {
                    Ok(assessment) => {
                        pending.assessment = questions
                            .exchange_eligible(&pending.question, &assessment)
                            .then_some(assessment);
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {
                        pending.reply = Some(reply);
                        self.publications.push_back(pending);
                        continue;
                    }
                    Err(_) => {
                        pending.retry = now
                            + Duration::from_millis(
                                self.intervals.finding_ms().max(
                                    crate::resources::limits().publication_backoff.as_millis()
                                        as u64,
                                ),
                            )
                    }
                }
            }
            if let Some(assessment) = pending.assessment.take()
                && questions.exchange_eligible(&pending.question, &assessment)
            {
                let current = pending
                    .batch
                    .as_ref()
                    .map(|(_, batch)| graph.batch_current(batch))
                    .transpose();
                match current {
                    Ok(Some(true)) => {
                        let learning_root = pending.batch.as_ref().map(|(root, _)| *root);
                        let evidence_root =
                            pending.batch.as_ref().expect("current checked candidate").0;
                        let outcome = (|| -> Result<Vec<ArtifactId>, crate::Error> {
                            let delta = questions.prepare_exchange(
                                graph,
                                &pending.question,
                                &assessment,
                            )?;
                            let (root, batch) =
                                pending.batch.take().expect("current checked candidate");
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
                                if let Some(frontier) = &mut self.frontier
                                    && let Err(error) = frontier.verified(
                                        &pending.question,
                                        graph,
                                        pending.job,
                                        evidence_root,
                                    )
                                {
                                    if error.fatal() {
                                        self.error = Some(error.to_string());
                                        return accepted;
                                    }
                                    self.evidence_publications.push_back(EvidencePublication {
                                        question: pending.question.clone(),
                                        job: pending.job,
                                        root: evidence_root,
                                    });
                                    accepted.extend(ids);
                                    continue;
                                }
                                accepted.extend(ids);
                                if let Some(root) = learning_root
                                    && !self.accepted_learning(pending.job, root)
                                {
                                    return accepted;
                                }
                                let job = pending.job;
                                drop(pending);
                                if !self.acknowledge(job) {
                                    return accepted;
                                }
                                continue;
                            }
                            Err(error) => {
                                pending.batch = None;
                                emit(json!({"event":"proof_candidate_deferred","error":error}));
                                if let Some(error) =
                                    questions.storage_error().or_else(|| graph.storage_error())
                                {
                                    self.error = Some(error);
                                    return accepted;
                                }
                                pending.retry =
                                    now + crate::resources::limits().publication_backoff;
                            }
                        }
                    }
                    Ok(_) => {
                        // Rebuild the mathematical delta against current roots;
                        // unrelated graph growth cannot spend another selection job.
                        pending.batch = None;
                        pending.retry = now;
                    }
                    Err(error) => {
                        self.error = Some(error.to_string());
                        return accepted;
                    }
                }
                pending.assessment = Some(assessment);
            }
            if pending.attempts >= crate::resources::limits().publication_retries {
                emit(
                    json!({"event":"publication_retry_limit","resolution_id":crate::hex(pending.question.resolution_id())}),
                );
                if let Some(frontier) = &mut self.frontier
                    && let Err(error) = frontier.abandon_publication(&pending.question, pending.job)
                {
                    if error.fatal() {
                        self.error = Some(error.to_string());
                    } else {
                        self.publications.push_back(pending);
                    }
                    return accepted;
                }
                if !self.acknowledge(pending.job) {
                    return accepted;
                }
                continue;
            }
            if now >= pending.retry
                && questions.available_local()
                && pending.eligible
                && pending.reply.is_none()
                && pending.assessment.is_none()
            {
                let (selected, reply) = questions.begin_exchange(
                    graph,
                    pending.question.clone(),
                    now + Duration::from_millis(self.intervals.jobs.selection.limits.horizon_ms),
                );
                if selected != pending.question {
                    if !self.acknowledge(pending.job) {
                        return accepted;
                    }
                    continue;
                }
                pending.reply = Some(reply);
                pending.attempts = pending.attempts.saturating_add(1);
            }
            self.publications.push_back(pending);
        }

        // Refill one fair FIFO item per turn. The complete backlog is durable;
        // the parsed queue is only a bounded working page, never a lifetime cap.
        if self.unanswered.len() < crate::resources::active_limits().question_page
            && let Some(question) = questions.next_backlog()
            && !self.solving.contains_key(question.resolution_id())
            && !self
                .publications
                .iter()
                .any(|p| p.question.resolution_id() == question.resolution_id())
        {
            self.retain(question);
        }

        let loop_goal = if let Some(goal) = &self.formal_goal {
            Some(goal.clone())
        } else if let Some(frontier) = &self.frontier {
            match frontier.loop_focus() {
                Ok(goal) => goal,
                Err(error) => {
                    if error.fatal() {
                        self.error = Some(error.to_string());
                    }
                    return accepted;
                }
            }
        } else {
            None
        };
        let mut goal_requirements = Vec::new();
        let mut required_goal = loop_goal.clone();
        let mut loop_candidates = None;
        if let (Some(goal), Some(frontier)) = (&loop_goal, &mut self.frontier) {
            match frontier.loop_work(goal, graph) {
                Ok(work) => {
                    required_goal = Some(work.target);
                    let planned = work.planned;
                    let pending = work
                        .pending
                        .into_iter()
                        .filter_map(|q| {
                            let q = questions.owned_question(&q).unwrap_or(q);
                            (questions.generation_decision(graph, &q).passed()
                                || questions.assess(graph, &q).passed())
                            .then_some(q)
                        })
                        .collect::<Vec<_>>();
                    if !planned.is_empty() {
                        loop_candidates = Some(if pending.is_empty() {
                            vec![goal.clone()]
                        } else {
                            pending.clone()
                        });
                    }
                    self.unanswered.retain(|q| {
                        if q.resolution_id() == goal.resolution_id() {
                            return pending.is_empty();
                        }
                        !planned
                            .iter()
                            .any(|p| p.resolution_id() == q.resolution_id())
                            || pending
                                .iter()
                                .any(|p| p.resolution_id() == q.resolution_id())
                    });
                    let waiting = !pending.is_empty();
                    for helper in pending {
                        if questions.generation_decision(graph, &helper).passed() {
                            self.retain(helper);
                        }
                    }
                    if !waiting {
                        let original = questions
                            .owned_question(goal)
                            .unwrap_or_else(|| goal.clone());
                        if questions.generation_decision(graph, &original).passed() {
                            self.retain(original);
                        }
                    }
                    goal_requirements = work.required;
                }
                Err(error) => {
                    if error.fatal() {
                        self.error = Some(error.to_string());
                    }
                    return accepted;
                }
            }
        }
        if now >= self.next_proof
            && self.solving.len() < crate::resources::active_limits().solving_jobs
            && self.publications.len() + self.solving.len() + self.evidence_publications.len()
                < crate::resources::active_limits().publications
        {
            self.next_proof = now + Duration::from_millis(self.intervals.solving_ms());
            let selected = if let Some(frontier) = &mut self.frontier {
                // Ranking is a scheduling hint. The selected target crosses the
                // fresh formal gate below before any provider work is admitted.
                let candidates = self.unanswered.iter().collect::<Vec<_>>();
                match frontier.choose(&candidates, graph, self.intervals.jobs.solving, false) {
                    Ok(index) => index,
                    Err(error) => {
                        if error.fatal() {
                            self.error = Some(error.to_string());
                        }
                        return accepted;
                    }
                }
            } else {
                (!self.unanswered.is_empty()).then_some(0)
            };
            if let Some(question) = selected.and_then(|index| self.unanswered.remove(index)) {
                let decision = questions.generation_decision(graph, &question);
                if decision.passed() {
                    let context = questions.formal_context(graph);
                    let required = if required_goal
                        .as_ref()
                        .is_some_and(|g| g.resolution_id() == question.resolution_id())
                    {
                        goal_requirements.clone()
                    } else {
                        Vec::new()
                    };
                    match self.client.submit_after(
                        jobs::Input::Solve {
                            question: question.source().to_owned(),
                        },
                        context.binding(),
                        required,
                    ) {
                        Ok(ticket) => {
                            self.solving.insert(
                                *question.resolution_id(),
                                Solving {
                                    completion: None,
                                    question,
                                    ticket,
                                    seen: questions.revision(graph),
                                },
                            );
                        }
                        Err(_) => self.retain(question),
                    }
                } else if !decision.has_answer() {
                    self.retain(question);
                } else {
                    questions.settle_backlog(question.resolution_id());
                }
            }
        }
        if now >= self.next_question
            && self.finding.is_none()
            && self.admissions.len() < crate::resources::active_limits().finding_admissions
            && questions.available_local()
        {
            // Admissions have their own bounded queue and durable backlog.
            // A full parsed solve page must not stop independent discovery.
            self.next_question = now + Duration::from_millis(self.intervals.finding_ms());
            let (input, binding) = if let Some(record) = self.recovered_finding.pop_front() {
                (record.input, record.binding)
            } else {
                let cursor = self.cursor;
                let Some(next) = cursor.checked_add(1) else {
                    self.error = Some("finding cursor exhausted".into());
                    return accepted;
                };
                self.cursor = next;
                let source = if let Some(frontier) = &mut self.frontier {
                    if self.formal_goal.as_ref().is_some_and(|question| {
                        questions.generation_decision(graph, question).has_answer()
                    }) {
                        return accepted;
                    }
                    frontier.retain_goals(|question| {
                        !questions.generation_decision(graph, question).has_answer()
                    });
                    if let Some(question) = &self.formal_goal {
                        frontier.focus(question.clone());
                    }
                    let mut eligible = |question: &CompiledQuestion| {
                        !self.admissions.iter().any(|pending| {
                            pending.question.resolution_id() == question.resolution_id()
                        }) && questions.assess(graph, question).passed()
                    };
                    match frontier.refresh(graph, &mut eligible) {
                        Ok(()) => {}
                        Err(error) if !error.fatal() => return accepted,
                        Err(error) => {
                            self.error = Some(error.to_string());
                            return accepted;
                        }
                    }
                    let mut candidates = if let Some(pending) = &loop_candidates {
                        pending.clone()
                    } else if let Some(goal) = &loop_goal {
                        match frontier.helpers_needed(goal) {
                            Ok(false) => vec![goal.clone()],
                            Ok(true) => frontier.goal_candidates(cursor, goal),
                            Err(error) => {
                                self.error = Some(error.to_string());
                                return accepted;
                            }
                        }
                    } else {
                        frontier.candidates(cursor)
                    };
                    // The explicit owner goal remains admissible even when a
                    // bounded research-context cache cannot retain its copy.
                    if let Some(goal) = &self.formal_goal
                        && !candidates
                            .iter()
                            .any(|q| q.resolution_id() == goal.resolution_id())
                    {
                        candidates.push(goal.clone());
                    }
                    let candidates = candidates
                        .into_iter()
                        .filter(&mut eligible)
                        .collect::<Vec<_>>();
                    let references = candidates.iter().collect::<Vec<_>>();
                    match frontier.choose(&references, graph, self.intervals.jobs.solving, false) {
                        Ok(Some(index)) => candidates[index].source().to_owned(),
                        Ok(None) => return accepted,
                        Err(error) => {
                            if error.fatal() {
                                self.error = Some(error.to_string());
                            }
                            return accepted;
                        }
                    }
                } else {
                    crate::mocks::create_question(cursor)
                };
                let context = questions.formal_context(graph);
                (
                    jobs::Input::Find {
                        cursor,
                        question: source,
                    },
                    context.binding(),
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
