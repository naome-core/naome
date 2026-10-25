//! Scheduling for long decisions. Selection validity belongs to Selection;
//! checked closures are evicted when their short grant or generation expires.
use super::*;

pub(super) enum Phase {
    Initial,
    Final { batch: Option<Box<CheckedBatch>> },
    Refresh { ready: bool },
}
pub(super) struct Waiting {
    pub description: Description,
    pub selection: Selection,
    pub phase: Phase,
    context: FormalContext,
    until: Instant,
}
enum WaitingStep {
    Waiting,
    Activate,
    Published(Vec<ProofId>),
}
enum ActiveStep {
    Waiting,
    Final(Box<CheckedBatch>, Instant),
    Published(Vec<ProofId>),
}

impl Intake {
    pub(crate) fn refresh_needed(&self) -> Vec<(PeerId, ProofId)> {
        self.active
            .iter()
            .filter(|root| {
                root.closure.has_programs() && root.description.transfer.refresh_due(Instant::now())
            })
            .map(|root| {
                (
                    root.description.transfer.peer(),
                    root.description.transfer.root(),
                )
            })
            .chain(
                self.waiting
                    .iter()
                    .filter(|waiting| matches!(waiting.phase, Phase::Refresh { ready: false }))
                    .map(|waiting| {
                        (
                            waiting.description.transfer.peer(),
                            waiting.description.transfer.root(),
                        )
                    }),
            )
            .collect()
    }
    pub(super) fn decline(
        &mut self,
        description: &Description,
        formal: FormalContext,
        now: Instant,
    ) {
        if self.declined.len() < crate::resources::limits().fetches {
            self.declined.insert(
                (
                    description.transfer.peer(),
                    description.transfer.root(),
                    description.statement,
                    *description.question.source_hash(),
                ),
                DeclineContext {
                    formal,
                    until: now + crate::resources::limits().pending_retry,
                },
            );
        }
    }
    fn advance_waiting<F, Fut>(
        &mut self,
        waiting: &mut Waiting,
        graph: &mut Graph,
        questions: &mut LocalQuestions<F>,
        context_changed: bool,
    ) -> Result<WaitingStep, crate::Error>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        let now = Instant::now();
        let id = waiting.description.transfer.root();
        if graph.contains(id)? {
            return Err("received answer makes pending metadata obsolete".into());
        }
        if now >= waiting.until {
            return Err("research decision horizon expired".into());
        }
        match &mut waiting.phase {
            Phase::Initial => {
                waiting.selection.poll(graph, questions)?;
                if waiting.selection.ready(SelectionStage::Initial) {
                    waiting.selection.prepare(graph, questions)?;
                    waiting.phase = Phase::Refresh { ready: false };
                }
            }
            Phase::Final { batch } => {
                if let Some(checked) = batch.as_ref()
                    && (!graph.batch_current(checked)?
                        || !waiting.description.transfer.live(now)
                        || !crate::resources::adaptive::work_available())
                {
                    *batch = None;
                }
                waiting.selection.poll(graph, questions)?;
                if waiting.selection.ready(SelectionStage::Final) {
                    if waiting.description.transfer.live(Instant::now())
                        && let Some(batch) = batch.take()
                    {
                        return waiting
                            .selection
                            .publish(graph, questions, &waiting.description.transfer, *batch)
                            .map(WaitingStep::Published);
                    }
                    waiting.selection.prepare(graph, questions)?;
                    waiting.phase = Phase::Refresh { ready: false };
                }
            }
            Phase::Refresh { ready } => {
                if context_changed || *ready {
                    waiting.selection.prepare(graph, questions)?;
                }
                if self.active.is_none() && *ready {
                    if !waiting.description.transfer.live(now) {
                        return Err("refreshed metadata lease expired".into());
                    }
                    return Ok(WaitingStep::Activate);
                }
            }
        }
        Ok(WaitingStep::Waiting)
    }
    pub(super) fn advance_managed<F, Fut>(
        &mut self,
        graph: &mut Graph,
        questions: &mut LocalQuestions<F>,
    ) -> Progress
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        let now = Instant::now();
        let revision = questions.revision(graph);
        let context_changed = self
            .managed_context
            .as_ref()
            .is_none_or(|(_, previous)| *previous != revision);
        if context_changed {
            self.managed_context = Some((questions.formal_context(graph), revision));
        }
        let (context, _) = self.managed_context.expect("current managed context");
        self.declined
            .retain(|_, declined| declined.formal == context && declined.until > now);
        if self.waiting.len() < crate::resources::active_limits().interest_decisions
            && questions.available_peer()
            && let Some(description) = self.queue.pop_front()
        {
            let id = description.transfer.root();
            if !description.transfer.live(now) {
                return Progress::Skipped(
                    id,
                    "queued metadata expired before research admission".into(),
                );
            }
            let until = questions.interest_deadline(now);
            let mut selection = Selection::new(id, description.question.clone());
            if let Err(error) = selection.begin(SelectionStage::Initial, graph, questions, until) {
                return Progress::Skipped(id, error);
            }
            self.waiting.push_back(Waiting {
                description,
                selection,
                phase: Phase::Initial,
                context,
                until,
            });
        }
        for _ in 0..self.waiting.len() {
            let mut waiting = self
                .waiting
                .pop_front()
                .expect("bounded metadata decision queue");
            let id = waiting.description.transfer.root();
            match self.advance_waiting(&mut waiting, graph, questions, context_changed) {
                Ok(WaitingStep::Published(ids)) => return Progress::Accepted(ids),
                Ok(WaitingStep::Waiting) => self.waiting.push_back(waiting),
                Ok(WaitingStep::Activate) => {
                    let mut closure = Closure::new(id, Some(waiting.description.statement));
                    if let Err(error) = closure.require_root(graph) {
                        return Progress::Skipped(id, error);
                    }
                    self.active = Some(ApprovedRoot {
                        closure,
                        description: waiting.description,
                        selection: waiting.selection,
                        phase: super::Phase::Fetch,
                    });
                }
                Err(error) if error.retryable() => self.waiting.push_back(waiting),
                Err(error) => {
                    graph.program_failure(&error);
                    self.decline(&waiting.description, waiting.context, now);
                    return Progress::Skipped(id, error);
                }
            }
        }
        let Some(mut root) = self.active.take() else {
            return Progress::Waiting;
        };
        let id = root.description.transfer.root();
        let result = (|| -> Result<ActiveStep, crate::Error> {
            if !root.description.transfer.live(now) {
                if !root.closure.has_programs() {
                    return Err("short proof grant expired".into());
                }
                return Ok(ActiveStep::Waiting);
            }
            if context_changed || root.closure.needed().next().is_none() {
                root.selection.prepare(graph, questions)?;
            }
            if root.closure.needed().next().is_some() || !root.closure.certificate_ready() {
                return Ok(ActiveStep::Waiting);
            }
            // Final selection drains a root that already owns its intake slot.
            // Blocking it behind the waiting limit after capacity falls makes
            // active and waiting roots wait for each other. New descriptions
            // remain bounded at admission, as do actual provider decisions.
            if !root.selection.ready(SelectionStage::Final) && !questions.available_peer() {
                return Err(crate::Error::ExecutionLimit);
            }
            let batch = root
                .closure
                .prepare_certificates(graph, root.selection.question())?;
            if root.selection.ready(SelectionStage::Final) {
                root.closure.invalidate_prefix();
                return root
                    .selection
                    .publish(graph, questions, &root.description.transfer, batch)
                    .map(ActiveStep::Published);
            }
            for waiting in &mut self.waiting {
                if let Phase::Final { batch } = &mut waiting.phase {
                    *batch = None;
                }
            }
            let until = questions.interest_deadline(Instant::now());
            if !root
                .selection
                .begin(SelectionStage::Final, graph, questions, until)?
            {
                return Err(crate::Error::ExecutionLimit);
            }
            Ok(ActiveStep::Final(Box::new(batch), until))
        })();
        match result {
            Ok(ActiveStep::Published(ids)) => Progress::Accepted(ids),
            Ok(ActiveStep::Final(batch, until)) => {
                self.waiting.push_back(Waiting {
                    description: root.description,
                    selection: root.selection,
                    phase: Phase::Final { batch: Some(batch) },
                    context,
                    until,
                });
                Progress::Waiting
            }
            Ok(ActiveStep::Waiting) => {
                self.active = Some(root);
                Progress::Waiting
            }
            Err(error) if error.retryable() => {
                self.active = Some(root);
                Progress::Waiting
            }
            Err(error) => {
                graph.program_failure(&error);
                let context = root
                    .selection
                    .selected()
                    .map(QuestionAssessment::formal_context)
                    .unwrap_or(context);
                self.decline(&root.description, context, now);
                Progress::Skipped(id, error)
            }
        }
    }
}
