//! Long decisions retain metadata and at most one live checked closure.
//! The closure is evicted when its short grant or checked generation expires.
use super::*;

pub(super) enum Phase {
    Initial(oneshot::Receiver<QuestionAssessment>),
    Final {
        reply: oneshot::Receiver<QuestionAssessment>,
        initial: QuestionAssessment,
        batch: Option<Box<CheckedBatch>>,
    },
    Refresh {
        initial: QuestionAssessment,
        final_assessment: Option<Box<QuestionAssessment>>,
        ready: bool,
    },
}

pub(super) struct Waiting {
    pub description: Description,
    question: CompiledQuestion,
    pub phase: Phase,
    context: FormalContext,
    until: Instant,
}

impl Intake {
    pub(crate) fn refresh_needed(&self) -> Vec<(PeerId, ProofId)> {
        self.active
            .iter()
            .filter(|root| {
                !root.helpers.is_empty() && root.description.transfer.refresh_due(Instant::now())
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
                    .filter(|w| matches!(w.phase, Phase::Refresh { ready: false, .. }))
                    .map(|w| (w.description.transfer.peer(), w.description.transfer.root())),
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
            if !description.transfer.live(now) {
                return Progress::Skipped(
                    description.transfer.root(),
                    "queued metadata expired before research admission".into(),
                );
            }
            let until = questions.interest_deadline(now);
            let (question, reply) = questions.begin_peer_exchange(
                graph,
                description.question.clone(),
                description.transfer.root(),
                crate::jobs::Purpose::Initial,
                until,
            );
            self.waiting.push_back(Waiting {
                description,
                question,
                phase: Phase::Initial(reply),
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
            let result = (|| -> Result<Option<Vec<ProofId>>, String> {
                if graph.contains(id)? {
                    return Err("received answer makes pending metadata obsolete".into());
                }
                if now >= waiting.until {
                    return Err("research decision horizon expired".into());
                }
                match &mut waiting.phase {
                    Phase::Initial(reply) => match reply.try_recv() {
                        Ok(assessment) => {
                            if !questions.exchange_eligible(&waiting.question, &assessment) {
                                return Err("initial interest declined or stale".into());
                            }
                            questions.prepare_exchange(graph, &waiting.question, &assessment)?;
                            waiting.phase = Phase::Refresh {
                                initial: assessment,
                                final_assessment: None,
                                ready: false,
                            };
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {}
                        Err(_) => return Err("initial interest cancelled".into()),
                    },
                    Phase::Final {
                        reply,
                        initial,
                        batch,
                    } => {
                        let current = batch
                            .as_ref()
                            .map(|batch| graph.batch_current(batch))
                            .transpose()?;
                        if current.is_some_and(|current| {
                            !current
                                || !waiting.description.transfer.live(now)
                                || !crate::resources::adaptive::work_available()
                        }) {
                            *batch = None;
                        }
                        match reply.try_recv() {
                            Ok(assessment) => {
                                if !questions.exchange_eligible(&waiting.question, initial)
                                    || !questions.exchange_eligible(&waiting.question, &assessment)
                                {
                                    return Err("final interest declined or stale".into());
                                }
                                let delta = questions.prepare_exchange(
                                    graph,
                                    &waiting.question,
                                    &assessment,
                                )?;
                                if let Some(batch) = batch.take()
                                    && waiting.description.transfer.live(Instant::now())
                                {
                                    return questions
                                        .publish_exchange(
                                            graph,
                                            id,
                                            *batch,
                                            delta,
                                            waiting.description.transfer.capability(),
                                            waiting.description.transfer.deadline(),
                                        )
                                        .map(Some)
                                        .map_err(String::from);
                                }
                                waiting.phase = Phase::Refresh {
                                    initial: initial.clone(),
                                    final_assessment: Some(Box::new(assessment)),
                                    ready: false,
                                };
                            }
                            Err(oneshot::error::TryRecvError::Empty) => {}
                            Err(_) => return Err("final interest cancelled".into()),
                        }
                    }
                    Phase::Refresh {
                        initial,
                        final_assessment,
                        ready,
                    } => {
                        let selected = final_assessment.as_deref().unwrap_or(initial);
                        if context_changed || *ready {
                            questions.prepare_exchange(graph, &waiting.question, selected)?;
                        }
                        if self.active.is_none() && *ready {
                            if !waiting.description.transfer.live(now) {
                                return Err("refreshed metadata lease expired".into());
                            }
                            let root = ApprovedRoot {
                                description: waiting.description.clone(),
                                question: waiting.question.clone(),
                                initial: Some(initial.clone()),
                                phase: super::Phase::Fetch,
                                needed: [id].into(),
                                staged: BTreeMap::new(),
                                helpers: program::Helpers::default(),
                                bytes: 0,
                                steps: 0,
                                checker_work: 0,
                                final_assessment: final_assessment.as_deref().cloned(),
                            };
                            self.active = Some(root);
                            return Ok(Some(Vec::new()));
                        }
                    }
                }
                Ok(None)
            })();
            match result {
                Ok(Some(ids)) if !ids.is_empty() => return Progress::Accepted(ids),
                Ok(Some(_)) => {}
                Ok(None) => self.waiting.push_back(waiting),
                Err(error) => {
                    self.decline(&waiting.description, waiting.context, now);
                    return Progress::Skipped(id, error);
                }
            }
        }

        let Some(mut root) = self.active.take() else {
            return Progress::Waiting;
        };
        let id = root.description.transfer.root();
        let result = (|| -> Result<Option<Vec<ProofId>>, String> {
            if !root.description.transfer.live(now) {
                if root.helpers.is_empty() {
                    return Err("short proof grant expired".into());
                } else {
                    return Ok(None);
                }
            }
            let selected = root
                .final_assessment
                .as_ref()
                .or(root.initial.as_ref())
                .ok_or("proof grant has no selected question")?;
            if context_changed || root.needed.is_empty() {
                questions.prepare_exchange(graph, &root.question, selected)?;
            }
            if !root.needed.is_empty() {
                return Ok(None);
            }
            if !root.helpers.ready() {
                return Ok(None);
            }
            let batch = graph.prepare_batch_after(
                id,
                std::mem::take(&mut root.staged),
                &root.question,
                root.helpers.take_prefix(),
            )?;
            if let Some(assessment) = &root.final_assessment {
                let delta = questions.prepare_exchange(graph, &root.question, assessment)?;
                if !root.description.transfer.live(Instant::now()) {
                    return Err("short commit grant expired".into());
                }
                let admitted = questions.publish_exchange(
                    graph,
                    id,
                    batch,
                    delta,
                    root.description.transfer.capability(),
                    root.description.transfer.deadline(),
                )?;
                return Ok(Some(admitted));
            }
            // The same sealed CheckedBatch used by program intake may survive
            // a short final decision. Keep one closure across all waiting roots;
            // long decisions and pressure retain only metadata and refetch later.
            for waiting in &mut self.waiting {
                if let Phase::Final { batch, .. } = &mut waiting.phase {
                    *batch = None;
                }
            }
            if self.waiting.len() >= crate::resources::active_limits().interest_decisions
                || !questions.available_peer()
            {
                return Err("final decision queue capacity".into());
            }
            let until = questions.interest_deadline(Instant::now());
            let (question, reply) = questions.begin_peer_exchange(
                graph,
                root.question.clone(),
                id,
                crate::jobs::Purpose::Final,
                until,
            );
            if question != root.question {
                return Err("original question provenance changed".into());
            }
            let initial = root.initial.take().ok_or("initial decision absent")?;
            let context = initial.formal_context();
            self.waiting.push_back(Waiting {
                description: root.description.clone(),
                question,
                phase: Phase::Final {
                    reply,
                    initial,
                    batch: Some(Box::new(batch)),
                },
                context,
                until,
            });
            Ok(Some(Vec::new()))
        })();
        match result {
            Ok(Some(admitted)) if !admitted.is_empty() => Progress::Accepted(admitted),
            Ok(Some(_)) => Progress::Waiting,
            Ok(None) => {
                self.active = Some(root);
                Progress::Waiting
            }
            Err(error) => {
                let context = root
                    .final_assessment
                    .as_ref()
                    .or(root.initial.as_ref())
                    .map(QuestionAssessment::formal_context)
                    .unwrap_or(context);
                self.decline(&root.description, context, now);
                Progress::Skipped(id, error)
            }
        }
    }
}
