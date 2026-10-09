//! Long decisions retain only metadata. Every payload grant remains short.
use super::*;

const MAX_DECISIONS: usize = 4;

pub(super) enum Phase {
    Initial(oneshot::Receiver<QuestionAssessment>),
    Final {
        reply: oneshot::Receiver<QuestionAssessment>,
        initial: QuestionAssessment,
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
    context: (Identity, Identity),
    until: Instant,
}

impl Intake {
    pub(crate) fn refresh_needed(&self) -> Vec<(PeerId, ProofId)> {
        self.waiting
            .iter()
            .filter(|w| matches!(w.phase, Phase::Refresh { ready: false, .. }))
            .map(|w| (w.description.peer, w.description.id))
            .collect()
    }

    fn decline(
        &mut self,
        description: &Description,
        snapshot: Identity,
        policy: Identity,
        now: Instant,
    ) {
        if self.declined.len() < crate::network::MAX_FETCHES {
            self.declined.insert(
                (
                    description.peer,
                    description.id,
                    description.statement,
                    *description.question.source_hash(),
                ),
                (snapshot, policy, now + crate::PENDING_TTL),
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
            self.managed_context = Some((questions.context_key(graph), revision));
        }
        let ((snapshot, policy), _) = self.managed_context.expect("current managed context");
        self.declined.retain(|_, (before, old_policy, until)| {
            *before == snapshot && *old_policy == policy && *until > now
        });
        if self.waiting.len() < MAX_DECISIONS
            && questions.available_peer()
            && let Some(description) = self.queue.pop_front()
        {
            if now.saturating_duration_since(description.created) >= ROOT_TTL {
                return Progress::Skipped(
                    description.id,
                    "queued metadata expired before research admission".into(),
                );
            }
            let until = questions.interest_deadline(now);
            let (question, reply) = questions.begin_peer_exchange(
                graph,
                description.question.clone(),
                description.id,
                crate::jobs::Purpose::Initial,
                until,
            );
            self.waiting.push_back(Waiting {
                description,
                question,
                phase: Phase::Initial(reply),
                context: (snapshot, policy),
                until,
            });
        }

        for _ in 0..self.waiting.len() {
            let mut waiting = self
                .waiting
                .pop_front()
                .expect("bounded metadata decision queue");
            let id = waiting.description.id;
            let result = (|| -> Result<bool, String> {
                if graph.contains(id) {
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
                    Phase::Final { reply, initial } => match reply.try_recv() {
                        Ok(assessment) => {
                            if !initial.prefilter.same_context(&assessment.prefilter)
                                || !questions.exchange_eligible(&waiting.question, &assessment)
                            {
                                return Err("final interest declined or stale".into());
                            }
                            questions.prepare_exchange(graph, &waiting.question, &assessment)?;
                            waiting.phase = Phase::Refresh {
                                initial: initial.clone(),
                                final_assessment: Some(Box::new(assessment)),
                                ready: false,
                            };
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {}
                        Err(_) => return Err("final interest cancelled".into()),
                    },
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
                            if now.saturating_duration_since(waiting.description.created)
                                >= ROOT_TTL
                            {
                                return Err("refreshed metadata lease expired".into());
                            }
                            let root = ApprovedRoot {
                                description: waiting.description.clone(),
                                question: waiting.question.clone(),
                                initial: Some(initial.clone()),
                                phase: super::Phase::Fetch,
                                needed: [id].into(),
                                staged: BTreeMap::new(),
                                bytes: 0,
                                steps: 0,
                                checker_work: 0,
                                final_assessment: final_assessment.as_deref().cloned(),
                            };
                            self.active = Some(root);
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            })();
            match result {
                Ok(true) => {}
                Ok(false) => self.waiting.push_back(waiting),
                Err(error) => {
                    self.decline(
                        &waiting.description,
                        waiting.context.0,
                        waiting.context.1,
                        now,
                    );
                    return Progress::Skipped(id, error);
                }
            }
        }

        let Some(mut root) = self.active.take() else {
            return Progress::Waiting;
        };
        let id = root.description.id;
        let result = (|| -> Result<Option<Vec<ProofId>>, String> {
            if now.saturating_duration_since(root.description.created) >= ROOT_TTL {
                return Err("short proof grant expired".into());
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
            let batch =
                graph.prepare_batch(id, std::mem::take(&mut root.staged), &root.question)?;
            if let Some(assessment) = &root.final_assessment {
                let delta = questions.prepare_exchange(graph, &root.question, assessment)?;
                if Instant::now().saturating_duration_since(root.description.created) >= ROOT_TTL {
                    return Err("short commit grant expired".into());
                }
                graph.persist_batch(id, &batch)?;
                let admitted = graph.apply_batch(batch);
                questions.apply_exchange(delta);
                return Ok(Some(admitted));
            }
            // Checked staging is deliberately dropped while final interest may
            // take days. One later metadata refresh and refetch is necessary.
            drop(batch);
            if self.waiting.len() >= MAX_DECISIONS || !questions.available_peer() {
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
            let context = (initial.prefilter.snapshot, initial.prefilter.policy);
            self.waiting.push_back(Waiting {
                description: root.description.clone(),
                question,
                phase: Phase::Final { reply, initial },
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
                    .map(|assessment| (assessment.prefilter.snapshot, assessment.prefilter.policy))
                    .unwrap_or((snapshot, policy));
                self.decline(&root.description, context.0, context.1, now);
                Progress::Skipped(id, error)
            }
        }
    }
}
