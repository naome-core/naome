//! One selection lifecycle for certificate and program intake. A completed
//! provider decision survives temporary formal-work exhaustion, but never a
//! changed source, owner policy or selection epoch. Transport grants are separate.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelectionStage {
    Initial,
    Final,
}
struct Pending {
    stage: SelectionStage,
    deadline: Instant,
    reply: oneshot::Receiver<QuestionAssessment>,
    received: Option<QuestionAssessment>,
}
pub(super) struct Selection {
    root: ArtifactId,
    question: CompiledQuestion,
    initial: Option<QuestionAssessment>,
    final_assessment: Option<QuestionAssessment>,
    pending: Option<Pending>,
    until: Instant,
}
impl Selection {
    pub(super) fn new(root: ArtifactId, question: CompiledQuestion) -> Self {
        Self {
            root,
            question,
            initial: None,
            final_assessment: None,
            pending: None,
            until: Instant::now(),
        }
    }
    pub(super) fn question(&self) -> &CompiledQuestion {
        &self.question
    }
    #[cfg(test)]
    pub(super) fn initial(&self) -> Option<&QuestionAssessment> {
        self.initial.as_ref()
    }
    pub(super) fn selected(&self) -> Option<&QuestionAssessment> {
        self.final_assessment.as_ref().or(self.initial.as_ref())
    }
    pub(super) fn ready(&self, stage: SelectionStage) -> bool {
        match stage {
            SelectionStage::Initial => self.initial.is_some(),
            SelectionStage::Final => self.final_assessment.is_some(),
        }
    }
    pub(super) fn begin<F, Fut>(
        &mut self,
        stage: SelectionStage,
        graph: &Graph,
        questions: &mut LocalQuestions<F>,
        deadline: Instant,
    ) -> Result<bool, crate::Error>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        if self.pending.is_some() {
            return Err("selection decision already pending".into());
        }
        if !questions.available_peer() {
            return Ok(false);
        }
        let purpose = match stage {
            SelectionStage::Initial => crate::jobs::Purpose::Initial,
            SelectionStage::Final => crate::jobs::Purpose::Final,
        };
        let (question, reply) = questions.begin_peer_exchange(
            graph,
            self.question.clone(),
            self.root,
            purpose,
            deadline,
        );
        if stage == SelectionStage::Final && question != self.question {
            return Err("original question provenance changed".into());
        }
        self.question = question;
        self.pending = Some(Pending {
            stage,
            deadline,
            reply,
            received: None,
        });
        Ok(true)
    }
    pub(super) fn poll<F, Fut>(
        &mut self,
        graph: &Graph,
        questions: &mut LocalQuestions<F>,
    ) -> Result<Option<SelectionStage>, crate::Error>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        let Some(pending) = &mut self.pending else {
            return Ok(None);
        };
        if Instant::now() >= pending.deadline {
            return Err("selection decision horizon expired".into());
        }
        if pending.received.is_none() {
            match pending.reply.try_recv() {
                Ok(assessment) => pending.received = Some(assessment),
                Err(oneshot::error::TryRecvError::Empty) => return Ok(None),
                Err(_) => return Err("selection assessment cancelled".into()),
            }
        }
        if pending.stage == SelectionStage::Final
            && self
                .initial
                .as_ref()
                .is_none_or(|initial| !questions.exchange_eligible(&self.question, initial))
        {
            return Err("initial selection declined or stale".into());
        }
        // Keep the received value until fresh formal work succeeds. Receiving a
        // oneshot is irreversible; retrying its receiver would lose the decision.
        let assessment = questions.refresh_exchange(
            graph,
            &self.question,
            pending.received.as_ref().expect("received selection"),
        )?;
        let stage = pending.stage;
        match stage {
            SelectionStage::Initial => {
                self.initial = Some(assessment);
                self.final_assessment = None;
            }
            SelectionStage::Final => self.final_assessment = Some(assessment),
        }
        self.until = Instant::now() + crate::resources::limits().root_timeout;
        self.pending = None;
        Ok(Some(stage))
    }
    pub(super) fn prepare<F, Fut>(
        &mut self,
        graph: &Graph,
        questions: &mut LocalQuestions<F>,
    ) -> Result<crate::question::QuestionDelta, crate::Error>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        if self
            .initial
            .as_ref()
            .is_none_or(|initial| !questions.exchange_eligible(&self.question, initial))
        {
            return Err("initial selection declined or stale".into());
        }
        let selected = self
            .selected()
            .ok_or("proof grant has no selected question")?;
        questions.prepare_exchange(graph, &self.question, selected)
    }
    /// Every intake format crosses the same current selection and short
    /// transfer boundary before the existing atomic Graph/Question publication.
    pub(super) fn publish<F, Fut>(
        &mut self,
        graph: &mut Graph,
        questions: &mut LocalQuestions<F>,
        transfer: &TransferGrant,
        batch: CheckedBatch,
    ) -> Result<Vec<ArtifactId>, crate::Error>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        if transfer.root() != self.root {
            return Err("publication root differs from selection".into());
        }
        if !self.ready(SelectionStage::Final) {
            return Err("final selection selection missing".into());
        }
        let delta = self.prepare(graph, questions)?;
        transfer.check(Instant::now())?;
        questions.publish_exchange(
            graph,
            transfer.root(),
            batch,
            delta,
            transfer.capability(),
            transfer.deadline(),
        )
    }
    /// Incremental program work may outlive a short assessment lease. Renewal
    /// performs a new provider decision; refreshing metadata never calls this.
    pub(super) fn renew<F, Fut>(
        &mut self,
        stage: SelectionStage,
        graph: &Graph,
        questions: &mut LocalQuestions<F>,
    ) -> Result<bool, crate::Error>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        let valid = self
            .selected()
            .is_some_and(|assessment| questions.exchange_eligible(&self.question, assessment));
        if self.pending.is_none() && (!self.ready(stage) || !valid || Instant::now() >= self.until)
        {
            if !valid || Instant::now() >= self.until && stage == SelectionStage::Initial {
                self.initial = None;
                self.final_assessment = None;
            } else if Instant::now() >= self.until {
                self.final_assessment = None;
            }
            let next = if self.initial.is_none() {
                SelectionStage::Initial
            } else {
                stage
            };
            let deadline = if questions.uses_jobs() {
                questions.selection_deadline(Instant::now())
            } else {
                Instant::now() + crate::resources::limits().root_timeout
            };
            self.begin(next, graph, questions, deadline)?;
        }
        self.poll(graph, questions)?;
        if self.pending.is_some() || !self.ready(stage) {
            return Ok(false);
        }
        if let Some(assessment) = self.selected()
            && assessment.formal_context() != questions.formal_context(graph)
        {
            let fresh = questions.refresh_exchange(graph, &self.question, assessment)?;
            if self.final_assessment.is_some() {
                self.final_assessment = Some(fresh);
            } else {
                self.initial = Some(fresh);
            }
        }
        Ok(true)
    }
    #[cfg(test)]
    pub(super) fn until(&self) -> Instant {
        self.until
    }
    #[cfg(test)]
    pub(super) fn set_until(&mut self, until: Instant) {
        self.until = until;
    }
}
