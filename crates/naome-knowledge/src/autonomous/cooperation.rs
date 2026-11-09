//! Finite peer offers are hints, never authority to start mathematical work.
use super::*;
use libp2p::PeerId;

struct Pending {
    peer: PeerId,
    goal: Identity,
    question: ResearchQuestion,
    reply: oneshot::Receiver<question::QuestionAssessment>,
    expires: Instant,
    _memory: std::sync::Arc<crate::resources::MemoryLease>,
}

pub(super) struct Selected {
    pub(super) peer: PeerId,
    pub(super) goal: Identity,
    pub(super) question: ResearchQuestion,
    pub(super) assessment: question::QuestionAssessment,
    pub(super) expires: Instant,
    pub(super) memory: std::sync::Arc<crate::resources::MemoryLease>,
}

#[derive(Default)]
pub(crate) struct Cooperation {
    pending: Option<Pending>,
    selected: Option<Selected>,
    wanted: Option<(
        Identity,
        ResearchQuestion,
        std::sync::Arc<crate::resources::MemoryLease>,
    )>,
    notices: VecDeque<(PeerId, Identity, Identity, bool, u64, Instant)>,
    next_notice: u64,
    pub(super) turn: bool,
}

impl Cooperation {
    pub(crate) fn wanted(&self) -> Option<(Identity, &ResearchQuestion)> {
        self.wanted
            .as_ref()
            .map(|(goal, question, _)| (*goal, question))
    }

    pub(super) fn request(&mut self, goal: Identity, question: ResearchQuestion) {
        if self
            .wanted
            .as_ref()
            .is_some_and(|(old_goal, old_question, _)| {
                *old_goal == goal && *old_question == question
            })
        {
            return;
        }
        let bytes = question
            .canonical_bytes()
            .len()
            .saturating_mul(128)
            .saturating_add(4096);
        if let Ok(memory) = crate::resources::MemoryLease::acquire(bytes) {
            self.wanted = Some((goal, question, memory));
        }
    }

    pub(super) fn clear_request(&mut self) {
        self.wanted = None;
    }

    pub(crate) fn offer<F, Fut>(
        &mut self,
        peer: PeerId,
        goal: Identity,
        source: &str,
        graph: &Graph,
        questions: &mut question::LocalQuestions<F>,
        own: impl Iterator<Item = ResearchQuestion>,
    ) -> bool
    where
        F: Fn(ResearchQuestion) -> Fut + Send + Sync + 'static,
        Fut:
            Future<Output = Result<bool, crate::question::SelectionProviderError>> + Send + 'static,
    {
        if self.pending.is_some()
            || self.selected.is_some()
            || !questions.available_local()
            || source.len() > 2 * naome_checker::question::QUESTION_BYTES
        {
            return false;
        }
        let Ok(memory) = crate::resources::MemoryLease::acquire(
            source.len().saturating_mul(64).saturating_add(4096),
        ) else {
            return false;
        };
        let Ok(question) = ResearchQuestion::from_hex_with_context(source, graph.checked_context())
        else {
            return false;
        };
        let mut has_own = false;
        let mut related = false;
        for goal in own {
            has_own = true;
            if crate::frontier::Frontier::related(&goal, &question) {
                related = true;
                break;
            }
        }
        if has_own && !related {
            return false;
        }
        let expires = questions.selection_deadline(Instant::now());
        let (question, reply) = questions.begin_exchange(graph, question, expires);
        self.pending = Some(Pending {
            peer,
            goal,
            question,
            reply,
            expires,
            _memory: memory,
        });
        true
    }

    pub(super) fn poll<F, Fut>(
        &mut self,
        graph: &Graph,
        questions: &mut question::LocalQuestions<F>,
    ) where
        F: Fn(ResearchQuestion) -> Fut + Send + Sync + 'static,
        Fut:
            Future<Output = Result<bool, crate::question::SelectionProviderError>> + Send + 'static,
    {
        if self
            .selected
            .as_ref()
            .is_some_and(|s| Instant::now() >= s.expires)
        {
            self.selected = None;
        }
        let Some(mut pending) = self.pending.take() else {
            return;
        };
        if Instant::now() >= pending.expires {
            return;
        }
        match pending.reply.try_recv() {
            Ok(assessment)
                if questions.exchange_eligible(graph, &pending.question, &assessment) =>
            {
                self.selected = Some(Selected {
                    peer: pending.peer,
                    goal: pending.goal,
                    question: pending.question,
                    assessment,
                    expires: pending.expires,
                    memory: pending._memory,
                });
            }
            Err(oneshot::error::TryRecvError::Empty) => self.pending = Some(pending),
            _ => {}
        }
    }

    pub(super) fn take(&mut self) -> Option<Selected> {
        self.selected.take()
    }

    pub(super) fn put_back(&mut self, selected: Selected) {
        self.selected = Some(selected);
    }

    pub(super) fn has_selected(&self) -> bool {
        self.selected.is_some()
    }

    pub(super) fn selected_is(&self, resolution: &Identity) -> bool {
        self.selected
            .as_ref()
            .is_some_and(|selected| selected.question.resolution_id() == resolution)
    }

    pub(super) fn selected_id(&self) -> Option<Identity> {
        self.selected
            .as_ref()
            .map(|selected| *selected.question.resolution_id())
    }

    pub(super) fn notice(
        &mut self,
        peer: PeerId,
        goal: Identity,
        question: Identity,
        active: bool,
    ) {
        if self.notices.len() < crate::resources::active_limits().queued_metadata {
            let Some(sequence) = self.next_notice.checked_add(1) else {
                return;
            };
            self.next_notice = sequence;
            self.notices.push_back((
                peer,
                goal,
                question,
                active,
                sequence,
                Instant::now() + crate::resources::limits().pending_retry,
            ));
        }
    }

    pub(crate) fn take_notice(
        &mut self,
    ) -> Option<(PeerId, Identity, Identity, bool, u64, Instant)> {
        while let Some(notice) = self.notices.pop_front() {
            if Instant::now() < notice.5 {
                return Some(notice);
            }
        }
        None
    }

    pub(crate) fn defer_notice(
        &mut self,
        notice: (PeerId, Identity, Identity, bool, u64, Instant),
    ) {
        if self.notices.len() < crate::resources::active_limits().queued_metadata {
            self.notices.push_back(notice);
        }
    }
}
