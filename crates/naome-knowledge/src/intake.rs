//! Receiver-owned, transient approval and complete proof-closure staging.
use crate::{
    Envelope, Graph,
    graph::CheckedBatch,
    object::Metadata,
    question::{FormalContext, LocalQuestions, QuestionAssessment},
};
use libp2p::PeerId;
use naome_authoring::CompiledQuestion;
use naome_checker::question::Identity;
use naome_proof::{ProofId, StatementId};
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    time::Instant,
};
use tokio::sync::oneshot;

mod certificate;
mod closure;
use closure::Closure;
mod managed;
mod program;
mod selection;
use selection::{Selection, SelectionStage};
mod transfer;
use transfer::TransferGrant;
#[cfg(test)]
mod tests;

#[derive(Clone)]
struct Description {
    transfer: TransferGrant,
    statement: StatementId,
    question: CompiledQuestion,
}

enum Phase {
    Initial,
    Fetch,
    Final(Box<CheckedBatch>),
}

/// Private grant binds a root, peer, derived source and selected original
/// question to the complete local assessment, positive interest and lifetime.
struct ApprovedRoot {
    description: Description,
    selection: Selection,
    phase: Phase,
    closure: Closure,
}

impl ApprovedRoot {
    fn fetching(&self) -> bool {
        matches!(self.phase, Phase::Fetch) && self.selection.ready(SelectionStage::Initial)
    }
}

type DeclinedDescriptionKey = (PeerId, ProofId, StatementId, Identity);
struct DeclineContext {
    formal: FormalContext,
    until: Instant,
}

#[derive(Default)]
pub(crate) struct Intake {
    queue: VecDeque<Description>,
    active: Option<ApprovedRoot>,
    declined: BTreeMap<DeclinedDescriptionKey, DeclineContext>,
    waiting: VecDeque<managed::Waiting>,
    managed_context: Option<(FormalContext, crate::question::Revision)>,
    programs: program::Programs,
}

pub(crate) enum Progress {
    Waiting,
    Skipped(ProofId, String),
    Accepted(Vec<ProofId>),
}

impl Intake {
    pub(crate) fn invalidate_interest(&mut self) {
        self.declined.clear();
        self.managed_context = None;
        self.programs.invalidate_interest();
    }
    pub(crate) fn selection_boundary_ready(&self) -> bool {
        if self.programs.selection_boundary_ready() {
            return true;
        }
        self.active
            .as_ref()
            .is_some_and(|root| root.closure.needed().next().is_none())
            || self.waiting.iter().any(|w| match &w.phase {
                managed::Phase::Initial | managed::Phase::Final { .. } => {
                    w.selection.boundary_ready()
                }
                managed::Phase::Refresh { ready, .. } => *ready,
            })
    }
    pub(crate) fn description_capacity(&self) -> usize {
        crate::resources::active_limits()
            .queued_metadata
            .saturating_sub(self.queue.len() + self.programs.queued())
    }
    pub(crate) fn contains(&self, id: ProofId) -> bool {
        if self.programs.contains(id) {
            return true;
        }
        self.active
            .as_ref()
            .is_some_and(|root| root.description.transfer.root() == id)
            || self
                .queue
                .iter()
                .any(|description| description.transfer.root() == id)
            || self
                .waiting
                .iter()
                .any(|waiting| waiting.description.transfer.root() == id)
    }

    #[cfg(test)]
    pub(crate) fn enqueue(
        &mut self,
        peer: PeerId,
        metadata: Metadata,
        graph: &Graph,
    ) -> Result<&'static str, crate::Error> {
        self.enqueue_with_grant(peer, metadata, graph, None)
    }
    pub(crate) fn enqueue_with_grant(
        &mut self,
        peer: PeerId,
        metadata: Metadata,
        graph: &Graph,
        grant: Option<crate::publication::PeerGrant>,
    ) -> Result<&'static str, crate::Error> {
        let (id, statement, question) = metadata.compile()?;
        if graph.contains(id)? {
            return Ok("duplicate");
        }
        if let Some(root) = &mut self.active
            && root.description.transfer.root() == id
            && root.closure.has_programs()
        {
            if root.description.statement != statement || root.description.question != question {
                return Err("refreshed parent metadata differs".into());
            }
            root.description.transfer = TransferGrant::new(peer, id, grant);
            return Ok("metadata_refreshed");
        }
        if let Some(waiting) = self
            .waiting
            .iter_mut()
            .find(|w| w.description.transfer.peer() == peer && w.description.transfer.root() == id)
        {
            if waiting.description.statement != statement
                || waiting.description.question != question
            {
                return Err("refreshed metadata differs from the original obligation".into());
            }
            if let managed::Phase::Refresh { ready, .. } = &mut waiting.phase {
                *ready = true;
                waiting.description.transfer = TransferGrant::new(peer, id, grant);
                return Ok("metadata_refreshed");
            }
            return Ok("queued_duplicate");
        }
        let same = |description: &Description| {
            description.transfer.peer() == peer
                && description.transfer.root() == id
                && description.statement == statement
                && description.question == question
        };
        if self.queue.iter().any(same)
            || self
                .active
                .as_ref()
                .is_some_and(|root| same(&root.description))
        {
            return Ok("queued_duplicate");
        }
        if self
            .declined
            .contains_key(&(peer, id, statement, *question.source_hash()))
        {
            return Ok("declined");
        }
        if self.queue.len() >= crate::resources::active_limits().queued_metadata {
            return Err("description queue capacity".into());
        }
        self.queue.push_back(Description {
            transfer: TransferGrant::new(peer, id, grant),
            statement,
            question,
        });
        Ok("queued")
    }

    pub(crate) fn needed(&self) -> Vec<(PeerId, ProofId, ProofId)> {
        self.active
            .as_ref()
            .filter(|root| {
                matches!(root.phase, Phase::Fetch) && root.description.transfer.live(Instant::now())
            })
            .map(|root| {
                root.closure
                    .needed()
                    .map(|id| {
                        (
                            root.description.transfer.peer(),
                            root.description.transfer.root(),
                            id,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .chain(self.programs.needed())
            .collect()
    }

    pub(crate) fn authorizes(&self, peer: PeerId, root_id: ProofId, id: ProofId) -> bool {
        self.programs.authorizes(peer, root_id, id)
            || self.active.as_ref().is_some_and(|root| {
                root.fetching()
                    && root
                        .description
                        .transfer
                        .authorizes(peer, root_id, Instant::now())
                    && (root.closure.needs(id) || root.closure.contains(id))
            })
    }

    pub(crate) fn payload(
        &mut self,
        peer: PeerId,
        root_id: ProofId,
        expected: ProofId,
        object: Envelope,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if self.programs.authorizes(peer, root_id, expected) {
            return self
                .programs
                .certificate_payload(peer, root_id, expected, object, graph);
        }
        if self.active.as_ref().is_some_and(|root| {
            root.description.transfer.peer() == peer
                && root.description.transfer.root() == root_id
                && !root.description.transfer.live(Instant::now())
        }) {
            return Err("expired proof fetch grant".into());
        }
        if !self.authorizes(peer, root_id, expected) {
            return Err("unrequested proof payload".into());
        }
        let root = self.active.as_mut().ok_or("unrequested proof payload")?;
        root.closure
            .certificate_payload(expected, object, graph, &root.description.transfer)
    }

    pub(crate) fn abort(&mut self, root_id: ProofId) {
        self.programs.remove(root_id);
        self.waiting
            .retain(|w| w.description.transfer.root() != root_id);
        if self
            .active
            .as_ref()
            .is_some_and(|root| root.description.transfer.root() == root_id)
        {
            self.active = None;
        }
    }

    pub(crate) fn disconnected(&mut self, peer: PeerId) {
        self.programs.failed(peer, None);
        self.waiting
            .retain(|w| w.description.transfer.peer() != peer);
        self.queue
            .retain(|description| description.transfer.peer() != peer);
        if self
            .active
            .as_ref()
            .is_some_and(|root| root.description.transfer.peer() == peer)
        {
            self.active = None;
        }
    }

    pub(crate) fn advance<F, Fut>(
        &mut self,
        graph: &mut Graph,
        questions: &mut LocalQuestions<F>,
    ) -> Progress
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        if self.active.as_ref().is_some_and(|root| {
            root.closure.member_count() > crate::resources::limits().closure_objects
        }) {
            let root = self.active.take().expect("overloaded closure");
            return Progress::Skipped(
                root.description.transfer.root(),
                "staged closure dependency capacity".into(),
            );
        }
        if let Err(error) = self.advance_program_helpers(graph, questions)
            && !error.retryable()
        {
            graph.program_failure(&error);
            if let Some(root) = self.active.take() {
                return Progress::Skipped(root.description.transfer.root(), error.to_string());
            }
        }
        match self.programs.advance(graph, questions) {
            Progress::Waiting => {}
            progress => return progress,
        }
        if questions.uses_jobs() {
            return self.advance_managed(graph, questions);
        }
        let now = Instant::now();
        let context = questions.formal_context(graph);
        self.declined
            .retain(|_, declined| declined.formal == context && declined.until > now);
        if self.active.is_none()
            && questions.available()
            && let Some(description) = self.queue.pop_front()
        {
            if !description.transfer.live(Instant::now()) {
                return Progress::Skipped(
                    description.transfer.root(),
                    "queued root intake deadline".into(),
                );
            }
            let mut selection =
                Selection::new(description.transfer.root(), description.question.clone());
            let started = selection.begin(
                SelectionStage::Initial,
                graph,
                questions,
                description.transfer.deadline(),
            );
            if let Err(error) = started {
                return Progress::Skipped(description.transfer.root(), error.to_string());
            }
            self.active = Some(ApprovedRoot {
                closure: Closure::new(description.transfer.root(), Some(description.statement)),
                description,
                selection,
                phase: Phase::Initial,
            });
        }
        let Some(mut root) = self.active.take() else {
            return Progress::Waiting;
        };
        let id = root.description.transfer.root();
        let operation = (|| -> Result<Option<Vec<ProofId>>, crate::Error> {
            if !root.description.transfer.live(now) {
                if !root.closure.has_programs() {
                    return Err("root intake deadline".into());
                } else {
                    return Ok(None);
                }
            }
            if matches!(root.phase, Phase::Fetch)
                && root
                    .selection
                    .selected()
                    .is_some_and(|assessment| assessment.formal_context() != context)
            {
                root.selection.prepare(graph, questions)?;
            }
            match &mut root.phase {
                Phase::Initial => {
                    root.selection.poll(graph, questions)?;
                    if root.selection.ready(SelectionStage::Initial) {
                        root.closure.require_root(graph)?;
                        root.phase = Phase::Fetch;
                    }
                }
                Phase::Fetch if root.closure.certificate_ready() => {
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
                            .map(Some);
                    }
                    root.description.transfer.check(Instant::now())?;
                    if !root.selection.begin(
                        SelectionStage::Final,
                        graph,
                        questions,
                        root.description.transfer.deadline(),
                    )? {
                        return Err(crate::Error::ExecutionLimit);
                    }
                    root.phase = Phase::Final(Box::new(batch));
                }
                Phase::Final(_) => {
                    root.selection.poll(graph, questions)?;
                    if root.selection.ready(SelectionStage::Final) {
                        let Phase::Final(batch) = std::mem::replace(&mut root.phase, Phase::Fetch)
                        else {
                            unreachable!()
                        };
                        root.closure.invalidate_prefix();
                        return root
                            .selection
                            .publish(graph, questions, &root.description.transfer, *batch)
                            .map(Some);
                    }
                }

                _ => {}
            }
            Ok(None)
        })();
        match operation {
            Ok(Some(admitted)) => Progress::Accepted(admitted),
            Ok(None) => {
                self.active = Some(root);
                Progress::Waiting
            }
            Err(error) if error.retryable() => {
                self.active = Some(root);
                Progress::Waiting
            }
            Err(error) => {
                graph.program_failure(&error);
                self.decline(&root.description, context, now);
                Progress::Skipped(id, error.to_string())
            }
        }
    }
}
