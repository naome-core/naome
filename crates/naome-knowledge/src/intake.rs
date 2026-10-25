//! Receiver-owned, transient approval and complete proof-closure staging.
use crate::{
    Envelope, Graph,
    graph::CheckedBatch,
    object::{Candidate, Metadata, id_bytes},
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
mod managed;
mod program;
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
    Initial(oneshot::Receiver<QuestionAssessment>),
    Fetch,
    Final(oneshot::Receiver<QuestionAssessment>, Box<CheckedBatch>),
}

/// Private grant binds a root, peer, derived source and selected original
/// question to the complete local assessment, positive interest and lifetime.
struct ApprovedRoot {
    description: Description,
    question: CompiledQuestion,
    initial: Option<QuestionAssessment>,
    phase: Phase,
    needed: BTreeSet<ProofId>,
    staged: BTreeMap<ProofId, Candidate>,
    helpers: program::Helpers,
    bytes: usize,
    steps: usize,
    checker_work: usize,
    final_assessment: Option<QuestionAssessment>,
}

impl ApprovedRoot {
    fn fetching(&self) -> bool {
        matches!(self.phase, Phase::Fetch) && self.initial.is_some()
    }
    fn member_count(&self) -> usize {
        self.staged
            .keys()
            .copied()
            .chain(self.needed.iter().copied())
            .chain(self.helpers.members())
            .chain(std::iter::once(self.description.transfer.root()))
            .collect::<BTreeSet<_>>()
            .len()
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
            .is_some_and(|root| root.needed.is_empty())
            || self.waiting.iter().any(|w| match &w.phase {
                managed::Phase::Initial(reply) | managed::Phase::Final { reply, .. } => {
                    !reply.is_empty()
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
    ) -> Result<&'static str, String> {
        self.enqueue_with_grant(peer, metadata, graph, None)
    }
    pub(crate) fn enqueue_with_grant(
        &mut self,
        peer: PeerId,
        metadata: Metadata,
        graph: &Graph,
        grant: Option<crate::publication::PeerGrant>,
    ) -> Result<&'static str, String> {
        let (id, statement, question) = metadata.compile()?;
        if graph.contains(id)? {
            return Ok("duplicate");
        }
        if let Some(root) = &mut self.active
            && root.description.transfer.root() == id
            && !root.helpers.is_empty()
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
                root.needed
                    .iter()
                    .copied()
                    .filter(|id| !root.helpers.contains(*id))
                    .chain(root.helpers.needed())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
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
                    && (root.needed.contains(&id)
                        || root.helpers.needs(id)
                        || root.helpers.contains(id))
            })
    }

    pub(crate) fn payload(
        &mut self,
        peer: PeerId,
        root_id: ProofId,
        expected: ProofId,
        object: Envelope,
        graph: &Graph,
    ) -> Result<(), String> {
        if self.programs.authorizes(peer, root_id, expected) {
            return self
                .programs
                .certificate_payload(peer, root_id, expected, object, graph)
                .map_err(String::from);
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
        let (bytes, steps) = certificate::resources(&object)?;
        let (helper_count, helper_bytes, helper_steps) = root.helpers.certificate_usage();
        if root.staged.len() + helper_count >= crate::resources::limits().closure_objects
            || root.bytes + helper_bytes + bytes > crate::resources::limits().closure_bytes
            || root.checker_work
                + (helper_count + 1) * naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES
                > crate::resources::limits().closure_work_bytes
        {
            return Err("staged closure resource capacity".into());
        }
        if root.steps + helper_steps + steps > crate::resources::limits().closure_steps {
            return Err("staged closure step work limit".into());
        }
        if root.helpers.needs(expected) {
            return root
                .helpers
                .certificate_payload(expected, object, graph)
                .map_err(String::from);
        }
        if !root.description.transfer.live(Instant::now()) {
            return Err("expired proof fetch grant".into());
        }
        if !root.needed.contains(&expected) || id_bytes(&object.proof_id)? != *expected.as_bytes() {
            return Err("unrequested or mismatched proof payload".into());
        }
        // The shared certificate header charge precedes decoding and allocation.
        let candidate = object.prepare()?;
        if !root.description.transfer.live(Instant::now()) {
            return Err("expired proof staging grant".into());
        }
        if candidate.id == root_id && candidate.statement != root.description.statement {
            return Err("root statement differs from approved metadata".into());
        }
        root.bytes += bytes;
        root.steps += steps;
        root.checker_work += naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES;
        root.needed.remove(&expected);
        for dependency in &candidate.dependencies {
            if !graph.contains(*dependency)?
                && !root.staged.contains_key(dependency)
                && !root.helpers.contains(*dependency)
                && *dependency != expected
            {
                root.needed.insert(*dependency);
            }
        }
        root.staged.insert(expected, candidate);
        if root.member_count() > crate::resources::limits().closure_objects {
            return Err("staged closure dependency capacity".into());
        }
        Ok(())
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
        if self
            .active
            .as_ref()
            .is_some_and(|root| root.member_count() > crate::resources::limits().closure_objects)
        {
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
            let (question, receiver) = questions.begin_exchange(
                graph,
                description.question.clone(),
                description.transfer.deadline(),
            );
            self.active = Some(ApprovedRoot {
                description,
                question,
                initial: None,
                phase: Phase::Initial(receiver),
                needed: BTreeSet::new(),
                staged: BTreeMap::new(),
                helpers: program::Helpers::default(),
                bytes: 0,
                steps: 0,
                checker_work: 0,
                final_assessment: None,
            });
        }
        let Some(mut root) = self.active.take() else {
            return Progress::Waiting;
        };
        let id = root.description.transfer.root();
        let operation = (|| -> Result<Option<Vec<ProofId>>, String> {
            if !root.description.transfer.live(now) {
                if root.helpers.is_empty() {
                    return Err("root intake deadline".into());
                } else {
                    return Ok(None);
                }
            }
            if matches!(root.phase, Phase::Fetch)
                && root
                    .initial
                    .as_ref()
                    .is_some_and(|assessment| assessment.formal_context() != context)
            {
                let current = questions.refresh_exchange(
                    graph,
                    &root.question,
                    root.initial.as_ref().expect("approved root"),
                )?;
                root.initial = Some(current);
            }
            match &mut root.phase {
                Phase::Initial(receiver) => match receiver.try_recv() {
                    Ok(assessment) => {
                        if !questions.exchange_eligible(&root.question, &assessment) {
                            return Err(format!(
                                "question declined: {:?}/{:?}",
                                assessment.prefilter.reason, assessment.interest
                            ));
                        }
                        root.initial = Some(assessment);
                        root.needed.insert(id); // Parent first; no advertised helper list.
                        root.phase = Phase::Fetch;
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(_) => return Err("question assessment cancelled".into()),
                },
                Phase::Fetch if root.needed.is_empty() => {
                    if !root.helpers.ready() {
                        return Ok(None);
                    }
                    let batch = graph.prepare_batch_after(
                        id,
                        std::mem::take(&mut root.staged),
                        &root.question,
                        root.helpers.take_prefix(),
                    )?;
                    if questions.available() {
                        if !root.description.transfer.live(Instant::now()) {
                            return Err("root validation deadline".into());
                        }
                        let (selected, receiver) = questions.begin_exchange(
                            graph,
                            root.question.clone(),
                            root.description.transfer.deadline(),
                        );
                        if selected != root.question {
                            return Err("question provenance changed".into());
                        }
                        root.phase = Phase::Final(receiver, Box::new(batch));
                    } else {
                        return Err("question receiving capacity".into());
                    }
                }
                Phase::Final(receiver, _) => match receiver.try_recv() {
                    Ok(assessment) => {
                        if !questions.exchange_eligible(
                            &root.question,
                            root.initial.as_ref().expect("approved root"),
                        ) || !questions.exchange_eligible(&root.question, &assessment)
                        {
                            return Err("stale or declined final interest".into());
                        }
                        let delta =
                            questions.prepare_exchange(graph, &root.question, &assessment)?;
                        if !root.description.transfer.live(Instant::now()) {
                            return Err("root commit deadline".into());
                        }
                        let Phase::Final(_, batch) =
                            std::mem::replace(&mut root.phase, Phase::Fetch)
                        else {
                            unreachable!()
                        };
                        let admitted = questions.publish_exchange(
                            graph,
                            id,
                            *batch,
                            delta,
                            root.description.transfer.capability(),
                            root.description.transfer.deadline(),
                        )?;
                        return Ok(Some(admitted));
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(_) => return Err("final question assessment cancelled".into()),
                },
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
            Err(error) => {
                self.decline(&root.description, context, now);
                Progress::Skipped(id, error)
            }
        }
    }
}
