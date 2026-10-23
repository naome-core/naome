//! Receiver-owned, transient approval and complete proof-closure staging.
use crate::{
    Envelope, Graph,
    graph::CheckedBatch,
    object::{Candidate, Metadata, id_bytes},
    question::{LocalQuestions, QuestionAssessment},
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

mod managed;
#[cfg(test)]
mod tests;

#[derive(Clone)]
struct Description {
    grant: Option<crate::graph::PeerGrant>,
    peer: PeerId,
    id: ProofId,
    statement: StatementId,
    question: CompiledQuestion,
    created: Instant,
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
    bytes: usize,
    steps: usize,
    checker_work: usize,
    final_assessment: Option<QuestionAssessment>,
}

type DeclinedDescriptionKey = (PeerId, ProofId, StatementId, Identity);
type DeclineContext = (Identity, Identity, Instant);

#[derive(Default)]
pub(crate) struct Intake {
    queue: VecDeque<Description>,
    active: Option<ApprovedRoot>,
    declined: BTreeMap<DeclinedDescriptionKey, DeclineContext>,
    waiting: VecDeque<managed::Waiting>,
    managed_context: Option<((Identity, Identity), crate::question::Revision)>,
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
    }
    pub(crate) fn selection_boundary_ready(&self) -> bool {
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
        crate::resources::limits().queued_metadata - self.queue.len()
    }
    pub(crate) fn contains(&self, id: ProofId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|root| root.description.id == id)
            || self.queue.iter().any(|description| description.id == id)
            || self
                .waiting
                .iter()
                .any(|waiting| waiting.description.id == id)
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
        grant: Option<crate::graph::PeerGrant>,
    ) -> Result<&'static str, String> {
        let (id, statement, question) = metadata.compile()?;
        if graph.contains(id)? {
            return Ok("duplicate");
        }
        if let Some(waiting) = self
            .waiting
            .iter_mut()
            .find(|w| w.description.peer == peer && w.description.id == id)
        {
            if waiting.description.statement != statement
                || waiting.description.question != question
            {
                return Err("refreshed metadata differs from the original obligation".into());
            }
            if let managed::Phase::Refresh { ready, .. } = &mut waiting.phase {
                *ready = true;
                waiting.description.created = Instant::now();
                waiting.description.grant = grant;
                return Ok("metadata_refreshed");
            }
            return Ok("queued_duplicate");
        }
        let same = |description: &Description| {
            description.peer == peer
                && description.id == id
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
        if self.queue.len() >= crate::resources::limits().queued_metadata {
            return Err("description queue capacity".into());
        }
        self.queue.push_back(Description {
            grant,
            peer,
            id,
            statement,
            question,
            created: Instant::now(),
        });
        Ok("queued")
    }

    pub(crate) fn needed(&self) -> Vec<(PeerId, ProofId, ProofId)> {
        self.active
            .as_ref()
            .filter(|root| {
                matches!(root.phase, Phase::Fetch)
                    && Instant::now().duration_since(root.description.created)
                        < crate::resources::limits().root_timeout
            })
            .map(|root| {
                root.needed
                    .iter()
                    .map(|id| (root.description.peer, root.description.id, *id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn authorizes(&self, peer: PeerId, root_id: ProofId, id: ProofId) -> bool {
        self.active.as_ref().is_some_and(|root| {
            root.description.peer == peer
                && root.description.id == root_id
                && matches!(root.phase, Phase::Fetch)
                && root.initial.is_some()
                && root.needed.contains(&id)
                && Instant::now().duration_since(root.description.created)
                    < crate::resources::limits().root_timeout
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
        let root = self.active.as_mut().ok_or("unrequested proof payload")?;
        if Instant::now().duration_since(root.description.created)
            >= crate::resources::limits().root_timeout
        {
            return Err("expired proof fetch grant".into());
        }
        if root.description.peer != peer
            || root.description.id != root_id
            || !matches!(root.phase, Phase::Fetch)
            || !root.needed.contains(&expected)
            || id_bytes(&object.proof_id)? != *expected.as_bytes()
        {
            return Err("unrequested or mismatched proof payload".into());
        }
        // Reserve before certificate decoding or normal-form construction.
        let bytes = object.proof.len() / 2;
        if object.proof.len() > 2 * crate::resources::limits().proof_bytes
            || !object.proof.len().is_multiple_of(2)
            || root.staged.len() >= crate::resources::limits().closure_objects
            || root.bytes + bytes > crate::resources::limits().closure_bytes
            || root.checker_work + naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES
                > crate::resources::limits().closure_work_bytes
        {
            return Err("staged closure byte or object capacity".into());
        }
        let header = crate::unhex(
            object
                .proof
                .get(..8)
                .ok_or("truncated certificate header")?,
        )?;
        let steps =
            u32::from_be_bytes(header.try_into().map_err(|_| "certificate header")?) as usize;
        if steps == 0 || steps > crate::resources::limits().closure_steps - root.steps {
            return Err("staged closure step work limit".into());
        }
        let candidate = object.prepare()?;
        if Instant::now().duration_since(root.description.created)
            >= crate::resources::limits().root_timeout
        {
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
                && *dependency != expected
            {
                root.needed.insert(*dependency);
            }
        }
        root.staged.insert(expected, candidate);
        if root.staged.len() + root.needed.len() > crate::resources::limits().closure_objects {
            return Err("staged closure dependency capacity".into());
        }
        Ok(())
    }

    pub(crate) fn abort(&mut self, root_id: ProofId) {
        self.waiting.retain(|w| w.description.id != root_id);
        if self
            .active
            .as_ref()
            .is_some_and(|root| root.description.id == root_id)
        {
            self.active = None;
        }
    }

    pub(crate) fn disconnected(&mut self, peer: PeerId) {
        self.waiting.retain(|w| w.description.peer != peer);
        self.queue.retain(|description| description.peer != peer);
        if self
            .active
            .as_ref()
            .is_some_and(|root| root.description.peer == peer)
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
        if questions.uses_jobs() {
            return self.advance_managed(graph, questions);
        }
        let now = Instant::now();
        let (snapshot, policy) = questions.context_key(graph);
        self.declined.retain(|_, (before, old_policy, until)| {
            *before == snapshot && *old_policy == policy && *until > now
        });
        if self.active.is_none()
            && questions.available()
            && let Some(description) = self.queue.pop_front()
        {
            if Instant::now().duration_since(description.created)
                >= crate::resources::limits().root_timeout
            {
                return Progress::Skipped(description.id, "queued root intake deadline".into());
            }
            let (question, receiver) = questions.begin_exchange(
                graph,
                description.question.clone(),
                description.created + crate::resources::limits().root_timeout,
            );
            self.active = Some(ApprovedRoot {
                description,
                question,
                initial: None,
                phase: Phase::Initial(receiver),
                needed: BTreeSet::new(),
                staged: BTreeMap::new(),
                bytes: 0,
                steps: 0,
                checker_work: 0,
                final_assessment: None,
            });
        }
        let Some(mut root) = self.active.take() else {
            return Progress::Waiting;
        };
        let id = root.description.id;
        let operation = (|| -> Result<Option<Vec<ProofId>>, String> {
            if now.duration_since(root.description.created)
                >= crate::resources::limits().root_timeout
            {
                return Err("root intake deadline".into());
            }
            if matches!(root.phase, Phase::Fetch)
                && root.initial.as_ref().is_some_and(|assessment| {
                    assessment.prefilter.snapshot != snapshot
                        || assessment.prefilter.policy != policy
                })
            {
                return Err("stale approval before proof fetch".into());
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
                    let batch = graph.prepare_batch(
                        id,
                        std::mem::take(&mut root.staged),
                        &root.question,
                    )?;
                    if questions.available() {
                        if Instant::now().duration_since(root.description.created)
                            >= crate::resources::limits().root_timeout
                        {
                            return Err("root validation deadline".into());
                        }
                        let (selected, receiver) = questions.begin_exchange(
                            graph,
                            root.question.clone(),
                            root.description.created + crate::resources::limits().root_timeout,
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
                        if !root
                            .initial
                            .as_ref()
                            .expect("approved root")
                            .prefilter
                            .same_context(&assessment.prefilter)
                            || !questions.exchange_eligible(&root.question, &assessment)
                        {
                            return Err("stale or declined final interest".into());
                        }
                        let delta =
                            questions.prepare_exchange(graph, &root.question, &assessment)?;
                        if Instant::now().duration_since(root.description.created)
                            >= crate::resources::limits().root_timeout
                        {
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
                            root.description.grant.clone(),
                            root.description.created + crate::resources::limits().root_timeout,
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
                if self.declined.len() < crate::resources::limits().fetches {
                    self.declined.insert(
                        (
                            root.description.peer,
                            id,
                            root.description.statement,
                            *root.description.question.source_hash(),
                        ),
                        (
                            snapshot,
                            policy,
                            now + crate::resources::limits().pending_retry,
                        ),
                    );
                }
                Progress::Skipped(id, error)
            }
        }
    }
}
