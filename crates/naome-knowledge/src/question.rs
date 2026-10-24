//! Local formal prefilter, optional interest selection and atomic question intake.
//!
//! Assessment is read-only. Admission rechecks the receiver's current graph,
//! registry and policy after interest, then commits in the same serialized node
//! operation. Baseline import is a separate owner-held administrative capability.
//! The ordinary registry preserves original inputs and admission provenance.
//! Peer descriptions carry derived
//! obligations; neither their source nor an earlier result authorizes a write.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use naome_authoring::CompiledQuestion;
use naome_checker::question::{
    AssessmentQuestion, Identity, KnowledgeSnapshot, NodeLocalNovelty, PrefilterDecision,
    PrefilterPolicy, QuestionRegistry, RegisteredQuestion, RejectionReason, assess_question,
};
use naome_foundation::FOUNDATION_ID;
use tokio::sync::{mpsc, oneshot};

use crate::Graph;

// Worst-case JSON escaping of one protocol-bounded source plus its receipt.
const QUESTION_ENTRY_MAX_BYTES: usize = 6 * naome_authoring::QUESTION_SOURCE_MAX_BYTES + 2048;
mod persistence;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterestAssessment {
    NotRun,
    Assessed(bool),
    Inconclusive,
    ProviderFailed,
    TimedOut,
    Stale,
}

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct QuestionAssessment {
    /// Supported finite formal checks, separate from interest selection.
    pub prefilter: PrefilterDecision,
    pub interest: InterestAssessment,
    pub submitted_negation_parity: bool,
    /// Exact provider and owner-selection epoch; absent after owner recovery error.
    pub selection: Option<Identity>,
    pub decision: Option<crate::interest::Evidence>,
}

impl QuestionAssessment {
    /// First discovery within the bound complete local world and finite rules.
    /// Interest failure or nonselection does not change this formal result.
    pub fn novelty(&self) -> Option<&NodeLocalNovelty> {
        self.prefilter.novelty()
    }
}

/// Observed local registry effect, emitted only after a successful insertion.
/// No API accepts this receipt or an earlier Pass as insertion authority.
///
/// ```compile_fail
/// fn rebind(receipt: &mut naome_knowledge::question::AdmissionReceipt) {
///     receipt.record = [0; 32];
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionReceipt {
    record: Identity,
    snapshot_after: Identity,
    registry_before: Identity,
    registry_after: Identity,
    novelty: NodeLocalNovelty,
    selection: Identity,
    interest_job: Option<u64>,
}

impl AdmissionReceipt {
    /// Exact owner/policy/model epoch used by this first admission.
    pub const fn selection_epoch(&self) -> Identity {
        self.selection
    }
    /// Durable research history entry containing the input and model evidence.
    /// Explicit cooperative embeddings have no managed job identifier.
    pub const fn interest_job(&self) -> Option<u64> {
        self.interest_job
    }
    pub const fn record(&self) -> Identity {
        self.record
    }
    pub const fn input(&self) -> Identity {
        self.novelty.input_id()
    }
    pub const fn policy(&self) -> Identity {
        self.novelty.policy_id()
    }
    pub const fn snapshot_before(&self) -> Identity {
        self.novelty.snapshot_id()
    }
    pub const fn snapshot_after(&self) -> Identity {
        self.snapshot_after
    }
    pub const fn registry_before(&self) -> Identity {
        self.registry_before
    }
    pub const fn registry_after(&self) -> Identity {
        self.registry_after
    }
    /// Fresh checker result for the world immediately before this insertion.
    pub const fn novelty(&self) -> &NodeLocalNovelty {
        &self.novelty
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionOutcome {
    Admitted(Box<AdmissionReceipt>),
    /// Formal rejection, stale context or no positive interest selection.
    /// Inspect prefilter and interest separately; selection is not correctness.
    NotInserted,
}

#[derive(Clone, Debug)]
pub struct QuestionAdmission {
    pub assessment: QuestionAssessment,
    pub outcome: AdmissionOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntakeError {
    QueueFull,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalQuestionContext {
    pub snapshot: Identity,
    pub policy: Identity,
    pub checked_proofs: usize,
    pub registered_questions: usize,
}

pub(crate) enum Command {
    Assess(CompiledQuestion, oneshot::Sender<QuestionAssessment>),
    Admit(CompiledQuestion, oneshot::Sender<QuestionAdmission>),
    ImportBaseline(
        CompiledQuestion,
        oneshot::Sender<Result<(), RejectionReason>>,
    ),
    Policy(PrefilterPolicy, oneshot::Sender<()>),
    Context(oneshot::Sender<LocalQuestionContext>),
    Stop(oneshot::Sender<()>),
}

/// Ordinary local intake. It cannot mint the administrative import capability.
///
/// ```compile_fail
/// fn bypass(handle: &naome_knowledge::question::QuestionHandle,
///           question: naome_authoring::CompiledQuestion) {
///     let _ = handle.import_baseline(question);
/// }
/// ```
#[derive(Clone)]
pub struct QuestionHandle {
    sender: mpsc::Sender<Command>,
}

/// Explicit capability retained by the receiving node's embedding owner.
/// Baseline import preserves known/preexisting questions and is not admission.
#[derive(Clone)]
pub struct QuestionAdminHandle {
    sender: mpsc::Sender<Command>,
}

pub struct QuestionInbox {
    receiver: mpsc::Receiver<Command>,
}

impl QuestionInbox {
    pub(crate) async fn receive(&mut self) -> Option<Command> {
        self.receiver.recv().await
    }
}

/// The creator chooses who receives the administrative capability; cloning an
/// ordinary handle never grants import or policy mutation.
pub fn channel() -> (QuestionHandle, QuestionAdminHandle, QuestionInbox) {
    let (sender, receiver) = mpsc::channel(crate::resources::limits().question_commands);
    (
        QuestionHandle {
            sender: sender.clone(),
        },
        QuestionAdminHandle { sender },
        QuestionInbox { receiver },
    )
}

async fn send<T>(
    sender: &mpsc::Sender<Command>,
    command: Command,
    reply: oneshot::Receiver<T>,
) -> Result<T, IntakeError> {
    sender.try_send(command).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => IntakeError::QueueFull,
        mpsc::error::TrySendError::Closed(_) => IntakeError::Stopped,
    })?;
    reply.await.map_err(|_| IntakeError::Stopped)
}

impl QuestionHandle {
    pub async fn assess(
        &self,
        question: CompiledQuestion,
    ) -> Result<QuestionAssessment, IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Assess(question, sender), reply).await
    }

    /// Fresh formal admission after positive optional interest selection.
    /// A changed graph, registry or policy invalidates the pending selection;
    /// an earlier assessment/receipt is never an argument or authorization.
    pub async fn admit_question(
        &self,
        question: CompiledQuestion,
    ) -> Result<QuestionAdmission, IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Admit(question, sender), reply).await
    }

    pub async fn context(&self) -> Result<LocalQuestionContext, IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Context(sender), reply).await
    }
}

impl QuestionAdminHandle {
    /// Imports parser-validated baseline knowledge, including already answered
    /// questions. This deliberate owner operation has no formal-admission claim.
    pub async fn import_baseline(
        &self,
        question: CompiledQuestion,
    ) -> Result<Result<(), RejectionReason>, IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(
            &self.sender,
            Command::ImportBaseline(question, sender),
            reply,
        )
        .await
    }

    pub async fn set_policy(&self, policy: PrefilterPolicy) -> Result<(), IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Policy(policy, sender), reply).await
    }

    pub async fn stop(&self) -> Result<(), IntakeError> {
        let (sender, reply) = oneshot::channel();
        send(&self.sender, Command::Stop(sender), reply).await
    }
}

enum Reply {
    Assessment(oneshot::Sender<QuestionAssessment>),
    Admission(oneshot::Sender<QuestionAdmission>),
    Exchange {
        reply: oneshot::Sender<QuestionAssessment>,
        deadline: Instant,
        root: Option<naome_proof::ProofId>,
        purpose: crate::jobs::Purpose,
    },
}

impl Reply {
    fn is_closed(&self) -> bool {
        match self {
            Self::Assessment(reply) | Self::Exchange { reply, .. } => reply.is_closed(),
            Self::Admission(reply) => reply.is_closed(),
        }
    }

    fn admission(&self) -> bool {
        matches!(self, Self::Admission(_))
    }

    fn exchange(&self) -> bool {
        matches!(self, Self::Exchange { .. })
    }

    fn send(self, assessment: QuestionAssessment, outcome: AdmissionOutcome) -> bool {
        match self {
            Self::Assessment(reply) | Self::Exchange { reply, .. } => {
                reply.send(assessment).is_ok()
            }
            Self::Admission(reply) => reply
                .send(QuestionAdmission {
                    assessment,
                    outcome,
                })
                .is_ok(),
        }
    }
}

struct Pending {
    question: CompiledQuestion,
    prefilter: PrefilterDecision,
    reply: Reply,
    future: Pin<Box<dyn Future<Output = ProviderResult> + Send>>,
    job: Option<u64>,
    peer: bool,
    selection: Option<Identity>,
    evidence: Option<crate::interest::Evidence>,
}

struct ProviderResult {
    assessment: InterestAssessment,
    job: Option<u64>,
    evidence: Option<crate::interest::Evidence>,
}

#[derive(Clone)]
struct AdmittedProvenance {
    question: CompiledQuestion,
    record: Identity,
}

pub(crate) struct QuestionDelta {
    registry: QuestionRegistry,
    question: Option<CompiledQuestion>,
}

struct RegistryCompaction {
    source: Arc<crate::index_storage::IndexStorage>,
    target: Arc<crate::index_storage::IndexStorage>,
    cursor: Option<naome_checker::question::QuestionRegistryCopy>,
    _disk: crate::resources::DiskLease,
}
impl Drop for RegistryCompaction {
    fn drop(&mut self) {
        self.source.end_mirror(&self.target);
    }
}

pub(crate) type Revision = (usize, usize, Identity, Option<Identity>);

pub(crate) struct LocalQuestions<F> {
    registry: QuestionRegistry,
    policy: PrefilterPolicy,
    provider: Option<Arc<F>>,
    managed: Option<crate::jobs::Client>,
    interest_context: Option<crate::interest::Context>,
    pending: BTreeMap<u64, Pending>,
    next_pending: u64,
    finished: Option<u64>,
    persistence: Option<persistence::Persistence>,
    index_storage: Option<Arc<crate::index_storage::IndexStorage>>,
    compaction: Option<RegistryCompaction>,
    next_compaction: usize,
    old_indexes: Vec<std::sync::Weak<crate::index_storage::IndexStorage>>,
    storage_error: Option<String>,
    interest_horizon: Duration,
    selection: Option<Identity>,
    /// One computed read-only decision, never an admission or interest receipt.
    cached: Option<PrefilterDecision>,
    /// Only successful local admission with an actually delivered receipt.
    admitted: BTreeMap<Identity, AdmittedProvenance>,
    known: BTreeMap<Identity, CompiledQuestion>,
    #[cfg(test)]
    computations: usize,
}

impl<F, Fut> LocalQuestions<F>
where
    F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<bool, String>> + Send + 'static,
{
    pub(crate) fn new(provider: Option<F>) -> Self {
        Self {
            registry: QuestionRegistry::new(),
            policy: crate::resources::limits().assessment_policy(),
            provider: provider.map(Arc::new),
            managed: None,
            interest_context: None,
            pending: BTreeMap::new(),
            next_pending: 1,
            finished: None,
            persistence: None,
            index_storage: None,
            compaction: None,
            next_compaction: crate::resources::limits().registry_index_cache_bytes,
            old_indexes: Vec::new(),
            storage_error: None,
            interest_horizon: crate::resources::limits().interest_timeout,
            selection: Some(
                crate::object::id_bytes(&crate::jobs::Binding::new([0; 32], [0; 32]).selection)
                    .expect("canonical built-in provider identity"),
            ),
            cached: None,
            admitted: BTreeMap::new(),
            known: BTreeMap::new(),
            #[cfg(test)]
            computations: 0,
        }
    }

    pub(crate) fn managed(
        client: crate::jobs::Client,
        directory: &std::path::Path,
        horizon: Duration,
    ) -> Result<Self, String> {
        let mut local = Self::new(None);
        local.attach_persistence(directory)?;
        local.managed = Some(client);
        local.interest_horizon = horizon;
        let profile = crate::runtime::owner_profile_at(directory)?;
        match crate::decision::liquid::Installed::load(directory) {
            Ok(installed) => {
                local.interest_context = Some(crate::interest::Context {
                    epoch: local.selection.expect("initial embedding epoch"),
                    interest: profile.interest,
                    revision: profile.revision,
                    digest: profile.digest,
                    model: installed
                        .map_or_else(crate::decision::liquid::unconfigured_identity, |model| {
                            model.identity()
                        }),
                })
            }
            Err(_) => local.selection = None,
        }
        Ok(local)
    }

    pub(crate) fn attach_persistence(&mut self, directory: &std::path::Path) -> Result<(), String> {
        if self.persistence.is_some() {
            return Ok(());
        }
        if !self.registry.is_empty() {
            return Err("cannot replace a populated local registry".into());
        }
        let persistence = persistence::Persistence::open(directory, self.policy)?;
        let storage = crate::index_storage::IndexStorage::open(directory, "questions")?;
        self.registry = QuestionRegistry::with_storage(storage.clone());
        persistence.replay(|entry,question|{
            let record=*question.source_hash();
            self.registry.insert(RegisteredQuestion::new(record,question.core()).map_err(|e|format!("recovered question: {e:?}"))?).map_err(|e|format!("recovered registry: {e:?}"))?;
            if entry.kind==persistence::Kind::Prepared {crate::network::emit(serde_json::json!({"event":"question_recovery_hold","source_id":crate::hex(&record),"reason":"original admission delivery is uncertain"}));}
            self.remember(question,entry.kind==persistence::Kind::Admitted);Ok(())
        })?;
        self.persistence = Some(persistence);
        self.index_storage = Some(storage);
        Ok(())
    }

    pub(crate) fn maintain_registry(&mut self) -> Result<(), crate::Error> {
        if !crate::resources::adaptive::work_available() {
            return Ok(());
        }
        let Some(storage) = self.index_storage.clone() else {
            return Ok(());
        };
        self.old_indexes.retain(|index| index.strong_count() > 0);
        if self.compaction.is_none()
            && self.old_indexes.len() < crate::resources::limits().retained_generations
            && storage.allocated_bytes()? >= self.next_compaction
        {
            let bytes = storage
                .allocated_bytes()?
                .checked_mul(2)
                .ok_or("registry compaction disk overflow")?;
            let disk = match crate::resources::DiskLease::acquire(
                storage.directory(),
                u64::try_from(bytes).map_err(|_| "registry disk width")?,
            ) {
                Ok(disk) => disk,
                Err(error) if error.retryable() => return Ok(()),
                Err(error) => return Err(error),
            };
            let target = storage.successor()?;
            storage.mirror_to(target.clone())?;
            let mut copy = RegistryCompaction {
                source: storage,
                target,
                cursor: None,
                _disk: disk,
            };
            copy.cursor = Some(
                self.registry
                    .begin_copy(copy.target.clone())
                    .map_err(|e| e.to_string())?,
            );
            self.compaction = Some(copy);
        }
        if let Some(mut copy) = self.compaction.take() {
            let progress = match copy.cursor.as_mut().expect("active registry copy").advance(
                naome_checker::DiskCopyBudget {
                    records: crate::resources::limits().compaction_records,
                    bytes: crate::resources::limits().compaction_bytes,
                },
            ) {
                Ok(progress) => progress,
                Err(naome_checker::ContextError::Limit) => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            if progress.complete {
                let registry = copy
                    .cursor
                    .take()
                    .expect("complete registry copy")
                    .finish(&self.registry)
                    .map_err(|e| e.to_string())?;
                let live = copy.target.allocated_bytes()?;
                self.next_compaction = live.saturating_mul(2).max(
                    live.saturating_add(crate::resources::limits().registry_index_cache_bytes),
                );
                copy.source.end_mirror(&copy.target);
                self.old_indexes.push(Arc::downgrade(&copy.source));
                self.registry = registry;
                self.index_storage = Some(copy.target.clone());
            } else {
                self.compaction = Some(copy);
            }
        }
        Ok(())
    }

    fn remember(&mut self, question: CompiledQuestion, admitted: bool) {
        fn bytes(q: &CompiledQuestion) -> usize {
            q.source()
                .len()
                .saturating_add(q.canonical_core().len().saturating_mul(256))
                .saturating_add(std::mem::size_of::<CompiledQuestion>() + 512)
        }
        let needed = bytes(&question);
        let budget = crate::resources::limits().checked_cache_bytes / 8;
        let limit = crate::resources::limits().question_page;
        if needed > budget {
            return;
        }
        while self.known.len() >= limit
            || self.known.values().map(bytes).sum::<usize>() + needed > budget
        {
            if self.known.pop_first().is_none() {
                break;
            }
        }
        self.known.insert(*question.source_hash(), question.clone());
        if admitted {
            while self.admitted.len() >= limit
                || self
                    .admitted
                    .values()
                    .map(|entry| bytes(&entry.question))
                    .sum::<usize>()
                    + needed
                    > budget
            {
                if self.admitted.pop_first().is_none() {
                    break;
                }
            }
            self.admitted.insert(
                *question.resolution_id(),
                AdmittedProvenance {
                    record: *question.source_hash(),
                    question,
                },
            );
        }
    }
    fn provenance(&self, resolution: &Identity) -> Option<AdmittedProvenance> {
        if let Some(persistence) = &self.persistence {
            return persistence
                .admitted(resolution)
                .ok()
                .flatten()
                .map(|(question, record)| AdmittedProvenance { question, record });
        }
        self.admitted.get(resolution).cloned()
    }
    pub(crate) fn next_backlog(&mut self) -> Option<CompiledQuestion> {
        let persistence = self.persistence.as_mut()?;
        match persistence.next_backlog() {
            Ok(question) => question,
            Err(error) => {
                self.storage_error = Some(error);
                None
            }
        }
    }
    pub(crate) fn settle_backlog(&mut self, resolution: &Identity) {
        if let Some(persistence) = &mut self.persistence
            && let Err(error) = persistence.settle_backlog(resolution)
        {
            self.storage_error = Some(error);
        }
    }

    pub(crate) fn restored_unanswered(&self, graph: &Graph) -> Vec<CompiledQuestion> {
        self.admitted
            .values()
            .filter_map(|entry| {
                let request = AssessmentQuestion::new(
                    FOUNDATION_ID,
                    entry.question.core(),
                    entry.question.source().as_bytes(),
                    &[],
                    Some(entry.record),
                )
                .ok()?;
                let decision = assess_question(&request, &self.snapshot(graph), &self.policy);
                (decision.passed() || decision.inconclusive()).then(|| entry.question.clone())
            })
            .collect()
    }

    pub(crate) fn storage_error(&self) -> Option<String> {
        self.storage_error
            .clone()
            .or_else(|| {
                self.persistence
                    .as_ref()
                    .and_then(persistence::Persistence::error)
            })
            .or_else(|| {
                self.index_storage
                    .as_ref()
                    .and_then(|storage| storage.error())
            })
    }
    pub(crate) fn uses_jobs(&self) -> bool {
        self.managed.is_some()
    }
    pub(crate) fn interest_deadline(&self, now: Instant) -> Instant {
        now + self.interest_horizon
    }

    /// The serialized driver supplies a validated provider/owner epoch. Errors
    /// invalidate selection instead of reusing the last known profile.
    pub(crate) fn select(&mut self, selection: Option<Identity>) -> bool {
        if selection == self.selection {
            return false;
        }
        self.selection = selection;
        self.cached = None;
        for (_, pending) in std::mem::take(&mut self.pending) {
            if let (Some(client), Some(job)) = (&self.managed, pending.job)
                && let Err(error) = client.acknowledge(job)
            {
                self.storage_error = Some(error);
            }
            pending.reply.send(
                QuestionAssessment {
                    prefilter: pending.prefilter,
                    interest: InterestAssessment::Stale,
                    submitted_negation_parity: pending.question.negation_parity(),
                    selection: pending.selection,
                    decision: pending.evidence,
                },
                AdmissionOutcome::NotInserted,
            );
        }
        self.finished = None;
        true
    }

    pub(crate) fn select_context(&mut self, context: Option<crate::interest::Context>) -> bool {
        let epoch = context.as_ref().map(|context| context.epoch);
        self.interest_context = context;
        self.select(epoch)
    }

    fn registry_capacity(&self, question: &CompiledQuestion) -> bool {
        self.storage_error().is_none()
            && (self.persistence.is_some()
                || self.known.contains_key(question.source_hash())
                || self
                    .known
                    .values()
                    .map(|q| q.source().len() + q.canonical_core().len() * 64)
                    .sum::<usize>()
                    + question.source().len()
                    + question.canonical_core().len() * 64
                    <= crate::resources::limits().checked_cache_bytes)
    }

    fn snapshot<'a>(&'a self, graph: &'a Graph) -> KnowledgeSnapshot<'a> {
        KnowledgeSnapshot::new(
            crate::compatibility(),
            graph.checked_context(),
            &self.registry,
        )
    }

    pub(crate) fn context_key(&self, graph: &Graph) -> (Identity, Identity) {
        (self.snapshot(graph).identity(), self.policy.identity())
    }
    pub(crate) fn revision(&self, graph: &Graph) -> Revision {
        (
            graph.accepted_count(),
            self.registry.len(),
            self.policy.identity(),
            self.selection,
        )
    }
    #[cfg(test)]
    pub(crate) fn computation_count(&self) -> usize {
        self.computations
    }

    fn evaluate(
        &mut self,
        graph: &Graph,
        question: &CompiledQuestion,
        reuse: bool,
    ) -> PrefilterDecision {
        self.evaluate_record(graph, question, reuse, None)
    }

    fn evaluate_record(
        &mut self,
        graph: &Graph,
        question: &CompiledQuestion,
        reuse: bool,
        record: Option<Identity>,
    ) -> PrefilterDecision {
        let snapshot = self.snapshot(graph);
        let request = AssessmentQuestion::new(
            FOUNDATION_ID,
            question.core(),
            question.source().as_bytes(),
            &[],
            record,
        )
        .expect("bounded parser-validated question input");
        if !crate::resources::adaptive::work_available() {
            return naome_checker::question::defer_question(&request, &snapshot, &self.policy);
        }
        if reuse
            && let Some(cached) = &self.cached
            && cached.matches_inputs(&request, &snapshot, &self.policy)
        {
            return cached.clone();
        }
        let mut decision = assess_question(&request, &snapshot, &self.policy);
        #[cfg(test)]
        {
            self.computations += 1;
        }
        if question.negation_parity() {
            decision.reason = match decision.reason {
                Some(RejectionReason::KnownProof) => Some(RejectionReason::KnownRefutation),
                Some(RejectionReason::KnownRefutation) => Some(RejectionReason::KnownProof),
                other => other,
            };
        }
        self.cached = (!decision.inconclusive()).then(|| decision.clone());
        decision
    }

    fn assess(&mut self, graph: &Graph, question: &CompiledQuestion) -> PrefilterDecision {
        self.evaluate(graph, question, true)
    }

    fn exchange_record(&self, question: &CompiledQuestion) -> Option<Identity> {
        self.provenance(question.resolution_id())
            .filter(|entry| entry.question == *question)
            .map(|entry| entry.record)
    }

    pub(crate) fn available(&self) -> bool {
        if self.managed.is_some() {
            self.pending.len() < 2 * crate::resources::limits().interest_decisions
        } else {
            self.pending.is_empty()
        }
    }

    pub(crate) fn available_peer(&self) -> bool {
        if self.managed.is_some() {
            self.pending.values().filter(|p| p.peer).count()
                < crate::resources::limits().interest_decisions
        } else {
            self.available()
        }
    }
    pub(crate) fn available_local(&self) -> bool {
        if self.managed.is_some() {
            self.pending.values().filter(|p| !p.peer).count()
                < crate::resources::limits().interest_decisions
        } else {
            self.available()
        }
    }

    /// Reassess only owner-admitted unanswered work before calling a producer.
    /// Stored answers and current policy always precede mock candidate creation.
    pub(crate) fn generation_decision(
        &mut self,
        graph: &Graph,
        question: &CompiledQuestion,
    ) -> PrefilterDecision {
        let record = self.exchange_record(question);
        self.evaluate_record(graph, question, false, record)
    }

    pub(crate) fn begin_exchange(
        &mut self,
        graph: &Graph,
        derived: CompiledQuestion,
        deadline: Instant,
    ) -> (CompiledQuestion, oneshot::Receiver<QuestionAssessment>) {
        // Family equality is only a lookup. The original source, orientation,
        // record and delivered first-admission evidence remain unchanged.
        let question = self
            .provenance(derived.resolution_id())
            .filter(|entry| {
                entry.question.core() == derived.core()
                    && entry.question.canonical_core() == derived.canonical_core()
            })
            .map(|entry| entry.question.clone())
            .unwrap_or(derived);
        let (reply, receiver) = oneshot::channel();
        self.begin(
            graph,
            question.clone(),
            Reply::Exchange {
                reply,
                deadline,
                root: None,
                purpose: crate::jobs::Purpose::Publication,
            },
        );
        (question, receiver)
    }

    pub(crate) fn begin_peer_exchange(
        &mut self,
        graph: &Graph,
        derived: CompiledQuestion,
        root: naome_proof::ProofId,
        purpose: crate::jobs::Purpose,
        deadline: Instant,
    ) -> (CompiledQuestion, oneshot::Receiver<QuestionAssessment>) {
        let question = self
            .provenance(derived.resolution_id())
            .filter(|entry| {
                entry.question.core() == derived.core()
                    && entry.question.canonical_core() == derived.canonical_core()
            })
            .map(|entry| entry.question.clone())
            .unwrap_or(derived);
        let (reply, receiver) = oneshot::channel();
        self.begin(
            graph,
            question.clone(),
            Reply::Exchange {
                reply,
                deadline,
                root: Some(root),
                purpose,
            },
        );
        (question, receiver)
    }

    pub(crate) fn exchange_eligible(
        &self,
        question: &CompiledQuestion,
        assessment: &QuestionAssessment,
    ) -> bool {
        self.storage_error().is_none()
            && assessment.prefilter.passed()
            && self.selection.is_some()
            && assessment.selection == self.selection
            && assessment.interest == InterestAssessment::Assessed(true)
            && (assessment.novelty().is_some() || self.exchange_record(question).is_some())
    }

    pub(crate) fn prepare_exchange(
        &mut self,
        graph: &Graph,
        question: &CompiledQuestion,
        assessment: &QuestionAssessment,
    ) -> Result<QuestionDelta, String> {
        let record = self.exchange_record(question);
        let fresh = self.evaluate_record(graph, question, false, record);
        if !fresh.same_context(&assessment.prefilter)
            || !fresh.passed()
            || !self.exchange_eligible(question, assessment)
        {
            return Err("stale or declined final question assessment".into());
        }
        let mut registry = self.registry.clone();
        let mut inserted = None;
        if record.is_none() {
            if !self.registry_capacity(question) {
                return Err("question registry receiving capacity".into());
            }
            if fresh.novelty().is_none() {
                return Err("missing fresh node-local novelty".into());
            }
            let entry = RegisteredQuestion::new(*question.source_hash(), question.core())
                .map_err(|reason| format!("question registration: {reason:?}"))?;
            registry
                .insert(entry)
                .map_err(|reason| format!("question registration: {reason:?}"))?;
            inserted = Some(question.clone());
        }
        Ok(QuestionDelta {
            registry,
            question: inserted,
        })
    }

    /// One publication completion contract for local generation and peer intake.
    /// The durable outbox survives every cut between proof, registry and job ack.
    pub(crate) fn publish_exchange(
        &mut self,
        graph: &mut Graph,
        root: naome_proof::ProofId,
        batch: crate::graph::CheckedBatch,
        delta: QuestionDelta,
        peer: Option<crate::graph::PeerGrant>,
        deadline: Instant,
    ) -> Result<Vec<naome_proof::ProofId>, crate::Error> {
        if let (Some(persistence), Some(question)) = (&mut self.persistence, &delta.question)
            && let Err(error) = persistence.stage_publication(root, question)
        {
            if error.fatal() {
                self.storage_error = Some(error.to_string());
            }
            return Err(error);
        }
        let admitted = match graph.commit_batch_granted(root, batch, deadline, peer) {
            Ok(admitted) => admitted,
            Err(error) => {
                if !error.fatal() {
                    self.finish_publication(root)?;
                }
                return Err(error);
            }
        };
        self.apply_exchange(delta)
            .map_err(crate::Error::UncertainDurability)?;
        self.finish_publication(root)?;
        Ok(admitted)
    }

    fn finish_publication(&mut self, root: naome_proof::ProofId) -> Result<(), crate::Error> {
        if let Some(persistence) = &mut self.persistence
            && let Err(error) = persistence.finish_publication(root)
        {
            self.storage_error = Some(error.to_string());
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn apply_exchange(&mut self, delta: QuestionDelta) -> Result<(), String> {
        if let Some(question) = &delta.question
            && let Some(persistence) = &mut self.persistence
            && let Err(error) = persistence.retain(question, persistence::Kind::Exchange, None)
        {
            self.storage_error = Some(error.clone());
            return Err(error);
        }
        self.registry = delta.registry;
        if let Some(question) = delta.question {
            self.remember(question, false);
        }
        self.cached = None;
        Ok(())
    }

    pub(crate) fn recover_publications(&mut self, graph: &Graph) -> Result<(), String> {
        loop {
            let entries = match &self.persistence {
                Some(p) => p.publications()?,
                None => return Ok(()),
            };
            if entries.is_empty() {
                return Ok(());
            }
            for (root, question) in entries {
                if graph.contains(root)? {
                    let metadata = graph
                        .describe(root)?
                        .ok_or("publication root description missing")?;
                    let (_, _, recovered) = metadata.compile()?;
                    if recovered.canonical_core() != question.canonical_core()
                        || recovered.resolution_id() != question.resolution_id()
                    {
                        return Err("publication recovery target differs from checked graph".into());
                    }
                    let mut registry = self.registry.clone();
                    if !registry
                        .contains_record(question.source_hash())
                        .map_err(|e| e.to_string())?
                    {
                        registry
                            .insert(
                                RegisteredQuestion::new(*question.source_hash(), question.core())
                                    .map_err(|e| format!("publication recovery: {e:?}"))?,
                            )
                            .map_err(|e| format!("publication recovery: {e:?}"))?;
                    }
                    self.apply_exchange(QuestionDelta {
                        registry,
                        question: Some(question),
                    })?;
                }
                self.persistence
                    .as_mut()
                    .expect("persistent publication recovery")
                    .finish_publication(root)?;
            }
        }
    }

    fn begin(&mut self, graph: &Graph, question: CompiledQuestion, reply: Reply) {
        if reply.is_closed() {
            return;
        }
        let mut prefilter = if reply.exchange() {
            self.evaluate_record(graph, &question, false, self.exchange_record(&question))
        } else {
            self.assess(graph, &question)
        };
        let peer = matches!(reply, Reply::Exchange { root: Some(_), .. });
        let available = if self.managed.is_some() {
            self.pending.values().filter(|p| p.peer == peer).count()
                < crate::resources::limits().interest_decisions
        } else {
            self.pending.is_empty()
        };
        if prefilter.passed() && !available {
            prefilter = prefilter.reject(RejectionReason::ReceivingLimit, "Q08_RECEIVING_LIMIT");
        }
        if prefilter.passed() && reply.admission() && !self.registry_capacity(&question) {
            prefilter = prefilter.reject(RejectionReason::ReceivingLimit, "Q08_REGISTRY_CAPACITY");
        }
        let remaining = match &reply {
            Reply::Exchange { deadline, .. } => deadline
                .saturating_duration_since(Instant::now())
                .min(crate::resources::limits().interest_timeout),
            _ => crate::resources::limits().interest_timeout,
        };
        if !prefilter.passed()
            || self.selection.is_none()
            || self.provider.is_none() && self.managed.is_none()
            || self.managed.is_none() && remaining.is_zero()
            || self.storage_error.is_some()
        {
            reply.send(
                QuestionAssessment {
                    interest: if self.selection.is_none() && prefilter.passed() {
                        InterestAssessment::ProviderFailed
                    } else {
                        InterestAssessment::NotRun
                    },
                    prefilter,
                    submitted_negation_parity: question.negation_parity(),
                    selection: self.selection,
                    decision: None,
                },
                AdmissionOutcome::NotInserted,
            );
            return;
        }
        let future: Pin<Box<dyn Future<Output = ProviderResult> + Send>> = if let Some(client) =
            &self.managed
        {
            let (purpose, root) = match &reply {
                Reply::Assessment(_) => (crate::jobs::Purpose::Assessment, None),
                Reply::Admission(_) => (crate::jobs::Purpose::Admission, None),
                Reply::Exchange { purpose, root, .. } => {
                    (*purpose, root.map(|id| crate::hex(id.as_bytes())))
                }
            };
            let binding = crate::jobs::Binding::new(prefilter.snapshot, prefilter.policy)
                .with_selection(self.selection.expect("available selection epoch"));
            let request = crate::jobs::Input::Interest {
                question: question.source().to_owned(),
                assessment: crate::interest::Input::from_context(
                    self.interest_context
                        .as_ref()
                        .expect("managed selection context"),
                ),
                purpose,
                root,
            };
            let crate::jobs::Input::Interest { assessment, .. } = &request else {
                unreachable!()
            };
            let assessment = assessment.clone();
            let compiled = question.clone();
            let epoch = self.selection.expect("managed selection epoch");
            let ticket = client.submit(request, binding.clone());
            Box::pin(async move {
                let Ok(mut ticket) = ticket else {
                    return ProviderResult {
                        assessment: InterestAssessment::ProviderFailed,
                        job: None,
                        evidence: None,
                    };
                };
                match ticket.completed().await {
                    Ok(completion) => {
                        let mut evidence = None;
                        let interest = if completion.binding != binding {
                            InterestAssessment::Stale
                        } else if completion.state == crate::jobs::State::Expired {
                            InterestAssessment::TimedOut
                        } else {
                            match completion.result {
                                #[cfg(any(test, feature = "developer-tools"))]
                                Ok(crate::jobs::Output::Interest(value)) => {
                                    InterestAssessment::Assessed(value)
                                }
                                Ok(crate::jobs::Output::Decision(distribution)) => match assessment
                                    .assess(&assessment.request(&compiled), &distribution)
                                {
                                    Ok(selection) => {
                                        evidence = Some(assessment.evidence(
                                            &compiled,
                                            &epoch,
                                            distribution,
                                        ));
                                        match selection {
                                            crate::interest::Selection::Accept => {
                                                InterestAssessment::Assessed(true)
                                            }
                                            crate::interest::Selection::Reject => {
                                                InterestAssessment::Assessed(false)
                                            }
                                            crate::interest::Selection::Inconclusive => {
                                                InterestAssessment::Inconclusive
                                            }
                                        }
                                    }
                                    Err(_) => InterestAssessment::ProviderFailed,
                                },
                                _ => InterestAssessment::ProviderFailed,
                            }
                        };
                        ProviderResult {
                            assessment: interest,
                            job: (completion.id != 0).then_some(completion.id),
                            evidence,
                        }
                    }
                    Err(_) => ProviderResult {
                        assessment: InterestAssessment::ProviderFailed,
                        job: None,
                        evidence: None,
                    },
                }
            })
        } else {
            let provider = self.provider.as_ref().expect("configured interest").clone();
            let input = question.clone();
            // Cooperative embeddings retain their documented nonblocking
            // contract. Even construction happens only when this future runs.
            Box::pin(async move {
                let bounded = tokio::time::timeout(remaining, async move { provider(input).await });
                let assessment = match bounded.await {
                    Ok(Ok(yes)) => InterestAssessment::Assessed(yes),
                    Ok(Err(_)) => InterestAssessment::ProviderFailed,
                    Err(_) => InterestAssessment::TimedOut,
                };
                ProviderResult {
                    assessment,
                    job: None,
                    evidence: None,
                }
            })
        };
        let id = self.next_pending;
        let Some(next) = id.checked_add(1) else {
            self.storage_error = Some("question interest identity exhausted".into());
            return;
        };
        self.next_pending = next;
        self.pending.insert(
            id,
            Pending {
                question,
                prefilter,
                reply,
                future,
                job: None,
                peer,
                selection: self.selection,
                evidence: None,
            },
        );
    }

    pub(crate) fn process(&mut self, command: Command, graph: &Graph) -> bool {
        match command {
            Command::Assess(question, reply) => {
                self.begin(graph, question, Reply::Assessment(reply))
            }
            Command::Admit(question, reply) => self.begin(graph, question, Reply::Admission(reply)),
            Command::ImportBaseline(question, reply) => {
                if !reply.is_closed() {
                    let previous = self.registry.clone();
                    let outcome = if self.registry.contains(question.core()).unwrap_or(true) {
                        Err(RejectionReason::ExactDuplicate)
                    } else if !self.registry_capacity(&question) {
                        Err(RejectionReason::ReceivingLimit)
                    } else {
                        RegisteredQuestion::new(*question.source_hash(), question.core())
                            .and_then(|entry| self.registry.insert(entry))
                    };
                    let inserted = outcome.is_ok();
                    if reply.send(outcome).is_err() {
                        self.registry = previous;
                    } else if inserted {
                        if let Some(persistence) = &mut self.persistence
                            && let Err(error) =
                                persistence.retain(&question, persistence::Kind::Baseline, None)
                        {
                            self.storage_error = Some(error);
                        }
                        self.remember(question, false);
                    }
                }
            }
            Command::Policy(policy, reply) => {
                if !reply.is_closed() {
                    let previous = self.policy;
                    self.policy = policy;
                    if reply.send(()).is_err() {
                        self.policy = previous;
                    }
                }
            }
            Command::Context(reply) => {
                let _ = reply.send(LocalQuestionContext {
                    snapshot: self.snapshot(graph).identity(),
                    policy: self.policy.identity(),
                    checked_proofs: graph.accepted_count(),
                    registered_questions: self.registry.len(),
                });
            }
            Command::Stop(reply) => {
                if !reply.is_closed() {
                    self.pending.clear();
                    let _ = reply.send(());
                    return false;
                }
            }
        }
        true
    }

    pub(crate) async fn completed(&mut self) -> InterestAssessment {
        if self.pending.is_empty() {
            return std::future::pending().await;
        }
        let (id, result) =
            libp2p::futures::future::select_all(self.pending.iter_mut().map(|(id, pending)| {
                Box::pin(async move { (*id, pending.future.as_mut().await) })
            }))
            .await
            .0;
        if let Some(pending) = self.pending.get_mut(&id) {
            pending.job = result.job;
            pending.evidence = result.evidence;
        }
        self.finished = Some(id);
        result.assessment
    }

    pub(crate) fn finish(&mut self, graph: &Graph, interest: InterestAssessment) {
        let Some(id) = self
            .finished
            .take()
            .or_else(|| self.pending.keys().next().copied())
        else {
            return;
        };
        let Some(pending) = self.pending.remove(&id) else {
            return;
        };
        if pending.reply.is_closed() {
            if let (Some(client), Some(job)) = (&self.managed, pending.job)
                && let Err(error) = client.acknowledge(job)
            {
                self.storage_error = Some(error);
            }
            return;
        }
        // Admission always computes again; a cached or caller-manufactured Pass
        // cannot authorize a write. Nothing below awaits or relinquishes ownership.
        let mut prefilter = if pending.reply.exchange() {
            self.evaluate_record(
                graph,
                &pending.question,
                false,
                self.exchange_record(&pending.question),
            )
        } else {
            self.evaluate(graph, &pending.question, !pending.reply.admission())
        };
        let interest = if pending.selection != self.selection || self.selection.is_none() {
            InterestAssessment::Stale
        } else if pending.prefilter.same_context(&prefilter) {
            interest
        } else {
            prefilter = prefilter.reject(RejectionReason::StaleContext, "Q09_STALE_CONTEXT");
            InterestAssessment::Stale
        };
        let mut previous_registry = None;
        let mut outcome = AdmissionOutcome::NotInserted;
        let mut provenance = None;
        let mut prepared = false;
        if pending.reply.admission()
            && prefilter.passed()
            && interest == InterestAssessment::Assessed(true)
            && let Some(novelty) = prefilter.novelty().cloned()
        {
            let previous = self.registry.clone();
            let registry_before = previous.identity();
            let record = *pending.question.source_hash();
            let inserted = RegisteredQuestion::new(record, pending.question.core())
                .and_then(|entry| self.registry.insert(entry));
            match inserted {
                Ok(()) => {
                    let receipt = AdmissionReceipt {
                        record,
                        snapshot_after: self.snapshot(graph).identity(),
                        registry_before,
                        registry_after: self.registry.identity(),
                        novelty,
                        selection: pending.selection.expect("positive current selection"),
                        interest_job: pending.job,
                    };
                    if let Some(persistence) = &mut self.persistence {
                        if let Err(error) = persistence.retain(
                            &pending.question,
                            persistence::Kind::Prepared,
                            Some(&receipt),
                        ) {
                            self.registry = previous;
                            self.storage_error = Some(error);
                            return;
                        }
                        prepared = true;
                    }
                    provenance = Some(AdmittedProvenance {
                        question: pending.question.clone(),
                        record: receipt.record(),
                    });
                    outcome = AdmissionOutcome::Admitted(Box::new(receipt));
                    previous_registry = Some(previous);
                    self.cached = None;
                }
                Err(reason) => {
                    prefilter = prefilter.reject(reason, "Q02_REGISTRY_INSERTION");
                }
            }
        }
        let delivered = pending.reply.send(
            QuestionAssessment {
                prefilter,
                interest,
                submitted_negation_parity: pending.question.negation_parity(),
                selection: pending.selection,
                decision: pending.evidence,
            },
            outcome,
        );
        // Failed delivery rolls back within this serialized operation. A delivered
        // receipt linearizes the effect; later client disappearance cannot undo it.
        if !delivered && let Some(previous) = previous_registry {
            self.registry = previous;
        }
        if prepared
            && let Some(persistence) = &mut self.persistence
            && let Err(error) = persistence.delivered(&pending.question, delivered)
        {
            self.storage_error = Some(error);
            return;
        }
        if delivered && let Some(provenance) = provenance {
            self.remember(provenance.question, true);
        }
        if let (Some(client), Some(job)) = (&self.managed, pending.job)
            && let Err(error) = client.acknowledge(job)
        {
            self.storage_error = Some(error);
        }
    }

    pub(crate) fn cancel_closed(&mut self) {
        self.pending.retain(|_, pending| !pending.reply.is_closed());
    }
}
