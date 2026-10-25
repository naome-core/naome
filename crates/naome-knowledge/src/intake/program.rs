//! Receiver-owned selection, transfer and independent incremental checking.
//! Persistent input remains untrusted until a fresh Checker result is committed
//! through the existing Graph/Question publication boundary.
use super::*;
mod dependencies;
mod helpers;
#[cfg(test)]
mod tests;
use crate::{
    graph::program::{PreparedProgram, ProgramAdmission, ProgramBudget, ProgramCheck},
    object::ProgramMetadata,
    proof_work::CheckedWork,
};
pub(super) use helpers::Helpers;
use naome_proof::program::{CHUNK_RECORDS, Chunk};

type ProgramRequest = (PeerId, ProofId, ProofId, u64, usize);

fn transfer_records() -> usize {
    // The wire format already bounds each chunk by CHUNK_RECORDS and
    // CHUNK_BYTES. CPU batches govern checking, not transport fragmentation;
    // still stop issuing new chunks while computation is paused.
    if crate::resources::adaptive::batch(1) == 0 {
        0
    } else {
        CHUNK_RECORDS
    }
}

#[derive(Default)]
pub(super) struct Programs {
    queue: VecDeque<Offer>,
    active: Option<Root>,
    declined: BTreeMap<ProofId, Instant>,
}
struct Offer {
    peer: PeerId,
    metadata: ProgramMetadata,
    grant: Option<crate::publication::PeerGrant>,
}
struct Root {
    offer: Offer,
    authority: QuestionAuthority,
    stage: Stage,
    described: Instant,
    refresh: bool,
    allowed: bool,
    budget: ProgramBudget,
    helpers: Helpers,
    scanned: u64,
    input_complete: bool,
}
struct QuestionAuthority {
    question: CompiledQuestion,
    assessment: Option<QuestionAssessment>,
    pending: Option<oneshot::Receiver<QuestionAssessment>>,
    until: Instant,
    finalized: bool,
    pending_final: bool,
}
enum Stage {
    Start,
    Fetch,
    Check(Box<ProgramCheck>),
    Prepare(Box<PreparedProgram>),
}
impl QuestionAuthority {
    fn refresh<F, Fut>(
        &mut self,
        id: ProofId,
        graph: &Graph,
        questions: &mut LocalQuestions<F>,
        final_stage: bool,
    ) -> Result<bool, crate::Error>
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        let authority = self;
        let context = questions.formal_context(graph);
        if authority
            .assessment
            .as_ref()
            .is_none_or(|assessment| !questions.exchange_eligible(&authority.question, assessment))
            || Instant::now() >= authority.until
            || (final_stage && !authority.finalized)
        {
            authority.assessment = None;
            if authority.pending.is_none() && questions.available() {
                let deadline = if questions.uses_jobs() {
                    questions.interest_deadline(Instant::now())
                } else {
                    Instant::now() + crate::resources::limits().root_timeout
                };
                let purpose = if final_stage {
                    crate::jobs::Purpose::Final
                } else {
                    crate::jobs::Purpose::Initial
                };
                let (selected, reply) = questions.begin_peer_exchange(
                    graph,
                    authority.question.clone(),
                    id,
                    purpose,
                    deadline,
                );
                authority.question = selected;
                authority.pending_final = final_stage;
                authority.pending = Some(reply);
            }
        }
        if let Some(reply) = &mut authority.pending {
            match reply.try_recv() {
                Ok(assessment) => {
                    authority.pending = None;
                    authority.assessment = Some(questions.refresh_exchange(
                        graph,
                        &authority.question,
                        &assessment,
                    )?);
                    authority.until = Instant::now() + crate::resources::limits().root_timeout;
                    authority.finalized = authority.pending_final;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(_) => return Err("program interest assessment cancelled".into()),
            }
        }
        if let Some(assessment) = &authority.assessment
            && assessment.formal_context() != context
        {
            authority.assessment =
                Some(questions.refresh_exchange(graph, &authority.question, assessment)?);
        }
        Ok(authority.assessment.is_some())
    }
}

impl Programs {
    pub(super) fn remove(&mut self, id: ProofId) {
        self.queue
            .retain(|offer| offer.metadata.manifest.proof_id() != id);
        if self
            .active
            .as_ref()
            .is_some_and(|root| root.offer.metadata.manifest.proof_id() == id)
        {
            self.active = None;
        }
    }
    pub(super) fn invalidate_interest(&mut self) {
        self.declined.clear();
    }
    pub(super) fn queued(&self) -> usize {
        self.queue.len() + usize::from(self.active.is_some())
    }
    pub(super) fn contains(&self, id: ProofId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|root| root.offer.metadata.manifest.proof_id() == id)
            || self
                .queue
                .iter()
                .any(|offer| offer.metadata.manifest.proof_id() == id)
    }
    pub(super) fn selection_boundary_ready(&self) -> bool {
        self.active.as_ref().is_some_and(|root| {
            root.authority
                .pending
                .as_ref()
                .is_some_and(|reply| !reply.is_empty())
        })
    }
    fn busy(&self) -> bool {
        self.active.as_ref().is_some_and(|root| {
            root.allowed
                && (matches!(root.stage, Stage::Check(_) | Stage::Prepare(_))
                    || root.input_complete && root.scanned < root.offer.metadata.manifest.commands
                    || root.helpers.busy())
        })
    }
    fn enqueue(
        &mut self,
        peer: PeerId,
        metadata: ProgramMetadata,
        graph: &Graph,
        grant: Option<crate::publication::PeerGrant>,
    ) -> Result<&'static str, crate::Error> {
        let id = metadata.manifest.proof_id();
        if graph.contains(id)? {
            return Ok("duplicate");
        }
        if let Some(root) = &mut self.active
            && root.offer.metadata.manifest.proof_id() == id
        {
            if root.offer.metadata.manifest != metadata.manifest {
                return Err("program manifest changed during transfer".into());
            }
            root.offer.peer = peer;
            root.offer.grant = grant;
            root.described = Instant::now();
            root.refresh = false;
            return Ok("metadata_refreshed");
        }
        if self
            .declined
            .get(&id)
            .is_some_and(|until| *until > Instant::now())
        {
            return Ok("declined");
        }
        if metadata.question()?.is_none() {
            return Ok("unselected");
        }
        if self
            .queue
            .iter()
            .any(|offer| offer.metadata.manifest.proof_id() == id)
        {
            return Ok("queued_duplicate");
        }
        self.queue.push_back(Offer {
            peer,
            metadata,
            grant,
        });
        Ok("queued")
    }
    fn request(&self, graph: &Graph) -> Result<Option<ProgramRequest>, crate::Error> {
        let Some(root) = &self.active else {
            return Ok(None);
        };
        if !root.allowed
            || root.refresh
            || !matches!(root.stage, Stage::Fetch)
            || root
                .offer
                .grant
                .as_ref()
                .is_some_and(|grant| grant.check().is_err())
            || Instant::now().duration_since(root.described)
                >= crate::resources::limits().root_timeout
        {
            return Ok(None);
        }
        let id = root.offer.metadata.manifest.proof_id();
        if let Some((helper, start, records)) = root.helpers.request(graph)? {
            return Ok(Some((root.offer.peer, id, helper, start, records)));
        }
        let progress = graph
            .ownership()
            .program_progress(&root.offer.metadata.manifest)?;
        if progress.commands == root.offer.metadata.manifest.commands {
            return Ok(None);
        }
        let records = transfer_records();
        Ok((records > 0).then_some((root.offer.peer, id, id, progress.commands, records)))
    }
    fn refresh_needed(&self) -> Vec<(PeerId, ProofId)> {
        self.active
            .as_ref()
            .filter(|root| {
                root.refresh
                    || root
                        .offer
                        .grant
                        .as_ref()
                        .is_some_and(|grant| grant.check().is_err())
                    || Instant::now().duration_since(root.described)
                        >= crate::resources::limits().root_timeout / 2
            })
            .map(|root| vec![(root.offer.peer, root.offer.metadata.manifest.proof_id())])
            .unwrap_or_default()
    }
    fn payload(
        &mut self,
        peer: PeerId,
        id: ProofId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        let root = self.active.as_mut().ok_or("unrequested program payload")?;
        if root.offer.peer != peer
            || root.offer.metadata.manifest.proof_id() != id
            || !root.allowed
            || root.refresh
            || !matches!(root.stage, Stage::Fetch)
            || root
                .offer
                .grant
                .as_ref()
                .is_some_and(|grant| grant.check().is_err())
        {
            return Err("unrequested program payload".into());
        }
        let progress = graph
            .ownership()
            .append_program(&root.offer.metadata.manifest, &chunk)?;
        root.input_complete = progress.commands == root.offer.metadata.manifest.commands;
        Ok(())
    }
    pub(super) fn failed(&mut self, peer: PeerId, id: Option<ProofId>) {
        if let Some(root) = &mut self.active
            && root.offer.peer == peer
            && id.is_none_or(|id| {
                root.offer.metadata.manifest.proof_id() == id
                    || root.helpers.contains(id)
                    || root.helpers.needs(id)
            })
        {
            root.refresh = true;
        }
        self.queue.retain(|offer| {
            offer.peer != peer || id.is_some_and(|id| offer.metadata.manifest.proof_id() != id)
        });
    }
    pub(super) fn advance<F, Fut>(
        &mut self,
        graph: &mut Graph,
        questions: &mut LocalQuestions<F>,
    ) -> Progress
    where
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
    {
        self.declined.retain(|_, until| *until > Instant::now());
        if self.active.is_none()
            && let Some(offer) = self.queue.pop_front()
        {
            let id = offer.metadata.manifest.proof_id();
            let authority = (|| -> Result<QuestionAuthority, crate::Error> {
                let question = offer
                    .metadata
                    .question()?
                    .ok_or("program has no supported interest question")?;
                Ok(QuestionAuthority {
                    question,
                    assessment: None,
                    pending: None,
                    until: Instant::now(),
                    finalized: false,
                    pending_final: false,
                })
            })();
            match authority {
                Ok(authority) => {
                    self.active = Some(Root {
                        offer,
                        authority,
                        stage: Stage::Start,
                        described: Instant::now(),
                        refresh: false,
                        allowed: false,
                        budget: ProgramBudget::default(),
                        helpers: Helpers::default(),
                        scanned: 0,
                        input_complete: false,
                    })
                }
                Err(error) => return Progress::Skipped(id, error.to_string()),
            }
        }
        let Some(mut root) = self.active.take() else {
            return Progress::Waiting;
        };
        let id = root.offer.metadata.manifest.proof_id();
        let result = (|| -> Result<Option<Vec<ProofId>>, crate::Error> {
            if graph.contains(id)? {
                return Ok(Some(Vec::new()));
            }
            root.allowed = root.authority.refresh(
                id,
                graph,
                questions,
                matches!(&root.stage, Stage::Prepare(prepared) if prepared.ready()),
            )?;
            if !root.allowed {
                return Ok(None);
            }
            let snapshot = root.budget.refresh(graph.ownership().directory())?.clone();
            let cache = root.helpers.cache_share(snapshot.budget.cache_bytes)?;
            match &mut root.stage {
                Stage::Check(check) => check.restrict_cache(cache)?,
                Stage::Prepare(prepared) => prepared.restrict_cache(cache)?,
                Stage::Start | Stage::Fetch => {}
            }
            if snapshot.budget.paused.is_some()
                && !matches!(&root.stage, Stage::Prepare(prepared) if prepared.ready())
            {
                return Ok(None);
            }
            if let Stage::Prepare(prepared) = &mut root.stage
                && !prepared.current(graph)?
            {
                prepared.invalidate();
                root.helpers.invalidate_prefix();
            }
            root.helpers.advance(graph)?;
            if root.helpers.member_count() + 1 > crate::resources::limits().closure_objects {
                return Err(crate::Error::InputLimit(
                    "program closure dependency capacity",
                ));
            }
            if !root.helpers.ready() && !matches!(root.stage, Stage::Start | Stage::Fetch) {
                return Ok(None);
            }
            match &mut root.stage {
                Stage::Start => {
                    let progress = graph
                        .ownership()
                        .start_program(&root.offer.metadata.manifest)?;
                    root.input_complete =
                        progress.commands == root.offer.metadata.manifest.commands;
                    root.stage = Stage::Fetch;
                }
                Stage::Fetch => {
                    if root.input_complete {
                        let (complete, _) = root.helpers.scan_dependencies(
                            &root.offer.metadata.manifest,
                            &mut root.scanned,
                            graph,
                        )?;
                        if root.helpers.member_count() + 1
                            > crate::resources::limits().closure_objects
                        {
                            return Err(crate::Error::InputLimit(
                                "program closure dependency capacity",
                            ));
                        }
                        if !complete || !root.helpers.ready() {
                            return Ok(None);
                        }
                        root.stage = Stage::Check(Box::new(ProgramCheck::open(
                            graph,
                            root.offer.metadata.manifest.clone(),
                        )?));
                    }
                }
                Stage::Check(check) => {
                    if let Some(proof) = check.advance(graph, root.helpers.context(graph))? {
                        root.authority
                            .question
                            .classify_checked_program(proof.proof()?)
                            .map_err(crate::Error::from)?;
                        root.stage = Stage::Prepare(Box::new(PreparedProgram::new(proof)));
                    }
                }
                Stage::Prepare(prepared) => {
                    let was_ready = prepared.ready();
                    let prefix = if prepared.pending() {
                        root.helpers.take_prefix()
                    } else {
                        None
                    };
                    let complete = match prepared.advance_after(
                        graph,
                        snapshot.budget.batch_steps.max(1),
                        prefix,
                    ) {
                        Ok(complete) => complete,
                        Err(error) => {
                            prepared.invalidate();
                            root.helpers.invalidate_prefix();
                            return Err(error);
                        }
                    };
                    if prepared.pending() {
                        root.helpers.invalidate_prefix();
                    }
                    if !complete || !was_ready {
                        return Ok(None);
                    }
                    if root.refresh
                        || Instant::now().duration_since(root.described)
                            >= crate::resources::limits().root_timeout
                        || root
                            .offer
                            .grant
                            .as_ref()
                            .is_some_and(|grant| grant.check().is_err())
                    {
                        return Ok(None);
                    }
                    let batch = prepared.take_batch().ok_or("program batch absent")?;
                    // The transferred batch owns the prefix. If preparation or
                    // publication defers, rebuild it from the checked helpers.
                    root.helpers.invalidate_prefix();
                    let deadline = Instant::now() + crate::resources::limits().root_timeout;
                    let assessment = root
                        .authority
                        .assessment
                        .as_ref()
                        .ok_or("program final interest missing")?;
                    let delta =
                        questions.prepare_exchange(graph, &root.authority.question, assessment)?;
                    let admitted = questions.publish_exchange(
                        graph,
                        id,
                        batch,
                        delta,
                        root.offer.grant.clone(),
                        deadline,
                    )?;
                    return Ok(Some(admitted));
                }
            }
            Ok(None)
        })();
        match result {
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
                if self.declined.len() < crate::resources::limits().fetches {
                    self.declined.insert(
                        id,
                        Instant::now() + crate::resources::limits().pending_retry,
                    );
                }
                Progress::Skipped(id, error.to_string())
            }
        }
    }
}

impl Intake {
    pub(crate) fn enqueue_program(
        &mut self,
        peer: PeerId,
        metadata: ProgramMetadata,
        graph: &Graph,
        grant: Option<crate::publication::PeerGrant>,
    ) -> Result<&'static str, crate::Error> {
        if self.programs.helper_contains(metadata.manifest.proof_id())
            || self
                .active
                .as_ref()
                .is_some_and(|root| root.helpers.contains(metadata.manifest.proof_id()))
        {
            return Ok("cited_program_pending");
        }
        if self.description_capacity() == 0 && !self.programs.contains(metadata.manifest.proof_id())
        {
            return Err("program description queue capacity".into());
        }
        self.programs.enqueue(peer, metadata, graph, grant)
    }
    pub(crate) fn program_request(
        &self,
        graph: &Graph,
    ) -> Result<Option<ProgramRequest>, crate::Error> {
        if let Some(root) = &self.active
            && !root.helpers.is_empty()
            && root
                .description
                .grant
                .as_ref()
                .is_none_or(|grant| grant.check().is_ok())
            && Instant::now().duration_since(root.description.created)
                < crate::resources::limits().root_timeout
            && let Some((id, start, records)) = root.helpers.request(graph)?
        {
            return Ok(Some((
                root.description.peer,
                root.description.id,
                id,
                start,
                records,
            )));
        }
        self.programs.request(graph)
    }
    pub(crate) fn program_payload(
        &mut self,
        peer: PeerId,
        root_id: ProofId,
        id: ProofId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if self.programs.authorizes(peer, root_id, id) {
            return self
                .programs
                .helper_payload(peer, root_id, id, chunk, graph);
        }
        if root_id != id {
            if !self.authorizes(peer, root_id, id) {
                return Err("unrequested cited program payload".into());
            }
            let root = self.active.as_mut().ok_or("cited program parent missing")?;
            if let Some(grant) = &root.description.grant {
                grant.check()?;
            }
            return root.helpers.payload(id, chunk, graph);
        }
        self.programs.payload(peer, id, chunk, graph)
    }
    pub(crate) fn program_failed(&mut self, peer: PeerId, id: ProofId) {
        self.programs.failed(peer, Some(id));
    }
    pub(crate) fn program_refresh_needed(&self) -> Vec<(PeerId, ProofId)> {
        self.programs.refresh_needed()
    }
    pub(crate) fn program_busy(&self) -> bool {
        self.programs.busy() || self.active.as_ref().is_some_and(|root| root.helpers.busy())
    }
}
