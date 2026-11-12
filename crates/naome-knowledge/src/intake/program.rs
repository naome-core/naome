//! Receiver-owned selection, transfer and independent incremental checking.
//! Persistent input remains untrusted until a fresh Checker result is committed
//! through the existing Graph/Question publication boundary.
use super::*;
mod dependencies;
#[cfg(test)]
mod tests;
#[cfg(test)]
use crate::proof_work::CheckedWork;
use crate::{
    graph::program::{PreparedProgram, ProgramCheck},
    object::ProgramMetadata,
    resources::adaptive::Observer,
};
use naome_proof::program::{CHUNK_RECORDS, Chunk};

type ProgramRequest = (PeerId, ArtifactId, ArtifactId, u64, usize);

pub(super) fn transfer_records() -> usize {
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
    declined: BTreeMap<ArtifactId, Instant>,
}
struct Offer {
    metadata: ProgramMetadata,
    transfer: TransferGrant,
    prefix: Option<CheckedBatch>,
}
struct Root {
    offer: Offer,
    authority: Selection,
    stage: Stage,
    refresh: bool,
    allowed: bool,
    budget: Observer,
    closure: Closure,
    scanned: u64,
    input_complete: bool,
}
enum Stage {
    Start,
    Fetch,
    Check(Box<ProgramCheck>),
    Prepare(Box<PreparedProgram>),
}
impl Root {
    fn fetching(&self) -> bool {
        self.allowed && !self.refresh && matches!(self.stage, Stage::Fetch)
    }
}

impl Programs {
    pub(super) fn remove(&mut self, id: ArtifactId) {
        self.queue
            .retain(|offer| offer.metadata.manifest.artifact_id() != id);
        if self
            .active
            .as_ref()
            .is_some_and(|root| root.offer.metadata.manifest.artifact_id() == id)
        {
            self.active = None;
        }
    }
    pub(super) fn invalidate_selection(&mut self) {
        self.declined.clear();
    }
    pub(super) fn queued(&self) -> usize {
        self.queue.len() + usize::from(self.active.is_some())
    }
    pub(super) fn contains(&self, id: ArtifactId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|root| root.offer.metadata.manifest.artifact_id() == id)
            || self
                .queue
                .iter()
                .any(|offer| offer.metadata.manifest.artifact_id() == id)
    }
    fn busy(&self) -> bool {
        self.active.as_ref().is_some_and(|root| {
            root.allowed
                && (matches!(root.stage, Stage::Check(_) | Stage::Prepare(_))
                    || root.input_complete && root.scanned < root.offer.metadata.manifest.commands
                    || root.closure.busy())
        })
    }
    pub(super) fn preparing_admission(&self) -> bool {
        self.active.as_ref().is_some_and(|root| {
            root.allowed
                && !root.refresh
                && root.offer.transfer.live(Instant::now())
                && matches!(&root.stage, Stage::Prepare(prepared) if !prepared.pending())
        })
    }
    pub(super) fn enqueue(
        &mut self,
        peer: PeerId,
        metadata: ProgramMetadata,
        graph: &Graph,
        grant: Option<crate::publication::PeerGrant>,
        prefix: Option<CheckedBatch>,
    ) -> Result<OfferStatus, crate::Error> {
        let id = metadata.manifest.artifact_id();
        if graph.contains(id)? {
            return Ok(OfferStatus::Duplicate);
        }
        if let Some(root) = &mut self.active
            && root.offer.metadata.manifest.artifact_id() == id
        {
            if root.offer.metadata.manifest != metadata.manifest {
                return Err(crate::InputFault::IntakeManifestChanged.into());
            }
            root.offer.transfer = TransferGrant::new(peer, id, grant);
            root.refresh = false;
            return Ok(OfferStatus::MetadataRefreshed);
        }
        if self
            .declined
            .get(&id)
            .is_some_and(|until| *until > Instant::now())
        {
            return Ok(OfferStatus::Declined);
        }
        let context = prefix
            .as_ref()
            .map_or(graph.checked_context(), CheckedBatch::context);
        if metadata.question(context)?.is_none() {
            return Ok(OfferStatus::Unselected);
        }
        if self
            .queue
            .iter()
            .any(|offer| offer.metadata.manifest.artifact_id() == id)
        {
            return Ok(OfferStatus::QueuedDuplicate);
        }
        self.queue.push_back(Offer {
            metadata,
            transfer: TransferGrant::new(peer, id, grant),
            prefix,
        });
        Ok(OfferStatus::Queued)
    }

    pub(in crate::intake) fn take_prefix(&mut self, root: ArtifactId) -> Option<CheckedBatch> {
        self.active
            .as_mut()
            .filter(|active| active.offer.transfer.root() == root)
            .and_then(|active| active.closure.take_prefix())
    }

    pub(in crate::intake) fn restore_prefix(
        &mut self,
        root: ArtifactId,
        prefix: CheckedBatch,
    ) -> Result<(), crate::Error> {
        let active = self
            .active
            .as_mut()
            .filter(|active| active.offer.transfer.root() == root)
            .ok_or(crate::InputFault::IntakeSelectionQuestionMissing)?;
        active.closure.restore_prefix(prefix);
        Ok(())
    }

    pub(in crate::intake) fn invalidate_prefix(&mut self, root: ArtifactId) {
        if let Some(active) = self
            .active
            .as_mut()
            .filter(|active| active.offer.transfer.root() == root)
        {
            active.closure.invalidate_prefix();
        }
    }
    fn request(&self, graph: &Graph) -> Result<Option<ProgramRequest>, crate::Error> {
        let Some(root) = &self.active else {
            return Ok(None);
        };
        if !root.fetching() || !root.offer.transfer.live(Instant::now()) {
            return Ok(None);
        }
        let id = root.offer.metadata.manifest.artifact_id();
        if let Some((helper, start, records)) = root.closure.request(graph)? {
            return Ok(Some((
                root.offer.transfer.peer(),
                id,
                helper,
                start,
                records,
            )));
        }
        let progress = graph
            .ownership()
            .program_progress(&root.offer.metadata.manifest)?;
        if progress.commands == root.offer.metadata.manifest.commands {
            return Ok(None);
        }
        let records = transfer_records();
        Ok((records > 0).then_some((
            root.offer.transfer.peer(),
            id,
            id,
            progress.commands,
            records,
        )))
    }
    fn refresh_needed(&self) -> Vec<(PeerId, ArtifactId)> {
        self.active
            .as_ref()
            .filter(|root| root.refresh || root.offer.transfer.refresh_due(Instant::now()))
            .map(|root| {
                vec![(
                    root.offer.transfer.peer(),
                    root.offer.metadata.manifest.artifact_id(),
                )]
            })
            .unwrap_or_default()
    }
    fn payload(
        &mut self,
        peer: PeerId,
        id: ArtifactId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        let root = self
            .active
            .as_mut()
            .ok_or(crate::InputFault::IntakeProgramUnrequested)?;
        if !root.fetching() {
            return Err(crate::InputFault::IntakeProgramUnrequested.into());
        }
        root.offer.transfer.authorize(peer, id, Instant::now())?;
        let progress = graph
            .ownership()
            .append_program(&root.offer.metadata.manifest, &chunk)?;
        root.input_complete = progress.commands == root.offer.metadata.manifest.commands;
        Ok(())
    }
    pub(super) fn failed(&mut self, peer: PeerId, id: Option<ArtifactId>) {
        if let Some(root) = &mut self.active
            && root.offer.transfer.peer() == peer
            && id.is_none_or(|id| {
                root.offer.metadata.manifest.artifact_id() == id
                    || root.closure.contains(id)
                    || root.closure.needs(id)
            })
        {
            root.refresh = true;
        }
        self.queue.retain(|offer| {
            offer.transfer.peer() != peer
                || id.is_some_and(|id| offer.metadata.manifest.artifact_id() != id)
        });
    }
    pub(in crate::intake) fn helper_definition_request(
        &mut self,
        graph: &Graph,
    ) -> Option<DefinitionRequest> {
        let root = self.active.as_mut().filter(|root| root.fetching())?;
        DefinitionRequest::for_helper(graph, &root.offer.transfer, &mut root.closure)
    }

    pub(super) fn advance<F, Fut>(
        &mut self,
        graph: &mut Graph,
        questions: &mut LocalQuestions<F>,
        metadata_waiter: Option<ArtifactId>,
    ) -> Progress
    where
        F: Fn(ResearchQuestion) -> Fut + Send + Sync + 'static,
        Fut:
            Future<Output = Result<bool, crate::question::SelectionProviderError>> + Send + 'static,
    {
        self.declined.retain(|_, until| *until > Instant::now());
        if self.active.is_none()
            && let Some(offer) = self.queue.pop_front()
        {
            let id = offer.metadata.manifest.artifact_id();
            if !offer.transfer.live(Instant::now()) {
                return Progress::Skipped(id, crate::InputFault::IntakeQueuedProgramExpired.into());
            }
            let authority = (|| -> Result<Selection, crate::Error> {
                let context = offer
                    .prefix
                    .as_ref()
                    .map_or(graph.checked_context(), CheckedBatch::context);
                let question = offer
                    .metadata
                    .question(context)?
                    .ok_or(crate::InputFault::IntakeSelectionQuestionMissing)?;
                Ok(Selection::new(id, question))
            })();
            match authority {
                Ok(authority) => {
                    let mut offer = offer;
                    let mut closure = Closure::new(id, None);
                    if let Some(prefix) = offer.prefix.take()
                        && let Err(error) = closure.adopt_prefix(graph, prefix)
                    {
                        return Progress::Skipped(id, error);
                    }
                    self.active = Some(Root {
                        offer,
                        authority,
                        stage: Stage::Start,
                        refresh: false,
                        allowed: false,
                        budget: Observer::default(),
                        closure,
                        scanned: 0,
                        input_complete: false,
                    })
                }
                Err(error) => return Progress::Skipped(id, error),
            }
        }
        if metadata_waiter.is_some_and(|waiting| {
            self.active
                .as_ref()
                .is_some_and(|root| root.offer.transfer.root() == waiting)
        }) {
            return Progress::Waiting;
        }
        let Some(mut root) = self.active.take() else {
            return Progress::Waiting;
        };
        let id = root.offer.metadata.manifest.artifact_id();
        let result = (|| -> Result<Option<Vec<ArtifactId>>, crate::Error> {
            if graph.contains(id)? {
                return Ok(Some(Vec::new()));
            }
            let selection_stage = if matches!(&root.stage, Stage::Prepare(prepared) if prepared.ready())
            {
                SelectionStage::Final
            } else {
                SelectionStage::Initial
            };
            root.allowed = root.authority.renew(
                selection_stage,
                graph,
                questions,
                root.closure.context(graph),
            )?;
            if !root.allowed {
                return Ok(None);
            }
            if root.closure.synchronize(graph)? && matches!(root.stage, Stage::Check(_)) {
                // A partial check borrowed the former private predecessor.
                // Replay its durable untrusted input against the rebuilt closure.
                root.stage = Stage::Fetch;
            }
            let snapshot = root.budget.refresh(graph.ownership().directory())?.clone();
            let cache = root.closure.working_cache(snapshot.budget.cache_bytes)?;
            match &mut root.stage {
                Stage::Check(check) => {
                    if root.closure.ready() {
                        check.restrict_cache(cache)?;
                    } else {
                        check.suspend_cache()?;
                    }
                }
                Stage::Prepare(prepared) => {
                    if root.closure.ready() {
                        prepared.restrict_cache(cache)?;
                    } else {
                        prepared.suspend_cache()?;
                    }
                }
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
                root.closure.invalidate_prefix();
            }
            root.closure.advance(graph)?;
            if root.closure.member_count() > crate::resources::limits().closure_objects {
                return Err(crate::Error::InputLimit(
                    crate::InputLimit::ProgramClosureDependencyCapacity,
                ));
            }
            if !root.closure.ready() && !matches!(root.stage, Stage::Start | Stage::Fetch) {
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
                        let (complete, _) = root.closure.scan_dependencies(
                            &root.offer.metadata.manifest,
                            &mut root.scanned,
                            graph,
                        )?;
                        if root.closure.member_count() > crate::resources::limits().closure_objects
                        {
                            return Err(crate::Error::InputLimit(
                                crate::InputLimit::ProgramClosureDependencyCapacity,
                            ));
                        }
                        if !complete || !root.closure.ready() {
                            return Ok(None);
                        }
                        root.stage = Stage::Check(Box::new(ProgramCheck::open(
                            graph,
                            root.offer.metadata.manifest.clone(),
                        )?));
                    }
                }
                Stage::Check(check) => {
                    if let Some(proof) = check.advance(graph, root.closure.context(graph))? {
                        root.authority
                            .question()
                            .classify_checked_program(proof.proof()?)
                            .map_err(crate::Error::from)?;
                        root.stage = Stage::Prepare(Box::new(PreparedProgram::new(proof)));
                    }
                }
                Stage::Prepare(prepared) => {
                    let was_ready = prepared.ready();
                    let prefix = if prepared.pending() {
                        root.closure.take_prefix()
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
                            root.closure.invalidate_prefix();
                            return Err(error);
                        }
                    };
                    if prepared.pending() {
                        root.closure.invalidate_prefix();
                    }
                    if !complete || !was_ready {
                        return Ok(None);
                    }
                    if root.refresh || !root.offer.transfer.live(Instant::now()) {
                        return Ok(None);
                    }
                    let mut batch = prepared
                        .take_batch()
                        .ok_or(crate::InputFault::IntakeBatchMissing)?;
                    root.closure.attach_questions(graph, &mut batch)?;
                    // The transferred batch owns the prefix. If preparation or
                    // publication defers, rebuild it from the checked helpers.
                    root.closure.invalidate_prefix();
                    let admitted =
                        root.authority
                            .publish(graph, questions, &root.offer.transfer, batch)?;
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
                Progress::Skipped(id, error)
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
    ) -> Result<OfferStatus, crate::Error> {
        self.enqueue_program_with_prefix(peer, metadata, graph, grant, None)
    }

    pub(super) fn enqueue_program_with_prefix(
        &mut self,
        peer: PeerId,
        metadata: ProgramMetadata,
        graph: &Graph,
        grant: Option<crate::publication::PeerGrant>,
        prefix: Option<CheckedBatch>,
    ) -> Result<OfferStatus, crate::Error> {
        if self
            .programs
            .helper_contains(metadata.manifest.artifact_id())
            || self
                .active
                .as_ref()
                .is_some_and(|root| root.closure.contains(metadata.manifest.artifact_id()))
        {
            return Ok(OfferStatus::CitedProgramPending);
        }
        if self.description_capacity() == 0
            && !self.programs.contains(metadata.manifest.artifact_id())
        {
            return Err(crate::InputLimit::IntakeProgramDescriptionCapacity.into());
        }
        self.programs.enqueue(peer, metadata, graph, grant, prefix)
    }
    pub(crate) fn program_request(
        &self,
        graph: &Graph,
    ) -> Result<Option<ProgramRequest>, crate::Error> {
        if let Some(fetch) = &self.definition
            && fetch.transfer.live(Instant::now())
            && let Some((id, start, records)) = fetch.closure.request(graph)?
        {
            return Ok(Some((
                fetch.transfer.peer(),
                fetch.transfer.root(),
                id,
                start,
                records,
            )));
        }
        if let Some(root) = &self.active
            && root.closure.has_programs()
            && root.description.transfer.live(Instant::now())
            && let Some((id, start, records)) = root.closure.request(graph)?
        {
            return Ok(Some((
                root.description.transfer.peer(),
                root.description.transfer.root(),
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
        root_id: ArtifactId,
        id: ArtifactId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if let Some(fetch) = &mut self.definition
            && fetch.transfer.authorizes(peer, root_id, Instant::now())
        {
            return fetch.closure.payload(id, chunk, graph);
        }
        if self.programs.authorizes(peer, root_id, id) {
            return self
                .programs
                .helper_payload(peer, root_id, id, chunk, graph);
        }
        if root_id != id {
            if !self.authorizes(peer, root_id, id) {
                return Err(crate::InputFault::IntakeCitedProgramUnrequested.into());
            }
            let root = self
                .active
                .as_mut()
                .ok_or(crate::InputFault::IntakeCitedParentMissing)?;
            root.description.transfer.check(Instant::now())?;
            return root.closure.payload(id, chunk, graph);
        }
        self.programs.payload(peer, id, chunk, graph)
    }
    pub(crate) fn program_failed(&mut self, peer: PeerId, id: ArtifactId) {
        self.programs.failed(peer, Some(id));
    }
    pub(crate) fn program_refresh_needed(&self) -> Vec<(PeerId, ArtifactId)> {
        self.programs.refresh_needed()
    }
    pub(crate) fn program_busy(&self) -> bool {
        self.programs.busy()
            || self
                .definition
                .as_ref()
                .is_some_and(|fetch| fetch.closure.busy())
            || self.active.as_ref().is_some_and(|root| root.closure.busy())
    }
}
