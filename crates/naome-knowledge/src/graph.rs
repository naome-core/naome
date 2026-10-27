use crate::Envelope;
use crate::object::{Candidate, CandidatePayload, CheckedArtifact, Metadata, id_bytes};
use crate::publication::{CommitGuard, PeerGrant, STALE_COMMIT};
use crate::store::{Store, Summary};
use naome_checker::{
    ContextView, DiskArtifactCopy, DiskArtifactState, DiskCopyBudget, check_normal_form_with_state,
};
use naome_proof::ArtifactId;
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

mod batch;
pub(crate) mod dependencies;
mod pending;
mod preparation;
use preparation::{Preparation, Stamp};
mod learning;
pub(crate) mod program;
mod storage;
pub(crate) use batch::CheckedBatch;
use storage::CheckedStorage;

#[derive(Debug)]
pub struct Ingest {
    pub status: &'static str,
    pub id: ArtifactId,
    pub admitted: Vec<ArtifactId>,
    pub rejected: Vec<(ArtifactId, crate::Error)>,
}

type PendingResolution = (Vec<ArtifactId>, Vec<(ArtifactId, crate::Error)>);

/// The sole acceptance owner for this operating path. Checked state is private.
pub struct Graph {
    context: DiskArtifactState,
    commit_guard: Option<CommitGuard>,
    #[cfg(test)]
    checks: [std::sync::atomic::AtomicU64; 2],
    pending: BTreeMap<ArtifactId, (Candidate, Instant)>,
    backlog: Mutex<pending::PendingStore>,
    count: usize,
    bytes: usize,
    context_bytes: usize,
    root: [u8; 32],
    storage_error: Arc<Mutex<Option<String>>>,
    store: Arc<Store>,
    checked_storage: Arc<CheckedStorage>,
    old_generations: Vec<Weak<CheckedStorage>>,
    next_compaction: usize,
    compaction: Option<Compaction>,
}

/// One unpublished successor, owned by the same Graph that publishes roots.
/// Dropping any partial copy removes its exact mirror before releasing bytes.
struct Compaction {
    source: Arc<CheckedStorage>,
    target: Arc<CheckedStorage>,
    cursor: Option<DiskArtifactCopy>,
    epoch: u64,
    _disk: crate::resources::DiskLease,
}

impl Drop for Compaction {
    fn drop(&mut self) {
        self.source.abort_copy(self.epoch, &self.target);
    }
}

impl Graph {
    #[cfg(test)]
    pub(crate) fn delay_next_write(
        started: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        CheckedStorage::delay_next_write(started, release);
    }
    #[cfg(test)]
    pub(crate) fn checker_calls(&self) -> (u64, u64) {
        (
            self.checks[0].load(std::sync::atomic::Ordering::Relaxed),
            self.checks[1].load(std::sync::atomic::Ordering::Relaxed),
        )
    }
    fn backlog(&self) -> Result<std::sync::MutexGuard<'_, pending::PendingStore>, crate::Error> {
        self.backlog
            .lock()
            .map_err(|_| "proof backlog lock poisoned".into())
    }
    pub(crate) fn ownership(&self) -> Arc<Store> {
        self.store.clone()
    }
    pub(crate) fn set_commit_guard(&mut self, guard: CommitGuard) {
        self.commit_guard = Some(guard);
    }
    fn publication_current(&self) -> Result<(), crate::Error> {
        self.commit_guard
            .as_ref()
            .map_or(Ok(()), CommitGuard::check)
    }
    #[cfg(test)]
    pub(crate) fn test_database_full(&self) {
        self.store.limit_current_pages();
    }
    #[cfg(test)]
    pub(crate) fn test_compaction_step(&mut self, records: usize) -> Result<bool, crate::Error> {
        self.maintain_checked_storage_step(
            0,
            DiskCopyBudget {
                records,
                bytes: naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES,
            },
        )?;
        Ok(self.compaction.is_some())
    }
    pub fn accepted_count(&self) -> usize {
        self.count
    }
    pub(crate) fn checked_context(&self) -> &DiskArtifactState {
        &self.context
    }
    #[cfg(all(test, feature = "system-tests"))]
    pub(crate) fn context_bytes(&self) -> usize {
        self.context_bytes
    }
    fn fixed_summary(&self) -> Summary {
        Summary {
            root: self.root,
            count: self.count,
            bytes: self.bytes,
        }
    }

    fn ensure_live(&self) -> Result<(), crate::Error> {
        match self.storage_error() {
            Some(error) => Err(crate::Error::CorruptStorage(error)),
            None => Ok(()),
        }
    }
    pub(crate) fn program_failure(&self, error: &crate::Error) {
        if error.fatal() {
            *self.storage_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
        }
    }
    fn cold<T, E: Into<crate::Error>>(&self, result: Result<T, E>) -> Result<T, crate::Error> {
        result.map_err(|error| {
            let error = error.into().storage();
            if error.fatal() {
                *self.storage_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(
                    error
                        .storage_detail()
                        .unwrap_or("checked storage failure")
                        .to_owned(),
                );
            }
            error
        })
    }
    pub(crate) fn describe(&self, id: ArtifactId) -> Result<Option<Metadata>, crate::Error> {
        self.ensure_live()?;
        let Some(proof_id) = self.cold(self.context.artifact_proof_id(id))? else {
            return Ok(None);
        };
        let header = self.cold(
            self.context
                .proof_header(proof_id)
                .map_err(crate::Error::from),
        )?;
        let Some(header) = header else {
            return Ok(None);
        };
        let statement = header.statement_id();
        let conclusion = self
            .cold(
                self.context
                    .proof_formula(header, naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES)
                    .map_err(crate::Error::from),
            )?
            .ok_or("checked proof conclusion missing")?;
        let derived = naome_authoring::CompiledQuestion::from_formula(conclusion.into_owned())
            .map_err(crate::Error::from)?;
        if derived.formula() != derived.positive_target()
            && derived.formula() != derived.negative_target()
        {
            return Err("description statement does not match a question target".into());
        }
        let metadata = Metadata {
            artifact_id: crate::hex(id.as_bytes()),
            proof_id: crate::hex(proof_id.as_bytes()),
            statement_id: crate::hex(statement.as_bytes()),
            question: format!("goal = {}", derived.core().to_source()),
        };
        Ok(Some(metadata))
    }

    /// Reconstruct empty authenticated roots from bounded owned canonical pages.
    /// Every dependency must already be checked; stored order grants no validity.
    pub fn open(directory: &Path) -> Result<Self, crate::Error> {
        Self::open_inner(directory, false, &mut || Ok(()))
    }
    pub(crate) fn open_observed(
        directory: &Path,
        observe: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Self, crate::Error> {
        Self::open_inner(directory, false, observe)
    }
    fn open_inner(
        directory: &Path,
        cleanup: bool,
        observe: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Self, crate::Error> {
        let store = Arc::new(Store::open(directory)?);
        let summary = store.summary()?;
        let halt = Arc::new(Mutex::new(None));
        let storage = CheckedStorage::open(store.clone(), cleanup, halt.clone())?;
        let mut graph = Self {
            context: DiskArtifactState::new(storage.clone())
                .with_read_cache_limits(
                    naome_checker::ReadCacheLimits::new(
                        crate::resources::active_limits().checker_cache_entries,
                        crate::resources::active_limits().checker_cache_bytes,
                    )
                    .map_err(crate::Error::from)?,
                )
                .map_err(crate::Error::from)?,
            commit_guard: None,
            #[cfg(test)]
            checks: [const { std::sync::atomic::AtomicU64::new(0) }; 2],
            checked_storage: storage,
            old_generations: Vec::new(),
            next_compaction: crate::resources::active_limits().checked_cache_bytes,
            compaction: None,
            pending: BTreeMap::new(),
            backlog: Mutex::new(pending::PendingStore::open(directory)?),
            count: 0,
            bytes: 0,
            context_bytes: 0,
            root: crate::corpus::root(0, [0; 32])?,
            storage_error: halt,
            store,
        };
        let mut after = 0u64;
        let mut replay_compaction = crate::resources::active_limits().checked_cache_bytes;
        #[cfg(test)]
        {
            replay_compaction = storage::startup_test_threshold(replay_compaction);
        }
        loop {
            observe()?;
            let page = graph
                .store
                .replay_page(after, crate::resources::active_limits().replay_page)?;
            if page.is_empty() {
                break;
            }
            graph.cold(graph.checked_storage.begin_startup_page())?;
            for (ordinal, record) in page {
                observe()?;
                graph.cold(graph.checked_storage.adapt_cache())?;
                if ordinal != after.checked_add(1).ok_or("replay ordinal overflow")? {
                    return Err("durable replay order is incomplete".into());
                }
                if let Some(manifest) = record.program()? {
                    graph
                        .replay_program(&manifest, observe)
                        .map_err(crate::Error::storage)?;
                    graph.bytes = graph
                        .bytes
                        .checked_add(record.bytes.len())
                        .ok_or("replayed payload byte overflow")?;
                    graph.count = graph
                        .count
                        .checked_add(1)
                        .ok_or("accepted count overflow")?;
                    after = ordinal;
                    continue;
                }
                let candidate = graph.cold(record.prepare_retained())?;
                graph.bytes = graph
                    .bytes
                    .checked_add(candidate.bytes.len())
                    .ok_or("replayed payload byte overflow")?;
                let mut ready = true;
                for dependency in &candidate.dependencies {
                    if !graph.cold(
                        graph
                            .context
                            .contains_artifact(*dependency)
                            .map_err(crate::Error::from),
                    )? {
                        ready = false;
                        break;
                    }
                }
                if !ready {
                    return Err("durable graph has missing or cyclic dependencies".into());
                }
                let (context, growth) = graph.cold(graph.check_candidate(candidate))?;
                graph.context = context;
                graph.context_bytes = graph
                    .context_bytes
                    .checked_add(growth)
                    .ok_or("checked context byte overflow")?;
                graph.count = graph
                    .count
                    .checked_add(1)
                    .ok_or("accepted count overflow")?;
                after = ordinal;
            }
            graph.cold(graph.checked_storage.finish_startup_page(&graph.context))?;
            if let Some(live) = graph.prune_startup_checked_storage_at(replay_compaction)? {
                replay_compaction = Self::replay_compaction_threshold(live);
            }
        }
        if graph.count != summary.count
            || after != u64::try_from(summary.count).map_err(|_| "replay count width")?
        {
            return Err("mathematical replay count differs from catalog".into());
        }
        let root = crate::corpus::root(graph.count, graph.context.artifact_set_fingerprint())?;
        if root != summary.root || graph.bytes != summary.bytes {
            return Err("mathematically replayed corpus differs from catalog".into());
        }
        graph.store.finish_replay(root)?;
        graph.root = root;
        Ok(graph)
    }

    /// Advance one bounded copy quantum, reclaiming unreachable copy-on-write
    /// nodes only at completed handoff. Retained snapshots keep their storage;
    /// all generations share the single bounded cache.
    pub(crate) fn maintain_checked_storage(&mut self) -> Result<(), crate::Error> {
        self.checked_storage.adapt_cache()?;
        let bytes = crate::resources::adaptive::cache(
            crate::resources::active_limits().checker_cache_bytes,
        );
        let cache_limits = naome_checker::ReadCacheLimits::new(
            crate::resources::active_limits()
                .checker_cache_entries
                .min(bytes / 512),
            bytes,
        )?;
        if self.context.read_cache_limits() != cache_limits {
            self.context = self.context.clone().with_read_cache_limits(cache_limits)?;
        }
        if !crate::resources::adaptive::work_available() {
            return Ok(());
        }
        match self.maintain_checked_storage_at(self.next_compaction) {
            Err(error) if error.retryable() => Ok(()),
            result => result.map(|_| ()),
        }
    }

    fn replay_compaction_threshold(live: usize) -> usize {
        live.saturating_add(live / 2)
            .max(live.saturating_add(crate::resources::active_limits().checked_cache_bytes))
    }

    // This call path is exclusive to open_inner, before any checked view escapes.
    // Runtime snapshots and prepared batches still use successor generations.
    fn prune_startup_checked_storage_at(
        &mut self,
        threshold: usize,
    ) -> Result<Option<usize>, crate::Error> {
        self.ensure_live()?;
        if self.cold(self.checked_storage.allocated_bytes())? < threshold {
            return Ok(None);
        }
        let live = self.cold(self.checked_storage.prune_startup(&self.context))?;
        self.next_compaction = live
            .saturating_mul(2)
            .max(live.saturating_add(crate::resources::active_limits().checked_cache_bytes));
        Ok(Some(live))
    }

    fn maintain_checked_storage_at(
        &mut self,
        threshold: usize,
    ) -> Result<Option<usize>, crate::Error> {
        self.maintain_checked_storage_step(
            threshold,
            DiskCopyBudget {
                records: crate::resources::active_limits().compaction_records,
                bytes: crate::resources::active_limits().compaction_bytes,
            },
        )
    }

    fn maintain_checked_storage_step(
        &mut self,
        threshold: usize,
        budget: DiskCopyBudget,
    ) -> Result<Option<usize>, crate::Error> {
        if let Err(error) = self.ensure_live() {
            drop(self.compaction.take());
            return Err(error);
        }
        // The threshold admits a new copy. An existing cursor keeps making
        // bounded progress even when a caller supplies a different threshold.
        if self.compaction.is_none() {
            if self.cold(self.checked_storage.allocated_bytes())? < threshold {
                return Ok(None);
            }
            self.old_generations
                .retain(|generation| generation.strong_count() != 0);
            if self.old_generations.len() >= crate::resources::limits().retained_generations {
                return Err(crate::Error::ExecutionLimit);
            }
            let source = self.checked_storage.clone();
            let bytes = self
                .cold(source.allocated_bytes())?
                .checked_mul(2)
                .ok_or("compaction disk overflow")?;
            let disk = match crate::resources::DiskLease::acquire(
                self.store.directory(),
                u64::try_from(bytes).map_err(|_| "compaction disk width")?,
            ) {
                Ok(disk) => disk,
                Err(error) if error.retryable() => return Ok(None),
                Err(error) => return self.cold(Err::<_, crate::Error>(error)),
            };
            let target = self.cold(source.successor())?;
            let mut gate = self.cold(source.write_gate())?;
            self.ensure_live()?;
            let epoch = self.cold(gate.attach(&source, target.clone()))?;
            // No fallible operation remains between attaching and installing
            // the abort guard. Pre-attach batches keep their previous epoch.
            self.compaction = Some(Compaction {
                source: source.clone(),
                target: target.clone(),
                cursor: Some(self.context.begin_copy(target)),
                epoch,
                _disk: disk,
            });
        }
        let mut copy = self.compaction.take().expect("active checked copy");
        let result = self.advance_checked_copy(&mut copy, budget);
        if matches!(result, Ok(None)) {
            self.compaction = Some(copy);
        }
        // On failure or completion, the local guard detaches the old source.
        result
    }

    fn advance_checked_copy(
        &mut self,
        copy: &mut Compaction,
        budget: DiskCopyBudget,
    ) -> Result<Option<usize>, crate::Error> {
        let source = copy.source.clone();
        let mut gate = self.cold(source.write_gate())?;
        self.ensure_live()?;
        if !Arc::ptr_eq(&source, &self.checked_storage) || !gate.matches(copy.epoch, &copy.target) {
            return self.cold(Err::<_, crate::Error>(
                "checked copy source epoch or target changed".into(),
            ));
        }
        // A copy transaction contains only this bounded quantum. Admissions
        // between quanta use separate per-proof transactions, including mirrors;
        // no corpus-sized transaction reaches finish.
        let started = Instant::now();
        self.cold(copy.target.begin_write_phase())?;
        let progress = self.cold(
            copy.cursor
                .as_mut()
                .expect("unfinished checked cursor")
                .advance(budget)
                .map_err(crate::Error::from),
        )?;
        self.cold(copy.target.finish_write_phase())?;
        crate::resources::feedback::record(
            crate::resources::feedback::Kind::Compact,
            progress.records.saturating_add(progress.node_visits),
            started.elapsed(),
        );
        if !progress.complete {
            return Ok(None);
        }
        let context = self.cold(
            copy.cursor
                .take()
                .expect("complete checked cursor")
                .finish(&self.context)
                .map_err(crate::Error::from),
        )?;
        let live = self.cold(copy.target.allocated_bytes())?;
        let threshold = live
            .saturating_mul(2)
            .max(live.saturating_add(crate::resources::active_limits().checked_cache_bytes));
        self.cold(gate.detach(copy.epoch, &copy.target))?;
        // Linearize publication with already reported failures, including a
        // concurrent cold reader. Everything below is an infallible state move.
        let halt = self.storage_error.clone();
        let failure = halt.lock().unwrap_or_else(|error| {
            let mut failure = error.into_inner();
            *failure = Some("checked storage halt lock poisoned".into());
            failure
        });
        if let Some(error) = &*failure {
            return Err(crate::Error::CorruptStorage(format!(
                "storage halted: {error}"
            )));
        }
        self.old_generations.push(Arc::downgrade(&source));
        self.context = context;
        self.checked_storage = copy.target.clone();
        // Startup keeps its smaller threshold local; ingest retains this one.
        self.next_compaction = threshold;
        Ok(Some(live))
    }

    pub fn author(&self, source: &str) -> Result<Envelope, crate::Error> {
        self.ensure_live()?;
        if source.len() > crate::resources::limits().proof_bytes {
            return Err("producer source byte limit".into());
        }
        let checked = CheckedArtifact::from_compiled(self.compile_source(source, &self.context)?);
        self.cold(checked.record(&self.context))
            .map(|record| record.envelope())
    }

    /// Compile and publish local source while retaining its sealed checker result.
    /// Local owner ingestion has its own authority; peer selection stays separate.
    pub(crate) fn produce(&mut self, source: &str) -> Result<(Envelope, Ingest), crate::Error> {
        crate::resources::require_work_admission()?;
        self.maintain_checked_storage()?;
        if source.len() > crate::resources::limits().proof_bytes {
            return Err("producer source byte limit".into());
        }
        let disk = self.reserve_publication(source.len(), 1)?;
        let checked = CheckedArtifact::from_compiled(self.compile_source(source, &self.context)?);
        let record = self.cold(checked.record(&self.context))?;
        if record.bytes.len() > crate::resources::limits().proof_bytes {
            return Err("proof byte limit".into());
        }
        let id = record.id;
        let envelope = record.envelope();
        if let Some(existing) = self.binary_object(id)? {
            if !existing.same_content(&record) {
                return Err("proof identity collision".into());
            }
            return Ok((
                envelope,
                Ingest {
                    status: "duplicate",
                    id,
                    admitted: Vec::new(),
                    rejected: Vec::new(),
                },
            ));
        }
        self.publish_checked(checked, record, disk)?;
        let (mut admitted, rejected) = self.resolve_pending()?;
        admitted.insert(0, id);
        Ok((
            envelope,
            Ingest {
                status: "accepted",
                id,
                admitted,
                rejected,
            },
        ))
    }

    pub fn ingest(&mut self, envelope: Envelope, now: Instant) -> Result<Ingest, crate::Error> {
        crate::resources::require_work_admission()?;
        self.maintain_checked_storage()?;
        let candidate = envelope.prepare()?;
        let id = candidate.id;
        if let Some(existing) = self.binary_object(id)? {
            if !existing.same_content(&candidate.record()) {
                return Err("proof identity collision".into());
            }
            return Ok(Ingest {
                status: "duplicate",
                id,
                admitted: Vec::new(),
                rejected: Vec::new(),
            });
        }
        if self.waiting(id) {
            return Ok(Ingest {
                status: "waiting_duplicate",
                id,
                admitted: Vec::new(),
                rejected: Vec::new(),
            });
        }
        if !self.ready(&candidate)? {
            let persisted = self.backlog()?.insert(&candidate, &self.context);
            match persisted {
                Err(error) if error.fatal() => return self.cold(Err::<_, crate::Error>(error)),
                result => result?,
            }
            let held = self
                .pending
                .values()
                .map(|(candidate, _)| candidate.bytes.len())
                .sum::<usize>();
            if self.pending.len() < crate::resources::active_limits().pending_page
                && candidate.bytes.len()
                    <= crate::resources::limits()
                        .closure_bytes
                        .saturating_sub(held)
            {
                self.pending.insert(id, (candidate, now));
            }
            return Ok(Ingest {
                status: "waiting",
                id,
                admitted: Vec::new(),
                rejected: Vec::new(),
            });
        }
        self.admit(candidate)?;
        let mut result = Ingest {
            status: "accepted",
            id,
            admitted: vec![id],
            rejected: Vec::new(),
        };
        let (admitted, rejected) = self.resolve_pending()?;
        result.admitted.extend(admitted);
        result.rejected.extend(rejected);
        Ok(result)
    }

    /// Process one fair bounded working page. Durable rows remain queued when
    /// memory is busy or a dependency is missing, and every tick advances FIFO.
    pub(crate) fn resolve_pending(&mut self) -> Result<PendingResolution, crate::Error> {
        self.ensure_live()?;
        self.pending.clear();
        if !crate::resources::adaptive::work_available() {
            return Ok((Vec::new(), Vec::new()));
        }
        let scheduled = self.backlog()?.schedule(&self.context);
        self.cold(scheduled)?;
        let page = self.backlog()?.next_page();
        let page = match page {
            Err(error) if error.retryable() => {
                crate::network::emit(
                    serde_json::json!({"event":"proof_backlog_deferred","error":error}),
                );
                return Ok((Vec::new(), Vec::new()));
            }
            other => self.cold(other)?,
        };
        let mut admitted = Vec::new();
        let mut rejected = Vec::new();
        for record in page {
            if !crate::resources::adaptive::work_available() {
                break;
            }
            let id = record.id;
            if self.contains(id)? {
                let removed = self.backlog()?.remove(id);
                self.cold(removed)?;
                continue;
            }
            let candidate = match record.for_admission() {
                Ok(candidate) => candidate,
                Err(error) if error.retryable() || matches!(error, crate::Error::InputLimit(_)) => {
                    crate::network::emit(
                        serde_json::json!({"event":"proof_backlog_overload","id":crate::hex(id.as_bytes()),"error":error}),
                    );
                    continue;
                }
                Err(error) => return self.cold(Err::<_, crate::Error>(error)),
            };
            if !self.ready(&candidate)? {
                self.pending.insert(id, (candidate, Instant::now()));
                continue;
            }
            match self.admit(candidate) {
                Ok(()) => admitted.push(id),
                Err(error) if error.retryable() => {
                    crate::network::emit(
                        serde_json::json!({"event":"proof_backlog_deferred","id":crate::hex(id.as_bytes()),"error":error}),
                    );
                    continue;
                }
                Err(error) => {
                    if self.storage_error().is_some() {
                        return Err(error);
                    }
                    rejected.push((id, error));
                }
            }
            let removed = self.backlog()?.remove(id);
            self.cold(removed)?;
        }
        Ok((admitted, rejected))
    }

    fn ready(&self, candidate: &Candidate) -> Result<bool, crate::Error> {
        for id in &candidate.dependencies {
            if !self.contains(*id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn compile_source(
        &self,
        source: &str,
        context: &DiskArtifactState,
    ) -> Result<naome_authoring::CompiledArtifact, crate::Error> {
        self.ensure_live()?;
        crate::resources::require_work_admission()?;
        #[cfg(test)]
        {
            self.checks[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        naome_authoring::compile_artifact_against_proof_context(source, context).map_err(|error| {
            let error = crate::Error::from(error);
            self.record_check_failure(&error);
            error
        })
    }

    fn check_normal(
        &self,
        normal: naome_proof::ProofNormalForm,
        context: &DiskArtifactState,
    ) -> Result<naome_checker::CheckedProof, crate::Error> {
        #[cfg(test)]
        {
            self.checks[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        check_normal_form_with_state(normal, context).map_err(|error| {
            let error = crate::Error::from(error);
            self.record_check_failure(&error);
            error
        })
    }

    fn record_check_failure(&self, error: &crate::Error) {
        if error.fatal() {
            *self.storage_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(
                error
                    .storage_detail()
                    .unwrap_or("checked storage failure")
                    .to_owned(),
            );
        }
    }

    fn check_artifact(
        &self,
        candidate: Candidate,
        context: &DiskArtifactState,
    ) -> Result<CheckedArtifact, crate::Error> {
        let checked = match &candidate.payload {
            CandidatePayload::Proof(normal) => {
                CheckedArtifact::Proof(self.check_normal(normal.clone(), context)?)
            }
            CandidatePayload::Definition(certificate) => {
                #[cfg(test)]
                {
                    self.checks[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let definition =
                    naome_checker::check_definition_with_state(certificate.clone(), context)
                        .map_err(crate::Error::from)?;
                if let Some(statement) = definition.obligation_statement_id() {
                    let witness = candidate
                        .obligation
                        .ok_or("function obligation witness missing")?;
                    let header = self
                        .cold(context.proof_header(witness).map_err(crate::Error::from))?
                        .ok_or("function obligation proof missing")?;
                    if header.statement_id() != statement {
                        return Err("function obligation proof conclusion differs".into());
                    }
                }
                CheckedArtifact::Definition(definition)
            }
        };
        if checked.id() != candidate.id || checked.statement() != candidate.statement {
            return Err("checked identity mismatch".into());
        }
        Ok(checked)
    }

    fn registration_growth(
        &self,
        context: &DiskArtifactState,
        checked: &CheckedArtifact,
    ) -> Result<usize, crate::Error> {
        let CheckedArtifact::Proof(checked) = checked else {
            let CheckedArtifact::Definition(definition) = checked else {
                unreachable!()
            };
            return Ok(definition.certificate().canonical_bytes().len());
        };
        let growth = if self.cold(
            context
                .contains_statement(checked.statement_id())
                .map_err(crate::Error::from),
        )? {
            0
        } else {
            checked
                .conclusion()
                .encode_canonical()
                .map_err(crate::Error::from)?
                .len()
        };
        Ok(growth)
    }

    fn registered_context(
        &self,
        checked: CheckedArtifact,
    ) -> Result<DiskArtifactState, crate::Error> {
        let mut context = self.context.clone();
        self.cold(checked.register(&mut context))?;
        Ok(context)
    }

    fn check_candidate(
        &self,
        candidate: Candidate,
    ) -> Result<(DiskArtifactState, usize), crate::Error> {
        // Replay owns its existing bounded page transaction, never a nested
        // per-admission transaction. Ordinary mathematical rejection is also
        // determined before any new runtime phase is opened.
        let checked = self.check_artifact(candidate, &self.context)?;
        let growth = self.registration_growth(&self.context, &checked)?;
        Ok((self.registered_context(checked)?, growth))
    }

    /// Cover payloads, journal duplication, immutable index paths and a possible
    /// concurrent compaction mirror before preparing any unpublished writes.
    fn reserve_publication(
        &self,
        bytes: usize,
        objects: usize,
    ) -> Result<crate::resources::DiskLease, crate::Error> {
        crate::resources::DiskLease::acquire(
            self.store.directory(),
            Self::publication_reservation(bytes, objects)?,
        )
    }
    fn publication_reservation(bytes: usize, objects: usize) -> Result<u64, crate::Error> {
        let index = objects
            .checked_mul(naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES)
            .and_then(|n| n.checked_mul(16))
            .ok_or("publication disk estimate overflow")?;
        let work = bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(index))
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or("publication disk estimate overflow")?;
        u64::try_from(work).map_err(|_| "publication disk width".into())
    }

    fn admit(&mut self, candidate: Candidate) -> Result<(), crate::Error> {
        self.publication_current()?;
        let disk = self.reserve_publication(candidate.bytes.len(), 1)?;
        let record = candidate.record();
        let checked = self.check_artifact(candidate, &self.context)?;
        self.publish_checked(checked, record, disk)
    }

    fn publish_checked(
        &mut self,
        checked: CheckedArtifact,
        record: crate::object::BinaryArtifact,
        disk: crate::resources::DiskLease,
    ) -> Result<(), crate::Error> {
        self.publication_current()?;
        let id = record.id;
        let stamp = Stamp::capture(self)?;
        let mut preparation = Preparation::reserved(self, stamp, disk);
        let registration = preparation.check_registration(self, checked, record)?;
        let source = self.checked_storage.clone();
        // The phase guard records every setup failure, including native close
        // errors. Do not overwrite that cleanup evidence through cold().
        let phase = source
            .admission_phase()
            .map_err(|error| format!("storage halted: {error}"))?;
        preparation.register_artifact(self, registration)?;
        let batch = preparation.finish(self, id)?;
        let mut gates = self.cold(phase.finish(self.checked_storage.as_ref()))?;
        let persisted = self.store.persist_binary_batch(
            id,
            batch.entries.iter().map(|(_, record)| record),
            self.fixed_summary(),
            None,
            crate::corpus::root(
                self.count.checked_add(1).ok_or("accepted count overflow")?,
                batch.context.artifact_set_fingerprint(),
            )?,
            self.commit_guard.as_ref(),
        );
        if persisted
            .as_ref()
            .is_err_and(|error| *error == STALE_COMMIT)
        {
            phase.discarded(&mut gates);
        }
        let summary = self.cold(persisted)?;
        // All fallible preparation precedes the durable transaction. Afterwards
        // publish only fixed roots and scalars; no catalog/context read can fail.
        self.context = batch.context;
        self.context_bytes = batch.context_bytes;
        self.count = summary.count;
        self.bytes = summary.bytes;
        self.root = summary.root;
        phase.published(&mut gates);
        let wake = self.backlog()?.accepted(id);
        self.cold(wake)?;
        Ok(())
    }

    pub fn pending_count(&self) -> Result<usize, crate::Error> {
        self.ensure_live()?;
        self.cold(self.backlog()?.len())
    }
    pub fn pending_ids_after(
        &self,
        after: Option<ArtifactId>,
        limit: usize,
    ) -> Result<Vec<ArtifactId>, crate::Error> {
        self.ensure_live()?;
        let after = after.map(|id| crate::hex(id.as_bytes()));
        self.cold(self.backlog()?.ids(after.as_deref(), limit))
    }
    pub fn missing(&self) -> Result<BTreeSet<ArtifactId>, crate::Error> {
        let mut missing = BTreeSet::new();
        for (candidate, _) in self.pending.values() {
            for id in &candidate.dependencies {
                if !self.waiting(*id) && !self.contains(*id)? {
                    missing.insert(*id);
                }
            }
        }
        Ok(missing)
    }
    pub fn pending_ids(&self) -> Result<Vec<ArtifactId>, crate::Error> {
        self.pending_ids_after(None, crate::resources::active_limits().id_page)
    }
    pub fn storage_error(&self) -> Option<String> {
        self.storage_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn contains(&self, id: ArtifactId) -> Result<bool, crate::Error> {
        self.ensure_live()?;
        let checked = self.cold(
            self.context
                .contains_artifact(id)
                .map_err(crate::Error::from),
        )?;
        let stored = self.cold(self.store.contains(id, self.fixed_summary()))?;
        if checked != stored {
            return self.cold(Err::<_, crate::Error>(
                "checked canonical membership differs".into(),
            ));
        }
        Ok(checked)
    }
    pub fn waiting(&self, id: ArtifactId) -> bool {
        self.cold(self.backlog().and_then(|backlog| backlog.contains(id)))
            .unwrap_or(false)
    }
    fn binary_object(
        &self,
        id: ArtifactId,
    ) -> Result<Option<crate::object::BinaryArtifact>, crate::Error> {
        self.ensure_live()?;
        let checked = self.cold(
            self.context
                .contains_artifact(id)
                .map_err(crate::Error::from),
        )?;
        let object = self.cold(self.store.get_binary(id, self.fixed_summary()))?;
        if checked != object.is_some() {
            return self.cold(Err::<_, crate::Error>(
                "checked canonical membership differs".into(),
            ));
        }
        Ok(object)
    }
    pub fn object(&self, id: ArtifactId) -> Result<Option<Envelope>, crate::Error> {
        self.binary_object(id)
            .map(|object| object.map(|object| object.envelope()))
    }
    pub fn ids_page(
        &self,
        after: Option<ArtifactId>,
        limit: usize,
    ) -> Result<Vec<ArtifactId>, crate::Error> {
        self.ensure_live()?;
        if limit == 0 || limit > crate::resources::active_limits().id_page {
            return Err("inventory page limit".into());
        }
        let expected = self.cold(
            self.context
                .artifact_ids_after(after)
                .take(limit)
                .collect::<Result<Vec<_>, _>>()
                .map_err(crate::Error::from),
        )?;
        let actual = self.cold(self.store.ids_page(after, limit, self.fixed_summary()))?;
        if actual != expected {
            return self.cold(Err::<_, crate::Error>(
                "canonical inventory differs from checked set".into(),
            ));
        }
        Ok(expected)
    }
    pub fn content_root(&self) -> [u8; 32] {
        self.root
    }

    /// Read a fixed admission-order interval without pinning a checked storage
    /// generation. Later insertions cannot change or extend the captured range.
    pub(crate) fn inventory_page(
        &self,
        after: Option<crate::corpus::InventoryCursor>,
        limit: usize,
    ) -> Result<Option<crate::corpus::InventoryPage>, crate::Error> {
        self.ensure_live()?;
        if limit == 0 || limit > crate::resources::limits().inventory_page {
            return Err(crate::Error::InputLimit("inventory page limit"));
        }
        let page = self.cold(
            self.store
                .inventory_page(after, limit, self.fixed_summary()),
        )?;
        if let Some(page) = &page {
            for id in &page.ids {
                if !self.cold(
                    self.context
                        .contains_artifact(*id)
                        .map_err(crate::Error::from),
                )? {
                    return self.cold(Err(crate::Error::CorruptStorage(
                        "canonical inventory differs from checked set".into(),
                    )));
                }
            }
        }
        Ok(page)
    }
    pub fn get(&self, id: &str) -> Result<Option<Envelope>, crate::Error> {
        self.object(ArtifactId::from_bytes(id_bytes(id)?))
    }
    #[cfg(test)]
    pub(crate) fn ids(&self) -> Vec<ArtifactId> {
        let mut ids = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .ids_page(after, 128)
                .expect("complete small test catalog");
            if page.is_empty() {
                return ids;
            }
            after = page.last().copied();
            ids.extend(page);
        }
    }
}

#[cfg(test)]
impl Default for Graph {
    fn default() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "naome-disk-graph-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("new isolated test catalog");
        Self::open_inner(&directory, true, &mut || Ok(())).expect("empty test catalog")
    }
}
#[cfg(test)]
mod tests;
