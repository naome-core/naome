use crate::Envelope;
use crate::object::{Candidate, Metadata, id_bytes};
use crate::store::{Store, Summary};
use naome_checker::{
    ContextView, DiskArtifactCopy, DiskArtifactState, DiskCopyBudget, check_normal_form_with_state,
};
use naome_proof::ProofId;
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

mod batch;
mod pending;
mod storage;
pub(crate) use batch::CheckedBatch;
use storage::CheckedStorage;

#[derive(Debug)]
pub struct Ingest {
    pub status: &'static str,
    pub id: ProofId,
    pub admitted: Vec<ProofId>,
    pub rejected: Vec<(ProofId, String)>,
}

type PendingResolution = (Vec<ProofId>, Vec<(ProofId, String)>);

pub(crate) const STALE_COMMIT: &str = "publication authority changed before durable commit";

/// Revocable operation authority, checked again inside the durable transaction.
/// It contains no mathematical state and cannot grant checked membership.
#[derive(Clone)]
pub(crate) struct CommitGuard {
    epoch: Arc<std::sync::atomic::AtomicU64>,
    expected: u64,
    control: Option<Arc<crate::runtime::Control>>,
    selection: Option<[u8; 32]>,
}
impl CommitGuard {
    pub(crate) fn new(
        epoch: Arc<std::sync::atomic::AtomicU64>,
        expected: u64,
        control: Option<Arc<crate::runtime::Control>>,
        selection: Option<[u8; 32]>,
    ) -> Self {
        Self {
            epoch,
            expected,
            control,
            selection,
        }
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        if self.epoch.load(Ordering::Acquire) != self.expected {
            return Err(STALE_COMMIT.into());
        }
        if let Some(control) = &self.control
            && (control.stopping() || control.selection().ok() != self.selection)
        {
            return Err(STALE_COMMIT.into());
        }
        if self.epoch.load(Ordering::Acquire) != self.expected {
            return Err(STALE_COMMIT.into());
        }
        Ok(())
    }
}

/// The sole acceptance owner for this operating path. Checked state is private.
pub struct Graph {
    context: DiskArtifactState,
    commit_guard: Option<CommitGuard>,
    #[cfg(test)]
    checks: [std::sync::atomic::AtomicU64; 2],
    pending: BTreeMap<ProofId, (Candidate, Instant)>,
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
    fn backlog(&self) -> Result<std::sync::MutexGuard<'_, pending::PendingStore>, String> {
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
    fn publication_current(&self) -> Result<(), String> {
        self.commit_guard
            .as_ref()
            .map_or(Ok(()), CommitGuard::check)
    }
    #[cfg(test)]
    pub(crate) fn test_database_full(&self) {
        self.store.limit_current_pages();
    }
    #[cfg(test)]
    pub(crate) fn test_compaction_step(&mut self, records: usize) -> Result<bool, String> {
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
    #[cfg(test)]
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

    fn ensure_live(&self) -> Result<(), String> {
        match self.storage_error() {
            Some(error) => Err(format!("storage halted: {error}")),
            None => Ok(()),
        }
    }
    fn cold<T>(&self, result: Result<T, String>) -> Result<T, String> {
        if let Err(error) = &result
            && error != STALE_COMMIT
        {
            *self.storage_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
        }
        result.map_err(|error| {
            if error == STALE_COMMIT {
                error
            } else {
                format!("storage halted: {error}")
            }
        })
    }
    pub(crate) fn describe(&self, id: ProofId) -> Result<Option<Metadata>, String> {
        self.ensure_live()?;
        let header = self.cold(self.context.proof_header(id).map_err(|e| e.to_string()))?;
        let Some(header) = header else {
            return Ok(None);
        };
        let statement = header.statement_id();
        let conclusion = self
            .cold(
                self.context
                    .proof_formula(header, naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES)
                    .map_err(|e| e.to_string()),
            )?
            .ok_or("checked proof conclusion missing")?;
        let derived = naome_authoring::CompiledQuestion::from_formula(conclusion.into_owned())
            .map_err(|e| e.to_string())?;
        if derived.formula() != derived.positive_target()
            && derived.formula() != derived.negative_target()
        {
            return Err("description statement does not match a question target".into());
        }
        let metadata = Metadata {
            proof_id: crate::hex(id.as_bytes()),
            statement_id: crate::hex(statement.as_bytes()),
            question: format!("goal = {}", derived.core().to_source()),
        };
        Ok(Some(metadata))
    }

    /// Reconstruct empty authenticated roots from bounded owned canonical pages.
    /// Every dependency must already be checked; stored order grants no validity.
    pub fn open(directory: &Path) -> Result<Self, String> {
        Self::open_inner(directory, false)
    }
    fn open_inner(directory: &Path, cleanup: bool) -> Result<Self, String> {
        let store = Arc::new(Store::open(directory)?);
        let summary = store.summary()?;
        let halt = Arc::new(Mutex::new(None));
        let storage = CheckedStorage::open(store.clone(), cleanup, halt.clone())?;
        let mut graph = Self {
            context: DiskArtifactState::new(storage.clone())
                .with_read_cache_limits(
                    naome_checker::ReadCacheLimits::new(
                        crate::resources::limits().checker_cache_entries,
                        crate::resources::limits().checker_cache_bytes,
                    )
                    .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?,
            commit_guard: None,
            #[cfg(test)]
            checks: [const { std::sync::atomic::AtomicU64::new(0) }; 2],
            checked_storage: storage,
            old_generations: Vec::new(),
            next_compaction: crate::resources::limits().checked_cache_bytes,
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
        let mut replay_compaction = crate::resources::limits().checked_cache_bytes;
        #[cfg(test)]
        {
            replay_compaction = storage::startup_test_threshold(replay_compaction);
        }
        loop {
            let page = graph
                .store
                .replay_page(after, crate::resources::limits().replay_page)?;
            if page.is_empty() {
                break;
            }
            graph.cold(graph.checked_storage.begin_write_phase())?;
            for (ordinal, record) in page {
                if ordinal != after.checked_add(1).ok_or("replay ordinal overflow")? {
                    return Err("durable replay order is incomplete".into());
                }
                let candidate = record.prepare()?;
                graph.bytes = graph
                    .bytes
                    .checked_add(candidate.normal.canonical_bytes().len())
                    .ok_or("replayed payload byte overflow")?;
                let mut ready = true;
                for dependency in &candidate.dependencies {
                    if !graph.cold(
                        graph
                            .context
                            .contains_proof(*dependency)
                            .map_err(|e| e.to_string()),
                    )? {
                        ready = false;
                        break;
                    }
                }
                if !ready {
                    return Err("durable graph has missing or cyclic dependencies".into());
                }
                let (context, growth) = graph.check_candidate(candidate)?;
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
            graph.cold(graph.checked_storage.finish_write_phase())?;
            if let Some(live) = graph.prune_startup_checked_storage_at(replay_compaction)? {
                replay_compaction = Self::replay_compaction_threshold(live);
            }
        }
        if graph.count != summary.count
            || after != u64::try_from(summary.count).map_err(|_| "replay count width")?
        {
            return Err("mathematical replay count differs from catalog".into());
        }
        let root = crate::corpus::root(graph.count, graph.context.proof_set_fingerprint())?;
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
    pub(crate) fn maintain_checked_storage(&mut self) -> Result<(), String> {
        self.maintain_checked_storage_at(self.next_compaction)
            .map(|_| ())
    }

    fn replay_compaction_threshold(live: usize) -> usize {
        live.saturating_add(live / 2)
            .max(live.saturating_add(crate::resources::limits().checked_cache_bytes))
    }

    // This call path is exclusive to open_inner, before any checked view escapes.
    // Runtime snapshots and prepared batches still use successor generations.
    fn prune_startup_checked_storage_at(
        &mut self,
        threshold: usize,
    ) -> Result<Option<usize>, String> {
        self.ensure_live()?;
        if self.cold(self.checked_storage.allocated_bytes())? < threshold {
            return Ok(None);
        }
        let live = self.cold(self.checked_storage.prune_startup(&self.context))?;
        self.next_compaction = live
            .saturating_mul(2)
            .max(live.saturating_add(crate::resources::limits().checked_cache_bytes));
        Ok(Some(live))
    }

    fn maintain_checked_storage_at(&mut self, threshold: usize) -> Result<Option<usize>, String> {
        self.maintain_checked_storage_step(
            threshold,
            DiskCopyBudget {
                records: crate::resources::limits().compaction_records,
                bytes: crate::resources::limits().compaction_bytes,
            },
        )
    }

    fn maintain_checked_storage_step(
        &mut self,
        threshold: usize,
        budget: DiskCopyBudget,
    ) -> Result<Option<usize>, String> {
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
                return Err("checked snapshot generation work limit".into());
            }
            let source = self.checked_storage.clone();
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
    ) -> Result<Option<usize>, String> {
        let source = copy.source.clone();
        let mut gate = self.cold(source.write_gate())?;
        self.ensure_live()?;
        if !Arc::ptr_eq(&source, &self.checked_storage) || !gate.matches(copy.epoch, &copy.target) {
            return self.cold(Err("checked copy source epoch or target changed".into()));
        }
        // A copy transaction contains only this bounded quantum. Admissions
        // between quanta use separate per-proof transactions, including mirrors;
        // no corpus-sized transaction reaches finish.
        self.cold(copy.target.begin_write_phase())?;
        let progress = self.cold(
            copy.cursor
                .as_mut()
                .expect("unfinished checked cursor")
                .advance(budget)
                .map_err(|error| error.to_string()),
        )?;
        self.cold(copy.target.finish_write_phase())?;
        if !progress.complete {
            return Ok(None);
        }
        let context = self.cold(
            copy.cursor
                .take()
                .expect("complete checked cursor")
                .finish(&self.context)
                .map_err(|error| error.to_string()),
        )?;
        let live = self.cold(copy.target.allocated_bytes())?;
        let threshold = live
            .saturating_mul(2)
            .max(live.saturating_add(crate::resources::limits().checked_cache_bytes));
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
            return Err(format!("storage halted: {error}"));
        }
        self.old_generations.push(Arc::downgrade(&source));
        self.context = context;
        self.checked_storage = copy.target.clone();
        // Startup keeps its smaller threshold local; ingest retains this one.
        self.next_compaction = threshold;
        Ok(Some(live))
    }

    pub fn author(&self, source: &str) -> Result<Envelope, String> {
        self.ensure_live()?;
        if source.len() > crate::resources::limits().proof_bytes {
            return Err("producer source byte limit".into());
        }
        self.compile_source(source, &self.context)
            .map(Envelope::from_compiled)
    }

    pub fn ingest(&mut self, envelope: Envelope, now: Instant) -> Result<Ingest, String> {
        self.maintain_checked_storage()?;
        let candidate = envelope.prepare()?;
        let id = candidate.id;
        if let Some(existing) = self.binary_object(id)? {
            if existing != candidate.record() {
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
            let persisted = self.backlog()?.insert(&candidate);
            match persisted {
                Err(error)
                    if error == "dependency cycle"
                        || error == "cycle traversal time budget exhausted"
                        || error.starts_with("disk overload") =>
                {
                    return Err(error);
                }
                other => self.cold(other)?,
            }
            let held = self
                .pending
                .values()
                .map(|(candidate, _)| candidate.bytes.len())
                .sum::<usize>();
            if self.pending.len() < crate::resources::limits().pending_page
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
    pub(crate) fn resolve_pending(&mut self) -> Result<PendingResolution, String> {
        self.ensure_live()?;
        self.pending.clear();
        let page = self.backlog()?.next_page();
        let page = match page {
            Err(error) if error.starts_with("memory overload") => {
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
            let id = record.id;
            if self.contains(id)? {
                let removed = self.backlog()?.remove(id);
                self.cold(removed)?;
                continue;
            }
            let candidate = match record.prepare() {
                Ok(candidate) => candidate,
                Err(error)
                    if error.starts_with("memory overload")
                        || error == "proof byte limit"
                        || error == "dependency count limit" =>
                {
                    crate::network::emit(
                        serde_json::json!({"event":"proof_backlog_overload","id":crate::hex(id.as_bytes()),"error":error}),
                    );
                    continue;
                }
                Err(error) => return self.cold(Err(error)),
            };
            if !self.ready(&candidate)? {
                self.pending.insert(id, (candidate, Instant::now()));
                continue;
            }
            match self.admit(candidate) {
                Ok(()) => admitted.push(id),
                Err(error)
                    if error.starts_with("disk overload")
                        || error.starts_with("memory overload")
                        || error == STALE_COMMIT =>
                {
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
        let started = Instant::now();
        loop {
            let mut ready = Vec::new();
            for (id, (candidate, _)) in &self.pending {
                if self.ready(candidate)? {
                    ready.push(*id);
                }
            }
            if ready.is_empty() {
                break;
            }
            for id in ready {
                if started.elapsed() >= crate::resources::limits().request_timeout {
                    return Ok((admitted, rejected));
                }
                let (candidate, _) = self.pending.remove(&id).expect("selected pending record");
                match self.admit(candidate) {
                    Ok(()) => admitted.push(id),
                    Err(error)
                        if error.starts_with("disk overload")
                            || error.starts_with("memory overload")
                            || error == STALE_COMMIT =>
                    {
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
        }
        Ok((admitted, rejected))
    }

    fn ready(&self, candidate: &Candidate) -> Result<bool, String> {
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
    ) -> Result<naome_authoring::CompiledProof, String> {
        #[cfg(test)]
        {
            self.checks[0].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.ensure_live()?;
        naome_authoring::compile_against_proof_context(source, context).map_err(|error| {
            let message = error.to_string();
            if matches!(&error, naome_authoring::CompileError::Check { source, .. }
                if matches!(source.as_ref(), naome_checker::CheckError::ContextAccess { .. }))
            {
                *self.storage_error.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(message.clone());
            }
            message
        })
    }

    fn check_normal(
        &self,
        normal: naome_proof::ProofNormalForm,
        context: &DiskArtifactState,
    ) -> Result<naome_checker::CheckedProof, String> {
        #[cfg(test)]
        {
            self.checks[1].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        check_normal_form_with_state(normal, context).map_err(|error| {
            let message = format!("mathematically invalid: {error}");
            if matches!(error, naome_checker::CheckError::ContextAccess { .. }) {
                *self.storage_error.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(message.clone());
            }
            message
        })
    }

    fn checked_registration(
        &self,
        candidate: Candidate,
    ) -> Result<(naome_checker::CheckedProof, usize), String> {
        self.ensure_live()?;
        let checked = self.check_normal(candidate.normal, &self.context)?;
        if checked.proof_id() != candidate.id || checked.statement_id() != candidate.statement {
            return Err("checked identity mismatch".into());
        }
        let growth = if self.cold(
            self.context
                .contains_statement(checked.statement_id())
                .map_err(|e| e.to_string()),
        )? {
            0
        } else {
            checked
                .conclusion()
                .encode_canonical()
                .map_err(|e| e.to_string())?
                .len()
        };
        Ok((checked, growth))
    }

    fn registered_context(
        &self,
        checked: naome_checker::CheckedProof,
    ) -> Result<DiskArtifactState, String> {
        let mut context = self.context.clone();
        self.cold(
            context
                .register_proof_for_replication(checked)
                .map_err(|e| e.to_string()),
        )?;
        Ok(context)
    }

    fn check_candidate(&self, candidate: Candidate) -> Result<(DiskArtifactState, usize), String> {
        // Replay owns its existing bounded page transaction, never a nested
        // per-admission transaction. Ordinary mathematical rejection is also
        // determined before any new runtime phase is opened.
        let (checked, growth) = self.checked_registration(candidate)?;
        Ok((self.registered_context(checked)?, growth))
    }

    fn admit(&mut self, candidate: Candidate) -> Result<(), String> {
        self.publication_current()?;
        crate::resources::require_disk_space(self.store.directory(), candidate.bytes.len() as u64)?;
        let record = candidate.record();
        let (checked, growth) = self.checked_registration(candidate)?;
        let context_bytes = self
            .context_bytes
            .checked_add(growth)
            .ok_or("checked context byte overflow")?;
        let source = self.checked_storage.clone();
        // The phase guard records every setup failure, including native close
        // errors. Do not overwrite that cleanup evidence through cold().
        let phase = source
            .admission_phase()
            .map_err(|error| format!("storage halted: {error}"))?;
        let context = self.registered_context(checked)?;
        let mut gates = self.cold(phase.finish(self.checked_storage.as_ref()))?;
        let persisted = self.store.persist_binary_batch(
            record.id,
            std::iter::once(&record),
            self.fixed_summary(),
            None,
            crate::corpus::root(
                self.count.checked_add(1).ok_or("accepted count overflow")?,
                context.proof_set_fingerprint(),
            )?,
            self.commit_guard.as_ref(),
        );
        if persisted.as_ref().is_err_and(|error| error == STALE_COMMIT) {
            phase.discarded(&mut gates);
        }
        let summary = self.cold(persisted)?;
        // All fallible preparation precedes the durable transaction. Afterwards
        // publish only fixed roots and scalars; no catalog/context read can fail.
        self.context = context;
        self.context_bytes = context_bytes;
        self.count = summary.count;
        self.bytes = summary.bytes;
        self.root = summary.root;
        phase.published(&mut gates);
        Ok(())
    }

    pub fn pending_count(&self) -> Result<usize, String> {
        self.ensure_live()?;
        self.cold(self.backlog()?.len())
    }
    pub fn pending_ids_after(
        &self,
        after: Option<ProofId>,
        limit: usize,
    ) -> Result<Vec<ProofId>, String> {
        self.ensure_live()?;
        let after = after.map(|id| crate::hex(id.as_bytes()));
        self.cold(self.backlog()?.ids(after.as_deref(), limit))
    }
    pub fn missing(&self) -> Result<BTreeSet<ProofId>, String> {
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
    pub fn pending_ids(&self) -> Result<Vec<ProofId>, String> {
        self.pending_ids_after(None, crate::resources::limits().id_page)
    }
    pub fn storage_error(&self) -> Option<String> {
        self.storage_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn contains(&self, id: ProofId) -> Result<bool, String> {
        self.ensure_live()?;
        let checked = self.cold(self.context.contains_proof(id).map_err(|e| e.to_string()))?;
        let stored = self.cold(self.store.contains(id, self.fixed_summary()))?;
        if checked != stored {
            return self.cold(Err("checked canonical membership differs".into()));
        }
        Ok(checked)
    }
    pub fn waiting(&self, id: ProofId) -> bool {
        self.cold(self.backlog().and_then(|backlog| backlog.contains(id)))
            .unwrap_or(false)
    }
    fn binary_object(&self, id: ProofId) -> Result<Option<crate::object::BinaryProof>, String> {
        self.ensure_live()?;
        let checked = self.cold(self.context.contains_proof(id).map_err(|e| e.to_string()))?;
        let object = self.cold(self.store.get_binary(id, self.fixed_summary()))?;
        if checked != object.is_some() {
            return self.cold(Err("checked canonical membership differs".into()));
        }
        Ok(object)
    }
    pub fn object(&self, id: ProofId) -> Result<Option<Envelope>, String> {
        self.binary_object(id)
            .map(|object| object.map(|object| object.envelope()))
    }
    pub fn ids_page(&self, after: Option<ProofId>, limit: usize) -> Result<Vec<ProofId>, String> {
        self.ensure_live()?;
        if limit == 0 || limit > crate::resources::limits().id_page {
            return Err("inventory page limit".into());
        }
        let expected = self.cold(
            self.context
                .proof_ids_after(after)
                .take(limit)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string()),
        )?;
        let actual = self.cold(self.store.ids_page(after, limit, self.fixed_summary()))?;
        if actual != expected {
            return self.cold(Err("canonical inventory differs from checked set".into()));
        }
        for id in &expected {
            if !self.cold(self.store.contains(*id, self.fixed_summary()))? {
                return self.cold(Err("checked inventory proof missing".into()));
            }
        }
        Ok(expected)
    }
    pub fn content_root(&self) -> [u8; 32] {
        self.root
    }
    pub fn get(&self, id: &str) -> Result<Option<Envelope>, String> {
        self.object(ProofId::from_bytes(id_bytes(id)?))
    }
    #[cfg(test)]
    pub(crate) fn ids(&self) -> Vec<ProofId> {
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
        Self::open_inner(&directory, true).expect("empty test catalog")
    }
}
#[cfg(test)]
mod tests;
