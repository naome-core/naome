use crate::Envelope;
use crate::object::{Candidate, MAX_DEPTH, Metadata, id_bytes};
use crate::store::{Store, Summary};
use naome_checker::{ContextView, DiskArtifactState, check_normal_form_with_state};
use naome_proof::ProofId;
use sha2::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

mod batch;
mod storage;
pub(crate) use batch::CheckedBatch;
use storage::CheckedStorage;

pub const MAX_PENDING: usize = 128;
pub const CHECKED_CACHE_BYTES: usize = storage::HOT_CACHE_BYTES;
pub const PENDING_TTL: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct Ingest {
    pub status: &'static str,
    pub id: ProofId,
    pub admitted: Vec<ProofId>,
    pub rejected: Vec<(ProofId, String)>,
}

type PendingResolution = (Vec<ProofId>, Vec<(ProofId, String)>);

/// The sole acceptance owner for this operating path. Checked state is private.
pub struct Graph {
    context: DiskArtifactState,
    pending: BTreeMap<ProofId, (Candidate, Instant)>,
    count: usize,
    bytes: usize,
    context_bytes: usize,
    root: [u8; 32],
    storage_error: Arc<Mutex<Option<String>>>,
    store: Arc<Store>,
    checked_storage: Arc<CheckedStorage>,
    old_generations: Vec<Weak<CheckedStorage>>,
    next_compaction: usize,
}

impl Graph {
    #[cfg(test)]
    pub(crate) fn test_database_full(&self) {
        self.store.limit_current_pages();
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
        if let Err(error) = &result {
            *self.storage_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
        }
        result.map_err(|error| format!("storage halted: {error}"))
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
                    .statement_formula(statement, naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES)
                    .map_err(|e| e.to_string()),
            )?
            .ok_or("checked proof conclusion missing")?;
        let derived = naome_authoring::CompiledQuestion::compile(&format!(
            "goal = {}",
            conclusion.to_source()
        ))
        .map_err(|e| e.to_string())?;
        let metadata = Metadata {
            proof_id: crate::hex(id.as_bytes()),
            statement_id: crate::hex(statement.as_bytes()),
            question: format!("goal = {}", derived.core().to_source()),
        };
        let _ = metadata.compile()?;
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
            context: DiskArtifactState::new(storage.clone()),
            checked_storage: storage,
            old_generations: Vec::new(),
            next_compaction: CHECKED_CACHE_BYTES,
            pending: BTreeMap::new(),
            count: 0,
            bytes: 0,
            context_bytes: 0,
            root: crate::corpus::start_root_hash(0)?.finalize().into(),
            storage_error: halt,
            store,
        };
        let mut after = 0u64;
        let mut replay_compaction = CHECKED_CACHE_BYTES;
        #[cfg(test)]
        {
            replay_compaction = storage::startup_test_threshold(replay_compaction);
        }
        loop {
            let page = graph.store.replay_page(after, 64)?;
            if page.is_empty() {
                break;
            }
            graph.cold(graph.checked_storage.begin_write_phase())?;
            for (ordinal, envelope) in page {
                if ordinal != after.checked_add(1).ok_or("replay ordinal overflow")? {
                    return Err("durable replay order is incomplete".into());
                }
                let candidate = envelope.prepare()?;
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
        let mut hash = crate::corpus::start_root_hash(graph.count)?;
        let mut checked_count = 0usize;
        for id in graph.context.proof_ids() {
            let id = graph.cold(id.map_err(|e| e.to_string()))?;
            hash.update(id.as_bytes());
            checked_count = checked_count
                .checked_add(1)
                .ok_or("checked replay count overflow")?;
        }
        let root: [u8; 32] = hash.finalize().into();
        if root != summary.root || checked_count != summary.count || graph.bytes != summary.bytes {
            return Err("mathematically replayed corpus differs from catalog".into());
        }
        graph.store.finish_replay(root)?;
        graph.root = root;
        Ok(graph)
    }

    /// Reclaim unreachable copy-on-write nodes without invalidating retained
    /// snapshots. All generations share the single bounded cache.
    pub(crate) fn maintain_checked_storage(&mut self) -> Result<(), String> {
        self.maintain_checked_storage_at(self.next_compaction)
            .map(|_| ())
    }

    fn replay_compaction_threshold(live: usize) -> usize {
        live.saturating_add(live / 2)
            .max(live.saturating_add(CHECKED_CACHE_BYTES))
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
            .max(live.saturating_add(CHECKED_CACHE_BYTES));
        Ok(Some(live))
    }

    fn maintain_checked_storage_at(&mut self, threshold: usize) -> Result<Option<usize>, String> {
        self.ensure_live()?;
        if self.cold(self.checked_storage.allocated_bytes())? < threshold {
            return Ok(None);
        }
        self.old_generations
            .retain(|generation| generation.strong_count() != 0);
        if self.old_generations.len() >= 4 {
            return Err("checked snapshot generation work limit".into());
        }
        let storage = self.cold(self.checked_storage.successor())?;
        self.cold(storage.begin_write_phase())?;
        let context = self.cold(
            self.context
                .copy_to(storage.clone())
                .map_err(|e| e.to_string()),
        )?;
        self.cold(storage.finish_write_phase())?;
        let live = self.cold(storage.allocated_bytes())?;
        let threshold = live
            .saturating_mul(2)
            .max(live.saturating_add(CHECKED_CACHE_BYTES));
        // Copy succeeds completely before the new generation becomes visible.
        self.old_generations
            .push(Arc::downgrade(&self.checked_storage));
        self.context = context;
        self.checked_storage = storage;
        // Startup keeps its smaller threshold local; ingest retains this one.
        self.next_compaction = threshold;
        Ok(Some(live))
    }

    pub fn author(&self, source: &str) -> Result<Envelope, String> {
        self.ensure_live()?;
        if source.len() > crate::MAX_PROOF_BYTES {
            return Err("producer source byte limit".into());
        }
        self.compile_source(source, &self.context)
            .map(Envelope::from_compiled)
    }

    pub fn ingest(&mut self, envelope: Envelope, now: Instant) -> Result<Ingest, String> {
        self.maintain_checked_storage()?;
        let candidate = envelope.prepare()?;
        let id = candidate.id;
        if let Some(existing) = self.object(id)? {
            if existing != candidate.envelope {
                return Err("proof identity collision".into());
            }
            return Ok(Ingest {
                status: "duplicate",
                id,
                admitted: Vec::new(),
                rejected: Vec::new(),
            });
        }
        if self.pending.contains_key(&id) {
            return Ok(Ingest {
                status: "waiting_duplicate",
                id,
                admitted: Vec::new(),
                rejected: Vec::new(),
            });
        }
        if !self.ready(&candidate)? {
            if self.pending.len() >= MAX_PENDING {
                return Err("pending capacity".into());
            }
            self.require_acyclic(&candidate)?;
            self.pending.insert(id, (candidate, now));
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

    /// Existing deferred local-owner ingestion, separate from peer staging.
    pub(crate) fn resolve_pending(&mut self) -> Result<PendingResolution, String> {
        self.ensure_live()?;
        let mut admitted = Vec::new();
        let mut rejected = Vec::new();
        // Each candidate is removed once. No asynchronous checker queue or busy polling.
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
                let (candidate, _) = self
                    .pending
                    .remove(&id)
                    .expect("selected pending candidate");
                match self.admit(candidate) {
                    Ok(()) => admitted.push(id),
                    Err(error) => {
                        if self.storage_error().is_some() {
                            return Err(error);
                        }
                        rejected.push((id, error));
                    }
                }
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
        check_normal_form_with_state(normal, context).map_err(|error| {
            let message = format!("mathematically invalid: {error}");
            if matches!(error, naome_checker::CheckError::ContextAccess { .. }) {
                *self.storage_error.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(message.clone());
            }
            message
        })
    }

    fn check_candidate(&self, candidate: Candidate) -> Result<(DiskArtifactState, usize), String> {
        self.ensure_live()?;
        let mut depth = 0usize;
        for id in &candidate.dependencies {
            let parent = self
                .cold(
                    self.context
                        .proof_dependency_depth(*id)
                        .map_err(|e| e.to_string()),
                )?
                .ok_or("missing checked dependency")?;
            depth = depth.max(parent);
        }
        let depth = depth.checked_add(1).ok_or("dependency depth overflow")?;
        if depth > MAX_DEPTH {
            return Err("dependency depth limit".into());
        }
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
        let mut context = self.context.clone();
        self.cold(
            context
                .register_proof_for_replication(checked)
                .map_err(|e| e.to_string()),
        )?;
        Ok((context, growth))
    }

    fn admit(&mut self, candidate: Candidate) -> Result<(), String> {
        let envelope = candidate.envelope.clone();
        let (context, growth) = self.check_candidate(candidate)?;
        let context_bytes = self
            .context_bytes
            .checked_add(growth)
            .ok_or("checked context byte overflow")?;
        let summary = self.cold(self.store.persist_checked(&envelope, self.fixed_summary()))?;
        // All fallible preparation precedes the durable transaction. Afterwards
        // publish only fixed roots and scalars; no catalog/context read can fail.
        self.context = context;
        self.context_bytes = context_bytes;
        self.count = summary.count;
        self.bytes = summary.bytes;
        self.root = summary.root;
        Ok(())
    }

    fn require_acyclic(&self, candidate: &Candidate) -> Result<(), String> {
        let mut queue: Vec<_> = candidate.dependencies.iter().copied().collect();
        let mut seen = BTreeSet::new();
        while let Some(id) = queue.pop() {
            if id == candidate.id {
                return Err("dependency cycle".into());
            }
            if seen.insert(id)
                && let Some((parent, _)) = self.pending.get(&id)
            {
                queue.extend(parent.dependencies.iter().copied());
            }
        }
        Ok(())
    }

    pub fn expire(&mut self, now: Instant) -> Vec<ProofId> {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(id, (_, since))| {
                (now.saturating_duration_since(*since) >= PENDING_TTL).then_some(*id)
            })
            .collect();
        for id in &expired {
            self.pending.remove(id);
        }
        expired
    }

    pub fn missing(&self) -> Result<BTreeSet<ProofId>, String> {
        let mut missing = BTreeSet::new();
        for (candidate, _) in self.pending.values() {
            for id in &candidate.dependencies {
                if !self.pending.contains_key(id) && !self.contains(*id)? {
                    missing.insert(*id);
                }
            }
        }
        Ok(missing)
    }
    pub fn pending_ids(&self) -> Vec<ProofId> {
        self.pending.keys().copied().collect()
    }
    pub fn storage_error(&self) -> Option<String> {
        self.storage_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn contains(&self, id: ProofId) -> Result<bool, String> {
        self.object(id).map(|object| object.is_some())
    }
    pub fn waiting(&self, id: ProofId) -> bool {
        self.pending.contains_key(&id)
    }
    pub fn object(&self, id: ProofId) -> Result<Option<Envelope>, String> {
        self.ensure_live()?;
        let checked = self.cold(self.context.contains_proof(id).map_err(|e| e.to_string()))?;
        // Validate the canonical record once, returning the same owned bytes
        // used for the checked/canonical membership comparison.
        let object = self.cold(self.store.get(id, self.fixed_summary()))?;
        if checked != object.is_some() {
            return self.cold(Err("checked canonical membership differs".into()));
        }
        Ok(object)
    }
    pub fn ids_page(&self, after: Option<ProofId>, limit: usize) -> Result<Vec<ProofId>, String> {
        self.ensure_live()?;
        if limit == 0 || limit > 128 {
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
