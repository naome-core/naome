//! Semantic calls consume prepared document indexes. Only genuinely new query
//! text can acquire query-sponsored inference; indexing is owned by writes.
use super::{
    cache::{Cache, Settings},
    host::Host,
    indexing,
    local::LocalEncoder,
    semantic::SemanticIndex,
    snapshot::Frozen,
};
use crate::{generation, jobs};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
pub(super) struct Invocation {
    pub request: generation::Request,
    pub name: String,
    pub arguments: Value,
    pub budget: jobs::RetrievalBudget,
    pub control: Arc<super::service::QueryControl>,
    pub reply: oneshot::Sender<Result<generation::ToolResult, String>>,
}

#[cfg(test)]
mod tests;
struct Task {
    call: Invocation,
    query: String,
    top_k: u16,
    window: String,
}
pub(super) struct Engine {
    settings: Option<Settings>,
    cache: Option<Result<Cache, String>>,
    tasks: VecDeque<Task>,
    indexes: BTreeMap<String, Arc<SemanticIndex>>,
    observed: BTreeMap<String, Weak<Frozen>>,
    indexer: indexing::Owner,
    index_turn: bool,
    stopped: Arc<AtomicBool>,
    cleanup_error: Option<String>,
}
impl Engine {
    pub fn open(
        directory: &Path,
        settings: Option<Settings>,
        stopped: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        if let Some(settings) = &settings {
            settings.validate()?;
        }
        let cache = settings.as_ref().map(|_| Cache::open(directory));
        Ok(Self {
            settings,
            cache,
            tasks: VecDeque::new(),
            indexes: BTreeMap::new(),
            observed: BTreeMap::new(),
            indexer: indexing::Owner::new(stopped.clone()),
            index_turn: true,
            stopped,
            cleanup_error: None,
        })
    }
    fn cache(&self) -> Result<&Cache, String> {
        match &self.cache {
            Some(Ok(cache)) => Ok(cache),
            Some(Err(error)) => Err(error.clone()),
            None => Err("retrieval encoder is not configured".into()),
        }
    }
    pub fn pending(&self) -> bool {
        self.cleanup_error.is_none() && (!self.tasks.is_empty() || self.indexer.pending())
    }
    pub fn reconcile(&mut self, source: Arc<Frozen>) -> Result<(), String> {
        if self.settings.is_some() {
            let cache = self
                .cache
                .as_ref()
                .ok_or("retrieval cache absent")?
                .as_ref()
                .map_err(Clone::clone)?;
            self.indexer.reconcile(source, cache)?;
            self.assemble_observed()?;
        }
        Ok(())
    }
    pub fn observe(&mut self, source: &Arc<Frozen>) -> Result<(), String> {
        if self.settings.is_some() {
            self.observed.retain(|_, source| source.strong_count() > 0);
            self.observed
                .insert(source.handle().snapshot_id.clone(), Arc::downgrade(source));
            if let Err(error) = self.assemble_observed() {
                // Derived availability never invalidates the successfully
                // published canonical source or its exact/native tools.
                crate::network::emit(
                    serde_json::json!({"event":"retrieval_source_index_unavailable","error":error}),
                );
            }
        }
        Ok(())
    }
    fn assemble_observed(&self) -> Result<(), String> {
        for source in self.observed.values().filter_map(Weak::upgrade) {
            let complete = self.cache()?.assemble(&source)?;
            self.cache()?.progress(
                &source,
                if complete { "complete" } else { "pending" },
                if complete {
                    source.corpus().references.len()
                } else {
                    0
                },
                None,
            )?;
        }
        Ok(())
    }
    pub fn enqueue(&mut self, call: Invocation) {
        let result = (|| {
            if call.control.cancelled() {
                return Err("retrieval query cancelled before admission".into());
            }
            if let Some(error) = &self.cleanup_error {
                return Err(error.clone());
            }
            if call.budget.request_id != call.request.identity() || call.budget.id == 0 {
                return Err("retrieval sponsor request binding differs".into());
            }
            let plan = call.request.semantic_query(&call.name, &call.arguments)?;
            if plan.is_none()
                || self.settings.is_none()
                || call.request.source()?.corpus().references.is_empty()
            {
                return Ok(Some(call.request.invoke_tool(&call.name, &call.arguments)?));
            }
            if let Err(error) = self.cache() {
                return Ok(Some(call.request.incomplete_tool(
                    &call.name,
                    &call.arguments,
                    &error,
                )?));
            }
            let (query, top_k, after) = plan.expect("semantic plan");
            let source = call.request.source()?;
            let window = crate::hex(&Sha256::digest(
                serde_json::to_vec(&(
                    "naome:ranked-window:v3",
                    call.request.identity(),
                    source.handle(),
                    &query,
                    top_k,
                    LocalEncoder::identity_specification(),
                ))
                .expect("finite window key"),
            ));
            if let Some(ranking) = self.cache()?.ranking(&window)? {
                let index=match self.indexes.get(&source.handle().snapshot_id) {
                    Some(index)=>index.clone(),
                    None=>Arc::new(self.cache()?.index(source)?.ok_or("saved semantic window complete index is missing; refusing replacement inference")?),
                };
                index.validate_ranking(source, &query, top_k, &ranking)?;
                if index.encoder_identity() != &LocalEncoder::identity_specification() {
                    return Err("saved semantic window encoder differs".into());
                }
                if self.indexes.len() >= 2 {
                    self.indexes.clear();
                }
                self.indexes
                    .insert(source.handle().snapshot_id.clone(), index);
                return Ok(Some(call.request.invoke_tool_with_ranking(
                    &call.name,
                    &call.arguments,
                    ranking,
                )?));
            }
            if after {
                return Err("semantic continuation ranked window is missing; refusing replacement or fresh inference".into());
            }
            if self.tasks.len() >= 8
                || self
                    .tasks
                    .iter()
                    .any(|task| task.call.budget.id == call.budget.id)
            {
                return Err("retrieval pending job or call capacity".into());
            }
            Ok(None)
        })();
        match result {
            Ok(Some(result)) => {
                let _ = call.reply.send(Ok(result));
            }
            Err(error) => {
                let _ = call.reply.send(Err(error));
            }
            Ok(None) => {
                let (query, top_k, _) = call
                    .request
                    .semantic_query(&call.name, &call.arguments)
                    .expect("checked semantic call")
                    .expect("semantic query");
                let source = call.request.source().expect("checked source");
                let window = crate::hex(&Sha256::digest(
                    serde_json::to_vec(&(
                        "naome:ranked-window:v3",
                        call.request.identity(),
                        source.handle(),
                        &query,
                        top_k,
                        LocalEncoder::identity_specification(),
                    ))
                    .expect("finite window key"),
                ));
                self.tasks.push_back(Task {
                    call,
                    query,
                    top_k,
                    window,
                });
            }
        }
    }
    pub fn step(&mut self) {
        if self.cleanup_error.is_some() {
            return;
        }
        if self.indexer.pending() && (self.index_turn || self.tasks.is_empty()) {
            self.index_turn = false;
            let result = (|| {
                let cache = self
                    .cache
                    .as_ref()
                    .ok_or("retrieval cache absent")?
                    .as_ref()
                    .map_err(Clone::clone)?;
                self.indexer.step(
                    cache,
                    self.settings.as_ref().ok_or("retrieval settings absent")?,
                )?;
                self.assemble_observed()
            })();
            if let Err(error) = result {
                if let Some(cleanup) = self.indexer.cleanup_error() {
                    self.cleanup_error = Some(cleanup.into());
                    self.fail_remaining(&error);
                }
                crate::network::emit(
                    serde_json::json!({"event":"retrieval_index_work_failed","error":error}),
                );
            }
            return;
        }
        self.index_turn = true;
        let Some(task) = self.tasks.pop_front() else {
            return;
        };
        let activity = task.call.control.begin();
        let halt = self.stopped.clone();
        let stopped = || {
            halt.load(Ordering::Acquire)
                || task.call.control.cancelled()
                || task.call.reply.is_closed()
                || Instant::now() >= task.call.budget.deadline
        };
        let result = (|| {
            let _activity = activity?;
            if stopped() {
                return Err("retrieval query cancelled or expired".into());
            }
            let source = task.call.request.source()?.clone();
            // No row scanning, document tokenization or backfill is admitted here.
            let index =
                match self.indexes.get(&source.handle().snapshot_id) {
                    Some(index) => index.clone(),
                    None => Arc::new(self.cache()?.index(&source)?.ok_or(
                        "document indexing is pending or failed; semantic index unavailable",
                    )?),
                };
            let stored = source.stored_query(&task.query)?.or(self
                .indexer
                .source()
                .map(|catalog| catalog.stored_query(&task.query))
                .transpose()?
                .flatten());
            let vector_query = stored.as_deref().unwrap_or(&task.query);
            let vector = match self.cache()?.query(vector_query)? {
                Some(vector) => vector,
                None if stored.is_some() => {
                    return Err(
                        "stored question indexing is pending or failed; query vector unavailable"
                            .into(),
                    );
                }
                None => {
                    let settings = self.settings.clone().ok_or("retrieval settings absent")?;
                    let deadline = task.call.budget.deadline.min(
                        Instant::now()
                            + Duration::from_millis(
                                settings.quantum_ms.saturating_sub(2_500).max(1),
                            ),
                    );
                    let cancelled = || stopped() || Instant::now() >= deadline;
                    task.call.budget.reserve("model_load", &cancelled)?;
                    let lease = self.cache()?.model_lock()?;
                    let mut host =
                        Host::start(settings, lease, &cancelled, deadline).map_err(|failure| {
                            if failure.cleanup_uncertain {
                                self.cleanup_error = Some(failure.message.clone());
                                task.call.control.uncertain(failure.message.clone());
                            }
                            failure.message
                        })?;
                    let encoded = (|| {
                        task.call.budget.reserve("query_tokenize", &cancelled)?;
                        task.call.budget.reserve("query_encode", &cancelled)?;
                        host.query(task.query.clone(), &cancelled, deadline)
                    })();
                    let cleanup = host.finish();
                    if let Err(error) = &cleanup {
                        self.cleanup_error = Some(error.clone());
                        task.call.control.uncertain(error.clone());
                    }
                    let vector = encoded.and_then(|vector| cleanup.map(|()| vector))?;
                    if stopped() {
                        return Err("retrieval query cancelled before vector publication".into());
                    }
                    self.cache()?.save_query(&task.query, vector.clone())?;
                    vector
                }
            };
            let ranking = index.search_vector(&source, &task.query, task.top_k, &vector)?;
            if stopped() {
                return Err("retrieval cancelled before ranked window publication".into());
            }
            self.cache()?.save_ranking(&task.window, &ranking)?;
            if self.indexes.len() >= 2 {
                self.indexes.clear();
            }
            self.indexes
                .insert(source.handle().snapshot_id.clone(), index);
            task.call.request.invoke_tool_with_ranking(
                &task.call.name,
                &task.call.arguments,
                ranking,
            )
        })();
        let result = result.or_else(|error| {
            task.call
                .request
                .incomplete_tool(&task.call.name, &task.call.arguments, &error)
        });
        let _ = task.call.reply.send(result);
        if let Some(error) = self.cleanup_error.clone() {
            self.fail_remaining(&error);
        }
    }
    fn fail_remaining(&mut self, reason: &str) {
        while let Some(task) = self.tasks.pop_front() {
            let result =
                task.call
                    .request
                    .incomplete_tool(&task.call.name, &task.call.arguments, reason);
            let _ = task.call.reply.send(result);
        }
    }
    pub fn stop(&mut self) -> Result<(), String> {
        self.fail_remaining("retrieval service stopped");
        self.cleanup_error.clone().map_or(Ok(()), Err)
    }
    pub fn repair(&mut self) -> Result<(), String> {
        if self.cleanup_error.is_some() || self.indexer.pending() {
            return Ok(());
        }
        if let Some(source) = self.indexer.source().cloned() {
            self.reconcile(source)?;
        }
        Ok(())
    }
    pub fn collect(&self, pins: &BTreeSet<String>) -> Result<(), String> {
        let mut pins = pins.clone();
        pins.extend(self.tasks.iter().filter_map(|task| {
            task.call
                .request
                .retrieval_snapshot
                .as_ref()
                .map(|handle| handle.snapshot_id.clone())
        }));
        pins.extend(
            self.observed
                .iter()
                .filter(|(_, source)| source.strong_count() > 0)
                .map(|(id, _)| id.clone()),
        );
        let mut rows = BTreeSet::new();
        if let Some(source) = self.indexer.source() {
            pins.insert(source.handle().snapshot_id.clone());
            for reference in &source.corpus().references {
                let content = source.semantic_content(&reference.proof.proof_id)?;
                rows.insert(super::semantic::SourceVectorRow::key(
                    &LocalEncoder::identity_specification(),
                    &reference.proof.proof_id,
                    &content,
                ));
            }
        }
        if self.settings.is_some()
            && let Err(error) = self
                .cache()
                .and_then(|cache| cache.collect_with_rows(&pins, &rows))
        {
            crate::network::emit(
                serde_json::json!({"event":"retrieval_cache_gc_failed","error":error}),
            );
        }
        Ok(())
    }
}
