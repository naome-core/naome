//! Bounded node-owned source work. Provider processes receive only handles.
use super::snapshot::{Seed, Store};
use crate::{generation, jobs};
use naome_checker::question::PrefilterPolicy;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Duration,
};
use tokio::sync::oneshot;

/// Coalesced canonical-write notification. Queue saturation cannot lose the
/// latest source; startup capture closes a crash between commit and notification.
#[derive(Clone, Default)]
pub(crate) struct IndexFeed(Arc<Mutex<Option<Seed>>>);
impl IndexFeed {
    pub(crate) fn publish(&self, seed: Seed) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(seed);
    }
}

/// Query cleanup is acknowledged independently of the document-work queue.
/// A pending call owns no model; an active call must finish its own host first.
#[derive(Default)]
pub(super) struct QueryControl(Mutex<QueryState>);
#[derive(Default)]
struct QueryState {
    cancelled: bool,
    active: bool,
    error: Option<String>,
}
pub(super) struct QueryActivity(Arc<QueryControl>);
impl Drop for QueryActivity {
    fn drop(&mut self) {
        self.0.0.lock().unwrap_or_else(|e| e.into_inner()).active = false;
    }
}
impl QueryControl {
    fn retain(&self) -> bool {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.active || state.error.is_some()
    }
    pub fn cancelled(&self) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).cancelled
    }
    pub fn begin(self: &Arc<Self>) -> Result<QueryActivity, String> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.cancelled {
            return Err("retrieval query already cancelled".into());
        }
        if state.active {
            return Err("retrieval query control already active".into());
        }
        state.active = true;
        Ok(QueryActivity(self.clone()))
    }
    pub fn uncertain(&self, error: String) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).error = Some(error);
    }
}

pub(crate) struct Preparation {
    pub input: jobs::Input,
    pub binding: jobs::Binding,
    pub seed: Seed,
    pub owner: generation::OwnerContext,
    pub policy: PrefilterPolicy,
}
enum Work {
    Prepare(
        Preparation,
        oneshot::Sender<Result<generation::Request, String>>,
    ),
    Ensure(
        generation::Request,
        oneshot::Sender<Result<generation::Request, String>>,
    ),
    Invoke(
        generation::Request,
        String,
        serde_json::Value,
        jobs::RetrievalBudget,
        Arc<QueryControl>,
        oneshot::Sender<Result<generation::ToolResult, String>>,
    ),
}
#[derive(Clone)]
pub(crate) struct Client {
    sender: mpsc::SyncSender<Work>,
    pins: Arc<Mutex<BTreeSet<String>>>,
    queries: Arc<Mutex<BTreeMap<u64, Arc<QueryControl>>>>,
}
pub(crate) struct Service {
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), String>>>,
}
impl Service {
    #[cfg(test)]
    pub fn open(directory: &Path, retained: BTreeSet<String>) -> Result<(Self, Client), String> {
        Self::open_with_retrieval(directory, retained, None)
    }
    #[cfg(test)]
    pub fn open_with_retrieval(
        directory: &Path,
        retained: BTreeSet<String>,
        settings: Option<super::cache::Settings>,
    ) -> Result<(Self, Client), String> {
        Self::open_with_feed(directory, retained, settings, IndexFeed::default())
    }
    pub fn open_with_feed(
        directory: &Path,
        retained: BTreeSet<String>,
        settings: Option<super::cache::Settings>,
        feed: IndexFeed,
    ) -> Result<(Self, Client), String> {
        let store = Store::open(directory)?;
        let cursor_key = store.cursor_key()?;
        let (sender, receiver) = mpsc::sync_channel(8);
        let pins = Arc::new(Mutex::new(retained));
        let stopped = Arc::new(AtomicBool::new(false));
        let halt = stopped.clone();
        let mut engine = super::retrieval::Engine::open(directory, settings, stopped.clone())?;
        let retained = pins.clone();
        let thread = std::thread::Builder::new()
            .name("naome-retrieval-source".into())
            .spawn(move || {
                let mut live: BTreeMap<String, Vec<Weak<super::snapshot::Frozen>>> =
                    BTreeMap::new();
                let mut next_reconcile = std::time::Instant::now();
                let mut next_repair = std::time::Instant::now() + Duration::from_secs(30);
                while !halt.load(Ordering::Acquire) {
                    let seed = if std::time::Instant::now() >= next_reconcile {
                        feed.0.lock().unwrap_or_else(|e| e.into_inner()).take()
                    } else { None };
                    if let Some(seed) = seed
                        && let Err(error) = seed.clone().freeze().and_then(|source| engine.reconcile(Arc::new(source))) {
                            let mut latest = feed.0.lock().unwrap_or_else(|e| e.into_inner());
                            if latest.is_none() { *latest = Some(seed); }
                            next_reconcile = std::time::Instant::now() + Duration::from_secs(1);
                            crate::network::emit(serde_json::json!({"event":"retrieval_storage_reconcile_failed","error":error}));
                    }
                    if std::time::Instant::now() >= next_repair {
                        next_repair = std::time::Instant::now() + Duration::from_secs(30);
                        if let Err(error) = engine.repair() { crate::network::emit(serde_json::json!({"event":"retrieval_index_repair_failed","error":error})); }
                    }
                    let work = if engine.pending() {
                        match receiver.try_recv() {
                            Ok(work) => Some(work),
                            Err(mpsc::TryRecvError::Empty) => None,
                            Err(mpsc::TryRecvError::Disconnected) => break,
                        }
                    } else {
                        match receiver.recv_timeout(Duration::from_millis(100)) {
                            Ok(work) => Some(work),
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    };
                    let Some(work) = work else {
                        engine.step();
                        continue;
                    };
                    let mut pins = retained.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    live.retain(|id, sources| {
                        sources.retain(|source| source.strong_count() > 0);
                        if !sources.is_empty() {
                            pins.insert(id.clone());
                            true
                        } else {
                            false
                        }
                    });
                    match work {
                        Work::Prepare(preparation, reply) => {
                            if reply.is_closed() {
                                continue;
                            }
                            let result = (|| {
                                store.collect(&pins)?;
                                engine.collect(&pins)?;
                                let frozen = Arc::new(preparation.seed.freeze()?);
                                let mut request = generation::Request::build_from_snapshot(
                                    &preparation.input,
                                    &preparation.binding,
                                    frozen,
                                    preparation.owner,
                                    preparation.policy,
                                )?;
                                request.attach_cursor_key(cursor_key.clone());
                                request.persist_source(&store)?;
                                let source = request.source()?;
                                engine.observe(source)?;
                                let instances =
                                    live.entry(source.handle().snapshot_id.clone()).or_default();
                                let weak = Arc::downgrade(source);
                                if !instances.iter().any(|existing| existing.ptr_eq(&weak)) {
                                    instances.push(weak);
                                }
                                Ok(request)
                            })();
                            let _ = reply.send(result);
                        }
                        Work::Ensure(mut request, reply) => {
                            if reply.is_closed() {
                                continue;
                            }
                            let result = (|| {
                                // The supplied Arc holds custody while publication is pending.
                                if let Some(handle) = &request.retrieval_snapshot {
                                    if request.source().is_err() {
                                        return Err(
                                            "generation private source custody absent".into()
                                        );
                                    }
                                    // Protect already published matching source before collection.
                                    if live.contains_key(&handle.snapshot_id) {
                                        pins.insert(handle.snapshot_id.clone());
                                    }
                                }
                                store.collect(&pins)?;
                                engine.collect(&pins)?;
                                request.attach_cursor_key(cursor_key.clone());
                                request.persist_source(&store)?;
                                let source = request.source()?;
                                engine.observe(source)?;
                                let instances =
                                    live.entry(source.handle().snapshot_id.clone()).or_default();
                                let weak = Arc::downgrade(source);
                                if !instances.iter().any(|existing| existing.ptr_eq(&weak)) {
                                    instances.push(weak);
                                }
                                Ok(request)
                            })();
                            let _ = reply.send(result);
                        }
                        Work::Invoke(request, name, arguments, budget, control, reply) => {
                            if !reply.is_closed() {
                                engine.enqueue(super::retrieval::Invocation {
                                    request,
                                    name,
                                    arguments,
                                    budget,
                                    control,
                                    reply,
                                });
                            }
                        }
                    }
                    engine.step();
                }
                let cleanup = engine.stop();
                if let Err(error) = &cleanup {
                    crate::network::emit(
                        serde_json::json!({"event":"retrieval_cleanup_failed","error":error}),
                    );
                }
                cleanup
            })
            .map_err(|e| e.to_string())?;
        Ok((
            Self {
                stopped,
                thread: Some(thread),
            },
            Client {
                sender,
                pins,
                queries: Default::default(),
            },
        ))
    }
}
impl Service {
    pub(crate) fn begin_shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
    }
    pub fn shutdown(&mut self) -> Result<(), String> {
        self.begin_shutdown();
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| "retrieval source owner panicked".to_owned())?,
            None => Ok(()),
        }
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            crate::network::emit(
                serde_json::json!({"event":"retrieval_cleanup_failed","error":error}),
            );
        }
    }
}
impl Client {
    pub async fn prepare(&self, preparation: Preparation) -> Result<generation::Request, String> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(Work::Prepare(preparation, reply))
            .map_err(|_| "retrieval source queue capacity or stopped")?;
        response
            .await
            .map_err(|_| "retrieval source preparation stopped")?
    }
    pub async fn ensure(
        &self,
        request: generation::Request,
    ) -> Result<generation::Request, String> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(Work::Ensure(request, reply))
            .map_err(|_| "retrieval source queue capacity or stopped")?;
        response
            .await
            .map_err(|_| "retrieval source publication stopped")?
    }
    pub async fn invoke(
        &self,
        request: generation::Request,
        name: String,
        arguments: serde_json::Value,
        budget: jobs::RetrievalBudget,
    ) -> Result<generation::ToolResult, String> {
        let (reply, response) = oneshot::channel();
        let control = {
            let mut queries = self.queries.lock().unwrap_or_else(|e| e.into_inner());
            queries.retain(|_, control| Arc::strong_count(control) > 1 || control.retain());
            if queries.len() >= 8 && !queries.contains_key(&budget.id) {
                return Err("retrieval query control capacity".into());
            }
            queries.entry(budget.id).or_default().clone()
        };
        self.sender
            .try_send(Work::Invoke(
                request, name, arguments, budget, control, reply,
            ))
            .map_err(|_| "retrieval tool queue capacity or stopped")?;
        response
            .await
            .map_err(|_| "retrieval tool source stopped")?
    }
    pub async fn cancel_job(&self, id: u64) -> Result<(), String> {
        let control = self
            .queries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .cloned();
        let Some(control) = control else {
            return Ok(());
        };
        loop {
            {
                let mut state = control.0.lock().unwrap_or_else(|e| e.into_inner());
                state.cancelled = true;
                if !state.active {
                    return state.error.clone().map_or(Ok(()), Err);
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    /// Every retained record pins its source, including acknowledged terminal
    /// history and InDoubt. Pending/live requests also hold a node-owned Arc.
    pub fn update_pins(&self, pins: BTreeSet<String>) {
        *self.pins.lock().unwrap_or_else(|e| e.into_inner()) = pins;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unserved_client(control: Arc<QueryControl>) -> (Client, mpsc::Receiver<Work>) {
        let (sender, receiver) = mpsc::sync_channel(1);
        let client = Client {
            sender,
            pins: Default::default(),
            queries: Arc::new(Mutex::new(BTreeMap::from([(1, control)]))),
        };
        (client, receiver)
    }
    #[tokio::test]
    async fn pending_query_cancellation_does_not_wait_for_the_document_queue() {
        let control = Arc::new(QueryControl::default());
        let (client, _blocked_document_queue) = unserved_client(control.clone());
        tokio::time::timeout(Duration::from_millis(20), client.cancel_job(1))
            .await
            .unwrap()
            .unwrap();
        assert!(control.cancelled());
        assert!(control.begin().is_err());
    }
    #[tokio::test]
    async fn active_query_cancellation_waits_for_owned_cleanup_and_preserves_uncertainty() {
        let control = Arc::new(QueryControl::default());
        let activity = control.begin().unwrap();
        let (client, _blocked_document_queue) = unserved_client(control.clone());
        let cancellation = tokio::spawn(async move { client.cancel_job(1).await });
        tokio::task::yield_now().await;
        assert!(!cancellation.is_finished());
        control.uncertain("owned query group absence unconfirmed".into());
        drop(activity);
        assert!(
            cancellation
                .await
                .unwrap()
                .unwrap_err()
                .contains("absence unconfirmed")
        );
    }
    #[tokio::test]
    async fn inactive_uncertain_query_receipt_survives_later_control_collection() {
        let control = Arc::new(QueryControl::default());
        let activity = control.begin().unwrap();
        control.uncertain("owned query group absence unconfirmed".into());
        drop(activity);
        let (client, _blocked_document_queue) = unserved_client(control.clone());
        drop(control);
        let graph = crate::Graph::default();
        let policy = PrefilterPolicy::default();
        let binding = jobs::Binding::new([0; 32], policy.identity());
        let request = generation::Request::build(
            &jobs::Input::Find { cursor: 0 },
            &binding,
            &graph,
            generation::OwnerContext::Unavailable {
                reason: "query cleanup fixture".into(),
            },
        )
        .unwrap();
        let (budget, _reservations) = jobs::RetrievalBudget::unserved_test(
            2,
            request.identity(),
            std::time::Instant::now() + Duration::from_secs(1),
        );
        let later = client.invoke(request, "fetch".into(), serde_json::json!({}), budget);
        tokio::pin!(later);
        tokio::select! { result = &mut later => panic!("unserved queue unexpectedly completed: {result:?}"), _=tokio::task::yield_now()=>{} }
        // Actual invoke registration/collection ran while its work queue stayed
        // unserved, exactly where the previous error tombstone was discarded.
        assert!(
            client
                .cancel_job(1)
                .await
                .unwrap_err()
                .contains("absence unconfirmed")
        );
    }
    #[tokio::test]
    async fn every_live_instance_protects_a_pending_source_from_collection() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = Directory(std::env::temp_dir().join(format!(
            "naome-source-live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let (_service, client) = Service::open(&directory.0, BTreeSet::new()).unwrap();
        let policy = PrefilterPolicy::default();
        let binding = jobs::Binding::new([0; 32], policy.identity());
        let mut graph = crate::Graph::default();
        let build = |graph: &crate::Graph, cursor| {
            generation::Request::build(
                &jobs::Input::Find { cursor },
                &binding,
                graph,
                generation::OwnerContext::Unavailable {
                    reason: "live source fixture".into(),
                },
            )
            .unwrap()
        };
        let first = client.ensure(build(&graph, 0)).await.unwrap();
        let second = client.ensure(build(&graph, 1)).await.unwrap();
        assert_eq!(first.retrieval_snapshot, second.retrieval_snapshot);
        assert!(!Arc::ptr_eq(
            first.source().unwrap(),
            second.source().unwrap()
        ));
        drop(second);
        let proof = graph
            .author("goal=all(x,eq(x,x)) proof: a=refl(x) b=gen(a,x) return b")
            .unwrap();
        graph.ingest(proof, std::time::Instant::now()).unwrap();
        let _other = client.ensure(build(&graph, 2)).await.unwrap();
        let store = Store::open(&directory.0).unwrap();
        assert_eq!(
            store
                .load(first.retrieval_snapshot.as_ref().unwrap())
                .unwrap()
                .handle(),
            first.retrieval_snapshot.as_ref().unwrap()
        );
    }
}
