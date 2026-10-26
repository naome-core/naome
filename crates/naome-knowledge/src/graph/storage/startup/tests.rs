use super::*;
use crate::resources::adaptive::{self, Budget, Observed, Selection, Snapshot};
use naome_checker::ContextView;
use std::{cell::Cell, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cut {
    Mark,
    Flush,
    Commit,
}
thread_local! { static CUT:Cell<Option<Cut>>=const{Cell::new(None)}; }
pub(super) fn at_stage(stage: Cut) -> Result<(), String> {
    if std::env::var("NAOME_STARTUP_EXIT_CUT").as_deref() == Ok("flush") && stage == Cut::Flush {
        std::process::exit(85);
    }
    if CUT.get() == Some(stage) {
        Err(format!("injected startup {stage:?} failure"))
    } else {
        Ok(())
    }
}
fn isolated(case: &str) -> bool {
    if std::env::var("NAOME_STARTUP_BUFFER_CASE").as_deref() == Ok(case) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", case, "--nocapture"])
        .env("NAOME_STARTUP_BUFFER_CASE", case)
        .output()
        .unwrap();
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}
fn budget(cache: usize) {
    let capacity = crate::resources::limits().memory_bytes as u64;
    adaptive::publish(Snapshot {
        selection: Selection::default(),
        budget: Budget {
            memory_bytes: capacity,
            concurrency: 1,
            cache_bytes: cache as u64,
            batch_steps: 64,
            network_requests: 1,
            yield_ms: 0,
            paused: None,
        },
        observed: Observed {
            memory_total: capacity,
            memory_available: capacity,
            memory_limit: capacity,
            process_rss: 0,
            peak_rss: 0,
            process_cpu_ms: 0,
            cpu_millis: 1000,
            load_millis: 0,
            disk_available: u64::MAX,
        },
        timestamp_ms: 0,
        pid: std::process::id(),
    });
}
fn object(graph: &crate::Graph, parent: Option<&crate::Envelope>) -> crate::Envelope {
    let source = parent
        .map(|p| {
            format!(
                "goal=all(x,eq(x,x)) proof:p0=cite(\"{}\") return p0",
                crate::hex(p.proof_id().unwrap().unwrap().as_bytes())
            )
        })
        .unwrap_or_else(|| "goal=all(x,eq(x,x)) proof:p0=refl(x) p1=gen(p0,x) return p1".into());
    graph.author(&source).unwrap()
}
fn corpus(directory: &Path, count: usize) -> (Vec<crate::Envelope>, [u8; 32], [u8; 32]) {
    let mut graph = crate::Graph::open(directory).unwrap();
    let mut objects = Vec::new();
    for _ in 0..count {
        let next = object(&graph, objects.last());
        graph.ingest(next.clone(), Instant::now()).unwrap();
        objects.push(next);
    }
    (objects, graph.content_root(), graph.context.snapshot_id())
}
fn register(graph: &mut crate::Graph, object: crate::Envelope) {
    let (context, growth) = graph.check_candidate(object.prepare().unwrap()).unwrap();
    graph.context = context;
    graph.context_bytes += growth;
}
fn cold_membership(graph: &crate::Graph, objects: &[crate::Envelope], snapshot: [u8; 32]) {
    graph.checked_storage.evict_cache();
    assert_eq!(graph.context.snapshot_id(), snapshot);
    for object in objects {
        let id = crate::object::id_bytes(&object.artifact_id).unwrap();
        let id = naome_proof::ArtifactId::from_bytes(id);
        assert!(graph.context.contains_artifact(id).unwrap());
        let normal =
            naome_proof::ProofCertificate::new(vec![naome_proof::ProofStep::ProofReference {
                proof_id: object.proof_id().unwrap().unwrap(),
            }])
            .unwrap()
            .into_unchecked_normal_form();
        let checked = naome_checker::check_normal_form_with_state(normal, &graph.context).unwrap();
        assert_eq!(
            crate::hex(checked.statement_id().as_bytes()),
            object.statement_id.as_deref().unwrap()
        );
    }
}
#[test]
fn buffered_garbage_is_never_written_or_retained_after_an_empty_page() {
    if isolated(
        "graph::storage::startup::tests::buffered_garbage_is_never_written_or_retained_after_an_empty_page",
    ) {
        return;
    }
    let graph = crate::Graph::default();
    let storage = &graph.checked_storage;
    storage.begin_startup_page().unwrap();
    storage.write([91; 32], b"disposable unused node").unwrap();
    assert!(storage.finish_write_phase().is_err());
    assert!(storage.successor().is_err());
    let count: i64 = storage
        .connection
        .lock()
        .unwrap()
        .open()
        .unwrap()
        .query_row("SELECT count(*) FROM nodes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(storage.cache.lock().unwrap().pending.len(), 1);
    storage.finish_startup_page(&graph.context).unwrap();
    storage.evict_cache();
    let count: i64 = storage
        .connection
        .lock()
        .unwrap()
        .open()
        .unwrap()
        .query_row("SELECT count(*) FROM nodes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(storage.cache.lock().unwrap().pending.len(), 0);
}
#[test]
fn pressure_and_live_reduction_materialize_dependencies_before_eviction() {
    if isolated(
        "graph::storage::startup::tests::pressure_and_live_reduction_materialize_dependencies_before_eviction",
    ) {
        return;
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let (objects, _, snapshot) = corpus(&directory.0, 32);
    for limit in [0, 600, 700, 1024, 4096, 32768] {
        budget(limit);
        let mut graph = crate::Graph::default();
        graph.checked_storage.begin_startup_page().unwrap();
        for object in objects.iter().cloned() {
            register(&mut graph, object);
            assert!(graph.checked_storage.cache.lock().unwrap().charged <= limit);
        }
        graph
            .checked_storage
            .finish_startup_page(&graph.context)
            .unwrap();
        cold_membership(&graph, &objects, snapshot);
    }
    budget(crate::resources::limits().checked_cache_bytes);
    let mut graph = crate::Graph::default();
    graph.checked_storage.begin_startup_page().unwrap();
    for object in objects.iter().cloned() {
        register(&mut graph, object);
    }
    assert!(
        !graph
            .checked_storage
            .cache
            .lock()
            .unwrap()
            .pending
            .is_empty()
    );
    budget(0);
    graph.checked_storage.adapt_cache().unwrap();
    {
        let cache = graph.checked_storage.cache.lock().unwrap();
        assert_eq!(cache.pending.len(), 0);
        assert_eq!(cache.charged, 0);
    }
    graph
        .checked_storage
        .finish_startup_page(&graph.context)
        .unwrap();
    cold_membership(&graph, &objects, snapshot);
}
#[test]
fn startup_cuts_and_abrupt_process_loss_replay_the_unchanged_canonical_corpus() {
    const CASE: &str = "graph::storage::startup::tests::startup_cuts_and_abrupt_process_loss_replay_the_unchanged_canonical_corpus";
    if let Some(directory) = std::env::var_os("NAOME_STARTUP_RECOVERY_DIR") {
        let _graph = crate::Graph::open(Path::new(&directory)).unwrap();
        panic!("startup must exit during its pending flush");
    }
    if isolated(CASE) {
        return;
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let (objects, root, snapshot) = corpus(&directory.0, 128);
    for stage in [Cut::Mark, Cut::Flush, Cut::Commit] {
        CUT.set(Some(stage));
        assert!(crate::Graph::open(&directory.0).is_err());
        CUT.set(None);
        let graph = crate::Graph::open(&directory.0).unwrap();
        assert_eq!(graph.content_root(), root);
        cold_membership(&graph, &objects, snapshot);
        drop(graph);
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CASE, "--nocapture"])
        .env("NAOME_STARTUP_RECOVERY_DIR", &directory.0)
        .env("NAOME_STARTUP_EXIT_CUT", "flush")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(85),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let graph = crate::Graph::open(&directory.0).unwrap();
    assert_eq!(graph.content_root(), root);
    assert_eq!(graph.accepted_count(), objects.len());
    cold_membership(&graph, &objects, snapshot);
}

#[derive(Default)]
struct Records(std::sync::Mutex<BTreeMap<[u8; 32], Vec<u8>>>);
impl ContextStorage for Records {
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        let rows = self.0.lock().unwrap();
        let bytes = rows.get(&address).ok_or(ContextError::Corrupt)?;
        if bytes.len() > maximum {
            return Err(ContextError::Limit);
        }
        Ok(bytes.clone())
    }
    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        let mut rows = self.0.lock().unwrap();
        if let Some(old) = rows.get(&address)
            && old != bytes
        {
            return Err(ContextError::Corrupt);
        }
        rows.insert(address, bytes.to_vec());
        Ok(())
    }
}
#[test]
fn replay_writes_exactly_the_page_contexts_and_preserves_cold_proof_identity() {
    if isolated(
        "graph::storage::startup::tests::replay_writes_exactly_the_page_contexts_and_preserves_cold_proof_identity",
    ) {
        return;
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = crate::Graph::open(&directory.0).unwrap();
    let expected = Arc::new(Records::default());
    let mut objects = Vec::new();
    let eager_start = sql_inserts();
    let page = crate::resources::limits().replay_page;
    for _ in 0..page * 2 {
        let next = object(&graph, objects.last());
        graph.ingest(next.clone(), Instant::now()).unwrap();
        objects.push(next);
        if objects.len() % page == 0 {
            let _ = graph.context.copy_to(expected.clone()).unwrap();
        }
    }
    let eager = sql_inserts() - eager_start;
    let root = graph.content_root();
    let snapshot = graph.context.snapshot_id();
    drop(graph);
    let before = sql_inserts();
    let graph = crate::Graph::open(&directory.0).unwrap();
    let inserts = sql_inserts() - before;
    assert_eq!(graph.content_root(), root);
    assert_eq!(graph.accepted_count(), objects.len());
    let rows = graph
        .checked_storage
        .connection
        .lock()
        .unwrap()
        .open()
        .unwrap()
        .prepare("SELECT address FROM nodes")
        .unwrap()
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|r| <[u8; 32]>::try_from(r.unwrap()).unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .0
        .lock()
        .unwrap()
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        rows, expected,
        "only records reachable at completed replay pages are materialized"
    );
    assert_eq!(inserts, rows.len());
    assert!(
        inserts < eager / 2,
        "{inserts} buffered inserts vs {eager} eager inserts"
    );
    cold_membership(&graph, &objects, snapshot);
}

#[test]
fn recency_rollover_never_discards_pinned_startup_records() {
    if isolated(
        "graph::storage::startup::tests::recency_rollover_never_discards_pinned_startup_records",
    ) {
        return;
    }
    let graph = crate::Graph::default();
    let storage = &graph.checked_storage;
    storage.write([92; 32], b"persisted").unwrap();
    storage.begin_startup_page().unwrap();
    storage.write([93; 32], b"pending").unwrap();
    storage.cache.lock().unwrap().clock = u64::MAX;
    assert_eq!(storage.read([92; 32], 100).unwrap(), b"persisted");
    assert_eq!(storage.read([93; 32], 100).unwrap(), b"pending");
    assert_eq!(storage.cache.lock().unwrap().pending.len(), 1);
    storage.evict_cache();
    assert_eq!(storage.read([93; 32], 100).unwrap(), b"pending");
    storage.finish_startup_page(&graph.context).unwrap();
    assert_eq!(storage.cache.lock().unwrap().pending.len(), 0);
    assert!(
        !storage
            .cache
            .lock()
            .unwrap()
            .entries
            .contains_key(&[93; 32])
    );
}
