//! Artificial persisted vectors distinguish cache use from inference admission.
use super::*;
use crate::{
    Graph,
    corpus::{
        local::EmbeddedChunk,
        semantic::SourceVectorRow,
        snapshot::{Frozen, Seed, Store},
    },
    question::{LocalQuestions, StoredQuestion, StoredQuestionKind},
};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "naome-prepared-search-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn settings() -> Settings {
    Settings {
        model_directory: PathBuf::from("/unavailable-model-no-inference-authorized"),
        quantum_ms: 30_000,
        memory_bytes: 1024 * 1024 * 1024,
    }
}
fn fixture(directory: &Path) -> (generation::Request, Arc<Frozen>, String) {
    // Exercise the actual durable proof write and startup checker reconstruction.
    let mut graph = Graph::open(directory).unwrap();
    let proof = graph
        .author("goal=all(x,eq(x,x)) proof: a=refl(x) b=gen(a,x) return b")
        .unwrap();
    graph.ingest(proof.clone(), Instant::now()).unwrap();
    assert_eq!(
        graph.ingest(proof, Instant::now()).unwrap().status,
        "duplicate"
    );
    drop(graph);
    let graph = Graph::open(directory).unwrap();
    let questions = LocalQuestions::new(Some(crate::mocks::assess_interest));
    let (snapshot, policy) = questions.context_key(&graph);
    let question = naome_authoring::CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let query = question.core().to_controlled_english();
    let seed = Seed::capture(
        &graph,
        Some(BTreeMap::from([(
            crate::hex(question.source_hash()),
            StoredQuestion {
                source: question.source().into(),
                kind: StoredQuestionKind::Baseline,
                first: None,
            },
        )])),
        &crate::hex(&snapshot),
    )
    .unwrap();
    let source = Arc::new(seed.freeze().unwrap());
    let mut request = generation::Request::build_from_snapshot(
        &jobs::Input::Find { cursor: 0 },
        &jobs::Binding::new(snapshot, policy),
        source.clone(),
        generation::OwnerContext::Unavailable {
            reason: "unit fixture".into(),
        },
        questions.generation_policy(),
    )
    .unwrap();
    let store = Store::open(directory).unwrap();
    request.attach_cursor_key(store.cursor_key().unwrap());
    request.persist_source(&store).unwrap();
    (request, source, query)
}
fn save_proof(cache: &Cache, source: &Frozen) {
    let reference = &source.corpus().references[0];
    let content = source.semantic_content(&reference.proof.proof_id).unwrap();
    let mut vector = vec![0.; 384];
    vector[0] = 1.;
    let row = SourceVectorRow::new(
        LocalEncoder::identity_specification(),
        reference,
        &content,
        vec![EmbeddedChunk {
            token_start: 0,
            token_end: 1,
            total_tokens: 1,
            byte_start: 0,
            byte_end: content.len(),
            vector,
        }],
    )
    .unwrap();
    cache.save_row(&row.bound_key(), &row).unwrap();
}
fn invoke(
    engine: &mut Engine,
    request: &generation::Request,
    query: &str,
) -> generation::ToolResult {
    let (reply, mut response) = oneshot::channel();
    // No reservation owner services this channel. Any inference admission
    // therefore makes the assertion below fail instead of using a test model.
    let (budget, mut events) = jobs::RetrievalBudget::unserved_test(
        1,
        request.identity(),
        Instant::now() + Duration::from_millis(100),
    );
    engine.enqueue(Invocation {
        request: request.clone(),
        name: "semantic_search".into(),
        arguments: json!({"request_id":request.identity(),"query":query,"top_k":1}),
        budget,
        control: Default::default(),
        reply,
    });
    engine.step();
    assert!(
        !events(),
        "prepared or known stored query must reserve zero inference units"
    );
    response.try_recv().unwrap().unwrap()
}
#[test]
fn pending_search_never_sponsors_document_encoding() {
    let directory = Directory::new();
    let (request, source, query) = fixture(&directory.0);
    let mut engine = Engine::open(
        &directory.0,
        Some(settings()),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    engine.observe(&source).unwrap();
    let result = invoke(&mut engine, &request, &query);
    assert!(
        serde_json::to_value(result)
            .unwrap()
            .to_string()
            .contains("index_incomplete")
    );
    assert!(
        !engine.indexer.pending(),
        "observing a request cannot schedule document work"
    );
}
#[test]
fn write_prepared_rows_and_question_vectors_reuse_after_restart_without_inference() {
    let directory = Directory::new();
    let (request, source, query) = fixture(&directory.0);
    let cache = Cache::open(&directory.0).unwrap();
    save_proof(&cache, &source);
    let mut vector = vec![0.; 384];
    vector[0] = 1.;
    cache.save_query(&query, vector).unwrap();
    let mut engine = Engine::open(
        &directory.0,
        Some(settings()),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    engine.reconcile(source.clone()).unwrap();
    assert!(!engine.indexer.pending());
    engine.observe(&source).unwrap();
    assert!(
        cache.index(&source).unwrap().is_some(),
        "complete index must be prepared before search"
    );
    let first = serde_json::to_value(invoke(&mut engine, &request, &query)).unwrap();
    drop(engine);
    let mut restarted = Engine::open(
        &directory.0,
        Some(settings()),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    restarted.reconcile(source.clone()).unwrap();
    restarted.observe(&source).unwrap();
    assert_eq!(
        first,
        serde_json::to_value(invoke(&mut restarted, &request, &query)).unwrap()
    );
    assert!(!restarted.indexer.pending());
    let raw = "goal=all(x,eq(x,x))";
    assert!(
        serde_json::to_value(invoke(&mut restarted, &request, raw))
            .unwrap()
            .to_string()
            .contains("semantic_ranking")
    );
}
#[test]
fn missing_stored_question_vector_is_repaired_only_by_write_owner() {
    let directory = Directory::new();
    let (request, source, query) = fixture(&directory.0);
    let cache = Cache::open(&directory.0).unwrap();
    save_proof(&cache, &source);
    cache.assemble(&source).unwrap();
    let mut engine = Engine::open(
        &directory.0,
        Some(settings()),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    engine.observe(&source).unwrap();
    let result = serde_json::to_value(invoke(&mut engine, &request, &query)).unwrap();
    assert!(
        result
            .to_string()
            .contains("stored question indexing is pending or failed")
    );
    assert!(cache.query(&query).unwrap().is_none());
    assert!(!engine.indexer.pending());
    engine.reconcile(source).unwrap();
    assert!(engine.indexer.pending());
}

#[test]
fn progress_cannot_claim_complete_when_a_proof_or_stored_question_is_missing() {
    let directory = Directory::new();
    let (_, source, query) = fixture(&directory.0);
    let cache = Cache::open(&directory.0).unwrap();
    cache
        .progress(&source, "complete", usize::MAX, None)
        .unwrap();
    let read = || {
        crate::jobs::read_checkpoint::<serde_json::Value>(&cache.root.join("progress.json"), 8192)
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        (
            read()["indexed_proofs"].as_u64(),
            read()["complete"].as_bool()
        ),
        (Some(0), Some(false))
    );
    save_proof(&cache, &source);
    cache.assemble(&source).unwrap();
    cache
        .progress(&source, "complete", usize::MAX, None)
        .unwrap();
    assert_eq!(
        (
            read()["indexed_proofs"].as_u64(),
            read()["indexed_questions"].as_u64(),
            read()["complete"].as_bool()
        ),
        (Some(1), Some(0), Some(false))
    );
    let mut vector = vec![0.; 384];
    vector[0] = 1.;
    cache.save_query(&query, vector).unwrap();
    cache.progress(&source, "complete", 0, None).unwrap();
    assert_eq!(read()["complete"], true);
}
