//! Artificial vector/coverage contracts; no encoder or model is executed.
use super::*;
use crate::{
    Graph,
    question::{StoredQuestion, StoredQuestionKind},
};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "naome-vector-cache-{}-{}",
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
fn source(comment: &str) -> Frozen {
    let mut graph = Graph::default();
    let proof = graph
        .author("goal=all(x,eq(x,x)) proof: a=refl(x) b=gen(a,x) return b")
        .unwrap();
    graph.ingest(proof, Instant::now()).unwrap();
    let original = format!("# {comment}\ngoal=all(x,eq(x,x))");
    let question = naome_authoring::CompiledQuestion::compile(&original).unwrap();
    let questions = BTreeMap::from([(
        crate::hex(question.source_hash()),
        StoredQuestion {
            source: original,
            kind: StoredQuestionKind::Baseline,
            first: None,
        },
    )]);
    Frozen::capture(&graph, Some(questions), &"00".repeat(32)).unwrap()
}
fn artificial_row(source: &Frozen) -> SourceVectorRow {
    let reference = &source.corpus().references[0];
    let input = source.semantic_content(&reference.proof.proof_id).unwrap();
    // Declared spans and a one-hot vector exercise persistence/bounds only.
    let mut vector = vec![0.; 384];
    vector[0] = 1.;
    SourceVectorRow::new(
        LocalEncoder::identity_specification(),
        reference,
        &input,
        vec![super::super::local::EmbeddedChunk {
            token_start: 0,
            token_end: 1,
            total_tokens: 1,
            byte_start: 0,
            byte_end: input.len(),
            vector,
        }],
    )
    .unwrap()
}

#[test]
fn partial_rows_survive_reopen_and_only_complete_index_is_searchable() {
    let directory = Directory::new();
    let source = source("actual locally retained Ω question");
    let row = artificial_row(&source);
    let key = row.bound_key();
    let cache = Cache::open(&directory.0).unwrap();
    cache.save_row(&key, &row).unwrap();
    cache
        .save_partial(&source, std::slice::from_ref(&row))
        .unwrap();
    assert!(cache.index(&source).unwrap().is_none());
    drop(cache);
    let cache = Cache::open(&directory.0).unwrap();
    let saved = cache.row(&key, &source).unwrap().unwrap();
    let index =
        SemanticIndex::build_source(&source, LocalEncoder::identity_specification(), vec![saved])
            .unwrap();
    cache.save_index(&source, &index).unwrap();
    drop(cache);
    let cache = Cache::open(&directory.0).unwrap();
    let index = cache.index(&source).unwrap().unwrap();
    let result = index
        .search_vector(&source, "reflexive equality", 1, &row.chunks[0].vector)
        .unwrap();
    assert_eq!(
        result.results[0].proof_id,
        source.corpus().references[0].proof.proof_id
    );
    assert!(result.complete_corpus_scan);
    let before = source.corpus().references[0].proof.clone();
    let path = cache
        .root
        .join("indexes")
        .join(format!("{}.json", Cache::index_key(&source)));
    fs::write(&path, b"corrupt cache").unwrap();
    assert!(cache.index(&source).is_err());
    assert_eq!(source.corpus().references[0].proof, before);
}

#[test]
fn actual_question_changes_invalidate_rows_and_chunk_gaps_are_rejected() {
    let first = source("original text");
    let changed = source("different actual text");
    assert_eq!(
        first.corpus().references[0].proof,
        changed.corpus().references[0].proof
    );
    assert_ne!(first.handle().snapshot_id, changed.handle().snapshot_id);
    let row = artificial_row(&first);
    assert!(
        row.validate(&changed, &LocalEncoder::identity_specification())
            .is_err()
    );
    let content = first.semantic_content(&row.proof_id).unwrap();
    assert!(content.contains("original text"));
    let matching = first.associations(&row.statement_id);
    assert_eq!(matching.len(), 1);
    assert_eq!(content.matches(&matching[0].record.source).count(), 1);
    assert!(content.contains("Target orientation: proved."));
    let mut gap = row.clone();
    gap.chunks[0].byte_start = 1;
    assert!(
        gap.validate(&first, &LocalEncoder::identity_specification())
            .is_err()
    );
    let mut missing = row.clone();
    missing.chunks[0].byte_end -= 1;
    assert!(
        missing
            .validate(&first, &LocalEncoder::identity_specification())
            .is_err()
    );
    let mut nonfinite = row;
    nonfinite.chunks[0].vector[0] = f32::NAN;
    assert!(
        nonfinite
            .validate(&first, &LocalEncoder::identity_specification())
            .is_err()
    );
}

#[test]
fn collection_keeps_pinned_partial_rows_then_reclaims_only_derived_files() {
    let directory = Directory::new();
    let source = source("pinned partial source");
    let row = artificial_row(&source);
    let key = row.bound_key();
    let cache = Cache::open(&directory.0).unwrap();
    cache.save_row(&key, &row).unwrap();
    cache.save_partial(&source, &[row]).unwrap();
    cache
        .collect(&BTreeSet::from([source.handle().snapshot_id.clone()]))
        .unwrap();
    assert!(cache.row(&key, &source).unwrap().is_some());
    cache.collect(&BTreeSet::new()).unwrap();
    assert!(cache.row(&key, &source).unwrap().is_none());
    assert_eq!(source.corpus().references.len(), 1);
}

#[test]
fn physical_model_lease_is_shared_across_node_directories() {
    let first = Directory::new();
    let second = Directory::new();
    let a = Cache::open(&first.0).unwrap();
    let b = Cache::open(&second.0).unwrap();
    let lease = a.model_lock().unwrap();
    assert!(b.model_lock().is_err());
    drop(lease);
    let next = b.model_lock().unwrap();
    drop(next);
}

#[test]
fn established_model_lease_refuses_missing_or_replaced_inode() {
    let directory = Directory::new();
    let owned = model_lease(&directory.0).unwrap();
    let path = directory.0.join(format!(
        "naome-retrieval-cpu-{}.lock",
        nix::unistd::geteuid().as_raw()
    ));
    assert!(model_lease(&directory.0).is_err());
    fs::remove_file(&path).unwrap();
    assert!(model_lease(&directory.0).is_err());
    assert!(!path.exists());
    fs::write(&path, []).unwrap();
    assert!(model_lease(&directory.0).unwrap_err().contains("inode"));
    drop(owned);
    assert!(model_lease(&directory.0).is_err());
}
