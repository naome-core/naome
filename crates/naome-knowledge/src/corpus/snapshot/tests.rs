use super::*;
use crate::question::StoredQuestionKind as Kind;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "naome-snapshot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn add(graph: &mut Graph, source: &str) -> String {
    let proof = graph.author(source).unwrap();
    let id = proof.proof_id.clone();
    assert_eq!(
        graph.ingest(proof, Instant::now()).unwrap().status,
        "accepted"
    );
    id
}
fn questions(sources: &[&str]) -> BTreeMap<String, StoredQuestion> {
    sources
        .iter()
        .map(|source| {
            let question = naome_authoring::CompiledQuestion::compile(source).unwrap();
            (
                crate::hex(question.source_hash()),
                StoredQuestion {
                    source: (*source).into(),
                    kind: Kind::Baseline,
                    first: None,
                },
            )
        })
        .collect()
}

#[test]
fn frozen_store_reopens_original_bytes_and_multiple_target_orientations() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let id = add(
        &mut graph,
        "goal=all(x,eq(x,x)) proof: p=refl(x) q=gen(p,x) return q",
    );
    let records = questions(&["goal=all(x,eq(x,x))", "goal=not(all(y,eq(y,y)))"]);
    let frozen = Frozen::capture(&graph, Some(records), &"0".repeat(64)).unwrap();
    let store = Store::open(&directory.0).unwrap();
    store.persist(&frozen).unwrap();
    let reopened = store.load(frozen.handle()).unwrap();
    assert_eq!(reopened.handle(), frozen.handle());
    assert_eq!(
        reopened.full_record(&id).unwrap(),
        frozen.full_record(&id).unwrap()
    );
    let reference = reopened.reference(&id).unwrap();
    let links = reopened.associations(&reference.proof.statement_id);
    assert_eq!(links.len(), 2);
    assert_eq!(
        links
            .iter()
            .map(|link| link.resolution)
            .collect::<BTreeSet<_>>(),
        ["proved", "refuted"].into()
    );
    assert!(
        links
            .iter()
            .all(|link| link.association == "matching_registered_question")
    );
    assert!(links.iter().all(|link| link.record.kind == Kind::Baseline));
    let changed = Frozen::capture(&graph, Some(BTreeMap::new()), &"0".repeat(64)).unwrap();
    assert_ne!(changed.handle().snapshot_id, frozen.handle().snapshot_id);
    assert_eq!(changed.handle().graph_root, frozen.handle().graph_root);
    assert!(reopened.reference(&id).is_some());
}

#[test]
fn semantic_projection_keeps_exact_question_sources_without_provenance_duplication() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let id = add(
        &mut graph,
        "goal=all(x,eq(x,x)) proof: p=refl(x) q=gen(p,x) return q",
    );
    let sources = [
        "# original spelling\ngoal=all(x,eq(x,x))",
        "goal=not(all(y,eq(y,y)))",
    ];
    let frozen = Frozen::capture(&graph, Some(questions(&sources)), &"0".repeat(64)).unwrap();
    let projection = frozen.semantic_content(&id).unwrap();
    for source in sources {
        assert_eq!(projection.matches(source).count(), 1);
    }
    assert!(projection.contains("Target orientation: proved."));
    assert!(projection.contains("Target orientation: refuted."));
    assert!(!projection.contains("source_hash"));
    assert!(!projection.contains("first_admission"));
    let record = frozen.full_record(&id).unwrap().unwrap();
    let retained = &record["original_question_records"]["matching_registered_questions"];
    assert_eq!(retained.as_array().unwrap().len(), 2);
    let store = Store::open(&directory.0).unwrap();
    store.persist(&frozen).unwrap();
    let reopened = store.load(frozen.handle()).unwrap();
    assert_eq!(reopened.semantic_content(&id).unwrap(), projection);
    assert_eq!(reopened.full_record(&id).unwrap().unwrap(), record);
    let absent = Frozen::capture(&graph, None, &"0".repeat(64)).unwrap();
    let empty = Frozen::capture(&graph, Some(BTreeMap::new()), &"0".repeat(64)).unwrap();
    assert!(
        absent
            .semantic_content(&id)
            .unwrap()
            .contains("unavailable in this frozen snapshot")
    );
    assert!(
        empty
            .semantic_content(&id)
            .unwrap()
            .contains("No matching registered question")
    );
    assert_ne!(absent.handle(), empty.handle());
}

#[test]
fn absent_and_empty_original_question_records_remain_distinct() {
    let graph = Graph::default();
    let absent = Frozen::capture(&graph, None, &"0".repeat(64)).unwrap();
    let empty = Frozen::capture(&graph, Some(BTreeMap::new()), &"0".repeat(64)).unwrap();
    assert_eq!(absent.handle().question_count, None);
    assert_eq!(empty.handle().question_count, Some(0));
    assert_ne!(absent.handle().snapshot_id, empty.handle().snapshot_id);
}

#[test]
fn missing_or_corrupt_frozen_sources_never_use_the_changed_current_graph() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let id = add(
        &mut graph,
        "goal=all(x,eq(x,x)) proof: p=refl(x) q=gen(p,x) return q",
    );
    let original = Frozen::capture(&graph, None, &"0".repeat(64)).unwrap();
    let store = Store::open(&directory.0).unwrap();
    store.persist(&original).unwrap();
    add(
        &mut graph,
        &crate::mocks::create_proof(
            &naome_authoring::CompiledQuestion::compile(&crate::mocks::create_question(1)).unwrap(),
        )
        .unwrap(),
    );
    let changed = Frozen::capture(&graph, None, &"1".repeat(64)).unwrap();
    store.persist(&changed).unwrap();
    let restored = store.load(original.handle()).unwrap();
    assert_eq!(restored.handle().proof_count, 1);
    assert!(restored.reference(&id).is_some());
    assert_eq!(
        store.load(changed.handle()).unwrap().handle().proof_count,
        2
    );
    let path = store
        .path("manifests", &original.handle().snapshot_id)
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(store.load(original.handle()).is_err());
    fs::write(&path, &bytes).unwrap();
    let row = store
        .path("proofs", &original.manifest.proofs[&id])
        .unwrap();
    fs::write(&row, b"{}").unwrap();
    assert!(store.load(original.handle()).is_err());
    assert!(
        store
            .persist(&original)
            .unwrap_err()
            .contains("refusing replacement")
    );
}

#[test]
fn collection_requires_all_actual_pins_and_preserves_shared_rows() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let id = add(
        &mut graph,
        "goal=all(x,eq(x,x)) proof: p=refl(x) q=gen(p,x) return q",
    );
    let first = Frozen::capture(&graph, None, &"0".repeat(64)).unwrap();
    let second = Frozen::capture(
        &graph,
        Some(questions(&["goal=all(x,eq(x,x))"])),
        &"1".repeat(64),
    )
    .unwrap();
    let store = Store::open(&directory.0).unwrap();
    store.persist(&first).unwrap();
    store.persist(&second).unwrap();
    let pins = [
        first.handle().snapshot_id.clone(),
        second.handle().snapshot_id.clone(),
    ]
    .into();
    store.collect(&pins).unwrap();
    assert!(store.load(first.handle()).unwrap().reference(&id).is_some());
    store
        .collect(&[second.handle().snapshot_id.clone()].into())
        .unwrap();
    assert!(store.load(first.handle()).is_err());
    assert_eq!(
        store.load(second.handle()).unwrap().handle(),
        second.handle()
    );
    store.collect(&BTreeSet::new()).unwrap();
    assert_eq!(store.inventory().unwrap(), (0, 0));
}

#[test]
fn complete_corpus_beyond_old_request_cap_has_a_small_durable_handle() {
    fn formula(n: usize) -> String {
        if n == 1 {
            "eq(x,x)".into()
        } else {
            format!("and({},{})", formula(n / 2), formula(n - n / 2))
        }
    }
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let a = formula(256);
    for n in 0..12 {
        let mut variables = vec!["x".to_owned()];
        variables.extend((0..n).map(|i| format!("u{i}")));
        let mut source = format!(
            "let: A={a} G=imp(A,imp(A,A)) goal=all([{}],G) proof: p0=simp(A,A)",
            variables.join(",")
        );
        let mut step = 0;
        for variable in variables.iter().rev() {
            source.push_str(&format!(" p{}=gen(p{step},{variable})", step + 1));
            step += 1;
        }
        source.push_str(&format!(" return p{step}"));
        add(&mut graph, &source);
    }
    let frozen = Frozen::capture(&graph, None, &"0".repeat(64)).unwrap();
    let corpus_bytes = encoded(frozen.corpus()).unwrap();
    assert!(
        corpus_bytes.len() > 256 * 1024,
        "fixture must cross the original embedded-context cap: {}",
        corpus_bytes.len()
    );
    assert!(encoded(frozen.handle()).unwrap().len() < 1024);
    let store = Store::open(&directory.0).unwrap();
    store.persist(&frozen).unwrap();
    let loaded = store.load(frozen.handle()).unwrap();
    assert_eq!(loaded.handle().proof_count, 12);
    assert_eq!(loaded.corpus().references.len(), 12);
    assert_eq!(loaded.handle(), frozen.handle());
    assert!(
        graph
            .ids()
            .iter()
            .all(|id| loaded.reference(&crate::hex(id.as_bytes())).is_some())
    );
}

#[test]
fn unsafe_file_aliases_and_nonregular_sources_fail_before_blocking_reads() {
    let directory = Directory::new();
    let original = directory.0.join("original");
    fs::write(&original, b"data").unwrap();
    let link = directory.0.join("link");
    std::os::unix::fs::symlink(&original, &link).unwrap();
    assert!(read_regular(&link, 32).is_err());
    let hard = directory.0.join("hard");
    fs::hard_link(&original, &hard).unwrap();
    assert!(read_regular(&hard, 32).is_err());
    let fifo = directory.0.join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let start = Instant::now();
    assert!(read_regular(&fifo, 32).is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn crash_temporary_rows_are_bounded_and_collected_without_publishing_source() {
    let directory = Directory::new();
    let store = Store::open(&directory.0).unwrap();
    let temporary = store
        .root
        .join("manifests")
        .join(format!(".incoming-{}.json", "0".repeat(64)));
    fs::write(&temporary, b"unfinished").unwrap();
    assert_eq!(store.inventory().unwrap(), (10, 0));
    assert!(
        store
            .load(&Handle {
                version: 1,
                snapshot_id: "0".repeat(64),
                artifact_snapshot: "0".repeat(64),
                graph_root: "0".repeat(64),
                knowledge_snapshot: "0".repeat(64),
                proof_count: 0,
                question_count: None
            })
            .is_err()
    );
    store.collect(&BTreeSet::new()).unwrap();
    assert!(!temporary.exists());
    assert_eq!(store.inventory().unwrap(), (0, 0));
}
