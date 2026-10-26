use super::*;

#[test]
fn nonempty_graph_replay_performs_one_complete_catalog_integrity_pass() {
    let directory = Directory::new();
    let (parent, child) = fixtures();
    let mut graph = Graph::open(&directory.0).unwrap();
    graph.ingest(parent, Instant::now()).unwrap();
    graph.ingest(child, Instant::now()).unwrap();
    let root = graph.content_root();
    drop(graph);
    let before = catalog::set_scan_count();
    let graph = Graph::open(&directory.0).unwrap();
    assert_eq!(catalog::set_scan_count() - before, 1);
    assert_eq!(graph.accepted_count(), 2);
    assert_eq!(graph.content_root(), root);
}

#[test]
fn external_write_after_integrity_validation_invalidates_the_replay_ticket() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let proof = graph.author(SOURCE).unwrap();
    graph.ingest(proof, Instant::now()).unwrap();
    let root = graph.content_root();
    drop(graph);
    let store = Store::open(&directory.0).unwrap();
    assert_eq!(store.summary().unwrap().root, root);
    let path = fs::canonicalize(&directory.0).unwrap().join(DATABASE_FILE);
    let other = rusqlite::Connection::open(path).unwrap();
    other
        .execute("UPDATE artifacts SET payload=zeroblob(length(payload))", [])
        .unwrap();
    drop(other);
    assert!(store.finish_replay(root).is_err());
    drop(store);
    assert!(Graph::open(&directory.0).is_err());
}
