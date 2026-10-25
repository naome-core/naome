use super::*;

#[test]
fn configured_sqlite_budgets_open_and_reopen_the_real_catalog() {
    const TEST: &str = "store::tests::resource_calibration::configured_sqlite_budgets_open_and_reopen_the_real_catalog";
    if std::env::var_os("NAOME_CATALOG_BUDGET_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_CATALOG_BUDGET_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut profile = crate::resources::ResourceProfile {
        memory_bytes: 1024 * 1024 * 1024,
        ..Default::default()
    };
    profile.tuning.catalog_cache_bytes = Some(3 * 1024 * 1024);
    profile.tuning.sqlite_busy_timeout_ms = Some(37);
    crate::resources::configure(profile).unwrap();
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let object = graph.author(SOURCE).unwrap();
    graph.ingest(object.clone(), Instant::now()).unwrap();
    let root = graph.content_root();
    drop(graph);
    let graph = Graph::open(&directory.0).unwrap();
    assert_eq!(graph.content_root(), root);
    assert_eq!(graph.get(&object.proof_id).unwrap(), Some(object));
}

#[test]
fn stored_commits_survive_smaller_admission_budgets_without_skipping_validation() {
    const TEST: &str = "store::tests::resource_calibration::stored_commits_survive_smaller_admission_budgets_without_skipping_validation";
    if let Some(path) = std::env::var_os("NAOME_CATALOG_REOPEN_TEST") {
        let mut profile = crate::resources::ResourceProfile::default();
        profile.tuning.batch_objects = Some(1);
        profile.tuning.batch_bytes = Some(1);
        crate::resources::configure(profile).unwrap();
        let graph = Graph::open(Path::new(&path)).unwrap();
        assert_eq!(graph.accepted_count(), 2);
        let expected = std::env::var("NAOME_CATALOG_EXPECTED_ROOT").unwrap();
        assert_eq!(crate::hex(&graph.content_root()), expected);
        drop(graph);
        // Resource-independent replay still authenticates the stored commitment.
        let connection = rusqlite::Connection::open(Path::new(&path).join(DATABASE_FILE)).unwrap();
        connection
            .execute("UPDATE commits SET member_count=member_count+1", [])
            .unwrap();
        drop(connection);
        assert!(Graph::open(Path::new(&path)).is_err());
        return;
    }
    let directory = Directory::new();
    let (parent, child) = fixtures();
    let mut baseline = Graph::default();
    baseline.ingest(parent.clone(), Instant::now()).unwrap();
    baseline.ingest(child.clone(), Instant::now()).unwrap();
    let store = Store::open(&directory.0).unwrap();
    store
        .finish_replay(Graph::default().content_root())
        .unwrap();
    let root = ProofId::from_bytes(crate::object::id_bytes(&child.proof_id).unwrap());
    store
        .persist_batch(root, [&parent, &child].into_iter())
        .unwrap();
    drop(store);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture"])
        .env("NAOME_CATALOG_REOPEN_TEST", &directory.0)
        .env(
            "NAOME_CATALOG_EXPECTED_ROOT",
            crate::hex(&baseline.content_root()),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
