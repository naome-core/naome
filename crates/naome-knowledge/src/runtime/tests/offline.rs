use super::*;

#[tokio::test]
async fn offline_controls_do_not_read_payloads_or_rebuild_checked_indexes() {
    let directory = Directory::new();
    let (helper, _, _) = closure();
    let mut graph = Graph::open(&directory.0).unwrap();
    graph.ingest(helper.clone(), Instant::now()).unwrap();
    drop(graph);
    let sentinel = directory.0.join(".checked-context.sqlite3");
    fs::write(&sentinel, b"disposable index must remain untouched").unwrap();
    let reads = crate::store::payload_reads();
    let recorded = status(&directory.0).await.unwrap();
    assert_eq!(recorded.accepted_artifacts, 1);
    assert_eq!(recorded.artifact_verification, ArtifactVerification::NotRun);
    assert_eq!(crate::store::payload_reads(), reads);
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"disposable index must remain untouched"
    );
    crate::store::corrupt_payload(&directory.0, &helper.artifact_id);
    assert_eq!(
        status(&directory.0).await.unwrap().artifact_verification,
        ArtifactVerification::NotRun
    );
    assert!(Graph::open(&directory.0).is_err());
}

#[tokio::test]
async fn offline_controls_keep_exclusive_directory_custody() {
    let directory = Directory::new();
    let graph = Graph::open(&directory.0).unwrap();
    assert!(status(&directory.0).await.is_err());
    drop(graph);
}
