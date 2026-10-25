use super::*;
#[test]
fn disk_pressure_at_work_creation_and_append_retains_the_completed_provider_candidate() {
    const CASE: &str = "autonomous::program::tests::disk_pressure_at_work_creation_and_append_retains_the_completed_provider_candidate";
    if std::env::var_os("NAOME_PROGRAM_CREATION_CASE").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_PROGRAM_CREATION_CASE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let graph = Graph::default();
    let owner = jobs::tests::Manual::new();
    let question = CompiledQuestion::compile(&crate::mocks::create_question(0)).unwrap();
    let mut generated = Generated::new(17, 1);
    let path = graph
        .ownership()
        .directory()
        .join(".program-work/candidate-17.sqlite3");
    crate::resources::with_disk_available(0, || {
        let error = generated
            .prepare(&graph, &owner.client, &question)
            .err()
            .expect("work creation must defer");
        assert!(error.retryable());
        assert!(!path.exists());
    });
    assert_eq!((generated.job, generated.unit), (17, 1));
    assert!(
        generated
            .prepare(&graph, &owner.client, &question)
            .unwrap()
            .is_none()
    );
    assert!(path.exists() && generated.pending.is_some());
    assert_eq!((generated.job, generated.unit), (17, 1));

    let records = vec![Command::Equal { left: 0, right: 0 }];
    let respond = || {
        let (send, receive) = oneshot::channel();
        send.send(Ok(records.clone())).unwrap();
        receive
    };
    generated.pending = Some(respond());
    crate::resources::with_disk_available(0, || {
        let error = generated
            .prepare(&graph, &owner.client, &question)
            .err()
            .expect("import must defer before advancing its in-memory cursor");
        assert!(error.retryable());
    });
    assert_eq!(
        (
            generated.unit,
            generated.prefix.commands,
            generated.prefix.hash
        ),
        (1, 0, [0; 32])
    );
    assert_eq!(
        generated.work.as_ref().unwrap().status().unwrap().commands,
        0
    );
    generated.pending = Some(respond());
    assert!(
        generated
            .prepare(&graph, &owner.client, &question)
            .unwrap()
            .is_none()
    );
    assert_eq!((generated.unit, generated.prefix.commands), (2, 1));
    assert_eq!(
        generated.work.as_ref().unwrap().status().unwrap().commands,
        1
    );
}
