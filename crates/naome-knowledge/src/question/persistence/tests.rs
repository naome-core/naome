use super::*;

#[test]
fn original_source_orientation_and_first_admission_survive_row_updates_and_restart() {
    let directory = crate::checkpoint::tests::Directory::new();
    let root = crate::storage::research_directory(&directory.0).unwrap();
    let policy = PrefilterPolicy::default();
    let question = ResearchQuestion::from_hex("02040001000000000100000000").unwrap();
    let key = crate::hex(question.record_id());
    let entry = Entry {
        encoded: question.to_hex(),
        kind: Kind::Prepared,
        first: Some(FirstAdmission {
            record: key.clone(),
            input: "01".repeat(32),
            policy: crate::hex(&policy.identity()),
            snapshot_before: "02".repeat(32),
            snapshot_after: "03".repeat(32),
            registry_before: "04".repeat(32),
            registry_after: "05".repeat(32),
        }),
    };
    let expected = crate::checkpoint::encode(entry.first.as_ref().unwrap()).unwrap();
    let mut persistence = Persistence::open(&directory.0, policy).unwrap();
    persistence
        .checkpoint
        .commit(
            &persistence.header,
            vec![crate::checkpoint::Update::put("question", &key, &entry).unwrap()],
        )
        .unwrap();
    let restored = persistence
        .entries_page(None, &naome_checker::ArtifactState::new())
        .unwrap()
        .into_iter()
        .map(|(_, entry)| entry)
        .collect::<Vec<_>>();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].kind, Kind::Prepared);
    assert!(
        ResearchQuestion::from_hex(&restored[0].encoded)
            .unwrap()
            .negation_parity()
    );
    persistence.delivered(&question, true).unwrap();
    assert_eq!(
        persistence.checkpoint.last_write.0, 5,
        "one question and its FIFO, source index and header change atomically"
    );
    drop(persistence);
    let persistence = Persistence::open(&directory.0, policy).unwrap();
    let restored = persistence
        .entries_page(None, &naome_checker::ArtifactState::new())
        .unwrap()
        .into_iter()
        .map(|(_, entry)| entry)
        .collect::<Vec<_>>();
    assert_eq!(restored[0].kind, Kind::Admitted);
    assert_eq!(restored[0].encoded, question.to_hex());
    assert_eq!(
        crate::checkpoint::encode(restored[0].first.as_ref().unwrap()).unwrap(),
        expected
    );
    drop(persistence);
    std::fs::remove_file(root.join("questions.sqlite3")).unwrap();
    assert!(matches!(
        Persistence::open(&directory.0, policy),
        Err(crate::Error::Runtime(
            crate::RuntimeFailure::QuestionRegistryMissing
        ))
    ));
}

#[cfg(test)]
#[cfg(feature = "system-tests")]
#[test]
fn thousands_of_question_records_replay_with_bounded_memory_and_persistent_fifo_cursor() {
    const TEST: &str = "question::persistence::tests::thousands_of_question_records_replay_with_bounded_memory_and_persistent_fifo_cursor";
    const BATCH: usize = 1024;
    if let Some(path) = std::env::var_os("NAOME_QUESTION_HISTORY_DIRECTORY") {
        let directory = std::path::PathBuf::from(path);
        let phase: usize = std::env::var("NAOME_QUESTION_HISTORY_PHASE")
            .unwrap()
            .parse()
            .unwrap();
        let started = Instant::now();
        let mut persistence = Persistence::open(&directory, PrefilterPolicy::default()).unwrap();
        for chunk in (phase * BATCH..(phase + 1) * BATCH)
            .collect::<Vec<_>>()
            .chunks(crate::resources::active_limits().question_page)
        {
            let mut updates = Vec::new();
            for index in chunk {
                let question =
                    ResearchQuestion::from_hex(&crate::checkpoint::tests::question_source(*index))
                        .unwrap();
                let key = crate::hex(question.record_id());
                // Synthetic receipts test provenance custody only; registry
                // replay still recompiles every source and grants no admission.
                let first = FirstAdmission {
                    record: key.clone(),
                    input: "01".repeat(32),
                    policy: crate::hex(&PrefilterPolicy::default().identity()),
                    snapshot_before: "02".repeat(32),
                    snapshot_after: "03".repeat(32),
                    registry_before: "04".repeat(32),
                    registry_after: "05".repeat(32),
                };
                let entry = Entry {
                    encoded: question.to_hex(),
                    kind: Kind::Admitted,
                    first: Some(first),
                };
                updates.push(crate::checkpoint::Update::put("question", &key, &entry).unwrap());
                updates.extend(persistence.queue_updates(&question).unwrap());
            }
            persistence
                .checkpoint
                .commit(&persistence.header, updates)
                .unwrap();
        }
        let write_seconds = started.elapsed().as_secs_f64();
        drop(persistence);
        let replay = Instant::now();
        let mut questions = LocalQuestions::new(Some(|_| std::future::ready(Ok(true))));
        let graph = crate::Graph::default();
        questions.attach_persistence(&directory, &graph).unwrap();
        let replay_seconds = replay.elapsed().as_secs_f64();
        assert_eq!(questions.registry.len(), (phase + 1) * BATCH);
        assert!(questions.known.len() <= crate::resources::active_limits().question_page);
        assert!(questions.admitted.len() <= crate::resources::active_limits().question_page);
        let persistence = questions.persistence.as_mut().unwrap();
        for index in phase * 16..(phase + 1) * 16 {
            assert_eq!(
                persistence
                    .next_backlog(graph.checked_context())
                    .unwrap()
                    .unwrap()
                    .to_hex(),
                crate::checkpoint::tests::question_source(index)
            );
        }
        let first =
            ResearchQuestion::from_hex(&crate::checkpoint::tests::question_source(0)).unwrap();
        assert_eq!(
            persistence
                .admitted(first.resolution_id(), graph.checked_context())
                .unwrap()
                .unwrap()
                .0
                .to_hex(),
            first.to_hex()
        );
        let peak = crate::checkpoint::tests::image_peak_rss_bytes();
        assert!(peak < 192 * 1024 * 1024, "isolated question RSS: {peak}");
        println!(
            "QUESTION_HISTORY_METRICS {}",
            serde_json::json!({"phase":phase,"history":questions.registry.len(),"known":questions.known.len(),"admitted":questions.admitted.len(),"peak_rss_bytes":peak,"write_seconds":write_seconds,"replay_seconds":replay_seconds})
        );
        return;
    }
    let directory = crate::checkpoint::tests::Directory::new();
    let mut first_peak = None;
    for phase in 0..4 {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_QUESTION_HISTORY_DIRECTORY", &directory.0)
            .env("NAOME_QUESTION_HISTORY_PHASE", phase.to_string())
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "phase {phase}: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let line = stdout
            .lines()
            .find_map(|line| line.strip_prefix("QUESTION_HISTORY_METRICS "))
            .unwrap();
        println!("QUESTION_HISTORY_METRICS {line}");
        let metrics: serde_json::Value = serde_json::from_str(line).unwrap();
        let peak = metrics["peak_rss_bytes"].as_u64().unwrap();
        let first = *first_peak.get_or_insert(peak);
        assert!(
            peak <= first + 32 * 1024 * 1024,
            "question history drives RSS: {line}"
        );
    }
}

#[cfg(test)]
#[test]
fn stricter_assessment_policy_preserves_current_sources_and_first_policy_identity() {
    let directory = crate::checkpoint::tests::Directory::new();
    let old = PrefilterPolicy::default();
    let question = ResearchQuestion::from_hex("040101000000000100000000").unwrap();
    let mut persistence = Persistence::open(&directory.0, old).unwrap();
    persistence.retain(&question, Kind::Baseline, None).unwrap();
    drop(persistence);
    let mut narrowed = old;
    narrowed.limits.operations /= 2;
    let persistence = Persistence::open(&directory.0, narrowed).unwrap();
    assert_eq!(persistence.header.policy, crate::hex(&old.identity()));
    let mut sources = Vec::new();
    persistence
        .replay(&naome_checker::ArtifactState::new(), |_, question| {
            sources.push(question.to_hex());
            Ok(())
        })
        .unwrap();
    assert_eq!(sources, [question.to_hex()]);
}

#[test]
fn replay_preserves_a_typed_visitor_failure_without_changing_records() {
    let directory = crate::checkpoint::tests::Directory::new();
    let question = ResearchQuestion::from_hex("040101000000000100000000").unwrap();
    let mut persistence = Persistence::open(&directory.0, PrefilterPolicy::default()).unwrap();
    persistence.retain(&question, Kind::Baseline, None).unwrap();
    let error = persistence
        .replay(&naome_checker::ArtifactState::new(), |_, _| {
            Err(crate::Error::MemoryOverload {
                requested: 7,
                charged: 11,
                budget: 13,
            })
        })
        .unwrap_err();
    assert!(matches!(
        error,
        crate::Error::MemoryOverload {
            requested: 7,
            charged: 11,
            budget: 13
        }
    ));
    let latched = persistence.error().unwrap();
    assert!(latched.fatal());
    let encoded = serde_json::to_value(latched).unwrap();
    assert_eq!(
        encoded["cause_code"],
        u32::from(crate::outcome::OperationCode::MemoryOverload)
    );
    assert_eq!(encoded["requested"], 7);

    drop(persistence);
    let persistence = Persistence::open(&directory.0, PrefilterPolicy::default()).unwrap();
    let mut count = 0;
    persistence
        .replay(&naome_checker::ArtifactState::new(), |_, replayed| {
            assert_eq!(replayed.to_hex(), question.to_hex());
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn backlog_settlement_preserves_uncertain_commit_and_freezes_the_owner() {
    let directory = crate::checkpoint::tests::Directory::new();
    let question = ResearchQuestion::from_hex("040101000000000100000000").unwrap();
    let mut persistence = Persistence::open(&directory.0, PrefilterPolicy::default()).unwrap();
    let updates = persistence.queue_updates(&question).unwrap();
    persistence
        .checkpoint
        .commit(&persistence.header, updates)
        .unwrap();
    crate::checkpoint::fail_after_commit();
    let error = persistence
        .settle_backlog(question.resolution_id())
        .unwrap_err();
    assert!(matches!(error, crate::Error::UncertainDurability(_)));
    assert!(error.fatal());
    let code = error.code();
    assert_eq!(error.fatal_storage().code(), code);
    assert!(
        persistence
            .settle_backlog(question.resolution_id())
            .is_err()
    );
}

#[test]
fn question_retention_preserves_uncertain_commit_until_replay() {
    let directory = crate::checkpoint::tests::Directory::new();
    let question = ResearchQuestion::from_hex("040101000000000100000000").unwrap();
    let mut persistence = Persistence::open(&directory.0, PrefilterPolicy::default()).unwrap();
    crate::checkpoint::fail_after_commit();
    let error = persistence
        .retain(&question, Kind::Baseline, None)
        .unwrap_err();
    assert!(matches!(error, crate::Error::UncertainDurability(_)));
    assert!(persistence.retain(&question, Kind::Baseline, None).is_err());
    drop(persistence);
    let persistence = Persistence::open(&directory.0, PrefilterPolicy::default()).unwrap();
    let mut count = 0;
    persistence
        .replay(&naome_checker::ArtifactState::new(), |_, restored| {
            assert_eq!(restored.to_hex(), question.to_hex());
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn question_delivery_preserves_uncertain_commit_and_replays_admission() {
    let directory = crate::checkpoint::tests::Directory::new();
    let question = ResearchQuestion::from_hex("040101000000000100000000").unwrap();
    let policy = PrefilterPolicy::default();
    let key = crate::hex(question.record_id());
    let entry = Entry {
        encoded: question.to_hex(),
        kind: Kind::Prepared,
        first: Some(FirstAdmission {
            record: key.clone(),
            input: "01".repeat(32),
            policy: crate::hex(&policy.identity()),
            snapshot_before: "02".repeat(32),
            snapshot_after: "03".repeat(32),
            registry_before: "04".repeat(32),
            registry_after: "05".repeat(32),
        }),
    };
    let mut persistence = Persistence::open(&directory.0, policy).unwrap();
    let update = crate::checkpoint::Update::put("question", key, &entry).unwrap();
    persistence
        .checkpoint
        .commit(&persistence.header, vec![update])
        .unwrap();
    crate::checkpoint::fail_after_commit();
    let error = persistence.delivered(&question, true).unwrap_err();
    assert!(matches!(error, crate::Error::UncertainDurability(_)));
    drop(persistence);
    let mut persistence = Persistence::open(&directory.0, policy).unwrap();
    let context = naome_checker::ArtifactState::new();
    let (restored, _) = persistence
        .admitted(question.resolution_id(), &context)
        .unwrap()
        .unwrap();
    assert_eq!(restored.to_hex(), question.to_hex());
    assert_eq!(
        persistence
            .next_backlog(&context)
            .unwrap()
            .unwrap()
            .to_hex(),
        question.to_hex()
    );
}

#[test]
fn corrupted_registry_marker_is_rejected_without_replacement() {
    let directory = crate::checkpoint::tests::Directory::new();
    let marker = directory.0.join("question-registry.initialized");
    std::fs::write(&marker, b"invalid marker").unwrap();
    assert!(matches!(
        Persistence::open(&directory.0, PrefilterPolicy::default()),
        Err(crate::Error::Runtime(
            crate::RuntimeFailure::QuestionMarkerRead
        ))
    ));
    assert_eq!(std::fs::read(&marker).unwrap(), b"invalid marker");
    assert!(!directory.0.join("research/questions.sqlite3").exists());
}
