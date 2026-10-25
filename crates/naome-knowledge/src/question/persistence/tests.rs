use super::*;

#[test]
fn original_source_orientation_and_first_admission_survive_row_updates_and_restart() {
    let directory = crate::checkpoint::tests::Directory::new();
    let root = crate::storage::research_directory(&directory.0).unwrap();
    let policy = PrefilterPolicy::default();
    let question = CompiledQuestion::compile("goal = not(all(x,eq(x,x)))").unwrap();
    let key = crate::hex(question.source_hash());
    let entry = Entry {
        source: question.source().to_owned(),
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
        .entries_page(None)
        .unwrap()
        .into_iter()
        .map(|(_, entry)| entry)
        .collect::<Vec<_>>();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].kind, Kind::Prepared);
    assert!(
        CompiledQuestion::compile(&restored[0].source)
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
        .entries_page(None)
        .unwrap()
        .into_iter()
        .map(|(_, entry)| entry)
        .collect::<Vec<_>>();
    assert_eq!(restored[0].kind, Kind::Admitted);
    assert_eq!(restored[0].source, question.source());
    assert_eq!(
        crate::checkpoint::encode(restored[0].first.as_ref().unwrap()).unwrap(),
        expected
    );
    drop(persistence);
    std::fs::remove_file(root.join("questions.sqlite3")).unwrap();
    assert!(Persistence::open(&directory.0, policy).is_err());
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
            .chunks(crate::resources::limits().question_page)
        {
            let mut updates = Vec::new();
            for index in chunk {
                let question =
                    CompiledQuestion::compile(&crate::checkpoint::tests::question_source(*index))
                        .unwrap();
                let key = crate::hex(question.source_hash());
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
                    source: question.source().to_owned(),
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
        questions.attach_persistence(&directory).unwrap();
        let replay_seconds = replay.elapsed().as_secs_f64();
        assert_eq!(questions.registry.len(), (phase + 1) * BATCH);
        assert!(questions.known.len() <= crate::resources::limits().question_page);
        assert!(questions.admitted.len() <= crate::resources::limits().question_page);
        let persistence = questions.persistence.as_mut().unwrap();
        for index in phase * 16..(phase + 1) * 16 {
            assert_eq!(
                persistence.next_backlog().unwrap().unwrap().source(),
                crate::checkpoint::tests::question_source(index)
            );
        }
        let first =
            CompiledQuestion::compile(&crate::checkpoint::tests::question_source(0)).unwrap();
        assert_eq!(
            persistence
                .admitted(first.resolution_id())
                .unwrap()
                .unwrap()
                .0
                .source(),
            first.source()
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
    let question = CompiledQuestion::compile("goal=all(x,mem(x,x))").unwrap();
    let mut persistence = Persistence::open(&directory.0, old).unwrap();
    persistence.retain(&question, Kind::Baseline, None).unwrap();
    drop(persistence);
    let mut narrowed = old;
    narrowed.limits.operations /= 2;
    let persistence = Persistence::open(&directory.0, narrowed).unwrap();
    assert_eq!(persistence.header.policy, crate::hex(&old.identity()));
    let mut sources = Vec::new();
    persistence
        .replay(|_, question| {
            sources.push(question.source().to_owned());
            Ok(())
        })
        .unwrap();
    assert_eq!(sources, [question.source()]);
}
