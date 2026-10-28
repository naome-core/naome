//! Development-only component comparison on genuinely qualified fresh parents.
//! The main independent-family qualification remains a separate experiment.
use super::*;

pub(super) fn check_outcomes(job: &Job, rows: &[serde_json::Value]) {
    let progress = job.progress.as_ref().unwrap();
    let mut position = 0;
    let mut scores = [0_u32; 2];
    let mut original = [0_u32; 2];
    let mut protected_loss = false;
    let mut anchor_loss = false;
    let mut transfer = transfer::Summary::default();
    let mut next = |source: &str| {
        let row = &rows[position];
        position += 1;
        assert_eq!(
            row["question"].as_str().unwrap(),
            source,
            "actual native qualification query order"
        );
        let pair = [
            row["before"]["solved"].as_bool().unwrap(),
            row["after"]["solved"].as_bool().unwrap(),
        ];
        for (name, solved) in [("before", pair[0]), ("after", pair[1])] {
            let proof = &row[name]["proof_id"];
            assert_eq!(
                proof.is_string(),
                solved,
                "every reported solution has its actual checked proof identity"
            );
            if let Some(id) = proof.as_str() {
                crate::object::id_bytes(id).unwrap();
            }
        }
        pair
    };
    for index in 0..EVALUATIONS as usize {
        if let Some(source) = if index < curriculum::DEVELOPMENT {
            Some(curriculum::development()[index].source.as_str())
        } else {
            job.base
                .anchors
                .get(index - curriculum::DEVELOPMENT)
                .map(|a| a.question.as_str())
        } {
            let pair = next(source);
            if index < curriculum::DEVELOPMENT {
                scores[0] += u32::from(pair[0]);
                scores[1] += u32::from(pair[1]);
                if index < curriculum::CORPUS_DEVELOPMENT {
                    original[0] += u32::from(pair[0]);
                    original[1] += u32::from(pair[1]);
                    protected_loss |= pair[0] && !pair[1];
                }
            } else {
                anchor_loss |= pair[0] && !pair[1];
            }
        }
        if let Some(case) = curriculum::adaptive::BANK.transfer.get(index) {
            let pair = next(&case.source);
            transfer.record(index, pair[0], pair[1]).unwrap();
        }
    }
    assert_eq!(position, rows.len());
    assert_eq!(scores, [progress.incumbent_score, progress.candidate_score]);
    assert_eq!(original, progress.original_score);
    assert_eq!(protected_loss, progress.development_regression);
    assert_eq!(anchor_loss, progress.anchor_regression);
    assert_eq!(transfer, progress.transfer);
}

fn controller_copy(source: &MetaSeed) -> MetaSeed {
    MetaSeed {
        state: source.state.clone(),
        io: MemoryStore(source.io.0.clone()),
    }
}

#[test]
#[ignore = "Explicit fresh6-context/3-method preservation comparison; development only"]
fn verified_own_preservation_comparison() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release only"
    );
    let path = std::env::var("NAOME_PRESERVATION_OUTPUT").expect("fresh preservation output");
    let path = Path::new(&path);
    assert!(!path.exists(), "preserve all prior experiments");
    std::fs::create_dir_all(path).unwrap();
    let clock = Clock::start();
    let protocol = crate::hex(&Sha256::digest(include_bytes!(
        "../../../preservation-protocol.json"
    )));
    write(
        &path.join("run-source.json"),
        &serde_json::json!({
            "scope":"development_only_preservation_component", "specification":model::specification(),
            "source_commit":std::env::var("NAOME_ADAPTIVE_COMMIT").expect("frozen source commit"),
            "protocol_sha256":protocol, "contexts":[4507,4603,4703,4801,4903,5003],
            "cold_forks_per_context":2,"warm_methods":["unmasked","binary","smoothed"],
            "maximum_complete_jobs":30,"final_inferences":0,
            "per_job_limits":{"units":150,"updates":250,"cpu_seconds":90,"wall_seconds":120,
                "io_bytes":model::REQUIREMENTS.io_bytes,"rss_bytes":model::REQUIREMENTS.work_bytes}
        }),
    );
    // Every source epoch in every context is fixed before the first update.
    let sources = [4507, 4603, 4703, 4801, 4903, 5003]
        .into_iter()
        .enumerate()
        .map(|(context, seed)| {
            let directory = path.join(format!("context-{context}"));
            let source = prepare_meta_source(seed, context, [16, 32], &directory);
            (context, seed, directory, source)
        })
        .collect::<Vec<_>>();
    write(
        &path.join("sources-ready.json"),
        &serde_json::json!({
            "contexts":sources.len(),"elapsed":clock.elapsed(),"optimizer_updates":0,
            "sources":sources.iter().map(|(context,_,_,s)|serde_json::json!({
                "context":context,"stages":s.rounds.iter().map(source_hash).collect::<Vec<_>>()
            })).collect::<Vec<_>>()
        }),
    );
    let mut all_rows = Vec::new();
    let mut coverage = 0;
    for (context, seed, directory, source) in sources {
        let mut controller = MetaSeed {
            state: meta::State::fresh(),
            io: MemoryStore::default(),
        };
        let mut parent = None;
        // Exactly two original cold forks; no forcing of a rejected parent.
        for fork in 0..2 {
            limits(&clock);
            let ((next, summary), outcomes) = transfer::observation::capture(|| {
                trial(
                    &source,
                    None,
                    None,
                    &mut controller,
                    (context, seed, 1, 0, fork),
                    &directory.join(format!("cold-fork-{fork}")),
                    model::PreservationMode::Unmasked,
                )
            });
            write(
                &directory.join(format!("cold-fork-{fork}/qualification-outcomes.json")),
                &outcomes,
            );
            let cold_job: Job = serde_json::from_slice(
                &std::fs::read(directory.join(format!("cold-fork-{fork}/job.json"))).unwrap(),
            )
            .unwrap();
            check_outcomes(&cold_job, &outcomes);
            parent = Some(retain_parent(parent, next));
            all_rows.push(
                serde_json::json!({"context":context,"method":"cold_unmasked","trial":summary}),
            );
            write(&path.join("trials.json"), &all_rows);
        }
        let mut parent = parent.unwrap();
        if !parent.promoted {
            all_rows.push(serde_json::json!({"context":context,"warm_coverage":false,"reason":"no_genuinely_qualified_cold_parent"}));
            write(&path.join("trials.json"), &all_rows);
            continue;
        }
        coverage += 1;
        assert_eq!(parent.state.model.updates, 250);
        let parent_digest = digest(&parent.state);
        // Actual disk serialization and restoration at the round boundary.
        let recovery = directory.join("parent-recovery");
        storage::spill(&mut parent.store, &recovery);
        let encoded = crate::checkpoint::encode(&parent.state).unwrap();
        std::fs::write(directory.join("parent-state.json"), &encoded).unwrap();
        parent.state =
            serde_json::from_slice(&std::fs::read(directory.join("parent-state.json")).unwrap())
                .unwrap();
        parent.state.validate().unwrap();
        storage::restore(&mut parent.store, &recovery);
        assert_eq!(digest(&parent.state), parent_digest);
        let mut plans = Vec::new();
        let methods = [
            ("unmasked", model::PreservationMode::Unmasked),
            ("binary", model::PreservationMode::Binary),
            ("smoothed", model::PreservationMode::Smoothed),
        ];
        for offset in 0..3 {
            limits(&clock);
            let (name, mode) = methods[(context + offset) % methods.len()];
            let mut current = controller_copy(&controller);
            let branch = directory.join(name);
            let ((selected, summary), outcomes) = transfer::observation::capture(|| {
                trial(
                    &source,
                    Some(&parent),
                    None,
                    &mut current,
                    (context, seed, 1, 1, 0),
                    &branch,
                    mode,
                )
            });
            write(&branch.join("qualification-outcomes.json"), &outcomes);
            assert_eq!(
                digest(&parent.state),
                parent_digest,
                "branches cannot mutate their common parent"
            );
            plans.push(digest(&summary["plan"]));
            assert!(
                plans.iter().all(|p| p == &plans[0]),
                "matched warm branches use the exact same selected plan"
            );
            let job: Job =
                serde_json::from_slice(&std::fs::read(branch.join("job.json")).unwrap()).unwrap();
            check_outcomes(&job, &outcomes);
            let training = &job.progress.as_ref().unwrap().training_cost;
            assert_eq!(training.preservation_states > 0, name != "unmasked");
            assert!(training.preservation_micros <= training.update_micros);
            assert_eq!(
                selected.state.model.updates,
                if selected.promoted { 500 } else { 250 }
            );
            all_rows.push(
                serde_json::json!({"context":context,"method":name,"trial":summary,
                "training_cost":training,"parent_state_sha256":parent_digest,
                "parent_and_controller_reused_exactly":true,"round_boundary_disk_restore":true}),
            );
            write(&path.join("trials.json"), &all_rows);
            eprintln!(
                "{}",
                serde_json::json!({"event":"preservation_branch_completed","context":context,
                "method":name,"promoted":selected.promoted,"elapsed":clock.elapsed()})
            );
        }
    }
    limits(&clock);
    write(
        &path.join("completed.json"),
        &serde_json::json!({
            "contexts":6,"qualified_warm_contexts":coverage,"coverage_complete":coverage==6,
            "elapsed":clock.elapsed(),"peak_rss_bytes":resource_boundary(),"final_inferences":0,
            "scope":"development_only_preservation_component","independent_quality_qualified":false
        }),
    );
}

fn limits(clock: &Clock) {
    assert!(
        clock.wall.elapsed() < Duration::from_secs(10_800),
        "unchanged outer wall allowance"
    );
    assert!(
        cpu_micros() - clock.cpu < 7_200_000_000,
        "unchanged outer CPU allowance"
    );
    resource_boundary();
}
