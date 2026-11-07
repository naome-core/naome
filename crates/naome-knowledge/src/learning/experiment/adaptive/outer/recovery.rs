//! Isolate retention and historical reload on fixed genuinely promoted parents.
use super::*;
use crate::learning::{coverage::control, model::observation};
mod history;
const SEEDS: [u64; 6] = [4507, 4603, 4703, 4801, 4903, 5003];
const METHODS: [(&str, bool, bool); 4] = [
    ("original", false, false),
    ("coverage", true, false),
    ("history", false, true),
    ("coverage_history", true, true),
];
fn limits(clock: &Clock) {
    assert!(clock.wall.elapsed() < Duration::from_secs(10_800));
    assert!(cpu_micros() - clock.cpu < 7_200_000_000);
    resource_boundary();
}
fn job_limits(clock: &Clock) {
    assert!(clock.wall.elapsed() < Duration::from_secs(120));
    assert!(cpu_micros() - clock.cpu < 90_000_000);
}
fn bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                bytes(&path)
            } else {
                path.metadata().unwrap().len()
            }
        })
        .sum()
}
fn later(source: &Source) -> acquisition::FrozenRound {
    let first = &source.rounds[0];
    let mut state = first.state.clone();
    for row in source.rounds[1].rows.iter().skip(first.rows.len()) {
        if !row["solution"].is_null() {
            let solution: Solution = serde_json::from_value(row["solution"].clone()).unwrap();
            state
                .accept(Example {
                    origin: Origin::Local,
                    job: row["job"].as_u64().unwrap(),
                    question: row["question"].as_str().unwrap().into(),
                    proof_id: solution.proof_id,
                    refuted: solution.refuted,
                    tree: solution.tree,
                })
                .unwrap();
        }
        state.observe_result(
            row["question"].as_str().unwrap(),
            !row["solution"].is_null(),
            row["diagnostic"].as_str().unwrap(),
            row["elapsed_micros"].as_u64().unwrap(),
            128,
        );
    }
    state
        .compact_with_meta_headroom(outer_metadata_headroom(&state))
        .unwrap();
    state.validate().unwrap();
    assert_eq!(digest(&state.knowledge), digest(&first.state.knowledge));
    assert_eq!(digest(&state.definitions), digest(&first.state.definitions));
    assert_eq!(digest(&state.anchors), digest(&first.state.anchors));
    acquisition::FrozenRound {
        state,
        evidence: source.rounds[1].evidence.clone(),
        rows: source.rounds[1].rows.clone(),
    }
}
fn warm(
    source: &Source,
    parent: &Parent,
    context: usize,
    reload: bool,
    directory: &Path,
    history: &Path,
) -> serde_json::Value {
    let clock = Clock::start();
    std::fs::create_dir_all(directory).unwrap();
    let input = later(source);
    let mut state = acquisition::bind(&input, &parent.state);
    state.preparation = Preparation::Targeted;
    state.validate().unwrap();
    assert_eq!(state.model, parent.state.model);
    if !state.needs_training() {
        write(&directory.join("input-state.json"), &state);
        return serde_json::json!({"complete":false,"reason":"no_eligible_continuation_epoch","elapsed":clock.elapsed()});
    }
    let mut io = history::Io {
        store: fork_store(&source.common.store),
        directory: history.into(),
        source_bytes: 0,
        source_reads: 0,
    };
    checkpoint_copy(&parent.store.inner, &mut io.store, &state.model);
    for blob in state.meta.model.blobs() {
        let mut input = MemoryStore(parent.store.inner.0.clone());
        let data = artifact::load(&mut input, blob).unwrap();
        assert_eq!(artifact::save(&mut io, &data).unwrap(), *blob);
    }
    export_model(&directory.join("parent"), &state.model, &io.store.inner);
    write(&directory.join("input-state.json"), &state);
    let mut job = state.job();
    job.training = true;
    job.evidence = evidence_for(&state, &input.evidence);
    let id = 9_500_000 + context as u64;
    if reload {
        job.request_history(id);
    }
    job.validate().unwrap();
    assert_eq!(job.units(), 150);
    state.attempted(state.learning_epoch());
    let current = observation::own_sources(&job);
    let mut earlier = source.rounds[0].state.job();
    earlier.evidence = evidence_for(&earlier.base, &source.rounds[0].evidence);
    let earlier = observation::own_sources(&earlier);
    let mut engine = Engine::default();
    engine.preservation_mode = model::PreservationMode::Unmasked;
    let mut available = observation::Decisions::new();
    let mut sampled = observation::Decisions::new();
    let mut units = Vec::new();
    let (_, outcomes) = transfer::observation::capture(|| {
        for unit in 1..=job.units() {
            job_limits(&clock);
            let before = job.progress.as_ref().map_or(job.base.draws, |p| p.rng);
            job.execute(unit, None, id, &mut engine, &mut io).unwrap();
            job.validate().unwrap();
            let progress = job.progress.as_ref().unwrap();
            if unit <= model::TRAINING_UNITS {
                assert_eq!(progress.plan.as_ref().unwrap().plan, meta::Plan::targeted());
                let batches = observation::consumed(
                    &engine,
                    before,
                    progress.rng,
                    &mut available,
                    &mut sampled,
                );
                units.push(serde_json::json!({"unit":unit,"cursor_before":before,"cursor_after":progress.rng,
                    "batches":batches,"checkpoint":progress.candidate,"phase":meta::Plan::targeted().phase(unit-1),
                    "first_loss_bits":progress.first_loss.unwrap().to_bits(),"last_loss_bits":progress.last_loss.unwrap().to_bits(),
                    "training_cost":progress.training_cost,"prepared":progress.prepared}));
            }
            if unit == 1 && reload {
                for (name, blob) in [
                    ("history-page", &job.history.as_ref().unwrap().blob),
                    (
                        "prepared-working",
                        &progress.prepared.as_ref().unwrap().blob,
                    ),
                ] {
                    let data = artifact::load(&mut io, blob).unwrap();
                    std::fs::write(directory.join(format!("{name}.json")), data).unwrap();
                }
            }
            if unit == model::TRAINING_UNITS {
                let candidate = progress.candidate.as_ref().unwrap();
                assert_eq!(candidate.updates, 500);
                export_model(&directory.join("candidate"), candidate, &io.store.inner);
            }
            collect(&mut io.store, &source.initial.model, Some(&job), &state);
        }
    });
    preservation::check_outcomes(&job, &outcomes);
    assert!(state.qualify(&job));
    state.validate().unwrap();
    let promoted = state.promotions > job.base.promotions;
    assert_eq!(state.model.updates, if promoted { 500 } else { 250 });
    if !promoted {
        assert_eq!(state.model, parent.state.model);
    }
    let progress = job.progress.as_ref().unwrap();
    assert_eq!(progress.rng - job.base.draws, 4000);
    export_model(&directory.join("selected"), &state.model, &io.store.inner);
    export_meta(&directory.join("meta"), &state.meta.model, &io.store.inner);
    write(&directory.join("job.json"), &job);
    write(&directory.join("state.json"), &state);
    write(&directory.join("qualification-outcomes.json"), &outcomes);
    write(&directory.join("units.json"), &units);
    write(&directory.join("available.json"), &available);
    write(&directory.join("sampled.json"), &sampled);
    let observed = serde_json::json!({"earlier":observation::coverage(&earlier,&available,&sampled),
        "current":observation::coverage(&current,&available,&sampled)});
    write(&directory.join("coverage.json"), &observed);
    let evidence_bytes = bytes(directory);
    let io_bytes = io.store.read_bytes + io.store.written_bytes + io.source_bytes + evidence_bytes;
    assert!(io_bytes <= model::REQUIREMENTS.io_bytes as u64);
    job_limits(&clock);
    serde_json::json!({"complete":true,"promoted":promoted,"selected":state.model,"parent_job":parent.job,
        "parent_checkpoint":parent.state.model,"prepared":progress.prepared,"plan":progress.plan,
        "diagnostic":progress.diagnostic,"before":progress.incumbent_score,"after":progress.candidate_score,
        "protected_loss":progress.development_regression,"anchor_loss":progress.anchor_regression,"transfer":progress.transfer,
        "elapsed":clock.elapsed(),"source_read_bytes":io.source_bytes,"source_read_operations":io.source_reads,
        "model_read_bytes":io.store.read_bytes,"model_written_bytes":io.store.written_bytes,
        "evidence_output_bytes":evidence_bytes,"total_accounted_io_bytes":io_bytes,"coverage":observed})
}
#[test]
#[ignore = "Explicit fixed six-context four-arm source-recovery comparison; development only"]
fn bounded_source_recovery_comparison() {
    assert!(!std::hint::black_box(cfg!(debug_assertions)));
    let output = std::env::var("NAOME_RECOVERY_OUTPUT").expect("fresh comparison output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve prior measurements");
    std::fs::create_dir_all(output).unwrap();
    let clock = Clock::start();
    write(
        &output.join("run-source.json"),
        &serde_json::json!({"source":std::env::var("NAOME_ADAPTIVE_COMMIT").unwrap(),
        "specification":model::specification(),"protocol_sha256":crate::hex(&Sha256::digest(include_bytes!("../../../recovery-protocol.json"))),
        "seeds":SEEDS,"scope":"development_only_source_recovery","maximum_jobs":36,"final_queries":0}),
    );
    let sources = SEEDS
        .into_iter()
        .enumerate()
        .map(|(context, seed)| {
            let path = output.join(format!("context-{context}"));
            let source = control::with(false, || {
                prepare_meta_source(seed, context, [16, 32], &path)
            });
            history::persist(&source, &path.join("history"));
            (context, seed, path, source)
        })
        .collect::<Vec<_>>();
    write(
        &output.join("sources-ready.json"),
        &serde_json::json!({"contexts":6,"elapsed":clock.elapsed(),"updates":0}),
    );
    let mut rows = Vec::new();
    let mut covered = 0;
    for (context, seed, path, source) in sources {
        let mut controller = MetaSeed {
            state: meta::State::fresh(),
            io: MemoryStore::default(),
        };
        let mut parent = None;
        for fork in 0..2 {
            limits(&clock);
            let branch = path.join(format!("cold-fork-{fork}"));
            let ((next, summary), outcomes) = transfer::observation::capture(|| {
                control::with(false, || {
                    trial(
                        &source,
                        None,
                        None,
                        &mut controller,
                        (context, seed, 1, 0, fork),
                        &branch,
                        model::PreservationMode::Unmasked,
                    )
                })
            });
            let job: Job =
                serde_json::from_slice(&std::fs::read(branch.join("job.json")).unwrap()).unwrap();
            preservation::check_outcomes(&job, &outcomes);
            write(&branch.join("qualification-outcomes.json"), &outcomes);
            parent = Some(retain_parent(parent, next));
            rows.push(
                serde_json::json!({"context":context,"method":"cold_unmasked","trial":summary}),
            );
            write(&output.join("trials.json"), &rows);
            eprintln!("source_recovery_cold_completed {context} {fork}");
        }
        let mut parent = parent.unwrap();
        if !parent.promoted {
            rows.push(serde_json::json!({"context":context,"warm_coverage":false,"reason":"no_genuine_parent"}));
            write(&output.join("trials.json"), &rows);
            continue;
        }
        covered += 1;
        let parent_hash = digest(&parent.state);
        let recovery = path.join("parent-recovery");
        storage::spill(&mut parent.store, &recovery);
        write(&path.join("parent-state.json"), &parent.state);
        parent.state =
            serde_json::from_slice(&std::fs::read(path.join("parent-state.json")).unwrap())
                .unwrap();
        storage::restore(&mut parent.store, &recovery);
        assert_eq!(digest(&parent.state), parent_hash);
        for offset in 0..METHODS.len() {
            limits(&clock);
            let (name, structural, reload) = METHODS[(context + offset) % METHODS.len()];
            eprintln!("source_recovery_warm_started {context} {name}");
            let result = control::with(structural, || {
                warm(
                    &source,
                    &parent,
                    context,
                    reload,
                    &path.join(name),
                    &path.join("history"),
                )
            });
            assert_eq!(digest(&parent.state), parent_hash);
            rows.push(serde_json::json!({"context":context,"method":name,"structural":structural,"history":reload,
                "common_parent_sha256":parent_hash,"trial":result}));
            write(&output.join("trials.json"), &rows);
            eprintln!("source_recovery_warm_completed {context} {name}");
        }
    }
    limits(&clock);
    write(
        &output.join("completed.json"),
        &serde_json::json!({"contexts":6,"qualified_warm_contexts":covered,
        "coverage_complete":covered==6,"elapsed":clock.elapsed(),"peak_rss_bytes":resource_boundary(),
        "scope":"development_only_source_recovery","final_queries":0,"independent_quality_qualified":false}),
    );
}

#[test]
#[ignore = "Explicit fresh acquisition and four-arm preparation preflight; zero optimizer updates"]
fn source_recovery_preflight() {
    let output = std::env::var("NAOME_RECOVERY_OUTPUT").expect("fresh preflight output");
    let output = Path::new(&output);
    assert!(!output.exists());
    std::fs::create_dir_all(output).unwrap();
    let clock = Clock::start();
    for (context, seed) in SEEDS.into_iter().enumerate() {
        let path = output.join(format!("context-{context}"));
        let source = control::with(false, || {
            prepare_meta_source(seed, context, [16, 32], &path)
        });
        history::persist(&source, &path.join("history"));
        for (name, structural, reload) in METHODS {
            control::with(structural, || {
                let input = later(&source);
                assert!(input.state.needs_training());
                let mut job = input.state.job();
                job.training = true;
                job.evidence = evidence_for(&job.base, &input.evidence);
                let mut io = history::Io {
                    store: fork_store(&source.common.store),
                    directory: path.join("history"),
                    source_bytes: 0,
                    source_reads: 0,
                };
                if reload {
                    job.request_history(9_500_000 + context as u64);
                    job.history = Some(io.history(job.history_request.as_ref().unwrap()).unwrap());
                    let result = job.preflight_history(&mut io).unwrap();
                    write(&path.join(format!("{name}-preflight.json")), &result);
                } else {
                    let pool = job.base.training_pool_for(&job.evidence, true).unwrap();
                    assert!(!pool.is_empty());
                }
            });
        }
        limits(&clock);
    }
    write(
        &output.join("completed.json"),
        &serde_json::json!({"contexts":6,"methods":4,"optimizer_updates":0,"final_queries":0,"elapsed":clock.elapsed()}),
    );
}
