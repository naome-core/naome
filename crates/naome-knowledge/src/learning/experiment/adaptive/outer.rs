//! Matched initial and genuinely retained lower-state meta-training trials.
use super::*;

pub(super) struct Controllers {
    pub(super) fresh: MetaSeed,
    pub(super) continuation: MetaSeed,
}
struct Source {
    initial: State,
    common: Common,
    rounds: Vec<acquisition::FrozenRound>,
}
struct Parent {
    state: State,
    store: Store,
    job: u64,
    promoted: bool,
    before: crate::training::ability::Profile,
}
fn source_hash(input: &acquisition::FrozenRound) -> String {
    digest(&(&input.state.replay, &input.state.anchors, &input.evidence))
}
fn retain_parent(current: Option<Parent>, next: Parent) -> Parent {
    match current {
        Some(previous) if previous.promoted || !next.promoted => previous,
        _ => next,
    }
}
fn checkpoint_copy(from: &MemoryStore, to: &mut Store, checkpoint: &Checkpoint) {
    for blob in checkpoint.blobs() {
        let mut input = MemoryStore(from.0.clone());
        let bytes = artifact::load(&mut input, blob).unwrap();
        assert_eq!(*blob, artifact::save(to, &bytes).unwrap());
    }
}
fn prepare_meta_source(seed: u64, context: usize, dir: &Path) -> Source {
    let mut common = common(seed, &dir.join("common"));
    let initial = common.state.clone();
    let mut rounds = Vec::new();
    let acquisition_clock = Clock::start();
    let mut engine = Engine::default();
    let mut graph = crate::Graph::default();
    for row in &common.rows {
        if !row["solution"].is_null() {
            let s: Solution = serde_json::from_value(row["solution"].clone()).unwrap();
            let q = CompiledQuestion::compile(row["question"].as_str().unwrap()).unwrap();
            admit_discovery(&mut graph, &q, &s).unwrap();
        }
    }
    let mut cases = curriculum::adaptive::BANK
        .learning
        .iter()
        .filter(|q| meta_partition(&q.source, true))
        .collect::<Vec<_>>();
    cases.sort_by_key(|q| Sha256::digest(format!("{seed}:{}", q.id).as_bytes()));
    // Contexts vary observed source structure without supplying witnesses.
    if context >= 3 {
        let wanted = format!("adaptive-operation-{}", 1 + (context - 3) % 3);
        cases.sort_by_key(|q| q.family != wanted);
    }
    for (i, q) in cases.into_iter().take(32).enumerate() {
        let row = acquire(
            &mut common.state,
            &q.source,
            100 + i as u64,
            &mut engine,
            &mut common.store,
            &mut graph,
            (&mut common.evidence, false),
        );
        common.state.observe_result(
            &q.source,
            !row["solution"].is_null(),
            row["diagnostic"].as_str().unwrap(),
            row["elapsed_micros"].as_u64().unwrap(),
            128,
        );
        common.rows.push(row);
        if (i + 1) % 16 == 0 {
            let stage = rounds.len();
            let mut state = common.state.clone();
            state
                .compact_with_meta_headroom(outer_metadata_headroom(&state))
                .unwrap();
            state.validate().unwrap();
            assert!(
                state.needs_training(),
                "each frozen outer epoch needs a genuine diverse pool"
            );
            let input = acquisition::FrozenRound {
                state,
                evidence: common.evidence.clone(),
                rows: common.rows.clone(),
            };
            write(&dir.join(format!("stage-{stage}-state.json")), &input.state);
            write(
                &dir.join(format!("stage-{stage}-evidence.json")),
                &input.evidence,
            );
            write(
                &dir.join(format!("stage-{stage}-acquisitions.json")),
                &input.rows,
            );
            write(
                &dir.join(format!("stage-{stage}-manifest.json")),
                &serde_json::json!({"source_sha256":source_hash(&input),"epoch":input.state.epoch,
                    "queries":(stage+1)*16,"replay":input.state.replay.len(),
                    "replay_dependencies":input.state.replay.iter().map(|e|
                        curriculum::owned::case(&e.question).unwrap().dependency).collect::<BTreeSet<_>>()}),
            );
            rounds.push(input);
        }
    }
    let metadata_headroom = outer_metadata_headroom(&common.state);
    common
        .state
        .compact_with_meta_headroom(metadata_headroom)
        .unwrap();
    write(&dir.join("source-state.json"), &common.state);
    write(&dir.join("source-evidence.json"), &common.evidence);
    write(&dir.join("source-acquisitions.json"), &common.rows);
    write(&dir.join("source-cost.json"), &acquisition_clock.elapsed());
    write(
        &dir.join("source-capacity.json"),
        &serde_json::json!({"meta_bytes":META_HEADROOM,"total_metadata_headroom":metadata_headroom,
            "state_bytes":crate::checkpoint::encode(&common.state).unwrap().len(),
            "development_capacity_bytes":crate::checkpoint::encode(&development_capacity_profile(common.state.feedback.checkpoint.clone())).unwrap().len()}),
    );
    assert!(
        common.state.needs_training(),
        "outer context must have a genuine diverse checked pool"
    );
    assert_eq!(rounds.len(), 2);
    assert!(
        rounds[1].state.epoch.saturating_sub(rounds[0].state.epoch) >= 4,
        "the later owned source epoch must independently enable continuation"
    );
    Source {
        initial,
        common,
        rounds,
    }
}
#[test]
#[ignore = "Explicit six-context two-epoch cold qualification; no optimizer or final inference"]
fn outer_source_layout_preflight() {
    let output = std::env::var("NAOME_META_SOURCE_OUTPUT").expect("fresh source output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve prior source qualification");
    std::fs::create_dir_all(output).unwrap();
    let clock = Clock::start();
    for (context, seed) in [4507, 4603, 4703, 4801, 4903, 5003].into_iter().enumerate() {
        let directory = output.join(format!("context-{context}"));
        let source = prepare_meta_source(seed, context, &directory);
        for input in &source.rounds {
            assert!(input.state.needs_training());
            input.state.validate().unwrap();
            let _ = input
                .state
                .training_pool(&evidence_for(&input.state, &input.evidence))
                .unwrap();
        }
    }
    write(
        &output.join("completed.json"),
        &serde_json::json!({"contexts":6,"stages":2,"queries_per_context":32,
            "elapsed":clock.elapsed(),"optimizer_updates":0,"final_inferences":0}),
    );
}
fn trial(
    source: &Source,
    parent: Option<&Parent>,
    observed: Option<&crate::training::ability::Profile>,
    controller: &mut MetaSeed,
    coordinates: (usize, u64, usize, usize, usize),
    path: &Path,
) -> (Parent, serde_json::Value) {
    let (context, seed, mode, stage, fork) = coordinates;
    let clock = Clock::start();
    std::fs::create_dir_all(path).unwrap();
    let input = &source.rounds[stage];
    let previous = parent.map_or(&source.initial, |p| &p.state);
    let mut state = acquisition::bind(input, previous);
    state.meta = controller.state.clone();
    state.preparation = Preparation::Meta;
    if let Some(observed) = observed {
        assert!(parent.is_none());
        assert_eq!(observed.checkpoint, digest(&state.model));
        state.feedback.development = observed.clone();
    }
    state.validate().unwrap();
    assert!(state.needs_training());
    assert_eq!(state.model, previous.model);
    assert_eq!(
        source_hash(input),
        digest(&(&state.replay, &state.anchors, &input.evidence))
    );
    let initial = source.initial.model.clone();
    let mut store = fork_store(&source.common.store);
    let io_start = store.read_bytes + store.written_bytes;
    if let Some(parent) = parent {
        checkpoint_copy(&parent.store.inner, &mut store, &parent.state.model);
    }
    copy_meta(&controller.io, &mut store, &controller.state);
    export_model(&path.join("parent"), &state.model, &store.inner);
    write(&path.join("input-state.json"), &state);
    let mut job = state.job();
    job.training = true;
    job.evidence = evidence_for(&state, &input.evidence);
    job.validate().unwrap();
    assert_eq!(job.units(), model::TRAINING_UNITS + EVALUATIONS + 1);
    state.attempted(state.learning_epoch());
    let job_id =
        9_000_000 + context as u64 * 100 + mode as u64 * 10 + stage as u64 * 2 + fork as u64;
    let mut engine = Engine::default();
    for unit in 1..=job.units() {
        assert!(
            clock.wall.elapsed() < Duration::from_secs(120)
                && cpu_micros() - clock.cpu < 90_000_000,
            "bounded complete outer trial"
        );
        job.execute(unit, None, job_id, &mut engine, &mut store)
            .unwrap();
        job.validate().unwrap();
        if unit == model::TRAINING_UNITS {
            export_model(
                &path.join("candidate"),
                job.progress.as_ref().unwrap().candidate.as_ref().unwrap(),
                &store.inner,
            );
        }
        collect(&mut store, &initial, Some(&job), &state);
    }
    assert!(
        store.read_bytes + store.written_bytes - io_start <= model::REQUIREMENTS.io_bytes as u64
    );
    assert!(state.qualify(&job));
    state.validate().unwrap();
    let progress = job.progress.as_ref().unwrap();
    let promoted = state.promotions > job.base.promotions;
    if promoted {
        assert_eq!(
            state.model.updates,
            job.base.model.updates + u64::from(model::TRAINING_UNITS) * model::UPDATES_PER_UNIT
        );
    } else {
        assert_eq!(
            state.model, job.base.model,
            "rejection retains exact lower weights and Adam"
        );
    }
    controller.state = state.meta.clone();
    controller.io.0.clear();
    for blob in controller.state.model.blobs() {
        for index in 0..blob.chunks() {
            controller.io.0.insert(
                (blob.sha256.clone(), index),
                store.inner.0[&(blob.sha256.clone(), index)].clone(),
            );
        }
    }
    export_meta(&path.join("meta"), &controller.state.model, &controller.io);
    export_model(&path.join("selected"), &state.model, &store.inner);
    write(&path.join("job.json"), &job);
    write(&path.join("state.json"), &state);
    resource_boundary();
    let summary = serde_json::json!({"context":context,"seed":seed,"mode":if mode==0 {"fresh"} else {"continuation"},
        "stage":stage,"fork":fork,"job":job_id,"parent_job":parent.map(|p|p.job),
        "parent_promoted":parent.is_some_and(|p|p.promoted),"base_model":job.base.model,
        "base_epoch":job.base.epoch,"base_trained":job.base.trained,"base_attempted":job.base.attempted,
        "source_sha256":source_hash(input),"promoted":promoted,"selected":state.model,
        "elapsed":clock.elapsed(),"io_bytes":store.read_bytes+store.written_bytes-io_start,
        "plan":progress.plan,"outcome":progress.meta_update,"meta_state":controller.state});
    let before = progress.development_before.clone();
    collect(&mut store, &initial, None, &state);
    (
        Parent {
            state,
            store,
            job: job_id,
            promoted,
            before,
        },
        summary,
    )
}
pub(super) fn train(path: &Path, pilot: bool) -> Controllers {
    std::fs::create_dir_all(path).unwrap();
    let clock = Clock::start();
    let contexts = if pilot {
        vec![3607]
    } else {
        vec![4507, 4603, 4703, 4801, 4903, 5003]
    };
    let mut controllers = Controllers {
        fresh: MetaSeed {
            state: meta::State::fresh(),
            io: MemoryStore::default(),
        },
        continuation: MetaSeed {
            state: meta::State::fresh(),
            io: MemoryStore::default(),
        },
    };
    // Both complete source epochs are fixed before the first optimizer call.
    let sources = contexts
        .into_iter()
        .enumerate()
        .map(|(context, seed)| {
            let dir = path.join(format!("context-{context}"));
            let source = prepare_meta_source(seed, context, &dir);
            (context, seed, dir, source)
        })
        .collect::<Vec<_>>();
    write(
        &path.join("sources-ready.json"),
        &serde_json::json!({"contexts":sources.len(),"stages":2,"elapsed":clock.elapsed()}),
    );
    let mut summaries = Vec::new();
    for (context, seed, dir, source) in sources {
        for mode in if context % 2 == 0 { [0, 1] } else { [1, 0] } {
            let name = if mode == 0 { "fresh" } else { "continuation" };
            let controller = if mode == 0 {
                &mut controllers.fresh
            } else {
                &mut controllers.continuation
            };
            let mut parent = None;
            for stage in 0..2 {
                let mut retained = None;
                for fork in 0..2 {
                    assert!(
                        clock.wall.elapsed() < Duration::from_secs(10_800)
                            && cpu_micros() - clock.cpu < 7_200_000_000,
                        "finite outer resource bound"
                    );
                    let trial_path = dir.join(name).join(format!("stage-{stage}-fork-{fork}"));
                    let (next, summary) = trial(
                        &source,
                        if mode == 1 { parent.as_ref() } else { None },
                        if mode == 0 {
                            parent.as_ref().map(|p| &p.before)
                        } else {
                            None
                        },
                        controller,
                        (context, seed, mode, stage, fork),
                        &trial_path,
                    );
                    retained = Some(retain_parent(retained, next));
                    summaries.push(summary);
                    write(&path.join("trials.json"), &summaries);
                    eprintln!(
                        "{}",
                        serde_json::json!({"event":"outer_meta_trial_completed","context":context,
                        "mode":name,"stage":stage,"fork":fork,"meta_updates":controller.state.model.updates,"elapsed":clock.elapsed()})
                    );
                }
                parent = retained;
            }
        }
    }
    let warm = summaries
        .iter()
        .filter(|s| s["base_model"]["updates"].as_u64().unwrap() > 0)
        .count();
    let warm_contexts = summaries
        .iter()
        .filter(|s| s["base_model"]["updates"].as_u64().unwrap() > 0)
        .map(|s| s["context"].as_u64().unwrap())
        .collect::<BTreeSet<_>>()
        .len();
    write(&path.join("trials.json"), &summaries);
    write(
        &path.join("completed.json"),
        &serde_json::json!({"experiences":summaries.len(),"elapsed":clock.elapsed(),
        "fresh":controllers.fresh.state,"continuation":controllers.continuation.state,
        "warm_trials":warm,"warm_contexts":warm_contexts,"coverage_complete":warm_contexts==if pilot {1} else {6}}),
    );
    controllers
}

#[cfg(test)]
mod tests;
