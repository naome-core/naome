//! Frozen-plan, bounded replay replacement as a diagnostic intervention only.
use super::*;

type Stratum = (bool, String);
fn stratum(e: &Example) -> Stratum {
    (
        matches!(e.origin, Origin::Peer { .. }),
        curriculum::owned::case(&e.question).unwrap().dependency,
    )
}

fn selected(previous: &State, current: &State) -> State {
    assert_eq!(digest(&previous.anchors), digest(&current.anchors));
    let anchors: BTreeSet<_> = current.anchors.iter().map(|e| &e.proof_id).collect();
    let old_ids: BTreeSet<_> = previous.training_sources().map(|e| &e.proof_id).collect();
    let mut counts: BTreeMap<Stratum, usize> = BTreeMap::new();
    let mut old: BTreeMap<Stratum, BTreeMap<String, Example>> = BTreeMap::new();
    let mut new: BTreeMap<Stratum, BTreeMap<String, Example>> = BTreeMap::new();
    let mut replay = Vec::new();
    for e in previous.training_sources() {
        if !anchors.contains(&e.proof_id) {
            old.entry(stratum(e))
                .or_default()
                .insert(e.proof_id.clone(), e.clone());
        }
    }
    for e in &current.replay {
        if anchors.contains(&e.proof_id) {
            replay.push(e.clone());
            continue;
        }
        *counts.entry(stratum(e)).or_default() += 1;
        if !old_ids.contains(&e.proof_id) {
            new.entry(stratum(e))
                .or_default()
                .insert(e.proof_id.clone(), e.clone());
        }
    }
    for (key, count) in counts {
        let old = old.remove(&key).unwrap_or_default();
        let new = new.remove(&key).unwrap_or_default();
        let historical = count
            .div_ceil(2)
            .clamp(count.saturating_sub(new.len()), old.len().min(count));
        replay.extend(old.into_values().take(historical));
        replay.extend(new.into_values().take(count - historical));
    }
    replay.sort_by(|a, b| a.job.cmp(&b.job).then(a.proof_id.cmp(&b.proof_id)));
    let mut state = current.clone();
    state.replay = replay;
    assert_eq!(state.replay.len(), current.replay.len());
    let distribution = |state: &State| {
        let mut counts = BTreeMap::new();
        for e in &state.replay {
            *counts.entry(stratum(e)).or_insert(0usize) += 1;
        }
        counts
    };
    assert_eq!(distribution(&state), distribution(current));
    state
        .validate()
        .expect("frozen selection must fit the unchanged state limits");
    assert!(state.needs_training(), "unchanged diverse training minimum");
    state
}

fn merged_evidence(case: &Case) -> Vec<Evidence> {
    let mut merged: BTreeMap<(u64, String), Evidence> = BTreeMap::new();
    for e in read::<Vec<Evidence>>(&case.parent_evidence)
        .into_iter()
        .chain(read::<Vec<Evidence>>(&case.current_evidence))
    {
        let key = (e.job, e.proof_id.clone());
        if let Some(previous) = merged.insert(key, e.clone()) {
            assert_eq!(digest(&previous), digest(&e));
        }
    }
    merged.into_values().collect()
}

fn inputs() -> Diagnosis {
    let path = std::env::var("NAOME_RETENTION_INPUT").expect("frozen owned inputs");
    let diagnosis: Diagnosis = read(&path);
    assert_eq!(diagnosis.cases.len(), 8);
    for (path, hash) in &diagnosis.original_sha256 {
        assert_eq!(
            crate::hex(&Sha256::digest(std::fs::read(path).unwrap())),
            *hash
        );
    }
    diagnosis
}

#[test]
#[ignore = "Explicit outcome-blind bounded selection preflight; no inference or updates"]
fn owned_retention_selection_preflight() {
    let output = std::env::var("NAOME_RETENTION_OUTPUT").expect("fresh preflight output");
    let output = Path::new(&output);
    assert!(!output.exists(), "preserve prior selections");
    let diagnosis = inputs();
    let mut rows = Vec::new();
    for case in &diagnosis.cases {
        let previous: State = read(&case.parent_state);
        let current: State = read(&case.current_state);
        previous.validate().unwrap();
        current.validate().unwrap();
        let chosen = selected(&previous, &current);
        let evidence = merged_evidence(case);
        let pool = chosen.training_pool_for(&evidence, true).unwrap();
        assert!(!pool.is_empty());
        let old: BTreeSet<_> = previous.training_sources().map(|e| &e.proof_id).collect();
        let directory = output.join(&case.name);
        std::fs::create_dir_all(&directory).unwrap();
        write(&directory.join("state.json"), &chosen);
        write(&directory.join("evidence.json"), &evidence);
        rows.push(serde_json::json!({"case":case.name,"state_sha256":digest(&chosen),
            "state_bytes":crate::checkpoint::encode(&chosen).unwrap().len(),
            "current_state_bytes":crate::checkpoint::encode(&current).unwrap().len(),
            "replay":chosen.replay.len(),"original_replay":current.replay.len(),
            "retained_old_sources":chosen.training_sources().filter(|e|old.contains(&e.proof_id)).count(),
            "new_sources":chosen.training_sources().filter(|e|!old.contains(&e.proof_id)).count(),
            "selected_proof_ids":chosen.training_sources().map(|e|&e.proof_id).collect::<Vec<_>>(),
            "checked_decision_states":pool.graphs().len()}));
    }
    write(
        &output.join("completed.json"),
        &serde_json::json!({"cases":rows,
        "optimizer_updates":0,"new_proof_queries":0,"all_cases_feasible":true}),
    );
}

fn train(
    state: &State,
    evidence: &[Evidence],
    plan: &meta::Plan,
    case: &Case,
    output: &Path,
) -> (Checkpoint, Store, u64, [f32; 2], Engine) {
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let mut store = Store::default();
    let parent = checkpoint(&case.parent_checkpoint, &mut store);
    assert_eq!(parent, state.model);
    let mut candidate = parent.clone();
    let mut engine = Engine::default();
    let mut cursor = state.draws;
    let mut losses = [0.; 2];
    let mut units = Vec::new();
    for unit in 0..model::TRAINING_UNITS {
        limits(started, cpu);
        let (next, first, last) = engine
            .train_replay_using(
                &candidate,
                state,
                evidence,
                &mut cursor,
                plan.phase(unit),
                &mut store,
            )
            .unwrap()
            .expect("same genuine checked pool");
        if unit == 0 {
            losses[0] = first;
        }
        losses[1] = last;
        candidate = next;
        state.validate().unwrap();
        units.push(
            serde_json::json!({"unit":unit+1,"checkpoint":candidate,"cursor":cursor,
            "first_loss":first,"last_loss":last,"training_cost":engine.cost}),
        );
        let keep = parent
            .blobs()
            .chain(candidate.blobs())
            .map(|b| &b.sha256)
            .collect::<BTreeSet<_>>();
        store.inner.0.retain(|(hash, _), _| keep.contains(hash));
    }
    limits(started, cpu);
    assert_eq!(candidate.updates, 500);
    assert!(store.read_bytes + store.written_bytes <= model::REQUIREMENTS.io_bytes as u64);
    std::fs::create_dir_all(output).unwrap();
    export_model(&output.join("candidate"), &candidate, &store.inner);
    write(&output.join("units.json"), &units);
    (candidate, store, cursor, losses, engine)
}

#[test]
#[ignore = "Explicit finite paired retention intervention; no final queries or upper updates"]
fn owned_retention_intervention() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "Release only"
    );
    let output = std::env::var("NAOME_RETENTION_OUTPUT").expect("fresh intervention output");
    let prepared = std::env::var("NAOME_RETENTION_PREPARED").expect("frozen feasible selections");
    let output = Path::new(&output);
    assert!(!output.exists());
    let meter = crate::resources::feedback::Meter::start();
    let whole = Instant::now();
    let whole_cpu = meta::cpu_micros().unwrap();
    let hashes: BTreeMap<String, String> = read(&format!("{prepared}/file-hashes.json"));
    for (path, hash) in hashes {
        assert_eq!(
            crate::hex(&Sha256::digest(std::fs::read(path).unwrap())),
            hash
        );
    }
    let diagnosis = inputs();
    let mut rows = Vec::new();
    for name in ["baseline", "retention"] {
        for case in &diagnosis.cases {
            let started = Instant::now();
            let cpu = meta::cpu_micros().unwrap();
            let current: State = read(&case.current_state);
            let previous: State = read(&case.parent_state);
            let path = Path::new(&case.current_state)
                .parent()
                .unwrap()
                .join("job.json");
            let expected: Job = read(path.to_str().unwrap());
            assert_eq!(digest(&expected.base), digest(&current));
            let expected = expected.progress.as_ref().unwrap();
            let plan = &expected.plan.as_ref().unwrap().plan;
            plan.validate().unwrap();
            let directory = output.join(&case.name);
            let selected: State = read(&format!("{prepared}/{}/state.json", case.name));
            assert_eq!(
                digest(&selected),
                digest(&self::selected(&previous, &current))
            );
            let evidence: Vec<Evidence> = read(&format!("{prepared}/{}/evidence.json", case.name));
            assert_eq!(digest(&evidence), digest(&merged_evidence(case)));
            let state = if name == "baseline" {
                &current
            } else {
                &selected
            };
            eprintln!("retention_branch_started {} {name}", case.name);
            let original: Vec<Evidence> = read(&case.current_evidence);
            let data = if name == "baseline" {
                &original
            } else {
                &evidence
            };
            let (candidate, mut store, cursor, losses, mut engine) =
                train(state, data, plan, case, &directory.join(name));
            let qualification = if name == "baseline" {
                let mut original_store = Store::default();
                assert_eq!(
                    candidate,
                    checkpoint(&case.candidate_checkpoint, &mut original_store)
                );
                assert_eq!(cursor, expected.rng);
                assert_eq!(Some(losses[0]), expected.first_loss);
                assert_eq!(Some(losses[1]), expected.last_loss);
                serde_json::json!({"original_checkpoint_and_adam_exact":true})
            } else {
                let result = qualification_screen(
                    state,
                    &candidate,
                    &mut engine,
                    &mut store,
                    expected.meta_update.as_ref().unwrap().experience.job,
                    (started, cpu),
                );
                assert_eq!(
                    result["before"].as_u64().unwrap(),
                    u64::from(expected.incumbent_score)
                );
                assert_eq!(
                    result["transfer"]["before"].as_u64().unwrap(),
                    u64::from(expected.transfer.before)
                );
                result
            };
            let old = records(&previous);
            let new = records(&current);
            let mut proofs = Vec::new();
            for (id, e) in &old {
                let graphs =
                    proof_graphs(&previous, &read::<Vec<Evidence>>(&case.parent_evidence), id);
                proofs.push(serde_json::json!({"proof_id":id,"job":e.job,
                    "group":if new.contains_key(id) {"old_retained"} else {"old_dropped"},
                    "metrics":decision_metrics(&candidate,&graphs,&mut engine,&mut store.inner)}));
            }
            for (id, e) in &new {
                if !old.contains_key(id) {
                    let graphs = proof_graphs(&current, &original, id);
                    proofs.push(serde_json::json!({"proof_id":id,"job":e.job,"group":"new",
                        "metrics":decision_metrics(&candidate,&graphs,&mut engine,&mut store.inner)}));
                }
            }
            assert_eq!(
                engine.snapshot(&candidate, &mut store.inner).unwrap(),
                candidate
            );
            assert_eq!(
                engine.snapshot(&current.model, &mut store.inner).unwrap(),
                current.model
            );
            limits(started, cpu);
            assert!(store.read_bytes + store.written_bytes <= model::REQUIREMENTS.io_bytes as u64);
            let result = serde_json::json!({"branch":name,"candidate":candidate,"cursor":cursor,
                "losses":losses,"proofs":proofs,"qualification":qualification,
                "cpu_micros":meta::cpu_micros().unwrap()-cpu,"wall_micros":started.elapsed().as_micros(),
                "read_bytes":store.read_bytes,"written_bytes":store.written_bytes});
            write(&directory.join(name).join("result.json"), &result);
            eprintln!("retention_branch_completed {} {name}", case.name);
            rows.push(serde_json::json!({"case":case.name,"plan":plan,"result":result}));
            write(&output.join("partial.json"), &rows);
        }
    }
    let resources = meter.finish(0, true);
    assert!(resources.peak_rss_bytes.unwrap() <= model::REQUIREMENTS.work_bytes as u64);
    write(
        &output.join("completed.json"),
        &serde_json::json!({"cases":rows,
        "lower_optimizer_updates":4000,"upper_optimizer_updates":0,"new_final_queries":0,
        "cpu_micros":meta::cpu_micros().unwrap()-whole_cpu,"wall_micros":whole.elapsed().as_micros(),
        "peak_rss_bytes":resources.peak_rss_bytes,"diagnostic_only":true}),
    );
}
