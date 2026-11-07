use super::*;

pub(super) struct Restored<'a> {
    pub state: State,
    pub io: sources::history::Io<'a>,
    pub graph: crate::Graph,
    pub finder: Frontier,
    pub questions: BTreeSet<String>,
    pub proofs: BTreeSet<String>,
    pub cursor: u64,
    pub job: u64,
    pub receipt: Value,
}

pub(super) fn restore<'a>(
    source: &Path,
    model: &Path,
    output: &'a Path,
    holdout: &lineage::Holdout,
    meter: &mut Meter,
) -> Result<Restored<'a>, String> {
    let cap = crate::resources::limits().native_model_blob_bytes;
    let recorded: Value = serde_json::from_slice(&meter.read(&source.join("result.json"), cap)?)
        .map_err(|e| e.to_string())?;
    if recorded["complete"] != true {
        return Err("warm parent is not a complete actual arm".into());
    }
    let (state, store) = meter.import(model)?;
    let original: State =
        serde_json::from_slice(&meter.read(&source.join("final-state.json"), cap)?)
            .map_err(|e| e.to_string())?;
    if digest(&state) != digest(&original) {
        return Err("warm model checkpoint substituted its original State".into());
    }
    let mut io = sources::history::Io::journal(store, output);
    let mut graph = crate::Graph::default();
    let mut questions = BTreeSet::new();
    let mut proofs = BTreeSet::new();
    let mut jobs = Vec::new();
    let mut pages = vec![(
        source.join("bootstrap-lineage.json"),
        recorded["preparation"].clone(),
    )];
    let rounds = recorded["rounds"]
        .as_array()
        .ok_or("warm parent rounds absent")?;
    let mut cursor = 0;
    for (round, value) in rounds.iter().enumerate() {
        let events = value["events"]
            .as_array()
            .ok_or("warm parent events absent")?;
        cursor += events.len() as u64;
        pages.push((
            source.join(format!("round-{round}/lineage.json")),
            Value::Array(events.clone()),
        ));
    }
    for (path, events) in pages {
        let ledger = lineage::Ledger::read(&meter.read(&path, history::PAGE_BYTES)?, holdout)?;
        for event in events.as_array().ok_or("warm source events absent")? {
            if event["empty_page"] == true {
                continue;
            }
            let job = event["job"].as_u64().ok_or("warm source job absent")?;
            if jobs.last().is_some_and(|last| *last >= job) {
                return Err("warm parent source order or job identity differs".into());
            }
            let episode_name = format!("episode-{job}.json");
            let state_name = format!("source-state-{job}.json");
            let episode_bytes = meter.read(&source.join(&episode_name), cap)?;
            let state_bytes = meter.read(&source.join(&state_name), cap)?;
            let episode: sources::Episode =
                serde_json::from_slice(&episode_bytes).map_err(|e| e.to_string())?;
            let acquisition: State =
                serde_json::from_slice(&state_bytes).map_err(|e| e.to_string())?;
            episode.validate(&acquisition, &ledger, holdout)?;
            if episode.observation.summary.job != job {
                return Err("warm source observation has another job".into());
            }
            let question = CompiledQuestion::compile(&episode.observation.question)
                .map_err(|e| e.to_string())?;
            if let Some(solution) = &episode.solution {
                crate::learning::experiment::knowledge::admit_discovery(
                    &mut graph, &question, solution,
                )
                .map_err(|e| e.to_string())?;
                questions.insert(crate::hex(question.resolution_id()));
                proofs.insert(solution.proof_id.clone());
            }
            io.append(episode, acquisition)?;
            // Preserve exact original trajectory/context bytes, not a new view.
            if meter.read(&output.join(&episode_name), cap)? != episode_bytes
                || meter.read(&output.join(&state_name), cap)? != state_bytes
            {
                return Err("warm restore reencoded an original source".into());
            }
            jobs.push(job);
            meter.check(&io)?;
        }
    }
    if jobs.len() + 24 > 144 {
        return Err("warm phase would exceed the unchanged finite source bound".into());
    }
    let directory = output.join("finder");
    std::fs::create_dir_all(directory.join("research")).map_err(|e| e.to_string())?;
    for name in ["evidence.sqlite3", "evidence.initialized"] {
        meter.copy(
            &source.join("finder/research").join(name),
            &directory.join("research").join(name),
            cap,
        )?;
    }
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let finder = Frontier::open(&directory, &graph, state.model.seed, settings)
        .map_err(|e| e.to_string())?;
    let snapshot: Value = serde_json::from_slice(
        &serde_json::to_vec(&finder.learning_snapshot()).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if snapshot != recorded["final_finder"] {
        return Err("warm Finder parameters or curriculum changed on actual restore".into());
    }
    let job = jobs
        .last()
        .copied()
        .ok_or("warm parent contains no actual sources")?
        + 1;
    let receipt = json!({"state_sha256":digest(&state),"model":state.model,"meta_model":state.meta.model,
        "source_jobs":jobs,"checked_resolution_count":questions.len(),"checked_proof_count":proofs.len(),
        "graph_content_root":crate::hex(&graph.content_root()),"finder":snapshot,"cursor":cursor,
        "last_owner_slot":job,"all_original_source_bytes_exact":true,"cost":meter.report(&io),
        "reference_development_successes":rounds.last().ok_or("warm parent has no completed rounds")?["evaluation"].as_array().ok_or("warm parent evaluation absent")?.iter().map(|row|row["solved"]==true).collect::<Vec<_>>()});
    meter.write(&output.join("restore.json"), &receipt)?;
    Ok(Restored {
        state,
        io,
        graph,
        finder,
        questions,
        proofs,
        cursor,
        job,
        receipt,
    })
}
