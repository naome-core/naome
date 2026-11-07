//! A complete, paired learning matrix is required before the first assessment.
use super::*;

pub(super) struct Sealed {
    pub directory: std::path::PathBuf,
    pub result: Value,
    pub cost: Value,
}

pub(super) fn headers(rows: &[Value], seeds: &[u64], identity: &Value) -> Result<(), String> {
    if rows.len() != seeds.len() * 3 || seeds.iter().collect::<BTreeSet<_>>().len() != seeds.len() {
        return Err("assessment requires distinct complete initialization seeds".into());
    }
    let mut seen = BTreeSet::new();
    let mut paired = BTreeMap::new();
    for row in rows {
        let seed = row["seed"].as_u64().ok_or("trajectory seed absent")?;
        let arm = Arm::read(row["arm"].as_str().ok_or("trajectory arm absent")?)?;
        if !seeds.contains(&seed)
            || !seen.insert((seed, arm.name()))
            || row["complete"] != true
            || row["assessment_model_calls"] != 0
            || row["design"] != *identity
        {
            return Err("trajectory matrix identity, completeness or independence differs".into());
        }
        let phases = row["phases"].as_array().ok_or("trajectory phases absent")?;
        if phases.len() != PHASES || phases.iter().enumerate().any(|(i, p)| p["phase"] != i + 1) {
            return Err("assessment requires all five ordered learning phases".into());
        }
        let initial = json!([
            row["initial_state_sha256"],
            row["initial_model"],
            row["initial_meta"],
            row["initial_finder"]
        ]);
        if initial.as_array().unwrap().iter().any(Value::is_null) {
            return Err("paired whole initialization absent".into());
        }
        if let Some(previous) = paired.insert(seed, initial.clone())
            && previous != initial
        {
            return Err("control arms did not share the same whole initialization".into());
        }
    }
    Ok(())
}

fn json_read(meter: &mut Meter, path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&meter.read(path, crate::resources::limits().native_model_blob_bytes)?)
        .map_err(|e| e.to_string())
}

pub(super) fn read(
    directory: &Path,
    design: &design::Design,
    pilot: bool,
    meter: &mut Meter,
) -> Result<Vec<Sealed>, String> {
    let seeds = if pilot {
        vec![2_903_001]
    } else {
        SEEDS.to_vec()
    };
    let mut matrix = Vec::new();
    // Check every terminal header first; no model is loaded in this pass.
    for seed in &seeds {
        for arm in [Arm::Adaptive, Arm::FrozenWeights, Arm::FixedChoices] {
            let path = directory.join(format!("{seed}/{}", arm.name()));
            let result = json_read(meter, &path.join("result.json"))?;
            let process = json_read(meter, &path.join("process.json"))?;
            let cost = json_read(meter, &path.join("cost-seal.json"))?;
            if result["seed"] != *seed
                || result["arm"] != arm.name()
                || process["exit_code"] != 0
                || process["allowance_passed"] != true
                || !process["resource_stop"].is_null()
            {
                return Err("trajectory lacks its successful independent process seal".into());
            }
            let count =
                |v: &Value, k: &str| v[k].as_u64().ok_or_else(|| format!("cost absent: {k}"));
            let cpu = count(&process, "cpu_micros")?
                .checked_add(count(&cost, "common_cpu_micros")?)
                .ok_or("cost overflow")?;
            let wall = count(&process, "wall_micros")?
                .checked_add(count(&cost, "common_wall_micros")?)
                .ok_or("cost overflow")?;
            let bytes = count(&cost, "charged_io_bytes")?;
            if cpu < count(&cost, "charged_cpu_micros")?
                || wall < count(&cost, "charged_wall_micros")?
                || cpu > 180_000_000
                || wall > 240_000_000
                || bytes > 2 * 1024 * 1024 * 1024
                || count(&process, "peak_rss_bytes")? > model::REQUIREMENTS.work_bytes as u64
            {
                return Err(
                    "whole-process cost seal exceeds or undercounts the original grant".into(),
                );
            }
            matrix.push(Sealed { directory:path, result,
                cost:json!({"cpu_micros":cpu,"wall_micros":wall,"model_io_bytes":bytes,"archive_written_bytes":0}) });
        }
    }
    headers(
        &matrix.iter().map(|s| s.result.clone()).collect::<Vec<_>>(),
        &seeds,
        &design.identity,
    )?;
    // Source and all six whole-state checkpoints must survive an independent
    // content-manifest check and native source replay before assessment.
    for sealed in &matrix {
        let manifest = json_read(meter, &sealed.directory.join("manifest.json"))?;
        let files = manifest
            .as_object()
            .ok_or("trajectory file manifest absent")?;
        for name in ["result.json", "cost-seal.json", "process.json"] {
            if !files.contains_key(name) {
                return Err("terminal seal absent from manifest".into());
            }
        }
        for (name, expected) in files {
            let relative = Path::new(name);
            if relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                return Err("trajectory manifest path is not relative".into());
            }
            let bytes = meter.read(
                &sealed.directory.join(relative),
                crate::resources::limits().native_model_blob_bytes,
            )?;
            if expected.as_str() != Some(crate::hex(&Sha256::digest(&bytes)).as_str()) {
                return Err("sealed trajectory content changed".into());
            }
        }
        for phase in 0..=PHASES {
            let path = sealed.directory.join(format!("phase-{phase}"));
            let receipt = json_read(meter, &path.join("phase.json"))?;
            let required = |name: &str| files.contains_key(&format!("phase-{phase}/{name}"));
            if !required("phase.json")
                || !required("learning/state.json")
                || !required("finder/research/evidence.sqlite3")
                || !required("finder/research/evidence.initialized")
                || receipt["phase"] != phase
                || receipt["arm"] != sealed.result["arm"]
                || receipt["checkpoint_reopened"] != true
                || receipt["saved_finder_reopened"] != true
                || receipt["assessment_model_calls"] != 0
            {
                return Err("whole phase checkpoint is missing or incomplete".into());
            }
            let (state, _) = meter.import(&path.join("learning"))?;
            if receipt["state_sha256"] != digest(&state)
                || receipt["model"] != json!(state.model)
                || receipt["meta"] != json!(state.meta.model)
            {
                return Err("phase selected State binding differs".into());
            }
            if phase == 0 {
                if receipt["state_sha256"] != sealed.result["initial_state_sha256"]
                    || receipt["model"] != sealed.result["initial_model"]
                    || receipt["meta"] != sealed.result["initial_meta"]["model"]
                    || receipt["finder"]["model"] != sealed.result["initial_finder"]
                {
                    return Err(
                        "paired initial whole checkpoint differs from its trajectory".into(),
                    );
                }
            } else if receipt["state_sha256"] != sealed.result["phases"][phase - 1]["state_sha256"]
                || receipt["model"] != sealed.result["phases"][phase - 1]["model"]
            {
                return Err("phase checkpoint differs from its selected trajectory state".into());
            }
            for blob in state.blobs() {
                if !required(&format!("learning/blobs/{}", blob.sha256)) {
                    return Err("whole phase model/Adam blob absent from manifest".into());
                }
            }
            let mut graph = crate::Graph::default();
            for source in receipt["sources"]
                .as_array()
                .ok_or("phase source history absent")?
            {
                let job = source["job"].as_u64().ok_or("phase source job absent")?;
                let raw = meter.read(
                    &sealed.directory.join(format!("episode-{job}.json")),
                    crate::resources::limits().native_model_blob_bytes,
                )?;
                let context = meter.read(
                    &sealed.directory.join(format!("source-state-{job}.json")),
                    history::PAGE_BYTES,
                )?;
                if source["episode"] != json!(Blob::of(&raw))
                    || source["state"] != json!(Blob::of(&context))
                {
                    return Err("phase source history content differs".into());
                }
                let episode: sources::Episode =
                    serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
                let acquisition: State =
                    serde_json::from_slice(&context).map_err(|e| e.to_string())?;
                episode.validate_context(&acquisition)?;
                let q = CompiledQuestion::compile(&episode.observation.question)
                    .map_err(|e| e.to_string())?;
                design
                    .holdout
                    .question(&q, Some(&episode.authored_lineage))?;
                if let Some(solution) = &episode.solution {
                    crate::learning::experiment::knowledge::admit_discovery(
                        &mut graph, &q, solution,
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
            if receipt["graph"] != crate::hex(&graph.content_root()) {
                return Err("phase native Graph root differs".into());
            }
        }
    }
    Ok(matrix)
}
