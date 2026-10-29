//! Whole selected states, checked source history and exact Finder reopening.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn save(
    state: &mut State,
    graph: &mut crate::Graph,
    io: &mut sources::history::Io<'_>,
    meter: &mut Meter,
    finder: Frontier,
    directory: &Path,
    path: &Path,
    phase: usize,
    arm: Arm,
) -> Result<Frontier, String> {
    std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
    meter.checkpoint(&path.join("learning"), state, io)?;
    let expected = finder.learning_snapshot();
    drop(finder);
    let destination = path.join("finder/research");
    std::fs::create_dir_all(&destination).map_err(|e| e.to_string())?;
    for name in ["evidence.sqlite3", "evidence.initialized"] {
        meter.copy(
            &directory.join("finder/research").join(name),
            &destination.join(name),
            crate::resources::limits().native_model_blob_bytes,
        )?;
    }
    let mut reconstructed = crate::Graph::default();
    let mut sources = Vec::new();
    for episode in io.episodes() {
        let job = episode.observation.summary.job;
        let raw = meter.read(
            &directory.join(format!("episode-{job}.json")),
            crate::resources::limits().native_model_blob_bytes,
        )?;
        let original: sources::Episode = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if digest(&original) != digest(&episode) {
            return Err("phase source episode changed".into());
        }
        let context = meter.read(
            &directory.join(format!("source-state-{job}.json")),
            history::PAGE_BYTES,
        )?;
        let acquisition: State = serde_json::from_slice(&context).map_err(|e| e.to_string())?;
        original.validate_context(&acquisition)?;
        if let Some(solution) = &original.solution {
            let q = CompiledQuestion::compile(&original.observation.question)
                .map_err(|e| e.to_string())?;
            crate::learning::experiment::knowledge::admit_discovery(
                &mut reconstructed,
                &q,
                solution,
            )
            .map_err(|e| e.to_string())?;
        }
        sources.push(json!({"job":job,"episode":Blob::of(&raw),"state":Blob::of(&context)}));
    }
    if reconstructed.content_root() != graph.content_root() {
        return Err("phase checked Graph changed on source-owner replay".into());
    }
    *graph = reconstructed;
    let settings = jobs::Settings {
        native_proof_learning: true,
        ..Default::default()
    };
    let mut archived = Frontier::open(&path.join("finder"), graph, state.model.seed, settings)
        .map_err(|e| e.to_string())?;
    arm.finder(&mut archived);
    if archived.learning_snapshot() != expected {
        return Err("saved Finder checkpoint differs on independent reopen".into());
    }
    drop(archived);
    let mut reopened = Frontier::open(&directory.join("finder"), graph, state.model.seed, settings)
        .map_err(|e| e.to_string())?;
    // Treatment and freezing are runtime controls, deliberately absent from
    // persisted model bytes. Restore them before comparing the full snapshot
    // and before any future observation can reach a gradient port.
    arm.finder(&mut reopened);
    if reopened.learning_snapshot() != expected {
        return Err("phase Finder parameters/history changed on reopen".into());
    }
    meter.write(&path.join("phase.json"),&json!({"phase":phase,"arm":arm.name(),
        "state_sha256":digest(state),"model":state.model,"meta":state.meta.model,
        "finder":expected,"graph":crate::hex(&graph.content_root()),"sources":sources,"cost":meter.report(io),
        "checkpoint_reopened":true,"saved_finder_reopened":true,"assessment_model_calls":0,
        "io_scope":"Counted source/model/archive transport; SQLite internal rereads and Graph memory operations have no separate byte counter. Their physical CPU/wall is included; no complete physical IO or efficiency claim."}))?;
    meter.check(io)?;
    Ok(reopened)
}
