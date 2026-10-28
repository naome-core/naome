//! Ordinary source preparation, native training and selected-checkpoint checks.
use super::*;

pub(super) fn available(
    meter: &mut Meter,
    io: &sources::history::Io<'_>,
    observer: &mut crate::resources::adaptive::Observer,
    path: &Path,
) -> Result<(), String> {
    meter.check(io)?;
    if observer.due(Instant::now()) {
        let observed = observer.refresh(path).map_err(|e| e.to_string())?;
        if let Some(reason) = &observed.budget.paused {
            return Err(format!(
                "experiment interrupted by resource owner: {reason}"
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate(
    state: &State,
    engine: &mut Engine,
    io: &mut sources::history::Io<'_>,
    meter: &mut Meter,
    observer: &mut crate::resources::adaptive::Observer,
    path: &Path,
    label: &str,
    holdout: &lineage::Holdout,
) -> Result<Value, String> {
    let mut rows = Vec::new();
    for (index, case) in curriculum::development().into_iter().enumerate() {
        let q = CompiledQuestion::compile(&case.source).map_err(|e| e.to_string())?;
        // No model call occurs until this entire original source passed its split.
        holdout.question(&q, Some(&case.dependency))?;
        available(meter, io, observer, path)?;
        let cpu = meta::cpu_micros()?;
        let wall = Instant::now();
        let bytes = io.store.bytes;
        let result = engine.with(&state.model, io, |runtime| {
            solve_with_report(
                q.source(),
                runtime,
                32,
                9_000_000 + index as u64,
                SolveContext {
                    definitions: &state.definitions,
                    ..Default::default()
                },
            )
        })?;
        if let Some(solution) = &result.solution {
            let checked = solution.checked()?.into_checked_proof();
            let expected = if solution.refuted {
                q.refuted_target()
            } else {
                q.proved_target()
            };
            if checked.conclusion() != expected {
                return Err("development proof conclusion differs".into());
            }
            meter.write(&path.join(format!("{label}-proof-{index}.json")), solution)?;
        }
        let cpu = meta::cpu_micros()?.saturating_sub(cpu);
        let wall = wall.elapsed().as_micros();
        let timely = cpu <= 2_500_000 && wall <= 5_000_000;
        rows.push(json!({"id":case.id,"family":case.family,"dependency":case.dependency,"protected":index<curriculum::CORPUS_DEVELOPMENT,"resolution":crate::hex(q.resolution_id()),"solved":result.solution.is_some()&&timely,"late_checked_solution":result.solution.is_some()&&!timely,"terminal":result.terminal,"diagnostic":result.diagnostic,"cost":result.cost,"cpu_micros":cpu,"wall_micros":wall,"model_io_bytes":io.store.bytes-bytes}));
        meter.write(&path.join(format!("{label}-evaluation.json")), &rows)?;
        available(meter, io, observer, path)?;
    }
    Ok(json!(rows))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn train(
    state: &mut State,
    engine: &mut Engine,
    io: &mut sources::history::Io<'_>,
    meter: &mut Meter,
    observer: &mut crate::resources::adaptive::Observer,
    episodes: &[sources::Episode],
    job: u64,
    path: &Path,
) -> Result<Value, String> {
    if !state.needs_training() {
        return Ok(
            json!({"status":"not_ready","selected_model":state.model,"learning_epoch":state.learning_epoch()}),
        );
    }
    available(meter, io, observer, path)?;
    let cpu = meta::cpu_micros()?;
    let wall = Instant::now();
    let bytes = io.store.bytes + io.source_bytes;
    let before = state.model.clone();
    state.attempted(state.learning_epoch());
    let mut native = state.job();
    native.training = true;
    let sources = episodes
        .iter()
        .filter_map(|episode| {
            episode.solution.as_ref().map(|solution| Evidence {
                job: episode.observation.summary.job,
                proof_id: solution.proof_id.clone(),
                trace: solution.tree.clone(),
            })
        })
        .collect::<Vec<_>>();
    native.evidence = owned_evidence(state, &sources)?;
    native.evidence.sort_by_key(|e| e.job);
    native.request_history(job);
    native.validate()?;
    let check = |io: &sources::history::Io<'_>| -> Result<(), String> {
        if meta::cpu_micros()?.saturating_sub(cpu) > TRAIN_CPU
            || wall.elapsed().as_micros() > u128::from(TRAIN_WALL)
            || io.store.bytes + io.source_bytes - bytes > 2 * 1024 * 1024 * 1024
        {
            Err("native trial exhausted its unchanged job allowance".into())
        } else {
            Ok(())
        }
    };
    let mut stopped_unit = None;
    let outcome = (|| -> Result<(), String> {
        for unit in 1..=native.units() {
            stopped_unit = Some(unit);
            available(meter, io, observer, path)?;
            check(io)?;
            native.execute(unit, None, job, engine, io)?;
            retained(&mut io.store, native.blobs());
            if unit == model::TRAINING_UNITS
                && let Some(candidate) = native.progress.as_ref().and_then(|p| p.candidate.as_ref())
            {
                // Rejected candidates remain reproducible without entering
                // the selected state or receiving an additional trial budget.
                meter.export(&path.join("candidate-model"), candidate, &io.store.inner)?;
            }
            if unit % 10 == 0 || unit == model::TRAINING_UNITS || unit == native.units() {
                meter.write(&path.join("progress.json"), &native.progress)?;
            }
            check(io)?;
            available(meter, io, observer, path)?;
        }
        let mut selected = state.clone();
        if !selected.qualify(&native) {
            return Err("complete native trial did not retain its actual selected state".into());
        }
        selected.validate()?;
        check(io)?;
        available(meter, io, observer, path)?;
        *state = selected;
        Ok(())
    })();
    let result = json!({"status":if outcome.is_ok(){"complete"}else{"interrupted"},"error":outcome.as_ref().err(),"last_unit":stopped_unit,"source_model":before,"selected_model":state.model,"retained_update":before!=state.model,"cpu_micros":meta::cpu_micros()?.saturating_sub(cpu),"wall_micros":wall.elapsed().as_micros(),"model_and_history_io_bytes":io.store.bytes+io.source_bytes-bytes,"history_request":native.history_request,"history_receipt":native.history,"progress":native.progress});
    meter.write(&path.join("trial.json"), &result)?;
    outcome?;
    retained(&mut io.store, state.blobs().collect());
    Ok(result)
}
