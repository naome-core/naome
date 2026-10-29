//! Prospective continuation of one actual selected state, never a restarted
//! original attempt or a replacement for independent-seed qualification.
use super::*;
mod restore;
use restore::{Restored, restore};

fn execute(
    source: &Path,
    model: &Path,
    output: &Path,
    holdout: &lineage::Holdout,
    arm: &str,
    accounting: &Path,
) -> Result<Value, String> {
    if output.exists() || !matches!(arm, "joint" | "uniform_finder" | "frozen_solver") {
        return Err("warm phase output or arm differs".into());
    }
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let mut meter = Meter::start()?;
    let mut reads = persistence::Cost::default();
    let bytes = persistence::read(accounting, history::PAGE_BYTES, &mut reads)?;
    let common: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    meter.common(&common, &json!({"source_read_bytes":reads.bytes}))?;
    let Restored {
        mut state,
        mut io,
        mut graph,
        finder,
        questions,
        proofs,
        cursor,
        job,
        receipt,
    } = restore(source, model, output, holdout, &mut meter)?;
    if common["state_sha256"] != digest(&state) {
        return Err("charged warm parent has another selected State".into());
    }
    let parent_model = state.model.clone();
    let parent_meta = state.meta.clone();
    let initial_finder = finder.learning_snapshot();
    let mut engine = Engine::default();
    if engine.snapshot(&state.model, &mut io)? != state.model {
        return Err("warm runtime did not load the actual paired parent".into());
    }
    let mut observer = crate::resources::adaptive::Observer::default();
    run::available(&mut meter, &io, &mut observer, output)?;
    let initial = run::evaluate(
        &state,
        &mut engine,
        &mut io,
        &mut meter,
        &mut observer,
        output,
        "initial",
        holdout,
    )?;
    let mask = initial
        .as_array()
        .ok_or("warm initial evaluation absent")?
        .iter()
        .map(|row| row["solved"] == true)
        .collect::<Vec<_>>();
    if json!(mask) != receipt["reference_development_successes"] {
        return Err("warm parent development outcomes do not reproduce".into());
    }
    let mut progress = advance::Progress {
        questions,
        proofs,
        cursor,
        job,
        rounds: Vec::new(),
        finder: initial_finder.clone(),
    };
    let outcome = advance::advance(
        &mut state,
        &mut graph,
        &mut io,
        &mut engine,
        &mut meter,
        &mut observer,
        finder,
        holdout,
        &mut progress,
        output,
        arm,
        (2, 12),
    );
    let actual = engine.snapshot(&state.model, &mut io)?;
    if actual != state.model
        || arm == "frozen_solver"
            && (actual != parent_model || digest(&state.meta) != digest(&parent_meta))
    {
        return Err("warm selected or frozen parent parameters/Adam changed unexpectedly".into());
    }
    if outcome.is_ok() {
        meter.checkpoint(&output.join("final-checkpoint"), &mut state, &mut io)?;
    }
    let result = json!({"arm":arm,"complete":outcome.is_ok(),"error":outcome.as_ref().err(),
        "parent_model":parent_model,"initial_model":parent_model,"final_model":actual,
        "initial_finder":initial_finder,"final_finder":progress.finder,"restore":receipt,
        "initial_evaluation":initial,"rounds":progress.rounds,"cost":meter.report(&io),
        "independent_confirmation_calls":0,"scope":"New prospective actual-parent warm phase; one previously observed parent, not independent initialization seeds"});
    meter.write(&output.join("final-state.json"), &state)?;
    meter.write(&output.join("result.json"), &result)?;
    let bounded = meter.check(&io);
    meter.write(
        &output.join("cost-seal.json"),
        &json!({"complete":outcome.is_ok()&&bounded.is_ok(),"cost":meter.report(&io)}),
    )?;
    outcome?;
    bounded?;
    Ok(result)
}

#[test]
#[ignore = "new prospective actual-parent comparison; requires a separately frozen protocol"]
fn actual_parent_warm_continuation() {
    let source = std::path::PathBuf::from(std::env::var("NAOME_WARM_SOURCE").unwrap());
    let model = std::path::PathBuf::from(std::env::var("NAOME_WARM_MODEL").unwrap());
    let output = std::path::PathBuf::from(std::env::var("NAOME_WARM_OUTPUT").unwrap());
    let accounting = std::path::PathBuf::from(std::env::var("NAOME_WARM_ACCOUNTING").unwrap());
    let bank = std::fs::read(std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap()).unwrap();
    let holdout = lineage::Holdout::read(
        &bank,
        &std::env::var("NAOME_EXPERIENCE_HOLDOUT_SHA256").unwrap(),
    )
    .unwrap();
    execute(
        &source,
        &model,
        &output,
        &holdout,
        &std::env::var("NAOME_WARM_ARM").unwrap(),
        &accounting,
    )
    .unwrap();
}

#[test]
#[ignore = "explicit source-owner restart audit; no new Solver search or optimization"]
fn reopen_actual_source_owners() {
    let source = std::path::PathBuf::from(std::env::var("NAOME_WARM_SOURCE").unwrap());
    let model = std::path::PathBuf::from(std::env::var("NAOME_WARM_MODEL").unwrap());
    let output = std::path::PathBuf::from(std::env::var("NAOME_WARM_OUTPUT").unwrap());
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let bank = std::fs::read(std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap()).unwrap();
    let holdout = lineage::Holdout::read(
        &bank,
        &std::env::var("NAOME_EXPERIENCE_HOLDOUT_SHA256").unwrap(),
    )
    .unwrap();
    let mut meter = Meter::start().unwrap();
    let mut restored = restore(&source, &model, &output, &holdout, &mut meter).unwrap();
    let state = digest(&restored.state);
    let mut pages = Vec::new();
    for lane in [history::Lane::Sources, history::Lane::Records] {
        let request = history::Request {
            lane,
            after: None,
            horizon: restored.job + 1,
        };
        let receipt = restored.io.history(&request).unwrap();
        let bytes = artifact::load(&mut restored.io, &receipt.blob).unwrap();
        let page: history::Page = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(page.request, request);
        pages.push(json!({"lane":lane,"sources":page.sources.len(),"records":page.records.len(),"receipt":receipt}));
    }
    assert_eq!(digest(&restored.state), state);
    meter.check(&restored.io).unwrap();
    meter
        .write(
            &output.join("result.json"),
            &json!({"complete":true,"restore":restored.receipt,
        "history_pages":pages,"cost":meter.report(&restored.io),"solver_forward_calls":0,
        "solver_optimizer_updates":0,"new_meta_trials":0,"state_after":state}),
        )
        .unwrap();
}
