//! Restore one completed Records-lane trial for a model-free sampler audit.
use super::*;
use std::{io::Read, path::PathBuf};
mod carry;

fn read_bytes(path: &Path, bytes: &mut u64, bindings: &mut Vec<Value>) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    *bytes += data.len() as u64;
    if data.len() > 4 * 1024 * 1024 {
        return Err("sequence audit metadata exceeds its bounded read".into());
    }
    bindings.push(json!({"path":path,"blob":Blob::of(&data)}));
    Ok(data)
}

fn read<T: serde::de::DeserializeOwned>(
    path: &Path,
    bytes: &mut u64,
    bindings: &mut Vec<Value>,
) -> Result<T, String> {
    serde_json::from_slice(&read_bytes(path, bytes, bindings)?).map_err(|e| e.to_string())
}

fn available(
    observer: &mut crate::resources::adaptive::Observer,
    started: Instant,
    cpu: u64,
    path: &Path,
) -> Result<(), String> {
    if meta::cpu_micros()?.saturating_sub(cpu) > TRAIN_CPU
        || started.elapsed().as_micros() > u128::from(TRAIN_WALL)
        || crate::resources::feedback::Meter::start()
            .finish(0, true)
            .peak_rss_bytes
            .is_none_or(|peak| peak > model::REQUIREMENTS.work_bytes as u64)
    {
        return Err("sequence audit exhausted its original diagnostic allowance".into());
    }
    if observer.due(Instant::now())
        && let Some(reason) = &observer
            .refresh(path)
            .map_err(|e| e.to_string())?
            .budget
            .paused
    {
        return Err(format!(
            "sequence audit interrupted by resource owner: {reason}"
        ));
    }
    Ok(())
}

#[test]
#[ignore = "model-free reconstruction of a completed frozen native trial"]
fn reconstruct_sequence_consumption() {
    let input = PathBuf::from(std::env::var("NAOME_SEQUENCE_AUDIT_SOURCES").unwrap());
    let original = PathBuf::from(std::env::var("NAOME_SEQUENCE_AUDIT_ARM").unwrap());
    let output = PathBuf::from(std::env::var("NAOME_SEQUENCE_AUDIT_OUTPUT").unwrap());
    assert!(!output.exists());
    std::fs::create_dir_all(&output).unwrap();
    let mut meter = Meter::start().unwrap();
    let started = Instant::now();
    let cpu = meta::cpu_micros().unwrap();
    let mut metadata_bytes = 0;
    let mut bindings = Vec::new();
    let mut observer = crate::resources::adaptive::Observer::default();
    let outcome = (|| -> Result<Value, String> {
        available(&mut observer, started, cpu, &output)?;
        let bank = read_bytes(
            Path::new(&std::env::var("NAOME_FINDER_CONFIRMATION_INPUTS").unwrap()),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        let holdout = lineage::Holdout::read(
            &bank,
            &std::env::var("NAOME_EXPERIENCE_HOLDOUT_SHA256").unwrap(),
        )?;
        let (frozen, restored) = sources::Frozen::read(&input, &holdout)?;
        available(&mut observer, started, cpu, &output)?;
        // Collection already happened. Only this audit's new restoration,
        // checking and reporting work is charged here.
        meter.common(
            &json!({"cpu_micros":0,"wall_micros":0,"model_io_bytes":0,"archive_written_bytes":0}),
            &restored,
        )?;
        let source: Value = read(
            &original.join("input.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        let result: Value = read(
            &original.join("result.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        let seal: Value = read(
            &original.join("cost-seal.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        if result["complete"] != true
            || seal["complete"] != true
            || source["initial_state_sha256"] != digest(&frozen.initial)
            || source["input_sources_sha256"] != frozen.cost["source_sha256"]
            || source["specification"] != input_specification()
            || result["arm"] != source["arm"]
            || result["seed"] != source["seed"]
            || source["seed"] != frozen.initial.model.seed
        {
            return Err("sequence audit requires complete matching frozen artifacts".into());
        }
        let arm = ARMS
            .into_iter()
            .chain(PRESERVATION_ARMS)
            .find(|arm| source["arm"] == arm.name())
            .ok_or("sequence audit arm is unknown")?;
        let (targets, recurrence) = match arm {
            Arm::Baseline => (model::Targets::Actions, model::Recurrence::Disabled),
            Arm::Experience => (model::Targets::Rich, model::Recurrence::Disabled),
            Arm::Latent => (model::Targets::Actions, model::Recurrence::Carry),
            Arm::Combined => (model::Targets::Rich, model::Recurrence::Carry),
            Arm::ComputeControl => (model::Targets::Rich, model::Recurrence::Reset),
            Arm::IndependentPreservation | Arm::ContextualPreservation => {
                (model::Targets::Rich, model::Recurrence::Carry)
            }
        };
        let previous: State = read(
            &original.join("epoch-0/selected-state.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        let trial: Value = read(
            &original.join("epoch-1/trial.json"),
            &mut metadata_bytes,
            &mut bindings,
        )?;
        if trial["status"] != "complete"
            || trial != result["rounds"][1]["trial"]
            || result["rounds"][0]["state_sha256"] != digest(&previous)
            || result["rounds"][1]["source_state_sha256"]
                != digest(frozen.epochs.get(1).ok_or("second source epoch absent")?)
        {
            return Err("sequence audit trial or preceding selected state differs".into());
        }
        let expected: Progress =
            serde_json::from_value(trial["progress"].clone()).map_err(|e| e.to_string())?;
        let receipt: history::Receipt =
            serde_json::from_value(trial["history_receipt"].clone()).map_err(|e| e.to_string())?;
        if receipt.request.lane != history::Lane::Records {
            return Err("sequence audit expected the actual Records lane".into());
        }
        let mut state = bind(
            frozen.epochs.get(1).ok_or("second source epoch absent")?,
            &previous,
        )?;
        if !state.needs_training()
            || serde_json::to_value(&state.model).unwrap() != trial["source_model"]
        {
            return Err("sequence audit source model or native readiness differs".into());
        }
        state.attempted(state.learning_epoch());
        let mut native = state.job();
        native.training = true;
        let evidence = frozen
            .episodes
            .iter()
            .take(96)
            .filter_map(|episode| {
                episode.solution.as_ref().map(|solution| Evidence {
                    job: episode.observation.summary.job,
                    proof_id: solution.proof_id.clone(),
                    trace: solution.tree.clone(),
                })
            })
            .collect::<Vec<_>>();
        native.evidence = owned_evidence(&state, &evidence)?;
        native.evidence.sort_by_key(|e| e.job);
        native.request_history(1_000_001);
        let mut io = sources::history::Io::new(&frozen, &input);
        io.epoch(0)?;
        io.epoch(1)?;
        run::available(&mut meter, &io, &mut observer, &output)?;
        let reconstructed = io.history(
            native
                .history_request
                .as_ref()
                .ok_or("history request absent")?,
        )?;
        if reconstructed.request != receipt.request
            || reconstructed.blob != receipt.blob
            || reconstructed.next != receipt.next
            || reconstructed.read_bytes != receipt.read_bytes
            || reconstructed.read_operations != receipt.read_operations
        {
            return Err("sequence audit reconstructed another original history page".into());
        }
        // The historical timing field is an input to the original Working
        // identity. Preserve it exactly; measure this audit's new cost apart.
        native.history = Some(receipt.clone());
        native.validate()?;
        let audit = model::observation::sequence_audit::audit(
            &native,
            &expected,
            targets,
            recurrence,
            matches!(arm, Arm::IndependentPreservation),
            &mut io,
            || available(&mut observer, started, cpu, &output),
        )?;
        run::available(&mut meter, &io, &mut observer, &output)?;
        let cost = meter.report(&io);
        if cost["charged_io_bytes"].as_u64().unwrap() + metadata_bytes > 2 * 1024 * 1024 * 1024 {
            return Err("sequence audit exhausted its original IO allowance".into());
        }
        Ok(
            json!({"arm":arm.name(),"epoch":1,"source_commit":std::env::var("NAOME_SEQUENCE_AUDIT_COMMIT").unwrap(),"native_specification":input_specification(),"historical_receipt":receipt,"reconstruction_receipt":reconstructed,"audit":audit,"cost":cost,"metadata_read_bytes":metadata_bytes,"input_bindings":bindings,"independent_quality_qualified":false}),
        )
    })();
    let report = json!({"complete":outcome.is_ok(),"error":outcome.as_ref().err(),"result":outcome.as_ref().ok(),"inference_calls":0,"optimizer_updates":0,"proof_searches":0});
    let bytes = serde_json::to_vec_pretty(&report).unwrap();
    std::fs::write(output.join("result.json"), &bytes).unwrap();
    let io_bytes = outcome.as_ref().ok().map(|result| {
        result["cost"]["charged_io_bytes"].as_u64().unwrap() + metadata_bytes + bytes.len() as u64
    });
    let final_check = available(&mut observer, started, cpu, &output).and_then(|()| {
        if io_bytes.is_some_and(|count| count > 2 * 1024 * 1024 * 1024) {
            Err("sequence audit exhausted its original IO allowance".into())
        } else {
            Ok(())
        }
    });
    write(
        &output.join("cost-seal.json"),
        &json!({"complete":outcome.is_ok()&&final_check.is_ok(),"error":final_check.as_ref().err(),"physical_cpu_micros":meta::cpu_micros().unwrap()-cpu,"physical_wall_micros":started.elapsed().as_micros(),"io_bytes":io_bytes,"report_bytes":bytes.len(),"seal_write_is_reporting_overhead":true,"whole_process_timing_required":true}),
    );
    outcome.unwrap();
    final_check.unwrap();
}
