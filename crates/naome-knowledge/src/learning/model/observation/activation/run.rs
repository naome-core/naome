//! Explicit offline invocation. It never installs a diagnostic checkpoint.
use super::*;
use crate::learning::{
    Evidence, State,
    artifact::{self, Blob},
    tests::MemoryStore,
};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    io::Read,
    ops::Range,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    arm: File,
    state: File,
    trial: File,
    checkpoint: File,
    model: File,
    optimizer: File,
    episodes: Vec<File>,
    selection: String,
}
#[derive(Deserialize)]
struct Episode {
    observation: crate::learning::experience::Observation,
    solution: Option<crate::learning::Solution>,
}

#[derive(Default)]
struct Io {
    store: MemoryStore,
    bytes: usize,
    operations: usize,
    source_bytes: usize,
}
impl Io {
    fn file(&mut self, input: &File) -> Result<Vec<u8>, String> {
        let file = std::fs::File::open(&input.path).map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        file.take(crate::learning::model::REQUIREMENTS.blob_bytes as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        self.source_bytes += data.len();
        if data.len() > crate::learning::model::REQUIREMENTS.blob_bytes
            || Blob::of(&data).sha256 != input.sha256
        {
            return Err("activation input size or frozen bytes differ".into());
        }
        Ok(data)
    }
    fn json<T: DeserializeOwned>(&mut self, file: &File) -> Result<T, String> {
        serde_json::from_slice(&self.file(file)?).map_err(|e| e.to_string())
    }
}
impl ArtifactIo for Io {
    fn read(&mut self, blob: &Blob, range: Range<usize>) -> Result<Vec<u8>, String> {
        let value = self.store.read(blob, range)?;
        self.bytes += value.len();
        self.operations += 1;
        Ok(value)
    }
    fn write(&mut self, blob: &Blob, range: Range<usize>, bytes: Vec<u8>) -> Result<(), String> {
        self.bytes += bytes.len();
        self.operations += 1;
        self.store.write(blob, range, bytes)
    }
}

fn run(input: Input, output: &Path) -> Result<(), String> {
    let started = Instant::now();
    let cpu_start = meta::cpu_micros()?;
    if output.exists()
        || input.episodes.len() > 48
        || input.selection != "first_combined_completed_rejected_activation_only"
    {
        return Err("activation diagnosis output or predeclared fallback differs".into());
    }
    std::fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let mut observer = crate::resources::adaptive::Observer::default();
    if observer
        .refresh(output)
        .map_err(|e| e.to_string())?
        .budget
        .paused
        .is_some()
    {
        return Err("activation diagnosis paused by resource owner".into());
    }
    let mut io = Io::default();
    let state: State = io.json(&input.state)?;
    state.validate()?;
    let arm: serde_json::Value = io.json(&input.arm)?;
    let trial: serde_json::Value = io.json(&input.trial)?;
    let checkpoint: Checkpoint = io.json(&input.checkpoint)?;
    checkpoint.validate()?;
    if arm["arm"] != "combined"
        || arm["complete"] != true
        || arm["retained_updates"] != 0
        || arm["rounds"].as_array().is_none_or(|rows| rows.len() != 1)
        || arm["rounds"][0]["trial"] != trial
        || trial["status"] != "complete"
        || trial["retained_update"] != false
        || trial["selected_model"]
            != serde_json::to_value(&state.model).map_err(|e| e.to_string())?
        // Final qualification consumes the candidate option; the evaluated
        // profile keeps its exact model/optimizer/checkpoint binding.
        || !trial["progress"]["candidate"].is_null()
        || trial["progress"]["development_after"]["checkpoint"] != digest(&checkpoint)
        || state.model.updates != 0
        || checkpoint.updates != 250
        || checkpoint.seed != state.model.seed
    {
        return Err("activation fallback differs from the completed rejected native trial".into());
    }
    for (file, expected) in [
        (&input.model, &checkpoint.model),
        (&input.optimizer, &checkpoint.optimizer),
    ] {
        let data = io.file(file)?;
        if Some(artifact::save(&mut io, &data)?) != *expected {
            return Err("activation model or optimizer binding differs".into());
        }
    }
    let needed = state
        .training_sources()
        .filter_map(crate::learning::Example::evidence_job)
        .collect::<BTreeSet<_>>();
    let mut evidence = BTreeMap::new();
    for file in &input.episodes {
        let episode: Episode = io.json(file)?;
        episode.observation.validate()?;
        let job = episode.observation.summary.job;
        if needed.contains(&job) {
            let solution = episode
                .solution
                .ok_or("eligible source has no checked proof")?;
            drop(solution.checked()?);
            if evidence
                .insert(
                    job,
                    Evidence {
                        job,
                        proof_id: solution.proof_id,
                        trace: solution.tree,
                    },
                )
                .is_some()
            {
                return Err("duplicate diagnostic source job".into());
            }
        }
    }
    if evidence.keys().copied().collect::<BTreeSet<_>>() != needed {
        return Err("activation source closure is incomplete".into());
    }
    let mut job = state.job();
    job.training = true;
    job.evidence = evidence.into_values().collect();
    let measurement = inspect(&job, &checkpoint, &mut io)?;
    if observer
        .refresh(output)
        .map_err(|e| e.to_string())?
        .budget
        .paused
        .is_some()
    {
        return Err("activation diagnosis interrupted by resource owner".into());
    }
    let peak = crate::resources::feedback::Meter::start()
        .finish(0, true)
        .peak_rss_bytes
        .ok_or("activation memory observation missing")?;
    let cpu = meta::cpu_micros()?.saturating_sub(cpu_start);
    let wall = started.elapsed().as_micros();
    let report = serde_json::json!({"selection":input.selection,"candidate_qualified":false,
        "influence_probe":"not run: no actually retained trained parent",
        "measurement":measurement,"cpu_micros":cpu,"wall_micros":wall,"peak_rss_bytes":peak,
        "source_read_bytes":io.source_bytes,"model_transport_bytes":io.bytes,"model_transport_operations":io.operations,
        "model_transport_is_in_memory":true,"optimizer_updates":0,"proof_searches":0,
        "timing_scope":"Through diagnosis; the separate cost seal includes result serialization and writing."});
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    if cpu > 90_000_000
        || wall > 120_000_000
        || peak > crate::learning::model::REQUIREMENTS.work_bytes as u64
        || io.source_bytes + io.bytes + bytes.len() > crate::learning::model::REQUIREMENTS.io_bytes
        || bytes.len() > 256 * 1024
    {
        return Err("activation diagnosis exhausted its unchanged allowance".into());
    }
    let result_bytes = bytes.len();
    let result_sha256 = Blob::of(&bytes).sha256;
    std::fs::write(output.join("results.json"), bytes).map_err(|e| e.to_string())?;
    let cpu = meta::cpu_micros()?.saturating_sub(cpu_start);
    let wall = started.elapsed().as_micros();
    if cpu > 90_000_000 || wall > 120_000_000 {
        return Err("activation reporting exhausted its unchanged allowance".into());
    }
    let seal = serde_json::to_vec_pretty(&serde_json::json!({
        "complete":true,"results_sha256":result_sha256,"cpu_micros":cpu,"wall_micros":wall,
        "source_read_bytes":io.source_bytes,"model_transport_bytes":io.bytes,
        "result_written_bytes":result_bytes,"peak_rss_bytes":peak,
        "seal_write_is_reporting_overhead":true
    }))
    .map_err(|e| e.to_string())?;
    if io.source_bytes + io.bytes + result_bytes + seal.len()
        > crate::learning::model::REQUIREMENTS.io_bytes
    {
        return Err("activation reporting exhausted its unchanged IO allowance".into());
    }
    std::fs::write(output.join("cost-seal.json"), seal).map_err(|e| e.to_string())
}

#[test]
#[ignore = "separately frozen bounded activation diagnosis; no training or qualification"]
fn frozen_activation_diagnosis() {
    let input = std::fs::read(std::env::var("NAOME_ACTIVATION_INPUT").unwrap()).unwrap();
    assert!(input.len() <= 256 * 1024);
    let input: Input = serde_json::from_slice(&input).unwrap();
    let output = PathBuf::from(std::env::var("NAOME_ACTIVATION_OUTPUT").unwrap());
    run(input, &output).unwrap();
}
