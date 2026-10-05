//! Offline binary question decisions; no production node or admission caller.
mod dataset;
mod decision;
mod experiment;
#[cfg(test)]
mod tests;
use crate::write;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::{fs, path::Path};
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub seeds: Vec<u64>,
    pub epochs: usize,
    pub learning_rate: f64,
    pub threshold_floor: f64,
    pub active_cpu_seconds: u64,
    pub max_rss_bytes: u64,
    pub max_output_bytes: u64,
    pub decision_millis: u64,
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || self.seeds != [17, 29, 43]
            || self.epochs != 12
            || self.learning_rate != 0.01
            || self.threshold_floor != 0.90
            || self.active_cpu_seconds != 900
            || self.max_rss_bytes != 512 * 1024 * 1024
            || self.max_output_bytes != 64 * 1024 * 1024
            || self.decision_millis != 5000
        {
            return Err("configuration differs from the frozen question experiment".into());
        }
        Ok(())
    }
}
fn bytes(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut input = fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take((maximum + 1) as u64);
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > maximum {
        return Err("question input file ceiling".into());
    }
    Ok(bytes)
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&bytes(path, 2 * 1024 * 1024)?).map_err(|e| e.to_string())
}
pub fn validate_config(path: &Path) -> Result<(), String> {
    let config: Config = serde_json::from_slice(&bytes(path, 4096)?).map_err(|e| e.to_string())?;
    config.validate()
}
pub fn run(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("Usage: naome-proof-lab questions-<generate|train|evaluate|replay|decide> <config.json> <run-directory>".into());
    }
    let config_bytes = bytes(Path::new(&args[1]), 4096)?;
    let config: Config = serde_json::from_slice(&config_bytes).map_err(|e| e.to_string())?;
    config.validate()?;
    let _lock = crate::experiment_lock()?;
    let output = Path::new(&args[2]);
    fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let config_digest = crate::dataset::digest(&config_bytes);
    match args[0].as_str() {
        "questions-generate" => {
            let corpus = dataset::generate()?;
            let inputs = corpus.replay()?;
            write(&output.join("question-corpus.json"), &corpus)?;
            write(
                &output.join("question-freeze.json"),
                &serde_json::json!({"schema":1,"config_sha256":config_digest,"corpus_sha256":corpus.digest(),"fixtures_sha256":corpus.fixtures_sha256,"policy":dataset::POLICY,"feature_schema":dataset::FEATURE_SCHEMA,"labels":dataset::LABELS,"rows":inputs.len(),"source_tree":env!("NAOME_LAB_SOURCE_TREE"),"source_clean":env!("NAOME_LAB_SOURCE_CLEAN")=="true","label_review_accepted":false,"qualified":false}),
            )?;
            println!(
                "{}",
                serde_json::json!({"schema":1,"command":"questions-generate","rows_validated":inputs.len(),"checked_contexts_replayed":inputs.len(),"exact_elementary_witnesses_checked":corpus.rows.iter().filter(|r|r.witness_source.is_some()).count(),"corpus_sha256":corpus.digest(),"fixtures_sha256":corpus.fixtures_sha256,"config_sha256":config_digest,"source_tree":env!("NAOME_LAB_SOURCE_TREE"),"source_clean":env!("NAOME_LAB_SOURCE_CLEAN")=="true","label_review_accepted":false,"training_executed":false})
            );
        }
        "questions-train" | "questions-evaluate" | "questions-replay" => {
            let corpus: dataset::Corpus = read(&output.join("question-corpus.json"))?;
            let inputs = corpus.replay()?;
            let freeze: serde_json::Value = read(&output.join("question-freeze.json"))?;
            if freeze["config_sha256"] != config_digest
                || freeze["corpus_sha256"] != corpus.digest()
            {
                return Err("frozen question inputs changed".into());
            }
            let acceptance: serde_json::Value = read(&output.join("question-label-review.json"))?;
            if acceptance["accepted"] != true
                || acceptance["corpus_sha256"] != corpus.digest()
                || acceptance["fixtures_sha256"] != corpus.fixtures_sha256
                || acceptance["reviewer"].as_str().is_none_or(str::is_empty)
            {
                return Err("independent frozen label acceptance missing".into());
            }
            experiment::run(&args[0], &config, &corpus, &inputs, output)?;
        }
        "questions-decide" => decision::run(&config, output)?,
        _ => return Err("unknown question command".into()),
    }
    Ok(())
}
