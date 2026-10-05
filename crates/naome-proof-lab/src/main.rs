//! Offline CPU research only. No admission, transport, reward or finality caller.
mod dataset;
mod experiment;
mod graph;
mod index;
mod model;
#[cfg(test)]
mod tests;
use crate::{dataset::Corpus, experiment::Config, model::Model};
use serde::{Serialize, de::DeserializeOwned};
use std::{fs, io::Write, path::Path};
fn read<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    if fs::metadata(path).map_err(|e| e.to_string())?.len() > 256 * 1024 * 1024 {
        return Err("input file ceiling".into());
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
fn write<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(&bytes).map_err(|e| e.to_string())
}
fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["--identity"] {
        println!(
            "{}",
            serde_json::json!({"schema":1,
            "compiler":env!("NAOME_LAB_COMPILER"),
            "source_tree":env!("NAOME_LAB_SOURCE_TREE"),
            "source_clean":env!("NAOME_LAB_SOURCE_CLEAN") == "true"})
        );
        return Ok(());
    }
    if args.len() == 2 && args[0] == "--validate-config" {
        let config: Config = read(Path::new(&args[1]))?;
        config.validate()?;
        println!("configuration accepted without experiment work");
        return Ok(());
    }
    if args.len() != 3 {
        return Err("Usage: naome-proof-lab <generate|train|evaluate|benchmark|replay> <configuration.json> <new-run-directory>; evaluate/benchmark/replay use existing run artifacts".into());
    }
    let config: Config = read(Path::new(&args[1]))?;
    config.validate()?;
    let output = Path::new(&args[2]);
    fs::create_dir_all(output).map_err(|e| e.to_string())?;
    // Cross-command single-process admission on this host, released by RAII.
    let lock_path = std::env::temp_dir().join("naome-proof-lab.lock");
    let mut lock=fs::OpenOptions::new().write(true).create_new(true).open(&lock_path).map_err(|e|format!("experiment lock unavailable ({e}); verify no owned process before removing a stale lock"))?;
    writeln!(lock, "{}", std::process::id()).map_err(|e| e.to_string())?;
    struct Lock(std::path::PathBuf);
    impl Drop for Lock {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _lock = Lock(lock_path);
    let config_digest = dataset::digest(&fs::read(&args[1]).map_err(|e| e.to_string())?);
    match args[0].as_str() {
        "generate" => {
            let corpus = dataset::generate(config.families)?;
            corpus.replay()?;
            write(&output.join("corpus.json"), &corpus)?;
            write(
                &output.join("freeze.json"),
                &serde_json::json!({"schema":1,"config_sha256":config_digest,"corpus_sha256":corpus.digest(),"labels":dataset::LABELS,"split":"family % 8: 0 test, 1 development, 2..7 train","config":config,"counts":corpus.counts()}),
            )?;
        }
        "train" => {
            let c: Corpus = read(&output.join("corpus.json"))?;
            c.replay()?;
            verify_freeze(output, &config_digest, &c)?;
            for seed in &config.seeds {
                write(
                    &output.join(format!("initial-model-{seed}.json")),
                    &Model::new(*seed, c.digest()),
                )?;
                let (model, result) = experiment::train(&c, &config, *seed);
                model.validate()?;
                write(&output.join(format!("model-{seed}.json")), &model)?;
                write(&output.join(format!("training-{seed}.json")), &result)?;
            }
        }
        "evaluate" | "replay" => {
            let c: Corpus = read(&output.join("corpus.json"))?;
            c.replay()?;
            verify_freeze(output, &config_digest, &c)?;
            for seed in &config.seeds {
                let m: Model = read(&output.join(format!("model-{seed}.json")))?;
                m.validate()?;
                if m.corpus_digest != c.digest() {
                    return Err("model/corpus mismatch".into());
                }
                let q: serde_json::Value = read(&output.join(format!("training-{seed}.json")))?;
                if q["trained_model_sha256"] != dataset::digest(&serde_json::to_vec(&m).unwrap()) {
                    return Err("model digest mismatch".into());
                }
                let actual = experiment::evaluate(
                    &c,
                    &m,
                    2,
                    q["threshold"].as_f64().ok_or("missing threshold")?,
                );
                if args[0] == "evaluate" {
                    write(&output.join(format!("quality-{seed}.json")), &actual)?;
                } else {
                    let saved: serde_json::Value =
                        read(&output.join(format!("quality-{seed}.json")))?;
                    if actual != saved {
                        return Err("held-out numerical replay mismatch".into());
                    }
                }
            }
            println!("checked corpus, model digests and held-out scores replay exactly");
        }
        "benchmark" => {
            let original: Corpus = read(&output.join("corpus.json"))?;
            verify_freeze(output, &config_digest, &original)?;
            let m: Model = read(&output.join(format!("model-{}.json", config.seeds[0])))?;
            m.validate()?;
            if m.corpus_digest != original.digest() {
                return Err("model/corpus mismatch".into());
            }
            for rows in &config.scale_rows {
                let families = (*rows / 8).min(config.max_scale_families);
                let c = dataset::generate(families)?;
                let (result, index) =
                    experiment::benchmark(&c, &original, &m, *rows, config.queries, config.repeats);
                write(&output.join(format!("index-{rows}.json")), &index)?;
                let restored: index::Index = read(&output.join(format!("index-{rows}.json")))?;
                restored.validate(&m, &c)?;
                if restored != index {
                    return Err("index serialization mismatch".into());
                }
                write(&output.join(format!("scale-{rows}.json")), &result)?;
                println!("completed {rows} rows, {families} generated families");
            }
        }
        _ => return Err("unknown command".into()),
    }
    Ok(())
}
fn verify_freeze(path: &Path, config: &str, c: &Corpus) -> Result<(), String> {
    let f: serde_json::Value = read(&path.join("freeze.json"))?;
    if f["config_sha256"] != config || f["corpus_sha256"] != c.digest() {
        return Err("frozen inputs changed".into());
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
