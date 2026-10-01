//! Explicit preparation leaves policy editable until the separate init command.

use super::{
    Config,
    budget::{Allowance, Budgets, Period},
};
use crate::{
    journal::{read_bounded, write_new},
    provider::ProviderConfig,
    run::Interests,
    state::{PoolConfig, hash, hex},
};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn read_config(path: &Path) -> Result<Config, String> {
    let config: Config = read_bounded(path, 64 * 1024)?;
    config.validate()?;
    Ok(config)
}
pub fn prepare(root: &Path, binary: &Path, home: &Path, model: &str) -> Result<PathBuf, String> {
    if !root.is_absolute() || !binary.is_absolute() || !home.is_absolute() || model.is_empty() {
        return Err(
            "absolute preparation, native Codex and Codex home paths plus explicit model required"
                .into(),
        );
    }
    fs::create_dir(root).map_err(|e| e.to_string())?;
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).map_err(|e| e.to_string())?;
    let identity_file = root.join("node-key.json");
    write_new(&identity_file, &seed)?;
    let config = Config {
        version: 2,
        directory: root.join("node"),
        identity_file,
        run_label: format!("local-node-{}", &hex(&hash(b"node-label", &seed))[..12]),
        interests: Interests {
            topics: vec!["Formal mathematical foundations".into()],
            context: "Investigate exact closed questions and reusable checked proofs.".into(),
        },
        provider: ProviderConfig {
            codex_binary: binary.into(),
            codex_home: home.into(),
            model: model.into(),
            timeout_seconds: 90,
            max_output_bytes: 256 * 1024,
            disabled_registries: Default::default(),
            pure_js: None,
        },
        budgets: Budgets {
            timezone: "Europe/Berlin".into(),
            research: Allowance {
                amount: 0,
                period: Period::Day,
            },
            discoveries: Allowance {
                amount: 0,
                period: Period::Hour,
            },
            evaluations: Allowance {
                amount: 0,
                period: Period::Hour,
            },
        },
        credit: 1,
        pool: PoolConfig::default(),
    };
    config.validate()?;
    let path = root.join("node-config.json");
    write_new(&path, &config)?;
    Ok(path)
}
