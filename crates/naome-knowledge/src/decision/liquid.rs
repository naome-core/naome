//! Local, pinned Liquid adapter configuration. No interest policy.
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(crate) const MODEL: &str = "LiquidAI/d1-3B-GGUF";
pub(crate) const REVISION: &str = "bb1e436ea78eb96a3f1acb6da865f70c2fbeb563";
pub(crate) const ADAPTER: &str = "naome:liquid-d1-3b-q8-llamacpp:v1";
pub(crate) const SCRIPT: &str = include_str!("liquid_worker.py");
pub(crate) const ASSETS: &str = include_str!("liquid_assets.json");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    pub version: u8,
    pub python: PathBuf,
    pub model_directory: PathBuf,
    pub runtime_directory: PathBuf,
    pub threads: usize,
    pub max_input_tokens: usize,
    pub memory_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Installed {
    pub configuration: Configuration,
    files: Vec<(String, u64, u64, i64, i64, i64, i64)>,
}

#[derive(Deserialize)]
struct Asset {
    file: String,
    bytes: Option<u64>,
    link: Option<String>,
}

fn platform() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("darwin-arm64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        _ => Err("unsupported decision runtime platform".into()),
    }
}

impl Installed {
    pub(crate) fn load(directory: &Path) -> Result<Option<Self>, String> {
        let path = directory.join("decision.json");
        if !path.try_exists().map_err(|e| e.to_string())? {
            return Ok(None);
        }
        crate::storage::owned_file(&path)?;
        let bytes = crate::store::read_bounded(&path, 8192).map_err(|e| e.to_string())?;
        let configuration: Configuration =
            serde_json::from_slice(&bytes).map_err(|e| format!("decision configuration: {e}"))?;
        configuration.validate()?;
        let python = std::fs::metadata(&configuration.python)
            .map_err(|e| format!("decision interpreter: {e}"))?;
        if !python.is_file() {
            return Err("decision interpreter is not a file".into());
        }
        let mut files = vec![stamp("interpreter".into(), &python)];
        let manifest: serde_json::Value = serde_json::from_str(ASSETS).expect("pinned manifest");
        for (scope, directory, assets) in [
            (
                "model",
                &configuration.model_directory,
                &manifest["model"]["files"],
            ),
            (
                "runtime",
                &configuration.runtime_directory,
                &manifest["runtime"]["platforms"][platform()?]["files"],
            ),
        ] {
            for asset in
                serde_json::from_value::<Vec<Asset>>(assets.clone()).expect("pinned assets")
            {
                let path = directory.join(&asset.file);
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|e| format!("decision asset {}: {e}", asset.file))?;
                if let Some(link) = &asset.link {
                    if !metadata.is_symlink()
                        || std::fs::read_link(&path).map_err(|e| e.to_string())? != Path::new(link)
                    {
                        return Err("decision runtime link differs".into());
                    }
                } else if !metadata.is_file() || Some(metadata.len()) != asset.bytes {
                    return Err("decision asset size or type differs".into());
                }
                files.push(stamp(format!("{scope}/{}", asset.file), &metadata));
            }
        }
        Ok(Some(Self {
            configuration,
            files,
        }))
    }

    pub(crate) fn identity(&self) -> String {
        super::digest(&(
            super::CONTRACT,
            ADAPTER,
            MODEL,
            REVISION,
            SCRIPT,
            ASSETS,
            self,
        ))
    }

    pub(crate) fn backend(&self) -> super::runtime::Backend {
        let configuration = &self.configuration;
        super::runtime::Backend {
            identity: self.identity(),
            executable: configuration.python.clone(),
            arguments: ["-I", "-u", "-c", SCRIPT]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            environment: [
                ("OMP_NUM_THREADS", configuration.threads.to_string()),
                ("OPENBLAS_NUM_THREADS", configuration.threads.to_string()),
            ]
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
            initialization: serde_json::json!({"configuration":configuration, "model":self.identity(), "platform":platform().expect("installed platform"),
                "assets":serde_json::from_str::<serde_json::Value>(ASSETS).expect("asset manifest")}),
            memory_bytes: configuration.memory_bytes,
            threads: configuration.threads,
        }
    }
}

fn stamp(name: String, metadata: &std::fs::Metadata) -> (String, u64, u64, i64, i64, i64, i64) {
    (
        name,
        metadata.dev(),
        metadata.ino(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

impl Configuration {
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !self.python.is_absolute()
            || !self.model_directory.is_absolute()
            || !self.runtime_directory.is_absolute()
            || self.threads == 0
            || self.threads > 64
            || !(128..=4096).contains(&self.max_input_tokens)
            || self.memory_bytes == 0
            || self.memory_bytes > isize::MAX as u64
        {
            return Err("invalid decision configuration or capacity".into());
        }
        platform()?;
        Ok(())
    }
}

pub(crate) fn unconfigured_identity() -> String {
    super::digest(&(super::CONTRACT, "unconfigured"))
}
