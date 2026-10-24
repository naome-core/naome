//! Local, pinned Liquid adapter configuration. No interest policy.
use crate::storage::FileGeneration;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::OnceLock,
};

pub(crate) const ADAPTER: &str = "naome:liquid-d1-3b-q8-llamacpp:v1";
pub(crate) const SCRIPT: &str = include_str!("liquid_worker.py");
const ASSETS: &str = include_str!("liquid_assets.json");

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

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Snapshot {
    configuration: Configuration,
    files: Vec<(String, FileGeneration)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Installed {
    snapshot: Snapshot,
    identity: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    model: Model,
    runtime: Runtime,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Model {
    pub repository: String,
    pub revision: String,
    files: Vec<Asset>,
    provenance: Vec<Asset>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    repository: String,
    release: String,
    source: String,
    platforms: BTreeMap<String, Platform>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Platform {
    archive: String,
    sha256: String,
    files: Vec<Asset>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<String>,
}

fn manifest() -> &'static Manifest {
    // Immutable bundled metadata, not a model/resource singleton.
    static MANIFEST: OnceLock<Manifest> = OnceLock::new();
    MANIFEST.get_or_init(|| serde_json::from_str(ASSETS).expect("pinned asset manifest"))
}
pub(crate) fn model() -> &'static Model {
    &manifest().model
}

fn platform() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("darwin-arm64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        _ => Err("unsupported decision runtime platform".into()),
    }
}

impl Snapshot {
    fn read(directory: &Path) -> Result<Option<Self>, String> {
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
        let mut files = vec![("interpreter".into(), FileGeneration::of(&python))];
        for (scope, directory, assets) in [
            (
                "model",
                &configuration.model_directory,
                &manifest().model.files,
            ),
            (
                "runtime",
                &configuration.runtime_directory,
                &manifest().runtime.platforms[platform()?].files,
            ),
        ] {
            for asset in assets {
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
                files.push((
                    format!("{scope}/{}", asset.file),
                    FileGeneration::of(&metadata),
                ));
            }
        }
        Ok(Some(Self {
            configuration,
            files,
        }))
    }
}

impl Installed {
    pub(crate) fn load(directory: &Path) -> Result<Option<Self>, String> {
        Ok(Snapshot::read(directory)?.map(|snapshot| {
            let identity = super::digest(&(
                super::CONTRACT,
                ADAPTER,
                &model().repository,
                &model().revision,
                SCRIPT,
                ASSETS,
                &snapshot,
            ));
            Self { snapshot, identity }
        }))
    }
    /// Observe mutable installation state without recomputing the pinned model
    /// identity or rebuilding a backend on each admission/commit boundary.
    pub(crate) fn matches_current(
        directory: &Path,
        expected: Option<&Self>,
    ) -> Result<bool, String> {
        Ok(Snapshot::read(directory)?.as_ref() == expected.map(|model| &model.snapshot))
    }
    pub(crate) fn identity(&self) -> String {
        self.identity.clone()
    }
    pub(crate) fn configuration(&self) -> &Configuration {
        &self.snapshot.configuration
    }

    pub(crate) fn backend(&self) -> super::runtime::Backend {
        let configuration = self.configuration();
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
            initialization: serde_json::json!({"configuration":configuration, "model":self.identity(),
                "platform":platform().expect("installed platform"), "assets":manifest()}),
            memory_bytes: configuration.memory_bytes,
            threads: configuration.threads,
        }
    }
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

#[cfg(test)]
mod tests;
