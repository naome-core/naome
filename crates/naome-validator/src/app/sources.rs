use std::{
    fs::File,
    path::{Path, PathBuf},
};

use naome_chain::ArtifactChainDefinition;
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits, ArtifactPayloadStoreLimits,
    CanonicalArtifactPayloadStore,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    Result,
    config::{Mode, decimal},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    mode: Mode,
    candidate_directory: PathBuf,
    payload_directory: PathBuf,
    candidate_entries: String,
    payload_entries: String,
    payload_bytes: String,
}

pub(super) struct Prepared {
    mode: Mode,
    candidate_directory: PathBuf,
    payload_directory: PathBuf,
    candidate_limit: ArtifactBlockCandidateStoreLimits,
    payload_limit: ArtifactPayloadStoreLimits,
}

impl Config {
    pub fn prepare(self, base: &Path) -> Result<Prepared> {
        let candidate_directory = base.join(self.candidate_directory);
        let payload_directory = base.join(self.payload_directory);
        if !candidate_directory.is_dir() || !payload_directory.is_dir() {
            return Err("source_directory");
        }
        Ok(Prepared {
            mode: self.mode,
            candidate_directory,
            payload_directory,
            candidate_limit: ArtifactBlockCandidateStoreLimits::new(decimal(
                &self.candidate_entries,
            )?)
            .map_err(|_| "source_candidate_limit")?,
            payload_limit: ArtifactPayloadStoreLimits::new(
                decimal(&self.payload_entries)?,
                decimal(&self.payload_bytes)?,
            )
            .map_err(|_| "source_payload_limit")?,
        })
    }
}

pub(super) struct Sources {
    pub candidates: ArtifactBlockCandidateStore,
    pub payloads: CanonicalArtifactPayloadStore,
}

impl Prepared {
    pub fn open(self, definition: ArtifactChainDefinition) -> Result<Sources> {
        let candidates = match self.mode {
            Mode::Create => ArtifactBlockCandidateStore::create(
                &self.candidate_directory,
                definition,
                self.candidate_limit,
            ),
            Mode::Open => ArtifactBlockCandidateStore::open(
                &self.candidate_directory,
                definition,
                self.candidate_limit,
            ),
        }
        .map_err(|_| "source_candidates_open")?;
        // The lower stores synchronize their contents. The process also owns
        // stabilization of the caller-provisioned directory entries.
        stabilize(&self.candidate_directory)?;
        let payloads = match self.mode {
            Mode::Create => {
                CanonicalArtifactPayloadStore::create(&self.payload_directory, self.payload_limit)
            }
            Mode::Open => {
                CanonicalArtifactPayloadStore::open(&self.payload_directory, self.payload_limit)
            }
        }
        .map_err(|_| "source_payloads_open")?;
        stabilize(&self.payload_directory)?;
        Ok(Sources {
            candidates,
            payloads,
        })
    }
}

fn stabilize(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| "source_directory_sync")
}

impl Sources {
    pub fn status(&self) -> Value {
        // Poisoned stores expose no counts. These are local retention counters,
        // never evidence that a candidate is valid for the current signer.
        json!({
            "event": "sources_status", "enabled": true, "acquisition": null,
            "candidate_entries": self.candidates.len().ok(),
            "payload_entries": self.payloads.len().ok(),
            "payload_bytes": self.payloads.total_payload_bytes().ok().map(|n| n.to_string()),
        })
    }
}
