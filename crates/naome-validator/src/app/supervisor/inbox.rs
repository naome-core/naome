//! Bounded untrusted intake and durable local proposer preference.
//! Neither the inbox nor this preference establishes selected history.
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use naome_chain::ArtifactBlockId;
use naome_storage::SelectedArtifactHistory;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::{Result, acquisition, files, report, sources::Sources};

const MAX_ENTRIES: usize = 256;
const MAX_BYTES: usize = 20_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    candidates: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Choice {
    height: String,
    parent: String,
    target: String,
}

pub(in crate::app) struct Inbox {
    path: PathBuf,
    state: PathBuf,
    choice: Option<Choice>,
    missing_cursor: usize,
    missing_attempts: usize,
    pub missing: Option<(ArtifactBlockId, bool)>,
}

impl Inbox {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: PathBuf::new(),
            choice: None,
            missing_cursor: 0,
            missing_attempts: 0,
            missing: None,
        }
    }

    pub fn bind(&mut self, directory: &Path, create: bool) -> Result<()> {
        self.state = directory.join("supervisor-choice-v0.json");
        if create {
            let bytes = encode(&None)?;
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&self.state)
                .map_err(|_| "supervisor_choice_create")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "supervisor_choice_write")?;
        } else {
            let bytes = files::bytes(&self.state, 1024)?;
            self.choice = decode(&bytes)?;
            if !files::match_and_sync(&self.state, &bytes)? {
                return Err("supervisor_choice_changed");
            }
        }
        sync_directory(directory)
    }

    pub fn target(&self, height: u64, head: ArtifactBlockId) -> Result<Option<ArtifactBlockId>> {
        let Some(choice) = &self.choice else {
            return Ok(None);
        };
        let recorded = super::config::decimal::<u64>(&choice.height)?;
        if recorded > height || (recorded == height && acquisition::block(&choice.parent)? != head)
        {
            return Err("supervisor_choice_position");
        }
        if recorded == height {
            Ok(Some(acquisition::block(&choice.target)?))
        } else {
            Ok(None)
        }
    }

    /// Called at most once per supervisor interval with idle source ownership.
    pub fn scan(
        &mut self,
        height: u64,
        history: &dyn SelectedArtifactHistory,
        sources: &mut Sources,
    ) -> Result<Option<&'static str>> {
        self.missing = None;
        let head = history
            .selected_head_block_id()
            .map_err(|_| "supervisor_selected_history")?;
        if self.target(height, head)?.is_some() {
            return Ok(None);
        }
        if sources.candidates.chain_id() != history.selected_chain_id() {
            return Err("supervisor_source_chain");
        }
        let ids = match read_batch(&self.path) {
            Ok(ids) => ids,
            // External intake is untrusted and may be temporarily incomplete.
            // Invalid batches never change the durable preference.
            Err(code) => return Ok(Some(code)),
        };
        let snapshot = history
            .selected_branch_snapshot_at(head)
            .map_err(|_| "supervisor_selected_history")?
            .ok_or("supervisor_selected_snapshot")?;
        let mut missing = Vec::new();
        for id in ids {
            let Some(block) = sources
                .candidates
                .get(id)
                .map_err(|_| "source_candidate_store")?
            else {
                missing.push((id, false));
                continue;
            };
            if block.parent_block_id() != head {
                continue;
            }
            let Some(payload) = sources
                .payloads
                .get(block.artifact_id())
                .map_err(|_| "source_local_store")?
            else {
                missing.push((id, true));
                continue;
            };
            if snapshot
                .validate_child(&block, payload.into_canonical_artifact_bytes().into_vec())
                .is_ok()
            {
                // IDs are canonical, deduplicated and sorted. Missing or invalid
                // lower IDs are not members of this observed eligible set.
                self.persist(Choice {
                    height: height.to_string(),
                    parent: report::hex(head.as_bytes()),
                    target: report::hex(id.as_bytes()),
                })?;
                return Ok(None);
            }
        }
        if !missing.is_empty() {
            self.missing_cursor %= missing.len();
            self.missing = Some(missing[self.missing_cursor]);
        }
        Ok(None)
    }

    pub fn acquired(&mut self, peers: usize) {
        // Exhaust a peer cycle before advancing the hint. Advancing both
        // cursors on every request could pin each hint to one unavailable peer
        // when the number of hints shares a factor with the peer count.
        self.missing_attempts += 1;
        if self.missing_attempts == peers {
            self.missing_attempts = 0;
            self.missing_cursor = (self.missing_cursor + 1) % MAX_ENTRIES;
        }
    }

    fn persist(&mut self, choice: Choice) -> Result<()> {
        let choice = Some(choice);
        let bytes = encode(&choice)?;
        let directory = self.state.parent().ok_or("supervisor_choice_path")?;
        let temporary = directory.join("supervisor-choice-v0.pending");
        // An interrupted replacement may leave this non-authoritative entry.
        // Remove its name under the signer lock; never follow or reuse its inode.
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("supervisor_choice_temporary"),
        }
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| "supervisor_choice_create")?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "supervisor_choice_write")?;
        fs::rename(&temporary, &self.state).map_err(|_| "supervisor_choice_replace")?;
        sync_directory(directory)?;
        self.choice = choice;
        Ok(())
    }
}

fn read_batch(path: &Path) -> Result<Vec<ArtifactBlockId>> {
    let bytes = files::bytes(path, MAX_BYTES)?;
    let batch: Batch = serde_json::from_slice(&bytes).map_err(|_| "supervisor_inbox_schema")?;
    if batch.candidates.len() > MAX_ENTRIES {
        return Err("supervisor_inbox_limit");
    }
    let mut ids = batch
        .candidates
        .iter()
        .map(|s| acquisition::block(s))
        .collect::<Result<Vec<_>>>()?;
    ids.sort_unstable_by_key(|id| *id.as_bytes());
    ids.dedup();
    Ok(ids)
}

fn encode(choice: &Option<Choice>) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(choice).map_err(|_| "supervisor_choice_encoding")?;
    let hash = report::hex(&Sha256::digest(&bytes));
    bytes.push(b'\n');
    bytes.extend_from_slice(hash.as_bytes());
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Option<Choice>> {
    let end = bytes
        .len()
        .checked_sub(65)
        .ok_or("supervisor_choice_encoding")?;
    let choice: Option<Choice> =
        serde_json::from_slice(&bytes[..end]).map_err(|_| "supervisor_choice_encoding")?;
    if encode(&choice)? != bytes {
        return Err("supervisor_choice_integrity");
    }
    if let Some(choice) = &choice {
        if super::config::decimal::<u64>(&choice.height)? == 0 {
            return Err("supervisor_choice_height");
        }
        let _ = acquisition::block(&choice.parent)?;
        let _ = acquisition::block(&choice.target)?;
    }
    Ok(choice)
}

fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| "supervisor_choice_sync")
}
