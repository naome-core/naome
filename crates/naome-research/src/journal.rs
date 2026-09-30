//! Immutable per-event files; replay checks every signature and transition.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Serialize, de::DeserializeOwned};

use crate::state::{Event, MAX_EVENTS, MAX_HISTORY_BYTES, ResearchState, SignedGenesis};

const MAX_RECORD_BYTES: u64 = 1024 * 1024;

pub struct Journal {
    root: PathBuf,
}

impl Journal {
    pub fn create(root: &Path, genesis: &SignedGenesis) -> Result<Self, String> {
        genesis.verify()?;
        fs::create_dir(root).map_err(|e| e.to_string())?;
        write_new(&root.join("genesis.json"), genesis)?;
        Ok(Self { root: root.into() })
    }
    pub fn open(root: &Path) -> Result<(Self, ResearchState), String> {
        let genesis = read_bounded(&root.join("genesis.json"), MAX_RECORD_BYTES)?;
        let mut files = Vec::new();
        let mut total_bytes = 0;
        for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non UTF-8 journal entry")?;
            if name == "genesis.json" {
                continue;
            }
            if !name.starts_with("event-")
                || !name.ends_with(".json")
                || !entry.file_type().map_err(|e| e.to_string())?.is_file()
            {
                return Err("unexpected journal entry".into());
            }
            files.push(name);
            if files.len() > MAX_EVENTS {
                return Err("journal event limit".into());
            }
            total_bytes += entry.metadata().map_err(|e| e.to_string())?.len();
            if total_bytes > MAX_HISTORY_BYTES as u64 * 4 {
                return Err("journal disk byte limit".into());
            }
        }
        files.sort();
        let mut events: Vec<Event> = Vec::new();
        for (index, name) in files.iter().enumerate() {
            if name != &format!("event-{index:06}.json") {
                return Err("journal gap or unexpected event filename".into());
            }
            events.push(read_bounded(&root.join(name), MAX_RECORD_BYTES)?);
        }
        let state = ResearchState::replay(genesis, &events)?;
        Ok((Self { root: root.into() }, state))
    }
    pub fn append(&self, event: &Event) -> Result<(), String> {
        write_new(
            &self
                .root
                .join(format!("event-{:06}.json", event.body.index)),
            event,
        )
    }
    /// Completeness requires a checkpoint supplied independently of this journal.
    pub fn open_at(
        root: &Path,
        expected_head: [u8; 32],
        expected_count: usize,
    ) -> Result<(Self, ResearchState), String> {
        let (journal, state) = Self::open(root)?;
        if state.head() != expected_head || state.events().len() != expected_count {
            return Err("independent history checkpoint mismatch".into());
        }
        Ok((journal, state))
    }
}

pub fn read_bounded<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("input must be a regular file".into());
    }
    let mut data = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > maximum {
        return Err("file byte limit".into());
    }
    serde_json::from_slice(&data).map_err(|e| e.to_string())
}

pub fn write_new<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    write_bytes_new(path, &bytes)
}

pub(crate) fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Action, Genesis, PoolConfig, SignedAction};
    use ed25519_dalek::SigningKey;
    #[test]
    fn immutable_journal_restarts_and_detects_gaps_and_tampering() {
        let root =
            std::env::temp_dir().join(format!("naome-research-journal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let key = SigningKey::from_bytes(&[31; 32]);
        let roster = vec![
            SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes(),
            SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes(),
        ];
        let genesis = SignedGenesis::sign(
            Genesis::new(
                "journal-test".into(),
                key.verifying_key().to_bytes(),
                roster,
                PoolConfig::default(),
            )
            .unwrap(),
            &key,
        )
        .unwrap();
        let journal = Journal::create(&root, &genesis).unwrap();
        let mut state = ResearchState::new(genesis).unwrap();
        let event = state
            .confirm(
                SignedAction::sign(state.genesis().genesis.id(), 1, Action::Tick, &key),
                &key,
            )
            .unwrap();
        journal.append(&event).unwrap();
        assert!(journal.append(&event).is_err());
        let (_, restarted) = Journal::open(&root).unwrap();
        assert_eq!(state.head(), restarted.head());
        assert_eq!(restarted.tick(), 1);
        fs::rename(
            root.join("event-000000.json"),
            root.join("event-000001.json"),
        )
        .unwrap();
        assert!(Journal::open(&root).is_err());
        fs::rename(
            root.join("event-000001.json"),
            root.join("event-000000.json"),
        )
        .unwrap();
        fs::write(root.join("event-000000.json"), b"{\"truncated\"").unwrap();
        assert!(Journal::open(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
