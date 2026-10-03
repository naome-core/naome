//! Ordered immutable records and small authenticated checkpoints.

use super::index::{EMPTY, Index, atomic_write, sync_directory};
use crate::{
    journal::read_bounded,
    state::{Id, hash},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

pub(super) const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 32 * 1024;
const MAX_WRITES: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Change {
    pub key: Id,
    pub value: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub count: u64,
    pub head: Id,
    pub root: Id,
    pub state: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedCheckpoint {
    checkpoint: Checkpoint,
    signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordBody {
    pub profile: Id,
    pub index: u64,
    pub previous: Id,
    pub previous_root: Id,
    pub operation: Value,
    pub changes: Vec<Change>,
    pub root: Id,
    pub state: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub body: RecordBody,
    signature: Vec<u8>,
}
impl Record {
    pub fn id(&self) -> Id {
        hash(b"naome:research:record:v2\0", &self.body)
    }
}

/// The open File owns an OS lock, released even if a process crashes. Opening
/// another handle cannot remove or reset the live owner's budget lineage.
pub(super) struct Store {
    directory: PathBuf,
    lock: Option<File>,
    key: Id,
    profile: Id,
    index: Index,
    pub checkpoint: Checkpoint,
    failed: bool,
}
impl Drop for Store {
    fn drop(&mut self) {
        if let Some(lock) = &self.lock {
            let _ = lock.unlock();
        }
    }
}

impl Store {
    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn create<T: Serialize>(
        directory: &Path,
        profile: Id,
        signing: &SigningKey,
        state: &T,
    ) -> Result<Self, String> {
        fs::create_dir(directory).map_err(|e| format!("new v2 store directory required: {e}"))?;
        let lock = lock(directory)?;
        fs::create_dir(directory.join("records")).map_err(|e| e.to_string())?;
        fs::create_dir(directory.join("index")).map_err(|e| e.to_string())?;
        let checkpoint = Checkpoint {
            count: 0,
            head: profile,
            root: EMPTY,
            state: serde_json::to_value(state).map_err(|e| e.to_string())?,
        };
        let store = Self {
            directory: directory.into(),
            lock: Some(lock),
            key: signing.verifying_key().to_bytes(),
            profile,
            index: Index::new(directory.join("index")),
            checkpoint,
            failed: false,
        };
        store.save_checkpoint(signing)?;
        atomic_write(
            &directory.join("initial.json"),
            &checkpoint_bytes(profile, &store.checkpoint, signing)?,
        )?;
        sync_directory(directory)?;
        Ok(store)
    }
    pub fn open(directory: &Path, profile: Id, key: Id) -> Result<Self, String> {
        let lock = lock(directory)?;
        Self::load(directory, profile, key, Some(lock))
    }
    pub fn inspect(directory: &Path, profile: Id, key: Id) -> Result<Self, String> {
        Self::load(directory, profile, key, None)
    }
    fn load(directory: &Path, profile: Id, key: Id, lock: Option<File>) -> Result<Self, String> {
        let signed: SignedCheckpoint =
            read_bounded(&directory.join("checkpoint.json"), MAX_CHECKPOINT_BYTES)?;
        verify(
            key,
            &hash(
                b"naome:research:checkpoint:v2\0",
                &(profile, &signed.checkpoint),
            ),
            &signed.signature,
        )?;
        let store = Self {
            directory: directory.into(),
            lock,
            key,
            profile,
            index: Index::new(directory.join("index")),
            checkpoint: signed.checkpoint,
            failed: false,
        };
        if store.checkpoint.count == 0 {
            if store.checkpoint.head != profile || store.checkpoint.root != EMPTY {
                return Err("invalid initial checkpoint".into());
            }
        } else {
            let record = store.record(store.checkpoint.count - 1)?;
            if record.id() != store.checkpoint.head
                || record.body.root != store.checkpoint.root
                || record.body.state != store.checkpoint.state
            {
                return Err("checkpoint does not match its immutable record".into());
            }
        }
        Ok(store)
    }
    fn path(&self, index: u64) -> PathBuf {
        self.directory
            .join("records")
            .join(format!("{:014x}", index >> 8))
            .join(format!("{:02x}.json", index & 255))
    }
    pub fn record(&self, index: u64) -> Result<Record, String> {
        let record: Record = read_bounded(&self.path(index), MAX_RECORD_BYTES)?;
        if record.body.profile != self.profile
            || record.body.index != index
            || record.body.changes.len() > MAX_WRITES
        {
            return Err("wrong local record lineage or bounds".into());
        }
        verify(self.key, &record.id(), &record.signature)?;
        Ok(record)
    }
    pub fn get<T: DeserializeOwned>(&self, key: Id) -> Result<Option<T>, String> {
        self.index.get(self.checkpoint.root, key)
    }
    pub fn initial(&self) -> Result<Checkpoint, String> {
        let signed: SignedCheckpoint =
            read_bounded(&self.directory.join("initial.json"), MAX_CHECKPOINT_BYTES)?;
        verify(
            self.key,
            &hash(
                b"naome:research:checkpoint:v2\0",
                &(self.profile, &signed.checkpoint),
            ),
            &signed.signature,
        )?;
        if signed.checkpoint.count != 0
            || signed.checkpoint.head != self.profile
            || signed.checkpoint.root != EMPTY
        {
            return Err("invalid immutable initial checkpoint".into());
        }
        Ok(signed.checkpoint)
    }
    pub fn unfinished_record(&self) -> Result<Option<Record>, String> {
        let path = self.path(self.checkpoint.count);
        if path.exists() {
            self.record(self.checkpoint.count).map(Some)
        } else {
            Ok(None)
        }
    }
    /// The caller validates and derives the operation before this commit.
    /// Immutable record sync is the selection point; a lost acknowledgement
    /// is recovered from that exact record, never by repeating a model call.
    pub fn append<O: Serialize, S: Serialize>(
        &mut self,
        operation: &O,
        state: &S,
        changes: Vec<Change>,
        key: &SigningKey,
    ) -> Result<(), String> {
        if self.failed {
            return Err("store requires reopen after failed commit".into());
        }
        if self.lock.is_none() {
            return Err("read-only node snapshot cannot append".into());
        }
        let result = self.append_inner(operation, state, changes, key);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn append_inner<O: Serialize, S: Serialize>(
        &mut self,
        operation: &O,
        state: &S,
        changes: Vec<Change>,
        key: &SigningKey,
    ) -> Result<(), String> {
        if key.verifying_key().to_bytes() != self.key
            || changes.len() > MAX_WRITES
            || self.path(self.checkpoint.count).exists()
        {
            return Err("wrong writer, excessive changes or unacknowledged record".into());
        }
        let mut root = self.checkpoint.root;
        for change in &changes {
            root = self.index.put(root, change.key, &change.value)?;
        }
        let body = RecordBody {
            profile: self.profile,
            index: self.checkpoint.count,
            previous: self.checkpoint.head,
            previous_root: self.checkpoint.root,
            operation: serde_json::to_value(operation).map_err(|e| e.to_string())?,
            changes,
            root,
            state: serde_json::to_value(state).map_err(|e| e.to_string())?,
        };
        let record = Record {
            signature: key
                .sign(&hash(b"naome:research:record:v2\0", &body))
                .to_bytes()
                .to_vec(),
            body,
        };
        let bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err("local record exceeds per-record limit".into());
        }
        // Validate the checkpoint bound before crossing the durable selection point.
        let next = Checkpoint {
            count: self
                .checkpoint
                .count
                .checked_add(1)
                .ok_or("record ordinal overflow")?,
            head: record.id(),
            root,
            state: record.body.state.clone(),
        };
        checkpoint_bytes(self.profile, &next, key)?;
        let path = self.path(self.checkpoint.count);
        fs::create_dir_all(path.parent().ok_or("record parent missing")?)
            .map_err(|e| e.to_string())?;
        sync_directory(&self.directory.join("records"))?;
        atomic_write(&path, &bytes)?;
        self.checkpoint = next;
        self.save_checkpoint(key)
    }
    pub fn recover(&mut self, record: &Record, key: &SigningKey) -> Result<(), String> {
        if self.lock.is_none() {
            return Err("read-only node snapshot cannot recover commits".into());
        }
        if record.body.index != self.checkpoint.count
            || record.body.previous != self.checkpoint.head
            || record.body.previous_root != self.checkpoint.root
        {
            return Err("unacknowledged record does not extend checkpoint".into());
        }
        let mut root = self.checkpoint.root;
        for change in &record.body.changes {
            root = self.index.put(root, change.key, &change.value)?;
        }
        if root != record.body.root {
            return Err("record index transition mismatch".into());
        }
        self.checkpoint = Checkpoint {
            count: self
                .checkpoint
                .count
                .checked_add(1)
                .ok_or("record ordinal overflow")?,
            head: record.id(),
            root,
            state: record.body.state.clone(),
        };
        self.save_checkpoint(key)
    }
    fn save_checkpoint(&self, key: &SigningKey) -> Result<(), String> {
        atomic_write(
            &self.directory.join("checkpoint.json"),
            &checkpoint_bytes(self.profile, &self.checkpoint, key)?,
        )
    }
}

fn checkpoint_bytes(
    profile: Id,
    checkpoint: &Checkpoint,
    key: &SigningKey,
) -> Result<Vec<u8>, String> {
    let signed = SignedCheckpoint {
        checkpoint: checkpoint.clone(),
        signature: key
            .sign(&hash(
                b"naome:research:checkpoint:v2\0",
                &(profile, checkpoint),
            ))
            .to_bytes()
            .to_vec(),
    };
    let bytes = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err("local checkpoint exceeds working-state limit".into());
    }
    Ok(bytes)
}
fn lock(directory: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("node.lock"))
        .map_err(|e| e.to_string())?;
    file.try_lock()
        .map_err(|e| format!("exclusive node lock unavailable: {e}"))?;
    Ok(file)
}
pub(super) fn verify(key: Id, message: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(&key).map_err(|e| e.to_string())?;
    if key.is_weak() {
        return Err("weak local identity".into());
    }
    key.verify_strict(
        message,
        &Signature::from_slice(signature).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}
pub(super) fn index_key<T: Serialize>(namespace: &str, id: &T) -> Id {
    hash(b"naome:research:index-key:v2\0", &(namespace, id))
}
pub(super) fn change<T: Serialize>(
    namespace: &str,
    id: &impl Serialize,
    value: &T,
) -> Result<Change, String> {
    Ok(Change {
        key: index_key(namespace, id),
        value: serde_json::to_value(value).map_err(|e| e.to_string())?,
    })
}
