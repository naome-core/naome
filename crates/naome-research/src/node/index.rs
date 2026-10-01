//! Disk-backed immutable Patricia indexes. A handle retains only its root.

use crate::{
    journal::read_bounded,
    state::{Id, hash, hex},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub(super) const EMPTY: Id = [0; 32];
const MAX_NODE_BYTES: u64 = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Node {
    Leaf { key: Id, value: Vec<u8> },
    Branch { bit: u8, left: Id, right: Id },
}

pub(super) struct Index {
    directory: PathBuf,
}

impl Index {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn path(&self, id: Id) -> PathBuf {
        let name = hex(&id);
        self.directory.join(&name[..2]).join(format!("{name}.json"))
    }

    fn load(&self, id: Id) -> Result<Node, String> {
        let node: Node = read_bounded(&self.path(id), MAX_NODE_BYTES)?;
        if hash(b"naome:research:index:v2\0", &node) != id {
            return Err("authenticated index node digest mismatch".into());
        }
        Ok(node)
    }

    fn save(&self, node: &Node) -> Result<Id, String> {
        let id = hash(b"naome:research:index:v2\0", node);
        let path = self.path(id);
        let bytes = serde_json::to_vec(node).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_NODE_BYTES {
            return Err("index leaf exceeds record bound".into());
        }
        if path.exists() {
            self.load(id)?;
        } else {
            fs::create_dir_all(path.parent().ok_or("index parent missing")?)
                .map_err(|e| e.to_string())?;
            sync_directory(&self.directory)?;
            atomic_write(&path, &bytes)?;
        }
        Ok(id)
    }

    fn terminal(&self, mut root: Id, key: Id) -> Result<(Id, Vec<u8>), String> {
        let mut previous = None;
        loop {
            match self.load(root)? {
                Node::Leaf { key, value } => return Ok((key, value)),
                Node::Branch { bit, left, right } => {
                    if previous.is_some_and(|p| bit <= p) || left == EMPTY || right == EMPTY {
                        return Err("invalid Patricia index path".into());
                    }
                    previous = Some(bit);
                    root = if key_bit(key, bit) { right } else { left };
                }
            }
        }
    }

    pub fn get<T: DeserializeOwned>(&self, root: Id, key: Id) -> Result<Option<T>, String> {
        if root == EMPTY {
            return Ok(None);
        }
        let (stored, bytes) = self.terminal(root, key)?;
        if stored != key {
            return Ok(None);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| e.to_string())
    }

    /// Copies only the bounded search path; old checkpoint roots remain valid.
    pub fn put<T: Serialize>(&self, root: Id, key: Id, value: &T) -> Result<Id, String> {
        let value = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        let leaf = self.save(&Node::Leaf { key, value })?;
        if root == EMPTY {
            return Ok(leaf);
        }
        let (stored, _) = self.terminal(root, key)?;
        let difference = first_difference(stored, key);
        let mut cursor = root;
        let mut parents = Vec::new();
        let mut previous = None;
        let mut replacement = loop {
            match self.load(cursor)? {
                Node::Branch { bit, left, right } if difference.is_none_or(|d| bit < d) => {
                    if previous.is_some_and(|p| bit <= p) {
                        return Err("invalid index path".into());
                    }
                    previous = Some(bit);
                    let rightward = key_bit(key, bit);
                    parents.push((bit, left, right, rightward));
                    cursor = if rightward { right } else { left };
                }
                _ => {
                    if let Some(bit) = difference {
                        let (left, right) = if key_bit(key, bit) {
                            (cursor, leaf)
                        } else {
                            (leaf, cursor)
                        };
                        break self.save(&Node::Branch { bit, left, right })?;
                    }
                    break leaf;
                }
            }
        };
        for (bit, left, right, rightward) in parents.into_iter().rev() {
            replacement = self.save(&Node::Branch {
                bit,
                left: if rightward { left } else { replacement },
                right: if rightward { replacement } else { right },
            })?;
        }
        Ok(replacement)
    }
}

fn first_difference(left: Id, right: Id) -> Option<u8> {
    left.iter().zip(right).enumerate().find_map(|(i, (l, r))| {
        let difference = l ^ r;
        (difference != 0).then(|| (i * 8 + difference.leading_zeros() as usize) as u8)
    })
}
fn key_bit(key: Id, bit: u8) -> bool {
    key[usize::from(bit) / 8] & (1 << (7 - bit % 8)) != 0
}

pub(super) fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// File contents are durable before the atomic name replacement. The caller
/// owns the directory lock; no provider contact follows a failed write.
pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let parent = path.parent().ok_or("file has no parent")?;
    let temporary = parent.join(format!(".write-{}", hex(&nonce)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|e| e.to_string())?;
    #[cfg(test)]
    if take_write_failure(path, WriteFailure::PartialWrite) {
        file.write_all(&bytes[..bytes.len() / 2])
            .map_err(|e| e.to_string())?;
        return Err("injected partial temporary write".into());
    }
    file.write_all(bytes).map_err(|e| e.to_string())?;
    #[cfg(test)]
    if take_write_failure(path, WriteFailure::FileSync) {
        return Err("injected file sync failure before rename".into());
    }
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    fs::rename(&temporary, path).map_err(|e| e.to_string())?;
    #[cfg(test)]
    if take_write_failure(path, WriteFailure::DirectorySync) {
        return Err("injected directory sync failure after rename".into());
    }
    sync_directory(parent)
}

// Thread-local injection drives the actual atomic write path without altering
// other tests or claiming physical filesystem/power-loss qualification.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WriteFailure {
    PartialWrite,
    FileSync,
    DirectorySync,
}
#[cfg(test)]
thread_local! {
    static WRITE_FAILURE: std::cell::RefCell<Option<(PathBuf, WriteFailure)>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn fail_next_write(path: PathBuf, failure: WriteFailure) {
    WRITE_FAILURE.with(|slot| {
        assert!(slot.borrow().is_none(), "unconsumed write failure");
        *slot.borrow_mut() = Some((path, failure));
    });
}
#[cfg(test)]
fn take_write_failure(path: &Path, failure: WriteFailure) -> bool {
    WRITE_FAILURE.with(|slot| {
        let matches = slot
            .borrow()
            .as_ref()
            .is_some_and(|(target, point)| target == path && *point == failure);
        if matches {
            slot.borrow_mut().take();
        }
        matches
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_index_preserves_old_roots_and_authenticates_bounded_paths() {
        let directory = std::env::temp_dir().join(format!("research-index-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let index = Index::new(directory.clone());
        let mut root = EMPTY;
        let mut keys = vec![[0; 32]];
        for bit in 0..256 {
            let mut key = [0; 32];
            key[bit / 8] = 1 << (7 - bit % 8);
            keys.push(key);
        }
        for (i, key) in keys.iter().enumerate() {
            root = index.put(root, *key, &i).unwrap();
        }
        let old = root;
        root = index.put(root, keys[0], &1000usize).unwrap();
        assert_eq!(index.get::<usize>(old, keys[0]).unwrap(), Some(0));
        assert_eq!(index.get::<usize>(root, keys[0]).unwrap(), Some(1000));
        for (i, key) in keys.iter().enumerate().skip(1) {
            assert_eq!(index.get::<usize>(root, *key).unwrap(), Some(i));
        }
        fs::write(index.path(root), b"{}").unwrap();
        assert!(index.get::<usize>(root, keys[0]).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
