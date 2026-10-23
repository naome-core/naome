//! Disposable authenticated bytes for local indexes. Canonical rows are replayed
//! at every startup; this file never restores mathematical validity or authority.
use naome_checker::{ContextError, ContextStorage};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

const APPLICATION_ID: u32 = 0x4e415149;

pub(crate) struct IndexStorage {
    connection: Mutex<Option<Connection>>,
    path: PathBuf,
    identity: (u64, u64),
    version: i64,
    error: Mutex<Option<String>>,
    _lease: fs::File,
}
impl IndexStorage {
    pub(crate) fn open(directory: &Path, label: &str) -> Result<Arc<Self>, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = crate::jobs::research_directory(directory)?;
        let lease_path = root.join(format!(".disposable-{label}.lock"));
        let lease = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&lease_path)
            .map_err(|e| e.to_string())?;
        owned(&lease_path)?;
        lease
            .try_lock()
            .map_err(|_| "local question index is already owned")?;
        let prefix = format!(".disposable-{label}-");
        for entry in fs::read_dir(&root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".sqlite3"))
                && disposable(&entry.path())?
            {
                fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
            }
        }
        let sequence = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| "disposable index sequence exhausted")?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let path = root.join(format!(
            "{prefix}{}-{nonce}-{sequence}.sqlite3",
            std::process::id()
        ));
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&path)
            .map_err(|e| e.to_string())?;
        let path = fs::canonicalize(path).map_err(|e| e.to_string())?;
        let identity = owned(&path)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| e.to_string())?;
        connection.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA trusted_schema=OFF; CREATE TABLE nodes(address BLOB PRIMARY KEY CHECK(length(address)=32), payload BLOB NOT NULL) STRICT, WITHOUT ROWID;").map_err(|e|e.to_string())?;
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(|e| e.to_string())?;
        connection
            .pragma_update(None, "user_version", 1)
            .map_err(|e| e.to_string())?;
        let cache = crate::resources::limits().registry_index_cache_bytes / 1024;
        connection
            .pragma_update(
                None,
                "cache_size",
                -(i64::try_from(cache.max(1)).map_err(|_| "index cache width")?),
            )
            .map_err(|e| e.to_string())?;
        let version = connection
            .pragma_query_value(None, "data_version", |r| r.get(0))
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
            connection: Mutex::new(Some(connection)),
            path,
            identity,
            version,
            error: Mutex::new(None),
            _lease: lease,
        }))
    }
    pub(crate) fn error(&self) -> Option<String> {
        self.error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn live(&self, connection: &Connection) -> Result<(), ContextError> {
        if let Some(error) = self.error() {
            return Err(ContextError::Storage(error));
        }
        if owned(&self.path).map_err(ContextError::Storage)? != self.identity {
            return Err(ContextError::Corrupt);
        }
        let version: i64 = connection
            .pragma_query_value(None, "data_version", |r| r.get(0))
            .map_err(sql)?;
        if version != self.version {
            return Err(ContextError::Corrupt);
        }
        Ok(())
    }
}
impl ContextStorage for IndexStorage {
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        let _memory = crate::resources::MemoryLease::acquire(
            maximum.checked_mul(2).ok_or(ContextError::Limit)?,
        )
        .map_err(|_| ContextError::Limit)?;
        let connection = self.connection.lock().map_err(|_| ContextError::Corrupt)?;
        let connection = connection.as_ref().ok_or(ContextError::Corrupt)?;
        self.live(connection)?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT substr(payload,1,?2) FROM nodes WHERE address=?1",
                params![
                    address.as_slice(),
                    i64::try_from(maximum.checked_add(1).ok_or(ContextError::Limit)?)
                        .map_err(|_| ContextError::Limit)?
                ],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        let bytes = bytes.ok_or(ContextError::Corrupt)?;
        if bytes.len() > maximum {
            return Err(ContextError::Limit);
        }
        Ok(bytes)
    }
    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        let connection = self.connection.lock().map_err(|_| ContextError::Corrupt)?;
        let connection = connection.as_ref().ok_or(ContextError::Corrupt)?;
        self.live(connection)?;
        let existing: Option<Vec<u8>> = connection
            .query_row(
                "SELECT substr(payload,1,?2) FROM nodes WHERE address=?1",
                params![
                    address.as_slice(),
                    i64::try_from(bytes.len() + 1).map_err(|_| ContextError::Limit)?
                ],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        if let Some(existing) = existing {
            if existing != bytes {
                return Err(ContextError::Corrupt);
            }
            return Ok(());
        }
        connection
            .execute(
                "INSERT INTO nodes VALUES(?1,?2)",
                params![address.as_slice(), bytes],
            )
            .map_err(sql)?;
        Ok(())
    }
    fn record_failure(&self, error: &ContextError) {
        if !matches!(error, ContextError::Limit) {
            *self.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
        }
    }
}
impl Drop for IndexStorage {
    fn drop(&mut self) {
        self.connection
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if owned(&self.path).ok() == Some(self.identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
// Read only a fixed SQLite header. An unrelated or incomplete file is left
// untouched and cannot block a fresh uniquely named disposable generation.
fn disposable(path: &Path) -> Result<bool, String> {
    let identity = owned(path)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if (metadata.dev(), metadata.ino()) != identity {
        return Err("disposable index changed before inspection".into());
    }
    let mut header = [0; 100];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error.to_string()),
    }
    let managed = &header[..16] == b"SQLite format 3\0"
        && header[60..64] == 1u32.to_be_bytes()
        && header[68..72] == APPLICATION_ID.to_be_bytes();
    if owned(path)? != identity {
        return Err("disposable index changed during inspection".into());
    }
    Ok(managed)
}

fn owned(path: &Path) -> Result<(u64, u64), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("disposable index must be an owned unaliased file".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}
fn sql(error: rusqlite::Error) -> ContextError {
    ContextError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_prunes_only_marked_generations_and_preserves_unrelated_files() {
        let directory = crate::checkpoint::tests::Directory::new();
        let storage = IndexStorage::open(&directory.0, "questions").unwrap();
        storage.write([1; 32], b"current disposable bytes").unwrap();
        let root = storage.path.parent().unwrap();
        let abandoned = root.join(".disposable-questions-abandoned.sqlite3");
        fs::copy(&storage.path, &abandoned).unwrap();
        let foreign = root.join(".disposable-questions-unrelated.sqlite3");
        let connection = Connection::open(&foreign).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('preserve');",
            )
            .unwrap();
        drop(connection);
        let before = fs::read(&foreign).unwrap();
        let incomplete = root.join(".disposable-questions-incomplete.sqlite3");
        fs::write(&incomplete, b"untouched bytes").unwrap();
        drop(storage);
        let _successor = IndexStorage::open(&directory.0, "questions").unwrap();
        assert!(!abandoned.exists());
        assert_eq!(fs::read(&foreign).unwrap(), before);
        assert_eq!(fs::read(&incomplete).unwrap(), b"untouched bytes");
    }

    #[test]
    fn dropping_a_replaced_index_never_deletes_the_replacement() {
        let directory = crate::checkpoint::tests::Directory::new();
        let storage = IndexStorage::open(&directory.0, "questions").unwrap();
        let path = storage.path.clone();
        let replacement = directory.0.join("replacement");
        fs::write(&replacement, b"unrelated replacement").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(storage.read([1; 32], 4096), Err(ContextError::Corrupt));
        drop(storage);
        assert_eq!(fs::read(&path).unwrap(), b"unrelated replacement");
    }
}
