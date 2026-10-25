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
    _lease: Arc<fs::File>,
    label: String,
    mirror: Mutex<Option<Arc<Self>>>,
}
impl IndexStorage {
    pub(crate) fn open(directory: &Path, label: &str) -> Result<Arc<Self>, String> {
        let root = crate::storage::research_directory(directory)?;
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
        Self::fresh(&root, label, Arc::new(lease))
    }
    fn fresh(root: &Path, label: &str, lease: Arc<fs::File>) -> Result<Arc<Self>, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let prefix = format!(".disposable-{label}-");
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
        connection.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; CREATE TABLE nodes(address BLOB PRIMARY KEY CHECK(length(address)=32), payload BLOB NOT NULL) STRICT, WITHOUT ROWID;").map_err(|e|e.to_string())?;
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(|e| e.to_string())?;
        connection
            .pragma_update(None, "user_version", 1)
            .map_err(|e| e.to_string())?;
        crate::storage::sqlite_common(
            &connection,
            crate::resources::active_limits().registry_index_cache_bytes,
        )
        .map_err(|error| error.to_string())?;
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
            label: label.to_owned(),
            mirror: Mutex::new(None),
        }))
    }
    pub(crate) fn directory(&self) -> &Path {
        self.path.parent().expect("index parent")
    }
    pub(crate) fn successor(&self) -> Result<Arc<Self>, String> {
        Self::fresh(
            self.path.parent().ok_or("index directory missing")?,
            &self.label,
            self._lease.clone(),
        )
    }
    pub(crate) fn mirror_to(&self, target: Arc<Self>) -> Result<(), String> {
        let _connection = self
            .connection
            .lock()
            .map_err(|_| "index connection poisoned")?;
        let mut mirror = self.mirror.lock().map_err(|_| "index mirror poisoned")?;
        if mirror.is_some() {
            return Err("index copy already active".into());
        }
        *mirror = Some(target);
        Ok(())
    }
    pub(crate) fn end_mirror(&self, target: &Arc<Self>) {
        let mut mirror = self.mirror.lock().unwrap_or_else(|e| e.into_inner());
        if mirror
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, target))
        {
            *mirror = None;
        }
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize, String> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| "index connection poisoned")?;
        let connection = connection.as_ref().ok_or("index connection closed")?;
        self.live(connection).map_err(|e| e.to_string())?;
        let pages: i64 = connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .map_err(|e| e.to_string())?;
        let size: i64 = connection
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .map_err(|e| e.to_string())?;
        pages
            .checked_mul(size)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or("index allocated size overflow".into())
    }
    pub(crate) fn error(&self) -> Option<String> {
        self.error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn live(&self, connection: &Connection) -> Result<(), ContextError> {
        crate::storage::sqlite_adapt(
            connection,
            crate::resources::active_limits().registry_index_cache_bytes,
        )
        .map_err(sql)?;
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
        let connection_guard = self.connection.lock().map_err(|_| ContextError::Corrupt)?;
        let connection = connection_guard.as_ref().ok_or(ContextError::Corrupt)?;
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
        } else {
            connection
                .execute(
                    "INSERT INTO nodes VALUES(?1,?2)",
                    params![address.as_slice(), bytes],
                )
                .map_err(sql)?;
        }
        let mirror = self
            .mirror
            .lock()
            .map_err(|_| ContextError::Corrupt)?
            .clone();
        if let Some(mirror) = mirror {
            mirror.write(address, bytes)?;
        }
        drop(connection_guard);
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
    let metadata = crate::storage::owned_file(path)?;
    Ok((metadata.dev(), metadata.ino()))
}
fn sql(error: rusqlite::Error) -> ContextError {
    ContextError::Storage(error.to_string())
}

#[cfg(test)]
mod tests;
