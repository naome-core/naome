use super::*;
use rusqlite::{Connection, OpenFlags, params};
use std::{fs::File, os::unix::fs::MetadataExt, path::PathBuf, time::Instant};
fn sql<T>(r: rusqlite::Result<T>) -> Result<T, String> {
    r.map_err(|e| e.to_string())
}
const APPLICATION: i64 = 0x4e415242;

pub(crate) struct Controller {
    directory: PathBuf,
    connection: Connection,
    _lock: File,
    identity: (u64, u64),
    version: i64,
    last: Option<Snapshot>,
    next: Instant,
    governor: Governor,
}
impl Controller {
    pub(crate) fn open(directory: &Path) -> Result<Self, String> {
        let lock_path = directory.join(".resource-history.lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&lock_path)
            .map_err(|e| e.to_string())?;
        crate::storage::owned_file(&lock_path)?;
        lock.try_lock()
            .map_err(|_| "resource history already owned")?;
        let path = directory.join("resource-history.sqlite3");
        if !path.exists() {
            fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(&path)
                .map_err(|e| e.to_string())?;
        }
        let metadata = crate::storage::owned_file(&path)?;
        let connection = sql(Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ))?;
        let app: i64 = sql(connection.pragma_query_value(None, "application_id", |r| r.get(0)))?;
        if app == 0 {
            let tables: i64 =
                sql(connection.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0)))?;
            if tables != 0 {
                return Err("unknown resource history database".into());
            }
            sql(connection.execute_batch("BEGIN IMMEDIATE;CREATE TABLE snapshots(sequence INTEGER PRIMARY KEY, payload BLOB NOT NULL CHECK(length(payload)<=4096)) STRICT;PRAGMA application_id=1312903746;PRAGMA user_version=1;COMMIT;"))?;
        } else if app != APPLICATION {
            return Err("resource history format mismatch".into());
        }
        sql(connection.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;"))?;
        crate::storage::sqlite_common(
            &connection,
            super::super::active_limits().checkpoint_cache_bytes,
        )
        .map_err(|e| e.to_string())?;
        File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        let version = sql(connection.pragma_query_value(None, "data_version", |r| r.get(0)))?;
        let mut owner = Self {
            directory: directory.to_owned(),
            connection,
            _lock: lock,
            identity: (metadata.dev(), metadata.ino()),
            version,
            last: None,
            next: Instant::now(),
            governor: Governor::default(),
        };
        owner.refresh()?;
        Ok(owner)
    }
    pub(crate) fn refresh(&mut self) -> Result<(), String> {
        if Instant::now() < self.next {
            return Ok(());
        }
        let sampled = Instant::now();
        let path = self.directory.join("resource-history.sqlite3");
        let metadata = crate::storage::owned_file(&path)?;
        let version: i64 = sql(self
            .connection
            .pragma_query_value(None, "data_version", |r| r.get(0)))?;
        if (metadata.dev(), metadata.ino()) != self.identity || version != self.version {
            return Err("resource history changed outside owner".into());
        }
        let selection = load(&self.directory)?;
        let (snapshot, valid) = match sample_node(&self.directory) {
            Ok(sample) => (
                self.governor.observe(
                    selection,
                    sample,
                    super::super::limits().memory_bytes as u64,
                )?,
                true,
            ),
            Err(error) => (self.governor.unavailable(selection).ok_or(error)?, false),
        };
        self.governor.sampled(sampled.elapsed());
        let interval = self.governor.interval();
        self.next = Instant::now()
            + if valid {
                interval
            } else {
                interval.min(std::time::Duration::from_secs(1))
            };
        let changed = self.last.as_ref().is_none_or(|last| {
            last.selection != snapshot.selection
                || last.budget != snapshot.budget
                || snapshot.timestamp_ms.saturating_sub(last.timestamp_ms) >= 60_000
        });
        if changed {
            let bytes = serde_json::to_vec(&snapshot).map_err(|e| e.to_string())?;
            sql(self
                .connection
                .execute("INSERT INTO snapshots(payload) VALUES(?1)", params![bytes]))?;
            self.last = Some(snapshot.clone());
        }
        publish(snapshot);
        Ok(())
    }
}
pub fn page(directory: &Path, after: u64) -> Result<Vec<serde_json::Value>, String> {
    let path = directory.join("resource-history.sqlite3");
    if !path.exists() {
        return Ok(Vec::new());
    }
    crate::storage::owned_file(&path)?;
    let path = fs::canonicalize(directory)
        .map_err(|e| e.to_string())?
        .join("resource-history.sqlite3");
    let connection = sql(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ))?;
    let app: i64 = sql(connection.pragma_query_value(None, "application_id", |r| r.get(0)))?;
    if app != APPLICATION {
        return Err("resource history format mismatch".into());
    }
    let mut statement=sql(connection.prepare("SELECT sequence,substr(payload,1,4097) FROM snapshots WHERE sequence>?1 ORDER BY sequence LIMIT ?2"))?;
    let mut rows = sql(statement.query([
        i64::try_from(after).map_err(|e| e.to_string())?,
        super::super::active_limits().status_page as i64,
    ]))?;
    let mut result = Vec::new();
    while let Some(row) = sql(rows.next())? {
        let sequence: i64 = sql(row.get(0))?;
        let bytes: Vec<u8> = sql(row.get(1))?;
        if bytes.len() > 4096 {
            return Err("resource history snapshot capacity".into());
        }
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        result.push(serde_json::json!({"sequence":sequence,"snapshot":snapshot}));
    }
    Ok(result)
}
