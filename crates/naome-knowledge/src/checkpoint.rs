//! Transactional local records shared by the job and question owners.
//! Canonical row digests, owned file identity and generation checks preserve
//! fail-closed reads. Only the current explicitly versioned format is accepted.
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[cfg(test)]
thread_local! { static FAIL_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn fail_next_commit() {
    FAIL_COMMIT.with(|value| value.set(true));
}

const APPLICATION_ID: i64 = 0x4e414f4a;
pub(crate) const MAX_ROW: usize = 64 * 1024 * 1024;
pub(crate) const MAX_HEADER: usize = 1024 * 1024;
const SCHEMA: [&str; 2] = [
    "CREATE TABLE checkpoint (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        domain TEXT NOT NULL,
        header BLOB NOT NULL CHECK(length(header) <= 1048576),
        digest BLOB NOT NULL CHECK(length(digest) = 32),
        entry_count INTEGER NOT NULL CHECK(entry_count >= 0)
    ) STRICT",
    "CREATE TABLE entries (
        kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 16),
        key TEXT NOT NULL CHECK(length(key) BETWEEN 1 AND 128),
        payload BLOB NOT NULL CHECK(length(payload) <= 67108864),
        digest BLOB NOT NULL CHECK(length(digest) = 32),
        PRIMARY KEY(kind, key)
    ) STRICT, WITHOUT ROWID",
];

pub(crate) enum Update {
    Put {
        kind: &'static str,
        key: String,
        payload: Vec<u8>,
    },
    Remove {
        kind: &'static str,
        key: String,
    },
}
impl Update {
    pub(crate) fn put(
        kind: &'static str,
        key: impl ToString,
        value: &impl Serialize,
    ) -> Result<Self, String> {
        Ok(Self::Put {
            kind,
            key: key.to_string(),
            payload: encode(value)?,
        })
    }
}

pub(crate) struct Checkpoint {
    path: PathBuf,
    identity: fs::Metadata,
    connection: Connection,
    domain: &'static str,
    data_version: i64,
    #[cfg(test)]
    pub(crate) last_write: (usize, usize),
}

impl Checkpoint {
    pub(crate) fn open(path: &Path, domain: &'static str) -> Result<Self, String> {
        let checkpoint = Self::open_for_replay(path, domain)?;
        checkpoint.scan_all(|_, _, _| Ok(()))?;
        Ok(checkpoint)
    }

    /// Domain replay must consume every primary row and validate its indexed
    /// relationships/cardinality. Avoid a preceding duplicate payload scan.
    pub(crate) fn open_for_replay(path: &Path, domain: &'static str) -> Result<Self, String> {
        let identity = owned(path)?;
        let connection = connect(path)?;
        let application: i64 = connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(sql)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(sql)?;
        if application != APPLICATION_ID || version != 1 {
            return Err("unsupported transactional checkpoint".into());
        }
        let definitions = connection
            .prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")
            .map_err(sql)?
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        if definitions.len() != SCHEMA.len()
            || definitions
                .iter()
                .zip(SCHEMA)
                .any(|(actual, expected)| normalize(actual) != normalize(expected))
        {
            return Err("transactional checkpoint schema differs".into());
        }
        let integrity: String = connection
            .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
            .map_err(sql)?;
        if integrity != "ok" {
            return Err("transactional checkpoint integrity failure".into());
        }
        let data_version = version_of(&connection)?;
        let checkpoint = Self {
            path: path.to_owned(),
            identity,
            connection,
            domain,
            data_version,
            #[cfg(test)]
            last_write: (0, 0),
        };
        let (_, expected) = checkpoint.raw_header()?;
        let observed: i64 = checkpoint
            .connection
            .query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
            .map_err(sql)?;
        if u64::try_from(observed).ok() != Some(expected) {
            return Err("transactional checkpoint row count differs".into());
        }
        Ok(checkpoint)
    }

    /// Publish a new checkpoint before creating the receipt. An empty
    /// interrupted staging transaction may be retried; accepted rows are never
    /// overwritten, and established canonical files are never recreated here.
    pub(crate) fn create(
        path: &Path,
        domain: &'static str,
        header: &impl Serialize,
        updates: Vec<Update>,
    ) -> Result<Self, String> {
        let stage = path.with_extension("initializing");
        if !stage.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(&stage)
                .map_err(|e| e.to_string())?;
        }
        let _ = owned(&stage)?;
        let mut connection = connect(&stage)?;
        let application: i64 = connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(sql)?;
        let stage_version: i64 = connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(sql)?;
        let objects: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE sql IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if application == 0 && stage_version == 0 && objects == 0 {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql)?;
            for definition in SCHEMA {
                transaction.execute_batch(definition).map_err(sql)?;
            }
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(sql)?;
            transaction
                .pragma_update(None, "user_version", 1)
                .map_err(sql)?;
            let payload = encode(header)?;
            if payload.len() > MAX_HEADER {
                return Err("checkpoint header capacity".into());
            }
            transaction
                .execute(
                    "INSERT INTO checkpoint VALUES(1, ?1, ?2, ?3, 0)",
                    params![
                        domain,
                        payload,
                        digest(domain, "header", "1", &payload).as_slice()
                    ],
                )
                .map_err(sql)?;
            apply(&transaction, domain, &updates)?;
            transaction.commit().map_err(sql)?;
        }
        drop(connection);
        // A fully committed stage is reusable after a crash before rename.
        drop(Self::open(&stage, domain)?);
        File::open(&stage)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        if path.exists() {
            return Err("checkpoint publication target already exists".into());
        }
        fs::rename(&stage, path).map_err(|e| e.to_string())?;
        sync_parent(path)?;
        Self::open(path, domain)
    }

    pub(crate) fn directory(&self) -> &Path {
        self.path.parent().expect("canonical checkpoint parent")
    }
    fn ensure_generation(&self) -> Result<(), String> {
        crate::storage::sqlite_adapt(
            &self.connection,
            crate::resources::active_limits().checkpoint_cache_bytes,
        )
        .map_err(sql)?;
        let current = owned(&self.path)?;
        if current.dev() != self.identity.dev() || current.ino() != self.identity.ino() {
            return Err("transactional checkpoint file was replaced".into());
        }
        if version_of(&self.connection)? != self.data_version {
            return Err("transactional checkpoint changed outside its owner".into());
        }
        Ok(())
    }
    fn raw_header(&self) -> Result<(Vec<u8>, u64), String> {
        self.ensure_generation()?;
        let (domain, payload, stored, count): (String, Vec<u8>, Vec<u8>, i64) = self.connection.query_row(
            "SELECT substr(domain,1,129), substr(header,1,1048577), substr(digest,1,33), entry_count FROM checkpoint WHERE singleton = 1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).map_err(sql)?;
        let rows: i64 = self
            .connection
            .query_row("SELECT count(*) FROM checkpoint", [], |r| r.get(0))
            .map_err(sql)?;
        if rows != 1
            || domain != self.domain
            || payload.len() > MAX_HEADER
            || stored.as_slice() != digest(self.domain, "header", "1", &payload)
        {
            return Err("transactional checkpoint header differs".into());
        }
        Ok((
            payload,
            u64::try_from(count).map_err(|_| "checkpoint count width")?,
        ))
    }
    pub(crate) fn header<T: DeserializeOwned + Serialize>(&self) -> Result<T, String> {
        decode(&self.raw_header()?.0)
    }

    pub(crate) fn get<T: DeserializeOwned + Serialize>(
        &self,
        kind: &str,
        key: &str,
        maximum: usize,
    ) -> Result<Option<T>, String> {
        self.ensure_generation()?;
        let maximum = maximum.min(MAX_ROW);
        let row: Option<(Vec<u8>, Vec<u8>)> = self.connection.query_row(
            "SELECT substr(payload,1,?3), substr(digest,1,33) FROM entries WHERE kind = ?1 AND key = ?2",
            params![kind, key, (maximum + 1) as i64], |r| Ok((r.get(0)?, r.get(1)?))).optional().map_err(sql)?;
        row.map(|(payload, stored)| {
            check_row(self.domain, kind, key, &payload, &stored, maximum)?;
            decode(&payload)
        })
        .transpose()
    }

    pub(crate) fn scan(
        &self,
        kind: &str,
        maximum: usize,
        mut visit: impl FnMut(&str, &[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        self.ensure_generation()?;
        let maximum = maximum.min(MAX_ROW);
        let mut statement = self.connection.prepare("SELECT substr(key,1,129), substr(payload,1,?2), substr(digest,1,33) FROM entries WHERE kind = ?1 ORDER BY key").map_err(sql)?;
        let mut rows = statement
            .query(params![kind, (maximum + 1) as i64])
            .map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            let key: String = row.get(0).map_err(sql)?;
            let payload: Vec<u8> = row.get(1).map_err(sql)?;
            let stored: Vec<u8> = row.get(2).map_err(sql)?;
            check_row(self.domain, kind, &key, &payload, &stored, maximum)?;
            visit(&key, &payload)?;
        }
        Ok(())
    }
    /// An opaque key cursor and an actual byte budget bound every materialized
    /// working page. A single oversized record is explicit overload, never EOF.
    pub(crate) fn page(
        &self,
        kind: &str,
        after: Option<&str>,
        records: usize,
        bytes: usize,
    ) -> Result<Vec<(String, Vec<u8>)>, crate::Error> {
        self.ensure_generation()?;
        if records == 0 || bytes == 0 {
            return Err("checkpoint page budget must be positive".into());
        }
        let mut statement=self.connection.prepare("SELECT substr(key,1,129), substr(payload,1,?3), substr(digest,1,33) FROM entries WHERE kind=?1 AND key>?2 ORDER BY key LIMIT ?4").map_err(sql)?;
        let mut rows = statement
            .query(params![
                kind,
                after.unwrap_or(""),
                i64::try_from(bytes.min(MAX_ROW) + 1).map_err(|_| "checkpoint byte width")?,
                i64::try_from(records).map_err(|_| "checkpoint page width")?
            ])
            .map_err(sql)?;
        let mut page = Vec::new();
        let mut retained = 0usize;
        while let Some(row) = rows.next().map_err(sql)? {
            let key: String = row.get(0).map_err(sql)?;
            let payload: Vec<u8> = row.get(1).map_err(sql)?;
            let stored: Vec<u8> = row.get(2).map_err(sql)?;
            check_row(
                self.domain,
                kind,
                &key,
                &payload,
                &stored,
                bytes.min(MAX_ROW),
            )?;
            let needed = key
                .len()
                .checked_add(payload.len())
                .and_then(|n| n.checked_add(128))
                .ok_or("checkpoint page memory overflow")?;
            if needed > bytes.saturating_sub(retained) {
                if page.is_empty() {
                    return Err("checkpoint record exceeds page memory budget".into());
                }
                break;
            }
            retained += needed;
            page.push((key, payload));
        }
        self.ensure_generation()?;
        Ok(page)
    }

    pub(crate) fn count(&self, kind: &str) -> Result<usize, String> {
        self.ensure_generation()?;
        let count: i64 = self
            .connection
            .query_row("SELECT count(*) FROM entries WHERE kind=?1", [kind], |r| {
                r.get(0)
            })
            .map_err(sql)?;
        usize::try_from(count).map_err(|_| "checkpoint count width".into())
    }
    pub(crate) fn get_bytes(
        &self,
        kind: &str,
        key: &str,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, String> {
        self.ensure_generation()?;
        let maximum = maximum.min(MAX_ROW);
        let row:Option<(Vec<u8>,Vec<u8>)>=self.connection.query_row("SELECT substr(payload,1,?3),substr(digest,1,33) FROM entries WHERE kind=?1 AND key=?2",params![kind,key,i64::try_from(maximum+1).map_err(|_|"checkpoint width")?],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(sql)?;
        row.map(|(payload, stored)| {
            check_row(self.domain, kind, key, &payload, &stored, maximum)?;
            Ok(payload)
        })
        .transpose()
    }
    /// Generation-checked access for domain-owned indexed queries. Generic
    /// storage deliberately has no knowledge of proof identities or edges.
    pub(crate) fn query<T>(
        &self,
        read: impl FnOnce(&Connection) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        self.ensure_generation()
            .map_err(crate::Error::CorruptStorage)?;
        let result = read(&self.connection)?;
        self.ensure_generation()
            .map_err(crate::Error::CorruptStorage)?;
        Ok(result)
    }

    fn scan_all(
        &self,
        mut visit: impl FnMut(&str, &str, &[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        self.ensure_generation()?;
        let mut statement = self.connection.prepare("SELECT substr(kind,1,17), substr(key,1,129), substr(payload,1,67108865), substr(digest,1,33) FROM entries ORDER BY kind,key").map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            let kind: String = row.get(0).map_err(sql)?;
            let key: String = row.get(1).map_err(sql)?;
            let payload: Vec<u8> = row.get(2).map_err(sql)?;
            let stored: Vec<u8> = row.get(3).map_err(sql)?;
            check_row(self.domain, &kind, &key, &payload, &stored, MAX_ROW)?;
            visit(&kind, &key, &payload)?;
        }
        Ok(())
    }
    pub(crate) fn require_kinds(&self, kinds: &[&str]) -> Result<(), String> {
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT kind FROM entries")
            .map_err(sql)?;
        let mut rows = statement.query([]).map_err(sql)?;
        while let Some(row) = rows.next().map_err(sql)? {
            let kind: String = row.get(0).map_err(sql)?;
            if !kinds.contains(&kind.as_str()) {
                return Err("unexpected checkpoint record kind".into());
            }
        }
        Ok(())
    }
    pub(crate) fn commit(
        &mut self,
        header: &impl Serialize,
        updates: Vec<Update>,
    ) -> Result<(), String> {
        #[cfg(test)]
        if FAIL_COMMIT.with(|value| value.replace(false)) {
            return Err("injected checkpoint write failure".into());
        }
        self.ensure_generation()?;
        let payload = encode(header)?;
        if payload.len() > MAX_HEADER {
            return Err("checkpoint header capacity".into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if version_of(&transaction)? != self.data_version {
            return Err("transactional checkpoint changed outside its owner".into());
        }
        apply(&transaction, self.domain, &updates)?;
        transaction
            .execute(
                "UPDATE checkpoint SET header = ?1, digest = ?2 WHERE singleton = 1",
                params![
                    payload,
                    digest(self.domain, "header", "1", &payload).as_slice()
                ],
            )
            .map_err(sql)?;
        transaction.commit().map_err(sql)?;
        #[cfg(test)]
        {
            self.last_write = (
                updates.len() + 1,
                payload.len()
                    + updates
                        .iter()
                        .map(|u| match u {
                            Update::Put { payload, .. } => payload.len(),
                            _ => 0,
                        })
                        .sum::<usize>(),
            );
        }
        Ok(())
    }
}

fn apply(connection: &Connection, domain: &str, updates: &[Update]) -> Result<(), String> {
    for update in updates {
        match update {
            Update::Put { kind, key, payload } => {
                if kind.is_empty()
                    || kind.len() > 16
                    || key.is_empty()
                    || key.len() > 128
                    || payload.len() > MAX_ROW
                {
                    return Err("checkpoint record capacity".into());
                }
                let existing: bool = connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM entries WHERE kind = ?1 AND key = ?2)",
                        params![kind, key],
                        |r| r.get(0),
                    )
                    .map_err(sql)?;
                connection.execute("INSERT INTO entries(kind,key,payload,digest) VALUES(?1,?2,?3,?4) ON CONFLICT(kind,key) DO UPDATE SET payload=excluded.payload,digest=excluded.digest",
                    params![kind, key, payload, digest(domain, kind, key, payload).as_slice()]).map_err(sql)?;
                if !existing {
                    connection.execute("UPDATE checkpoint SET entry_count = entry_count + 1 WHERE singleton = 1", []).map_err(sql)?;
                }
            }
            Update::Remove { kind, key } => {
                let removed = connection
                    .execute(
                        "DELETE FROM entries WHERE kind = ?1 AND key = ?2",
                        params![kind, key],
                    )
                    .map_err(sql)?;
                connection
                    .execute(
                        "UPDATE checkpoint SET entry_count = entry_count - ?1 WHERE singleton = 1",
                        params![i64::try_from(removed).map_err(|_| "checkpoint removal width")?],
                    )
                    .map_err(sql)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}
pub(crate) fn decode<T: DeserializeOwned + Serialize>(payload: &[u8]) -> Result<T, String> {
    let value: T = serde_json::from_slice(payload)
        .map_err(|e| format!("checkpoint record corruption: {e}"))?;
    if encode(&value)? != payload {
        return Err("noncanonical checkpoint record".into());
    }
    Ok(value)
}
fn check_row(
    domain: &str,
    kind: &str,
    key: &str,
    payload: &[u8],
    stored: &[u8],
    maximum: usize,
) -> Result<(), String> {
    if kind.is_empty()
        || kind.len() > 16
        || key.is_empty()
        || key.len() > 128
        || payload.len() > maximum
        || stored != digest(domain, kind, key, payload)
    {
        return Err("checkpoint record digest or capacity differs".into());
    }
    Ok(())
}
fn digest(domain: &str, kind: &str, key: &str, payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:checkpoint:row:v1\0");
    for bytes in [domain.as_bytes(), kind.as_bytes(), key.as_bytes(), payload] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}
fn connect(path: &Path) -> Result<Connection, String> {
    let parent = fs::canonicalize(path.parent().ok_or("checkpoint parent missing")?)
        .map_err(|e| e.to_string())?;
    let path = parent.join(path.file_name().ok_or("checkpoint filename missing")?);
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql)?;
    crate::storage::sqlite_common(
        &connection,
        crate::resources::active_limits().checkpoint_cache_bytes,
    )
    .map_err(sql)?;
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;")
        .map_err(sql)?;
    #[cfg(target_os = "macos")]
    connection
        .pragma_update(None, "fullfsync", true)
        .map_err(sql)?;
    Ok(connection)
}
fn owned(path: &Path) -> Result<fs::Metadata, String> {
    crate::storage::owned_file(path)
}
fn version_of(connection: &Connection) -> Result<i64, String> {
    connection
        .pragma_query_value(None, "data_version", |r| r.get(0))
        .map_err(sql)
}
fn normalize(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
fn sync_parent(path: &Path) -> Result<(), String> {
    File::open(path.parent().ok_or("checkpoint parent missing")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
fn sql(error: rusqlite::Error) -> String {
    format!("transactional checkpoint: {error}")
}

#[cfg(test)]
pub(crate) mod tests;
