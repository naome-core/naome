//! Exclusive local custody of a bounded-record, fully replayed SQLite journal.
use crate::{Error, Genesis, MAX_RECORD_BYTES, NetworkId, SignedTransaction, State, TransactionId};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const DATABASE: &str = "ledger.sqlite3";
const PENDING: &str = ".ledger-incoming.sqlite3";
const RECEIPT: &str = "ledger.json";
const APPLICATION: i64 = 0x4e414f4c;
const META: &str = "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), genesis BLOB NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), committed_count INTEGER NOT NULL CHECK(committed_count>=0), head BLOB NOT NULL CHECK(length(head)=32)) STRICT";
const EVENTS: &str = "CREATE TABLE events (sequence INTEGER PRIMARY KEY CHECK(sequence>0), id BLOB NOT NULL UNIQUE CHECK(length(id)=32), payload BLOB NOT NULL) STRICT";

struct DirectoryLock(File);
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u8,
    network: NetworkId,
}

/// An exclusive local ledger. Open rechecks every recorded signature and transition.
///
/// Separate nodes may use the same directory serially. This is not replication
/// or distributed consensus. Filesystem custody belongs to the local account.
pub struct Ledger {
    connection: Connection,
    state: State,
    poisoned: bool,
    database: PathBuf,
    generation: (u64, u64),
    _lock: DirectoryLock,
}
impl Ledger {
    /// Initializes the selected network's canonical genesis; never resets an established ledger.
    pub fn create(directory: &Path, genesis: &Genesis) -> Result<Self, Error> {
        let bytes = record(genesis)?;
        let _ = State::new(genesis)?;
        let (directory, lock) = lock_directory(directory, true)?;
        let database = directory.join(DATABASE);
        let pending = directory.join(PENDING);
        let receipt = directory.join(RECEIPT);
        if receipt.try_exists()? {
            return Err(Error::Invalid(
                "ledger already initialized; open it instead",
            ));
        }
        if !database.try_exists()? {
            if !pending.try_exists()? {
                let file = new_file(&pending)?;
                file.sync_all()?;
                let mut connection = connect(&pending)?;
                let transaction = connection.transaction()?;
                transaction.execute_batch(META)?;
                transaction.execute_batch(EVENTS)?;
                transaction.pragma_update(None, "application_id", APPLICATION)?;
                transaction.pragma_update(None, "user_version", 1)?;
                transaction.execute(
                    "INSERT INTO metadata VALUES (1,?1,0,0,?2)",
                    params![bytes, genesis.network()?.as_bytes().as_slice()],
                )?;
                transaction.commit()?;
                drop(connection);
                File::open(&pending)?.sync_all()?;
            }
            let connection = connect(&pending)?;
            let (stored, active, count, _) = metadata(&connection)?;
            if active || count != 0 || stored != *genesis {
                return Err(Error::Invalid("incomplete ledger has a different genesis"));
            }
            drop(connection);
            fs::rename(&pending, &database)?;
            sync(&directory)?;
        }
        let connection = connect(&database)?;
        let (stored, active, count, _) = metadata(&connection)?;
        if active || count != 0 || stored != *genesis {
            return Err(Error::Invalid("existing ledger cannot be recreated"));
        }
        Self::load(directory, connection, lock, genesis.network()?)
    }
    /// Opens existing state without creating a missing ledger or issuing new coins.
    pub fn open(directory: &Path, expected_network: NetworkId) -> Result<Self, Error> {
        let (directory, lock) = lock_directory(directory, false)?;
        if !directory.join(DATABASE).try_exists()? {
            return Err(Error::Invalid(
                "ledger database is missing; restore its backup",
            ));
        }
        let connection = connect(&directory.join(DATABASE))?;
        Self::load(directory, connection, lock, expected_network)
    }
    fn load(
        directory: PathBuf,
        mut connection: Connection,
        lock: DirectoryLock,
        expected_network: NetworkId,
    ) -> Result<Self, Error> {
        let (genesis, active, count, head) = metadata(&connection)?;
        let mut state = State::new(&genesis)?;
        let network = state.network();
        if network != expected_network {
            return Err(Error::WrongNetwork);
        }
        let mut statement=connection.prepare("SELECT sequence,id,length(payload),CASE WHEN length(payload)<=?1 THEN payload END FROM events ORDER BY sequence")?;
        let mut rows = statement.query([MAX_RECORD_BYTES as i64])?;
        while let Some(row) = rows.next()? {
            let sequence: i64 = row.get(0)?;
            if sequence
                != i64::try_from(state.transaction_count() + 1).map_err(|_| Error::Capacity)?
            {
                return Err(Error::Invalid("ledger journal sequence gap"));
            }
            let id: Vec<u8> = row.get(1)?;
            let length: i64 = row.get(2)?;
            if length < 0 || length > MAX_RECORD_BYTES as i64 {
                return Err(Error::Capacity);
            }
            let bytes: Vec<u8> = row.get(3)?;
            let transaction: SignedTransaction = serde_json::from_slice(&bytes)?;
            if record(&transaction)? != bytes {
                return Err(Error::Invalid("noncanonical ledger record"));
            }
            let verified = state.apply(&transaction)?;
            if id.as_slice() != verified.as_bytes() {
                return Err(Error::Invalid("ledger transaction identity mismatch"));
            }
        }
        drop(rows);
        drop(statement);
        if state.transaction_count() != count || state.journal_root().as_slice() != head {
            return Err(Error::Invalid("ledger committed journal mismatch"));
        }
        let receipt = directory.join(RECEIPT);
        if receipt.try_exists()? {
            let bytes = read_file(&receipt, 256)?;
            let stored: Receipt = serde_json::from_slice(&bytes)?;
            if stored.version != 1 || stored.network != network {
                return Err(Error::Invalid("ledger identity receipt mismatch"));
            }
        } else {
            if active || count != 0 {
                return Err(Error::Invalid(
                    "established ledger identity receipt is missing",
                ));
            }
            write_new(
                &receipt,
                &record(&Receipt {
                    version: 1,
                    network,
                })?,
            )?;
            sync(&directory)?;
        }
        if !active {
            if count != 0 {
                return Err(Error::Invalid("inactive ledger contains transactions"));
            }
            let transaction = connection.transaction()?;
            transaction.execute("UPDATE metadata SET active=1 WHERE singleton=1", [])?;
            transaction.commit()?;
        }
        let database = directory.join(DATABASE);
        let metadata = fs::symlink_metadata(&database)?;
        owned(&metadata)?;
        Ok(Self {
            connection,
            state,
            poisoned: false,
            database,
            generation: (metadata.dev(), metadata.ino()),
            _lock: lock,
        })
    }
    /// Returns checked state, unless the last disk commit has an uncertain result.
    pub fn state(&self) -> Result<&State, Error> {
        if self.poisoned {
            return Err(Error::RecoveryRequired);
        }
        let metadata = fs::symlink_metadata(&self.database)?;
        owned(&metadata)?;
        if (metadata.dev(), metadata.ino()) != self.generation {
            return Err(Error::Invalid(
                "ledger database was replaced; reopen before use",
            ));
        }
        Ok(&self.state)
    }
    /// Atomically records a validated operation before exposing its resulting state.
    pub fn submit(&mut self, transaction: &SignedTransaction) -> Result<TransactionId, Error> {
        self.submit_at(transaction, |_| Ok(()))
    }
    fn submit_at(
        &mut self,
        transaction: &SignedTransaction,
        mut checkpoint: impl FnMut(u8) -> Result<(), Error>,
    ) -> Result<TransactionId, Error> {
        let checked = self.state()?.validate(transaction)?;
        let bytes = record(transaction)?;
        let next =
            i64::try_from(self.state.transaction_count() + 1).map_err(|_| Error::Capacity)?;
        let id = checked.id;
        let sql = self.connection.transaction()?;
        sql.execute(
            "INSERT INTO events VALUES (?1,?2,?3)",
            params![next, id.as_bytes().as_slice(), bytes],
        )?;
        sql.execute(
            "UPDATE metadata SET committed_count=?1,head=?2 WHERE singleton=1",
            params![next, self.state.next_journal_root(id).as_slice()],
        )?;
        checkpoint(1)?;
        if sql.commit().is_err() {
            self.poisoned = true;
            return Err(Error::RecoveryRequired);
        }
        if checkpoint(2).is_err() {
            self.poisoned = true;
            return Err(Error::RecoveryRequired);
        }
        self.state.commit(checked);
        Ok(id)
    }
}

fn metadata(connection: &Connection) -> Result<(Genesis, bool, u64, Vec<u8>), Error> {
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application != APPLICATION || version != 1 {
        return Err(Error::Invalid("unsupported ledger database format"));
    }
    let integrity: String = connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    if integrity != "ok" {
        return Err(Error::Invalid("ledger integrity check failed"));
    }
    let mut statement = connection
        .prepare("SELECT sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let schema = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if schema != [EVENTS.to_string(), META.to_string()] {
        return Err(Error::Invalid("ledger schema mismatch"));
    }
    let rows: i64 = connection.query_row("SELECT count(*) FROM metadata", [], |row| row.get(0))?;
    if rows != 1 {
        return Err(Error::Invalid("ledger metadata row count"));
    }
    let (length,bytes,active,count,head):(i64,Option<Vec<u8>>,i64,i64,Vec<u8>)=connection.query_row("SELECT length(genesis),CASE WHEN length(genesis)<=?1 THEN genesis END,active,committed_count,head FROM metadata WHERE singleton=1",[MAX_RECORD_BYTES as i64],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
    if length < 0
        || length > MAX_RECORD_BYTES as i64
        || count < 0
        || ![0, 1].contains(&active)
        || head.len() != 32
    {
        return Err(Error::Invalid("invalid ledger metadata"));
    }
    let bytes = bytes.ok_or(Error::Capacity)?;
    let genesis: Genesis = serde_json::from_slice(&bytes)?;
    if record(&genesis)? != bytes {
        return Err(Error::Invalid("noncanonical genesis record"));
    }
    Ok((genesis, active == 1, count as u64, head))
}
fn record(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Capacity);
    }
    Ok(bytes)
}
fn connect(path: &Path) -> Result<Connection, Error> {
    owned(&fs::symlink_metadata(path)?)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; PRAGMA locking_mode=EXCLUSIVE; PRAGMA trusted_schema=OFF; PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA cache_size=-1024;")?;
    connection.busy_timeout(std::time::Duration::ZERO)?;
    // Keep SQLite's own exclusion for this owner's lifetime. External SQL
    // writers must not change the journal behind the checked in-memory state.
    connection.execute_batch("BEGIN EXCLUSIVE; COMMIT;")?;
    Ok(connection)
}
fn lock_directory(directory: &Path, create: bool) -> Result<(PathBuf, DirectoryLock), Error> {
    if create {
        fs::create_dir_all(directory)?;
    }
    let directory = fs::canonicalize(directory)?;
    let metadata = fs::metadata(&directory)?;
    if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(Error::Invalid("ledger requires an owned directory"));
    }
    if create
        && fs::read_dir(&directory)?.any(|entry| {
            entry.map_or(true, |entry| {
                ![
                    DATABASE,
                    PENDING,
                    RECEIPT,
                    "ledger.lock",
                    "ledger.sqlite3-journal",
                    ".ledger-incoming.sqlite3-journal",
                ]
                .contains(&entry.file_name().to_string_lossy().as_ref())
            })
        })
    {
        return Err(Error::Invalid("ledger requires a dedicated directory"));
    }
    if create {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    if fs::metadata(&directory)?.permissions().mode() & 0o077 != 0 {
        return Err(Error::Invalid("ledger directory must be owner-only"));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(directory.join("ledger.lock"))?;
    owned(&file.metadata()?)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Busy),
        Err(error) => return Err(Error::Storage(error.to_string())),
    }
    Ok((directory, DirectoryLock(file)))
}
fn owned(metadata: &fs::Metadata) -> Result<(), Error> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(Error::Invalid(
            "ledger requires one owner-only regular file",
        ));
    }
    Ok(())
}
fn new_file(path: &Path) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn read_file(path: &Path, maximum: usize) -> Result<Vec<u8>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)?;
    owned(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(Error::Capacity);
    }
    Ok(bytes)
}
fn sync(directory: &Path) -> Result<(), Error> {
    Ok(File::open(directory)?.sync_all()?)
}

#[cfg(test)]
mod tests;
