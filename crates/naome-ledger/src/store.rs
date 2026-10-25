//! Exclusive local custody of a bounded-record, fully replayed SQLite journal.
use crate::{
    Control, Error, Genesis, Limits, MAX_RECORD_BYTES, NetworkId, SignedTransaction, State,
    TransactionId,
};
use naome_storage::CommitError;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
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
const PENDING_RECEIPT: &str = ".ledger-identity-incoming";
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
    generation: Generation,
    directory: PathBuf,
    _lock: DirectoryLock,
}
impl Ledger {
    /// Initializes the selected network's canonical genesis; never resets an established ledger.
    pub fn create(directory: &Path, genesis: &Genesis) -> Result<Self, Error> {
        Self::create_with_limits(directory, genesis, Limits::default(), &Control::default())
    }
    /// Initializes with host-supplied state/cache budgets and operation control.
    pub fn create_with_limits(
        directory: &Path,
        genesis: &Genesis,
        limits: Limits,
        control: &Control,
    ) -> Result<Self, Error> {
        control.check()?;
        let limits = limits.validate()?;
        let bytes = record(genesis)?;
        let _ = State::with_budget(genesis, limits.state_bytes)?;
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
                new_file(&pending)?.sync_all()?;
            }
            let mut connection = connect_with_limits(&pending, limits)?;
            install_control(&connection, control)?;
            let application: i64 =
                connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
            let version: i64 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            let objects: i64 = connection.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE sql IS NOT NULL",
                [],
                |row| row.get(0),
            )?;
            if application == 0 && version == 0 && objects == 0 {
                naome_storage::write(
                    &mut connection,
                    TransactionBehavior::Immediate,
                    Error::from,
                    |transaction| {
                        transaction.execute_batch(META)?;
                        transaction.execute_batch(EVENTS)?;
                        transaction.pragma_update(None, "application_id", APPLICATION)?;
                        transaction.pragma_update(None, "user_version", 1)?;
                        transaction.execute(
                            "INSERT INTO metadata VALUES (1,?1,0,0,?2)",
                            params![bytes, genesis.network()?.as_bytes().as_slice()],
                        )?;
                        control.check()
                    },
                )
                .map_err(commit_error)?;
                File::open(&pending)?.sync_all()?;
            }
            let (stored, active, count, _) = metadata(&connection)?;
            if active || count != 0 || stored != *genesis {
                return Err(Error::Invalid("incomplete ledger has a different genesis"));
            }
            drop(connection);
            fs::rename(&pending, &database)?;
            sync(&directory)?;
        }
        let connection = connect_with_limits(&database, limits)?;
        install_control(&connection, control)?;
        let (stored, active, count, _) = metadata(&connection)?;
        if active || count != 0 || stored != *genesis {
            return Err(Error::Invalid("existing ledger cannot be recreated"));
        }
        Self::load(
            directory,
            connection,
            lock,
            genesis.network()?,
            limits,
            control,
        )
    }
    /// Opens existing state without creating a missing ledger or issuing new coins.
    pub fn open(directory: &Path, expected_network: NetworkId) -> Result<Self, Error> {
        Self::open_with_limits(
            directory,
            expected_network,
            Limits::default(),
            &Control::default(),
        )
    }
    /// Replays within explicit host budgets. Cancellation/deadlines never mark history invalid.
    pub fn open_with_limits(
        directory: &Path,
        expected_network: NetworkId,
        limits: Limits,
        control: &Control,
    ) -> Result<Self, Error> {
        control.check()?;
        let limits = limits.validate()?;
        let (directory, lock) = lock_directory(directory, false)?;
        if !directory.join(DATABASE).try_exists()? {
            return Err(Error::Invalid(
                "ledger database is missing; restore its backup",
            ));
        }
        let connection = connect_with_limits(&directory.join(DATABASE), limits)?;
        Self::load(
            directory,
            connection,
            lock,
            expected_network,
            limits,
            control,
        )
    }
    fn load(
        directory: PathBuf,
        mut connection: Connection,
        lock: DirectoryLock,
        expected_network: NetworkId,
        limits: Limits,
        control: &Control,
    ) -> Result<Self, Error> {
        install_control(&connection, control)?;
        let (genesis, active, count, head) =
            metadata(&connection).map_err(|error| controlled(error, control))?;
        let mut state = State::with_budget(&genesis, limits.state_bytes)?;
        let network = state.network();
        if network != expected_network {
            return Err(Error::WrongNetwork);
        }
        let mut statement=connection.prepare("SELECT sequence,id,length(payload),CASE WHEN length(payload)<=?1 THEN payload END FROM events ORDER BY sequence")?;
        let mut rows = statement.query([MAX_RECORD_BYTES as i64])?;
        while let Some(row) = rows
            .next()
            .map_err(|error| controlled(error.into(), control))?
        {
            #[cfg(test)]
            tests::replayed(control);
            control.check()?;
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
            let pending = directory.join(PENDING_RECEIPT);
            if pending.try_exists()? {
                read_file(&pending, 256)?;
                fs::remove_file(&pending)?;
            }
            write_new(
                &pending,
                &record(&Receipt {
                    version: 1,
                    network,
                })?,
            )?;
            fs::rename(&pending, &receipt)?;
            sync(&directory)?;
        }
        if !active {
            if count != 0 {
                return Err(Error::Invalid("inactive ledger contains transactions"));
            }
            naome_storage::write(
                &mut connection,
                TransactionBehavior::Immediate,
                Error::from,
                |transaction| {
                    transaction.execute("UPDATE metadata SET active=1 WHERE singleton=1", [])?;
                    control.check()
                },
            )
            .map_err(commit_error)?;
        }
        let database = directory.join(DATABASE);
        let metadata = fs::symlink_metadata(&database)?;
        owned(&metadata)?;
        control.check()?;
        connection.progress_handler(0, None::<fn() -> bool>)?;
        Ok(Self {
            connection,
            state,
            poisoned: false,
            database,
            generation: Generation::of(&metadata),
            directory,
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
        if Generation::of(&metadata) != self.generation {
            return Err(Error::Invalid(
                "ledger database was replaced; reopen before use",
            ));
        }
        Ok(&self.state)
    }
    /// Canonical local session directory, used to bind wallet associations.
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    /// Looks up an admitted transaction in this session's fully verified journal.
    pub fn transaction(&self, id: TransactionId) -> Result<Option<SignedTransaction>, Error> {
        self.state()?;
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT payload FROM events WHERE id=?1",
                [id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Error::from))
            .transpose()
    }
    /// Atomically records a validated operation before exposing its resulting state.
    /// Repeating an already admitted signed transaction returns its ID without a second effect.
    pub fn submit(&mut self, transaction: &SignedTransaction) -> Result<TransactionId, Error> {
        self.submit_with_control(transaction, &Control::default())
    }
    pub fn submit_with_control(
        &mut self,
        transaction: &SignedTransaction,
        control: &Control,
    ) -> Result<TransactionId, Error> {
        self.submit_controlled(transaction, control, |_| Ok(()))
    }
    #[cfg(test)]
    fn submit_at(
        &mut self,
        transaction: &SignedTransaction,
        checkpoint: impl FnMut(u8) -> Result<(), Error>,
    ) -> Result<TransactionId, Error> {
        self.submit_controlled(transaction, &Control::default(), checkpoint)
    }
    fn submit_controlled(
        &mut self,
        transaction: &SignedTransaction,
        control: &Control,
        checkpoint: impl FnMut(u8) -> Result<(), Error>,
    ) -> Result<TransactionId, Error> {
        control.check()?;
        self.state()?;
        install_control(&self.connection, control)?;
        let result = self.submit_inner(transaction, control, checkpoint);
        if self
            .connection
            .progress_handler(0, None::<fn() -> bool>)
            .is_err()
        {
            self.poisoned = true;
            return Err(Error::RecoveryRequired);
        }
        result.map_err(|error| controlled(error, control))
    }
    fn submit_inner(
        &mut self,
        transaction: &SignedTransaction,
        control: &Control,
        mut checkpoint: impl FnMut(u8) -> Result<(), Error>,
    ) -> Result<TransactionId, Error> {
        if transaction.network != self.state.network() {
            return Err(Error::WrongNetwork);
        }
        let id = transaction.verify_signature()?;
        if self.transaction(id)?.is_some() {
            return Ok(id);
        }
        let checked = self.state()?.validate_verified(transaction, id)?;
        let bytes = record(transaction)?;
        let next =
            i64::try_from(self.state.transaction_count() + 1).map_err(|_| Error::Capacity)?;
        let id = checked.id;
        let root = self.state.next_journal_root(id);
        let result = naome_storage::write(
            &mut self.connection,
            TransactionBehavior::Immediate,
            Error::from,
            |sql| {
                sql.execute(
                    "INSERT INTO events VALUES (?1,?2,?3)",
                    params![next, id.as_bytes().as_slice(), bytes],
                )?;
                sql.execute(
                    "UPDATE metadata SET committed_count=?1,head=?2 WHERE singleton=1",
                    params![next, root.as_slice()],
                )?;
                checkpoint(1)?;
                control.check()
            },
        );
        match result {
            Ok(()) => {}
            Err(CommitError::Uncertain(_)) => {
                self.poisoned = true;
                return Err(Error::RecoveryRequired);
            }
            Err(error) => {
                self.refresh_generation()?;
                return Err(commit_error(error));
            }
        }
        if checkpoint(2).is_err() {
            self.poisoned = true;
            return Err(Error::RecoveryRequired);
        }
        self.refresh_generation()?;
        self.state.commit(checked);
        Ok(id)
    }
    fn refresh_generation(&mut self) -> Result<(), Error> {
        let metadata = match fs::symlink_metadata(&self.database) {
            Ok(metadata) => metadata,
            Err(_) => {
                self.poisoned = true;
                return Err(Error::RecoveryRequired);
            }
        };
        if owned(&metadata).is_err()
            || (metadata.dev(), metadata.ino()) != (self.generation.device, self.generation.inode)
        {
            self.poisoned = true;
            return Err(Error::RecoveryRequired);
        }
        self.generation = Generation::of(&metadata);
        Ok(())
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
#[cfg(test)]
fn connect(path: &Path) -> Result<Connection, Error> {
    connect_with_limits(path, Limits::default())
}
fn connect_with_limits(path: &Path, limits: Limits) -> Result<Connection, Error> {
    owned(&fs::symlink_metadata(path)?)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; PRAGMA locking_mode=EXCLUSIVE; PRAGMA trusted_schema=OFF; PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA cache_size=-1024;")?;
    connection.pragma_update(
        None,
        "cache_size",
        -i64::try_from(limits.sqlite_cache_bytes / 1024).map_err(|_| Error::Capacity)?,
    )?;
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
                    PENDING_RECEIPT,
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

fn install_control(connection: &Connection, control: &Control) -> Result<(), Error> {
    let control = control.clone();
    connection.progress_handler(1000, Some(move || control.check().is_err()))?;
    Ok(())
}
fn controlled(error: Error, control: &Control) -> Error {
    match error {
        Error::Storage(_) => control.check().err().unwrap_or(error),
        other => other,
    }
}
fn commit_error(error: CommitError<Error>) -> Error {
    match error {
        CommitError::NotWritten(error) | CommitError::RolledBack(error) => error,
        CommitError::Uncertain(_) => Error::RecoveryRequired,
    }
}
#[derive(PartialEq, Eq)]
struct Generation {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Generation {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}
#[cfg(test)]
mod tests;
