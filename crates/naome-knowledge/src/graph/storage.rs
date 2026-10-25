//! Disposable bytes for the checker's authenticated immutable context.
//! Startup always rebuilds empty checked roots by mathematical corpus replay.

use crate::store::Store;
use naome_checker::{ContextError, ContextStorage, DiskArtifactState};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
mod admission;
mod codec;
mod startup;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

#[cfg(test)]
thread_local! { static SQL_INSERTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(super) fn sql_inserts() -> usize {
    SQL_INSERTS.with(std::cell::Cell::get)
}

const CACHE_ENTRY_BYTES: usize = 512;
const PREFIX: &str = ".checked-context-";
const SUFFIX: &str = ".sqlite3";
static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    // One-shot, per-thread scheduling only. The production write path has no
    // hook, and a mirrored target write cannot consume the pause twice.
    static WRITE_TEST_PAUSE: std::cell::RefCell<Option<Arc<std::sync::Barrier>>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
thread_local! {
    static WRITE_TEST_DELAY:std::cell::RefCell<Option<(std::sync::mpsc::Sender<()>,std::sync::mpsc::Receiver<()>)>>=const{std::cell::RefCell::new(None)};
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryState {
    Persisted(u64),
    Buffered,
    Reachable,
}
struct CacheEntry {
    bytes: Vec<u8>,
    state: EntryState,
    clock: u64,
}
#[derive(Default)]
struct Cache {
    closed: bool,
    entries: BTreeMap<[u8; 32], CacheEntry>,
    recency: BTreeMap<u64, [u8; 32]>,
    charged: usize,
    clock: u64,
    buffering: Option<u64>,
    pending: BTreeSet<[u8; 32]>,
}
struct Owner {
    lease: Arc<Store>,
    cleanup_directory: bool,
}
/// Every generation shares one byte-accounted cache and canonical directory
/// lease. Old question/batch clones keep their generation's bytes available.
pub(super) struct CheckedStorage {
    live_cache_budget: AtomicUsize,
    connection: Mutex<IndexConnection>,
    write_gate: Mutex<WriteRoute>,
    write_ready: Condvar,
    generation: u64,
    cache: Arc<Mutex<Cache>>,
    path: PathBuf,
    owner: Arc<Owner>,
    halt: Arc<Mutex<Option<String>>>,
}

// A fatal disposable-index phase can close its connection while snapshots
// retain the generation. Every production SQL access checks this slot.
struct IndexConnection(Option<Connection>, Option<String>);
impl IndexConnection {
    fn open(&self) -> Result<&Connection, String> {
        if let Some(error) = &self.1 {
            return Err(format!("checked index close unresolved: {error}"));
        }
        self.0
            .as_ref()
            .ok_or_else(|| "checked index connection closed".into())
    }
}
/// The one source-generation write boundary. Every successful immutable write
/// includes the current mirror, even when its local cache or SQL row existed.
#[derive(Default)]
pub(super) struct WriteRoute {
    epoch: u64,
    phase_owner: Option<std::thread::ThreadId>,
    mirror: Option<Arc<CheckedStorage>>,
}

impl WriteRoute {
    pub(super) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(super) fn attach(
        &mut self,
        source: &CheckedStorage,
        target: Arc<CheckedStorage>,
    ) -> Result<u64, String> {
        if self.mirror.is_some() || std::ptr::eq(source, target.as_ref()) {
            return Err("checked copy mirror already attached or cyclic".into());
        }
        if target.write_gate()?.mirror.is_some() {
            return Err("checked copy target already mirrors another generation".into());
        }
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or("checked copy epoch overflow")?;
        self.epoch = epoch;
        self.mirror = Some(target);
        Ok(epoch)
    }

    pub(super) fn matches(&self, epoch: u64, target: &Arc<CheckedStorage>) -> bool {
        self.epoch == epoch
            && self
                .mirror
                .as_ref()
                .is_some_and(|mirror| Arc::ptr_eq(mirror, target))
    }

    pub(super) fn detach(
        &mut self,
        epoch: u64,
        target: &Arc<CheckedStorage>,
    ) -> Result<(), String> {
        if !self.matches(epoch, target) {
            return Err("checked copy source epoch or target changed".into());
        }
        self.mirror = None;
        Ok(())
    }
}

impl CheckedStorage {
    pub(super) fn adapt_cache(&self) -> Result<(), String> {
        let budget = crate::resources::adaptive::cache(usize::MAX);
        if self.live_cache_budget.load(Ordering::Acquire) == budget {
            return Ok(());
        }
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| "checked cache lock poisoned")?;
            let limit =
                crate::resources::adaptive::cache(crate::resources::limits().checked_cache_bytes);
            cache.trim(limit);
            if cache.charged > limit {
                self.flush_buffered(&mut cache, false)
                    .map_err(|e| e.to_string())?;
                cache.trim(limit);
            }
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| "checked index lock poisoned")?;
        connection
            .open()?
            .pragma_update(
                None,
                "cache_size",
                -i64::try_from(
                    (crate::resources::adaptive::cache(
                        crate::resources::limits().checked_index_cache_bytes,
                    ) / 1024)
                        .max(1),
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        self.live_cache_budget.store(budget, Ordering::Release);
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn delay_next_write(
        started: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        WRITE_TEST_DELAY.with(|slot| *slot.borrow_mut() = Some((started, release)));
    }

    pub(super) fn write_gate(&self) -> Result<MutexGuard<'_, WriteRoute>, String> {
        let mut route = self
            .write_gate
            .lock()
            .map_err(|_| "checked write gate poisoned")?;
        let owner = std::thread::current().id();
        while route.phase_owner.is_some_and(|active| active != owner) {
            self.require_live()?;
            route = self
                .write_ready
                .wait(route)
                .map_err(|_| "checked write gate poisoned")?;
        }
        Ok(route)
    }

    pub(super) fn copy_epoch(&self) -> Result<u64, String> {
        Ok(self.write_gate()?.epoch())
    }

    /// Drop/abort never commits a target. Recover a poisoned gate only to
    /// remove our exact route; the shared failure still halts the live owner.
    pub(super) fn abort_copy(&self, epoch: u64, target: &Arc<CheckedStorage>) {
        let mut route = self.write_gate.lock().unwrap_or_else(|error| {
            self.record_failure(&ContextError::Storage("checked write gate poisoned".into()));
            error.into_inner()
        });
        if route.matches(epoch, target) {
            route.mirror = None;
        } else if route.mirror.is_some() {
            self.record_failure(&ContextError::Storage(
                "checked copy abort found another route".into(),
            ));
        }
    }

    /// Batch only disposable index writes. Canonical admission has its own
    /// transaction; unfinished checked generations never become live roots.
    pub(super) fn begin_write_phase(&self) -> Result<(), String> {
        let connection_guard = self
            .connection
            .lock()
            .map_err(|_| "checked index lock poisoned")?;
        let connection = connection_guard.open()?;
        if !connection.is_autocommit() {
            return Err("checked index write phase already active".into());
        }
        connection.execute_batch("BEGIN").map_err(|e| e.to_string())
    }
    pub(super) fn finish_write_phase(&self) -> Result<(), String> {
        if self
            .cache
            .lock()
            .map_err(|_| "checked cache lock poisoned")?
            .buffering
            .is_some()
        {
            return Err("startup buffer must finish before COMMIT".into());
        }
        let connection_guard = self
            .connection
            .lock()
            .map_err(|_| "checked index lock poisoned")?;
        let connection = connection_guard.open()?;
        if connection.is_autocommit() {
            return Err("checked index write phase missing".into());
        }
        connection
            .execute_batch("COMMIT")
            .map_err(|e| e.to_string())
    }
    #[cfg(test)]
    pub(super) fn evict_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        if !cache.pending.is_empty() {
            cache.trim(0);
        } else {
            let closed = cache.closed;
            let buffering = cache.buffering;
            *cache = Cache {
                closed,
                buffering,
                ..Cache::default()
            };
        }
    }
    pub(super) fn open(
        lease: Arc<Store>,
        cleanup_directory: bool,
        halt: Arc<Mutex<Option<String>>>,
    ) -> Result<Arc<Self>, String> {
        // The exclusive canonical lease excludes all prior live generations.
        for entry in fs::read_dir(lease.directory()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let owned = name
                .strip_prefix(PREFIX)
                .and_then(|s| s.strip_suffix(SUFFIX))
                .is_some_and(|number| number.parse::<u64>().is_ok());
            if owned || name == ".checked-context.sqlite3" {
                require_regular(&entry.path())?;
                fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
            }
        }
        Self::fresh(
            Arc::new(Owner {
                lease,
                cleanup_directory,
            }),
            Arc::new(Mutex::new(Cache::default())),
            halt,
            true,
        )
    }
    pub(super) fn successor(&self) -> Result<Arc<Self>, String> {
        if self
            .cache
            .lock()
            .map_err(|_| "checked cache lock poisoned")?
            .buffering
            .is_some()
        {
            return Err("startup buffer has no published successor".into());
        }
        Self::fresh(
            self.owner.clone(),
            self.cache.clone(),
            self.halt.clone(),
            false,
        )
    }
    fn fresh(
        owner: Arc<Owner>,
        cache: Arc<Mutex<Cache>>,
        halt: Arc<Mutex<Option<String>>>,
        startup: bool,
    ) -> Result<Arc<Self>, String> {
        let number = NEXT_FILE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| "checked generation number overflow")?;
        let directory = fs::canonicalize(owner.lease.directory()).map_err(|e| e.to_string())?;
        let path = directory.join(format!("{PREFIX}{number}{SUFFIX}"));
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| e.to_string())?;
        crate::storage::sqlite_common(
            &connection,
            crate::resources::limits().checked_index_cache_bytes,
        )
        .map_err(|error| error.to_string())?;
        if startup {
            // Only the fresh, exclusive startup generation is pruned in place.
            // SQLite requires the pointer map before any table is created.
            connection
                .execute_batch("PRAGMA auto_vacuum=INCREMENTAL")
                .map_err(|e| e.to_string())?;
            let mode: i64 = connection
                .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
                .map_err(|e| e.to_string())?;
            if mode != 2 {
                return Err("startup checked storage requires incremental vacuum".into());
            }
        }
        // Corruption fails the owner. These bytes and all roots are discarded
        // at the next startup; this database never establishes proof validity.
        connection
            .execute_batch(
                "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
            CREATE TABLE nodes(address BLOB PRIMARY KEY CHECK(length(address)=32),
                payload BLOB NOT NULL) STRICT, WITHOUT ROWID;",
            )
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
            live_cache_budget: AtomicUsize::new(usize::MAX),
            connection: Mutex::new(IndexConnection(Some(connection), None)),
            write_gate: Mutex::new(WriteRoute::default()),
            write_ready: Condvar::new(),
            generation: number,
            cache,
            path,
            owner,
            halt,
        }))
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize, String> {
        let connection_guard = self
            .connection
            .lock()
            .map_err(|_| "checked index lock poisoned")?;
        let connection = connection_guard.open()?;
        let pages: i64 = connection
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let size: i64 = connection
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let bytes = pages
            .checked_mul(size)
            .ok_or("checked index size overflow")?;
        usize::try_from(bytes).map_err(|_| "checked index size width".into())
    }

    /// Called only between startup replay pages, before any view is published.
    /// The checker still authenticates its complete live maps and nested buckets.
    pub(super) fn prune_startup(
        self: &Arc<Self>,
        context: &DiskArtifactState,
    ) -> Result<usize, String> {
        let result = (|| {
            {
                let connection_guard = self
                    .connection
                    .lock()
                    .map_err(|_| "checked index lock poisoned")?;
                let connection = connection_guard.open()?;
                if !connection.is_autocommit() {
                    return Err("startup prune requires a finished replay page".into());
                }
                let mode: i64 = connection
                    .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
                    .map_err(|e| e.to_string())?;
                if mode != 2 {
                    return Err("startup prune requires incremental vacuum".into());
                }
                // Keep only addresses on disk; small replays never create this table.
                connection
                    .execute_batch(
                        "CREATE TABLE IF NOT EXISTS startup_keep(
                            address BLOB PRIMARY KEY CHECK(length(address)=32)
                        ) STRICT, WITHOUT ROWID;
                        BEGIN; DELETE FROM startup_keep;",
                    )
                    .map_err(|e| e.to_string())?;
            }
            // Never hold the SQL mutex across the checker's recursive storage calls.
            // The returned view is a traversal vehicle, not a new checked root.
            drop(
                context
                    .copy_to(Arc::new(StartupMarker {
                        storage: self.clone(),
                    }))
                    .map_err(|e| e.to_string())?,
            );
            {
                let connection_guard = self
                    .connection
                    .lock()
                    .map_err(|_| "checked index lock poisoned")?;
                let connection = connection_guard.open()?;
                connection
                    .execute(
                        "DELETE FROM nodes WHERE NOT EXISTS(
                            SELECT 1 FROM startup_keep WHERE startup_keep.address=nodes.address)",
                        [],
                    )
                    .map_err(|e| e.to_string())?;
                #[cfg(test)]
                startup_prune_test_fault(StartupPruneStage::Sweep)?;
                connection
                    .execute("DELETE FROM startup_keep", [])
                    .map_err(|e| e.to_string())?;
            }
            // A removed address may be written again in this same generation.
            // No persisted-generation tag may survive the sweep.
            *self
                .cache
                .lock()
                .map_err(|_| "checked cache lock poisoned")? = Cache::default();
            {
                let connection_guard = self
                    .connection
                    .lock()
                    .map_err(|_| "checked index lock poisoned")?;
                let connection = connection_guard.open()?;
                connection
                    .execute_batch("COMMIT")
                    .map_err(|e| e.to_string())?;
                #[cfg(test)]
                startup_prune_test_fault(StartupPruneStage::Reclaim)?;
                // This PRAGMA returns a row per step. execute_batch would stop
                // after its first row; the cursor must reach SQLITE_DONE.
                let mut vacuum = connection
                    .prepare("PRAGMA incremental_vacuum")
                    .map_err(|e| e.to_string())?;
                let mut rows = vacuum.query([]).map_err(|e| e.to_string())?;
                while rows.next().map_err(|e| e.to_string())?.is_some() {}
                drop(rows);
                drop(vacuum);
                let remaining: i64 = connection
                    .pragma_query_value(None, "freelist_count", |row| row.get(0))
                    .map_err(|e| e.to_string())?;
                if remaining != 0 {
                    return Err("startup checked storage reclaim is incomplete".into());
                }
            }
            self.allocated_bytes()
        })();
        if let Err(error) = &result {
            // journal_mode=OFF cannot safely recover a partial sweep by rollback.
            // Graph::open propagates this error and discards the whole generation.
            *self.halt.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
        }
        result
    }
    fn read_inner(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| ContextError::Storage("checked cache lock poisoned".into()))?;
            if let Some(entry) = cache.entries.get(&address) {
                if entry.bytes.len() > maximum {
                    return Err(ContextError::Limit);
                }
                let bytes = entry.bytes.clone();
                cache.touch(address);
                return Ok(bytes);
            }
        }
        let bytes = self.read_uncached(address, maximum)?;
        self.cache
            .lock()
            .map_err(|_| ContextError::Storage("checked cache lock poisoned".into()))?
            .insert(address, bytes.clone(), self.generation);
        Ok(bytes)
    }
    fn read_uncached(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        let connection_guard = self
            .connection
            .lock()
            .map_err(|_| ContextError::Storage("checked index lock poisoned".into()))?;
        let connection = connection_guard.open().map_err(ContextError::Storage)?;
        // Read only a fixed header before fetching or allocating decoded bytes.
        let encoded_bound = codec::maximum_encoded(maximum)?;
        let record: Option<(i64, Option<Vec<u8>>)> = connection
            .prepare_cached(
                "SELECT length(payload),CASE WHEN length(payload)<=?3
                    THEN substr(payload,1,?2) ELSE NULL END FROM nodes WHERE address=?1",
            )
            .map_err(context_error)?
            .query_row(
                params![
                    address.as_slice(),
                    codec::HEADER_BYTES as i64,
                    i64::try_from(encoded_bound).map_err(|_| ContextError::Limit)?
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(context_error)?;
        let (length, header) = record.ok_or(ContextError::Corrupt)?;
        let header = header.ok_or(ContextError::Limit)?;
        let length = usize::try_from(length).map_err(|_| ContextError::Limit)?;
        let decoded = codec::decoded_length(&header, length, maximum)?;
        let bound = codec::maximum_encoded(decoded)?;
        let encoded: Vec<u8> = connection
            .prepare_cached("SELECT CASE WHEN length(payload)<=?2 THEN payload ELSE NULL END FROM nodes WHERE address=?1")
            .map_err(context_error)?
            .query_row(params![address.as_slice(), i64::try_from(bound).map_err(|_| ContextError::Limit)?], |r| r.get(0))
            .map_err(context_error)?;
        if encoded.len() != length || encoded.get(..codec::HEADER_BYTES) != Some(header.as_slice())
        {
            return Err(ContextError::Corrupt);
        }
        let bytes = codec::decode(&encoded, maximum)?;
        Ok(bytes)
    }
    fn write_inner(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| ContextError::Storage("checked cache lock poisoned".into()))?;
            if self.buffer_write(&mut cache, address, bytes)? {
                return Ok(());
            }
            // Shared raw bytes prove a row only in their recorded generation.
            if let Some(entry) = cache.entries.get(&address)
                && entry.state == EntryState::Persisted(self.generation)
            {
                if entry.bytes != bytes {
                    return Err(ContextError::Corrupt);
                }
                cache.touch(address);
                return Ok(());
            }
        }
        let connection_guard = self
            .connection
            .lock()
            .map_err(|_| ContextError::Storage("checked index lock poisoned".into()))?;
        let connection = connection_guard.open().map_err(ContextError::Storage)?;
        persist_record(connection, self.generation, address, bytes)?;
        drop(connection_guard);
        self.cache
            .lock()
            .map_err(|_| ContextError::Storage("checked cache lock poisoned".into()))?
            .insert(address, bytes.to_vec(), self.generation);
        Ok(())
    }
    fn record_error<T>(&self, result: Result<T, ContextError>) -> Result<T, ContextError> {
        if let Err(error) = &result {
            *self.halt.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
        }
        result
    }
}

fn persist_record(
    connection: &Connection,
    _generation: u64,
    address: [u8; 32],
    bytes: &[u8],
) -> Result<(), ContextError> {
    let bound = codec::maximum_encoded(bytes.len())?;
    let bound = i64::try_from(bound).map_err(|_| ContextError::Limit)?;
    let encoded = codec::encode(bytes)?;
    #[cfg(test)]
    {
        SQL_INSERTS.with(|count| count.set(count.get() + 1));
        admission::test_insert_state(_generation, connection.is_autocommit());
    }
    let inserted = connection
        .prepare_cached(
            "INSERT INTO nodes(address,payload) VALUES(?1,?2)
                    ON CONFLICT(address) DO NOTHING",
        )
        .map_err(context_error)?
        .execute(params![address.as_slice(), encoded])
        .map_err(context_error)?;
    match inserted {
        0 => {
            let previous: Option<Option<Vec<u8>>> = connection
                    .prepare_cached("SELECT CASE WHEN length(payload)<=?2 THEN payload ELSE NULL END FROM nodes WHERE address=?1")
                    .map_err(context_error)?
                    .query_row(params![address.as_slice(), bound], |r| r.get(0))
                    .optional().map_err(context_error)?;
            let Some(Some(previous)) = previous else {
                return Err(ContextError::Corrupt);
            };
            let raw = codec::decode(&previous, bytes.len()).map_err(|_| ContextError::Corrupt)?;
            if raw != bytes {
                return Err(ContextError::Corrupt);
            }
        }
        1 => {}
        _ => return Err(ContextError::Corrupt),
    }
    Ok(())
}

/// A destination for the unchanged authenticated copy traversal. A hot cached
/// value never establishes that its existing persistent row is intact or live.
struct StartupMarker {
    storage: Arc<CheckedStorage>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartupPruneStage {
    Mark,
    Sweep,
    Reclaim,
}
#[cfg(test)]
thread_local! {
    static STARTUP_TEST_FORCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static STARTUP_TEST_FAULT: std::cell::Cell<Option<StartupPruneStage>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(super) fn with_startup_prune_test<T>(
    fault: Option<StartupPruneStage>,
    action: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            STARTUP_TEST_FORCE.set(false);
            STARTUP_TEST_FAULT.set(None);
        }
    }
    assert!(
        !STARTUP_TEST_FORCE.replace(true),
        "nested startup prune fixture"
    );
    STARTUP_TEST_FAULT.set(fault);
    let _reset = Reset;
    action()
}
#[cfg(test)]
pub(super) fn startup_test_threshold(threshold: usize) -> usize {
    if STARTUP_TEST_FORCE.get() {
        0
    } else {
        threshold
    }
}
#[cfg(test)]
fn startup_prune_test_fault(stage: StartupPruneStage) -> Result<(), String> {
    if STARTUP_TEST_FAULT.get() == Some(stage) {
        Err(format!("test-controlled startup prune {stage:?} failure"))
    } else {
        Ok(())
    }
}
impl ContextStorage for StartupMarker {
    fn record_failure(&self, error: &ContextError) {
        self.storage.record_failure(error);
    }
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        self.storage
            .record_error(self.storage.read_uncached(address, maximum))
    }
    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        self.storage.record_error((|| {
            // Decode the actual bounded SQL row on every visit, including repeats.
            // Missing, malformed, oversized or different rows are never repaired.
            if self.storage.read_uncached(address, bytes.len())? != bytes {
                return Err(ContextError::Corrupt);
            }
            self.storage
                .connection
                .lock()
                .map_err(|_| ContextError::Storage("checked index lock poisoned".into()))?
                .open()
                .map_err(ContextError::Storage)?
                .prepare_cached(
                    "INSERT INTO startup_keep(address) VALUES(?1) ON CONFLICT(address) DO NOTHING",
                )
                .map_err(context_error)?
                .execute([address.as_slice()])
                .map_err(context_error)?;
            #[cfg(test)]
            startup_prune_test_fault(StartupPruneStage::Mark).map_err(ContextError::Storage)?;
            Ok(())
        })())
    }
}
impl Cache {
    fn trim(&mut self, limit: usize) {
        // Buffered records are pinned until a checked frontier or a pressure
        // spill materializes them. Only persisted entries have LRU positions.
        while self.charged > limit {
            let Some((_, key)) = self.recency.pop_first() else {
                break;
            };
            if let Some(old) = self.entries.remove(&key) {
                self.charged -= old.bytes.capacity() + CACHE_ENTRY_BYTES;
            }
        }
    }
    fn reset_clock(&mut self) {
        self.clock = 0;
        self.recency.clear();
        for (address, entry) in &mut self.entries {
            if matches!(entry.state, EntryState::Persisted(_)) {
                self.clock += 1;
                entry.clock = self.clock;
                self.recency.insert(self.clock, *address);
            }
        }
    }
    fn touch(&mut self, address: [u8; 32]) {
        if self
            .entries
            .get(&address)
            .is_none_or(|entry| !matches!(entry.state, EntryState::Persisted(_)))
        {
            return;
        }
        if self.clock == u64::MAX && self.pending.is_empty() {
            let entry = self.entries.remove(&address).expect("cached record");
            self.entries.clear();
            self.recency.clear();
            self.charged = 0;
            self.clock = 0;
            let EntryState::Persisted(generation) = entry.state else {
                unreachable!()
            };
            self.insert(address, entry.bytes, generation);
            return;
        }
        if self.clock == u64::MAX {
            self.reset_clock();
        }
        let entry = self.entries.get_mut(&address).expect("cached record");
        self.recency.remove(&entry.clock);
        self.clock += 1;
        entry.clock = self.clock;
        self.recency.insert(entry.clock, address);
    }
    fn insert(&mut self, address: [u8; 32], bytes: Vec<u8>, generation: u64) {
        if self.closed {
            return;
        }
        if let Some(old) = self.entries.remove(&address) {
            self.recency.remove(&old.clock);
            self.charged -= old.bytes.capacity() + CACHE_ENTRY_BYTES;
            if !matches!(old.state, EntryState::Persisted(_)) {
                self.pending.remove(&address);
            }
        }
        let charge = bytes.capacity().saturating_add(CACHE_ENTRY_BYTES);
        let limit =
            crate::resources::adaptive::cache(crate::resources::limits().checked_cache_bytes);
        self.trim(limit);
        if charge > limit {
            return;
        }
        self.trim(limit - charge);
        if self.charged > limit - charge {
            return;
        }
        if self.clock == u64::MAX {
            if self.pending.is_empty() {
                self.entries.clear();
                self.recency.clear();
                self.charged = 0;
                self.clock = 0;
            } else {
                self.reset_clock();
            }
        }
        self.clock += 1;
        self.charged += charge;
        self.recency.insert(self.clock, address);
        self.entries.insert(
            address,
            CacheEntry {
                bytes,
                state: EntryState::Persisted(generation),
                clock: self.clock,
            },
        );
    }
}
impl ContextStorage for CheckedStorage {
    fn record_failure(&self, error: &ContextError) {
        *self.halt.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
    }
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        self.require_live().map_err(ContextError::Storage)?;
        self.record_error(self.read_inner(address, maximum))
    }
    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        self.require_live().map_err(ContextError::Storage)?;
        let route = match self.write_gate() {
            Ok(route) => route,
            Err(error) => return self.record_error(Err(ContextError::Storage(error))),
        };
        self.require_live().map_err(ContextError::Storage)?;
        #[cfg(test)]
        WRITE_TEST_PAUSE.with(|slot| {
            let pause = slot.borrow_mut().take();
            if let Some(pause) = pause {
                pause.wait();
                pause.wait();
            }
        });
        #[cfg(test)]
        WRITE_TEST_DELAY.with(|slot| {
            if let Some((started, release)) = slot.borrow_mut().take() {
                let _ = started.send(());
                let _ = release.recv_timeout(std::time::Duration::from_secs(10));
            }
        });
        let result = (|| {
            // write_inner releases both the shared cache and SQL lock before
            // returning, including its cached and existing-row success paths.
            self.write_inner(address, bytes)?;
            if let Some(target) = &route.mirror {
                target.write(address, bytes)?;
            }
            Ok(())
        })();
        // Report a failed local or mirrored write before finish can acquire
        // the source gate and consider publishing this target.
        let result = self.record_error(result);
        drop(route);
        result
    }
}
impl Drop for CheckedStorage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if self.cleanup_directory {
            let _ = fs::remove_dir_all(self.lease.directory());
        }
    }
}
fn require_regular(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("checked index is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("checked index has linked aliases".into());
        }
    }
    Ok(())
}
fn context_error(error: rusqlite::Error) -> ContextError {
    ContextError::Storage(error.to_string())
}

#[cfg(test)]
mod tests;
