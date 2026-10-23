//! Disposable bytes for the checker's authenticated immutable context.
//! Startup always rebuilds empty checked roots by mathematical corpus replay.

use crate::store::Store;
use naome_checker::{ContextError, ContextStorage, DiskArtifactState};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
mod admission;
mod codec;
#[cfg(test)]
mod compaction_discriminator;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

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
struct CacheEntry {
    bytes: Vec<u8>,
    persisted_generation: u64,
    clock: u64,
}
#[derive(Default)]
struct Cache {
    closed: bool,
    entries: BTreeMap<[u8; 32], CacheEntry>,
    recency: BTreeMap<u64, [u8; 32]>,
    charged: usize,
    clock: u64,
}
struct Owner {
    lease: Arc<Store>,
    cleanup_directory: bool,
}
/// Every generation shares one byte-accounted cache and canonical directory
/// lease. Old question/batch clones keep their generation's bytes available.
pub(super) struct CheckedStorage {
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
        let closed = cache.closed;
        *cache = Cache {
            closed,
            ..Cache::default()
        };
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
        connection
            .busy_timeout(crate::resources::limits().sqlite_busy_timeout)
            .map_err(|e| e.to_string())?;
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
             PRAGMA temp_store=FILE; PRAGMA mmap_size=0;
            PRAGMA trusted_schema=OFF;
            CREATE TABLE nodes(address BLOB PRIMARY KEY CHECK(length(address)=32),
                payload BLOB NOT NULL) STRICT, WITHOUT ROWID;",
            )
            .map_err(|e| e.to_string())?;
        connection
            .pragma_update(
                None,
                "cache_size",
                -(i64::try_from(
                    (crate::resources::limits().checked_index_cache_bytes / 1024).max(1),
                )
                .map_err(|_| "SQLite cache width")?),
            )
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
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
        let bound = codec::maximum_encoded(bytes.len())?;
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| ContextError::Storage("checked cache lock poisoned".into()))?;
            // Shared raw bytes prove a row only in their recorded generation.
            if let Some(entry) = cache.entries.get(&address)
                && entry.persisted_generation == self.generation
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
        let bound = i64::try_from(bound).map_err(|_| ContextError::Limit)?;
        let encoded = codec::encode(bytes)?;
        #[cfg(test)]
        admission::test_insert_state(self.generation, connection.is_autocommit());
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
                let raw =
                    codec::decode(&previous, bytes.len()).map_err(|_| ContextError::Corrupt)?;
                if raw != bytes {
                    return Err(ContextError::Corrupt);
                }
            }
            1 => {}
            _ => return Err(ContextError::Corrupt),
        }
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
    fn touch(&mut self, address: [u8; 32]) {
        if self.clock == u64::MAX {
            let Some(entry) = self.entries.remove(&address) else {
                return;
            };
            self.recency.remove(&entry.clock);
            self.charged -= entry.bytes.capacity() + CACHE_ENTRY_BYTES;
            // Reuse the existing rollover clear while retaining this allocation.
            self.insert(address, entry.bytes, entry.persisted_generation);
            return;
        }
        let Some(entry) = self.entries.get_mut(&address) else {
            return;
        };
        self.recency.remove(&entry.clock);
        self.clock += 1;
        entry.clock = self.clock;
        self.recency.insert(entry.clock, address);
    }

    fn insert(&mut self, address: [u8; 32], bytes: Vec<u8>, persisted_generation: u64) {
        // A cold read that started before a fatal abort may finish later. It
        // must never repopulate provisional tags after the shared cache closes.
        if self.closed {
            return;
        }
        if let Some(old) = self.entries.remove(&address) {
            self.recency.remove(&old.clock);
            self.charged -= old.bytes.capacity() + CACHE_ENTRY_BYTES;
        }
        let charge = bytes.capacity().saturating_add(CACHE_ENTRY_BYTES);
        if charge > crate::resources::limits().checked_cache_bytes {
            return;
        }
        while self.charged > crate::resources::limits().checked_cache_bytes - charge {
            let Some((_, key)) = self.recency.pop_first() else {
                break;
            };
            if let Some(old) = self.entries.remove(&key) {
                self.charged -= old.bytes.capacity() + CACHE_ENTRY_BYTES;
            }
        }
        if self.clock == u64::MAX {
            self.entries.clear();
            self.recency.clear();
            self.charged = 0;
            self.clock = 0;
        }
        self.clock += 1;
        self.charged += charge;
        self.recency.insert(self.clock, address);
        self.entries.insert(
            address,
            CacheEntry {
                bytes,
                persisted_generation,
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
mod tests {
    use super::*;
    use crate::Graph;
    use naome_checker::ContextView;

    #[test]
    fn hot_reads_keep_owned_bytes_and_cached_allocation_generation_and_charge() {
        let graph = Graph::default();
        let storage = &graph.checked_storage;
        let address = [47; 32];
        let bytes = vec![7; 4096];
        storage.write(address, &bytes).unwrap();
        let (pointer, capacity, charged) = {
            let mut cache = storage.cache.lock().unwrap();
            let mut cached = Vec::with_capacity(bytes.len() + 4096);
            cached.extend_from_slice(&bytes);
            cache.insert(address, cached, storage.generation);
            let entry = &cache.entries[&address];
            (entry.bytes.as_ptr(), entry.bytes.capacity(), cache.charged)
        };
        let successor = storage.successor().unwrap();
        let mut owned = successor.read(address, bytes.len()).unwrap();
        assert_eq!(owned, bytes);
        owned[0] ^= 1;
        assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
        let clock = {
            let cache = storage.cache.lock().unwrap();
            let entry = &cache.entries[&address];
            assert_eq!(entry.bytes.as_ptr(), pointer);
            assert_eq!(entry.bytes.capacity(), capacity);
            assert_eq!(entry.persisted_generation, storage.generation);
            assert_eq!(cache.charged, charged);
            assert!(cache.charged <= crate::resources::limits().checked_cache_bytes);
            cache.clock
        };
        assert!(matches!(
            successor.read(address, bytes.len() - 1),
            Err(ContextError::Limit)
        ));
        assert_eq!(storage.cache.lock().unwrap().clock, clock);
        assert!(graph.storage_error().is_some());
    }

    #[test]
    fn hot_read_and_write_rollover_preserves_generation_charge_and_successor_persistence() {
        for write_hit in [false, true] {
            let graph = Graph::default();
            let storage = &graph.checked_storage;
            let address = [48; 32];
            let bytes = vec![8; 4096];
            storage.write(address, &bytes).unwrap();
            storage.write([49; 32], &bytes).unwrap();
            let successor = storage.successor().unwrap();
            let (pointer, capacity, charged) = {
                let mut cache = storage.cache.lock().unwrap();
                let mut cached = Vec::with_capacity(bytes.len() + 4096);
                cached.extend_from_slice(&bytes);
                cache.insert(address, cached, storage.generation);
                cache.clock = u64::MAX - 1;
                let entry = &cache.entries[&address];
                (entry.bytes.as_ptr(), entry.bytes.capacity(), cache.charged)
            };
            let hit = || {
                if write_hit {
                    storage.write(address, &bytes).unwrap();
                } else {
                    assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
                }
            };
            hit();
            {
                let cache = storage.cache.lock().unwrap();
                assert_eq!(cache.clock, u64::MAX);
                assert_eq!(cache.entries.len(), 2);
                assert_eq!(cache.recency.len(), 2);
                assert_eq!(cache.recency.get(&u64::MAX), Some(&address));
                assert_eq!(cache.charged, charged);
            }
            hit();
            {
                let cache = storage.cache.lock().unwrap();
                let entry = &cache.entries[&address];
                assert_eq!(cache.clock, 1);
                assert_eq!(cache.entries.len(), 1);
                assert_eq!(cache.recency.len(), 1);
                assert_eq!(cache.recency.get(&1), Some(&address));
                assert_eq!(entry.clock, 1);
                assert_eq!(entry.bytes.as_ptr(), pointer);
                assert_eq!(entry.bytes.capacity(), capacity);
                assert_eq!(entry.persisted_generation, storage.generation);
                assert_eq!(cache.charged, capacity + CACHE_ENTRY_BYTES);
                assert!(cache.charged <= crate::resources::limits().checked_cache_bytes);
            }
            successor.write(address, &bytes).unwrap();
            successor.evict_cache();
            assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
            storage.evict_cache();
            assert_eq!(storage.read(address, bytes.len()).unwrap(), bytes);
            assert!(graph.storage_error().is_none());
        }
    }

    #[test]
    fn cold_records_decode_with_raw_cache_charges_and_caller_bounds() {
        let graph = Graph::default();
        let storage = &graph.checked_storage;
        let bytes = vec![0; 16 * 1024];
        let address = [41; 32];
        storage.write(address, &bytes).unwrap();
        storage.write(address, &bytes).unwrap();
        let (count, stored): (i64, i64) = storage
            .connection
            .lock()
            .unwrap()
            .open()
            .unwrap()
            .query_row(
                "SELECT count(*),sum(length(payload)) FROM nodes",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert!(stored < bytes.len() as i64 / 10);
        assert_eq!(
            storage.cache.lock().unwrap().charged,
            bytes.len() + CACHE_ENTRY_BYTES
        );
        storage.evict_cache();
        assert_eq!(storage.read(address, bytes.len()).unwrap(), bytes);
        assert_eq!(
            storage.cache.lock().unwrap().charged,
            bytes.len() + CACHE_ENTRY_BYTES
        );
        storage.evict_cache();
        assert!(matches!(
            storage.read(address, bytes.len() - 1),
            Err(ContextError::Limit)
        ));
        assert!(graph.storage_error().is_some());
    }

    #[test]
    fn conflicting_raw_bytes_do_not_replace_a_compressed_record() {
        let graph = Graph::default();
        let storage = &graph.checked_storage;
        let bytes = vec![0; 4096];
        let address = [42; 32];
        storage.write(address, &bytes).unwrap();
        let mut conflict = bytes.clone();
        conflict[2000] = 1;
        assert!(matches!(
            storage.write(address, &conflict),
            Err(ContextError::Corrupt)
        ));
        storage.evict_cache();
        assert_eq!(storage.read_inner(address, bytes.len()).unwrap(), bytes);
        assert!(graph.storage_error().is_some());
    }

    #[test]
    fn cold_identical_and_conflicting_writes_preserve_the_original_payload() {
        let graph = Graph::default();
        let storage = &graph.checked_storage;
        let bytes = vec![0; 4096];
        let address = [46; 32];
        storage.write(address, &bytes).unwrap();
        let stored = || -> Vec<u8> {
            storage
                .connection
                .lock()
                .unwrap()
                .open()
                .unwrap()
                .query_row(
                    "SELECT payload FROM nodes WHERE address=?1",
                    params![address.as_slice()],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let original = stored();
        storage.evict_cache();
        storage.write(address, &bytes).unwrap();
        assert_eq!(stored(), original);
        assert!(graph.storage_error().is_none());
        storage.evict_cache();
        let mut conflict = bytes.clone();
        conflict[2000] = 1;
        assert!(matches!(
            storage.write(address, &conflict),
            Err(ContextError::Corrupt)
        ));
        assert_eq!(stored(), original);
        storage.evict_cache();
        assert_eq!(storage.read_inner(address, bytes.len()).unwrap(), bytes);
        assert!(graph.storage_error().is_some());
    }

    #[test]
    fn cached_old_bytes_still_persist_in_a_successor_generation() {
        let graph = Graph::default();
        let old = &graph.checked_storage;
        let bytes = vec![0; 4096];
        let address = [45; 32];
        old.write(address, &bytes).unwrap();
        let successor = old.successor().unwrap();
        // This shared-cache read must not claim a row in the empty successor.
        assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
        successor.write(address, &bytes).unwrap();
        successor.evict_cache();
        assert_eq!(successor.read(address, bytes.len()).unwrap(), bytes);
        old.evict_cache();
        assert_eq!(old.read(address, bytes.len()).unwrap(), bytes);
        assert!(graph.storage_error().is_none());
    }

    fn rows(storage: &CheckedStorage, address: [u8; 32]) -> i64 {
        storage
            .connection
            .lock()
            .unwrap()
            .open()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM nodes WHERE address=?1",
                [address.as_slice()],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn checked_graph() -> Graph {
        let mut graph = Graph::default();
        let object = graph
            .author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1")
            .unwrap();
        graph.ingest(object, std::time::Instant::now()).unwrap();
        graph
    }

    #[test]
    fn every_cached_existing_and_unreferenced_write_reaches_the_mirror() {
        for cached in [false, true] {
            for target_existing in [false, true] {
                let graph = Graph::default();
                let source = &graph.checked_storage;
                let target = source.successor().unwrap();
                let address = [67; 32];
                let bytes = vec![5; 8192];
                source.write(address, &bytes).unwrap();
                if target_existing {
                    target.write(address, &bytes).unwrap();
                }
                if cached {
                    source
                        .cache
                        .lock()
                        .unwrap()
                        .insert(address, bytes.clone(), source.generation);
                } else {
                    source.evict_cache();
                }
                assert_eq!(rows(&target, address), if target_existing { 1 } else { 0 });
                let epoch = source
                    .write_gate()
                    .unwrap()
                    .attach(source, target.clone())
                    .unwrap();
                source.write(address, &bytes).unwrap();
                source.write_gate().unwrap().detach(epoch, &target).unwrap();
                // Reads alone could use another generation's shared hot bytes.
                // Evict the entire cache before establishing either SQL row.
                target.evict_cache();
                assert_eq!(target.read(address, bytes.len()).unwrap(), bytes);
                source.evict_cache();
                assert_eq!(source.read(address, bytes.len()).unwrap(), bytes);
                assert_eq!(rows(&target, address), 1);
                assert!(Arc::ptr_eq(&source.cache, &target.cache));
                assert!(
                    source.cache.lock().unwrap().charged
                        <= crate::resources::limits().checked_cache_bytes
                );
                assert!(graph.storage_error().is_none());
            }
        }
    }

    #[test]
    fn conflicting_mirror_row_is_not_repaired_or_hidden_by_a_source_cache_hit() {
        let graph = Graph::default();
        let source = &graph.checked_storage;
        let target = source.successor().unwrap();
        let address = [71; 32];
        source.write(address, b"original source").unwrap();
        target.write(address, b"different target").unwrap();
        source.cache.lock().unwrap().insert(
            address,
            b"original source".to_vec(),
            source.generation,
        );
        let epoch = source
            .write_gate()
            .unwrap()
            .attach(source, target.clone())
            .unwrap();
        assert!(matches!(
            source.write(address, b"original source"),
            Err(ContextError::Corrupt)
        ));
        source.abort_copy(epoch, &target);
        assert!(source.write_gate().unwrap().mirror.is_none());
        target.evict_cache();
        assert_eq!(
            target.read_uncached(address, 64).unwrap(),
            b"different target"
        );
        source.evict_cache();
        assert_eq!(
            source.read_uncached(address, 64).unwrap(),
            b"original source"
        );
        assert!(graph.storage_error().is_some());
    }

    #[test]
    fn source_gate_orders_real_writes_before_attach_and_current_root_handoff() {
        use std::sync::Barrier;
        for finishing in [false, true] {
            let mut graph = checked_graph();
            if finishing {
                assert!(graph.test_compaction_step(1).unwrap());
            }
            let source = graph.checked_storage.clone();
            let paused = Arc::new(Barrier::new(2));
            let writer_pause = paused.clone();
            let writer_source = source.clone();
            let writer = std::thread::spawn(move || {
                WRITE_TEST_PAUSE.with(|slot| *slot.borrow_mut() = Some(writer_pause));
                writer_source
                    .write([68; 32], b"inflight immutable bytes")
                    .unwrap();
            });
            paused.wait(); // writer owns the actual source gate
            let started = Arc::new(Barrier::new(2));
            let operation_started = started.clone();
            let operation = std::thread::spawn(move || {
                operation_started.wait();
                if finishing {
                    for _ in 0..4096 {
                        let _ = graph
                            .maintain_checked_storage_step(
                                usize::MAX,
                                naome_checker::DiskCopyBudget {
                                    records: 1,
                                    bytes: naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES,
                                },
                            )
                            .unwrap();
                        if graph.compaction.is_none() {
                            return graph;
                        }
                    }
                    panic!("small copy did not complete");
                }
                assert!(graph.test_compaction_step(1).unwrap());
                graph
            });
            started.wait();
            paused.wait(); // allow write, then queued attach/finish
            writer.join().unwrap();
            let graph = operation.join().unwrap();
            let target = if finishing {
                assert!(!Arc::ptr_eq(&source, &graph.checked_storage));
                graph.checked_storage.clone()
            } else {
                assert!(Arc::ptr_eq(&source, &graph.checked_storage));
                graph.compaction.as_ref().unwrap().target.clone()
            };
            assert_eq!(rows(&target, [68; 32]), if finishing { 1 } else { 0 });
            source.write([69; 32], b"after boundary").unwrap();
            assert_eq!(rows(&target, [69; 32]), if finishing { 0 } else { 1 });
            if finishing {
                target.evict_cache();
                assert_eq!(
                    target.read([68; 32], 64).unwrap(),
                    b"inflight immutable bytes"
                );
                assert!(source.write_gate().unwrap().mirror.is_none());
            }
            assert!(graph.storage_error().is_none());
        }
    }

    #[test]
    fn copy_read_mirror_and_real_sql_commit_failures_halt_without_handoff() {
        for failure in 0..3 {
            let mut graph = checked_graph();
            let source = graph.checked_storage.clone();
            let snapshot = graph.context.snapshot_id();
            let corpus = graph.content_root();
            assert!(graph.test_compaction_step(1).unwrap());
            let target = graph.compaction.as_ref().unwrap().target.clone();
            match failure {
                0 => {
                    source
                        .connection
                        .lock()
                        .unwrap()
                        .open()
                        .unwrap()
                        .execute("DELETE FROM nodes", [])
                        .unwrap();
                    source.evict_cache();
                }
                1 => {
                    target
                        .connection
                        .lock()
                        .unwrap()
                        .open()
                        .unwrap()
                        .execute_batch(
                            "CREATE TRIGGER reject_mirror BEFORE INSERT ON nodes BEGIN
                         SELECT RAISE(ABORT,'injected mirror I/O refusal'); END;",
                        )
                        .unwrap();
                    assert!(source.write([70; 32], b"unpublished staged write").is_err());
                }
                _ => {
                    // A real deferred constraint lets node writes succeed and
                    // makes the bounded transaction's COMMIT fail separately.
                    target
                        .connection
                        .lock()
                        .unwrap()
                        .open()
                        .unwrap()
                        .execute_batch(
                            "PRAGMA foreign_keys=ON;
                         CREATE TABLE copy_parent(id INTEGER PRIMARY KEY);
                         CREATE TABLE copy_child(id INTEGER REFERENCES copy_parent(id)
                             DEFERRABLE INITIALLY DEFERRED);
                         CREATE TRIGGER reject_copy_commit AFTER INSERT ON nodes BEGIN
                             INSERT INTO copy_child(id) VALUES(1); END;",
                        )
                        .unwrap();
                }
            }
            let error = graph.test_compaction_step(1).unwrap_err();
            if failure == 2 {
                assert!(error.contains("FOREIGN KEY"), "{error}");
            }
            assert!(graph.compaction.is_none());
            assert!(graph.storage_error().is_some());
            assert!(source.write_gate().unwrap().mirror.is_none());
            assert!(Arc::ptr_eq(&source, &graph.checked_storage));
            assert_eq!(graph.context.snapshot_id(), snapshot);
            assert_eq!(graph.content_root(), corpus);
            assert_eq!(graph.store.summary().unwrap().count, 1);
            assert!(
                graph
                    .author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1")
                    .is_err()
            );
        }
    }

    #[test]
    fn setup_failure_and_cancelled_copy_never_publish_or_retain_a_mirror() {
        let mut graph = checked_graph();
        let source = graph.checked_storage.clone();
        let snapshot = graph.context.snapshot_id();
        let corpus = graph.content_root();
        assert!(graph.test_compaction_step(1).unwrap());
        let target = Arc::downgrade(&graph.compaction.as_ref().unwrap().target);
        drop(graph.compaction.take());
        assert!(
            target.upgrade().is_none(),
            "abort guard releases the unfinished target"
        );
        assert!(source.write_gate().unwrap().mirror.is_none());
        assert!(Arc::ptr_eq(&source, &graph.checked_storage));
        assert_eq!(graph.context.snapshot_id(), snapshot);
        assert_eq!(graph.content_root(), corpus);
        source.evict_cache();
        assert_eq!(graph.ids().len(), 1);
        assert!(graph.storage_error().is_none());
        // Overflow is rejected before attach; the newly created empty target
        // must be dropped without changing the live context or route.
        source.write_gate().unwrap().epoch = u64::MAX;
        assert!(
            graph
                .test_compaction_step(1)
                .unwrap_err()
                .contains("epoch overflow")
        );
        assert!(graph.compaction.is_none());
        assert!(source.write_gate().unwrap().mirror.is_none());
        assert!(graph.storage_error().is_some());
        assert_eq!(graph.context.snapshot_id(), snapshot);
        assert_eq!(graph.content_root(), corpus);
    }

    #[test]
    fn malicious_decoded_length_is_refused_from_the_sql_header() {
        let graph = Graph::default();
        let storage = &graph.checked_storage;
        let address = [43; 32];
        let mut encoded = codec::encode(&vec![0; 4096]).unwrap();
        encoded[5..13].copy_from_slice(&u64::MAX.to_be_bytes());
        storage
            .connection
            .lock()
            .unwrap()
            .open()
            .unwrap()
            .execute(
                "INSERT INTO nodes(address,payload) VALUES(?1,?2)",
                params![address.as_slice(), encoded],
            )
            .unwrap();
        assert!(matches!(
            storage.read(address, 4096),
            Err(ContextError::Limit)
        ));
        assert!(graph.storage_error().is_some());
    }

    #[test]
    fn oversized_sql_blob_is_refused_before_parsing_its_header() {
        let graph = Graph::default();
        let storage = &graph.checked_storage;
        let address = [44; 32];
        storage
            .connection
            .lock()
            .unwrap()
            .open()
            .unwrap()
            .execute(
                "INSERT INTO nodes(address,payload) VALUES(?1,zeroblob(8192))",
                params![address.as_slice()],
            )
            .unwrap();
        assert!(matches!(
            storage.read(address, 64),
            Err(ContextError::Limit)
        ));
        assert!(graph.storage_error().is_some());
    }

    fn startup_prune_graph() -> (Graph, crate::Envelope, naome_proof::ProofId) {
        let mut graph = Graph::default();
        let envelope = graph
            .author("goal = all(x,eq(x,x)) proof: p0 = refl(x) p1 = gen(p0,x) return p1")
            .unwrap();
        let id = naome_proof::ProofId::from_bytes(
            crate::unhex(&envelope.proof_id)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            graph
                .ingest(envelope.clone(), std::time::Instant::now())
                .unwrap()
                .status,
            "accepted"
        );
        (graph, envelope, id)
    }

    #[test]
    fn startup_prune_checks_actual_map_formula_and_nested_bucket_rows_despite_hot_cache() {
        use naome_checker::ContextView;
        use sha2::{Digest, Sha256};
        for target in ["proof-map", "formula", "nested-bucket"] {
            for damage in ["missing", "corrupt", "oversized", "different"] {
                let (mut graph, _, id) = startup_prune_graph();
                let storage = graph.checked_storage.clone();
                let header = graph.context.proof_header(id).unwrap().unwrap();
                let formula = graph
                    .context
                    .statement_formula(
                        header.statement_id(),
                        naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES,
                    )
                    .unwrap()
                    .unwrap()
                    .encode_canonical()
                    .unwrap();
                let mut raw = Vec::new();
                let domain: &[u8] = if target == "formula" {
                    raw = formula;
                    b"naome:checked-formula-storage:v1\0"
                } else {
                    // Identify a real live authenticated leaf; none is inserted by this fixture.
                    raw.extend_from_slice(&[1, 0]);
                    if target == "proof-map" {
                        raw.extend_from_slice(id.as_bytes());
                        raw.extend_from_slice(&40u16.to_be_bytes());
                        raw.extend_from_slice(header.derivation_id().as_bytes());
                        raw.extend_from_slice(
                            &(graph.context.proof_dependency_depth(id).unwrap().unwrap() as u64)
                                .to_be_bytes(),
                        );
                    } else {
                        raw.extend_from_slice(header.statement_id().as_bytes());
                        raw.extend_from_slice(&0u16.to_be_bytes());
                    }
                    b"naome:checked-map:storage:v1\0"
                };
                let mut hash = Sha256::new();
                hash.update(domain);
                hash.update(&raw);
                let address: [u8; 32] = hash.finalize().into();
                assert_eq!(storage.read(address, raw.len()).unwrap(), raw, "{target}");
                {
                    let guard = storage.connection.lock().unwrap();
                    let connection = guard.open().unwrap();
                    let changed = match damage {
                        "missing" => connection
                            .execute("DELETE FROM nodes WHERE address=?1", [address.as_slice()]),
                        "corrupt" => connection.execute(
                            "UPDATE nodes SET payload=zeroblob(length(payload)) WHERE address=?1",
                            [address.as_slice()],
                        ),
                        "oversized" => connection.execute(
                            "UPDATE nodes SET payload=zeroblob(?2) WHERE address=?1",
                            params![
                                address.as_slice(),
                                i64::try_from(
                                    raw.len().checked_add(codec::HEADER_BYTES + 1).unwrap()
                                )
                                .unwrap()
                            ],
                        ),
                        "different" => {
                            let mut different = raw.clone();
                            *different.last_mut().unwrap() ^= 1;
                            connection.execute(
                                "UPDATE nodes SET payload=?2 WHERE address=?1",
                                params![address.as_slice(), codec::encode(&different).unwrap()],
                            )
                        }
                        _ => unreachable!(),
                    }
                    .unwrap();
                    assert_eq!(changed, 1, "{target}/{damage}");
                }
                // This proves that the ordinary source read still has the correct hot value.
                assert_eq!(storage.read(address, raw.len()).unwrap(), raw);
                let persistent = || {
                    let guard = storage.connection.lock().unwrap();
                    let connection = guard.open().unwrap();
                    let count: i64 = connection
                        .query_row("SELECT count(*) FROM nodes", [], |row| row.get(0))
                        .unwrap();
                    let bytes: Option<Vec<u8>> = connection
                        .query_row(
                            "SELECT payload FROM nodes WHERE address=?1",
                            [address.as_slice()],
                            |row| row.get(0),
                        )
                        .optional()
                        .unwrap();
                    (count, bytes)
                };
                let before = persistent();
                let root = graph.content_root();
                let snapshot = graph.context.snapshot_id();
                assert!(
                    graph.prune_startup_checked_storage_at(0).is_err(),
                    "{target}/{damage}"
                );
                assert!(graph.storage_error().is_some());
                assert_eq!(
                    persistent(),
                    before,
                    "marking must neither insert nor repair {target}/{damage}"
                );
                assert_eq!(graph.content_root(), root);
                assert_eq!(graph.context.snapshot_id(), snapshot);
                assert_eq!(graph.accepted_count(), 1);
            }
        }
    }

    #[test]
    fn startup_prune_clears_same_generation_tags_and_drains_the_physical_freelist() {
        use naome_checker::ContextView;
        let (mut graph, envelope, id) = startup_prune_graph();
        let storage = graph.checked_storage.clone();
        let generation = storage.generation;
        let root = graph.content_root();
        let snapshot = graph.context.snapshot_id();
        let mut last = ([0; 32], Vec::new());
        storage.begin_write_phase().unwrap();
        for index in 0u64..64 {
            let mut address = [0xa5; 32];
            address[..8].copy_from_slice(&index.to_be_bytes());
            let mut state = index + 1;
            let bytes: Vec<_> = (0..8192)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            storage.write(address, &bytes).unwrap();
            last = (address, bytes);
        }
        storage.finish_write_phase().unwrap();
        assert_eq!(storage.read(last.0, last.1.len()).unwrap(), last.1);
        let before = storage.allocated_bytes().unwrap();
        let before_file = fs::metadata(&storage.path).unwrap();
        assert!(storage.cache.lock().unwrap().charged > 0);
        let live = graph.prune_startup_checked_storage_at(0).unwrap().unwrap();
        assert!(Arc::ptr_eq(&storage, &graph.checked_storage));
        assert_eq!(storage.generation, generation);
        {
            let cache = storage.cache.lock().unwrap();
            assert!(cache.entries.is_empty() && cache.recency.is_empty());
            assert_eq!(cache.charged, 0);
            assert_eq!(cache.clock, 0);
        }
        let after_file = fs::metadata(&storage.path).unwrap();
        assert!(live < before, "unused pages must actually be reclaimed");
        assert_eq!(live, storage.allocated_bytes().unwrap());
        assert!(after_file.len() < before_file.len());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(after_file.ino(), before_file.ino());
            assert!(after_file.blocks() < before_file.blocks());
        }
        {
            let guard = storage.connection.lock().unwrap();
            let connection = guard.open().unwrap();
            assert!(connection.is_autocommit());
            assert_eq!(
                connection
                    .pragma_query_value(None, "auto_vacuum", |row| row.get::<_, i64>(0))
                    .unwrap(),
                2
            );
            assert_eq!(
                connection
                    .pragma_query_value(None, "freelist_count", |row| row.get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                connection
                    .query_row("SELECT count(*) FROM startup_keep", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT count(*) FROM nodes WHERE address=?1",
                        [last.0.as_slice()],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                0
            );
        }
        // A stale same-generation cache tag would wrongly skip this SQL insertion.
        storage.write(last.0, &last.1).unwrap();
        storage.evict_cache();
        assert_eq!(storage.read(last.0, last.1.len()).unwrap(), last.1);
        assert_eq!(graph.context.snapshot_id(), snapshot);
        assert_eq!(graph.content_root(), root);
        assert_eq!(graph.object(id).unwrap(), Some(envelope));
        assert!(graph.storage_error().is_none());
    }

    #[test]
    fn startup_prune_requires_a_finished_page_and_leaves_runtime_successors_unchanged() {
        let (graph, _, _) = startup_prune_graph();
        let storage = graph.checked_storage.clone();
        assert_eq!(
            storage
                .connection
                .lock()
                .unwrap()
                .open()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name='startup_keep'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0,
            "the keep table must remain lazy for small graphs"
        );
        let successor = storage.successor().unwrap();
        assert_eq!(
            successor
                .connection
                .lock()
                .unwrap()
                .open()
                .unwrap()
                .pragma_query_value(None, "auto_vacuum", |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(
            successor
                .prune_startup(&DiskArtifactState::new(successor.clone()))
                .unwrap_err()
                .contains("incremental vacuum")
        );
        assert!(
            successor
                .connection
                .lock()
                .unwrap()
                .open()
                .unwrap()
                .is_autocommit()
        );
        drop(graph);
        drop(storage);
        drop(successor);

        let (graph, _, _) = startup_prune_graph();
        graph.checked_storage.begin_write_phase().unwrap();
        assert!(
            graph
                .checked_storage
                .prune_startup(&graph.context)
                .unwrap_err()
                .contains("finished replay page")
        );
        assert!(graph.storage_error().is_some());
        // The failed owner is discarded; journal_mode=OFF is never rolled back for reuse.
    }
}
