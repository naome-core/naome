//! Disposable authenticated bytes for local indexes. The catalog is replayed
//! at startup; this file never restores mathematical validity or authority.
use naome_checker::{ContextError, ContextStorage};
use sha2::{Digest, Sha256};
use std::{
    collections::hash_map::RandomState,
    fs::{self, File, OpenOptions},
    hash::BuildHasher,
    io::{self, Read},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

const MAGIC: &[u8; 16] = b"NAOME-INDEX\0\0\0\0\0";
const SLOT_BYTES: u64 = 48;
const FIRST_TABLE: u64 = 4096;
const INITIAL_SLOTS: u64 = 64;
const IO_RESERVE: u64 = 64 * 1024;
const MAX_SEGMENTS: usize = 64;
const MAX_PROBES: u64 = 1024;

#[derive(Clone, Copy)]
struct Segment {
    table: u64,
    capacity: u64,
    count: u64,
}
impl Segment {
    const EMPTY: Self = Self {
        table: 0,
        capacity: 0,
        count: 0,
    };
}

#[cfg(test)]
thread_local! {
    static TEST_FAIL_AFTER_RECORD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct IndexLease(crate::storage::LockFile);
impl Drop for IndexLease {
    fn drop(&mut self) {
        // A helper can temporarily inherit a descriptor. Only the last live
        // generation owns the explicit lock handoff.
        let _ = self.0.file().unlock();
    }
}

struct NativeIndex {
    file: File,
    generation: crate::storage::FileGeneration,
    hash: RandomState,
    segments: [Segment; MAX_SEGMENTS],
    segment_count: usize,
    end: u64,
    _memory: Arc<crate::resources::MemoryLease>,
}

pub(crate) struct IndexStorage {
    state: Mutex<Option<NativeIndex>>,
    path: PathBuf,
    identity: (u64, u64),
    error: Mutex<Option<ContextError>>,
    _lease: Arc<IndexLease>,
    label: String,
    mirror: Mutex<Option<Arc<Self>>>,
}
impl IndexStorage {
    pub(crate) fn open(directory: &Path, label: &str) -> Result<Arc<Self>, crate::Error> {
        let root = crate::storage::research_directory(directory)?;
        let lease_path = root.join(format!(".disposable-{label}.lock"));
        let lease = crate::storage::LockFile::open(&lease_path)?;
        lease.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => crate::InputFault::DisposableIndexOwned.into(),
            std::fs::TryLockError::Error(error) => crate::Error::from(error),
        })?;
        let prefix = format!(".disposable-{label}-");
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".index"))
                && disposable(&entry.path())?
            {
                fs::remove_file(entry.path())?;
            }
        }
        Self::fresh(&root, label, Arc::new(IndexLease(lease)))
    }

    fn fresh(root: &Path, label: &str, lease: Arc<IndexLease>) -> Result<Arc<Self>, crate::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| crate::InputFault::DisposableIndexSequence)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| crate::InputFault::DisposableIndexClock)?
            .as_nanos();
        let path = root.join(format!(
            ".disposable-{label}-{}-{nonce}-{sequence}.index",
            std::process::id()
        ));
        let end = FIRST_TABLE + INITIAL_SLOTS * SLOT_BYTES;
        let memory = crate::resources::MemoryLease::acquire(4096)?;
        let initial = end
            .checked_add(reservation_overhead(root)?)
            .ok_or(crate::InputFault::DisposableIndexSize)?;
        let _disk = crate::resources::DiskLease::acquire(root, initial)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&path)?;
        file.write_all_at(MAGIC, 0)?;
        file.set_len(end)?;
        let path = fs::canonicalize(path)?;
        let metadata = crate::storage::owned_file(&path)?;
        let opened = file.metadata()?;
        let generation = crate::storage::FileGeneration::of(&metadata);
        if generation != crate::storage::FileGeneration::of(&opened) {
            return Err(crate::InputFault::DisposableIndexChanged.into());
        }
        let mut segments = [Segment::EMPTY; MAX_SEGMENTS];
        segments[0] = Segment {
            table: FIRST_TABLE,
            capacity: INITIAL_SLOTS,
            count: 0,
        };
        Ok(Arc::new(Self {
            state: Mutex::new(Some(NativeIndex {
                file,
                generation,
                hash: RandomState::new(),
                segments,
                segment_count: 1,
                end,
                _memory: memory,
            })),
            path,
            identity: (metadata.dev(), metadata.ino()),
            error: Mutex::new(None),
            _lease: lease,
            label: label.to_owned(),
            mirror: Mutex::new(None),
        }))
    }

    pub(crate) fn directory(&self) -> &Path {
        self.path.parent().expect("index parent")
    }
    pub(crate) fn successor(&self) -> Result<Arc<Self>, crate::Error> {
        Self::fresh(
            self.path
                .parent()
                .ok_or(crate::InputFault::DisposableIndexParent)?,
            &self.label,
            self._lease.clone(),
        )
    }
    pub(crate) fn mirror_to(&self, target: Arc<Self>) -> Result<(), crate::Error> {
        let _state = self
            .state
            .lock()
            .map_err(|_| crate::InputFault::DisposableIndexConnectionPoisoned)?;
        let mut mirror = self
            .mirror
            .lock()
            .map_err(|_| crate::InputFault::DisposableIndexMirrorPoisoned)?;
        if mirror.is_some() {
            return Err(crate::InputFault::DisposableIndexMirrorActive.into());
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
    pub(crate) fn allocated_bytes(&self) -> Result<usize, crate::Error> {
        let state = self
            .state
            .lock()
            .map_err(|_| crate::InputFault::DisposableIndexConnectionPoisoned)?;
        let state = state
            .as_ref()
            .ok_or(crate::InputFault::DisposableIndexClosed)?;
        self.live(state)
            .map_err(|_| crate::InputFault::DisposableIndexChanged)?;
        let physical = state
            .file
            .metadata()?
            .blocks()
            .checked_mul(512)
            .ok_or(crate::InputFault::DisposableIndexSize)?;
        usize::try_from(state.end.max(physical))
            .map_err(|_| crate::InputFault::DisposableIndexSize.into())
    }
    pub(crate) fn error(&self) -> Option<ContextError> {
        self.error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn live(&self, state: &NativeIndex) -> Result<(), ContextError> {
        if let Some(error) = self.error() {
            return Err(error);
        }
        let path = crate::storage::owned_file(&self.path).map_err(|_| {
            ContextError::Storage(naome_proof::ContextStorageFailure::OwnerUnavailable)
        })?;
        // The descriptor was bound to this inode when the generation opened;
        // the owned pathname's metadata also describes that same inode.
        if crate::storage::FileGeneration::of(&path) != state.generation {
            return Err(ContextError::Corrupt);
        }
        Ok(())
    }
}

impl NativeIndex {
    fn slot_offset(&self, table: u64, bucket: u64) -> Result<u64, ContextError> {
        bucket
            .checked_mul(SLOT_BYTES)
            .and_then(|v| table.checked_add(v))
            .ok_or(ContextError::Limit)
    }
    fn lookup(
        &self,
        table: u64,
        capacity: u64,
        address: &[u8; 32],
    ) -> Result<(u64, Option<(u64, u64)>), ContextError> {
        let mut bucket = self.hash.hash_one(address) & (capacity - 1);
        let mut slot = [0u8; 48];
        for _ in 0..capacity.min(MAX_PROBES) {
            self.file
                .read_exact_at(&mut slot, self.slot_offset(table, bucket)?)
                .map_err(system)?;
            let offset = u64::from_be_bytes(slot[32..40].try_into().expect("slot width"));
            let length = u64::from_be_bytes(slot[40..48].try_into().expect("slot width"));
            if offset == 0 {
                if slot[..32].iter().any(|byte| *byte != 0) || length != 0 {
                    return Err(ContextError::Corrupt);
                }
                return Ok((bucket, None));
            }
            if &slot[..32] == address {
                return Ok((bucket, Some((offset - 1, length))));
            }
            bucket = (bucket + 1) & (capacity - 1);
        }
        Err(ContextError::Limit)
    }
    fn find(&self, address: &[u8; 32]) -> Result<Option<(u64, u64)>, ContextError> {
        for segment in self.segments[..self.segment_count].iter().rev() {
            let (_, found) = self.lookup(segment.table, segment.capacity, address)?;
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }
    fn read_value(
        &self,
        address: &[u8; 32],
        offset: u64,
        length: u64,
        maximum: usize,
    ) -> Result<Vec<u8>, ContextError> {
        let length = usize::try_from(length).map_err(|_| ContextError::Limit)?;
        if length > maximum {
            return Err(ContextError::Limit);
        }
        let record_length = length.checked_add(32).ok_or(ContextError::Limit)?;
        let record_end = offset
            .checked_add(u64::try_from(record_length).map_err(|_| ContextError::Limit)?)
            .ok_or(ContextError::Corrupt)?;
        if offset < FIRST_TABLE || record_end > self.end {
            return Err(ContextError::Corrupt);
        }
        let mut record = vec![0; record_length];
        self.file
            .read_exact_at(&mut record, offset)
            .map_err(system)?;
        let expected = value_digest(address, &record[32..]);
        if record[..32] != expected {
            return Err(ContextError::Corrupt);
        }
        record.copy_within(32.., 0);
        record.truncate(length);
        Ok(record)
    }
    fn grow(&mut self) -> Result<(), ContextError> {
        if self.segment_count == MAX_SEGMENTS {
            return Err(ContextError::Limit);
        }
        let previous = self.segments[self.segment_count - 1];
        let capacity = previous
            .capacity
            .checked_mul(2)
            .ok_or(ContextError::Limit)?;
        let table_bytes = capacity
            .checked_mul(SLOT_BYTES)
            .ok_or(ContextError::Limit)?;
        let table = self.end;
        let end = table.checked_add(table_bytes).ok_or(ContextError::Limit)?;
        self.file.set_len(end).map_err(system)?;
        self.segments[self.segment_count] = Segment {
            table,
            capacity,
            count: 0,
        };
        self.segment_count += 1;
        self.end = end;
        Ok(())
    }
}

impl ContextStorage for IndexStorage {
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        let work = maximum
            .checked_mul(2)
            .and_then(|n| n.checked_add(64))
            .ok_or(ContextError::Limit)?;
        let _memory =
            crate::resources::MemoryLease::acquire(work).map_err(|_| ContextError::Limit)?;
        let state = self.state.lock().map_err(|_| ContextError::Corrupt)?;
        let state = state.as_ref().ok_or(ContextError::Corrupt)?;
        self.live(state)?;
        let (offset, length) = state.find(&address)?.ok_or(ContextError::Corrupt)?;
        let bytes = state.read_value(&address, offset, length, maximum)?;
        self.live(state)?;
        Ok(bytes)
    }
    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        let memory = bytes.len().checked_add(64).ok_or(ContextError::Limit)?;
        let _memory =
            crate::resources::MemoryLease::acquire(memory).map_err(|_| ContextError::Limit)?;
        let mut guard = self.state.lock().map_err(|_| ContextError::Corrupt)?;
        let state = guard.as_mut().ok_or(ContextError::Corrupt)?;
        self.live(state)?;
        let existing = state.find(&address)?;
        if let Some((offset, length)) = existing {
            if u64::try_from(bytes.len()).ok() != Some(length) {
                return Err(ContextError::Corrupt);
            }
            if state.read_value(&address, offset, length, bytes.len())? != bytes {
                return Err(ContextError::Corrupt);
            }
            self.live(state)?;
        } else {
            let active = state.segments[state.segment_count - 1];
            let grow = active.count.checked_mul(2).ok_or(ContextError::Limit)? >= active.capacity;
            let table_bytes = if grow {
                active
                    .capacity
                    .checked_mul(2)
                    .and_then(|n| n.checked_mul(SLOT_BYTES))
                    .ok_or(ContextError::Limit)?
            } else {
                0
            };
            let record_bytes = u64::try_from(bytes.len())
                .map_err(|_| ContextError::Limit)?
                .checked_add(32)
                .ok_or(ContextError::Limit)?;
            let overhead = reservation_overhead(self.directory()).map_err(system)?;
            let reserve = table_bytes
                .checked_add(record_bytes)
                .and_then(|n| n.checked_add(overhead))
                .ok_or(ContextError::Limit)?;
            let _disk = crate::resources::DiskLease::acquire(self.directory(), reserve)
                .map_err(disk_error)?;
            let result = (|| {
                if grow {
                    state.grow()?;
                }
                let active = state.segments[state.segment_count - 1];
                let (bucket, found) = state.lookup(active.table, active.capacity, &address)?;
                if found.is_some() {
                    return Err(ContextError::Corrupt);
                }
                let offset = state.end;
                let end = offset
                    .checked_add(record_bytes)
                    .ok_or(ContextError::Limit)?;
                let mut record = Vec::with_capacity(bytes.len() + 32);
                record.extend_from_slice(&value_digest(&address, bytes));
                record.extend_from_slice(bytes);
                state.file.write_all_at(&record, offset).map_err(system)?;
                #[cfg(test)]
                if TEST_FAIL_AFTER_RECORD.with(|fail| fail.replace(false)) {
                    return Err(system(io::Error::from_raw_os_error(nix::libc::ENOSPC)));
                }
                #[cfg(test)]
                if std::env::var_os("NAOME_TEST_EXIT_INDEX_WRITE")
                    .is_some_and(|marker| Path::new(&marker).is_file())
                {
                    std::process::exit(79);
                }
                let mut slot = [0u8; 48];
                slot[..32].copy_from_slice(&address);
                slot[32..40].copy_from_slice(
                    &offset
                        .checked_add(1)
                        .ok_or(ContextError::Limit)?
                        .to_be_bytes(),
                );
                slot[40..48].copy_from_slice(
                    &u64::try_from(bytes.len())
                        .map_err(|_| ContextError::Limit)?
                        .to_be_bytes(),
                );
                state
                    .file
                    .write_all_at(&slot, state.slot_offset(active.table, bucket)?)
                    .map_err(system)?;
                state.segments[state.segment_count - 1].count =
                    active.count.checked_add(1).ok_or(ContextError::Limit)?;
                state.end = end;
                state.generation =
                    crate::storage::FileGeneration::of(&state.file.metadata().map_err(system)?);
                self.live(state)
            })();
            if let Err(error) = result {
                // A failed write may have changed the disposable file. Never
                // serve it again until the canonical catalog is replayed.
                *self.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
                return Err(error);
            }
        }
        let mirror = self
            .mirror
            .lock()
            .map_err(|_| ContextError::Corrupt)?
            .clone();
        if let Some(mirror) = mirror {
            mirror.write(address, bytes)?;
        }
        drop(guard);
        Ok(())
    }
    fn record_failure(&self, error: &ContextError) {
        if !matches!(error, ContextError::Limit) {
            *self.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
        }
    }
}
impl Drop for IndexStorage {
    fn drop(&mut self) {
        self.state
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if owned(&self.path).ok() == Some(self.identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn value_digest(address: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:disposable-index-value\0");
    hash.update(address);
    hash.update(bytes);
    hash.finalize().into()
}
fn disposable(path: &Path) -> Result<bool, crate::Error> {
    let identity = owned(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if (metadata.dev(), metadata.ino()) != identity {
        return Err(crate::InputFault::DisposableIndexChanged.into());
    }
    let mut header = [0; MAGIC.len()];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    if owned(path)? != identity {
        return Err(crate::InputFault::DisposableIndexChanged.into());
    }
    Ok(&header == MAGIC)
}
fn owned(path: &Path) -> Result<(u64, u64), crate::Error> {
    let metadata = crate::storage::owned_file(path)?;
    Ok((metadata.dev(), metadata.ino()))
}
fn system(error: io::Error) -> ContextError {
    ContextError::Storage(naome_proof::ContextStorageFailure::System(
        error.raw_os_error(),
    ))
}
fn reservation_overhead(path: &Path) -> io::Result<u64> {
    let stats = nix::sys::statvfs::statvfs(path)
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let block = stats.block_size().max(stats.fragment_size());
    block
        .checked_mul(4)
        .map(|bytes| bytes.max(IO_RESERVE))
        .ok_or_else(|| io::Error::other("index reservation overflow"))
}
fn disk_error(error: crate::Error) -> ContextError {
    match error {
        crate::Error::DiskOverload { .. } | crate::Error::ExecutionLimit => ContextError::Limit,
        crate::Error::Io { os_code, .. } | crate::Error::StorageIo { os_code, .. } => {
            ContextError::Storage(naome_proof::ContextStorageFailure::System(
                os_code.map(|n| n.get()),
            ))
        }
        _ => ContextError::Storage(naome_proof::ContextStorageFailure::System(None)),
    }
}

#[cfg(test)]
mod tests;
