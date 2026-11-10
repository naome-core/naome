#[cfg(test)]
use crate::Envelope;
use crate::object::BinaryArtifact;
use naome_proof::ArtifactId;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

mod catalog;
mod program;
use catalog::Catalog;
pub(crate) use catalog::Summary;
#[cfg(test)]
pub(crate) use catalog::program::manifest_reads;
#[cfg(test)]
pub(crate) use catalog::{payload_reads, set_scan_count};
pub(crate) use naome_proof::program::Progress as ProgramProgress;

pub(crate) const DATABASE_FILE: &str = "proof-corpus.sqlite3";
pub(crate) const COMMIT_DEADLINE_ERROR: crate::Error = crate::Error::Deadline;
pub(crate) struct Publication<'a> {
    pub root: ArtifactId,
    pub questions: &'a BTreeMap<ArtifactId, Vec<u8>>,
}
const FORMAT_FILE: &str = "proof-corpus.format";
const FORMAT_MAGIC: &[u8; 8] = b"NAOCORP\0";
const INITIAL_DATABASE: &str = ".proof-corpus-initializing.sqlite3";
#[cfg(test)]
std::thread_local! { static FORMAT_SYNC_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// One locked canonical catalog. An immutable receipt binds its durable lineage.
pub(crate) struct Store {
    directory: PathBuf,
    database_generation: Mutex<crate::storage::FileGeneration>,
    catalog: Mutex<Catalog>,
    #[cfg(test)]
    cut: Mutex<Option<BatchCut>>,
    #[cfg(test)]
    replay_cut: Mutex<Option<ReplayCut>>,
    // Close catalog state before releasing this owner's directory authority.
    _lock: DirectoryLock,
}

struct DirectoryLock(crate::storage::LockFile);
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        // A child spawning concurrently can temporarily inherit this open-file
        // description. Closing only our descriptor would leave its lock alive.
        let _ = self.0.file().unlock();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchCut {
    BeforeWrite,
    DuringWrite,
    BeforeCommit,
    AfterCommit,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayCut {
    BeforeActivation,
    AfterActivation,
}

impl Store {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn open(directory: &Path) -> Result<Self, crate::Error> {
        crate::storage::private_directory(directory)?;
        let directory = fs::canonicalize(directory).map_err(|error| {
            crate::error::storage_io_error(crate::StorageIoOperation::ResolveParent, error)
        })?;
        let directory = directory.as_path();
        let lock = crate::storage::LockFile::open(&directory.join("knowledge.lock"))
            .map_err(crate::Error::from)?;
        lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => crate::InputFault::CatalogDirectoryOwned.into(),
            std::fs::TryLockError::Error(error) => crate::error::storage_io_error(
                crate::StorageIoOperation::AcquireDirectoryLock,
                error,
            ),
        })?;
        let lock = DirectoryLock(lock);
        let database = directory.join(DATABASE_FILE);
        let receipt = directory.join(FORMAT_FILE);
        let has_receipt = catalog_leaf_exists(&receipt)?;
        let has_database = catalog_leaf_exists(&database)?;
        let catalog = if has_receipt {
            let id = read_format(&receipt)?;
            if !has_database {
                return Err(crate::InputFault::CatalogActivatedMissing.into());
            }
            Catalog::open(&database, id)?
        } else if has_database {
            // A crash may interrupt initial receipt creation, but only an
            // inactive, fully identified staging database can resume it.
            let id = Catalog::inspect_identity(&database)?;
            let catalog = Catalog::open(&database, id)?;
            if catalog.active()? {
                return Err(crate::InputFault::CatalogReceiptMissing.into());
            }
            write_format(directory, id)?;
            catalog
        } else {
            let incoming = directory.join(INITIAL_DATABASE);
            let (id, catalog) = match Catalog::inspect_identity(&incoming) {
                Ok(id) => (id, Catalog::open(&incoming, id)?),
                Err(_) => {
                    let id = new_identity(directory)?;
                    (id, Catalog::initialize_stage(&incoming, id)?)
                }
            };
            if catalog.active()? || catalog.summary()?.count != 0 {
                return Err(crate::InputFault::CatalogStageAcceptedData.into());
            }
            drop(catalog);
            File::open(&incoming)
                .and_then(|file| file.sync_all())
                .map_err(|error| {
                    crate::error::storage_io_error(crate::StorageIoOperation::SyncStage, error)
                })?;
            fs::rename(&incoming, &database).map_err(|error| {
                crate::error::storage_io_error(crate::StorageIoOperation::Publish, error)
            })?;
            sync_directory(directory)?;
            write_format(directory, id)?;
            Catalog::open(&database, id)?
        };
        // SQL configuration/schema checks are not mathematical validity.
        let _ = catalog.identity()?;
        Ok(Self {
            directory: directory.to_path_buf(),
            _lock: lock,
            database_generation: Mutex::new(crate::storage::FileGeneration::of(
                &fs::symlink_metadata(&database).map_err(|error| {
                    crate::error::storage_io_error(
                        crate::StorageIoOperation::InspectOwnedFile,
                        error,
                    )
                })?,
            )),
            catalog: Mutex::new(catalog),
            #[cfg(test)]
            cut: Mutex::new(None),
            #[cfg(test)]
            replay_cut: Mutex::new(None),
        })
    }

    fn ensure_database(&self) -> Result<(), crate::Error> {
        let current = crate::storage::owned_file(&self.directory.join(DATABASE_FILE))?;
        let expected = self
            .database_generation
            .lock()
            .map_err(|_| crate::InputFault::CatalogGenerationPoisoned)?;
        if crate::storage::FileGeneration::of(&current) != *expected {
            return Err(crate::Error::from(crate::InputFault::CatalogFileChanged).fatal_storage());
        }
        Ok(())
    }
    fn record_generation(&self) -> Result<(), crate::Error> {
        let metadata =
            crate::storage::owned_file(&self.directory.join(DATABASE_FILE)).map_err(|_| {
                crate::Error::UncertainDurability(crate::DurabilityFailure::new(
                    crate::DurabilityCode::CatalogGeneration,
                ))
            })?;
        *self.database_generation.lock().map_err(|_| {
            crate::Error::UncertainDurability(crate::DurabilityFailure::new(
                crate::DurabilityCode::CatalogGeneration,
            ))
        })? = crate::storage::FileGeneration::of(&metadata);
        Ok(())
    }

    pub(crate) fn summary(&self) -> Result<Summary, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.summary()
    }

    /// Read an explicitly unverified admission count under directory custody.
    /// This neither replays proofs nor creates a checked catalog generation.
    pub(crate) fn stored_count(&self) -> Result<usize, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.stored_count()
    }

    pub(crate) fn replay_page(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<(u64, BinaryArtifact)>, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.replay_page(after, limit)
    }

    pub(crate) fn ids_page(
        &self,
        after: Option<ArtifactId>,
        limit: usize,
        expected: Summary,
    ) -> Result<Vec<ArtifactId>, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.ids_page(after, limit, expected)
    }

    pub(crate) fn peer_learning_page(
        &self,
        after: u64,
        limit: usize,
        expected: Summary,
    ) -> Result<Vec<(u64, ArtifactId, Option<libp2p::PeerId>)>, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.peer_learning_page(after, limit, expected)
    }
    pub(crate) fn inventory_page(
        &self,
        after: Option<crate::corpus::InventoryCursor>,
        limit: usize,
        expected: Summary,
    ) -> Result<Option<crate::corpus::InventoryPage>, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.inventory_page(after, limit, expected)
    }

    pub(crate) fn get_binary(
        &self,
        id: ArtifactId,
        expected: Summary,
    ) -> Result<Option<BinaryArtifact>, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.get(id, expected)
    }

    #[cfg(test)]
    pub(crate) fn get(
        &self,
        id: ArtifactId,
        expected: Summary,
    ) -> Result<Option<Envelope>, crate::Error> {
        self.get_binary(id, expected)
            .map(|object| object.map(|object| object.envelope()))
    }

    pub(crate) fn contains(&self, id: ArtifactId, expected: Summary) -> Result<bool, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.contains(id, expected)
    }

    pub(crate) fn exchange_question(
        &self,
        id: ArtifactId,
        expected: Summary,
    ) -> Result<Option<Vec<u8>>, crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        catalog.exchange_question(id, expected)
    }

    /// Small test fixtures may collect a corpus; production callers use pages.
    #[cfg(test)]
    pub(crate) fn load(&self) -> Result<Vec<Envelope>, crate::Error> {
        let summary = self.summary()?;
        if summary.count > crate::resources::limits().batch_objects {
            return Err("test fixture collection limit".into());
        }
        let mut objects = Vec::with_capacity(summary.count);
        let mut after = 0;
        loop {
            let page = self.replay_page(after, 64)?;
            if page.is_empty() {
                break;
            }
            for (ordinal, object) in page {
                after = ordinal;
                objects.push(object.envelope());
            }
        }
        if objects.len() != summary.count {
            return Err("test fixture catalog count differs".into());
        }
        Ok(objects)
    }

    /// Only Graph calls this after rechecking every proof mathematically.
    pub(crate) fn finish_replay(&self, root: [u8; 32]) -> Result<(), crate::Error> {
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        #[cfg(test)]
        self.fail_replay(ReplayCut::BeforeActivation)?;
        catalog.activate(root)?;
        self.record_generation()?;
        #[cfg(test)]
        self.fail_replay(ReplayCut::AfterActivation)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn persist_checked(
        &self,
        object: &Envelope,
        expected: Summary,
    ) -> Result<Summary, crate::Error> {
        let root = ArtifactId::from_bytes(crate::object::id_bytes(&object.artifact_id)?);
        self.persist_batch_checked(root, std::iter::once(object), expected, None)
    }
    #[cfg(test)]
    pub(crate) fn persist_batch_checked<'a>(
        &self,
        root: ArtifactId,
        objects: impl Iterator<Item = &'a Envelope>,
        expected: Summary,
        deadline: Option<Instant>,
    ) -> Result<Summary, crate::Error> {
        let objects = objects
            .map(|object| object.clone().prepare().map(|c| c.record()))
            .collect::<Result<Vec<_>, _>>()?;
        self.persist_records(
            Publication {
                root,
                questions: &BTreeMap::new(),
            },
            objects.iter(),
            expected,
            deadline,
            None,
            None,
        )
    }

    pub(crate) fn persist_binary_batch<'a>(
        &self,
        root: Publication<'_>,
        objects: impl Iterator<Item = &'a BinaryArtifact>,
        expected: Summary,
        deadline: Option<Instant>,
        next_root: [u8; 32],
        guard: Option<&crate::publication::CommitGuard>,
    ) -> Result<Summary, crate::Error> {
        self.persist_records(root, objects, expected, deadline, Some(next_root), guard)
    }

    fn persist_records<'a>(
        &self,
        root: Publication<'_>,
        objects: impl Iterator<Item = &'a BinaryArtifact>,
        expected: Summary,
        deadline: Option<Instant>,
        next_root: Option<[u8; 32]>,
        guard: Option<&crate::publication::CommitGuard>,
    ) -> Result<Summary, crate::Error> {
        let mut batch = Vec::new();
        for object in objects {
            if batch.len() >= crate::resources::limits().batch_objects {
                return Err(crate::InputFault::CatalogBatchCount.into());
            }
            batch.push(object);
        }
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| crate::InputFault::CatalogLockPoisoned)?;
        self.ensure_database()?;
        #[cfg(test)]
        let cut = *self.cut.lock().map_err(|_| "test cut lock poisoned")?;
        #[cfg(not(test))]
        let cut = None;
        let result = catalog.persist(
            root,
            &batch,
            catalog::Commit {
                expected,
                deadline,
                cut,
                next_root,
                guard,
                peer: guard
                    .and_then(|guard| guard.peer_origin())
                    .map(|peer| peer.to_string()),
            },
        );
        // Physical generation follows every owned transaction, including a
        // rollback or ambiguous COMMIT. This grants no checked membership:
        // Graph remains halted on uncertain durability and replay is mandatory.
        match (result, self.record_generation()) {
            (Err(primary @ crate::Error::UncertainDurability(_)), Err(_)) => Err(primary),
            (_, Err(generation)) => Err(generation),
            (result, Ok(())) => result,
        }
    }

    #[cfg(test)]
    pub(crate) fn persist(&self, object: &Envelope) -> Result<Summary, crate::Error> {
        self.persist_checked(object, self.summary()?)
    }

    #[cfg(test)]
    pub(crate) fn persist_batch<'a>(
        &self,
        root: ArtifactId,
        objects: impl Iterator<Item = &'a Envelope>,
    ) -> Result<Summary, crate::Error> {
        self.persist_batch_checked(root, objects, self.summary()?, None)
    }
    #[cfg(test)]
    pub(crate) fn set_cut(&self, cut: BatchCut) {
        *self.cut.lock().unwrap() = Some(cut);
    }
    #[cfg(test)]
    pub(crate) fn limit_current_pages(&self) {
        let catalog = self.catalog.lock().unwrap();
        let pages = catalog.page_count().unwrap();
        catalog.set_max_page_count(pages).unwrap();
    }
    #[cfg(test)]
    pub(crate) fn set_replay_cut(&self, cut: ReplayCut) {
        *self.replay_cut.lock().unwrap() = Some(cut);
    }
    #[cfg(test)]
    fn fail_replay(&self, cut: ReplayCut) -> Result<(), crate::Error> {
        if *self.replay_cut.lock().unwrap() == Some(cut) {
            Err("injected replay cut".into())
        } else {
            Ok(())
        }
    }
}

fn catalog_leaf_exists(path: &Path) -> Result<bool, crate::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(crate::error::storage_io_error(
                crate::StorageIoOperation::InspectOwnedFile,
                error,
            ));
        }
    };
    if !metadata.is_file() {
        return Err(crate::InputFault::CorpusLeafType.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(crate::InputFault::CorpusLeafLinks.into());
        }
    }
    Ok(true)
}

fn new_identity(directory: &Path) -> Result<[u8; 32], crate::Error> {
    let mut hash = Sha256::new();
    hash.update(b"naome:proof-catalog-lineage\0");
    hash.update(directory.to_string_lossy().as_bytes());
    hash.update(std::process::id().to_be_bytes());
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crate::InputFault::CatalogClock)?
            .as_nanos()
            .to_be_bytes(),
    );
    Ok(hash.finalize().into())
}
fn read_format(path: &Path) -> Result<[u8; 32], crate::Error> {
    let mut bytes = Vec::new();
    receipt_file(path, false)?
        .take(73)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            crate::error::storage_io_error(crate::StorageIoOperation::ReadInput, error)
        })?;
    if bytes.len() != 72 || &bytes[..8] != FORMAT_MAGIC || bytes[8..40] != crate::compatibility() {
        return Err(crate::InputFault::CorpusReceiptInvalid.into());
    }
    bytes[40..]
        .try_into()
        .map_err(|_| crate::Error::from(crate::InputFault::CorpusReceiptWidth))
}
fn write_format(directory: &Path, id: [u8; 32]) -> Result<(), crate::Error> {
    let mut bytes = FORMAT_MAGIC.to_vec();
    bytes.extend_from_slice(&crate::compatibility());
    bytes.extend_from_slice(&id);
    let pending = directory.join(".proof-corpus-format-incoming");
    if pending.exists() {
        let mut previous = Vec::new();
        receipt_file(&pending, false)?
            .take(73)
            .read_to_end(&mut previous)
            .map_err(|error| {
                crate::error::storage_io_error(crate::StorageIoOperation::ReadInput, error)
            })?;
        if previous.len() < bytes.len() && bytes.starts_with(&previous) {
            // Only a strictly identified inactive catalog reaches recovery.
            // A partial temporary receipt establishes no lineage or validity.
            let mut file = receipt_file(&pending, true)?;
            file.set_len(0).map_err(|error| {
                crate::error::storage_io_error(crate::StorageIoOperation::WriteMarker, error)
            })?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| {
                    crate::error::storage_io_error(crate::StorageIoOperation::WriteMarker, error)
                })?;
        } else if previous != bytes {
            return Err(crate::InputFault::CorpusReceiptConflict.into());
        }
    } else {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&pending)
            .map_err(|error| {
                crate::error::storage_io_error(crate::StorageIoOperation::CreateMarker, error)
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| {
                crate::error::storage_io_error(crate::StorageIoOperation::WriteMarker, error)
            })?;
    }
    // Previously complete bytes may have survived only in the page cache after
    // a failed sync. Every retry must synchronize them before publication.
    #[cfg(test)]
    if FORMAT_SYNC_FAILURE.get() {
        return Err("injected format receipt sync failure".into());
    }
    receipt_file(&pending, false)?.sync_all().map_err(|error| {
        crate::error::storage_io_error(crate::StorageIoOperation::SyncMarker, error)
    })?;
    fs::rename(&pending, directory.join(FORMAT_FILE)).map_err(|error| {
        crate::error::storage_io_error(crate::StorageIoOperation::Publish, error)
    })?;
    sync_directory(directory)
}
fn receipt_file(path: &Path, write: bool) -> Result<File, crate::Error> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        crate::error::storage_io_error(crate::StorageIoOperation::InspectOwnedFile, error)
    })?;
    if !before.is_file() {
        return Err(crate::InputFault::CorpusReceiptType.into());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if before.nlink() != 1 {
            return Err(crate::InputFault::CorpusReceiptLinks.into());
        }
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| {
        crate::error::storage_io_error(crate::StorageIoOperation::OpenInput, error)
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(|error| {
            crate::error::storage_io_error(crate::StorageIoOperation::InspectInput, error)
        })?;
        if !opened.is_file()
            || opened.nlink() != 1
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
        {
            return Err(crate::InputFault::CorpusReceiptChanged.into());
        }
    }
    Ok(file)
}
fn sync_directory(directory: &Path) -> Result<(), crate::Error> {
    #[cfg(unix)]
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            crate::error::storage_io_error(crate::StorageIoOperation::SyncParent, error)
        })?;
    Ok(())
}
pub(crate) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, crate::Error> {
    let file = File::open(path).map_err(|error| {
        bounded_file_error(
            crate::RuntimeFailure::BoundedFileOpen,
            crate::StorageIoOperation::OpenInput,
            error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        bounded_file_error(
            crate::RuntimeFailure::BoundedFileMetadata,
            crate::StorageIoOperation::InspectInput,
            error,
        )
    })?;
    if !metadata.is_file() {
        return Err(crate::Error::InputFault(
            crate::InputFault::RegularFileRequired,
        ));
    }
    if metadata.len() > maximum as u64 {
        return Err(crate::Error::InputLimit(
            crate::InputLimit::BoundedFileBytes,
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            bounded_file_error(
                crate::RuntimeFailure::BoundedFileRead,
                crate::StorageIoOperation::ReadInput,
                error,
            )
        })?;
    if bytes.len() > maximum {
        return Err(crate::Error::InputLimit(
            crate::InputLimit::BoundedFileBytes,
        ));
    }
    Ok(bytes)
}

fn bounded_file_error(
    code: crate::RuntimeFailure,
    operation: crate::StorageIoOperation,
    error: std::io::Error,
) -> crate::Error {
    crate::Error::RuntimeContext {
        code,
        cause: Box::new(crate::error::storage_io_error(operation, error)),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn corrupt_payload(directory: &Path, proof: &str) {
    let database = rusqlite::Connection::open(directory.join(DATABASE_FILE)).unwrap();
    assert_eq!(
        database
            .execute(
                "UPDATE artifacts SET payload=zeroblob(length(payload)) WHERE id=?1",
                rusqlite::params![crate::unhex(proof).unwrap()]
            )
            .unwrap(),
        1
    );
}

#[cfg(test)]
pub(crate) fn payload_bytes(directory: &Path, proof: &str) -> Vec<u8> {
    let database = rusqlite::Connection::open(directory.join(DATABASE_FILE)).unwrap();
    let (encoded, length): (Vec<u8>, u32) = database
        .query_row(
            "SELECT payload,payload_length FROM artifacts WHERE id=?1",
            rusqlite::params![crate::unhex(proof).unwrap()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    catalog::codec::decode(&encoded, length as usize).unwrap()
}
