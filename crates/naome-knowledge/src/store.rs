use crate::Envelope;
use naome_proof::ProofId;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

mod catalog;
use catalog::Catalog;
pub(crate) use catalog::Summary;

pub(crate) const DATABASE_FILE: &str = "proof-corpus.sqlite3";
pub(crate) const COMMIT_DEADLINE_ERROR: &str =
    "catalog commit deadline expired before durable commit";
const FORMAT_FILE: &str = "proof-corpus.format";
const FORMAT_MAGIC: &[u8; 8] = b"NAOCORP3";
const INITIAL_DATABASE: &str = ".proof-corpus-initializing.sqlite3";
#[cfg(test)]
std::thread_local! { static FORMAT_SYNC_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// One locked canonical catalog. An immutable receipt binds its durable lineage.
pub(crate) struct Store {
    directory: PathBuf,
    _lock: File,
    database_identity: fs::Metadata,
    catalog: Mutex<Catalog>,
    #[cfg(test)]
    cut: Mutex<Option<BatchCut>>,
    #[cfg(test)]
    replay_cut: Mutex<Option<ReplayCut>>,
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
    pub fn open(directory: &Path) -> Result<Self, String> {
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        let directory = fs::canonicalize(directory).map_err(|error| error.to_string())?;
        let directory = directory.as_path();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("knowledge.lock"))
            .map_err(|error| error.to_string())?;
        lock.try_lock()
            .map_err(|error| format!("knowledge directory already owned: {error}"))?;
        reject_legacy_objects(directory)?;
        let database = directory.join(DATABASE_FILE);
        let receipt = directory.join(FORMAT_FILE);
        let has_receipt = catalog_leaf_exists(&receipt)?;
        let has_database = catalog_leaf_exists(&database)?;
        let catalog = if has_receipt {
            let id = read_format(&receipt)?;
            if !has_database {
                return Err("activated proof catalog missing".into());
            }
            Catalog::open(&database, id)?
        } else if has_database {
            // A crash may interrupt initial receipt creation, but only an
            // inactive, fully identified staging database can resume it.
            let id = Catalog::inspect_identity(&database)?;
            let catalog = Catalog::open(&database, id)?;
            if catalog.active()? {
                return Err("active proof catalog format receipt missing".into());
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
                return Err("unexpected accepted data in catalog initialization stage".into());
            }
            drop(catalog);
            File::open(&incoming)
                .and_then(|file| file.sync_all())
                .map_err(|error| error.to_string())?;
            fs::rename(&incoming, &database).map_err(|error| error.to_string())?;
            sync_directory(directory)?;
            write_format(directory, id)?;
            Catalog::open(&database, id)?
        };
        // SQL configuration/schema checks are not mathematical validity.
        let _ = catalog.identity()?;
        Ok(Self {
            directory: directory.to_path_buf(),
            _lock: lock,
            database_identity: fs::symlink_metadata(&database)
                .map_err(|error| error.to_string())?,
            catalog: Mutex::new(catalog),
            #[cfg(test)]
            cut: Mutex::new(None),
            #[cfg(test)]
            replay_cut: Mutex::new(None),
        })
    }

    fn ensure_database(&self) -> Result<(), String> {
        let current = fs::symlink_metadata(self.directory.join(DATABASE_FILE))
            .map_err(|error| format!("proof catalog disappeared during ownership: {error}"))?;
        if !current.is_file() {
            return Err("proof catalog file replaced during ownership".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.nlink() != 1
                || current.dev() != self.database_identity.dev()
                || current.ino() != self.database_identity.ino()
            {
                return Err("proof catalog file replaced during ownership".into());
            }
        }
        Ok(())
    }

    pub(crate) fn summary(&self) -> Result<Summary, String> {
        self.ensure_database()?;
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        catalog.summary()
    }

    pub(crate) fn replay_page(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<(u64, Envelope)>, String> {
        self.ensure_database()?;
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        catalog.replay_page(after, limit)
    }

    pub(crate) fn ids_page(
        &self,
        after: Option<ProofId>,
        limit: usize,
        expected: Summary,
    ) -> Result<Vec<ProofId>, String> {
        self.ensure_database()?;
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        catalog.ids_page(after, limit, expected)
    }

    pub(crate) fn get(&self, id: ProofId, expected: Summary) -> Result<Option<Envelope>, String> {
        self.ensure_database()?;
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        catalog.get(id, expected)
    }

    pub(crate) fn contains(&self, id: ProofId, expected: Summary) -> Result<bool, String> {
        self.ensure_database()?;
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        catalog.contains(id, expected)
    }

    /// Small test fixtures may collect a corpus; production callers use pages.
    #[cfg(test)]
    pub(crate) fn load(&self) -> Result<Vec<Envelope>, String> {
        let summary = self.summary()?;
        if summary.count > catalog::MAX_BATCH_OBJECTS {
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
                objects.push(object);
            }
        }
        if objects.len() != summary.count {
            return Err("test fixture catalog count differs".into());
        }
        Ok(objects)
    }

    /// Only Graph calls this after rechecking every proof mathematically.
    pub(crate) fn finish_replay(&self, root: [u8; 32]) -> Result<(), String> {
        self.ensure_database()?;
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        #[cfg(test)]
        self.fail_replay(ReplayCut::BeforeActivation)?;
        catalog.activate(root)?;
        #[cfg(test)]
        self.fail_replay(ReplayCut::AfterActivation)?;
        Ok(())
    }

    pub(crate) fn persist_checked(
        &self,
        object: &Envelope,
        expected: Summary,
    ) -> Result<Summary, String> {
        let root = ProofId::from_bytes(crate::object::id_bytes(&object.proof_id)?);
        self.persist_batch_checked(root, std::iter::once(object), expected, None)
    }
    pub(crate) fn persist_batch_checked<'a>(
        &self,
        root: ProofId,
        objects: impl Iterator<Item = &'a Envelope>,
        expected: Summary,
        deadline: Option<Instant>,
    ) -> Result<Summary, String> {
        self.ensure_database()?;
        let mut batch = Vec::new();
        for object in objects {
            if batch.len() >= catalog::MAX_BATCH_OBJECTS {
                return Err("catalog batch object count limit".into());
            }
            batch.push(object);
        }
        let catalog = self
            .catalog
            .lock()
            .map_err(|_| "proof catalog lock poisoned")?;
        #[cfg(test)]
        let cut = *self.cut.lock().map_err(|_| "test cut lock poisoned")?;
        #[cfg(not(test))]
        let cut = None;
        catalog.persist(root, &batch, expected, deadline, cut)
    }

    #[cfg(test)]
    pub(crate) fn persist(&self, object: &Envelope) -> Result<Summary, String> {
        self.persist_checked(object, self.summary()?)
    }

    #[cfg(test)]
    pub(crate) fn persist_batch<'a>(
        &self,
        root: ProofId,
        objects: impl Iterator<Item = &'a Envelope>,
    ) -> Result<Summary, String> {
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
    fn fail_replay(&self, cut: ReplayCut) -> Result<(), String> {
        if *self.replay_cut.lock().unwrap() == Some(cut) {
            Err("injected replay cut".into())
        } else {
            Ok(())
        }
    }
}

fn reject_legacy_objects(directory: &Path) -> Result<(), String> {
    match fs::symlink_metadata(directory.join("objects")) {
        Ok(_) => Err("unsupported legacy proof corpus objects namespace".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect legacy proof corpus namespace: {error}"
        )),
    }
}

fn catalog_leaf_exists(path: &Path) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect proof corpus leaf: {error}")),
    };
    if !metadata.is_file() {
        return Err("proof corpus leaf must be a regular unaliased file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("proof corpus leaf has linked aliases".into());
        }
    }
    Ok(true)
}

fn new_identity(directory: &Path) -> Result<[u8; 32], String> {
    let mut hash = Sha256::new();
    hash.update(b"naome:proof-catalog-lineage:v1\0");
    hash.update(directory.to_string_lossy().as_bytes());
    hash.update(std::process::id().to_be_bytes());
    hash.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
            .to_be_bytes(),
    );
    Ok(hash.finalize().into())
}
fn read_format(path: &Path) -> Result<[u8; 32], String> {
    let mut bytes = Vec::new();
    receipt_file(path, false)?
        .take(73)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() != 72 || &bytes[..8] != FORMAT_MAGIC || bytes[8..40] != crate::compatibility() {
        return Err("unsupported or corrupt proof corpus format receipt".into());
    }
    bytes[40..]
        .try_into()
        .map_err(|_| "proof corpus format identity width".into())
}
fn write_format(directory: &Path, id: [u8; 32]) -> Result<(), String> {
    let mut bytes = FORMAT_MAGIC.to_vec();
    bytes.extend_from_slice(&crate::compatibility());
    bytes.extend_from_slice(&id);
    let pending = directory.join(".proof-corpus-format-incoming");
    if pending.exists() {
        let mut previous = Vec::new();
        receipt_file(&pending, false)?
            .take(73)
            .read_to_end(&mut previous)
            .map_err(|error| error.to_string())?;
        if previous.len() < bytes.len() && bytes.starts_with(&previous) {
            // Only a strictly identified inactive catalog reaches recovery.
            // A partial temporary receipt establishes no lineage or validity.
            let mut file = receipt_file(&pending, true)?;
            file.set_len(0).map_err(|error| error.to_string())?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| error.to_string())?;
        } else if previous != bytes {
            return Err("conflicting proof corpus format recovery receipt".into());
        }
    } else {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&pending)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
    }
    // Previously complete bytes may have survived only in the page cache after
    // a failed sync. Every retry must synchronize them before publication.
    #[cfg(test)]
    if FORMAT_SYNC_FAILURE.get() {
        return Err("injected format receipt sync failure".into());
    }
    receipt_file(&pending, false)?
        .sync_all()
        .map_err(|error| error.to_string())?;
    fs::rename(&pending, directory.join(FORMAT_FILE)).map_err(|error| error.to_string())?;
    sync_directory(directory)
}
fn receipt_file(path: &Path, write: bool) -> Result<File, String> {
    let before = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !before.is_file() {
        return Err("proof corpus receipt must be a regular unaliased file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if before.nlink() != 1 {
            return Err("proof corpus receipt has linked aliases".into());
        }
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(|error| error.to_string())?;
        if !opened.is_file()
            || opened.nlink() != 1
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
        {
            return Err("proof corpus receipt identity changed".into());
        }
    }
    Ok(file)
}
fn sync_directory(directory: &Path) -> Result<(), String> {
    #[cfg(unix)]
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(())
}
pub(crate) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("non-regular file".into());
    }
    if metadata.len() > maximum as u64 {
        return Err("file byte limit".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > maximum {
        return Err("file byte limit".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn corrupt_payload(directory: &Path, proof: &str) {
    let database = rusqlite::Connection::open(directory.join(DATABASE_FILE)).unwrap();
    assert_eq!(
        database
            .execute(
                "UPDATE proofs SET payload=zeroblob(length(payload)) WHERE id=?1",
                rusqlite::params![crate::unhex(proof).unwrap()]
            )
            .unwrap(),
        1
    );
}

#[cfg(test)]
pub(crate) fn payload_bytes(directory: &Path, proof: &str) -> Vec<u8> {
    let database = rusqlite::Connection::open(directory.join(DATABASE_FILE)).unwrap();
    database
        .query_row(
            "SELECT payload FROM proofs WHERE id=?1",
            rusqlite::params![crate::unhex(proof).unwrap()],
            |row| row.get(0),
        )
        .unwrap()
}
