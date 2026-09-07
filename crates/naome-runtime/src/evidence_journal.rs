//! Optional bounded raw inbox image; never a source of signer authority.
use crate::publication_journal::{regular_options, sync_directory};
use naome_node::FixedValidatorNodeEvidenceErrorV0;
use sha2::{Digest, Sha256};
use std::{
    collections::TryReserveError,
    error::Error,
    fmt,
    fs::{self, File, TryLockError},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const IMAGE: &str = "fixed-validator-retained.evidence";
const LOCK: &str = "fixed-validator-retained.evidence.lock";
const DOMAIN: &[u8] = b"naome:fixed-validator-retained-evidence-checksum:v0\0";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorEvidenceJournalErrorV0 {
    Io(io::Error),
    Allocation(TryReserveError),
    Evidence(FixedValidatorNodeEvidenceErrorV0),
    Invalid,
    Locked,
    Poisoned,
    UnsupportedPlatform,
    AlreadyEnabled,
}
use FixedValidatorEvidenceJournalErrorV0 as Failure;
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "retained evidence journal requires strict restart: {self:?}"
        )
    }
}
impl Error for Failure {}
impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<TryReserveError> for Failure {
    fn from(e: TryReserveError) -> Self {
        Self::Allocation(e)
    }
}
impl From<FixedValidatorNodeEvidenceErrorV0> for Failure {
    fn from(e: FixedValidatorNodeEvidenceErrorV0) -> Self {
        Self::Evidence(e)
    }
}
type Result<T> = std::result::Result<T, Failure>;
struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(crate) struct EvidenceJournal {
    directory: PathBuf,
    limit: u64,
    image: Vec<u8>,
    poisoned: bool,
    _lock: Lock,
}
impl EvidenceJournal {
    pub(crate) fn open(
        directory: &Path,
        create: bool,
        initial: Vec<u8>,
        limit: u64,
    ) -> Result<Self> {
        if !cfg!(unix) {
            return Err(Failure::UnsupportedPlatform);
        }
        let lock = regular_options(true, true)
            .create(true)
            .truncate(false)
            .open(directory.join(LOCK))?;
        if !lock.metadata()?.is_file() {
            return Err(Failure::Invalid);
        }
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Failure::Locked),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        let mut owner = Self {
            directory: directory.to_owned(),
            limit,
            image: Vec::new(),
            poisoned: false,
            _lock: Lock(lock),
        };
        if create {
            owner.replace(initial, true)?;
        } else {
            let mut file = regular_options(true, false).open(directory.join(IMAGE))?;
            let metadata = file.metadata()?;
            let cap = limit.checked_add(32).ok_or(Failure::Invalid)?;
            if !metadata.is_file() || metadata.len() > cap || metadata.len() < 32 {
                return Err(Failure::Invalid);
            }
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(
                usize::try_from(metadata.len()).map_err(|_| Failure::Invalid)?,
            )?;
            Read::by_ref(&mut file)
                .take(cap.checked_add(1).ok_or(Failure::Invalid)?)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != metadata.len() {
                return Err(Failure::Invalid);
            }
            let split = bytes.len() - 32;
            if checksum(&bytes[..split]).as_slice() != &bytes[split..] {
                return Err(Failure::Invalid);
            }
            bytes.truncate(split);
            owner.image = bytes;
        }
        Ok(owner)
    }
    pub(crate) fn image(&self) -> &[u8] {
        &self.image
    }
    pub(crate) fn save(&mut self, image: Vec<u8>) -> Result<()> {
        if self.poisoned {
            return Err(Failure::Poisoned);
        }
        if self.image == image {
            return Ok(());
        }
        self.replace(image, false)
    }
    fn replace(&mut self, image: Vec<u8>, create: bool) -> Result<()> {
        if image.len() as u64 > self.limit {
            return Err(Failure::Invalid);
        }
        let digest = checksum(&image);
        self.poisoned = true;
        #[cfg(all(test, unix))]
        faults::check(faults::Stage::Create)?;
        let target = self.directory.join(IMAGE);
        let temporary = self.directory.join(format!(
            "{IMAGE}.tmp-{}-{}",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let path = if create { &target } else { &temporary };
        let mut file = regular_options(false, true).create_new(true).open(path)?;
        #[cfg(all(test, unix))]
        faults::check(faults::Stage::Write)?;
        file.write_all(&image)?;
        file.write_all(&digest)?;
        #[cfg(all(test, unix))]
        faults::check(faults::Stage::FileSync)?;
        file.sync_all()?;
        drop(file);
        if !create {
            #[cfg(all(test, unix))]
            faults::check(faults::Stage::Rename)?;
            fs::rename(&temporary, &target)?;
        }
        #[cfg(all(test, unix))]
        faults::check(faults::Stage::DirectorySync)?;
        sync_directory(&self.directory)?;
        self.image = image;
        self.poisoned = false;
        Ok(())
    }
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(bytes);
    h.finalize().into()
}

#[cfg(all(test, unix))]
mod faults {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Stage {
        Create,
        Write,
        FileSync,
        Rename,
        DirectorySync,
    }
    thread_local! {pub(super) static FAIL:std::cell::Cell<Option<Stage>>=const{std::cell::Cell::new(None)};}
    pub(super) fn check(stage: Stage) -> std::io::Result<()> {
        FAIL.with(|f| {
            if f.get() == Some(stage) {
                f.set(None);
                Err(std::io::Error::other("injected evidence image failure"))
            } else {
                Ok(())
            }
        })
    }
}
#[cfg(all(test, unix))]
mod tests;
