//! File locking and ordered durable frame writes shared by storage owners.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

pub(crate) enum ExclusiveLockError {
    LockFile(io::Error),
    Locked,
    Lock(io::Error),
}

pub(crate) fn open_exclusive_lock(
    directory: &Path,
    file_name: &str,
) -> Result<File, ExclusiveLockError> {
    let lock_path = directory.join(file_name);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(ExclusiveLockError::LockFile)?;

    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(ExclusiveLockError::Locked),
        Err(TryLockError::Error(source)) => Err(ExclusiveLockError::Lock(source)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AppendPhase {
    Body,
    Commit,
}

pub(crate) trait StoreIo: Read + Write + Seek {
    fn set_len(&mut self, size: u64) -> io::Result<()>;
    fn sync_all(&mut self) -> io::Result<()>;

    fn append_write_all(&mut self, _phase: AppendPhase, bytes: &[u8]) -> io::Result<()> {
        self.write_all(bytes)
    }

    fn append_sync_all(&mut self, _phase: AppendPhase) -> io::Result<()> {
        self.sync_all()
    }
}

impl StoreIo for File {
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        File::set_len(self, size)
    }

    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

pub(crate) fn append_body_and_commit<F: StoreIo>(
    file: &mut F,
    body_segments: &[&[u8]],
    commit: &[u8],
) -> io::Result<()> {
    for bytes in body_segments {
        file.append_write_all(AppendPhase::Body, bytes)?;
    }
    file.append_sync_all(AppendPhase::Body)?;
    file.append_write_all(AppendPhase::Commit, commit)?;
    file.append_sync_all(AppendPhase::Commit)
}
