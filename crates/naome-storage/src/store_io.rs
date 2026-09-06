//! File locking and ordered durable frame writes shared by storage owners.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

#[derive(Debug)]
pub(crate) enum ExclusiveLockError {
    LockFile(io::Error),
    Locked,
    Lock(io::Error),
}

/// Owns only a successfully acquired lock; never exposes or clones its file.
#[derive(Debug)]
pub(crate) struct ExclusiveLock(File);

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        // Closing alone can retain a Unix flock while an incidental fork still
        // holds the shared file description. Windows also permits delayed
        // release on close. Explicitly unlock before File's close fallback.
        // Drop cannot report an OS unlock error; the file is still closed.
        let _ = self.0.unlock();
    }
}

pub(crate) fn open_exclusive_lock(
    directory: &Path,
    file_name: &str,
) -> Result<ExclusiveLock, ExclusiveLockError> {
    let lock_path = directory.join(file_name);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(ExclusiveLockError::LockFile)?;

    match lock.try_lock() {
        Ok(()) => Ok(ExclusiveLock(lock)),
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

#[cfg(test)]
mod lock_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "naome-storage-lock-release-{}-{sequence}",
                    std::process::id()
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => panic!("temporary test directory failed: {source}"),
                }
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn owner_drop_releases_lock_with_an_open_duplicate() {
        let directory = TestDirectory::new();
        let owner = open_exclusive_lock(&directory.0, "owner.lock").unwrap();
        // A safe duplicate deterministically models a shared file description
        // retained across a Unix fork, without relying on fork/exec timing.
        // The same guard lifecycle is exercised on Windows as well.
        let duplicate = owner.0.try_clone().unwrap();
        for _ in 0..2 {
            let contender = open_exclusive_lock(&directory.0, "owner.lock");
            assert!(
                matches!(contender, Err(ExclusiveLockError::Locked)),
                "{contender:?}"
            );
        }
        // A rejected contender must not unlock the live owner's lock.
        drop(owner);
        let successor = open_exclusive_lock(&directory.0, "owner.lock")
            .expect("owner drop must release the lock even with an open duplicate");
        drop(duplicate);
        let contender = open_exclusive_lock(&directory.0, "owner.lock");
        assert!(
            matches!(contender, Err(ExclusiveLockError::Locked)),
            "{contender:?}"
        );
        drop(successor);
        drop(open_exclusive_lock(&directory.0, "owner.lock").unwrap());
    }

    #[test]
    fn unwinding_releases_lock_with_an_open_duplicate() {
        let directory = TestDirectory::new();
        let owner = open_exclusive_lock(&directory.0, "owner.lock").unwrap();
        let duplicate = owner.0.try_clone().unwrap();
        let result = std::panic::catch_unwind(move || {
            let _owner = owner;
            panic!("simulate failure while owning a lock");
        });
        assert!(result.is_err());
        let successor = open_exclusive_lock(&directory.0, "owner.lock")
            .expect("unwinding must release the lock before the duplicate closes");
        drop(duplicate);
        drop(successor);
    }
}
