use std::collections::TryReserveError;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;

#[derive(Debug)]
pub(crate) enum ExclusiveLockError {
    Locked,
    Io(io::Error),
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

pub(crate) enum BoundedReadError {
    Open(io::Error),
    Read(io::Error),
    TooLong { actual: usize, maximum: usize },
    Allocation(TryReserveError),
}

pub(crate) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, BoundedReadError> {
    let file = File::open(path).map_err(BoundedReadError::Open)?;
    let length =
        usize::try_from(file.metadata().map_err(BoundedReadError::Read)?.len()).map_err(|_| {
            BoundedReadError::TooLong {
                actual: usize::MAX,
                maximum,
            }
        })?;
    if length > maximum {
        return Err(BoundedReadError::TooLong {
            actual: length,
            maximum,
        });
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(BoundedReadError::Allocation)?;
    file.take(
        u64::try_from(maximum.checked_add(1).expect("the snapshot cap is bounded"))
            .expect("the snapshot cap fits in u64"),
    )
    .read_to_end(&mut bytes)
    .map_err(BoundedReadError::Read)?;
    if bytes.len() > maximum {
        return Err(BoundedReadError::TooLong {
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(bytes)
}

pub(crate) fn open_exclusive(
    directory: &Path,
    lock_file_name: &str,
) -> Result<ExclusiveLock, ExclusiveLockError> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(lock_file_name))
        .map_err(ExclusiveLockError::Io)?;
    match lock.try_lock() {
        Ok(()) => Ok(ExclusiveLock(lock)),
        Err(TryLockError::WouldBlock) => Err(ExclusiveLockError::Locked),
        Err(TryLockError::Error(source)) => Err(ExclusiveLockError::Io(source)),
    }
}

pub(crate) fn replace_synced(
    directory: &Path,
    temporary_file_name: &str,
    snapshot_file_name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let temporary_path = directory.join(temporary_file_name);
    let mut temporary = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary_path)?;
    temporary.write_all(bytes)?;
    temporary.sync_all()?;
    fs::rename(temporary_path, directory.join(snapshot_file_name))?;
    sync_directory(directory)
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    // std exposes no safe portable parent-directory synchronization contract
    // on every non-Unix target. File contents are synchronized before rename.
    Ok(())
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
                    "naome-network-lock-release-{}-{sequence}",
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
        let owner = open_exclusive(&directory.0, "owner.lock").unwrap();
        // A safe duplicate deterministically models a shared file description
        // retained across a Unix fork, without relying on fork/exec timing.
        // The same guard lifecycle is exercised on Windows as well.
        let duplicate = owner.0.try_clone().unwrap();
        for _ in 0..2 {
            let contender = open_exclusive(&directory.0, "owner.lock");
            assert!(
                matches!(contender, Err(ExclusiveLockError::Locked)),
                "{contender:?}"
            );
        }
        // A rejected contender must not unlock the live owner's lock.
        drop(owner);
        let successor = open_exclusive(&directory.0, "owner.lock")
            .expect("owner drop must release the lock even with an open duplicate");
        drop(duplicate);
        let contender = open_exclusive(&directory.0, "owner.lock");
        assert!(
            matches!(contender, Err(ExclusiveLockError::Locked)),
            "{contender:?}"
        );
        drop(successor);
        drop(open_exclusive(&directory.0, "owner.lock").unwrap());
    }

    #[test]
    fn unwinding_releases_lock_with_an_open_duplicate() {
        let directory = TestDirectory::new();
        let owner = open_exclusive(&directory.0, "owner.lock").unwrap();
        let duplicate = owner.0.try_clone().unwrap();
        let result = std::panic::catch_unwind(move || {
            let _owner = owner;
            panic!("simulate failure while owning a lock");
        });
        assert!(result.is_err());
        let successor = open_exclusive(&directory.0, "owner.lock")
            .expect("unwinding must release the lock before the duplicate closes");
        drop(duplicate);
        drop(successor);
    }
}
