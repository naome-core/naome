use std::collections::TryReserveError;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;

pub(crate) enum ExclusiveLockError {
    Locked,
    Io(io::Error),
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
) -> Result<File, ExclusiveLockError> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(lock_file_name))
        .map_err(ExclusiveLockError::Io)?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
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
