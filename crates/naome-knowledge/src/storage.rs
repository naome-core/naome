//! Shared local persistence primitives; domain owners retain their own records.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// Node state contains the identity key and private local owner preferences.
/// Tighten only the owned node directory, without changing parent directories.
pub(crate) fn private_directory(directory: &Path) -> Result<(), String> {
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let directory = fs::canonicalize(directory).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(&directory).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err("node state must be one owned directory".into());
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

pub(crate) fn research_directory(directory: &Path) -> Result<PathBuf, String> {
    let path = directory.join("research");
    match fs::symlink_metadata(&path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == nix::unistd::geteuid().as_raw() => {}
        Ok(_) => return Err("research path must be one owned directory".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if marker_valid(
                &directory.join("research.initialized"),
                b"naome-research-jobs-v3\n",
            )? {
                return Err("established research directory is missing; no fresh allowance".into());
            }
            fs::create_dir(&path).map_err(|e| e.to_string())?;
            File::open(directory)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
        }
        Err(e) => return Err(e.to_string()),
    }
    Ok(path)
}

pub(crate) fn marker_valid(path: &Path, expected: &[u8]) -> Result<bool, String> {
    match read_owned(path, 64)? {
        None => Ok(false),
        Some(bytes) if bytes == expected => Ok(true),
        Some(_) => Err("research initialization marker corruption".into()),
    }
}

pub(crate) fn write_marker(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(path.parent().ok_or("research marker parent absent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

/// Read one bounded local input after validating the opened descriptor. Opening
/// special files must not wait for another process before their type is known.
pub(crate) fn read_owned(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    read_input(path, limit, InputLinks::One)
}

/// Mutable configuration may be replaced after opening. Its opened generation
/// remains a coherent owned snapshot, even after the old directory entry is gone.
pub(crate) fn read_owned_snapshot(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    read_input(path, limit, InputLinks::Snapshot)
}

#[derive(Clone, Copy)]
enum InputLinks {
    One,
    Snapshot,
}

fn read_input(path: &Path, limit: usize, links: InputLinks) -> Result<Option<Vec<u8>>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    read_descriptor(file, limit, links).map(Some)
}

fn read_descriptor(file: File, limit: usize, links: InputLinks) -> Result<Vec<u8>, String> {
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    require_input_owned(&metadata, links)?;
    let mut bytes = Vec::new();
    let maximum = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or("local input read limit")?;
    file.take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("local input byte capacity".into());
    }
    Ok(bytes)
}

pub(crate) fn owned_file(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require_owned(&metadata)?;
    Ok(metadata)
}
fn require_owned(metadata: &fs::Metadata) -> Result<(), String> {
    require_input_owned(metadata, InputLinks::One)
}

fn require_input_owned(metadata: &fs::Metadata, links: InputLinks) -> Result<(), String> {
    let links_valid = match links {
        InputLinks::One => metadata.nlink() == 1,
        // Atomic replacement can unlink this already-open generation. It has
        // no pathname aliases; multiple hard links remain invalid.
        InputLinks::Snapshot => metadata.nlink() <= 1,
    };
    if !metadata.is_file() || !links_valid || metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err("local store must be one owned regular file".into());
    }
    Ok(())
}
pub(crate) fn sqlite_common(
    connection: &rusqlite::Connection,
    cache_bytes: usize,
) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(crate::resources::limits().sqlite_busy_timeout)?;
    connection
        .execute_batch("PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA trusted_schema=OFF;")?;
    connection.pragma_update(None, "cache_size", sqlite_cache_kib(cache_bytes)?)
}

pub(crate) fn sqlite_cache_kib(bytes: usize) -> rusqlite::Result<i64> {
    i64::try_from((bytes / 1024).max(1))
        .map(|kib| -kib)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

/// Only volatile cache policy changes here. Journaling, synchronization, schema
/// trust and integrity checks remain owned by each persistence implementation.
pub(crate) fn sqlite_adapt(
    connection: &rusqlite::Connection,
    bytes: usize,
) -> rusqlite::Result<()> {
    let desired = sqlite_cache_kib(bytes)?;
    let current: i64 = connection.pragma_query_value(None, "cache_size", |row| row.get(0))?;
    if desired != current {
        connection.pragma_update(None, "cache_size", desired)?;
        if desired > current {
            connection.execute_batch("PRAGMA shrink_memory")?;
        }
    }
    Ok(())
}

/// The exact inode and physical write generation owned by a serialized store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileGeneration {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl FileGeneration {
    pub(crate) fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

#[cfg(test)]
mod tests;
