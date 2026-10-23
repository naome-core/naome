//! Shared local persistence primitives; domain owners retain their own records.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

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

fn read_owned(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("research checkpoint must be one regular owned file".into());
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).map_err(|_| "research read limit")? + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("research checkpoint byte capacity".into());
    }
    Ok(Some(bytes))
}

pub(crate) fn owned_file(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("local store must be one owned regular file".into());
    }
    Ok(metadata)
}
pub(crate) fn sqlite_common(
    connection: &rusqlite::Connection,
    cache_bytes: usize,
) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(crate::resources::limits().sqlite_busy_timeout)?;
    connection
        .execute_batch("PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA trusted_schema=OFF;")?;
    connection.pragma_update(
        None,
        "cache_size",
        -i64::try_from((cache_bytes / 1024).max(1))
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
    )
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
