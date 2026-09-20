//! Platform durability primitives shared by canonical history and signer logs.
#[cfg(unix)]
use std::fs::File;
use std::{fmt, fs::OpenOptions, io, path::Path};
#[cfg(windows)]
mod windows;

pub(crate) fn durable_open_options() -> OpenOptions {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
        let mut options = OpenOptions::new();
        options.custom_flags(FILE_FLAG_WRITE_THROUGH);
        options
    }
    #[cfg(not(windows))]
    {
        OpenOptions::new()
    }
}

pub(crate) fn require_finality_platform(directory: &Path) -> Result<(), StoragePlatformError> {
    #[cfg(windows)]
    {
        windows::require_local_ntfs(directory)
            .map_err(|source| StoragePlatformError::Open { source })
    }
    #[cfg(not(windows))]
    {
        let _ = directory;
        require_durable_directory_sync()
    }
}

pub(crate) fn sync_finality_file(
    directory: &Path,
    file_name: &str,
) -> Result<(), StoragePlatformError> {
    require_finality_platform(directory)?;
    sync_file_binding(directory, file_name).map_err(|source| StoragePlatformError::Write { source })
}

fn sync_file_binding(directory: &Path, file_name: &str) -> io::Result<()> {
    #[cfg(windows)]
    {
        // Flush the destination's data AND metadata after replacement, or on
        // strict reopen. A source handle's flags do not govern a later rename.
        durable_open_options()
            .read(true)
            .write(true)
            .open(directory.join(file_name))?
            .sync_all()
    }
    #[cfg(not(windows))]
    {
        let _ = file_name;
        sync_directory_platform(directory)
    }
}

#[cfg(unix)]
fn sync_directory_platform(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(any(unix, windows)))]
fn sync_directory_platform(_directory: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable parent-directory synchronization is unavailable on this platform",
    ))
}

#[cfg(not(windows))]
fn require_durable_directory_sync() -> Result<(), StoragePlatformError> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(StoragePlatformError::UnsupportedDurableDirectorySync)
    }
}

/// A platform cannot provide the required durable file binding.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoragePlatformError {
    UnsupportedDurableDirectorySync,
    Open { source: io::Error },
    Write { source: io::Error },
}
impl fmt::Display for StoragePlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDurableDirectorySync => {
                f.write_str("this platform cannot provide durable parent-directory synchronization")
            }
            Self::Open { source } => write!(f, "cannot establish storage durability: {source}"),
            Self::Write { source } => write!(f, "cannot synchronize storage binding: {source}"),
        }
    }
}
impl std::error::Error for StoragePlatformError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open { source } | Self::Write { source } => Some(source),
            Self::UnsupportedDurableDirectorySync => None,
        }
    }
}
