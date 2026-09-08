use std::{fs::File, io::Read, path::Path};

#[cfg(unix)]
use rustix::fs::OFlags;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use zeroize::Zeroizing;

use super::Result;

#[cfg(windows)]
mod windows;
#[cfg(any(windows, test))]
mod windows_acl;

pub(super) fn bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    // Inspect the opened descriptor. NONBLOCK prevents a FIFO open from
    // hanging before that inspection; NOFOLLOW rejects the final symlink.
    let file = regular(path)?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file_read")?;
    if bytes.len() > maximum {
        return Err("file_too_large");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn regular(path: &Path) -> Result<File> {
    let file = File::options()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| "file_open")?;
    if !file.metadata().map_err(|_| "file_metadata")?.is_file() {
        return Err("file_not_regular");
    }
    Ok(file)
}

#[cfg(windows)]
fn regular(path: &Path) -> Result<File> {
    windows::regular(path)
}

pub(super) fn seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let file = regular(path)?;
    #[cfg(unix)]
    {
        let metadata = file.metadata().map_err(|_| "seed_metadata")?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err("seed_permissions");
        }
    }
    #[cfg(windows)]
    windows::private(&file)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    file.take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| "seed_read")?;
    if bytes.len() != 32 {
        return Err("seed_length");
    }
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&bytes);
    Ok(seed)
}
