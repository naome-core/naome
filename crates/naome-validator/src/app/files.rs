use std::{fs::File, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

use rustix::fs::OFlags;
use std::os::unix::fs::MetadataExt;
use zeroize::Zeroizing;

use super::Result;

fn regular(path: &Path) -> Result<File> {
    // NONBLOCK makes opening a FIFO safe before examining the same descriptor.
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

/// Compare and stabilize the same regular descriptor before authorizing reuse.
pub(super) fn match_and_sync(path: &Path, expected: &[u8]) -> Result<bool> {
    let mut file = regular(path)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file_read")?;
    if bytes != expected {
        return Ok(false);
    }
    file.sync_all().map_err(|_| "file_sync")?;
    Ok(true)
}

pub(super) fn bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    bytes_u64(path, maximum as u64)
}

pub(super) fn bytes_u64(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = regular(path)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|_| "file_read")?;
    // Probe the same descriptor without adding to or narrowing a full-width cap.
    if bytes.len() as u64 == maximum && file.read(&mut [0]).map_err(|_| "file_read")? != 0 {
        return Err("file_too_large");
    }
    Ok(bytes)
}

pub(super) fn seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let file = regular(path)?;
    let metadata = file.metadata().map_err(|_| "seed_metadata")?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err("seed_permissions");
    }
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
