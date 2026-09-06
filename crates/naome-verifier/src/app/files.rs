use std::{fs::File, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

use rustix::fs::OFlags;

use super::Result;

pub(super) fn bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    // Inspect the opened descriptor. NONBLOCK prevents a FIFO open from
    // hanging before that inspection; NOFOLLOW rejects the final symlink.
    let file = File::options()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| "file_open")?;
    if !file.metadata().map_err(|_| "file_metadata")?.is_file() {
        return Err("file_not_regular");
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file_read")?;
    if bytes.len() > maximum {
        return Err("file_too_large");
    }
    Ok(bytes)
}
