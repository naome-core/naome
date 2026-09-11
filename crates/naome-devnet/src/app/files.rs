use super::Result;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

pub(super) fn directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

pub(super) fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or("parent directory")?)?.sync_all()?;
    Ok(())
}

pub(super) fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    // All paths are local operator inputs, never remote manifest paths.
    let file = File::options()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("expected regular local file".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err("local file limit".into());
    }
    Ok(bytes)
}

pub(super) fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let pending = path.with_extension("pending");
    create(&pending, bytes)?;
    fs::rename(pending, path)?;
    File::open(path.parent().ok_or("parent directory")?)?.sync_all()?;
    Ok(())
}
