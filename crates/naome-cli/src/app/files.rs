use super::Result;
use ed25519_dalek::SigningKey;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected exact-width hexadecimal identifier".into());
    }
    let mut bytes = [0; N];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}
pub fn random() -> Result<Zeroizing<[u8; 32]>> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|e| format!("secure random source: {e}"))?;
    Ok(bytes)
}
pub fn directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
pub fn read(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("input is not a bounded regular file".into());
    }
    if private
        && (metadata.mode() & 0o077 != 0 || metadata.uid() != rustix::process::geteuid().as_raw())
    {
        return Err("private file must belong to this user with mode 0600".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("input grew beyond its size limit".into());
    }
    Ok(bytes)
}
/// No overwrite: a durable same-directory staging file is linked into place.
/// A crash leaves either the previous destination or a complete new file.
pub fn create(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".naome-stage-{}", hex(random()?.as_ref())));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if private { 0o600 } else { 0o644 })
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let cleanup = fs::remove_file(&temporary);
    result?;
    cleanup?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn create_or_match(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    if path.try_exists()? {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() != bytes.len() as u64
            || (private
                && (metadata.mode() & 0o077 != 0
                    || metadata.uid() != rustix::process::geteuid().as_raw()))
        {
            return Err("existing output is not the expected bounded private file".into());
        }
        let mut existing = Zeroizing::new(Vec::new());
        (&mut file)
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut existing)?;
        if existing.as_slice() != bytes {
            return Err(
                "existing output has different content; preserve it and choose a new path".into(),
            );
        }
        // A prior failed creation may have linked the name without acknowledging
        // the directory sync. Reaffirm both before any dependent transmission.
        file.sync_all()?;
        File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        return Ok(());
    }
    create(path, bytes, private)
}
pub fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let _ = read(path, 16384, true)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".naome-replace-{}", hex(random()?.as_ref())));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
pub fn write_key(path: &Path, role: u8) -> Result<SigningKey> {
    let seed = random()?;
    let key = SigningKey::from_bytes(&seed);
    let mut bytes = Zeroizing::new(Vec::with_capacity(41));
    bytes.extend_from_slice(b"NSKEY001");
    bytes.push(role);
    bytes.extend_from_slice(seed.as_ref());
    create(path, &bytes, true)?;
    Ok(key)
}
pub fn key(path: &Path, role: u8) -> Result<SigningKey> {
    let bytes = Zeroizing::new(read(path, 41, true)?);
    if bytes.len() != 41 || &bytes[..8] != b"NSKEY001" || bytes[8] != role {
        return Err("key role or format mismatch".into());
    }
    let seed = Zeroizing::new(<[u8; 32]>::try_from(&bytes[9..])?);
    Ok(SigningKey::from_bytes(&seed))
}
pub fn available(path: &Path) -> Result<u64> {
    let stat = rustix::fs::statvfs(path)?;
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or_else(|| "free-space arithmetic overflow".into())
}

#[cfg(test)]
mod tests;
