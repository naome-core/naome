//! Durable prepared payment requests. Only the selected ledger admits effects.
use naome_ledger::{MAX_RECORD_BYTES, SignedTransaction, TransactionId};
use std::{fs, path::Path};

const DIRECTORY: &str = "wallet-payments";

pub(super) fn save(directory: &Path, payment: &SignedTransaction) -> Result<TransactionId, String> {
    let id = payment.id().map_err(|error| error.to_string())?;
    let directory = request_directory(directory, true)?;
    let name = id.to_string();
    let bytes = serde_json::to_vec(payment).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err("payment request byte capacity".into());
    }
    if let Some(existing) = crate::storage::read_owned(&directory.join(&name), MAX_RECORD_BYTES)? {
        if bytes != existing {
            return Err("payment request identity collision".into());
        }
        super::sync(&directory)?;
        super::sync(
            directory
                .parent()
                .ok_or("payment directory parent absent")?,
        )?;
        return Ok(id);
    }
    let incoming = format!(".{name}-incoming");
    if crate::storage::read_owned(&directory.join(&incoming), MAX_RECORD_BYTES)?.is_some() {
        fs::remove_file(directory.join(&incoming)).map_err(|error| error.to_string())?;
    }
    super::write_new(&directory, &incoming, &bytes)?;
    fs::rename(directory.join(&incoming), directory.join(name))
        .map_err(|error| error.to_string())?;
    super::sync(&directory)?;
    // The new request directory must also survive a process/host restart.
    super::sync(
        directory
            .parent()
            .ok_or("payment directory parent absent")?,
    )?;
    Ok(id)
}

pub(super) fn read(directory: &Path, id: TransactionId) -> Result<SignedTransaction, String> {
    let directory = request_directory(directory, false)?;
    let bytes = crate::storage::read_owned(&directory.join(id.to_string()), MAX_RECORD_BYTES)?
        .ok_or("prepared payment request is missing; restore its record")?;
    let payment: SignedTransaction =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if payment
        .verify_signature()
        .map_err(|error| error.to_string())?
        != id
        || serde_json::to_vec(&payment).map_err(|error| error.to_string())? != bytes
    {
        return Err("prepared payment identity mismatch".into());
    }
    Ok(payment)
}

fn request_directory(directory: &Path, create: bool) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let directory = directory.join(DIRECTORY);
    if create {
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    let metadata = fs::symlink_metadata(&directory).map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("payment requests require an owned private directory".into());
    }
    Ok(directory)
}
