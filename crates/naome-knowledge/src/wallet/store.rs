//! Local wallet custody. The caller serializes initialization with the node's
//! lifecycle lock. Existing private keys are immutable and never regenerated.
use super::{Address, OwnershipChallenge, OwnershipProof};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

const KEY: &str = "wallet.key";
const PENDING_KEY: &str = ".wallet-key-incoming";
const IDENTITY: &str = "wallet.json";
const PENDING_IDENTITY: &str = ".wallet-identity-incoming";
const MAGIC: &[u8] = b"naome:wallet-key:v1\0";

/// A public address receipt, retained independently of the private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub(crate) version: u8,
    pub(crate) address: Address,
}

pub(crate) fn identity(directory: &Path) -> Result<Option<Identity>, String> {
    crate::storage::read_owned(&directory.join(IDENTITY), 256)?
        .map(|bytes| {
            let identity: Identity =
                serde_json::from_slice(&bytes).map_err(|_| "invalid wallet identity receipt")?;
            if identity.version != 1 {
                return Err("unsupported wallet identity version".into());
            }
            Ok(identity)
        })
        .transpose()
}

fn read_key(directory: &Path, name: &str) -> Result<Option<SigningKey>, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(directory.join(name))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("wallet key unavailable: {error}")),
    };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("wallet key must be one owner-only regular file".into());
    }
    let mut bytes = Zeroizing::new(vec![0u8; MAGIC.len() + 64]);
    file.read_exact(&mut bytes)
        .map_err(|_| "invalid wallet key length")?;
    let mut extra = Zeroizing::new([0u8; 1]);
    if file.read(&mut *extra).map_err(|e| e.to_string())? != 0 || !bytes.starts_with(MAGIC) {
        return Err("invalid wallet key format".into());
    }
    let keypair = Zeroizing::new(
        <[u8; 64]>::try_from(&bytes[MAGIC.len()..]).expect("fixed wallet key length"),
    );
    SigningKey::from_keypair_bytes(&keypair)
        .map(Some)
        .map_err(|_| "wallet private and public keys do not match".into())
}

fn sync(directory: &Path) -> Result<(), String> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

fn write_new(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(directory.join(name))
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| error.to_string())?;
    sync(directory)
}

pub(crate) fn initialize(directory: &Path) -> Result<Identity, String> {
    initialize_at(directory, |_| Ok(()))
}

fn initialize_at(
    directory: &Path,
    mut checkpoint: impl FnMut(u8) -> Result<(), String>,
) -> Result<Identity, String> {
    if let Some(identity) = identity(directory)? {
        let key = read_key(directory, KEY)?
            .ok_or("existing wallet private key is missing; restore its backup")?;
        if Address::from_key(key.verifying_key())? != identity.address {
            return Err("wallet private key does not match its address receipt".into());
        }
        return Ok(identity);
    }
    let key = if let Some(key) = read_key(directory, KEY)? {
        // Recover a first initialization interrupted before the public receipt.
        key
    } else {
        let key = if let Some(key) = read_key(directory, PENDING_KEY)? {
            key
        } else {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut *seed).map_err(|_| "wallet randomness unavailable")?;
            let key = SigningKey::from_bytes(&seed);
            let mut bytes = Zeroizing::new(Vec::with_capacity(MAGIC.len() + 64));
            bytes.extend_from_slice(MAGIC);
            let keypair = Zeroizing::new(key.to_keypair_bytes());
            bytes.extend_from_slice(&*keypair);
            write_new(directory, PENDING_KEY, &bytes)?;
            key
        };
        checkpoint(1)?;
        fs::rename(directory.join(PENDING_KEY), directory.join(KEY))
            .map_err(|error| error.to_string())?;
        sync(directory)?;
        key
    };
    checkpoint(2)?;
    let identity = Identity {
        version: 1,
        address: Address::from_key(key.verifying_key())?,
    };
    if crate::storage::read_owned(&directory.join(PENDING_IDENTITY), 256)?.is_some() {
        fs::remove_file(directory.join(PENDING_IDENTITY)).map_err(|error| error.to_string())?;
    }
    write_new(
        directory,
        PENDING_IDENTITY,
        &serde_json::to_vec(&identity).map_err(|error| error.to_string())?,
    )?;
    checkpoint(3)?;
    fs::rename(directory.join(PENDING_IDENTITY), directory.join(IDENTITY))
        .map_err(|error| error.to_string())?;
    sync(directory)?;
    Ok(identity)
}

pub(crate) fn prove(
    directory: &Path,
    challenge: OwnershipChallenge,
) -> Result<OwnershipProof, String> {
    let identity = identity(directory)?.ok_or("wallet is not initialized; start the node first")?;
    let key = read_key(directory, KEY)?
        .ok_or("existing wallet private key is missing; restore its backup")?;
    if Address::from_key(key.verifying_key())? != identity.address {
        return Err("wallet private key does not match its address receipt".into());
    }
    OwnershipProof::sign(&key, challenge)
}

#[cfg(test)]
mod tests;
