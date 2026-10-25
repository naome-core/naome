//! Local wallet custody. The caller serializes initialization with the node's
//! lifecycle lock. Existing private keys are immutable and never regenerated.
use naome_wallet::{Address, WalletKey};
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
            if crate::runtime::wallet_anchor(directory)?
                .is_some_and(|address| address != identity.address)
            {
                return Err("wallet identity does not match the initialized node receipt".into());
            }
            Ok(identity)
        })
        .transpose()
}

fn read_key(directory: &Path, name: &str) -> Result<Option<WalletKey>, String> {
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
    WalletKey::from_keypair_bytes(&keypair).map(Some)
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
    let expected = crate::runtime::wallet_anchor(directory)?;
    if let Some(identity) = identity(directory)? {
        if expected.is_some_and(|address| address != identity.address) {
            return Err("wallet identity does not match the initialized node receipt".into());
        }
        let key = read_key(directory, KEY)?
            .ok_or("existing wallet private key is missing; restore its backup")?;
        if key.address() != identity.address {
            return Err("wallet private key does not match its address receipt".into());
        }
        return Ok(identity);
    }
    let key = if let Some(key) = read_key(directory, KEY)? {
        // Recover a first initialization interrupted before the public receipt.
        key
    } else {
        if expected.is_some() {
            return Err("existing wallet private key is missing; refusing to replace it".into());
        }
        let key = if let Some(key) = read_key(directory, PENDING_KEY)? {
            key
        } else {
            let key = WalletKey::generate()?;
            let mut bytes = Zeroizing::new(Vec::with_capacity(MAGIC.len() + 64));
            bytes.extend_from_slice(MAGIC);
            let keypair = key.to_keypair_bytes();
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
    if expected.is_some_and(|address| address != key.address()) {
        return Err("wallet private key does not match the initialized node receipt".into());
    }
    checkpoint(2)?;
    let identity = Identity {
        version: 1,
        address: key.address(),
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

/// Loads an existing, receipt-bound key without creating or rotating it.
pub(crate) fn key(directory: &Path) -> Result<WalletKey, String> {
    let identity = identity(directory)?.ok_or("wallet is not initialized; start the node first")?;
    let key = read_key(directory, KEY)?
        .ok_or("existing wallet private key is missing; restore its backup")?;
    if key.address() != identity.address {
        return Err("wallet private key does not match its address receipt".into());
    }
    Ok(key)
}
mod connection;
mod payment;
mod session;
pub use session::WalletLedger;
mod service;
pub(crate) use service::observe;
pub use service::{
    NodeWallet, PaymentStatus, WalletConnection, WalletError, WalletFunds, WalletStatus,
};

#[cfg(test)]
mod tests;
