//! Public node-to-wallet association. Spending grants live in the ledger.
use naome_ledger::NetworkId;
use naome_wallet::Address;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

const FILE: &str = "wallet-connection.json";
const INCOMING: &str = ".wallet-connection-incoming";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Connection {
    pub(crate) version: u8,
    pub(crate) ledger: PathBuf,
    pub(crate) network: NetworkId,
    pub(crate) wallet: Address,
    pub(crate) signer: Address,
}

pub(crate) fn read(directory: &Path) -> Result<Option<Connection>, String> {
    crate::storage::read_owned_snapshot(&directory.join(FILE), 8192)?
        .map(|bytes| {
            let connection: Connection =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if connection.version != 1 || !connection.ledger.is_absolute() {
                return Err("invalid wallet connection format".into());
            }
            let identity = super::identity(directory)?.ok_or("wallet identity is missing")?;
            if connection.signer != identity.address {
                return Err("wallet connection signing identity mismatch".into());
            }
            Ok(connection)
        })
        .transpose()
}

/// The caller holds the node lifecycle lock and has checked the ledger grant.
pub(crate) fn save(directory: &Path, connection: &Connection) -> Result<(), String> {
    if let Some(existing) = read(directory)? {
        if existing == *connection {
            return Ok(());
        }
        return Err("disconnect the existing wallet before connecting another".into());
    }
    if crate::storage::read_owned(&directory.join(INCOMING), 8192)?.is_some() {
        fs::remove_file(directory.join(INCOMING)).map_err(|error| error.to_string())?;
    }
    let bytes = serde_json::to_vec(connection).map_err(|error| error.to_string())?;
    if bytes.len() > 8192 {
        return Err("wallet connection byte capacity".into());
    }
    super::write_new(directory, INCOMING, &bytes)?;
    fs::rename(directory.join(INCOMING), directory.join(FILE))
        .map_err(|error| error.to_string())?;
    super::sync(directory)
}

/// A delegate must durably revoke itself before removing its local connection.
pub(crate) fn remove(directory: &Path) -> Result<(), String> {
    if read(directory)?.is_some() {
        fs::remove_file(directory.join(FILE)).map_err(|error| error.to_string())?;
        super::sync(directory)?;
    }
    Ok(())
}
