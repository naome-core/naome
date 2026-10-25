//! Existing wallet custody, node association, and direct internal payments.
use super::connection::{self, Connection};
use naome_ledger::{Amount, Ledger, NetworkId, TransactionId};
use naome_wallet::{Address, WalletKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The state of the public association, without asserting a verified balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletConnection {
    Local,
    Connected,
    Unavailable,
}
/// Bounded passive node information. Financial state is queried separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletStatus {
    pub signing_address: Address,
    pub network: Option<NetworkId>,
    pub wallet_address: Option<Address>,
    pub connection: WalletConnection,
    pub key_available: bool,
}
/// Fully rechecked local coin funds and individual node spending grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletFunds {
    pub network: NetworkId,
    pub address: Address,
    pub available: Amount,
    pub can_spend: bool,
    pub authorized_nodes: Vec<Address>,
}

/// # Internal wallet service
///
/// Applications and autonomous node tasks call this service directly. There is
/// no wallet or ledger CLI. The ordinary CLI remains start, stop, status,
/// interest, help, and version.
///
/// Open an existing node wallet after normal initialization. No key, coins, or
/// genesis are created by this service. The chain owner initializes storage from
/// its adopted genesis through `naome_ledger::Ledger`; the wallet must supply the
/// selected network identity independently when connecting.
///
/// ```no_run
/// # fn example(network: naome_ledger::NetworkId) -> Result<(), String> {
/// use naome_knowledge::NodeWallet;
/// use naome_ledger::Amount;
/// use std::path::Path;
/// let owner = NodeWallet::open(Path::new("/nodes/owner"))?;
/// let first = NodeWallet::open(Path::new("/nodes/first"))?;
/// let second = NodeWallet::open(Path::new("/nodes/second"))?;
/// let ledger = Path::new("/ledger");
/// owner.connect(ledger, network, owner.signing_address())?;
/// owner.authorize_node(first.signing_address())?;
/// owner.authorize_node(second.signing_address())?;
/// first.connect(ledger, network, owner.signing_address())?;
/// second.connect(ledger, network, owner.signing_address())?;
/// first.pay(first.signing_address(), Amount::from_units(300))?;
/// let funds = second.funds()?;
/// owner.revoke_node(first.signing_address())?;
/// first.disconnect()?;
/// # Ok(())
/// # }
/// ```
///
/// Each authorized node may spend the entire available balance. The owner signs
/// separate node grants without copying its main key. Delegated nodes cannot
/// authorize other nodes; revocation disables future admission, and a regrant
/// does not revive payments signed under the earlier grant epoch.
///
/// `funds()` fully verifies the selected network's journal and current grants.
/// A busy, missing, or corrupt ledger is an error, never a zero balance. Passive
/// node status reads only bounded custody/association metadata; a configured
/// association is not evidence that its spending grant is still active.
///
/// The current storage adapter is local and exclusive per operation. Independent
/// hosts require the network's accepted-order/replication layer; no network
/// filesystem or distributed settlement qualification is claimed. Test fixtures
/// exercise this same production path with their own genesis/network identity.
/// Work reward and purchase policies remain separate system responsibilities.
///
/// The internal wallet interface for applications and autonomous node services.
///
/// Opening does not create a key or coins. Each payment loads the existing key,
/// checks the current node grant, and commits atomically. Authorization grants
/// full access to the shared available funds; only the main owner can add nodes.
/// No CLI or transport command is needed to perform these operations.
#[derive(Debug, Clone)]
pub struct NodeWallet {
    directory: PathBuf,
    signer: Address,
}
struct AssociationLock(crate::storage::LockFile);
impl Drop for AssociationLock {
    fn drop(&mut self) {
        let _ = self.0.file().unlock();
    }
}
fn fail(error: naome_ledger::Error) -> String {
    error.to_string()
}
impl NodeWallet {
    pub fn open(directory: &Path) -> Result<Self, String> {
        let directory = std::fs::canonicalize(directory).map_err(|error| error.to_string())?;
        let key = super::key(&directory)?;
        Ok(Self {
            directory,
            signer: key.address(),
        })
    }
    /// The node's own key address, used when its owner authorizes this node.
    pub const fn signing_address(&self) -> Address {
        self.signer
    }
    /// Reads only bounded local custody/association files, never replays a ledger.
    pub fn status(&self) -> Result<WalletStatus, String> {
        let status = observe(&self.directory).ok_or("wallet identity is unavailable")?;
        if status.signing_address != self.signer {
            return Err("node wallet identity changed; reopen it".into());
        }
        Ok(status)
    }
    fn lock(&self) -> Result<AssociationLock, String> {
        let lock = crate::storage::LockFile::open(&self.directory.join("wallet-association.lock"))
            .map_err(|error| error.to_string())?;
        lock.try_lock()
            .map_err(|error| format!("wallet operation unavailable: {error}"))?;
        Ok(AssociationLock(lock))
    }
    fn key(&self) -> Result<WalletKey, String> {
        let key = super::key(&self.directory)?;
        if key.address() != self.signer {
            return Err("node wallet identity changed; reopen it".into());
        }
        Ok(key)
    }
    fn connected(&self) -> Result<(Connection, Ledger), String> {
        let connection =
            connection::read(&self.directory)?.ok_or("wallet is not connected to a ledger")?;
        if connection.signer != self.signer {
            return Err("node wallet signing identity changed".into());
        }
        let ledger = Ledger::open(&connection.ledger, connection.network).map_err(fail)?;
        Ok((connection, ledger))
    }
    /// Associates the node after the wallet owner has granted its signing key access.
    pub fn connect(
        &self,
        directory: &Path,
        expected_network: NetworkId,
        wallet: Address,
    ) -> Result<(), String> {
        let _lock = self.lock()?;
        let _key = self.key()?;
        let path = std::fs::canonicalize(directory).map_err(|error| error.to_string())?;
        let ledger = Ledger::open(&path, expected_network).map_err(fail)?;
        let state = ledger.state().map_err(fail)?;
        if state.spending_authority(wallet, self.signer).is_none() {
            return Err("wallet must first authorize this node's signing address".into());
        }
        connection::save(
            &self.directory,
            &Connection {
                version: 1,
                ledger: path,
                network: state.network(),
                wallet,
                signer: self.signer,
            },
        )
    }
    /// Replays and verifies funds. Call outside latency-sensitive node control.
    pub fn funds(&self) -> Result<WalletFunds, String> {
        let _lock = self.lock()?;
        let (connection, ledger) = self.connected()?;
        let state = ledger.state().map_err(fail)?;
        Ok(WalletFunds {
            network: state.network(),
            address: connection.wallet,
            available: state.balance(connection.wallet).map_err(fail)?,
            can_spend: self.key().is_ok()
                && state
                    .spending_authority(connection.wallet, self.signer)
                    .is_some(),
            authorized_nodes: state.authorized_nodes(connection.wallet),
        })
    }
    /// Applies a payment to the locally selected order under the caller's policy.
    /// This does not establish network finality. Distributed deployment requires
    /// the network ordering layer; work-purchase and reward policies are separate.
    pub fn pay(&self, recipient: Address, amount: Amount) -> Result<TransactionId, String> {
        let _lock = self.lock()?;
        let key = self.key()?;
        let (connection, mut ledger) = self.connected()?;
        let payment = ledger
            .state()
            .map_err(fail)?
            .payment(connection.wallet, &key, recipient, amount)
            .map_err(fail)?;
        ledger.submit(&payment).map_err(fail)
    }
    /// Main-wallet user action: authorize one node with full shared spending access.
    pub fn authorize_node(&self, node: Address) -> Result<TransactionId, String> {
        self.access_change(node, true)
    }
    /// Main-wallet user action, or a node revoking its own access.
    pub fn revoke_node(&self, node: Address) -> Result<TransactionId, String> {
        self.access_change(node, false)
    }
    fn access_change(&self, node: Address, enabled: bool) -> Result<TransactionId, String> {
        let _lock = self.lock()?;
        let key = self.key()?;
        let (connection, mut ledger) = self.connected()?;
        let change = ledger
            .state()
            .map_err(fail)?
            .access_change(connection.wallet, &key, node, enabled)
            .map_err(fail)?;
        ledger.submit(&change).map_err(fail)
    }
    /// Durably revokes a node's grant before removing its local association.
    pub fn disconnect(&self) -> Result<(), String> {
        let _lock = self.lock()?;
        if connection::read(&self.directory)?.is_none() {
            return Ok(());
        }
        let (connection, mut ledger) = self.connected()?;
        let state = ledger.state().map_err(fail)?;
        if self.signer != connection.wallet
            && state
                .spending_authority(connection.wallet, self.signer)
                .is_some()
        {
            let key = self.key()?;
            let revoke = state
                .access_change(connection.wallet, &key, self.signer, false)
                .map_err(fail)?;
            ledger.submit(&revoke).map_err(fail)?;
        }
        connection::remove(&self.directory)
    }
}

pub(crate) fn observe(directory: &Path) -> Option<WalletStatus> {
    let identity = super::identity(directory).ok()??;
    let (wallet_address, network, state) = match connection::read(directory) {
        Ok(Some(connection)) => (
            Some(connection.wallet),
            Some(connection.network),
            WalletConnection::Connected,
        ),
        Ok(None) => (Some(identity.address), None, WalletConnection::Local),
        Err(_) => (None, None, WalletConnection::Unavailable),
    };
    Some(WalletStatus {
        signing_address: identity.address,
        network,
        wallet_address,
        connection: state,
        key_available: super::key(directory).is_ok(),
    })
}

#[cfg(test)]
mod tests;
