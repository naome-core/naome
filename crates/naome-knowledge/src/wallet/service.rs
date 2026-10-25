//! ## Internal wallet service and existing nodes
//!
//! The application-facing `naome_knowledge::NodeWallet` service uses the existing
//! `wallet.key` and `wallet.json` files. There is no wallet or ledger CLI, including
//! in the developer binary. The ordinary node CLI remains start, stop, status,
//! interest, help, and version. Applications and autonomous tasks call the service
//! methods directly.
//!
//! Start each node once through the normal lifecycle. Opening `NodeWallet` then
//! validates its existing key and receipt; it never creates or rotates a key.
//! One node can have one persistent public wallet association. Several nodes may
//! use the same owner's wallet. Each node keeps its own private key, and the owner
//! signs the node's spending grant without copying the owner's main key.
//!
//! A minimal integration sequence is:
//!
//! ```no_run
//! # fn example() -> Result<(), String> {
//! use naome_knowledge::NodeWallet;
//! use std::path::Path;
//! let owner_node_directory=Path::new("/nodes/owner");
//! let first_node_directory=Path::new("/nodes/first");
//! let second_node_directory=Path::new("/nodes/second");
//! let test_ledger_directory=Path::new("/test-ledgers/example");
//! use naome_ledger::Amount;
//!
//! let owner = NodeWallet::open(owner_node_directory)?;
//! let first = NodeWallet::open(first_node_directory)?;
//! let second = NodeWallet::open(second_node_directory)?;
//!
//! // Explicit test setup; ordinary startup never calls this method.
//! owner.create_test_ledger(test_ledger_directory, Amount::from_units(1000))?;
//! owner.connect(test_ledger_directory, owner.signing_address())?;
//!
//! // User-authorized wallet association, suitable for a settings/application API.
//! owner.authorize_node(first.signing_address())?;
//! owner.authorize_node(second.signing_address())?;
//! first.connect(test_ledger_directory, owner.signing_address())?;
//! second.connect(test_ledger_directory, owner.signing_address())?;
//!
//! // Called directly by the system's authorized purchase/work policy.
//! first.pay(first.signing_address(), Amount::from_units(300))?;
//! let funds = second.funds()?;
//! assert_eq!(funds.available.units(), 700);
//!
//! owner.revoke_node(first.signing_address())?;
//! first.disconnect()?;
//! # Ok(())
//! # }
//! ```
//!
//! Every authorized node may spend the entire available shared balance. There is
//! no per-node allowance or automatic increase in rights. Delegated nodes cannot authorize
//! other nodes. The owner can revoke one node while leaving all other grants
//! active. `disconnect` durably revokes a delegate's own grant before removing its
//! public association; it requires the ledger to be available. An owner disconnect
//! removes its local association while its main key retains ownership. A revoked
//! node requires a fresh owner grant before reconnecting. Regranting does not
//! revive old prepared payments.
//!
//! A payment to the associated wallet address increases that wallet's funds;
//! there is no special self-credit operation. Work rewards and autonomous purchase
//! selection still require their own agreed protocol and economic rules. This
//! change supplies the internal authorization, payment, and bookkeeping services,
//! not an automatic research market or production currency.
//!
//! `NodeWallet::funds` fully replays and verifies the local test journal, returning
//! its network, available units, current spending authorization, and authorized
//! node addresses. Its scope is always `local_test_coins`. Errors such as a busy
//! or unavailable ledger remain errors and are never rendered as a zero balance.
//! Amounts are whole indivisible test units, with no NAO conversion.
//!
//! Passive `naome status` uses bounded local metadata only: signing address,
//! configured wallet address, association state, and key availability. A configured
//! association does not assert that its grant is still active. Financial views
//! use `funds()` to verify the grant and balance. Full history replay is deliberately
//! kept outside latency-sensitive start/stop/status control and resource-governor
//! operation. The node has no implicit test genesis, mint, reward, or payment step.
//!
//! The current test backend uses one dedicated local ledger directory, with short
//! exclusive ownership per service operation. It does not synchronize independent
//! machines or qualify network filesystems. Do not place the ledger inside a node
//! directory or copy its SQLite files while it is open. The SDK and state-transition
//! contracts leave network ordering and consensus as a separate implementation.

use super::connection::{self, Connection};
use naome_ledger::{Amount, Ledger, NetworkId, Output, TestGenesis, TransactionId};
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
    pub wallet_address: Option<Address>,
    pub connection: WalletConnection,
    pub key_available: bool,
}
/// The sole currency scope supported by the current wallet service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletFundsScope {
    LocalTestCoins,
}
/// Fully rechecked local test-coin funds and individual node spending grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletFunds {
    pub scope: WalletFundsScope,
    pub network: NetworkId,
    pub address: Address,
    pub available: Amount,
    pub can_spend: bool,
    pub authorized_nodes: Vec<Address>,
}

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
            connection::read(&self.directory)?.ok_or("wallet is not connected to a test ledger")?;
        if connection.signer != self.signer {
            return Err("node wallet signing identity changed".into());
        }
        let ledger = Ledger::open(&connection.ledger).map_err(fail)?;
        if ledger.state().map_err(fail)?.network() != connection.network {
            return Err("wallet connection network mismatch".into());
        }
        Ok((connection, ledger))
    }
    /// Explicit test bootstrap only. Node startup never calls this method.
    pub fn create_test_ledger(
        &self,
        directory: &Path,
        amount: Amount,
    ) -> Result<NetworkId, String> {
        let _lock = self.lock()?;
        let key = self.key()?;
        let genesis = TestGenesis::random(vec![Output {
            address: key.address(),
            amount,
        }])
        .map_err(fail)?;
        let ledger = Ledger::create(directory, &genesis).map_err(fail)?;
        Ok(ledger.state().map_err(fail)?.network())
    }
    /// Associates the node after the wallet owner has granted its signing key access.
    pub fn connect(&self, directory: &Path, wallet: Address) -> Result<(), String> {
        let _lock = self.lock()?;
        let _key = self.key()?;
        let path = std::fs::canonicalize(directory).map_err(|error| error.to_string())?;
        let ledger = Ledger::open(&path).map_err(fail)?;
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
            scope: WalletFundsScope::LocalTestCoins,
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
    /// Pays automatically when called by an authorized application policy.
    /// This test ledger has no work-purchase or reward policy of its own.
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
    let (wallet_address, state) = match connection::read(directory) {
        Ok(Some(connection)) => (Some(connection.wallet), WalletConnection::Connected),
        Ok(None) => (Some(identity.address), WalletConnection::Local),
        Err(_) => (None, WalletConnection::Unavailable),
    };
    Some(WalletStatus {
        signing_address: identity.address,
        wallet_address,
        connection: state,
        key_available: super::key(directory).is_ok(),
    })
}

#[cfg(test)]
mod tests;
