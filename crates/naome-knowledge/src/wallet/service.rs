//! Existing wallet custody, node association, and direct internal payments.
use super::connection::{self, Connection};
use naome_ledger::{
    Amount, Control, Ledger, NetworkId, Operation, SignedTransaction, TransactionId,
};
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

/// The result of reconciling a durable payment request against the selected order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    /// Recorded for submission; it may still be rejected by current ledger state.
    Prepared,
    Committed,
}

/// Wallet outcomes retain ledger rejection, overload and uncertain durability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    Local(String),
    Ledger(naome_ledger::Error),
    Host(crate::Error),
}
impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(message) => f.write_str(message),
            Self::Ledger(error) => error.fmt(f),
            Self::Host(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for WalletError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ledger(error) => Some(error),
            Self::Host(error) => Some(error),
            _ => None,
        }
    }
}
impl From<naome_ledger::Error> for WalletError {
    fn from(error: naome_ledger::Error) -> Self {
        Self::Ledger(error)
    }
}
impl From<String> for WalletError {
    fn from(error: String) -> Self {
        Self::Local(error)
    }
}
impl From<&str> for WalletError {
    fn from(error: &str) -> Self {
        Self::Local(error.into())
    }
}
impl From<WalletError> for String {
    fn from(error: WalletError) -> Self {
        error.to_string()
    }
}

/// Internal wallet custody and revocable spending through one caller-owned ledger session.
///
/// The caller opens the ledger once with an independently selected network and
/// host budgets. Nodes on this host use that same checked handle serially;
/// financial calls never reopen or replay the journal. Close the handle before
/// another process opens the directory. Passive status does not access the ledger.
///
/// ```no_run
/// # fn example(network: naome_ledger::NetworkId) -> Result<(), String> {
/// use naome_knowledge::NodeWallet;
/// use naome_ledger::{Amount, Ledger};
/// use std::path::Path;
/// let owner = NodeWallet::open(Path::new("/nodes/owner"))?;
/// let node = NodeWallet::open(Path::new("/nodes/worker"))?;
/// let bootstrap = Ledger::open(Path::new("/ledger"), network).map_err(|error| error.to_string())?;
/// owner.connect(&bootstrap, owner.signing_address())?;
/// drop(bootstrap);
/// let mut ledger = owner.open_ledger(network, &naome_ledger::Control::default())?;
/// owner.authorize_node(&mut ledger, node.signing_address())?;
/// node.connect(&ledger, owner.signing_address())?;
/// let request = node.prepare_payment(&ledger, node.signing_address(), Amount::from_units(300))?;
/// // Retain the returned request ID before submitting; reuse it after any lost result.
/// node.submit_payment(&mut ledger, request)?;
/// let funds = owner.funds(&ledger)?;
/// owner.revoke_node(&mut ledger, node.signing_address())?;
/// node.disconnect(&mut ledger)?;
/// # Ok(())
/// # }
/// ```
///
/// Preparation durably stores the exact signed transaction under `wallet-payments`
/// before returning its ID. Submission and retry use this ID, including after a
/// restart or an uncertain commit. Preparation can select new inputs after a
/// commit: never replace a lost submission result with a newly prepared payment. Retain request
/// records with the node's custody backup; no private key is included in them.
///
/// Each authorized node can spend the entire shared balance. Only the owner can
/// add nodes; delegates can revoke themselves. Regranting does not revive an old
/// grant epoch. An admitted request remains queryable after revocation.
///
/// There is no wallet CLI, implicit coin allocation, network settlement or
/// finality. The ledger admits a caller-supplied selected order. Issuance,
/// work-reward and purchase policies remain separate system responsibilities.
#[derive(Debug, Clone)]
pub struct NodeWallet {
    pub(super) directory: PathBuf,
    pub(super) signer: Address,
}
pub(super) struct AssociationLock(crate::storage::LockFile);
impl Drop for AssociationLock {
    fn drop(&mut self) {
        let _ = self.0.file().unlock();
    }
}
impl NodeWallet {
    pub fn open(directory: &Path) -> Result<Self, WalletError> {
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
    pub fn status(&self) -> Result<WalletStatus, WalletError> {
        let status = observe(&self.directory).ok_or("wallet identity is unavailable")?;
        if status.signing_address != self.signer {
            return Err("node wallet identity changed; reopen it".into());
        }
        Ok(status)
    }
    pub(super) fn lock(&self) -> Result<AssociationLock, WalletError> {
        let lock = crate::storage::LockFile::open(&self.directory.join("wallet-association.lock"))
            .map_err(|error| error.to_string())?;
        lock.try_lock()
            .map_err(|error| format!("wallet operation unavailable: {error}"))?;
        Ok(AssociationLock(lock))
    }
    fn key(&self) -> Result<WalletKey, WalletError> {
        let key = super::key(&self.directory)?;
        if key.address() != self.signer {
            return Err("node wallet identity changed; reopen it".into());
        }
        Ok(key)
    }
    fn connected(&self, ledger: &Ledger) -> Result<Connection, WalletError> {
        let connection =
            connection::read(&self.directory)?.ok_or("wallet is not connected to a ledger")?;
        if connection.signer != self.signer {
            return Err("node wallet signing identity changed".into());
        }
        if connection.ledger != ledger.directory()
            || connection.network != ledger.state()?.network()
        {
            return Err(naome_ledger::Error::WrongNetwork.into());
        }
        Ok(connection)
    }
    /// Associates the node after the wallet owner has granted its signing key access.
    pub fn connect(&self, ledger: &Ledger, wallet: Address) -> Result<(), WalletError> {
        let _lock = self.lock()?;
        let _key = self.key()?;
        let state = ledger.state()?;
        if state.spending_authority(wallet, self.signer).is_none() {
            return Err(naome_ledger::Error::Unauthorized.into());
        }
        connection::save(
            &self.directory,
            &Connection {
                version: 1,
                ledger: ledger.directory().to_owned(),
                network: state.network(),
                wallet,
                signer: self.signer,
            },
        )?;
        Ok(())
    }
    /// Queries the session's verified funds and current grants, without replay.
    pub fn funds(&self, ledger: &Ledger) -> Result<WalletFunds, WalletError> {
        let _lock = self.lock()?;
        let connection = self.connected(ledger)?;
        let state = ledger.state()?;
        Ok(WalletFunds {
            network: state.network(),
            address: connection.wallet,
            available: state.balance(connection.wallet)?,
            can_spend: self.key().is_ok()
                && state
                    .spending_authority(connection.wallet, self.signer)
                    .is_some(),
            authorized_nodes: state.authorized_nodes(connection.wallet),
        })
    }
    /// Durably prepares a request before any funds move. Retain the returned ID.
    pub fn prepare_payment(
        &self,
        ledger: &Ledger,
        recipient: Address,
        amount: Amount,
    ) -> Result<TransactionId, WalletError> {
        self.prepare_payment_with_control(ledger, recipient, amount, &Control::default())
    }
    pub fn prepare_payment_with_control(
        &self,
        ledger: &Ledger,
        recipient: Address,
        amount: Amount,
        control: &Control,
    ) -> Result<TransactionId, WalletError> {
        control.check()?;
        let _lock = self.lock()?;
        let key = self.key()?;
        let connection = self.connected(ledger)?;
        let payment = ledger.state()?.payment_with_control(
            connection.wallet,
            &key,
            recipient,
            amount,
            control,
        )?;
        let _disk = crate::resources::DiskLease::acquire(
            &self.directory,
            4 * naome_ledger::MAX_RECORD_BYTES as u64,
        )
        .map_err(WalletError::Host)?;
        control.check()?;
        Ok(super::payment::save(&self.directory, &payment)?)
    }
    fn request(
        &self,
        ledger: &Ledger,
        id: TransactionId,
    ) -> Result<SignedTransaction, WalletError> {
        let connection = self.connected(ledger)?;
        let payment = super::payment::read(&self.directory, id)?;
        if payment.signer != self.signer
            || payment.network != connection.network
            || !matches!(payment.operation, Operation::Payment { owner, .. } if owner == connection.wallet)
        {
            return Err(naome_ledger::Error::Unauthorized.into());
        }
        Ok(payment)
    }
    /// Submits the same durable request on every retry. Success means one admission.
    pub fn submit_payment(
        &self,
        ledger: &mut Ledger,
        id: TransactionId,
    ) -> Result<TransactionId, WalletError> {
        self.submit_payment_with_control(ledger, id, &Control::default())
    }
    pub fn submit_payment_with_control(
        &self,
        ledger: &mut Ledger,
        id: TransactionId,
        control: &Control,
    ) -> Result<TransactionId, WalletError> {
        control.check()?;
        let _lock = self.lock()?;
        let _key = self.key()?;
        let payment = self.request(ledger, id)?;
        self.submit(ledger, &payment, control)
    }
    fn submit(
        &self,
        ledger: &mut Ledger,
        transaction: &SignedTransaction,
        control: &Control,
    ) -> Result<TransactionId, WalletError> {
        // A known admitted request needs no new write reservation.
        let _disk = if ledger.transaction(transaction.id()?)?.is_none() {
            Some(
                crate::resources::DiskLease::acquire(
                    ledger.directory(),
                    4 * naome_ledger::MAX_RECORD_BYTES as u64,
                )
                .map_err(WalletError::Host)?,
            )
        } else {
            None
        };
        Ok(ledger.submit_with_control(transaction, control)?)
    }
    pub fn payment_status(
        &self,
        ledger: &Ledger,
        id: TransactionId,
    ) -> Result<PaymentStatus, WalletError> {
        let _lock = self.lock()?;
        self.request(ledger, id)?;
        Ok(if ledger.transaction(id)?.is_some() {
            PaymentStatus::Committed
        } else {
            PaymentStatus::Prepared
        })
    }
    /// Main-wallet user action: authorize one node with full shared spending access.
    pub fn authorize_node(
        &self,
        ledger: &mut Ledger,
        node: Address,
    ) -> Result<TransactionId, WalletError> {
        self.access_change(ledger, node, true)
    }
    /// Main-wallet user action, or a node revoking its own access.
    pub fn revoke_node(
        &self,
        ledger: &mut Ledger,
        node: Address,
    ) -> Result<TransactionId, WalletError> {
        self.access_change(ledger, node, false)
    }
    fn access_change(
        &self,
        ledger: &mut Ledger,
        node: Address,
        enabled: bool,
    ) -> Result<TransactionId, WalletError> {
        let _lock = self.lock()?;
        let key = self.key()?;
        let connection = self.connected(ledger)?;
        let change = ledger
            .state()?
            .access_change(connection.wallet, &key, node, enabled)?;
        self.submit(ledger, &change, &Control::default())
    }
    /// Durably revokes a node's grant before removing its local association.
    pub fn disconnect(&self, ledger: &mut Ledger) -> Result<(), WalletError> {
        let _lock = self.lock()?;
        if connection::read(&self.directory)?.is_none() {
            return Ok(());
        }
        let connection = self.connected(ledger)?;
        let state = ledger.state()?;
        if self.signer != connection.wallet
            && state
                .spending_authority(connection.wallet, self.signer)
                .is_some()
        {
            let key = self.key()?;
            let revoke = state.access_change(connection.wallet, &key, self.signer, false)?;
            self.submit(ledger, &revoke, &Control::default())?;
        }
        Ok(connection::remove(&self.directory)?)
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
