//! A node-hosted ledger session reserves the existing host memory budget.
use super::{NodeWallet, WalletError, connection};
use naome_ledger::{Control, Ledger, Limits, MAX_RECORD_BYTES, NetworkId};
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

/// One checked local ledger, charged to the node host until the session closes.
/// Share it serially between local wallet adapters. Independent hosts still need
/// the selected-order/replication layer; this is not a network settlement service.
pub struct WalletLedger {
    ledger: Ledger,
    _memory: Arc<crate::resources::MemoryLease>,
}
impl Deref for WalletLedger {
    type Target = Ledger;
    fn deref(&self) -> &Ledger {
        &self.ledger
    }
}
impl DerefMut for WalletLedger {
    fn deref_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }
}
impl NodeWallet {
    /// Opens the configured local ledger once, within the current host policy.
    /// Keep this session for related operations; pass a fresh control on each write.
    pub fn open_ledger(
        &self,
        expected_network: NetworkId,
        control: &Control,
    ) -> Result<WalletLedger, WalletError> {
        control.check()?;
        let _lock = self.lock()?;
        let connection =
            connection::read(&self.directory)?.ok_or("wallet is not connected to a ledger")?;
        if connection.signer != self.signer || connection.network != expected_network {
            return Err(naome_ledger::Error::WrongNetwork.into());
        }
        let policy = crate::resources::limits();
        let limits = Limits {
            state_bytes: policy.ledger_state_bytes,
            sqlite_cache_bytes: policy.ledger_cache_bytes,
        };
        // Cover bounded JSON, signature/input selection scratch and SQLite row buffers.
        let bytes = limits
            .state_bytes
            .checked_add(limits.sqlite_cache_bytes)
            .and_then(|bytes| bytes.checked_add(16 * MAX_RECORD_BYTES))
            .ok_or("ledger memory reservation overflow")?;
        let memory = crate::resources::MemoryLease::acquire(bytes).map_err(WalletError::Host)?;
        let ledger =
            Ledger::open_with_limits(&connection.ledger, expected_network, limits, control)?;
        Ok(WalletLedger {
            ledger,
            _memory: memory,
        })
    }
}
