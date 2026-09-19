//! Anchored canonical state history and restart-safe signer custody.
//!
//! Complete records replay through consensus and ledger validation before
//! becoming selected. Separate anchors bind durable journal prefixes; they do
//! not detect coordinated rollback of both files or provide hardware monotonicity.

#[cfg(test)]
mod fault_io;
mod platform;
pub mod state;
mod store_io;
pub use platform::StoragePlatformError;
#[cfg(test)]
use store_io::{AppendPhase, ExclusiveLockError, StoreIo, open_exclusive_lock};

// Keep the existing lock identity until the on-disk namespace boundary changes.
const LOCK_FILE_NAME: &str = "artifact-chain.lock";
const JOURNAL_FILE_NAME: &str = "artifact-chain.journal";
