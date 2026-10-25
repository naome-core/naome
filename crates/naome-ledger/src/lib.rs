//! # NAOME local test-coin ledger
//!
//! `naome-ledger` owns integer coin amounts, canonical signed transactions,
//! UTXO validation, revocable node spending rights, and a durable local journal.
//! It depends on `naome-wallet`, not on the gossip node or mathematical proof
//! packages. The node supplies its existing wallet custody and internal service adapter.
//!
//! This is an isolated test ledger with worthless test coins. It does not issue
//! NAO, pay for work, implement mining, replicate balances, or choose a shared
//! transaction order across independent machines. Its initialization allocations
//! are explicit test fixtures, not a production issuance rule. A later production
//! protocol must choose consensus, finality, storage proofs, and issuance rules;
//! it must use a distinct signature and network domain.
//!
//! ## Validation contract
//!
//! - Amounts use `u64` units and checked arithmetic. Outputs and payments must be
//!   positive. Input and output sums must match exactly; there are no fees or burns.
//! - A payment uses at most 128 inputs and 128 outputs. Inputs must be distinct,
//!   unspent, and owned by the payment's stated wallet. Input selection is
//!   deterministic. The signing key must be the owner or a currently authorized
//!   node, with the exact current grant epoch.
//! - Only an owner key can grant access. An owner can revoke any of its node keys;
//!   a node can revoke itself. Each access change uses the next owner sequence.
//! - Every signature binds version, test network, signing address, operation,
//!   consumed outputs, and created outputs or the complete access change.
//!   Ownership challenges cannot authorize payments.
//! - Validation runs before mutation. Rejections leave both balances and the
//!   committed journal unchanged. The local selected order admits at most one
//!   of two transactions spending the same output. Network consensus is still
//!   required for independent nodes to choose the same order.
//!
//! ## Canonical bytes
//!
//! All integers below are unsigned, big-endian. Addresses are their canonical
//! 32-byte Ed25519 public keys. JSON is the bounded interchange representation;
//! identities are computed from the following binary layout, independent of JSON
//! field order or whitespace.
//!
//! A network ID is SHA-256 of `naome:test-ledger-genesis:v1\0`, version `u8`,
//! instance nonce `[u8;32]`, output count `u16`, then each address and amount `u64`.
//! Genesis outputs become outpoints `(network_digest, output_index_u32)`.
//!
//! A transaction ID/signing digest is SHA-256 of
//! `naome:test-ledger-transaction:v1\0`, version `u8`, network ID `[u8;32]`, signer
//! address, then one operation:
//!
//! - Payment tag `0`: owner address, grant epoch `u64` (zero for the owner key),
//!   input count `u16`, each transaction ID `[u8;32]` and output index `u32`, output
//!   count `u16`, then each address and amount `u64`.
//! - Access tag `1`: owner address, delegate address, sequence `u64`, enabled byte
//!   (`0` or `1`).
//!
//! The wallet signs `naome:test-ledger-signature:v1\0` followed by that digest,
//! using strict Ed25519 verification. Signatures are canonical lower-case hex;
//! transaction and network IDs are 32-byte lower-case hex. Every `\0` above means
//! one zero byte. Current format version is 1; other versions are rejected.
//!
//! The journal starts at the network ID. Each admitted transaction updates its
//! root to SHA-256 of `naome:test-ledger-journal:v1\0`, previous root `[u8;32]`, and
//! transaction ID `[u8;32]`. The stored count and root bind the complete order.
//!
//! ## Persistence and limits
//!
//! On supported Unix targets, `Ledger` owns one private directory and exclusive
//! filesystem/SQLite locks. SQLite stores the genesis, ordered signed operations,
//! and committed count/root in one transaction. No private wallet material is
//! stored in the ledger. Each open replays and verifies every operation, checking
//! signatures, value conservation, rights, ordering, canonical records, and the
//! committed count/root. No stored balance or checked flag is trusted.
//!
//! Each genesis/transaction record is limited to 64 KiB. SQLite's page cache is
//! 1 MiB, temporary storage uses files, and memory mapping is disabled. Replay
//! streams records; active UTXOs and grants remain in memory. No scale or
//! performance qualification is claimed for large histories.
//!
//! The database uses DELETE journaling, `synchronous=EXTRA`, and `fullfsync=ON`.
//! EXTRA also synchronizes journal removal as described in the
//! [SQLite durability contract](https://www.sqlite.org/pragma.html#pragma_synchronous).
//! Success is returned only after commit. An uncertain commit poisons the handle;
//! reopen reconstructs whether the transaction was committed. Tests terminate a
//! real child process before and after commit and verify recovery. This does not
//! constitute a physical power-loss test.
//!
//! Missing or corrupt established database/receipt files are errors, never a
//! fresh allowance. A validated empty initialization stage can resume without
//! changing its genesis. Back up the dedicated ledger directory only while it is
//! closed. Restoring an older, internally consistent backup rolls back local test
//! history; detecting that requires an external accepted-state witness.

mod model;
mod state;
#[cfg(unix)]
mod store;

pub use model::{
    Amount, NetworkId, Operation, OutPoint, Output, SignedTransaction, TestGenesis, TransactionId,
};
pub use state::State;
#[cfg(unix)]
pub use store::Ledger;

/// Maximum inputs, outputs, or initial allocations in one bounded operation.
pub const MAX_ITEMS: usize = 128;
/// Maximum encoded JSON bytes of one genesis or signed transaction.
pub const MAX_RECORD_BYTES: usize = 65_536;

/// A rejected transaction or an unavailable local ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    WrongNetwork,
    InvalidSignature,
    DuplicateInput,
    MissingInput,
    Unauthorized,
    InvalidSequence,
    ValueMismatch,
    AmountOverflow,
    Capacity,
    Busy,
    RecoveryRequired,
    Storage(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::WrongNetwork => f.write_str("test-ledger network mismatch"),
            Self::InvalidSignature => f.write_str("invalid test-ledger signature"),
            Self::DuplicateInput => f.write_str("duplicate transaction input"),
            Self::MissingInput => f.write_str("input is missing or already spent"),
            Self::Unauthorized => f.write_str("wallet has not authorized this spending key"),
            Self::InvalidSequence => f.write_str("stale wallet authorization sequence"),
            Self::ValueMismatch => f.write_str("input and output values must match exactly"),
            Self::AmountOverflow => f.write_str("test-coin amount overflow or insufficient funds"),
            Self::Capacity => f.write_str("test-ledger operation capacity"),
            Self::Busy => f.write_str("test ledger is already in use"),
            Self::RecoveryRequired => {
                f.write_str("test-ledger commit unconfirmed; reopen before use")
            }
            Self::Storage(message) => write!(f, "test-ledger storage: {message}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(error.to_string())
    }
}
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Storage(error.to_string())
    }
}
#[cfg(unix)]
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

#[cfg(test)]
mod test_support;
